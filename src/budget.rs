//! The memory budget for response bodies (SPEC R-36).
//!
//! Every byte of HTTP body the pipeline holds (captured bodies, fetched
//! pages, scripts, chunks, source maps, inline maps) must be covered by a
//! [`Reservation`]. A reservation is an RAII guard: it is taken from the
//! [`Budget`] *before* the bytes exist, can be grown (fallibly) or shrunk,
//! and gives everything back when dropped, even on early return, error,
//! panic, or task cancellation.
//!
//! Under the hood the budget is a [`tokio::sync::Semaphore`] with one
//! permit per KiB:
//!
//! * [`Budget::reserve`] waits for room (backpressure),
//! * [`Budget::try_reserve`] and [`Reservation::try_grow`] never wait,
//! * [`Reservation::shrink_to`] returns the unused part right away.
//!
//! **Deadlock rule:** only wait (`reserve`) while holding *no other*
//! reservation. The semaphore is FIFO-fair, so a holder waiting for more
//! could block everyone queued behind it. Holders that need more use
//! `try_grow` and fail instead of waiting.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Bytes per semaphore permit.
pub const UNIT: usize = 1024;

/// Bytes → permits, rounded up, at least one.
fn units(bytes: usize) -> usize {
    bytes.div_ceil(UNIT).max(1)
}

#[derive(Debug)]
struct Inner {
    sem: Arc<Semaphore>,
    total_units: usize,
    /// Highest number of units held at once (for tests and diagnostics).
    peak_units: AtomicUsize,
}

impl Inner {
    fn record_peak(&self) {
        let used = self.total_units - self.sem.available_permits();
        self.peak_units.fetch_max(used, Ordering::AcqRel);
    }
}

/// A shared, cheap-to-clone byte budget.
#[derive(Debug, Clone)]
pub struct Budget {
    inner: Arc<Inner>,
}

impl Budget {
    pub fn new(bytes: usize) -> Self {
        let total_units = units(bytes).min(Semaphore::MAX_PERMITS);
        Self {
            inner: Arc::new(Inner {
                sem: Arc::new(Semaphore::new(total_units)),
                total_units,
                peak_units: AtomicUsize::new(0),
            }),
        }
    }

    /// Total budget in bytes.
    pub fn capacity(&self) -> usize {
        self.inner.total_units * UNIT
    }

    /// Bytes currently reserved.
    pub fn in_use(&self) -> usize {
        (self.inner.total_units - self.inner.sem.available_permits()) * UNIT
    }

    /// The most bytes ever reserved at once.
    pub fn peak(&self) -> usize {
        self.inner.peak_units.load(Ordering::Acquire) * UNIT
    }

    /// Reserve exactly `bytes`, waiting for room. Returns `None` (without
    /// waiting) if the request is larger than the whole budget: it could
    /// never be granted, and silently granting less would let the caller
    /// allocate more than it reserved. Only call this while holding no
    /// other reservation.
    pub async fn reserve(&self, bytes: usize) -> Option<Reservation> {
        let n = units(bytes);
        if n > self.inner.total_units {
            return None;
        }
        let permit = Arc::clone(&self.inner.sem)
            .acquire_many_owned(n as u32)
            .await
            .expect("budget semaphore is never closed");
        self.inner.record_peak();
        Some(Reservation {
            budget: self.clone(),
            permit,
        })
    }

    /// Reserve `bytes` only if room is available right now.
    pub fn try_reserve(&self, bytes: usize) -> Option<Reservation> {
        let n = units(bytes);
        if n > self.inner.total_units {
            return None;
        }
        let permit = Arc::clone(&self.inner.sem)
            .try_acquire_many_owned(n as u32)
            .ok()?;
        self.inner.record_peak();
        Some(Reservation {
            budget: self.clone(),
            permit,
        })
    }
}

/// Bytes held against a [`Budget`]; released on drop.
#[derive(Debug)]
pub struct Reservation {
    budget: Budget,
    permit: OwnedSemaphorePermit,
}

impl Reservation {
    /// Bytes covered by this reservation (a multiple of [`UNIT`]).
    pub fn bytes(&self) -> usize {
        self.permit.num_permits() * UNIT
    }

    /// Make sure at least `bytes` are covered, without waiting. Returns
    /// `false` (and changes nothing) if the budget has no room.
    pub fn try_grow(&mut self, bytes: usize) -> bool {
        let have = self.permit.num_permits();
        let want = units(bytes);
        if want <= have {
            return true;
        }
        match Arc::clone(&self.budget.inner.sem).try_acquire_many_owned((want - have) as u32) {
            Ok(extra) => {
                self.permit.merge(extra);
                self.budget.inner.record_peak();
                true
            }
            Err(_) => false,
        }
    }

    /// Give back everything above `bytes` now.
    pub fn shrink_to(&mut self, bytes: usize) {
        let have = self.permit.num_permits();
        let keep = units(bytes);
        if keep < have {
            // Splitting off the excess and dropping it releases it.
            drop(self.permit.split(have - keep));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reserve_grow_shrink_release() {
        let b = Budget::new(10 * UNIT);
        let mut r = b.reserve(3 * UNIT).await.unwrap();
        assert_eq!((r.bytes(), b.in_use()), (3 * UNIT, 3 * UNIT));
        assert!(r.try_grow(8 * UNIT));
        assert_eq!(b.in_use(), 8 * UNIT);
        assert!(!r.try_grow(11 * UNIT), "can't exceed the budget");
        assert!(b.try_reserve(3 * UNIT).is_none(), "only 2 units left");
        r.shrink_to(1);
        assert_eq!(b.in_use(), UNIT);
        drop(r);
        assert_eq!(b.in_use(), 0);
        assert_eq!(b.peak(), 8 * UNIT);
    }

    #[tokio::test]
    async fn waiters_get_room_when_holders_drop() {
        let b = Budget::new(4 * UNIT);
        let held = b.reserve(4 * UNIT).await.unwrap();
        let b2 = b.clone();
        let waiter = tokio::spawn(async move { b2.reserve(2 * UNIT).await.unwrap().bytes() });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(held);
        assert_eq!(waiter.await.unwrap(), 2 * UNIT);
        assert!(b.peak() <= b.capacity());
    }

    #[tokio::test]
    async fn oversized_requests() {
        let b = Budget::new(4 * UNIT);
        assert!(b.try_reserve(5 * UNIT).is_none());
        // Never silently granted less, never waits forever.
        assert!(b.reserve(100 * UNIT).await.is_none());
    }
}
