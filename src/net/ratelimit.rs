//! A tiny async rate limiter (SPEC R-55).
//!
//! Instead of a full token bucket this spaces requests evenly: with a limit
//! of N requests per second, consecutive requests are at least `1/N` seconds
//! apart. Each caller reserves the next free time slot under a mutex, then
//! sleeps until that slot *without* holding the lock, so many tasks can wait
//! concurrently and are released in order.
//!
//! The per-minute limit is folded in the same way (`60/M` seconds spacing),
//! and the stricter of the two wins. This is slightly more conservative than
//! a sliding window (no bursts), which is what you want when being polite to
//! a target. Supporting bursts is one of the exercises in `CHALLENGES.md`.

use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

#[derive(Debug)]
pub struct RateLimiter {
    /// Minimum spacing between requests; `None` = unlimited.
    interval: Option<Duration>,
    /// The earliest instant the next request may start.
    next_slot: Mutex<Instant>,
}

impl RateLimiter {
    /// `per_second` / `per_minute` of 0 mean "no limit" for that window.
    pub fn new(per_second: u32, per_minute: u32) -> Self {
        let from_sec = (per_second > 0).then(|| Duration::from_secs_f64(1.0 / per_second as f64));
        let from_min = (per_minute > 0).then(|| Duration::from_secs_f64(60.0 / per_minute as f64));
        // `Option` implements `Ord` with `None < Some`, so `max` picks the
        // larger (stricter) spacing when both are set.
        let interval = from_sec.max(from_min);
        Self {
            interval,
            next_slot: Mutex::new(Instant::now()),
        }
    }

    pub fn interval(&self) -> Option<Duration> {
        self.interval
    }

    /// Wait until this caller may send a request.
    pub async fn acquire(&self) {
        let Some(interval) = self.interval else {
            return;
        };
        let slot = {
            let mut next = self.next_slot.lock().await;
            let now = Instant::now();
            let slot = (*next).max(now);
            *next = slot + interval;
            slot
        }; // lock released here, before sleeping
        tokio::time::sleep_until(slot).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stricter_limit_wins() {
        let rl = RateLimiter::new(10, 60); // 100ms vs 1s
        assert_eq!(rl.interval(), Some(Duration::from_secs(1)));
        assert_eq!(RateLimiter::new(0, 0).interval(), None);
        assert_eq!(
            RateLimiter::new(4, 0).interval(),
            Some(Duration::from_millis(250))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn spaces_requests() {
        let rl = RateLimiter::new(2, 0); // 500ms apart
        let start = Instant::now();
        for _ in 0..3 {
            rl.acquire().await;
        }
        // first is immediate, then +500ms, +1000ms
        assert_eq!(start.elapsed(), Duration::from_millis(1000));
    }
}
