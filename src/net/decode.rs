//! Decoding `Content-Encoding` on captured bodies (SPEC R-11b).
//!
//! The ingest contract says `body` / `body_base64` are the bytes as they
//! went over the wire. Proxies like Caido forward responses still
//! gzip/brotli/deflate-encoded, together with the original headers, so the
//! pipeline decodes them here.
//!
//! Decompression is the classic zip-bomb vector: a few KiB can expand to
//! gigabytes. Output is produced in bounded steps; every step is charged to
//! the memory [`Budget`] *before* the buffer grows (never waiting, since the
//! caller already holds a reservation), and the total is capped at
//! `max_bytes`.

use std::io::Read;

use crate::budget::{Budget, Reservation};
use crate::model::Headers;

/// Decode step size.
const STEP: usize = 64 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("unsupported Content-Encoding `{0}`")]
    Unsupported(String),
    #[error("decoded body exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("memory budget exhausted while decoding")]
    OverBudget,
    #[error("corrupt {0} stream")]
    Corrupt(&'static str),
}

/// The encodings to undo, outermost last (`Content-Encoding: gzip, br`
/// means br was applied last, so it's removed first). `None` when there's
/// nothing to do.
fn encodings(headers: &Headers) -> Option<Vec<String>> {
    let v = headers.get("content-encoding")?;
    let list: Vec<String> = v
        .split(',')
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty() && e != "identity")
        .collect();
    (!list.is_empty()).then_some(list)
}

/// Decode `body` according to its `Content-Encoding`, if any. On success
/// returns the decoded bytes, a reservation covering them, and the headers
/// with `Content-Encoding`/`Content-Length` removed. `Ok(None)` means the
/// body wasn't encoded.
pub fn decode_captured(
    headers: &Headers,
    body: &[u8],
    max_bytes: usize,
    budget: &Budget,
) -> Result<Option<(Vec<u8>, Reservation, Headers)>, DecodeError> {
    let Some(list) = encodings(headers) else {
        return Ok(None);
    };
    let mut data: Option<(Vec<u8>, Reservation)> = None;
    for enc in list.iter().rev() {
        let input: &[u8] = data.as_ref().map_or(body, |(d, _)| d.as_slice());
        let decoded = decode_one(enc, input, max_bytes, budget)?;
        // The previous layer's buffer and reservation are dropped here.
        data = Some(decoded);
    }
    let (bytes, reservation) = data.expect("at least one encoding");
    let cleaned = Headers(
        headers
            .0
            .iter()
            .filter(|(k, _)| {
                !k.eq_ignore_ascii_case("content-encoding")
                    && !k.eq_ignore_ascii_case("content-length")
            })
            .cloned()
            .collect(),
    );
    Ok(Some((bytes, reservation, cleaned)))
}

fn decode_one(
    enc: &str,
    input: &[u8],
    max_bytes: usize,
    budget: &Budget,
) -> Result<(Vec<u8>, Reservation), DecodeError> {
    match enc {
        "gzip" | "x-gzip" => read_capped(
            flate2::read::MultiGzDecoder::new(input),
            "gzip",
            max_bytes,
            budget,
        ),
        // "deflate" is meant to be zlib-wrapped, but some servers send raw
        // deflate; try zlib first, then raw.
        "deflate" => read_capped(
            flate2::read::ZlibDecoder::new(input),
            "deflate",
            max_bytes,
            budget,
        )
        .or_else(|_| {
            read_capped(
                flate2::read::DeflateDecoder::new(input),
                "deflate",
                max_bytes,
                budget,
            )
        }),
        "br" => read_capped(
            brotli_decompressor::Decompressor::new(input, 4096),
            "br",
            max_bytes,
            budget,
        ),
        other => Err(DecodeError::Unsupported(other.to_string())),
    }
}

/// Read `r` to the end in [`STEP`]-sized pieces, charging the budget for
/// each piece before the buffer grows, and stopping at `max_bytes`.
fn read_capped(
    mut r: impl Read,
    name: &'static str,
    max_bytes: usize,
    budget: &Budget,
) -> Result<(Vec<u8>, Reservation), DecodeError> {
    let first = STEP.min(max_bytes.max(1));
    let mut res = budget.try_reserve(first).ok_or(DecodeError::OverBudget)?;
    let mut out: Vec<u8> = Vec::with_capacity(first);
    let mut chunk = [0u8; 8192];
    loop {
        let n = r.read(&mut chunk).map_err(|_| DecodeError::Corrupt(name))?;
        if n == 0 {
            break;
        }
        let new_len = out.len() + n;
        if new_len > max_bytes {
            return Err(DecodeError::TooLarge { limit: max_bytes });
        }
        if new_len > out.capacity() {
            let target = (out.capacity() + STEP).min(max_bytes).max(new_len);
            if !res.try_grow(target) {
                return Err(DecodeError::OverBudget);
            }
            out.reserve_exact(target - out.len());
            if !res.try_grow(out.capacity()) {
                return Err(DecodeError::OverBudget);
            }
        }
        out.extend_from_slice(&chunk[..n]);
        debug_assert!(res.bytes() >= out.capacity());
    }
    out.shrink_to_fit();
    res.shrink_to(out.capacity());
    Ok((out, res))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn h(enc: &str) -> Headers {
        let mut h = Headers::new();
        h.push("Content-Type", "application/javascript");
        h.push("Content-Encoding", enc);
        h.push("Content-Length", "123");
        h
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn gzip_deflate_identity() {
        let budget = Budget::new(1 << 20);
        let (out, r, hdrs) = decode_captured(&h("gzip"), &gzip(b"var a = 1;"), 1 << 20, &budget)
            .unwrap()
            .unwrap();
        assert_eq!(out, b"var a = 1;");
        assert!(r.bytes() >= out.capacity());
        assert!(hdrs.get("content-encoding").is_none() && hdrs.get("content-length").is_none());
        drop(r);

        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b"deflated").unwrap();
        let (out, ..) = decode_captured(&h("deflate"), &z.finish().unwrap(), 1 << 20, &budget)
            .unwrap()
            .unwrap();
        assert_eq!(out, b"deflated");

        assert!(
            decode_captured(&h("identity"), b"x", 10, &budget)
                .unwrap()
                .is_none()
        );
        assert_eq!(budget.in_use(), 0, "reservations released");
    }

    #[test]
    fn brotli() {
        // "hello" compressed with brotli (quality 11), produced offline.
        let br: &[u8] = &[0x0b, 0x02, 0x80, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x03];
        let budget = Budget::new(1 << 20);
        let (out, ..) = decode_captured(&h("br"), br, 1 << 20, &budget)
            .unwrap()
            .unwrap();
        assert_eq!(out, b"hello");
    }

    /// A gzip bomb: 10 MiB of zeros compresses to ~10 KiB.
    #[test]
    fn decompression_bombs_are_capped() {
        let bomb = gzip(&vec![0u8; 10 * 1024 * 1024]);
        assert!(bomb.len() < 64 * 1024);
        let budget = Budget::new(64 * 1024 * 1024);
        assert_eq!(
            decode_captured(&h("gzip"), &bomb, 1024 * 1024, &budget).unwrap_err(),
            DecodeError::TooLarge { limit: 1024 * 1024 }
        );
        // With a large cap but a small budget, the budget stops it.
        let small = Budget::new(512 * 1024);
        assert_eq!(
            decode_captured(&h("gzip"), &bomb, 100 * 1024 * 1024, &small).unwrap_err(),
            DecodeError::OverBudget
        );
        assert_eq!((budget.in_use(), small.in_use()), (0, 0));
        assert!(small.peak() <= small.capacity());
    }

    #[test]
    fn unsupported_and_corrupt() {
        let budget = Budget::new(1 << 20);
        assert!(matches!(
            decode_captured(&h("zstd"), b"x", 10, &budget),
            Err(DecodeError::Unsupported(_))
        ));
        assert!(matches!(
            decode_captured(&h("gzip"), b"not gzip", 10, &budget),
            Err(DecodeError::Corrupt("gzip"))
        ));
    }
}
