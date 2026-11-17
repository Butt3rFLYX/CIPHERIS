//! API endpoints. All of them are `POST`, need a session and run only after
//! the access checks in `Server::admit` (in `lib.rs`) passed on the request
//! head.

use std::sync::atomic::{AtomicUsize, Ordering};

use cipheris_stego::{
    StegoError, MAX_MESSAGE_BYTES, MAX_PIXELS, MAX_PNG_BYTES, WARN_EMBEDDING_RATE,
};

use crate::http::Response;

/// Longest accepted key field in bytes.
pub const MAX_KEY_FIELD: usize = 256;

/// Largest body an API endpoint accepts.
pub fn body_limit(path: &str) -> usize {
    match path {
        "/api/capacity" => MAX_PNG_BYTES,
        "/api/hide" => MAX_PNG_BYTES + 4 + MAX_MESSAGE_BYTES,
        "/api/reveal" => MAX_PNG_BYTES + 4 + MAX_KEY_FIELD,
        _ => 0,
    }
}

/// Limits how many image operations run at once. Each one can use a few
/// hundred MB (decoded pixels plus 64 MiB of Argon2 memory).
pub struct HeavySlots {
    in_use: AtomicUsize,
    max: usize,
}

pub struct HeavyGuard<'a>(&'a HeavySlots);

impl Drop for HeavyGuard<'_> {
    fn drop(&mut self) {
        self.0.in_use.fetch_sub(1, Ordering::AcqRel);
    }
}

impl HeavySlots {
    pub fn new(max: usize) -> Self {
        Self {
            in_use: AtomicUsize::new(0),
            max,
        }
    }

    pub fn try_acquire(&self) -> Option<HeavyGuard<'_>> {
        self.in_use
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.max).then_some(n + 1)
            })
            .ok()
            .map(|_| HeavyGuard(self))
    }
}

pub fn busy() -> Response {
    Response::text(
        503,
        "CIPHERIS is busy with another image. Try again in a moment.",
    )
}

/// Splits `[u32 big endian length][field][rest]`.
fn split_field(body: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(body.get(..4)?.try_into().ok()?) as usize;
    let end = 4usize.checked_add(len)?;
    Some((body.get(4..end)?, body.get(end..)?))
}

fn stego_err(e: StegoError) -> Response {
    let status = match e {
        StegoError::Internal => 500,
        StegoError::ImageTooLarge => 413,
        _ => 422,
    };
    Response::text(status, &e.to_string())
}

pub fn status(idle_minutes: u64) -> Response {
    Response::new(
        200,
        "application/json",
        format!(
            "{{\"maxPngBytes\":{MAX_PNG_BYTES},\"maxPixels\":{MAX_PIXELS},\"maxMessageBytes\":{MAX_MESSAGE_BYTES},\"warnRate\":{WARN_EMBEDDING_RATE},\"idleMinutes\":{idle_minutes}}}"
        ),
    )
}

pub fn capacity(body: &[u8]) -> Response {
    match cipheris_stego::capacity(body) {
        Ok(c) => Response::new(
            200,
            "application/json",
            format!(
                "{{\"width\":{},\"height\":{},\"maxBytes\":{},\"slots\":{}}}",
                c.width, c.height, c.max_message_bytes, c.slots
            ),
        ),
        Err(e) => stego_err(e),
    }
}

pub fn hide(body: &[u8]) -> Response {
    let Some((msg, image)) = split_field(body) else {
        return Response::text(400, "The request was malformed. Reload the page.");
    };
    let Ok(msg) = std::str::from_utf8(msg) else {
        return Response::text(422, "The message is not valid text.");
    };
    match cipheris_stego::hide_text(image, msg) {
        Ok(h) => {
            let key = h.key.to_display_string();
            let rate_ppm = (h.embedding_rate() * 1_000_000.0).round() as u64;
            let mut r = Response::new(200, "image/png", Vec::new());
            r.extra.push(("X-Cipheris-Key", key));
            r = r
                .header("X-Cipheris-Envelope-Bytes", h.envelope_bytes.to_string())
                .header("X-Cipheris-Bits", h.bits.to_string())
                .header("X-Cipheris-Slots", h.slots.to_string())
                .header("X-Cipheris-Rate-Ppm", rate_ppm.to_string());
            r.body = zeroize::Zeroizing::new(h.png);
            r
        }
        Err(e) => stego_err(e),
    }
}

pub fn reveal(body: &[u8]) -> Response {
    let Some((key, image)) = split_field(body) else {
        return Response::text(400, "The request was malformed. Reload the page.");
    };
    // A key is 28 characters plus separators; anything far longer is not a key.
    if key.len() > MAX_KEY_FIELD {
        return stego_err(StegoError::InvalidKey);
    }
    let Ok(key) = std::str::from_utf8(key) else {
        return stego_err(StegoError::InvalidKey);
    };
    match cipheris_stego::reveal_text(image, key) {
        Ok(text) => {
            let mut r = Response::new(200, "text/plain; charset=utf-8", text.as_bytes().to_vec());
            r = r.header("X-Cipheris-Bytes", text.len().to_string());
            r
        }
        Err(e) => stego_err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_field_rejects_bad_lengths() {
        assert!(split_field(&[]).is_none());
        assert!(split_field(&[0, 0, 0]).is_none());
        assert!(split_field(&[0, 0, 0, 5, 1, 2]).is_none());
        assert!(split_field(&[0xff, 0xff, 0xff, 0xff]).is_none());
        assert_eq!(
            split_field(&[0, 0, 0, 1, 7, 8, 9]),
            Some((&[7u8][..], &[8u8, 9][..]))
        );
    }

    #[test]
    fn heavy_slots_are_bounded_and_released() {
        let s = HeavySlots::new(2);
        let a = s.try_acquire();
        let b = s.try_acquire();
        assert!(a.is_some() && b.is_some());
        assert!(s.try_acquire().is_none());
        drop(a);
        assert!(s.try_acquire().is_some());
    }
}
