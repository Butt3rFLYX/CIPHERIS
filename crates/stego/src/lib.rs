//! Keyed PNG embedding for CIPHERIS.
//!
//! Pipeline for [`hide_text`]:
//!
//! 1. A fresh 128 bit [`SecretKey`] is generated from the system random source.
//! 2. The message is wrapped in a small inner schema and sealed with
//!    [`cipheris_core::encrypt`] (Argon2id + XChaCha20 Poly1305) under the key.
//! 3. A placement seed is derived from the key and the image dimensions with
//!    domain separated BLAKE2b. A ChaCha20 stream selects pseudo random,
//!    non repeating channel positions (lazy Fisher Yates shuffle) and masks the
//!    length prefix.
//! 4. Bits are written with LSB *matching* (plus or minus one at random instead
//!    of overwriting the lowest bit), which avoids the pairs of values artefact
//!    of LSB replacement.
//! 5. The result is written as a fresh PNG without any input metadata.
//!
//! Without the key, positions are unknown and no marker sits at a fixed
//! position. Statistical undetectability is **not** claimed; see
//! `docs/THREAT_MODEL.md`.
//!
//! Compatibility: every constant and derivation here is part of the v1 file
//! format. Images made by the earlier SSS releases open unchanged; a
//! regression test pins this.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod carrier;
mod key;
mod placement;

use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use rand_core::OsRng;

use cipheris_core::{EnvelopeError, KdfParams, Limits, Zeroizing, ENVELOPE_OVERHEAD};

pub use carrier::{Carrier, MAX_PIXELS, MAX_PNG_BYTES};
pub use key::SecretKey;
use placement::Placement;

/// Maximum message length in bytes (UTF 8).
pub const MAX_MESSAGE_BYTES: usize = 32 * 1024;
/// At most this fraction of the eligible channel values may carry payload.
/// Lower is less detectable; the interface warns well below this hard limit.
pub const MAX_EMBEDDING_RATE: f64 = 0.25;
/// The interface warns when a message uses more than this fraction.
pub const WARN_EMBEDDING_RATE: f64 = 0.05;

const LEN_PREFIX: usize = 4;
const INNER_VERSION: u8 = 1;
const KIND_TEXT: u8 = 1;
const INNER_OVERHEAD: usize = 2;
const MAX_ENVELOPE: usize = ENVELOPE_OVERHEAD + INNER_OVERHEAD + MAX_MESSAGE_BYTES;

/// Errors with user facing English messages. They never contain key
/// material, message text or file paths.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum StegoError {
    /// Not a readable PNG (or truncated, or an unsupported variant).
    #[error("This image cannot be read. Use a PNG or JPEG file; other formats are converted automatically when hiding.")]
    UnsupportedImage,
    /// Over [`MAX_PIXELS`] or [`MAX_PNG_BYTES`].
    #[error("The image is larger than 40 megapixels or 100 MB. Use a smaller one.")]
    ImageTooLarge,
    /// Message is empty.
    #[error("Type a message first.")]
    EmptyMessage,
    /// Message does not fit.
    #[error("The message is too long for this image (at most {max_bytes} bytes). Use a larger image or shorten the text.")]
    MessageTooLong {
        /// Largest message (bytes) that fits.
        max_bytes: usize,
    },
    /// Key text is malformed or has a wrong checksum.
    #[error("This key contains a typo. Check it character by character.")]
    InvalidKey,
    /// Wrong key, modified image, or no message present. Deliberately one
    /// error so that the cases cannot be told apart.
    #[error("No message found: the key does not match, or the image was changed (for example compressed by a messenger).")]
    NotFound,
    /// Unexpected internal failure (for example the system random source).
    #[error("Something went wrong inside CIPHERIS. Nothing was saved. Try again.")]
    Internal,
}

/// Capacity information for a carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity {
    /// Image width.
    pub width: u32,
    /// Image height.
    pub height: u32,
    /// Largest message in bytes that fits under [`MAX_EMBEDDING_RATE`]
    /// (capped at [`MAX_MESSAGE_BYTES`]). 0 if the image is too small.
    pub max_message_bytes: usize,
    /// Number of channel values that may carry payload.
    pub slots: u64,
}

/// Result of [`hide_text`].
pub struct Hidden {
    /// The new PNG file.
    pub png: Vec<u8>,
    /// The generated key. The message cannot be recovered without it.
    pub key: SecretKey,
    /// Size of the encrypted envelope in bytes.
    pub envelope_bytes: usize,
    /// Number of payload bits written (length prefix plus envelope).
    pub bits: u64,
    /// Number of eligible channel values in the image.
    pub slots: u64,
}

impl Hidden {
    /// Fraction of eligible channel values that carry payload bits.
    pub fn embedding_rate(&self) -> f64 {
        if self.slots == 0 {
            0.0
        } else {
            self.bits as f64 / self.slots as f64
        }
    }
}

/// Capacity of a PNG carrier.
pub fn capacity(png: &[u8]) -> Result<Capacity, StegoError> {
    let c = Carrier::decode_png(png)?;
    Ok(capacity_of(&c))
}

fn capacity_of(c: &Carrier) -> Capacity {
    let slots = c.slot_count();
    let max_bits = (slots as f64 * MAX_EMBEDDING_RATE) as u64;
    let max_stream = usize::try_from(max_bits / 8).unwrap_or(usize::MAX);
    let max_message_bytes = max_stream
        .saturating_sub(LEN_PREFIX + ENVELOPE_OVERHEAD + INNER_OVERHEAD)
        .min(MAX_MESSAGE_BYTES);
    Capacity {
        width: c.width(),
        height: c.height(),
        max_message_bytes,
        slots,
    }
}

/// Encrypts `message` with a freshly generated key and hides it in `png`.
pub fn hide_text(png: &[u8], message: &str) -> Result<Hidden, StegoError> {
    let mut carrier = Carrier::decode_png(png)?;
    let key = SecretKey::generate()?;
    let (envelope_bytes, bits) = embed(&mut carrier, message.as_bytes(), &key)?;
    let slots = carrier.slot_count();
    Ok(Hidden {
        png: carrier.encode_png()?,
        key,
        envelope_bytes,
        bits,
        slots,
    })
}

/// Extracts and decrypts the message hidden in `png` with `key_text`.
///
/// The key is checked first, so a typo is reported before any image work.
pub fn reveal_text(png: &[u8], key_text: &str) -> Result<Zeroizing<String>, StegoError> {
    let key = SecretKey::parse(key_text)?;
    let carrier = Carrier::decode_png(png)?;
    let inner = extract(&carrier, &key)?;
    match inner.as_slice() {
        [INNER_VERSION, KIND_TEXT, text @ ..] => std::str::from_utf8(text)
            .map(|s| Zeroizing::new(s.to_owned()))
            .map_err(|_| StegoError::NotFound),
        _ => Err(StegoError::NotFound),
    }
}

fn envelope_limits() -> Limits {
    Limits {
        max_ciphertext_bytes: MAX_ENVELOPE,
        max_argon2_memory_kib: 256 * 1024,
        max_argon2_iterations: 8,
        max_argon2_parallelism: 8,
    }
}

fn embed(
    carrier: &mut Carrier,
    message: &[u8],
    key: &SecretKey,
) -> Result<(usize, u64), StegoError> {
    if message.is_empty() {
        return Err(StegoError::EmptyMessage);
    }
    let cap = capacity_of(carrier);
    if message.len() > cap.max_message_bytes {
        return Err(StegoError::MessageTooLong {
            max_bytes: cap.max_message_bytes,
        });
    }

    let mut inner = Zeroizing::new(Vec::with_capacity(INNER_OVERHEAD + message.len()));
    inner.extend_from_slice(&[INNER_VERSION, KIND_TEXT]);
    inner.extend_from_slice(message);
    let envelope = cipheris_core::encrypt(
        &inner,
        key.as_bytes(),
        KdfParams::default(),
        envelope_limits(),
    )
    .map_err(|_| StegoError::Internal)?;
    let envelope_len = u32::try_from(envelope.len()).map_err(|_| StegoError::Internal)?;

    let mut placement = Placement::new(carrier, key);
    let mask = placement.mask();
    let mut stream = Vec::with_capacity(LEN_PREFIX + envelope.len());
    stream.extend(
        envelope_len
            .to_be_bytes()
            .iter()
            .zip(mask)
            .map(|(a, b)| a ^ b),
    );
    stream.extend_from_slice(&envelope);

    let bits = u64::try_from(stream.len())
        .ok()
        .and_then(|n| n.checked_mul(8))
        .ok_or(StegoError::Internal)?;
    if bits > placement.slots() {
        return Err(StegoError::Internal);
    }
    let map = carrier.slot_map();
    let mut coin = ChaCha20Rng::from_rng(OsRng).map_err(|_| StegoError::Internal)?;
    let mut coin_bits = 0u64;
    let mut coin_left = 0u32;
    for byte in &stream {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            let k = placement.next().ok_or(StegoError::Internal)?;
            let idx = map.index(k).ok_or(StegoError::Internal)?;
            let v = carrier.pixel_mut(idx).ok_or(StegoError::Internal)?;
            if *v & 1 != bit {
                // LSB matching: move by one in a random direction (forced at
                // the ends of the value range).
                if coin_left == 0 {
                    coin_bits = coin.next_u64();
                    coin_left = 64;
                }
                let up = coin_bits & 1 == 1;
                coin_bits >>= 1;
                coin_left -= 1;
                *v = match *v {
                    0 => 1,
                    255 => 254,
                    x if up => x + 1,
                    x => x - 1,
                };
            }
        }
    }
    Ok((envelope.len(), bits))
}

fn extract(carrier: &Carrier, key: &SecretKey) -> Result<Zeroizing<Vec<u8>>, StegoError> {
    let mut placement = Placement::new(carrier, key);
    if placement.slots() < (LEN_PREFIX * 8) as u64 {
        return Err(StegoError::NotFound);
    }
    let map = carrier.slot_map();
    let mask = placement.mask();
    let read_byte = |p: &mut Placement| -> Result<u8, StegoError> {
        let mut b = 0u8;
        for _ in 0..8 {
            let k = p.next().ok_or(StegoError::NotFound)?;
            let idx = map.index(k).ok_or(StegoError::Internal)?;
            let v = carrier.pixel(idx).ok_or(StegoError::Internal)?;
            b = (b << 1) | (v & 1);
        }
        Ok(b)
    };
    let mut len = [0u8; LEN_PREFIX];
    for (slot, m) in len.iter_mut().zip(mask) {
        *slot = read_byte(&mut placement)? ^ m;
    }
    let len = u32::from_be_bytes(len) as usize;
    let available = usize::try_from(placement.slots() / 8)
        .unwrap_or(usize::MAX)
        .saturating_sub(LEN_PREFIX);
    if !(ENVELOPE_OVERHEAD + INNER_OVERHEAD..=MAX_ENVELOPE.min(available)).contains(&len) {
        return Err(StegoError::NotFound);
    }
    let mut envelope = Zeroizing::new(Vec::with_capacity(len));
    for _ in 0..len {
        envelope.push(read_byte(&mut placement)?);
    }
    cipheris_core::decrypt(&envelope, key.as_bytes(), envelope_limits()).map_err(|e| match e {
        EnvelopeError::ResourceLimit
        | EnvelopeError::AuthenticationFailed
        | EnvelopeError::InvalidEnvelope
        | EnvelopeError::UnsupportedFormat => StegoError::NotFound,
        EnvelopeError::CryptoFailure => StegoError::Internal,
    })
}

#[cfg(test)]
mod tests;
