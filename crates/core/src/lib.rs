//! CIPHERIS cryptographic envelope.
//!
//! This crate knows nothing about images. It turns a plaintext and a secret
//! into a self describing, authenticated envelope and back:
//!
//! * Argon2id (RFC 9106) derives a key encryption key from the secret and a
//!   fresh random salt.
//! * A fresh random data encryption key encrypts the payload with
//!   XChaCha20 Poly1305; the key encryption key wraps the data key.
//! * Every header byte (format marker, version, suite, KDF costs, salt,
//!   nonces, wrapped key) is authenticated.
//! * Attacker controlled KDF costs and sizes are checked against local
//!   [`Limits`] before any expensive work.
//!
//! The on disk marker is `SSS1` for compatibility with files created before
//! the project was renamed to CIPHERIS. See `docs/FORMAT.md`.
//!
//! ```
//! use cipheris_core::{decrypt, encrypt, KdfParams, Limits};
//!
//! let envelope = encrypt(b"secret", b"pw", KdfParams::default(), Limits::default())?;
//! let plaintext = decrypt(&envelope, b"pw", Limits::default())?;
//! assert_eq!(&plaintext[..], b"secret");
//! # Ok::<(), cipheris_core::EnvelopeError>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod envelope;
mod error;
mod limits;
#[cfg(test)]
mod vectors;

pub use envelope::{decrypt, encrypt, KdfParams, ENVELOPE_OVERHEAD};
pub use error::EnvelopeError;
pub use limits::Limits;
pub use zeroize::Zeroizing;
