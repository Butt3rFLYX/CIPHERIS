use thiserror::Error;

/// Errors returned by [`encrypt`](crate::encrypt) and [`decrypt`](crate::decrypt).
///
/// Messages are intentionally generic and never contain key material,
/// plaintext or file paths. A user interface should merge `InvalidEnvelope`
/// and `AuthenticationFailed` into one message so that the distinction cannot
/// serve as an oracle.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum EnvelopeError {
    /// Input is too short or does not carry the format marker.
    #[error("input is not a supported envelope")]
    InvalidEnvelope,
    /// Version or algorithm suite is not on the allowlist.
    #[error("unsupported envelope version or algorithm suite")]
    UnsupportedFormat,
    /// Declared or requested parameters violate the local [`Limits`](crate::Limits).
    #[error("declared parameters exceed local safety limits")]
    ResourceLimit,
    /// Wrong secret, corruption, or tampering.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// Unexpected failure inside a cryptographic primitive or the system random source.
    #[error("cryptographic operation failed")]
    CryptoFailure,
}
