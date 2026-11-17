use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{EnvelopeError, Limits};

/// Format marker. Kept as `SSS1` so files made before the rename still open.
const MAGIC: &[u8; 4] = b"SSS1";
const VERSION: u16 = 1;
const SUITE: u16 = 1; // Argon2id v1.3 + XChaCha20 Poly1305
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const DEK_LEN: usize = 32;
const TAG_LEN: usize = 16;

// Field offsets. Every slice into an envelope is derived from these constants so
// that the parser and the serializer cannot silently drift apart.
const OFF_VERSION: usize = MAGIC.len();
const OFF_SUITE: usize = OFF_VERSION + 2;
const OFF_MEMORY: usize = OFF_SUITE + 2;
const OFF_ITERATIONS: usize = OFF_MEMORY + 4;
const OFF_PARALLELISM: usize = OFF_ITERATIONS + 4;
const OFF_SALT: usize = OFF_PARALLELISM + 4;
const OFF_WRAP_NONCE: usize = OFF_SALT + SALT_LEN;
const OFF_DATA_NONCE: usize = OFF_WRAP_NONCE + NONCE_LEN;
const PREFIX_LEN: usize = OFF_DATA_NONCE + NONCE_LEN;
const WRAPPED_DEK_LEN: usize = DEK_LEN + TAG_LEN;
const HEADER_LEN: usize = PREFIX_LEN + WRAPPED_DEK_LEN;

/// Bytes an envelope adds to its plaintext (header plus payload tag).
pub const ENVELOPE_OVERHEAD: usize = HEADER_LEN + TAG_LEN;

// The layout documented in docs/FORMAT.md. A change here is a format break.
const _: () = assert!(PREFIX_LEN == 84 && HEADER_LEN == 132);

/// Argon2id cost parameters stored (authenticated) in every envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Number of lanes.
    pub parallelism: u32,
}

impl Default for KdfParams {
    /// RFC 9106 §4, second recommended option (64 MiB, t = 3, p = 4).
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

/// Encrypts `plaintext` under `password` into a self describing v1 envelope.
///
/// A fresh salt, two fresh nonces and a fresh data-encryption key are drawn
/// from the operating system CSPRNG for every call.
pub fn encrypt(
    plaintext: &[u8],
    password: &[u8],
    params: KdfParams,
    limits: Limits,
) -> Result<Vec<u8>, EnvelopeError> {
    encrypt_with_rng(plaintext, password, params, limits, &mut OsRng)
}

fn encrypt_with_rng<R: RngCore + CryptoRng>(
    plaintext: &[u8],
    password: &[u8],
    params: KdfParams,
    limits: Limits,
    rng: &mut R,
) -> Result<Vec<u8>, EnvelopeError> {
    let ciphertext_len = plaintext
        .len()
        .checked_add(TAG_LEN)
        .filter(|n| *n <= limits.max_ciphertext_bytes)
        .ok_or(EnvelopeError::ResourceLimit)?;
    validate_kdf(params, limits)?;

    let mut salt = [0u8; SALT_LEN];
    let mut wrap_nonce = [0u8; NONCE_LEN];
    let mut data_nonce = [0u8; NONCE_LEN];
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    // `try_fill_bytes` reports a failing system random source as an error
    // instead of panicking.
    for buf in [
        &mut salt[..],
        &mut wrap_nonce[..],
        &mut data_nonce[..],
        &mut dek[..],
    ] {
        rng.try_fill_bytes(buf)
            .map_err(|_| EnvelopeError::CryptoFailure)?;
    }

    let kek = derive_kek(password, &salt, params)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext_len);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&SUITE.to_be_bytes());
    out.extend_from_slice(&params.memory_kib.to_be_bytes());
    out.extend_from_slice(&params.iterations.to_be_bytes());
    out.extend_from_slice(&params.parallelism.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&wrap_nonce);
    out.extend_from_slice(&data_nonce);
    debug_assert_eq!(out.len(), PREFIX_LEN);

    let wrapped = aead(&kek)
        .encrypt(
            &XNonce::from(wrap_nonce),
            Payload {
                msg: dek.as_ref(),
                aad: &out,
            },
        )
        .map_err(|_| EnvelopeError::CryptoFailure)?;
    out.extend_from_slice(&wrapped);
    debug_assert_eq!(out.len(), HEADER_LEN);

    let ciphertext = aead(&dek)
        .encrypt(
            &XNonce::from(data_nonce),
            Payload {
                msg: plaintext,
                aad: &out,
            },
        )
        .map_err(|_| EnvelopeError::CryptoFailure)?;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Authenticates and decrypts a v1 envelope.
///
/// Plaintext is returned only after every byte of the envelope has been
/// authenticated. The returned buffer is wiped when dropped.
pub fn decrypt(
    envelope: &[u8],
    password: &[u8],
    limits: Limits,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    if envelope.len() < HEADER_LEN + TAG_LEN {
        return Err(EnvelopeError::InvalidEnvelope);
    }
    if envelope.len() - HEADER_LEN > limits.max_ciphertext_bytes {
        return Err(EnvelopeError::ResourceLimit);
    }
    if envelope[..OFF_VERSION] != MAGIC[..] {
        return Err(EnvelopeError::InvalidEnvelope);
    }
    if read_u16(envelope, OFF_VERSION)? != VERSION || read_u16(envelope, OFF_SUITE)? != SUITE {
        return Err(EnvelopeError::UnsupportedFormat);
    }
    let params = KdfParams {
        memory_kib: read_u32(envelope, OFF_MEMORY)?,
        iterations: read_u32(envelope, OFF_ITERATIONS)?,
        parallelism: read_u32(envelope, OFF_PARALLELISM)?,
    };
    // Bound attacker-declared cost before Argon2 allocates anything.
    validate_kdf(params, limits)?;

    let salt = &envelope[OFF_SALT..OFF_WRAP_NONCE];
    let wrap_nonce = read_nonce(envelope, OFF_WRAP_NONCE)?;
    let data_nonce = read_nonce(envelope, OFF_DATA_NONCE)?;
    let prefix = &envelope[..PREFIX_LEN];
    let wrapped = &envelope[PREFIX_LEN..HEADER_LEN];
    let header = &envelope[..HEADER_LEN];
    let ciphertext = &envelope[HEADER_LEN..];

    let kek = derive_kek(password, salt, params)?;
    let dek_bytes = Zeroizing::new(
        aead(&kek)
            .decrypt(
                &wrap_nonce,
                Payload {
                    msg: wrapped,
                    aad: prefix,
                },
            )
            .map_err(|_| EnvelopeError::AuthenticationFailed)?,
    );
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    if dek_bytes.len() != DEK_LEN {
        return Err(EnvelopeError::AuthenticationFailed);
    }
    dek.copy_from_slice(&dek_bytes);

    aead(&dek)
        .decrypt(
            &data_nonce,
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| EnvelopeError::AuthenticationFailed)
}

fn aead(key: &[u8; DEK_LEN]) -> XChaCha20Poly1305 {
    // `XChaCha20Poly1305` wipes its internal key copy on drop. Array-based
    // conversion avoids `GenericArray::from_slice`, which is deprecated in
    // recent generic-array 0.14 releases and would fail `clippy -D warnings`.
    XChaCha20Poly1305::new(&Key::from(*key))
}

fn derive_kek(
    password: &[u8],
    salt: &[u8],
    p: KdfParams,
) -> Result<Zeroizing<[u8; DEK_LEN]>, EnvelopeError> {
    let params = Params::new(p.memory_kib, p.iterations, p.parallelism, Some(DEK_LEN))
        .map_err(|_| EnvelopeError::ResourceLimit)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; DEK_LEN]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| EnvelopeError::CryptoFailure)?;
    Ok(out)
}

fn validate_kdf(p: KdfParams, l: Limits) -> Result<(), EnvelopeError> {
    // Argon2 requires at least 8 KiB per lane.
    let minimum_memory = p
        .parallelism
        .checked_mul(8)
        .ok_or(EnvelopeError::ResourceLimit)?;
    if p.memory_kib < minimum_memory
        || p.iterations == 0
        || p.parallelism == 0
        || p.memory_kib > l.max_argon2_memory_kib
        || p.iterations > l.max_argon2_iterations
        || p.parallelism > l.max_argon2_parallelism
    {
        return Err(EnvelopeError::ResourceLimit);
    }
    Ok(())
}

fn read_array<const N: usize>(input: &[u8], at: usize) -> Result<[u8; N], EnvelopeError> {
    at.checked_add(N)
        .and_then(|end| input.get(at..end))
        .and_then(|s| s.try_into().ok())
        .ok_or(EnvelopeError::InvalidEnvelope)
}

fn read_u16(input: &[u8], at: usize) -> Result<u16, EnvelopeError> {
    read_array(input, at).map(u16::from_be_bytes)
}

fn read_u32(input: &[u8], at: usize) -> Result<u32, EnvelopeError> {
    read_array(input, at).map(u32::from_be_bytes)
}

fn read_nonce(input: &[u8], at: usize) -> Result<XNonce, EnvelopeError> {
    read_array::<NONCE_LEN>(input, at).map(XNonce::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const PAYLOAD: &[u8] = b"byte-exact payload";

    /// Deliberately cheap parameters so that exhaustive mutation tests stay
    /// fast. Security of the parameters is irrelevant for these tests.
    const CHEAP: KdfParams = KdfParams {
        memory_kib: 64,
        iterations: 2,
        parallelism: 1,
    };

    fn seeded(params: KdfParams) -> Vec<u8> {
        encrypt_with_rng(
            PAYLOAD,
            PASSWORD,
            params,
            Limits::default(),
            &mut ChaCha20Rng::from_seed([7u8; 32]),
        )
        .unwrap()
    }

    fn open(envelope: &[u8], password: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        decrypt(envelope, password, Limits::default()).map(|p| p.to_vec())
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn round_trip_with_default_parameters() {
        let envelope = seeded(KdfParams::default());
        assert_eq!(envelope.len(), HEADER_LEN + PAYLOAD.len() + TAG_LEN);
        assert_eq!(open(&envelope, PASSWORD).unwrap(), PAYLOAD);
    }

    #[test]
    fn round_trip_through_public_api_and_os_rng() {
        let envelope = encrypt(PAYLOAD, PASSWORD, CHEAP, Limits::default()).unwrap();
        assert_eq!(open(&envelope, PASSWORD).unwrap(), PAYLOAD);
    }

    #[test]
    fn empty_and_binary_payloads_round_trip() {
        let binary: Vec<u8> = (0..=255u8).cycle().take(4099).collect();
        for payload in [&[][..], &[0u8][..], &binary[..]] {
            let envelope = encrypt(payload, PASSWORD, CHEAP, Limits::default()).unwrap();
            assert_eq!(open(&envelope, PASSWORD).unwrap(), payload);
        }
    }

    #[test]
    fn empty_password_is_supported_but_distinct() {
        let envelope = encrypt(PAYLOAD, b"", CHEAP, Limits::default()).unwrap();
        assert_eq!(open(&envelope, b"").unwrap(), PAYLOAD);
        assert_eq!(
            open(&envelope, b"\0"),
            Err(EnvelopeError::AuthenticationFailed)
        );
    }

    #[test]
    fn every_operation_uses_fresh_randomness() {
        let a = encrypt(PAYLOAD, PASSWORD, CHEAP, Limits::default()).unwrap();
        let b = encrypt(PAYLOAD, PASSWORD, CHEAP, Limits::default()).unwrap();
        assert_ne!(a[OFF_SALT..OFF_WRAP_NONCE], b[OFF_SALT..OFF_WRAP_NONCE]);
        assert_ne!(
            a[OFF_WRAP_NONCE..OFF_DATA_NONCE],
            b[OFF_WRAP_NONCE..OFF_DATA_NONCE]
        );
        assert_ne!(a[OFF_DATA_NONCE..PREFIX_LEN], b[OFF_DATA_NONCE..PREFIX_LEN]);
        assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
        // The two nonces inside one envelope are independent draws as well.
        assert_ne!(
            a[OFF_WRAP_NONCE..OFF_DATA_NONCE],
            a[OFF_DATA_NONCE..PREFIX_LEN]
        );
    }

    #[test]
    fn wrong_password_fails_closed() {
        assert_eq!(
            open(&seeded(CHEAP), b"wrong"),
            Err(EnvelopeError::AuthenticationFailed)
        );
    }

    #[test]
    fn every_single_bit_flip_is_rejected() {
        // Strict application limits keep flipped KDF cost bits cheap to test.
        let strict = Limits {
            max_argon2_memory_kib: 1024,
            max_argon2_iterations: 4,
            max_argon2_parallelism: 4,
            ..Limits::default()
        };
        let original = seeded(CHEAP);
        for index in 0..original.len() {
            for bit in 0..8 {
                let mut changed = original.clone();
                changed[index] ^= 1 << bit;
                assert!(
                    decrypt(&changed, PASSWORD, strict).is_err(),
                    "mutation accepted at byte {index}, bit {bit}"
                );
            }
        }
    }

    #[test]
    fn truncation_is_never_accepted() {
        let original = seeded(CHEAP);
        for len in 0..original.len() {
            assert!(open(&original[..len], PASSWORD).is_err(), "length {len}");
        }
    }

    #[test]
    fn appended_bytes_are_rejected() {
        let mut envelope = seeded(CHEAP);
        envelope.push(0);
        assert_eq!(
            open(&envelope, PASSWORD),
            Err(EnvelopeError::AuthenticationFailed)
        );
    }

    #[test]
    fn unknown_version_or_suite_is_not_guessed() {
        for offset in [OFF_VERSION, OFF_SUITE] {
            let mut envelope = seeded(CHEAP);
            envelope[offset + 1] = 2;
            assert_eq!(
                open(&envelope, PASSWORD),
                Err(EnvelopeError::UnsupportedFormat)
            );
        }
    }

    #[test]
    fn wrong_magic_is_invalid() {
        let mut envelope = seeded(CHEAP);
        envelope[0] = b'X';
        assert_eq!(
            open(&envelope, PASSWORD),
            Err(EnvelopeError::InvalidEnvelope)
        );
    }

    #[test]
    fn attacker_controlled_kdf_cost_is_bounded_before_argon2() {
        for (offset, value) in [
            (OFF_MEMORY, u32::MAX),
            (OFF_MEMORY, 0),
            (OFF_ITERATIONS, u32::MAX),
            (OFF_ITERATIONS, 0),
            (OFF_PARALLELISM, u32::MAX),
            (OFF_PARALLELISM, 0),
        ] {
            let mut envelope = seeded(CHEAP);
            envelope[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            assert_eq!(
                open(&envelope, PASSWORD),
                Err(EnvelopeError::ResourceLimit),
                "offset {offset}, value {value}"
            );
        }
    }

    #[test]
    fn oversized_ciphertext_is_rejected_before_argon2() {
        let envelope = seeded(CHEAP);
        let limits = Limits {
            max_ciphertext_bytes: PAYLOAD.len() + TAG_LEN - 1,
            ..Limits::default()
        };
        assert_eq!(
            decrypt(&envelope, PASSWORD, limits).map(|_| ()),
            Err(EnvelopeError::ResourceLimit)
        );
    }

    #[test]
    fn encrypt_enforces_limits() {
        let limits = Limits {
            max_ciphertext_bytes: TAG_LEN + 3,
            ..Limits::default()
        };
        assert!(encrypt(b"abc", PASSWORD, CHEAP, limits).is_ok());
        assert_eq!(
            encrypt(b"abcd", PASSWORD, CHEAP, limits),
            Err(EnvelopeError::ResourceLimit)
        );
        for bad in [
            KdfParams {
                memory_kib: 7,
                ..CHEAP
            },
            KdfParams {
                iterations: 0,
                ..CHEAP
            },
            KdfParams {
                parallelism: 0,
                ..CHEAP
            },
            KdfParams {
                memory_kib: 64,
                parallelism: 9,
                iterations: 1,
            },
            KdfParams {
                iterations: 11,
                ..CHEAP
            },
        ] {
            assert_eq!(
                encrypt(PAYLOAD, PASSWORD, bad, Limits::default()),
                Err(EnvelopeError::ResourceLimit),
                "{bad:?}"
            );
        }
    }

    /// Format regression vector. It was cross checked against an independent
    /// implementation (libsodium XChaCha20 Poly1305 + OpenSSL Argon2id via
    /// `tools/crosscheck.py`). If this test fails, the wire format changed.
    #[test]
    fn known_answer_vector() {
        let expected = hex(KAT_HEX);
        assert_eq!(seeded(CHEAP), expected);
        assert_eq!(open(&expected, PASSWORD).unwrap(), PAYLOAD);
    }

    const KAT_HEX: &str = include_str!("../tests/vectors/v1_cheap.hex");
}
