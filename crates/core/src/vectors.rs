//! Official test vectors for the primitives this crate relies on. They pin the
//! behaviour of the selected library versions; each value was also confirmed
//! against OpenSSL (Argon2id) and libsodium (XChaCha20 Poly1305) before it
//! was committed.

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 9106 §5.3: Argon2id, m = 32 KiB, t = 3, p = 4, with secret and associated data.
#[test]
fn argon2id_rfc9106_vector() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&[4u8; 12]).unwrap())
        .build()
        .unwrap();
    let argon =
        Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    argon
        .hash_password_into(&[1u8; 32], &[2u8; 16], &mut out)
        .unwrap();
    assert_eq!(
        out.to_vec(),
        hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
}

/// draft-irtf-cfrg-xchacha-03 §A.3.1: XChaCha20 Poly1305 AEAD.
#[test]
fn xchacha20poly1305_draft_vector() {
    let key: Vec<u8> = (0x80..0xa0).collect();
    let nonce: Vec<u8> = (0x40..0x58).collect();
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = hex(concat!(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
        "21f9664c97637da9768812f615c68b13b52e",
        "c0875924c1c7987947deafd8780acf49"
    ));
    let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce = XNonce::from(<[u8; 24]>::try_from(nonce.as_slice()).unwrap());
    let ct = cipher
        .encrypt(&nonce, Payload { msg: pt, aad: &aad })
        .unwrap();
    assert_eq!(ct, expected);
    let back = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(back, pt);
    let mut tampered = ct.clone();
    tampered[0] ^= 1;
    assert!(cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &tampered,
                aad: &aad
            }
        )
        .is_err());
}

/// RFC 7693 Appendix A (BLAKE2b-512 of "abc") and the 256 bit variant used by
/// the embedding layer, as produced by Python's hashlib.
#[test]
fn blake2b_vectors() {
    use blake2::{digest::consts::U32, Blake2b, Blake2b512, Digest};
    assert_eq!(
        Blake2b512::digest(b"abc").to_vec(),
        hex("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
    );
    assert_eq!(
        Blake2b::<U32>::digest(b"abc").to_vec(),
        hex("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319")
    );
}

/// Random and mutated inputs must never panic and never yield plaintext.
#[test]
fn arbitrary_input_never_panics() {
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha20Rng,
    };
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let strict = crate::Limits {
        max_argon2_memory_kib: 256,
        max_argon2_iterations: 2,
        max_argon2_parallelism: 2,
        ..crate::Limits::default()
    };
    let cheap = crate::KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };
    let valid = crate::encrypt(b"fuzz", b"pw", cheap, strict).unwrap();
    for round in 0..4000u32 {
        let len = (rng.next_u32() % 300) as usize;
        let mut input = vec![0u8; len];
        rng.fill_bytes(&mut input);
        if round % 2 == 0 {
            // Mutate a valid envelope: random flips, truncation or extension.
            input = valid.clone();
            let flips = 1 + rng.next_u32() % 4;
            for _ in 0..flips {
                let i = (rng.next_u32() as usize) % input.len();
                input[i] ^= 1 << (rng.next_u32() % 8);
            }
            if round % 6 == 0 {
                input.truncate((rng.next_u32() as usize) % input.len());
            }
        }
        if input == valid {
            continue;
        }
        assert!(
            crate::decrypt(&input, b"pw", strict).is_err(),
            "round {round}"
        );
    }
}
