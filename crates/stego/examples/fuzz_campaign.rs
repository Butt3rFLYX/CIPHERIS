//! Time boxed mutation fuzzing of every parser in core and stego, without a
//! nightly compiler. Not coverage guided: it mutates valid inputs with
//! structure aware operations (bit flips, byte overwrites, insertions,
//! deletions, truncation, chunk duplication, length field edits, splicing).
//!
//!   cargo run --release -p cipheris_stego --example fuzz_campaign -- 60
//!
//! The argument is the number of seconds per target. Release builds keep
//! overflow checks and abort on panic, so any bug ends the process with a
//! non zero exit code and the seed and target are printed beforehand.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, Instant};

use cipheris_core::{decrypt, encrypt, KdfParams, Limits};
use cipheris_stego::{capacity, hide_text, reveal_text, SecretKey};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};

fn mutate(rng: &mut ChaCha20Rng, input: &[u8], pool: &[Vec<u8>]) -> Vec<u8> {
    let mut v = input.to_vec();
    let rounds = 1 + rng.next_u32() % 6;
    for _ in 0..rounds {
        let len = v.len().max(1);
        let at = (rng.next_u32() as usize) % len;
        match rng.next_u32() % 10 {
            0 | 1 => {
                if let Some(b) = v.get_mut(at) {
                    *b ^= 1 << (rng.next_u32() % 8);
                }
            }
            2 => {
                if let Some(b) = v.get_mut(at) {
                    *b = [0u8, 0xff, 0x7f, 0x80, 1][(rng.next_u32() % 5) as usize];
                }
            }
            3 => {
                let n = 1 + (rng.next_u32() % 16) as usize;
                let bytes: Vec<u8> = (0..n).map(|_| rng.next_u32() as u8).collect();
                let at = at.min(v.len());
                v.splice(at..at, bytes);
            }
            4 => {
                let n = (1 + (rng.next_u32() % 64) as usize).min(v.len().saturating_sub(at));
                v.drain(at..at + n);
            }
            5 => v.truncate(at),
            6 => {
                // Duplicate a slice (repeats PNG chunks or header fields).
                let n = (1 + (rng.next_u32() % 256) as usize).min(v.len().saturating_sub(at));
                let copy = v[at..at + n].to_vec();
                let to = (rng.next_u32() as usize) % (v.len() + 1);
                v.splice(to..to, copy);
            }
            7 => {
                // Big endian length fields: write an extreme u32.
                if at + 4 <= v.len() {
                    let x = [0u32, 1, 0x7fff_ffff, 0xffff_ffff, 13, 132, 148]
                        [(rng.next_u32() % 7) as usize];
                    v[at..at + 4].copy_from_slice(&x.to_be_bytes());
                }
            }
            8 => {
                // Splice the tail of another valid input.
                let other = &pool[(rng.next_u32() as usize) % pool.len()];
                let from = (rng.next_u32() as usize) % other.len().max(1);
                v.truncate(at);
                v.extend_from_slice(&other[from.min(other.len())..]);
            }
            _ => {
                let n = (rng.next_u32() % 8) as usize;
                v.extend((0..n).map(|_| rng.next_u32() as u8));
            }
        }
    }
    v
}

fn png(w: u32, h: u32, color: png::ColorType, seed: u8) -> Vec<u8> {
    let ch = match color {
        png::ColorType::Rgba => 4,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Grayscale => 1,
        _ => 3,
    };
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let data: Vec<u8> = (0..w * h * ch).map(|_| rng.next_u32() as u8).collect();
    let mut out = Vec::new();
    let mut enc = png::Encoder::new(&mut out, w, h);
    enc.set_color(color);
    enc.set_depth(png::BitDepth::Eight);
    let mut wr = enc.write_header().unwrap();
    wr.write_image_data(&data).unwrap();
    wr.finish().unwrap();
    out
}

fn run(name: &str, secs: u64, seed: u8, mut step: impl FnMut(&mut ChaCha20Rng)) {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let start = Instant::now();
    let mut n = 0u64;
    eprintln!("target {name}: seed {seed}");
    while start.elapsed() < Duration::from_secs(secs) {
        step(&mut rng);
        n += 1;
    }
    println!("{name:<12} {n:>10} inputs in {secs} s, no crash");
}

fn main() {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let strict = Limits {
        max_ciphertext_bytes: 1 << 16,
        max_argon2_memory_kib: 64,
        max_argon2_iterations: 1,
        max_argon2_parallelism: 1,
    };
    let cheap = KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    // 1. Envelope parser and AEAD.
    let envelopes: Vec<Vec<u8>> = [&b""[..], b"x", &[7u8; 300]]
        .iter()
        .map(|p| encrypt(p, b"pw", cheap, strict).unwrap())
        .collect();
    run("envelope", secs, 1, |rng| {
        let base = &envelopes[(rng.next_u32() as usize) % envelopes.len()];
        let input = mutate(rng, base, &envelopes);
        if let Ok(pt) = decrypt(&input, b"pw", strict) {
            // Only an unmodified envelope may decrypt.
            assert!(
                envelopes.contains(&input),
                "mutated envelope decrypted to {} bytes",
                pt.len()
            );
        }
    });

    // 2. PNG decoder (capacity runs the full decode).
    let pngs = vec![
        png(17, 9, png::ColorType::Rgb, 2),
        png(8, 8, png::ColorType::Rgba, 3),
        png(12, 5, png::ColorType::Grayscale, 4),
        png(6, 11, png::ColorType::GrayscaleAlpha, 5),
    ];
    run("png", secs, 2, |rng| {
        let base = &pngs[(rng.next_u32() as usize) % pngs.len()];
        let _ = capacity(&mutate(rng, base, &pngs));
    });

    // 3. Extraction from mutated stego images with the right key.
    let hidden = hide_text(&png(64, 64, png::ColorType::Rgb, 6), "fuzz target").unwrap();
    let key = hidden.key.to_display_string();
    let stego = vec![hidden.png.clone()];
    run("reveal", secs, 3, |rng| {
        let input = mutate(rng, &stego[0], &stego);
        if let Ok(text) = reveal_text(&input, &key) {
            assert_eq!(text.as_str(), "fuzz target", "wrong text accepted");
        }
    });

    // 4. Key parser.
    let good = SecretKey::generate()
        .unwrap()
        .to_display_string()
        .to_string();
    let keys = vec![
        good.clone().into_bytes(),
        good.replace(' ', "-").into_bytes(),
    ];
    run("key", secs, 4, |rng| {
        let pick = (rng.next_u32() as usize) % 2;
        let input = mutate(rng, &keys[pick], &keys);
        if let Ok(s) = std::str::from_utf8(&input) {
            let _ = SecretKey::parse(s);
        }
    });
}
