//! Key and image dependent sequence of distinct slot indices.
//!
//! Part of the v1 file format: the seed derivation, the order of draws from
//! the ChaCha20 stream (4 mask bytes first, then positions) and the uniform
//! sampling method must never change.

use std::collections::HashMap;

use blake2::{digest::consts::U32, Blake2b, Digest};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};

use cipheris_core::Zeroizing;

use crate::{carrier::Carrier, key::SecretKey, LEN_PREFIX};

/// Domain label that separates the placement secret from every other use of
/// the key (the envelope derives its key with Argon2id and a random salt).
const PLAN_LABEL: &[u8] = b"SSS/v1/embed-plan";

pub(crate) struct Placement {
    rng: ChaCha20Rng,
    slots: u64,
    step: u64,
    swaps: HashMap<u64, u64>,
}

impl Placement {
    pub(crate) fn new(c: &Carrier, key: &SecretKey) -> Self {
        let seed: [u8; 32] = Blake2b::<U32>::new()
            .chain_update(PLAN_LABEL)
            .chain_update(key.as_bytes())
            .chain_update(c.width().to_be_bytes())
            .chain_update(c.height().to_be_bytes())
            .chain_update((c.channels() as u32).to_be_bytes())
            .finalize()
            .into();
        let seed = Zeroizing::new(seed);
        Self {
            rng: ChaCha20Rng::from_seed(*seed),
            slots: c.slot_count(),
            step: 0,
            swaps: HashMap::new(),
        }
    }

    pub(crate) fn slots(&self) -> u64 {
        self.slots
    }

    /// The 4 byte mask for the length prefix. Must be drawn before any position.
    pub(crate) fn mask(&mut self) -> [u8; LEN_PREFIX] {
        let mut m = [0u8; LEN_PREFIX];
        self.rng.fill_bytes(&mut m);
        m
    }

    /// Next position of a lazily evaluated Fisher Yates shuffle of
    /// `0..slots`. Memory is proportional to the number of steps taken, and
    /// no position is ever returned twice. `None` once all slots are used.
    pub(crate) fn next(&mut self) -> Option<u64> {
        let i = self.step;
        let remaining = self.slots.checked_sub(i).filter(|r| *r > 0)?;
        let j = i + self.below(remaining);
        let at_j = *self.swaps.get(&j).unwrap_or(&j);
        let at_i = *self.swaps.get(&i).unwrap_or(&i);
        self.swaps.insert(j, at_i);
        self.swaps.remove(&i);
        self.step += 1;
        Some(at_j)
    }

    /// Unbiased integer in `0..n` for `n > 0` (Lemire's method).
    fn below(&mut self, n: u64) -> u64 {
        let threshold = n.wrapping_neg() % n;
        loop {
            let m = u128::from(self.rng.next_u64()) * u128::from(n);
            if (m as u64) >= threshold {
                return (m >> 64) as u64;
            }
        }
    }
}
