//! Generated 128 bit secret keys in a human friendly, typo checked text form.
//!
//! Format: 26 Crockford Base32 characters (128 bits plus 2 zero bits) followed
//! by 2 checksum characters (10 bits of BLAKE2b), shown as 7 groups of 4
//! separated by spaces: `7K2Q M9XD ...`. Parsing ignores case, spaces and
//! dashes (keys from the SSS releases used dashes) and accepts the usual
//! confusions (O for 0, I and L for 1).

use std::fmt;

use blake2::{digest::consts::U32, Blake2b, Digest};
use cipheris_core::Zeroizing;
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::StegoError;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const KEY_BYTES: usize = 16;
const DATA_CHARS: usize = 26;
const CHECK_CHARS: usize = 2;
const TOTAL_CHARS: usize = DATA_CHARS + CHECK_CHARS;

/// A randomly generated secret key. Wiped from memory when dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_BYTES]);

impl SecretKey {
    /// Draws a fresh key from the operating system CSPRNG. A failing random
    /// source is reported as [`StegoError::Internal`], never as a panic.
    pub fn generate() -> Result<Self, StegoError> {
        let mut k = Self([0u8; KEY_BYTES]);
        OsRng
            .try_fill_bytes(&mut k.0)
            .map_err(|_| StegoError::Internal)?;
        Ok(k)
    }

    /// Parses the text form. Returns [`StegoError::InvalidKey`] on any
    /// formatting or checksum error.
    pub fn parse(text: &str) -> Result<Self, StegoError> {
        let mut symbols = Vec::with_capacity(TOTAL_CHARS);
        for c in text.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            let c = match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                other => other,
            };
            let v = ALPHABET
                .iter()
                .position(|&a| a as char == c)
                .ok_or(StegoError::InvalidKey)?;
            symbols.push(v as u8);
            if symbols.len() > TOTAL_CHARS {
                return Err(StegoError::InvalidKey);
            }
        }
        if symbols.len() != TOTAL_CHARS {
            return Err(StegoError::InvalidKey);
        }

        // 26 symbols * 5 bits = 130 bits; the last two must be zero.
        let mut acc: u32 = 0;
        let mut nbits = 0;
        let mut out = Vec::with_capacity(KEY_BYTES + 1);
        for &s in &symbols[..DATA_CHARS] {
            acc = (acc << 5) | s as u32;
            nbits += 5;
            if nbits >= 8 {
                nbits -= 8;
                out.push((acc >> nbits) as u8);
                acc &= (1 << nbits) - 1;
            }
        }
        if out.len() != KEY_BYTES || acc != 0 {
            out.zeroize();
            return Err(StegoError::InvalidKey);
        }
        let mut key = [0u8; KEY_BYTES];
        key.copy_from_slice(&out);
        out.zeroize();
        let key = Self(key);
        if key.checksum() != [symbols[DATA_CHARS], symbols[DATA_CHARS + 1]] {
            return Err(StegoError::InvalidKey);
        }
        Ok(key)
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(b: [u8; KEY_BYTES]) -> Self {
        Self(b)
    }

    /// Raw key bytes (used as the Argon2id password and placement secret).
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    fn checksum(&self) -> [u8; CHECK_CHARS] {
        let h = Blake2b::<U32>::new()
            .chain_update(b"SSS/v1/key-checksum")
            .chain_update(self.0)
            .finalize();
        let v = u16::from_be_bytes([h[0], h[1]]) >> 6; // 10 bits
        [(v >> 5) as u8, (v & 31) as u8]
    }

    /// Text form, for example `7K2Q M9XD ...` (7 groups of 4 characters).
    /// The returned string is wiped from memory when dropped.
    pub fn to_display_string(&self) -> Zeroizing<String> {
        let mut symbols = Vec::with_capacity(TOTAL_CHARS);
        let mut acc: u32 = 0;
        let mut nbits = 0;
        for &b in &self.0 {
            acc = (acc << 8) | b as u32;
            nbits += 8;
            while nbits >= 5 {
                nbits -= 5;
                symbols.push(((acc >> nbits) & 31) as u8);
            }
            acc &= (1 << nbits) - 1;
        }
        symbols.push(((acc << (5 - nbits)) & 31) as u8); // 3 bits + 2 zero bits
        symbols.extend_from_slice(&self.checksum());
        debug_assert_eq!(symbols.len(), TOTAL_CHARS);

        let mut s = Zeroizing::new(String::with_capacity(TOTAL_CHARS + 6));
        for (i, sym) in symbols.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                s.push(' ');
            }
            if let Some(c) = ALPHABET.get(usize::from(*sym)) {
                s.push(char::from(*c));
            }
        }
        symbols.zeroize();
        s
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_format() {
        for _ in 0..200 {
            let k = SecretKey::generate().unwrap();
            let s = k.to_display_string();
            assert_eq!(s.len(), 34);
            assert_eq!(s.matches(' ').count(), 6);
            assert!(!s.contains('-'));
            assert_eq!(SecretKey::parse(&s).unwrap(), k);
        }
    }

    #[test]
    fn tolerant_input_including_legacy_dashes() {
        let k = SecretKey([0u8; 16]);
        let s = k.to_display_string();
        assert!(s.starts_with("0000 0000"));
        let sloppy = format!("  {}  ", s.to_lowercase().replace('0', "o"));
        assert_eq!(SecretKey::parse(&sloppy).unwrap(), k);
        let legacy = s.replace(' ', "-");
        assert_eq!(SecretKey::parse(&legacy).unwrap(), k);
        let squashed = s.replace(' ', "");
        assert_eq!(SecretKey::parse(&squashed).unwrap(), k);
    }

    #[test]
    fn typos_are_detected() {
        let k = SecretKey::generate().unwrap();
        let s = k.to_display_string().to_string();
        let mut detected = 0;
        let mut total = 0;
        for (i, c) in s.char_indices() {
            if c == ' ' {
                continue;
            }
            let other = if c == 'X' { 'Y' } else { 'X' };
            let mut t = s.clone();
            t.replace_range(i..i + 1, &other.to_string());
            total += 1;
            if SecretKey::parse(&t).is_err() {
                detected += 1;
            }
        }
        // 10 bit checksum: a single random typo slips through with p of about 1/1024.
        assert!(detected >= total - 1, "{detected}/{total}");
        assert!(SecretKey::parse(&s[..s.len() - 1]).is_err());
        assert!(SecretKey::parse(&format!("{s}0")).is_err());
        assert!(SecretKey::parse("").is_err());
        assert!(SecretKey::parse("hello").is_err());
        assert!(SecretKey::parse("ÄÖÜ ✓").is_err());
    }

    #[test]
    fn keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(SecretKey::generate().unwrap().0));
        }
    }

    #[test]
    fn debug_does_not_leak() {
        assert_eq!(
            format!("{:?}", SecretKey::generate().unwrap()),
            "SecretKey(<redacted>)"
        );
    }
}
