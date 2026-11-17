use super::*;
use crate::carrier::Carrier;

/// Builds a PNG with a smooth gradient plus deterministic noise.
fn make_png(w: u32, h: u32, color: png::ColorType, depth: png::BitDepth) -> Vec<u8> {
    let ch = match color {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Indexed => 1,
    };
    let bytes_per_sample = if depth == png::BitDepth::Sixteen {
        2
    } else {
        1
    };
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let mut data = Vec::new();
    for y in 0..h {
        for x in 0..w {
            for c in 0..ch {
                let base = ((x * 255 / w.max(1)) as u8)
                    .wrapping_add((y * 97 / h.max(1)) as u8)
                    .wrapping_add(c as u8 * 40)
                    .wrapping_add((rng.next_u32() % 9) as u8);
                let v = if color == png::ColorType::Indexed {
                    base % 4
                } else {
                    base
                };
                // Left quarter fully transparent for alpha images.
                let v = if (ch == 2 || ch == 4) && c == ch - 1 {
                    if x < w / 4 {
                        0
                    } else {
                        255
                    }
                } else {
                    v
                };
                data.push(v);
                if bytes_per_sample == 2 {
                    data.push(0x5a);
                }
            }
        }
    }
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(color);
        enc.set_depth(depth);
        if color == png::ColorType::Indexed {
            enc.set_palette(vec![0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255]);
        }
        let mut wr = enc.write_header().unwrap();
        wr.write_image_data(&data).unwrap();
        wr.finish().unwrap();
    }
    out
}

fn rgb(w: u32, h: u32) -> Vec<u8> {
    make_png(w, h, png::ColorType::Rgb, png::BitDepth::Eight)
}

#[test]
fn round_trip_all_supported_png_kinds() {
    use png::{BitDepth::*, ColorType::*};
    for (color, depth) in [
        (Rgb, Eight),
        (Rgba, Eight),
        (Grayscale, Eight),
        (GrayscaleAlpha, Eight),
        (Rgb, Sixteen),
        (Indexed, Eight),
    ] {
        let cover = make_png(120, 90, color, depth);
        let msg = "Meet at the bridge, 7 pm 🌉 (Grüße, ñ, 日本)";
        let hidden = hide_text(&cover, msg).unwrap();
        let out = reveal_text(&hidden.png, &hidden.key.to_display_string()).unwrap();
        assert_eq!(out.as_str(), msg, "{color:?} {depth:?}");
    }
}

#[test]
fn wrong_key_finds_nothing() {
    let hidden = hide_text(&rgb(100, 100), "geheim").unwrap();
    for _ in 0..5 {
        let other = SecretKey::generate().unwrap().to_display_string();
        assert_eq!(reveal_text(&hidden.png, &other), Err(StegoError::NotFound));
    }
    // A clean image with any key: nothing there.
    let key = hidden.key.to_display_string();
    assert_eq!(reveal_text(&rgb(100, 100), &key), Err(StegoError::NotFound));
}

#[test]
fn malformed_key_is_reported_as_such() {
    let hidden = hide_text(&rgb(64, 64), "x").unwrap();
    assert_eq!(reveal_text(&hidden.png, "abc"), Err(StegoError::InvalidKey));
}

#[test]
fn changes_are_minimal_and_alpha_is_untouched() {
    let cover_png = make_png(200, 150, png::ColorType::Rgba, png::BitDepth::Eight);
    let cover = Carrier::decode_png(&cover_png).unwrap();
    let hidden = hide_text(&cover_png, "kleine Nachricht").unwrap();
    let stego = Carrier::decode_png(&hidden.png).unwrap();
    assert_eq!(
        (stego.width(), stego.height(), stego.channels()),
        (200, 150, 4)
    );

    let mut changed = 0;
    for (i, (a, b)) in cover.pixels().iter().zip(stego.pixels()).enumerate() {
        let diff = (*a as i16 - *b as i16).abs();
        assert!(diff <= 1, "pixel value changed by {diff}");
        if diff == 1 {
            changed += 1;
            let px = i / 4;
            assert_ne!(i % 4, 3, "alpha modified");
            assert_ne!(cover.pixels()[px * 4 + 3], 0, "transparent pixel modified");
        }
    }
    // About half of the payload bits already match by chance.
    let bits = (4 + 148 + 2 + "kleine Nachricht".len()) * 8;
    assert!(changed <= bits && changed > bits / 4, "{changed} of {bits}");
    assert!(hidden.embedding_rate() < 0.1);
}

#[test]
fn any_change_to_payload_pixels_is_detected() {
    let cover_png = rgb(80, 80);
    let cover = Carrier::decode_png(&cover_png).unwrap();
    let hidden = hide_text(&cover_png, "unverändert?").unwrap();
    let key = hidden.key.to_display_string();
    let stego = Carrier::decode_png(&hidden.png).unwrap();
    let mut seen = 0;
    for i in (0..stego.pixels().len())
        .filter(|&i| stego.pixels()[i] != cover.pixels()[i])
        .take(25)
    {
        let mut t = stego.clone();
        t.pixels_mut()[i] ^= 1;
        assert_eq!(
            reveal_text(&t.encode_png().unwrap(), &key),
            Err(StegoError::NotFound)
        );
        seen += 1;
    }
    assert_eq!(seen, 25);
}

#[test]
fn every_hide_uses_a_new_key_and_layout() {
    let cover = rgb(100, 100);
    let a = hide_text(&cover, "gleich").unwrap();
    let b = hide_text(&cover, "gleich").unwrap();
    assert_ne!(a.key, b.key);
    assert_ne!(a.png, b.png);
    assert_eq!(
        reveal_text(&a.png, &b.key.to_display_string()),
        Err(StegoError::NotFound)
    );
}

#[test]
fn capacity_limits_are_enforced() {
    let cover = rgb(40, 40); // 4800 slots → 1200 bits → 150 bytes stream
    let cap = capacity(&cover).unwrap();
    assert_eq!(cap.slots, 4800);
    assert_eq!(cap.max_message_bytes, 0);
    assert!(matches!(
        hide_text(&cover, "a"),
        Err(StegoError::MessageTooLong { max_bytes: 0 })
    ));

    let cover = rgb(100, 100);
    let cap = capacity(&cover).unwrap();
    assert_eq!(cap.max_message_bytes, 30_000 / 4 / 8 - 4 - 148 - 2);
    let fits = "x".repeat(cap.max_message_bytes);
    let hidden = hide_text(&cover, &fits).unwrap();
    assert!(hidden.embedding_rate() <= MAX_EMBEDDING_RATE);
    assert_eq!(
        reveal_text(&hidden.png, &hidden.key.to_display_string())
            .unwrap()
            .as_str(),
        fits
    );
    assert!(matches!(
        hide_text(&cover, &format!("{fits}x")),
        Err(StegoError::MessageTooLong { .. })
    ));
    assert!(matches!(
        hide_text(&cover, ""),
        Err(StegoError::EmptyMessage)
    ));
}

#[test]
fn large_images_cap_message_size() {
    let cap = capacity(&rgb(1200, 1000)).unwrap();
    assert_eq!(cap.max_message_bytes, MAX_MESSAGE_BYTES);
}

#[test]
fn non_png_input_is_rejected() {
    assert_eq!(
        capacity(b"GIF89a....").unwrap_err(),
        StegoError::UnsupportedImage
    );
    let mut truncated = rgb(50, 50);
    truncated.truncate(truncated.len() / 2);
    assert!(capacity(&truncated).is_err());
}

#[test]
fn output_has_no_ancillary_chunks() {
    let hidden = hide_text(&rgb(60, 60), "meta").unwrap();
    let mut pos = 8;
    let mut kinds = Vec::new();
    while pos + 8 <= hidden.png.len() {
        let len = u32::from_be_bytes(hidden.png[pos..pos + 4].try_into().unwrap()) as usize;
        kinds.push(String::from_utf8_lossy(&hidden.png[pos + 4..pos + 8]).to_string());
        pos += 12 + len;
    }
    kinds.dedup();
    assert_eq!(kinds, ["IHDR", "IDAT", "IEND"]);
}

#[test]
fn opaque_rgba_is_stored_as_rgb() {
    let mut data = Vec::new();
    for i in 0..(64 * 64) {
        data.extend_from_slice(&[(i % 251) as u8, (i % 13) as u8 * 9, 77, 255]);
    }
    let mut cover = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut cover, 64, 64);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut wr = enc.write_header().unwrap();
        wr.write_image_data(&data).unwrap();
        wr.finish().unwrap();
    }
    let hidden = hide_text(&cover, "opak").unwrap();
    let stego = Carrier::decode_png(&hidden.png).unwrap();
    assert_eq!(stego.channels(), 3);
    assert_eq!(hidden.png[25], 2, "IHDR colour type must be RGB");
    assert_eq!(
        reveal_text(&hidden.png, &hidden.key.to_display_string())
            .unwrap()
            .as_str(),
        "opak"
    );
}

/// Images and keys made by the SSS releases (before the rename) must keep
/// working. The fixture was produced by SSS 0.1.0 and its key uses dashes.
#[test]
fn legacy_sss_image_still_opens() {
    let png = include_bytes!("../tests/fixtures/sss_v1.png");
    let key = include_str!("../tests/fixtures/sss_v1.key");
    assert!(key.contains('-'));
    let text = reveal_text(png, key).unwrap();
    assert_eq!(text.as_str(), "Legacy SSS message: Grüße aus 2026 🌉");
    let spaced = key.replace('-', " ");
    assert_eq!(reveal_text(png, &spaced).unwrap().as_str(), text.as_str());
}

fn seeded_keys(n: usize) -> Vec<SecretKey> {
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    (0..n)
        .map(|_| {
            let mut b = [0u8; 16];
            rng.fill_bytes(&mut b);
            SecretKey::from_bytes(b)
        })
        .collect()
}

/// The placement is a permutation: no slot is ever written twice.
#[test]
fn placement_never_repeats_a_slot() {
    let carrier = Carrier::decode_png(&rgb(40, 50)).unwrap();
    let key = &seeded_keys(1)[0];
    let mut p = placement::Placement::new(&carrier, key);
    let _ = p.mask();
    let n = p.slots();
    let mut seen = vec![false; n as usize];
    for _ in 0..n {
        let k = p.next().unwrap() as usize;
        assert!(!seen[k], "slot {k} returned twice");
        seen[k] = true;
    }
    assert!(seen.iter().all(|s| *s));
    assert_eq!(p.next(), None);
}

/// Positions are spread evenly over the image (chi square test, 30 bands,
/// 29 degrees of freedom; 58.3 is the critical value at p = 0.001).
/// Deterministic keys make the test reproducible.
#[test]
fn placement_is_uniform() {
    let carrier = Carrier::decode_png(&rgb(100, 100)).unwrap();
    let bands = 30usize;
    let mut counts = vec![0u64; bands];
    let keys = seeded_keys(200);
    for key in &keys {
        let mut p = placement::Placement::new(&carrier, key);
        let _ = p.mask();
        for _ in 0..300 {
            let k = p.next().unwrap();
            counts[(k as usize) * bands / 30_000] += 1;
        }
    }
    let expected = (keys.len() * 300) as f64 / bands as f64;
    let chi2: f64 = counts
        .iter()
        .map(|&c| (c as f64 - expected).powi(2) / expected)
        .sum();
    assert!(chi2 < 58.3, "chi square {chi2:.1}, counts {counts:?}");
}

/// Different keys for the same image give unrelated positions.
#[test]
fn different_keys_choose_different_positions() {
    let carrier = Carrier::decode_png(&rgb(100, 100)).unwrap();
    let keys = seeded_keys(2);
    let take = |key: &SecretKey| {
        let mut p = placement::Placement::new(&carrier, key);
        let _ = p.mask();
        (0..2000)
            .map(|_| p.next().unwrap())
            .collect::<std::collections::HashSet<_>>()
    };
    let (a, b) = (take(&keys[0]), take(&keys[1]));
    // Two random 2000 element subsets of 30000 overlap by about 133.
    let overlap = a.intersection(&b).count();
    assert!(overlap < 250, "overlap {overlap}");
}

/// Image quality stays very high: PSNR above 60 dB at a typical payload.
#[test]
fn psnr_stays_high() {
    let cover_png = rgb(400, 300);
    let cover = Carrier::decode_png(&cover_png).unwrap();
    let hidden = hide_text(&cover_png, &"x".repeat(1000)).unwrap();
    let stego = Carrier::decode_png(&hidden.png).unwrap();
    let mse: f64 = cover
        .pixels()
        .iter()
        .zip(stego.pixels())
        .map(|(a, b)| (f64::from(*a) - f64::from(*b)).powi(2))
        .sum::<f64>()
        / cover.pixels().len() as f64;
    let psnr = 10.0 * (255.0f64 * 255.0 / mse).log10();
    assert!(psnr > 60.0, "PSNR {psnr:.1} dB");
}

/// Multibyte UTF 8 right at the capacity limit.
#[test]
fn unicode_at_the_limit() {
    let cover = rgb(100, 100);
    let max = capacity(&cover).unwrap().max_message_bytes;
    let msg: String = "ü".repeat(max / 2);
    let hidden = hide_text(&cover, &msg).unwrap();
    assert_eq!(
        reveal_text(&hidden.png, &hidden.key.to_display_string())
            .unwrap()
            .as_str(),
        msg
    );
    let over: String = "€".repeat(max / 3 + 1);
    assert!(matches!(
        hide_text(&cover, &over),
        Err(StegoError::MessageTooLong { .. })
    ));
}

/// Random and corrupted PNG input never panics.
#[test]
fn corrupted_images_never_panic() {
    let hidden = hide_text(&rgb(48, 48), "fuzz").unwrap();
    let key = hidden.key.to_display_string();
    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    for round in 0..1500u32 {
        let mut input = hidden.png.clone();
        match round % 3 {
            0 => {
                let i = (rng.next_u32() as usize) % input.len();
                input[i] ^= 1 << (rng.next_u32() % 8);
            }
            1 => input.truncate((rng.next_u32() as usize) % input.len()),
            _ => {
                let len = (rng.next_u32() % 512) as usize;
                input = b"\x89PNG\r\n\x1a\n".to_vec();
                input.extend((0..len).map(|_| rng.next_u32() as u8));
            }
        }
        let _ = capacity(&input);
        let _ = reveal_text(&input, &key);
    }
}

#[test]
fn oversized_file_is_rejected_before_decoding() {
    let mut big = b"\x89PNG\r\n\x1a\n".to_vec();
    big.resize(MAX_PNG_BYTES + 1, 0);
    assert_eq!(capacity(&big).unwrap_err(), StegoError::ImageTooLarge);
}

#[test]
fn messages_contain_no_dashes_or_secrets() {
    for e in [
        StegoError::UnsupportedImage,
        StegoError::ImageTooLarge,
        StegoError::EmptyMessage,
        StegoError::MessageTooLong { max_bytes: 10 },
        StegoError::InvalidKey,
        StegoError::NotFound,
        StegoError::Internal,
    ] {
        let m = e.to_string();
        assert!(
            !m.contains('\u{2013}') && !m.contains('\u{2014}') && !m.contains(" - "),
            "{m}"
        );
    }
}
