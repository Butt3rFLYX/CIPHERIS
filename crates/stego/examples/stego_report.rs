//! Measures how much hiding changes an image, and compares CIPHERIS (LSB
//! matching at key dependent positions) with plain LSB replacement as a
//! control. Run it on your own photos:
//!
//!   cargo run --release -p cipheris_stego --example stego_report -- photo.png
//!
//! Metrics, all on the R, G and B values:
//! * PSNR in dB (higher means closer to the original).
//! * SSIM on luminance, mean over 8 by 8 windows with stride 4 (1.0 means
//!   structurally identical).
//! * Changed values in percent.
//! * Pair asymmetry: sum of |n(2k) - n(2k+1)| over the sum of all counts.
//!   LSB replacement pulls each pair of values towards equal counts, which is
//!   what the classic chi square attack (Westfeld and Pfitzmann) detects. LSB
//!   matching should leave this close to the original.
//!
//! This is a sanity check against one classic detector, not a steganalysis
//! study. Modern detectors (rich models, neural networks) are not covered.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;

use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};

fn rgb_values(png_bytes: &[u8]) -> Vec<u8> {
    let mut dec = png::Decoder::new(Cursor::new(png_bytes));
    dec.set_transformations(png::Transformations::normalize_to_color8());
    let mut r = dec.read_info().unwrap();
    let mut buf = vec![0; r.output_buffer_size()];
    let info = r.next_frame(&mut buf).unwrap();
    buf.truncate(info.buffer_size());
    match info.color_type {
        png::ColorType::Rgb => buf,
        png::ColorType::Rgba => buf.chunks(4).flat_map(|p| [p[0], p[1], p[2]]).collect(),
        png::ColorType::Grayscale => buf.iter().flat_map(|&g| [g, g, g]).collect(),
        png::ColorType::GrayscaleAlpha => buf.chunks(2).flat_map(|p| [p[0], p[0], p[0]]).collect(),
        png::ColorType::Indexed => panic!("palette images are normalized by the decoder"),
    }
}

fn psnr(a: &[u8], b: &[u8]) -> f64 {
    let mse: f64 = a
        .iter()
        .zip(b)
        .map(|(x, y)| (f64::from(*x) - f64::from(*y)).powi(2))
        .sum::<f64>()
        / a.len() as f64;
    if mse == 0.0 {
        f64::INFINITY
    } else {
        10.0 * (255.0f64 * 255.0 / mse).log10()
    }
}

/// Mean SSIM (Wang et al. 2004) on luminance over 8 by 8 windows, stride 4.
fn ssim(a: &[u8], b: &[u8], w: usize, h: usize) -> f64 {
    let luma = |v: &[u8]| -> Vec<f64> {
        v.chunks(3)
            .map(|p| 0.299 * f64::from(p[0]) + 0.587 * f64::from(p[1]) + 0.114 * f64::from(p[2]))
            .collect()
    };
    let (ya, yb) = (luma(a), luma(b));
    let (c1, c2) = ((0.01f64 * 255.0).powi(2), (0.03f64 * 255.0).powi(2));
    let (mut sum, mut count) = (0.0, 0u64);
    let mut y = 0;
    while y + 8 <= h {
        let mut x = 0;
        while x + 8 <= w {
            let (mut ma, mut mb) = (0.0, 0.0);
            for j in 0..8 {
                for i in 0..8 {
                    ma += ya[(y + j) * w + x + i];
                    mb += yb[(y + j) * w + x + i];
                }
            }
            ma /= 64.0;
            mb /= 64.0;
            let (mut va, mut vb, mut cov) = (0.0, 0.0, 0.0);
            for j in 0..8 {
                for i in 0..8 {
                    let da = ya[(y + j) * w + x + i] - ma;
                    let db = yb[(y + j) * w + x + i] - mb;
                    va += da * da;
                    vb += db * db;
                    cov += da * db;
                }
            }
            va /= 63.0;
            vb /= 63.0;
            cov /= 63.0;
            sum += ((2.0 * ma * mb + c1) * (2.0 * cov + c2))
                / ((ma * ma + mb * mb + c1) * (va + vb + c2));
            count += 1;
            x += 4;
        }
        y += 4;
    }
    sum / count.max(1) as f64
}

fn changed(a: &[u8], b: &[u8]) -> f64 {
    a.iter().zip(b).filter(|(x, y)| x != y).count() as f64 / a.len() as f64 * 100.0
}

fn pair_asymmetry(v: &[u8]) -> f64 {
    let mut h = [0u64; 256];
    for &x in v {
        h[x as usize] += 1;
    }
    let diff: u64 = (0..128).map(|k| h[2 * k].abs_diff(h[2 * k + 1])).sum();
    diff as f64 / v.len() as f64
}

/// Control: overwrite the lowest bit of `bits` random values with random bits.
fn lsb_replacement(cover: &[u8], bits: usize, rng: &mut ChaCha20Rng) -> Vec<u8> {
    let mut out = cover.to_vec();
    let mut idx: Vec<usize> = (0..out.len()).collect();
    for i in 0..bits.min(out.len()) {
        let j = i + (rng.next_u64() as usize) % (out.len() - i);
        idx.swap(i, j);
        let k = idx[i];
        out[k] = (out[k] & !1) | (rng.next_u32() as u8 & 1);
    }
    out
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: stego_report <image.png>");
    let cover_png = std::fs::read(&path).unwrap();
    let cover = rgb_values(&cover_png);
    let cap = cipheris_stego::capacity(&cover_png).unwrap();
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    println!(
        "# {path}: {} × {} px, {} slots\n",
        cap.width, cap.height, cap.slots
    );
    let (w, h) = (cap.width as usize, cap.height as usize);
    println!("| rate | method | PSNR dB | SSIM | changed % | pair asymmetry |");
    println!("| --- | --- | --- | --- | --- | --- |");
    println!(
        "| 0 | original | inf | 1.000000 | 0 | {:.4} |",
        pair_asymmetry(&cover)
    );
    for target in [0.005, 0.02, 0.05, 0.10, 0.25] {
        let bits = (cap.slots as f64 * target) as usize;
        let len = (bits / 8)
            .saturating_sub(4 + 150)
            .min(cap.max_message_bytes);
        if len == 0 {
            continue;
        }
        let msg: String = (0..len)
            .map(|i| char::from(b'a' + (i % 26) as u8))
            .collect();
        let hidden = cipheris_stego::hide_text(&cover_png, &msg).unwrap();
        let stego = rgb_values(&hidden.png);
        let rate = hidden.embedding_rate();
        println!(
            "| {:.1} % | CIPHERIS (LSB matching) | {:.1} | {:.6} | {:.2} | {:.4} |",
            rate * 100.0,
            psnr(&cover, &stego),
            ssim(&cover, &stego, w, h),
            changed(&cover, &stego),
            pair_asymmetry(&stego)
        );
        let control = lsb_replacement(&cover, hidden.bits as usize, &mut rng);
        println!(
            "| {:.1} % | control: LSB replacement | {:.1} | {:.6} | {:.2} | {:.4} |",
            rate * 100.0,
            psnr(&cover, &control),
            ssim(&cover, &control, w, h),
            changed(&cover, &control),
            pair_asymmetry(&control)
        );
    }
}
