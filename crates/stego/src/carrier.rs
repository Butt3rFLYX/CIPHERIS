//! PNG decoding into a normalized 8 bit RGB or RGBA pixel model, and
//! re encoding.
//!
//! Output never copies ancillary chunks: EXIF, XMP, text, time stamps, ICC
//! profiles and thumbnails of the input are dropped.

use std::io::Cursor;

use crate::StegoError;

/// Maximum accepted image size in pixels.
pub const MAX_PIXELS: u64 = 40_000_000;
/// Maximum accepted PNG file size in bytes, checked before decoding.
pub const MAX_PNG_BYTES: usize = 100 * 1024 * 1024;

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/// A decoded carrier image: 8 bits per channel, 3 (RGB) or 4 (RGBA) channels.
#[derive(Clone, PartialEq, Eq)]
pub struct Carrier {
    width: u32,
    height: u32,
    channels: usize,
    pixels: Vec<u8>,
}

impl Carrier {
    /// Image width in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Image height in pixels.
    pub fn height(&self) -> u32 {
        self.height
    }

    pub(crate) fn channels(&self) -> usize {
        self.channels
    }

    pub(crate) fn pixel(&self, idx: usize) -> Option<u8> {
        self.pixels.get(idx).copied()
    }

    pub(crate) fn pixel_mut(&mut self, idx: usize) -> Option<&mut u8> {
        self.pixels.get_mut(idx)
    }

    #[cfg(test)]
    pub(crate) fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    #[cfg(test)]
    pub(crate) fn pixels_mut(&mut self) -> &mut Vec<u8> {
        &mut self.pixels
    }

    /// Decodes a PNG file. Palette, grayscale and 16 bit images are
    /// normalized to 8 bit RGB or RGBA. Truncated files, bad checksums and
    /// anything beyond the size limits are rejected before or during decoding,
    /// never by a panic.
    pub fn decode_png(bytes: &[u8]) -> Result<Self, StegoError> {
        if bytes.len() > MAX_PNG_BYTES {
            return Err(StegoError::ImageTooLarge);
        }
        if !bytes.starts_with(PNG_SIGNATURE) {
            return Err(StegoError::UnsupportedImage);
        }
        let limits = png::Limits {
            bytes: usize::try_from(MAX_PIXELS * 8).unwrap_or(usize::MAX),
        };
        let mut decoder = png::Decoder::new_with_limits(Cursor::new(bytes), limits);
        decoder.set_transformations(png::Transformations::normalize_to_color8());
        let mut reader = decoder.read_info().map_err(map_png_err)?;
        let (w, h) = {
            let info = reader.info();
            (info.width, info.height)
        };
        if w == 0 || h == 0 {
            return Err(StegoError::UnsupportedImage);
        }
        // Checked before the pixel buffer is allocated.
        if u64::from(w) * u64::from(h) > MAX_PIXELS {
            return Err(StegoError::ImageTooLarge);
        }
        let mut buf = vec![0u8; reader.output_buffer_size()];
        let frame = reader.next_frame(&mut buf).map_err(map_png_err)?;
        // Reads the remaining chunks up to IEND: catches truncated files.
        reader.finish().map_err(map_png_err)?;
        if frame.bit_depth != png::BitDepth::Eight {
            return Err(StegoError::UnsupportedImage);
        }
        let (w, h) = (frame.width, frame.height);
        let width = w as usize;
        let line = frame.line_size;

        let src_ch: usize = match frame.color_type {
            png::ColorType::Grayscale => 1,
            png::ColorType::GrayscaleAlpha => 2,
            png::ColorType::Rgb => 3,
            png::ColorType::Rgba => 4,
            png::ColorType::Indexed => return Err(StegoError::UnsupportedImage),
        };
        let channels = if matches!(src_ch, 2 | 4) { 4 } else { 3 };
        let n = width
            .checked_mul(h as usize)
            .and_then(|n| n.checked_mul(channels))
            .ok_or(StegoError::ImageTooLarge)?;
        let row_bytes = width.checked_mul(src_ch).ok_or(StegoError::ImageTooLarge)?;
        let mut pixels = Vec::with_capacity(n);
        for y in 0..h as usize {
            let start = y.checked_mul(line).ok_or(StegoError::UnsupportedImage)?;
            let row = start
                .checked_add(row_bytes)
                .and_then(|end| buf.get(start..end))
                .ok_or(StegoError::UnsupportedImage)?;
            match src_ch {
                1 => row
                    .iter()
                    .for_each(|&g| pixels.extend_from_slice(&[g, g, g])),
                2 => row.chunks_exact(2).for_each(|p| {
                    if let [g, a] = p {
                        pixels.extend_from_slice(&[*g, *g, *g, *a]);
                    }
                }),
                _ => pixels.extend_from_slice(row),
            }
        }
        // Fully opaque RGBA (typical for photos converted in the browser) is
        // stored as RGB: smaller files and no pointless alpha channel.
        let opaque = channels == 4 && pixels.chunks_exact(4).all(|p| p.get(3) == Some(&255));
        let (channels, pixels) = if opaque {
            let rgb = pixels
                .chunks_exact(4)
                .flat_map(|p| p.iter().take(3).copied())
                .collect();
            (3, rgb)
        } else {
            (channels, pixels)
        };
        Ok(Self {
            width: w,
            height: h,
            channels,
            pixels,
        })
    }

    /// Encodes as an 8 bit RGB or RGBA PNG without any ancillary metadata.
    pub fn encode_png(&self) -> Result<Vec<u8>, StegoError> {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, self.width, self.height);
            enc.set_color(if self.channels == 4 {
                png::ColorType::Rgba
            } else {
                png::ColorType::Rgb
            });
            enc.set_depth(png::BitDepth::Eight);
            enc.set_compression(png::Compression::Fast);
            let mut writer = enc.write_header().map_err(|_| StegoError::Internal)?;
            writer
                .write_image_data(&self.pixels)
                .map_err(|_| StegoError::Internal)?;
            writer.finish().map_err(|_| StegoError::Internal)?;
        }
        Ok(out)
    }

    /// Number of values that may carry payload bits: the R, G and B channel
    /// of every pixel that is not fully transparent. Alpha is never modified,
    /// and fully transparent pixels are skipped because many tools rewrite
    /// their colour values.
    pub(crate) fn slot_count(&self) -> u64 {
        if self.channels == 3 {
            self.pixels.len() as u64
        } else {
            self.pixels
                .chunks_exact(4)
                .filter(|p| p.get(3) != Some(&0))
                .count() as u64
                * 3
        }
    }

    pub(crate) fn slot_map(&self) -> SlotMap {
        if self.channels == 3 {
            SlotMap::Dense
        } else {
            SlotMap::Sparse(
                self.pixels
                    .chunks_exact(4)
                    .enumerate()
                    .filter(|(_, p)| p.get(3) != Some(&0))
                    .filter_map(|(i, _)| u32::try_from(i).ok())
                    .collect(),
            )
        }
    }
}

pub(crate) enum SlotMap {
    Dense,
    Sparse(Vec<u32>),
}

impl SlotMap {
    /// Maps the k th eligible slot to a byte index into the pixel buffer.
    pub(crate) fn index(&self, k: u64) -> Option<usize> {
        match self {
            SlotMap::Dense => usize::try_from(k).ok(),
            SlotMap::Sparse(px) => {
                let pixel = *px.get(usize::try_from(k / 3).ok()?)? as usize;
                pixel.checked_mul(4)?.checked_add((k % 3) as usize)
            }
        }
    }
}

fn map_png_err(e: png::DecodingError) -> StegoError {
    match e {
        png::DecodingError::LimitsExceeded => StegoError::ImageTooLarge,
        _ => StegoError::UnsupportedImage,
    }
}
