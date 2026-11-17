#![no_main]
use libfuzzer_sys::fuzz_target;

// The first 28 bytes are read as a key, the rest as the image.
fuzz_target!(|data: &[u8]| {
    if data.len() < 28 {
        return;
    }
    let (key, png) = data.split_at(28);
    if let Ok(key) = std::str::from_utf8(key) {
        let _ = cipheris_stego::reveal_text(png, key);
    }
});
