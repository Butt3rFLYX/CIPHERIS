#![no_main]
use libfuzzer_sys::fuzz_target;

// Any byte string must be rejected or decrypted without panicking, and costs
// must stay inside the strict limits below.
fuzz_target!(|data: &[u8]| {
    let limits = cipheris_core::Limits {
        max_ciphertext_bytes: 1 << 16,
        max_argon2_memory_kib: 64,
        max_argon2_iterations: 1,
        max_argon2_parallelism: 1,
    };
    let _ = cipheris_core::decrypt(data, b"fuzz", limits);
});
