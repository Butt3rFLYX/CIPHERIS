/// Local denial-of-service limits. Applications should select stricter values
/// when appropriate; the library applies them before allocating or running
/// Argon2.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum ciphertext length including the 16-byte payload tag.
    pub max_ciphertext_bytes: usize,
    /// Maximum Argon2 memory cost in KiB that an envelope may declare.
    pub max_argon2_memory_kib: u32,
    /// Maximum Argon2 pass count that an envelope may declare.
    pub max_argon2_iterations: u32,
    /// Maximum Argon2 lane count that an envelope may declare.
    pub max_argon2_parallelism: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_ciphertext_bytes: 256 * 1024 * 1024,
            max_argon2_memory_kib: 1024 * 1024,
            max_argon2_iterations: 10,
            max_argon2_parallelism: 16,
        }
    }
}
