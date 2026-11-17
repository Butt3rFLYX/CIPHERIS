#!/usr/bin/env python3
"""Independent decoder for CIPHERIS v1 envelopes (format marker SSS1) (differential test).

Uses implementations that share no code with the Rust crate:
  * Argon2id  -> OpenSSL via `cryptography` (>= 44)
  * XChaCha20-Poly1305 (IETF) -> system libsodium via ctypes

Usage: crosscheck.py ENVELOPE.hex PASSWORD [EXPECTED_PLAINTEXT]
Exit code 0 only if the envelope authenticates (and matches, if given).
"""
import ctypes
import ctypes.util
import struct
import sys

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MAGIC, PREFIX_LEN, HEADER_LEN = b"SSS1", 84, 132


def load_sodium():
    name = ctypes.util.find_library("sodium") or "libsodium.so.23"
    lib = ctypes.CDLL(name)
    if lib.sodium_init() < 0:
        raise RuntimeError("sodium_init failed")
    return lib


def xchacha_open(lib, key, nonce, ciphertext, aad):
    out = ctypes.create_string_buffer(max(len(ciphertext) - 16, 1))
    out_len = ctypes.c_ulonglong()
    rc = lib.crypto_aead_xchacha20poly1305_ietf_decrypt(
        out, ctypes.byref(out_len), None,
        ciphertext, ctypes.c_ulonglong(len(ciphertext)),
        aad, ctypes.c_ulonglong(len(aad)),
        nonce, key,
    )
    if rc != 0:
        raise ValueError("authentication failed")
    return out.raw[: out_len.value]


def open_envelope(env: bytes, password: bytes) -> bytes:
    if len(env) < HEADER_LEN + 16 or env[:4] != MAGIC:
        raise ValueError("invalid envelope")
    version, suite, mem, iters, lanes = struct.unpack(">HHIII", env[4:20])
    if (version, suite) != (1, 1):
        raise ValueError("unsupported format")
    salt, wrap_nonce, data_nonce = env[20:36], env[36:60], env[60:84]
    kek = Argon2id(salt=salt, length=32, iterations=iters, lanes=lanes,
                   memory_cost=mem).derive(password)
    lib = load_sodium()
    dek = xchacha_open(lib, kek, wrap_nonce, env[PREFIX_LEN:HEADER_LEN], env[:PREFIX_LEN])
    return xchacha_open(lib, dek, data_nonce, env[HEADER_LEN:], env[:HEADER_LEN])


def main():
    env = bytes.fromhex("".join(open(sys.argv[1]).read().split()))
    plaintext = open_envelope(env, sys.argv[2].encode())
    if len(sys.argv) > 3 and plaintext != sys.argv[3].encode():
        sys.exit("plaintext mismatch")
    # Negative control: one flipped ciphertext bit must be rejected.
    tampered = bytearray(env)
    tampered[-1] ^= 1
    try:
        open_envelope(bytes(tampered), sys.argv[2].encode())
        sys.exit("tampered envelope accepted")
    except ValueError:
        pass
    print(f"OK  m={struct.unpack('>I', env[8:12])[0]}KiB "
          f"t={struct.unpack('>I', env[12:16])[0]} p={struct.unpack('>I', env[16:20])[0]} "
          f"plaintext={plaintext!r}")


if __name__ == "__main__":
    main()
