# CIPHERIS file format, version 1

Everything on this page is part of the stored format. Changing any of it makes existing pictures unreadable, so a change needs a new version number and a migration path. Files made by SSS 0.1.0 use exactly this format; the marker `SSS1` and the labels below keep that name on purpose.

## 1. Key

* 16 random bytes from the operating system random source (128 bits).
* Text form: 26 Crockford Base32 characters (128 bits plus 2 zero bits), then 2 checksum characters holding the first 10 bits of `BLAKE2b-256("SSS/v1/key-checksum" || key)`.
* Shown as 7 groups of 4 characters separated by spaces. Parsing ignores case, spaces and dashes, and reads `O` as `0`, `I` and `L` as `1`.
* Keys are only ever generated, never chosen by a person. This is what allows the placement in section 3 without a stored salt.

## 2. Envelope

All integers are unsigned big endian.

| Offset | Size | Field | Protection |
| --- | --- | --- | --- |
| 0 | 4 | marker `SSS1` | authenticated as payload associated data |
| 4 | 2 | version = 1 | authenticated |
| 6 | 2 | suite = 1 (Argon2id v1.3 + XChaCha20 Poly1305) | authenticated |
| 8 | 4 | Argon2 memory in KiB | authenticated by key wrap and payload |
| 12 | 4 | Argon2 passes | authenticated by key wrap and payload |
| 16 | 4 | Argon2 lanes | authenticated by key wrap and payload |
| 20 | 16 | random salt | authenticated by key wrap and payload |
| 36 | 24 | key wrap nonce | authenticated by key wrap and payload |
| 60 | 24 | payload nonce | authenticated by key wrap and payload |
| 84 | 48 | data key (32 bytes) encrypted with the key encryption key, plus tag | authenticated by payload; internally by its own tag |
| 132 | rest | payload ciphertext plus 16 byte tag | XChaCha20 Poly1305 |

* Key encryption key = Argon2id(secret, salt, memory, passes, lanes), 32 bytes. CIPHERIS uses 64 MiB, 3 passes, 4 lanes (RFC 9106, second recommended option). The secret is the 16 raw key bytes.
* The data key is random per message. It is wrapped with the key encryption key using bytes 0 to 83 as associated data, and encrypts the payload using bytes 0 to 131 as associated data.
* Readers check marker, version and suite, then check the declared Argon2 costs against local limits before any allocation, then authenticate. Unknown versions or suites are rejected, never guessed.

Inner payload (encrypted): `[0x01 version][0x01 kind = text][UTF 8 text]`.

## 3. Placement in the picture

* The picture is decoded to 8 bit RGB or RGBA. Palette, grayscale and 16 bit images are normalized; fully opaque RGBA is treated as RGB.
* Slots are the R, G and B values of every pixel whose alpha is not 0, in row order. Alpha is never changed.
* Seed = `BLAKE2b-256("SSS/v1/embed-plan" || key || width || height || channels)`, with width, height and channel count as 32 bit big endian integers.
* A ChaCha20 generator seeded with it produces first 4 bytes that mask the length prefix, then positions: a lazily evaluated Fisher Yates shuffle over all slots, drawing each index with Lemire's unbiased method from successive 64 bit outputs.
* Stream = `(envelope length as u32 big endian) XOR mask`, then the envelope, most significant bit first.
* Each bit is written by LSB matching: if the lowest bit differs, the value moves up or down by one at random (from the operating system random source), forced to 1 at 0 and to 254 at 255.
* Limits: at most 25 % of slots, at most 32 KiB of text, at most 40 megapixels and 100 MB per file.

## 4. Output

A freshly encoded 8 bit RGB or RGBA PNG containing only `IHDR`, `IDAT` and `IEND`. No metadata of the original is copied.

## Test vectors

* `crates/core/tests/vectors/v1_cheap.hex`: an envelope with cheap Argon2 settings, opened by the independent decoder `tools/crosscheck.py`.
* `crates/stego/tests/fixtures/sss_v1.png` and `.key`: a picture made by SSS 0.1.0 that every later version must open.
