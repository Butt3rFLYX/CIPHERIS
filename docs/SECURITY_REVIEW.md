# Security review against the hardening checklist

Version 0.2.0, reviewed 29 October 2026. Every item of the project's hardening checklist is listed with a status and the evidence behind it. Tests named here run in CI (`cargo test --workspace`, the browser test `tools/e2e/ui.test.mjs` and the cross check `tools/crosscheck.py`).

**Status values**

| Status | Meaning |
| --- | --- |
| **Done** | implemented and backed by a test or by construction that can be read in the code |
| **Fixed** | was faulty in SSS 0.1.0 and is corrected in 0.2.0 |
| **Partial** | partly implemented; the gap is named |
| **Open** | not implemented yet |
| **N/A** | does not apply to this design; the reason is given |
| **Unverified** | cannot be confirmed from this environment (for example needs macOS, Windows or an external party) |

## Critical findings in SSS 0.1.0, fixed in 0.2.0

| Finding | Risk | Fix | Evidence |
| --- | --- | --- | --- |
| One thread was spawned per connection, with no limit | any local page or program could exhaust threads and memory | fixed pool of 8 workers, queue of 16, immediate 503 beyond that | `crates/app/src/lib.rs` `start`; test `connection_floods_get_503_instead_of_threads` |
| Read timeouts only per read, no total deadline | a client sending one byte at a time held a worker indefinitely | total deadlines for head (10 s) and body (60 s) | `http::read_request`, `read_with_deadline`; test `slow_clients_are_cut_off` |
| Session token travelled in the URL query and was stored in `sessionStorage` | token in browser history and readable by any script on the page | one time launch link `/launch/<code>` (2 minutes, one use), answered with a redirect that sets an HttpOnly SameSite Strict cookie | `session.rs`; test `launch_link_works_exactly_once`, browser checks "nothing stored in browser storage", "session cookie is invisible to JavaScript", "launch link cannot be used twice" |
| `OsRng.fill_bytes` panics if the system random source fails | crash instead of a clean error | `try_fill_bytes` everywhere, mapped to an error | `envelope.rs` `encrypt_with_rng`, `key.rs` `SecretKey::generate`, `session.rs` `random_hex` |
| Request bodies with messages and responses with keys or text were not wiped | secrets lingered in freed memory | `Zeroizing` request bodies, response bodies and headers | `http.rs` `Request::body`, `Response` |
| Unlimited concurrent image operations (each up to several hundred MB) | memory exhaustion | at most two at once, then 503 | `api::HeavySlots`; test `heavy_slots_are_bounded_and_released` |

## Findings of the 0.2.0 review, fixed before release

Found while reviewing the rebuilt code against the checklist, so they never shipped in a CIPHERIS release.

| Finding | Risk | Fix | Evidence |
| --- | --- | --- | --- |
| Browser features could send text to online services: automatic page translation, enhanced spell check, writing assistant extensions | the decrypted message, or the message being typed, leaves the computer | page marked `translate="no"` plus `notranslate`; spell checking, autocorrect and autocomplete off in every field; opt out attributes for common writing assistants and password managers | browser checks "page refuses machine translation", "spell checking off in every text field", "writing assistants and password managers told to ignore the fields" |
| The first launch design kept the code in the URL fragment and needed JavaScript to redeem it | some ways of opening a link drop the fragment, so the app would not open; the code stayed in the address bar until the script ran | path based launch link; the server redeems it and redirects with `303 See Other`; no script and no fragment involved | test `launch_link_works_exactly_once`; browser checks "launch link redirects to the interface", "launch link cannot be used twice", "reload keeps the session" |
| Headers that carry security decisions could appear twice | two parts of a stack might read different values (parser differential) | duplicate `Origin`, `Cookie`, `X-Cipheris` and `Content-Length` are refused with 400 | test `duplicate_security_headers_are_refused` |
| Access checks ran only after the whole body had been read | any local program or page that reached the port could make the server wait for and buffer up to 100 MB per worker (800 MB in total) without a session | Host, Origin, custom header and session cookie are checked on the head; refused requests are answered before a single body byte is read or reserved | `lib.rs` `Server::admit`; test `bodies_of_refused_requests_are_never_read` |
| Request head buffers were wiped only on the success path; header values (including the cookie) were never wiped | the session cookie lingered in freed memory after refused requests | head buffer, read buffer and header values are `Zeroizing`; the head buffer is sized once, so it never reallocates | `http.rs` `read_request` |
| The key field of a reveal request had no own length limit | needless work and memory on hostile input | 256 bytes at most, checked before any image work; body limit per endpoint includes it | test `overlong_key_field_is_refused` |
| Answers sent before the body was read (413, 401, 403) could be lost | the operating system resets the connection when unread data remains, so the browser shows a network error instead of the real message | lingering close: shut down writing, then drain at most 256 KiB for at most 200 ms | `lib.rs` `linger`; test `refusal_reaches_a_client_that_is_still_uploading` (fails with "connection reset" when the lingering close is removed) |
| CI pinned the toolchain action by commit, but without naming a toolchain | the pinned action needs an explicit version, so every CI run would fail | `toolchain: 1.97.0` in every job, matching the new `rust-toolchain.toml` | `.github/workflows/ci.yml`, `release.yml` |
| The two fuzzing examples were not formatted and one failed a clippy lint | `cargo fmt --check` and `cargo clippy -D warnings` in CI would have failed | formatted, lint fixed | full local run of both commands, see section 4 |

## 1. Cryptography

| Item | Status | Evidence |
| --- | --- | --- |
| Only established, reviewed crypto libraries | Done | RustCrypto `argon2`, `chacha20poly1305`, `blake2`; no own primitives |
| Authenticated encryption | Done | XChaCha20 Poly1305 for key wrap and payload (`envelope.rs`) |
| Correct nonce generation and uniqueness | Done | two fresh 192 bit random nonces per envelope; random data key per message makes reuse harmless; test `every_operation_uses_fresh_randomness` |
| Cryptographically secure random generator | Done | `OsRng` (operating system); placement uses ChaCha20 seeded by BLAKE2b of the key |
| No predictable keys | Done | 128 bit keys from `OsRng`; test `keys_are_unique` (10 000 keys) |
| Sufficient key entropy | Done | 128 bits; keys are never chosen by people |
| No key reuse across purposes | Done | key bytes feed Argon2id (with random salt) for the envelope and BLAKE2b with a separate label for placement |
| Domain separation in key derivation | Done | labels `SSS/v1/embed-plan`, `SSS/v1/key-checksum`; Argon2id with its own salt |
| HKDF where suitable | N/A | the only derivations are Argon2id (password style KDF) and a keyed BLAKE2b hash with a label, which is a sound KDF for a uniformly random key; switching would break the v1 format |
| Argon2id with suitable parameters for password based keys | Done | 64 MiB, 3 passes, 4 lanes (RFC 9106); keys are random, so Argon2 is defence in depth |
| Resource limits for key derivation | Done | declared costs checked before Argon2: test `attacker_controlled_kdf_cost_is_bounded_before_argon2`; stego limits 256 MiB, 8 passes, 8 lanes |
| Authentication before use | Done | text is returned only after both AEAD tags verify; test `every_single_bit_flip_is_rejected` |
| Detect manipulated ciphertexts | Done | tests `every_single_bit_flip_is_rejected`, `truncation_is_never_accepted`, `appended_bytes_are_rejected`, `any_change_to_payload_pixels_is_detected` |
| Handle wrong keys safely | Done | tests `wrong_password_fails_closed`, `wrong_key_finds_nothing`, browser check "wrong key gives the generic message" |
| No sensitive data in error messages | Done | fixed message set; test `messages_contain_no_dashes_or_secrets` |
| No secret keys in logs | Done | the app prints only its address and the one time launch code at start; nothing is logged per request |
| No unnecessary copies of key material | Partial | keys and derived keys are wiped on drop; the key necessarily appears in the response header and the page; library internals may copy |
| Zeroize sensitive memory where possible | Done | `Zeroizing` for KEK, data key, placement seed, plaintext, request and response bodies; `SecretKey` derives `ZeroizeOnDrop`; Argon2 `zeroize` feature |
| Respect the limits of zeroizing | Done | documented in SECURITY.md: registers, swap, crash dumps and the browser are outside its reach |
| No secrets in debug output | Done | `SecretKey` debug prints `<redacted>`; test `debug_does_not_leak` |
| Versioned crypto format | Done | version and suite fields, allowlist; test `unknown_version_or_suite_is_not_guessed`; docs/FORMAT.md |
| Authenticate security relevant headers | Done | all 132 header bytes are associated data |
| Crypto test vectors | Done | RFC 9106 Argon2id, XChaCha20 Poly1305 draft A.3.1, RFC 7693 BLAKE2b (`vectors.rs`); format vector `known_answer_vector`; all also confirmed with OpenSSL and libsodium |
| Plan for key rotation and migrations | Partial | version and suite fields allow a v2 reader next to v1; no v2 exists yet. Keys are per message, so rotation means simply hiding again |
| Check random sources on all supported OSes | Unverified | `getrandom` covers Windows, macOS and Linux; CI runs the tests on all three, not yet observed here |
| Check crypto error handling for leaks | Done | one generic error for wrong key, changed picture and missing message; typos are reported separately but say nothing about the picture |
| Timing side channels in secret dependent operations | Partial | token, launch code and checksum comparisons are constant time; primitives rely on the libraries; no measurement was done |
| Independent crypto review | Open | needs an external reviewer |

## 2. Steganography

| Item | Status | Evidence |
| --- | --- | --- |
| Validate image formats strictly | Done | PNG signature, CRC checks, full read up to IEND (`carrier.rs` `decode_png`) |
| Allow only supported formats | Done | the server accepts PNG only; the browser converts other formats before hiding; reveal rejects anything but PNG |
| Avoid lossy formats unintentionally | Done | output is always PNG; JPEG input is converted once and warned about in reveal mode |
| Maximum image size | Done | 100 MB per file, checked before decoding; test `oversized_file_is_rejected_before_decoding`, server test `oversized_bodies_are_refused_before_reading` |
| Maximum pixel count | Done | 40 megapixels, checked before the pixel buffer is allocated |
| Limit decoder memory | Done | `png::Limits` of 320 MB; dimensions checked first |
| Reject damaged files safely | Done | test `corrupted_images_never_panic` (1 500 mutated files) |
| Detect incomplete files | Done | `reader.finish()` reads to IEND; truncations in the same test |
| Prevent integer overflows | Done | checked arithmetic in `decode_png`, `SlotMap::index`, `embed`; release builds keep overflow checks on |
| Reliable capacity calculation | Done | tests `capacity_limits_are_enforced`, `unicode_at_the_limit`, `large_images_cap_message_size` |
| Check payload limits before processing | Done | `embed` checks length before encrypting; `extract` checks the declared length before reading |
| No repeated writes to the same position | Done | lazy Fisher Yates permutation; test `placement_never_repeats_a_slot` (every slot exactly once) |
| Verify key dependent position selection | Done | test `different_keys_choose_different_positions` |
| Analyse the position distribution statistically | Done | chi square over 30 bands, 60 000 draws, p < 0.001 threshold; test `placement_is_uniform` |
| Investigate detectability experimentally | Partial | `stego_report` measured three photographs at five rates (results below); no modern detector yet |
| Test LSB matching with established steganalysis | Partial | the classic pairs of values measure (basis of the Westfeld chi square attack) was run against CIPHERIS and an LSB replacement control; rich model and neural detectors are open |
| Compare image types | Partial | colour photos, a grayscale photo, synthetic RGB, RGBA, palette and 16 bit images are tested for correctness; detectability only on the three photos |
| Test different payload sizes | Done | report rates 0.5 % to 25 %; correctness tests from 1 byte to the limit |
| Measure PSNR and SSIM | Done | PSNR 57 dB at 25 %, 64 dB at 5 %, 74 dB at 0.5 %; SSIM at least 0.9993 at 25 % and at least 0.9998 at 5 % on all three photos (table below); PSNR also pinned by the test `psnr_stays_high` |
| Authenticate extracted data before use | Done | `extract` returns only after AEAD succeeds |
| Reject wrong keys reliably | Done | see section 1 |
| Handle damaged payloads safely | Done | `any_change_to_payload_pixels_is_detected` |
| Handle image metadata deliberately | Done | output has only IHDR, IDAT, IEND; test `output_has_no_ancillary_chunks` |
| Remove unnecessary metadata without losing needed data | Done | colour profiles are dropped; browsers render the output as sRGB, which matches how the pixels were decoded |
| Protect originals from being overwritten | Done | CIPHERIS never writes files; the browser saves a new download |
| Fuzz image processing | Partial | mutation campaign `fuzz_campaign` (120 s per target, no crash, no wrong acceptance): PNG decoder 64 995 605 inputs, reveal with the right key 25 614 inputs; deterministic mutation tests run in CI; coverage guided fuzzing with the targets in `fuzz/` needs a nightly compiler and has not been run yet |
| Document the limits of steganography | Done | README, THREAT_MODEL.md, interface hints |
| Never claim guaranteed undetectability | Done | stated in README, interface and docs |

**Measurement** (`cargo run --release -p cipheris_stego --example stego_report -- <photo>`). Pair asymmetry is the classic LSB replacement fingerprint; lower than the original means pairs of values were pulled together. SSIM is computed on luminance over 8 × 8 windows with a stride of 4 pixels.

| Photo | Rate | PSNR | SSIM | Original asymmetry | CIPHERIS | LSB replacement control |
| --- | --- | --- | --- | --- | --- | --- |
| coffee, 600 × 400 | 5 % | 64.2 dB | 0.999925 | 0.0402 | 0.0390 | 0.0380 |
| coffee | 25 % | 57.2 dB | 0.999618 | 0.0402 | 0.0380 | 0.0307 |
| camera (grayscale), 512 × 512 | 5 % | 64.1 dB | 0.999899 | 0.0690 | 0.0684 | 0.0657 |
| camera | 25 % | 57.2 dB | 0.999502 | 0.0690 | 0.0661 | 0.0538 |
| astronaut, 512 × 512 | 5 % | 64.2 dB | 0.999911 | 0.1163 | 0.1111 | 0.1107 |
| astronaut | 25 % | 57.2 dB | 0.999383 | 0.1163 | 0.0898 | 0.0894 |

Reading: on two of three photos LSB matching preserves the fingerprint clearly better than replacement. On the astronaut photo, which has large saturated areas, both behave alike, because values at 0 and 255 can move in one direction only. At the 5 % warning threshold all changes are small. This is one classic detector on three public sample images (scikit image data), not proof of undetectability.

## 3. Local HTTP server

| Item | Status | Evidence |
| --- | --- | --- |
| Bind only to loopback | Done | `127.0.0.1` in `start`; test `only_loopback_is_bound` |
| No unintended network exposure | Done | no other listener, no outgoing connections |
| Limit concurrent connections | Fixed | worker pool plus queue; test `connection_floods_get_503_instead_of_threads` |
| Prevent unbounded thread creation | Fixed | same |
| Bounded thread pool or controlled async | Fixed | 8 workers, configurable in `Config` |
| Maximum request size | Done | head 16 KiB, body per endpoint (`api::body_limit`) |
| Maximum header size | Done | 16 KiB, 64 headers; test in `unsupported_methods_and_framing_are_refused` (431) |
| Maximum upload size | Done | 100 MB plus framing; refused before reading the body |
| Connection timeouts | Fixed | total head deadline 10 s |
| Read timeouts | Fixed | per read and total; body deadline 60 s |
| Write timeouts | Done | 20 s per response, 1 s for busy answers |
| Abort slow requests | Fixed | test `slow_clients_are_cut_off` |
| Handle incomplete requests | Done | closed without answer; no partial processing |
| Check access before reading the body | Done | Host, Origin, custom header and cookie are checked on the head; test `bodies_of_refused_requests_are_never_read` |
| Error answers survive an unfinished upload | Done | lingering close; test `refusal_reaches_a_client_that_is_still_uploading` |
| Validate HTTP methods strictly | Done | GET and POST only, 405 with `Allow` otherwise |
| Disable unneeded endpoints | Done | fixed route table; everything else is 404 |
| Validate the Host header | Done | exact match, exactly one Host header; test `wrong_host_and_foreign_origin_are_refused` |
| Check the Origin header | Done | must match when present, required on every POST, at most one; test `duplicate_security_headers_are_refused` |
| Deny cross origin access by default | Done | no CORS headers are ever sent; preflights get 405 |
| CSRF protection for state changing endpoints | Done | SameSite Strict cookie, Origin and custom `X-Cipheris` header |
| Protection against unwanted local browser requests | Done | same checks; DNS rebinding blocked by the Host check |
| Session bound access tokens | Fixed | one time launch code and HttpOnly cookie |
| No secrets in URLs | Fixed | the only secret ever in a URL is the launch code in `/launch/<code>`: it works once, expires after 2 minutes and is replaced by `/` through a redirect before the page loads; test `launch_link_works_exactly_once`, browser check "launch link cannot be used twice" |
| Disable caching of sensitive responses | Done | `Cache-Control: no-store` on every response |
| Content Security Policy | Done | `default-src 'none'`, scripts and styles only from the app; browser check "CSP present" |
| Check XSS protection | Done | all dynamic text goes through `textContent`; no inline script or style is allowed by the CSP |
| Check clickjacking protection | Done | `frame-ancestors 'none'` and `X-Frame-Options: DENY` |
| No unchecked file paths | Done | assets are compiled into the binary (`assets.rs`); test `no_path_reaches_the_file_system` |
| No unintended local file access | Done | the server never opens files |
| Do not expose internal error details | Done | fixed short messages |
| Release resources on exit | Done | quit and idle shutdown end the process; tests `quit_and_idle_shutdown_stop_the_server`, browser check "quit stops the app" |
| Minimal network services | Done | one loopback listener |

## 4. Rust code and memory safety

| Item | Status | Evidence |
| --- | --- | --- |
| Keep `#![forbid(unsafe_code)]` | Done | every crate and the workspace lint table |
| Review security relevant `unwrap()` | Done | `clippy::unwrap_used` is denied outside tests |
| Review security relevant `expect()` | Done | `clippy::expect_used` is denied outside tests |
| No panics from invalid input | Done | `clippy::panic` denied; mutation tests for envelopes, PNGs and HTTP framing |
| Prevent integer overflows | Done | checked arithmetic on all size calculations; `overflow-checks = true` in release |
| Checked arithmetic | Done | `checked_mul`, `checked_add`, `try_from` in parser and stego code |
| Safe size conversions | Done | `try_from` instead of `as` where values come from input |
| Limit memory allocations | Done | every allocation size is bounded by a limit checked first |
| Prevent unbounded recursion | Done | no recursion in the code base |
| Structured error types | Done | `EnvelopeError`, `StegoError`, `ReadError` |
| Release resources on errors | Done | RAII guards (`HeavyGuard`, `Zeroizing`) |
| Investigate race conditions | Done | shared state is atomics or a mutex around the launch code; redeem is atomic under the lock |
| Prevent deadlocks | Done | single short lived mutex per structure, never nested |
| Thread safety | Done | enforced by the compiler; no unsafe code |
| Correct UTF 8 and Unicode handling | Done | tests with emoji, CJK, umlauts at the capacity limit; invalid UTF 8 is refused |
| No uncontrolled buffers | Done | all buffers are Vec with checked bounds |
| Review native dependencies | Done | none; all dependencies are pure Rust |
| Test debug and release builds | Done | CI runs `cargo test` and `cargo test --release` |
| `cargo fmt --check` | Done | CI |
| `cargo clippy --all-targets --all-features -- -D warnings` | Done | CI, plus the stricter workspace lints |
| `cargo test --workspace` | Done | 62 tests (19 core, 25 stego, 18 app) plus one documentation example, debug and release, all passing on Linux; CI repeats them on macOS and Windows |

## 5. File system and privacy

| Item | Status | Evidence |
| --- | --- | --- |
| Check file sizes before reading | Done | the browser checks size before upload; the server checks Content Length before reading |
| Validate file types by content | Done | PNG signature and full decode, not the file name |
| Prevent path traversal | N/A | the app never builds paths from input |
| Handle symbolic links safely | N/A | no file system access |
| File system race conditions | N/A | no file system access |
| Create temporary files safely | N/A | none are created (the only temporary file is the root check at start, created with exclusive create and removed at once) |
| Restrictive file permissions | N/A | no files written |
| Avoid sensitive temporary files | Done | none exist |
| Write output atomically | N/A | the browser's download manager writes the file |
| Prevent unintended overwriting | Done | CIPHERIS never writes files; browsers save the download as a new file and rename it on a name clash |
| Handle write errors | N/A | no writes |
| Handle full disks | N/A | no writes |
| Detect partially written files | Done | a partly written download fails PNG decoding (IEND check) when revealing |
| Keep sensitive data out of logs | Done | no request logging |
| No secrets in telemetry | Done | there is no telemetry |
| Check browser storage for confidential data | Done | browser check "nothing stored in browser storage" |
| Check the clipboard for leaks | Partial | copying is only on request and the interface warns that clipboard managers may keep keys; automatic clearing is not possible without clipboard read permission |
| Document safe key storage | Done | README "Keep in mind", interface note |
| Test backup and recovery | N/A | there is nothing to back up; keys are shown once by design |

## 6. Automated security tests

| Item | Status | Evidence |
| --- | --- | --- |
| Unit tests for critical functions | Done | 44 tests in core and stego |
| Integration tests | Done | 16 server tests over raw sockets, 31 browser checks |
| Encrypt and decrypt fully tested | Done | envelope tests and vectors |
| Embed and extract fully tested | Done | stego tests over all PNG kinds |
| Wrong keys | Done | see above |
| Manipulated ciphertexts | Done | see above |
| Damaged image files | Done | `corrupted_images_never_panic` |
| Truncated files | Done | same, plus `truncation_is_never_accepted` |
| Empty messages | Done | `capacity_limits_are_enforced` |
| Large messages | Done | `unicode_at_the_limit`, `large_images_cap_message_size` |
| Invalid inputs | Done | framing, method, header and key tests |
| Random binary data | Done | `arbitrary_input_never_panics`, `corrupted_images_never_panic` |
| Property based tests | Partial | deterministic randomized tests over thousands of inputs; no property testing framework, to avoid new dependencies |
| Fuzz image parsers | Partial | mutation campaign: 64 995 605 PNG inputs in 120 s, no crash; coverage guided target `png_decode` not run yet (needs nightly) |
| Fuzz steganography | Partial | mutation campaign: 25 614 mutated stego images revealed with the right key in 120 s, no crash, no wrong text accepted; coverage guided target `reveal` not run yet |
| Fuzz file formats | Partial | mutation campaign: 2 662 244 envelopes in 120 s, no crash, no mutated envelope decrypted; 312 580 495 key strings in 120 s; coverage guided target `decrypt` not run yet |
| Fuzz the HTTP server | Done | `http_fuzz` over real sockets, two runs: 2 527 898 mutated requests in 300 s, and 1 279 415 in 180 s against the final code; the health check after every 500 requests always passed and no API endpoint ever answered without the session cookie |
| Parallel requests | Done | `connection_floods_get_503_instead_of_threads` |
| Server under load | Partial | flood test and 300 s of sequential mutated traffic (see above); no sustained parallel load test |
| Measure memory use | Done | peak resident memory: 2.7 MiB idle; 249 MiB for hide and reveal of a 12 megapixel RGB photo (27.7 MB PNG); 512 MiB at the limit (40 megapixel RGBA, 55 MB PNG). With two image slots the worst case is about 1 GiB |
| Measure CPU use | Done | release build on a 2 core Linux machine: 12 megapixels hide 1.0 s, reveal about 0.5 s; 40 megapixels hide about 2.5 s, reveal 1.0 s (two runs each) |
| Check time limits | Done | slow client and idle shutdown tests |
| Resource exhaustion | Done | oversized bodies, floods, busy slots |
| Interrupted writes | N/A | no writes |
| Windows compatibility | Unverified | CI job exists |
| macOS compatibility | Unverified | CI job exists; SSS 0.1.0 ran on the author's Mac |
| Linux compatibility | Done | all tests pass on Linux x86 64 |
| Regression tests for fixed bugs | Done | each fixed finding above has its test; `legacy_sss_image_still_opens` pins the format |
| Independent security review | Open | needs an external party |

## 7. Dependencies and supply chain

| Item | Status | Evidence |
| --- | --- | --- |
| Set up `cargo audit` | Done | covered by `cargo deny check advisories` in CI (same RustSec database) |
| Set up `cargo deny` | Done | `deny.toml`, CI job `supply-chain` |
| Version `Cargo.lock` | Done | committed; its dependency graph was checked against cargo's own resolution (50 packages, 47 from crates.io), all 47 checksums match the official crates.io index of 29 October 2026 and no locked version is yanked; CI and releases build with `--locked` |
| Review direct dependencies | Done | 8 direct crates, all from RustCrypto, the image rs project or widely used basics |
| Review transitive dependencies | Partial | 47 crates, pure Rust; licences and advisories checked (see below); no line by line review |
| Check licences | Done | every locked crate is under MIT, Apache 2.0, BSD, Zlib or Unicode 3.0 terms, all on the `deny.toml` allow list; `cargo deny check licenses` repeats this in CI |
| Remove unnecessary dependencies | Done | the server uses only the standard library; no JSON, HTTP or async framework |
| Check for outdated libraries | Done | Dependabot weekly |
| Fix known vulnerabilities | Done | `tools/audit_lock.py` checked all 47 locked crates against the RustSec advisory database of 29 October 2026 (commit ee1a49a): no advisory applies to any locked version. `cargo deny check advisories` repeats this on every CI run |
| Review build scripts | Done | the workspace has no build scripts of its own |
| Review native components | Done | none |
| Minimize CI permissions | Done | `contents: read` everywhere; write only in the publish job; checkout without persisted credentials |
| Pin CI actions to trusted fixed versions | Done | every action pinned to a commit hash |
| Keep secrets out of CI logs | Done | no secrets are used |
| Guard automatic dependency updates with tests | Done | Dependabot pull requests run the full CI |
| Software bill of materials | Done | CycloneDX 1.5 SBOM generated by `tools/sbom.py` from `cargo metadata`, validated against the official schema, attached to each release |
| Publish release checksums | Done | `SHA256SUMS.txt` in each release |
| Sign releases where possible | Partial | macOS apps are ad hoc signed; no paid Apple or Microsoft certificate, no GPG signature yet |
| Aim for reproducible builds | Partial | locked dependencies, compiler pinned to Rust 1.97.0 in `rust-toolchain.toml` and in CI; byte identical output not verified |
| Monitor dependency advisories | Done | `cargo deny` on every push, Dependabot |

## 8. User interface

| Item | Status | Evidence |
| --- | --- | --- |
| Clearly separate encryption and decryption | Done | two modes, *hide* and *reveal* |
| Detect invalid input early | Done | file size and type before upload, key length and checksum before any image work |
| Understandable error messages | Done | every message says what happened and what to do |
| No sensitive technical details | Done | fixed message set |
| Progress display for longer operations | Done | spinner row while waiting; real step rows after the answer (no fake percentages, the server answers in one piece) |
| Safely cancel running operations | Done | *cancel* aborts the request and discards the result; browser check "cancel saves nothing" |
| Show maximum file sizes | Done | shown in the drop zone; browser check "maximum file size shown" |
| Show payload capacity | Done | meter and byte counter |
| Warn about incompatible formats | Done | reveal mode explains why a JPEG cannot carry a message |
| Do not store keys unintentionally | Done | no storage; browser check |
| Mask password fields by default | Done | key input is a password field with a *show* toggle; browser check |
| No confidential data in URLs | Fixed | see section 3 |
| Keep browser features from sending text to online services | Done | no machine translation, no spell check, opt out attributes for writing assistants and password managers; three browser checks (see the findings above). Extensions that ignore these hints are scenario G of the threat model, and the README advises a profile without extensions |
| No success message before completion | Done | log rows appear only after the server confirmed |
| Protect users from overwriting | Done | downloads never replace the original (see section 5) |
| Explain security limits | Done | sending hint, warning above 5 %, README |
| Check the interface for XSS | Done | `textContent` only; strict CSP |

## 9. Documentation and threat model

| Item | Status | Evidence |
| --- | --- | --- |
| Update the threat model | Done | docs/THREAT_MODEL.md |
| Define assets | Done | threat model section 4 |
| Document attacker models | Done | threat model sections 2 and 6 |
| Rate confidentiality separately | Done | threat model section 1 and 3 |
| Rate integrity separately | Done | same |
| Rate concealment separately | Done | same |
| Document algorithms | Done | docs/FORMAT.md |
| Document parameters | Done | docs/FORMAT.md |
| Version file formats | Done | docs/FORMAT.md |
| Document key management | Done | docs/FORMAT.md section 1, README |
| Disclose security limits | Done | README table, SECURITY.md |
| Document known limitations | Done | SECURITY.md |
| No unproven security promises | Done | wording reviewed in README, interface and docs |
| Describe safe installation | Done | README "Install" with checksums |
| Describe safe updates | Done | SECURITY.md "Updates" |
| Vulnerability reporting process | Done | SECURITY.md |
| Document security relevant changes | Done | CHANGELOG.md |
| Store test evidence traceably | Done | this file, CI logs and the screenshots artifact |

## 10. Release and production readiness

| Item | Status | Evidence |
| --- | --- | --- |
| Release builds without debug features | Done | release profile: LTO, stripped, panic abort; Windows build without console |
| Separate development and production configuration | Done | debug only behaviour is limited to optimisation settings; no debug endpoints exist |
| Test Windows releases | Unverified | release workflow builds and tests on Windows |
| Test macOS releases | Unverified | same on macOS |
| Test Linux releases | Done | release build tested here |
| Check installation packages | Unverified | first release not yet built |
| Ship no secrets | Done | the repository contains no keys or tokens; test fixtures are public test data |
| Provide checksums | Done | release workflow |
| Check release signatures | Partial | see section 7 |
| Maintain version numbers | Done | single version in the workspace manifest |
| Changelog | Done | CHANGELOG.md |
| Enable security updates | Done | Dependabot, release workflow |
| Test compatibility between versions | Done | `legacy_sss_image_still_opens` |
| Check downgrade behaviour | Done | older readers reject unknown versions; this reader rejects unknown versions and suites |
| Test format migrations | N/A | there is only format v1 |
| Independent review before publication | Open | needs an external party |
| Watch security reports after publication | Done | process in SECURITY.md |

## 11. Additional measures

| Item | Status | Evidence |
| --- | --- | --- |
| Check keys and metadata for unintended correlations | Done | fresh key, salt, nonces and positions per message; test `every_hide_uses_a_new_key_and_layout` |
| Separate encryption and steganography keys logically | Done | domain separated derivations (section 1) |
| No reuse of random values where forbidden | Done | see nonce and key tests |
| Verify crypto libraries with official vectors | Done | `vectors.rs` |
| Secret dependent branches and memory access | Partial | constant time comparisons for secrets; the placement is secret dependent by design and runs locally only |
| Check memory dumps and crash reports | Partial | panic is abort in release and secrets are wiped; the OS may still write crash dumps |
| Keep secrets in memory only as long as needed | Done | buffers are wiped when each request finishes; the page clears the key on *new message* and the text on *clear* |
| Handle decryption errors safely | Done | section 1 |
| No unencrypted intermediate files | Done | none are written |
| Conservative defaults | Done | 25 % hard limit, 5 % warning, 2 minute launch code, 6 minute idle shutdown |
| Optional features get only the permissions they need | Done | Permissions Policy denies camera, microphone, location, USB and payment |
| Check process isolation and sandboxing | Partial | the browser sandboxes the interface; the server runs unprivileged; no OS level sandbox for the decoder yet |
| Do not run the server with elevated rights | Done | refuses to start as root on Unix unless `--allow-root` is given explicitly |
| Limit resources for intentionally invalid input | Done | section 3 |
| Check dependencies for unsafe deserialization | Done | no serialization framework is used |
| Guard input formats against parser differentials | Done | one PNG decoder; HTTP parser rejects duplicate Host, Content Length, Origin, Cookie and `X-Cipheris` headers, chunked encoding and line folding |
| Document safe default configuration | Done | SECURITY.md |
| Confirm security critical configuration changes explicitly | Done | the only one, running as root, needs an explicit flag |
| Run security checks on every relevant change | Done | CI on every push and pull request |
| Document external audits | Open | none yet |

## 12. Acceptance criteria

| Criterion | Met |
| --- | --- |
| 1. All critical measures checked, needed fixes done | yes, for everything verifiable here |
| 2. All security critical tests pass | yes on Linux (62 Rust tests in debug and release, 31 browser checks, cross check with OpenSSL and libsodium) |
| 3. Wrong keys and manipulated data reliably rejected | yes |
| 4. Invalid files never cause uncontrolled crashes | yes in tests and in mutation fuzzing (about 380 million parser inputs, 3.8 million HTTP requests, no crash); coverage guided fuzzing still to run |
| 5. Server protected against unwanted access and exhaustion | yes |
| 6. Secrets not stored or logged unintentionally | yes |
| 7. Dependencies checked for known vulnerabilities | yes: no RustSec advisory applies to any locked crate (database of 29 October 2026); CI repeats the check on every run |
| 8. Tested on all supported systems | no, macOS and Windows pending in CI |
| 9. Threat model documented and current | yes |
| 10. Limits of steganography communicated | yes |
| 11. No open known critical vulnerabilities in the model | none known |
| 12. Independent security review done | **no** |

Therefore CIPHERIS 0.2.0 must not yet be called "comprehensively security reviewed". Criteria 8 and 12 are the remaining gates: the first CI run on macOS and Windows, and a review by an independent party.
