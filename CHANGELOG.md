# Changelog

## 0.4.0 (2026-11-17): own app window

### Interface
* New: on macOS and Windows CIPHERIS opens in its own window instead of a browser tab. The window uses the web view of the system (WebKit, Microsoft Edge WebView2), runs in private mode, may only show the local server, opens no other windows and has no browser extensions.
* Saved pictures go to the Downloads folder, which then opens in Finder or Explorer.
* macOS: menu bar with Edit (copy, paste, select all) and Window menus; Dock icon.
* Linux keeps opening the browser, so it needs no extra libraries. `--browser` opens the browser on every system; if the web view cannot start, CIPHERIS falls back to the browser.

### Tests
* `cipheris --selftest`: a full round trip (picture in, message hidden, picture saved, message revealed) in the real window. CI runs it on macOS and Windows, and the release build runs it on the exact app that is shipped.
* `cargo deny` and `tools/audit_lock.py` check the crates that the release builds contain.

## 0.3.0 (2026-11-17): German and Turkish

### Interface
* New: the interface speaks German, Turkish and English. It starts in the language of the system or browser and can be switched in the title bar (DE, TR, EN). The choice is kept only in memory, like everything else.
* Error messages from the local server are shown in the chosen language.
* README in German (`README.de.md`) and Turkish (`README.tr.md`).

### Project
* CI runs once per change, Dependabot groups its updates, major updates of Rust crates are done by hand.

## 0.2.0 (2026-10-29): SSS becomes CIPHERIS

Compatibility: pictures and keys made with SSS 0.1.0 open unchanged (pinned by a test). Keys with dashes and with spaces are both accepted.

### Security
* Fixed: the local server spawned one thread per connection without a limit. It now uses a fixed worker pool and answers 503 when full.
* Fixed: requests had no total deadline, so slow clients could hold workers. Head and body now have total deadlines.
* Fixed: the session token was passed in the URL query and kept in sessionStorage. A one time launch link (`/launch/<code>`, 2 minutes, one use) now sets an HttpOnly SameSite Strict cookie and redirects to the interface; it needs no JavaScript and no URL fragment.
* Fixed: a failing system random source caused a panic. It is now reported as an error.
* Fixed: request and response buffers holding messages or keys were not wiped.
* New: at most two image operations at once; strict HTTP parsing (single Host, no chunked encoding, no line folding); Permissions Policy; refusal to run as root.
* New: all access checks run on the request head, so a refused request never has its body read or buffered.
* New: duplicate `Origin`, `Cookie`, `X-Cipheris` and `Content-Length` headers are refused; the key field is limited to 256 bytes.
* New: lingering close, so error answers reach a browser that is still uploading.
* New: request head buffers and header values, including the session cookie, are wiped on every path.
* New: the page refuses machine translation and turns off spell checking, so browsers never send the message to an online service; writing assistants and password managers are asked to ignore the fields.
* New: official test vectors for Argon2id, XChaCha20 Poly1305 and BLAKE2b; randomized robustness tests; statistical tests of the placement; PSNR test; fuzzing targets.
* New: mutation fuzzing without a nightly compiler (`fuzz_campaign` for all parsers, `http_fuzz` for the server); SSIM in `stego_report`.
* New: CI with cargo deny, pinned actions, least privilege; releases with SHA256 checksums and an SBOM.
* New: compiler pinned to Rust 1.97.0 (`rust-toolchain.toml`); offline RustSec check of `Cargo.lock` (`tools/audit_lock.py`); CycloneDX SBOM generator (`tools/sbom.py`).

### Interface
* New terminal style interface in English, Obsidian Violet palette, IBM Plex Mono.
* Honest process log with values reported by the server; cancel button; masked key input with a show toggle; decryption animation that respects reduced motion.
* Key shown in groups separated by spaces.

### Packaging
* App icon from the CIPHERIS logo for macOS, Windows and Linux; `CIPHERIS.app` build script.

## 0.1.0 (2026-10-29): SSS
* First version: envelope, PNG embedding, local web interface.
