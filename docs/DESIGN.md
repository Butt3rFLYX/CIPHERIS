# CIPHERIS design

## Architecture

```
app window or browser tab (interface)
   │  fetch, same origin only, session cookie + X-Cipheris header
   ▼
cipheris (crates/app)          local server on 127.0.0.1:<random port>
   │  worker pool · deadlines · access checks on the head · body limits · 2 image slots
   ▼
cipheris_stego (crates/stego)  key format · PNG decode/encode · placement · LSB matching
   ▼
cipheris_core (crates/core)    envelope: Argon2id · XChaCha20 Poly1305 · limits
```

* **Why a local web interface?** It runs the same on macOS, Windows and Linux: the server uses only the Rust standard library, and the interface is plain HTML, CSS and JavaScript compiled into the binary. The web view sandboxes the interface; the security relevant work happens in Rust.
* **Why an app window on macOS and Windows?** The interface opens in its own window that uses the web view of the system (WebKit on macOS, Microsoft Edge WebView2 on Windows) through `tao`, `wry` and, for the macOS menu, `muda`. Browser extensions do not exist there, the web view runs in private mode and may only show the local server, and the app feels like an app. On Linux the interface opens in the browser, so no GTK or WebKitGTK libraries are needed; `--browser` does the same on every system, and if the web view cannot start, CIPHERIS falls back to the browser. `cipheris --selftest` runs a full round trip in the real window; CI and the release build run it on macOS and Windows.
* **Why generated keys only?** A 128 bit random key cannot be guessed, so a short key protects as well as any password could, and the embedding positions can be derived from it without storing a salt in the picture (no marker, see FORMAT.md).
* **Why LSB matching?** It changes the same number of values as LSB replacement, but in most photos it pulls pairs of values together much less, and that pull is what the classic chi square attack detects. Pictures with large pure white or pure black areas are an exception. See SECURITY_REVIEW.md for the measurements.

## Request flow

1. The app starts, binds a random loopback port and opens the one time launch link `http://127.0.0.1:<port>/launch/<code>` in its window (or the browser).
2. The server trades the code for an HttpOnly SameSite Strict cookie and redirects to `/` with `303 See Other`. The code then stops working, so the link left in the browser history is useless. The flow needs no JavaScript and no URL fragment, which makes it work the same with every browser and every way an operating system hands a link to the browser.
3. *Hide:* the browser converts non PNG pictures to PNG, posts them to `/api/capacity`, then `[length][message][png]` to `/api/hide`. The answer is the new PNG; the key and real statistics come in response headers.
4. *Reveal:* `[length][key][png]` to `/api/reveal`; the answer is the text, only after authentication.
5. The page pings every 20 seconds; the server stops six minutes after the last contact, or at once on *quit*.

## Interface design system

The full concept (logo usage, icons, colour contrast, typography, layout, components, motion and copy) is in the CIPHERIS design concept document. The implementation follows it:

| Token | Hex | Role |
| --- | --- | --- |
| void | #101019 | page, text on violet buttons |
| surface | #1C1A2A | terminal window |
| raised | #262338 | inputs |
| accent | #A78BFA | key, focus, main action, prompt sign |
| ink | #E4D8FF | text |
| dim | #9A94B4 | secondary text |
| edge | #726C94 | control borders |
| line | #34304A | dividers |
| danger | #FF7A90 | errors |
| warn | #F2C46D | warnings |

* One typeface, IBM Plex Mono 400 and 600, shipped with the app.
* One accent: violet always means secret or active.
* One signature motion: the decrypted text resolves out of random glyphs within at most 900 ms, and appears instantly with reduced motion.
* The log prints only steps the server confirmed, with real numbers.

Logo files are in `packaging/brand/`: `logo.svg` (primary, outline), `altlogo.svg` (solid, for light backgrounds) and `logo_small.svg` (below 48 px).
