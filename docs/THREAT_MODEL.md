# CIPHERIS threat model

Status: version 0.2.0, 29 October 2026. A measure counts as implemented only when code and a test exist; the evidence for each one is in [SECURITY_REVIEW.md](SECURITY_REVIEW.md).

## 1. Two separate questions

1. **Confidentiality and integrity:** can an attacker read or silently change the message?
2. **Concealment:** can an attacker tell, or guess with better than even odds, that a picture carries a message at all?

They are measured separately and never traded against each other. Strong encryption does not make a statistically visible picture invisible, and a detected picture is still unreadable without the key.

Kerckhoffs' principle applies: the attacker knows the source code, the file format and all defaults. Only the key, and what is derived from it, is secret.

## 2. Assumptions

* CIPHERIS runs locally and needs no network for any feature.
* Supported carriers are PNG files; other formats are converted to PNG in the browser before hiding.
* Recovery is promised only for byte identical transport of the PNG CIPHERIS wrote.
* The attacker can read, copy, compare, modify, replace and resubmit files, own any number of installations, and guess keys offline.
* Operating system, CPU, system random source and the official binary are trusted in the primary model. A fully compromised computer is analysed but outside what CIPHERIS can protect.

## 3. Security goals

| Goal | Meaning | Priority | Kind of promise |
| --- | --- | --- | --- |
| Confidentiality | no access to the text without the key | critical | cryptographic, given a safe computer |
| Integrity | any change to hidden data is detected | critical | AEAD and strict parsing, tested |
| Fail closed | never show unauthenticated or partial text | critical | tested |
| Resource limits | hostile input cannot exhaust CPU, memory or threads | high | limits and attack tests |
| Concealment | hiding changes the picture as little as possible | high | empirical only, dataset dependent |
| Metadata privacy | no names, paths, EXIF or GPS leak through the output | high | tested |
| Robustness | recovery after defined changes | low | only byte identical transport is supported |

## 4. Assets

| Asset | Where it lives | Main threats | Protection |
| --- | --- | --- | --- |
| Message text | text field, request body, server memory, revealed text | logging, swap, crash dumps, malware, browser features that send text to online services (translation, enhanced spell check, writing assistants) | never logged or stored; buffers wiped after use; shown only after authentication; page marked as not translatable, spell checking off, opt out attributes for writing assistants |
| Key | server memory, response header, key block, clipboard if copied | shoulder surfing, clipboard managers, malware | 128 bit random; masked input when revealing; never in URLs or browser storage; wiped buffers |
| Derived keys (KEK, data key, placement seed) | server memory only | memory disclosure | short lived, wiped on drop, domain separated |
| Envelope | inside the picture | tampering, truncation, offline guessing | authenticated header and payload; 128 bit key makes guessing infeasible |
| Original picture | user's disk, browser | known cover comparison, metadata | never modified; metadata dropped from output; advice not to share it |
| Output picture | user's disk, transport | steganalysis, compression | LSB matching at key dependent positions, low default rates, warnings |
| Session secret | HttpOnly cookie | cross site requests, other local programs | one time launch link (2 minutes, one use), SameSite Strict cookie, Origin and custom header checks |
| Existence of a message | statistics of the picture | classifiers, correlation of many files | no fixed marker, fresh key per message; no absolute promise |

## 5. Trust boundaries

1. **Browser to local server.** Every API call needs the session cookie, the exact origin and a custom header; the host must be `127.0.0.1:<port>`. All of this is checked on the request head, so a refused request never gets its body read.
2. **File to decoder.** All bytes are hostile until size, dimensions and format are checked; decoding is bounded and never panics.
3. **Extracted bits to crypto core.** Extracted data is untrusted until AEAD authentication succeeds.
4. **App to operating system.** Random numbers, memory and process isolation depend on the OS.
5. **App window (macOS, Windows).** The system web view runs in private mode (no history, cache or cookies on disk), may navigate only to the local server and its own `blob:` addresses, opens no new windows and has no developer tools. Saved pictures go to the Downloads folder.
5. **Build system to release.** Locked dependencies, pinned CI actions, checksums and an SBOM reduce, but do not remove, supply chain risk.

## 6. Scenarios

**A. The attacker has only the output picture.** They see size, dimensions and pixel statistics. Without the key, positions and the length are unknown and the extracted bits look random. Classifiers can still detect embedding, especially at high rates. Content stays protected: the key has 128 bits, so offline guessing is infeasible.

**B. The attacker knows the source code.** This is the normal assumption. Remaining risk lies in implementation bugs and dependencies; countermeasures are official test vectors, an independent decoder, fuzzing targets, strict lints and dependency checks.

**C. The attacker has the original and the output.** A comparison reveals the changed values and roughly the payload size. Concealment is lost; confidentiality is not, because the envelope remains encrypted under a 128 bit key. CIPHERIS advises using each picture once and not sharing the original.

**D. The attacker modifies the picture.** Every bit flip in the payload, truncation, extension or substitution is rejected as "No message found". The attacker can always destroy availability.

**E. The attacker collects many pictures.** Every message has a fresh key, so positions, salts, nonces and data keys never repeat. Camera, size and timing patterns remain correlatable.

**F. A service recompresses the picture.** Messengers, social networks and image hosts usually change pixels; the message is then lost and reported as not found. Only byte identical transport is supported, and the interface says so.

**G. The computer is compromised.** Malware can read the screen, keystrokes, clipboard and process memory. CIPHERIS cannot protect against this and does not claim to. Browser extensions with access to all sites count as part of this scenario; the app window on macOS and Windows has none.

**H. The attacker controls input files.** Oversized files, decompression bombs, bad checksums, truncated chunks, extreme dimensions and hostile envelope parameters are rejected before expensive work. Paths never reach the file system because the server serves only compiled in assets.

**I. Hostile web pages or local programs talk to the server.** Cross site requests fail the Origin, custom header and SameSite checks; DNS rebinding fails the Host check; the one time launch code cannot be replayed from browser history. Other programs running as the same user on the same computer are outside the model (scenario G).

**J. Resource exhaustion through the local server.** A fixed worker pool, a short queue, total request deadlines, body limits per endpoint and at most two concurrent image operations keep the server responsive; excess connections receive 503. Without the session no body is read at all, so only the unlocked page can make the server hold large uploads. Measured peak memory is about 250 MiB for a 12 megapixel photo and 512 MiB at the 40 megapixel limit, so two parallel operations stay near 1 GiB.

## 7. Covered, partly covered, out of scope

**Covered:** confidentiality with a safe computer; detection of every tested change; no unauthenticated output; rejection of unknown versions and dangerous parameters; byte exact recovery from unchanged PNGs; metadata removal; cross site and rebinding protection; bounded resources.

**Partly covered, measured where possible:** statistical concealment (see SECURITY_REVIEW.md section 2 for the measurement); memory wiping (best effort); timing side channels (comparisons of secrets are constant time, the primitives are the libraries' responsibility).

**Out of scope:** compromised computer, firmware or random source; coercion; guaranteed undetectability or deniability; recovery after arbitrary changes; forensic deletion; network and social metadata outside the file.

## 8. Error handling

| Event | What the user sees | Never |
| --- | --- | --- |
| wrong key, changed picture, no message | one message: "No message found" | partial text, the reason for the failure |
| typo in the key | "This key contains a typo" (says nothing about the picture) | an attempt to decrypt |
| unreadable or oversized file | a plain explanation and the limit | a crash, an attempt to repair |
| server busy | "busy, try again" | unbounded queues or threads |
| session lost | "Start CIPHERIS again" | silent failure |
