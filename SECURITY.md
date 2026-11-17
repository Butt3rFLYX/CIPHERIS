# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not include real messages, keys or private pictures. You will get an answer within 14 days. Confirmed issues are fixed in a new release and listed in CHANGELOG.md.

## What is in scope

* the encryption envelope (`crates/core`)
* the picture embedding layer (`crates/stego`)
* the local server and the interface (`crates/app`)
* the release workflow and packaging

## Guarantees and their limits

* **Fail closed.** A wrong key, a changed picture or a picture without a message produce no text, only "No message found".
* **Bounded work.** Sizes, pixel counts, Argon2 costs, connections, request time and concurrent image operations are limited before expensive work starts.
* **Local only.** The server listens on 127.0.0.1, accepts only its own page (Host, Origin, custom header, and a one time launch link that sets an HttpOnly SameSite Strict cookie, all checked before any request body is read) and never touches the file system.
* **No accidental sharing through the browser.** The page refuses machine translation, turns off spell checking and asks writing assistants and password managers to ignore its fields, because these features can send text to online services.
* **No storage.** CIPHERIS logs no content and keeps nothing in browser storage. The only file it writes is the picture you save: the app window puts it into your Downloads folder, a browser saves it where you choose. The app window runs the web view in private mode, so nothing is cached on disk.

Known limitations:

* Statistical undetectability is not guaranteed. See docs/SECURITY_REVIEW.md section 2 for what was measured.
* Wiping memory reduces exposure but cannot reach registers, swap, hibernation files, crash dumps or the memory of the web view or browser.
* In a browser (Linux, or `--browser`), extensions that can read all sites can read the CIPHERIS page, including keys and messages. Use a browser profile without extensions for sensitive use. The app window on macOS and Windows has no extensions.
* Copied keys may be kept by clipboard managers.
* The opt out attributes for writing assistants and password managers are the ones used by common tools (Grammarly, LanguageTool, 1Password, LastPass, Bitwarden, Dashlane). They are requests, not enforcement, and were not tested with each tool.
* XChaCha20 Poly1305 is not key committing. Because keys are random and decryption happens locally without an oracle, partitioning attacks do not apply in this design.
* No external audit has happened yet.

## Safe defaults

| Setting | Default | Why |
| --- | --- | --- |
| Hard limit for the share of changed values | 25 % | beyond this, detection becomes easy |
| Warning threshold | 5 % | the interface warns above it |
| Launch code lifetime | 2 minutes, one use | an old address from browser history is useless |
| Idle shutdown | 6 minutes after the last tab | no forgotten background server |
| Concurrent image operations | 2 | memory stays bounded |
| Running as root on Unix | refused | needs the explicit flag `--allow-root` |

## Updates

Download new versions only from the repository's Releases page and compare the file with `SHA256SUMS.txt` from the same release. CIPHERIS never updates itself and never connects to the internet.
