//! CIPHERIS desktop app entry point.

#![forbid(unsafe_code)]
// Release builds on Windows start without a console window.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::process::{Command, ExitCode};

#[cfg(any(target_os = "macos", target_os = "windows"))]
mod window;

/// Where the interface is shown.
#[derive(PartialEq, Eq)]
enum Show {
    /// Own app window (macOS and Windows; falls back to the browser).
    Window,
    /// The default browser.
    Browser,
    /// Nothing; the address is only printed (tests, servers).
    Nothing,
}

fn main() -> ExitCode {
    let mut cfg = cipheris_app::Config::default();
    let mut show = if cfg!(any(target_os = "macos", target_os = "windows")) {
        Show::Window
    } else {
        Show::Browser
    };
    let mut self_test = false;
    let mut allow_root = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--no-browser" => show = Show::Nothing,
            "--browser" => show = Show::Browser,
            "--selftest" => {
                show = Show::Window;
                self_test = true;
            }
            "--stay" => cfg.idle_shutdown = None,
            "--allow-root" => allow_root = true,
            "--port" => cfg.port = args.next().and_then(|p| p.parse().ok()).unwrap_or(0),
            "--version" => {
                println!("CIPHERIS {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "-h" | "--help" => {
                println!(
                    "cipheris [--browser | --no-browser] [--port N] [--stay] [--allow-root] [--version]"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("Unknown option: {other}");
                return ExitCode::from(2);
            }
        }
    }

    if running_as_root() && !allow_root {
        eprintln!("CIPHERIS refuses to run with administrator rights. Start it as a normal user.");
        return ExitCode::from(1);
    }

    #[cfg_attr(
        not(any(target_os = "macos", target_os = "windows")),
        allow(unused_mut)
    )]
    let mut running = match cipheris_app::start(cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("CIPHERIS could not start: {e}");
            return ExitCode::from(1);
        }
    };
    let Some(url) = running.launch_url() else {
        eprintln!("CIPHERIS could not start: no launch code.");
        return ExitCode::from(1);
    };
    println!(
        "CIPHERIS is running on this computer only ({}).",
        running.addr
    );
    println!("If no window opens, open this address once in a browser:");
    println!("  {url}");
    println!("Quit with the button in the app, or press Ctrl+C here.");
    match show {
        Show::Nothing => {}
        Show::Browser => open_url(&url),
        Show::Window => {
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            match window::run(url.clone(), running, self_test) {
                Ok(never) => match never {},
                Err((why, back)) => {
                    eprintln!(
                        "The app window could not be opened ({why}). Using the browser instead."
                    );
                    if self_test {
                        return ExitCode::from(1);
                    }
                    running = back;
                }
            }
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            if self_test {
                eprintln!("The self test needs the app window (macOS or Windows).");
                return ExitCode::from(1);
            }
            open_url(&url);
        }
    }
    running.wait();
    ExitCode::SUCCESS
}

/// Opens the launch link in the default browser. The link contains only
/// `http`, `127.0.0.1`, digits, letters, `:` and `/`, so no shell quoting
/// issues arise on any platform. Each platform has a fallback.
fn open_url(url: &str) {
    #[cfg(target_os = "macos")]
    let tries: &[(&str, &[&str])] = &[("open", &[])];
    #[cfg(target_os = "windows")]
    let tries: &[(&str, &[&str])] = &[
        ("rundll32", &["url.dll,FileProtocolHandler"]),
        ("explorer", &[]),
    ];
    #[cfg(all(unix, not(target_os = "macos")))]
    let tries: &[(&str, &[&str])] = &[
        ("xdg-open", &[]),
        ("gio", &["open"]),
        ("sensible-browser", &[]),
    ];
    for (program, args) in tries {
        if Command::new(program).args(*args).arg(url).spawn().is_ok() {
            return;
        }
    }
    eprintln!("The browser could not be opened automatically.");
}

/// Detects an effective root user on Unix without unsafe code: a freshly
/// created file belongs to the effective user.
#[cfg(unix)]
fn running_as_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    let mut name = [0u8; 8];
    if rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, &mut name).is_err() {
        return false;
    }
    let file: String = name.iter().map(|b| format!("{b:02x}")).collect();
    let path = std::env::temp_dir().join(format!("cipheris_uid_check_{file}"));
    let uid = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|f| f.metadata())
        .map(|m| m.uid());
    let _ = std::fs::remove_file(&path);
    matches!(uid, Ok(0))
}

#[cfg(not(unix))]
fn running_as_root() -> bool {
    false
}
