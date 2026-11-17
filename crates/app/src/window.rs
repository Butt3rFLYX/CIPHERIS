//! The app window on macOS and Windows: the same local interface, shown in
//! the web view of the system (WKWebView, WebView2) instead of a browser tab.
//!
//! The window only ever shows the local server of this process. Navigation
//! to any other address and new windows are refused, browser extensions do
//! not exist here, and the web view keeps no history, cache or cookies on
//! disk (private mode). Saved images go to the Downloads folder, which is
//! then shown in Finder or Explorer.

use std::cell::RefCell;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::time::{Duration, Instant};

use cipheris_app::Running;
use tao::dpi::LogicalSize;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::{Theme, WindowBuilder};
use wry::{NewWindowResponse, PageLoadEvent, WebContext, WebViewBuilder};

/// Background of the interface, shown before the page has loaded.
const BACKGROUND: (u8, u8, u8, u8) = (11, 10, 18, 255);

/// How long the self test may take before it counts as failed.
const SELF_TEST_LIMIT: Duration = Duration::from_secs(120);

enum UserEvent {
    /// The server stopped (quit button or idle timeout).
    Stopped,
    /// A page finished loading.
    Loaded(String),
    /// A download finished.
    Saved(Option<PathBuf>, bool),
    /// Result reported by the self test script.
    SelfTest(String),
}

/// Opens the window and runs until it is closed. Returns only if the window
/// or the web view cannot be created; the caller then falls back to the
/// browser, so `running` is handed back.
pub fn run(
    url: String,
    running: Running,
    self_test: bool,
) -> Result<Infallible, (String, Running)> {
    let origin = match url.find("/launch/") {
        Some(i) => url[..=i].to_string(),
        None => return Err(("unexpected launch address".into(), running)),
    };

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let window = match WindowBuilder::new()
        .with_title("CIPHERIS")
        .with_inner_size(LogicalSize::new(980.0, 880.0))
        .with_min_inner_size(LogicalSize::new(400.0, 560.0))
        .with_theme(Some(Theme::Dark))
        .with_window_icon(window_icon())
        .build(&event_loop)
    {
        Ok(w) => w,
        Err(e) => return Err((e.to_string(), running)),
    };

    #[cfg(target_os = "macos")]
    let _menu = match mac_menu() {
        Ok(m) => m,
        Err(e) => return Err((e, running)),
    };

    let proxy = event_loop.create_proxy();
    let mut context = WebContext::new(data_dir());

    // The path of the most recent download, for the completion handler
    // (macOS does not report it there).
    let last_download: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
    let started = Rc::clone(&last_download);
    let finished = Rc::clone(&last_download);
    let saved_proxy = proxy.clone();
    let loaded_proxy = proxy.clone();
    let allowed = origin.clone();
    let blob = format!("blob:{origin}");

    let mut builder = WebViewBuilder::new_with_web_context(&mut context)
        .with_url(&url)
        .with_incognito(true)
        .with_devtools(false)
        .with_clipboard(true)
        .with_background_color(BACKGROUND)
        .with_navigation_handler(move |to: String| {
            to.starts_with(&allowed) || to.starts_with(&blob) || to == "about:blank"
        })
        .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
        .with_download_started_handler(move |_, path: &mut PathBuf| {
            *started.borrow_mut() = Some(path.clone());
            true
        })
        .with_download_completed_handler(move |_, path, ok| {
            let path = path.or_else(|| finished.borrow_mut().take());
            let _ = saved_proxy.send_event(UserEvent::Saved(path, ok));
        })
        .with_on_page_load_handler(move |event, at| {
            if matches!(event, PageLoadEvent::Finished) {
                let _ = loaded_proxy.send_event(UserEvent::Loaded(at));
            }
        });
    if self_test {
        let test_proxy = proxy.clone();
        builder = builder.with_ipc_handler(move |req| {
            let _ = test_proxy.send_event(UserEvent::SelfTest(req.body().clone()));
        });
    }
    let webview = match builder.build(&window) {
        Ok(v) => v,
        Err(e) => return Err((e.to_string(), running)),
    };

    // Close the window when the interface quits or the idle timer fires.
    let stop_proxy = proxy;
    std::thread::spawn(move || {
        running.wait();
        let _ = stop_proxy.send_event(UserEvent::Stopped);
    });

    let deadline = Instant::now() + SELF_TEST_LIMIT;
    let mut test = SelfTest::default();

    event_loop.run(move |event, _, control_flow| {
        // Keep these alive for as long as the loop runs.
        let _ = (&window, &context);
        #[cfg(target_os = "macos")]
        let _ = &_menu;

        *control_flow = if self_test {
            ControlFlow::WaitUntil(deadline)
        } else {
            ControlFlow::Wait
        };
        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::ExitWithCode(i32::from(self_test)),
            Event::UserEvent(UserEvent::Stopped) => {
                *control_flow = ControlFlow::ExitWithCode(i32::from(self_test));
            }
            Event::UserEvent(UserEvent::Loaded(at)) => {
                if self_test && !test.injected && at == origin {
                    test.injected = true;
                    if let Err(e) = webview.evaluate_script(SELF_TEST_JS) {
                        eprintln!("selftest: script failed: {e}");
                        *control_flow = ControlFlow::ExitWithCode(1);
                    }
                }
            }
            Event::UserEvent(UserEvent::Saved(path, ok)) => {
                if self_test {
                    test.saved = ok && path.as_deref().is_some_and(is_png_file);
                    if let Some(p) = path {
                        let _ = std::fs::remove_file(p);
                    }
                    eprintln!(
                        "selftest: download {}",
                        if test.saved { "ok" } else { "failed" }
                    );
                } else if ok {
                    if let Some(p) = path {
                        reveal(&p);
                    }
                }
            }
            Event::UserEvent(UserEvent::SelfTest(result)) => {
                eprintln!("selftest: {result}");
                test.result = Some(result);
            }
            Event::NewEvents(StartCause::ResumeTimeReached { .. }) if self_test => {
                eprintln!("selftest: timed out");
                *control_flow = ControlFlow::ExitWithCode(1);
            }
            _ => {}
        }
        if self_test {
            match test.result.as_deref() {
                Some("ok") if test.saved => *control_flow = ControlFlow::ExitWithCode(0),
                Some("ok") | None => {}
                Some(_) => *control_flow = ControlFlow::ExitWithCode(1),
            }
        }
    })
}

#[derive(Default)]
struct SelfTest {
    injected: bool,
    saved: bool,
    result: Option<String>,
}

fn is_png_file(path: &Path) -> bool {
    std::fs::read(path).is_ok_and(|b| b.starts_with(b"\x89PNG\r\n\x1a\n"))
}

/// The icon in the title bar and task bar on Windows. macOS takes the icon
/// from the app bundle.
fn window_icon() -> Option<tao::window::Icon> {
    #[cfg(target_os = "windows")]
    {
        let bytes: &[u8] =
            include_bytes!("../../../packaging/macos/AppIcon.iconset/icon_256x256.png");
        let mut decoder = png::Decoder::new(bytes);
        decoder.set_transformations(png::Transformations::EXPAND);
        let mut reader = decoder.read_info().ok()?;
        let mut rgba = vec![0; reader.output_buffer_size()];
        let info = reader.next_frame(&mut rgba).ok()?;
        if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
            return None;
        }
        rgba.truncate(info.buffer_size());
        tao::window::Icon::from_rgba(rgba, info.width, info.height).ok()
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

/// Where WebView2 keeps its working files (it needs a writable folder even
/// in private mode). macOS ignores this.
fn data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("CIPHERIS").join("WebView2"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

/// Shows a saved file in Finder or Explorer.
fn reveal(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg("-R").arg(path).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // Explorer expects `/select,"C:\path\file.png"` as one raw argument.
        let _ = Command::new("explorer")
            .raw_arg(format!("/select,\"{}\"", path.display()))
            .spawn();
    }
}

/// The menu bar on macOS. Without an Edit menu, copy and paste shortcuts do
/// not reach the web view.
#[cfg(target_os = "macos")]
fn mac_menu() -> Result<muda::Menu, String> {
    use muda::{Menu, PredefinedMenuItem as P, Submenu};
    let app = Submenu::with_items(
        "CIPHERIS",
        true,
        &[
            &P::about(None, None),
            &P::separator(),
            &P::hide(None),
            &P::hide_others(None),
            &P::show_all(None),
            &P::separator(),
            &P::quit(None),
        ],
    );
    let edit = Submenu::with_items(
        "Edit",
        true,
        &[
            &P::undo(None),
            &P::redo(None),
            &P::separator(),
            &P::cut(None),
            &P::copy(None),
            &P::paste(None),
            &P::select_all(None),
        ],
    );
    let win = Submenu::with_items(
        "Window",
        true,
        &[&P::minimize(None), &P::close_window(None)],
    );
    let (app, edit, win) = match (app, edit, win) {
        (Ok(a), Ok(e), Ok(w)) => (a, e, w),
        _ => return Err("menu could not be created".into()),
    };
    let menu = Menu::with_items(&[&app, &edit, &win]).map_err(|e| e.to_string())?;
    menu.init_for_nsapp();
    win.set_as_windows_menu_for_nsapp();
    Ok(menu)
}

/// Runs a full round trip in the real web view: load a generated picture,
/// hide a message, save the picture, reveal the message again. Used by CI on
/// macOS and Windows (`cipheris --selftest`).
const SELF_TEST_JS: &str = r#"
(async () => {
  const $ = (id) => document.getElementById(id);
  const until = async (ok, ms = 30000) => {
    const start = Date.now();
    while (!ok()) {
      if (Date.now() - start > ms) throw new Error("timeout");
      await new Promise((r) => setTimeout(r, 50));
    }
  };
  const setFile = (input, file) => {
    const dt = new DataTransfer();
    dt.items.add(file);
    input.files = dt.files;
    input.dispatchEvent(new Event("change"));
  };
  const message = "CIPHERIS selftest \u2713 \u00e4\u00f6\u00fc \u011f\u015f\u0131";
  try {
    await until(() => $("status-idle").textContent.length > 0);
    const c = document.createElement("canvas");
    c.width = 320;
    c.height = 240;
    const g = c.getContext("2d");
    const img = g.createImageData(c.width, c.height);
    for (let i = 0; i < img.data.length; i += 4) {
      img.data[i] = (i * 7) & 255;
      img.data[i + 1] = (i * 13) & 255;
      img.data[i + 2] = (i * 29) & 255;
      img.data[i + 3] = 255;
    }
    g.putImageData(img, 0, 0);
    const picture = await new Promise((r) => c.toBlob(r, "image/png"));
    setFile($("hide-file"), new File([picture], "selftest.png", { type: "image/png" }));
    await until(() => $("hide-drop").classList.contains("filled"));
    $("hide-text").value = message;
    $("hide-text").dispatchEvent(new Event("input"));
    // The page policy allows no fetch of blob: addresses, so keep the result
    // picture when the page turns it into a download link.
    let out = null;
    const createObjectURL = URL.createObjectURL;
    URL.createObjectURL = (b) => ((out = b), createObjectURL.call(URL, b));
    $("hide-go").click();
    await until(() => !$("hide-result").hidden, 60000);
    URL.createObjectURL = createObjectURL;
    const key = $("hide-key").textContent;
    if (!out) throw new Error("no result picture");
    $("hide-save").click();
    $("tab-reveal").click();
    setFile($("reveal-file"), new File([out], "selftest.png", { type: "image/png" }));
    await until(() => $("reveal-drop").classList.contains("filled"));
    $("reveal-key").value = key;
    $("reveal-key").dispatchEvent(new Event("input"));
    $("reveal-go").click();
    await until(() => $("reveal-text-sr").textContent === message, 60000);
    window.ipc.postMessage("ok");
  } catch (e) {
    const logs = ($("hide-log").textContent + " | " + $("reveal-log").textContent).slice(-300);
    window.ipc.postMessage("fail: " + e.message + " | " + logs);
  }
})();
"#;
