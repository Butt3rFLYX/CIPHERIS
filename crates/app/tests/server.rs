//! End to end tests of the local server's protections, using raw sockets.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use cipheris_app::{start, Config, Running};

struct Reply {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    }
}

fn send(addr: SocketAddr, raw: &[u8]) -> Reply {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(raw).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let split = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no response head");
    let head = String::from_utf8_lossy(&out[..split]).to_string();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    Reply {
        status,
        head,
        body: out[split + 4..].to_vec(),
    }
}

fn get(addr: SocketAddr, path: &str, extra: &str) -> Reply {
    send(
        addr,
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{extra}\r\n").as_bytes(),
    )
}

fn post(addr: SocketAddr, path: &str, extra: &str, body: &[u8]) -> Reply {
    let mut raw = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n{extra}\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(body);
    send(addr, &raw)
}

fn origin(addr: SocketAddr) -> String {
    format!("Origin: http://{addr}\r\nX-Cipheris: 1\r\n")
}

fn server(cfg: Config) -> (Running, SocketAddr, String) {
    let r = start(cfg).unwrap();
    let url = r.launch_url().unwrap();
    let code = url.split("/launch/").nth(1).unwrap().to_string();
    let addr = r.addr;
    (r, addr, code)
}

fn login(addr: SocketAddr, code: &str) -> String {
    let r = get(addr, &format!("/launch/{code}"), "");
    assert_eq!(r.status, 303);
    let cookie = r.header("set-cookie").unwrap();
    cookie.split(';').next().unwrap().to_string()
}

fn api(addr: SocketAddr, cookie: &str) -> String {
    format!("{}Cookie: {cookie}\r\n", origin(addr))
}

#[test]
fn serves_the_interface_with_strict_headers() {
    let (_r, addr, _) = server(Config::default());
    let r = get(addr, "/", "");
    assert_eq!(r.status, 200);
    assert!(r
        .header("content-security-policy")
        .unwrap()
        .contains("default-src 'none'"));
    assert_eq!(r.header("cache-control").unwrap(), "no-store");
    assert_eq!(r.header("x-frame-options").unwrap(), "DENY");
    for path in [
        "/app.js",
        "/style.css",
        "/favicon.svg",
        "/logo.svg",
        "/fonts/plex-mono-400.woff2",
    ] {
        assert_eq!(get(addr, path, "").status, 200, "{path}");
    }
}

#[test]
fn only_loopback_is_bound() {
    let (r, _, _) = server(Config::default());
    assert!(r.addr.ip().is_loopback());
}

#[test]
fn wrong_host_and_foreign_origin_are_refused() {
    let (_r, addr, code) = server(Config::default());
    let r = send(addr, b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n");
    assert_eq!(r.status, 421);
    let r = get(addr, "/", "Origin: http://evil.example\r\n");
    assert_eq!(r.status, 403);
    let r = get(
        addr,
        &format!("/launch/{code}"),
        "Origin: http://evil.example\r\n",
    );
    assert_eq!(r.status, 403);
    // The refused attempt did not use up the code.
    assert_eq!(get(addr, &format!("/launch/{code}"), "").status, 303);
}

#[test]
fn api_needs_origin_custom_header_and_session() {
    let (_r, addr, code) = server(Config::default());
    let cookie = login(addr, &code);
    let c = format!("Cookie: {cookie}\r\n");
    // Valid cookie, but no Origin.
    let no_origin = format!("X-Cipheris: 1\r\n{c}");
    assert_eq!(post(addr, "/api/status", &no_origin, b"").status, 403);
    // Valid cookie, but no custom header.
    let no_header = format!("Origin: http://{addr}\r\n{c}");
    assert_eq!(post(addr, "/api/status", &no_header, b"").status, 403);
    // No cookie.
    assert_eq!(post(addr, "/api/status", &origin(addr), b"").status, 401);
    // Wrong cookie.
    let fake = format!("{}Cookie: cipheris_{}=00\r\n", origin(addr), addr.port());
    assert_eq!(post(addr, "/api/status", &fake, b"").status, 401);
    // All three present.
    assert_eq!(
        post(addr, "/api/status", &api(addr, &cookie), b"").status,
        200
    );
}

#[test]
fn launch_link_works_exactly_once() {
    let (running, addr, code) = server(Config::default());
    let wrong = "0".repeat(64);
    assert_eq!(get(addr, &format!("/launch/{wrong}"), "").status, 401);
    assert_eq!(get(addr, "/launch/short", "").status, 404);
    assert_eq!(get(addr, &format!("/launch/{code}/x"), "").status, 404);
    let r = get(addr, &format!("/launch/{code}"), "");
    assert_eq!(r.status, 303);
    assert_eq!(r.header("location").unwrap(), "/");
    assert_eq!(r.header("referrer-policy").unwrap(), "no-referrer");
    let set = r.header("set-cookie").unwrap();
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Strict"),
        "{set}"
    );
    assert!(!set.contains("Max-Age") && !set.contains("Expires"));
    assert!(
        running.launch_url().is_none(),
        "the code must be gone after use"
    );
    // A second use without the cookie fails; with the cookie it only redirects.
    assert_eq!(get(addr, &format!("/launch/{code}"), "").status, 401);
    let cookie = set.split(';').next().unwrap().to_string();
    let again = get(
        addr,
        &format!("/launch/{code}"),
        &format!("Cookie: {cookie}\r\n"),
    );
    assert_eq!(again.status, 303);
    assert!(again.header("set-cookie").is_none());
    let r = post(addr, "/api/status", &api(addr, &cookie), b"");
    assert_eq!(r.status, 200);
    assert!(String::from_utf8_lossy(&r.body).contains("\"maxMessageBytes\":32768"));
}

#[test]
fn duplicate_security_headers_are_refused() {
    let (_r, addr, code) = server(Config::default());
    let cookie = login(addr, &code);
    for dup in [
        format!("Origin: http://{addr}\r\nOrigin: http://{addr}\r\nX-Cipheris: 1\r\nCookie: {cookie}\r\n"),
        format!("Origin: http://{addr}\r\nX-Cipheris: 1\r\nX-Cipheris: 1\r\nCookie: {cookie}\r\n"),
        format!("{}Cookie: {cookie}\r\n", api(addr, &cookie)),
    ] {
        assert_eq!(post(addr, "/api/status", &dup, b"").status, 400);
    }
    let raw = format!(
        "POST /api/status HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nContent-Length: 0\r\n{}\r\n",
        api(addr, &cookie)
    );
    assert_eq!(send(addr, raw.as_bytes()).status, 400);
}

#[test]
fn overlong_key_field_is_refused() {
    let (_r, addr, code) = server(Config::default());
    let cookie = login(addr, &code);
    let key = " ".repeat(10_000);
    let mut body = (key.len() as u32).to_be_bytes().to_vec();
    body.extend_from_slice(key.as_bytes());
    let r = post(addr, "/api/reveal", &api(addr, &cookie), &body);
    assert_eq!(r.status, 422);
    assert!(String::from_utf8_lossy(&r.body).contains("typo"));
}

#[test]
fn unsupported_methods_and_framing_are_refused() {
    let (_r, addr, _) = server(Config::default());
    for m in ["PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH"] {
        let r = send(
            addr,
            format!("{m} / HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes(),
        );
        assert_eq!(r.status, 405, "{m}");
    }
    let r = send(
        addr,
        format!("POST /api/status HTTP/1.1\r\nHost: {addr}\r\nTransfer-Encoding: chunked\r\n\r\n")
            .as_bytes(),
    );
    assert_eq!(r.status, 411);
    let r = send(
        addr,
        format!("POST /api/status HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes(),
    );
    assert_eq!(r.status, 411);
    let r = send(
        addr,
        format!("GET / HTTP/1.1\r\nHost: {addr}\r\nHost: {addr}\r\n\r\n").as_bytes(),
    );
    assert_eq!(r.status, 400);
    let r = send(addr, b"GET / HTTP/2.0\r\nHost: x\r\n\r\n");
    assert_eq!(r.status, 400);
    let r = send(
        addr,
        format!(
            "GET / HTTP/1.1\r\nHost: {addr}\r\nX: {}\r\n\r\n",
            "a".repeat(20_000)
        )
        .as_bytes(),
    );
    assert_eq!(r.status, 431);
}

#[test]
fn oversized_bodies_are_refused_before_reading() {
    let (_r, addr, code) = server(Config::default());
    let cookie = login(addr, &code);
    // Announce 2 GB but send nothing: the answer must come at once.
    let t = Instant::now();
    let r = send(
        addr,
        format!(
            "POST /api/hide HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 2000000000\r\n{}\r\n",
            api(addr, &cookie)
        )
        .as_bytes(),
    );
    assert_eq!(r.status, 413);
    assert!(t.elapsed() < Duration::from_secs(2));
    // GET requests may not carry a body.
    let r = send(
        addr,
        format!("GET / HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 5\r\n\r\nhello").as_bytes(),
    );
    assert_eq!(r.status, 413);
}

#[test]
fn refusal_reaches_a_client_that_is_still_uploading() {
    // A browser keeps sending the body after the server refused it. Without
    // a lingering close the unread bytes make the operating system reset
    // the connection, and on Windows the 413 answer is then lost. The test
    // therefore demands a clean end of the connection, not only the answer.
    let (_r, addr, code) = server(Config::default());
    let cookie = login(addr, &code);
    let mut raw = format!(
        "POST /api/hide HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 200000000\r\n{}\r\n",
        api(addr, &cookie)
    )
    .into_bytes();
    raw.extend(std::iter::repeat_n(7u8, 64 * 1024));
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(&raw).unwrap();
    let mut out = Vec::new();
    let end = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 413 "), "{text}");
    assert!(text.contains("larger than 100 MB"));
    assert!(end.is_ok(), "connection was reset: {end:?}");
}

#[test]
fn bodies_of_refused_requests_are_never_read() {
    // Access checks run on the head. A request that fails them is answered
    // at once, even when it announces a large body and never sends it, so
    // nobody without the session can make the server wait for or buffer a
    // body.
    let (_r, addr, code) = server(Config::default());
    let cookie = login(addr, &code);
    let head = |extra: &str| {
        format!(
            "POST /api/hide HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 50000000\r\n{extra}\r\n"
        )
    };
    let cases = [
        (head(&origin(addr)), 401),
        (
            head(&format!("{}Cookie: cipheris_1=00\r\n", origin(addr))),
            401,
        ),
        (
            head(&format!(
                "Origin: http://evil.example\r\nX-Cipheris: 1\r\nCookie: {cookie}\r\n"
            )),
            403,
        ),
        (
            head(&format!("Origin: http://{addr}\r\nCookie: {cookie}\r\n")),
            403,
        ),
        (head(&format!("Cookie: {cookie}\r\nX-Cipheris: 1\r\n")), 403),
        (
            format!(
                "POST /api/hide HTTP/1.1\r\nHost: localhost\r\nContent-Length: 50000000\r\n{}\r\n",
                api(addr, &cookie)
            ),
            421,
        ),
    ];
    for (raw, want) in cases {
        let t = Instant::now();
        let r = send(addr, raw.as_bytes());
        assert_eq!(r.status, want, "{raw}");
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "waited for a body: {raw}"
        );
    }
}

#[test]
fn no_path_reaches_the_file_system() {
    let (_r, addr, _) = server(Config::default());
    for p in [
        "/../../etc/passwd",
        "/%2e%2e/etc/passwd",
        "/ui/index.html",
        "/Cargo.toml",
        "/fonts/../app.js",
    ] {
        assert_eq!(get(addr, p, "").status, 404, "{p}");
    }
}

#[test]
fn slow_clients_are_cut_off() {
    let cfg = Config {
        head_timeout: Duration::from_millis(400),
        ..Config::default()
    };
    let (_r, addr, _) = server(cfg);
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: ").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let t = Instant::now();
    let mut buf = [0u8; 16];
    let n = s.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "server should close without answering");
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
}

/// Connects and reads without sending anything: the server answers 503 at
/// accept time when it is full, before any request bytes are expected.
fn read_only(addr: SocketAddr) -> Option<u16> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let head = String::from_utf8_lossy(&out).to_string();
    head.split(' ').nth(1)?.parse().ok()
}

#[test]
fn connection_floods_get_503_instead_of_threads() {
    let cfg = Config {
        workers: 2,
        queue: 1,
        head_timeout: Duration::from_secs(3),
        ..Config::default()
    };
    let (_r, addr, _) = server(cfg);
    std::thread::sleep(Duration::from_millis(200));
    // Idle connections occupy both workers and the queue.
    let idle: Vec<TcpStream> = (0..3)
        .map(|_| {
            let s = TcpStream::connect(addr).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            s
        })
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    let busy = (0..4).filter(|_| read_only(addr) == Some(503)).count();
    assert_eq!(
        busy, 4,
        "every extra connection must get 503 while workers and queue are full"
    );
    drop(idle);
    // Once the idle connections are gone, normal service resumes.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(get(addr, "/", "").status, 200);
}

#[test]
fn hide_and_reveal_through_the_api() {
    let (_r, addr, code) = server(Config::default());
    let cookie = login(addr, &code);
    let cover = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../stego/tests/fixtures/sss_v1.png"
    ))
    .unwrap();
    let r = post(addr, "/api/capacity", &api(addr, &cookie), &cover);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let msg = "API round trip ✓";
    let mut body = (msg.len() as u32).to_be_bytes().to_vec();
    body.extend_from_slice(msg.as_bytes());
    body.extend_from_slice(&cover);
    let r = post(addr, "/api/hide", &api(addr, &cookie), &body);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let key = r.header("x-cipheris-key").unwrap();
    assert_eq!(key.len(), 34);
    assert!(r.header("x-cipheris-bits").unwrap().parse::<u64>().unwrap() > 1000);
    let png = r.body;
    let mut body = (key.len() as u32).to_be_bytes().to_vec();
    body.extend_from_slice(key.as_bytes());
    body.extend_from_slice(&png);
    let r = post(addr, "/api/reveal", &api(addr, &cookie), &body);
    assert_eq!(r.status, 200);
    assert_eq!(String::from_utf8(r.body).unwrap(), msg);
    // A wrong key gives the one generic message.
    let wrong = "0000 0000 0000 0000 0000 0000 0000";
    let mut body = (wrong.len() as u32).to_be_bytes().to_vec();
    body.extend_from_slice(wrong.as_bytes());
    body.extend_from_slice(&png);
    let r = post(addr, "/api/reveal", &api(addr, &cookie), &body);
    assert_eq!(r.status, 422);
    // Malformed framing.
    assert_eq!(
        post(addr, "/api/hide", &api(addr, &cookie), &[0, 0, 0, 9]).status,
        400
    );
}

#[test]
fn quit_and_idle_shutdown_stop_the_server() {
    let (r, addr, code) = server(Config::default());
    let cookie = login(addr, &code);
    assert_eq!(
        post(addr, "/api/quit", &api(addr, &cookie), b"").status,
        204
    );
    r.wait();

    let cfg = Config {
        idle_shutdown: Some(Duration::from_millis(300)),
        ..Config::default()
    };
    let (r, _, _) = server(cfg);
    let t = Instant::now();
    r.wait();
    assert!(t.elapsed() < Duration::from_secs(5));
}
