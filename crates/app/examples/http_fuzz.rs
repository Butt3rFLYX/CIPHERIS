//! Time boxed mutation fuzzing of the local server over real sockets.
//!
//!   cargo run --release -p cipheris --example http_fuzz -- 60
//!
//! Sends mutated versions of valid requests (launch link, assets, every API
//! endpoint) and checks after every batch that the server still answers a
//! valid request, that no mutated request without the session cookie ever
//! reaches the API, and that nothing crashes (release builds abort on panic).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use cipheris_app::{start, Config};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};

fn exchange(addr: SocketAddr, raw: &[u8]) -> Option<u16> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let _ = s.write_all(raw);
    let _ = s.shutdown(Shutdown::Write);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let head = String::from_utf8_lossy(out.get(..out.len().min(64))?).to_string();
    head.split(' ').nth(1)?.parse().ok()
}

fn mutate(rng: &mut ChaCha20Rng, input: &[u8]) -> Vec<u8> {
    let mut v = input.to_vec();
    for _ in 0..1 + rng.next_u32() % 5 {
        let len = v.len().max(1);
        let at = (rng.next_u32() as usize) % len;
        match rng.next_u32() % 8 {
            0 => {
                if let Some(b) = v.get_mut(at) {
                    *b ^= 1 << (rng.next_u32() % 8);
                }
            }
            1 => {
                let junk: &[u8] = [
                    &b"\r\n"[..],
                    b"\r\n\r\n",
                    b":",
                    b" ",
                    b"\0",
                    b"\n",
                    b"%2e%2e/",
                    b"Content-Length: 99999999999\r\n",
                    b"Transfer-Encoding: chunked\r\n",
                    b"Host: 127.0.0.1\r\n",
                    b"Origin: null\r\n",
                    b"Cookie: x=y\r\n",
                ][(rng.next_u32() % 12) as usize];
                let at = at.min(v.len());
                v.splice(at..at, junk.iter().copied());
            }
            2 => {
                let n = (1 + (rng.next_u32() % 32) as usize).min(v.len().saturating_sub(at));
                v.drain(at..at + n);
            }
            3 => v.truncate(at),
            4 => {
                let n = (rng.next_u32() % 64) as usize;
                v.extend((0..n).map(|_| rng.next_u32() as u8));
            }
            5 => {
                let n = (1 + (rng.next_u32() % 128) as usize).min(v.len().saturating_sub(at));
                let copy = v[at..at + n].to_vec();
                v.splice(at..at, copy);
            }
            6 => {
                if let Some(b) = v.get_mut(at) {
                    *b = b.to_ascii_lowercase();
                }
            }
            _ => {
                if let Some(b) = v.get_mut(at) {
                    *b = rng.next_u32() as u8;
                }
            }
        }
    }
    v
}

fn main() {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let cfg = Config {
        head_timeout: Duration::from_millis(300),
        body_timeout: Duration::from_millis(500),
        idle_shutdown: None,
        ..Config::default()
    };
    let running = start(cfg).unwrap();
    let addr = running.addr;
    let code = running
        .launch_url()
        .unwrap()
        .split("/launch/")
        .nth(1)
        .unwrap()
        .to_string();

    // Corpus: valid requests, the last ones with a valid session.
    let launch = format!("GET /launch/{code} HTTP/1.1\r\nHost: {addr}\r\n\r\n");
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(launch.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let cookie = out
        .lines()
        .find_map(|l| l.strip_prefix("Set-Cookie: "))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let api = |path: &str, body: &[u8]| {
        let mut r = format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nX-Cipheris: 1\r\nCookie: {cookie}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        r.extend_from_slice(body);
        r
    };
    let tiny_png = {
        let mut out = Vec::new();
        let mut enc = png::Encoder::new(&mut out, 4, 4);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        let mut wr = enc.write_header().unwrap();
        wr.write_image_data(&[90u8; 48]).unwrap();
        wr.finish().unwrap();
        out
    };
    let mut framed = 1u32.to_be_bytes().to_vec();
    framed.push(b'x');
    framed.extend_from_slice(&tiny_png);
    let corpus: Vec<Vec<u8>> = vec![
        format!("GET / HTTP/1.1\r\nHost: {addr}\r\n\r\n").into_bytes(),
        format!("GET /style.css HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\n\r\n")
            .into_bytes(),
        launch.into_bytes(),
        api("/api/status", b""),
        api("/api/ping", b""),
        api("/api/capacity", &tiny_png),
        api("/api/hide", &framed),
        api("/api/reveal", &framed),
    ];
    let health = api("/api/status", b"");

    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    let started = Instant::now();
    let mut n = 0u64;
    let mut statuses = std::collections::BTreeMap::new();
    while started.elapsed() < Duration::from_secs(secs) {
        let base = &corpus[(rng.next_u32() as usize) % corpus.len()];
        let input = mutate(&mut rng, base);
        let status = exchange(addr, &input);
        *statuses.entry(status).or_insert(0u64) += 1;
        // Without the exact session cookie no API endpoint may answer 2xx.
        let text = String::from_utf8_lossy(&input);
        if status.is_some_and(|s| (200..300).contains(&s)) && text.contains("/api/") {
            assert!(
                text.contains(&cookie),
                "API answered without the session cookie:\n{text}"
            );
        }
        n += 1;
        if n.is_multiple_of(500) {
            assert_eq!(
                exchange(addr, &health),
                Some(200),
                "server stopped answering after {n} inputs"
            );
        }
    }
    assert_eq!(exchange(addr, &health), Some(200));
    println!("http         {n:>10} requests in {secs} s, server healthy, statuses {statuses:?}");
}
