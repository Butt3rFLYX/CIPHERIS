//! Who may talk to the local server.
//!
//! * The app opens a one time launch link, `/launch/<code>`. The server
//!   trades the code for a session cookie (`HttpOnly`, `SameSite=Strict`, no
//!   expiry) and redirects to `/`. The code works exactly once and only for
//!   [`LAUNCH_CODE_TTL`], so the link left in the browser history unlocks
//!   nothing. `Referrer-Policy: no-referrer` keeps it out of `Referer`.
//! * JavaScript never sees the session secret; it is never stored in browser
//!   storage or put in a URL.
//! * Every API call additionally needs the same origin `Origin` header and a
//!   custom `X-Cipheris` header, which browsers refuse to send cross site
//!   without a CORS preflight that this server never grants.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

pub const LAUNCH_CODE_TTL: Duration = Duration::from_secs(120);

pub struct Session {
    pub host: String,
    pub origin: String,
    pub cookie_name: String,
    token: Zeroizing<String>,
    launch_code: Mutex<Option<(Zeroizing<String>, Instant)>>,
    started: Instant,
    last_seen: AtomicU64,
}

fn random_hex() -> Option<Zeroizing<String>> {
    let mut b = Zeroizing::new([0u8; 32]);
    OsRng.try_fill_bytes(&mut b[..]).ok()?;
    let mut s = Zeroizing::new(String::with_capacity(64));
    for byte in b.iter() {
        s.push_str(&format!("{byte:02x}"));
    }
    Some(s)
}

/// Constant time comparison for secrets.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Session {
    /// Fails only if the system random source fails.
    pub fn new(port: u16) -> Option<Self> {
        let code = random_hex()?;
        Some(Self {
            host: format!("127.0.0.1:{port}"),
            origin: format!("http://127.0.0.1:{port}"),
            cookie_name: format!("cipheris_{port}"),
            token: random_hex()?,
            launch_code: Mutex::new(Some((code, Instant::now()))),
            started: Instant::now(),
            last_seen: AtomicU64::new(0),
        })
    }

    /// The launch code, for the launch URL. Only readable while unused.
    pub fn launch_code(&self) -> Option<Zeroizing<String>> {
        let guard = self.launch_code.lock().ok()?;
        guard.as_ref().map(|(c, _)| c.clone())
    }

    /// Trades the launch code for the session cookie. Works once.
    pub fn redeem(&self, code: &[u8]) -> Option<String> {
        let mut guard = self.launch_code.lock().ok()?;
        let (stored, issued) = guard.as_ref()?;
        if issued.elapsed() > LAUNCH_CODE_TTL || !ct_eq(stored.as_bytes(), code) {
            return None;
        }
        *guard = None;
        self.touch();
        Some(format!(
            "{}={}; Path=/; HttpOnly; SameSite=Strict",
            self.cookie_name,
            self.token.as_str()
        ))
    }

    /// True if the `Cookie` header carries this session.
    pub fn authorized(&self, cookie_header: Option<&str>) -> bool {
        let Some(header) = cookie_header else {
            return false;
        };
        header.split(';').any(|pair| {
            pair.trim().split_once('=').is_some_and(|(k, v)| {
                k == self.cookie_name && ct_eq(v.as_bytes(), self.token.as_bytes())
            })
        })
    }

    pub fn touch(&self) {
        self.last_seen
            .store(self.started.elapsed().as_secs(), Ordering::Relaxed);
    }

    pub fn idle_for(&self) -> Duration {
        let now = self.started.elapsed().as_secs();
        Duration::from_secs(now.saturating_sub(self.last_seen.load(Ordering::Relaxed)))
    }
}
