//! CIPHERIS local server: serves the interface and the API on
//! `127.0.0.1:<random port>` only.
//!
//! Protection of the local bridge, in the order a request meets it:
//!
//! 1. Bound to the loopback address, never to other interfaces.
//! 2. A fixed pool of worker threads and a short queue; a connection that
//!    does not fit is answered `503` at once instead of spawning a thread.
//! 3. Strict request parsing with size limits and total deadlines
//!    ([`http`]), so slow clients cannot hold a worker.
//! 4. `Host` must be exactly `127.0.0.1:<port>` (blocks DNS rebinding); a
//!    present `Origin` must be exactly this origin.
//! 5. The interface is unlocked once through a one time launch link; every
//!    API call then needs the session cookie, the same origin `Origin`
//!    header and the custom `X-Cipheris` header ([`session`]).
//!    Checks 4 and 5 run on the request head, before any body is read.
//! 6. At most two image operations run at once.
//! 7. Strict Content Security Policy and no caching on every response.

#![forbid(unsafe_code)]

mod api;
mod assets;
mod http;
mod session;

use std::io::Read;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use http::{Admit, Incoming, Method, ReadError, Request, Response};
use session::Session;

/// Server settings. [`Config::default`] is what the app uses.
#[derive(Clone, Debug)]
pub struct Config {
    /// Port to bind, 0 for a random free port.
    pub port: u16,
    /// Worker threads handling connections.
    pub workers: usize,
    /// Connections waiting for a worker before new ones get `503`.
    pub queue: usize,
    /// Image operations allowed at the same time.
    pub heavy_slots: usize,
    /// Total time allowed to receive the request head.
    pub head_timeout: Duration,
    /// Total time allowed to receive the request body.
    pub body_timeout: Duration,
    /// Quit after this long without contact from an open tab.
    pub idle_shutdown: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 0,
            workers: 8,
            queue: 16,
            heavy_slots: 2,
            head_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(60),
            idle_shutdown: Some(Duration::from_secs(6 * 60)),
        }
    }
}

/// Why the server could not start.
#[derive(Debug)]
pub enum StartError {
    /// The loopback port could not be bound.
    Bind(std::io::Error),
    /// The system random source failed.
    Random,
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::Bind(e) => write!(f, "could not open a local port: {e}"),
            StartError::Random => f.write_str("the system random source is not available"),
        }
    }
}

/// A started server.
pub struct Running {
    /// Bound address.
    pub addr: SocketAddr,
    session: Arc<Session>,
    shutdown: Receiver<()>,
}

impl Running {
    /// The URL that opens the interface: a one time launch link. Opening it
    /// sets the session cookie and redirects to `/`; afterwards the link is
    /// useless, so a copy in the browser history unlocks nothing.
    pub fn launch_url(&self) -> Option<String> {
        self.session
            .launch_code()
            .map(|c| format!("http://{}/launch/{}", self.session.host, c.as_str()))
    }

    /// Blocks until the interface asks to quit or the idle timeout fires.
    pub fn wait(&self) {
        let _ = self.shutdown.recv();
    }
}

struct Server {
    cfg: Config,
    session: Arc<Session>,
    heavy: api::HeavySlots,
    shutdown: Mutex<SyncSender<()>>,
}

/// Binds to loopback and starts the acceptor, the workers and the watchdog.
pub fn start(cfg: Config) -> Result<Running, StartError> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], cfg.port)))
        .map_err(StartError::Bind)?;
    let addr = listener.local_addr().map_err(StartError::Bind)?;
    let session = Arc::new(Session::new(addr.port()).ok_or(StartError::Random)?);
    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel(1);
    let server = Arc::new(Server {
        heavy: api::HeavySlots::new(cfg.heavy_slots),
        session: Arc::clone(&session),
        shutdown: Mutex::new(shutdown_tx),
        cfg,
    });

    let (tx, rx) = mpsc::sync_channel::<TcpStream>(server.cfg.queue);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..server.cfg.workers.max(1) {
        let rx = Arc::clone(&rx);
        let server = Arc::clone(&server);
        thread::spawn(move || loop {
            let next = match rx.lock() {
                Ok(guard) => guard.recv(),
                Err(_) => return,
            };
            match next {
                Ok(stream) => server.handle(stream),
                Err(_) => return,
            }
        });
    }

    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            match tx.try_send(stream) {
                Ok(()) => {}
                Err(TrySendError::Full(mut s)) => {
                    // Answer at once and never wait on this connection, so a
                    // flood cannot slow the acceptor down.
                    let _ = s.set_write_timeout(Some(Duration::from_secs(1)));
                    let _ = http::write_response(&mut s, &api::busy());
                    let _ = s.shutdown(Shutdown::Write);
                }
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
    });

    if let Some(idle) = server.cfg.idle_shutdown {
        let server = Arc::clone(&server);
        let tick = (idle / 4).clamp(Duration::from_millis(50), Duration::from_secs(5));
        thread::spawn(move || loop {
            thread::sleep(tick);
            if server.session.idle_for() > idle {
                server.quit();
                return;
            }
        });
    }

    Ok(Running {
        addr,
        session,
        shutdown: shutdown_rx,
    })
}

impl Server {
    fn quit(&self) {
        if let Ok(tx) = self.shutdown.lock() {
            let _ = tx.try_send(());
        }
    }

    fn handle(&self, mut stream: TcpStream) {
        let resp = match http::read_request(
            &mut stream,
            self.cfg.head_timeout,
            self.cfg.body_timeout,
            |head| self.admit(head),
        ) {
            Ok(Incoming::Complete(req)) => self.route(&req),
            Ok(Incoming::Refused(resp)) => resp,
            Err(ReadError::Gone) => return,
            Err(ReadError::BadRequest) => Response::text(400, "Bad request."),
            Err(ReadError::MethodNotAllowed) => Response::text(405, "Method not allowed."),
            Err(ReadError::LengthRequired) => Response::text(411, "Length required."),
            Err(ReadError::TooLarge) => Response::text(413, "The file is larger than 100 MB."),
            Err(ReadError::HeadTooLarge) => Response::text(431, "Request header too large."),
        };
        let _ = http::write_response(&mut stream, &resp);
        linger(&mut stream);
    }

    /// Runs every access check on the request head, before any body byte is
    /// read, and sets the body limit for requests that pass. So a hostile
    /// page or program can never make the server read or buffer a body.
    fn admit(&self, req: &Request) -> Admit {
        let s = &self.session;
        if req.header("host") != Some(s.host.as_str()) {
            return Admit::Refuse(Response::text(421, "Wrong host."));
        }
        let origin = req.header("origin");
        if origin.is_some_and(|o| o != s.origin) {
            return Admit::Refuse(Response::text(
                403,
                "Requests from other sites are refused.",
            ));
        }
        match req.method {
            Method::Get => Admit::Body(0),
            Method::Post if req.path.starts_with("/api/") => {
                // Browsers always send Origin on POST; anything without it is
                // not our page.
                if origin.is_none() || req.header("x-cipheris") != Some("1") {
                    return Admit::Refuse(Response::text(
                        403,
                        "Requests from other sites are refused.",
                    ));
                }
                if !s.authorized(req.header("cookie")) {
                    return Admit::Refuse(Response::text(
                        401,
                        "This session has ended. Start CIPHERIS again.",
                    ));
                }
                Admit::Body(api::body_limit(&req.path))
            }
            Method::Post => Admit::Refuse(Response::text(404, "Not found.")),
        }
    }

    /// Answers a request that passed [`Server::admit`] and was read in full.
    fn route(&self, req: &Request) -> Response {
        match (req.method, req.path.as_str()) {
            (Method::Get, path) if path.starts_with("/launch/") => self.launch(req, path),
            (Method::Get, path) => match assets::lookup(path) {
                Some(a) => Response::new(200, a.content_type, a.bytes.to_vec()),
                None => Response::text(404, "Not found."),
            },
            (Method::Post, path) if path.starts_with("/api/") => {
                self.session.touch();
                self.api(path, &req.body)
            }
            _ => Response::text(404, "Not found."),
        }
    }

    /// `GET /launch/<code>`: trades the one time launch code for the session
    /// cookie and redirects to the interface. A second visit with the cookie
    /// already set (for example a duplicate navigation) just redirects.
    fn launch(&self, req: &Request, path: &str) -> Response {
        let s = &self.session;
        let code = path.trim_start_matches("/launch/");
        if code.len() != 64 || !code.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Response::text(404, "Not found.");
        }
        match s.redeem(code.as_bytes()) {
            Some(cookie) => Response::redirect("/").header("Set-Cookie", cookie),
            None if s.authorized(req.header("cookie")) => Response::redirect("/"),
            None => Response::text(
                401,
                "This launch link was already used or has expired. Start CIPHERIS again.",
            ),
        }
    }

    fn api(&self, path: &str, body: &[u8]) -> Response {
        let idle_minutes = self.cfg.idle_shutdown.map_or(0, |d| d.as_secs() / 60);
        match path {
            "/api/status" => api::status(idle_minutes),
            "/api/ping" => Response::empty(204),
            "/api/quit" => {
                self.quit();
                Response::empty(204)
            }
            "/api/capacity" | "/api/hide" | "/api/reveal" => {
                let Some(_slot) = self.heavy.try_acquire() else {
                    return api::busy();
                };
                match path {
                    "/api/capacity" => api::capacity(body),
                    "/api/hide" => api::hide(body),
                    _ => api::reveal(body),
                }
            }
            _ => Response::text(404, "Not found."),
        }
    }
}

/// "Lingering close": after answering, stop sending and read away what the
/// client may still be sending (at most 256 KiB, at most 200 ms). Closing a
/// socket with unread data makes many TCP stacks send a reset, which can
/// destroy the answer before the client reads it; error answers to requests
/// that were not read completely would then never arrive.
fn linger(stream: &mut TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let deadline = std::time::Instant::now() + Duration::from_millis(200);
    let mut buf = [0u8; 8192];
    let mut total = 0usize;
    while total < 256 * 1024 && std::time::Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
}
