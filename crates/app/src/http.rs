//! Minimal, strict HTTP/1.1 request reader and response writer.
//!
//! Only what the local interface needs: one request per connection,
//! `Content-Length` bodies, no chunked encoding, no keep alive. Every read has
//! a size limit and a total deadline, so a slow or malicious client cannot hold
//! a worker forever.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// Largest accepted request head (request line plus headers).
pub const MAX_HEAD: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

pub struct Request {
    pub method: Method,
    pub path: String,
    /// Values include the session cookie: wiped when dropped.
    headers: Vec<(String, Zeroizing<String>)>,
    /// May contain a message or a key: wiped when dropped.
    pub body: Zeroizing<Vec<u8>>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Why a request could not be read. Each maps to one status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// Connection closed or timed out before a full request arrived.
    Gone,
    BadRequest,
    MethodNotAllowed,
    LengthRequired,
    TooLarge,
    HeadTooLarge,
}

/// What the caller decides once the request head is known.
pub enum Admit {
    /// Read a body of at most this many bytes.
    Body(usize),
    /// Answer at once; the body is never read.
    Refuse(Response),
}

/// A request that was read completely, or the answer to one that was
/// refused after its head.
pub enum Incoming {
    Complete(Request),
    Refused(Response),
}

/// Reads one request. After the head, `admit` sees the request with an
/// empty body and decides whether and how much body to read, so requests
/// that fail the access checks or announce a body above the limit never
/// cause a body to be read or memory to be reserved for it.
pub fn read_request(
    stream: &mut TcpStream,
    head_timeout: Duration,
    body_timeout: Duration,
    admit: impl FnOnce(&Request) -> Admit,
) -> Result<Incoming, ReadError> {
    let start = Instant::now();
    // Head and early body bytes may hold the session cookie or secrets, so
    // both buffers are wiped on every return. The capacity covers the
    // largest head plus one chunk, so the buffer never reallocates and
    // leaves no unwiped copy behind.
    let mut chunk = Zeroizing::new([0u8; 4096]);
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(MAX_HEAD + chunk.len()));
    let head_end = loop {
        if let Some(pos) = find_head_end(&buf) {
            break pos;
        }
        if buf.len() >= MAX_HEAD {
            return Err(ReadError::HeadTooLarge);
        }
        let n = read_with_deadline(stream, chunk.as_mut_slice(), start + head_timeout)?;
        buf.extend_from_slice(chunk.get(..n).ok_or(ReadError::Gone)?);
    };
    if head_end > MAX_HEAD {
        return Err(ReadError::HeadTooLarge);
    }
    let head = std::str::from_utf8(buf.get(..head_end).ok_or(ReadError::BadRequest)?)
        .map_err(|_| ReadError::BadRequest)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(ReadError::BadRequest)?;
    let mut parts = request_line.split(' ');
    let method = match parts.next() {
        Some("GET") => Method::Get,
        Some("POST") => Method::Post,
        Some(m) if !m.is_empty() && m.bytes().all(|b| b.is_ascii_uppercase()) => {
            return Err(ReadError::MethodNotAllowed)
        }
        _ => return Err(ReadError::BadRequest),
    };
    let target = parts.next().ok_or(ReadError::BadRequest)?;
    let version = parts.next().ok_or(ReadError::BadRequest)?;
    if parts.next().is_some() || !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(ReadError::BadRequest);
    }
    if !target.starts_with('/') || target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(ReadError::BadRequest);
    }
    // The query string is never used; fragments never reach the server.
    let path = target.split('?').next().unwrap_or("/").to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(ReadError::BadRequest); // obsolete line folding
        }
        let (name, value) = line.split_once(':').ok_or(ReadError::BadRequest)?;
        if name.is_empty() || name.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(ReadError::BadRequest);
        }
        headers.push((
            name.to_ascii_lowercase(),
            Zeroizing::new(value.trim().to_string()),
        ));
        if headers.len() > MAX_HEADERS {
            return Err(ReadError::HeadTooLarge);
        }
    }
    let count = |n: &str| headers.iter().filter(|(k, _)| k == n).count();
    if count("transfer-encoding") > 0 {
        return Err(ReadError::LengthRequired);
    }
    if count("host") != 1 {
        return Err(ReadError::BadRequest);
    }
    // Headers that carry security decisions must appear at most once, so no
    // two parts of a stack can read different values.
    for name in ["content-length", "origin", "cookie", "x-cipheris"] {
        if count(name) > 1 {
            return Err(ReadError::BadRequest);
        }
    }
    let len = match headers.iter().find(|(k, _)| k == "content-length") {
        None => 0,
        Some((_, v)) if !v.is_empty() && v.len() <= 12 && v.bytes().all(|b| b.is_ascii_digit()) => {
            v.parse::<usize>().map_err(|_| ReadError::BadRequest)?
        }
        Some(_) => return Err(ReadError::BadRequest),
    };
    if method == Method::Post && count("content-length") == 0 {
        return Err(ReadError::LengthRequired);
    }
    let already = buf.get(head_end + 4..).unwrap_or(&[]);
    if already.len() > len {
        return Err(ReadError::BadRequest); // pipelining is not supported
    }

    let mut req = Request {
        method,
        path,
        headers,
        body: Zeroizing::new(Vec::new()),
    };
    let limit = match admit(&req) {
        Admit::Body(limit) => limit,
        Admit::Refuse(resp) => return Ok(Incoming::Refused(resp)),
    };
    if len > limit {
        return Err(ReadError::TooLarge);
    }

    let mut body = Zeroizing::new(Vec::with_capacity(len));
    body.extend_from_slice(already);
    let body_start = Instant::now();
    while body.len() < len {
        let want = (len - body.len()).min(chunk.len());
        let n = read_with_deadline(
            stream,
            chunk.get_mut(..want).ok_or(ReadError::Gone)?,
            body_start + body_timeout,
        )?;
        body.extend_from_slice(chunk.get(..n).ok_or(ReadError::Gone)?);
    }
    req.body = body;
    Ok(Incoming::Complete(req))
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn read_with_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<usize, ReadError> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(ReadError::Gone)?;
    stream
        .set_read_timeout(Some(left.min(Duration::from_secs(5))))
        .map_err(|_| ReadError::Gone)?;
    loop {
        match stream.read(buf) {
            Ok(0) => return Err(ReadError::Gone),
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) && Instant::now() < deadline =>
            {
                continue
            }
            Err(_) => return Err(ReadError::Gone),
        }
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub extra: Vec<(&'static str, Zeroizing<String>)>,
    /// May contain plaintext or key material: wiped when dropped.
    pub body: Zeroizing<Vec<u8>>,
}

impl Response {
    pub fn new(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            extra: Vec::new(),
            body: Zeroizing::new(body.into()),
        }
    }

    pub fn text(status: u16, msg: &str) -> Self {
        Self::new(status, "text/plain; charset=utf-8", msg.as_bytes().to_vec())
    }

    pub fn empty(status: u16) -> Self {
        Self::new(status, "text/plain; charset=utf-8", Vec::new())
    }

    /// `303 See Other` to a fixed path inside the app.
    pub fn redirect(location: &'static str) -> Self {
        Self::empty(303).header("Location", location)
    }

    pub fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.extra.push((name, Zeroizing::new(value.into())));
        self
    }
}

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; \
font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        303 => "See Other",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Content Too Large",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

pub fn write_response(stream: &mut TcpStream, r: &Response) -> std::io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    let mut head = Zeroizing::new(format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\
         Cache-Control: no-store\r\nPragma: no-cache\r\nX-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\n\
         Cross-Origin-Resource-Policy: same-origin\r\nCross-Origin-Opener-Policy: same-origin\r\n\
         Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=()\r\n\
         Content-Security-Policy: {CSP}\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len()
    ));
    if r.status == 405 {
        head.push_str("Allow: GET, POST\r\n");
    }
    for (k, v) in &r.extra {
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&r.body)?;
    stream.flush()
}
