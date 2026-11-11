//! The Go CLI's HTTP client over a unix socket (`unixClient` in cmd/limbo/quarantine_cmd.go: net/http's Client with a
//! 60 s timeout and a dialer that ignores the address): the request URL `"http://limbo"+path` as http.NewRequest reads it,
//! the request as the transport writes it (Host, Content-Length when Go sends one, Referer after a redirect; not the
//! User-Agent and `Accept-Encoding: gzip`, which no Limbo daemon reads), the response as http.ReadResponse reads it
//! (status line, MIME headers, Content-Length, chunked, close-delimited, 1xx skipped), redirects as Client.do follows
//! them (301-303 become GET without a body, 307 and 308 keep both, 10 requests at most), and every error with Go's text:
//! `Get "http://limbo/v1/x": dial unix S: connect: no such file or directory`. Pinned by `testdata/parity/cliclient.json`
//! and rust/parity/cli-differential.py.

use super::url::{self, quote_bytes, Url};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// The Go client's Timeout: the whole exchange, redirects and body included.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// Why a read stopped: io.EOF, the client's deadline, or another socket error (Go's text).
#[derive(Debug, PartialEq)]
pub enum ReadErr {
    Eof,
    Timeout,
    Other(String),
}

/// A buffered reader with bufio's line semantics, over the connection or (in tests) bytes.
pub struct Buf<R> {
    r: R,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
    deadline: Option<Instant>,
}

/// What a connection can do to honour the deadline.
pub trait Timed: Read {
    fn set_timeout(&mut self, _d: Duration) {}
}

impl Timed for UnixStream {
    fn set_timeout(&mut self, d: Duration) {
        let _ = self.set_read_timeout(Some(d.max(Duration::from_millis(1))));
    }
}

impl Timed for &[u8] {}

impl<R: Timed> Buf<R> {
    pub fn new(r: R, deadline: Option<Instant>) -> Buf<R> {
        Buf { r, buf: Vec::with_capacity(4096), pos: 0, eof: false, deadline }
    }

    fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Reads more into the buffer: Ok(false) at the end of the stream.
    fn fill(&mut self) -> Result<bool, ReadErr> {
        if self.eof {
            return Ok(false);
        }
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        if let Some(d) = self.deadline {
            let left = d.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(ReadErr::Timeout);
            }
            self.r.set_timeout(left);
        }
        let mut tmp = [0u8; 4096];
        loop {
            match self.r.read(&mut tmp) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(false);
                }
                Ok(n) => {
                    self.buf.extend_from_slice(&tmp[..n]);
                    return Ok(true);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Err(ReadErr::Timeout),
                Err(e) => return Err(ReadErr::Other(format!("read: {}", crate::sys::go_err(&e)))),
            }
        }
    }

    fn peek(&mut self, n: usize) -> Result<&[u8], ReadErr> {
        while self.buffered() < n {
            if !self.fill()? {
                break;
            }
        }
        let end = (self.pos + n).min(self.buf.len());
        Ok(&self.buf[self.pos..end])
    }

    /// bufio.Reader.ReadLine as textproto uses it: the line without "\n" or "\r\n"; a last line without one is returned
    /// whole; nothing left is EOF.
    fn read_line(&mut self) -> Result<Vec<u8>, ReadErr> {
        let mut scanned = 0;
        loop {
            if let Some(i) = self.buf[self.pos + scanned..].iter().position(|&c| c == b'\n') {
                let end = self.pos + scanned + i;
                let mut line = self.buf[self.pos..end].to_vec();
                self.pos = end + 1;
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            scanned = self.buffered();
            if !self.fill()? {
                if self.buffered() == 0 {
                    return Err(ReadErr::Eof);
                }
                let line = self.buf[self.pos..].to_vec();
                self.pos = self.buf.len();
                return Ok(line);
            }
        }
    }

    /// bufio.Reader.ReadSlice('\n') with the transport's 4096-byte buffer: the line with its "\n".
    fn read_slice(&mut self) -> Result<Vec<u8>, ReadErr> {
        let mut scanned = 0;
        loop {
            if let Some(i) = self.buf[self.pos + scanned..].iter().position(|&c| c == b'\n') {
                let end = self.pos + scanned + i + 1;
                if end - self.pos > 4096 {
                    return Err(ReadErr::Other("header line too long".into()));
                }
                let line = self.buf[self.pos..end].to_vec();
                self.pos = end;
                return Ok(line);
            }
            scanned = self.buffered();
            if scanned >= 4096 {
                return Err(ReadErr::Other("header line too long".into()));
            }
            if !self.fill()? {
                return Err(ReadErr::Other("unexpected EOF".into()));
            }
        }
    }

    fn read_byte(&mut self) -> Result<Option<u8>, ReadErr> {
        if self.buffered() == 0 && !self.fill()? {
            return Ok(None);
        }
        let c = self.buf[self.pos];
        self.pos += 1;
        Ok(Some(c))
    }

    /// Up to `max` bytes of what is there (reading once when nothing is buffered); empty at the end.
    fn read_some(&mut self, max: usize) -> Result<Vec<u8>, ReadErr> {
        if self.buffered() == 0 && !self.fill()? {
            return Ok(vec![]);
        }
        let n = self.buffered().min(max);
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }
}

/// A response's head as http.ReadResponse reads it.
#[derive(Debug)]
pub struct Head {
    /// "404 Not Found": the status line after the protocol, as the server wrote it (Go's resp.Status).
    pub status: String,
    pub code: i64,
    /// Canonical keys (or as sent, when a key has a space), values in order.
    pub headers: Vec<(String, Vec<u8>)>,
    minor_ok: bool,
}

impl Head {
    /// Header.Get: the first value of a canonical key.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.headers.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_slice())
    }

    fn all(&self, key: &str) -> Vec<&[u8]> {
        self.headers.iter().filter(|(k, _)| k == key).map(|(_, v)| v.as_slice()).collect()
    }

    /// Header.Get as a string ("" when absent).
    pub fn get_str(&self, key: &str) -> String {
        String::from_utf8_lossy(self.get(key).unwrap_or_default()).into_owned()
    }
}

fn token_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

/// textproto's canonicalMIMEHeaderKey: None when the key is invalid; a key with a space stays as sent.
fn canonical_key(k: &[u8]) -> Option<String> {
    if k.is_empty() {
        return None;
    }
    let mut space = false;
    for &c in k {
        if token_byte(c) {
            continue;
        }
        if c == b' ' {
            space = true;
            continue;
        }
        return None;
    }
    let s = String::from_utf8_lossy(k).into_owned();
    if space {
        return Some(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut upper = true;
    for c in s.chars() {
        let c = if upper { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() };
        out.push(c);
        upper = c == '-';
    }
    Some(out)
}

fn trim_ascii_space(b: &[u8]) -> &[u8] {
    let is = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r');
    let start = b.iter().position(|c| !is(c)).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !is(c)).map_or(start, |i| i + 1);
    &b[start..end.max(start)]
}

fn read_err_text(e: ReadErr) -> String {
    match e {
        ReadErr::Eof => "EOF".into(),
        ReadErr::Timeout => "timeout".into(),
        ReadErr::Other(s) => s,
    }
}

/// textproto's readMIMEHeader. Errors: io.EOF as "EOF" (the caller turns it into "unexpected EOF").
fn read_mime_header<R: Timed>(b: &mut Buf<R>) -> Result<Vec<(String, Vec<u8>)>, ReadErr> {
    let mut out = vec![];
    if let Some(&c) = b.peek(1)?.first() {
        if c == b' ' || c == b'\t' {
            let line = b.read_line()?;
            if line.len() > 80 {
                return Err(ReadErr::Other("message too large".into()));
            }
            return Err(ReadErr::Other(format!("malformed MIME header initial line: {}", quote_bytes(&line))));
        }
    }
    loop {
        let line = b.read_line()?;
        if line.is_empty() {
            return Ok(out);
        }
        if !line.contains(&b':') {
            return Err(ReadErr::Other(format!("malformed MIME header: missing colon: {}", quote_bytes(&line))));
        }
        let mut kv = trim_ascii_space(&line).to_vec();
        // continuation lines (obs-fold): each joined with one space
        loop {
            let next = b.peek(1)?.first().copied();
            if next != Some(b' ') && next != Some(b'\t') {
                break;
            }
            while matches!(b.peek(1)?.first(), Some(b' ' | b'\t')) {
                b.read_byte()?;
            }
            kv.push(b' ');
            let more = b.read_line()?;
            kv.extend_from_slice(trim_ascii_space(&more));
        }
        let colon = kv.iter().position(|&c| c == b':').unwrap_or(kv.len());
        let (k, v) = (&kv[..colon], kv.get(colon + 1..).unwrap_or_default());
        let Some(key) = canonical_key(k) else {
            return Err(ReadErr::Other(format!("malformed MIME header line: {}", quote_bytes(&kv))));
        };
        if v.iter().any(|&c| c < 0x80 && c != b'\t' && !(0x20..0x7f).contains(&c)) {
            return Err(ReadErr::Other(format!("malformed MIME header line: {}", quote_bytes(&kv))));
        }
        let start = v.iter().position(|&c| c != b' ' && c != b'\t').unwrap_or(v.len());
        out.push((key, v[start..].to_vec()));
    }
}

/// http.ParseHTTPVersion
fn parse_version(v: &[u8]) -> Option<(u32, u32)> {
    match v {
        b"HTTP/1.1" => return Some((1, 1)),
        b"HTTP/1.0" => return Some((1, 0)),
        _ => {}
    }
    if !v.starts_with(b"HTTP/") || v.len() != 8 || v[6] != b'.' || !v[5].is_ascii_digit() || !v[7].is_ascii_digit() {
        return None;
    }
    Some(((v[5] - b'0') as u32, (v[7] - b'0') as u32))
}

/// strconv.Atoi of the three status characters.
fn atoi3(s: &[u8]) -> Option<i64> {
    let (neg, d) = match s.first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    if d.is_empty() || !d.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n: i64 = std::str::from_utf8(d).ok()?.parse().ok()?;
    Some(if neg { -n } else { n })
}

fn bad_string(what: &str, v: &[u8]) -> ReadErr {
    ReadErr::Other(format!("{what} {}", quote_bytes(v)))
}

/// http.ReadResponse up to the body (for a GET or POST; the CLI sends no HEAD): the head, and how its body is framed.
pub fn read_response<R: Timed>(b: &mut Buf<R>) -> Result<(Head, Framing), ReadErr> {
    let line = match b.read_line() {
        Err(ReadErr::Eof) => return Err(ReadErr::Other("unexpected EOF".into())),
        r => r?,
    };
    let Some(sp) = line.iter().position(|&c| c == b' ') else {
        return Err(bad_string("malformed HTTP response", &line));
    };
    let proto = &line[..sp];
    let rest = &line[sp + 1..];
    let status = &rest[rest.iter().position(|&c| c != b' ').unwrap_or(rest.len())..];
    let code_part = &status[..status.iter().position(|&c| c == b' ').unwrap_or(status.len())];
    if code_part.len() != 3 {
        return Err(bad_string("malformed HTTP status code", code_part));
    }
    let code = match atoi3(code_part) {
        Some(c) if c >= 0 => c,
        _ => return Err(bad_string("malformed HTTP status code", code_part)),
    };
    let Some(ver) = parse_version(proto) else { return Err(bad_string("malformed HTTP version", proto)) };
    let headers = match read_mime_header(b) {
        Err(ReadErr::Eof) => return Err(ReadErr::Other("unexpected EOF".into())),
        r => r?,
    };
    let mut head = Head { status: String::from_utf8_lossy(status).into_owned(), code, headers, minor_ok: ver >= (1, 1) };
    let framing = framing(&mut head)?;
    Ok((head, framing))
}

/// How a body ends.
#[derive(Debug, PartialEq)]
pub enum Framing {
    None,
    Length(u64),
    Chunked,
    Close,
}

/// readTransfer for a response to GET or POST: Transfer-Encoding, then fixLength.
fn framing(h: &mut Head) -> Result<Framing, ReadErr> {
    let te: Vec<Vec<u8>> = h.all("Transfer-Encoding").into_iter().map(<[u8]>::to_vec).collect();
    let mut chunked = false;
    if !te.is_empty() {
        h.headers.retain(|(k, _)| k != "Transfer-Encoding");
        if h.minor_ok {
            if te.len() != 1 {
                let list: Vec<String> = te.iter().map(|v| quote_bytes(v)).collect();
                return Err(ReadErr::Other(format!("too many transfer encodings: [{}]", list.join(" "))));
            }
            if !te[0].eq_ignore_ascii_case(b"chunked") {
                return Err(ReadErr::Other(format!("unsupported transfer encoding: {}", quote_bytes(&te[0]))));
            }
            chunked = true;
        }
    }
    let cls: Vec<Vec<u8>> = h.all("Content-Length").into_iter().map(<[u8]>::to_vec).collect();
    let mut n: Option<u64> = None;
    if !cls.is_empty() {
        let first = trim_ascii_space(&cls[0]).to_vec();
        if cls[1..].iter().any(|c| trim_ascii_space(c) != first.as_slice()) {
            let list: Vec<String> = cls.iter().map(|v| quote_bytes(v)).collect();
            return Err(ReadErr::Other(format!("http: message cannot contain multiple Content-Length headers; got [{}]", list.join(" "))));
        }
        if first.is_empty() {
            return Err(bad_string("invalid empty Content-Length", b""));
        }
        let parsed = if first.iter().all(u8::is_ascii_digit) {
            std::str::from_utf8(&first).ok().and_then(|s| s.parse::<u64>().ok()).filter(|&x| x < 1 << 63)
        } else {
            None
        };
        match parsed {
            Some(x) => n = Some(x),
            None => return Err(bad_string("bad Content-Length", &first)),
        }
    }
    let code = h.code;
    if code / 100 == 1 || code == 204 || code == 304 {
        return Ok(Framing::None);
    }
    if chunked {
        return Ok(Framing::Chunked);
    }
    Ok(match n {
        Some(0) => Framing::None,
        Some(x) => Framing::Length(x),
        None => Framing::Close,
    })
}

/// A response body being read, with Go's errors ("unexpected EOF", the chunked reader's).
pub struct Body<R> {
    b: Buf<R>,
    framing: Framing,
    left: u64,
    chunk_started: bool,
    done: bool,
    err: Option<ReadErr>,
}

impl<R: Timed> Body<R> {
    pub fn new(b: Buf<R>, framing: Framing) -> Body<R> {
        let left = if let Framing::Length(n) = framing { n } else { 0 };
        Body { b, done: framing == Framing::None, framing, left, chunk_started: false, err: None }
    }

    fn fail(&mut self, e: ReadErr) -> Result<Vec<u8>, ReadErr> {
        self.done = true;
        let keep = match &e {
            ReadErr::Eof => ReadErr::Eof,
            ReadErr::Timeout => ReadErr::Timeout,
            ReadErr::Other(s) => ReadErr::Other(s.clone()),
        };
        self.err = Some(keep);
        Err(e)
    }

    /// The next piece of the body (at most `max` bytes): empty at its end.
    pub fn next(&mut self, max: usize) -> Result<Vec<u8>, ReadErr> {
        if let Some(e) = &self.err {
            return Err(match e {
                ReadErr::Eof => ReadErr::Eof,
                ReadErr::Timeout => ReadErr::Timeout,
                ReadErr::Other(s) => ReadErr::Other(s.clone()),
            });
        }
        if self.done || max == 0 {
            return Ok(vec![]);
        }
        match self.framing {
            Framing::None => Ok(vec![]),
            Framing::Close => match self.b.read_some(max) {
                Ok(v) => {
                    if v.is_empty() {
                        self.done = true;
                    }
                    Ok(v)
                }
                Err(e) => self.fail(e),
            },
            Framing::Length(_) => {
                let want = (max as u64).min(self.left) as usize;
                match self.b.read_some(want) {
                    Ok(v) if v.is_empty() => self.fail(ReadErr::Other("unexpected EOF".into())),
                    Ok(v) => {
                        self.left -= v.len() as u64;
                        if self.left == 0 {
                            self.done = true;
                        }
                        Ok(v)
                    }
                    Err(e) => self.fail(e),
                }
            }
            Framing::Chunked => self.next_chunked(max),
        }
    }

    fn next_chunked(&mut self, max: usize) -> Result<Vec<u8>, ReadErr> {
        {
            if self.left == 0 {
                if self.chunk_started {
                    // the CRLF after a chunk's data
                    match self.b.peek(2) {
                        Ok(p) if p.len() < 2 => return self.fail(ReadErr::Other("unexpected EOF".into())),
                        Ok(p) if p != b"\r\n" => return self.fail(ReadErr::Other("malformed chunked encoding".into())),
                        Ok(_) => self.b.pos += 2,
                        Err(e) => return self.fail(e),
                    }
                }
                self.chunk_started = true;
                let line = match self.b.read_slice() {
                    Ok(l) => l,
                    Err(e) => return self.fail(e),
                };
                let cr = line.iter().position(|&c| c == b'\r');
                match cr {
                    None => return self.fail(ReadErr::Other("chunked line ends with bare LF".into())),
                    Some(i) if i != line.len() - 2 => return self.fail(ReadErr::Other("invalid CR in chunked line".into())),
                    _ => {}
                }
                let mut p = &line[..line.len() - 2];
                if p.len() >= 4096 {
                    return self.fail(ReadErr::Other("header line too long".into()));
                }
                while let Some(&c) = p.last() {
                    if c == b' ' || c == b'\t' {
                        p = &p[..p.len() - 1];
                    } else {
                        break;
                    }
                }
                if let Some(i) = p.iter().position(|&c| c == b';') {
                    p = &p[..i];
                }
                if p.is_empty() {
                    return self.fail(ReadErr::Other("empty hex number for chunk length".into()));
                }
                let mut n: u64 = 0;
                for (i, &c) in p.iter().enumerate() {
                    if !c.is_ascii_hexdigit() {
                        return self.fail(ReadErr::Other("invalid byte in chunk length".into()));
                    }
                    if i == 16 {
                        return self.fail(ReadErr::Other("http chunk length too large".into()));
                    }
                    n = n << 4 | (c as char).to_digit(16).unwrap_or(0) as u64;
                }
                if n == 0 {
                    // the trailer: an empty line, or header lines up to one
                    self.done = true;
                    match self.b.peek(2) {
                        Ok(p) if p == b"\r\n" => {
                            self.b.pos += 2;
                            return Ok(vec![]);
                        }
                        Ok(p) if p.len() < 2 => return self.fail(ReadErr::Other("http: unexpected EOF reading trailer".into())),
                        Ok(_) => {}
                        Err(e) => return self.fail(e),
                    }
                    return match read_mime_header(&mut self.b) {
                        Ok(_) => Ok(vec![]),
                        Err(ReadErr::Eof) => self.fail(ReadErr::Other("http: unexpected EOF reading trailer".into())),
                        Err(e) => self.fail(e),
                    };
                }
                self.left = n;
            }
            let want = (max as u64).min(self.left) as usize;
            match self.b.read_some(want) {
                Ok(v) if v.is_empty() => self.fail(ReadErr::Other("unexpected EOF".into())),
                Ok(v) => {
                    self.left -= v.len() as u64;
                    Ok(v)
                }
                Err(e) => self.fail(e),
            }
        }
    }

    /// io.ReadAll(io.LimitReader(body, limit)) with the error dropped, as the CLI reads an answer.
    pub fn read_limited(&mut self, limit: usize) -> Vec<u8> {
        let mut out = vec![];
        while out.len() < limit {
            match self.next(limit - out.len()) {
                Ok(v) if v.is_empty() => break,
                Ok(v) => out.extend(v),
                Err(_) => break,
            }
        }
        out
    }

    /// io.ReadAll(body): everything and the error (Go's text) that ended it.
    pub fn read_all(&mut self) -> (Vec<u8>, String) {
        let mut out = vec![];
        loop {
            match self.next(1 << 16) {
                Ok(v) if v.is_empty() => return (out, String::new()),
                Ok(v) => out.extend(v),
                Err(e) => return (out, body_err_text(e)),
            }
        }
    }
}

/// A body read error as Go writes it.
pub fn body_err_text(e: ReadErr) -> String {
    match e {
        ReadErr::Timeout => "context deadline exceeded (Client.Timeout or context cancellation while reading body)".into(),
        e => read_err_text(e),
    }
}

/// A response with its body still to read.
pub struct Response {
    pub head: Head,
    pub body: Body<UnixStream>,
}

/// One request as it goes out.
struct Req {
    method: String,
    url: Url,
    body: Option<Vec<u8>>,
    referer: Option<Vec<u8>>,
    /// The Content-Type header (http.Client.Post's), copied to every redirect that keeps the body.
    content_type: Option<String>,
}

/// (*http.Request).write: the request line and headers as the transport sends them (less User-Agent and
/// Accept-Encoding), and the body.
fn request_bytes(r: &Req) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(r.method.as_bytes());
    out.push(b' ');
    out.extend(r.url.request_uri());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(&r.url.host);
    out.extend_from_slice(b"\r\n");
    let n = r.body.as_ref().map_or(0, Vec::len);
    // transferWriter.shouldSendContentLength (a request without a body has no transfer encoding, so only these three)
    if n > 0 || matches!(r.method.as_str(), "POST" | "PUT" | "PATCH") {
        out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
    }
    // the URL's user as Basic authentication (a Location may name one)
    if let Some(u) = &r.url.user {
        let mut cred = u.username.clone();
        cred.push(b':');
        cred.extend_from_slice(u.password.as_deref().unwrap_or_default());
        out.extend_from_slice(b"Authorization: Basic ");
        out.extend_from_slice(base64(&cred).as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if let Some(ct) = &r.content_type {
        out.extend_from_slice(b"Content-Type: ");
        out.extend_from_slice(ct.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if let Some(rf) = &r.referer {
        out.extend_from_slice(b"Referer: ");
        out.extend_from_slice(rf);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    if let Some(b) = &r.body {
        out.extend_from_slice(b);
    }
    out
}

/// net.Dialer.DialContext("unix", sock): Go's net.OpError text on failure.
fn dial(sock: &str) -> Result<UnixStream, String> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr;
    if sock.is_empty() {
        return Err("dial unix: missing address".into());
    }
    let fail = |e: &io::Error| format!("dial unix {sock}: connect: {}", crate::sys::go_err(e));
    let einval = io::Error::from_raw_os_error(libc::EINVAL);
    let addr = if let Some(name) = sock.strip_prefix('@') {
        SocketAddr::from_abstract_name(name.as_bytes()).map_err(|_| fail(&einval))?
    } else {
        if sock.len() >= 108 {
            return Err(fail(&einval));
        }
        SocketAddr::from_pathname(sock).map_err(|_| fail(&einval))?
    };
    UnixStream::connect_addr(&addr).map_err(|e| fail(&e))
}

/// http.Client.Do over the unix socket at `sock`: `method` on "http://limbo"+path with `body`. The error is the whole
/// text Go's CLI prints after "limbo: ".
pub fn send(sock: &str, method: &str, path: &str, body: Option<Vec<u8>>) -> Result<Response, String> {
    send_url(sock, method, request_url(path)?, body)
}

/// http.NewRequest's URL: `"http://limbo"+path` read by url.Parse, its error as NewRequest returns it.
pub fn request_url(path: &str) -> Result<Url, String> {
    url::parse(format!("http://limbo{path}").as_bytes()).map_err(|e| e.text())
}

/// Client.Do of a request already made (see `send`).
pub fn send_url(sock: &str, method: &str, first: Url, body: Option<Vec<u8>>) -> Result<Response, String> {
    send_typed(sock, method, first, body, None)
}

/// [`send_url`] with a Content-Type header: `http.Client.Post(url, content_type, body)`.
pub fn send_typed(sock: &str, method: &str, first: Url, body: Option<Vec<u8>>, content_type: Option<&str>) -> Result<Response, String> {
    let deadline = Instant::now() + TIMEOUT;
    let op = {
        let mut c = method.chars();
        match c.next() {
            Some(f) => f.to_string() + &c.as_str().to_ascii_lowercase(),
            None => "Get".into(),
        }
    };
    let uerr = |u: &[u8], e: &str| format!("{op} {}: {e}", quote_bytes(u));
    let orig_body = body.clone();
    let content_type = content_type.map(String::from);
    let mut cur = Req { method: method.into(), url: first, body, referer: None, content_type: content_type.clone() };
    let mut include_body = true;
    let mut sent = 0;
    loop {
        sent += 1;
        let resp = exchange(sock, &cur, deadline).map_err(|e| uerr(&cur.url.string(), &e))?;
        let (next_method, follow, with_body) = match resp.head.code {
            301..=303 => (if matches!(cur.method.as_str(), "GET" | "HEAD") { cur.method.clone() } else { "GET".into() }, true, false),
            307 | 308 => (cur.method.clone(), true, true),
            _ => (String::new(), false, false),
        };
        if !follow {
            return Ok(resp);
        }
        if !with_body {
            include_body = false;
        }
        let loc = resp.head.get("Location").unwrap_or_default().to_vec();
        if loc.is_empty() {
            return Ok(resp);
        }
        let u = match cur.url.join(&loc) {
            Ok(u) => u,
            Err(e) => {
                return Err(uerr(&cur.url.string(), &format!("failed to parse Location header {}: {}", quote_bytes(&loc), e.text())));
            }
        };
        // refererForURL
        let referer = if cur.url.scheme == b"https" && u.scheme == b"http" {
            None
        } else {
            let mut r = cur.url.string();
            if let Some(user) = &cur.url.user {
                let mut auth = user.string();
                auth.push(b'@');
                if let Some(i) = r.windows(auth.len()).position(|w| w == auth.as_slice()) {
                    r.drain(i..i + auth.len());
                }
            }
            Some(r)
        };
        if sent >= 10 {
            return Err(uerr(&loc, "stopped after 10 redirects"));
        }
        let body = if include_body { orig_body.clone() } else { None };
        // a redirect that drops the body drops its Content-Type too, as Go's client does
        let ct = if include_body { content_type.clone() } else { None };
        cur = Req { method: next_method, url: u, body, referer, content_type: ct };
    }
}

/// One request on a new connection, up to the response's head.
fn exchange(sock: &str, r: &Req, deadline: Instant) -> Result<Response, String> {
    if r.url.scheme != b"http" {
        // https would need TLS over the socket, which no Limbo daemon speaks
        return Err(format!("unsupported protocol scheme {}", quote_bytes(&r.url.scheme)));
    }
    if r.url.host.is_empty() {
        return Err("http: no Host in request URL".into());
    }
    let mut conn = dial(sock)?;
    let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
    let _ = conn.set_write_timeout(Some(left));
    // a server that answers without reading everything is read below like any other
    let _ = conn.write_all(&request_bytes(r));
    let mut b = Buf::new(conn, Some(deadline));
    loop {
        match b.peek(1) {
            Ok([]) => return Err("EOF".into()),
            Ok(_) => {}
            Err(ReadErr::Timeout) => return Err(timeout_text()),
            Err(e) => return Err(read_err_text(e)),
        }
        // once the server has said something, a bad answer breaks the connection (Go's mapRoundTripError)
        let (head, framing) = match read_response(&mut b) {
            Ok(x) => x,
            Err(ReadErr::Timeout) => return Err(timeout_text()),
            Err(e) => return Err(format!("net/http: HTTP/1.x transport connection broken: {}", read_err_text(e))),
        };
        // 1xx answers other than 101 are skipped
        if (100..=199).contains(&head.code) && head.code != 101 {
            continue;
        }
        return Ok(Response { head, body: Body::new(b, framing) });
    }
}

/// base64.StdEncoding
fn base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn timeout_text() -> String {
    "context deadline exceeded (Client.Timeout exceeded while awaiting headers)".into()
}
