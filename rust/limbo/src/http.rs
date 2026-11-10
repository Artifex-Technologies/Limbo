//! Plain HTTP/1.1 over a unix socket, one request per connection, and Go's ServeMux routing rules (Go 1.22 patterns:
//! "METHOD /path/{wildcard}", GET also answering HEAD, 405 with Allow for a path that exists under another method, 404
//! "404 page not found" otherwise, a path that is not clean redirected). Requests are small JSON documents; anything
//! larger than the header limit or slower than the header timeout is refused, as Go's server does.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::time::Duration;

pub const MAX_HEADER_BYTES: usize = 1 << 20;
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
/// The cap on a request body the handlers read (Go: http.MaxBytesReader(64 KiB) in wrap); one byte more is kept to see
/// that it was larger.
pub const MAX_BODY: usize = 64 << 10;

#[derive(Debug, Clone, Default)]
pub struct Request {
    pub method: String,
    /// the path as sent (escaped)
    pub raw_path: String,
    pub body: Vec<u8>,
    /// the body was longer than MAX_BODY (only the first MAX_BODY + 1 bytes are kept)
    pub body_too_large: bool,
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

pub enum Body {
    Bytes(Vec<u8>),
    /// a file streamed after the headers (exchange take), with its length
    File(std::fs::File, u64),
}

impl Response {
    pub fn json(status: u16, body: String) -> Response {
        Response { status, headers: vec![("Content-Type".into(), "application/json".into())], body: Body::Bytes(format!("{body}\n").into_bytes()) }
    }
    pub fn text(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![
                ("Content-Type".into(), "text/plain; charset=utf-8".into()),
                ("X-Content-Type-Options".into(), "nosniff".into()),
            ],
            body: Body::Bytes(body.as_bytes().to_vec()),
        }
    }
    pub fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(h, _)| h.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
    pub fn bytes(&self) -> &[u8] {
        match &self.body {
            Body::Bytes(b) => b,
            Body::File(..) => &[],
        }
    }
}

pub fn status_text(s: u16) -> &'static str {
    match s {
        200 => "OK",
        202 => "Accepted",
        301 => "Moved Permanently",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Request Entity Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// Why a request could not be read: the status to answer (or none: the connection just ends).
pub enum ReadErr {
    Status(u16, &'static str),
    Closed,
}

/// Reads one request from a stream (headers within MAX_HEADER_BYTES; a Content-Length or chunked body).
pub fn read_request<R: Read>(r: R) -> Result<Request, ReadErr> {
    let mut br = BufReader::with_capacity(8192, r);
    let mut head_bytes = 0usize;
    let mut line = Vec::new();
    let mut read_line = |br: &mut BufReader<R>, line: &mut Vec<u8>| -> Result<(), ReadErr> {
        line.clear();
        let n = br.by_ref().take((MAX_HEADER_BYTES - head_bytes.min(MAX_HEADER_BYTES)) as u64 + 1).read_until(b'\n', line).map_err(|_| ReadErr::Closed)?;
        head_bytes += n;
        if n == 0 {
            return Err(ReadErr::Closed);
        }
        if head_bytes > MAX_HEADER_BYTES || !line.ends_with(b"\n") {
            return Err(ReadErr::Status(431, "431 Request Header Fields Too Large"));
        }
        while line.last().is_some_and(|c| *c == b'\n' || *c == b'\r') {
            line.pop();
        }
        Ok(())
    };
    // Go skips empty lines before the request line? No: it refuses them; a client never sends one
    read_line(&mut br, &mut line)?;
    let first = String::from_utf8_lossy(&line).into_owned();
    let mut parts = first.splitn(3, ' ');
    let (method, target, proto) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if method.is_empty() || target.is_empty() || !proto.starts_with("HTTP/1.") {
        return Err(ReadErr::Status(400, "400 Bad Request"));
    }
    let raw_path = target.split('?').next().unwrap_or("").to_string();
    if !raw_path.starts_with('/') {
        return Err(ReadErr::Status(400, "400 Bad Request"));
    }
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        read_line(&mut br, &mut line)?;
        if line.is_empty() {
            break;
        }
        let l = String::from_utf8_lossy(&line);
        let Some((k, v)) = l.split_once(':') else { return Err(ReadErr::Status(400, "400 Bad Request")) };
        let (k, v) = (k.trim(), v.trim());
        if k.eq_ignore_ascii_case("content-length") {
            match v.parse::<usize>() {
                Ok(n) if content_length.is_none_or(|c| c == n) => content_length = Some(n),
                _ => return Err(ReadErr::Status(400, "400 Bad Request")),
            }
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            if v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else {
                return Err(ReadErr::Status(501, "501 Not Implemented"));
            }
        }
    }
    let mut req = Request { method: method.to_string(), raw_path, body: Vec::new(), body_too_large: false };
    let keep = MAX_BODY + 1;
    if chunked {
        loop {
            read_line(&mut br, &mut line).map_err(|_| ReadErr::Closed)?;
            let sz = String::from_utf8_lossy(&line);
            let sz = sz.split(';').next().unwrap_or("").trim().to_string();
            let n = usize::from_str_radix(&sz, 16).map_err(|_| ReadErr::Status(400, "400 Bad Request"))?;
            if n == 0 {
                // trailers end with an empty line
                loop {
                    read_line(&mut br, &mut line).map_err(|_| ReadErr::Closed)?;
                    if line.is_empty() {
                        break;
                    }
                }
                break;
            }
            let mut chunk = vec![0u8; n.min(keep)];
            br.read_exact(&mut chunk).map_err(|_| ReadErr::Closed)?;
            if n > chunk.len() {
                io::copy(&mut br.by_ref().take((n - chunk.len()) as u64), &mut io::sink()).map_err(|_| ReadErr::Closed)?;
            }
            let room = keep.saturating_sub(req.body.len());
            req.body.extend_from_slice(&chunk[..chunk.len().min(room)]);
            if req.body.len() >= keep || n > room {
                req.body_too_large = true;
            }
            let mut crlf = [0u8; 2];
            br.read_exact(&mut crlf).map_err(|_| ReadErr::Closed)?;
        }
    } else if let Some(n) = content_length {
        let take = n.min(keep);
        req.body = vec![0u8; take];
        br.read_exact(&mut req.body).map_err(|_| ReadErr::Closed)?;
        req.body_too_large = n > MAX_BODY;
    }
    req.body_too_large = req.body_too_large || req.body.len() > MAX_BODY;
    Ok(req)
}

/// Writes a response (Connection: close; the date as Go writes it).
pub fn write_response<W: Write>(mut w: W, req_method: &str, resp: Response) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\n", resp.status, status_text(resp.status));
    for (k, v) in &resp.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    let len = match &resp.body {
        Body::Bytes(b) => b.len() as u64,
        Body::File(_, n) => *n,
    };
    if resp.header("Content-Length").is_none() {
        head.push_str(&format!("Content-Length: {len}\r\n"));
    }
    head.push_str(&format!("Date: {}\r\nConnection: close\r\n\r\n", http_date()));
    w.write_all(head.as_bytes())?;
    if req_method == "HEAD" {
        return w.flush();
    }
    match resp.body {
        Body::Bytes(b) => w.write_all(&b)?,
        Body::File(mut f, n) => {
            io::copy(&mut (&mut f).take(n), &mut w)?;
        }
    }
    w.flush()
}

fn http_date() -> String {
    let t = crate::gotime::Time::now().utc();
    let (y, mo, d, h, mi, s) = t.civil();
    let days = t.unix().div_euclid(86_400);
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][(mo as usize).saturating_sub(1).min(11)];
    format!("{wd}, {d:02} {mon} {y} {h:02}:{mi:02}:{s:02} GMT")
}

// ---- routing ----

/// One route: method, pattern ("/v1/quarantine/{id}/raise") and what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route<R: Copy> {
    pub method: &'static str,
    pub pattern: &'static str,
    pub id: R,
}

/// Go's cleanPath: path.Clean, keeping a trailing slash.
pub fn clean_path(p: &str) -> String {
    if p.is_empty() {
        return "/".into();
    }
    let p2 = if p.starts_with('/') { p.to_string() } else { format!("/{p}") };
    let mut np = crate::sys::clean(&p2);
    if p.ends_with('/') && np != "/" {
        np.push('/');
    }
    np
}

/// Go's url.PathUnescape for one segment ("%2F" becomes "/"); a bad escape makes the segment unmatchable (None).
pub fn unescape(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(crate::gotext::lossy_owned(out))
}

fn match_pattern(pattern: &str, segs: &[&str]) -> Option<Vec<(String, String)>> {
    let ps: Vec<&str> = pattern.trim_start_matches('/').split('/').collect();
    if ps.len() != segs.len() {
        return None;
    }
    let mut vals = vec![];
    for (p, s) in ps.iter().zip(segs) {
        if let Some(name) = p.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
            if s.is_empty() {
                return None;
            }
            vals.push((name.to_string(), unescape(s)?));
        } else if unescape(s).as_deref() != Some(*p) {
            return None;
        }
    }
    Some(vals)
}

pub enum Matched<R: Copy> {
    Route(R, Vec<(String, String)>),
    /// the path exists under other methods: 405 with this Allow list
    MethodNotAllowed(String),
    NotFound,
    Redirect(String),
}

/// Go's ServeMux choice for `method` and the escaped `raw_path` among `routes`.
pub fn route<R: Copy>(routes: &[Route<R>], method: &str, raw_path: &str) -> Matched<R> {
    let clean = clean_path(raw_path);
    if clean != raw_path {
        return Matched::Redirect(clean);
    }
    let segs: Vec<&str> = raw_path.trim_start_matches('/').split('/').collect();
    // the most specific match: a literal segment beats a wildcard (no two Limbo patterns overlap otherwise)
    let mut best: Option<(usize, R, Vec<(String, String)>)> = None;
    let mut allow: Vec<&str> = vec![];
    for r in routes {
        let Some(vals) = match_pattern(r.pattern, &segs) else { continue };
        let ok = r.method == method || (r.method == "GET" && method == "HEAD");
        if !ok {
            allow.push(r.method);
            if r.method == "GET" {
                allow.push("HEAD");
            }
            continue;
        }
        let literal = r.pattern.split('/').filter(|p| !p.starts_with('{')).count();
        if best.as_ref().is_none_or(|b| literal > b.0) {
            best = Some((literal, r.id, vals));
        }
    }
    match best {
        Some((_, id, vals)) => Matched::Route(id, vals),
        None if !allow.is_empty() => {
            allow.sort();
            allow.dedup();
            Matched::MethodNotAllowed(allow.join(", "))
        }
        None => Matched::NotFound,
    }
}

/// A redirect as Go's http.Redirect writes it.
pub fn redirect(method: &str, to: &str) -> Response {
    let mut r = Response { status: 307, headers: vec![("Location".into(), to.to_string())], body: Body::Bytes(Vec::new()) };
    if method == "GET" || method == "HEAD" {
        r.headers.insert(0, ("Content-Type".into(), "text/html; charset=utf-8".into()));
        r.body = Body::Bytes(format!("<a href=\"{}\">Temporary Redirect</a>.\n\n", html_escape(to)).into_bytes());
    }
    r
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&#34;").replace('\'', "&#39;")
}
