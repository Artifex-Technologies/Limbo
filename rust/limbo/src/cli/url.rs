//! Go's net/url as the CLI's HTTP client uses it: `url.Parse` of `"http://limbo"+path` and of a redirect's Location
//! (with the module's GODEBUG defaults: go 1.24, so `urlstrictcolons=0`), `ResolveReference`, `EscapedPath`,
//! `RequestURI` and `String`, and the error texts. Unescaped parts are bytes, as in Go (`%e9` is one byte, not a
//! character). Pinned by `testdata/parity/cliclient.json`.

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Path,
    Host,
    Zone,
    UserPassword,
    Fragment,
}

/// Go's shouldEscape (the encoding table in net/url).
fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if (mode == Mode::Host || mode == Mode::Zone)
        && matches!(
            c,
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'[' | b']' | b'<' | b'>' | b'"'
        )
    {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            Mode::Path => return c == b'?',
            Mode::UserPassword => return c == b'@' || c == b'/' || c == b'?' || c == b':',
            Mode::Fragment => return false,
            _ => {}
        },
        _ => {}
    }
    if mode == Mode::Fragment && matches!(c, b'!' | b'(' | b')' | b'*') {
        return false;
    }
    true
}

fn unhex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

/// strconv.Quote of bytes that may not be UTF-8 (each stray byte as `\xNN`).
pub fn quote_bytes(b: &[u8]) -> String {
    let mut out = String::from("\"");
    for chunk in b.utf8_chunks() {
        let q = crate::gotext::quote(chunk.valid());
        out.push_str(&q[1..q.len() - 1]);
        for x in chunk.invalid() {
            out.push_str(&format!("\\x{x:02x}"));
        }
    }
    out.push('"');
    out
}

fn escape_error(s: &[u8]) -> String {
    format!("invalid URL escape {}", quote_bytes(s))
}

fn unescape(s: &[u8], mode: Mode) -> Result<Vec<u8>, String> {
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                if i + 2 >= s.len() || !s[i + 1].is_ascii_hexdigit() || !s[i + 2].is_ascii_hexdigit() {
                    let rest = &s[i..];
                    return Err(escape_error(&rest[..rest.len().min(3)]));
                }
                if mode == Mode::Host && unhex(s[i + 1]) < 8 && &s[i..i + 3] != b"%25" {
                    return Err(escape_error(&s[i..i + 3]));
                }
                if mode == Mode::Zone {
                    let v = unhex(s[i + 1]) << 4 | unhex(s[i + 2]);
                    if &s[i..i + 3] != b"%25" && v != b' ' && should_escape(v, Mode::Host) {
                        return Err(escape_error(&s[i..i + 3]));
                    }
                }
                i += 3;
            }
            c => {
                if (mode == Mode::Host || mode == Mode::Zone) && c < 0x80 && should_escape(c, mode) {
                    return Err(format!("invalid character {} in host name", quote_bytes(&s[i..i + 1])));
                }
                i += 1;
            }
        }
    }
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            out.push(unhex(s[i + 1]) << 4 | unhex(s[i + 2]));
            i += 3;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn escape(s: &[u8], mode: Mode) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        if should_escape(c, mode) {
            out.extend_from_slice(&[b'%', HEX[(c >> 4) as usize], HEX[(c & 15) as usize]]);
        } else {
            out.push(c);
        }
    }
    out
}

fn valid_encoded(s: &[u8], mode: Mode) -> bool {
    s.iter().all(|&c| {
        matches!(c, b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'@' | b'[' | b']' | b'%')
            || !should_escape(c, mode)
    })
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct User {
    pub username: Vec<u8>,
    pub password: Option<Vec<u8>>,
}

impl User {
    /// Userinfo.String
    pub fn string(&self) -> Vec<u8> {
        let mut s = escape(&self.username, Mode::UserPassword);
        if let Some(p) = &self.password {
            s.push(b':');
            s.extend(escape(p, Mode::UserPassword));
        }
        s
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Url {
    pub scheme: Vec<u8>,
    pub opaque: Vec<u8>,
    pub user: Option<User>,
    pub host: Vec<u8>,
    pub path: Vec<u8>,
    pub raw_path: Vec<u8>,
    pub omit_host: bool,
    pub force_query: bool,
    pub raw_query: Vec<u8>,
    pub fragment: Vec<u8>,
    pub raw_fragment: Vec<u8>,
}

fn cut(s: &[u8], c: u8) -> (&[u8], Option<&[u8]>) {
    match s.iter().position(|&x| x == c) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

fn rfind(s: &[u8], c: u8) -> Option<usize> {
    s.iter().rposition(|&x| x == c)
}

fn find_sub(s: &[u8], sub: &[u8]) -> Option<usize> {
    s.windows(sub.len()).position(|w| w == sub)
}

/// A url.Parse failure: the URL the *url.Error names and the reason. `text()` is the error's own text.
#[derive(Debug, PartialEq)]
pub struct ParseError {
    pub url: Vec<u8>,
    pub err: String,
}

impl ParseError {
    pub fn text(&self) -> String {
        format!("parse {}: {}", quote_bytes(&self.url), self.err)
    }
}

/// url.Parse
pub fn parse(raw: &[u8]) -> Result<Url, ParseError> {
    let (u, frag) = cut(raw, b'#');
    let mut url = parse_ref(u).map_err(|err| ParseError { url: u.to_vec(), err })?;
    match frag {
        None | Some(b"") => Ok(url),
        Some(f) => {
            url.set_fragment(f).map_err(|err| ParseError { url: raw.to_vec(), err })?;
            Ok(url)
        }
    }
}

fn get_scheme(raw: &[u8]) -> Result<(&[u8], &[u8]), String> {
    for (i, &c) in raw.iter().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok((b"", raw));
                }
            }
            b':' => {
                if i == 0 {
                    return Err("missing protocol scheme".into());
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok((b"", raw)),
        }
    }
    Ok((b"", raw))
}

fn parse_ref(raw: &[u8]) -> Result<Url, String> {
    if raw.iter().any(|&b| b < b' ' || b == 0x7f) {
        return Err("net/url: invalid control character in URL".into());
    }
    let mut url = Url::default();
    if raw == b"*" {
        url.path = b"*".to_vec();
        return Ok(url);
    }
    let (scheme, mut rest) = get_scheme(raw)?;
    url.scheme = scheme.to_ascii_lowercase();
    if rest.ends_with(b"?") && rest.iter().filter(|&&c| c == b'?').count() == 1 {
        url.force_query = true;
        rest = &rest[..rest.len() - 1];
    } else {
        let (r, q) = cut(rest, b'?');
        rest = r;
        url.raw_query = q.unwrap_or_default().to_vec();
    }
    if !rest.starts_with(b"/") {
        if !url.scheme.is_empty() {
            url.opaque = rest.to_vec();
            return Ok(url);
        }
        if cut(rest, b'/').0.contains(&b':') {
            return Err("first path segment in URL cannot contain colon".into());
        }
    }
    if (!url.scheme.is_empty() || !rest.starts_with(b"///")) && rest.starts_with(b"//") {
        let mut authority = &rest[2..];
        rest = b"";
        if let Some(i) = authority.iter().position(|&c| c == b'/') {
            rest = &authority[i..];
            authority = &authority[..i];
        }
        let (user, host) = parse_authority(&url.scheme, authority)?;
        url.user = user;
        url.host = host;
    } else if !url.scheme.is_empty() && rest.starts_with(b"/") {
        url.omit_host = true;
    }
    url.set_path(rest)?;
    Ok(url)
}

fn valid_userinfo(s: &[u8]) -> bool {
    s.iter().all(|&c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
                    | b'@'
            )
    })
}

fn parse_authority(scheme: &[u8], authority: &[u8]) -> Result<(Option<User>, Vec<u8>), String> {
    let Some(i) = rfind(authority, b'@') else {
        return Ok((None, parse_host(scheme, authority)?));
    };
    let host = parse_host(scheme, &authority[i + 1..])?;
    let userinfo = &authority[..i];
    if !valid_userinfo(userinfo) {
        return Err("net/url: invalid userinfo".into());
    }
    let user = match cut(userinfo, b':') {
        (name, None) => User { username: unescape(name, Mode::UserPassword)?, password: None },
        (name, Some(pass)) => User { username: unescape(name, Mode::UserPassword)?, password: Some(unescape(pass, Mode::UserPassword)?) },
    };
    Ok((Some(user), host))
}

fn valid_optional_port(port: &[u8]) -> bool {
    port.is_empty() || port[0] == b':' && port[1..].iter().all(u8::is_ascii_digit)
}

fn parse_host(scheme: &[u8], host: &[u8]) -> Result<Vec<u8>, String> {
    match rfind(host, b'[') {
        Some(open) if open > 0 => return Err("invalid IP-literal".into()),
        Some(_) => {
            let Some(close) = rfind(host, b']') else { return Err("missing ']' in host".into()) };
            let colon_port = &host[close + 1..];
            if !valid_optional_port(colon_port) {
                return Err(format!("invalid port {} after host", quote_bytes(colon_port)));
            }
            let colon_port = unescape(colon_port, Mode::Host)?;
            let hostname = if close >= 1 { &host[1..close] } else { &host[1..1] };
            let unescaped = match find_sub(hostname, b"%25") {
                Some(z) => {
                    let mut h = unescape(&hostname[..z], Mode::Host)?;
                    h.extend(unescape(&hostname[z..], Mode::Zone)?);
                    h
                }
                None => unescape(hostname, Mode::Host)?,
            };
            // netip.ParseAddr: an IPv6 address with an optional zone; an IPv4 one is refused as a literal
            let text = String::from_utf8_lossy(&unescaped).into_owned();
            let addr_part = text.split_once('%').map_or(text.as_str(), |(a, _)| a);
            match addr_part.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(_)) if !text.contains('%') => return Err("invalid IP-literal".into()),
                Ok(_) => {}
                Err(_) => return Err(format!("invalid host: ParseAddr({}): unable to parse IP", quote_bytes(&unescaped))),
            }
            let mut out = b"[".to_vec();
            out.extend(unescaped);
            out.push(b']');
            out.extend(colon_port);
            return Ok(out);
        }
        None => {}
    }
    if let Some(i) = host.iter().position(|&c| c == b':') {
        // urlstrictcolons=0 (the module's go 1.24 default) for http and https, always for other schemes: the last colon
        let _ = scheme;
        let i = rfind(host, b':').unwrap_or(i);
        let colon_port = &host[i..];
        if !valid_optional_port(colon_port) {
            return Err(format!("invalid port {} after host", quote_bytes(colon_port)));
        }
    }
    unescape(host, Mode::Host)
}

impl Url {
    fn set_path(&mut self, p: &[u8]) -> Result<(), String> {
        let path = unescape(p, Mode::Path)?;
        self.raw_path = if escape(&path, Mode::Path) == p { vec![] } else { p.to_vec() };
        self.path = path;
        Ok(())
    }

    fn set_fragment(&mut self, f: &[u8]) -> Result<(), String> {
        let frag = unescape(f, Mode::Fragment)?;
        self.raw_fragment = if escape(&frag, Mode::Fragment) == f { vec![] } else { f.to_vec() };
        self.fragment = frag;
        Ok(())
    }

    pub fn escaped_path(&self) -> Vec<u8> {
        if !self.raw_path.is_empty() && valid_encoded(&self.raw_path, Mode::Path) {
            if let Ok(p) = unescape(&self.raw_path, Mode::Path) {
                if p == self.path {
                    return self.raw_path.clone();
                }
            }
        }
        if self.path == b"*" {
            return b"*".to_vec();
        }
        escape(&self.path, Mode::Path)
    }

    fn escaped_fragment(&self) -> Vec<u8> {
        if !self.raw_fragment.is_empty() && valid_encoded(&self.raw_fragment, Mode::Fragment) {
            if let Ok(f) = unescape(&self.raw_fragment, Mode::Fragment) {
                if f == self.fragment {
                    return self.raw_fragment.clone();
                }
            }
        }
        escape(&self.fragment, Mode::Fragment)
    }

    /// URL.String
    pub fn string(&self) -> Vec<u8> {
        let mut buf = vec![];
        if !self.scheme.is_empty() {
            buf.extend_from_slice(&self.scheme);
            buf.push(b':');
        }
        if !self.opaque.is_empty() {
            buf.extend_from_slice(&self.opaque);
        } else {
            if (!self.scheme.is_empty() || !self.host.is_empty() || self.user.is_some())
                && !(self.omit_host && self.host.is_empty() && self.user.is_none())
            {
                if !self.host.is_empty() || !self.path.is_empty() || self.user.is_some() {
                    buf.extend_from_slice(b"//");
                }
                if let Some(u) = &self.user {
                    buf.extend(u.string());
                    buf.push(b'@');
                }
                if !self.host.is_empty() {
                    buf.extend(escape(&self.host, Mode::Host));
                }
            }
            let mut path = self.escaped_path();
            if self.omit_host && self.host.is_empty() && self.user.is_none() && path.starts_with(b"//") {
                buf.extend_from_slice(b"%2F");
                path.remove(0);
            }
            if !path.is_empty() && path[0] != b'/' && !self.host.is_empty() {
                buf.push(b'/');
            }
            if buf.is_empty() && cut(&path, b'/').0.contains(&b':') {
                buf.extend_from_slice(b"./");
            }
            buf.extend(path);
        }
        if self.force_query || !self.raw_query.is_empty() {
            buf.push(b'?');
            buf.extend_from_slice(&self.raw_query);
        }
        if !self.fragment.is_empty() {
            buf.push(b'#');
            buf.extend(self.escaped_fragment());
        }
        buf
    }

    /// URL.RequestURI: the request line's target.
    pub fn request_uri(&self) -> Vec<u8> {
        let mut r = self.opaque.clone();
        if r.is_empty() {
            r = self.escaped_path();
            if r.is_empty() {
                r = b"/".to_vec();
            }
        } else if r.starts_with(b"//") {
            let mut s = self.scheme.clone();
            s.push(b':');
            s.extend(r);
            r = s;
        }
        if self.force_query || !self.raw_query.is_empty() {
            r.push(b'?');
            r.extend_from_slice(&self.raw_query);
        }
        r
    }

    /// u.Parse(ref): ref read and resolved against u. The error is url.Parse's own (`parse "ref": ...`).
    pub fn join(&self, r: &[u8]) -> Result<Url, ParseError> {
        let rf = parse(r)?;
        Ok(self.resolve(&rf))
    }

    /// URL.ResolveReference
    pub fn resolve(&self, rf: &Url) -> Url {
        let mut url = rf.clone();
        if rf.scheme.is_empty() {
            url.scheme = self.scheme.clone();
        }
        if !rf.scheme.is_empty() || !rf.host.is_empty() || rf.user.is_some() {
            let _ = url.set_path(&resolve_path(&rf.escaped_path(), b""));
            return url;
        }
        if !rf.opaque.is_empty() {
            url.user = None;
            url.host = vec![];
            url.path = vec![];
            return url;
        }
        if rf.path.is_empty() && !rf.force_query && rf.raw_query.is_empty() {
            url.raw_query = self.raw_query.clone();
            if rf.fragment.is_empty() {
                url.fragment = self.fragment.clone();
                url.raw_fragment = self.raw_fragment.clone();
            }
        }
        if rf.path.is_empty() && !self.opaque.is_empty() {
            url.opaque = self.opaque.clone();
            url.user = None;
            url.host = vec![];
            url.path = vec![];
            return url;
        }
        url.host = self.host.clone();
        url.user = self.user.clone();
        let _ = url.set_path(&resolve_path(&self.escaped_path(), &rf.escaped_path()));
        url
    }
}

/// net/url's resolvePath: RFC 3986 dot-segment removal on escaped paths.
fn resolve_path(base: &[u8], r: &[u8]) -> Vec<u8> {
    let full: Vec<u8> = if r.is_empty() {
        base.to_vec()
    } else if r[0] != b'/' {
        let i = rfind(base, b'/').map_or(0, |i| i + 1);
        let mut f = base[..i].to_vec();
        f.extend_from_slice(r);
        f
    } else {
        r.to_vec()
    };
    if full.is_empty() {
        return vec![];
    }
    let mut dst = vec![b'/'];
    let mut first = true;
    let mut elem: &[u8] = b"";
    let mut remaining: &[u8] = &full;
    let mut found = true;
    while found {
        let (e, rest) = cut(remaining, b'/');
        elem = e;
        found = rest.is_some();
        remaining = rest.unwrap_or_default();
        match elem {
            b"." => {
                first = false;
                continue;
            }
            b".." => {
                match rfind(&dst[1..], b'/') {
                    Some(i) => dst.truncate(i + 1),
                    None => dst.truncate(1),
                }
                first = dst.len() == 1;
            }
            _ => {
                if !first {
                    dst.push(b'/');
                }
                dst.extend_from_slice(elem);
                first = false;
            }
        }
    }
    if elem == b"." || elem == b".." {
        dst.push(b'/');
    }
    if dst.len() > 1 && dst[1] == b'/' {
        return dst[1..].to_vec();
    }
    dst
}
