//! JSON read and written the way Go's encoding/json (v1, as the Go limbo is built) does.
//!
//! Started from Heimdall's port (rust/heimdall/src/gojson.rs, same author and licence) and extended for Limbo, where the
//! decoder's own words reach callers: an agent-socket refusal reads "the request body is not valid JSON for this route
//! (json: unknown field \"x\")", and a profile refusal quotes the decoder too. So this reader gives Go's exact messages:
//! the scanner's syntax errors ("invalid character 'x' looking for beginning of object key string"), the stream reader's
//! "unexpected EOF" and EOF, the type errors with their struct and field path ("json: cannot unmarshal string into Go
//! struct field Manifest.cpus of type int"), and `DisallowUnknownFields` ("json: unknown field \"x\""), the first error in
//! document order winning as in Go. Go's leniency is kept: a lone UTF-16 surrogate or a stray byte inside a string reads
//! as U+FFFD, keys match struct fields without regard to case, the last of duplicate keys wins.
//!
//! The writer escapes as Go's encoder does (`<`, `>`, `&`, U+2028, U+2029), and `write_indented` is MarshalIndent's layout.

use crate::gotext;
use std::fmt;

/// A JSON value. Numbers keep their text, so each reader applies Go's rule for its own type (an int refuses "1.0").
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    /// Members in document order, duplicates kept (a struct reader applies them in order, so the last one wins).
    Object(Vec<(String, Value)>),
}

/// Why a document did not read: Go's error text.
#[derive(Clone, Debug, PartialEq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl Error {
    /// The stream reader's io.EOF: nothing but white space was there (callers of Decode often accept it as "no body").
    pub fn is_eof(&self) -> bool {
        self.0 == "EOF"
    }
}

/// Go's nesting limit (encoding/json's scanner refuses deeper documents).
const MAX_DEPTH: usize = 10_000;

/// Go's quoteChar: how the scanner names the byte it stopped at.
fn quote_char(c: u8) -> String {
    match c {
        b'\'' => "'\\''".into(),
        b'"' => "'\"'".into(),
        _ => {
            // strconv.Quote(string(c)): the byte as the rune of the same number
            let q = gotext::quote(&char::from(c).to_string());
            format!("'{}'", &q[1..q.len() - 1])
        }
    }
}

enum Stop {
    /// A syntax error at a byte: Go's "invalid character ..." text.
    Syntax(String),
    /// The input ended inside the value.
    End,
}

fn syn<T>(c: u8, context: &str) -> Result<T, Stop> {
    Err(Stop::Syntax(format!("invalid character {} {context}", quote_char(c))))
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.b.get(self.i).is_some_and(|&c| is_ws(c)) {
            self.i += 1;
        }
    }

    fn peek(&self) -> Result<u8, Stop> {
        self.b.get(self.i).copied().ok_or(Stop::End)
    }

    fn value(&mut self) -> Result<Value, Stop> {
        let c = self.peek()?;
        match c {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Ok(Value::String(self.string()?)),
            b't' => self.word(b"true", Value::Bool(true)),
            b'f' => self.word(b"false", Value::Bool(false)),
            b'n' => self.word(b"null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => syn(c, "looking for beginning of value"),
        }
    }

    fn word(&mut self, w: &[u8], v: Value) -> Result<Value, Stop> {
        let name = std::str::from_utf8(w).unwrap_or("");
        self.i += 1;
        for &want in &w[1..] {
            let c = self.peek()?;
            if c != want {
                return syn(c, &format!("in literal {name} (expecting '{}')", want as char));
            }
            self.i += 1;
        }
        Ok(v)
    }

    fn enter(&mut self, c: u8) -> Result<(), Stop> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return syn(c, "exceeded max depth");
        }
        Ok(())
    }

    fn object(&mut self) -> Result<Value, Stop> {
        self.enter(b'{')?;
        self.i += 1;
        let mut members = Vec::new();
        self.ws();
        if self.peek()? == b'}' {
            self.i += 1;
            self.depth -= 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.ws();
            let c = self.peek()?;
            if c != b'"' {
                return syn(c, "looking for beginning of object key string");
            }
            let k = self.string()?;
            self.ws();
            let c = self.peek()?;
            if c != b':' {
                return syn(c, "after object key");
            }
            self.i += 1;
            self.ws();
            let v = self.value()?;
            members.push((k, v));
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Value::Object(members));
                }
                c => return syn(c, "after object key:value pair"),
            }
        }
    }

    fn array(&mut self) -> Result<Value, Stop> {
        self.enter(b'[')?;
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek()? == b']' {
            self.i += 1;
            self.depth -= 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Value::Array(items));
                }
                c => return syn(c, "after array element"),
            }
        }
    }

    fn digits(&mut self) {
        while self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
            self.i += 1;
        }
    }

    fn number(&mut self) -> Result<Value, Stop> {
        let start = self.i;
        if self.b[self.i] == b'-' {
            self.i += 1;
        }
        match self.peek()? {
            b'0' => self.i += 1,
            b'1'..=b'9' => self.digits(),
            c => return syn(c, "in numeric literal"),
        }
        // a number may end the input (a top-level "5"); the stream reader then knows it is complete
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            let c = self.peek()?;
            if !c.is_ascii_digit() {
                return syn(c, "after decimal point in numeric literal");
            }
            self.digits();
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek()?, b'+' | b'-') {
                self.i += 1;
            }
            let c = self.peek()?;
            if !c.is_ascii_digit() {
                return syn(c, "in exponent of numeric literal");
            }
            self.digits();
        }
        Ok(Value::Number(String::from_utf8_lossy(&self.b[start..self.i]).into_owned()))
    }

    fn hex4(&mut self) -> Result<u32, Stop> {
        let mut v = 0u32;
        for _ in 0..4 {
            let c = self.peek()?;
            let d = (c as char).to_digit(16);
            match d {
                Some(d) => v = v * 16 + d,
                None => return syn(c, "in \\u hexadecimal character escape"),
            }
            self.i += 1;
        }
        Ok(v)
    }

    /// Four hex digits of a `\u` escape at `at` without moving (Go's getu4 for the second half of a pair).
    fn u4_at(&self, at: usize) -> Option<u32> {
        let h = self.b.get(at..at + 6)?;
        if h[0] != b'\\' || h[1] != b'u' {
            return None;
        }
        let mut v = 0u32;
        for &c in &h[2..] {
            v = v * 16 + (c as char).to_digit(16)?;
        }
        Some(v)
    }

    fn string(&mut self) -> Result<String, Stop> {
        self.i += 1; // the opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let run = self.i;
            while let Some(&c) = self.b.get(self.i) {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            out.extend_from_slice(&self.b[run..self.i]);
            let c = self.peek()?;
            match c {
                b'"' => {
                    self.i += 1;
                    // stray bytes become U+FFFD one by one, as Go's decoder writes them
                    return Ok(gotext::lossy_owned(out));
                }
                c if c < 0x20 => return syn(c, "in string literal"),
                _ => {
                    self.i += 1; // the backslash
                    let e = self.peek()?;
                    let simple = match e {
                        b'"' => Some(b'"'),
                        b'\\' => Some(b'\\'),
                        b'/' => Some(b'/'),
                        b'b' => Some(8),
                        b'f' => Some(12),
                        b'n' => Some(b'\n'),
                        b'r' => Some(b'\r'),
                        b't' => Some(b'\t'),
                        b'u' => None,
                        _ => return syn(e, "in string escape code"),
                    };
                    self.i += 1;
                    if let Some(c) = simple {
                        out.push(c);
                        continue;
                    }
                    let r = self.hex4()?;
                    let mut ch = char::from_u32(r);
                    if (0xD800..0xE000).contains(&r) {
                        // a pair only when a high surrogate is followed by a low one; anything else is U+FFFD (Go)
                        ch = None;
                        if r < 0xDC00 {
                            if let Some(r2) = self.u4_at(self.i) {
                                if (0xDC00..0xE000).contains(&r2) {
                                    ch = char::from_u32(0x10000 + ((r - 0xD800) << 10) + (r2 - 0xDC00));
                                    self.i += 6;
                                }
                            }
                        }
                    }
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.unwrap_or('\u{FFFD}').encode_utf8(&mut buf).as_bytes());
                }
            }
        }
    }
}

/// Reads one whole document, as Go's `json.Unmarshal` does (white space around it allowed, nothing else).
pub fn parse(b: &[u8]) -> Result<Value, Error> {
    let mut p = Parser { b, i: 0, depth: 0 };
    p.ws();
    let v = match p.value() {
        Ok(v) => v,
        Err(Stop::End) => return Err(Error("unexpected end of JSON input".into())),
        Err(Stop::Syntax(s)) => return Err(Error(s)),
    };
    p.ws();
    if let Some(&c) = b.get(p.i) {
        return Err(Error(format!("invalid character {} after top-level value", quote_char(c))));
    }
    Ok(v)
}

/// Reads the first value of a stream, as one `json.Decoder.Decode` call does: what follows it is not looked at. An empty
/// stream (white space only) is Go's io.EOF ("EOF"), one cut short io.ErrUnexpectedEOF ("unexpected EOF").
pub fn parse_first(b: &[u8]) -> Result<Value, Error> {
    let mut p = Parser { b, i: 0, depth: 0 };
    p.ws();
    if p.i >= b.len() {
        return Err(Error("EOF".into()));
    }
    match p.value() {
        Ok(v) => Ok(v),
        Err(Stop::End) => Err(Error("unexpected EOF".into())),
        Err(Stop::Syntax(s)) => Err(Error(s)),
    }
}

/// Reads the first value of a stream and says whether more than white space follows it (Decoder.More).
pub fn parse_first_more(b: &[u8]) -> Result<(Value, bool), Error> {
    let mut p = Parser { b, i: 0, depth: 0 };
    p.ws();
    if p.i >= b.len() {
        return Err(Error("EOF".into()));
    }
    let v = match p.value() {
        Ok(v) => v,
        Err(Stop::End) => return Err(Error("unexpected EOF".into())),
        Err(Stop::Syntax(s)) => return Err(Error(s)),
    };
    p.ws();
    Ok((v, p.i < b.len()))
}

// ---- reading a value into Go-typed targets ----

/// Go's field-name match for keys of a struct: the key equals the field name, ignoring case (ASCII letters, plus the long s
/// and the Kelvin sign, which Go folds to s and k).
pub fn key_matches(key: &str, field: &str) -> bool {
    if key == field {
        return true;
    }
    let mut k = key.chars().map(|c| match c {
        '\u{17F}' => 's',
        '\u{212A}' => 'k',
        c => c.to_ascii_lowercase(),
    });
    let mut f = field.chars();
    loop {
        match (k.next(), f.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) if a == b.to_ascii_lowercase() => {}
            _ => return false,
        }
    }
}

/// The decoder's state while reading one document into typed targets: whether unknown fields are refused, the first error
/// (Go keeps reading after a type error and reports the first), and the error context (the struct being read and the
/// path of field names from the top, as Go's errorContext).
#[derive(Default)]
pub struct Ctx {
    pub strict: bool,
    first: Option<Error>,
    struct_name: &'static str,
    stack: Vec<String>,
}

impl Ctx {
    pub fn new(strict: bool) -> Ctx {
        Ctx { strict, ..Ctx::default() }
    }

    pub fn save(&mut self, e: Error) {
        if self.first.is_none() {
            self.first = Some(e);
        }
    }

    /// Go's UnmarshalTypeError: `what` is "string", "number 1.5", "object", ...; `ty` the Go type's name.
    pub fn type_err(&mut self, what: &str, ty: &str) {
        let msg = if self.struct_name.is_empty() && self.stack.is_empty() {
            format!("json: cannot unmarshal {what} into Go value of type {ty}")
        } else {
            format!("json: cannot unmarshal {what} into Go struct field {}.{} of type {ty}", self.struct_name, self.stack.join("."))
        };
        self.save(Error(msg));
    }

    pub fn mismatch(&mut self, v: &Value, ty: &str) {
        let what = match v {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        };
        self.type_err(what, ty);
    }

    pub fn finish(self) -> Result<(), Error> {
        self.first.map_or(Ok(()), Err)
    }

    /// Reads the members of an object into a struct of the given JSON field names: `each(index, value, ctx)` for each member
    /// that names a field (exactly, else without regard to case), in document order; an unknown member is refused when
    /// strict. `go_name` is the struct's Go type name without its package, `ty` its full name for a type error.
    pub fn read_struct(
        &mut self,
        v: &Value,
        go_name: &'static str,
        ty: &str,
        fields: &[&'static str],
        mut each: impl FnMut(usize, &Value, &mut Ctx),
    ) {
        let members = match v {
            Value::Null => return,
            Value::Object(m) => m,
            other => return self.mismatch(other, ty),
        };
        let (saved_name, saved_len) = (self.struct_name, self.stack.len());
        for (k, val) in members {
            let idx = fields.iter().position(|f| f == k).or_else(|| fields.iter().position(|f| key_matches(k, f)));
            match idx {
                Some(i) => {
                    self.struct_name = go_name;
                    self.stack.push(fields[i].to_string());
                    each(i, val, self);
                    self.stack.truncate(saved_len);
                    self.struct_name = saved_name;
                }
                None if self.strict => self.save(Error(format!("json: unknown field {}", gotext::quote(k)))),
                None => {}
            }
        }
    }
}

/// A Go-typed target: how one JSON value is read into it. Null leaves the target as it was (Go), except for slices, maps
/// and pointers, which Go sets to nil. `ty` is the Go type's name as a type error names it.
pub trait FromGo {
    fn read(&mut self, v: &Value, cx: &mut Ctx, ty: &str);
}

impl FromGo for String {
    fn read(&mut self, v: &Value, cx: &mut Ctx, ty: &str) {
        match v {
            Value::Null => {}
            Value::String(s) => self.clone_from(s),
            other => cx.mismatch(other, ty),
        }
    }
}

impl FromGo for bool {
    fn read(&mut self, v: &Value, cx: &mut Ctx, ty: &str) {
        match v {
            Value::Null => {}
            Value::Bool(b) => *self = *b,
            other => cx.mismatch(other, ty),
        }
    }
}

macro_rules! go_int {
    ($t:ty) => {
        impl FromGo for $t {
            fn read(&mut self, v: &Value, cx: &mut Ctx, ty: &str) {
                match v {
                    Value::Null => {}
                    Value::Number(n) => match n.parse::<$t>() {
                        Ok(x) => *self = x,
                        Err(_) => cx.type_err(&format!("number {n}"), ty),
                    },
                    other => cx.mismatch(other, ty),
                }
            }
        }
    };
}
go_int!(i64);
go_int!(i32);
go_int!(u64);
go_int!(u32);

impl<T: FromGo + Default> FromGo for Vec<T> {
    fn read(&mut self, v: &Value, cx: &mut Ctx, ty: &str) {
        let elem = ty.strip_prefix("[]").unwrap_or(ty);
        match v {
            Value::Null => self.clear(),
            Value::Array(items) => {
                // Go reuses the slice: elements are read into it, its length becomes the array's
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    let mut x = T::default();
                    x.read(it, cx, elem);
                    out.push(x);
                }
                *self = out;
            }
            other => cx.mismatch(other, ty),
        }
    }
}

impl<T: FromGo + Default> FromGo for std::collections::BTreeMap<String, T> {
    fn read(&mut self, v: &Value, cx: &mut Ctx, ty: &str) {
        let elem = ty.strip_prefix("map[string]").unwrap_or(ty);
        match v {
            Value::Null => self.clear(),
            Value::Object(members) => {
                // Go keeps an existing map and adds to it; a value that does not read is not stored
                for (k, it) in members {
                    let before = cx.first.is_some();
                    let mut x = T::default();
                    // Go (1.27) names a map element by its key in the field path ("openReq.evidence.a")
                    cx.stack.push(k.clone());
                    x.read(it, cx, elem);
                    cx.stack.pop();
                    if before || cx.first.is_none() {
                        self.insert(k.clone(), x);
                    }
                }
            }
            other => cx.mismatch(other, ty),
        }
    }
}

/// A Go pointer field (`*bool`, `*[]string`, `*manifest.Network`): null sets it to nil, anything else allocates.
impl<T: FromGo + Default> FromGo for Option<T> {
    fn read(&mut self, v: &Value, cx: &mut Ctx, ty: &str) {
        let elem = ty.strip_prefix('*').unwrap_or(ty);
        match v {
            Value::Null => *self = None,
            _ => {
                let mut x = self.take().unwrap_or_default();
                x.read(v, cx, elem);
                *self = Some(x);
            }
        }
    }
}

impl FromGo for crate::gotime::Time {
    fn read(&mut self, v: &Value, cx: &mut Ctx, ty: &str) {
        match v {
            Value::Null => {}
            Value::String(s) => match crate::gotime::Time::parse_rfc3339(s) {
                Some(t) => *self = t,
                None => cx.save(Error(format!("parsing time {} as \"2006-01-02T15:04:05Z07:00\": cannot parse", gotext::quote(s)))),
            },
            other => cx.mismatch(other, ty),
        }
    }
}

impl FromGo for Value {
    fn read(&mut self, v: &Value, _cx: &mut Ctx, _ty: &str) {
        *self = v.clone();
    }
}

/// Declares how a struct reads from JSON the way Go's decoder would: `Type as "GoName" { field: "json" => "go type", ... }`.
#[macro_export]
macro_rules! go_struct {
    ($ty:ty as $go:literal { $($field:ident : $name:literal => $gty:literal),* $(,)? }) => {
        impl $crate::gojson::FromGo for $ty {
            fn read(&mut self, v: &$crate::gojson::Value, cx: &mut $crate::gojson::Ctx, ty: &str) {
                const NAMES: &[&str] = &[$($name),*];
                const TYPES: &[&str] = &[$($gty),*];
                let short: &'static str = match $go.rsplit_once('.') { Some((_, s)) => s, None => $go };
                cx.read_struct(v, short, ty, NAMES, |i, val, cx| {
                    let mut k = 0usize;
                    $(
                        if i == k {
                            $crate::gojson::FromGo::read(&mut self.$field, val, cx, TYPES[k]);
                        }
                        k += 1;
                    )*
                    let _ = k;
                });
            }
        }
    };
}

/// `json.Unmarshal(b, &v)` starting from `init`.
pub fn unmarshal<T: FromGo>(b: &[u8], mut init: T, ty: &str) -> Result<T, Error> {
    let v = parse(b)?;
    let mut cx = Ctx::new(false);
    init.read(&v, &mut cx, ty);
    cx.finish().map(|_| init)
}

/// One `Decode` of a `json.Decoder` (with `DisallowUnknownFields` when `strict`) over `b`, starting from `init`. The value
/// is returned with the error too, as far as it was read (Go leaves the target partly filled).
pub fn decode<T: FromGo>(b: &[u8], mut init: T, ty: &str, strict: bool) -> (T, Result<(), Error>) {
    let v = match parse_first(b) {
        Ok(v) => v,
        Err(e) => return (init, Err(e)),
    };
    let mut cx = Ctx::new(strict);
    init.read(&v, &mut cx, ty);
    let r = cx.finish();
    (init, r)
}

// ---- writing, as Go's encoder ----

/// Appends `s` as a JSON string the way Go's encoder writes it (HTML-safe escaping on, as `json.Marshal` and `Encoder` do).
pub fn write_str(out: &mut String, s: &str) {
    use std::fmt::Write;
    out.push('"');
    let mut start = 0;
    for (i, c) in s.char_indices() {
        let esc: Option<&str> = match c {
            '"' => Some("\\\""),
            '\\' => Some("\\\\"),
            '\n' => Some("\\n"),
            '\r' => Some("\\r"),
            '\t' => Some("\\t"),
            '\u{8}' => Some("\\b"),
            '\u{c}' => Some("\\f"),
            _ => None,
        };
        let needs_u = matches!(c, '<' | '>' | '&' | '\u{2028}' | '\u{2029}') || (c as u32) < 0x20;
        if esc.is_none() && !needs_u {
            continue;
        }
        out.push_str(&s[start..i]);
        match esc {
            Some(e) => out.push_str(e),
            None => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
        }
        start = i + c.len_utf8();
    }
    out.push_str(&s[start..]);
    out.push('"');
}

/// A JSON string as Go writes it.
pub fn str_json(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    write_str(&mut o, s);
    o
}

/// Writes a value compactly as Go would (members in the order held).
pub fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(n),
        Value::String(s) => write_str(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, it);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, it)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write_value(out, it);
            }
            out.push('}');
        }
    }
}

/// Go's `json.MarshalIndent(v, "", indent)` layout of a compact document Go wrote (or `write_value` did): one member or
/// element per line, `": "` after a key, empty arrays and objects as `[]` and `{}`.
pub fn indent(compact: &str, indent: &str) -> String {
    match parse(compact.as_bytes()) {
        Ok(v) => {
            let mut out = String::with_capacity(compact.len() * 2);
            write_indented(&mut out, &v, indent);
            out
        }
        Err(_) => compact.to_owned(),
    }
}

pub fn write_indented(out: &mut String, v: &Value, indent: &str) {
    fn go(out: &mut String, v: &Value, indent: &str, depth: usize) {
        let nl = |out: &mut String, d: usize| {
            out.push('\n');
            for _ in 0..d {
                out.push_str(indent);
            }
        };
        match v {
            Value::Array(items) if !items.is_empty() => {
                out.push('[');
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    nl(out, depth + 1);
                    go(out, it, indent, depth + 1);
                }
                nl(out, depth);
                out.push(']');
            }
            Value::Object(m) if !m.is_empty() => {
                out.push('{');
                for (i, (k, it)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    nl(out, depth + 1);
                    write_str(out, k);
                    out.push_str(": ");
                    go(out, it, indent, depth + 1);
                }
                nl(out, depth);
                out.push('}');
            }
            other => write_value(out, other),
        }
    }
    go(out, v, indent, 0)
}

/// A builder for one JSON object written in a fixed member order, as Go writes a struct (or sorted keys, for a map).
pub struct Obj {
    out: String,
    first: bool,
}

impl Default for Obj {
    fn default() -> Self {
        Obj::new()
    }
}

impl Obj {
    pub fn new() -> Obj {
        Obj { out: String::from("{"), first: true }
    }

    fn key(&mut self, k: &str) {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        write_str(&mut self.out, k);
        self.out.push(':');
    }

    pub fn str(mut self, k: &str, v: &str) -> Obj {
        self.key(k);
        write_str(&mut self.out, v);
        self
    }

    /// `omitempty` on a string.
    pub fn str_omit(self, k: &str, v: &str) -> Obj {
        if v.is_empty() {
            self
        } else {
            self.str(k, v)
        }
    }

    pub fn int(mut self, k: &str, v: i64) -> Obj {
        self.key(k);
        self.out.push_str(&v.to_string());
        self
    }

    pub fn int_omit(self, k: &str, v: i64) -> Obj {
        if v == 0 {
            self
        } else {
            self.int(k, v)
        }
    }

    pub fn bool(mut self, k: &str, v: bool) -> Obj {
        self.key(k);
        self.out.push_str(if v { "true" } else { "false" });
        self
    }

    pub fn bool_omit(self, k: &str, v: bool) -> Obj {
        if v {
            self.bool(k, v)
        } else {
            self
        }
    }

    /// A value already written as JSON.
    pub fn raw(mut self, k: &str, json: &str) -> Obj {
        self.key(k);
        self.out.push_str(json);
        self
    }

    pub fn strs(mut self, k: &str, v: &[String]) -> Obj {
        self.key(k);
        self.out.push_str(&strs(v));
        self
    }

    /// A []string that Go writes as null when it is nil (here: `None`).
    pub fn strs_nil(mut self, k: &str, v: Option<&[String]>) -> Obj {
        self.key(k);
        match v {
            Some(v) => self.out.push_str(&strs(v)),
            None => self.out.push_str("null"),
        }
        self
    }

    pub fn map(mut self, k: &str, m: &std::collections::BTreeMap<String, String>) -> Obj {
        self.key(k);
        self.out.push_str(&map(m));
        self
    }

    pub fn end(mut self) -> String {
        self.out.push('}');
        self.out
    }
}

/// A []string as Go writes it (a non-nil one).
pub fn strs(v: &[String]) -> String {
    let mut o = String::from("[");
    for (i, s) in v.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        write_str(&mut o, s);
    }
    o.push(']');
    o
}

/// A map[string]string as Go writes it: keys sorted.
pub fn map(m: &std::collections::BTreeMap<String, String>) -> String {
    let mut o = String::from("{");
    for (i, (k, v)) in m.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        write_str(&mut o, k);
        o.push(':');
        write_str(&mut o, v);
    }
    o.push('}');
    o
}

/// A list of values already written as JSON.
pub fn list(items: &[String]) -> String {
    let mut o = String::from("[");
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(s);
    }
    o.push(']');
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lone_surrogates_and_stray_bytes_read_as_go_reads_them() {
        let v = parse(br#""a\ud800b\udc00c\ud83d\ude00d\ud800\u0041""#).unwrap();
        assert_eq!(v, Value::String("a\u{FFFD}b\u{FFFD}c\u{1F600}d\u{FFFD}A".into()));
        let v = parse(b"\"x\xff\xe2\x84y\"").unwrap();
        assert_eq!(v, Value::String("x\u{FFFD}\u{FFFD}\u{FFFD}y".into()));
    }

    #[test]
    fn syntax_errors_read_as_go_writes_them() {
        // each from Go 1.27: json.Unmarshal(doc, &v) and json.NewDecoder(doc).Decode(&v)
        for (doc, unmarshal, decode) in [
            (&b"{\"a\":1,}"[..], "invalid character '}' looking for beginning of object key string", "same"),
            (b"[1 2]", "invalid character '2' after array element", "same"),
            (b"{\"a\" 1}", "invalid character '1' after object key", "same"),
            (b"{\"a\":1 \"b\"}", "invalid character '\"' after object key:value pair", "same"),
            (b"\"\x01\"", "invalid character '\\x01' in string literal", "same"),
            (b"\"\\x\"", "invalid character 'x' in string escape code", "same"),
            (b"\"\\u12g4\"", "invalid character 'g' in \\u hexadecimal character escape", "same"),
            (b"tru", "unexpected end of JSON input", "unexpected EOF"),
            (b"trUe", "invalid character 'U' in literal true (expecting 'u')", "same"),
            (b"nul", "unexpected end of JSON input", "unexpected EOF"),
            (b"1.x", "invalid character 'x' after decimal point in numeric literal", "same"),
            (b"-x", "invalid character 'x' in numeric literal", "same"),
            (b"1e+", "unexpected end of JSON input", "unexpected EOF"),
            (b"{", "unexpected end of JSON input", "unexpected EOF"),
            (b"'a'", "invalid character '\\'' looking for beginning of value", "same"),
            (b"\xc3\xa9", "invalid character '\u{c3}' looking for beginning of value", "same"),
            (b"  ", "unexpected end of JSON input", "EOF"),
        ] {
            assert_eq!(parse(doc).unwrap_err().0, unmarshal, "{:?}", String::from_utf8_lossy(doc));
            let want = if decode == "same" { unmarshal } else { decode };
            assert_eq!(parse_first(doc).unwrap_err().0, want, "{:?}", String::from_utf8_lossy(doc));
        }
        assert_eq!(parse(b"{} {}").unwrap_err().0, "invalid character '{' after top-level value");
        assert!(parse_first(b"{} {").is_ok());
    }

    #[test]
    fn writes_as_go_writes() {
        let mut s = String::new();
        write_str(&mut s, &gotext::lossy(b"\x08\x0c\n\r\t\x01<>&\xe2\x80\xa8\x7f\xff \xc3\xa9"));
        assert_eq!(s, "\"\\b\\f\\n\\r\\t\\u0001\\u003c\\u003e\\u0026\\u2028\x7f\u{FFFD} é\"");
    }

    #[test]
    fn struct_keys_match_as_in_go() {
        assert!(key_matches("Ring_Size", "ring_size"));
        assert!(key_matches("\u{17F}ession_id", "session_id"));
        assert!(!key_matches("ringsize", "ring_size"));
    }
}
