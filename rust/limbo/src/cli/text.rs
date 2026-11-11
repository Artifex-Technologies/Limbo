//! What the Go CLI's output is made of, where Rust's own behaviour differs: json.Indent and the compaction json.Marshal
//! gives a RawMessage (both keep each token's own bytes), a top-level member as json.RawMessage, `%v` of a decoded JSON
//! value, `Format(time.RFC3339)`, and the CLI's sizes.

use crate::gojson::{self, Value};
use crate::gotext;
use crate::gotime::Time;

/// The CLI's size(): GiB and MiB with one decimal, else KiB.
pub fn size(n: i64) -> String {
    if n >= 1 << 30 {
        format!("{} GiB", gotext::fixed(n as f64 / (1u64 << 30) as f64, 1))
    } else if n >= 1 << 20 {
        format!("{} MiB", gotext::fixed(n as f64 / (1u64 << 20) as f64, 1))
    } else {
        format!("{} KiB", n >> 10)
    }
}

/// `t.Format(time.RFC3339)`: like RFC3339Nano without the fraction.
pub fn rfc3339(t: &Time) -> String {
    let s = t.rfc3339_nano();
    match (s.find('.'), s.rfind(['Z', '+', '-'])) {
        (Some(dot), Some(z)) if z > dot => format!("{}{}", &s[..dot], &s[z..]),
        _ => s,
    }
}

fn valid(b: &[u8]) -> bool {
    gojson::parse(b).is_ok()
}

/// `json.Indent(&buf, src, "", ind)`: None when src is not one valid JSON value (Go then reports an error). Leading
/// white space is dropped, trailing white space kept, every token's bytes as they were.
pub fn indent(src: &[u8], ind: &str) -> Option<Vec<u8>> {
    if !valid(src) {
        return None;
    }
    let mut out = Vec::with_capacity(src.len() * 2);
    let mut depth = 0usize;
    let mut need_indent = false;
    let mut in_str = false;
    let mut esc = false;
    let mut seen = false;
    let nl = |out: &mut Vec<u8>, d: usize| {
        out.push(b'\n');
        for _ in 0..d {
            out.extend_from_slice(ind.as_bytes());
        }
    };
    for &c in src {
        if in_str {
            out.push(c);
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
            if seen && depth == 0 && !need_indent {
                out.push(c); // trailing space after the value is copied
            }
            continue;
        }
        seen = true;
        if need_indent && c != b']' && c != b'}' {
            need_indent = false;
            depth += 1;
            nl(&mut out, depth);
        }
        match c {
            b'"' => {
                in_str = true;
                out.push(c);
            }
            b'{' | b'[' => {
                need_indent = true;
                out.push(c);
            }
            b',' => {
                out.push(c);
                nl(&mut out, depth);
            }
            b':' => {
                out.push(c);
                out.push(b' ');
            }
            b'}' | b']' => {
                if need_indent {
                    need_indent = false; // an empty object or array stays on its line
                } else {
                    depth -= 1;
                    nl(&mut out, depth);
                }
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    Some(out)
}

/// The compaction json.Marshal applies to a json.RawMessage: white space outside strings dropped, `<`, `>`, `&`,
/// U+2028 and U+2029 in strings escaped, everything else as it was. None when not valid JSON.
pub fn compact_html(src: &[u8]) -> Option<Vec<u8>> {
    if !valid(src) {
        return None;
    }
    let mut out = Vec::with_capacity(src.len());
    let mut in_str = false;
    let mut esc = false;
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        if in_str {
            if esc {
                esc = false;
                out.push(c);
            } else if c == b'\\' {
                esc = true;
                out.push(c);
            } else if c == b'"' {
                in_str = false;
                out.push(c);
            } else if matches!(c, b'<' | b'>' | b'&') {
                out.extend_from_slice(format!("\\u00{:02x}", c).as_bytes());
            } else if c == 0xE2 && i + 2 < src.len() && src[i + 1] == 0x80 && (src[i + 2] == 0xA8 || src[i + 2] == 0xA9) {
                out.extend_from_slice(if src[i + 2] == 0xA8 { b"\\u2028" } else { b"\\u2029" });
                i += 2;
            } else {
                out.push(c);
            }
        } else if c == b'"' {
            in_str = true;
            out.push(c);
        } else if !matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
            out.push(c);
        }
        i += 1;
    }
    Some(out)
}

/// `json.Unmarshal(raw, &map[string]json.RawMessage{})` then `m[key]`: Err when raw does not read as an object of values
/// (Go's error text), Ok(None) when the key is absent, else the bytes of its last occurrence as they were.
pub fn member_raw(raw: &[u8], key: &str) -> Result<Option<Vec<u8>>, String> {
    let v = gojson::parse(raw).map_err(|e| e.0)?;
    match v {
        Value::Object(_) => {}
        Value::Null => return Ok(None),
        other => {
            let what = match other {
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                _ => "array",
            };
            return Err(format!("json: cannot unmarshal {what} into Go value of type map[string]jsontext.Value"));
        }
    }
    // walk the top-level members with their byte spans
    let mut found = None;
    let mut i = skip_ws(raw, 0) + 1; // past '{'
    loop {
        i = skip_ws(raw, i);
        if raw[i] == b'}' {
            break;
        }
        let kend = string_end(raw, i);
        let k = match gojson::parse(&raw[i..kend]) {
            Ok(Value::String(s)) => s,
            _ => String::new(),
        };
        i = skip_ws(raw, kend) + 1; // past ':'
        i = skip_ws(raw, i);
        let vend = value_end(raw, i);
        if k == key {
            found = Some(raw[i..vend].to_vec());
        }
        i = skip_ws(raw, vend);
        if raw[i] == b',' {
            i += 1;
        }
    }
    Ok(found)
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

fn string_end(b: &[u8], i: usize) -> usize {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    j
}

fn value_end(b: &[u8], i: usize) -> usize {
    match b[i] {
        b'"' => string_end(b, i),
        b'{' | b'[' => {
            let mut depth = 0;
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => {
                        j = string_end(b, j);
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return j + 1;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            j
        }
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                j += 1;
            }
            j
        }
    }
}

/// `fmt.Sprint(v)` of what json.Unmarshal puts in an `any`: `<nil>`, `true`, a string as is, a float64 as `%v` writes
/// it, `[a b]`, `map[k:v]` (keys sorted).
pub fn go_v(v: &Value) -> String {
    match v {
        Value::Null => "<nil>".into(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => s.clone(),
        Value::Number(n) => float_v(n.parse::<f64>().unwrap_or(0.0)),
        Value::Array(a) => format!("[{}]", a.iter().map(go_v).collect::<Vec<_>>().join(" ")),
        Value::Object(m) => {
            let mut last: std::collections::BTreeMap<&str, &Value> = std::collections::BTreeMap::new();
            for (k, x) in m {
                last.insert(k, x);
            }
            format!("map[{}]", last.iter().map(|(k, x)| format!("{k}:{}", go_v(x))).collect::<Vec<_>>().join(" "))
        }
    }
}

/// `%v` of a float64 (`%g`, shortest): the shortest digits, in exponent form when the exponent is below -4 or at least 6.
pub fn float_v(x: f64) -> String {
    if x == 0.0 {
        return if x.is_sign_negative() { "-0".into() } else { "0".into() };
    }
    if x.is_infinite() {
        return if x > 0.0 { "+Inf".into() } else { "-Inf".into() };
    }
    if x.is_nan() {
        return "NaN".into();
    }
    let e = format!("{x:e}"); // shortest round-trip digits: "-1.5e21"
    let (mant, exp) = e.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    if !(-4..6).contains(&exp) {
        let sign = if exp < 0 { '-' } else { '+' };
        return format!("{mant}e{sign}{:02}", exp.abs());
    }
    format!("{x}")
}
