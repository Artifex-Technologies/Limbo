//! Text the way the Go daemon makes it, so the Rust port writes the same answers and events byte for byte.
//! (From Heimdall's port, rust/heimdall/src/gotext; the tables are generated from the Go that builds limbo.)
//!
//! Go strings may hold any bytes; Rust strings are UTF-8. Everything that comes from outside (a file, a journal line) is turned
//! into a Rust string by [`lossy`], which replaces each byte that does not start a valid UTF-8 sequence with U+FFFD, one per
//! byte, exactly as Go's `for range`, its regular expressions and its JSON encoder see such a byte. The rest are Go's
//! formatting rules where Rust's differ: `%q` ([`quote`]), `time.Duration.String` ([`duration`]), `%.Nf` ([`fixed`]),
//! `unicode.IsSpace`/`strings.Fields` ([`is_space`], [`fields`]).

mod tables;

pub use tables::GO_UNICODE_VERSION;

fn in_table(table: &[(u32, u32)], c: char) -> bool {
    let c = c as u32;
    table
        .binary_search_by(|&(lo, hi)| {
            if hi < c {
                std::cmp::Ordering::Less
            } else if lo > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Go's `unicode.IsPrint`.
pub fn is_print(c: char) -> bool {
    if (c as u32) < 0x80 {
        return (0x20..0x7f).contains(&(c as u32));
    }
    in_table(tables::PRINT, c)
}

/// Go's `unicode.IsControl`: C0, DEL and C1.
pub fn is_control(c: char) -> bool {
    let c = c as u32;
    c < 0x20 || (0x7f..=0x9f).contains(&c)
}

/// Go's `unicode.Is(unicode.Cf, c)`.
pub fn is_cf(c: char) -> bool {
    in_table(tables::CF, c)
}

/// Go's `unicode.IsSpace`.
pub fn is_space(c: char) -> bool {
    in_table(tables::SPACE, c)
}

/// Go's `strings.Fields`: the text split around runs of spaces.
pub fn fields(s: &str) -> impl Iterator<Item = &str> {
    s.split(is_space).filter(|w| !w.is_empty())
}

/// Go's `strings.TrimSpace`.
pub fn trim_space(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// Bytes to a string as Go reads them: each byte that does not start a valid UTF-8 sequence becomes one U+FFFD.
pub fn lossy(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_owned(),
        Err(_) => lossy_slow(b),
    }
}

/// [`lossy`] for an owned buffer: no copy when it is valid UTF-8 already.
pub fn lossy_owned(b: Vec<u8>) -> String {
    match String::from_utf8(b) {
        Ok(s) => s,
        Err(e) => lossy_slow(e.as_bytes()),
    }
}

fn lossy_slow(mut b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() + 8);
    loop {
        match std::str::from_utf8(b) {
            Ok(s) => {
                out.push_str(s);
                return out;
            }
            Err(e) => {
                let good = e.valid_up_to();
                // SAFETY-free: the prefix was just checked
                out.push_str(std::str::from_utf8(&b[..good]).unwrap_or_default());
                out.push('\u{FFFD}');
                b = &b[good + 1..];
            }
        }
    }
}

/// Go's `strings.ToValidUTF8(s, "�")`: each run of bytes that are not valid UTF-8 becomes one U+FFFD (unlike
/// [`lossy`], which gives each such byte its own, as Go's `range` and JSON encoder do).
pub fn to_valid_utf8(mut b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    let mut in_run = false;
    loop {
        match std::str::from_utf8(b) {
            Ok(s) => {
                out.push_str(s);
                return out;
            }
            Err(e) => {
                let good = e.valid_up_to();
                if good > 0 {
                    out.push_str(std::str::from_utf8(&b[..good]).unwrap_or_default());
                    in_run = false;
                }
                if !in_run {
                    out.push('\u{FFFD}');
                    in_run = true;
                }
                let bad = e.error_len().unwrap_or(b.len() - good);
                b = &b[good + bad..];
            }
        }
    }
}

/// The first `n` bytes of `s` as Go's `s[:n]` would look once written out: a character cut in two leaves one U+FFFD per byte
/// kept, as Go's encoders show the stray bytes.
pub fn byte_prefix(s: &str, n: usize) -> String {
    if n >= s.len() {
        return s.to_owned();
    }
    let mut cut = n;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = String::with_capacity(n + 6);
    out.push_str(&s[..cut]);
    for _ in cut..n {
        out.push('\u{FFFD}');
    }
    out
}

/// Go's `strconv.Quote` (`%q`) of a valid string.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        quote_char(&mut out, c);
    }
    out.push('"');
    out
}

fn quote_char(out: &mut String, c: char) {
    use std::fmt::Write;
    if c == '"' || c == '\\' {
        out.push('\\');
        out.push(c);
        return;
    }
    if is_print(c) {
        out.push(c);
        return;
    }
    match c {
        '\u{7}' => out.push_str("\\a"),
        '\u{8}' => out.push_str("\\b"),
        '\u{c}' => out.push_str("\\f"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\u{b}' => out.push_str("\\v"),
        c if (c as u32) < 0x20 || c as u32 == 0x7f => {
            let _ = write!(out, "\\x{:02x}", c as u32);
        }
        c if (c as u32) < 0x10000 => {
            let _ = write!(out, "\\u{:04x}", c as u32);
        }
        c => {
            let _ = write!(out, "\\U{:08x}", c as u32);
        }
    }
}

/// Go's `time.Duration.String` for a duration in nanoseconds ("15m0s", "1.5s", "26h0m0s", "0s").
pub fn duration(d: i64) -> String {
    if d == 0 {
        return "0s".into();
    }
    let neg = d < 0;
    let mut u = d.unsigned_abs();
    let mut out = String::new();
    if u < 1_000_000_000 {
        // under a second: ns, µs or ms with a fraction
        let (unit, prec) = if u < 1_000 {
            ("ns", 0)
        } else if u < 1_000_000 {
            ("µs", 3)
        } else {
            ("ms", 6)
        };
        out.push_str(&frac(u, prec));
        out.push_str(unit);
    } else {
        let secs_frac = frac(u % 60_000_000_000, 9);
        out.push_str(&secs_frac);
        out.push('s');
        u /= 60_000_000_000;
        if u > 0 {
            let m = u % 60;
            u /= 60;
            out.insert_str(0, &format!("{m}m"));
            if u > 0 {
                out.insert_str(0, &format!("{u}h"));
            }
        }
    }
    if neg {
        out.insert(0, '-');
    }
    out
}

/// v / 10^prec with the fraction's trailing zeros (and a bare point) dropped, as Go's fmtFrac + fmtInt.
fn frac(v: u64, prec: u32) -> String {
    let p = 10u64.pow(prec);
    let (whole, mut f) = (v / p, v % p);
    let mut s = whole.to_string();
    if f != 0 {
        let mut digits = prec as usize;
        while f % 10 == 0 {
            f /= 10;
            digits -= 1;
        }
        s.push('.');
        s.push_str(&format!("{f:0digits$}"));
    }
    s
}

/// Go's `%.Nf`: Rust's fixed formatting rounds alike (both are exact, ties to even); NaN and the infinities are written as Go
/// writes them.
pub fn fixed(x: f64, prec: usize) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "+Inf".into() } else { "-Inf".into() };
    }
    format!("{x:.prec$}")
}

/// Go's `strconv.ParseFloat(s, 64)` for the values Heimdall reads (decimal and exponent forms, "inf"/"nan" words): `None`
/// where Go returns an error, including out of range.
pub fn parse_float(s: &str) -> Option<f64> {
    let t = s.strip_prefix(['+', '-']).unwrap_or(s);
    let lower = t.to_ascii_lowercase();
    if matches!(lower.as_str(), "inf" | "infinity" | "nan") {
        return s.parse::<f64>().ok(); // Rust reads these words as Go does, any case, with a sign
    }
    // Go accepts hex floats and underscores only in other forms Heimdall never writes; plain decimal is what is checked here.
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-')) {
        return None;
    }
    let v: f64 = s.parse().ok()?;
    if v.is_infinite() {
        return None; // Go: value out of range
    }
    Some(v)
}

/// Go's `strings.ToLower`: each character by its simple lowercase mapping. Rust's `str::to_lowercase` differs in two places:
/// it writes the dotted capital I (U+0130) as two characters where Go writes `i`, and it writes a word-final capital sigma as
/// final sigma where Go writes σ.
pub fn to_lower(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let mut l = c.to_lowercase();
        match (l.next(), l.next()) {
            (Some(one), None) => out.push(one),
            _ => out.push('i'), // U+0130, the only character whose lowercase is longer than one
        }
    }
    out
}

/// Go's `strconv.Atoi`: decimal, optional sign, no spaces, within int64.
pub fn atoi(s: &str) -> Option<i64> {
    let t = s.strip_prefix(['+', '-']).unwrap_or(s);
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lossy_is_one_replacement_per_bad_byte() {
        assert_eq!(lossy(b"a\xffb"), "a\u{FFFD}b");
        // a cut three-byte sequence is two bad bytes to Go, one maximal subpart to Rust's from_utf8_lossy
        assert_eq!(lossy(b"\xe2\x84A"), "\u{FFFD}\u{FFFD}A");
        assert_eq!(lossy(b"\xed\xa0\x80"), "\u{FFFD}\u{FFFD}\u{FFFD}"); // an encoded surrogate
        assert_eq!(lossy("é".as_bytes()), "é");
    }

    #[test]
    fn quote_matches_go() {
        // from Go: fmt.Printf("%q", s) of a, a zero-width space, b, a no-break space, c, \x01, é
        assert_eq!(quote("a\u{200b}b\u{a0}c\u{1}é"), "\"a\x5Cu200bb\x5Cu00a0c\x5Cx01é\"");
        assert_eq!(quote("\u{E0041}"), r#""\U000e0041""#);
        assert_eq!(quote("K\"\\\n"), "\"K\\\"\\\\\\n\"");
    }

    #[test]
    fn durations_match_go() {
        let s = 1_000_000_000i64;
        assert_eq!(duration(15 * 60 * s), "15m0s");
        assert_eq!(duration(5 * 60 * s), "5m0s");
        assert_eq!(duration(90 * s), "1m30s");
        assert_eq!(duration(1_500_000_000), "1.5s");
        assert_eq!(duration(26 * 3600 * s), "26h0m0s");
        assert_eq!(duration(0), "0s");
        assert_eq!(duration(1500), "1.5µs");
        assert_eq!(duration(-2 * s), "-2s");
    }

    #[test]
    fn fixed_matches_go() {
        // from Go: %.2f %.1f %.0f
        assert_eq!(fixed(0.125, 2), "0.12");
        assert_eq!(fixed(0.375, 1), "0.4");
        assert_eq!(fixed(2.5, 0), "2");
        assert_eq!(fixed(0.25, 1), "0.2");
        assert_eq!(fixed(f64::INFINITY, 1), "+Inf");
    }

    #[test]
    fn byte_prefix_cuts_like_go() {
        assert_eq!(byte_prefix("api\u{212A}ey", 4), "api\u{FFFD}");
        assert_eq!(byte_prefix("abcdef", 4), "abcd");
        assert_eq!(byte_prefix("ab", 4), "ab");
    }
}
