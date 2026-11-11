//! Wall-clock times as the Go daemon keeps them: an instant plus the UTC offset it was written with, read and written in
//! RFC 3339 the way Go's `time.Time` JSON does, so the state files Go wrote read the same and the ones written here read in Go.
//! No time-zone database is needed: Heimdall's files carry their offset, and the alerts are in UTC.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds from Go's zero time (January 1, year 1, UTC) to the Unix epoch.
const GO_ZERO_TO_UNIX: i64 = 62_135_596_800;

/// An instant with the offset it is shown in. The zero value is Go's zero time (year 1), which Go writes as
/// "0001-01-01T00:00:00Z" and treats as "never".
#[derive(Clone, Copy, Debug, Default)]
pub struct Time {
    /// Seconds since Go's zero time, UTC.
    secs: i64,
    nanos: u32,
    /// The UTC offset in seconds the time is shown in.
    offset: i32,
}

impl PartialEq for Time {
    /// The same instant (Go's `Equal`), whatever the offset it is shown in.
    fn eq(&self, o: &Time) -> bool {
        self.secs == o.secs && self.nanos == o.nanos
    }
}
impl Eq for Time {}

impl PartialOrd for Time {
    fn partial_cmp(&self, o: &Time) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Time {
    fn cmp(&self, o: &Time) -> std::cmp::Ordering {
        (self.secs, self.nanos).cmp(&(o.secs, o.nanos))
    }
}

const NS: i128 = 1_000_000_000;

impl Time {
    pub fn now() -> Time {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        Time { secs: d.as_secs() as i64 + GO_ZERO_TO_UNIX, nanos: d.subsec_nanos(), offset: 0 }
    }

    pub fn from_unix(secs: i64, nanos: u32) -> Time {
        Time { secs: secs + GO_ZERO_TO_UNIX, nanos, offset: 0 }
    }

    pub fn unix(&self) -> i64 {
        self.secs - GO_ZERO_TO_UNIX
    }

    pub fn unix_nanos(&self) -> i128 {
        self.unix() as i128 * NS + self.nanos as i128
    }

    pub fn is_zero(&self) -> bool {
        self.secs == 0 && self.nanos == 0
    }

    /// The same instant shown in UTC.
    pub fn utc(self) -> Time {
        Time { offset: 0, ..self }
    }

    pub fn offset(&self) -> i32 {
        self.offset
    }

    fn total_nanos(&self) -> i128 {
        self.secs as i128 * NS + self.nanos as i128
    }

    fn from_total(t: i128, offset: i32) -> Time {
        Time { secs: t.div_euclid(NS) as i64, nanos: t.rem_euclid(NS) as u32, offset }
    }

    /// The time `d` nanoseconds later (Go's `Add`).
    #[allow(clippy::should_implement_trait)] // Go's name; an i64 of nanoseconds is not a Time
    pub fn add(self, d: i64) -> Time {
        Time::from_total(self.total_nanos() + d as i128, self.offset)
    }

    /// Nanoseconds from `o` to `self` (Go's `Sub`, saturating at the int64 range as Go does).
    pub fn sub(&self, o: &Time) -> i64 {
        let d = self.total_nanos() - o.total_nanos();
        d.clamp(i64::MIN as i128, i64::MAX as i128) as i64
    }

    pub fn before(&self, o: &Time) -> bool {
        self < o
    }

    pub fn after(&self, o: &Time) -> bool {
        self > o
    }

    /// Go's `Truncate`: rounded down to a multiple of `d` since the zero time (which, for any `d` that divides a day, is a
    /// multiple in UTC as well).
    pub fn truncate(self, d: i64) -> Time {
        if d <= 0 {
            return self;
        }
        let t = self.total_nanos();
        Time::from_total(t - t.rem_euclid(d as i128), self.offset)
    }

    /// (year, month, day, hour, minute, second) in the time's own offset.
    pub fn civil(&self) -> (i64, u32, u32, u32, u32, u32) {
        let local = self.secs + self.offset as i64 - GO_ZERO_TO_UNIX;
        let days = local.div_euclid(86_400);
        let sod = local.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        (y, m, d, (sod / 3600) as u32, (sod / 60 % 60) as u32, (sod % 60) as u32)
    }

    /// Go's `Format("15:04")`.
    pub fn hhmm(&self) -> String {
        let (_, _, _, h, mi, _) = self.civil();
        format!("{h:02}:{mi:02}")
    }

    /// Go's `Format(time.RFC3339Nano)`, which is how `time.Time` is written to JSON.
    pub fn rfc3339_nano(&self) -> String {
        let (y, mo, d, h, mi, s) = self.civil();
        let mut out = if (0..=9999).contains(&y) {
            format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}")
        } else {
            format!("{y}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}")
        };
        if self.nanos != 0 {
            let f = format!("{:09}", self.nanos);
            out.push('.');
            out.push_str(f.trim_end_matches('0'));
        }
        if self.offset == 0 {
            out.push('Z');
        } else {
            let o = self.offset.abs();
            out.push(if self.offset < 0 { '-' } else { '+' });
            out.push_str(&format!("{:02}:{:02}", o / 3600, o / 60 % 60));
        }
        out
    }

    /// Reads RFC 3339 as Go 1.27's `time.Time.UnmarshalJSON` does: `time.Parse(time.RFC3339, s)`, fractional seconds
    /// optional (after a period or a comma), a one-digit hour taken, an offset of up to 24 hours and 60 minutes.
    pub fn parse_rfc3339(s: &str) -> Option<Time> {
        parse_go_rfc3339(s).ok()
    }
}

/// time's own quote(): ASCII as is (with `"` and `\\` escaped), every byte of anything else as `\xNN`.
fn time_quote(b: &[u8]) -> String {
    let mut out = String::from("\"");
    for &c in b {
        if !(b' '..0x80).contains(&c) {
            out.push_str(&format!("\\x{c:02x}"));
        } else {
            if c == b'"' || c == b'\\' {
                out.push('\\');
            }
            out.push(c as char);
        }
    }
    out.push('"');
    out
}

/// `time.Parse(time.RFC3339, s)`: the time, or Go's error text ("parsing time \"x\" as \"2006-01-02T15:04:05Z07:00\":
/// cannot parse \"x\" as \"2006\"", "parsing time \"...\": month out of range", "... extra text: ...").
pub fn parse_go_rfc3339(s: &str) -> Result<Time, String> {
    const LAYOUT: &str = "2006-01-02T15:04:05Z07:00";
    let all = s.as_bytes();
    let cannot = |layout_elem: &[u8], value_elem: &[u8]| {
        format!(
            "parsing time {} as {}: cannot parse {} as {}",
            time_quote(all),
            time_quote(LAYOUT.as_bytes()),
            time_quote(value_elem),
            time_quote(layout_elem)
        )
    };
    let message = |m: &str| format!("parsing time {}{m}", time_quote(all));
    let digit = |v: &[u8], i: usize| v.get(i).is_some_and(u8::is_ascii_digit);
    // getnum(value, fixed)
    let getnum = |v: &[u8], fixed: bool| -> Option<(i64, usize)> {
        if !digit(v, 0) {
            return None;
        }
        if !digit(v, 1) {
            return if fixed { None } else { Some(((v[0] - b'0') as i64, 1)) };
        }
        Some((((v[0] - b'0') * 10 + v[1] - b'0') as i64, 2))
    };
    let mut v = all;
    let (mut year, mut month, mut day, mut hour, mut min, mut sec, mut nanos, mut offset) =
        (0i64, 0i64, 0i64, 0i64, 0i64, 0i64, 0u32, 0i32);
    // the layout as nextStdChunk cuts it: (literal prefix, element)
    for (prefix, elem) in [("", "2006"), ("-", "01"), ("-", "02"), ("T", "15"), (":", "04"), (":", "05"), ("", "Z07:00")] {
        if let Some(&p) = prefix.as_bytes().first() {
            if v.first() != Some(&p) {
                return Err(cannot(prefix.as_bytes(), v));
            }
            v = &v[1..];
        }
        let hold = v;
        let mut range = "";
        let mut bad = false;
        match elem {
            "2006" => {
                if v.len() < 4 || !digit(v, 0) || !v[..4].iter().all(u8::is_ascii_digit) {
                    bad = true;
                } else {
                    year = std::str::from_utf8(&v[..4]).unwrap_or("0").parse().unwrap_or(0);
                    v = &v[4..];
                }
            }
            "01" | "02" | "15" | "04" | "05" => match getnum(v, elem != "15") {
                None => bad = true,
                Some((n, w)) => {
                    v = &v[w..];
                    match elem {
                        "01" => {
                            month = n;
                            if !(1..=12).contains(&n) {
                                range = "month";
                            }
                        }
                        "02" => day = n,
                        "15" if n >= 24 => range = "hour",
                        "15" => hour = n,
                        "04" if n >= 60 => range = "minute",
                        "04" => min = n,
                        "05" if n >= 60 => range = "second",
                        "05" => {
                            sec = n;
                            if v.len() >= 2 && (v[0] == b'.' || v[0] == b',') && digit(v, 1) {
                                let mut n = 2;
                                while digit(v, n) {
                                    n += 1;
                                }
                                // parseNanoseconds: at most nine digits count
                                let digits = std::str::from_utf8(&v[1..n.min(10)]).unwrap_or("0");
                                nanos = format!("{digits:0<9}").parse().unwrap_or(0);
                                v = &v[n..];
                            }
                        }
                        _ => {}
                    }
                }
            },
            _ => {
                if v.first() == Some(&b'Z') {
                    v = &v[1..];
                } else if v.len() < 6 || v[3] != b':' {
                    bad = true;
                } else {
                    match (getnum(&v[1..3], true), getnum(&v[4..6], true)) {
                        (Some((hr, _)), Some((mm, _))) => {
                            if hr > 24 {
                                range = "time zone offset hour";
                            }
                            if mm > 60 {
                                range = "time zone offset minute";
                            }
                            offset = (hr * 3600 + mm * 60) as i32;
                            match v[0] {
                                b'+' => {}
                                b'-' => offset = -offset,
                                _ => bad = true,
                            }
                        }
                        _ => bad = true,
                    }
                    v = &v[6..];
                }
            }
        }
        if !range.is_empty() {
            return Err(message(&format!(": {range} out of range")));
        }
        if bad {
            return Err(cannot(elem.as_bytes(), hold));
        }
    }
    if !v.is_empty() {
        return Err(message(&format!(": extra text: {}", time_quote(v))));
    }
    if day < 1 || day > days_in_month(year, month as u32) as i64 {
        return Err(message(": day out of range"));
    }
    let days = days_from_civil(year, month as u32, day as u32);
    let local = days * 86_400 + hour * 3600 + min * 60 + sec;
    Ok(Time { secs: local - offset as i64 + GO_ZERO_TO_UNIX, nanos, offset })
}

fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_time_is_go_zero() {
        assert_eq!(Time::default().rfc3339_nano(), "0001-01-01T00:00:00Z");
        assert_eq!(Time::parse_rfc3339("0001-01-01T00:00:00Z"), Some(Time::default()));
        assert!(Time::parse_rfc3339("0001-01-01T00:00:00Z").unwrap().is_zero());
    }

    #[test]
    fn round_trips_like_go() {
        for s in ["2026-01-02T03:04:05.12Z", "2026-11-09T08:15:00+01:00", "2024-02-29T23:59:59.999999999-07:30", "1970-01-01T00:00:00Z"] {
            assert_eq!(Time::parse_rfc3339(s).unwrap().rfc3339_nano(), s);
        }
        let t = Time::parse_rfc3339("2026-11-09T08:15:00+01:00").unwrap();
        assert_eq!(t.unix(), 1_794_208_500);
        assert_eq!(t.hhmm(), "08:15");
        assert_eq!(t.utc().hhmm(), "07:15");
        for bad in
            ["2026-02-30T00:00:00Z", "2026-01-02 03:04:05Z", "2026-01-02T03:04:05", "2026-01-02T03:04:05.Z", "x", "2026-01-02T24:00:00Z"]
        {
            assert!(Time::parse_rfc3339(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn truncate_and_arithmetic() {
        let t = Time::parse_rfc3339("2026-11-09T08:17:31.5Z").unwrap();
        assert_eq!(t.truncate(15 * 60 * 1_000_000_000).rfc3339_nano(), "2026-11-09T08:15:00Z");
        let u = t.add(-90 * 1_000_000_000);
        assert_eq!(t.sub(&u), 90 * 1_000_000_000);
        assert!(u.before(&t) && t.after(&u));
    }
}
