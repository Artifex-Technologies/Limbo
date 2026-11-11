//! Go's local time zone (`time.Local`): chosen from $TZ and /etc/localtime exactly as Go's initLocal chooses it, read
//! from a TZif file as LoadLocationFromTZData reads it, and looked up as Location.lookup looks it up (the transitions,
//! then the file's POSIX TZ string past the last one). Go's own rules, not libc's: a $TZ that names no file (a POSIX
//! string such as "<+03>-3") is UTC in Go, so it is UTC here. Go's embedded or GOROOT zoneinfo.zip is not consulted (a
//! -trimpath binary without $GOROOT has neither).

use std::sync::OnceLock;

const ALPHA: i64 = i64::MIN;
const HOUR: i64 = 3600;
const DAY: i64 = 86_400;

#[derive(Clone, Debug, PartialEq)]
struct Zone {
    name: String,
    offset: i64,
    is_dst: bool,
}

#[derive(Clone, Debug)]
struct Trans {
    when: i64,
    index: usize,
}

/// A loaded zone (Go's Location, less its cache, which never changes an answer).
#[derive(Clone, Debug, Default)]
pub struct Location {
    zones: Vec<Zone>,
    tx: Vec<Trans>,
    extend: String,
}

const PLATFORM_SOURCES: [&str; 4] = ["/usr/share/zoneinfo/", "/usr/share/lib/zoneinfo/", "/usr/lib/locale/TZ/", "/etc/zoneinfo"];

/// time.Local: loaded once per process, as Go loads it.
pub fn local() -> &'static Location {
    static L: OnceLock<Location> = OnceLock::new();
    L.get_or_init(|| init_local(std::env::var_os("TZ").map(|v| v.to_string_lossy().into_owned())))
}

/// initLocal for a given $TZ (None: unset).
pub fn init_local(tz: Option<String>) -> Location {
    match tz {
        None => {
            if let Some(z) = load_location("localtime", &["/etc"]) {
                return z;
            }
        }
        Some(tz) if !tz.is_empty() => {
            let tz = tz.strip_prefix(':').unwrap_or(&tz).to_string();
            if tz.starts_with('/') {
                if let Some(z) = load_location(&tz, &[""]) {
                    return z;
                }
            } else if !tz.is_empty() && tz != "UTC" {
                if let Some(z) = load_location(&tz, &PLATFORM_SOURCES) {
                    return z;
                }
            }
        }
        _ => {}
    }
    Location::default() // UTC
}

fn load_location(name: &str, sources: &[&str]) -> Option<Location> {
    for src in sources {
        let path = if src.is_empty() { name.to_string() } else { format!("{src}/{name}") };
        if let Some(data) = read_file(&path) {
            if let Some(l) = from_tzdata(&data) {
                return Some(l);
            }
        }
    }
    None
}

/// time's readFile: at most 10 MB.
fn read_file(p: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(p).ok()?;
    let mut b = vec![];
    f.take(10 << 20).read_to_end(&mut b).ok()?;
    if b.len() >= 10 << 20 {
        return None; // Go: "is too large"
    }
    Some(b)
}

struct Data<'a> {
    p: &'a [u8],
    error: bool,
}

impl<'a> Data<'a> {
    fn read(&mut self, n: usize) -> &'a [u8] {
        if self.p.len() < n {
            self.p = &[];
            self.error = true;
            return &[];
        }
        let (a, b) = self.p.split_at(n);
        self.p = b;
        a
    }
    fn big4(&mut self) -> Option<u32> {
        let p = self.read(4);
        if p.len() < 4 {
            self.error = true;
            return None;
        }
        Some(u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
    }
    fn big8(&mut self) -> Option<u64> {
        let (a, b) = (self.big4(), self.big4());
        Some((a? as u64) << 32 | b? as u64)
    }
    fn byte(&mut self) -> Option<u8> {
        let p = self.read(1);
        p.first().copied().or_else(|| {
            self.error = true;
            None
        })
    }
}

/// LoadLocationFromTZData; None where Go returns errBadData.
pub fn from_tzdata(data: &[u8]) -> Option<Location> {
    let mut d = Data { p: data, error: false };
    if d.read(4) != b"TZif" {
        return None;
    }
    let p = d.read(16);
    if p.len() != 16 {
        return None;
    }
    let version = match p[0] {
        0 => 1,
        b'2' => 2,
        b'3' => 3,
        _ => return None,
    };
    let mut n = [0usize; 6];
    for x in n.iter_mut() {
        *x = d.big4()? as usize;
    }
    let (n_utclocal, n_stdwall, n_leap, n_time, n_zone, n_char) = (0, 1, 2, 3, 4, 5);
    let mut is64 = false;
    if version > 1 {
        let skip = n[n_time] * 4 + n[n_time] + n[n_zone] * 6 + n[n_char] + n[n_leap] * 8 + n[n_stdwall] + n[n_utclocal] + 4 + 16;
        d.read(skip);
        is64 = true;
        for x in n.iter_mut() {
            *x = d.big4()? as usize;
        }
    }
    let size = if is64 { 8 } else { 4 };
    let mut txtimes = Data { p: d.read(n[n_time] * size), error: false };
    let txzones = d.read(n[n_time]);
    let mut zonedata = Data { p: d.read(n[n_zone] * 6), error: false };
    let abbrev = d.read(n[n_char]);
    d.read(n[n_leap] * (size + 4));
    let _isstd = d.read(n[n_stdwall]);
    let _isutc = d.read(n[n_utclocal]);
    if d.error {
        return None;
    }
    let rest = d.p;
    let extend = if rest.len() > 2 && rest[0] == b'\n' && rest[rest.len() - 1] == b'\n' {
        String::from_utf8_lossy(&rest[1..rest.len() - 1]).into_owned()
    } else {
        String::new()
    };
    if n[n_zone] == 0 {
        return None;
    }
    let mut zones = Vec::with_capacity(n[n_zone]);
    for _ in 0..n[n_zone] {
        let off = zonedata.big4()? as i32 as i64;
        let is_dst = zonedata.byte()? != 0;
        let b = zonedata.byte()? as usize;
        if b >= abbrev.len() {
            return None;
        }
        let name = &abbrev[b..];
        let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
        zones.push(Zone { name: String::from_utf8_lossy(name).into_owned(), offset: off, is_dst });
    }
    let mut tx = Vec::with_capacity(n[n_time]);
    for i in 0..n[n_time] {
        let when = if is64 { txtimes.big8()? as i64 } else { txtimes.big4()? as i32 as i64 };
        let index = *txzones.get(i)? as usize;
        if index >= zones.len() {
            return None;
        }
        tx.push(Trans { when, index });
    }
    if tx.is_empty() {
        tx.push(Trans { when: ALPHA, index: 0 });
    }
    Some(Location { zones, tx, extend })
}

impl Location {
    /// Location.lookup: (name, offset in seconds east of UTC, is DST) at Unix time `sec`.
    pub fn lookup(&self, sec: i64) -> (String, i64, bool) {
        if self.zones.is_empty() {
            return ("UTC".into(), 0, false);
        }
        if self.tx.is_empty() || sec < self.tx[0].when {
            let z = &self.zones[self.lookup_first_zone()];
            return (z.name.clone(), z.offset, z.is_dst);
        }
        let (mut lo, mut hi) = (0usize, self.tx.len());
        while hi - lo > 1 {
            let m = (lo + hi) / 2;
            if sec < self.tx[m].when {
                hi = m;
            } else {
                lo = m;
            }
        }
        let z = &self.zones[self.tx[lo].index];
        if lo == self.tx.len() - 1 && !self.extend.is_empty() {
            if let Some((n, o, d)) = tzset(&self.extend, self.tx[lo].when, sec) {
                return (n, o, d);
            }
        }
        (z.name.clone(), z.offset, z.is_dst)
    }

    fn lookup_first_zone(&self) -> usize {
        if !self.tx.iter().any(|t| t.index == 0) {
            return 0;
        }
        if let Some(t0) = self.tx.first() {
            if self.zones[t0.index].is_dst {
                for zi in (0..t0.index).rev() {
                    if !self.zones[zi].is_dst {
                        return zi;
                    }
                }
            }
        }
        self.zones.iter().position(|z| !z.is_dst).unwrap_or(0)
    }
}

fn tzset_name(s: &str) -> Option<(&str, &str)> {
    if s.is_empty() {
        return None;
    }
    if !s.starts_with('<') {
        for (i, r) in s.char_indices() {
            if matches!(r, '0'..='9' | ',' | '-' | '+') {
                if i < 3 {
                    return None;
                }
                return Some((&s[..i], &s[i..]));
            }
        }
        if s.len() < 3 {
            return None;
        }
        Some((s, ""))
    } else {
        let i = s.find('>')?;
        Some((&s[1..i], &s[i + 1..]))
    }
}

fn tzset_num(s: &str, min: i64, max: i64) -> Option<(i64, &str)> {
    if s.is_empty() {
        return None;
    }
    let mut num = 0i64;
    for (i, r) in s.char_indices() {
        if !r.is_ascii_digit() {
            if i == 0 || num < min {
                return None;
            }
            return Some((num, &s[i..]));
        }
        num = num * 10 + (r as i64 - '0' as i64);
        if num > max {
            return None;
        }
    }
    if num < min {
        return None;
    }
    Some((num, ""))
}

fn tzset_offset(s: &str) -> Option<(i64, &str)> {
    let mut s = s;
    if s.is_empty() {
        return None;
    }
    let mut neg = false;
    if let Some(r) = s.strip_prefix('+') {
        s = r;
    } else if let Some(r) = s.strip_prefix('-') {
        s = r;
        neg = true;
    }
    let sign = |o: i64| if neg { -o } else { o };
    let (hours, r) = tzset_num(s, 0, 24 * 7)?;
    let mut off = hours * HOUR;
    let Some(r) = r.strip_prefix(':') else { return Some((sign(off), r)) };
    let (mins, r) = tzset_num(r, 0, 59)?;
    off += mins * 60;
    let Some(r) = r.strip_prefix(':') else { return Some((sign(off), r)) };
    let (secs, r) = tzset_num(r, 0, 59)?;
    Some((sign(off + secs), r))
}

#[derive(Clone, Copy)]
enum Rule {
    Julian { day: i64, time: i64 },
    Doy { day: i64, time: i64 },
    Mwd { mon: i64, week: i64, day: i64, time: i64 },
}

fn tzset_rule(s: &str) -> Option<(Rule, &str)> {
    if s.is_empty() {
        return None;
    }
    enum K {
        J(i64),
        D(i64),
        M(i64, i64, i64),
    }
    let (k, mut s) = if let Some(r) = s.strip_prefix('J') {
        let (d, r) = tzset_num(r, 1, 365)?;
        (K::J(d), r)
    } else if let Some(r) = s.strip_prefix('M') {
        let (mon, r) = tzset_num(r, 1, 12)?;
        let r = r.strip_prefix('.')?;
        let (week, r) = tzset_num(r, 1, 5)?;
        let r = r.strip_prefix('.')?;
        let (day, r) = tzset_num(r, 0, 6)?;
        (K::M(mon, week, day), r)
    } else {
        let (d, r) = tzset_num(s, 0, 365)?;
        (K::D(d), r)
    };
    let time = match s.strip_prefix('/') {
        None => 2 * HOUR,
        Some(r) => {
            let (o, r) = tzset_offset(r)?;
            s = r;
            o
        }
    };
    Some((
        match k {
            K::J(day) => Rule::Julian { day, time },
            K::D(day) => Rule::Doy { day, time },
            K::M(mon, week, day) => Rule::Mwd { mon, week, day, time },
        },
        s,
    ))
}

fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn days_in(m: i64, y: i64) -> i64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_before(m: i64) -> i64 {
    (1..m).map(|x| days_in(x, 1)).sum()
}

fn tzrule_time(year: i64, r: Rule, off: i64) -> i64 {
    let (s, time) = match r {
        Rule::Julian { day, time } => {
            let mut s = (day - 1) * DAY;
            if is_leap(year) && day >= 60 {
                s += DAY;
            }
            (s, time)
        }
        Rule::Doy { day, time } => (day * DAY, time),
        Rule::Mwd { mon, week, day, time } => {
            let m1 = (mon + 9) % 12 + 1;
            let yy0 = if mon <= 2 { year - 1 } else { year };
            let (yy1, yy2) = (yy0 / 100, yy0 % 100);
            let mut dow = ((26 * m1 - 2) / 10 + 1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
            if dow < 0 {
                dow += 7;
            }
            let mut d = day - dow;
            if d < 0 {
                d += 7;
            }
            for _ in 1..week {
                if d + 7 >= days_in(mon, year) {
                    break;
                }
                d += 7;
            }
            d += days_before(mon);
            if is_leap(year) && mon > 2 {
                d += 1;
            }
            (d * DAY, time)
        }
    };
    s + time - off
}

/// (year, day of the year from 1) of a Unix time, UTC.
fn year_yday(sec: i64) -> (i64, i64) {
    let t = crate::gotime::Time::from_unix(sec, 0);
    let (y, m, d, ..) = t.civil();
    let yday = days_before(m as i64) + d as i64 + if is_leap(y) && m > 2 { 1 } else { 0 };
    (y, yday)
}

/// tzset: what a POSIX TZ string says about Unix time `sec` (name, offset, DST), or None when Go cannot read it.
fn tzset(s: &str, _last_tx: i64, sec: i64) -> Option<(String, i64, bool)> {
    let (mut std_name, s) = tzset_name(s)?;
    let (std_off, s) = tzset_offset(s)?;
    let mut std_offset = -std_off;
    if s.is_empty() || s.starts_with(',') {
        return Some((std_name.into(), std_offset, false));
    }
    let (mut dst_name, mut s) = tzset_name(s)?;
    let mut dst_offset = if s.is_empty() || s.starts_with(',') {
        std_offset + HOUR
    } else {
        let (o, r) = tzset_offset(s)?;
        s = r;
        -o
    };
    if s.is_empty() {
        s = ",M3.2.0,M11.1.0";
    }
    if !s.starts_with(',') && !s.starts_with(';') {
        return None;
    }
    let (start_rule, s) = tzset_rule(&s[1..])?;
    let s = s.strip_prefix(',')?;
    let (end_rule, s) = tzset_rule(s)?;
    if !s.is_empty() {
        return None;
    }
    let (year, yday) = year_yday(sec);
    let ysec = (yday - 1) * DAY + sec % DAY;
    let mut start = tzrule_time(year, start_rule, std_offset);
    let mut end = tzrule_time(year, end_rule, dst_offset);
    let (mut dst_is_dst, mut std_is_dst) = (true, false);
    if end < start {
        std::mem::swap(&mut start, &mut end);
        std::mem::swap(&mut std_name, &mut dst_name);
        std::mem::swap(&mut std_offset, &mut dst_offset);
        std::mem::swap(&mut std_is_dst, &mut dst_is_dst);
    }
    if ysec < start || ysec >= end {
        Some((std_name.into(), std_offset, std_is_dst))
    } else {
        Some((dst_name.into(), dst_offset, dst_is_dst))
    }
}

/// `t.Local().Format("2006-01-02 15:04")`.
pub fn local_ymd_hm(t: &crate::gotime::Time) -> String {
    let (_, off, _) = local().lookup(t.unix());
    t.in_offset(off as i32).ymd_hm()
}
