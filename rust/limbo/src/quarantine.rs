//! Which guests are held, why, and what a human decided (Go: internal/quarantine). Pure state and rules: a level only ever
//! goes up, a record is decided once, an advisory never changes status. Kani harnesses at the end prove the first two over
//! every level and status; the same claims run exhaustively in the normal tests.

use crate::gojson::{self, Obj};
use crate::gotext;
use crate::gotime::Time;
use crate::{go_struct, sys};
use std::collections::BTreeMap;
use std::io;
use std::sync::Mutex;

pub const LEVEL_RESTRICT: &str = "restrict";
pub const LEVEL_ISOLATE: &str = "isolate";

pub const STATUS_OPEN: &str = "open";
pub const STATUS_SAFE: &str = "safe";
pub const STATUS_DANGEROUS: &str = "dangerous";
pub const STATUS_CLOSED: &str = "closed";

const MAX_REASON: usize = 512;
const MAX_ADVISORY: usize = 8 << 10;
const MAX_ADVISORS: usize = 16;
const MAX_EVIDENCE: usize = 32;
const MAX_EV_KEY: usize = 64;
const MAX_EV_VALUE: usize = 512;

/// How strongly a level holds: 0 for an unknown one.
pub fn rank(level: &str) -> u8 {
    match level {
        LEVEL_RESTRICT => 1,
        LEVEL_ISOLATE => 2,
        _ => 0,
    }
}

/// The errors callers match on, with Go's texts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QErr {
    NotFound,
    NotOpen,
    LowerLevel,
    BadVerdict,
    NotDanger,
    BadLevel,
    TooManyAdvs,
}

impl QErr {
    pub fn text(self) -> &'static str {
        match self {
            QErr::NotFound => "quarantine: no such record",
            QErr::NotOpen => "quarantine: record is not open",
            QErr::LowerLevel => "quarantine: a level can only be raised",
            QErr::BadVerdict => "quarantine: verdict must be safe or dangerous",
            QErr::NotDanger => "quarantine: only a dangerous record can be closed",
            QErr::BadLevel => "quarantine: unknown level",
            QErr::TooManyAdvs => "quarantine: too many advisories on this record",
        }
    }
}

/// A store failure: a rule (QErr) or the disk.
#[derive(Debug)]
pub enum Error {
    Rule(QErr),
    Io(io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Rule(q) => f.write_str(q.text()),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<QErr> for Error {
    fn from(q: QErr) -> Self {
        Error::Rule(q)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Advisory {
    pub source: String,
    pub time: Time,
    pub text: String,
}
go_struct!(Advisory as "quarantine.Advisory" { source: "source" => "string", time: "time" => "time.Time", text: "text" => "string" });

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Verdict {
    pub value: String,
    pub by: String,
    pub note: String,
    pub time: Time,
}
go_struct!(Verdict as "quarantine.Verdict" { value: "value" => "quarantine.Status", by: "by" => "string", note: "note" => "string", time: "time" => "time.Time" });

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Record {
    pub id: String,
    pub guest: String,
    pub reason: String,
    pub source: String,
    pub level: String,
    pub status: String,
    pub opened: Time,
    pub evidence: Option<BTreeMap<String, String>>,
    pub advisory: Option<Vec<Advisory>>,
    pub verdict: Option<Verdict>,
}
go_struct!(Record as "quarantine.Record" {
    id: "id" => "string", guest: "guest" => "string", reason: "reason" => "string", source: "source" => "string",
    level: "level" => "quarantine.Level", status: "status" => "quarantine.Status", opened: "opened" => "time.Time",
    evidence: "evidence" => "map[string]string", advisory: "advisory" => "[]quarantine.Advisory",
    verdict: "verdict" => "*quarantine.Verdict",
});

impl Record {
    /// Go's json.Marshal of the record.
    pub fn json(&self) -> String {
        let mut o = Obj::new()
            .str("id", &self.id)
            .str("guest", &self.guest)
            .str("reason", &self.reason)
            .str("source", &self.source)
            .str("level", &self.level)
            .str("status", &self.status)
            .str("opened", &self.opened.rfc3339_nano());
        if let Some(ev) = self.evidence.as_ref().filter(|m| !m.is_empty()) {
            o = o.map("evidence", ev);
        }
        if let Some(adv) = self.advisory.as_ref().filter(|a| !a.is_empty()) {
            let items: Vec<String> = adv
                .iter()
                .map(|a| Obj::new().str("source", &a.source).str("time", &a.time.rfc3339_nano()).str("text", &a.text).end())
                .collect();
            o = o.raw("advisory", &gojson::list(&items));
        }
        if let Some(v) = &self.verdict {
            let vj = Obj::new().str("value", &v.value).str("by", &v.by).str("note", &v.note).str("time", &v.time.rfc3339_nano()).end();
            o = o.raw("verdict", &vj);
        }
        o.end()
    }

    fn holding(&self) -> bool {
        self.status == STATUS_OPEN || self.status == STATUS_DANGEROUS
    }
}

/// Records as one JSON file each (0600) in a folder.
pub struct Store {
    dir: String,
    recs: Mutex<BTreeMap<String, Record>>,
    now: fn() -> Time,
}

fn now_utc() -> Time {
    Time::now().utc()
}

impl Store {
    pub fn open(dir: &str) -> Result<Store, String> {
        Self::open_with_clock(dir, now_utc)
    }

    pub fn open_with_clock(dir: &str, now: fn() -> Time) -> Result<Store, String> {
        // Go's texts: "mkdir ...", "open DIR: ...", "open|read FILE: ..."
        sys::go_mkdir_all(dir, 0o700)?;
        let mut recs = BTreeMap::new();
        for (name, ft) in sys::read_dir_sorted(dir).map_err(|e| sys::go_path_error("open", dir, &e))? {
            if ft.is_dir() || !name.ends_with(".json") {
                continue;
            }
            let p = sys::join(&[dir, &name]);
            let b = read_file(&p)?;
            let r =
                gojson::unmarshal(&b, Record::default(), "quarantine.Record").map_err(|e| format!("quarantine: {name} is corrupt: {e}"))?;
            recs.insert(r.id.clone(), r);
        }
        Ok(Store { dir: dir.to_string(), recs: Mutex::new(recs), now })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Record>> {
        self.recs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether the guest is held: an open or dangerous record exists.
    pub fn holding(&self, guest: &str) -> Option<Record> {
        self.lock().values().find(|r| r.guest == guest && r.holding()).cloned()
    }

    /// Opens a record, or raises and notes the existing open one. `created` says whether a new record was made.
    pub fn quarantine(
        &self,
        guest: &str,
        reason: &str,
        source: &str,
        level: &str,
        evidence: Option<&BTreeMap<String, String>>,
    ) -> Result<(Record, bool), Error> {
        if rank(level) == 0 {
            return Err(QErr::BadLevel.into());
        }
        let mut recs = self.lock();
        // Go walks its map in random order; at most one record per guest is open, so the order does not matter
        if let Some(r) = recs.values_mut().find(|r| r.guest == guest && r.status == STATUS_OPEN) {
            if rank(level) > rank(&r.level) {
                r.level = level.to_string();
            }
            let ev = r.evidence.get_or_insert_with(BTreeMap::new);
            if ev.len() < MAX_EVIDENCE {
                let k = format!("also[{}]", ev.len());
                ev.insert(k, clean(&format!("{source}: {reason}"), MAX_EV_VALUE));
            }
            let r = r.clone();
            return self.save(&r).map(|_| (r, false));
        }
        let r = Record {
            id: format!("q-{}", sys::rand_hex(6)),
            guest: guest.to_string(),
            reason: clean(reason, MAX_REASON),
            source: clean(source, MAX_EV_KEY),
            level: level.to_string(),
            status: STATUS_OPEN.into(),
            opened: (self.now)(),
            evidence: clean_evidence(evidence),
            advisory: None,
            verdict: None,
        };
        recs.insert(r.id.clone(), r.clone());
        self.save(&r).map(|_| (r, true))
    }

    /// Raises an open record's level; lowering is refused.
    pub fn raise(&self, id: &str, level: &str) -> Result<Record, Error> {
        if rank(level) == 0 {
            return Err(QErr::BadLevel.into());
        }
        let mut recs = self.lock();
        let r = recs.get_mut(id).ok_or(QErr::NotFound)?;
        if r.status != STATUS_OPEN {
            return Err(QErr::NotOpen.into());
        }
        if rank(level) < rank(&r.level) {
            return Err(QErr::LowerLevel.into());
        }
        r.level = level.to_string();
        let r = r.clone();
        self.save(&r).map(|_| r)
    }

    /// Attaches an opinion; it cannot change status or level.
    pub fn add_advisory(&self, id: &str, source: &str, text: &str) -> Result<Record, Error> {
        let mut recs = self.lock();
        let r = recs.get_mut(id).ok_or(QErr::NotFound)?;
        if r.status != STATUS_OPEN {
            return Err(QErr::NotOpen.into());
        }
        let adv = r.advisory.get_or_insert_with(Vec::new);
        if adv.len() >= MAX_ADVISORS {
            return Err(QErr::TooManyAdvs.into());
        }
        adv.push(Advisory { source: clean(source, MAX_EV_KEY), time: (self.now)(), text: clean(text, MAX_ADVISORY) });
        let r = r.clone();
        self.save(&r).map(|_| r)
    }

    /// A human verdict on an open record: the only way out of the open state.
    pub fn decide(&self, id: &str, verdict: &str, by: &str, note: &str) -> Result<Record, Error> {
        if verdict != STATUS_SAFE && verdict != STATUS_DANGEROUS {
            return Err(QErr::BadVerdict.into());
        }
        let mut recs = self.lock();
        let r = recs.get_mut(id).ok_or(QErr::NotFound)?;
        if r.status != STATUS_OPEN {
            return Err(QErr::NotOpen.into());
        }
        r.status = verdict.to_string();
        r.verdict =
            Some(Verdict { value: verdict.to_string(), by: clean(by, MAX_EV_KEY), note: clean(note, MAX_REASON), time: (self.now)() });
        let r = r.clone();
        self.save(&r).map(|_| r)
    }

    /// Finishes a dangerous record, freeing the name.
    pub fn close(&self, id: &str, by: &str) -> Result<Record, Error> {
        let mut recs = self.lock();
        let r = recs.get_mut(id).ok_or(QErr::NotFound)?;
        if r.status != STATUS_DANGEROUS {
            return Err(QErr::NotDanger.into());
        }
        r.status = STATUS_CLOSED.into();
        if let Some(v) = &mut r.verdict {
            v.note = clean(&format!("{} [closed by {by}]", v.note), MAX_REASON);
        }
        let r = r.clone();
        self.save(&r).map(|_| r)
    }

    pub fn get(&self, id: &str) -> Result<Record, Error> {
        self.lock().get(id).cloned().ok_or(Error::Rule(QErr::NotFound))
    }

    /// Every record, newest first.
    pub fn list(&self) -> Vec<Record> {
        let mut out: Vec<Record> = self.lock().values().cloned().collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.opened));
        out
    }

    fn save(&self, r: &Record) -> Result<(), Error> {
        let b = gojson::indent(&r.json(), "  ");
        let path = sys::join(&[&self.dir, &format!("{}.json", r.id)]);
        let tmp = format!("{path}.tmp");
        sys::write_file(&tmp, b.as_bytes(), 0o600).map_err(Error::Io)?;
        std::fs::rename(&tmp, &path).map_err(Error::Io)
    }
}

/// os.ReadFile with Go's error text.
fn read_file(p: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut f = std::fs::File::open(p).map_err(|e| sys::go_path_error("open", p, &e))?;
    let mut b = vec![];
    f.read_to_end(&mut b).map_err(|e| sys::go_path_error("read", p, &e))?;
    Ok(b)
}

/// Bounds a string and strips control characters, newlines and tabs becoming spaces (Go's clean).
pub fn clean(s: &str, max: usize) -> String {
    let mut out = String::new();
    for mut c in s.chars() {
        if gotext::is_control(c) && c != '\n' && c != '\t' {
            continue;
        }
        if c == '\n' || c == '\t' {
            c = ' ';
        }
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

fn clean_evidence(input: Option<&BTreeMap<String, String>>) -> Option<BTreeMap<String, String>> {
    let input = input.filter(|m| !m.is_empty())?;
    let mut out = BTreeMap::new();
    for (k, v) in input {
        if out.len() >= MAX_EVIDENCE {
            break;
        }
        out.insert(clean(k, MAX_EV_KEY), clean(v, MAX_EV_VALUE));
    }
    Some(out)
}

/// Whether a guest is held (engine and instances ask; the store answers, fakes in tests).
pub trait Holder: Send + Sync {
    fn holding(&self, guest: &str) -> Option<Record>;
}

impl Holder for Store {
    fn holding(&self, guest: &str) -> Option<Record> {
        Store::holding(self, guest)
    }
}

/// What a level request does to a held level: the new level, or the refusal. The rule that matters for safety: the
/// result is never weaker than what was held.
pub fn raise_rule(held: &str, requested: &str) -> Result<&'static str, QErr> {
    match (rank(held), rank(requested)) {
        (_, 0) => Err(QErr::BadLevel),
        (h, r) if r < h => Err(QErr::LowerLevel),
        (_, 2) => Ok(LEVEL_ISOLATE),
        _ => Ok(LEVEL_RESTRICT),
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn level(n: u8) -> &'static str {
        match n % 3 {
            0 => "",
            1 => LEVEL_RESTRICT,
            _ => LEVEL_ISOLATE,
        }
    }

    #[kani::proof]
    fn a_raise_never_lowers() {
        let held = level(kani::any());
        let req = level(kani::any());
        kani::assume(rank(held) > 0);
        if let Ok(new) = raise_rule(held, req) {
            assert!(rank(new) >= rank(held));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_raise_never_lowers_exhaustively() {
        for held in [LEVEL_RESTRICT, LEVEL_ISOLATE] {
            for req in ["", "x", LEVEL_RESTRICT, LEVEL_ISOLATE] {
                if let Ok(new) = raise_rule(held, req) {
                    assert!(rank(new) >= rank(held));
                }
            }
        }
    }

    #[test]
    fn clean_bounds_and_strips() {
        assert_eq!(clean("a\u{1b}[31mb\nc\td\u{85}", 100), "a[31mb c d");
        assert_eq!(clean("éé", 3), "é");
        let _ = gotext::quote("x");
    }
}
