//! The audit trail: an append-only JSON-lines file (Go: internal/events). It is the contract with Heimdall
//! (docs/EVENTS.md) and the evidence trail, so every line is written and synced before the action it describes.

use crate::gojson::{self, Obj};
use crate::gotime::Time;
use crate::Detail;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Mutex;

pub const GUEST_DEFINE: &str = "guest.define";
pub const GUEST_START: &str = "guest.start";
pub const GUEST_STOP: &str = "guest.stop";
pub const POLICY_APPLY: &str = "policy.apply";
pub const POLICY_REMOVE: &str = "policy.remove";
pub const IMAGE_VERIFIED: &str = "image.verified";
pub const IMAGE_REJECTED: &str = "image.rejected";
pub const GATE_BLOCKED: &str = "gate.blocked";
pub const QUARANTINE_OPEN: &str = "quarantine.open";
pub const QUARANTINE_RAISE: &str = "quarantine.raise";
pub const QUARANTINE_ADVISORY: &str = "quarantine.advisory";
pub const QUARANTINE_VERDICT: &str = "quarantine.verdict";
pub const POLICY_RESTRICT: &str = "policy.restrict";
pub const POLICY_RELEASE: &str = "policy.release";
pub const LINK_DOWN: &str = "link.down";
pub const LINK_UP: &str = "link.up";
pub const RUN_START: &str = "run.start";
pub const RUN_END: &str = "run.end";
pub const RUN_ERROR: &str = "run.error";
pub const HARDWARE_STUCK: &str = "hardware.stuck";

/// Writes the audit log. Implemented by [`Logger`], by fakes in tests, and by the daemon's wrapper that tells the flow
/// aggregator about a torn-down guest.
pub trait Emitter: Send + Sync {
    fn emit(&self, kind: &str, guest: &str, detail: Detail) -> io::Result<()>;
}

/// One line, as Go's `json.Marshal(Event{...})` writes it: time, kind, guest, then detail unless it is empty.
pub fn line(t: &Time, kind: &str, guest: &str, detail: &Detail) -> String {
    let mut o = Obj::new().str("time", &t.rfc3339_nano()).str("kind", kind).str("guest", guest);
    if !detail.is_empty() {
        o = o.raw("detail", &gojson::map(detail));
    }
    o.end()
}

/// Appends events to a file (mode 0600, its folder 0700 when made).
pub struct Logger {
    f: Mutex<File>,
    now: fn() -> Time,
}

impl Logger {
    pub fn open(path: &str) -> io::Result<Logger> {
        Self::open_with_clock(path, || Time::now().utc())
    }

    pub fn open_with_clock(path: &str, now: fn() -> Time) -> io::Result<Logger> {
        if let Some(dir) = std::path::Path::new(path).parent() {
            crate::sys::mkdir_all(dir, 0o700)?;
        }
        let f = OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
        Ok(Logger { f: Mutex::new(f), now })
    }
}

impl Emitter for Logger {
    /// Writes one event and syncs it, so an event describing an action that then crashes the host is still on disk.
    fn emit(&self, kind: &str, guest: &str, detail: Detail) -> io::Result<()> {
        let mut b = line(&(self.now)(), kind, guest, &detail);
        b.push('\n');
        let f = self.f.lock().unwrap_or_else(|e| e.into_inner());
        (&*f).write_all(b.as_bytes())?;
        f.sync_all()
    }
}

/// A recorder for tests: every event, in order.
#[derive(Default)]
pub struct Recorder {
    pub events: Mutex<Vec<(String, String, Detail)>>,
    pub fail: std::sync::atomic::AtomicBool,
}

impl Emitter for Recorder {
    fn emit(&self, kind: &str, guest: &str, detail: Detail) -> io::Result<()> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(io::Error::other("disk full"));
        }
        self.events.lock().unwrap_or_else(|e| e.into_inner()).push((kind.into(), guest.into(), detail));
        Ok(())
    }
}

/// One line of the log as Go's `events.Event` reads it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Event {
    pub time: Time,
    pub kind: String,
    pub guest: String,
    pub detail: Option<std::collections::BTreeMap<String, String>>,
}
crate::go_struct!(Event as "events.Event" {
    time: "time" => "time.Time", kind: "kind" => "string", guest: "guest" => "string", detail: "detail" => "map[string]string",
});

impl Event {
    /// A detail value ("" when absent).
    pub fn get(&self, k: &str) -> Option<&str> {
        self.detail.as_ref().and_then(|d| d.get(k)).map(String::as_str)
    }
}

/// bufio.Scanner's limit as Read sets it, and its error text.
const MAX_LINE: usize = 1 << 20;
pub const ERR_TOO_LONG: &str = "bufio.Scanner: token too long";

/// What [`read`] failed with: Go's error text, and whether it is os.IsNotExist.
#[derive(Debug)]
pub struct ReadErr {
    pub not_exist: bool,
    pub msg: String,
}

/// Go's `events.Read`: every line that reads as an event with a kind, and how many lines did not (blank lines are
/// neither). The error is Go's: an open or read failure, or a line longer than the scanner takes (the events before it
/// are returned with it, as Go returns them).
pub fn read(path: &str) -> (Vec<Event>, usize, Option<ReadErr>) {
    use std::io::Read;
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            let msg = crate::sys::go_path_error("open", path, &e);
            return (vec![], 0, Some(ReadErr { not_exist: e.kind() == io::ErrorKind::NotFound, msg }));
        }
    };
    let mut b = vec![];
    let read_err = f.read_to_end(&mut b).err();
    let (mut evs, mut skipped) = (vec![], 0);
    let mut rest = &b[..];
    while !rest.is_empty() {
        let (line, next, terminated) = match rest.iter().position(|&c| c == b'\n') {
            Some(i) => (&rest[..i], &rest[i + 1..], true),
            None => (rest, &rest[rest.len()..], false),
        };
        // the scanner needs the line and its newline in a buffer of at most MAX_LINE bytes
        if line.len() + usize::from(terminated) > MAX_LINE || (!terminated && line.len() >= MAX_LINE) {
            return (evs, skipped, Some(ReadErr { not_exist: false, msg: ERR_TOO_LONG.into() }));
        }
        rest = next;
        let line = crate::cli::commands::trim_space(line);
        if line.is_empty() {
            continue;
        }
        match gojson::unmarshal(line, Event::default(), "events.Event") {
            Ok(e) if !e.kind.is_empty() => evs.push(e),
            _ => skipped += 1,
        }
    }
    if let Some(e) = read_err {
        let msg = crate::sys::go_path_error("read", path, &e);
        return (evs, skipped, Some(ReadErr { not_exist: false, msg }));
    }
    (evs, skipped, None)
}
