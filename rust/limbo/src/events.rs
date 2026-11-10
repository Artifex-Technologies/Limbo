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
