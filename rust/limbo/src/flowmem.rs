//! The flow aggregator's "first time" memory kept across restarts of `limbo serve` (LIM-6), so a restart does not report
//! a guest's known flows as new again. Kept in the state folder (`flows-seen.json`, root's, 0600; `/run/limbo` is emptied
//! at every stop) and written at most every 30 seconds while it changes, and at the stop.
//!
//! Each guest's entry names the SHA-256 of the guest's manifest when it was written. A guest torn down while the daemon
//! was stopped and made again under the same name has a new manifest, so it starts afresh and its flows are reported as
//! new; a guest without a manifest now is not taken back at all. A damaged file is ignored (every flow is new again, as
//! before this memory existed), never trusted further than its bounds.

use crate::engine;
use crate::flows::{Aggregator, Memory};
use crate::gojson::{self, Value};
use crate::manifest;
use crate::sys;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io;

pub const FILE: &str = "flows-seen.json";
/// At most this many guests and flows a guest are read back (the aggregator's own bounds).
const MAX_GUESTS: usize = 128;
const MAX_FLOWS: usize = 256;
const MAX_BYTES: u64 = 4 << 20;

/// The SHA-256 of a guest's manifest now, or None when it has none (or the name is not a guest's).
fn manifest_sum(state_dir: &str, guest: &str) -> Option<String> {
    if !manifest::name_ok(guest) {
        return None;
    }
    let b = std::fs::read(engine::manifest_path(state_dir, guest)).ok()?;
    Some(sys::hex(&Sha256::digest(&b)))
}

/// The memory as the file holds it: guests by name, each with its manifest's SHA-256 (a guest without a manifest is left
/// out: it cannot be told apart from a new one of the same name later).
pub fn to_json(state_dir: &str, mem: &BTreeMap<String, Memory>) -> String {
    let mut out = String::from("{\"version\":1,\"guests\":{");
    let mut first = true;
    for (g, m) in mem {
        let Some(sum) = manifest_sum(state_dir, g) else { continue };
        if !first {
            out.push(',');
        }
        first = false;
        let seen: Vec<String> = m.seen.iter().map(|k| gojson::str_json(k)).collect();
        out.push_str(&format!(
            "{}:{{\"manifest\":{},\"capped\":{},\"seen\":[{}]}}",
            gojson::str_json(g),
            gojson::str_json(&sum),
            m.capped,
            seen.join(",")
        ));
    }
    out.push_str("}}\n");
    out
}

/// What the file says about each guest whose manifest is the one it was written with.
pub fn from_json(state_dir: &str, b: &[u8]) -> BTreeMap<String, Memory> {
    let get = |o: &Value, k: &str| -> Option<Value> {
        match o {
            Value::Object(ms) => ms.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.clone()),
            _ => None,
        }
    };
    let mut out = BTreeMap::new();
    let Ok(doc) = gojson::parse(b) else { return out };
    if !matches!(get(&doc, "version"), Some(Value::Number(n)) if n == "1") {
        return out;
    }
    let Some(Value::Object(guests)) = get(&doc, "guests") else { return out };
    for (g, entry) in guests.into_iter().take(MAX_GUESTS) {
        let Some(Value::String(sum)) = get(&entry, "manifest") else { continue };
        if manifest_sum(state_dir, &g).as_deref() != Some(sum.as_str()) {
            continue;
        }
        let capped = matches!(get(&entry, "capped"), Some(Value::Bool(true)));
        let Some(Value::Array(keys)) = get(&entry, "seen") else { continue };
        let mut seen: Vec<String> = keys
            .into_iter()
            .filter_map(|k| match k {
                Value::String(s) if s.len() <= 128 => Some(s),
                _ => None,
            })
            .take(MAX_FLOWS)
            .collect();
        seen.sort();
        seen.dedup();
        out.insert(g, Memory { capped, seen });
    }
    out
}

/// Writes the aggregator's memory (through a file beside it, renamed over, so a stop halfway leaves the old one).
pub fn save(state_dir: &str, agg: &Aggregator) -> io::Result<()> {
    let path = sys::join(&[state_dir, FILE]);
    let tmp = format!("{path}.tmp");
    sys::write_file(&tmp, to_json(state_dir, &agg.memory()).as_bytes(), 0o600)?;
    std::fs::rename(&tmp, &path)
}

/// Gives the aggregator back what was remembered of the guests that are still the same ones; the number taken back.
pub fn load(state_dir: &str, agg: &mut Aggregator) -> usize {
    let path = sys::join(&[state_dir, FILE]);
    let b = match std::fs::metadata(&path) {
        Ok(m) if m.is_file() && m.len() <= MAX_BYTES => std::fs::read(&path).unwrap_or_default(),
        _ => return 0,
    };
    let mem = from_json(state_dir, &b);
    let n = mem.len();
    for (g, m) in mem {
        agg.remember(&g, m);
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Emitter;
    use crate::flows::{Ip, Packet};
    use std::sync::{Arc, Mutex};

    struct Kinds(Mutex<Vec<String>>);
    impl Emitter for Kinds {
        fn emit(&self, kind: &str, guest: &str, _d: crate::Detail) -> io::Result<()> {
            self.0.lock().unwrap().push(format!("{kind} {guest}"));
            Ok(())
        }
    }

    fn packet(guest: &str, port: i64) -> Packet {
        Packet { guest: guest.into(), verdict: "a".into(), proto: "tcp".into(), dst: Ip::V4([198, 51, 100, 7]), dport: port, icmp: -1 }
    }

    /// LIM-6: the flows watcher restarted with the memory it saved reports no flow seen before, and still reports a new
    /// one; a guest whose manifest changed (torn down and made again under its name), one with no manifest and a damaged
    /// file all start afresh.
    #[test]
    fn a_restart_does_not_report_known_flows_again() {
        let dir = std::env::temp_dir().join(format!("limbo-flowmem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.to_str().unwrap();
        std::fs::write(engine::manifest_path(d, "lab"), "{\"name\":\"lab\"}").unwrap();
        std::fs::write(engine::manifest_path(d, "web"), "{\"name\":\"web\"}").unwrap();
        let start = |log: &Arc<Kinds>| {
            let mut a = Aggregator::new(Some(log.clone() as Arc<dyn Emitter>), crate::gotime::Time::now);
            load(d, &mut a);
            a
        };
        let log = Arc::new(Kinds(Mutex::new(vec![])));
        let mut a = start(&log);
        for g in ["lab", "web", "gone"] {
            a.handle(&packet(g, 443));
        }
        assert!(a.take_changed() && !a.take_changed(), "changed once, then not until something new");
        save(d, &a).unwrap();
        assert_eq!(log.0.lock().unwrap().len(), 3);
        let mode = std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(dir.join(FILE)).unwrap().permissions());
        assert_eq!(mode & 0o777, 0o600);

        // web is torn down and made again while the daemon is stopped: a new manifest
        std::fs::write(engine::manifest_path(d, "web"), "{\"name\":\"web\",\"memory_mb\":2048}").unwrap();
        let log = Arc::new(Kinds(Mutex::new(vec![])));
        let mut b = start(&log);
        b.handle(&packet("lab", 443));
        b.handle(&packet("lab", 80));
        b.handle(&packet("web", 443));
        b.handle(&packet("gone", 443));
        assert_eq!(
            *log.0.lock().unwrap(),
            ["net.flow lab", "net.flow web", "net.flow gone"],
            "lab's known flow is not new; its new one is; web and gone start afresh"
        );

        // a damaged or foreign file: every flow is new again
        std::fs::write(dir.join(FILE), "{\"version\":2}").unwrap();
        let log = Arc::new(Kinds(Mutex::new(vec![])));
        start(&log).handle(&packet("lab", 443));
        assert_eq!(log.0.lock().unwrap().len(), 1);
        std::fs::write(dir.join(FILE), "not json").unwrap();
        assert!(from_json(d, b"{\"version\":1,\"guests\":{\"../x\":{\"manifest\":\"a\",\"seen\":[\"k\"]}}}").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
