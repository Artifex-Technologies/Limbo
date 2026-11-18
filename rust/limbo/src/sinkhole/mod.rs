//! Network mode `sinkhole` (docs/SINKHOLE.md, built 2026-11-18): a guest with no route off the host, whose DNS answers
//! every name with its own gateway address and whose every connection lands on a logging responder there.
//!
//! The pieces: the guest's libvirt network is isolated (virt), its table redirects all IPv4 TCP and UDP to the responder's
//! three ports and forwards nothing (policy), and `limbo serve` runs one responder per guest ([`Service`]) as the
//! unprivileged account `limbo-sinkhole`, from guest start to teardown. The responder (responder.rs) writes one JSON line
//! per record; this side reads them, keeps only the kinds and keys it knows, bounds and escapes every value again
//! (guest-controlled text, untrusted everywhere), drops repeats, caps each guest at [`BUDGET`] records, and writes them
//! as events (`sinkhole.dns`, `sinkhole.connect`) and into the run's result.

pub mod responder;

use crate::events::{self, Emitter};
use crate::gojson::{self, Obj, Value};
use crate::manifest::Manifest;
use crate::{detail, osuser, virt, Detail};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

/// The responder's ports on the guest's gateway address (the guest's table redirects to them; UFW is opened for them).
pub const DNS_PORT: u16 = 7253;
pub const TCP_PORT: u16 = 7280;
pub const UDP_PORT: u16 = 7281;
/// The account the responder runs as (packaging/arch/limbo.sysusers).
pub const ACCOUNT: &str = "limbo-sinkhole";
/// Records written per guest; past it they are counted, and `sinkhole.capped` says so once.
pub const BUDGET: usize = 256;
const MAX_LINE: usize = 16 << 10;
const READY_WAIT: Duration = Duration::from_secs(5);
/// Finished guests whose records a run can still collect.
const KEEP_FINISHED: usize = 8;

/// A value as printable ASCII, at most `max` bytes (anything else is escaped as `\xNN`, as the responder does).
fn clean(v: &str, max: usize) -> String {
    let mut s = responder::escape(v.as_bytes());
    if s.len() > max {
        s.truncate(max);
    }
    s
}

/// A decimal number of at most 10 digits, or "".
fn number(v: &str) -> String {
    if !v.is_empty() && v.len() <= 10 && v.bytes().all(|c| c.is_ascii_digit()) {
        v.to_string()
    } else {
        String::new()
    }
}

/// A dotted IPv4 address, or "".
fn ipv4(v: &str) -> String {
    v.parse::<std::net::Ipv4Addr>().map(|a| a.to_string()).unwrap_or_default()
}

/// What one guest's responder reported.
#[derive(Clone, Debug, Default)]
pub struct Log {
    pub addr: String,
    pub dns: u64,
    pub tcp: u64,
    pub udp: u64,
    /// Records not written: repeats are not counted here, records over the budget and refused connections are.
    pub unrecorded: u64,
    pub recorded: Vec<(String, Detail)>,
    seen: HashSet<String>,
    capped: bool,
}

impl Log {
    /// One line from the responder: the events to write for it (none for a repeat, a line that is not a record, or
    /// one over the budget, which is counted).
    pub fn take(&mut self, line: &[u8]) -> Vec<(&'static str, Detail)> {
        let Ok(Value::Object(members)) = gojson::parse(line) else { return vec![] };
        let mut r: BTreeMap<&str, &str> = BTreeMap::new();
        for (k, v) in &members {
            if let Value::String(s) = v {
                r.insert(k.as_str(), s.as_str());
            }
        }
        let get = |k: &str| r.get(k).copied().unwrap_or("");
        let (kind, d, key) = match get("kind") {
            "dns" => {
                self.dns += 1;
                let proto = if get("proto") == "tcp" { "tcp" } else { "udp" };
                let d = detail([
                    ("proto", proto),
                    ("name", &clean(get("name"), 1024)),
                    ("type", &clean(get("type"), 16)),
                    ("answer", &ipv4(get("answer"))),
                ]);
                let key = format!("dns {} {}", d["name"], d["type"]);
                (events::SINKHOLE_DNS, d, Some(key))
            }
            "tcp" => {
                self.tcp += 1;
                let reply = match get("reply") {
                    "http-200" => "http-200",
                    _ => "none",
                };
                let d = detail([
                    ("proto", "tcp"),
                    ("dst", &ipv4(get("dst"))),
                    ("dport", &number(get("dport"))),
                    ("bytes", &number(get("bytes"))),
                    ("first", &clean(get("first"), 4 * responder::FIRST_BYTES)),
                    ("sni", &clean(get("sni"), 1024)),
                    ("http", &clean(get("http"), 1024)),
                    ("host", &clean(get("host"), 1024)),
                    ("reply", reply),
                    ("ms_first", &number(get("ms_first"))),
                    ("ms", &number(get("ms"))),
                ]);
                (events::SINKHOLE_CONNECT, d, None)
            }
            "udp" => {
                self.udp += 1;
                let d = detail([
                    ("proto", "udp"),
                    ("dport", &number(get("dport"))),
                    ("bytes", &number(get("bytes"))),
                    ("first", &clean(get("first"), 4 * responder::FIRST_BYTES)),
                ]);
                let key = format!("udp {}", d["dport"]);
                (events::SINKHOLE_CONNECT, d, Some(key))
            }
            "busy" => {
                self.tcp += 1;
                self.unrecorded += 1;
                return vec![];
            }
            _ => return vec![],
        };
        let d: Detail = d.into_iter().filter(|(_, v)| !v.is_empty()).collect();
        if key.as_ref().is_some_and(|k| self.seen.contains(k)) {
            return vec![];
        }
        if self.recorded.len() >= BUDGET {
            self.unrecorded += 1;
            if self.capped {
                return vec![];
            }
            self.capped = true;
            return vec![(events::SINKHOLE_CAPPED, detail([("limit", &BUDGET.to_string())]))];
        }
        if let Some(k) = key {
            self.seen.insert(k);
        }
        self.recorded.push((kind.to_string(), d.clone()));
        vec![(kind, d)]
    }

    /// The totals, as `sinkhole.stop` and the run's result carry them.
    pub fn totals(&self) -> Detail {
        detail([
            ("addr", &self.addr),
            ("dns", &self.dns.to_string()),
            ("tcp", &self.tcp.to_string()),
            ("udp", &self.udp.to_string()),
            ("recorded", &self.recorded.len().to_string()),
            ("unrecorded", &self.unrecorded.to_string()),
        ])
    }

    /// The run's result's `sinkhole` part: the totals and the records, every value a string the guest controlled in
    /// part (escaped, bounded).
    pub fn json(&self) -> String {
        let recs: Vec<String> = self
            .recorded
            .iter()
            .map(|(k, d)| {
                let mut m = d.clone();
                m.insert("kind".into(), k.clone());
                gojson::map(&m)
            })
            .collect();
        Obj::new().map("totals", &self.totals()).raw("records", &gojson::list(&recs)).end()
    }
}

struct Running {
    child: Child,
    log: Arc<Mutex<Log>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

/// The responders of the guests in mode sinkhole (one per guest), in `limbo serve`.
pub struct Service {
    pub events: Arc<dyn Emitter>,
    /// The program run as the responder (`limbo sinkhole-responder`): the daemon's own binary.
    pub exe: String,
    /// The account it runs as. None runs it as the caller, which only the namespace test does (it is root there only
    /// inside its own user namespace, which the responder tells from real root).
    pub account: Option<String>,
    guests: Mutex<HashMap<String, Running>>,
    finished: Mutex<VecDeque<(String, Log)>>,
}

/// Lines from the responder: the first must say it is ready; every later one is a record.
fn read_loop(mut from: impl Read, ready: mpsc::Sender<Result<(), String>>, log: Arc<Mutex<Log>>, ev: Arc<dyn Emitter>, guest: String) {
    let mut buf = vec![0u8; 8192];
    let mut line: Vec<u8> = Vec::new();
    let mut too_long = false;
    let mut first = true;
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for &c in &buf[..n] {
            if c != b'\n' {
                if line.len() < MAX_LINE {
                    line.push(c);
                } else {
                    too_long = true;
                }
                continue;
            }
            if first {
                first = false;
                let ok = matches!(gojson::parse(&line), Ok(Value::Object(m)) if m.iter().any(|(k, v)| k == "kind" && *v == Value::String("ready".into())));
                let _ = ready.send(if ok { Ok(()) } else { Err("it did not say it was ready".into()) });
            } else if !too_long {
                let out = log.lock().unwrap_or_else(|e| e.into_inner()).take(&line);
                for (kind, d) in out {
                    let _ = ev.emit(kind, &guest, d);
                }
            } else {
                log.lock().unwrap_or_else(|e| e.into_inner()).unrecorded += 1;
            }
            line.clear();
            too_long = false;
        }
    }
    if first {
        let _ = ready.send(Err("it ended before it was ready (its error is in the daemon's journal)".into()));
    }
}

/// In the responder, before it runs: no new privileges, no core files, no files written, few descriptors, and every
/// descriptor of the daemon's closed at exec.
fn harden() -> std::io::Result<()> {
    // SAFETY: plain system calls between fork and exec (async-signal-safe), on values owned here
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        for (res, n) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_FSIZE, 0), (libc::RLIMIT_NOFILE, 128)] {
            let l = libc::rlimit { rlim_cur: n, rlim_max: n };
            if libc::setrlimit(res, &l) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        // CLOSE_RANGE_CLOEXEC (4): std's own error pipe still works until exec
        if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

impl Service {
    pub fn new(events: Arc<dyn Emitter>) -> Service {
        Service {
            events,
            exe: "/proc/self/exe".into(),
            account: Some(ACCOUNT.into()),
            guests: Mutex::new(HashMap::new()),
            finished: Mutex::new(VecDeque::new()),
        }
    }

    /// The responder's uid and gid; refused when the account is missing or is root.
    fn ids(&self) -> Result<Option<(u32, u32)>, String> {
        let Some(name) = &self.account else { return Ok(None) };
        match osuser::user_ids(name) {
            None => Err(format!(
                "network mode sinkhole needs the account {name} for its responder (the package's sysusers file makes it; without the package: sudo useradd --system --no-create-home --shell /usr/bin/nologin {name})"
            )),
            Some((0, _)) | Some((_, 0)) => Err(format!("the account {name} is root's (uid or gid 0); the sinkhole's responder never runs as root")),
            Some(ids) => Ok(Some(ids)),
        }
    }

    /// Whether a sinkhole guest can start here (checked before anything is set up).
    pub fn ready(&self) -> Result<(), String> {
        self.ids().map(|_| ())
    }

    /// Starts the guest's responder, bound to its gateway address (the bridge must have it: after net-start).
    pub fn start(&self, m: &Manifest) -> Result<(), String> {
        let ids = self.ids()?;
        let gw = virt::ip4(virt::addr(m).gateway);
        self.stop(&m.name);
        self.events
            .emit(
                events::SINKHOLE_START,
                &m.name,
                detail([
                    ("addr", &gw),
                    ("dns_port", &DNS_PORT.to_string()),
                    ("tcp_port", &TCP_PORT.to_string()),
                    ("udp_port", &UDP_PORT.to_string()),
                    ("account", self.account.as_deref().unwrap_or("")),
                ]),
            )
            .map_err(|e| crate::sys::go_err(&e))?;
        let mut c = Command::new(&self.exe);
        c.args(["sinkhole-responder", "--addr", &gw])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some((uid, gid)) = ids {
            // std drops every supplementary group (setgroups) before setuid when it runs as root
            c.uid(uid).gid(gid);
        }
        // SAFETY: harden makes only async-signal-safe system calls
        unsafe {
            c.pre_exec(harden);
        }
        let mut child = c.spawn().map_err(|e| format!("sinkhole: starting the responder: {}", crate::sys::go_err(&e)))?;
        let out = child.stdout.take().ok_or("sinkhole: the responder has no output")?;
        let log = Arc::new(Mutex::new(Log { addr: gw.clone(), ..Log::default() }));
        let (tx, rx) = mpsc::channel();
        let (log2, ev, guest) = (log.clone(), self.events.clone(), m.name.clone());
        let reader = std::thread::Builder::new()
            .name("sinkhole".into())
            .stack_size(128 << 10)
            .spawn(move || read_loop(out, tx, log2, ev, guest))
            .map_err(|e| format!("sinkhole: {}", crate::sys::go_err(&e)));
        let reader = match reader {
            Ok(r) => r,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let r = rx.recv_timeout(READY_WAIT).unwrap_or_else(|_| Err("it did not start within 5 seconds".into()));
        let running = Running { child, log, reader: Some(reader) };
        self.guests.lock().unwrap_or_else(|e| e.into_inner()).insert(m.name.clone(), running);
        if let Err(e) = r {
            self.stop(&m.name);
            return Err(format!("sinkhole: the responder for {} on {gw} did not start: {e}", m.name));
        }
        Ok(())
    }

    /// Ends the guest's responder, if it has one, and writes its totals (`sinkhole.stop`).
    pub fn stop(&self, guest: &str) {
        let Some(mut r) = self.guests.lock().unwrap_or_else(|e| e.into_inner()).remove(guest) else { return };
        let _ = r.child.kill();
        let _ = r.child.wait();
        drop(r.child.stdin.take());
        if let Some(h) = r.reader.take() {
            let _ = h.join();
        }
        let log = r.log.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let _ = self.events.emit(events::SINKHOLE_STOP, guest, log.totals());
        let mut f = self.finished.lock().unwrap_or_else(|e| e.into_inner());
        f.retain(|(g, _)| g != guest);
        f.push_back((guest.to_string(), log));
        while f.len() > KEEP_FINISHED {
            f.pop_front();
        }
    }

    /// The finished guest's records as the run's result shows them (once).
    pub fn take(&self, guest: &str) -> Option<String> {
        let mut f = self.finished.lock().unwrap_or_else(|e| e.into_inner());
        let i = f.iter().position(|(g, _)| g == guest)?;
        f.remove(i).map(|(_, l)| l.json())
    }

    pub fn running(&self, guest: &str) -> bool {
        self.guests.lock().unwrap_or_else(|e| e.into_inner()).contains_key(guest)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let names: Vec<String> = self.guests.lock().unwrap_or_else(|e| e.into_inner()).keys().cloned().collect();
        for g in names {
            self.stop(&g);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(l: &mut Log, line: &str) -> Vec<(&'static str, Detail)> {
        l.take(line.as_bytes())
    }

    #[test]
    fn records_become_bounded_escaped_events() {
        let mut l = Log::default();
        let e = take(&mut l, r#"{"kind":"dns","proto":"udp","name":"callhome.example","type":"A","answer":"10.213.7.1","extra":"x"}"#);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].0, "sinkhole.dns");
        assert_eq!(e[0].1, detail([("proto", "udp"), ("name", "callhome.example"), ("type", "A"), ("answer", "10.213.7.1")]));
        // a repeat is counted, not written
        assert!(take(&mut l, r#"{"kind":"dns","name":"callhome.example","type":"A"}"#).is_empty());
        assert_eq!(l.dns, 2);
        // values the responder should have escaped are escaped here again; numbers and addresses are checked
        let e = take(
            &mut l,
            "{\"kind\":\"tcp\",\"dst\":\"not an address\",\"dport\":\"80; rm\",\"first\":\"\u{202e}\\u001b[2J\",\"reply\":\"owned\",\"ms\":\"12\"}",
        );
        let d = &e[0].1;
        assert_eq!(d.get("dst"), None);
        assert_eq!(d.get("dport"), None);
        assert_eq!(d["first"], "\\xe2\\x80\\xae\\x1b[2J");
        assert_eq!(d["reply"], "none");
        assert_eq!(d["ms"], "12");
        assert!(d.values().all(|v| v.bytes().all(|c| (0x20..=0x7e).contains(&c))));
        let long = format!(r#"{{"kind":"udp","dport":"4242","first":"{}"}}"#, "A".repeat(10_000));
        let e = take(&mut l, &long);
        assert_eq!(e[0].1["first"].len(), 4 * responder::FIRST_BYTES);
        assert!(take(&mut l, r#"{"kind":"udp","dport":"4242","first":"again"}"#).is_empty(), "one record per UDP port");
        for junk in ["", "{", "[]", r#"{"kind":"verdict","id":"q-1"}"#, r#"{"kind":5}"#] {
            assert!(take(&mut l, junk).is_empty(), "{junk}");
        }
    }

    #[test]
    fn the_budget_caps_records_once() {
        let mut l = Log::default();
        let mut capped = 0;
        for i in 0..BUDGET + 50 {
            for (k, _) in take(&mut l, &format!(r#"{{"kind":"tcp","dst":"198.51.100.7","dport":"{}"}}"#, 1 + i)) {
                if k == "sinkhole.capped" {
                    capped += 1;
                }
            }
        }
        assert_eq!(capped, 1);
        assert_eq!(l.recorded.len(), BUDGET);
        assert_eq!(l.unrecorded, 50);
        assert_eq!(l.tcp as usize, BUDGET + 50);
        let j = l.json();
        assert!(j.starts_with(r#"{"totals":{"addr":"","dns":"0","recorded":"256","tcp":"306","udp":"0","unrecorded":"50"},"records":[{"#));
        assert!(gojson::parse(j.as_bytes()).is_ok());
    }

    #[test]
    fn read_loop_needs_ready_first() {
        let ev = Arc::new(events::Recorder::default());
        let (tx, rx) = mpsc::channel();
        let log = Arc::new(Mutex::new(Log::default()));
        let input = b"{\"kind\":\"ready\",\"addr\":\"10.213.7.1\"}\n{\"kind\":\"dns\",\"name\":\"a.example\",\"type\":\"A\"}\n".to_vec();
        read_loop(&input[..], tx, log.clone(), ev.clone(), "g".into());
        assert_eq!(rx.recv().unwrap(), Ok(()));
        {
            let evs = ev.events.lock().unwrap();
            assert_eq!(evs.len(), 1);
            assert_eq!(evs[0].0, "sinkhole.dns");
            assert_eq!(evs[0].1, "g");
        }
        let (tx, rx) = mpsc::channel();
        read_loop(&b"{\"kind\":\"dns\"}\n"[..], tx, log.clone(), ev.clone(), "g".into());
        assert!(rx.recv().unwrap().is_err());
        let (tx, rx) = mpsc::channel();
        read_loop(&b""[..], tx, log, ev, "g".into());
        assert!(rx.recv().unwrap().is_err());
    }

    #[test]
    fn no_account_no_start() {
        let mut s = Service::new(Arc::new(events::Recorder::default()));
        s.account = Some("limbo-no-such-account-x".into());
        let e = s.ready().unwrap_err();
        assert!(e.contains("useradd --system"), "{e}");
        s.account = Some("root".into());
        assert!(s.ready().unwrap_err().contains("never runs as root"));
    }
}
