//! The Go CLI's socket-client commands, line for line: `limbo quarantine` (cmd/limbo/quarantine_cmd.go) and `limbo
//! settings | instance | license | exchange` (cmd/limbo/settings_cmd.go). Same arguments, output, errors, exit status
//! and requests as Go; rust/parity/cli-differential.py runs both binaries against one scripted socket and compares them.

use super::client::{self, ReadErr, Response};
use super::flags::{self, FlagSet};
use super::{tabw, text};
use crate::gojson::{self, Ctx, FromGo, Obj, Value};
use crate::gotext::{self, quote};
use crate::quarantine::Record;
use std::io::{Read, Write};

pub const ADMIN_SOCK: &str = "/run/limbo/admin.sock";
pub const USER_SOCK: &str = "/run/limbo/user.sock";

/// How a command ended badly: a message main prints as "limbo: MSG", or nothing more to print (exit status 1 both).
#[derive(Debug, PartialEq)]
pub enum Fail {
    Msg(String),
    Silent,
}

impl From<String> for Fail {
    fn from(s: String) -> Fail {
        Fail::Msg(s)
    }
}

impl From<&str> for Fail {
    fn from(s: &str) -> Fail {
        Fail::Msg(s.to_string())
    }
}

/// What a command reads from its process: the environment, the effective uid, stdin and whether it is a terminal-like
/// character device, and where it writes.
pub struct Io<'a> {
    pub env: &'a dyn Fn(&str) -> String,
    pub euid: u32,
    pub stdin: &'a mut dyn Read,
    pub stdin_is_char_device: bool,
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

/// The five commands; None for any other.
pub fn run(cmd: &str, args: &[String], io: &mut Io) -> Option<Result<(), Fail>> {
    Some(match cmd {
        "quarantine" => quarantine(args, io),
        "settings" => settings(args, io),
        "instance" => instance(args, io),
        "license" => license(args, io),
        "exchange" => exchange(args, io),
        _ => return None,
    })
}

// ---- small Go pieces ----

/// strings.TrimSpace on bytes that may not be UTF-8 (a stray byte is not a space).
pub fn trim_space(b: &[u8]) -> &[u8] {
    fn first(b: &[u8]) -> Option<(char, usize)> {
        (1..=b.len().min(4)).find_map(|k| std::str::from_utf8(&b[..k]).ok().and_then(|s| s.chars().next()).map(|c| (c, k)))
    }
    fn last(b: &[u8]) -> Option<(char, usize)> {
        (1..=b.len().min(4)).find_map(|k| {
            std::str::from_utf8(&b[b.len() - k..]).ok().and_then(|s| {
                let mut it = s.chars();
                let c = it.next()?;
                it.next().is_none().then_some((c, k))
            })
        })
    }
    let mut s = b;
    while let Some((c, k)) = first(s) {
        if !gotext::is_space(c) {
            break;
        }
        s = &s[k..];
    }
    while let Some((c, k)) = last(s) {
        if !gotext::is_space(c) {
            break;
        }
        s = &s[..s.len() - k];
    }
    s
}

/// A JSON string as json.Marshal (Go 1.27) writes bytes: each byte that is not UTF-8 as U+FFFD itself.
pub fn json_bytes(b: &[u8]) -> String {
    gojson::str_json(&gotext::lossy(b))
}

fn w(out: &mut dyn Write, b: &[u8]) {
    let _ = out.write_all(b);
}

fn parse_flags(fs: &mut FlagSet, args: &[String], io: &mut Io) -> Result<Vec<String>, Fail> {
    let mut stderr = vec![];
    let r = flags::parse_interspersed(fs, args.to_vec(), &mut stderr);
    w(io.err, &stderr);
    r.map_err(Fail::Msg)
}

/// whoAmI: the person behind sudo, else $USER.
fn who_am_i(io: &Io) -> String {
    let u = (io.env)("SUDO_USER");
    if u.is_empty() {
        (io.env)("USER")
    } else {
        u
    }
}

/// `json.Unmarshal(raw, &struct{Error string `json:"error"`}) == nil && e.Error != ""`
fn error_field(raw: &[u8]) -> Option<String> {
    #[derive(Default)]
    struct E {
        error: String,
    }
    crate::go_struct!(E as "struct { Error string \"json:\\\"error\\\"\" }" { error: "error" => "string" });
    let e = gojson::unmarshal(raw, E::default(), "struct { Error string \"json:\\\"error\\\"\" }").ok()?;
    (!e.error.is_empty()).then_some(e.error)
}

/// json.Unmarshal into a struct, keeping what was read when it fails part way (Go fills the fields it can).
fn partial<T: FromGo>(raw: &[u8], mut init: T, ty: &str) -> T {
    if let Ok(v) = gojson::parse(raw) {
        init.read(&v, &mut Ctx::new(false), ty);
    }
    init
}

/// json.Unmarshal into a map[string]any: the members, last one of a key winning; nil for null.
fn unmarshal_map(raw: &[u8]) -> Result<Vec<(String, Value)>, String> {
    // a number beyond float64 anywhere in it fails the whole document
    fn floats(v: &Value, path: &mut Vec<(String, bool)>) -> Result<(), String> {
        match v {
            Value::Number(n) if n.parse::<f64>().map_or(true, f64::is_infinite) => {
                let p: Vec<&str> = path.iter().map(|(s, _)| s.as_str()).collect();
                let into = if path.last().is_some_and(|x| x.1) { "" } else { "Go struct field " };
                Err(format!("json: cannot unmarshal number {n} into {into}.{} of type float64", p.join(".")))
            }
            Value::Array(a) => a.iter().enumerate().try_for_each(|(i, x)| {
                path.push((i.to_string(), true));
                let r = floats(x, path);
                path.pop();
                r
            }),
            Value::Object(m) => m.iter().try_for_each(|(k, x)| {
                path.push((k.clone(), false));
                let r = floats(x, path);
                path.pop();
                r
            }),
            _ => Ok(()),
        }
    }
    match gojson::parse(raw).map_err(|e| e.0)? {
        Value::Null => Ok(vec![]),
        Value::Object(m) => {
            for (k, x) in &m {
                floats(x, &mut vec![(k.clone(), false)])?;
            }
            Ok(m)
        }
        other => {
            let what = match other {
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                _ => "array",
            };
            Err(format!("json: cannot unmarshal {what} into Go value of type map[string]interface {{}}"))
        }
    }
}

fn map_get<'a>(m: &'a [(String, Value)], k: &str) -> Option<&'a Value> {
    m.iter().rev().find(|(key, _)| key == k).map(|(_, v)| v)
}

// ---- limbo quarantine ----

/// doJSON: one request; an answer of 300 or more is its "error" text or "server returned STATUS".
fn do_json(sock: &str, method: &str, path: &str, body: Option<String>) -> Result<Vec<u8>, String> {
    let mut resp = client::send(sock, method, path, body.map(String::into_bytes))?;
    let raw = resp.body.read_limited(4 << 20);
    if resp.head.code >= 300 {
        return Err(error_field(&raw).unwrap_or_else(|| format!("server returned {}", resp.head.status)));
    }
    Ok(raw)
}

const Q_USAGE: &str =
    "usage: limbo quarantine [--socket S] list | show ID | restrict GUEST | verdict ID safe|dangerous [--note N] | close ID";

fn quarantine(args: &[String], io: &mut Io) -> Result<(), Fail> {
    let mut fs = FlagSet::new("quarantine");
    fs.string("socket", ADMIN_SOCK, "admin socket (root only)");
    fs.string("note", "", "verdict: a note for the record");
    fs.string("reason", "manually quarantined", "restrict: why");
    fs.string("level", "restrict", "restrict: restrict or isolate");
    let pos = parse_flags(&mut fs, args, io)?;
    if pos.is_empty() {
        return Err(Q_USAGE.into());
    }
    let sock = fs.str("socket");
    match pos[0].as_str() {
        "list" => {
            let raw = do_json(&sock, "GET", "/v1/quarantine", None)?;
            let recs = gojson::unmarshal(&raw, Vec::<Record>::new(), "[]quarantine.Record").map_err(|e| e.0)?;
            let mut t = String::from("ID\tGUEST\tSTATUS\tLEVEL\tOPENED\tSOURCE\tREASON\n");
            for r in recs {
                t.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                    r.id,
                    r.guest,
                    r.status,
                    r.level,
                    text::rfc3339(&r.opened),
                    r.source,
                    r.reason
                ));
            }
            w(io.out, &tabw::format(t.as_bytes()));
            Ok(())
        }
        "show" => {
            if pos.len() != 2 {
                return Err("show: record id required".into());
            }
            let raw = do_json(&sock, "GET", &format!("/v1/quarantine/{}", pos[1]), None)?;
            let r = gojson::unmarshal(&raw, Record::default(), "quarantine.Record").map_err(|e| e.0)?;
            print_record(io.out, &r);
            Ok(())
        }
        "restrict" => {
            if pos.len() != 2 {
                return Err("restrict: guest name required".into());
            }
            let body = Obj::new()
                .str("guest", &pos[1])
                .str("level", &fs.str("level"))
                .str("reason", &fs.str("reason"))
                .str("source", &format!("human:{}", who_am_i(io)))
                .end();
            let raw = do_json(&sock, "POST", "/v1/quarantine", Some(body))?;
            let res = unmarshal_map(&raw)?;
            let applied = map_get(&res, "applied").map_or("<nil>".to_string(), text::go_v);
            w(io.out, format!("applied={applied}\n").as_bytes());
            if let Some(Value::String(e)) = map_get(&res, "error") {
                if !e.is_empty() {
                    w(io.out, format!("note: {e}\n").as_bytes());
                }
            }
            Ok(())
        }
        "verdict" => {
            if pos.len() != 3 {
                return Err("verdict: usage: verdict ID safe|dangerous".into());
            }
            let v = &pos[2];
            if v != "safe" && v != "dangerous" {
                return Err("verdict must be exactly 'safe' or 'dangerous'".into());
            }
            let raw = do_json(&sock, "GET", &format!("/v1/quarantine/{}", pos[1]), None)?;
            let r = gojson::unmarshal(&raw, Record::default(), "quarantine.Record").map_err(|e| e.0)?;
            print_record(io.out, &r);
            w(io.out, format!("\nMarking guest {} as {}.\n", quote(&r.guest), v.to_uppercase()).as_bytes());
            let body = Obj::new().str("by", &who_am_i(io)).str("note", &fs.str("note")).str("verdict", v).end();
            let raw = do_json(&sock, "POST", &format!("/v1/quarantine/{}/verdict", pos[1]), Some(body))?;
            unmarshal_map(&raw)?;
            w(io.out, b"recorded.\n");
            Ok(())
        }
        "close" => {
            if pos.len() != 2 {
                return Err("close: record id required".into());
            }
            let body = Obj::new().str("by", &who_am_i(io)).end();
            do_json(&sock, "POST", &format!("/v1/quarantine/{}/close", pos[1]), Some(body))?;
            Ok(())
        }
        other => Err(format!("unknown quarantine subcommand {}", quote(other)).into()),
    }
}

fn print_record(out: &mut dyn Write, r: &Record) {
    let mut s = format!("{}  guest={}  status={}  level={}\n", r.id, r.guest, r.status, r.level);
    s.push_str(&format!("opened {} by {}\nreason: {}\n", text::rfc3339(&r.opened), r.source, r.reason));
    if let Some(ev) = &r.evidence {
        for (k, v) in ev {
            s.push_str(&format!("evidence {k}: {v}\n"));
        }
    }
    for a in r.advisory.iter().flatten() {
        s.push_str(&format!("\n--- ADVISORY from {} ({}) ---\n", a.source, text::rfc3339(&a.time)));
        s.push_str("This is an automated opinion produced from guest-derived data. It is untrusted,\n");
        s.push_str("informational only, and has not changed anything.\n");
        s.push_str(&a.text);
        s.push_str("\n--- end advisory ---\n");
    }
    if let Some(v) = &r.verdict {
        s.push_str(&format!("\nverdict: {} by {} at {}\nnote: {}\n", v.value, v.by, text::rfc3339(&v.time), v.note));
    }
    w(out, s.as_bytes());
}

// ---- the Settings page's commands ----

/// A refusal from the server, kept whole for --json (Go's apiFail), or any other error.
enum CliErr {
    Api { raw: Vec<u8>, msg: String },
    Plain(String),
}

struct Cli {
    sock: String,
    as_json: bool,
}

fn new_cli(name: &'static str, io: &Io) -> FlagSet {
    let mut fs = FlagSet::new(name);
    fs.string("socket", if io.euid == 0 { ADMIN_SOCK } else { USER_SOCK }, "socket: admin.sock as root, user.sock otherwise");
    fs.bool("json", false, "print the server's JSON answer");
    fs
}

impl Cli {
    fn from(fs: &FlagSet) -> Cli {
        Cli { sock: fs.str("socket"), as_json: fs.is_true("json") }
    }

    fn api_fail(resp: &mut Response, limit: usize, prefix: &str) -> CliErr {
        let raw = resp.body.read_limited(limit);
        let msg = error_field(&raw).unwrap_or_else(|| format!("{prefix}{}", resp.head.status));
        CliErr::Api { raw, msg }
    }

    fn do_(&self, method: &str, path: &str, body: Option<String>) -> Result<Vec<u8>, CliErr> {
        let url = client::request_url(path).map_err(CliErr::Plain)?;
        let mut resp = match client::send_url(&self.sock, method, url, body.map(String::into_bytes)) {
            Ok(r) => r,
            Err(e) if self.sock == USER_SOCK => {
                return Err(CliErr::Plain(format!("{e} (is Limbo running, and are you in the limbo-users group?)")))
            }
            Err(e) => return Err(CliErr::Plain(e)),
        };
        if resp.head.code >= 300 {
            return Err(Cli::api_fail(&mut resp, 8 << 20, "server returned "));
        }
        Ok(resp.body.read_limited(8 << 20))
    }

    /// emit with --json (or no human form): the answer indented when it is JSON, trimmed, one line.
    fn emit_json(&self, io: &mut Io, raw: &[u8]) {
        let b = text::indent(raw, "  ").unwrap_or_else(|| raw.to_vec());
        let mut line = trim_space(&b).to_vec();
        line.push(b'\n');
        w(io.out, &line);
    }

    fn finish(&self, io: &mut Io, e: CliErr) -> Fail {
        match e {
            CliErr::Api { raw, .. } if self.as_json && !raw.is_empty() => {
                let mut line = trim_space(&raw).to_vec();
                line.push(b'\n');
                w(io.out, &line);
                Fail::Silent
            }
            CliErr::Api { msg, .. } => Fail::Msg(msg),
            CliErr::Plain(m) => Fail::Msg(m),
        }
    }
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "available"
    } else {
        "not available"
    }
}

fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

#[derive(Default)]
struct Space {
    total_bytes: i64,
}
crate::go_struct!(Space as "struct { TotalBytes int64 \"json:\\\"total_bytes\\\"\" }" { total_bytes: "total_bytes" => "int64" });

#[derive(Default)]
struct Status {
    version: String,
    kvm: bool,
    ask_password: bool,
    space: Space,
}
const STATUS_TY: &str = "struct { Version string \"json:\\\"version\\\"\"; KVM bool \"json:\\\"kvm\\\"\"; AskPassword bool \"json:\\\"ask_password\\\"\"; Space struct { TotalBytes int64 \"json:\\\"total_bytes\\\"\" } \"json:\\\"space\\\"\" }";
crate::go_struct!(Status as "" {
    version: "version" => "string", kvm: "kvm" => "bool", ask_password: "ask_password" => "bool",
    space: "space" => "struct { TotalBytes int64 \"json:\\\"total_bytes\\\"\" }",
});

#[derive(Default)]
struct Disk {
    own_bytes: i64,
    base_bytes: i64,
}
crate::go_struct!(Disk as "" { own_bytes: "own_bytes" => "int64", base_bytes: "base_bytes" => "int64" });

#[derive(Default)]
struct ViewRow {
    name: String,
    kind: String,
    os: String,
    state: String,
    cpus: i64,
    memory_mb: i64,
    network: String,
    disk: Disk,
    held_by_heimdall: bool,
    owner: String,
    pending: bool,
}
crate::go_struct!(ViewRow as "main.viewRow" {
    name: "name" => "string", kind: "kind" => "string", os: "os" => "string", state: "state" => "string",
    cpus: "cpus" => "int", memory_mb: "memory_mb" => "int", network: "network" => "string",
    disk: "disk" => "struct { OwnBytes int64 \"json:\\\"own_bytes\\\"\"; BaseBytes int64 \"json:\\\"base_bytes\\\"\" }",
    held_by_heimdall: "held_by_heimdall" => "bool", owner: "owner" => "string", pending: "pending" => "bool",
});

#[derive(Default)]
struct RowsWrap {
    instances: Vec<ViewRow>,
}
const WRAP_TY: &str = "struct { Instances []main.viewRow \"json:\\\"instances\\\"\" }";
crate::go_struct!(RowsWrap as "" { instances: "instances" => "[]main.viewRow" });

fn print_instances(out: &mut dyn Write, raw: &[u8]) -> Result<(), Fail> {
    let rows = match gojson::unmarshal(raw, Vec::<ViewRow>::new(), "[]main.viewRow") {
        Ok(r) => r,
        Err(_) => gojson::unmarshal(raw, RowsWrap::default(), WRAP_TY).map_err(|e| e.0)?.instances,
    };
    let mut t = String::from("NAME\tKIND\tSYSTEM\tSTATE\tCPUS\tMEMORY\tNETWORK\tOWN DISK\tBASE\tOWNER\n");
    for r in rows {
        let mut st = r.state.clone();
        if r.held_by_heimdall {
            st = "held by Heimdall".into();
        }
        if r.pending {
            st.push_str(" (changes at next start)");
        }
        t.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{} MiB\t{}\t{}\t{}\t{}\n",
            r.name,
            r.kind,
            r.os,
            st,
            r.cpus,
            r.memory_mb,
            r.network,
            text::size(r.disk.own_bytes),
            text::size(r.disk.base_bytes),
            r.owner
        ));
    }
    w(out, &tabw::format(t.as_bytes()));
    Ok(())
}

fn settings(args: &[String], io: &mut Io) -> Result<(), Fail> {
    let mut fs = new_cli("settings", io);
    let pos = parse_flags(&mut fs, args, io)?;
    let c = Cli::from(&fs);
    if pos.is_empty() {
        return Err("usage: limbo settings show [--json] | limbo settings password on|off (root)".into());
    }
    match pos[0].as_str() {
        "show" => {
            let mut got: Vec<(&str, Vec<u8>)> = vec![];
            for (key, path) in [("status", "/v1/status"), ("instances", "/v1/instances"), ("licenses", "/v1/licenses")] {
                let mut raw = match c.do_("GET", path, None) {
                    Ok(r) => r,
                    Err(e) => return Err(c.finish(io, e)),
                };
                if key != "status" {
                    if let Ok(m) = text::member_raw(&raw, key) {
                        raw = m.unwrap_or_default();
                    }
                }
                got.push((key, raw));
            }
            let get = |k: &str| got.iter().find(|(key, _)| *key == k).map(|(_, v)| v.clone()).unwrap_or_default();
            // json.Marshal(map[string]json.RawMessage): keys sorted, each value compacted; nil when one is not JSON
            let mut b = Some(String::from("{"));
            for (i, k) in ["instances", "licenses", "status"].iter().enumerate() {
                let raw = get(k);
                let v = if raw.is_empty() { Some(b"null".to_vec()) } else { text::compact_html(&raw) };
                match (v, b.as_mut()) {
                    (Some(v), Some(s)) => {
                        if i > 0 {
                            s.push(',');
                        }
                        s.push_str(&gojson::str_json(k));
                        s.push(':');
                        s.push_str(&String::from_utf8_lossy(&v));
                    }
                    _ => b = None,
                }
            }
            let b = b.map(|mut s| {
                s.push('}');
                s.into_bytes()
            });
            if c.as_json {
                c.emit_json(io, &b.unwrap_or_default());
                return Ok(());
            }
            let st = partial(&get("status"), Status::default(), STATUS_TY);
            w(
                io.out,
                format!(
                    "Limbo {}: running; KVM {}; space used {}; ask for password: {}\n\n",
                    st.version,
                    yes_no(st.kvm),
                    text::size(st.space.total_bytes),
                    on_off(st.ask_password)
                )
                .as_bytes(),
            );
            print_instances(io.out, &get("instances"))
        }
        "password" => {
            if pos.len() != 2 || (pos[1] != "on" && pos[1] != "off") {
                return Err("usage: limbo settings password on|off (needs root: sudo or pkexec)".into());
            }
            if c.sock == USER_SOCK {
                return Err("settings password: needs root (sudo or pkexec)".into());
            }
            let body = Obj::new().bool("ask_password", pos[1] == "on").end();
            let raw = match c.do_("POST", "/v1/settings", Some(body)) {
                Ok(r) => r,
                Err(e) => return Err(c.finish(io, e)),
            };
            if c.as_json {
                c.emit_json(io, &raw);
            } else {
                w(io.out, format!("Ask for my password for Limbo changes: {}\n", pos[1]).as_bytes());
            }
            Ok(())
        }
        other => Err(format!("unknown settings subcommand {}", quote(other)).into()),
    }
}

const I_USAGE: &str = "usage: limbo instance list | show NAME | start NAME | stop NAME | set NAME [--cpus N] [--memory-mb N] [--disk-gb N] [--shared-folder on|off] [--clipboard off|text] [--devices A,B] [--network none|internet-only|allowlist --allow A:tcp:443,...] | free-space NAME [--yes] | add MANIFEST [--owner USER] (root) | remove NAME [--delete-disk] (root)";

/// bufio.Reader.ReadString('\n') on stdin (at most `limit` bytes): the line with its newline, or what came before EOF.
fn read_line(stdin: &mut dyn Read, limit: usize) -> Vec<u8> {
    let mut line = vec![];
    let mut b = [0u8; 1];
    while line.len() < limit {
        match stdin.read(&mut b) {
            Ok(1) => {
                line.push(b[0]);
                if b[0] == b'\n' {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            _ => break,
        }
    }
    line
}

/// networkChange: --network and --allow as the request's "network" object.
fn network_change(mode: &str, allow: &str) -> Result<String, String> {
    let mut list = vec![];
    for a in allow.split(',') {
        let a = gotext::trim_space(a);
        if a.is_empty() {
            continue;
        }
        let i = a.rfind(':');
        let j = a[..i.unwrap_or(0)].rfind(':');
        let (Some(i), Some(j)) = (i, j) else {
            return Err(format!("--allow {}: write ADDRESS:tcp|udp:PORT", quote(a)));
        };
        let Some(port) = gotext::atoi(&a[i + 1..]) else {
            return Err(format!("--allow {}: the port is not a number", quote(a)));
        };
        list.push(Obj::new().str("addr", &a[..j]).int("port", port).str("proto", &a[j + 1..i]).end());
    }
    Ok(Obj::new().raw("allow", &gojson::list(&list)).str("mode", mode).end())
}

fn instance(args: &[String], io: &mut Io) -> Result<(), Fail> {
    let mut fs = new_cli("instance", io);
    fs.int("cpus", 0, "set: processors");
    fs.int("memory-mb", 0, "set: memory in MiB");
    fs.int("disk-gb", 0, "set: disk size in GiB (grows only)");
    fs.string("shared-folder", "", "set: on|off");
    fs.string("clipboard", "", "set: off|text");
    fs.string(
        "devices",
        "\x00",
        "set: comma-separated PCI addresses or USB IDs (vendor:product), from the manifest's own list; empty for none",
    );
    fs.string("network", "", "set (root): none, internet-only, or allowlist (with --allow); from the guest's next start");
    fs.string("allow", "", "set --network allowlist: comma-separated ADDRESS[/BITS]:tcp|udp:PORT, e.g. 1.2.3.4:tcp:443");
    fs.string("owner", "", "add: the account that may change it without the password (default: the sudo user)");
    fs.bool("delete-disk", false, "remove: also delete the guest's own disk");
    fs.bool("yes", false, "free-space: do not ask");
    let pos = parse_flags(&mut fs, args, io)?;
    let c = Cli::from(&fs);
    if pos.is_empty() {
        return Err(I_USAGE.into());
    }
    let need = |n: usize| if pos.len() != n { Err(Fail::from(I_USAGE)) } else { Ok(()) };
    let r = match pos[0].as_str() {
        "list" => {
            let raw = match c.do_("GET", "/v1/instances", None) {
                Ok(r) => r,
                Err(e) => return Err(c.finish(io, e)),
            };
            if c.as_json {
                c.emit_json(io, &raw);
                return Ok(());
            }
            return print_instances(io.out, &raw);
        }
        "show" => {
            need(2)?;
            c.do_("GET", &format!("/v1/instances/{}", pos[1]), None)
        }
        "start" | "stop" => {
            need(2)?;
            c.do_("POST", &format!("/v1/instances/{}/{}", pos[1], pos[0]), None)
        }
        "set" => {
            need(2)?;
            // map[string]any: keys sorted
            let mut ch = Obj::new();
            if !fs.str("clipboard").is_empty() {
                ch = ch.str("clipboard", &fs.str("clipboard"));
            }
            if fs.num("cpus") != 0 {
                ch = ch.int("cpus", fs.num("cpus"));
            }
            let devices = fs.str("devices");
            if devices != "\x00" {
                let list: Vec<String> = devices.split(',').map(gotext::trim_space).filter(|d| !d.is_empty()).map(String::from).collect();
                ch = ch.strs("devices", &list);
            }
            if fs.num("disk-gb") != 0 {
                ch = ch.int("disk_gb", fs.num("disk-gb"));
            }
            if fs.num("memory-mb") != 0 {
                ch = ch.int("memory_mb", fs.num("memory-mb"));
            }
            let (network, allow) = (fs.str("network"), fs.str("allow"));
            if !network.is_empty() {
                ch = ch.raw("network", &network_change(&network, &allow)?);
            } else if !allow.is_empty() {
                return Err("set: --allow goes with --network allowlist".into());
            }
            if !fs.str("shared-folder").is_empty() {
                ch = ch.str("shared_folder", &fs.str("shared-folder"));
            }
            c.do_("POST", &format!("/v1/instances/{}/settings", pos[1]), Some(ch.end()))
        }
        "free-space" => {
            need(2)?;
            if !fs.is_true("yes") {
                w(io.err, format!("This deletes everything {} changed since its base image. Type yes to go on: ", pos[1]).as_bytes());
                let _ = io.err.flush();
                let line = read_line(io.stdin, usize::MAX);
                if trim_space(&line) != b"yes" {
                    return Err("free-space: not confirmed".into());
                }
            }
            c.do_("POST", &format!("/v1/instances/{}/free-space", pos[1]), Some(Obj::new().bool("confirm", true).end()))
        }
        "add" => {
            need(2)?;
            let m = crate::manifest::load(&pos[1])?;
            let mut o = fs.str("owner");
            if o.is_empty() {
                o = (io.env)("SUDO_USER");
                if o.is_empty() {
                    o = (io.env)("PKEXEC_UID");
                    if !o.is_empty() {
                        o = crate::osuser::lookup_id(&o).map(|u| u.0).unwrap_or_default();
                    }
                }
            }
            c.do_("POST", "/v1/instances", Some(Obj::new().raw("manifest", &m.json()).str("owner", &o).end()))
        }
        "remove" => {
            need(2)?;
            let body = Obj::new().bool("delete_disk", fs.is_true("delete-disk")).end();
            c.do_("DELETE", &format!("/v1/instances/{}", pos[1]), Some(body))
        }
        _ => return Err(I_USAGE.into()),
    };
    let raw = match r {
        Ok(r) => r,
        Err(e) => return Err(c.finish(io, e)),
    };
    if c.as_json {
        c.emit_json(io, &raw);
        return Ok(());
    }
    let has = |n: &[u8]| raw.windows(n.len()).any(|x| x == n);
    if has(b"\"freed_bytes\"") || has(b"\"removed\"") {
        let mut line = trim_space(&raw).to_vec();
        line.push(b'\n');
        w(io.out, &line);
        return Ok(());
    }
    let mut wrapped = b"[".to_vec();
    wrapped.extend_from_slice(&raw);
    wrapped.push(b']');
    print_instances(io.out, &wrapped)
}

const L_USAGE: &str = "usage: limbo license list | add --name NAME (the key is read from stdin, never from the command line) | remove ID | reveal ID | assign ID GUEST | unassign ID GUEST";

#[derive(Default)]
struct Lic {
    id: String,
    name: String,
    masked: String,
    assigned: Vec<String>,
}
crate::go_struct!(Lic as "" { id: "ID" => "string", name: "Name" => "string", masked: "Masked" => "string", assigned: "Assigned" => "[]string" });

#[derive(Default)]
struct Lics {
    licenses: Vec<Lic>,
}
const LICS_TY: &str = "struct { Licenses []struct { ID string; Name string; Masked string; Assigned []string } \"json:\\\"licenses\\\"\" }";
crate::go_struct!(Lics as "" { licenses: "licenses" => "[]struct { ID string; Name string; Masked string; Assigned []string }" });

fn license(args: &[String], io: &mut Io) -> Result<(), Fail> {
    let mut fs = new_cli("license", io);
    fs.string("name", "", "add: a name for the license, e.g. \"Windows 11 Pro, old PC\"");
    let pos = parse_flags(&mut fs, args, io)?;
    let c = Cli::from(&fs);
    if pos.is_empty() {
        return Err(L_USAGE.into());
    }
    let r = match pos[0].as_str() {
        "list" => {
            let raw = match c.do_("GET", "/v1/licenses", None) {
                Ok(r) => r,
                Err(e) => return Err(c.finish(io, e)),
            };
            if c.as_json {
                c.emit_json(io, &raw);
                return Ok(());
            }
            let l = gojson::unmarshal(&raw, Lics::default(), LICS_TY).map_err(|e| e.0)?;
            let mut t = String::from("ID\tNAME\tKEY\tGUESTS\n");
            for x in l.licenses {
                t.push_str(&format!("{}\t{}\t{}\t{}\n", x.id, x.name, x.masked, x.assigned.join(",")));
            }
            w(io.out, &tabw::format(t.as_bytes()));
            return Ok(());
        }
        "add" => {
            if pos.len() != 1 {
                return Err(L_USAGE.into());
            }
            if io.stdin_is_char_device {
                w(io.err, b"Product key: ");
                let _ = io.err.flush();
            }
            let line = read_line(io.stdin, 256);
            let body = format!("{{\"key\":{},\"name\":{}}}", json_bytes(trim_space(&line)), gojson::str_json(&fs.str("name")));
            c.do_("POST", "/v1/licenses", Some(body))
        }
        "remove" => {
            if pos.len() != 2 {
                return Err(L_USAGE.into());
            }
            c.do_("DELETE", &format!("/v1/licenses/{}", pos[1]), None)
        }
        "reveal" => {
            if pos.len() != 2 {
                return Err(L_USAGE.into());
            }
            c.do_("GET", &format!("/v1/licenses/{}/key", pos[1]), None)
        }
        "assign" | "unassign" => {
            if pos.len() != 3 {
                return Err(L_USAGE.into());
            }
            c.do_("POST", &format!("/v1/licenses/{}/{}", pos[1], pos[0]), Some(Obj::new().str("guest", &pos[2]).end()))
        }
        _ => return Err(L_USAGE.into()),
    };
    match r {
        Ok(raw) => {
            c.emit_json(io, &raw);
            Ok(())
        }
        Err(e) => Err(c.finish(io, e)),
    }
}

const X_USAGE: &str = "usage: limbo exchange list GUEST | take GUEST PATH DEST (ClamAV scans it first; DEST must not exist)";

#[derive(Default)]
struct XFile {
    path: String,
    size: i64,
}
crate::go_struct!(XFile as "" { path: "path" => "string", size: "size" => "int64" });

#[derive(Default)]
struct XList {
    files: Vec<XFile>,
    unlisted: i64,
}
const XLIST_TY: &str = "struct { Files []struct { Path string \"json:\\\"path\\\"\"; Size int64 \"json:\\\"size\\\"\" } \"json:\\\"files\\\"\"; Unlisted int \"json:\\\"unlisted\\\"\" }";
crate::go_struct!(XList as "" {
    files: "files" => "[]struct { Path string \"json:\\\"path\\\"\"; Size int64 \"json:\\\"size\\\"\" }",
    unlisted: "unlisted" => "int",
});

fn exchange(args: &[String], io: &mut Io) -> Result<(), Fail> {
    let mut fs = new_cli("exchange", io);
    let pos = parse_flags(&mut fs, args, io)?;
    let c = Cli::from(&fs);
    if pos.len() < 2 {
        return Err(X_USAGE.into());
    }
    match pos[0].as_str() {
        "list" => {
            let raw = match c.do_("GET", &format!("/v1/exchange/{}", pos[1]), None) {
                Ok(r) => r,
                Err(e) => return Err(c.finish(io, e)),
            };
            if c.as_json {
                c.emit_json(io, &raw);
                return Ok(());
            }
            let l = gojson::unmarshal(&raw, XList::default(), XLIST_TY).map_err(|e| e.0)?;
            let mut s = format!("Files the guest {} left (names come from the guest: untrusted):\n", pos[1]);
            for f in &l.files {
                s.push_str(&format!("  {}  {}\n", quote(&f.path), text::size(f.size)));
            }
            if l.unlisted > 0 {
                s.push_str(&format!("  ({} entries not shown: not plain files, or unsafe names)\n", l.unlisted));
            }
            w(io.out, s.as_bytes());
            Ok(())
        }
        "take" => {
            if pos.len() != 4 {
                return Err(X_USAGE.into());
            }
            take(&c, io, &pos[1], &pos[2], &pos[3])
        }
        _ => Err(X_USAGE.into()),
    }
}

/// take: one scanned file from the daemon, written to dest as the caller (never executable, never over an existing file
/// or through a link), checked against the daemon's sha256; under sudo or pkexec given to the person behind it.
fn take(c: &Cli, io: &mut Io, guest: &str, rel: &str, dest: &str) -> Result<(), Fail> {
    use sha2::Digest;
    use std::os::unix::fs::OpenOptionsExt;
    let body = Obj::new().str("path", rel).end();
    let url = client::request_url(&format!("/v1/exchange/{guest}/take"))?;
    let mut resp = client::send_url(&c.sock, "POST", url, Some(body.into_bytes()))?;
    if resp.head.code != 200 {
        let e = Cli::api_fail(&mut resp, 64 << 10, "");
        return Err(c.finish(io, e));
    }
    let want = resp.head.get("X-Limbo-Sha256").unwrap_or_default().to_vec();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o644)
        .open(dest)
        .map_err(|e| crate::sys::go_path_error("open", dest, &e))?;
    let mut h = sha2::Sha256::new();
    let mut cerr: Option<String> = None;
    loop {
        match resp.body.next(1 << 16) {
            Ok(v) if v.is_empty() => break,
            Ok(v) => {
                if let Err(e) = f.write_all(&v) {
                    cerr = Some(crate::sys::go_path_error("write", dest, &e));
                    break;
                }
                h.update(&v);
            }
            Err(e) => {
                cerr = Some(match e {
                    ReadErr::Eof => "EOF".into(),
                    e => client::body_err_text(e),
                });
                break;
            }
        }
    }
    if let Err(e) = rustix::fs::fchmod(&f, rustix::fs::Mode::from_raw_mode(0o644)) {
        if cerr.is_none() {
            cerr = Some(crate::sys::go_path_error("chmod", dest, &std::io::Error::from(e)));
        }
    }
    let fd = std::os::fd::IntoRawFd::into_raw_fd(f);
    // SAFETY: fd was just taken out of the File, which no longer closes it
    if unsafe { libc::close(fd) } != 0 && cerr.is_none() {
        cerr = Some(crate::sys::go_path_error("close", dest, &std::io::Error::last_os_error()));
    }
    let got = crate::sys::hex(&h.finalize());
    if cerr.is_none() && got.as_bytes() != want.as_slice() {
        cerr = Some(format!("the file arrived damaged (sha256 {got}, expected {})", String::from_utf8_lossy(&want)));
    }
    if let Some(e) = cerr {
        let _ = std::fs::remove_file(dest);
        return Err(e.into());
    }
    if io.euid == 0 {
        if let Some((uid, gid)) = sudo_ids(io) {
            if let Ok(p) = std::ffi::CString::new(dest) {
                // SAFETY: a valid C string; the result is ignored as Go ignores it
                unsafe {
                    libc::lchown(p.as_ptr(), uid as libc::uid_t, gid as libc::gid_t);
                }
            }
        }
    }
    let mut out = if c.as_json {
        format!(
            "{{\"path\":{},\"scan\":{},\"sha256\":{}}}\n",
            gojson::str_json(&crate::sys::clean(dest)),
            json_bytes(resp.head.get("X-Limbo-Scan").unwrap_or_default()),
            json_bytes(&want)
        )
        .into_bytes()
    } else {
        format!("{dest}: scanned clean by ClamAV, sha256 ").into_bytes()
    };
    if !c.as_json {
        out.extend_from_slice(&want);
        out.push(b'\n');
    }
    w(io.out, &out);
    Ok(())
}

/// sudoIDs: SUDO_UID and SUDO_GID, else PKEXEC_UID's account.
fn sudo_ids(io: &Io) -> Option<(i64, i64)> {
    if let (Some(u), Some(g)) = (gotext::atoi(&(io.env)("SUDO_UID")), gotext::atoi(&(io.env)("SUDO_GID"))) {
        return Some((u, g));
    }
    let pu = (io.env)("PKEXEC_UID");
    if pu.is_empty() {
        return None;
    }
    let (_, uid, gid) = crate::osuser::lookup_id(&pu)?;
    Some((gotext::atoi(&uid)?, gotext::atoi(&gid)?))
}
