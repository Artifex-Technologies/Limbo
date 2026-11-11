//! A run's machine-readable record and its folder (Go: internal/wine/record.go): run.json, written when the run starts
//! and again when it ends; the run folders under the state folder, the oldest pruned beyond 200; the program's hash; the
//! event log's text helpers.

use super::sandbox::Sandbox;
use super::Options;
use crate::gojson::{self, Obj};
use crate::gotime::Time;
use crate::sys;
use sha2::Digest;
use std::io::Read;

pub fn runs_dir(state: &str) -> String {
    sys::join(&[state, "wine-runs"])
}

pub const KEEP_RUNS: usize = 200;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Record {
    pub id: String,
    pub prefix: String,
    pub via: String,
    pub parent: String,
    pub profile: String,
    pub profile_sha256: String,
    pub program: String,
    pub args: Vec<String>,
    pub program_path: String,
    pub program_sha256: String,
    pub program_size: i64,
    pub cwd: String,
    pub arch: String,
    pub windows: String,
    pub started: Time,
    pub ended: Option<Time>,
    pub status: String,
    pub exit_code: Option<i64>,
    pub stopped: String,
    pub allowed: Allowed,
    pub trace: Option<Trace>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Allowed {
    pub network: String,
    pub gpu: bool,
    pub display: Vec<String>,
    pub audio: String,
    pub shares: Vec<RecordShare>,
    pub env: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RecordShare {
    pub path: String,
    pub source: String,
    pub writable: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Trace {
    pub file: String,
    pub channels: String,
    pub bytes: i64,
    pub limit: i64,
    pub truncated: bool,
}

/// allowed: what the sandbox was given.
pub fn allowed(o: &Options, s: &Sandbox) -> Allowed {
    let mut a = Allowed {
        network: o.network.clone(),
        gpu: s.gpu,
        display: s.display.clone(),
        audio: if s.audio.is_empty() { "none".into() } else { s.audio.clone() },
        shares: vec![],
        env: o.env.keys().cloned().collect(),
    };
    for sh in &o.shares {
        a.shares.push(RecordShare {
            path: sh.path.clone(),
            source: if sh.source != sh.path { sh.source.clone() } else { String::new() },
            writable: sh.writable,
        });
    }
    a
}

impl Record {
    /// json.MarshalIndent(r, "", "  ") and a newline.
    pub fn to_json(&self) -> String {
        let a = &self.allowed;
        let shares: Vec<String> = a
            .shares
            .iter()
            .map(|sh| Obj::new().str("path", &sh.path).str_omit("source", &sh.source).bool("writable", sh.writable).end())
            .collect();
        let allowed = Obj::new()
            .str("network", &a.network)
            .bool("gpu", a.gpu)
            .strs("display", &a.display)
            .str("audio", &a.audio)
            .raw("shares", &gojson::list(&shares))
            .strs("env", &a.env)
            .end();
        let mut o = Obj::new()
            .str("id", &self.id)
            .str("prefix", &self.prefix)
            .str("via", &self.via)
            .str_omit("parent", &self.parent)
            .str_omit("profile", &self.profile)
            .str_omit("profile_sha256", &self.profile_sha256)
            .str("program", &self.program)
            .strs("args", &self.args)
            .str_omit("program_path", &self.program_path)
            .str_omit("program_sha256", &self.program_sha256)
            .int_omit("program_size", self.program_size)
            .str("cwd", &self.cwd)
            .str_omit("arch", &self.arch)
            .str_omit("windows", &self.windows)
            .str("started", &self.started.rfc3339_nano());
        if let Some(e) = &self.ended {
            o = o.str("ended", &e.rfc3339_nano());
        }
        o = o.str("status", &self.status);
        if let Some(c) = self.exit_code {
            o = o.int("exit_code", c);
        }
        o = o.str_omit("stopped", &self.stopped).raw("allowed", &allowed);
        if let Some(t) = &self.trace {
            let t = Obj::new()
                .str("file", &t.file)
                .str("channels", &t.channels)
                .int("bytes", t.bytes)
                .int("limit", t.limit)
                .bool("truncated", t.truncated)
                .end();
            o = o.raw("trace", &t);
        }
        gojson::indent(&o.end(), "  ") + "\n"
    }

    /// save: run.json in the run folder, atomically.
    pub fn save(&self, dir: &str) -> Result<(), String> {
        super::prefix::write_file_atomic(&sys::join(&[dir, "run.json"]), self.to_json().as_bytes())
    }
}

/// newRunDir: a run folder named by its start time and a random suffix; the oldest beyond keepRuns pruned.
pub fn new_run_dir(state: &str, now: &Time) -> Result<(String, String), String> {
    let root = runs_dir(state);
    sys::go_mkdir_all(&root, 0o700)?;
    prune_runs(&root, KEEP_RUNS - 1);
    let (y, mo, d, h, mi, s) = now.utc().civil();
    let id = format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z-{}", sys::rand_hex(4));
    let dir = sys::join(&[&root, &id]);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| sys::go_path_error("mkdir", &dir, &e))?;
    Ok((id, dir))
}

use std::os::unix::fs::DirBuilderExt;

/// pruneRuns: keeps the newest `keep` run folders (names that look like a run's).
pub fn prune_runs(root: &str, keep: usize) {
    let Ok(ents) = sys::read_dir_sorted(root) else { return };
    let mut names: Vec<String> =
        ents.into_iter().filter(|(n, t)| t.is_dir() && n.len() > 16 && n.as_bytes()[8] == b'T').map(|(n, _)| n).collect();
    names.sort();
    while names.len() > keep {
        let _ = std::fs::remove_dir_all(sys::join(&[root, &names[0]]));
        names.remove(0);
    }
}

/// maxHash bounds the program file Limbo hashes before a run.
pub const MAX_HASH: u64 = 512 << 20;

/// hashFile: a regular file's SHA-256 and size; the hash is empty above maxHash.
pub fn hash_file(p: &str) -> Option<(String, i64)> {
    let f = std::fs::File::open(p).ok()?;
    let m = f.metadata().ok()?;
    if !m.is_file() {
        return None;
    }
    if m.len() > MAX_HASH {
        return Some((String::new(), m.len() as i64));
    }
    let mut h = sha2::Sha256::new();
    let mut r = std::io::BufReader::with_capacity(64 << 10, f);
    let mut buf = vec![0u8; 64 << 10];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some((sys::hex(&h.finalize()), m.len() as i64))
}

/// clean: text fit for the event log (valid UTF-8 with each bad run as "?", control and invisible characters as "?",
/// at most n bytes).
pub fn clean(s: &[u8], n: usize) -> String {
    let mut out = String::new();
    for c in to_valid_utf8_q(s).chars() {
        let u = c as u32;
        let c = if crate::gotext::is_control(c)
            || (0x200b..=0x200f).contains(&u)
            || (0x202a..=0x202e).contains(&u)
            || (0x2066..=0x2069).contains(&u)
        {
            '?'
        } else {
            c
        };
        if out.len() + c.len_utf8() > n {
            break;
        }
        out.push(c);
    }
    out
}

/// strings.ToValidUTF8(s, "?").
fn to_valid_utf8_q(mut b: &[u8]) -> String {
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
                    out.push('?');
                    in_run = true;
                }
                let bad = e.error_len().unwrap_or(b.len() - good);
                b = &b[good + bad..];
            }
        }
    }
}

/// pathList: paths comma-separated, "%" and "," escaped, each cleaned to 512 bytes.
pub fn path_list(paths: &[&[u8]]) -> String {
    let out: Vec<String> = paths
        .iter()
        .map(|p| {
            let mut e = Vec::with_capacity(p.len());
            for &c in p.iter() {
                match c {
                    b'%' => e.extend_from_slice(b"%25"),
                    b',' => e.extend_from_slice(b"%2C"),
                    c => e.push(c),
                }
            }
            clean(&e, 512)
        })
        .collect();
    out.join(",")
}
