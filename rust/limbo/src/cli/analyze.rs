//! `limbo analyze` (cmd/limbo/analyze_cmd.go), line for line: one file copied into Limbo's inbox, a sample run asked
//! for on the admin socket, its result polled every 3 seconds and printed. Same arguments, output, errors, exit status,
//! requests and files as Go; rust/parity/cli-differential.py compares the two binaries on a scripted socket.

use super::client;
use super::commands::{decode_map, map_get, unmarshal_map, Fail, Io};
use super::flags::FlagSet;
use super::text::go_v;
use crate::gojson::{self, Value};
use crate::sys;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

/// What a sample run does when no command is given.
pub const DEFAULT_ANALYSIS: &str = "limbo-decompile triage sample; echo; echo '== functions'; limbo-decompile functions sample";

const USAGE: &str = "usage: limbo analyze [--profile P] [--timeout S] [--json] FILE [COMMAND]";

/// os.CreateTemp(dir, prefix) with Go's names (the prefix, then a random uint32 in decimal) and error texts.
fn go_create_temp(dir: &str, prefix: &str) -> Result<(std::fs::File, String), String> {
    let dir = if dir.is_empty() {
        let t = std::env::var("TMPDIR").unwrap_or_default();
        if t.is_empty() {
            "/tmp".to_string()
        } else {
            t
        }
    } else {
        dir.to_string()
    };
    let prefix = if dir.ends_with('/') { format!("{dir}{prefix}") } else { format!("{dir}/{prefix}") };
    for _ in 0..10_000 {
        let mut r = [0u8; 4];
        rustix::rand::getrandom(&mut r, rustix::rand::GetRandomFlags::empty()).ok();
        let name = format!("{prefix}{}", u32::from_le_bytes(r));
        match std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&name) {
            Ok(f) => return Ok((f, name)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(sys::go_path_error("open", &name, &e)),
        }
    }
    Err(format!("createtemp {prefix}*: file already exists"))
}

pub fn run(args: &[String], io: &mut Io) -> Result<(), Fail> {
    let mut fs = FlagSet::new("analyze");
    fs.string("profile", "malware-analysis", "a sealed profile with allow_sample");
    fs.int("timeout", 900, "seconds the analysis may take (the profile's limit applies)");
    fs.string("inbox", "/var/lib/limbo/inbox", "Limbo's inbox (as for limbo serve)");
    fs.string("socket", "/run/limbo/admin.sock", "admin socket (root only)");
    fs.bool("json", false, "print the whole result as JSON");
    let mut stderr = vec![];
    let r = fs.parse(args, &mut stderr);
    let _ = io.err.write_all(&stderr);
    let pos = r.map_err(Fail::Msg)?;
    if pos.is_empty() || pos.len() > 2 {
        return Err(Fail::Msg(USAGE.into()));
    }
    let (profile, timeout, inbox, sock, as_json) =
        (fs.str("profile"), fs.num("timeout"), fs.str("inbox"), fs.str("socket"), fs.is_true("json"));
    let command = pos.get(1).cloned().unwrap_or_else(|| DEFAULT_ANALYSIS.to_string());
    let mut src = std::fs::File::open(&pos[0]).map_err(|e| Fail::Msg(sys::go_path_error("open", &pos[0], &e)))?;
    let (mut tmp, tmp_name) = go_create_temp(&inbox, ".incoming-")
        .map_err(|e| Fail::Msg(format!("the inbox {inbox}: {e} (is limbo serve running, and are you root?)")))?;
    // io.Copy(MultiWriter(tmp, h), LimitReader(src, 64 MiB + 1))
    let mut h = Sha256::new();
    let mut left: u64 = (64 << 20) + 1;
    let mut buf = vec![0u8; 32 << 10];
    let copied: Result<(), String> = loop {
        if left == 0 {
            break Ok(());
        }
        let want = buf.len().min(left as usize);
        match src.read(&mut buf[..want]) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                left -= n as u64;
                if let Err(e) = tmp.write_all(&buf[..n]) {
                    break Err(sys::go_path_error("write", &tmp_name, &e));
                }
                h.update(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => break Err(sys::go_path_error("read", &pos[0], &e)),
        }
    };
    drop(tmp);
    if let Err(e) = copied {
        let _ = std::fs::remove_file(&tmp_name);
        return Err(Fail::Msg(e));
    }
    let sum = sys::hex(&h.finalize());
    let name = format!("{sum}.sample");
    let fin = sys::join(&[&inbox, &name]);
    if let Err(e) = std::fs::rename(&tmp_name, &fin) {
        let _ = std::fs::remove_file(&tmp_name);
        return Err(Fail::Msg(format!("rename {tmp_name} {fin}: {}", sys::go_err(&e))));
    }
    let r = ask(io, &sock, &profile, &command, &name, &sum, timeout, as_json);
    let _ = std::fs::remove_file(&fin);
    r
}

#[allow(clippy::too_many_arguments)]
fn ask(io: &mut Io, sock: &str, profile: &str, command: &str, name: &str, sum: &str, timeout: i64, as_json: bool) -> Result<(), Fail> {
    // json.Marshal of the map: keys sorted
    let body = format!(
        "{{\"command\":{},\"profile\":{},\"sample\":{},\"timeout_seconds\":{timeout}}}",
        gojson::str_json(command),
        gojson::str_json(profile),
        gojson::str_json(name)
    );
    let url = client::request_url("/v1/sample-runs")?;
    let mut resp = client::send_typed(sock, "POST", url, Some(body.into_bytes()), Some("application/json"))?;
    let raw = resp.body.read_limited(usize::MAX);
    let started = decode_map(&raw).unwrap_or_default();
    let id = match map_get(&started, "id") {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    };
    if resp.head.code != 202 || id.is_empty() {
        let e = map_get(&started, "error").map_or("<nil>".to_string(), go_v);
        return Err(Fail::Msg(format!("refused: {e}")));
    }
    let _ = writeln!(io.err, "limbo analyze: run {id} ({profile}, sha256 {sum}); booting a sealed guest...");
    // time.Duration(timeout+400) * time.Second, int64 nanoseconds that wrap
    let d = timeout.wrapping_add(400).wrapping_mul(1_000_000_000);
    let start = Instant::now();
    let in_time = |now: Instant| d > 0 && now.duration_since(start) < Duration::from_nanos(d as u64);
    while in_time(Instant::now()) {
        std::thread::sleep(Duration::from_secs(3));
        let url = client::request_url(&format!("/v1/runs/{id}"))?;
        let mut r = client::send_typed(sock, "GET", url, None, None)?;
        let raw = r.body.read_limited(1 << 20);
        let res = unmarshal_map(&raw).unwrap_or_default();
        if matches!(map_get(&res, "status"), Some(Value::String(s)) if s == "running") {
            continue;
        }
        if as_json {
            let _ = io.out.write_all(&raw);
            let _ = io.out.write_all(b"\n");
        } else {
            let _ = io.out.write_all(map_get(&res, "stdout").map_or("<nil>".to_string(), go_v).as_bytes());
            if let Some(Value::String(e)) = map_get(&res, "stderr") {
                if !e.is_empty() {
                    let _ = io.err.write_all(e.as_bytes());
                }
            }
            if let Some(Value::String(e)) = map_get(&res, "error") {
                if !e.is_empty() {
                    return Err(Fail::Msg(e.clone()));
                }
            }
        }
        return Ok(());
    }
    Err(Fail::Msg("the run did not finish in time".into()))
}
