//! The Go CLI's commands that read a manifest and the files here (cmd/limbo/main.go, report_cmd.go): `limbo version |
//! validate | plan | address | report`, an unknown command (which Go reads as one taking a manifest), and no command. Same arguments,
//! output, errors and exit status as Go; rust/parity/cli-differential.py compares the two binaries.

use super::commands::{Fail, Io};
use super::flags::FlagSet;
use crate::gotext::quote;
use crate::manifest::{self, Manifest};
use crate::{launch, license, policy, sys, virt};

pub const VERSION: &str = crate::api::VERSION;

/// limbo.service's state folder.
pub const DAEMON_STATE_DIR: &str = "/var/lib/limbo/state";

const USAGE: &str = "usage: limbo <validate|plan|seed|up|launch|down|address|export|screenshot|capture|version> <manifest> [args] | limbo serve | limbo quarantine ... | limbo report | limbo doctor | limbo setup | limbo passthrough ... | limbo analyze FILE | limbo settings|instance|license|exchange ... | limbo image list|verify | limbo wine [options] -- PROGRAM [ARGS]";

/// The commands main.go's `run` handles before its manifest flag set, and those it handles after it that are still
/// the Go binary's.
const OWN_SWITCH: [&str; 11] =
    ["serve", "quarantine", "doctor", "setup", "passthrough", "settings", "instance", "license", "exchange", "net", "wine"];
const STILL_GO: [&str; 6] = ["up", "down", "launch", "capture", "export", "screenshot"];

/// `limbo` with no command, `version`, `validate`, `plan`, `seed`, `address`, `report`, `analyze`, `image` and any command Go does not know; None
/// for the rest.
pub fn run(cmd: Option<&str>, args: &[String], io: &mut Io) -> Option<Result<(), Fail>> {
    let Some(cmd) = cmd else { return Some(Err(Fail::Msg(USAGE.into()))) };
    if cmd == "version" {
        let _ = writeln!(io.out, "{VERSION}");
        return Some(Ok(()));
    }
    if cmd == "report" {
        return Some(report(args, io));
    }
    if cmd == "analyze" {
        return Some(super::analyze::run(args, io));
    }
    if cmd == "image" {
        return Some(super::image::run(args, io));
    }
    if OWN_SWITCH.contains(&cmd) || STILL_GO.contains(&cmd) {
        return None;
    }
    Some(manifest_cmd(cmd, args, io))
}

/// defaultStateDir: $LIMBO_STATE_DIR, the daemon's folder for root, else ~/.local/state/limbo ("limbo-state" with no
/// $HOME).
pub fn default_state_dir(io: &Io) -> String {
    let d = (io.env)("LIMBO_STATE_DIR");
    if !d.is_empty() {
        return d;
    }
    if io.euid == 0 {
        return DAEMON_STATE_DIR.into();
    }
    let home = (io.env)("HOME");
    if home.is_empty() {
        return "limbo-state".into();
    }
    sys::join(&[&home, ".local", "state", "limbo"])
}

/// checkRootStateDir: as root, only the daemon's state folder unless --i-know.
pub fn check_root_state_dir(io: &Io, state: &str, i_know: bool) -> Result<(), Fail> {
    if io.euid != 0 || i_know || sys::clean(state) == DAEMON_STATE_DIR {
        return Ok(());
    }
    Err(Fail::Msg(format!(
        "as root the state folder is the daemon's ({DAEMON_STATE_DIR}), where the quarantine holds and Heimdall's view are; \
         add --i-know to use {state} anyway"
    )))
}

/// The flags every manifest command shares (main.go's `run`).
struct Opts {
    state: String,
    iso: String,
    pos: Vec<String>,
}

fn parse(cmd: &str, args: &[String], io: &mut Io) -> Result<Opts, Fail> {
    let name: &'static str = Box::leak(cmd.to_string().into_boxed_str());
    let mut fs = FlagSet::new(name);
    fs.string("state-dir", &default_state_dir(io), "directory for event log and generated definitions");
    fs.string("iso", "", "seed: also build the seed CD at this path: cloud-init for Linux, the answer file for Windows (needs xorriso)");
    fs.bool("i-know", false, "as root, allow a state folder other than the daemon's");
    fs.int("seconds", 120, "capture: how long to record (at most 3600)");
    fs.bool("check", false, "launch: run every check (hold, address, pinned key, ssh, the app and waypipe in the guest, waypipe and a display here) without opening a window");
    fs.string("identity", "", "launch: the ssh private key to use (default: your ssh defaults)");
    let mut stderr = vec![];
    let r = fs.parse(args, &mut stderr);
    let _ = io.err.write_all(&stderr);
    let pos = r.map_err(Fail::Msg)?;
    Ok(Opts { state: fs.str("state-dir"), iso: fs.str("iso"), pos })
}

fn manifest_cmd(cmd: &str, args: &[String], io: &mut Io) -> Result<(), Fail> {
    let o = parse(cmd, args, io)?;
    if o.pos.is_empty() {
        return Err(Fail::Msg(format!("{cmd}: manifest path required")));
    }
    let m = manifest::load(&o.pos[0])?;
    match cmd {
        "validate" => {
            let _ = writeln!(io.out, "{}: ok ({} guest, network {})", m.name, m.os, m.network.mode);
            Ok(())
        }
        "plan" => plan(&m, &o.state, io),
        "seed" => {
            if o.pos.len() != 2 {
                return Err(Fail::Msg("seed: output directory required".into()));
            }
            super::seed::seed(&m, &o.pos[1], &o.iso, io)
        }
        "address" => {
            let ip = guest_address(&m, &o.state)?;
            let _ = writeln!(io.out, "{ip}");
            Ok(())
        }
        _ => Err(Fail::Msg(format!("unknown command {}", quote(cmd)))),
    }
}

/// guestAddress: the guest's IPv4 address from the subnet recorded at up (the state folder's record, then the
/// daemon's).
pub fn guest_address(m: &Manifest, state: &str) -> Result<String, String> {
    for dir in [state, DAEMON_STATE_DIR] {
        let s = virt::Subnets { path: sys::join(&[dir, "subnets.json"]), in_use: None };
        if let Some(x) = s.lookup(&m.name) {
            let mut cp = m.clone();
            cp.subnet = x;
            return Ok(virt::ip4(virt::addr(&cp).guest));
        }
    }
    Err(format!("guest {} is not up (no subnet is recorded for it)", quote(&m.name)))
}

/// plan: everything `up` would apply, changing nothing.
fn plan(m: &Manifest, state: &str, io: &mut Io) -> Result<(), Fail> {
    if let Err(e) = license::check(m) {
        let _ = writeln!(io.out, "# GATE: {e}");
    }
    let net = virt::network_xml(m);
    let dom = virt::domain_xml(m, &sys::join(&[state, &virt::disk_name(m)]))?;
    let rules = policy::nft(m)?;
    let launch_line = match launch::build(m, "<known_hosts holding the pinned key>") {
        Ok(c) => c.args.join(" "),
        Err(e) => format!("refused: {e}"),
    };
    let _ = writeln!(io.out, "# addresses are placeholders: each guest's subnet is given and recorded at up (limbo address MANIFEST)");
    let _ = write!(io.out, "# libvirt network\n{net}\n# libvirt domain\n{dom}\n# nftables\n{rules}\n# launch\n{launch_line}\n");
    Ok(())
}

// ---- report (cmd/limbo/report_cmd.go) ----

fn report(args: &[String], io: &mut Io) -> Result<(), Fail> {
    let mut fs = FlagSet::new("report");
    fs.string("state-dir", &default_state_dir(io), "directory holding events.jsonl and quarantine/");
    fs.string("guest", "", "only this guest");
    fs.string("since", "", "only this period: a duration like 24h or 7d, or a date like 2026-10-01");
    fs.string("out", "", "write to this file instead of stdout");
    let mut stderr = vec![];
    let r = super::flags::parse_interspersed(&mut fs, args.to_vec(), &mut stderr);
    let _ = io.err.write_all(&stderr);
    r.map_err(Fail::Msg)?;
    let (state, since, out) = (fs.str("state-dir"), fs.str("since"), fs.str("out"));
    let now = crate::gotime::Time::now().utc();
    let mut inp =
        crate::report::Input { events: vec![], skipped: 0, records: vec![], guest: fs.str("guest"), since: Default::default(), now };
    if !since.is_empty() {
        inp.since = parse_since(&since, now)?;
    }
    let (evs, skipped, err) = crate::events::read(&sys::join(&[&state, "events.jsonl"]));
    if let Some(e) = err {
        if !e.not_exist {
            return Err(Fail::Msg(e.msg));
        }
    }
    inp.events = evs;
    inp.skipped = skipped;
    let store = crate::quarantine::Store::open(&sys::join(&[&state, "quarantine"]))?;
    inp.records = store.list();
    let doc = crate::report::render(&inp);
    if out.is_empty() {
        let _ = io.out.write_all(doc.as_bytes());
        return Ok(());
    }
    sys::write_file(&out, doc.as_bytes(), 0o644).map_err(|e| Fail::Msg(sys::go_path_error("open", &out, &e)))
}

/// parseSince: "36h", "7d" or a calendar date.
pub fn parse_since(s: &str, now: crate::gotime::Time) -> Result<crate::gotime::Time, String> {
    let n = s.len();
    if n > 1 && s.ends_with('d') {
        if let Some(days) = sscanf_int(&s[..n - 1]) {
            if days > 0 {
                // Go: now.Add(-time.Duration(days) * 24 * time.Hour), int64 arithmetic that wraps
                return Ok(now.add(days.wrapping_neg().wrapping_mul(86_400_000_000_000)));
            }
        }
    }
    if let Some(d) = crate::gotime::parse_duration(s) {
        if d > 0 {
            return Ok(now.add(-d));
        }
    }
    if let Some(t) = crate::gotime::parse_date(s) {
        return Ok(t);
    }
    Err("--since must be a duration (24h, 7d) or a date (2026-10-01)".into())
}

/// fmt's isSpace (the scanner's own table).
fn fmt_space(c: char) -> bool {
    matches!(c as u32, 0x09..=0x0d | 0x20 | 0x85 | 0xa0 | 0x1680 | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000)
}

/// `fmt.Sscanf(s, "%d", &n)`: spaces skipped (a newline is an error), an optional sign, at least one digit, within
/// int64; anything after the number is left unread.
fn sscanf_int(s: &str) -> Option<i64> {
    let mut rest = s;
    loop {
        let c = rest.chars().next()?;
        if c == '\r' && rest[1..].starts_with('\n') {
            rest = &rest[1..];
            continue;
        }
        if c == '\n' {
            return None;
        }
        if !fmt_space(c) {
            break;
        }
        rest = &rest[c.len_utf8()..];
    }
    let b = rest.as_bytes();
    let sign = usize::from(matches!(b.first(), Some(b'+' | b'-')));
    let digits = b[sign..].iter().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    rest[..sign + digits].parse().ok()
}
