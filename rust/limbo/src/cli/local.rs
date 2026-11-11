//! The Go CLI's commands that read a manifest and the files here (cmd/limbo/main.go): `limbo version | validate | plan
//! | address`, an unknown command (which Go reads as one taking a manifest), and no command at all. Same arguments,
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
const OWN_SWITCH: [&str; 14] = [
    "serve",
    "quarantine",
    "report",
    "doctor",
    "setup",
    "passthrough",
    "analyze",
    "settings",
    "instance",
    "license",
    "exchange",
    "net",
    "wine",
    "image",
];
const STILL_GO: [&str; 7] = ["seed", "up", "down", "launch", "capture", "export", "screenshot"];

/// `limbo` with no command, `version`, `validate`, `plan`, `address` and any command Go does not know; None for the
/// rest.
pub fn run(cmd: Option<&str>, args: &[String], io: &mut Io) -> Option<Result<(), Fail>> {
    let Some(cmd) = cmd else { return Some(Err(Fail::Msg(USAGE.into()))) };
    if cmd == "version" {
        let _ = writeln!(io.out, "{VERSION}");
        return Some(Ok(()));
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

/// The flags every manifest command shares (main.go's `run`).
struct Opts {
    state: String,
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
    Ok(Opts { state: fs.str("state-dir"), pos })
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
