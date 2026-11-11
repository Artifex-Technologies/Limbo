//! `limbo passthrough status | approve [--minutes N] DEVICE... | revoke | clear` (cmd/limbo/passthrough_cmd.go): the
//! only way to approve a passthrough window. Root at a terminal, a typed "yes", a root-only file; there is no socket
//! route for it. Same output, errors, events and files as Go; rust/parity/cli-differential.py compares the two
//! binaries over fake sysfs device folders in a mount namespace (never the host's devices).

use super::commands::{Fail, Io};
use super::flags::{self, FlagSet};
use super::local::{check_root_state_dir, default_state_dir};
use crate::events::{self, Emitter};
use crate::gotime::{duration_string, Time};
use crate::hostpolicy::{Policy, Refused};
use crate::{detail, gotext, manifest, sys};

const USAGE: &str = "usage: limbo passthrough status | approve [--minutes N] DEVICE... | revoke | clear  (DEVICE: a PCI address 0000:03:00.0 or a USB ID 5059:4040)";

/// whoAmI: $SUDO_USER, else $USER.
fn who_am_i(io: &Io) -> String {
    let u = (io.env)("SUDO_USER");
    if !u.is_empty() {
        return u;
    }
    (io.env)("USER")
}

/// `t.Local().Format(time.RFC3339)`.
fn local_rfc3339(t: &Time) -> String {
    let (_, off, _) = crate::tz::local().lookup(t.unix());
    super::text::rfc3339(&t.in_offset(off as i32))
}

pub fn run(args: &[String], io: &mut Io) -> Result<(), Fail> {
    let mut fs = FlagSet::new("passthrough");
    fs.string("state-dir", &default_state_dir(io), "directory for the event log and the approval");
    fs.string("run-dir", "/run/limbo", "directory for the reboot-needed marker");
    fs.int("minutes", 30, "approve: how long the approval lasts (max 120)");
    fs.bool("i-know", false, "allow a state folder other than the daemon's");
    let mut stderr = vec![];
    let r = flags::parse_interspersed(&mut fs, args.to_vec(), &mut stderr);
    let _ = io.err.write_all(&stderr);
    let pos = r.map_err(Fail::Msg)?;
    if io.euid != 0 {
        return Err("passthrough: must run as root (it changes what guests may take from the host)".into());
    }
    let state = fs.str("state-dir");
    check_root_state_dir(io, &state, fs.is_true("i-know"))?;
    let tty = io.stdin_is_char_device;
    let log = events::Logger::open_go(&sys::join(&[&state, "events.jsonl"]))?;
    let p = Policy::new(&state, &fs.str("run-dir"));
    let d = fs.num("minutes").wrapping_mul(60_000_000_000);
    let who = who_am_i(io);
    passthrough(&pos, d, &p, &log, io, tty, &who)
}

fn passthrough(pos: &[String], d: i64, p: &Policy, log: &dyn Emitter, io: &mut Io, tty: bool, who: &str) -> Result<(), Fail> {
    let Some(first) = pos.first() else { return Err(USAGE.into()) };
    match first.as_str() {
        "status" => {
            let _ = writeln!(io.out, "host OS: {}", gotext::quote(&p.host_id()));
            match p.approval() {
                Some(a) => {
                    let _ = writeln!(
                        io.out,
                        "approved: {} until {} (by {})",
                        a.devices.unwrap_or_default().join(", "),
                        local_rfc3339(&a.expires),
                        a.by
                    );
                }
                None => {
                    let _ = writeln!(io.out, "approved: nothing for now");
                }
            }
            let (standing, ignored) = p.standing();
            if !standing.is_empty() {
                let _ = writeln!(
                    io.out,
                    "standing approval: {} (usb_standing in /etc/limbo/host-policy.json; lasts until removed there)",
                    standing.join(", ")
                );
            }
            if !ignored.is_empty() {
                let _ = writeln!(io.out, "ignored in usb_standing: {} (not a USB ID on usb_allow)", ignored.join(", "));
            }
            if p.blocked() {
                let _ = writeln!(
                    io.out,
                    "BLOCKED: an earlier run left a device unusable; reboot the host (or 'limbo passthrough clear' once you have recovered it)"
                );
            }
            Ok(())
        }
        "revoke" => {
            p.revoke()?;
            let _ = log.emit(events::PASSTHROUGH_REVOKE, "", detail([("by", who)]));
            let _ = writeln!(io.out, "approval removed");
            Ok(())
        }
        "clear" => {
            p.clear()?;
            let _ = writeln!(io.out, "reboot-needed marker removed");
            Ok(())
        }
        "approve" => approve(&pos[1..], d, p, log, io, tty, who),
        _ => Err(USAGE.into()),
    }
}

/// usbOnly: every named device is a USB ID, so the USB warning is the one shown.
fn usb_only(devs: &[String]) -> bool {
    !devs.is_empty() && devs.iter().all(|d| manifest::usb_id_ok(d))
}

fn approve(devs: &[String], d: i64, p: &Policy, log: &dyn Emitter, io: &mut Io, tty: bool, who: &str) -> Result<(), Fail> {
    if devs.is_empty() {
        return Err("approve: name the device(s), e.g. 0000:03:00.0 0000:03:00.1, or a USB device by its ID, e.g. 5059:4040".into());
    }
    if !tty {
        return Err("approve: run this from a terminal; it asks you to confirm".into());
    }
    if p.blocked() {
        return Err("approve: an earlier run left a device unusable; reboot the host first".into());
    }
    if let Err(e) = p.can_approve(devs) {
        if let Refused::Busy(who) = &e {
            let _ = writeln!(io.out, "These are using the device right now:");
            for w in who {
                let _ = writeln!(io.out, "  {w}");
            }
            let _ = writeln!(io.out, "Save your work and close them, then run this again.");
            if !usb_only(devs) {
                let _ = writeln!(io.out, "(If it is your desktop session, the display must run on the other GPU first.)");
            }
        }
        return Err(Fail::Msg(e.to_string()));
    }
    let names = devs.join(", ");
    let span = duration_string(d);
    if usb_only(devs) {
        let _ = write!(
            io.out,
            "USB passthrough approval for: {names}
For the next {span}, guests that ask for this device may take it from the host.

  - While a guest holds it, programs on the host cannot reach it.
  - The guest gets the device's raw USB traffic: it can send the device anything, including
    commands that change its contents or update its firmware. Approve only a device you
    accept may be changed.
  - Nothing on the host is using it right now.

Type \"yes\" to approve: "
        );
    } else {
        let _ = write!(
            io.out,
            "GPU test approval for: {names}
For the next {span}, validation runs (Sarina's) may take this device away from the host.

  - While a run holds it, the host cannot use it. Anything using it fails or is killed.
  - After a run the card may not reset cleanly. If it does not, Limbo refuses further
    passthrough runs until you reboot the host, and unsaved work on a display driven by
    this card could be lost.
  - Nothing appears to be using the device right now. Keep it that way: save your work
    and close anything that draws on this GPU (games, video, compositors, AI models).

Type \"yes\" to approve: "
        );
    }
    let _ = io.out.flush();
    let line = read_line(io);
    if gotext::trim_space(&gotext::lossy(&line)) != "yes" {
        let _ = writeln!(io.out, "not approved");
        return Ok(());
    }
    let a = p.approve(devs, d, who)?;
    let expires = super::text::rfc3339(&a.expires);
    let devices = a.devices.as_deref().unwrap_or_default().join(",");
    if let Err(e) = log.emit(events::PASSTHROUGH_APPROVE, "", detail([("devices", &devices), ("expires", &expires), ("by", who)])) {
        let _ = p.revoke(); // an approval that cannot be audited does not stand
        return Err(Fail::Msg(sys::go_err(&e)));
    }
    let _ = writeln!(io.out, "approved until {}", local_rfc3339(&a.expires));
    Ok(())
}

/// `bufio.NewReader(in).ReadString('\n')`: up to and including the first newline, or all there is.
fn read_line(io: &mut Io) -> Vec<u8> {
    let mut out = vec![];
    let mut b = [0u8; 1];
    loop {
        match io.stdin.read(&mut b) {
            Ok(1) => {
                out.push(b[0]);
                if b[0] == b'\n' {
                    return out;
                }
            }
            Ok(_) => return out,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return out,
        }
    }
}
