//! `limbo wine [options] [--] PROGRAM [ARGS]` (cmd/limbo/wine_cmd.go): a Windows program with Wine, on the desktop,
//! inside its prefix's bubblewrap sandbox (crate::wine). Limbo's `wine` on PATH runs `limbo wine --shim`. Same
//! arguments, output, errors, events, records and exit status as Go; rust/parity/cli-differential.py compares the two
//! binaries on a made-up host (fake bwrap, display and sound sockets, graphics nodes and accounts in a namespace).

use super::commands::{Fail, Io};
use super::flags::FlagSet;
use super::local::default_state_dir;
use crate::events::{self, Emitter};
use crate::wine::{self, profile, run::Run, Dirs, Flags};
use crate::{sys, Detail};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;

const USAGE: &str = "usage: limbo wine [options] [--] PROGRAM [ARGS]   (Windows programs with Wine, inside a sandbox)";

/// The command, or None when the environment or the working folder is not UTF-8 (the Go limbo runs it then).
pub fn run(args: &[String], io: &mut Io) -> Option<Result<(), Fail>> {
    let mut environ = BTreeMap::new();
    for (k, v) in std::env::vars_os() {
        let (Some(k), Some(v)) = (k.to_str(), v.to_str()) else { return None };
        environ.insert(k.to_string(), v.to_string());
    }
    let cwd = match getwd() {
        Ok(Some(c)) => Ok(c),
        Ok(None) => return None,
        Err(e) => Err(e),
    };
    Some(wine_cmd(args, io, &environ, cwd))
}

/// os.Getwd: $PWD when it names the working folder, else getcwd; Ok(None) when the answer is not UTF-8.
fn getwd() -> Result<Option<String>, String> {
    let pwd = std::env::var_os("PWD").unwrap_or_default();
    if pwd.as_encoded_bytes().first() == Some(&b'/') {
        let dot = std::fs::metadata(".").map_err(|e| sys::go_path_error("stat", ".", &e))?;
        if let Ok(d) = std::fs::metadata(&pwd) {
            if d.dev() == dot.dev() && d.ino() == dot.ino() {
                return Ok(pwd.to_str().map(String::from));
            }
        }
    }
    match std::env::current_dir() {
        Ok(p) => Ok(p.to_str().map(String::from)),
        Err(e) => Err(format!("getwd: {}", sys::go_err(&e))),
    }
}

fn wine_cmd(args: &[String], io: &mut Io, environ: &BTreeMap<String, String>, cwd: Result<String, String>) -> Result<(), Fail> {
    let mut fs = FlagSet::new("wine");
    fs.usage_header(USAGE);
    fs.string(
        "prefix",
        "",
        "the prefix ~/.local/share/limbo/wine/NAME, with its profile ~/.config/limbo/wine/NAME.json (default \"default\")",
    );
    fs.bool("network", false, "share the host's network (default: no network at all)");
    fs.list("share", "a folder (or file) the program may read, at the same path inside (repeatable)");
    fs.list("share-rw", "a folder (or file) the program may read and write (repeatable)");
    fs.list("env", "NAME=VALUE in the program's environment (repeatable)");
    fs.bool("no-gpu", false, "no graphics card (software rendering)");
    fs.bool("no-audio", false, "no sound");
    fs.bool("no-x11", false, "Wayland only (an X11 program can read other X11 programs' windows and keys)");
    fs.bool("no-display", false, "no display (console programs)");
    fs.bool("headless", false, "no display and no sound: console programs in the background");
    fs.string(
        "windows",
        "",
        "the Windows version the prefix reports: win11, win10 (a new prefix's default), win81, win8, win7, vista, winxp64, winxp, win2k, win98",
    );
    fs.string("arch", "", "a new prefix's architecture: win64 (the default; it runs 32-bit programs too) or win32");
    fs.bool("trace", false, "record Wine's behaviour trace (processes, DLLs, network use, services) in the run's folder");
    fs.bool("dry-run", false, "print the sandbox and the steps; change nothing");
    fs.string("state-dir", &default_state_dir(io), "Limbo's state folder: the event log and the run folders");
    fs.bool("shim", false, "for Limbo's wine command on PATH: the prefix comes from WINEPREFIX");
    let mut stderr = vec![];
    let r = fs.parse(args, &mut stderr);
    let _ = io.err.write_all(&stderr);
    let rest = r.map_err(Fail::Msg)?;
    let f = Flags {
        network: fs.is_true("network"),
        no_gpu: fs.is_true("no-gpu"),
        no_audio: fs.is_true("no-audio"),
        no_x11: fs.is_true("no-x11"),
        no_display: fs.is_true("no-display"),
        headless: fs.is_true("headless"),
        share: fs.strs("share"),
        share_rw: fs.strs("share-rw"),
        env: fs.strs("env"),
        windows: fs.str("windows"),
        arch: fs.str("arch"),
        trace: fs.is_true("trace"),
    };
    let (dry, shim, state) = (fs.is_true("dry-run"), fs.is_true("shim"), fs.str("state-dir"));

    let h = wine::probe::probe(environ)?;
    let cwd = cwd?;
    let dirs = Dirs::default_dirs(io.env, &h.home, &state);
    let (via, parent) = if shim { ("path", parent_name()) } else { ("cli", vec![]) };

    // refusals before a run exists go to the log too
    let log_path = sys::join(&[&state, "events.jsonl"]);
    let mut log: Option<events::Logger> = None;
    let open_log = |log: &mut Option<events::Logger>| -> Result<(), String> {
        if log.is_some() || dry {
            return Ok(());
        }
        let l =
            events::Logger::open_go(&log_path).map_err(|e| format!("wine: the event log could not be opened, so nothing was run: {e}"))?;
        *log = Some(l);
        Ok(())
    };
    let log_err = |e: &std::io::Error| format!("write {log_path}: {}", sys::go_err(e));
    let refuse = |log: &mut Option<events::Logger>, guest: &str, err: String| -> Fail {
        if open_log(log).is_ok() {
            if let Some(l) = log.as_ref() {
                let mut d: Detail = crate::detail([("reason", &err), ("via", via)]);
                if !parent.is_empty() {
                    d.insert("parent".into(), crate::gotext::lossy(&parent));
                }
                let _ = l.emit(wine::run::WINE_REFUSED, guest, d);
            }
        }
        Fail::Msg(err)
    };

    let mut name = fs.str("prefix");
    if shim && !name.is_empty() {
        return Err("wine: --shim takes the prefix from WINEPREFIX; leave out --prefix".into());
    } else if shim {
        let wp = environ_get(io, "WINEPREFIX");
        name = wine::shim_prefix(&wp, &dirs).map_err(|e| refuse(&mut log, "wine", e))?;
    } else if name.is_empty() {
        name = wine::DEFAULT_PREFIX.into();
    }
    wine::valid_name(&name)?;
    if !f.windows.is_empty() {
        wine::valid_windows(&f.windows)?;
    }
    if !f.arch.is_empty() {
        wine::valid_arch(&f.arch)?;
    }
    let mut profile_path = dirs.profile(&name);
    let (p, profile_sha) = profile::load_profile(&profile_path).map_err(|e| refuse(&mut log, &wine::guest(&name), e))?;
    if p.is_none() {
        profile_path.clear();
    }
    let o = wine::merge(&name, p.as_ref(), &f, &cwd, &h.home).map_err(|e| refuse(&mut log, &wine::guest(&name), e))?;
    let (program, prog_args) = if let Some((first, more)) = rest.split_first() {
        (first.clone(), more.to_vec())
    } else if let Some(p) = p.as_ref().filter(|p| !p.program.is_empty()) {
        (p.program.clone(), p.args.clone().unwrap_or_default())
    } else if shim {
        return Err("usage: wine PROGRAM [ARGS]   (Limbo's wine: it runs in Limbo's sandbox; see limbo wine --help)".into());
    } else {
        (String::new(), vec![])
    };

    let mut r = Run {
        options: o,
        host: h,
        dirs,
        program,
        args: prog_args,
        cwd,
        via: via.into(),
        parent: parent.clone(),
        profile: profile_path,
        profile_sha,
        log: None,
        stop_grace: std::time::Duration::ZERO,
        log_err: &log_err,
    };
    if dry {
        return r.dry_run(io.out).map_err(Fail::Msg);
    }
    open_log(&mut log)?;
    r.log = log.as_ref().map(|l| l as &dyn Emitter);
    let _ = io.out.flush();
    let (code, err) = r.run();
    if let Some(e) = err {
        return Err(Fail::Msg(e));
    }
    if code != 0 {
        return Err(Fail::Exit(code));
    }
    Ok(())
}

fn environ_get(io: &Io, k: &str) -> String {
    (io.env)(k)
}

/// parentName: the program that ran Limbo's wine command (its /proc comm), for the event log.
fn parent_name() -> Vec<u8> {
    let ppid = rustix::process::getppid().map_or(0, |p| p.as_raw_nonzero().get());
    let Ok(b) = std::fs::read(format!("/proc/{ppid}/comm")) else { return vec![] };
    match std::str::from_utf8(&b) {
        Ok(s) => crate::gotext::trim_space(s).as_bytes().to_vec(),
        Err(_) => b.trim_ascii().to_vec(),
    }
}
