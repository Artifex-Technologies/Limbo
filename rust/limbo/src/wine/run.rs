//! One `limbo wine` run (Go: internal/wine/run_linux.go): the checks, the prefix's setup, the sandbox run with its stop
//! handling, the run record and the events; and the dry run.
//!
//! bwrap is started as Go's os/exec starts it: fork and execve (no shell fallback for a file without a `#!`), its own
//! process group, the stop pipe on descriptor 3, the started pipe on 4, the data files from 5, every signal back to its
//! default in the child. A first SIGINT, SIGTERM or SIGHUP asks the sandbox to stop (a line on the stop pipe); a second
//! one, or the stop grace without an end, kills the process group.

use super::prefix::{self, PrefixRecord};
use super::record::{self, allowed, clean, Record, Trace};
use super::sandbox::{self, Sandbox};
use super::trace::{split_trace, TRACE_CHANNELS, TRACE_LIMIT};
use super::{check_share, guest, paths, valid_arch, valid_name, valid_windows, visible, within};
use super::{Dirs, Options, ARCH_WIN32, ARCH_WIN64, BWRAP_PATH, DEFAULT_WINDOWS, MAX_SHARES, NET_HOST, NET_NONE};
use super::{WINESERVER_PATH, WINE_PATH};
use crate::events::Emitter;
use crate::gotext::quote;
use crate::gotime::Time;
use crate::{sys, Detail};
use std::ffi::CString;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::time::{Duration, Instant};

pub const WINE_START: &str = "wine.start";
pub const WINE_STOP: &str = "wine.stop";
pub const WINE_SETUP: &str = "wine.setup";
pub const WINE_REFUSED: &str = "wine.refused";

/// The in-sandbox script: it reports that it runs (descriptor 4), starts the prefix's wineserver without persistence,
/// runs body, waits for the wineserver, and answers a line on descriptor 3 with `wineserver -k`.
pub fn script(body: &str) -> String {
    format!(
        "printf x >&4; exec 4>&- 5<&- 6<&- 7<&- 8<&- 9<&-; {{ read -r x <&3 && {WINESERVER_PATH} -k; }} & {WINESERVER_PATH} -p0 3<&-; {body}; s=$?; {WINESERVER_PATH} -w 3<&-; exit $s"
    )
}

pub fn body_run() -> String {
    format!("{WINE_PATH} \"$@\" 3<&-")
}

pub fn body_create() -> String {
    format!("{WINE_PATH} wineboot --init 3<&- && {WINE_PATH} winecfg -v \"$1\" 3<&-")
}

pub fn body_windows() -> String {
    format!("{WINE_PATH} winecfg -v \"$1\" 3<&-")
}

/// One `limbo wine` run.
pub struct Run<'a> {
    pub options: Options,
    pub host: sandbox::Host,
    pub dirs: Dirs,
    pub program: String,
    pub args: Vec<String>,
    pub cwd: String,
    /// "cli", or "path" through Limbo's wine command on PATH
    pub via: String,
    /// the program that ran Limbo's wine command (its /proc comm, as bytes)
    pub parent: Vec<u8>,
    pub profile: String,
    pub profile_sha: String,
    pub log: Option<&'a dyn Emitter>,
    /// how long a stop request may take before the sandbox is killed (Go's default: 10 s)
    pub stop_grace: Duration,
    /// how an event log error reads (Go's *PathError text of the failed write)
    pub log_err: &'a dyn Fn(&std::io::Error) -> String,
}

/// What exec gives back.
#[derive(Default)]
struct ExecResult {
    code: i32,
    started: bool,
    stopped: String,
    err: Option<String>,
}

/// Where the sandbox's standard input and output go: this process's own descriptor, or /dev/null.
#[derive(Clone, Copy)]
enum Stdio {
    Fd(RawFd),
    Null,
}

impl Run<'_> {
    fn emit(&self, kind: &str, guest: &str, d: Detail) -> Result<(), String> {
        match self.log {
            Some(l) => l.emit(kind, guest, d).map_err(|e| (self.log_err)(&e)),
            None => Ok(()),
        }
    }

    /// detail: what every Wine event carries about the run's origin.
    fn detail(&self, mut d: Detail) -> Detail {
        d.insert("prefix".into(), self.options.prefix.clone());
        d.insert("program".into(), clean(self.program.as_bytes(), 200));
        d.insert("via".into(), self.via.clone());
        if !self.parent.is_empty() {
            d.insert("parent".into(), clean(&self.parent, 64));
        }
        d
    }

    /// Do: runs the program; the exit status and limbo's own error. Every run is recorded: wine.start before the
    /// sandbox starts, wine.stop after, each refusal as wine.refused.
    pub fn run(&mut self) -> (i32, Option<String>) {
        if self.via.is_empty() {
            self.via = "cli".into();
        }
        if self.log.is_none() {
            return (1, Some("wine: no event log, so nothing was run".into()));
        }
        let g = guest(&self.options.prefix);
        let refuse = |me: &Self, err: String| -> (i32, Option<String>) {
            let d = me.detail(crate::detail([("reason", &clean(err.as_bytes(), 300))]));
            let _ = me.emit(WINE_REFUSED, &g, d);
            (1, Some(err))
        };
        if rustix::process::geteuid().is_root() {
            return refuse(self, "wine: refusing to run Windows programs as root; run limbo wine as yourself".into());
        }
        if !executable(BWRAP_PATH) {
            return refuse(
                self,
                format!("wine: bubblewrap is not installed ({BWRAP_PATH}); Limbo runs Wine only inside it: sudo pacman -S bubblewrap"),
            );
        }
        if !executable(WINE_PATH) {
            return refuse(self, format!("wine: Wine is not installed ({WINE_PATH}): sudo pacman -S wine (or wine-staging)"));
        }
        if let Err(e) = self.check() {
            return refuse(self, e);
        }
        if let Err(e) = prefix::ensure_dir(&self.dirs.root) {
            return refuse(self, e);
        }
        let _lock = match prefix::lock_prefix(&self.dirs, &self.options.prefix) {
            Ok(f) => f,
            Err(e) => return refuse(self, e),
        };
        for dir in [self.dirs.prefix(&self.options.prefix), self.dirs.cache.clone(), self.dirs.prefix_cache(&self.options.prefix)] {
            if let Err(e) = prefix::ensure_dir(&dir) {
                return refuse(self, e);
            }
        }
        let mut s = match sandbox::build(&self.options, &self.host, &self.dirs) {
            Ok(s) => s,
            Err(e) => return refuse(self, e),
        };
        if let Ok(cwd) = paths::eval_symlinks(&self.cwd) {
            if visible(&cwd, &self.options, &self.dirs) && visible(&self.cwd, &self.options, &self.dirs) {
                s.set_chdir(&self.cwd.clone());
            }
        }

        let start = Time::now().utc();
        let started_at = Instant::now();
        let (id, dir) = match record::new_run_dir(&self.dirs.state, &start) {
            Ok(x) => x,
            Err(e) => return refuse(self, format!("wine: the run folder: {e}")),
        };
        let record_path = sys::join(&[&dir, "run.json"]);
        let mut rec = Record {
            id: id.clone(),
            prefix: self.options.prefix.clone(),
            via: self.via.clone(),
            parent: crate::gotext::lossy(&self.parent),
            profile: self.profile.clone(),
            profile_sha256: self.profile_sha.clone(),
            program: self.program.clone(),
            args: self.args.clone(),
            cwd: s.chdir.clone(),
            started: start,
            status: "running".into(),
            allowed: allowed(&self.options, &s),
            ..Record::default()
        };
        let pf = self.program_file();
        if !pf.is_empty() {
            if let Some((sum, size)) = record::hash_file(&pf) {
                (rec.program_path, rec.program_sha256, rec.program_size) = (pf, sum, size);
            }
        }
        if let Err((code, err)) = self.setup(&s, &mut rec, &id, &record_path) {
            rec.ended = Some(Time::now().utc());
            rec.exit_code = Some(code as i64);
            rec.status = "setup_failed".into();
            let _ = rec.save(&dir);
            return (code, Some(err));
        }
        if self.options.trace {
            rec.trace = Some(Trace {
                file: sys::join(&[&dir, "trace.log"]),
                channels: TRACE_CHANNELS.into(),
                limit: TRACE_LIMIT,
                ..Trace::default()
            });
        }

        let mut start_detail = self.detail(crate::detail([
            ("run", &id),
            ("record", &record_path),
            ("network", &self.options.network),
            ("gpu", on_off(s.gpu)),
            ("display", &or_none(&s.display.join(","))),
            ("audio", &or_none(&s.audio)),
            ("share", &share_list(&self.options, false)),
            ("share_rw", &share_list(&self.options, true)),
        ]));
        if !rec.program_sha256.is_empty() {
            start_detail.insert("sha256".into(), rec.program_sha256.clone());
        }
        if self.options.trace {
            start_detail.insert("trace".into(), "on".into());
        }
        if let Err(e) = rec.save(&dir) {
            return (1, Some(format!("wine: the run record could not be written, so nothing was run: {e}")));
        }
        if let Err(e) = self.emit(WINE_START, &g, start_detail) {
            rec.status = "not_started".into();
            let _ = rec.save(&dir);
            return (1, Some(format!("wine: the event log could not be written, so nothing was run: {e}")));
        }

        let env = if self.options.trace { s.with_env("WINEDEBUG", TRACE_CHANNELS) } else { s.env.clone() };
        let mut argv_args = vec![self.program.clone()];
        argv_args.extend(self.args.iter().cloned());
        let mut res = self.exec(&s, &script(&body_run()), &argv_args, &env, Stdio::Fd(0), Stdio::Fd(1), rec.trace.as_mut());
        let end = Time::now().utc();
        let seconds = started_at.elapsed().as_secs_f64();
        rec.ended = Some(end);
        rec.exit_code = Some(res.code as i64);
        rec.stopped = res.stopped.clone();
        rec.status = if res.err.is_some() || !res.started {
            "sandbox_failed"
        } else if !res.stopped.is_empty() {
            "stopped"
        } else {
            "exited"
        }
        .into();
        let save_err = rec.save(&dir).err();
        let mut stop = self.detail(crate::detail([
            ("run", &id),
            ("record", &record_path),
            ("exit_code", &res.code.to_string()),
            ("seconds", &crate::gotext::fixed(seconds, 1)),
            ("status", &rec.status),
        ]));
        if !res.stopped.is_empty() {
            stop.insert("stopped".into(), res.stopped.clone());
        }
        if let Err(e) = self.emit(WINE_STOP, &g, stop) {
            if res.err.is_none() {
                res.err = Some(format!("wine: the program ran, but its end could not be logged: {e}"));
            }
        }
        if res.err.is_none() && !res.started {
            res.err = Some(format!("wine: the sandbox could not be set up (bwrap exit status {}; its message is above)", res.code));
        }
        if res.err.is_none() {
            res.err = save_err;
        }
        (res.code, res.err)
    }

    /// check: bad names, shares Limbo will not give, a program outside the sandbox.
    pub fn check(&self) -> Result<(), String> {
        let o = &self.options;
        valid_name(&o.prefix)?;
        if !o.windows.is_empty() {
            valid_windows(&o.windows)?;
        }
        if !o.arch.is_empty() {
            valid_arch(&o.arch)?;
        }
        if o.network != NET_NONE && o.network != NET_HOST {
            return Err(format!("wine: network must be {} or {}", quote(NET_NONE), quote(NET_HOST)));
        }
        if o.shares.len() > MAX_SHARES {
            return Err(format!("wine: more than {MAX_SHARES} shares"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for sh in &o.shares {
            if !seen.insert(sh.path.clone()) {
                return Err(format!("wine: {} is shared twice", sh.path));
            }
            check_share(sh, &self.host.home, &self.dirs)?;
        }
        if self.program.is_empty() {
            return Err("wine: no program to run (limbo wine [options] -- PROGRAM [ARGS], or a profile's \"program\")".into());
        }
        if self.program.contains('/') {
            let p = self.unix_program();
            if std::fs::metadata(&p).is_ok() && !visible(&p, o, &self.dirs) {
                return Err(format!(
                    "wine: {p} is outside the sandbox, so Wine would not find it: share its folder read-only (--share {}) or copy it into the prefix ({})",
                    sys::dir(&p),
                    sys::join(&[&self.dirs.prefix(&o.prefix), "drive_c"])
                ));
            }
        }
        Ok(())
    }

    fn unix_program(&self) -> String {
        let p = if self.program.starts_with('/') { self.program.clone() } else { sys::join(&[&self.cwd, &self.program]) };
        sys::clean(&p)
    }

    /// programFile: the host file the program names when Limbo can tell, and only when it is inside the sandbox.
    pub fn program_file(&self) -> String {
        let prog = self.program.as_bytes();
        let p = if self.program.contains('/') {
            self.unix_program()
        } else if prog.len() > 3 && (prog[0] == b'c' || prog[0] == b'C') && prog[1] == b':' && prog[2] == b'\\' {
            let drive_c = sys::join(&[&self.dirs.prefix(&self.options.prefix), "drive_c"]);
            let p = sys::join(&[&drive_c, &self.program[3..].replace('\\', "/")]);
            if !within(&p, &drive_c) {
                return String::new();
            }
            p
        } else {
            return String::new();
        };
        match paths::eval_symlinks(&p) {
            Ok(real) if visible(&p, &self.options, &self.dirs) && visible(&real, &self.options, &self.dirs) => real,
            _ => String::new(),
        }
    }

    /// setup: makes a new prefix, or sets an existing one's Windows version when asked for one Limbo did not last set.
    fn setup(&self, s: &Sandbox, rec: &mut Record, id: &str, record_path: &str) -> Result<(), (i32, String)> {
        let name = &self.options.prefix;
        let pfx = self.dirs.prefix(name);
        let g = guest(name);
        let last = prefix::read_prefix_record(&self.dirs.record_file(name)).unwrap_or_default();
        let creating = self.dirs.creating_file(name);
        let fail = |step: &str, res: ExecResult, hint: &str| -> (i32, String) {
            let mut d = self.detail(crate::detail([
                ("run", id),
                ("record", record_path),
                ("during", "setup"),
                ("step", step),
                ("exit_code", &res.code.to_string()),
                ("status", "setup_failed"),
            ]));
            if !res.stopped.is_empty() {
                d.insert("stopped".into(), res.stopped.clone());
            }
            let _ = self.emit(WINE_STOP, &g, d);
            if let Some(e) = res.err {
                return (1, e);
            }
            if !res.stopped.is_empty() {
                return (res.code.max(1), format!("wine: stopped while setting up prefix {}", quote(name)));
            }
            (res.code.max(1), format!("wine: setting up prefix {} ({step}) failed with exit status {}{hint}", quote(name), res.code))
        };
        let logged = |e: String| (1, format!("wine: the event log could not be written, so nothing was run: {e}"));
        if !prefix::prefix_exists(&pfx) || prefix::exists(&creating) {
            let arch = if self.options.arch.is_empty() { ARCH_WIN64.to_string() } else { self.options.arch.clone() };
            let win = if self.options.windows.is_empty() { DEFAULT_WINDOWS.to_string() } else { self.options.windows.clone() };
            self.emit(WINE_SETUP, &g, crate::detail([("run", id), ("step", "create"), ("arch", &arch), ("windows", &win)]))
                .map_err(logged)?;
            let _ = writeln!(std::io::stderr(), "limbo wine: making prefix {} ({arch}, reporting {win}) in {pfx}...", quote(name));
            sys::write_file(&creating, b"", 0o600).map_err(|e| (1, sys::go_path_error("open", &creating, &e)))?;
            let res = self.exec(
                s,
                &script(&body_create()),
                std::slice::from_ref(&win),
                &s.with_env("WINEARCH", &arch),
                Stdio::Null,
                Stdio::Fd(2),
                None,
            );
            if res.err.is_some() || res.code != 0 || !res.stopped.is_empty() || !res.started {
                let hint = if arch == ARCH_WIN32 {
                    "; this Wine may not make 32-bit prefixes at all (a WoW64-only build, as Arch's Wine 11 is): a 64-bit prefix runs 32-bit programs too"
                } else {
                    ""
                };
                return Err(fail("create", res, hint));
            }
            prefix::write_prefix_record(
                &self.dirs.record_file(name),
                &PrefixRecord { arch: arch.clone(), windows: win.clone(), updated: Time::now().utc() },
            )
            .map_err(|e| (1, e))?;
            std::fs::remove_file(&creating).map_err(|e| (1, sys::go_path_error("remove", &creating, &e)))?;
            (rec.arch, rec.windows) = (arch, win);
            return Ok(());
        }
        let arch = prefix::prefix_arch(&pfx);
        if !self.options.arch.is_empty() && !arch.is_empty() && self.options.arch != arch {
            return Err((
                1,
                format!(
                    "wine: prefix {} is {arch}, and a prefix's architecture is fixed when it is made; use another --prefix for {}",
                    quote(name),
                    self.options.arch
                ),
            ));
        }
        (rec.arch, rec.windows) = (arch.clone(), last.windows.clone());
        let want = &self.options.windows;
        if !want.is_empty() && *want != last.windows {
            self.emit(WINE_SETUP, &g, crate::detail([("run", id), ("step", "windows"), ("windows", want)])).map_err(logged)?;
            let res = self.exec(s, &script(&body_windows()), std::slice::from_ref(want), &s.env, Stdio::Null, Stdio::Fd(2), None);
            if res.err.is_some() || res.code != 0 || !res.stopped.is_empty() || !res.started {
                return Err(fail("windows", res, ""));
            }
            prefix::write_prefix_record(
                &self.dirs.record_file(name),
                &PrefixRecord { arch, windows: want.clone(), updated: Time::now().utc() },
            )
            .map_err(|e| (1, e))?;
            rec.windows = want.clone();
        }
        Ok(())
    }

    /// exec: one sandbox to its end.
    #[allow(clippy::too_many_arguments)]
    fn exec(
        &self,
        s: &Sandbox,
        script: &str,
        args: &[String],
        env: &[String],
        stdin: Stdio,
        stdout: Stdio,
        tr: Option<&mut Trace>,
    ) -> ExecResult {
        let mut res = ExecResult::default();
        let argv = s.command(script, args);
        let _ = std::io::stdout().flush();
        let pipe = || -> Result<(OwnedFd, OwnedFd), String> { pipe2().map_err(|e| sys::go_err(&e)) };
        let (stop_r, stop_w) = match pipe() {
            Ok(p) => p,
            Err(e) => {
                res.err = Some(e);
                return res;
            }
        };
        let (stat_r, stat_w) = match pipe() {
            Ok(p) => p,
            Err(e) => {
                res.err = Some(e);
                return res;
            }
        };
        let mut extra: Vec<OwnedFd> = vec![stop_r, stat_w];
        let mut writers: Vec<(OwnedFd, Vec<u8>)> = vec![];
        for d in &s.data {
            match pipe() {
                Ok((r, w)) => {
                    extra.push(r);
                    writers.push((w, d.content.clone()));
                }
                Err(e) => {
                    res.err = Some(e);
                    return res;
                }
            }
        }
        // the trace: Wine's lines to the file, the rest to this process's error output
        let mut trace_pipe: Option<(OwnedFd, std::fs::File)> = None;
        let mut stderr_fd: OwnedFd = match dup_std(2) {
            Ok(fd) => fd,
            Err(e) => {
                res.err = Some(e);
                return res;
            }
        };
        if let Some(t) = tr.as_ref() {
            let tf = match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&t.file) {
                Ok(f) => f,
                Err(e) => {
                    res.err = Some(sys::go_path_error("open", &t.file, &e));
                    return res;
                }
            };
            match pipe() {
                Ok((r, w)) => {
                    stderr_fd = w;
                    trace_pipe = Some((r, tf));
                }
                Err(e) => {
                    res.err = Some(e);
                    return res;
                }
            }
        }
        let null = |write: bool| -> Result<OwnedFd, String> {
            std::fs::OpenOptions::new()
                .read(!write)
                .write(write)
                .open("/dev/null")
                .map(OwnedFd::from)
                .map_err(|e| sys::go_path_error("open", "/dev/null", &e))
        };
        let stdio_fd = |io: Stdio, write: bool| -> Result<OwnedFd, String> {
            match io {
                Stdio::Fd(fd) => dup_std(fd),
                Stdio::Null => null(write),
            }
        };
        let (in_fd, out_fd) = match (stdio_fd(stdin, false), stdio_fd(stdout, true)) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => {
                res.err = Some(e);
                return res;
            }
        };

        let signals = Signals::block();
        let child = spawn(&argv, env, [in_fd, out_fd, stderr_fd], extra);
        let pid = match child {
            Ok(pid) => pid,
            Err(e) => {
                drop(signals);
                res.err = Some(format!("wine: starting bwrap: {e}"));
                return res;
            }
        };
        for (w, content) in writers {
            std::thread::spawn(move || {
                let mut f = std::fs::File::from(w);
                let _ = f.write_all(&content);
            });
        }
        let tracer = trace_pipe.map(|(r, mut tf)| {
            let limit = tr.as_ref().map_or(TRACE_LIMIT, |t| t.limit);
            std::thread::spawn(move || {
                let mut err = std::io::stderr();
                split_trace(std::fs::File::from(r), &mut tf, &mut err, limit)
            })
        });
        let (wait_r, wait_w) = match pipe() {
            Ok(p) => p,
            Err(e) => {
                // cannot watch the child: wait for it as it is
                kill_group(pid);
                let _ = wait_pid(pid);
                res.err = Some(e);
                return res;
            }
        };
        let waiter = std::thread::spawn(move || {
            let st = wait_pid(pid);
            let _ = rustix::io::write(&wait_w, b"x");
            st
        });

        let grace = if self.stop_grace.is_zero() { Duration::from_secs(10) } else { self.stop_grace };
        let mut deadline: Option<Instant> = None;
        let kill = || kill_group(pid);
        loop {
            let timeout = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            match signals.wait(&wait_r, timeout) {
                Event::Done => break,
                Event::Signal(name) => {
                    if !res.stopped.is_empty() {
                        kill();
                        continue;
                    }
                    res.stopped = name.into();
                    let _ = writeln!(std::io::stderr(), "limbo wine: {name}: stopping the program (again to kill it at once)");
                    let _ = rustix::io::write(&stop_w, b"stop\n");
                    deadline = Some(Instant::now() + grace);
                }
                Event::Timeout => {
                    kill();
                    deadline = None;
                }
            }
        }
        let status = waiter.join().unwrap_or(0);
        drop(signals);
        if let Some(t) = tracer {
            if let Ok((bytes, truncated)) = t.join() {
                if let Some(t) = tr {
                    (t.bytes, t.truncated) = (bytes, truncated);
                }
            }
        }
        let mut b = [0u8; 1];
        res.started = matches!(rustix::io::read(&stat_r, &mut b), Ok(1));
        drop(stop_w);
        res.code = if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        res
    }

    /// DryRun: what a run would do (the checks, the sandbox, the steps); changes nothing.
    pub fn dry_run(&self, w: &mut dyn Write) -> Result<(), String> {
        self.check()?;
        let mut s = sandbox::build(&self.options, &self.host, &self.dirs)?;
        if visible(&self.cwd, &self.options, &self.dirs) {
            s.set_chdir(&self.cwd);
        }
        let o = &self.options;
        let pfx = self.dirs.prefix(&o.prefix);
        let mut out = String::new();
        out.push_str(&format!("# prefix {}: {pfx}\n", o.prefix));
        if !prefix::prefix_exists(&pfx) || prefix::exists(&self.dirs.creating_file(&o.prefix)) {
            let arch = if o.arch.is_empty() { ARCH_WIN64 } else { &o.arch };
            let win = if o.windows.is_empty() { DEFAULT_WINDOWS } else { &o.windows };
            out.push_str(&format!(
                "# it does not exist yet: it would first be made {arch}, reporting Windows version {win} (wineboot --init; winecfg -v {win})\n"
            ));
        } else if !o.windows.is_empty() {
            out.push_str(&format!("# its Windows version would be set to {} if Limbo last set another\n", o.windows));
        }
        let shares = if o.shares.is_empty() {
            "none".to_string()
        } else {
            o.shares
                .iter()
                .map(|sh| format!("{} ({})", sh.path, if sh.writable { "writable" } else { "read-only" }))
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(&format!(
            "# network {}; graphics card {}; display {}; sound {}; shares: {shares}\n",
            o.network,
            on_off(s.gpu),
            or_none(&s.display.join(",")),
            or_none(&s.audio)
        ));
        if o.trace {
            out.push_str(&format!("# traced: WINEDEBUG={TRACE_CHANNELS}, into the run folder (at most {} MiB)\n", TRACE_LIMIT >> 20));
        }
        out.push_str("# environment:\n");
        for kv in &s.env {
            out.push_str(&format!("#   {kv}\n"));
        }
        let mut bytes = out.into_bytes();
        for (i, d) in s.data.iter().enumerate() {
            bytes.extend_from_slice(format!("# descriptor {} becomes {}:\n", sandbox::FD_DATA as usize + i, d.dest).as_bytes());
            if d.dest.contains("Xauthority") || d.dest.contains("cookie") {
                bytes.extend_from_slice(format!("#   ({} bytes, not shown)\n", d.content.len()).as_bytes());
                continue;
            }
            let mut c: &[u8] = &d.content;
            while c.last() == Some(&b'\n') {
                c = &c[..c.len() - 1];
            }
            for line in c.split(|&b| b == b'\n') {
                bytes.extend_from_slice(b"#   ");
                bytes.extend_from_slice(line);
                bytes.push(b'\n');
            }
        }
        let mut a = vec![self.program.clone()];
        a.extend(self.args.iter().cloned());
        let argv = s.command(&script(&body_run()), &a);
        let mut lines: Vec<Vec<String>> = vec![];
        let mut command = false;
        for (i, x) in argv.iter().enumerate() {
            if i == 0 || (!command && x.starts_with("--")) {
                lines.push(vec![]);
            }
            command = command || x == "--";
            if let Some(l) = lines.last_mut() {
                l.push(shell_quote(x));
            }
        }
        let n = lines.len();
        for (i, l) in lines.iter().enumerate() {
            bytes.extend_from_slice(l.join(" ").as_bytes());
            bytes.extend_from_slice(if i == n - 1 { b"\n" } else { b" \\\n" });
        }
        let _ = w.write_all(&bytes);
        Ok(())
    }
}

/// quote: a word for the dry run's command lines, single-quoted unless it is plain.
pub fn shell_quote(s: &str) -> String {
    const PLAIN: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=,+@%";
    if !s.is_empty() && s.chars().all(|c| PLAIN.contains(c)) {
        return s.into();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn share_list(o: &Options, writable: bool) -> String {
    let paths: Vec<&[u8]> = o.shares.iter().filter(|sh| sh.writable == writable).map(|sh| sh.path.as_bytes()).collect();
    record::path_list(&paths)
}

/// executable: a regular file with an execute bit.
pub fn executable(p: &str) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

pub fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

pub fn or_none(s: &str) -> String {
    if s.is_empty() {
        "none".into()
    } else {
        s.into()
    }
}

/// pipe2 with O_CLOEXEC.
fn pipe2() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 fills two descriptors that are ours from then on
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both were just made and are owned by nothing else
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// A copy (close-on-exec) of one of this process's standard descriptors.
fn dup_std(fd: RawFd) -> Result<OwnedFd, String> {
    // SAFETY: fd is one of this process's standard descriptors, borrowed only to duplicate it
    let b = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    rustix::io::fcntl_dupfd_cloexec(b, 3).map_err(|e| sys::go_err(&std::io::Error::from(e)))
}

/// SIGKILL to the sandbox's process group.
fn kill_group(pid: i32) {
    // SAFETY: kill with a negative pid signals our child's own process group
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
}

/// waitpid for the child: its raw status (0 when it cannot be had).
fn wait_pid(pid: i32) -> i32 {
    let mut st = 0;
    loop {
        // SAFETY: waitpid on our own child with a valid status pointer
        let r = unsafe { libc::waitpid(pid, &mut st, 0) };
        if r == pid {
            return st;
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return 0;
        }
    }
}

/// os.StartProcess as Go does it for bwrap: fork, then in the child its own process group, the standard descriptors
/// and the extra ones from 3, every signal's default action, an empty signal mask, and execve (an exec failure comes
/// back through a pipe as Go's "fork/exec PATH: ..." text).
fn spawn(argv: &[String], env: &[String], stdio: [OwnedFd; 3], extra: Vec<OwnedFd>) -> Result<i32, String> {
    let path = argv[0].clone();
    let fail = |e: std::io::Error| format!("fork/exec {path}: {}", sys::go_err(&e));
    let cstr = |s: &str| CString::new(s).map_err(|_| fail(std::io::Error::from_raw_os_error(libc::EINVAL)));
    let c_path = cstr(&path)?;
    let c_argv: Vec<CString> = argv.iter().map(|a| cstr(a)).collect::<Result<_, _>>()?;
    let c_env: Vec<CString> = env.iter().map(|a| cstr(a)).collect::<Result<_, _>>()?;
    let mut p_argv: Vec<*const libc::c_char> = c_argv.iter().map(|c| c.as_ptr()).collect();
    p_argv.push(std::ptr::null());
    let mut p_env: Vec<*const libc::c_char> = c_env.iter().map(|c| c.as_ptr()).collect();
    p_env.push(std::ptr::null());

    // every source descriptor above every target, so placing one never overwrites another
    let base = 3 + extra.len() as RawFd + 1;
    let high = |fd: &OwnedFd| -> Result<OwnedFd, String> { rustix::io::fcntl_dupfd_cloexec(fd, base).map_err(|e| fail(e.into())) };
    let mut sources: Vec<(OwnedFd, RawFd)> = vec![];
    for (i, fd) in stdio.iter().enumerate() {
        sources.push((high(fd)?, i as RawFd));
    }
    for (i, fd) in extra.iter().enumerate() {
        sources.push((high(fd)?, 3 + i as RawFd));
    }
    drop(stdio);
    drop(extra);
    let (err_r, err_low) = pipe2().map_err(fail)?;
    let err_w = high(&err_low)?;
    drop(err_low);
    let pairs: Vec<(RawFd, RawFd)> = sources.iter().map(|(fd, t)| (fd.as_raw_fd(), *t)).collect();
    let err_fd = err_w.as_raw_fd();

    // SAFETY: fork in a process whose other threads (if any) hold no locks the child needs: the child only makes
    // async-signal-safe calls (setpgid, dup2, sigaction, sigprocmask, execve, write, _exit) on memory prepared above.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(fail(std::io::Error::last_os_error()));
    }
    if pid == 0 {
        // SAFETY: the child, see above
        unsafe {
            unsafe fn die(fd: RawFd) -> ! {
                let e = *libc::__errno_location();
                let b = e.to_ne_bytes();
                libc::write(fd, b.as_ptr().cast(), 4);
                libc::_exit(127)
            }
            if libc::setpgid(0, 0) < 0 {
                die(err_fd);
            }
            for &(src, target) in &pairs {
                if libc::dup2(src, target) < 0 {
                    die(err_fd);
                }
            }
            let mut dfl: libc::sigaction = std::mem::zeroed();
            dfl.sa_sigaction = libc::SIG_DFL;
            for sig in 1..65 {
                if sig != libc::SIGKILL && sig != libc::SIGSTOP {
                    libc::sigaction(sig, &dfl, std::ptr::null_mut());
                }
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
            libc::execve(c_path.as_ptr(), p_argv.as_ptr(), p_env.as_ptr());
            die(err_fd);
        }
    }
    drop(sources);
    drop(err_w);
    let mut b = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match rustix::io::read(&err_r, &mut b[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => break,
        }
    }
    if got == 4 {
        let _ = wait_pid(pid);
        return Err(fail(std::io::Error::from_raw_os_error(i32::from_ne_bytes(b))));
    }
    Ok(pid)
}

/// What the wait loop saw.
enum Event {
    Done,
    Signal(&'static str),
    Timeout,
}

/// SIGINT, SIGTERM and SIGHUP held back while a sandbox runs and read from a signalfd (Go's signal.Notify); dropping it
/// discards what arrived but was not read (Go's signal.Stop with the channel left unread) and lets them through again.
struct Signals {
    fd: Option<OwnedFd>,
    set: libc::sigset_t,
}

impl Signals {
    fn block() -> Signals {
        // SAFETY: plain signal-set calls on a local set; signalfd returns a new descriptor or -1
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                libc::sigaddset(&mut set, s);
            }
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            let fd = libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
            Signals { fd: (fd >= 0).then(|| OwnedFd::from_raw_fd(fd)), set }
        }
    }

    /// Waits for the child's end (a byte on `done`), a signal, or the timeout.
    fn wait(&self, done: &OwnedFd, timeout: Option<Duration>) -> Event {
        use rustix::event::{poll, PollFd, PollFlags};
        loop {
            let mut fds = vec![PollFd::new(done, PollFlags::IN)];
            if let Some(fd) = &self.fd {
                fds.push(PollFd::new(fd, PollFlags::IN));
            }
            let ts = timeout.map(|t| rustix::event::Timespec { tv_sec: t.as_secs() as i64, tv_nsec: t.subsec_nanos() as i64 });
            match poll(&mut fds, ts.as_ref()) {
                Ok(0) => return Event::Timeout,
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => return Event::Done,
            }
            if !fds[0].revents().is_empty() {
                return Event::Done;
            }
            if let Some(name) = self.read_one() {
                return Event::Signal(name);
            }
        }
    }

    fn read_one(&self) -> Option<&'static str> {
        let fd = self.fd.as_ref()?;
        let mut info = [0u8; std::mem::size_of::<libc::signalfd_siginfo>()];
        match rustix::io::read(fd, &mut info) {
            Ok(n) if n == info.len() => {
                let signo = u32::from_ne_bytes([info[0], info[1], info[2], info[3]]) as i32;
                Some(match signo {
                    libc::SIGINT => "interrupt",
                    libc::SIGTERM => "terminated",
                    _ => "hangup",
                })
            }
            _ => None,
        }
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        while self.read_one().is_some() {}
        self.fd = None;
        // SAFETY: unblocking the set blocked in `block`
        unsafe {
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &self.set, std::ptr::null_mut());
        }
    }
}
