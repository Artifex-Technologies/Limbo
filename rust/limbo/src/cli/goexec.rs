//! os/exec as the Go CLI uses it: `exec.LookPath`, and `exec.Command(name, args...)` run with `CombinedOutput`,
//! `Output` or `Run`, with Go's error texts (`exec: "x": executable file not found in $PATH`, `fork/exec /p: ...`,
//! `exit status 1`, `signal: killed`). The child gets /dev/null for what Go leaves nil, and the CLI's environment.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

/// findExecutable: a file (not a folder) the caller may execute (eaccess, as Go asks it).
fn find_executable(p: &str) -> Result<(), String> {
    let m = std::fs::metadata(p).map_err(|e| crate::sys::go_path_error("stat", p, &e))?;
    if m.is_dir() {
        return Err("is a directory".into());
    }
    rustix::fs::accessat(rustix::fs::CWD, p, rustix::fs::Access::EXEC_OK, rustix::fs::AtFlags::EACCESS)
        .map_err(|e| crate::sys::go_err(&std::io::Error::from(e)))
}

/// exec.LookPath(file): the path to run, or Go's `exec: "file": ...` error.
pub fn look_path(file: &str) -> Result<String, String> {
    let fail = |why: &str| format!("exec: {}: {why}", crate::gotext::quote(file));
    if file.contains('/') {
        return find_executable(file).map(|_| file.to_string()).map_err(|e| fail(&e));
    }
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let p = crate::sys::join(&[dir, file]);
        if find_executable(&p).is_ok() {
            if !p.starts_with('/') {
                return Err(fail("cannot run executable found relative to current directory"));
            }
            return Ok(p);
        }
    }
    Err(fail("executable file not found in $PATH"))
}

fn command(name: &str, args: &[String]) -> Result<(Command, String), String> {
    let path = look_path(name)?;
    let mut c = Command::new(&path);
    c.arg0(name).args(args).stdin(Stdio::null());
    Ok((c, path))
}

fn wait_text(st: std::process::ExitStatus) -> Result<(), String> {
    if st.success() {
        Ok(())
    } else {
        Err(crate::engine::status_text(&st))
    }
}

fn start_err(path: &str, e: &std::io::Error) -> String {
    format!("fork/exec {path}: {}", crate::sys::go_err(e))
}

/// `exec.Command(name, args...).CombinedOutput()`: stdout and stderr in one pipe, in the order written.
pub fn combined_output(name: &str, args: &[String]) -> (Vec<u8>, Result<(), String>) {
    let (mut c, path) = match command(name, args) {
        Ok(x) => x,
        Err(e) => return (vec![], Err(e)),
    };
    let mut fds = [0i32; 2];
    // SAFETY: pipe2 fills the two descriptors, which are then owned here and nowhere else
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return (vec![], Err(crate::sys::go_err(&std::io::Error::last_os_error())));
    }
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: as above
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let w2 = match w.try_clone() {
        Ok(w2) => w2,
        Err(e) => return (vec![], Err(crate::sys::go_err(&e))),
    };
    c.stdout(Stdio::from(w)).stderr(Stdio::from(w2));
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => return (vec![], Err(start_err(&path, &e))),
    };
    drop(c); // the parent's copies of the write end, so the read ends when the child's do
    let mut out = vec![];
    let _ = std::fs::File::from(r).read_to_end(&mut out);
    let st = child.wait();
    (out, st.map_err(|e| crate::sys::go_err(&e)).and_then(wait_text))
}

/// `exec.Command(name, args...).Output()`: stdout only (stderr is kept by Go for the error value, never shown).
pub fn output(name: &str, args: &[String]) -> (Vec<u8>, Result<(), String>) {
    let (mut c, path) = match command(name, args) {
        Ok(x) => x,
        Err(e) => return (vec![], Err(e)),
    };
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    match c.output() {
        Ok(o) => (o.stdout, wait_text(o.status)),
        Err(e) => (vec![], Err(start_err(&path, &e))),
    }
}

/// `exec.Command(name, args...).Run()` with no stdio: /dev/null for all three.
pub fn run(name: &str, args: &[String]) -> Result<(), String> {
    let (mut c, path) = command(name, args)?;
    c.stdout(Stdio::null()).stderr(Stdio::null());
    match c.status() {
        Ok(st) => wait_text(st),
        Err(e) => Err(start_err(&path, &e)),
    }
}

/// `exec.Command(name, args...)` with this process's stdin, stdout and stderr, `Run()`.
pub fn run_inherit(name: &str, args: &[String]) -> Result<(), String> {
    let path = look_path(name)?;
    match Command::new(&path).arg0(name).args(args).status() {
        Ok(st) => wait_text(st),
        Err(e) => Err(start_err(&path, &e)),
    }
}
