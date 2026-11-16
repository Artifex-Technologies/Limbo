//! `limbo net watch [--seconds N]` (cmd/limbo/net_cmd.go): guests' flows and refusals as they happen, as JSON lines in
//! the form the audit log uses (root; only while limbo serve is not reading them itself: one reader per kernel log
//! group). Same output, errors and exit status as Go; rust/parity/cli-differential.py compares the two binaries on
//! real NFLOG packets from nft rules in a user and network namespace of their own.

use super::commands::{Fail, Io};
use super::flags::{self, FlagSet};
use crate::events::Emitter;
use crate::flows::{self, Aggregator};
use crate::gojson::Obj;
use crate::gotime::Time;
use crate::{sys, Detail};
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const USAGE: &str = "usage: limbo net watch [--seconds N]   (root; limbo serve normally reads these into its log)";

/// The aggregator's events, kept until the loop writes them out (Go's json.Encoder on stdout, one line each).
#[derive(Default)]
struct Lines(Mutex<Vec<String>>);

impl Emitter for Lines {
    fn emit(&self, kind: &str, guest: &str, detail: Detail) -> std::io::Result<()> {
        // map[string]any{"time", "kind", "guest", "detail"} as Go marshals it: keys sorted
        let line =
            Obj::new().map("detail", &detail).str("guest", guest).str("kind", kind).str("time", &Time::now().utc().rfc3339_nano()).end();
        self.0.lock().unwrap_or_else(|e| e.into_inner()).push(line);
        Ok(())
    }
}

/// SIGINT and SIGTERM read from a signalfd (Go's signal.NotifyContext).
fn block_signals() -> Option<OwnedFd> {
    // SAFETY: plain signal-set calls on a local set; signalfd returns a new descriptor or -1
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        let fd = libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        (fd >= 0).then(|| OwnedFd::from_raw_fd(fd))
    }
}

pub fn run(args: &[String], io: &mut Io) -> Result<(), Fail> {
    let mut fs = FlagSet::new("net");
    fs.int("seconds", 0, "stop after this many seconds (0: until interrupted)");
    let mut stderr = vec![];
    let r = flags::parse_interspersed(&mut fs, args.to_vec(), &mut stderr);
    let _ = io.err.write_all(&stderr);
    let pos = r.map_err(Fail::Msg)?;
    if pos.len() != 1 || pos[0] != "watch" {
        return Err(USAGE.into());
    }
    let sig = block_signals();
    // context.WithTimeout(time.Duration(secs) * time.Second): the product wraps as Go's does; not positive is over already
    let secs = fs.num("seconds");
    let deadline = (secs > 0).then(|| {
        let d = secs.wrapping_mul(1_000_000_000);
        Instant::now() + Duration::from_nanos(d.max(0) as u64)
    });
    let lines = Arc::new(Lines::default());
    let mut agg = Aggregator::new(Some(lines.clone() as Arc<dyn Emitter>), Time::now);
    let fd = flows::listen(crate::policy::NFLOG_GROUP)
        .map_err(|e| format!("{e} (limbo serve may be reading them already: see its log, events.jsonl)"))?;
    let mut buf = vec![0u8; 1 << 16];
    use rustix::event::{poll, PollFd, PollFlags};
    loop {
        let left = match deadline {
            Some(d) => match d.checked_duration_since(Instant::now()) {
                Some(l) if !l.is_zero() => Some(l),
                _ => return Ok(()),
            },
            None => None,
        };
        let mut fds = vec![PollFd::new(&fd, PollFlags::IN)];
        if let Some(s) = &sig {
            fds.push(PollFd::new(s, PollFlags::IN));
        }
        let ts = left.map(|t| rustix::event::Timespec { tv_sec: t.as_secs() as i64, tv_nsec: t.subsec_nanos() as i64 });
        match poll(&mut fds, ts.as_ref()) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(Fail::Msg(format!("flows: reading NFLOG: {}", sys::go_err(&e.into())))),
        }
        if fds.get(1).is_some_and(|f| !f.revents().is_empty()) {
            return Ok(()); // interrupted: Go's Listen sees its context end and returns nil
        }
        if fds[0].revents().is_empty() {
            continue;
        }
        loop {
            let n = match rustix::io::read(&fd, &mut buf[..]) {
                Ok(n) => n,
                Err(rustix::io::Errno::AGAIN) => break,
                // ENOBUFS: the kernel dropped copies we were too slow for
                Err(rustix::io::Errno::INTR) | Err(rustix::io::Errno::NOBUFS) => continue,
                Err(e) => return Err(Fail::Msg(format!("flows: reading NFLOG: {}", sys::go_err(&e.into())))),
            };
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(());
            }
            for (prefix, payload) in flows::parse_messages(&buf[..n]) {
                if let Some(p) = flows::decode(&prefix, &payload) {
                    agg.handle(&p);
                }
            }
            for l in std::mem::take(&mut *lines.0.lock().unwrap_or_else(|e| e.into_inner())) {
                let _ = writeln!(io.out, "{l}");
            }
            let _ = io.out.flush();
        }
    }
}
