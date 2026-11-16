//! `limbo capture [--seconds N] <manifest> <out.pcap>` (cmd/limbo/main.go `capture`): the guest's passed-through USB
//! devices' traffic (package usbcap) into a pcap file Wireshark opens, for the given seconds or until Ctrl+C. Only those
//! devices' events are written; anything else on their bus is not. Same output, errors, file and exit status as Go;
//! rust/parity/cli-differential.py compares the two binaries over made-up sysfs folders and a usbmon stand-in that
//! answers the ioctl (rust/limbo/examples/usbmon_fake.rs), never a device of this computer.

use super::commands::{Fail, Io};
use crate::manifest::Manifest;
use crate::usbcap::{self, Deadline};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

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

pub fn capture(m: &Manifest, out: &str, seconds: i64, io: &mut Io) -> Result<(), Fail> {
    let usb = m.devices.usb.clone().unwrap_or_default();
    if usb.is_empty() {
        return Err(Fail::Msg(format!("capture: {}'s manifest names no USB device", m.name)));
    }
    if !out.starts_with('/') {
        return Err("capture: the output file needs an absolute path".into());
    }
    if !(1..=3600).contains(&seconds) {
        return Err("capture: --seconds must be 1 to 3600".into());
    }
    let devs = usbcap::find("/sys/bus/usb/devices", &usb)?;
    if std::fs::metadata(format!("/dev/usbmon{}", devs[0].bus)).is_err() {
        let _ = super::goexec::run("modprobe", &["usbmon".to_string()]);
    }
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(out)
        .map_err(|e| crate::sys::go_path_error("open", out, &e))?;
    super::act::give_to_sudo_user(io, out);
    let mut stop = Deadline { until: Instant::now() + Duration::from_secs(seconds as u64), signals: block_signals() };
    for d in &devs {
        let _ = writeln!(io.err, "recording {} (bus {}, device {}) for {seconds} s (Ctrl+C stops)...", d.id, d.bus, d.dev);
    }
    let mut w = usbcap::GoBuf::new(f, out);
    let (n, r) = usbcap::capture(&devs, &mut |b: &[u8]| w.write(b), &mut stop);
    let fr = w.flush();
    let r = r.and(fr);
    let _ = writeln!(io.out, "{n} events written to {out}");
    r.map_err(Fail::Msg)
}
