//! internal/usbcap: a passed-through USB device's traffic recorded into a pcap file Wireshark opens (how the
//! conversation between a maker's program in a guest and its device, a vehicle tuner, is learned from outside the guest).
//!
//! It reads Linux's usbmon binary interface (/dev/usbmonN for the device's bus; the text interface keeps only the first
//! 32 bytes of each transfer) and keeps only the events of the named devices: everything else on that bus (a keyboard, a
//! mouse) is read by the kernel interface but never written anywhere. Records are usbmon's own 64-byte header plus the
//! data, which is pcap's LINKTYPE_USB_LINUX_MMAPPED (220). Root only, like the rest of passthrough.

use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

/// pcap's link type for usbmon's 64-byte header followed by the data.
pub const LINK_TYPE: u32 = 220;

/// The size of usbmon's binary header (struct mon_bin_hdr, the MON_IOCX_GETX form).
pub const HEADER_LEN: usize = 64;

/// The data buffer handed to the kernel for each event.
const DATA_LEN: usize = 65536;

/// Where a USB device is on the host.
#[derive(Clone, Debug, PartialEq)]
pub struct Device {
    pub id: String,
    pub bus: i64,
    pub dev: i64,
}

/// Find: where each USB ID is plugged in, from the folder that is /sys/bus/usb/devices. An ID that is not plugged in,
/// or plugged in more than once, is an error.
pub fn find(sys: &str, ids: &[String]) -> Result<Vec<Device>, String> {
    // os.DirFS(sys).ReadDir("."): the entries sorted by name; an error names "."
    let mut names: Vec<String> = std::fs::read_dir(sys)
        .map_err(|e| crate::sys::go_path_error("open", ".", &e))?
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect();
    names.sort();
    let read = |dir: &str, f: &str| -> String {
        std::fs::read(format!("{sys}/{dir}/{f}"))
            .map(|b| crate::gotext::trim_space(&String::from_utf8_lossy(&b)).to_string())
            .unwrap_or_default()
    };
    let mut out = vec![];
    for id in ids {
        let (vendor, product) = id.split_once(':').unwrap_or((id.as_str(), ""));
        let mut found = vec![];
        for n in &names {
            if n.contains(':') || read(n, "idVendor").to_lowercase() != vendor || read(n, "idProduct").to_lowercase() != product {
                continue;
            }
            // strconv.Atoi: an optional sign and decimal digits, as i64's own parser reads them
            if let (Ok(bus), Ok(dev)) = (read(n, "busnum").parse::<i64>(), read(n, "devnum").parse::<i64>()) {
                found.push(Device { id: id.clone(), bus, dev });
            }
        }
        match found.len() {
            0 => return Err(format!("usbcap: {id} is not plugged in")),
            1 => out.push(found.remove(0)),
            k => return Err(format!("usbcap: {k} devices with ID {id} are plugged in")),
        }
    }
    Ok(out)
}

/// pcap's global header for LINK_TYPE records.
pub fn header() -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // microsecond timestamps
    h[4..6].copy_from_slice(&2u16.to_le_bytes()); // version 2.4
    h[6..8].copy_from_slice(&4u16.to_le_bytes());
    h[16..20].copy_from_slice(&((HEADER_LEN + DATA_LEN) as u32).to_le_bytes()); // snapshot length
    h[20..24].copy_from_slice(&LINK_TYPE.to_le_bytes());
    h
}

/// Where the event's device is.
pub fn bus(h: &[u8; HEADER_LEN]) -> i64 {
    u16::from_le_bytes([h[12], h[13]]) as i64
}

pub fn dev(h: &[u8; HEADER_LEN]) -> i64 {
    h[11] as i64
}

/// When usbmon saw the event, as Go's time.Unix(sec, usec*1000) normalises it: (seconds, nanoseconds in 0..1e9).
pub fn time(h: &[u8; HEADER_LEN]) -> (i64, i64) {
    let mut sec = i64::from_le_bytes(h[16..24].try_into().expect("8 bytes"));
    let mut nsec = i32::from_le_bytes(h[24..28].try_into().expect("4 bytes")) as i64 * 1000;
    if !(0..1_000_000_000).contains(&nsec) {
        let n = nsec / 1_000_000_000;
        sec = sec.wrapping_add(n);
        nsec -= n * 1_000_000_000;
        if nsec < 0 {
            nsec += 1_000_000_000;
            sec = sec.wrapping_sub(1);
        }
    }
    (sec, nsec)
}

/// One pcap record: usbmon's header as it is, then the data.
pub fn record(h: &[u8; HEADER_LEN], data: &[u8]) -> Vec<u8> {
    let n = (HEADER_LEN + data.len()) as u32;
    let (sec, nsec) = time(h);
    let mut r = Vec::with_capacity(16 + HEADER_LEN + data.len());
    r.extend_from_slice(&(sec as u32).to_le_bytes());
    r.extend_from_slice(&((nsec / 1000) as u32).to_le_bytes());
    r.extend_from_slice(&n.to_le_bytes());
    r.extend_from_slice(&n.to_le_bytes());
    r.extend_from_slice(h);
    r.extend_from_slice(data);
    r
}

/// Keep: whether an event belongs to one of the devices.
pub fn keep(h: &[u8; HEADER_LEN], devs: &[Device]) -> bool {
    devs.iter().any(|d| bus(h) == d.bus && dev(h) == d.dev)
}

/// struct mon_bin_get: where MON_IOCX_GETX puts the next event's header and data.
#[repr(C)]
struct MonBinGet {
    hdr: *mut u8,
    data: *mut u8,
    alloc: usize,
}

/// MON_IOCX_GETX = _IOW(0x92, 10, struct mon_bin_get): the next event, with the 64-byte header.
const MON_IOCX_GETX: u32 = 0x4000_0000 | ((std::mem::size_of::<MonBinGet>() as u32) << 16) | (0x92 << 8) | 10;

/// Why recording stops early: the deadline or a signal (Go's context).
pub trait Stop {
    /// Waits up to `d` (or not at all) and says whether recording must stop.
    fn wait(&mut self, d: Duration) -> bool;
}

/// A file write error as Go's *os.File writes it.
pub type WriteErr = String;

/// Capture: the devices' events (all on one bus) into `w` as pcap until `stop` says so; how many it kept. usbmon must be
/// loaded (/dev/usbmonN exists).
pub fn capture(devs: &[Device], w: &mut dyn FnMut(&[u8]) -> Result<(), WriteErr>, stop: &mut dyn Stop) -> (usize, Result<(), String>) {
    let Some(first) = devs.first() else { return (0, Err("usbcap: no devices".into())) };
    let b = first.bus;
    for d in devs {
        if d.bus != b {
            return (0, Err(format!("usbcap: the devices are on different buses ({b} and {}); record one at a time", d.bus)));
        }
    }
    // non-blocking: with no event waiting, the read says so at once, and the loop checks the stop between tries
    let path = format!("/dev/usbmon{b}");
    let fd: OwnedFd = match rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) => {
            return (0, Err(format!("usbcap: {path}: {} (is the usbmon module loaded? modprobe usbmon)", crate::sys::go_err(&e.into()))));
        }
    };
    if let Err(e) = w(&header()) {
        return (0, Err(e));
    }
    let mut data = vec![0u8; DATA_LEN];
    let mut kept = 0;
    while !stop.wait(Duration::ZERO) {
        let mut h = [0u8; HEADER_LEN];
        let mut arg = MonBinGet { hdr: h.as_mut_ptr(), data: data.as_mut_ptr(), alloc: data.len() };
        // SAFETY: MON_IOCX_GETX writes at most HEADER_LEN bytes at hdr and at most alloc bytes at data, both owned here
        // and alive for the call
        let r = unsafe { libc::ioctl(fd.as_raw_fd(), MON_IOCX_GETX as _, &mut arg as *mut MonBinGet) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => {
                    if stop.wait(Duration::from_millis(5)) {
                        break;
                    }
                    continue;
                }
                _ => return (kept, Err(format!("usbcap: reading usbmon: {}", crate::sys::go_err(&e)))),
            }
        }
        if !keep(&h, devs) {
            continue; // another device on the bus: never written
        }
        let cap_len = (u32::from_le_bytes([h[36], h[37], h[38], h[39]]) as usize).min(data.len());
        if let Err(e) = w(&record(&h, &data[..cap_len])) {
            return (kept, Err(e));
        }
        kept += 1;
    }
    (kept, Ok(()))
}

/// The deadline and SIGINT/SIGTERM through a signalfd (Go's signal.NotifyContext with a timeout).
pub struct Deadline {
    pub until: Instant,
    pub signals: Option<OwnedFd>,
}

impl Stop for Deadline {
    fn wait(&mut self, d: Duration) -> bool {
        use rustix::event::{poll, PollFd, PollFlags};
        let now = Instant::now();
        if now >= self.until {
            return true;
        }
        let d = d.min(self.until - now);
        match &self.signals {
            Some(s) => {
                let mut fds = [PollFd::new(s, PollFlags::IN)];
                let ts = rustix::event::Timespec { tv_sec: d.as_secs() as i64, tv_nsec: d.subsec_nanos() as i64 };
                let _ = poll(&mut fds, Some(&ts));
                if !fds[0].revents().is_empty() {
                    return true;
                }
            }
            None => std::thread::sleep(d),
        }
        Instant::now() >= self.until
    }
}

/// bufio.Writer over the output file (4,096 bytes; the first error is kept and returned by every later write).
pub struct GoBuf<W: Write> {
    w: W,
    buf: Vec<u8>,
    err: Option<String>,
    path: String,
}

impl<W: Write> GoBuf<W> {
    pub fn new(w: W, path: &str) -> GoBuf<W> {
        GoBuf { w, buf: Vec::with_capacity(4096), err: None, path: path.to_string() }
    }

    fn flush_buf(&mut self) -> Result<(), String> {
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        if self.buf.is_empty() {
            return Ok(());
        }
        let r = self.w.write_all(&self.buf);
        self.buf.clear();
        if let Err(e) = r {
            let m = crate::sys::go_path_error("write", &self.path, &e);
            self.err = Some(m.clone());
            return Err(m);
        }
        Ok(())
    }

    pub fn write(&mut self, mut p: &[u8]) -> Result<(), String> {
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        while p.len() > 4096 - self.buf.len() {
            if self.buf.is_empty() {
                // a large write with nothing buffered goes straight to the file
                if let Err(e) = self.w.write_all(p) {
                    let m = crate::sys::go_path_error("write", &self.path, &e);
                    self.err = Some(m.clone());
                    return Err(m);
                }
                return Ok(());
            }
            let n = 4096 - self.buf.len();
            self.buf.extend_from_slice(&p[..n]);
            p = &p[n..];
            self.flush_buf()?;
        }
        self.buf.extend_from_slice(p);
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), String> {
        self.flush_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_number_is_the_kernels() {
        assert_eq!(MON_IOCX_GETX, 0x4018_920a);
    }

    #[test]
    fn times_normalise_as_go() {
        let mut h = [0u8; HEADER_LEN];
        h[16..24].copy_from_slice(&5i64.to_le_bytes());
        h[24..28].copy_from_slice(&(-1i32).to_le_bytes());
        assert_eq!(time(&h), (4, 999_999_000));
        h[24..28].copy_from_slice(&2_500_000i32.to_le_bytes());
        assert_eq!(time(&h), (7, 500_000_000));
    }
}
