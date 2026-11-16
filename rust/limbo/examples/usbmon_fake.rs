//! A stand-in for the kernel's usbmon, for rust/parity/cli-differential.py only (never shipped: the package builds
//! the limbo-rs binary alone). `limbo capture` reads usbmon with one ioctl, MON_IOCX_GETX, which no file a test can make
//! answers. This program starts the command under a seccomp filter that hands exactly that ioctl to it (a user
//! notification) and answers it from a script: an event (header and data written into the caller's buffers), an errno,
//! or a signal sent to the command. Every other system call, and every other ioctl, goes to the kernel as usual. The same
//! script answers the Go and the Rust limbo, so the pcap files they write can be compared byte for byte.
//!
//!     usbmon_fake SCRIPT LOG -- PROGRAM [ARGS...]
//!
//! SCRIPT has one item per line: `event HEADER_HEX DATA_HEX` (DATA_HEX may be `-` for none), `errno N`, `signal N`.
//! After the last item every call is answered EAGAIN (no event waiting). LOG gets a line per item served, with the
//! buffer size the caller offered. Exits with the command's status (128 + N for a signal).

use std::io::Write;

const MON_IOCX_GETX: u32 = 0x4018_920a;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const NOTIF_RECV: libc::c_ulong = 0xc050_2100;
const NOTIF_SEND: libc::c_ulong = 0xc018_2101;
const NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

#[repr(C)]
#[derive(Default)]
struct Notif {
    id: u64,
    pid: u32,
    flags: u32,
    nr: i32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
}

#[repr(C)]
struct Resp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

enum Item {
    Event(Vec<u8>, Vec<u8>),
    Errno(i32),
    Signal(i32),
}

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return vec![];
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
}

fn script(path: &str) -> Vec<Item> {
    std::fs::read_to_string(path)
        .expect("script")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            match f[0] {
                "event" => {
                    let h = hex(f[1]);
                    assert_eq!(h.len(), 64, "a header is 64 bytes");
                    Item::Event(h, hex(f.get(2).copied().unwrap_or("-")))
                }
                "errno" => Item::Errno(f[1].parse().expect("errno")),
                "signal" => Item::Signal(f[1].parse().expect("signal")),
                o => panic!("unknown item {o}"),
            }
        })
        .collect()
}

fn filter() -> Vec<libc::sock_filter> {
    let st = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter { code: 0x15, jt, jf, k };
    vec![
        st(0x20, 4), // ld arch
        jeq(AUDIT_ARCH, 0, 4),
        st(0x20, 0), // ld nr
        jeq(libc::SYS_ioctl as u32, 0, 2),
        st(0x20, 24), // ld the low half of args[1], the request
        jeq(MON_IOCX_GETX, 1, 0),
        st(0x06, SECCOMP_RET_ALLOW),
        st(0x06, SECCOMP_RET_USER_NOTIF),
    ]
}

fn mem(pid: u32, addr: u64, buf: &mut [u8], write: bool) -> bool {
    let local = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    let remote = libc::iovec { iov_base: addr as *mut libc::c_void, iov_len: buf.len() };
    // SAFETY: one local buffer owned here, one remote range in the traced command; the kernel checks the remote side
    let n = unsafe {
        if write {
            libc::process_vm_writev(pid as i32, &local, 1, &remote, 1, 0)
        } else {
            libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0)
        }
    };
    n == buf.len() as isize
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 || a[3] != "--" {
        eprintln!("usage: usbmon_fake SCRIPT LOG -- PROGRAM [ARGS...]");
        std::process::exit(2);
    }
    let items = script(&a[1]);
    let mut log = std::fs::OpenOptions::new().create(true).append(true).open(&a[2]).expect("log");
    let argv: Vec<std::ffi::CString> = a[4..].iter().map(|s| std::ffi::CString::new(s.as_str()).expect("arg")).collect();
    let mut argp: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argp.push(std::ptr::null());
    let prog = filter();
    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_ptr() as *mut _ };
    let (mut up, mut down) = ([0i32; 2], [0i32; 2]);
    // SAFETY: two pipes; fork in a single-threaded program; the child makes only async-signal-safe calls on memory
    // prepared above, then execs
    let child = unsafe {
        assert_eq!(libc::pipe2(up.as_mut_ptr(), libc::O_CLOEXEC), 0);
        assert_eq!(libc::pipe2(down.as_mut_ptr(), libc::O_CLOEXEC), 0);
        let pid = libc::fork();
        if pid == 0 {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                libc::_exit(126);
            }
            let l = libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog) as i32;
            if l < 0 {
                libc::_exit(126);
            }
            let b = l.to_ne_bytes();
            libc::write(up[1], b.as_ptr().cast(), 4);
            let mut go = [0u8; 1];
            libc::read(down[0], go.as_mut_ptr().cast(), 1);
            libc::close(l);
            libc::execvp(argp[0], argp.as_ptr());
            libc::_exit(127);
        }
        pid
    };
    assert!(child > 0, "fork");
    // SAFETY: plain system calls on descriptors owned here
    let (listener, pidfd) = unsafe {
        let mut b = [0u8; 4];
        assert_eq!(libc::read(up[0], b.as_mut_ptr().cast(), 4), 4, "the child installed no filter");
        let pidfd = libc::syscall(libc::SYS_pidfd_open, child, 0) as i32;
        assert!(pidfd >= 0, "pidfd_open");
        let l = libc::syscall(libc::SYS_pidfd_getfd, pidfd, i32::from_ne_bytes(b), 0) as i32;
        assert!(l >= 0, "pidfd_getfd: {}", std::io::Error::last_os_error());
        libc::write(down[1], [1u8].as_ptr().cast(), 1);
        (l, pidfd)
    };
    let mut next = 0usize;
    let mut served = 0usize;
    loop {
        let mut fds =
            [libc::pollfd { fd: listener, events: libc::POLLIN, revents: 0 }, libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 }];
        // SAFETY: two descriptors owned here
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            continue;
        }
        if fds[1].revents != 0 {
            break;
        }
        if fds[0].revents & libc::POLLIN == 0 {
            if fds[0].revents != 0 {
                // the command's every thread is gone: wait for its end
                // SAFETY: a pidfd owned here
                unsafe {
                    let mut p = [libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 }];
                    libc::poll(p.as_mut_ptr(), 1, -1);
                }
                break;
            }
            continue;
        }
        let mut n = Notif::default();
        // SAFETY: the kernel fills a zeroed seccomp_notif
        if unsafe { libc::ioctl(listener, NOTIF_RECV, &mut n as *mut Notif) } < 0 {
            continue;
        }
        let mut resp = Resp { id: n.id, val: 0, error: -libc::EAGAIN, flags: 0 };
        let mut get = [0u8; 24];
        let mut line = None;
        if mem(n.pid, n.args[2], &mut get, false) {
            let hdr = u64::from_ne_bytes(get[0..8].try_into().expect("8"));
            let data = u64::from_ne_bytes(get[8..16].try_into().expect("8"));
            let alloc = u64::from_ne_bytes(get[16..24].try_into().expect("8"));
            match items.get(next) {
                None => {}
                Some(Item::Errno(e)) => {
                    resp.error = -e;
                    line = Some(format!("errno {e} (buffer {alloc})"));
                }
                Some(Item::Signal(s)) => {
                    // SAFETY: a signal to the command started here
                    unsafe { libc::kill(child, *s) };
                    line = Some(format!("signal {s} (buffer {alloc})"));
                }
                Some(Item::Event(h, d)) => {
                    let mut h = h.clone();
                    let mut d = d[..d.len().min(alloc as usize)].to_vec();
                    let mut id = n.id;
                    // SAFETY: NOTIF_ID_VALID reads the id
                    let valid = unsafe { libc::ioctl(listener, NOTIF_ID_VALID, &mut id as *mut u64) } == 0;
                    if valid && mem(n.pid, hdr, &mut h, true) && (d.is_empty() || mem(n.pid, data, &mut d, true)) {
                        resp.error = 0;
                        served += 1;
                        line = Some(format!("event {served} (buffer {alloc}, {} bytes of data written)", d.len()));
                    }
                }
            }
        }
        // SAFETY: the answer to the notification received above
        let sent = unsafe { libc::ioctl(listener, NOTIF_SEND, &mut resp as *mut Resp) } == 0;
        // a signal was sent whether or not the answer arrived (it may interrupt the very call it answers)
        if sent || matches!(items.get(next), Some(Item::Signal(_))) {
            if let Some(l) = line {
                let _ = writeln!(log, "{l}");
                next += 1;
            }
        }
    }
    let mut st = 0;
    // SAFETY: the child started here
    unsafe { libc::waitpid(child, &mut st, 0) };
    if libc::WIFSIGNALED(st) {
        std::process::exit(128 + libc::WTERMSIG(st));
    }
    std::process::exit(libc::WEXITSTATUS(st));
}
