//! The sinkhole's responder: `limbo sinkhole-responder --addr 10.213.X.1`, started by `limbo serve` for one guest in
//! network mode `sinkhole`, as the unprivileged account limbo-sinkhole (docs/SINKHOLE.md).
//!
//! It is bound only to the guest's gateway address, on three ports the guest's table redirects everything to: DNS
//! (every A question is answered with the gateway address), TCP (every connection is accepted, its first bytes read and
//! logged; an HTTP request gets an empty 200, a TLS ClientHello has its server name read, then the connection is closed)
//! and UDP (each datagram's first bytes and the port it was sent to). It writes one JSON line per record on stdout for
//! the daemon, which checks, bounds and writes them as events; it reads nothing but the guest's packets and opens no
//! file. Everything a guest sends is hostile: it is parsed by the small functions below, bounded, and written out
//! escaped (printable ASCII only). Threads, no async runtime; at most MAX_CONNS connections at once.

use crate::gojson::Obj;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Bytes of a connection or datagram kept for the log.
pub const FIRST_BYTES: usize = 512;
/// Bytes read from a connection at most (a TLS ClientHello with its server name can be well over 512).
const READ_CAP: usize = 4096;
/// A connection's whole budget, and how long it may stay silent between reads.
const CONN_BUDGET: Duration = Duration::from_secs(5);
const IDLE: Duration = Duration::from_millis(1500);
const MAX_CONNS: usize = 32;
/// The TTL of the sinkhole's answers: short, so a later run with another sinkhole is not answered from a cache.
const TTL: u32 = 30;

const SO_MARK: libc::c_int = 36;
const SO_RCVMARK: libc::c_int = 75;
const SO_ORIGINAL_DST: libc::c_int = 80;

/// Bytes as printable ASCII: 0x20-0x7e as they are (the backslash doubled), everything else as `\xNN`.
pub fn escape(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len());
    for &c in b {
        match c {
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(c as char),
            _ => s.push_str(&format!("\\x{c:02x}")),
        }
    }
    s
}

fn be16(b: &[u8], i: usize) -> Option<usize> {
    Some(((*b.get(i)? as usize) << 8) | *b.get(i + 1)? as usize)
}

/// A DNS question: its name (escaped, labels joined by dots; a dot inside a label is `\x2e`), type and class, and where
/// the question section ends.
#[derive(Clone, Debug, PartialEq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    end: usize,
}

/// The first question of a standard query, or None (a reply, another opcode, no question, a compressed or overlong name).
pub fn parse_query(q: &[u8]) -> Option<Question> {
    if q.len() < 12 || q[2] & 0x80 != 0 || (q[2] >> 3) & 0x0f != 0 || be16(q, 4)? == 0 {
        return None;
    }
    let mut i = 12;
    let mut labels: Vec<String> = vec![];
    let mut total = 0;
    loop {
        let n = *q.get(i)? as usize;
        i += 1;
        if n == 0 {
            break;
        }
        if n > 63 {
            return None;
        }
        total += n + 1;
        if total > 255 {
            return None;
        }
        let label = q.get(i..i + n)?;
        labels.push(escape(label).replace('.', "\\x2e"));
        i += n;
    }
    let qtype = be16(q, i)? as u16;
    let qclass = be16(q, i + 2)? as u16;
    let name = if labels.is_empty() { ".".to_string() } else { labels.join(".") };
    Some(Question { name, qtype, qclass, end: i + 4 })
}

/// The DNS type's usual name, or `TYPEn`.
pub fn type_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        n => format!("TYPE{n}"),
    }
}

/// The sinkhole's answer to a query: an A (or ANY) question in class IN gets `addr`; every other question an empty
/// answer (no error, no data), which an AAAA one gets too: the guest has no IPv6, so a resolver falls back to A at once.
/// Returns the reply, the question, and the address answered ("" for none).
pub fn dns_reply(q: &[u8], addr: Ipv4Addr) -> Option<(Vec<u8>, Question, String)> {
    let qs = parse_query(q)?;
    let answer = (qs.qtype == 1 || qs.qtype == 255) && qs.qclass == 1;
    let mut r = Vec::with_capacity(qs.end + 16);
    r.extend_from_slice(&q[0..2]);
    // QR, the query's opcode (0) and RD, AA; RA; no error
    r.push(0x84 | (q[2] & 0x01));
    r.push(0x80);
    r.extend_from_slice(&[0, 1, 0, u8::from(answer), 0, 0, 0, 0]);
    r.extend_from_slice(&q[12..qs.end]);
    let mut shown = String::new();
    if answer {
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        r.extend_from_slice(&TTL.to_be_bytes());
        r.extend_from_slice(&[0, 4]);
        r.extend_from_slice(&addr.octets());
        shown = addr.to_string();
    }
    Some((r, qs, shown))
}

/// The server name of a TLS ClientHello (as far as the bytes read go), escaped and at most 255 bytes long.
pub fn client_hello_sni(b: &[u8]) -> Option<String> {
    if *b.first()? != 0x16 || *b.get(1)? != 3 {
        return None;
    }
    let rec_end = (5 + be16(b, 3)?).min(b.len());
    let body = b.get(5..rec_end)?;
    if *body.first()? != 1 {
        return None;
    }
    // handshake header (4), version (2), random (32)
    let mut i = 4 + 2 + 32;
    i += 1 + *body.get(i)? as usize;
    i += 2 + be16(body, i)?;
    i += 1 + *body.get(i)? as usize;
    let ext_end = (i + 2 + be16(body, i)?).min(body.len());
    i += 2;
    while i + 4 <= ext_end {
        let (typ, len) = (be16(body, i)?, be16(body, i + 2)?);
        i += 4;
        if typ == 0 {
            // server_name: list length, then (type 0 = host name, length, name)
            let list = body.get(i..(i + len).min(ext_end))?;
            if *list.get(2)? != 0 {
                return None;
            }
            let n = be16(list, 3)?;
            let name = list.get(5..5 + n)?;
            return Some(escape(&name[..name.len().min(255)]));
        }
        i += len;
    }
    None
}

/// An HTTP request: its first line and Host header, escaped (at most 200 bytes each), when the bytes start with one.
pub fn http_request(b: &[u8]) -> Option<(String, String)> {
    let sp = b.iter().take(9).position(|&c| c == b' ')?;
    if sp < 3 || !b[..sp].iter().all(|c| c.is_ascii_uppercase()) {
        return None;
    }
    let line_end = b.windows(2).position(|w| w == b"\r\n").unwrap_or(b.len());
    let line = &b[..line_end.min(200)];
    let mut host = String::new();
    let head_end = b.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(b.len());
    for h in b[..head_end].split(|&c| c == b'\n').skip(1) {
        let h = h.strip_suffix(b"\r").unwrap_or(h);
        if h.len() > 5 && h[..5].eq_ignore_ascii_case(b"host:") {
            let v = h[5..].trim_ascii();
            host = escape(&v[..v.len().min(200)]);
            break;
        }
    }
    Some((escape(line), host))
}

/// Whether what a connection sent so far is a whole message the responder can act on.
fn complete(b: &[u8], port: u16) -> bool {
    if port == 53 {
        return be16(b, 0).is_some_and(|n| b.len() >= 2 + n);
    }
    if b.first() == Some(&0x16) && b.get(1) == Some(&3) {
        return be16(b, 3).is_some_and(|n| b.len() >= 5 + n);
    }
    http_request(b).is_some() && b.windows(4).any(|w| w == b"\r\n\r\n")
}

/// The records' way out: one JSON line each on stdout. When the daemon is gone there is nobody to tell: the responder
/// ends.
struct Out(Mutex<std::io::Stdout>);

impl Out {
    fn emit(&self, o: Obj) {
        let mut line = o.end();
        line.push('\n');
        let mut w = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if w.write_all(line.as_bytes()).and_then(|_| w.flush()).is_err() {
            std::process::exit(0);
        }
    }
}

/// The connection's destination before the guest's table redirected it.
fn original_dst(s: &TcpStream) -> Option<(Ipv4Addr, u16)> {
    // SAFETY: getsockopt fills a sockaddr_in we own, at most its size
    unsafe {
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let r = libc::getsockopt(s.as_raw_fd(), libc::SOL_IP, SO_ORIGINAL_DST, &mut sa as *mut _ as *mut libc::c_void, &mut len);
        if r != 0 || sa.sin_family as libc::c_int != libc::AF_INET {
            return None;
        }
        Some((Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)), u16::from_be(sa.sin_port)))
    }
}

/// One datagram, its real length (MSG_TRUNC) and the packet mark the guest's table set to its destination port.
fn recv_marked(sock: &UdpSocket, buf: &mut [u8]) -> std::io::Result<(usize, Option<u32>)> {
    // SAFETY: recvmsg writes into buf and the control buffer, both ours and of the sizes given; the control messages are
    // walked with the CMSG macros over that buffer only
    unsafe {
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
        let mut cbuf = [0u64; 16];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_TRUNC);
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut mark = None;
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == SO_MARK {
                let mut v = [0u8; 4];
                std::ptr::copy_nonoverlapping(libc::CMSG_DATA(c), v.as_mut_ptr(), 4);
                mark = Some(u32::from_ne_bytes(v));
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
        Ok((n as usize, mark))
    }
}

fn dns_record(proto: &str, qs: &Question, answer: &str) -> Obj {
    Obj::new().str("kind", "dns").str("proto", proto).str("name", &qs.name).str("type", &type_name(qs.qtype)).str("answer", answer)
}

fn udp_record(port: Option<u16>, n: usize, b: &[u8]) -> Obj {
    Obj::new()
        .str("kind", "udp")
        .str("dport", &port.map(|p| p.to_string()).unwrap_or_default())
        .str("bytes", &n.to_string())
        .str("first", &escape(&b[..b.len().min(FIRST_BYTES)]))
}

fn serve_dns(sock: UdpSocket, gw: Ipv4Addr, out: Arc<Out>) {
    let mut buf = [0u8; 1500];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        let q = &buf[..n];
        match dns_reply(q, gw) {
            Some((r, qs, answer)) => {
                let _ = sock.send_to(&r, from);
                out.emit(dns_record("udp", &qs, &answer));
            }
            None => out.emit(udp_record(Some(53), n, q)),
        }
    }
}

fn serve_udp(sock: UdpSocket, out: Arc<Out>) {
    let mut buf = [0u8; FIRST_BYTES];
    loop {
        let Ok((n, mark)) = recv_marked(&sock, &mut buf) else { continue };
        let port = mark.filter(|m| (1..=65535).contains(m)).map(|m| m as u16);
        out.emit(udp_record(port, n, &buf[..n.min(buf.len())]));
    }
}

fn ms(d: Duration) -> String {
    d.as_millis().to_string()
}

fn serve_conn(mut s: TcpStream, gw: Ipv4Addr, out: &Out) {
    let t0 = Instant::now();
    let (dst, port) = original_dst(&s).map_or((String::new(), 0), |(a, p)| (a.to_string(), p));
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    let mut b: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let mut first: Option<Duration> = None;
    while b.len() < READ_CAP {
        let left = CONN_BUDGET.saturating_sub(t0.elapsed());
        if left.is_zero() {
            break;
        }
        let _ = s.set_read_timeout(Some(left.min(IDLE)));
        let room = (READ_CAP - b.len()).min(chunk.len());
        match s.read(&mut chunk[..room]) {
            Ok(0) => break,
            Ok(n) => {
                first.get_or_insert(t0.elapsed());
                b.extend_from_slice(&chunk[..n]);
                if complete(&b, port) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    if port == 53 {
        if let Some(n) = be16(&b, 0) {
            if let Some((r, qs, answer)) = b.get(2..2 + n).and_then(|q| dns_reply(q, gw)) {
                let mut framed = (r.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&r);
                let _ = s.write_all(&framed);
                out.emit(dns_record("tcp", &qs, &answer));
                return;
            }
        }
    }
    let mut reply = "none";
    let (mut http, mut host) = (String::new(), String::new());
    if let Some((line, h)) = http_request(&b) {
        (http, host) = (line, h);
        if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").is_ok() {
            reply = "http-200";
        }
    }
    let sni = client_hello_sni(&b).unwrap_or_default();
    let _ = s.shutdown(std::net::Shutdown::Both);
    out.emit(
        Obj::new()
            .str("kind", "tcp")
            .str("dst", &dst)
            .str("dport", &if port == 0 { String::new() } else { port.to_string() })
            .str("bytes", &b.len().to_string())
            .str("first", &escape(&b[..b.len().min(FIRST_BYTES)]))
            .str("sni", &sni)
            .str("http", &http)
            .str("host", &host)
            .str("reply", reply)
            .str("ms_first", &first.map(ms).unwrap_or_default())
            .str("ms", &ms(t0.elapsed())),
    );
}

fn serve_tcp(l: TcpListener, gw: Ipv4Addr, out: Arc<Out>) {
    static ACTIVE: AtomicUsize = AtomicUsize::new(0);
    loop {
        let Ok((s, _)) = l.accept() else {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        if ACTIVE.load(Ordering::SeqCst) >= MAX_CONNS {
            drop(s);
            out.emit(Obj::new().str("kind", "busy"));
            continue;
        }
        ACTIVE.fetch_add(1, Ordering::SeqCst);
        let out2 = out.clone();
        let spawned = std::thread::Builder::new().name("conn".into()).stack_size(128 << 10).spawn(move || {
            serve_conn(s, gw, &out2);
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Root in the system's own user namespace. Root inside a test's user namespace (unshare -r) is not real root.
fn system_root() -> bool {
    if !rustix::process::geteuid().is_root() {
        return false;
    }
    match std::fs::read_to_string("/proc/self/uid_map") {
        Ok(m) => m.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"],
        Err(_) => true,
    }
}

/// A Limbo guest gateway: 10.213.X.1.
pub fn gateway_ok(a: Ipv4Addr) -> bool {
    let o = a.octets();
    o[0] == 10 && o[1] == 213 && (1..=254).contains(&o[2]) && o[3] == 1
}

const USAGE: &str = "usage: limbo sinkhole-responder --addr 10.213.X.1 (started by limbo serve for a guest in network mode sinkhole)";

/// The responder's main; its exit status.
pub fn run(args: &[String]) -> i32 {
    let addr = match args {
        [flag, a] if flag == "--addr" || flag == "-addr" => a.parse::<Ipv4Addr>().ok().filter(|a| gateway_ok(*a)),
        _ => None,
    };
    let Some(gw) = addr else {
        eprintln!("{USAGE}");
        return 2;
    };
    if system_root() {
        eprintln!("limbo sinkhole-responder: refusing to run as root (limbo serve starts it as the account {})", super::ACCOUNT);
        return 2;
    }
    let bind = |what: &str, r: std::io::Result<()>| r.map_err(|e| eprintln!("limbo sinkhole-responder: {what} on {gw}: {e}")).is_ok();
    let dns = UdpSocket::bind(SocketAddr::from((gw, super::DNS_PORT)));
    let udp = UdpSocket::bind(SocketAddr::from((gw, super::UDP_PORT)));
    let tcp = TcpListener::bind(SocketAddr::from((gw, super::TCP_PORT)));
    let (dns, udp, tcp) = match (dns, udp, tcp) {
        (Ok(d), Ok(u), Ok(t)) => (d, u, t),
        (d, u, t) => {
            bind("DNS", d.map(|_| ()));
            bind("UDP", u.map(|_| ()));
            bind("TCP", t.map(|_| ()));
            return 1;
        }
    };
    // SAFETY: setsockopt with an int we own; without it UDP records carry no port (a kernel before 5.19)
    unsafe {
        let one: libc::c_int = 1;
        libc::setsockopt(
            udp.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_RCVMARK,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    let out = Arc::new(Out(Mutex::new(std::io::stdout())));
    out.emit(Obj::new().str("kind", "ready").str("addr", &gw.to_string()));
    // the daemon holds stdin open; when it closes (the guest is torn down, or the daemon is gone), the responder ends
    let spawn = |name: &str, f: Box<dyn FnOnce() + Send>| std::thread::Builder::new().name(name.into()).stack_size(128 << 10).spawn(f);
    let started = [
        spawn(
            "stdin",
            Box::new(|| {
                let mut b = [0u8; 64];
                while matches!(std::io::stdin().read(&mut b), Ok(n) if n > 0) {}
                std::process::exit(0);
            }),
        ),
        spawn("dns", {
            let out = out.clone();
            Box::new(move || serve_dns(dns, gw, out))
        }),
        spawn("udp", {
            let out = out.clone();
            Box::new(move || serve_udp(udp, out))
        }),
    ];
    if started.iter().any(|s| s.is_err()) {
        eprintln!("limbo sinkhole-responder: cannot start its threads");
        return 1;
    }
    serve_tcp(tcp, gw, out);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        for l in name.split('.').filter(|l| !l.is_empty()) {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        // an EDNS OPT record in the additional section, as resolvers send
        q.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        q
    }

    const GW: Ipv4Addr = Ipv4Addr::new(10, 213, 7, 1);

    #[test]
    fn a_is_answered_with_the_gateway() {
        let (r, qs, ans) = dns_reply(&query("callhome.example", 1), GW).unwrap();
        assert_eq!(qs.name, "callhome.example");
        assert_eq!(type_name(qs.qtype), "A");
        assert_eq!(ans, "10.213.7.1");
        assert_eq!(&r[0..2], &[0x12, 0x34]);
        assert_eq!(r[2] & 0x80, 0x80, "a reply");
        assert_eq!(r[3] & 0x0f, 0, "no error");
        assert_eq!(&r[4..8], &[0, 1, 0, 1]);
        assert_eq!(&r[r.len() - 4..], &[10, 213, 7, 1]);
    }

    #[test]
    fn aaaa_and_txt_get_no_data() {
        for t in [28, 16] {
            let (r, qs, ans) = dns_reply(&query("x.example", t), GW).unwrap();
            assert_eq!(qs.qtype, t);
            assert_eq!(ans, "");
            assert_eq!(&r[6..8], &[0, 0], "no answer");
            assert_eq!(r[3] & 0x0f, 0, "but no error");
        }
    }

    #[test]
    fn hostile_queries_are_refused_or_escaped() {
        assert!(dns_reply(&[], GW).is_none());
        assert!(dns_reply(&[0; 11], GW).is_none());
        let mut reply = query("a.example", 1);
        reply[2] |= 0x80;
        assert!(dns_reply(&reply, GW).is_none(), "a reply is not a question");
        let mut ptr = query("a.example", 1);
        ptr[12] = 0xc0;
        assert!(dns_reply(&ptr, GW).is_none(), "no compression in a question");
        let mut long = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for _ in 0..5 {
            long.push(63);
            long.extend_from_slice(&[b'a'; 63]);
        }
        long.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(dns_reply(&long, GW).is_none(), "over 255 bytes");
        let mut odd = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4];
        odd.extend_from_slice(b"a.\x1b\n");
        odd.extend_from_slice(&[0, 0, 1, 0, 1]);
        let (_, qs, _) = dns_reply(&odd, GW).unwrap();
        assert_eq!(qs.name, "a\\x2e\\x1b\\x0a");
        // every prefix of a valid query: never a panic
        let q = query("callhome.example", 1);
        for n in 0..q.len() {
            let _ = dns_reply(&q[..n], GW);
        }
    }

    fn client_hello(sni: &[u8]) -> Vec<u8> {
        let mut ext = vec![0, 0];
        let name_list_len = 3 + sni.len();
        ext.extend_from_slice(&((name_list_len + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(name_list_len as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(sni);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        // a GREASE extension first, as browsers send
        let mut exts = vec![0x0a, 0x0a, 0, 0];
        exts.extend_from_slice(&ext);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1, (hs.len() >> 8) as u8, hs.len() as u8];
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn sni_is_read_from_a_client_hello() {
        let ch = client_hello(b"c2.example");
        assert_eq!(client_hello_sni(&ch).as_deref(), Some("c2.example"));
        assert!(complete(&ch, 443));
        assert_eq!(client_hello_sni(&client_hello(b"evil\x1b[2J")).as_deref(), Some("evil\\x1b[2J"));
        for n in 0..ch.len() {
            let _ = client_hello_sni(&ch[..n]);
        }
        assert_eq!(client_hello_sni(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn http_requests_are_recognised() {
        let r = b"GET /beacon?id=7 HTTP/1.1\r\nHost: c2.example\r\nUser-Agent: x\r\n\r\n";
        let (line, host) = http_request(r).unwrap();
        assert_eq!(line, "GET /beacon?id=7 HTTP/1.1");
        assert_eq!(host, "c2.example");
        assert!(complete(r, 80));
        assert!(!complete(b"GET / HTTP/1.1\r\nHost: x\r\n", 80));
        assert!(http_request(b"\x16\x03\x01").is_none());
        assert!(http_request(b"get / HTTP/1.1\r\n").is_none());
        assert!(http_request(b"SSH-2.0-x\r\n").is_none());
    }

    #[test]
    fn escape_is_printable_ascii() {
        assert_eq!(escape(b"ok \\ \x00\x7f\xff\xe2\x80\xae"), "ok \\\\ \\x00\\x7f\\xff\\xe2\\x80\\xae");
        let all: Vec<u8> = (0..=255).collect();
        assert!(escape(&all).bytes().all(|c| (0x20..=0x7e).contains(&c)));
    }

    #[test]
    fn only_limbo_gateways() {
        assert!(gateway_ok(GW));
        for bad in ["10.213.7.2", "10.213.0.1", "10.214.7.1", "203.0.113.1", "0.0.0.0"] {
            assert!(!gateway_ok(bad.parse().unwrap()), "{bad}");
        }
        assert_eq!(run(&["--addr".into(), "203.0.113.1".into()]), 2);
        assert_eq!(run(&[]), 2);
    }
}
