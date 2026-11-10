//! Guests' network flows and refusals, from the NFLOG group their tables log to, turned into bounded events for
//! Heimdall (Go: internal/flows). The kernel part (`listen`) is a netlink socket the daemon's loop polls; the rest is
//! pure and pinned by the Go fixtures.

use crate::events::Emitter;
use crate::gotime::Time;
use crate::Detail;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const KIND_FLOW: &str = "net.flow";
pub const KIND_BLOCKED: &str = "net.blocked";
pub const KIND_ANOMALY: &str = "net.anomaly";
pub const KIND_CAPPED: &str = "net.capped";

const MAX_KEYS_PER_GUEST: usize = 256;
const MAX_GUESTS: usize = 128;
const SCAN_WINDOW_NS: i64 = 60_000_000_000;
const SCAN_THRESHOLD: usize = 20;
const ANOMALY_QUIET_NS: i64 = 600_000_000_000;

/// A destination address as netip keeps it: 4 or 16 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ip {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl Ip {
    fn unmap(self) -> Ip {
        match self {
            Ip::V6(b) => match Ipv6Addr::from(b).to_ipv4_mapped() {
                Some(v4) => Ip::V4(v4.octets()),
                None => self,
            },
            v => v,
        }
    }
    pub fn is_loopback(self) -> bool {
        match self.unmap() {
            Ip::V4(b) => b[0] == 127,
            Ip::V6(b) => Ipv6Addr::from(b) == Ipv6Addr::LOCALHOST,
        }
    }
    pub fn is_private(self) -> bool {
        match self.unmap() {
            Ip::V4(b) => b[0] == 10 || (b[0] == 172 && b[1] & 0xf0 == 16) || (b[0] == 192 && b[1] == 168),
            Ip::V6(b) => b[0] & 0xfe == 0xfc,
        }
    }
    pub fn is_link_local_unicast(self) -> bool {
        match self.unmap() {
            Ip::V4(b) => b[0] == 169 && b[1] == 254,
            Ip::V6(b) => b[0] == 0xfe && b[1] & 0xc0 == 0x80,
        }
    }
    pub fn is_link_local_multicast(self) -> bool {
        match self.unmap() {
            Ip::V4(b) => b[0] == 224 && b[1] == 0 && b[2] == 0,
            Ip::V6(b) => b[0] == 0xff && b[1] & 0x0f == 0x02,
        }
    }
    pub fn is_interface_local_multicast(self) -> bool {
        matches!(self, Ip::V6(b) if b[0] == 0xff && b[1] & 0x0f == 0x01)
    }
    pub fn is_multicast(self) -> bool {
        match self.unmap() {
            Ip::V4(b) => b[0] & 0xf0 == 0xe0,
            Ip::V6(b) => b[0] == 0xff,
        }
    }
    pub fn is_unspecified(self) -> bool {
        match self {
            Ip::V4(b) => b == [0; 4],
            Ip::V6(b) => b == [0; 16],
        }
    }
}

impl std::fmt::Display for Ip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ip::V4(b) => write!(f, "{}", Ipv4Addr::from(*b)),
            Ip::V6(b) => write!(f, "{}", crate::manifest::Addr::V6(*b, String::new())),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Packet {
    pub guest: String,
    pub verdict: String,
    pub proto: String,
    pub dst: Ip,
    pub dport: i64,
    pub icmp: i64,
}

/// "limbo:<guest>:<verdict>" (trailing spaces and NULs allowed).
pub fn parse_prefix(p: &str) -> Option<(String, String)> {
    let p = p.trim_end_matches([' ', '\0']);
    let parts: Vec<&str> = p.split(':').collect();
    if parts.len() != 3 || parts[0] != "limbo" || !crate::manifest::name_ok(parts[1]) {
        return None;
    }
    match parts[2] {
        "a" | "d" | "h" => Some((parts[1].to_string(), parts[2].to_string())),
        _ => None,
    }
}

fn proto_name(n: u8) -> String {
    match n {
        6 => "tcp".into(),
        17 => "udp".into(),
        1 => "icmp".into(),
        58 => "icmpv6".into(),
        n => n.to_string(),
    }
}

/// The destination, protocol and port from the start of an IPv4 or IPv6 packet: (proto, dst, dport, icmp type or -1).
pub fn parse_ip(b: &[u8]) -> Result<(String, Ip, i64, i64), &'static str> {
    if b.is_empty() {
        return Err("flows: empty packet");
    }
    let (next, rest, dst) = match b[0] >> 4 {
        4 => {
            let ihl = (b[0] & 0x0f) as usize * 4;
            if b.len() < 20 || ihl < 20 || b.len() < ihl {
                return Err("flows: short IPv4 header");
            }
            let dst = Ip::V4([b[16], b[17], b[18], b[19]]);
            let next = b[9];
            if u16::from_be_bytes([b[6], b[7]]) & 0x1fff != 0 {
                return Ok((proto_name(next), dst, 0, -1));
            }
            (next, &b[ihl..], dst)
        }
        6 => {
            if b.len() < 40 {
                return Err("flows: short IPv6 header");
            }
            let mut d = [0u8; 16];
            d.copy_from_slice(&b[24..40]);
            let mut next = b[6];
            let mut rest = &b[40..];
            let mut i = 0;
            while i < 4 && matches!(next, 0 | 43 | 60) && rest.len() >= 8 {
                let l = (rest[1] as usize + 1) * 8;
                if rest.len() < l {
                    break;
                }
                next = rest[0];
                rest = &rest[l..];
                i += 1;
            }
            (next, rest, Ip::V6(d))
        }
        _ => return Err("flows: not an IP packet"),
    };
    let (mut dport, mut icmp) = (0i64, -1i64);
    match next {
        6 | 17 if rest.len() >= 4 => dport = u16::from_be_bytes([rest[2], rest[3]]) as i64,
        1 | 58 if !rest.is_empty() => icmp = rest[0] as i64,
        _ => {}
    }
    Ok((proto_name(next), dst, dport, icmp))
}

/// Where a destination is.
pub fn scope(dst: Ip) -> &'static str {
    let is6 = matches!(dst, Ip::V6(b) if Ipv6Addr::from(b).to_ipv4_mapped().is_none());
    if is6 {
        return "ipv6";
    }
    // Go's predicates on a 4-in-6 address answer as for the IPv6 form, except the CGNAT check (it unmaps)
    let cgnat = matches!(dst.unmap(), Ip::V4(b) if b[0] == 100 && b[1] & 0xc0 == 64);
    if dst.is_loopback() {
        "loopback"
    } else if dst.is_private() || dst.is_link_local_unicast() || cgnat {
        "lan"
    } else if dst.is_multicast() || dst.is_unspecified() {
        "other"
    } else {
        "internet"
    }
}

#[derive(Default)]
struct GuestState {
    seen: HashSet<String>,
    capped: bool,
    suppressed: i64,
    recent: Vec<Time>,
    last_anom: HashMap<String, Time>,
    anom_count: HashMap<String, i64>,
    touched: Time,
}

/// Decides which packets become events.
pub struct Aggregator {
    pub events: Option<std::sync::Arc<dyn Emitter>>,
    pub now: fn() -> Time,
    pub gateway: Option<Box<dyn Fn(&str) -> Option<Ip> + Send + Sync>>,
    guests: BTreeMap<String, GuestState>,
}

impl Aggregator {
    pub fn new(events: Option<std::sync::Arc<dyn Emitter>>, now: fn() -> Time) -> Aggregator {
        Aggregator { events, now, gateway: None, guests: BTreeMap::new() }
    }

    fn state(&mut self, g: &str) -> &mut GuestState {
        let now = (self.now)();
        if !self.guests.contains_key(g) {
            if self.guests.len() >= MAX_GUESTS {
                // the least recently touched one (Go: its map order breaks a tie; touched times practically never tie)
                let oldest = self.guests.iter().min_by(|a, b| a.1.touched.cmp(&b.1.touched)).map(|(n, _)| n.clone());
                if let Some(o) = oldest {
                    self.guests.remove(&o);
                }
            }
            self.guests.insert(g.to_string(), GuestState::default());
        }
        let st = self.guests.get_mut(g).expect("inserted above");
        st.touched = now;
        st
    }

    /// Drops what is remembered of a guest (torn down; the name may be reused).
    pub fn forget(&mut self, guest: &str) {
        self.guests.remove(guest);
    }

    fn emit(&self, kind: &str, guest: &str, d: Detail) {
        if let Some(e) = &self.events {
            let _ = e.emit(kind, guest, d);
        }
    }

    /// One packet into zero or more events.
    pub fn handle(&mut self, p: &Packet) {
        let mut sc = scope(p.dst);
        if p.verdict == "h" {
            sc = "host";
        }
        let (kind, verdict) = if p.verdict == "a" { (KIND_FLOW, "allowed") } else { (KIND_BLOCKED, "dropped") };
        let key = format!("{}|{}|{}|{}", p.verdict, p.proto, p.dst, p.dport);
        let mut out: Vec<(&'static str, Detail)> = vec![];
        let st = self.state(&p.guest);
        let fresh = !st.seen.contains(&key);
        if fresh {
            if st.seen.len() >= MAX_KEYS_PER_GUEST {
                if !st.capped {
                    st.capped = true;
                    out.push((KIND_CAPPED, crate::detail([("limit", &MAX_KEYS_PER_GUEST.to_string())])));
                }
                st.suppressed += 1;
            } else {
                st.seen.insert(key);
                let mut d = crate::detail([("proto", &p.proto), ("dst", &p.dst.to_string()), ("verdict", verdict), ("scope", sc)]);
                if p.dport > 0 {
                    d.insert("dport".into(), p.dport.to_string());
                }
                if p.icmp >= 0 {
                    d.insert("icmp_type".into(), p.icmp.to_string());
                }
                out.push((kind, d));
            }
        }
        for (k, d) in out.drain(..) {
            self.emit(k, &p.guest, d);
        }
        if p.verdict == "a" {
            return;
        }
        let gw = self.gateway.as_ref().and_then(|g| g(&p.guest));
        let mut reasons: Vec<&'static str> = vec![];
        match sc {
            "host" => {
                let dns_to_gateway = gw.is_some_and(|g| g == p.dst) && p.dport == 53;
                if !dns_to_gateway && (p.proto == "tcp" || p.proto == "udp") {
                    reasons.push("host_probe");
                }
            }
            "lan" | "loopback" => reasons.push("lan_probe"),
            "ipv6" => {
                if !p.dst.is_link_local_unicast() && !p.dst.is_link_local_multicast() && !p.dst.is_interface_local_multicast() {
                    reasons.push("ipv6");
                }
            }
            _ => {}
        }
        for r in reasons {
            self.anomaly(p, r);
        }
        if fresh {
            let now = (self.now)();
            let st = self.state(&p.guest);
            st.recent.retain(|t| now.sub(t) < SCAN_WINDOW_NS);
            st.recent.push(now);
            if st.recent.len() >= SCAN_THRESHOLD {
                st.recent.clear();
                self.anomaly(p, "scan");
            }
        }
    }

    fn anomaly(&mut self, p: &Packet, reason: &'static str) {
        let now = (self.now)();
        let st = self.guests.get_mut(&p.guest).expect("state made by handle");
        *st.anom_count.entry(reason.into()).or_insert(0) += 1;
        if let Some(last) = st.last_anom.get(reason) {
            if now.sub(last) < ANOMALY_QUIET_NS {
                return;
            }
        }
        st.last_anom.insert(reason.into(), now);
        let mut sc = scope(p.dst);
        if p.verdict == "h" {
            sc = "host";
        }
        let count = st.anom_count.get(reason).copied().unwrap_or(0);
        let mut d = crate::detail([("reason", reason), ("proto", &p.proto), ("dst", &p.dst.to_string()), ("scope", sc), ("count", &count.to_string())]);
        if p.dport > 0 {
            d.insert("dport".into(), p.dport.to_string());
        }
        if reason == "scan" {
            d.insert("window_seconds".into(), "60".into());
            d.insert("threshold".into(), SCAN_THRESHOLD.to_string());
        }
        st.anom_count.insert(reason.into(), 0);
        self.emit(KIND_ANOMALY, &p.guest, d);
    }
}

// ---- netlink ----

const NLMSG_HDR_LEN: usize = 16;
const NFGEN_HDR_LEN: usize = 4;
const NFNL_SUBSYS_LOG: u16 = 4;
const NFULNL_MSG_PKT: u16 = 0;
const NFULNL_MSG_CFG: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;
const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;
const NFULA_CFG_QTHR: u16 = 5;
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;
const COPY_RANGE: u32 = 96;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn ne16(b: &[u8]) -> u16 {
    u16::from_ne_bytes([b[0], b[1]])
}
fn ne32(b: &[u8]) -> u32 {
    u32::from_ne_bytes([b[0], b[1], b[2], b[3]])
}

/// One netlink read split into NFLOG packet messages (prefix, payload); anything else is skipped.
pub fn parse_messages(mut buf: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    while buf.len() >= NLMSG_HDR_LEN {
        let l = ne32(&buf[0..4]) as usize;
        let typ = ne16(&buf[4..6]);
        if l < NLMSG_HDR_LEN || l > buf.len() {
            break;
        }
        let msg = &buf[NLMSG_HDR_LEN..l];
        if typ == (NFNL_SUBSYS_LOG << 8 | NFULNL_MSG_PKT) && msg.len() >= NFGEN_HDR_LEN {
            let (mut prefix, mut payload) = (String::new(), Vec::new());
            let mut attrs = &msg[NFGEN_HDR_LEN..];
            while attrs.len() >= 4 {
                let al = ne16(&attrs[0..2]) as usize;
                let at = ne16(&attrs[2..4]) & 0x3fff;
                if al < 4 || al > attrs.len() {
                    break;
                }
                let val = &attrs[4..al];
                match at {
                    NFULA_PREFIX => {
                        let end = val.iter().position(|&c| c == 0).unwrap_or(val.len());
                        prefix = crate::gotext::lossy(&val[..end]);
                    }
                    NFULA_PAYLOAD => payload = val.to_vec(),
                    _ => {}
                }
                attrs = &attrs[align4(al).min(attrs.len())..];
            }
            if !prefix.is_empty() && !payload.is_empty() {
                out.push((prefix, payload));
            }
        }
        buf = &buf[align4(l).min(buf.len())..];
    }
    out
}

fn attr(typ: u16, val: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; align4(4 + val.len())];
    b[0..2].copy_from_slice(&((4 + val.len()) as u16).to_ne_bytes());
    b[2..4].copy_from_slice(&typ.to_ne_bytes());
    b[4..4 + val.len()].copy_from_slice(val);
    b
}

fn config_msg(group: u16, seq: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![0u8, 0, (group >> 8) as u8, group as u8];
    for a in attrs {
        body.extend_from_slice(a);
    }
    let mut b = vec![0u8; NLMSG_HDR_LEN + body.len()];
    let len = b.len() as u32;
    b[0..4].copy_from_slice(&len.to_ne_bytes());
    b[4..6].copy_from_slice(&(NFNL_SUBSYS_LOG << 8 | NFULNL_MSG_CFG).to_ne_bytes());
    b[6..8].copy_from_slice(&(0x1u16 | 0x4).to_ne_bytes());
    b[8..12].copy_from_slice(&seq.to_ne_bytes());
    b[NLMSG_HDR_LEN..].copy_from_slice(&body);
    b
}

/// The two requests that bind a group and ask for COPY_RANGE bytes of each packet, delivered at once.
pub fn bind_requests(group: u16) -> Vec<Vec<u8>> {
    let mut mode = COPY_RANGE.to_be_bytes().to_vec();
    mode.extend_from_slice(&[NFULNL_COPY_PACKET, 0]);
    vec![
        config_msg(group, 1, &[attr(NFULA_CFG_CMD, &[NFULNL_CFG_CMD_BIND])]),
        config_msg(group, 2, &[attr(NFULA_CFG_MODE, &mode), attr(NFULA_CFG_QTHR, &1u32.to_be_bytes())]),
    ]
}

/// A netlink ack: Ok for a positive one, the errno otherwise.
pub fn ack_error(mut buf: &[u8]) -> Result<(), String> {
    while buf.len() >= NLMSG_HDR_LEN {
        let l = ne32(&buf[0..4]) as usize;
        let typ = ne16(&buf[4..6]);
        if l < NLMSG_HDR_LEN || l > buf.len() {
            return Err("flows: malformed netlink answer".into());
        }
        if typ == NLMSG_ERROR && l >= NLMSG_HDR_LEN + 4 {
            let code = ne32(&buf[NLMSG_HDR_LEN..NLMSG_HDR_LEN + 4]) as i32;
            if code != 0 {
                return Err(format!("flows: netlink: {}", crate::sys::go_err(&std::io::Error::from_raw_os_error(-code))));
            }
            return Ok(());
        }
        buf = &buf[align4(l).min(buf.len())..];
    }
    Ok(())
}

/// A logged packet as a Packet, or None for anything that is not one of Limbo's.
pub fn decode(prefix: &str, payload: &[u8]) -> Option<Packet> {
    let (guest, verdict) = parse_prefix(prefix)?;
    let (proto, dst, dport, icmp) = parse_ip(payload).ok()?;
    Some(Packet { guest, verdict, proto, dst, dport, icmp })
}

/// Binds the NFLOG group on a netlink socket and returns it non-blocking, for the daemon's poll loop.
pub fn listen(group: u16) -> Result<std::os::fd::OwnedFd, String> {
    use rustix::net::{netlink, AddressFamily, SocketFlags, SocketType};
    let fd = rustix::net::socket_with(AddressFamily::NETLINK, SocketType::RAW, SocketFlags::CLOEXEC, Some(netlink::NETFILTER))
        .map_err(|e| format!("flows: netlink socket: {}", crate::sys::go_err(&e.into())))?;
    let me = netlink::SocketAddrNetlink::new(0, 0);
    rustix::net::bind(&fd, &me).map_err(|e| format!("flows: netlink bind: {}", crate::sys::go_err(&e.into())))?;
    let _ = rustix::net::sockopt::set_socket_recv_buffer_size(&fd, 1 << 20);
    let mut buf = vec![0u8; 1 << 16];
    for req in bind_requests(group) {
        rustix::net::sendto(&fd, &req, rustix::net::SendFlags::empty(), &me)
            .map_err(|e| format!("flows: binding NFLOG group {group}: {}", crate::sys::go_err(&e.into())))?;
        let (n, _) = rustix::net::recv(&fd, &mut buf[..], rustix::net::RecvFlags::empty())
            .map_err(|e| format!("flows: binding NFLOG group {group}: {}", crate::sys::go_err(&e.into())))?;
        ack_error(&buf[..n.min(buf.len())]).map_err(|e| format!("flows: binding NFLOG group {group} (is another program using it?): {e}"))?;
    }
    rustix::io::ioctl_fionbio(&fd, true).map_err(|e| crate::sys::go_err(&e.into()))?;
    Ok(fd)
}
