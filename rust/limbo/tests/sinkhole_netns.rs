//! The release check for the analysis network modes (docs/SINKHOLE.md "The isolation test"): a guest in mode `sinkhole`
//! or `none` gets nothing out to the home connection, its DNS answers point at the sinkhole, and its connections land in
//! the sinkhole's log. A guest in `internet-only` is the control: the same probes do reach the outside, so a quiet
//! outside means the rules held, not that the harness saw nothing.
//!
//! It needs a network of its own, so it runs only inside a throwaway user and network namespace, which
//! scripts/netns-sinkhole.sh makes (`unshare -rn`, as Heimdall's packaging/tests/netns-rogue.sh does). There it is root
//! of nothing but that namespace. Elsewhere it returns at once. Needs iproute2, nftables, util-linux and python3.
//!
//! The rulesets are the real ones (`policy::nft`, `policy::nft_replace`, as `limbo up` and a hold load them); the
//! responder is the real one, started by the real `sinkhole::Service` from the test build of limbo-rs. Layout:
//!
//!   guest ns: g0 10.213.7.2, default route via 10.213.7.1
//!     | veth
//!   this ns: lb-sh 10.213.7.1 (the guest's bridge, vl-sh in it), the guest's table, the responder; forwarding on and a
//!            masquerade to up0, as a host whose other guests have NAT would have
//!     | veth  up0 192.0.2.1 (default route)
//!   outside ns: up1 192.0.2.2 (the home router and the internet; 198.51.100.7 on lo answers TCP 80), and a counter of
//!            every packet that arrives on up1

use limbo::{events, manifest, policy, sinkhole};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

fn sh(cmd: &str) -> (bool, String) {
    let o = Command::new("sh").arg("-c").arg(cmd).stdin(Stdio::null()).output().expect("sh");
    let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&o.stderr));
    (o.status.success(), s)
}

fn must(cmd: &str) -> String {
    let (ok, out) = sh(cmd);
    assert!(ok, "{cmd}: {out}");
    out
}

/// A network namespace held open by a sleeping child.
struct Ns(Child);

impl Ns {
    fn new() -> Ns {
        let c = Command::new("unshare").args(["-n", "sleep", "600"]).spawn().expect("unshare -n");
        for _ in 0..100 {
            let mine = std::fs::read_link("/proc/self/ns/net").ok();
            if std::fs::read_link(format!("/proc/{}/ns/net", c.id())).ok().is_some_and(|n| Some(n) != mine) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Ns(c)
    }
    fn pid(&self) -> u32 {
        self.0.id()
    }
    fn run(&self, cmd: &str) -> (bool, String) {
        sh(&format!("nsenter -t {} -n sh -c '{}'", self.pid(), cmd.replace('\'', r"'\''")))
    }
    fn must(&self, cmd: &str) -> String {
        let (ok, out) = self.run(cmd);
        assert!(ok, "in ns {}: {cmd}: {out}", self.pid());
        out
    }
}

impl Drop for Ns {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The guest's probes: one line of result each.
const PROBE: &str = r#"
import socket, struct, sys
what = sys.argv[1]
def q(name, qtype):
    b = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for l in name.split("."):
        b += bytes([len(l)]) + l.encode()
    return b + b"\x00" + struct.pack("!HH", qtype, 1)
try:
    if what == "dns":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
        s.sendto(q(sys.argv[3], int(sys.argv[4])), (sys.argv[2], 53))
        r = s.recv(512)
        an = struct.unpack("!H", r[6:8])[0]
        print("answer " + socket.inet_ntoa(r[-4:]) if an else "nodata rcode=%d" % (r[3] & 15))
    elif what == "http":
        s = socket.create_connection((sys.argv[2], int(sys.argv[3])), timeout=2)
        s.sendall(b"GET /beacon?id=7 HTTP/1.1\r\nHost: c2.example\r\n\r\n")
        print("reply " + s.recv(100).split(b"\r\n")[0].decode("ascii", "replace"))
    elif what == "tls":
        s = socket.create_connection((sys.argv[2], 443), timeout=2)
        name = sys.argv[3].encode()
        sni = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
        body = b"\x03\x03" + b"\x07" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack("!H", len(sni)) + sni
        hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
        s.sendall(b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs)
        print("sent, then " + ("closed" if s.recv(10) == b"" else "data"))
    elif what == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(sys.argv[4].encode(), (sys.argv[2], int(sys.argv[3])))
        print("sent")
    elif what == "icmp":
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); s.settimeout(2)
        p = b"\x08\x00\x00\x00\x12\x34\x00\x01ping"
        c = sum(struct.unpack("!%dH" % (len(p) // 2), p)); c = (c >> 16) + (c & 0xffff); c = ~(c + (c >> 16)) & 0xffff
        s.sendto(p[:2] + struct.pack("!H", c) + p[4:], (sys.argv[2], 0))
        while s.recv(200)[20] != 0:
            pass
        print("echo reply")
    elif what == "raw":
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, int(sys.argv[3]))
        s.sendto(b"x" * 20, (sys.argv[2], 0))
        print("sent")
    elif what == "connect":
        s = socket.create_connection((sys.argv[2], int(sys.argv[3])), timeout=2)
        s.settimeout(3)
        print("connected, then " + ("closed" if s.recv(10) == b"" else "data"))
except Exception as e:
    print("failed " + type(e).__name__)
"#;

/// What the outside answers on 198.51.100.7:80, to the control mode only.
const OUTSIDE: &str = r#"
import socket
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("198.51.100.7", 80)); l.listen()
while True:
    c, _ = l.accept(); c.recv(1000); c.sendall(b"OUTSIDE\r\n"); c.close()
"#;

fn manifest(mode: &str) -> manifest::Manifest {
    let doc = format!(
        r#"{{"name":"sh","os":"linux","image":{{"path":"/var/lib/limbo/images/x.qcow2","sha256":"{}"}},"cpus":1,"memory_mb":512,
        "subnet":7,"network":{{"mode":"{mode}"}},"disposable":true,"access":{{"user":"analyst"}},"app":{{"name":"a","exec":"true"}}}}"#,
        "0".repeat(64)
    );
    manifest::parse(doc.as_bytes()).expect("manifest")
}

/// Packets that reached the outside on up1 (IPv6 link-local chatter aside).
fn outside_count(o: &Ns) -> u64 {
    let out = o.must("nft list chain inet watch in");
    out.split("counter packets ").nth(1).and_then(|s| s.split_whitespace().next()).and_then(|n| n.parse().ok()).expect("counter")
}

#[test]
fn analysis_modes_reach_nothing_but_the_sinkhole() {
    if std::env::var("LIMBO_NETNS_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: run through scripts/netns-sinkhole.sh (needs its own user and network namespace)");
        return;
    }
    // refuse to touch a real network: this namespace must have nothing but lo
    let links = must("ip -o link show");
    assert!(links.lines().count() == 1 && links.contains(": lo:"), "not a fresh network namespace:\n{links}");
    must("ip link set lo up");

    let guest = Ns::new();
    let outside = Ns::new();
    must("ip link add lb-sh type bridge && ip addr add 10.213.7.1/24 dev lb-sh && ip link set lb-sh up");
    must(&format!("ip link add vl-sh type veth peer name g0 && ip link set vl-sh master lb-sh up && ip link set g0 netns {}", guest.pid()));
    guest.must("ip link set lo up && ip link set g0 up && ip addr add 10.213.7.2/24 dev g0 && ip route add default via 10.213.7.1");
    must(&format!("ip link add up0 type veth peer name up1 && ip link set up1 netns {}", outside.pid()));
    must("ip addr add 192.0.2.1/24 dev up0 && ip link set up0 up && ip route add default via 192.0.2.2");
    outside.must(
        "ip link set lo up && ip link set up1 up && ip addr add 192.0.2.2/24 dev up1 && ip addr add 198.51.100.7/32 dev lo \
         && ip route add 10.213.0.0/16 via 192.0.2.1",
    );
    outside.must(
        "nft -f - <<EOF
table inet watch {
  chain in {
    type filter hook prerouting priority -300; policy accept;
    iifname \"up1\" ip6 saddr { ::, fe80::/10 } return
    iifname \"up1\" counter
  }
}
EOF",
    );
    // the worst case for a host: it forwards, and masquerades whatever it forwards to its uplink
    must("echo 1 > /proc/sys/net/ipv4/ip_forward");
    must(
        "nft -f - <<EOF
table ip home {
  chain post {
    type nat hook postrouting priority 100; policy accept;
    oifname \"up0\" masquerade
  }
}
EOF",
    );
    let _listener = Command::new("nsenter")
        .args(["-t", &outside.pid().to_string(), "-n", "python3", "-I", "-c", OUTSIDE])
        .stdout(Stdio::null())
        .spawn()
        .map(KillOnDrop)
        .expect("outside listener");
    std::thread::sleep(std::time::Duration::from_millis(300));

    let probe = |args: &str| -> String {
        let (_, out) = sh(&format!("nsenter -t {} -n python3 -I -c '{}' {args}", guest.pid(), PROBE.replace('\'', r"'\''")));
        out.trim().to_string()
    };

    // ---- sinkhole: everything the guest sends lands on the responder, nothing reaches the outside ----
    let m = manifest(manifest::NET_SINKHOLE);
    let rules = policy::nft(&m).expect("rules");
    must(&format!("nft -f - <<'EOF'\n{rules}EOF"));
    let rec = Arc::new(events::Recorder::default());
    let mut svc = sinkhole::Service::new(rec.clone());
    svc.exe = env!("CARGO_BIN_EXE_limbo-rs").into();
    svc.account = None;
    svc.start(&m).expect("the responder starts");
    let before = outside_count(&outside);
    assert_eq!(probe("dns 198.51.100.53 callhome.example 1"), "answer 10.213.7.1", "DNS to any server is the sinkhole's");
    assert_eq!(probe("dns 10.213.7.1 callhome.example 28"), "nodata rcode=0", "AAAA: no data, so the guest falls back to A");
    assert_eq!(probe("http 198.51.100.7 80"), "reply HTTP/1.1 200 OK", "HTTP gets the sinkhole's empty 200");
    assert_eq!(probe("tls 198.51.100.7 c2.example"), "sent, then closed");
    assert_eq!(probe("udp 198.51.100.9 4242 ping"), "sent");
    assert_eq!(probe("connect 192.0.2.2 22"), "connected, then closed", "the home router's address is the sinkhole's too");
    assert_eq!(probe("connect 10.213.7.1 22"), "connected, then closed", "so is the host's own");
    assert_eq!(probe("icmp 198.51.100.7"), "failed TimeoutError", "ICMP is not answered or forwarded");
    assert_eq!(probe("raw 198.51.100.7 47"), "sent");
    std::thread::sleep(std::time::Duration::from_millis(300));
    svc.stop("sh");
    assert_eq!(outside_count(&outside), before, "a sinkhole guest's packet reached the outside");
    let evs = rec.events.lock().unwrap().clone();
    let find = |kind: &str, pairs: &[(&str, &str)]| {
        evs.iter().any(|(k, g, d)| k == kind && g == "sh" && pairs.iter().all(|(a, b)| d.get(*a).map(String::as_str) == Some(*b)))
    };
    let shown = || evs.iter().map(|e| format!("{e:?}")).collect::<Vec<_>>().join("\n");
    assert!(find("sinkhole.start", &[("addr", "10.213.7.1")]), "{}", shown());
    assert!(find("sinkhole.dns", &[("name", "callhome.example"), ("type", "A"), ("answer", "10.213.7.1")]), "{}", shown());
    assert!(find("sinkhole.dns", &[("name", "callhome.example"), ("type", "AAAA")]), "{}", shown());
    assert!(
        find(
            "sinkhole.connect",
            &[
                ("proto", "tcp"),
                ("dst", "198.51.100.7"),
                ("dport", "80"),
                ("http", "GET /beacon?id=7 HTTP/1.1"),
                ("host", "c2.example"),
                ("reply", "http-200")
            ]
        ),
        "{}",
        shown()
    );
    assert!(find("sinkhole.connect", &[("dst", "198.51.100.7"), ("dport", "443"), ("sni", "c2.example")]), "{}", shown());
    assert!(find("sinkhole.connect", &[("proto", "udp"), ("dport", "4242"), ("first", "ping")]), "{}", shown());
    assert!(find("sinkhole.connect", &[("dst", "192.0.2.2"), ("dport", "22")]), "{}", shown());
    assert!(find("sinkhole.connect", &[("dst", "10.213.7.1"), ("dport", "22")]), "{}", shown());
    assert!(find("sinkhole.stop", &[("dns", "2"), ("udp", "1"), ("tcp", "4")]), "{}", shown());
    let report = svc.take("sh").expect("the run's part");
    assert!(report.contains(r#""name":"callhome.example""#) && report.contains(r#""sni":"c2.example""#), "{report}");

    // ---- none (and a held guest: a hold loads mode none's rules): nothing answers, nothing gets out ----
    must(&format!("nft -f - <<'EOF'\n{}EOF", policy::nft_restrict(&m).expect("rules")));
    let before = outside_count(&outside);
    assert_eq!(probe("dns 198.51.100.53 callhome.example 1"), "failed TimeoutError");
    assert_eq!(probe("http 198.51.100.7 80"), "failed TimeoutError");
    assert_eq!(probe("connect 192.0.2.2 22"), "failed TimeoutError");
    probe("udp 198.51.100.9 4242 ping");
    assert_eq!(probe("icmp 198.51.100.7"), "failed TimeoutError");
    probe("raw 198.51.100.7 47");
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(outside_count(&outside), before, "a mode none guest's packet reached the outside");

    // ---- the control: internet-only does get out through the same host, so the counter and probes can see a leak ----
    must(&format!("nft -f - <<'EOF'\n{}EOF", policy::nft_replace(&m, manifest::NET_INTERNET_ONLY).expect("rules")));
    let before = outside_count(&outside);
    assert_eq!(probe("http 198.51.100.7 80"), "reply OUTSIDE");
    assert_eq!(probe("icmp 198.51.100.7"), "echo reply");
    assert!(outside_count(&outside) > before, "the control reached the outside but the counter did not move");
    must(&format!("nft delete table inet {}", policy::table_name(&m)));
    eprintln!("sinkhole and none: nothing reached the outside; the control (internet-only) did");
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
