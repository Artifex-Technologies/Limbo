//! The fuzz targets' bodies. cargo-fuzz (nightly, rust/fuzz) calls them; tests/fuzz_smoke.rs runs them on stable with
//! random and structured inputs on every `cargo test`. Each states what must hold for any input.

use crate::api::{self, Principal};
use crate::{flows, gojson, http, manifest};

/// Any bytes as a request on any socket: never a panic, and on control.sock and agent.sock never a route outside
/// their tables (whatever the path, method or encoding).
pub fn http_request(data: &[u8]) {
    let Ok(req) = http::read_request(data) else { return };
    let s = api::Present { runs: true, samples: true, instances: true, licenses: true, exchange: true };
    for p in [Principal::Control, Principal::Agent] {
        let table = api::routes(p, s);
        if let http::Matched::Route(id, _) = http::route(&table, &req.method, &req.raw_path) {
            assert!(api::allowed_for(p, id), "{p:?} reached {id:?}");
        }
    }
}

/// Any bytes as JSON: no panic; what parses writes back and parses to the same value.
pub fn json(data: &[u8]) {
    if let Ok(v) = gojson::parse(data) {
        let mut s = String::new();
        gojson::write_value(&mut s, &v);
        assert_eq!(gojson::parse(s.as_bytes()).ok(), Some(v));
    }
    let _ = gojson::parse_first(data);
}

/// Any bytes as a manifest: no panic; one that parses validates and survives its own round trip.
pub fn manifest(data: &[u8]) {
    if let Ok(m) = manifest::parse(data) {
        assert!(m.validate().is_ok());
        let again = manifest::parse(m.json().as_bytes()).expect("a parsed manifest reads back");
        assert_eq!(again, m);
        let _ = crate::virt::domain_xml(&m, "/x/overlay.qcow2");
        let _ = crate::policy::nft(&m);
    }
}

/// Any bytes as a netlink read: no panic; a decoded packet names a valid guest.
pub fn nflog(data: &[u8]) {
    for (prefix, payload) in flows::parse_messages(data) {
        if let Some(p) = flows::decode(&prefix, &payload) {
            assert!(manifest::name_ok(&p.guest));
        }
    }
    let _ = flows::parse_ip(data);
    let _ = flows::ack_error(data);
}

/// Any bytes as what a guest in network mode sinkhole sends (a DNS question, a TCP connection's first bytes) and as a
/// line the responder writes: no panic; whatever is logged is printable ASCII.
pub fn sinkhole(data: &[u8]) {
    use crate::sinkhole::responder;
    let gw = std::net::Ipv4Addr::new(10, 213, 7, 1);
    let printable = |s: &str| s.bytes().all(|c| (0x20..=0x7e).contains(&c));
    if let Some((reply, q, _)) = responder::dns_reply(data, gw) {
        assert!(printable(&q.name) && reply.len() >= 12 && reply[..2] == data[..2]);
    }
    if let Some(sni) = responder::client_hello_sni(data) {
        assert!(printable(&sni));
    }
    if let Some((line, host)) = responder::http_request(data) {
        assert!(printable(&line) && printable(&host));
    }
    let mut log = crate::sinkhole::Log::default();
    for (_, d) in log.take(data) {
        assert!(d.values().all(|v| printable(v)));
    }
}
