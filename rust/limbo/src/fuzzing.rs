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
