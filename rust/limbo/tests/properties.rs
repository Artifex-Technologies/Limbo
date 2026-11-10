//! Properties (proptest) and the fuzz targets' bodies on stable. The Kani harnesses' claims run here exhaustively.

use limbo::api::{self, Present, Principal, R};
use limbo::{fuzzing, gojson, http, quarantine};
use proptest::prelude::*;

fn all_presents() -> Vec<Present> {
    (0..32u8)
        .map(|b| Present { runs: b & 1 != 0, samples: b & 2 != 0, instances: b & 4 != 0, licenses: b & 8 != 0, exchange: b & 16 != 0 })
        .collect()
}

/// The Kani harness `control_and_agent_have_no_loosening_route`, over every combination of services.
#[test]
fn control_and_agent_have_no_loosening_route_exhaustively() {
    for s in all_presents() {
        assert!(api::loosening_free(s), "{s:?}");
        for r in api::routes(Principal::Control, s) {
            assert!(
                !matches!(r.id, R::QVerdict | R::QClose | R::GuestDown | R::PutSettings | R::StartInstance | R::StopInstance | R::TakeExchange),
                "control.sock has {:?}",
                r.id
            );
        }
        for r in api::routes(Principal::Agent, s) {
            assert!(matches!(r.id, R::Profiles | R::StartRun | R::RunGet), "agent.sock has {:?}", r.id);
        }
    }
}

/// The Kani harness `user_sock_never_has_verdicts_or_root_routes`.
#[test]
fn user_sock_never_has_verdicts_or_root_routes_exhaustively() {
    for s in all_presents() {
        for r in api::routes(Principal::User, s) {
            assert!(!matches!(
                r.id,
                R::QVerdict | R::QClose | R::GuestDown | R::PutSettings | R::AddInstance | R::RemoveInstance | R::AddLicense | R::RemoveLicense
                    | R::RevealLicense | R::SampleRun | R::AgentRunsStop | R::QOpen | R::QRaise
            ));
        }
    }
}

/// No two routes of one table share a method and pattern, and every pattern is clean (so the mux reaches each).
#[test]
fn route_tables_are_well_formed() {
    let s = Present { runs: true, samples: true, instances: true, licenses: true, exchange: true };
    for p in [Principal::Admin, Principal::Control, Principal::Agent, Principal::User] {
        let t = api::routes(p, s);
        for (i, a) in t.iter().enumerate() {
            assert_eq!(http::clean_path(a.pattern), a.pattern);
            for b in &t[i + 1..] {
                assert!(!(a.method == b.method && a.pattern == b.pattern), "{p:?} {}", a.pattern);
            }
        }
    }
}

#[test]
fn a_raise_never_lowers() {
    for held in ["restrict", "isolate"] {
        for req in ["", "restrict", "isolate", "x", "RESTRICT"] {
            if let Ok(n) = quarantine::raise_rule(held, req) {
                assert!(quarantine::rank(n) >= quarantine::rank(held));
            }
        }
    }
}

fn smoke(f: fn(&[u8]), seeds: &[&[u8]]) {
    for s in seeds {
        for n in 0..=s.len() {
            f(&s[..n]);
        }
    }
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..3000 {
        let mut b = vec![];
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let n = (x % 300) as usize;
        for _ in 0..n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            b.push((x >> 24) as u8);
        }
        f(&b);
    }
}

#[test]
fn fuzz_http_request_smoke() {
    let seeds: &[&[u8]] = &[
        b"POST /v1/quarantine/x/verdict HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
        b"POST /v1/guests/lab/down HTTP/1.1\r\n\r\n",
        b"POST /v1/settings HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        b"GET /v1/%71uarantine HTTP/1.1\r\n\r\n",
        b"POST /v1/quarantine/a%2F..%2Fx/close HTTP/1.1\r\n\r\n",
        b"POST /v1//guests/x/down HTTP/1.1\r\n\r\n",
        b"DELETE /v1/instances/lab HTTP/1.1\r\n\r\n",
        b"POST /v1/agent-runs/stop HTTP/1.0\r\n\r\n",
    ];
    smoke(fuzzing::http_request, seeds);
}

#[test]
fn fuzz_json_smoke() {
    smoke(fuzzing::json, &[br#"{"a":[1,2.5e-3,true,null,"s\ud800"],"b":{}}"#, b"[[[[[[[[]]]]]]]]", br#""x\n""#]);
}

#[test]
fn fuzz_manifest_smoke() {
    smoke(
        fuzzing::manifest,
        &[br#"{"name":"lab","os":"linux","image":{"path":"/i/a.qcow2","sha256":"0000000000000000000000000000000000000000000000000000000000000000"},"access":{"user":"a"},"app":{"name":"A","exec":"a"},"network":{"mode":"allowlist","allow":[{"addr":"10.0.0.0/8","port":443}]}}"#],
    );
}

#[test]
fn fuzz_nflog_smoke() {
    smoke(fuzzing::nflog, &[b"\x2c\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x1c\x2d\x10\x00\x0a\x00limbo:lab:a\x00\x08\x00\x09\x00\x45\x00\x00\x00"]);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// On a valid document gojson reads what serde_json reads (strings, numbers, structure).
    #[test]
    fn gojson_agrees_with_serde_on_valid_documents(v in arb_json()) {
        let text = serde_json::to_string(&v).unwrap();
        let ours = gojson::parse(text.as_bytes()).unwrap();
        let mut back = String::new();
        gojson::write_value(&mut back, &ours);
        let again: serde_json::Value = serde_json::from_str(&back).unwrap();
        prop_assert_eq!(again, v);
    }

    /// Any path and method on control.sock or agent.sock reaches only their own routes.
    #[test]
    fn any_path_reaches_only_allowed_routes(segs in proptest::collection::vec("[a-z0-9%./-]{0,12}", 0..6), m in "(GET|POST|DELETE|HEAD|PUT)") {
        let path = format!("/{}", segs.join("/"));
        let s = Present { runs: true, samples: true, instances: true, licenses: true, exchange: true };
        for p in [Principal::Control, Principal::Agent] {
            if let http::Matched::Route(id, _) = http::route(&api::routes(p, s), &m, &path) {
                prop_assert!(api::allowed_for(p, id));
            }
        }
    }
}

fn arb_json() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::Value::from(n)),
        "\\PC{0,12}".prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..5).prop_map(serde_json::Value::Array),
            proptest::collection::btree_map("[a-z]{0,6}", inner, 0..5).prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
}
