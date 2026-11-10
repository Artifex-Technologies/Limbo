//! testdata/parity/flows.json: NFLOG parsing and the aggregator's events, as the Go code makes them.

mod common;
use common::{fixture, s, Diffs};
use limbo::events::Recorder;
use limbo::flows::{self, Aggregator, Ip, Packet};
use limbo::gotime::Time;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

static NOW: AtomicI64 = AtomicI64::new(0);

fn now() -> Time {
    let n = NOW.load(Ordering::SeqCst);
    Time::from_unix(n.div_euclid(1_000_000_000), n.rem_euclid(1_000_000_000) as u32)
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ip(b: &[u8]) -> Ip {
    if b.len() == 4 {
        Ip::V4([b[0], b[1], b[2], b[3]])
    } else {
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        Ip::V6(a)
    }
}

#[test]
fn flows_match_go() {
    let mut d = Diffs::default();
    for c in fixture("flows") {
        let o = &c["out"];
        match c["fn"].as_str().unwrap() {
            "ParsePrefix" => {
                let r = flows::parse_prefix(&s(&c["in"]));
                let (g, v) = r.clone().unwrap_or_default();
                d.eq("prefix", &format!("{g}|{v}|{}", r.is_some()), &format!("{}|{}|{}", s(&o["guest"]), s(&o["verdict"]), o["ok"]));
            }
            "Scope" => {
                let a = ip(&hex(&s(&c["in"])));
                d.eq("scope", flows::scope(a), &s(&o["scope"]));
                d.eq("addr text", &a.to_string(), &s(&o["string"]));
            }
            "ParseIP" => {
                let b = hex(&s(&c["in"]));
                let got = match flows::parse_ip(&b) {
                    Ok((p, dst, port, icmp)) => format!("{p}|{dst}|{port}|{icmp}|"),
                    Err(e) => {
                        // Go's zero values beside an error: no destination unless it was read
                        format!("||0|-1|{e}")
                    }
                };
                let want = format!("{}|{}|{}|{}|{}", s(&o["proto"]), s(&o["dst"]), o["dport"], o["icmp"], s(&o["error"]));
                d.eq(&format!("ParseIP {}", s(&c["in"])), &got, &want);
            }
            "parseMessages" => {
                let b = hex(&s(&c["in"]));
                let msgs = flows::parse_messages(&b);
                let mut got = vec![];
                for (prefix, payload) in &msgs {
                    let mut x = format!("{prefix}|{}", hexs(payload));
                    if let Some(p) = flows::decode(prefix, payload) {
                        x += &format!("|{}|{}|{}|{}|{}|{}", p.guest, p.verdict, p.proto, p.dst, p.dport, p.icmp);
                    }
                    got.push(x);
                }
                let want: Vec<String> = o
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|m| {
                                let mut x = format!("{}|{}", s(&m["prefix"]), s(&m["payload"]));
                                if m.get("guest").is_some() {
                                    x += &format!(
                                        "|{}|{}|{}|{}|{}|{}",
                                        s(&m["guest"]),
                                        s(&m["verdict"]),
                                        s(&m["proto"]),
                                        s(&m["dst"]),
                                        s(&m["dport"]),
                                        s(&m["icmp"])
                                    );
                                }
                                x
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                d.eq("parseMessages", &got.join("\n"), &want.join("\n"));
            }
            "bindRequests" => {
                let got: Vec<String> = flows::bind_requests(7213).iter().map(|b| hexs(b)).collect();
                let want: Vec<String> = o.as_array().unwrap().iter().map(s).collect();
                d.eq("bindRequests", &got.join(","), &want.join(","));
            }
            "ackError" => {
                let got = match flows::ack_error(&hex(&s(&c["in"]))) {
                    Ok(()) => String::new(),
                    Err(e) => e,
                };
                d.eq("ackError", &got, &s(o));
            }
            "Aggregator" => {
                let rec = Arc::new(Recorder::default());
                let mut a = Aggregator::new(Some(rec.clone()), now);
                a.gateway = Some(Box::new(|g: &str| if g == "lab" { Some(Ip::V4([10, 213, 4, 1])) } else { None }));
                for st in c["in"].as_array().unwrap() {
                    NOW.store(st["at"].as_i64().unwrap(), Ordering::SeqCst);
                    if let Some(g) = st.get("forget") {
                        a.forget(&s(g));
                        continue;
                    }
                    a.handle(&Packet {
                        guest: s(&st["guest"]),
                        verdict: s(&st["verdict"]),
                        proto: s(&st["proto"]),
                        dst: ip(&hex(&s(&st["dst"]))),
                        dport: st["dport"].as_i64().unwrap(),
                        icmp: st["icmp"].as_i64().unwrap(),
                    });
                }
                let got: Vec<String> = rec
                    .events
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(k, g, det)| format!("{k}|{g}|{}", serde_json::to_string(det).unwrap()))
                    .collect();
                let want: Vec<String> = o
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|e| {
                                let det: std::collections::BTreeMap<String, String> =
                                    serde_json::from_value(e["detail"].clone()).unwrap_or_default();
                                format!("{}|{}|{}", s(&e["kind"]), s(&e["guest"]), serde_json::to_string(&det).unwrap())
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                d.eq("aggregator events", &got.join("\n"), &want.join("\n"));
            }
            other => panic!("unknown case {other}"),
        }
    }
    d.done("flows");
}
