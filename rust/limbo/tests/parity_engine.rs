//! testdata/parity/engine.json: the commands, stdin, events and files of up, down, holds and release.

mod common;
use common::{fixture, s, Diffs};
use limbo::engine::{Ctx, Engine, FakeRunner};
use limbo::events::Recorder;
use limbo::quarantine::{Holder, Record};
use limbo::virt::Subnets;
use limbo::{manifest, sys, virt};
use std::sync::{Arc, Mutex};

struct Held(Option<Record>);
impl Holder for Held {
    fn holding(&self, _: &str) -> Option<Record> {
        self.0.clone()
    }
}

static IN_USE: Mutex<Vec<i64>> = Mutex::new(Vec::new());
fn in_use() -> Vec<i64> {
    IN_USE.lock().unwrap().clone()
}

fn tempdir() -> String {
    let p = std::env::temp_dir().join(format!("limbo-e-{}-{}", std::process::id(), sys::rand_hex(6)));
    std::fs::create_dir_all(&p).unwrap();
    p.to_string_lossy().into_owned()
}

fn walk(dir: &str, out: &mut Vec<String>, norm: &dyn Fn(&str) -> String) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path().to_string_lossy().into_owned();
        let ft = e.file_type().unwrap();
        if ft.is_dir() {
            walk(&p, out, norm);
        } else if !p.ends_with(".lock") {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            let body = String::from_utf8_lossy(&std::fs::read(&p).unwrap()).into_owned();
            out.push(format!("{} {:o}\n{}", norm(&p), mode, norm(&body)));
        }
    }
}

#[test]
fn engine_matches_go() {
    let mut d = Diffs::default();
    for c in fixture("engine") {
        let sc = &c["in"];
        let dir = tempdir();
        let norm = |x: &str| x.replace(&dir, "$T");
        let bytes = s(&sc["image_bytes"]);
        let bytes = if bytes.is_empty() { "abc".to_string() } else { bytes };
        if bytes != "-" {
            sys::write_file(format!("{dir}/a.img"), bytes.as_bytes(), 0o600).unwrap();
        }
        let mut m = manifest::parse(s(&sc["manifest"]).replace("$T", &dir).as_bytes()).unwrap();
        let runner = Arc::new(FakeRunner::default());
        let fail = s(&sc["fail_on"]);
        if !fail.is_empty() {
            runner.fail.lock().unwrap().insert(fail.clone(), "boom".into());
        }
        let ev = Arc::new(Recorder::default());
        let mut e = Engine::new(runner.clone(), ev.clone(), &format!("{dir}/state"));
        if sc["ufw"].as_bool().unwrap() {
            e.ufw_active = Some(|| true);
        }
        if sc["subnets"].as_bool().unwrap() {
            *IN_USE.lock().unwrap() = sc["in_use"].as_array().map(|a| a.iter().map(|x| x.as_i64().unwrap()).collect()).unwrap_or_default();
            e.subnets = Some(Subnets { path: format!("{dir}/state/subnets.json"), in_use: Some(in_use) });
        }
        if sc["exchange"].as_bool().unwrap() {
            e.exchange_root = format!("{dir}/exchange");
        }
        let held = s(&sc["held"]);
        if !held.is_empty() {
            e.holds = Some(Arc::new(Held(Some(Record { id: "q-0123456789ab".into(), status: held, ..Record::default() }))));
        }
        if sc["overlay"].as_bool().unwrap() {
            std::fs::create_dir_all(format!("{dir}/state")).unwrap();
            sys::write_file(format!("{dir}/state/{}", virt::overlay_name(&m)), b"overlay", 0o600).unwrap();
        }
        let ctx = Ctx::background();
        let o = &c["out"];
        let op = s(&sc["op"]);
        let err = match op.as_str() {
            "up" => {
                let r = e.up(&ctx, &mut m);
                d.eq("subnet", &m.subnet.to_string(), &o["subnet"].to_string());
                r.err().map(|x| x.to_string())
            }
            "down" => e.down(&ctx, &m).err().map(|x| x.to_string()),
            "hold-restrict" => e.hold(&ctx, &m, "restrict").err().map(|x| x.to_string()),
            "hold-isolate" => e.hold(&ctx, &m, "isolate").err().map(|x| x.to_string()),
            "hold-bogus" => e.hold(&ctx, &m, "bogus").err().map(|x| x.to_string()),
            "release" => e.release(&ctx, &m).err().map(|x| x.to_string()),
            "defined" => {
                d.eq("defined", &e.defined(&ctx, &m).to_string(), &o["defined"].to_string());
                None
            }
            x => panic!("op {x}"),
        };
        let what = format!("{op} fail_on={fail:?} {}", s(&sc["manifest"]).chars().skip(150).take(120).collect::<String>());
        d.eq(&format!("error of {what}"), &norm(&err.unwrap_or_default()), &s(&o["error"]));
        let calls: Vec<String> = runner.calls.lock().unwrap().iter().map(|(n, a, stdin)| norm(&format!("{n} {}\n{stdin}", a.join(" ")))).collect();
        let want: Vec<String> = o["calls"].as_array().map(|a| a.iter().map(|c| format!("{}\n{}", s(&c["cmd"]), s(&c["stdin"]))).collect()).unwrap_or_default();
        d.eq(&format!("calls of {what}"), &calls.join("\n--\n"), &want.join("\n--\n"));
        let evs: Vec<String> = ev
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|(k, g, det)| {
                let det: std::collections::BTreeMap<String, String> = det.iter().map(|(a, b)| (a.clone(), norm(b))).collect();
                format!("{k}|{g}|{}", serde_json::to_string(&det).unwrap())
            })
            .collect();
        let want: Vec<String> = o["events"].as_array().cloned().unwrap_or_default()
            .iter()
            .map(|x| {
                let det: std::collections::BTreeMap<String, String> = serde_json::from_value(x["detail"].clone()).unwrap_or_default();
                format!("{}|{}|{}", s(&x["kind"]), s(&x["guest"]), serde_json::to_string(&det).unwrap())
            })
            .collect();
        d.eq(&format!("events of {what}"), &evs.join("\n"), &want.join("\n"));
        let mut files = vec![];
        walk(&dir, &mut files, &norm);
        files.sort();
        let want: Vec<String> = o["files"].as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default();
        d.eq(&format!("files of {what}"), &files.join("\n--\n"), &want.join("\n--\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }
    d.done("engine");
}
