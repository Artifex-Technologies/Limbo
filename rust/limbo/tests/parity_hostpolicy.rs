//! testdata/parity/hostpolicy.json: Check, Ready, Standing, HostID, Before and After on fake hosts (a sysfs tree,
//! os-release, the host policy, an approval file, the reboot marker, open files and drivers), as the Go code answers
//! (internal/hostpolicy/parity_test.go: every case of the package's tests, then 120 generated hosts).

mod common;
use common::{fixture, s, Diffs};
use limbo::gotime::Time;
use limbo::hostpolicy::{Policy, Refused};
use limbo::manifest::{Devices, Manifest};
use serde_json::Value;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

/// The scenario's clock, in Unix nanoseconds (one #[test] walks the scenarios in turn).
static NOW: AtomicI64 = AtomicI64::new(0);

fn now() -> Time {
    let n = NOW.load(Ordering::SeqCst);
    Time::from_unix(n.div_euclid(1_000_000_000), n.rem_euclid(1_000_000_000) as u32)
}

fn strings(v: &Value) -> Option<Vec<String>> {
    v.as_array().map(|a| a.iter().map(s).collect())
}

fn smap(v: &Value) -> BTreeMap<String, String> {
    v.as_object().map(|o| o.iter().map(|(k, x)| (k.clone(), s(x))).collect()).unwrap_or_default()
}

fn kind(r: &Result<(), Refused>) -> (&'static str, String) {
    match r {
        Ok(()) => ("", String::new()),
        Err(e @ Refused::Denied(_)) => ("denied", e.to_string()),
        Err(e @ Refused::NeedsApproval) => ("needs_approval", e.to_string()),
        Err(e @ Refused::Busy(_)) => ("busy", e.to_string()),
        Err(e @ Refused::RebootNeeded) => ("reboot", e.to_string()),
    }
}

fn tempdir(tag: &str) -> String {
    let p = std::env::temp_dir().join(format!("limbo-hp-{tag}-{}-{}", std::process::id(), limbo::sys::rand_hex(4)));
    std::fs::create_dir_all(&p).unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn hostpolicy_matches_go() {
    let mut d = Diffs::default();
    for c in fixture("hostpolicy") {
        let sc = &c["in"];
        let name = s(&sc["name"]);
        let (root, state, run) = (tempdir("root"), tempdir("state"), tempdir("run"));
        for (path, body) in sc["files"].as_object().unwrap() {
            let p = format!("{root}/{path}");
            std::fs::create_dir_all(std::path::Path::new(&p).parent().unwrap()).unwrap();
            std::fs::write(&p, s(body)).unwrap();
        }
        if let Some(a) = sc["approval"].as_object() {
            let p = format!("{state}/passthrough-approval.json");
            std::fs::write(&p, s(&a["body"])).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(a["mode"].as_u64().unwrap() as u32)).unwrap();
        }
        if sc["blocked"].as_bool().unwrap() {
            std::fs::write(format!("{run}/passthrough.blocked"), "earlier run\n").unwrap();
        }
        let t = Time::parse_rfc3339(&s(&sc["now"])).unwrap();
        NOW.store(t.unix_nanos() as i64, Ordering::SeqCst);
        let open: BTreeMap<String, Vec<String>> = sc["open"]
            .as_object()
            .map(|o| o.iter().map(|(k, v)| (k.clone(), strings(v).unwrap_or_default())).collect())
            .unwrap_or_default();
        let drv = Arc::new(Mutex::new(smap(&sc["drv"])));
        let usb_drv = smap(&sc["usb_drv"]);
        let mut p = Policy::new(&state, &run);
        p.root = root.clone();
        p.now = now;
        p.open_files = Some(Box::new(move || open.clone()));
        let drv2 = drv.clone();
        p.driver = Some(Box::new(move |a: &str| drv2.lock().unwrap().get(a).cloned().unwrap_or_default()));
        p.usb_driver = Some(Box::new(move |i: &str| usb_drv.get(i).cloned().unwrap_or_default()));

        let want = c["out"].as_array().unwrap();
        for (i, st) in sc["steps"].as_array().unwrap().iter().enumerate() {
            NOW.fetch_add(st["advance_seconds"].as_i64().unwrap() * 1_000_000_000, Ordering::SeqCst);
            let m = Manifest { devices: Devices { pci: strings(&st["pci"]), usb: strings(&st["usb"]) }, ..Manifest::default() };
            let w = &want[i];
            let what = format!("{name} #{i} {} pci={} usb={}", s(&st["op"]), st["pci"], st["usb"]);
            match s(&st["op"]).as_str() {
                "check" | "ready" => {
                    let r = if s(&st["op"]) == "check" { p.check(&m) } else { p.ready(&m) };
                    let (k, e) = kind(&r);
                    d.eq(&format!("kind of {what}"), k, &s(&w["kind"]));
                    d.eq(&format!("error of {what}"), &e, &s(&w["err"]));
                }
                "standing" => {
                    let (st_, ig) = p.standing();
                    d.eq(&format!("standing of {what}"), &st_.join(","), &s(&w["standing"]));
                    d.eq(&format!("ignored of {what}"), &ig.join(","), &s(&w["ignored"]));
                }
                "host_id" => d.eq(&what, &p.host_id(), &s(&w["id"])),
                "after" => {
                    let before = p.before(&m);
                    d.eq(&format!("before of {what}"), &limbo::gojson::map(&before), &s(&w["before"]));
                    *drv.lock().unwrap() = smap(&st["drv_after"]);
                    let r = p.after(&m, if st["no_record"].as_bool().unwrap() { None } else { Some(&before) });
                    d.eq(&format!("after of {what}"), &r.err().unwrap_or_default(), &s(&w["err"]));
                }
                op => panic!("unknown op {op}"),
            }
            d.eq(&format!("blocked after {what}"), &p.blocked().to_string(), &w["blocked"].to_string());
        }
        for dir in [&root, &state, &run] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    d.done("hostpolicy");
}
