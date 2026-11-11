//! testdata/parity/hostpolicy.json: Check, Ready, Standing, HostID, Before and After on fake hosts (a sysfs tree,
//! os-release, the host policy, the boot id, an approval file, the reboot markers, open files and drivers), with the
//! daemon restarted (the run folder emptied, as systemd does at every stop), the host rebooted (a new boot id) and the
//! markers cleared between questions, as the Go code answers (internal/hostpolicy/parity_test.go: every case of the
//! package's tests, then 120 generated hosts). After each step the markers' bytes are compared too.

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

/// A marker file's bytes, or "<none>".
fn marker_text(path: &str) -> String {
    match std::fs::read(path) {
        Ok(b) => String::from_utf8(b).expect("the fixtures' markers are UTF-8"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "<none>".into(),
        Err(_) => "<unreadable>".into(),
    }
}

/// A Policy on these folders, as a newly started daemon makes it.
fn start(
    root: &str,
    state: &str,
    run: &str,
    open: &BTreeMap<String, Vec<String>>,
    drv: &Arc<Mutex<BTreeMap<String, String>>>,
    usb_drv: &BTreeMap<String, String>,
) -> Policy {
    let mut p = Policy::new(state, run);
    p.root = root.to_string();
    p.now = now;
    let open = open.clone();
    p.open_files = Some(Box::new(move || open.clone()));
    let drv = drv.clone();
    p.driver = Some(Box::new(move |a: &str| drv.lock().unwrap().get(a).cloned().unwrap_or_default()));
    let usb_drv = usb_drv.clone();
    p.usb_driver = Some(Box::new(move |i: &str| usb_drv.get(i).cloned().unwrap_or_default()));
    p
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
        let t = Time::parse_rfc3339(&s(&sc["now"])).unwrap();
        NOW.store(t.unix_nanos() as i64, Ordering::SeqCst);
        let open: BTreeMap<String, Vec<String>> = sc["open"]
            .as_object()
            .map(|o| o.iter().map(|(k, v)| (k.clone(), strings(v).unwrap_or_default())).collect())
            .unwrap_or_default();
        let drv = Arc::new(Mutex::new(smap(&sc["drv"])));
        let usb_drv = smap(&sc["usb_drv"]);
        let mut p = start(&root, &state, &run, &open, &drv, &usb_drv);
        if sc["blocked"].as_bool().unwrap() {
            p.block("earlier run");
        }
        let (marker, run_marker) = (format!("{state}/passthrough.blocked"), format!("{run}/passthrough.blocked"));
        for (path, body) in [(&marker, &sc["marker"]), (&run_marker, &sc["run_marker"])] {
            if let Some(b) = body.as_str() {
                std::fs::write(path, b).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }

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
                op @ ("restart" | "reboot") => {
                    std::fs::remove_dir_all(&run).unwrap();
                    std::fs::create_dir(&run).unwrap();
                    if op == "reboot" {
                        // every device back under the driver it boots with, and a new boot id
                        *drv.lock().unwrap() = smap(&sc["drv"]);
                        let id = format!("{root}/proc/sys/kernel/random/boot_id");
                        let _ = std::fs::remove_file(&id);
                        if s(&st["boot_id"]) != "-" {
                            std::fs::create_dir_all(std::path::Path::new(&id).parent().unwrap()).unwrap();
                            std::fs::write(&id, format!("{}\n", s(&st["boot_id"]))).unwrap();
                        }
                    }
                    p = start(&root, &state, &run, &open, &drv, &usb_drv);
                }
                "clear" => d.eq(&format!("clear of {what}"), &p.clear().err().unwrap_or_default(), &s(&w["err"])),
                op => panic!("unknown op {op}"),
            }
            d.eq(&format!("blocked after {what}"), &p.blocked().to_string(), &w["blocked"].to_string());
            d.eq(&format!("state marker after {what}"), &marker_text(&marker), &s(&w["marker"]));
            d.eq(&format!("run marker after {what}"), &marker_text(&run_marker), &s(&w["run_marker"]));
        }
        for dir in [&root, &state, &run] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    d.done("hostpolicy");
}
