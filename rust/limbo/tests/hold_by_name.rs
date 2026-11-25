//! LIM-5: a guest whose manifest copy in the state folder is gone can still be held by name, from what the hypervisor still
//! has; a release (loosening) still needs the copy, and nothing is held for a name the hypervisor does not know.

use limbo::api::{Actions, EngineActions, Peer, Principal, Server};
use limbo::engine::{Engine, FakeRunner};
use limbo::events::Emitter;
use limbo::http::{Body, Request};
use limbo::quarantine::Store;
use limbo::Detail;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Events(Mutex<Vec<(String, String)>>);

impl Emitter for Events {
    fn emit(&self, kind: &str, guest: &str, _: Detail) -> std::io::Result<()> {
        self.0.lock().unwrap().push((kind.into(), guest.into()));
        Ok(())
    }
}

fn tempdir() -> String {
    let p = std::env::temp_dir().join(format!("limbo-hold-{}-{}", std::process::id(), limbo::sys::rand_hex(6)));
    std::fs::create_dir_all(p.join("state")).unwrap();
    p.to_string_lossy().into_owned()
}

/// The commands the engine ran, one line each, with what it fed nft.
fn calls(r: &FakeRunner) -> Vec<String> {
    r.calls
        .lock()
        .unwrap()
        .iter()
        .map(|(n, a, stdin)| format!("{n} {}{}", a.join(" "), if stdin.is_empty() { "" } else { " <stdin>" }))
        .collect()
}

#[test]
fn a_guest_without_its_manifest_copy_is_held_by_name() {
    let dir = tempdir();
    let runner = Arc::new(FakeRunner::default());
    // "ghost" is no guest the hypervisor has; "lab" is one, but its manifest copy was removed (no file in state/)
    runner.fail.lock().unwrap().insert("virsh -c qemu:///system dominfo limbo-ghost".into(), "error: failed to get domain".into());
    let ev = Arc::new(Events::default());
    let eng = Arc::new(Engine::new(runner.clone(), ev.clone(), &format!("{dir}/state")));
    let actions = EngineActions(eng);

    // a release still has no record to go on; a hold has the name
    assert!(actions.guest("lab").unwrap_err().contains("no record of a running guest"));
    let m = actions.guest_to_hold("lab").unwrap();
    assert_eq!(m.name, "lab");
    assert!(actions.guest_to_hold("ghost").unwrap_err().contains("no record of a running guest \"ghost\""));
    assert!(actions.guest_to_hold("Bad/name").is_err());

    // isolating by name: the deny-all table for the guest's bridge, and its link down
    runner.calls.lock().unwrap().clear();
    actions.hold(&m, "isolate").unwrap();
    let c = calls(&runner);
    assert_eq!(c, ["nft -f - <stdin>", "virsh -c qemu:///system domif-setlink limbo-lab vl-lab down"]);
    let rules = runner.calls.lock().unwrap()[0].2.clone();
    assert!(rules.starts_with("table inet limbo_lab\ndelete table inet limbo_lab\n"), "{rules}");
    assert!(rules.contains("iifname \"lb-lab\" goto blocked"), "{rules}");
    assert!(!rules.contains("iifname \"lb-lab\" accept"), "{rules}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn heimdalls_hold_applies_and_only_a_teardown_ends_it() {
    let dir = tempdir();
    let runner = Arc::new(FakeRunner::default());
    runner.fail.lock().unwrap().insert("virsh -c qemu:///system dominfo limbo-ghost".into(), "error: failed to get domain".into());
    let ev = Arc::new(Events::default());
    let eng = Arc::new(Engine::new(runner.clone(), ev.clone(), &format!("{dir}/state")));
    let srv = Server {
        store: Arc::new(Store::open(&format!("{dir}/q")).unwrap()),
        actions: Arc::new(EngineActions(eng)),
        events: ev.clone(),
        runs: None,
        instances: None,
        licenses: None,
        settings: None,
        exchange: None,
        kvm: || false,
    };
    let ask = |p: Principal, method: &str, path: &str, body: &str| {
        let req = Request { method: method.into(), raw_path: path.into(), body: body.as_bytes().to_vec(), body_too_large: false };
        let r = srv.handle(p, Peer::default(), &req);
        let b = match &r.body {
            Body::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            Body::File(..) => "<file>".into(),
        };
        (r.status, b)
    };

    // Heimdall asks first whether the guest exists (it skips the hold for one that does not)
    let (st, body) = ask(Principal::Control, "GET", "/v1/guests/lab", "");
    assert_eq!((st, body), (200, r#"{"exists":true,"name":"lab"}"#.to_string() + "\n"));
    let (st, body) = ask(Principal::Control, "GET", "/v1/guests/ghost", "");
    assert_eq!((st, body), (404, r#"{"exists":false}"#.to_string() + "\n"));

    // Heimdall's hold on the control socket: recorded and applied, by name
    let (st, body) = ask(Principal::Control, "POST", "/v1/quarantine", r#"{"guest":"lab","reason":"probed the host","level":"isolate"}"#);
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"applied\":true"), "{body}");
    let id = body.split("\"id\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    assert!(calls(&runner).iter().any(|c| c == "virsh -c qemu:///system domif-setlink limbo-lab vl-lab down"));
    assert!(ev.0.lock().unwrap().iter().any(|(k, g)| k == "policy.restrict" && g == "lab"));

    // a name the hypervisor does not have: refused as before, nothing recorded
    let (st, body) = ask(Principal::Control, "POST", "/v1/quarantine", r#"{"guest":"ghost","reason":"x"}"#);
    assert_eq!(st, 404, "{body}");

    // the record cannot be closed while the guest exists
    let (st, body) = ask(Principal::Admin, "POST", &format!("/v1/quarantine/{id}/close"), r#"{"by":"root"}"#);
    assert_eq!(st, 409, "{body}");

    // a "safe" verdict cannot lift what it has no record of: nothing is loosened
    runner.calls.lock().unwrap().clear();
    let (st, body) = ask(Principal::Admin, "POST", &format!("/v1/quarantine/{id}/verdict"), r#"{"verdict":"safe","by":"root"}"#);
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"applied\":false"), "{body}");
    assert!(calls(&runner).iter().all(|c| !c.contains(" up") && !c.starts_with("nft")), "{:?}", calls(&runner));

    // a second hold, found dangerous: isolated by name
    let (_, body) = ask(Principal::Control, "POST", "/v1/quarantine", r#"{"guest":"lab","reason":"again"}"#);
    let id = body.split("\"id\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    runner.calls.lock().unwrap().clear();
    let (st, body) = ask(Principal::Admin, "POST", &format!("/v1/quarantine/{id}/verdict"), r#"{"verdict":"dangerous","by":"root"}"#);
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"applied\":true"), "{body}");
    assert!(calls(&runner).iter().any(|c| c == "virsh -c qemu:///system domif-setlink limbo-lab vl-lab down"));
    let _ = std::fs::remove_dir_all(&dir);
}
