//! LIM-22 and YGG-139: a new instance's processors and memory are set by root through `POST /v1/settings/defaults`
//! (admin.sock only), logged before they are saved, shown in the status when set, and kept when the password switch
//! changes.

use limbo::api::{EngineActions, Peer, Principal, Server, SettingsStore};
use limbo::engine::{Engine, FakeRunner};
use limbo::events::Emitter;
use limbo::http::{Body, Request};
use limbo::quarantine::Store;
use limbo::settings::Settings;
use limbo::{instances, Detail};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Events(Mutex<Vec<(String, Detail)>>);

impl Emitter for Events {
    fn emit(&self, kind: &str, _: &str, d: Detail) -> std::io::Result<()> {
        self.0.lock().unwrap().push((kind.into(), d));
        Ok(())
    }
}

#[derive(Default)]
struct File(Mutex<Settings>);

impl SettingsStore for File {
    fn load(&self) -> (Settings, Option<String>) {
        (*self.0.lock().unwrap(), None)
    }
    fn save(&self, s: Settings) -> std::io::Result<()> {
        *self.0.lock().unwrap() = s;
        Ok(())
    }
}

#[test]
fn root_sets_a_new_instances_defaults() {
    let dir = std::env::temp_dir().join(format!("limbo-defaults-api-{}-{}", std::process::id(), limbo::sys::rand_hex(4)));
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let d = dir.to_string_lossy().into_owned();
    let ev = Arc::new(Events::default());
    let runner = Arc::new(FakeRunner::default());
    let eng = Arc::new(Engine::new(runner, ev.clone(), &format!("{d}/state")));
    let inst = instances::Service::new(&format!("{d}/instances"), &format!("{d}/state"), &d, &format!("{d}/exchange"), eng.clone());
    let file = Arc::new(File(Mutex::new(Settings { ask_password: false, ..Default::default() })));
    let srv = Server {
        store: Arc::new(Store::open(&format!("{d}/q")).unwrap()),
        actions: Arc::new(EngineActions(eng)),
        events: ev.clone(),
        runs: None,
        instances: Some(Arc::new(inst)),
        licenses: None,
        settings: Some(file.clone()),
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

    // unset: the status is as Go wrote it
    let (_, st) = ask(Principal::User, "GET", "/v1/status", "");
    assert!(!st.contains("default_"), "{st}");
    // root sets them; it is logged and saved
    let (code, body) = ask(Principal::Admin, "POST", "/v1/settings/defaults", r#"{"default_cpus":4,"default_memory_mb":8192}"#);
    assert_eq!((code, body.trim()), (200, r#"{"default_cpus":4,"default_memory_mb":8192}"#));
    let saved = *file.0.lock().unwrap();
    assert_eq!((saved.default_cpus, saved.default_memory_mb), (4, 8192));
    let logged = ev.0.lock().unwrap().iter().any(|(k, d)| k == "settings.change" && d.get("default_cpus").map(String::as_str) == Some("4"));
    assert!(logged);
    let (_, st) = ask(Principal::User, "GET", "/v1/status", "");
    assert!(st.contains(r#""ask_password":false,"default_cpus":4,"default_memory_mb":8192,"#), "{st}");
    // the switch keeps them
    let (code, _) = ask(Principal::Admin, "POST", "/v1/settings", r#"{"ask_password":true}"#);
    assert_eq!(code, 200);
    assert_eq!(*file.0.lock().unwrap(), Settings { ask_password: true, default_cpus: 4, default_memory_mb: 8192 });
    // not on user.sock; out of range, or one missing, refused; 0 0 is Limbo's own again
    let (code, _) = ask(Principal::User, "POST", "/v1/settings/defaults", r#"{"default_cpus":1,"default_memory_mb":1024}"#);
    assert!(code == 404 || code == 405, "{code}");
    for bad in [r#"{"default_cpus":65,"default_memory_mb":0}"#, r#"{"default_cpus":0,"default_memory_mb":100}"#, r#"{"default_cpus":2}"#] {
        let (code, body) = ask(Principal::Admin, "POST", "/v1/settings/defaults", bad);
        assert_eq!(code, 400, "{bad}: {body}");
    }
    assert_eq!(file.0.lock().unwrap().default_cpus, 4, "a refused request changes nothing");
    let (code, _) = ask(Principal::Admin, "POST", "/v1/settings/defaults", r#"{"default_cpus":0,"default_memory_mb":0}"#);
    assert_eq!(code, 200);
    let (_, st) = ask(Principal::User, "GET", "/v1/status", "");
    assert!(!st.contains("default_"), "{st}");
    let _ = std::fs::remove_dir_all(&dir);
}
