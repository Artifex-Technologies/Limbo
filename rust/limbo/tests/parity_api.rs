//! testdata/parity/api.json: the route tables and handlers, request by request, against the Go handlers with the same
//! fakes (internal/api/parity_test.go).

mod common;
use common::{fixture, s, Diffs};
use limbo::api::{self, Actions, LicenseService, Peer, Principal, RunService, Server, SettingsStore};
use limbo::engine::{Engine, FakeRunner};
use limbo::events::Emitter;
use limbo::http::{Body, Request};
use limbo::manifest::Manifest;
use limbo::quarantine::Store;
use limbo::settings::Settings;
use limbo::{gojson, gotext, instances, license, Detail, Refusal};
use std::sync::{Arc, Mutex};

struct PActions {
    known: Vec<String>,
    defined: bool,
    hold_err: String,
    release_err: String,
    down_err: String,
    calls: Mutex<Vec<String>>,
}

impl Actions for PActions {
    fn guest(&self, name: &str) -> Result<Manifest, String> {
        if !self.known.iter().any(|k| k == name) {
            return Err(format!("engine: no record of a running guest {}", gotext::quote(name)));
        }
        Ok(Manifest { name: name.into(), ..Manifest::default() })
    }
    fn defined(&self, _: &Manifest) -> bool {
        self.defined
    }
    fn hold(&self, m: &Manifest, level: &str) -> Result<(), String> {
        self.calls.lock().unwrap().push(format!("hold:{}:{level}", m.name));
        if self.hold_err.is_empty() {
            Ok(())
        } else {
            Err(self.hold_err.clone())
        }
    }
    fn release(&self, m: &Manifest) -> Result<(), String> {
        self.calls.lock().unwrap().push(format!("release:{}", m.name));
        if self.release_err.is_empty() {
            Ok(())
        } else {
            Err(self.release_err.clone())
        }
    }
    fn down(&self, m: &Manifest) -> Result<(), String> {
        self.calls.lock().unwrap().push(format!("down:{}", m.name));
        if self.down_err.is_empty() {
            Ok(())
        } else {
            Err(self.down_err.clone())
        }
    }
}

struct PEvents {
    evs: Mutex<Vec<(String, String, Detail)>>,
    fail_after: usize,
}

impl Emitter for PEvents {
    fn emit(&self, kind: &str, guest: &str, d: Detail) -> std::io::Result<()> {
        let mut e = self.evs.lock().unwrap();
        if self.fail_after > 0 && e.len() >= self.fail_after {
            return Err(std::io::Error::other("disk full"));
        }
        e.push((kind.into(), guest.into(), d));
        Ok(())
    }
}

struct PRuns {
    stopped: Mutex<i64>,
}

fn coded(code: &str, msg: &str, remedy: &str) -> Refusal {
    Refusal::new(None, code, remedy, msg.into())
}

impl PRuns {
    fn start_any(&self, profile: &str) -> Result<String, Refusal> {
        match profile {
            "arch-update" => Ok("r00000001".into()),
            "busy" => Err(coded("busy", "2 validation runs are already in progress", "wait about a minute and retry")),
            "gone" => Err(coded("profile_unknown", "there is no profile named \"gone\"", "call limbo_profiles for the names that exist")),
            // Go's fake returns a plain error; the port's services only ever return coded ones, so the test codes it as
            // the API would show an uncoded one (no code of its own)
            _ => Err(Refusal { status: Some(0), code: String::new(), message: "unknown profile".into(), remedy: String::new(), short: String::new() }),
        }
    }
}

impl RunService for PRuns {
    fn profiles(&self) -> Vec<String> {
        vec!["arch-update".into()]
    }
    fn details_json(&self) -> String {
        r#"[{"max_seconds":900,"name":"arch-update","network":"none","passthrough":false,"sudo":true}]"#.into()
    }
    fn skipped_json(&self) -> String {
        r#"[{"code":"profile_invalid","name":"broken","reason":"the profile file is not valid JSON or has unknown fields","remedy":"ask the operator to fix the profile file"}]"#.into()
    }
    fn start(&self, profile: &str, _: &str, _: i64, _: Option<Vec<u8>>) -> Result<String, Refusal> {
        self.start_any(profile)
    }
    fn get_json(&self, id: &str) -> Option<String> {
        (id == "r00000001").then(|| format!(r#"{{"id":"{id}","status":"running"}}"#))
    }
    fn bundles(&self) -> bool {
        true
    }
    fn samples(&self) -> bool {
        true
    }
    fn start_sample(&self, profile: &str, _: &str, _: &str, _: i64) -> Result<String, Refusal> {
        self.start_any(profile)
    }
    fn stop_agent_runs(&self) -> i64 {
        let mut n = self.stopped.lock().unwrap();
        *n += 1;
        *n
    }
}

struct PSettings {
    s: Mutex<Settings>,
    err: String,
}

impl SettingsStore for PSettings {
    fn load(&self) -> (Settings, Option<String>) {
        if !self.err.is_empty() {
            return (Settings::default(), Some(self.err.clone()));
        }
        (*self.s.lock().unwrap(), None)
    }
    fn save(&self, s: Settings) -> std::io::Result<()> {
        *self.s.lock().unwrap() = s;
        Ok(())
    }
}

struct NoLicenses;

impl LicenseService for NoLicenses {
    fn list(&self) -> Result<Vec<license::Masked>, license::Error> {
        Ok(vec![])
    }
    fn add(&self, _: &str, _: &str) -> Result<license::Masked, license::Error> {
        Err(license::LErr::BadKey.into())
    }
    fn remove(&self, _: &str) -> Result<(), license::Error> {
        Err(license::LErr::NoLicense.into())
    }
    fn reveal(&self, _: &str) -> Result<String, license::Error> {
        Err(license::LErr::NoLicense.into())
    }
    fn assign(&self, _: &str, _: &str) -> Result<license::Masked, license::Error> {
        Err(license::LErr::NoLicense.into())
    }
    fn unassign(&self, _: &str, _: &str) -> Result<license::Masked, license::Error> {
        Err(license::LErr::NoLicense.into())
    }
}

fn tempdir() -> String {
    let p = std::env::temp_dir().join(format!("limbo-api-{}-{}", std::process::id(), limbo::sys::rand_hex(6)));
    std::fs::create_dir_all(&p).unwrap();
    p.to_string_lossy().into_owned()
}

/// Times in a body as Go's fixture writes them ("T"), and record ids by the order they first appear.
fn norm(x: &str, ids: &[String]) -> String {
    let mut x = x.to_string();
    for (i, id) in ids.iter().enumerate() {
        x = x.replace(id.as_str(), &format!("q-{:012}", i + 1));
    }
    // a JSON string holding an RFC 3339 UTC time ("2026-11-10T09:00:00.123Z", the zero time too) becomes "T"
    let is_time = |t: &str| {
        let b = t.as_bytes();
        b.len() >= 20
            && b[..4].iter().all(u8::is_ascii_digit)
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && t.ends_with('Z')
            && b[11..b.len() - 1].iter().all(|c| c.is_ascii_digit() || *c == b':' || *c == b'.')
    };
    let mut out = String::with_capacity(x.len());
    let mut rest = x.as_str();
    while let Some(q) = rest.find('"') {
        out.push_str(&rest[..q]);
        let after = &rest[q + 1..];
        match after.find('"') {
            Some(e) if is_time(&after[..e]) => {
                out.push_str("\"T\"");
                rest = &after[e + 1..];
            }
            _ => {
                out.push('"');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[test]
fn api_matches_go() {
    let mut d = Diffs::default();
    for c in fixture("api") {
        let sc = &c["in"];
        let dir = tempdir();
        let store = Arc::new(Store::open(&format!("{dir}/q")).unwrap());
        let known: Vec<String> = sc["known"].as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default();
        let actions = Arc::new(PActions {
            known,
            defined: sc["defined"].as_bool().unwrap(),
            hold_err: s(&sc["hold_err"]),
            release_err: s(&sc["release_err"]),
            down_err: s(&sc["down_err"]),
            calls: Mutex::new(vec![]),
        });
        let ev = Arc::new(PEvents { evs: Mutex::new(vec![]), fail_after: sc["fail_after"].as_u64().unwrap() as usize });
        let runner = Arc::new(FakeRunner::default());
        runner.fail.lock().unwrap().insert(String::new(), "no runner".into());
        let eng = Arc::new(Engine::new(runner, ev.clone(), &format!("{dir}/state")));
        let mut inst = instances::Service::new(&format!("{dir}/instances"), &format!("{dir}/state"), &dir, &format!("{dir}/exchange"), eng);
        inst.holds = Some(store.clone());
        inst.events = Some(ev.clone());
        let srv = Server {
            store: store.clone(),
            actions: actions.clone(),
            events: ev.clone(),
            runs: if sc["no_runs"].as_bool().unwrap() { None } else { Some(Arc::new(PRuns { stopped: Mutex::new(0) })) },
            instances: Some(Arc::new(inst)),
            licenses: Some(Arc::new(NoLicenses)),
            settings: Some(Arc::new(PSettings { s: Mutex::new(Settings { ask_password: sc["ask"].as_bool().unwrap() }), err: s(&sc["settings_err"]) })),
            exchange: Some(Arc::new(limbo::exchange::Service {
                root: format!("{dir}/exchange"),
                scratch: String::new(),
                held: String::new(),
                scanner: None,
                events: None,
            })),
            kvm: || false,
        };
        let mut ids: Vec<String> = vec![];
        let name = s(&sc["name"]);
        let want_steps = c["out"]["steps"].as_array().unwrap();
        for (i, st) in sc["steps"].as_array().unwrap().iter().enumerate() {
            let mut path = s(&st["path"]);
            for (k, id) in ids.iter().enumerate() {
                path = path.replace(&format!("{{q{}}}", k + 1), id);
            }
            let raw_path = path.split('?').next().unwrap().to_string();
            let body = s(&st["body"]).into_bytes();
            let too_large = body.len() > limbo::http::MAX_BODY;
            let req = Request { method: s(&st["method"]), raw_path, body, body_too_large: too_large };
            let p = match s(&st["p"]).as_str() {
                "admin" => Principal::Admin,
                "control" => Principal::Control,
                "agent" => Principal::Agent,
                _ => Principal::User,
            };
            let resp = srv.handle(p, Peer::default(), &req);
            let got_body = match &resp.body {
                Body::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
                Body::File(..) => "<file>".into(),
            };
            let mut k = 0;
            while let Some(at) = got_body[k..].find("q-") {
                let at = k + at;
                let cand = &got_body[at..(at + 14).min(got_body.len())];
                if cand.len() == 14 && cand[2..].bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) && cand != "q-ffffffffffff" && !ids.iter().any(|x| x == cand) {
                    ids.push(cand.to_string());
                }
                k = at + 2;
            }
            let w = &want_steps[i];
            let what = format!("{name} #{i} {} {} {} {}", s(&st["p"]), s(&st["method"]), s(&st["path"]), s(&st["body"]).chars().take(80).collect::<String>());
            d.eq(&format!("status of {what}"), &resp.status.to_string(), &w["status"].to_string());
            d.eq(&format!("body of {what}"), &norm(&got_body, &ids), &s(&w["body"]));
            d.eq(&format!("content type of {what}"), resp.header("Content-Type").unwrap_or(""), &s(&w["content_type"]));
            d.eq(&format!("allow of {what}"), resp.header("Allow").unwrap_or(""), &s(&w["allow"]));
            d.eq(&format!("location of {what}"), resp.header("Location").unwrap_or(""), &s(&w["location"]));
        }
        let evs = ev.evs.lock().unwrap();
        let got = if evs.is_empty() {
            "null".to_string()
        } else {
            let items: Vec<String> = evs
                .iter()
                .map(|(k, g, det)| gojson::Obj::new().raw("detail", &gojson::map(det)).str("guest", g).str("kind", k).end())
                .collect();
            gojson::list(&items)
        };
        d.eq(&format!("events of {name}"), &norm(&got, &ids), &s(&c["out"]["events"]));
        let calls = actions.calls.lock().unwrap().clone();
        let want_calls: Vec<String> = c["out"]["calls"].as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default();
        d.eq(&format!("actions of {name}"), &calls.join(","), &want_calls.join(","));
        let _ = std::fs::remove_dir_all(&dir);
    }
    d.done("api");
    let _ = api::VERSION;
}
