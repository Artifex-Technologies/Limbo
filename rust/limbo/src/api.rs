//! Limbo's local control surface (Go: internal/api). One route table per principal, each holding only the routes that
//! principal may use: a route a principal may not use does not exist on its socket (404), rather than existing and being
//! refused. Which principal a caller is comes from the socket it reached; the peer's uid and pid are evidence in the
//! audit log, not access control.
//!
//! The rule that matters most: control.sock (Heimdall) and agent.sock (Sarina) have no route that loosens. `routes` is
//! the one place the tables are made; `loosening_free` states the property, a Kani harness proves it over every service
//! combination, and the tests check it exhaustively.

use crate::events::{self, Emitter};
use crate::gojson::{self, Obj};
use crate::http::{self, Body, Request, Response, Route};
use crate::instances::{self, Caller, Change};
use crate::license::{self, LErr};
use crate::manifest::{self, Manifest};
use crate::quarantine::{self, QErr, Store};
use crate::{detail, go_struct, gotext, sys, Detail, Refusal};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Reported by GET /v1/status; the Go limbo's version string, so the Settings page sees the same daemon contract.
pub const VERSION: &str = "0.1.0-dev";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Principal {
    Admin,
    Control,
    Agent,
    User,
}

impl Principal {
    pub fn as_str(self) -> &'static str {
        match self {
            Principal::Admin => "admin",
            Principal::Control => "control",
            Principal::Agent => "agent",
            Principal::User => "user",
        }
    }
}

/// What a route is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum R {
    QOpen,
    QList,
    QGet,
    QRaise,
    QAdvisory,
    GuestExists,
    QVerdict,
    QClose,
    GuestDown,
    SampleRun,
    RunGet,
    AgentRunsStop,
    Status,
    GetSettings,
    ListInstances,
    GetInstance,
    StartInstance,
    StopInstance,
    ConfigureInstance,
    FreeSpace,
    ListLicenses,
    AssignLicense,
    UnassignLicense,
    PutSettings,
    AddInstance,
    RemoveInstance,
    AddLicense,
    RemoveLicense,
    RevealLicense,
    ListExchange,
    TakeExchange,
    Profiles,
    StartRun,
}

/// Which services the daemon has (each may be absent, and then its routes do not exist).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Present {
    pub runs: bool,
    pub samples: bool,
    pub instances: bool,
    pub licenses: bool,
    pub exchange: bool,
}

const fn rt(method: &'static str, pattern: &'static str, id: R) -> Route<R> {
    Route { method, pattern, id }
}

/// The route table of one principal (Go: Server.Handler, settingsRoutes, exchangeRoutes).
pub fn routes(p: Principal, s: Present) -> Vec<Route<R>> {
    use Principal::*;
    let mut v = vec![];
    if p == Control || p == Admin {
        v.push(rt("POST", "/v1/quarantine", R::QOpen));
        v.push(rt("GET", "/v1/quarantine", R::QList));
        v.push(rt("GET", "/v1/quarantine/{id}", R::QGet));
        v.push(rt("POST", "/v1/quarantine/{id}/raise", R::QRaise));
        v.push(rt("POST", "/v1/quarantine/{id}/advisory", R::QAdvisory));
        v.push(rt("GET", "/v1/guests/{name}", R::GuestExists));
    }
    if p == Admin {
        v.push(rt("POST", "/v1/quarantine/{id}/verdict", R::QVerdict));
        v.push(rt("POST", "/v1/quarantine/{id}/close", R::QClose));
        v.push(rt("POST", "/v1/guests/{name}/down", R::GuestDown));
        if s.runs && s.samples {
            v.push(rt("POST", "/v1/sample-runs", R::SampleRun));
            v.push(rt("GET", "/v1/runs/{id}", R::RunGet));
            v.push(rt("POST", "/v1/agent-runs/stop", R::AgentRunsStop));
        }
    }
    if p == User || p == Admin {
        if s.instances {
            v.push(rt("GET", "/v1/status", R::Status));
            v.push(rt("GET", "/v1/settings", R::GetSettings));
            v.push(rt("GET", "/v1/instances", R::ListInstances));
            v.push(rt("GET", "/v1/instances/{name}", R::GetInstance));
            v.push(rt("POST", "/v1/instances/{name}/start", R::StartInstance));
            v.push(rt("POST", "/v1/instances/{name}/stop", R::StopInstance));
            v.push(rt("POST", "/v1/instances/{name}/settings", R::ConfigureInstance));
            v.push(rt("POST", "/v1/instances/{name}/free-space", R::FreeSpace));
        }
        if s.licenses {
            v.push(rt("GET", "/v1/licenses", R::ListLicenses));
            v.push(rt("POST", "/v1/licenses/{id}/assign", R::AssignLicense));
            v.push(rt("POST", "/v1/licenses/{id}/unassign", R::UnassignLicense));
        }
        if p == Admin {
            v.push(rt("POST", "/v1/settings", R::PutSettings));
            if s.instances {
                v.push(rt("POST", "/v1/instances", R::AddInstance));
                v.push(rt("DELETE", "/v1/instances/{name}", R::RemoveInstance));
            }
            if s.licenses {
                v.push(rt("POST", "/v1/licenses", R::AddLicense));
                v.push(rt("DELETE", "/v1/licenses/{id}", R::RemoveLicense));
                v.push(rt("GET", "/v1/licenses/{id}/key", R::RevealLicense));
            }
        }
        if s.exchange {
            v.push(rt("GET", "/v1/exchange/{guest}", R::ListExchange));
            v.push(rt("POST", "/v1/exchange/{guest}/take", R::TakeExchange));
        }
    }
    if p == Agent && s.runs {
        v.push(rt("GET", "/v1/profiles", R::Profiles));
        v.push(rt("POST", "/v1/runs", R::StartRun));
        v.push(rt("GET", "/v1/runs/{id}", R::RunGet));
    }
    v
}

/// The routes an automated actor may have. control.sock: open, read, raise and annotate holds, and ask whether a guest
/// exists (restrict only). agent.sock: list profiles, start and read validation runs.
pub fn allowed_for(p: Principal, r: R) -> bool {
    match p {
        Principal::Control => matches!(r, R::QOpen | R::QList | R::QGet | R::QRaise | R::QAdvisory | R::GuestExists),
        Principal::Agent => matches!(r, R::Profiles | R::StartRun | R::RunGet),
        Principal::Admin | Principal::User => true,
    }
}

/// The safety property: no route outside `allowed_for` on control.sock or agent.sock, whatever services are present.
pub fn loosening_free(s: Present) -> bool {
    [Principal::Control, Principal::Agent].iter().all(|&p| routes(p, s).iter().all(|r| allowed_for(p, r.id)))
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(40)]
    fn control_and_agent_have_no_loosening_route() {
        let s = Present { runs: kani::any(), samples: kani::any(), instances: kani::any(), licenses: kani::any(), exchange: kani::any() };
        assert!(loosening_free(s));
    }

    #[kani::proof]
    #[kani::unwind(40)]
    fn user_sock_never_has_verdicts_or_root_routes() {
        let s = Present { runs: kani::any(), samples: kani::any(), instances: kani::any(), licenses: kani::any(), exchange: kani::any() };
        for r in routes(Principal::User, s) {
            assert!(!matches!(
                r.id,
                R::QVerdict | R::QClose | R::GuestDown | R::PutSettings | R::AddInstance | R::RemoveInstance | R::AddLicense
                    | R::RemoveLicense | R::RevealLicense | R::SampleRun | R::AgentRunsStop | R::QOpen | R::QRaise
            ));
        }
    }
}

// ---- the services the handlers use ----

/// The side effects the API may trigger on guests (Go: api.Actions).
pub trait Actions: Send + Sync {
    fn guest(&self, name: &str) -> Result<Manifest, String>;
    fn defined(&self, m: &Manifest) -> bool;
    fn hold(&self, m: &Manifest, level: &str) -> Result<(), String>;
    fn release(&self, m: &Manifest) -> Result<(), String>;
    fn down(&self, m: &Manifest) -> Result<(), String>;
}

/// The validation-run backend (Go: api.RunService, BundleRunService, SampleRunService).
pub trait RunService: Send + Sync {
    fn profiles(&self) -> Vec<String>;
    fn details_json(&self) -> String;
    fn skipped_json(&self) -> String;
    fn start(&self, profile: &str, command: &str, timeout: i64, bundle: Option<Vec<u8>>) -> Result<String, Refusal>;
    fn get_json(&self, id: &str) -> Option<String>;
    fn bundles(&self) -> bool;
    fn samples(&self) -> bool;
    fn start_sample(&self, profile: &str, command: &str, sample: &str, timeout: i64) -> Result<String, Refusal>;
    fn stop_agent_runs(&self) -> i64;
}

pub struct EngineActions(pub Arc<crate::engine::Engine>);

impl Actions for EngineActions {
    fn guest(&self, name: &str) -> Result<Manifest, String> {
        crate::engine::load_guest(&self.0.state_dir, name)
    }
    fn defined(&self, m: &Manifest) -> bool {
        self.0.defined(&crate::engine::Ctx::background(), m)
    }
    fn hold(&self, m: &Manifest, level: &str) -> Result<(), String> {
        self.0.hold(&crate::engine::Ctx::background(), m, level).map_err(|e| e.to_string())
    }
    fn release(&self, m: &Manifest) -> Result<(), String> {
        self.0.release(&crate::engine::Ctx::background(), m).map_err(|e| e.to_string())
    }
    fn down(&self, m: &Manifest) -> Result<(), String> {
        self.0.down(&crate::engine::Ctx::background(), m).map_err(|e| e.to_string())
    }
}

impl RunService for crate::runs::Manager {
    fn profiles(&self) -> Vec<String> {
        crate::runs::Manager::profiles(self)
    }
    fn details_json(&self) -> String {
        crate::runs::Manager::details_json(self)
    }
    fn skipped_json(&self) -> String {
        gojson::list(&self.skipped().iter().map(|s| s.json()).collect::<Vec<_>>())
    }
    fn start(&self, profile: &str, command: &str, timeout: i64, bundle: Option<Vec<u8>>) -> Result<String, Refusal> {
        match bundle {
            Some(b) => self.start_bundle(profile, command, b, timeout),
            None => crate::runs::Manager::start(self, profile, command, timeout),
        }
    }
    fn get_json(&self, id: &str) -> Option<String> {
        self.get(id).map(|r| r.json())
    }
    fn bundles(&self) -> bool {
        true
    }
    fn samples(&self) -> bool {
        true
    }
    fn start_sample(&self, profile: &str, command: &str, sample: &str, timeout: i64) -> Result<String, Refusal> {
        crate::runs::Manager::start_sample(self, profile, command, sample, timeout)
    }
    fn stop_agent_runs(&self) -> i64 {
        crate::runs::Manager::stop_agent_runs(self)
    }
}

/// The password switch (Go: api.SettingsStore): the file, or a fake in tests.
pub trait SettingsStore: Send + Sync {
    /// The settings, and why the file could not be trusted (then the settings are the default).
    fn load(&self) -> (crate::settings::Settings, Option<String>);
    fn save(&self, s: crate::settings::Settings) -> std::io::Result<()>;
}

/// The password switch's file.
pub struct SettingsFile {
    pub path: String,
    pub require_root: bool,
}

impl SettingsStore for SettingsFile {
    fn load(&self) -> (crate::settings::Settings, Option<String>) {
        crate::settings::load(&self.path, self.require_root)
    }
    fn save(&self, s: crate::settings::Settings) -> std::io::Result<()> {
        crate::settings::save(&self.path, s)
    }
}

/// The Windows license store (Go: api.LicenseService).
pub trait LicenseService: Send + Sync {
    fn list(&self) -> Result<Vec<license::Masked>, license::Error>;
    fn add(&self, name: &str, key: &str) -> Result<license::Masked, license::Error>;
    fn remove(&self, id: &str) -> Result<(), license::Error>;
    fn reveal(&self, id: &str) -> Result<String, license::Error>;
    fn assign(&self, id: &str, guest: &str) -> Result<license::Masked, license::Error>;
    fn unassign(&self, id: &str, guest: &str) -> Result<license::Masked, license::Error>;
}

impl LicenseService for license::Store {
    fn list(&self) -> Result<Vec<license::Masked>, license::Error> {
        license::Store::list(self)
    }
    fn add(&self, name: &str, key: &str) -> Result<license::Masked, license::Error> {
        license::Store::add(self, name, key)
    }
    fn remove(&self, id: &str) -> Result<(), license::Error> {
        license::Store::remove(self, id)
    }
    fn reveal(&self, id: &str) -> Result<String, license::Error> {
        license::Store::reveal(self, id)
    }
    fn assign(&self, id: &str, guest: &str) -> Result<license::Masked, license::Error> {
        license::Store::assign(self, id, guest)
    }
    fn unassign(&self, id: &str, guest: &str) -> Result<license::Masked, license::Error> {
        license::Store::unassign(self, id, guest)
    }
}

pub struct Server {
    pub store: Arc<Store>,
    pub actions: Arc<dyn Actions>,
    pub events: Arc<dyn Emitter>,
    pub runs: Option<Arc<dyn RunService>>,
    pub instances: Option<Arc<instances::Service>>,
    pub licenses: Option<Arc<dyn LicenseService>>,
    pub settings: Option<Arc<dyn SettingsStore>>,
    pub exchange: Option<Arc<crate::exchange::Service>>,
    /// is /dev/kvm there (replaced in tests)
    pub kvm: fn() -> bool,
}

/// The connection's peer, from SO_PEERCRED.
#[derive(Clone, Copy, Debug, Default)]
pub struct Peer {
    pub uid: Option<u32>,
    pub pid: i32,
}

impl Peer {
    /// "uid=N pid=N", or "unknown" (Go's peerOf).
    pub fn text(&self) -> String {
        match self.uid {
            Some(u) => format!("uid={u} pid={}", self.pid),
            None => "unknown".into(),
        }
    }
}

/// An answer that went wrong: a coded refusal, or plain text (Go's errorBody chooses by whether the error is coded).
#[derive(Debug)]
pub enum Fail {
    Coded(u16, Refusal),
    Plain(u16, String),
}

type Out = Result<(u16, String), Fail>;

fn plain(status: u16, s: impl Into<String>) -> Fail {
    Fail::Plain(status, s.into())
}

fn coded(status: u16, code: &str, remedy: &str, msg: String) -> Fail {
    Fail::Coded(status, Refusal::new(Some(status), code, remedy, msg))
}

/// The JSON every failure carries.
pub fn error_body(f: &Fail) -> (u16, String) {
    match f {
        Fail::Coded(st, r) => {
            (*st, Obj::new().str("code", &r.code).str("error", &r.to_string()).str("message", &r.message).str("remedy", &r.remedy).end())
        }
        Fail::Plain(st, text) => {
            let code = match st {
                400 => "bad_request",
                404 => "not_found",
                409 => "conflict",
                _ => "internal",
            };
            (*st, Obj::new().str("code", code).str("error", text).end())
        }
    }
}

/// A service refusal as an answer: its own status when it has one (Go's failWith).
fn fail_with(r: Refusal) -> Fail {
    match r.status {
        Some(500) if r.code == "internal" && r.remedy.is_empty() => Fail::Plain(500, r.message),
        Some(st) => Fail::Coded(st, r),
        None => Fail::Plain(500, r.to_string()),
    }
}

fn license_fail(e: license::Error) -> Fail {
    match e {
        license::Error::L(l) => {
            let t = l.text().to_string();
            match l {
                LErr::NoLicense => coded(404, "not_found", "list the licenses for the ids that exist", t),
                LErr::BadKey => coded(400, "bad_key", "check the key and type it again", t),
                LErr::BadName => coded(400, "bad_name", "give a short name such as \"Windows 11 Pro, old PC\"", t),
                LErr::Duplicate => coded(409, "exists", "it is already stored", t),
                LErr::TooMany | LErr::BadGuest => coded(400, "bad_request", "check the request", t),
                _ => plain(500, t),
            }
        }
        license::Error::Io(s) => plain(500, s),
    }
}

fn state_err(e: quarantine::Error) -> Fail {
    match e {
        quarantine::Error::Rule(q) => {
            let st = match q {
                QErr::NotFound => 404,
                QErr::NotOpen | QErr::NotDanger => 409,
                _ => 400,
            };
            plain(st, q.text())
        }
        quarantine::Error::Io(e) => plain(500, sys::go_err(&e)),
    }
}

/// One Decode of the body (unknown fields refused), as `decode` and `decodeStrict` read it: (value, error text). An
/// empty body is no error (Go accepts io.EOF).
fn read_body<T: gojson::FromGo>(req: &Request, init: T, ty: &str) -> (T, Option<String>) {
    let cut = &req.body[..req.body.len().min(http::MAX_BODY)];
    match gojson::parse_first(cut) {
        Err(e) if e.is_eof() && !req.body_too_large => (init, None),
        Err(e) if (e.is_eof() || e.0 == "unexpected EOF") && req.body_too_large => (init, Some("http: request body too large".into())),
        Err(e) => (init, Some(e.0)),
        Ok(v) => {
            let mut cx = gojson::Ctx::new(true);
            let mut t = init;
            t.read(&v, &mut cx, ty);
            match cx.finish() {
                Ok(()) => (t, None),
                Err(e) => (t, Some(e.0)),
            }
        }
    }
}

/// Go's decode: a coded bad_request naming the decoder's error.
fn decode<T: gojson::FromGo>(req: &Request, init: T, ty: &str) -> Result<T, Fail> {
    let (t, e) = read_body(req, init, ty);
    match e {
        None => Ok(t),
        Some(e) if e == "http: request body too large" => {
            Err(coded(400, "bad_request", "send a shorter command", format!("the request body is larger than {} bytes", http::MAX_BODY)))
        }
        Some(e) => Err(coded(
            400,
            "bad_request",
            "send {\"profile\":\"...\",\"command\":\"...\",\"timeout_seconds\":N} and nothing else",
            format!("the request body is not valid JSON for this route ({e})"),
        )),
    }
}

/// Go's decodeStrict: a coded bad_request with the route's shape as the remedy.
fn decode_strict<T: gojson::FromGo>(req: &Request, init: T, ty: &str, shape: &str) -> Result<T, Fail> {
    match read_body(req, init, ty) {
        (t, None) => Ok(t),
        (_, Some(_)) => Err(coded(400, "bad_request", &format!("send {shape}"), "the request body is not valid JSON for this route".into())),
    }
}

// request shapes
#[derive(Default)]
struct OpenReq {
    guest: String,
    reason: String,
    source: String,
    level: String,
    evidence: Option<BTreeMap<String, String>>,
}
go_struct!(OpenReq as "api.openReq" {
    guest: "guest" => "string", reason: "reason" => "string", source: "source" => "string", level: "level" => "quarantine.Level",
    evidence: "evidence" => "map[string]string",
});

#[derive(Default)]
struct LevelReq {
    level: String,
}
go_struct!(LevelReq as "" { level: "level" => "quarantine.Level" });

#[derive(Default)]
struct AdvisoryReq {
    source: String,
    text: String,
}
go_struct!(AdvisoryReq as "" { source: "source" => "string", text: "text" => "string" });

#[derive(Default)]
struct VerdictReq {
    verdict: String,
    by: String,
    note: String,
}
go_struct!(VerdictReq as "" { verdict: "verdict" => "quarantine.Status", by: "by" => "string", note: "note" => "string" });

#[derive(Default)]
struct ByReq {
    by: String,
}
go_struct!(ByReq as "" { by: "by" => "string" });

#[derive(Default)]
struct RunReq {
    profile: String,
    command: String,
    timeout_seconds: i64,
    bundle: String,
}
go_struct!(RunReq as "" { profile: "profile" => "string", command: "command" => "string", timeout_seconds: "timeout_seconds" => "int", bundle: "bundle" => "string" });

#[derive(Default)]
struct SampleReq {
    profile: String,
    command: String,
    sample: String,
    timeout_seconds: i64,
}
go_struct!(SampleReq as "" { profile: "profile" => "string", command: "command" => "string", sample: "sample" => "string", timeout_seconds: "timeout_seconds" => "int" });

#[derive(Default)]
struct AskReq {
    ask_password: Option<bool>,
}
go_struct!(AskReq as "" { ask_password: "ask_password" => "*bool" });

#[derive(Default)]
struct ConfirmReq {
    confirm: bool,
}
go_struct!(ConfirmReq as "" { confirm: "confirm" => "bool" });

#[derive(Default)]
struct AddReq {
    manifest: Option<Manifest>,
    owner: String,
}
go_struct!(AddReq as "" { manifest: "manifest" => "*manifest.Manifest", owner: "owner" => "string" });

#[derive(Default)]
struct RemoveReq {
    delete_disk: bool,
}
go_struct!(RemoveReq as "" { delete_disk: "delete_disk" => "bool" });

#[derive(Default)]
struct LicenseReq {
    name: String,
    key: String,
}
go_struct!(LicenseReq as "" { name: "name" => "string", key: "key" => "string" });

#[derive(Default)]
struct GuestReq {
    guest: String,
}
go_struct!(GuestReq as "" { guest: "guest" => "string" });

#[derive(Default)]
struct PathReq {
    path: String,
}
go_struct!(PathReq as "" { path: "path" => "string" });

/// Go's base64.StdEncoding.DecodeString (padding required; CR and LF ignored).
pub fn base64_std(s: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = s.bytes().filter(|c| *c != b'\r' && *c != b'\n').collect();
    if clean.len() % 4 != 0 {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for (ci, ch) in clean.chunks(4).enumerate() {
        let last = ci == clean.len() / 4 - 1;
        let pad = ch.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (i, &c) in ch.iter().enumerate() {
            let v = if i >= 4 - pad { 0 } else { val(c)? };
            n = n << 6 | v;
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        // Go refuses non-zero bits in the padding
        if (pad == 1 && bytes[2] != 0) || (pad == 2 && (bytes[1] != 0 || bytes[2] != 0)) {
            return None;
        }
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

/// The result of an action that changes a hold.
fn result_json(rec: &quarantine::Record, created: bool, applied: bool, error: &str) -> String {
    Obj::new().raw("record", &rec.json()).bool_omit("created", created).bool("applied", applied).str_omit("error", error).end()
}

pub struct Ctx<'a> {
    pub p: Principal,
    pub peer: Peer,
    pub vals: &'a [(String, String)],
    pub req: &'a Request,
}

impl Ctx<'_> {
    fn val(&self, k: &str) -> String {
        self.vals.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default()
    }
}

impl Server {
    pub fn present(&self) -> Present {
        Present {
            runs: self.runs.is_some(),
            samples: self.runs.as_ref().is_some_and(|r| r.samples()),
            instances: self.instances.is_some(),
            licenses: self.licenses.is_some(),
            exchange: self.exchange.is_some(),
        }
    }

    /// One request on one principal's socket.
    pub fn handle(&self, p: Principal, peer: Peer, req: &Request) -> Response {
        let table = routes(p, self.present());
        let (id, vals) = match http::route(&table, &req.method, &req.raw_path) {
            http::Matched::Route(id, vals) => (id, vals),
            http::Matched::NotFound => return Response::text(404, "404 page not found\n"),
            http::Matched::MethodNotAllowed(allow) => {
                let mut r = Response::text(405, "Method Not Allowed\n");
                r.headers.insert(0, ("Allow".into(), allow));
                return r;
            }
            http::Matched::Redirect(to) => return http::redirect(&req.method, &to),
        };
        let cx = Ctx { p, peer, vals: &vals, req };
        if id == R::TakeExchange {
            return self.take_exchange(&cx);
        }
        let out = match id {
            R::QOpen => self.open(&cx),
            R::QList => Ok((200, gojson::list(&self.store.list().iter().map(|r| r.json()).collect::<Vec<_>>()))),
            R::QGet => self.store.get(&cx.val("id")).map(|r| (200, r.json())).map_err(state_err),
            R::QRaise => self.raise(&cx),
            R::QAdvisory => self.advisory(&cx),
            R::GuestExists => Ok(self.guest_exists(&cx)),
            R::QVerdict => self.verdict(&cx),
            R::QClose => self.close(&cx),
            R::GuestDown => self.down(&cx),
            R::SampleRun => self.start_sample(&cx),
            R::RunGet => self.get_run(&cx),
            R::AgentRunsStop => Ok((200, Obj::new().int("stopped", self.runs.as_ref().map_or(0, |r| r.stop_agent_runs())).end())),
            R::Profiles => Ok(self.profiles()),
            R::StartRun => self.start_run(&cx),
            R::Status => Ok(self.status(&cx)),
            R::GetSettings => Ok((200, Obj::new().bool("ask_password", self.ask_password()).end())),
            R::PutSettings => self.put_settings(&cx),
            R::ListInstances => {
                let c = self.caller(&cx).0;
                let list = self.inst().list(&c);
                Ok((200, Obj::new().raw("instances", &gojson::list(&list.iter().map(|v| v.json()).collect::<Vec<_>>())).end()))
            }
            R::GetInstance => self.inst().get(&cx.val("name"), &self.caller(&cx).0).map(|v| (200, v.json())).map_err(fail_with),
            R::StartInstance => self.gated(&cx).and_then(|c| self.inst().start(&cx.val("name"), &c).map(|v| (200, v.json())).map_err(fail_with)),
            R::StopInstance => self.gated(&cx).and_then(|c| self.inst().stop(&cx.val("name"), &c).map(|v| (200, v.json())).map_err(fail_with)),
            R::ConfigureInstance => self.gated(&cx).and_then(|_| self.configure(&cx)),
            R::FreeSpace => self.gated(&cx).and_then(|_| self.free_space(&cx)),
            R::AddInstance => self.add_instance(&cx),
            R::RemoveInstance => self.remove_instance(&cx),
            R::ListLicenses => match self.lic().list() {
                Ok(l) => Ok((200, Obj::new().raw("licenses", &gojson::list(&l.iter().map(|m| m.json()).collect::<Vec<_>>())).end())),
                Err(_) => Err(plain(500, "the license store cannot be read")),
            },
            R::AddLicense => self.add_license(&cx),
            R::RemoveLicense => self.remove_license(&cx),
            R::RevealLicense => self.reveal_license(&cx),
            R::AssignLicense => self.gated(&cx).and_then(|_| self.assign_license(&cx, true)),
            R::UnassignLicense => self.gated(&cx).and_then(|_| self.assign_license(&cx, false)),
            R::ListExchange => self.exch().list(&cx.val("guest")).map(|l| (200, l.json())).map_err(fail_with),
            R::TakeExchange => unreachable!("answered above"),
        };
        match out {
            Ok((st, body)) => Response::json(st, body),
            Err(f) => {
                let (st, body) = error_body(&f);
                Response::json(st, body)
            }
        }
    }

    fn inst(&self) -> &instances::Service {
        self.instances.as_deref().expect("routes exist only when the service does")
    }
    fn lic(&self) -> &dyn LicenseService {
        self.licenses.as_deref().expect("routes exist only when the service does")
    }
    fn exch(&self) -> &crate::exchange::Service {
        self.exchange.as_deref().expect("routes exist only when the service does")
    }

    /// The audit record of a request: principal and peer added.
    fn audit(&self, cx: &Ctx, kind: &str, guest: &str, mut d: Detail) -> std::io::Result<()> {
        d.insert("principal".into(), cx.p.as_str().into());
        d.insert("peer".into(), cx.peer.text());
        self.events.emit(kind, guest, d)
    }

    fn apply(&self, m: &Manifest, rec: &quarantine::Record, created: bool) -> String {
        if !self.actions.defined(m) {
            return result_json(rec, created, false, "guest is not currently running; hold recorded and will block the next start");
        }
        match self.actions.hold(m, &rec.level) {
            Err(e) => result_json(rec, created, false, &e),
            Ok(()) => result_json(rec, created, true, ""),
        }
    }

    fn open(&self, cx: &Ctx) -> Out {
        let mut r = decode(cx.req, OpenReq::default(), "api.openReq")?;
        if r.level.is_empty() {
            r.level = quarantine::LEVEL_RESTRICT.into();
        }
        let probe = Manifest { name: r.guest.clone(), ..Manifest::default() };
        probe.validate_name().map_err(|e| plain(400, e))?;
        let m = self.actions.guest(&r.guest).map_err(|e| plain(404, e))?;
        if r.source.is_empty() {
            r.source = cx.p.as_str().into();
        }
        let (rec, created) = self.store.quarantine(&r.guest, &r.reason, &r.source, &r.level, r.evidence.as_ref()).map_err(state_err)?;
        let kind = if created { events::QUARANTINE_OPEN } else { events::QUARANTINE_RAISE };
        let _ = self.audit(cx, kind, &r.guest, detail([("id", &rec.id), ("level", &rec.level), ("reason", &rec.reason), ("source", &rec.source)]));
        Ok((200, self.apply(&m, &rec, created)))
    }

    fn raise(&self, cx: &Ctx) -> Out {
        let r = decode(cx.req, LevelReq::default(), "struct { Level quarantine.Level \"json:\\\"level\\\"\" }")?;
        let rec = self.store.raise(&cx.val("id"), &r.level).map_err(state_err)?;
        let _ = self.audit(cx, events::QUARANTINE_RAISE, &rec.guest, detail([("id", &rec.id), ("level", &rec.level)]));
        match self.actions.guest(&rec.guest) {
            Err(e) => Ok((200, result_json(&rec, false, false, &e))),
            Ok(m) => Ok((200, self.apply(&m, &rec, false))),
        }
    }

    fn advisory(&self, cx: &Ctx) -> Out {
        let r = decode(cx.req, AdvisoryReq::default(), "struct { Source string \"json:\\\"source\\\"\"; Text string \"json:\\\"text\\\"\" }")?;
        let rec = self.store.add_advisory(&cx.val("id"), &r.source, &r.text).map_err(state_err)?;
        let _ = self.audit(cx, events::QUARANTINE_ADVISORY, &rec.guest, detail([("id", &rec.id), ("source", &r.source)]));
        Ok((200, rec.json()))
    }

    fn verdict(&self, cx: &Ctx) -> Out {
        let r = decode(cx.req, VerdictReq::default(), r#"struct { Verdict quarantine.Status "json:\"verdict\""; By string "json:\"by\""; Note string "json:\"note\"" }"#)?;
        let id = cx.val("id");
        let rec = self.store.get(&id).map_err(state_err)?;
        if rec.status != quarantine::STATUS_OPEN {
            return Err(plain(409, QErr::NotOpen.text()));
        }
        if r.verdict != quarantine::STATUS_SAFE && r.verdict != quarantine::STATUS_DANGEROUS {
            return Err(plain(400, QErr::BadVerdict.text()));
        }
        let by = format!("{} (peer {})", gotext::trim_space(&r.by), cx.peer.text());
        // the audit entry first; no record, no verdict
        if let Err(e) = self.audit(cx, events::QUARANTINE_VERDICT, &rec.guest, detail([("id", &id), ("verdict", &r.verdict), ("by", &by), ("note", &r.note)])) {
            return Err(plain(500, format!("cannot record verdict in the audit log: {}", sys::go_err(&e))));
        }
        let g = self.actions.guest(&rec.guest);
        let defined = g.as_ref().is_ok_and(|m| self.actions.defined(m));
        let (mut applied, mut error) = (false, String::new());
        if defined {
            let m = g.as_ref().expect("checked");
            if r.verdict == quarantine::STATUS_SAFE {
                if let Err(e) = self.actions.release(m) {
                    return Err(plain(502, format!("could not lift restrictions, record left open: {e}")));
                }
                applied = true;
            } else {
                match self.actions.hold(m, quarantine::LEVEL_ISOLATE) {
                    Err(e) => error = format!("could not isolate: {e}"),
                    Ok(()) => applied = true,
                }
            }
        }
        let out = self.store.decide(&id, &r.verdict, &by, &r.note).map_err(state_err)?;
        Ok((200, result_json(&out, false, applied, &error)))
    }

    fn close(&self, cx: &Ctx) -> Out {
        let r = decode(cx.req, ByReq::default(), r#"struct { By string "json:\"by\"" }"#)?;
        let by = format!("{} (peer {})", gotext::trim_space(&r.by), cx.peer.text());
        let id = cx.val("id");
        if let Ok(cur) = self.store.get(&id) {
            if let Ok(m) = self.actions.guest(&cur.guest) {
                if self.actions.defined(&m) {
                    return Err(plain(409, format!("guest {} still exists; tear it down before closing its record", gotext::quote(&cur.guest))));
                }
            }
        }
        let rec = self.store.close(&id, &by).map_err(state_err)?;
        let _ = self.audit(cx, events::QUARANTINE_VERDICT, &rec.guest, detail([("id", &rec.id), ("verdict", "closed"), ("by", &by)]));
        Ok((200, rec.json()))
    }

    fn guest_exists(&self, cx: &Ctx) -> (u16, String) {
        match self.actions.guest(&cx.val("name")) {
            Ok(m) => (200, Obj::new().bool("exists", true).str("name", &m.name).end()),
            Err(_) => (404, Obj::new().bool("exists", false).end()),
        }
    }

    fn down(&self, cx: &Ctx) -> Out {
        let m = self.actions.guest(&cx.val("name")).map_err(|e| plain(404, e))?;
        let _ = self.audit(cx, events::GUEST_STOP, &m.name, detail([("via", "api")]));
        self.actions.down(&m).map_err(|e| plain(500, e))?;
        Ok((200, Obj::new().str("status", "down").end()))
    }

    fn profiles(&self) -> (u16, String) {
        let r = self.runs.as_ref().expect("route exists only with runs");
        (200, Obj::new().raw("details", &r.details_json()).strs("profiles", &r.profiles()).raw("skipped", &r.skipped_json()).end())
    }

    fn run_fail(e: Refusal) -> Fail {
        let st = if e.code == crate::runs::CODE_BUSY { 429 } else { 400 };
        // an uncoded failure (no code of its own) is answered with the code its status gives, as Go does
        if e.code.is_empty() {
            return Fail::Plain(st, e.message);
        }
        Fail::Coded(st, e)
    }

    fn start_run(&self, cx: &Ctx) -> Out {
        let r = match decode(cx.req, RunReq::default(), r#"struct { Profile string "json:\"profile\""; Command string "json:\"command\""; TimeoutSeconds int "json:\"timeout_seconds\""; Bundle string "json:\"bundle\"" }"#) {
            Ok(r) => r,
            Err(e) => {
                let _ = self.audit(cx, events::RUN_ERROR, "", detail([("code", "bad_request")]));
                return Err(e);
            }
        };
        let runs = self.runs.as_ref().expect("route exists only with runs");
        let bundle = if r.bundle.is_empty() {
            None
        } else {
            match base64_std(&r.bundle) {
                Some(b) if runs.bundles() => Some(b),
                _ => {
                    return Err(coded(
                        400,
                        "bad_request",
                        "send the tar as standard base64, to a profile that allows bundles",
                        "the bundle is not accepted here or is not valid base64".into(),
                    ))
                }
            }
        };
        let id = runs.start(&r.profile, &r.command, r.timeout_seconds, bundle).map_err(Self::run_fail)?;
        Ok((202, Obj::new().str("id", &id).end()))
    }

    fn start_sample(&self, cx: &Ctx) -> Out {
        let r = decode(cx.req, SampleReq::default(), r#"struct { Profile string "json:\"profile\""; Command string "json:\"command\""; Sample string "json:\"sample\""; TimeoutSeconds int "json:\"timeout_seconds\"" }"#)?;
        let runs = self.runs.as_ref().expect("route exists only with runs");
        let id = runs.start_sample(&r.profile, &r.command, &r.sample, r.timeout_seconds).map_err(Self::run_fail)?;
        Ok((202, Obj::new().str("id", &id).end()))
    }

    fn get_run(&self, cx: &Ctx) -> Out {
        match self.runs.as_ref().and_then(|r| r.get_json(&cx.val("id"))) {
            Some(j) => Ok((200, j)),
            None => Err(coded(
                404,
                "run_unknown",
                "the id may have expired or Limbo restarted (its guest is destroyed either way); start the run again",
                "there is no run with that id".into(),
            )),
        }
    }

    // ---- the Settings page ----

    fn caller(&self, cx: &Ctx) -> (Caller, bool) {
        if cx.p == Principal::Admin {
            return (Caller { admin: true, uid: 0, user: "root".into() }, true);
        }
        match cx.peer.uid {
            None => (Caller { admin: false, uid: -1, user: String::new() }, false),
            Some(uid) => (Caller { admin: false, uid: uid as i64, user: crate::osuser::user_name(uid).unwrap_or_default() }, true),
        }
    }

    fn ask_password(&self) -> bool {
        match &self.settings {
            None => true,
            Some(f) => {
                let (s, err) = f.load();
                err.is_some() || s.ask_password
            }
        }
    }

    /// A changing route on user.sock: refused with the switch on (or unknown), or a caller the kernel cannot name.
    fn gated(&self, cx: &Ctx) -> Result<Caller, Fail> {
        if cx.p != Principal::Admin {
            if self.ask_password() {
                return Err(coded(
                    403,
                    "password_required",
                    "use the password: run the same action with pkexec or sudo (limbo ...), or turn off \"Ask for my password for Limbo changes\"",
                    "Limbo changes need the password on this computer".into(),
                ));
            }
            if !self.caller(cx).1 {
                return Err(coded(403, "unknown_caller", "connect over the unix socket", "the caller's account could not be read".into()));
            }
        }
        Ok(self.caller(cx).0)
    }

    fn status(&self, cx: &Ctx) -> (u16, String) {
        let c = self.caller(cx).0;
        let i = self.inst();
        let (mut total, mut running, mut held) = (0, 0, 0);
        for v in i.list(&c) {
            total += 1;
            if v.running {
                running += 1;
            }
            if v.hold.is_some() {
                held += 1;
            }
        }
        let inst = Obj::new().int("total", total).int("running", running).int("held", held).end();
        (
            200,
            Obj::new()
                .str("version", VERSION)
                .bool("running", true)
                .bool("kvm", (self.kvm)())
                .bool("ask_password", self.ask_password())
                .raw("space", &i.space().json())
                .raw("instances", &inst)
                .end(),
        )
    }

    fn put_settings(&self, cx: &Ctx) -> Out {
        let r = decode_strict(cx.req, AskReq::default(), "api.askReq", r#"{"ask_password": true|false}"#)?;
        let Some(ask) = r.ask_password else {
            return Err(coded(400, "bad_request", r#"send {"ask_password": true|false}"#, "ask_password is missing".into()));
        };
        let Some(f) = &self.settings else {
            return Err(coded(500, "internal", "see the Limbo log", "no settings file is configured".into()));
        };
        let v = if ask { "true" } else { "false" };
        if let Err(e) = self.audit(cx, "settings.change", "", detail([("ask_password", v)])) {
            return Err(plain(500, format!("cannot record the change in the audit log: {}", sys::go_err(&e))));
        }
        f.save(crate::settings::Settings { ask_password: ask }).map_err(|e| plain(500, sys::go_err(&e)))?;
        Ok((200, Obj::new().bool("ask_password", ask).end()))
    }

    fn configure(&self, cx: &Ctx) -> Out {
        let ch = decode_strict(
            cx.req,
            Change::default(),
            "instances.Change",
            r#"{"cpus":N,"memory_mb":N,"disk_gb":N,"shared_folder":"off|on","clipboard":"off|text","devices":["0000:03:00.0"]} (any of them)"#,
        )?;
        let c = self.caller(cx).0;
        self.inst().configure(&cx.val("name"), &ch, &c).map(|v| (200, v.json())).map_err(fail_with)
    }

    fn free_space(&self, cx: &Ctx) -> Out {
        let r = decode_strict(cx.req, ConfirmReq::default(), "api.confirmReq", r#"{"confirm": true}"#)?;
        if !r.confirm {
            return Err(coded(400, "confirm_required", r#"send {"confirm": true}"#, "freeing space deletes everything the guest changed since its base image".into()));
        }
        let c = self.caller(cx).0;
        let n = self.inst().free_space(&cx.val("name"), &c).map_err(fail_with)?;
        Ok((200, Obj::new().int("freed_bytes", n).end()))
    }

    fn add_instance(&self, cx: &Ctx) -> Out {
        let r = decode_strict(cx.req, AddReq::default(), "api.addReq", r#"{"manifest": {...}, "owner": "account"}"#)?;
        let Some(m) = r.manifest else {
            return Err(coded(400, "bad_request", r#"send {"manifest": {...}}"#, "manifest is missing".into()));
        };
        let c = self.caller(cx).0;
        self.inst().add(&m, &r.owner, &c).map(|v| (200, v.json())).map_err(fail_with)
    }

    fn remove_instance(&self, cx: &Ctx) -> Out {
        let r = decode_strict(cx.req, RemoveReq::default(), "api.removeReq", r#"{"delete_disk": true|false}"#)?;
        let c = self.caller(cx).0;
        let name = cx.val("name");
        self.inst().remove(&name, r.delete_disk, &c).map_err(fail_with)?;
        Ok((200, Obj::new().str("removed", &name).end()))
    }

    fn add_license(&self, cx: &Ctx) -> Out {
        let r = decode_strict(cx.req, LicenseReq::default(), "api.licenseReq", r#"{"name": "...", "key": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"}"#)?;
        let m = self.lic().add(&r.name, &r.key).map_err(license_fail)?;
        let _ = self.audit(cx, "license.add", "", detail([("id", &m.id)]));
        Ok((200, m.json()))
    }

    fn remove_license(&self, cx: &Ctx) -> Out {
        let id = cx.val("id");
        self.lic().remove(&id).map_err(license_fail)?;
        let _ = self.audit(cx, "license.remove", "", detail([("id", &id)]));
        Ok((200, Obj::new().str("removed", &id).end()))
    }

    fn reveal_license(&self, cx: &Ctx) -> Out {
        let id = cx.val("id");
        if let Err(e) = self.audit(cx, "license.reveal", "", detail([("id", &id)])) {
            return Err(plain(500, format!("cannot record the request in the audit log: {}", sys::go_err(&e))));
        }
        let k = self.lic().reveal(&id).map_err(license_fail)?;
        Ok((200, Obj::new().str("id", &id).str("key", &k).end()))
    }

    fn assign_license(&self, cx: &Ctx, assign: bool) -> Out {
        let r = decode_strict(cx.req, GuestReq::default(), "api.guestReq", r#"{"guest": "name"}"#)?;
        let c = self.caller(cx).0;
        if let Some(i) = &self.instances {
            let v = i.get(&r.guest, &c).map_err(fail_with)?;
            if v.kind != "instance" || v.os != manifest::OS_WINDOWS {
                return Err(coded(400, "bad_request", "assign licenses to Windows instances only", format!("{} is not a Windows instance", gotext::quote(&r.guest))));
            }
            if !v.mine {
                return Err(coded(403, instances::CODE_NOT_OWNER, "ask its owner or use the password", format!("instance {} belongs to {}", gotext::quote(&r.guest), v.owner)));
            }
        }
        let id = cx.val("id");
        let (m, kind) = if assign {
            (self.lic().assign(&id, &r.guest), "license.assign")
        } else {
            (self.lic().unassign(&id, &r.guest), "license.unassign")
        };
        let m = m.map_err(license_fail)?;
        let _ = self.audit(cx, kind, &r.guest, detail([("id", &m.id)]));
        Ok((200, m.json()))
    }

    /// The file's bytes (octet-stream) with its hash, or the usual JSON error.
    fn take_exchange(&self, cx: &Ctx) -> Response {
        let err = |f: Fail| {
            let (st, body) = error_body(&f);
            Response::json(st, body)
        };
        let guest = cx.val("guest");
        let c = match self.gated(cx) {
            Ok(c) => c,
            Err(f) => return err(f),
        };
        if let (Some(i), false) = (&self.instances, cx.p == Principal::Admin) {
            let v = match i.get(&guest, &c) {
                Ok(v) => v,
                Err(r) => return err(fail_with(r)),
            };
            if v.hold.is_some() {
                return err(coded(409, "held_by_heimdall", "decide about the guest on Heimdall's page (Settings > Security) first", format!("guest {} is held", gotext::quote(&guest))));
            }
            if !v.mine {
                return err(coded(403, "not_owner", "ask its owner or use the password", format!("guest {} belongs to {}", gotext::quote(&guest), v.owner)));
            }
        }
        let r = match decode_strict(cx.req, PathReq::default(), "api.pathReq", r#"{"path": "name as listed"}"#) {
            Ok(r) => r,
            Err(f) => return err(f),
        };
        let d = detail([("principal", cx.p.as_str()), ("peer", &cx.peer.text())]);
        match self.exch().take(&guest, &r.path, d) {
            Err(r) => err(fail_with(r)),
            Ok(t) => {
                let len = t.size as u64;
                let file = match t.file.try_clone() {
                    Ok(f) => f,
                    Err(e) => return err(plain(500, sys::go_err(&e))),
                };
                let resp = Response {
                    status: 200,
                    headers: vec![
                        ("Content-Type".into(), "application/octet-stream".into()),
                        ("Content-Length".into(), len.to_string()),
                        ("X-Limbo-Sha256".into(), t.sha256.clone()),
                        ("X-Limbo-Scan".into(), crate::exchange::CLEAN.into()),
                    ],
                    body: Body::File(file, len),
                };
                // the private copy's name goes once the stream is open (the open file keeps the bytes)
                drop(t);
                resp
            }
        }
    }
}
