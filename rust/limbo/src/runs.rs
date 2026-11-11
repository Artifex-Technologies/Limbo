//! Validation and sample runs: a command in a throwaway guest (Go: internal/runs). The caller names a profile, never a
//! manifest; profiles live in a root-only folder; each run gets a fresh guest that is torn down whatever happens. Each
//! run is a thread of its own (Go: a goroutine).

use crate::engine::{Ctx, Engine, EngineErr};
use crate::events::{self, Emitter};
use crate::gojson::{self, Obj};
use crate::gotime::Time;
use crate::hostpolicy::Refused;
use crate::image::{CheckErr, Proofs};
use crate::manifest::{self, Manifest};
use crate::{detail, go_struct, gotext, provision, sys, virt, Refusal};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_COMMAND: usize = 4096;
const MAX_BUNDLE: usize = 40 << 10;
const MAX_SAMPLE: usize = 64 << 20;
const DEFAULT_SECONDS: i64 = 300;
const MAX_RESULTS: usize = 50;
const MAX_CONCURRENT: usize = 2;
const MAX_SAMPLES: usize = 1;
const DEFAULT_OUTPUT_CAP: i64 = 64 << 10;
const READY_WAIT_SECONDS: u64 = 180;
const BOOT_BUDGET_SECONDS: u64 = 300;
const TEARDOWN_TIMEOUT_MS: u64 = 60_000;
const MAX_SKIPPED: usize = 20;

pub const CODE_BAD_REQUEST: &str = "bad_request";
pub const CODE_PROFILE_INVALID: &str = "profile_invalid";
pub const CODE_PROFILE_UNKNOWN: &str = "profile_unknown";
pub const CODE_BUSY: &str = "busy";
pub const CODE_IMAGE_MISSING: &str = "image_missing";
pub const CODE_IMAGE_MISMATCH: &str = "image_mismatch";
pub const CODE_BOOT_FAILED: &str = "boot_failed";
pub const CODE_BOOT_TIMEOUT: &str = "boot_timeout";
pub const CODE_COMMAND_TIMEOUT: &str = "command_timeout";
pub const CODE_GUEST_KILLED: &str = "guest_killed";
pub const CODE_HOST_RESOURCES: &str = "host_resources";
pub const CODE_VIRT_UNAVAIL: &str = "virt_unavailable";
pub const CODE_RUN_FAILED: &str = "run_failed";
pub const CODE_HARDWARE_DENIED: &str = "hardware_denied";
pub const CODE_APPROVAL_REQUIRED: &str = "approval_required";
pub const CODE_HARDWARE_BUSY: &str = "hardware_busy";
pub const CODE_REBOOT_REQUIRED: &str = "reboot_required";
pub const CODE_OUTPUT_TRUNC: &str = "output_truncated";
pub const CODE_TEARDOWN_FAILED: &str = "teardown_failed";
pub const CODE_CONTAINED: &str = "contained";
pub const CODE_MORE: &str = "more";

fn new_err(code: &str, remedy: &str, msg: String) -> Refusal {
    Refusal::new(None, code, remedy, msg)
}

fn bad_profile(short: &str, msg: String) -> Refusal {
    let mut e = new_err(CODE_PROFILE_INVALID, "ask the operator to fix the profile file", msg);
    e.short = short.into();
    e
}

/// `^[a-z][a-z0-9-]{0,31}$`
pub fn profile_name_ok(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// `^r[0-9a-f]{8}$`
pub fn run_id_ok(n: &str) -> bool {
    n.len() == 9 && n.starts_with('r') && n[1..].bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`
fn sample_name_ok(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

#[derive(Clone, Debug, Default)]
pub struct Profile {
    pub manifest: Manifest,
    pub ssh_identity: String,
    pub max_seconds: i64,
    pub max_output_bytes: i64,
    pub allow_bundle: bool,
    pub allow_sample: bool,
}
go_struct!(Profile as "runs.Profile" {
    manifest: "manifest" => "manifest.Manifest", ssh_identity: "ssh_identity" => "string", max_seconds: "max_seconds" => "int",
    max_output_bytes: "max_output_bytes" => "int", allow_bundle: "allow_bundle" => "bool", allow_sample: "allow_sample" => "bool",
});

#[derive(Clone, Debug, PartialEq)]
pub struct RunResult {
    pub id: String,
    pub profile: String,
    pub status: String,
    pub exit_code: Option<i64>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub error: String,
    pub code: String,
    pub remedy: String,
    pub started: Time,
    pub ended: Time,
}

impl RunResult {
    pub fn json(&self) -> String {
        let mut o = Obj::new().str("id", &self.id).str("profile", &self.profile).str("status", &self.status);
        if let Some(c) = self.exit_code {
            o = o.int("exit_code", c);
        }
        o.str("stdout", &self.stdout)
            .str("stderr", &self.stderr)
            .bool_omit("truncated", self.truncated)
            .str_omit("error", &self.error)
            .str_omit("code", &self.code)
            .str_omit("remedy", &self.remedy)
            .str("started", &self.started.rfc3339_nano())
            .str("ended", &self.ended.rfc3339_nano())
            .end()
    }
}

/// A failure while running a command in a guest.
#[derive(Clone, Debug)]
pub struct ExecErr {
    pub text: String,
    /// ssh's own failure (exit 255), not the command's
    pub connection: bool,
    pub not_found: bool,
}

/// What a command printed: (stdout, stderr, exit, truncated).
pub type Output = (String, String, i64, bool);

/// Runs a command inside a guest. Real one: ssh.
pub trait Executor: Send + Sync {
    fn wait_ready(&self, ctx: &Ctx, ip: &str, user: &str, identity: &str) -> Result<(), ExecErr>;
    /// `stdin` carries a bundle (unpacked) or a sample (stored read-only), as `wrap` says.
    fn run(
        &self,
        ctx: &Ctx,
        ip: &str,
        user: &str,
        identity: &str,
        command: &str,
        stdin: Option<&[u8]>,
        limit: i64,
    ) -> (Output, Option<ExecErr>);
    fn bundles(&self) -> bool {
        true
    }
    fn samples(&self) -> bool {
        true
    }
}

/// Builds the cloud-init ISO for a run's guest.
pub type SeedBuilder = Box<dyn Fn(&Ctx, &Manifest, &str, &str) -> Result<(), EngineErr> + Send + Sync>;

#[derive(Default)]
struct State {
    results: HashMap<String, RunResult>,
    order: Vec<String>,
    dev_held: HashMap<String, Vec<String>>,
    kinds: HashMap<String, &'static str>,
    cancels: HashMap<String, Arc<AtomicBool>>,
}

pub struct Manager {
    pub profile_dir: String,
    pub state_dir: String,
    pub engine: Arc<Engine>,
    pub exec: Arc<dyn Executor>,
    pub events: Arc<dyn Emitter>,
    pub build_seed: SeedBuilder,
    pub sample_dir: String,
    pub contained: Option<Box<dyn Fn() -> bool + Send + Sync>>,
    pub images: Arc<Proofs>,
    st: Mutex<State>,
    scan_mu: Mutex<HashMap<String, String>>,
    /// a gate each run's thread waits on before it starts (tests); None in the daemon
    pub hold_runs: Mutex<Option<Arc<AtomicBool>>>,
    me: Mutex<std::sync::Weak<Manager>>,
}

const AGENT: &str = "agent";
const SAMPLE: &str = "sample";

/// The real seed: user-data and meta-data packed by xorriso.
pub fn seed_iso(engine: &Engine, ctx: &Ctx, m: &Manifest, work_dir: &str, iso: &str) -> Result<(), EngineErr> {
    let s = provision::build(m).map_err(EngineErr::Other)?;
    sys::mkdir_all(work_dir, 0o700).map_err(|e| EngineErr::Other(sys::go_path_error("mkdir", work_dir, &e)))?;
    for (name, body) in [("user-data", &s.user_data), ("meta-data", &s.meta_data)] {
        let p = sys::join(&[work_dir, name]);
        sys::write_file(&p, body.as_bytes(), 0o600).map_err(|e| EngineErr::Other(sys::go_path_error("open", &p, &e)))?;
    }
    let args: Vec<String> = ["-as", "mkisofs", "-o", iso, "-V", "cidata", "-J", "-r", work_dir].iter().map(|x| x.to_string()).collect();
    engine.runner.run(ctx, "", "xorriso", &args).map_err(EngineErr::Cmd)
}

impl Manager {
    pub fn new(profile_dir: &str, state_dir: &str, engine: Arc<Engine>, exec: Arc<dyn Executor>, events: Arc<dyn Emitter>) -> Manager {
        let e2 = engine.clone();
        let images = engine.images.clone().unwrap_or_else(|| Arc::new(Proofs::new("", 0)));
        Manager {
            profile_dir: profile_dir.into(),
            state_dir: state_dir.into(),
            engine,
            exec,
            events,
            build_seed: Box::new(move |ctx, m, work, iso| seed_iso(&e2, ctx, m, work, iso)),
            sample_dir: String::new(),
            contained: None,
            images,
            st: Mutex::new(State::default()),
            scan_mu: Mutex::new(HashMap::new()),
            hold_runs: Mutex::new(None),
            me: Mutex::new(std::sync::Weak::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn load_profile(&self, name: &str) -> Result<Profile, Refusal> {
        if !profile_name_ok(name) {
            return Err(new_err(
                CODE_PROFILE_INVALID,
                "use a name from limbo_profiles",
                "profile names are lowercase letters, digits and hyphens".into(),
            ));
        }
        let q = gotext::quote(name);
        let b = std::fs::read(sys::join(&[&self.profile_dir, &format!("{name}.json")])).map_err(|_| {
            new_err(CODE_PROFILE_UNKNOWN, "call limbo_profiles for the names that exist", format!("there is no profile named {q}"))
        })?;
        let (mut p, r) = gojson::decode(&b, Profile::default(), "runs.Profile", true);
        if let Err(e) = r {
            return Err(bad_profile("the profile file is not valid JSON or has unknown fields", format!("profile {q} is malformed ({e})")));
        }
        if !p.manifest.disposable {
            return Err(bad_profile("the profile is not marked disposable", format!("profile {q} is not disposable, so Limbo refuses it")));
        }
        if p.manifest.os != manifest::OS_LINUX {
            return Err(bad_profile("the profile is not a Linux guest", format!("profile {q} is not a Linux guest")));
        }
        if !p.ssh_identity.starts_with('/') {
            return Err(bad_profile(
                "the profile ssh_identity is not an absolute path",
                format!("profile {q}: ssh_identity must be an absolute path"),
            ));
        }
        if p.max_seconds <= 0 {
            p.max_seconds = 900;
        }
        if p.max_output_bytes <= 0 {
            p.max_output_bytes = DEFAULT_OUTPUT_CAP;
        }
        let mf = manifest::parse(p.manifest.json().as_bytes())
            .map_err(|e| bad_profile("the profile manifest is invalid", format!("profile {q} is malformed ({e})")))?;
        p.manifest = mf;
        Ok(p)
    }

    pub fn start(&self, profile: &str, command: &str, timeout: i64) -> Result<String, Refusal> {
        self.start_logged(profile, command, None, None, AGENT, timeout)
    }

    pub fn start_bundle(&self, profile: &str, command: &str, bundle: Vec<u8>, timeout: i64) -> Result<String, Refusal> {
        let b = if bundle.is_empty() { None } else { Some(bundle) };
        self.start_logged(profile, command, b, None, AGENT, timeout)
    }

    /// One file from root's inbox analysed in a sealed guest (admin socket only).
    pub fn start_sample(&self, profile: &str, command: &str, sample: &str, timeout: i64) -> Result<String, Refusal> {
        if !sample_name_ok(sample) || self.sample_dir.is_empty() {
            return Err(new_err(
                CODE_BAD_REQUEST,
                "put the file in Limbo's inbox and give its name only",
                "the sample must be a plain file name in the inbox".into(),
            ));
        }
        let path = sys::join(&[&self.sample_dir, sample]);
        let mut f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path).map_err(|_| {
            new_err(
                CODE_BAD_REQUEST,
                "put the file in Limbo's inbox first",
                format!("the sample {} cannot be opened in the inbox", gotext::quote(sample)),
            )
        })?;
        if !f.metadata().is_ok_and(|m| m.is_file()) {
            return Err(new_err(CODE_BAD_REQUEST, "send a regular file", "the sample is not a regular file".into()));
        }
        let mut b = Vec::new();
        let r = (&mut f).take(MAX_SAMPLE as u64 + 1).read_to_end(&mut b);
        if r.is_err() || b.is_empty() || b.len() > MAX_SAMPLE {
            return Err(new_err(
                CODE_BAD_REQUEST,
                "send a file of 1 byte to 64 MiB",
                format!("the sample is empty, unreadable or larger than {MAX_SAMPLE} bytes"),
            ));
        }
        self.start_logged(profile, command, None, Some(b), SAMPLE, timeout)
    }

    /// Ends every agent run now (Heimdall contained Sarina). Sample runs go on.
    pub fn stop_agent_runs(&self) -> i64 {
        let st = self.lock();
        let mut n = 0;
        for (id, k) in &st.kinds {
            if *k == AGENT {
                if let Some(c) = st.cancels.get(id) {
                    c.store(true, Ordering::SeqCst);
                    n += 1;
                }
            }
        }
        n
    }

    fn start_logged(
        &self,
        profile: &str,
        command: &str,
        bundle: Option<Vec<u8>>,
        sample: Option<Vec<u8>>,
        kind: &'static str,
        timeout: i64,
    ) -> Result<String, Refusal> {
        let r = self.start_inner(profile, command, bundle, sample, kind, timeout);
        if let Err(e) = &r {
            let guest = if profile_name_ok(profile) { profile } else { "" };
            let _ = self.events.emit(events::RUN_ERROR, guest, detail([("code", &e.code)]));
        }
        r
    }

    fn start_inner(
        &self,
        profile: &str,
        command: &str,
        bundle: Option<Vec<u8>>,
        sample: Option<Vec<u8>>,
        kind: &'static str,
        timeout: i64,
    ) -> Result<String, Refusal> {
        if kind == AGENT && self.contained.as_ref().is_some_and(|c| c()) {
            return Err(new_err(
                CODE_CONTAINED,
                "wait until the owner releases Sarina (Settings > Security)",
                "Heimdall has contained Sarina: no runs for her agents meanwhile".into(),
            ));
        }
        let p = self.load_profile(profile)?;
        let q = gotext::quote(profile);
        if kind == SAMPLE {
            let mf = &p.manifest;
            if !p.allow_sample || mf.network.mode != "none" || mf.access.sudo || !mf.exchange_dir.is_empty() || mf.devices.any() {
                return Err(new_err(
                    CODE_PROFILE_INVALID,
                    "use a sealed profile with allow_sample (no network, no sudo, no shared folder, no devices)",
                    format!("profile {q} may not analyse samples"),
                ));
            }
            if !self.exec.samples() {
                return Err(new_err(
                    CODE_BAD_REQUEST,
                    "this Limbo cannot carry a sample into a guest",
                    "samples are not supported here".into(),
                ));
            }
        }
        if let Some(b) = &bundle {
            if !p.allow_bundle {
                return Err(new_err(
                    CODE_BAD_REQUEST,
                    "use a profile whose author allows bundles (allow_bundle in the profile)",
                    format!("profile {q} does not accept files"),
                ));
            }
            if b.len() > MAX_BUNDLE {
                return Err(new_err(
                    CODE_BAD_REQUEST,
                    "send less: only source files, no data or binaries",
                    format!("the bundle is larger than {MAX_BUNDLE} bytes"),
                ));
            }
            if !self.exec.bundles() {
                return Err(new_err(
                    CODE_BAD_REQUEST,
                    "this Limbo cannot carry files into a guest",
                    "bundles are not supported here".into(),
                ));
            }
        }
        if std::fs::metadata(&p.manifest.image.path).is_err() {
            return Err(new_err(
                CODE_IMAGE_MISSING,
                "ask the operator to restore the profile's base image",
                format!("the base image for profile {q} is missing or unreadable"),
            ));
        }
        for check in [Engine::check_hardware, Engine::ready_hardware] {
            if let Err(e) = check(&self.engine, &p.manifest) {
                let _ = self.events.emit(events::GATE_BLOCKED, profile, detail([("reason", &e.to_string())]));
                return Err(hardware_err(&e));
            }
        }
        if command.is_empty() || command.len() > MAX_COMMAND || command.contains('\0') {
            return Err(new_err(
                CODE_BAD_REQUEST,
                "send a non-empty command without NUL bytes",
                format!("command must be 1-{MAX_COMMAND} bytes"),
            ));
        }
        let mut timeout = if timeout <= 0 { DEFAULT_SECONDS } else { timeout };
        if timeout > p.max_seconds {
            timeout = p.max_seconds;
        }
        let mut st = self.lock();
        let running = st.kinds.values().filter(|k| **k == kind).count();
        if kind == SAMPLE && running >= MAX_SAMPLES {
            return Err(new_err(CODE_BUSY, "wait about a minute and retry", "a sample analysis is already in progress".into()));
        }
        if kind != SAMPLE && running >= MAX_CONCURRENT {
            return Err(new_err(
                CODE_BUSY,
                "wait about a minute and retry",
                format!("{MAX_CONCURRENT} validation runs are already in progress"),
            ));
        }
        for d in p.manifest.devices.all() {
            if st.dev_held.values().any(|held| held.contains(&d)) {
                return Err(new_err(
                    CODE_BUSY,
                    "wait for the run using the device to finish, then retry",
                    "a device this profile needs is in use by another run".into(),
                ));
            }
        }
        let id = format!("r{}", sys::rand_hex(4));
        if p.manifest.devices.any() {
            st.dev_held.insert(id.clone(), p.manifest.devices.all());
        }
        let res = RunResult {
            id: id.clone(),
            profile: profile.to_string(),
            status: "running".into(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
            error: String::new(),
            code: String::new(),
            remedy: String::new(),
            started: Time::now().utc(),
            ended: Time::default(),
        };
        st.results.insert(id.clone(), res);
        let (ctx, cancel) = Ctx::background().with_cancel();
        st.kinds.insert(id.clone(), kind);
        st.cancels.insert(id.clone(), cancel);
        st.order.push(id.clone());
        while st.order.len() > MAX_RESULTS {
            let old = st.order.remove(0);
            st.results.remove(&old);
        }
        drop(st);
        let stdin = sample.map(|s| (s, true)).or(bundle.map(|b| (b, false)));
        let me = self.self_arc();
        let id2 = id.clone();
        let cmd = command.to_string();
        let limit = Duration::from_secs(timeout as u64);
        let spawned = std::thread::Builder::new().name(format!("run-{id}")).stack_size(256 << 10).spawn(move || {
            if let Some(m) = me.upgrade() {
                m.execute(&ctx, &id2, &p, &cmd, stdin, limit);
            }
        });
        if spawned.is_err() {
            self.finish(&id, |r| {
                r.status = "failed".into();
            });
        }
        Ok(id)
    }

    /// The Arc this manager lives in (set by `into_arc`), so a run's thread can hold it.
    fn self_arc(&self) -> std::sync::Weak<Manager> {
        self.me.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn get(&self, id: &str) -> Option<RunResult> {
        self.lock().results.get(id).cloned()
    }

    fn finish(&self, id: &str, f: impl FnOnce(&mut RunResult)) {
        let mut st = self.lock();
        if let Some(r) = st.results.get_mut(id) {
            f(r);
            r.ended = Time::now().utc();
        }
        st.dev_held.remove(id);
        if let Some(c) = st.cancels.remove(id) {
            c.store(true, Ordering::SeqCst);
        }
        st.kinds.remove(id);
    }

    fn execute(&self, ctx: &Ctx, id: &str, p: &Profile, command: &str, stdin: Option<(Vec<u8>, bool)>, limit: Duration) {
        if let Some(gate) = self.hold_runs.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            while !gate.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let mut mf = p.manifest.clone();
        mf.name = id.to_string();
        let runs_dir = sys::join(&[&self.state_dir, "runs"]);
        let run_dir = sys::join(&[&runs_dir, id]);
        let iso = sys::join(&[&run_dir, "seed.iso"]);
        mf.provision.seed_iso = iso.clone();
        let mut start = detail([
            ("profile", &sys::base(&p.ssh_identity)),
            ("command_sha256", &sys::hex(&Sha256::digest(command.as_bytes()))),
            ("command", &clip(command, 200)),
        ]);
        match &stdin {
            Some((b, false)) => {
                start.insert("bundle_sha256".into(), sys::hex(&Sha256::digest(b)));
                start.insert("bundle_bytes".into(), b.len().to_string());
            }
            Some((s, true)) => {
                start.insert("sample_sha256".into(), sys::hex(&Sha256::digest(s)));
                start.insert("sample_bytes".into(), s.len().to_string());
            }
            None => {}
        }
        let _ = self.events.emit(events::RUN_START, id, start);
        let boot = ctx.with_timeout(Duration::from_secs(BOOT_BUDGET_SECONDS));
        let mut out: Output = (String::new(), String::new(), 0, false);
        let mut timed_out = false;
        let mut fail: Option<Refusal> = None;
        let mut leaked = false;
        for d in [&runs_dir, &run_dir] {
            if let Err(e) = mkdir_traversable(d) {
                fail = Some(classify("prepare", &Failure::text(&sys::go_err(&e)), false));
                break;
            }
        }
        if fail.is_none() {
            (|| {
                if let Err(e) = (self.build_seed)(&boot, &mf, &sys::join(&[&run_dir, "seed"]), &iso) {
                    fail = Some(classify("seed", &Failure::engine(&e), boot.deadline_exceeded()));
                    return;
                }
                if let Err(e) = self.engine.up(&boot, &mut mf) {
                    fail = Some(classify("up", &Failure::engine(&e), boot.deadline_exceeded()));
                    return;
                }
                let ip = virt::ip4(virt::addr(&mf).guest);
                let wctx = boot.with_timeout(Duration::from_secs(READY_WAIT_SECONDS));
                if let Err(e) = self.exec.wait_ready(&wctx, &ip, &mf.access.user, &p.ssh_identity) {
                    fail = Some(classify("ready", &Failure::exec(&e), wctx.deadline_exceeded()));
                    return;
                }
                let cctx = ctx.with_timeout(limit);
                let wrapped = wrap(command, stdin.as_ref());
                let (o, err) = self.exec.run(
                    &cctx,
                    &ip,
                    &mf.access.user,
                    &p.ssh_identity,
                    &wrapped,
                    stdin.as_ref().map(|x| x.0.as_slice()),
                    p.max_output_bytes,
                );
                out = o;
                timed_out = cctx.deadline_exceeded() && !ctx.cancelled();
                if let Some(e) = err {
                    if !timed_out {
                        fail = Some(classify("command", &Failure::exec(&e), false));
                    }
                }
            })();
            let dctx = Ctx::background().with_timeout(Duration::from_millis(TEARDOWN_TIMEOUT_MS));
            leaked = self.engine.down(&dctx, &mf).is_err();
            self.engine.clean_state(&mf);
            if !leaked {
                let _ = std::fs::remove_dir_all(&run_dir);
            }
        }
        let (status, note): (&str, Option<Refusal>) = if let Some(f) = fail {
            ("failed", Some(f))
        } else if timed_out {
            (
                "timeout",
                Some(new_err(
                    CODE_COMMAND_TIMEOUT,
                    "raise timeout_seconds (up to the profile's limit) or run something shorter",
                    format!("the command was still running after {} seconds and was killed", limit.as_secs()),
                )),
            )
        } else if leaked {
            (
                "done",
                Some(new_err(
                    CODE_TEARDOWN_FAILED,
                    &format!("ask the operator to destroy the leftover guest limbo-{id} (virsh -c qemu:///system list --all)"),
                    "the command ran but cleaning up the guest did not finish".into(),
                )),
            )
        } else if out.3 {
            (
                "done",
                Some(new_err(
                    CODE_OUTPUT_TRUNC,
                    "filter the output (grep, tail) and rerun if the missing part matters",
                    "the command ran but its output was cut at the profile's size limit".into(),
                )),
            )
        } else {
            ("done", None)
        };
        let mut d = detail([("status", status)]);
        if status == "done" {
            d.insert("exit_code".into(), out.2.to_string());
        }
        if let Some(n) = &note {
            d.insert("code".into(), n.code.clone());
        }
        if leaked {
            d.insert("teardown".into(), "failed".into());
        }
        let _ = self.events.emit(events::RUN_END, id, d);
        if let Some(n) = &note {
            if n.code != CODE_OUTPUT_TRUNC {
                let _ = self.events.emit(events::RUN_ERROR, id, detail([("code", &n.code)]));
            }
        }
        sys::trim();
        self.finish(id, |r| {
            r.status = status.into();
            r.stdout = sanitize(&out.0);
            r.stderr = sanitize(&out.1);
            r.truncated = out.3;
            if status == "done" {
                r.exit_code = Some(out.2);
            }
            if let Some(n) = note {
                r.code = n.code.clone();
                r.remedy = n.remedy.clone();
                if n.code != CODE_OUTPUT_TRUNC {
                    r.error = n.to_string();
                }
            }
        });
    }

    /// Destroys guests left by runs that did not finish (a restart mid-run, a failed teardown). Once, at startup.
    pub fn reap_orphans(&self) -> i64 {
        let dir = sys::join(&[&self.state_dir, "runs"]);
        let mut n = 0;
        for (id, ft) in sys::read_dir_sorted(&dir).unwrap_or_default() {
            if !ft.is_dir() || !run_id_ok(&id) {
                continue;
            }
            let mf = crate::engine::load_guest(&self.state_dir, &id).unwrap_or(Manifest {
                name: id.clone(),
                disposable: true,
                ..Manifest::default()
            });
            if self.engine.down(&Ctx::background(), &mf).is_err() {
                let _ = self.events.emit(events::RUN_ERROR, &id, detail([("code", CODE_TEARDOWN_FAILED), ("during", "startup reap")]));
                continue;
            }
            self.engine.clean_state(&mf);
            let _ = std::fs::remove_dir_all(sys::join(&[&dir, &id]));
            let _ = self.events.emit(events::RUN_ERROR, &id, detail([("code", CODE_GUEST_KILLED), ("during", "startup reap")]));
            n += 1;
        }
        n
    }

    // ---- profiles ----

    fn scan(&self) -> (Vec<(String, Profile)>, Vec<Skipped>) {
        let mut seen = self.scan_mu.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(ents) = sys::read_dir_sorted(&self.profile_dir) else { return (vec![], vec![]) };
        let (mut ok, mut skipped) = (vec![], vec![]);
        let mut now: HashMap<String, String> = HashMap::new();
        for (file, ft) in ents {
            if !ft.is_file() || !file.ends_with(".json") {
                continue;
            }
            let n = file.trim_end_matches(".json").to_string();
            let n = file.strip_suffix(".json").map(String::from).unwrap_or(n);
            let mut sk = if !profile_name_ok(&n) {
                Skipped {
                    name: String::new(),
                    code: CODE_PROFILE_INVALID.into(),
                    reason: "the profile file name is not a valid profile name".into(),
                    remedy: "rename it: lowercase letters, digits and hyphens".into(),
                }
            } else {
                match self.load_profile(&n) {
                    Err(e) => skip_for(&e),
                    Ok(p) => match self.check_image(&p) {
                        Err(e) => skip_for(&e),
                        Ok(()) => match self.engine.check_hardware(&p.manifest) {
                            Err(e) => skip_for(&hardware_err(&e)),
                            Ok(()) => {
                                ok.push((n, p));
                                continue;
                            }
                        },
                    },
                }
            };
            if sk.name.is_empty() && profile_name_ok(&n) {
                sk.name = n.clone();
            }
            now.insert(file.clone(), sk.code.clone());
            if seen.get(&file) != Some(&sk.code) {
                let guest = if profile_name_ok(&n) { n.as_str() } else { "" };
                let _ = self.events.emit(events::RUN_ERROR, guest, detail([("code", &sk.code), ("during", "profile scan")]));
            }
            skipped.push(sk);
        }
        *seen = now;
        ok.sort_by(|a, b| a.0.cmp(&b.0));
        skipped.sort_by(|a, b| a.name.cmp(&b.name));
        (ok, skipped)
    }

    fn check_image(&self, p: &Profile) -> Result<(), Refusal> {
        let img = &p.manifest.image;
        let missing = || {
            new_err(
                CODE_IMAGE_MISSING,
                "ask the operator to restore the profile's base image",
                "the profile's base image is missing".into(),
            )
        };
        if std::fs::metadata(&img.path).is_err() {
            return Err(missing());
        }
        match self.images.check_cached(&img.path, &img.sha256).1 {
            Ok(()) => Ok(()),
            Err(CheckErr::Mismatch(_)) => Err(new_err(
                CODE_IMAGE_MISMATCH,
                "ask the operator to re-verify the image and update the profile's sha256",
                "the profile's base image does not match its recorded checksum".into(),
            )),
            Err(_) => Err(missing()),
        }
    }

    pub fn profiles(&self) -> Vec<String> {
        self.scan().0.into_iter().map(|(n, _)| n).collect()
    }

    pub fn details_json(&self) -> String {
        let items: Vec<String> = self
            .scan()
            .0
            .iter()
            .map(|(n, p)| {
                Obj::new()
                    .str("name", n)
                    .str("network", &p.manifest.network.mode)
                    .bool("sudo", p.manifest.access.sudo)
                    .bool("passthrough", p.manifest.devices.any())
                    .int("max_seconds", p.max_seconds)
                    .end()
            })
            .collect();
        gojson::list(&items)
    }

    /// The uncapped list, for `limbo doctor` (Go's SkippedAll).
    pub fn skipped_all(&self) -> Vec<Skipped> {
        self.scan().1
    }

    pub fn skipped(&self) -> Vec<Skipped> {
        let mut sk = self.scan().1;
        if sk.len() > MAX_SKIPPED {
            let more = sk.len() - MAX_SKIPPED;
            sk.truncate(MAX_SKIPPED);
            sk.push(Skipped {
                name: String::new(),
                code: CODE_MORE.into(),
                reason: format!("{more} more profiles skipped"),
                remedy: "see the Limbo log or 'limbo doctor'".into(),
            });
        }
        sk
    }
}

/// A Manager in an Arc, with the weak self-reference its run threads use.
pub fn into_arc(m: Manager) -> Arc<Manager> {
    let a = Arc::new(m);
    *a.me.lock().unwrap_or_else(|e| e.into_inner()) = Arc::downgrade(&a);
    a
}

#[derive(Clone, Debug, PartialEq)]
pub struct Skipped {
    pub name: String,
    pub code: String,
    pub reason: String,
    pub remedy: String,
}

impl Skipped {
    pub fn json(&self) -> String {
        Obj::new().str("name", &self.name).str("code", &self.code).str("reason", &self.reason).str("remedy", &self.remedy).end()
    }
}

fn skip_for(e: &Refusal) -> Skipped {
    let mut s = Skipped { name: String::new(), code: e.code.clone(), reason: e.short.clone(), remedy: e.remedy.clone() };
    if s.reason.is_empty() {
        match e.code.as_str() {
            CODE_IMAGE_MISSING => s.reason = "the profile's base image is missing".into(),
            CODE_IMAGE_MISMATCH => s.reason = "the profile's base image does not match its recorded checksum".into(),
            _ => {
                s.code = CODE_PROFILE_INVALID.into();
                s.reason = "the profile file could not be read".into();
                s.remedy = "ask the operator to fix the profile file".into();
            }
        }
    }
    s
}

/// What went wrong at a stage, with what classify tells apart.
pub struct Failure {
    pub text: String,
    pub not_exist: bool,
    pub mismatch: bool,
    pub not_found: bool,
    pub connection: bool,
}

impl Failure {
    pub fn text(t: &str) -> Failure {
        Failure { text: t.into(), not_exist: false, mismatch: false, not_found: false, connection: false }
    }
    pub fn engine(e: &EngineErr) -> Failure {
        let mut f = Failure::text(&e.to_string());
        match e {
            EngineErr::Image(CheckErr::Mismatch(_)) => f.mismatch = true,
            EngineErr::Image(CheckErr::Io { not_exist, .. }) => f.not_exist = *not_exist,
            EngineErr::Cmd(c) => f.not_found = c.not_found,
            _ => {}
        }
        f
    }
    pub fn exec(e: &ExecErr) -> Failure {
        let mut f = Failure::text(&e.text);
        f.connection = e.connection;
        f.not_found = e.not_found;
        f
    }
}

/// What went wrong at a stage of a run, as a coded error; raw text (host paths) is never copied into the message.
pub fn classify(stage: &str, f: &Failure, deadline_exceeded: bool) -> Refusal {
    let text = f.text.to_lowercase();
    if deadline_exceeded && stage != "command" {
        return new_err(
            CODE_BOOT_TIMEOUT,
            "retry once; if it repeats, check the host load and the guest image",
            "the guest did not become ready within its boot budget".into(),
        );
    }
    if f.not_exist && stage == "up" {
        return new_err(
            CODE_IMAGE_MISSING,
            "ask the operator to restore the profile's base image",
            "the profile's base image is missing".into(),
        );
    }
    if f.mismatch {
        return new_err(
            CODE_IMAGE_MISMATCH,
            "ask the operator to re-verify the image and update the profile's sha256",
            "the profile's base image does not match its recorded checksum".into(),
        );
    }
    if text.contains("no space left") || text.contains("cannot allocate memory") || text.contains("out of memory") {
        return new_err(
            CODE_HOST_RESOURCES,
            "ask the operator to free disk space or memory, then retry",
            "the host ran out of disk space or memory".into(),
        );
    }
    if f.not_found || text.contains("failed to connect to the hypervisor") || text.contains("failed to connect socket") {
        return new_err(
            CODE_VIRT_UNAVAIL,
            "ask the operator to check that libvirtd and QEMU are running",
            "the virtualization stack is unavailable on the host".into(),
        );
    }
    if f.connection && stage == "command" {
        return new_err(
            CODE_GUEST_KILLED,
            "retry; if it repeats the command may be crashing or powering off the guest",
            "the guest stopped responding while the command was running".into(),
        );
    }
    if stage == "command" {
        return new_err(
            CODE_RUN_FAILED,
            "retry; if it repeats, ask the operator to read the Limbo logs",
            "Limbo could not run the command in the guest (this is not the command failing)".into(),
        );
    }
    new_err(
        CODE_BOOT_FAILED,
        "retry once; if it repeats, ask the operator to read the Limbo logs",
        "the guest could not be started or never became reachable".into(),
    )
}

/// Guest output made safe for JSON and a model: valid UTF-8, no control characters but newline and tab.
pub fn sanitize(s: &str) -> String {
    s.chars().filter(|&c| !((c as u32) < 0x20 && c != '\n' && c != '\t' || c as u32 == 0x7f)).collect()
}

/// The engine's hardware refusal as the coded error a model may see.
pub fn hardware_err(e: &EngineErr) -> Refusal {
    let (code, remedy, msg, short) = match e {
        EngineErr::Hardware(Refused::NeedsApproval) => (
            CODE_APPROVAL_REQUIRED,
            "tell the user a GPU test needs their approval (they run 'sudo limbo passthrough approve' at a terminal); you cannot approve it",
            "the profile needs a real host device and the user has not approved a GPU test window",
            "the profile needs a GPU test window the user has not approved",
        ),
        EngineErr::Hardware(Refused::Busy(_)) => (
            CODE_HARDWARE_BUSY,
            "tell the user to close apps using the GPU, then retry",
            "the device is in use on the host",
            "the profile's device is in use on the host",
        ),
        EngineErr::Hardware(Refused::RebootNeeded) => (
            CODE_REBOOT_REQUIRED,
            "tell the user the GPU did not come back cleanly after an earlier run and the host must be rebooted",
            "a passthrough device did not return to the host cleanly",
            "a passthrough device needs a host reboot",
        ),
        _ => (
            CODE_HARDWARE_DENIED,
            "this profile cannot run on this host; use a profile without devices, or ask the operator",
            "the profile needs a host device and this host does not allow it",
            "the profile needs a host device this host does not allow",
        ),
    };
    let mut r = new_err(code, remedy, msg.into());
    r.short = short.into();
    r
}

fn mkdir_traversable(p: &str) -> std::io::Result<()> {
    sys::mkdir_all(p, 0o711)?;
    sys::chmod(p, 0o711)
}

fn clip(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        gotext::byte_prefix(s, n)
    }
}

// ---- ssh ----

/// The real executor: ssh with host key checking off (each run's guest is disposable, its address fixed by Limbo).
pub struct Ssh;

fn ssh_args(ip: &str, user: &str, identity: &str) -> Vec<String> {
    [
        "-i",
        identity,
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "LogLevel=ERROR",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain([format!("{user}@{ip}")])
    .collect()
}

pub fn bundle_wrap(command: &str) -> String {
    format!(
        r#"rm -rf "$HOME/agent" && mkdir "$HOME/agent" && tar --no-same-owner --no-same-permissions -xf - -C "$HOME/agent" && cd "$HOME/agent" && ({command})"#
    )
}

pub fn sample_wrap(command: &str) -> String {
    format!(
        r#"umask 077 && rm -rf "$HOME/sample" && mkdir "$HOME/sample" && cat > "$HOME/sample/sample" && chmod 0400 "$HOME/sample/sample" && cd "$HOME/sample" && export LIMBO_SAMPLE_DIR="$HOME/sample" && ({command})"#
    )
}

fn ctx_err(ctx: &Ctx) -> ExecErr {
    let t = if ctx.cancelled() { "context canceled" } else { "context deadline exceeded" };
    ExecErr { text: t.into(), connection: false, not_found: false }
}

impl Ssh {
    fn spawn_capture(ctx: &Ctx, args: Vec<String>, stdin: Option<&[u8]>, limit: i64) -> (Output, Option<ExecErr>) {
        use std::process::{Command, Stdio};
        let Some(path) = crate::exchange::look_path("ssh") else {
            return (
                (String::new(), String::new(), 0, false),
                Some(ExecErr { text: crate::engine::not_found("ssh").text, connection: false, not_found: true }),
            );
        };
        let mut c = Command::new(path);
        c.args(&args).stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        let mut child = match c.spawn() {
            Ok(ch) => ch,
            Err(e) => {
                return (
                    (String::new(), String::new(), 0, false),
                    Some(ExecErr { text: sys::go_err(&e), connection: false, not_found: false }),
                )
            }
        };
        if let (Some(data), Some(mut w)) = (stdin.map(|d| d.to_vec()), child.stdin.take()) {
            std::thread::spawn(move || {
                use std::io::Write;
                let _ = w.write_all(&data);
            });
        }
        let cap = |r: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let (mut b, mut trunc) = (Vec::new(), false);
                let mut chunk = [0u8; 8192];
                if let Some(mut r) = r {
                    while let Ok(n) = r.read(&mut chunk) {
                        if n == 0 {
                            break;
                        }
                        let room = (limit.max(0) as usize).saturating_sub(b.len());
                        if n > room {
                            trunc = true;
                        }
                        b.extend_from_slice(&chunk[..n.min(room)]);
                    }
                }
                (b, trunc)
            })
        };
        let so = cap(child.stdout.take().map(|x| Box::new(x) as Box<dyn Read + Send>));
        let se = cap(child.stderr.take().map(|x| Box::new(x) as Box<dyn Read + Send>));
        let status = match crate::engine::wait_ctx(ctx, &mut child) {
            Ok((s, _)) => Some(s),
            _ => None,
        };
        let (ob, ot) = so.join().unwrap_or_default();
        let (eb, et) = se.join().unwrap_or_default();
        // Go keeps the bytes and makes them valid UTF-8 (a run of bad bytes as one U+FFFD) before they are shown
        let (o, e) = (gotext::to_valid_utf8(&ob), gotext::to_valid_utf8(&eb));
        let trunc = ot || et;
        match status {
            Some(s) if s.success() => ((o, e, 0, trunc), None),
            Some(s) if s.code() == Some(255) => {
                let t = format!("ssh connection failed: {e}");
                ((o, e, 0, trunc), Some(ExecErr { text: t, connection: true, not_found: false }))
            }
            Some(s) if s.code().is_some() => ((o, e, s.code().unwrap_or(0) as i64, trunc), None),
            // killed by a signal (its time ran out, or the run was stopped): Go reads exit -1 and no error
            Some(_) => ((o, e, -1, trunc), None),
            None => ((o, e, 0, trunc), Some(ctx_err(ctx))),
        }
    }
}

impl Executor for Ssh {
    fn wait_ready(&self, ctx: &Ctx, ip: &str, user: &str, identity: &str) -> Result<(), ExecErr> {
        loop {
            let mut a = ssh_args(ip, user, identity);
            a.push("true".into());
            let (_, err) = Ssh::spawn_capture(ctx, a, None, 0);
            if err.is_none() && !ctx.done() {
                return Ok(());
            }
            let until = std::time::Instant::now() + Duration::from_secs(2);
            while std::time::Instant::now() < until {
                if ctx.done() {
                    return Err(ctx_err(ctx));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    fn run(
        &self,
        ctx: &Ctx,
        ip: &str,
        user: &str,
        identity: &str,
        command: &str,
        stdin: Option<&[u8]>,
        limit: i64,
    ) -> (Output, Option<ExecErr>) {
        let mut a = ssh_args(ip, user, identity);
        a.push(command.to_string());
        Ssh::spawn_capture(ctx, a, stdin, limit)
    }
}

/// The run's command for the executor: a bundle is unpacked first, a sample stored read-only first.
pub fn wrap(command: &str, stdin: Option<&(Vec<u8>, bool)>) -> String {
    match stdin {
        Some((_, true)) => sample_wrap(command),
        Some((_, false)) => bundle_wrap(command),
        None => command.to_string(),
    }
}
