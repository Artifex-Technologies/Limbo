//! Limbo's Wine backend (Go: internal/wine; docs/ARCHITECTURE.md section 13): Windows programs run with Wine on the host
//! desktop, each prefix inside its own bubblewrap sandbox. Wine is not a security boundary, so Limbo never runs it bare:
//! the sandbox gets the system read-only, a private /tmp and home holding only the prefix, the display, sound and
//! graphics card, and nothing else unless a share or a profile names it.
//!
//! The port follows the Go package file by file: this module is wine.go, options.go and shares.go; `profile`, `sandbox`,
//! `xauth`, `trace`, `prefix`, `record`, `probe` and `run` the others; `paths` holds Go's path functions the package
//! relies on (EvalSymlinks, Rel). Pinned by testdata/parity/wine.json (internal/wine/parity_test.go) and compared with the
//! Go binary by rust/parity/cli-differential.py.

pub mod paths;
pub mod prefix;
pub mod probe;
pub mod profile;
pub mod record;
pub mod run;
pub mod sandbox;
pub mod trace;
pub mod xauth;

use crate::gotext::quote;
use crate::sys;
use profile::Profile;
use std::collections::BTreeMap;

/// Fixed paths (absolute on purpose: Limbo's own `wine` shim sits earlier in PATH).
pub const BWRAP_PATH: &str = "/usr/bin/bwrap";
pub const WINE_PATH: &str = "/usr/bin/wine";
pub const WINESERVER_PATH: &str = "/usr/bin/wineserver";
pub const SH_PATH: &str = "/usr/bin/sh";

/// The prefix used when none is named.
pub const DEFAULT_PREFIX: &str = "default";

const NAME_RE: &str = "^[a-z0-9][a-z0-9_-]{0,47}$";

/// ValidName: `^[a-z0-9][a-z0-9_-]{0,47}$`.
pub fn valid_name(name: &str) -> Result<(), String> {
    let b = name.as_bytes();
    let first = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let ok = !b.is_empty() && b.len() <= 48 && first(b[0]) && b[1..].iter().all(|&c| first(c) || c == b'_' || c == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!("wine: prefix name {} must match {NAME_RE} (lowercase letters, digits, - and _)", quote(name)))
    }
}

/// The name a prefix's events carry in the log's guest field.
pub fn guest(prefix: &str) -> String {
    format!("wine:{prefix}")
}

pub const ARCH_WIN64: &str = "win64";
pub const ARCH_WIN32: &str = "win32";
pub const DEFAULT_WINDOWS: &str = "win10";
const WINDOWS_VERSIONS: [&str; 10] = ["win11", "win10", "win81", "win8", "win7", "vista", "winxp64", "winxp", "win2k", "win98"];

pub fn valid_windows(v: &str) -> Result<(), String> {
    if WINDOWS_VERSIONS.contains(&v) {
        return Ok(());
    }
    Err(format!("wine: Windows version {} is not one of {}", quote(v), WINDOWS_VERSIONS.join(", ")))
}

pub fn valid_arch(a: &str) -> Result<(), String> {
    if a != ARCH_WIN64 && a != ARCH_WIN32 {
        return Err(format!("wine: arch must be {} or {}, got {}", quote(ARCH_WIN64), quote(ARCH_WIN32), quote(a)));
    }
    Ok(())
}

pub const NET_NONE: &str = "none";
pub const NET_HOST: &str = "host";

/// Where Limbo keeps each prefix and what must never be shared into a sandbox.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Dirs {
    pub root: String,
    pub cache: String,
    pub config: String,
    pub state: String,
}

impl Dirs {
    /// DefaultDirs: the XDG base directories (a relative value is ignored).
    pub fn default_dirs(getenv: &dyn Fn(&str) -> String, home: &str, state: &str) -> Dirs {
        let xdg = |name: &str, fallback: &str| {
            let v = getenv(name);
            if v.starts_with('/') {
                sys::clean(&v)
            } else {
                sys::join(&[home, fallback])
            }
        };
        Dirs {
            root: sys::join(&[&xdg("XDG_DATA_HOME", ".local/share"), "limbo", "wine"]),
            cache: sys::join(&[&xdg("XDG_CACHE_HOME", ".cache"), "limbo", "wine"]),
            config: sys::join(&[&xdg("XDG_CONFIG_HOME", ".config"), "limbo", "wine"]),
            state: sys::clean(state),
        }
    }

    pub fn prefix(&self, name: &str) -> String {
        sys::join(&[&self.root, name])
    }

    pub fn prefix_cache(&self, name: &str) -> String {
        sys::join(&[&self.cache, name])
    }

    pub fn profile(&self, name: &str) -> String {
        sys::join(&[&self.config, &format!("{name}.json")])
    }

    pub fn lock_file(&self, name: &str) -> String {
        sys::join(&[&self.root, &format!(".{name}.lock")])
    }

    pub fn record_file(&self, name: &str) -> String {
        sys::join(&[&self.root, &format!(".{name}.json")])
    }

    pub fn creating_file(&self, name: &str) -> String {
        sys::join(&[&self.root, &format!(".{name}.creating")])
    }
}

/// A host folder (or file) mounted into the sandbox at the path the person gave.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Share {
    pub path: String,
    pub source: String,
    pub writable: bool,
}

/// What one run asks for: a profile's settings merged with the command line's.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Options {
    pub prefix: String,
    pub network: String,
    pub gpu: bool,
    pub audio: bool,
    pub display: bool,
    pub x11: bool,
    pub shares: Vec<Share>,
    pub env: BTreeMap<String, String>,
    pub arch: String,
    pub windows: String,
    pub trace: bool,
}

/// The command line's settings, which go on top of a profile's.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Flags {
    pub network: bool,
    pub no_gpu: bool,
    pub no_audio: bool,
    pub no_x11: bool,
    pub no_display: bool,
    pub headless: bool,
    pub share: Vec<String>,
    pub share_rw: Vec<String>,
    pub env: Vec<String>,
    pub windows: String,
    pub arch: String,
    pub trace: bool,
}

/// maxShares bounds how many folders one run may be given.
pub const MAX_SHARES: usize = 32;

/// Merge: the defaults, then the profile, then the command line (which may narrow what the profile allows, never widen
/// the display, sound or graphics card back on). Shares are resolved here and checked when the run starts.
pub fn merge(prefix: &str, p: Option<&Profile>, f: &Flags, cwd: &str, home: &str) -> Result<Options, String> {
    let mut o =
        Options { prefix: prefix.into(), network: NET_NONE.into(), gpu: true, audio: true, display: true, x11: true, ..Options::default() };
    let (mut ro, mut rw): (Vec<String>, Vec<String>) = (vec![], vec![]);
    if let Some(p) = p {
        if !p.network.is_empty() {
            o.network = p.network.clone();
        }
        let on = |b: Option<bool>| b.unwrap_or(true);
        (o.gpu, o.audio, o.display, o.x11) = (on(p.gpu), on(p.audio), on(p.display), on(p.x11));
        for (k, v) in p.env.iter().flatten() {
            o.env.insert(k.clone(), v.clone());
        }
        (o.windows, o.arch, o.trace) = (p.windows.clone(), p.arch.clone(), p.trace);
        for (list, out) in [(&p.share, &mut ro), (&p.share_rw, &mut rw)] {
            for s in list.iter().flatten() {
                let s = match s.strip_prefix("~/") {
                    Some(rest) => sys::join(&[home, rest]),
                    None => s.clone(),
                };
                if !s.starts_with('/') {
                    return Err(format!("wine profile: share {} must be an absolute path (or start with ~/)", quote(&s)));
                }
                out.push(s);
            }
        }
    }
    if f.network {
        o.network = NET_HOST.into();
    }
    if f.no_gpu {
        o.gpu = false;
    }
    if f.no_audio || f.headless {
        o.audio = false;
    }
    if f.no_display || f.headless {
        o.display = false;
    }
    if f.no_x11 {
        o.x11 = false;
    }
    if !f.windows.is_empty() {
        o.windows = f.windows.clone();
    }
    if !f.arch.is_empty() {
        o.arch = f.arch.clone();
    }
    o.trace = o.trace || f.trace;
    for kv in &f.env {
        let Some((k, v)) = kv.split_once('=') else {
            return Err(format!("wine: --env {} is not NAME=VALUE", quote(kv)));
        };
        sandbox::valid_env_name(k)?;
        o.env.insert(k.into(), v.into());
    }
    ro.extend(f.share.iter().cloned());
    rw.extend(f.share_rw.iter().cloned());
    if ro.len() + rw.len() > MAX_SHARES {
        return Err(format!("wine: more than {MAX_SHARES} shares"));
    }
    let mut by_path: BTreeMap<String, usize> = BTreeMap::new();
    for (paths, writable) in [(&ro, false), (&rw, true)] {
        for given in paths {
            let sh = resolve_share(given, cwd, writable)?;
            if let Some(&i) = by_path.get(&sh.path) {
                if o.shares[i].writable != sh.writable {
                    return Err(format!("wine: {} is shared both read-only and writable", sh.path));
                }
                continue;
            }
            by_path.insert(sh.path.clone(), o.shares.len());
            o.shares.push(sh);
        }
    }
    Ok(o)
}

/// ShimPrefix: the prefix for a run through Limbo's `wine` on PATH, from the caller's WINEPREFIX.
pub fn shim_prefix(wineprefix: &str, d: &Dirs) -> Result<String, String> {
    if wineprefix.is_empty() {
        return Ok(DEFAULT_PREFIX.into());
    }
    let p = sys::clean(wineprefix);
    if p.starts_with('/') && sys::dir(&p) == d.root && valid_name(&sys::base(&p)).is_ok() {
        return Ok(sys::base(&p));
    }
    Err(format!(
        "wine: WINEPREFIX={wineprefix} is not one of Limbo's prefixes, and Wine runs only through Limbo, in its own: set WINEPREFIX={}/NAME (made on first use), or run limbo wine --prefix NAME",
        d.root
    ))
}

/// ResolveShare: relative paths from cwd, the source with every symlink resolved; a folder or a regular file.
pub fn resolve_share(given: &str, cwd: &str, writable: bool) -> Result<Share, String> {
    if given.is_empty() {
        return Err("wine: an empty share".into());
    }
    let p = if given.starts_with('/') { given.to_string() } else { sys::join(&[cwd, given]) };
    let p = sys::clean(&p);
    let src = paths::eval_symlinks(&p).map_err(|e| format!("wine: share {given}: {e}"))?;
    let m = std::fs::metadata(&src).map_err(|e| format!("wine: share {given}: {}", sys::go_path_error("stat", &src, &e)))?;
    if !m.is_dir() && !m.is_file() {
        return Err(format!("wine: share {given} is not a folder or a regular file"));
    }
    Ok(Share { path: p, source: src, writable })
}

/// CheckShare: both the path as given and the resolved source.
pub fn check_share(sh: &Share, home: &str, d: &Dirs) -> Result<(), String> {
    for p in [&sh.path, &sh.source] {
        check_share_path(p, sh.writable, home, d).map_err(|e| format!("wine: share {} refused: {e}", sh.path))?;
    }
    Ok(())
}

fn check_share_path(p: &str, writable: bool, home: &str, d: &Dirs) -> Result<(), String> {
    if !p.starts_with('/') || sys::clean(p) != p {
        return Err("not an absolute, clean path".into());
    }
    if within(home, p) {
        return Err("it is your home folder or holds it".into());
    }
    for s in ["/proc", "/sys", "/dev", "/run"] {
        if within(p, s) {
            return Err(format!("it is a live system folder ({s})"));
        }
    }
    if p == "/tmp" || p == "/var/tmp" {
        return Err("it is the whole shared temporary folder (other programs' files and sockets); share a folder inside it".into());
    }
    let mut hidden = String::new();
    if let Ok(rel) = paths::rel(home, p) {
        if rel != "." && !rel.starts_with("..") {
            let first = rel.split('/').next().unwrap_or_default();
            if first.starts_with('.') {
                hidden = first.to_string();
                if rel == first {
                    return Err(format!("it is a whole hidden folder of your home ({first} holds settings, secrets or startup files)"));
                }
                if first == ".ssh" || first == ".gnupg" {
                    return Err(format!("it is inside {first} (keys)"));
                }
            }
        }
    }
    for own in [&d.root, &d.cache, &d.config, &d.state] {
        if !own.is_empty() && (within(p, own) || within(own, p)) {
            return Err(format!("it overlaps Limbo's own folder {own} (prefixes, profiles or the event log)"));
        }
    }
    if !hidden.is_empty() && writable {
        return Err(format!("a writable share inside a hidden folder of your home ({hidden}) could leave behind something the host runs"));
    }
    Ok(())
}

/// within: p is dir or inside it.
pub fn within(p: &str, dir: &str) -> bool {
    p == dir || dir == "/" || p.starts_with(&format!("{dir}/"))
}

/// visible: a host path is inside the sandbox at the same path (the prefix, a share, /usr).
pub fn visible(p: &str, o: &Options, d: &Dirs) -> bool {
    if within(p, &d.prefix(&o.prefix)) || within(p, "/usr") {
        return true;
    }
    o.shares.iter().any(|sh| within(p, &sh.path))
}
