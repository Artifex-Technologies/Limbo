//! Probe (Go: internal/wine/probe_linux.go): the Host facts from this machine and session. It only reads: the account,
//! which /etc entries exist, the display and sound sockets by stat, the graphics nodes by stat (never opened), the
//! sysfs folders the drivers read, and the folders under /opt that the system's Vulkan and EGL driver files name.

use super::paths::{eval_symlinks, glob_suffix};
use super::prefix::read_small;
use super::sandbox::{etc_all, Host};
use super::within;
use super::xauth::filter_xauth;
use crate::gojson::{self, Value};
use crate::osuser;
use crate::sys;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::FileTypeExt;

/// Probe, with the caller's environment.
pub fn probe(environ: &BTreeMap<String, String>) -> Result<Host, String> {
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let mut h = Host { uid, gid, env: environ.clone(), ..Host::default() };
    let env = |k: &str| h.env.get(k).cloned().unwrap_or_default();
    h.user = env("USER");
    h.home = env("HOME");
    if let Some(u) = osuser::current(uid, &env("USER"), &env("HOME")) {
        h.user = u.username;
        if !h.home.starts_with('/') {
            h.home = u.home_dir;
        }
    }
    if h.user.is_empty() || !h.home.starts_with('/') {
        return Err("wine: cannot tell this account's name and home folder (set USER and HOME)".into());
    }
    h.group = h.user.clone();
    if let Some(name) = osuser::lookup_group_id(&gid.to_string()) {
        h.group = name;
    }
    h.home = sys::clean(&h.home);

    for n in ["/bin", "/sbin", "/lib", "/lib64", "/lib32"] {
        if let Ok(m) = std::fs::symlink_metadata(n) {
            if m.file_type().is_symlink() {
                if let Ok(t) = std::fs::read_link(n) {
                    h.root_links.insert(n.into(), t.to_string_lossy().into_owned());
                }
            } else if m.is_dir() {
                h.root_dirs.push(n.into());
            }
        }
    }
    for n in etc_all() {
        if std::fs::metadata(format!("/etc/{n}")).is_ok() {
            h.etc.insert(n.into(), true);
        }
    }
    if let Ok(m) = std::fs::symlink_metadata("/etc/localtime") {
        if m.file_type().is_symlink() {
            if let Ok(t) = std::fs::read_link("/etc/localtime") {
                let mut t = t.to_string_lossy().into_owned();
                if !t.starts_with('/') {
                    t = sys::join(&["/etc", &t]);
                }
                let t = sys::clean(&t);
                if within(&t, "/usr") {
                    h.localtime = t;
                }
            }
        } else if m.is_file() {
            h.etc.insert("localtime".into(), true);
        }
    }
    h.ntsync = is_char("/dev/ntsync");
    h.cpuinfo = is_dir("/sys/devices/system/cpu");
    h.fontcache = is_dir("/var/cache/fontconfig");

    let mut run = env("XDG_RUNTIME_DIR");
    if !run.starts_with('/') {
        run.clear();
    }
    let w = env("WAYLAND_DISPLAY");
    if !w.is_empty() {
        let w = if !w.starts_with('/') && !run.is_empty() { sys::join(&[&run, &w]) } else { w };
        if w.starts_with('/') && is_socket(&w) {
            h.wayland = w;
        }
    }
    if let Some(n) = x11_display(&env("DISPLAY")) {
        let sock = format!("/tmp/.X11-unix/X{n}");
        if is_socket(&sock) {
            h.x11_display = n;
            h.x11_socket = sock;
            let mut xa = env("XAUTHORITY");
            if !xa.starts_with('/') {
                xa = sys::join(&[&h.home, ".Xauthority"]);
            }
            if let Ok(b) = read_small(&xa, 64 << 10) {
                h.xauth = Some(filter_xauth(&b, n));
            }
        }
    }
    let pulse_env = env("PULSE_SERVER");
    let mut pulse = pulse_env.strip_prefix("unix:").unwrap_or(&pulse_env).to_string();
    if !pulse.starts_with('/') && !run.is_empty() {
        pulse = sys::join(&[&run, "pulse", "native"]);
    }
    if pulse.starts_with('/') && is_socket(&pulse) {
        h.pulse = pulse;
        let mut cookie = env("PULSE_COOKIE");
        if !cookie.starts_with('/') {
            cookie = sys::join(&[&h.home, ".config", "pulse", "cookie"]);
        }
        if let Ok(b) = read_small(&cookie, 4 << 10) {
            h.pulse_cookie = b;
        }
    }
    if !run.is_empty() && is_socket(&sys::join(&[&run, "pipewire-0"])) {
        h.pipewire = sys::join(&[&run, "pipewire-0"]);
    }

    (h.gpu_nodes, h.gpu_sys) = probe_gpu();
    h.driver_dirs = driver_dirs();
    Ok(h)
}

/// nvidiaNode: `^nvidia([0-9]+|ctl|-modeset|-uvm|-uvm-tools)$`.
pub fn nvidia_node(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("nvidia") else { return false };
    (!rest.is_empty() && rest.bytes().all(|c| c.is_ascii_digit())) || matches!(rest, "ctl" | "-modeset" | "-uvm" | "-uvm-tools")
}

/// probeGPU: the DRM nodes and NVIDIA's, and the sysfs their drivers read.
fn probe_gpu() -> (Vec<String>, Vec<String>) {
    let (mut nodes, mut sys_dirs) = (vec![], vec![]);
    let mut seen = BTreeSet::new();
    let mut add_sys = |p: String, sys_dirs: &mut Vec<String>| {
        if !seen.contains(&p) && is_dir(&p) {
            seen.insert(p.clone());
            sys_dirs.push(p);
        }
    };
    if let Ok(ents) = sys::read_dir_sorted("/dev/dri") {
        nodes.push("/dev/dri".to_string());
        for (name, t) in ents {
            if t.is_dir() {
                continue;
            }
            let Ok(dev) = eval_symlinks(&sys::join(&["/sys/class/drm", &name])) else { continue };
            if sys::base(&sys::dir(&dev)) != "drm" {
                continue;
            }
            let card = sys::dir(&sys::dir(&dev));
            if card.starts_with("/sys/devices/") {
                add_sys(card, &mut sys_dirs);
            }
        }
        if !sys_dirs.is_empty() {
            add_sys("/sys/dev/char".into(), &mut sys_dirs);
        }
    }
    if let Ok(ents) = sys::read_dir_sorted("/dev") {
        for (name, _) in ents {
            let p = format!("/dev/{name}");
            if nvidia_node(&name) && is_char(&p) {
                nodes.push(p);
            }
        }
    }
    for m in ["nvidia", "nvidia_drm", "nvidia_modeset", "nvidia_uvm"] {
        add_sys(format!("/sys/module/{m}"), &mut sys_dirs);
    }
    (nodes, sys_dirs)
}

const DRIVER_FOLDERS: [&str; 10] = [
    "/etc/vulkan/icd.d",
    "/etc/vulkan/implicit_layer.d",
    "/etc/vulkan/explicit_layer.d",
    "/usr/share/vulkan/icd.d",
    "/usr/share/vulkan/implicit_layer.d",
    "/usr/share/vulkan/explicit_layer.d",
    "/etc/glvnd/egl_vendor.d",
    "/usr/share/glvnd/egl_vendor.d",
    "/etc/egl/egl_external_platform.d",
    "/usr/share/egl/egl_external_platform.d",
];

/// driverDirs: the folders under /opt that driver and layer manifests name a library in, sorted.
fn driver_dirs() -> Vec<String> {
    let mut out = BTreeSet::new();
    for dir in DRIVER_FOLDERS {
        for f in glob_suffix(dir, ".json") {
            let Ok(b) = read_small(&f, 64 << 10) else { continue };
            let Ok(v) = gojson::parse(&b) else { continue };
            for lib in library_paths(&v) {
                let lib = sys::clean(&lib);
                if lib.starts_with("/opt/") {
                    let d = sys::dir(&lib);
                    if !out.contains(&d) && is_dir(&d) {
                        out.insert(d);
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

/// libraryPaths: every "library_path" string in a manifest, wherever it is (an object's members as Go's map holds them:
/// the last of duplicate keys).
pub fn library_paths(v: &Value) -> Vec<String> {
    let mut out = vec![];
    match v {
        Value::Object(members) => {
            let mut m: BTreeMap<&str, &Value> = BTreeMap::new();
            for (k, x) in members {
                m.insert(k, x);
            }
            for (k, x) in m {
                match x {
                    Value::String(s) if k == "library_path" => out.push(s.clone()),
                    _ => out.extend(library_paths(x)),
                }
            }
        }
        Value::Array(items) => {
            for x in items {
                out.extend(library_paths(x));
            }
        }
        _ => {}
    }
    out
}

/// x11Display: `^(?:unix)?:([0-9]{1,4})(?:\.[0-9]+)?$`.
pub fn x11_display(d: &str) -> Option<i64> {
    let rest = d.strip_prefix("unix").unwrap_or(d).strip_prefix(':')?;
    let n = rest.bytes().take_while(u8::is_ascii_digit).count();
    if !(1..=4).contains(&n) {
        return None;
    }
    let tail = &rest[n..];
    if !tail.is_empty() {
        let screen = tail.strip_prefix('.')?;
        if screen.is_empty() || !screen.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
    }
    rest[..n].parse().ok()
}

pub fn is_dir(p: &str) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_dir())
}

pub fn is_char(p: &str) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.file_type().is_char_device())
}

pub fn is_socket(p: &str) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket())
}
