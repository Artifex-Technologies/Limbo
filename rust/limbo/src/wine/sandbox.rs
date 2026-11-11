//! The bubblewrap argument vector (Go: internal/wine/sandbox.go): deny-first, built from a described host, never a shell
//! string. Mount order matters to bwrap: system, devices, /tmp, /etc, the private home, the prefix's cache and the
//! prefix, then the shares, parents before children.

use super::{valid_name, Dirs, Options, BWRAP_PATH, NET_HOST, NET_NONE, SH_PATH};
use crate::gotext::quote;
use crate::sys;
use std::collections::BTreeMap;

/// Everything about this machine and session the sandbox is built from (Probe gathers it; tests write it by hand).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Host {
    pub uid: u32,
    pub gid: u32,
    pub user: String,
    pub group: String,
    pub home: String,
    pub env: BTreeMap<String, String>,
    pub root_links: BTreeMap<String, String>,
    pub root_dirs: Vec<String>,
    pub etc: BTreeMap<String, bool>,
    pub localtime: String,
    pub ntsync: bool,
    pub cpuinfo: bool,
    pub fontcache: bool,
    pub wayland: String,
    pub x11_display: i64,
    pub x11_socket: String,
    /// The X authority entries for that display, rewritten; None is Go's nil.
    pub xauth: Option<Vec<u8>>,
    pub pulse: String,
    pub pipewire: String,
    pub pulse_cookie: Vec<u8>,
    pub gpu_nodes: Vec<String>,
    pub gpu_sys: Vec<String>,
    pub driver_dirs: Vec<String>,
}

/// One run's bubblewrap invocation, without the command.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sandbox {
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub data: Vec<DataFile>,
    pub display: Vec<String>,
    pub audio: String,
    pub gpu: bool,
    pub chdir: String,
}

/// Content bwrap copies into the sandbox read-only (--ro-bind-data).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DataFile {
    pub dest: String,
    pub content: Vec<u8>,
}

/// The descriptors the runner passes to bwrap: the stop pipe, the started pipe, then the data files.
pub const FD_STOP: i32 = 3;
pub const FD_STARTED: i32 = 4;
pub const FD_DATA: i32 = 5;

pub fn runtime_dir(uid: u32) -> String {
    format!("/run/user/{uid}")
}

pub const ETC_BASE: [&str; 8] = ["ld.so.cache", "ld.so.conf", "ld.so.conf.d", "fonts", "nsswitch.conf", "ssl", "ca-certificates", "pki"];
pub const ETC_AUDIO: [&str; 3] = ["pulse", "alsa", "asound.conf"];
pub const ETC_GPU: [&str; 6] = ["vulkan", "glvnd", "egl", "nvidia", "drirc", "drirc.d"];
pub const ETC_NET: [&str; 6] = ["resolv.conf", "hosts", "host.conf", "gai.conf", "services", "protocols"];

/// etcAll: every /etc name Probe looks for.
pub fn etc_all() -> Vec<&'static str> {
    ETC_BASE.iter().chain(&ETC_AUDIO).chain(&ETC_GPU).chain(&ETC_NET).copied().collect()
}

const PASS_NAMES: [&str; 10] = [
    "LANG",
    "LANGUAGE",
    "TZ",
    "PULSE_LATENCY_MSEC",
    "WINEDEBUG",
    "WINEDLLOVERRIDES",
    "WINEESYNC",
    "WINEFSYNC",
    "WINENTSYNC",
    "WINEUSERNAME",
];
const PASS_PREFIXES: [&str; 13] = [
    "LC_",
    "WINE_",
    "DXVK_",
    "VKD3D_",
    "VK_",
    "__GL_",
    "__NV_",
    "MESA_",
    "ENABLE_",
    "DISABLE_",
    "KAIROS_",
    "LABYRINTH_FRAMEGEN_",
    "MANGOHUD",
];
const RESERVED_ENV: [&str; 19] = [
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "WINEPREFIX",
    "WINEARCH",
    "WINESERVER",
    "WINELOADER",
    "WINEDLLPATH",
    "XDG_RUNTIME_DIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "XAUTHORITY",
    "PULSE_SERVER",
    "PULSE_COOKIE",
];

/// passEnv: the caller's variables that may reach the sandbox.
pub fn pass_env(name: &str) -> bool {
    if RESERVED_ENV.contains(&name) {
        return false;
    }
    PASS_NAMES.contains(&name) || PASS_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// ValidEnvName: a name given with --env or in a profile.
pub fn valid_env_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') && !name.as_bytes()[0].is_ascii_digit();
    if !ok {
        return Err(format!("wine: {} is not an environment variable name", quote(name)));
    }
    if RESERVED_ENV.contains(&name) {
        return Err(format!("wine: {name} is set by Limbo (the sandbox's layout depends on it)"));
    }
    Ok(())
}

/// Build: a run's options to bwrap's options. What is not added here is not in the sandbox.
pub fn build(o: &Options, h: &Host, d: &Dirs) -> Result<Sandbox, String> {
    valid_name(&o.prefix)?;
    if o.network != NET_NONE && o.network != NET_HOST {
        return Err(format!("wine: network must be {} or {}", quote(NET_NONE), quote(NET_HOST)));
    }
    if !h.home.starts_with('/') || h.home == "/" || h.user.is_empty() {
        return Err(format!("wine: no usable home folder or user name (home {}, user {})", quote(&h.home), quote(&h.user)));
    }
    let mut s = Sandbox::default();
    fn a(s: &mut Sandbox, args: &[&str]) {
        s.args.extend(args.iter().map(|x| x.to_string()));
    }
    fn data(s: &mut Sandbox, dest: &str, content: Vec<u8>) {
        let fd = (FD_DATA as usize + s.data.len()).to_string();
        a(s, &["--ro-bind-data", &fd, dest]);
        s.data.push(DataFile { dest: dest.into(), content });
    }
    let etc = |s: &mut Sandbox, names: &[&str]| {
        for n in names {
            if h.etc.get(*n).copied().unwrap_or(false) {
                let p = format!("/etc/{n}");
                a(s, &["--ro-bind", &p, &p]);
            }
        }
    };

    a(&mut s, &["--unshare-user", "--disable-userns", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try"]);
    if o.network != NET_HOST {
        a(&mut s, &["--unshare-net"]);
    }
    a(&mut s, &["--die-with-parent", "--new-session", "--cap-drop", "ALL", "--hostname", "limbo"]);

    a(&mut s, &["--ro-bind", "/usr", "/usr"]);
    for (name, target) in &h.root_links {
        a(&mut s, &["--symlink", target, name]);
    }
    for dir in &h.root_dirs {
        a(&mut s, &["--ro-bind", dir, dir]);
    }
    for dir in &h.driver_dirs {
        a(&mut s, &["--ro-bind", dir, dir]);
    }
    a(&mut s, &["--proc", "/proc", "--dev", "/dev"]);
    if h.ntsync {
        a(&mut s, &["--dev-bind", "/dev/ntsync", "/dev/ntsync"]);
    }
    if o.gpu {
        for n in &h.gpu_nodes {
            a(&mut s, &["--dev-bind", n, n]);
        }
        for p in &h.gpu_sys {
            a(&mut s, &["--ro-bind", p, p]);
        }
        s.gpu = !h.gpu_nodes.is_empty();
    }
    if h.cpuinfo {
        a(&mut s, &["--ro-bind", "/sys/devices/system/cpu", "/sys/devices/system/cpu"]);
    }
    a(&mut s, &["--tmpfs", "/tmp"]);

    etc(&mut s, &ETC_BASE);
    if !h.localtime.is_empty() {
        a(&mut s, &["--symlink", &h.localtime, "/etc/localtime"]);
    } else if h.etc.get("localtime").copied().unwrap_or(false) {
        a(&mut s, &["--ro-bind", "/etc/localtime", "/etc/localtime"]);
    }
    if o.gpu {
        etc(&mut s, &ETC_GPU);
    }
    if o.audio {
        etc(&mut s, &ETC_AUDIO);
    }
    if o.network == NET_HOST {
        etc(&mut s, &ETC_NET);
    }
    let passwd = format!(
        "root:x:0:0::/root:/usr/bin/nologin\n{}:x:{}:{}::{}:/usr/bin/sh\nnobody:x:65534:65534::/:/usr/bin/nologin\n",
        h.user, h.uid, h.gid, h.home
    );
    data(&mut s, "/etc/passwd", passwd.into_bytes());
    data(&mut s, "/etc/group", format!("root:x:0:\n{}:x:{}:\nnobody:x:65534:\n", h.group, h.gid).into_bytes());
    if h.fontcache {
        a(&mut s, &["--ro-bind", "/var/cache/fontconfig", "/var/cache/fontconfig"]);
    }

    let run = runtime_dir(h.uid);
    a(&mut s, &["--perms", "0700", "--tmpfs", &h.home, "--perms", "0700", "--dir", &run]);
    let mut env: BTreeMap<String, String> = h.env.iter().filter(|(k, _)| pass_env(k)).map(|(k, v)| (k.clone(), v.clone())).collect();

    if o.display && !h.wayland.is_empty() {
        let name = sys::base(&h.wayland);
        a(&mut s, &["--ro-bind", &h.wayland, &format!("{run}/{name}")]);
        env.insert("WAYLAND_DISPLAY".into(), name);
        s.display.push("wayland".into());
    }
    if o.display && o.x11 && !h.x11_socket.is_empty() {
        a(&mut s, &["--ro-bind", &h.x11_socket, &h.x11_socket]);
        env.insert("DISPLAY".into(), format!(":{}", h.x11_display));
        if let Some(xa) = h.xauth.as_ref().filter(|x| !x.is_empty()) {
            data(&mut s, &format!("{run}/Xauthority"), xa.clone());
            env.insert("XAUTHORITY".into(), format!("{run}/Xauthority"));
        }
        s.display.push("x11".into());
    }
    if o.audio {
        if !h.pulse.is_empty() {
            a(&mut s, &["--ro-bind", &h.pulse, &format!("{run}/pulse/native")]);
            env.insert("PULSE_SERVER".into(), format!("unix:{run}/pulse/native"));
            if !h.pulse_cookie.is_empty() {
                data(&mut s, &format!("{run}/pulse/cookie"), h.pulse_cookie.clone());
                env.insert("PULSE_COOKIE".into(), format!("{run}/pulse/cookie"));
            }
            s.audio = "pulse".into();
        } else if !h.pipewire.is_empty() {
            a(&mut s, &["--ro-bind", &h.pipewire, &format!("{run}/pipewire-0")]);
            s.audio = "pipewire".into();
        }
    }

    let prefix = d.prefix(&o.prefix);
    a(&mut s, &["--bind", &d.prefix_cache(&o.prefix), &sys::join(&[&h.home, ".cache"])]);
    a(&mut s, &["--bind", &prefix, &prefix]);

    let mut shares = o.shares.clone();
    shares.sort_by_key(|sh| depth(&sh.path));
    for sh in &shares {
        let op = if sh.writable { "--bind" } else { "--ro-bind" };
        a(&mut s, &[op, &sh.source, &sh.path]);
    }
    s.chdir = h.home.clone();
    a(&mut s, &["--chdir", &h.home]);

    for (k, v) in &o.env {
        valid_env_name(k)?;
        env.insert(k.clone(), v.clone());
    }
    env.insert("PATH".into(), "/usr/bin".into());
    env.insert("HOME".into(), h.home.clone());
    env.insert("USER".into(), h.user.clone());
    env.insert("LOGNAME".into(), h.user.clone());
    env.insert("XDG_RUNTIME_DIR".into(), run.clone());
    env.insert("XDG_CACHE_HOME".into(), sys::join(&[&h.home, ".cache"]));
    env.insert("WINEPREFIX".into(), prefix);
    s.env = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    Ok(s)
}

impl Sandbox {
    /// SetChdir: start the program in dir instead of the private home.
    pub fn set_chdir(&mut self, dir: &str) {
        let mut i = 0;
        while i + 1 < self.args.len() {
            if self.args[i] == "--chdir" {
                self.args[i + 1] = dir.into();
            }
            i += 1;
        }
        self.chdir = dir.into();
    }

    /// Command: bwrap, its options, and the in-sandbox script with its arguments.
    pub fn command(&self, script: &str, args: &[String]) -> Vec<String> {
        let mut cmd = vec![BWRAP_PATH.to_string()];
        cmd.extend(self.args.iter().cloned());
        cmd.extend(["--", SH_PATH, "-c", script, "limbo-wine"].map(String::from));
        cmd.extend(args.iter().cloned());
        cmd
    }

    /// WithEnv: the environment with name set to value, sorted.
    pub fn with_env(&self, name: &str, value: &str) -> Vec<String> {
        let pre = format!("{name}=");
        let mut out: Vec<String> = self.env.iter().filter(|kv| !kv.starts_with(&pre)).cloned().collect();
        out.push(format!("{name}={value}"));
        out.sort();
        out
    }
}

fn depth(p: &str) -> usize {
    sys::clean(p).matches('/').count()
}
