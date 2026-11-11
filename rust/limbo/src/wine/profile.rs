//! A prefix's own settings (Go: internal/wine/profile.go): ~/.config/limbo/wine/NAME.json, written by the person, read
//! strictly (unknown fields refused), only when it is theirs and nobody else may write it.

use super::{sandbox, valid_arch, valid_windows, MAX_SHARES, NET_HOST, NET_NONE};
use crate::gojson::{self, Value};
use crate::gotext::quote;
use crate::sys;
use sha2::Digest;
use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

/// Profile, with Go's nil and empty kept apart (`None` is nil).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Profile {
    pub network: String,
    pub gpu: Option<bool>,
    pub audio: Option<bool>,
    pub display: Option<bool>,
    pub x11: Option<bool>,
    pub share: Option<Vec<String>>,
    pub share_rw: Option<Vec<String>>,
    pub env: Option<BTreeMap<String, String>>,
    pub windows: String,
    pub arch: String,
    pub trace: bool,
    pub program: String,
    pub args: Option<Vec<String>>,
}

crate::go_struct!(Profile as "wine.Profile" {
    network: "network" => "string",
    gpu: "gpu" => "*bool",
    audio: "audio" => "*bool",
    display: "display" => "*bool",
    x11: "x11" => "*bool",
    share: "share" => "[]string",
    share_rw: "share_rw" => "[]string",
    env: "env" => "map[string]string",
    windows: "windows" => "string",
    arch: "arch" => "string",
    trace: "trace" => "bool",
    program: "program" => "string",
    args: "args" => "[]string",
});

/// maxProfile bounds a profile file.
pub const MAX_PROFILE: u64 = 64 << 10;

/// LoadProfile: a missing file is no profile (None, ""); the file must be the person's own and not writable by others.
/// The second value is the file's SHA-256.
pub fn load_profile(path: &str) -> Result<(Option<Profile>, String), String> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok((None, String::new())),
        Err(e) => return Err(sys::go_path_error("open", path, &e)),
    };
    let m = f.metadata().map_err(|e| sys::go_path_error("stat", path, &e))?;
    let uid = rustix::process::getuid().as_raw();
    if m.uid() != uid {
        return Err(format!(
            "wine: profile {path} is not yours (owner uid {}); whoever can write it decides what the sandbox may reach",
            m.uid()
        ));
    }
    let perm = m.mode() & 0o777;
    if perm & 0o022 != 0 {
        return Err(format!("wine: profile {path} is writable by others ({}); chmod go-w it", perm_string(perm)));
    }
    if !m.is_file() || m.len() > MAX_PROFILE {
        return Err(format!("wine: profile {path} is not a regular file under {} KiB", MAX_PROFILE >> 10));
    }
    let mut b = Vec::with_capacity(m.len() as usize);
    if let Err(e) = (&mut f).take(m.len()).read_to_end(&mut b) {
        if m.len() > 0 {
            return Err(sys::go_path_error("read", path, &e));
        }
    }
    // ReadAt into a buffer of the size stat gave: a file that shrank leaves zero bytes, one that grew is cut
    b.resize(m.len() as usize, 0);
    let p = parse_profile(&b).map_err(|e| format!("{path}: {e}"))?;
    Ok((Some(p), sys::hex(&sha2::Sha256::digest(&b))))
}

/// A FileMode's permission bits as Go's `%v` prints them ("-rw-rw-rw-").
pub fn perm_string(perm: u32) -> String {
    let mut s = String::from("-");
    for (i, c) in "rwxrwxrwx".chars().enumerate() {
        s.push(if perm & (1 << (8 - i)) != 0 { c } else { '-' });
    }
    s
}

/// ParseProfile: one JSON value (Decoder with DisallowUnknownFields, then More), then the checks.
pub fn parse_profile(b: &[u8]) -> Result<Profile, String> {
    let (v, more) = decode_more(b).map_err(|e| format!("wine profile: {}", e.0))?;
    let mut cx = gojson::Ctx::new(true);
    let mut p = Profile::default();
    gojson::FromGo::read(&mut p, &v, &mut cx, "wine.Profile");
    cx.finish().map_err(|e| format!("wine profile: {}", e.0))?;
    if more {
        return Err("wine profile: more than one JSON value".into());
    }
    if !p.network.is_empty() && p.network != NET_NONE && p.network != NET_HOST {
        return Err(format!(
            "wine profile: network must be {} or {} (finer network rules are not built yet)",
            quote(NET_NONE),
            quote(NET_HOST)
        ));
    }
    if !p.windows.is_empty() {
        valid_windows(&p.windows)?;
    }
    if !p.arch.is_empty() {
        valid_arch(&p.arch)?;
    }
    for k in p.env.iter().flatten().map(|(k, _)| k) {
        sandbox::valid_env_name(k)?;
    }
    if p.share.as_ref().map_or(0, Vec::len) + p.share_rw.as_ref().map_or(0, Vec::len) > MAX_SHARES {
        return Err(format!("wine profile: more than {MAX_SHARES} shares"));
    }
    Ok(p)
}

/// One Decode of a json.Decoder, then Decoder.More: true when what follows the value (past white space) is anything but
/// nothing, `]` or `}`.
fn decode_more(b: &[u8]) -> Result<(Value, bool), gojson::Error> {
    let v = gojson::parse_first(b)?;
    let end = gojson::first_value_end(b);
    let next = b[end..].iter().find(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'));
    Ok((v, next.is_some_and(|&c| c != b']' && c != b'}')))
}
