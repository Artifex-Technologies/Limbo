//! The password switch (Go: internal/settings). Root's file, /etc/limbo/settings.json. Anything unexpected about it
//! reads as "ask for the password": the switch only turns off on purpose.

use crate::go_struct;
use crate::gojson::{self, Obj};
use crate::sys;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

pub const DEFAULT_PATH: &str = "/etc/limbo/settings.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub ask_password: bool,
}
go_struct!(Settings as "settings.Settings" { ask_password: "ask_password" => "bool" });

impl Default for Settings {
    fn default() -> Self {
        Settings { ask_password: true }
    }
}

/// Reads the file. Missing: the default. Any other problem comes back with the default, so a caller that ignores the
/// error still fails closed. `require_root` is off only in tests.
pub fn load(path: &str, require_root: bool) -> (Settings, Option<String>) {
    let d = Settings::default();
    let mut f = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (d, None),
        Err(e) => return (d, Some(format!("settings: open {path}: {e}"))),
    };
    let st = match f.metadata() {
        Ok(m) => sys::Stat::of(&m),
        Err(e) => return (d, Some(format!("settings: {e}"))),
    };
    if !st.is_regular() {
        return (d, Some(format!("settings: {path} is not a regular file")));
    }
    if st.perm() & 0o022 != 0 {
        return (d, Some(format!("settings: {path} is writable by others than its owner")));
    }
    if require_root && st.uid != 0 {
        return (d, Some(format!("settings: {path} is not owned by root")));
    }
    let mut buf = Vec::new();
    if (&mut f).take(4097).read_to_end(&mut buf).is_err() || buf.len() >= 4096 {
        // Go's limited reader fails once 4096 bytes are read, before it sees the end
        return (d, Some("settings: file too large".into()));
    }
    let (s, r) = gojson::decode(&buf, Settings::default(), "settings.Settings", true);
    match r {
        Ok(()) => (s, None),
        Err(e) => (d, Some(format!("settings: {path}: {e}"))),
    }
}

/// Writes the file atomically, mode 0644 (the choice is not secret).
pub fn save(path: &str, s: Settings) -> std::io::Result<()> {
    let b = gojson::indent(&Obj::new().bool("ask_password", s.ask_password).end(), "  ");
    let dir = sys::dir(path);
    sys::mkdir_all(&dir, 0o755)?;
    let (mut f, tmp) = sys::create_temp(&dir, ".settings-*")?;
    let r = (|| {
        f.write_all(format!("{b}\n").as_bytes())?;
        sys::chmod(&tmp, 0o644)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    let _ = std::fs::remove_file(&tmp);
    r
}
