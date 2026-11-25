//! The password switch (Go: internal/settings), and since 2026-11-25 the processors and memory a new instance gets when
//! its manifest names none (LIM-22). Root's file, /etc/limbo/settings.json. Anything unexpected about it reads as "ask
//! for the password" and no defaults: the switch only turns off on purpose.

use crate::go_struct;
use crate::gojson::{self, Obj};
use crate::sys;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

pub const DEFAULT_PATH: &str = "/etc/limbo/settings.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub ask_password: bool,
    /// Processors and memory (MiB) for a new instance whose manifest names none; 0: Limbo's own (2 and 4096).
    pub default_cpus: i64,
    pub default_memory_mb: i64,
}
go_struct!(Settings as "settings.Settings" {
    ask_password: "ask_password" => "bool", default_cpus: "default_cpus" => "int", default_memory_mb: "default_memory_mb" => "int",
});

impl Default for Settings {
    fn default() -> Self {
        Settings { ask_password: true, default_cpus: 0, default_memory_mb: 0 }
    }
}

/// The ranges a manifest takes (manifest.rs `validate`): a default outside them would make every new instance refused.
pub const CPUS: std::ops::RangeInclusive<i64> = 1..=64;
pub const MEMORY_MB: std::ops::RangeInclusive<i64> = 512..=1 << 20;

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
        Err(e) => (d, Some(format!("settings: {path}: {e}"))),
        Ok(()) if s.default_cpus != 0 && !CPUS.contains(&s.default_cpus) => {
            (d, Some(format!("settings: {path}: default_cpus {} is not 1 to 64", s.default_cpus)))
        }
        Ok(()) if s.default_memory_mb != 0 && !MEMORY_MB.contains(&s.default_memory_mb) => {
            (d, Some(format!("settings: {path}: default_memory_mb {} is not 512 to 1048576", s.default_memory_mb)))
        }
        Ok(()) => (s, None),
    }
}

/// Writes the file atomically, mode 0644 (the choice is not secret).
pub fn save(path: &str, s: Settings) -> std::io::Result<()> {
    // the defaults only when set: a file without them is the one Go wrote
    let b = gojson::indent(
        &Obj::new()
            .bool("ask_password", s.ask_password)
            .int_omit("default_cpus", s.default_cpus)
            .int_omit("default_memory_mb", s.default_memory_mb)
            .end(),
        "  ",
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    /// LIM-22: the defaults are read, written only when set (a file without them is Go's), and one outside the
    /// manifest's range makes the whole file read as the safe default (ask for the password, no defaults).
    #[test]
    fn a_new_instances_defaults_in_the_file() {
        let dir = std::env::temp_dir().join(format!("limbo-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("settings.json").to_string_lossy().into_owned();
        save(&p, Settings { ask_password: false, ..Default::default() }).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\n  \"ask_password\": false\n}\n");
        let s = Settings { ask_password: false, default_cpus: 4, default_memory_mb: 8192 };
        save(&p, s).unwrap();
        assert_eq!(load(&p, false), (s, None));
        for bad in [r#"{"ask_password":false,"default_cpus":65}"#, r#"{"ask_password":false,"default_memory_mb":100}"#] {
            std::fs::write(&p, bad).unwrap();
            let (got, err) = load(&p, false);
            assert_eq!(got, Settings::default(), "{bad}");
            assert!(err.unwrap().contains("default_"), "{bad}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
