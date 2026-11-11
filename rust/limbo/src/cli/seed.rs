//! `limbo seed MANIFEST DIR [--iso F]` (cmd/limbo/main.go: seed, seedWindows, guestHostKey, newPassword): the guest's
//! host key pair made once in DIR, then a Linux guest's cloud-init files or a Windows guest's answer file and
//! first-logon script, and with --iso the CD that carries them (xorriso). Same output, errors and files as Go.

use super::commands::{trim_space, Fail, Io};
use super::goexec;
use crate::manifest::{self, Manifest};
use crate::{gotext, license, provision, sys};
use std::io::Write;

const HOST_KEY_FILE: &str = "ssh_host_ed25519_key";
const WINDOWS_PASSWORD_FILE: &str = "windows-password";

/// os.ReadFile with Go's error text.
fn read_file(p: &str) -> Result<Vec<u8>, (std::io::ErrorKind, String)> {
    use std::io::Read;
    let mut f = std::fs::File::open(p).map_err(|e| (e.kind(), sys::go_path_error("open", p, &e)))?;
    let mut b = vec![];
    f.read_to_end(&mut b).map_err(|e| (e.kind(), sys::go_path_error("read", p, &e)))?;
    Ok(b)
}

/// os.WriteFile with Go's error text.
fn write_file(p: &str, b: &[u8], perm: u32) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(perm)
        .open(p)
        .map_err(|e| sys::go_path_error("open", p, &e))?;
    f.write_all(b).map_err(|e| sys::go_path_error("write", p, &e))
}

/// strings.Fields on bytes: split around runs of Unicode white space (a byte that is not UTF-8 is not a space).
fn fields(b: &[u8]) -> Vec<&[u8]> {
    let mut out = vec![];
    let mut start: Option<usize> = None;
    let mut i = 0;
    while i < b.len() {
        let (c, w) = (1..=4.min(b.len() - i))
            .find_map(|k| std::str::from_utf8(&b[i..i + k]).ok().and_then(|s| s.chars().next()).map(|c| (Some(c), k)))
            .unwrap_or((None, 1));
        let space = c.is_some_and(gotext::is_space);
        match (space, start) {
            (true, Some(s)) => {
                out.push(&b[s..i]);
                start = None;
            }
            (false, None) => start = Some(i),
            _ => {}
        }
        i += w;
    }
    if let Some(s) = start {
        out.push(&b[s..]);
    }
    out
}

/// guestHostKey: the pair made the first time (ssh-keygen) and reused after; (private, public trimmed).
fn guest_host_key(m: &Manifest, dir: &str, io: &mut Io) -> Result<Option<(Vec<u8>, Vec<u8>)>, Fail> {
    if m.os != manifest::OS_LINUX && m.os != manifest::OS_WINDOWS {
        return Ok(None);
    }
    let private_path = sys::join(&[dir, HOST_KEY_FILE]);
    if std::fs::symlink_metadata(&private_path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        let comment = format!("limbo-{}", m.name);
        let args: Vec<String> =
            ["-q", "-t", "ed25519", "-N", "", "-C", &comment, "-f", &private_path].iter().map(|s| s.to_string()).collect();
        let (out, r) = goexec::combined_output("ssh-keygen", &args);
        if let Err(e) = r {
            return Err(Fail::Msg(format!("ssh-keygen: {e}: {}", gotext::lossy(&out))));
        }
    }
    let pub_path = format!("{private_path}.pub");
    let (pb, ub) = (read_file(&private_path), read_file(&pub_path));
    let (pb, ub) = match (pb, ub) {
        (Ok(p), Ok(u)) => (p, u),
        (a, b) => {
            let t = |r: &Result<Vec<u8>, (std::io::ErrorKind, String)>| match r {
                Ok(_) => "<nil>".to_string(),
                Err((_, e)) => e.clone(),
            };
            return Err(Fail::Msg(format!("seed: reading the guest's host key in {dir}: {} {}", t(&a), t(&b))));
        }
    };
    let public = trim_space(&ub).to_vec();
    let f = fields(&public);
    if f.len() < 2 {
        return Err(Fail::Msg(format!("seed: {private_path}.pub is not a public key")));
    }
    let mut pin = f[0].to_vec();
    pin.push(b' ');
    pin.extend_from_slice(f[1]);
    let pinned = fields(m.provision.host_key.as_bytes());
    if pinned.is_empty() {
        let _ = writeln!(
            io.err,
            "pin: add this to {}'s manifest under \"provision\" (limbo launch refuses a guest without it):\n  \"host_key\": {}",
            m.name,
            super::url::quote_bytes(&pin)
        );
    } else if pinned.len() < 2 || [pinned[0], b" ", pinned[1]].concat() != pin {
        return Err(Fail::Msg(format!(
            "seed: the manifest pins a different host key than {private_path}.pub; fix provision.host_key, or delete the key \
             pair in {dir} to make a new one (then update the pin)"
        )));
    }
    Ok(Some((pb, public)))
}

pub fn seed(m: &Manifest, dir: &str, iso: &str, io: &mut Io) -> Result<(), Fail> {
    sys::go_mkdir_all(dir, 0o700)?;
    let hk = guest_host_key(m, dir, io)?;
    if m.os == manifest::OS_WINDOWS {
        return seed_windows(m, dir, iso, hk, io);
    }
    let s = provision::build_with_host_key(m, hk.as_ref().map(|(p, u)| (p.as_slice(), u.as_slice())))?;
    for (name, body) in [("user-data", &s.user_data), ("meta-data", &s.meta_data)] {
        write_file(&sys::join(&[dir, name]), body.as_bytes(), 0o600)?;
    }
    if iso.is_empty() {
        let _ = writeln!(io.out, "wrote {dir}/{{user-data,meta-data}}; add --iso PATH to build the seed disk");
        return Ok(());
    }
    xorriso(iso, "cidata", dir)?;
    let _ = writeln!(io.out, "wrote seed disk {iso}");
    Ok(())
}

fn xorriso(iso: &str, label: &str, dir: &str) -> Result<(), Fail> {
    let args: Vec<String> = ["-as", "mkisofs", "-o", iso, "-V", label, "-J", "-r", dir].iter().map(|s| s.to_string()).collect();
    let (out, r) = goexec::combined_output("xorriso", &args);
    r.map_err(|e| Fail::Msg(format!("xorriso: {e}: {}", gotext::lossy(&out))))
}

fn seed_windows(m: &Manifest, dir: &str, iso: &str, hk: Option<(Vec<u8>, Vec<u8>)>, io: &mut Io) -> Result<(), Fail> {
    let pw_path = sys::join(&[dir, WINDOWS_PASSWORD_FILE]);
    let pw = match read_file(&pw_path) {
        Ok(b) => b,
        Err((std::io::ErrorKind::NotFound, _)) => {
            let pw = new_password().into_bytes();
            write_file(&pw_path, &[pw.as_slice(), b"\n"].concat(), 0o600)?;
            pw
        }
        Err((_, e)) => return Err(Fail::Msg(e)),
    };
    let mut key = String::new();
    if io.euid == 0 {
        if let Ok(st) = license::Store::open(license::DEFAULT_DIR, true) {
            let id = st.assigned_to(&m.name);
            if !id.is_empty() {
                if let Ok(k) = st.reveal(&id) {
                    key = k;
                }
            }
        }
    }
    let o = provision::WindowsOptions { password: gotext::lossy(trim_space(&pw)), product_key: key.clone(), host_key: hk, image_index: 0 };
    let mut files = provision::build_windows(m, &o)?;
    files.sort_by(|a, b| a.0.cmp(&b.0)); // Go writes them sorted by name since 2026-11-11 (a map's order before)
    let cd = sys::join(&[dir, "cd"]);
    sys::go_mkdir_all(&cd, 0o700)?;
    for (name, body) in &files {
        write_file(&sys::join(&[&cd, name]), body, 0o600)?;
    }
    if !key.is_empty() {
        let _ = writeln!(io.out, "the license assigned to this guest goes into its answer file");
    } else {
        let _ =
            writeln!(io.out, "no license is assigned to this guest: its Windows installs without a product key (an evaluation edition)");
    }
    let _ = writeln!(io.out, "the local account {}'s password is in {pw_path} (limbo launch asks for it)", gotext::quote(&m.access.user));
    if iso.is_empty() {
        let _ = writeln!(io.out, "wrote {cd}; add --iso PATH to build the seed CD");
        return Ok(());
    }
    xorriso(iso, "LIMBOSEED", &cd)?;
    let _ = sys::chmod(iso, 0o600); // it holds the password and the guest's host key
    let _ = writeln!(io.out, "wrote seed CD {iso} (Windows Setup finds autounattend.xml on it)");
    Ok(())
}

/// newPassword: 20 characters without look-alikes, at least one lower case letter, capital and digit.
fn new_password() -> String {
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"23456789";
    let all: Vec<u8> = [LOWER, UPPER, DIGITS].concat();
    let mut b = [0u8; 20];
    let _ = rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty());
    let mut out: Vec<u8> = b.iter().map(|&x| all[x as usize % all.len()]).collect();
    out[0] = LOWER[b[0] as usize % LOWER.len()];
    out[1] = UPPER[b[1] as usize % UPPER.len()];
    out[2] = DIGITS[b[2] as usize % DIGITS.len()];
    String::from_utf8(out).unwrap_or_default()
}
