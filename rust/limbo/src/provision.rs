//! The cloud-init seed for a validation run's Linux guest (Go: internal/provision, Build). Every value is validated and
//! written as a JSON string (JSON is YAML), so no value can change the document's structure.

use crate::gojson::str_json as q;
use crate::manifest::{self, Manifest};

pub struct Seed {
    pub user_data: String,
    pub meta_data: String,
}

/// `^[A-Za-z0-9][A-Za-z0-9+._-]*$`
fn pkg_ok(p: &str) -> bool {
    let b = p.as_bytes();
    !b.is_empty() && b[0].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'_' | b'-'))
}

/// `^(ssh-[a-z0-9]+|ecdsa-sha2-[a-z0-9]+) [A-Za-z0-9+/=]+( [^\r\n]*)?$`
fn key_ok(k: &str) -> bool {
    let alg_end = match k.find(' ') {
        Some(i) => i,
        None => return false,
    };
    let alg = &k[..alg_end];
    let lower_digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let alg_ok = alg.strip_prefix("ssh-").is_some_and(lower_digits) || alg.strip_prefix("ecdsa-sha2-").is_some_and(lower_digits);
    if !alg_ok {
        return false;
    }
    let rest = &k[alg_end + 1..];
    let n = rest.bytes().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=')).count();
    if n == 0 {
        return false;
    }
    let tail = &rest[n..];
    tail.is_empty() || (tail.starts_with(' ') && !tail.contains(['\r', '\n']))
}

pub fn build(m: &Manifest) -> Result<Seed, String> {
    if m.os != manifest::OS_LINUX {
        return Err("provision: only Linux guests are supported".into());
    }
    if !key_ok(&m.provision.ssh_public_key) {
        return Err("provision: provision.ssh_public_key missing or not a single-line public key".into());
    }
    let pkgs = m.provision.packages.as_deref().unwrap_or(&[]);
    for p in pkgs {
        if !pkg_ok(p) {
            return Err(format!("provision: invalid package name {}", crate::gotext::quote(p)));
        }
    }
    let mut b = String::from("#cloud-config\nusers:\n");
    b.push_str(&format!("  - name: {}\n", q(&m.access.user)));
    b.push_str("    lock_passwd: true\n    shell: /bin/bash\n");
    if m.access.sudo {
        b.push_str("    sudo: \"ALL=(ALL) NOPASSWD:ALL\"\n");
    }
    b.push_str(&format!("    ssh_authorized_keys: [{}]\n", q(&m.provision.ssh_public_key)));
    b.push_str("disable_root: true\nssh_pwauth: false\n");
    b.push_str("bootcmd:\n  - [systemctl, mask, --now, systemd-time-wait-sync.service]\n");
    if pkgs.is_empty() {
        b.push_str("package_update: false\npackage_upgrade: false\n");
    } else {
        b.push_str("package_update: true\npackages:\n");
        for p in pkgs {
            b.push_str(&format!("  - {}\n", q(p)));
        }
    }
    let meta = format!("instance-id: {}\nlocal-hostname: {}\n", q(&format!("limbo-{}", m.name)), q(&m.name));
    Ok(Seed { user_data: b, meta_data: meta })
}
