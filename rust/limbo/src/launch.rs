//! The host-side command that shows a guest application as a window (Go: internal/launch): waypipe over ssh for a
//! Linux guest, FreeRDP's RemoteApp for a Windows one. Argument vectors only, never a shell string.

use crate::gotext::quote;
use crate::manifest::{self, Manifest};
use crate::virt;

/// A program to run on the host; `password_prompt` when it takes the guest password on stdin.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Command {
    pub args: Vec<String>,
    pub password_prompt: bool,
}

fn host_alias(m: &Manifest) -> String {
    format!("limbo-{}", m.name)
}

fn fields(s: &str) -> Vec<&str> {
    crate::gotext::fields(s).collect()
}

/// The one known_hosts line: the pinned key under the guest's own name.
pub fn known_hosts_line(m: &Manifest) -> Result<String, String> {
    let f = fields(&m.provision.host_key);
    if f.len() < 2 || !manifest::host_key_ok(&m.provision.host_key) {
        return Err(format!(
            "launch: {} has no pinned host key: run `limbo seed` for it, add the provision.host_key line it prints \
             to the manifest, and rebuild the guest from that seed (launch never trusts a key on first use)",
            m.name
        ));
    }
    Ok(format!("{} {} {}\n", host_alias(m), f[0], f[1]))
}

/// The launch command; `known_hosts` is the file holding [`known_hosts_line`], `m.subnet` the guest's.
pub fn build(m: &Manifest, known_hosts: &str) -> Result<Command, String> {
    let ip = virt::ip4(virt::addr(m).guest);
    match m.os.as_str() {
        manifest::OS_LINUX => {
            if m.clipboard != manifest::CLIP_TEXT {
                return Err(format!(
                    "launch: a Linux app's window comes through waypipe, which shares the clipboard and cannot switch it off; \
                     set \"clipboard\": {} in {}'s manifest to accept that",
                    quote(manifest::CLIP_TEXT),
                    m.name
                ));
            }
            known_hosts_line(m)?;
            let a = [
                "waypipe",
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                &format!("UserKnownHostsFile={known_hosts}"),
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                &format!("HostKeyAlias={}", host_alias(m)),
                "-o",
                "CheckHostIP=no",
                &format!("{}@{ip}", m.access.user),
                &m.app.exec,
            ];
            Ok(Command { args: a.iter().map(|s| s.to_string()).collect(), password_prompt: false })
        }
        manifest::OS_WINDOWS => {
            let clip = if m.clipboard == manifest::CLIP_TEXT { "+clipboard" } else { "-clipboard" };
            let a = [
                "xfreerdp3",
                &format!("/v:{ip}"),
                &format!("/u:{}", m.access.user),
                "/from-stdin",
                "/cert:tofu",
                &format!("/app:program:{},name:{}", m.app.exec, m.app.name),
                clip,
                "-drives",
                "-sound",
                "-microphone",
            ];
            Ok(Command { args: a.iter().map(|s| s.to_string()).collect(), password_prompt: true })
        }
        _ => Err(format!("launch: unsupported os {}", quote(&m.os))),
    }
}

/// A Linux launch with one ssh private key (and only that one).
pub fn with_identity(c: Command, identity: &str) -> Command {
    if identity.is_empty() || c.args.len() < 2 || c.args[0] != "waypipe" || c.args[1] != "ssh" {
        return c;
    }
    let mut args: Vec<String> = ["waypipe", "ssh", "-i", identity, "-o", "IdentitiesOnly=yes"].iter().map(|s| s.to_string()).collect();
    args.extend_from_slice(&c.args[2..]);
    Command { args, password_prompt: c.password_prompt }
}

/// A Linux launch as a plain ssh running `remote` instead of the application.
pub fn check_args(c: &Command, remote: &str) -> Result<Vec<String>, String> {
    if c.args.len() < 4 || c.args[0] != "waypipe" || c.args[1] != "ssh" {
        return Err("launch: only a Linux (waypipe) launch can be checked this way".into());
    }
    let mut args = vec!["ssh".to_string()];
    args.extend_from_slice(&c.args[2..c.args.len() - 1]);
    args.push(remote.into());
    Ok(args)
}
