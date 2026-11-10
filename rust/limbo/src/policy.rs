//! A guest's network profile as an nftables ruleset (Go: internal/policy): one table per guest, matched on its bridge,
//! refusals logged to the NFLOG group limbo serve reads, then dropped.

use crate::manifest::{self, Manifest, Network};
use crate::virt;

pub const NFLOG_GROUP: u16 = 7213;

const PRIVATE_V4: &str = "0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4";
const PRIVATE_V6: &str = "::1/128, fc00::/7, fe80::/10, ff00::/8";

pub fn table_name(m: &Manifest) -> String {
    format!("limbo_{}", m.name.replace('-', "_"))
}

pub fn log_prefix(m: &Manifest, kind: &str) -> String {
    format!("limbo:{}:{}", m.name, kind)
}

/// The ruleset, loadable with `nft -f -`.
pub fn nft(m: &Manifest) -> Result<String, String> {
    m.validate_name()?;
    m.network.validate()?;
    let tap = virt::bridge_name(m);
    let mut b = String::new();
    let mut w = |s: String| {
        b.push_str(&s);
        b.push('\n');
    };
    w(format!("table inet {} {{", table_name(m)));
    for (name, kind) in [("hostblocked", "h"), ("blocked", "d")] {
        w(format!("  chain {name} {{"));
        w(format!(
            "    meta pkttype unicast limit rate 20/second burst 40 packets log prefix \"{}\" group {NFLOG_GROUP}",
            log_prefix(m, kind)
        ));
        w("    drop".into());
        w("  }".into());
    }
    w("  chain input {".into());
    w("    type filter hook input priority -10; policy accept;".into());
    w(format!("    iifname \"{tap}\" ct state established,related accept"));
    w(format!("    iifname \"{tap}\" udp sport 68 udp dport 67 accept"));
    if m.network.mode == manifest::NET_INTERNET_ONLY {
        let gw = virt::ip4(virt::addr(m).gateway);
        w(format!("    iifname \"{tap}\" ip daddr {gw} udp dport 53 accept"));
        w(format!("    iifname \"{tap}\" ip daddr {gw} tcp dport 53 accept"));
    }
    w(format!("    iifname \"{tap}\" goto hostblocked"));
    w("  }".into());
    w("  chain forward {".into());
    w("    type filter hook forward priority -10; policy accept;".into());
    w(format!("    oifname \"{tap}\" ct state established,related accept"));
    w(format!("    oifname \"{tap}\" drop"));
    match m.network.mode.as_str() {
        manifest::NET_INTERNET_ONLY => {
            w(format!("    iifname \"{tap}\" ip daddr {{ {PRIVATE_V4} }} goto blocked"));
            w(format!("    iifname \"{tap}\" ip6 daddr {{ {PRIVATE_V6} }} goto blocked"));
            w(format!("    iifname \"{tap}\" meta nfproto ipv6 goto blocked"));
            w(format!(
                "    iifname \"{tap}\" ct state new limit rate 50/second burst 100 packets log prefix \"{}\" group {NFLOG_GROUP}",
                log_prefix(m, "a")
            ));
            w(format!("    iifname \"{tap}\" accept"));
        }
        manifest::NET_ALLOWLIST => {
            for a in m.network.allow() {
                let p = a.prefix()?;
                let fam = if p.addr.is6() { "ip6" } else { "ip" };
                w(format!(
                    "    iifname \"{tap}\" {fam} daddr {p} {} dport {} ct state new limit rate 50/second burst 100 packets log prefix \"{}\" group {NFLOG_GROUP}",
                    a.proto,
                    a.port,
                    log_prefix(m, "a")
                ));
                w(format!("    iifname \"{tap}\" {fam} daddr {p} {} dport {} accept", a.proto, a.port));
            }
        }
        _ => {}
    }
    w(format!("    iifname \"{tap}\" goto blocked"));
    w("  }".into());
    w("}".into());
    Ok(b)
}

/// A script that replaces the guest's table with the ruleset of `mode` in one transaction.
pub fn nft_replace(m: &Manifest, mode: &str) -> Result<String, String> {
    let mut cp = m.clone();
    cp.network = Network { mode: mode.to_string(), allow: None };
    if mode == manifest::NET_ALLOWLIST {
        cp.network.allow = m.network.allow.clone();
    }
    let rules = nft(&cp)?;
    let t = table_name(m);
    Ok(format!("table inet {t}\ndelete table inet {t}\n{rules}"))
}

/// The quarantine ruleset: mode none's, whatever the manifest asked for.
pub fn nft_restrict(m: &Manifest) -> Result<String, String> {
    nft_replace(m, manifest::NET_NONE)
}

/// The ruleset the manifest asked for, restored.
pub fn nft_release(m: &Manifest) -> Result<String, String> {
    nft_replace(m, &m.network.mode.clone())
}
