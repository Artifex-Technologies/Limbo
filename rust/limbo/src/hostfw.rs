//! Room for a guest's bridge in UFW, when UFW is on (Go: internal/hostfw). Limbo's own table, which runs first and whose
//! drops are final, does the restricting; opening the bridge widens nothing.

/// UFW is installed and `ENABLED=yes` in its config.
pub fn ufw_active() -> bool {
    if std::fs::metadata("/usr/bin/ufw").is_err() && std::fs::metadata("/usr/sbin/ufw").is_err() {
        return false;
    }
    ufw_enabled("/etc/ufw/ufw.conf")
}

pub fn ufw_enabled(path: &str) -> bool {
    let Ok(text) = std::fs::read(path) else { return false };
    let text = crate::gotext::lossy(&text);
    for line in text.split('\n') {
        let line = crate::gotext::trim_space(line.strip_suffix('\r').unwrap_or(line));
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if crate::gotext::trim_space(k) == "ENABLED" {
                return crate::gotext::trim_space(v).trim_matches(['"', '\'']).eq_ignore_ascii_case("yes");
            }
        }
    }
    false
}

fn rules(bridge: &str) -> Vec<Vec<String>> {
    let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    vec![
        v(&["allow", "in", "on", bridge, "to", "any", "port", "67", "proto", "udp"]),
        v(&["allow", "in", "on", bridge, "to", "any", "port", "53", "proto", "udp"]),
        v(&["allow", "in", "on", bridge, "to", "any", "port", "53", "proto", "tcp"]),
        v(&["route", "allow", "in", "on", bridge]),
    ]
}

/// Mode sinkhole's (docs/SINKHOLE.md): DHCP, and the responder's ports, which is what UFW sees once the guest's table
/// has redirected a packet. No route rule: nothing from a sinkhole guest is ever forwarded.
fn sinkhole_rules(bridge: &str) -> Vec<Vec<String>> {
    let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let (dns, udp, tcp) =
        (crate::sinkhole::DNS_PORT.to_string(), crate::sinkhole::UDP_PORT.to_string(), crate::sinkhole::TCP_PORT.to_string());
    vec![
        v(&["allow", "in", "on", bridge, "to", "any", "port", "67", "proto", "udp"]),
        v(&["allow", "in", "on", bridge, "to", "any", "port", &dns, "proto", "udp"]),
        v(&["allow", "in", "on", bridge, "to", "any", "port", &udp, "proto", "udp"]),
        v(&["allow", "in", "on", bridge, "to", "any", "port", &tcp, "proto", "tcp"]),
    ]
}

/// The rules for a guest's network mode.
fn rules_for(bridge: &str, mode: &str) -> Vec<Vec<String>> {
    if mode == crate::manifest::NET_SINKHOLE {
        sinkhole_rules(bridge)
    } else {
        rules(bridge)
    }
}

pub fn ufw_open(bridge: &str) -> Vec<Vec<String>> {
    ufw_open_mode(bridge, "")
}

pub fn ufw_close(bridge: &str) -> Vec<Vec<String>> {
    ufw_close_mode(bridge, "")
}

pub fn ufw_open_mode(bridge: &str, mode: &str) -> Vec<Vec<String>> {
    rules_for(bridge, mode)
        .into_iter()
        .map(|mut r| {
            r.push("comment".into());
            r.push("limbo".into());
            r
        })
        .collect()
}

pub fn ufw_close_mode(bridge: &str, mode: &str) -> Vec<Vec<String>> {
    rules_for(bridge, mode)
        .into_iter()
        .map(|r| {
            let mut out: Vec<String> = Vec::new();
            if r[0] == "route" {
                out.extend(["--force", "route", "delete"].map(String::from));
                out.extend(r[1..].iter().cloned());
            } else {
                out.extend(["--force", "delete"].map(String::from));
                out.extend(r);
            }
            out
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn sinkhole_opens_the_responder_and_never_routes() {
        let open = super::ufw_open_mode("lb-sh", "sinkhole");
        let lines: Vec<String> = open.iter().map(|r| r.join(" ")).collect();
        assert_eq!(
            lines,
            [
                "allow in on lb-sh to any port 67 proto udp comment limbo",
                "allow in on lb-sh to any port 7253 proto udp comment limbo",
                "allow in on lb-sh to any port 7281 proto udp comment limbo",
                "allow in on lb-sh to any port 7280 proto tcp comment limbo",
            ]
        );
        assert!(super::ufw_close_mode("lb-sh", "sinkhole").iter().all(|r| r[1] == "delete"));
        assert_eq!(super::ufw_open_mode("lb-x", "none"), super::ufw_open("lb-x"));
    }
}
