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

pub fn ufw_open(bridge: &str) -> Vec<Vec<String>> {
    rules(bridge)
        .into_iter()
        .map(|mut r| {
            r.push("comment".into());
            r.push("limbo".into());
            r
        })
        .collect()
}

pub fn ufw_close(bridge: &str) -> Vec<Vec<String>> {
    rules(bridge)
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
