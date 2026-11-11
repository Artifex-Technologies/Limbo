//! Accounts and groups as the Go limbo finds them. It is built with CGO_ENABLED=0, so os/user reads /etc/passwd and
//! /etc/group itself (no NSS); this does the same, so both daemons agree on who is who.

fn lookup(file: &str, want: impl Fn(&[&str]) -> bool) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(file).ok()?;
    for line in text.lines() {
        let line = line.trim_start_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') || line.starts_with('+') || line.starts_with('-') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 3 {
            continue;
        }
        if want(&parts) {
            return Some(parts.iter().map(|s| s.to_string()).collect());
        }
    }
    None
}

/// user.LookupGroup(name).Gid
pub fn group_gid(name: &str) -> Option<u32> {
    group_gid_in("/etc/group", name)
}

pub fn group_gid_in(file: &str, name: &str) -> Option<u32> {
    if name.is_empty() {
        return None;
    }
    let p = lookup(file, |p| p[0] == name)?;
    p[2].parse().ok()
}

/// user.LookupId(uid).Username
pub fn user_name(uid: u32) -> Option<String> {
    let s = uid.to_string();
    let p = lookup("/etc/passwd", |p| p.len() >= 3 && p[2] == s)?;
    Some(p[0].clone())
}

/// user.LookupId(uid) as the Go limbo (built with CGO_ENABLED=0) reads it: the uid as given (Atoi must accept it), the
/// first /etc/passwd line whose third field is that text and whose uid and gid are numbers. (name, uid, gid).
pub fn lookup_id(uid: &str) -> Option<(String, String, String)> {
    crate::gotext::atoi(uid)?;
    let text = std::fs::read("/etc/passwd").ok()?;
    let sub = format!(":{uid}:");
    for line in text.split(|&c| c == b'\n') {
        let line = String::from_utf8_lossy(line.trim_ascii());
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.contains(&sub) || line.matches(':').count() < 6 {
            continue;
        }
        let parts: Vec<&str> = line.splitn(7, ':').collect();
        if parts.len() < 6 || parts[2] != uid || parts[0].is_empty() || parts[0].starts_with(['+', '-']) {
            continue;
        }
        if crate::gotext::atoi(parts[2]).is_none() || crate::gotext::atoi(parts[3]).is_none() {
            continue;
        }
        return Some((parts[0].to_string(), parts[2].to_string(), parts[3].to_string()));
    }
    None
}

/// One account as Go's os/user (CGO_ENABLED=0) reads it.
pub struct User {
    pub username: String,
    pub home_dir: String,
}

/// The lines of an /etc/passwd or /etc/group file as readColonFile hands them on: without the line end, white space
/// trimmed, blank lines and comments skipped.
fn colon_lines(file: &str) -> Vec<String> {
    let Ok(b) = std::fs::read(file) else { return vec![] };
    b.split(|&c| c == b'\n')
        .map(|l| crate::gotext::lossy(l.strip_suffix(b"\r").unwrap_or(l)))
        .map(|l| crate::gotext::trim_space(&l).to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// user.Current() with CGO_ENABLED=0: the /etc/passwd entry of `uid` (matchUserIndexValue), else $USER and $HOME when
/// both are set; None when Go returns an error.
pub fn current(uid: u32, user_env: &str, home_env: &str) -> Option<User> {
    let id = uid.to_string();
    let sub = format!(":{id}:");
    for line in colon_lines("/etc/passwd") {
        if !line.contains(&sub) || line.matches(':').count() < 6 {
            continue;
        }
        let parts: Vec<&str> = line.splitn(7, ':').collect();
        if parts.len() < 6 || parts[2] != id || parts[0].is_empty() || parts[0].starts_with(['+', '-']) {
            continue;
        }
        if crate::gotext::atoi(parts[2]).is_none() || crate::gotext::atoi(parts[3]).is_none() {
            continue;
        }
        return Some(User { username: parts[0].into(), home_dir: parts[5].into() });
    }
    if !user_env.is_empty() && !home_env.is_empty() {
        return Some(User { username: user_env.into(), home_dir: home_env.into() });
    }
    None
}

/// user.LookupGroupId(gid).Name with CGO_ENABLED=0 (matchGroupIndexValue).
pub fn lookup_group_id(gid: &str) -> Option<String> {
    let sub = format!(":{gid}:");
    for line in colon_lines("/etc/group") {
        if !line.contains(&sub) || line.matches(':').count() < 3 {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, ':').collect();
        if parts.len() < 4 || parts[0].is_empty() || parts[2] != gid || parts[0].starts_with(['+', '-']) {
            continue;
        }
        if crate::gotext::atoi(parts[2]).is_none() {
            continue;
        }
        return Some(parts[0].into());
    }
    None
}
