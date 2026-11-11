//! Go's path/filepath functions the Wine backend relies on, with Go's results and error texts: EvalSymlinks (Go's own
//! walk, component by component, with "lstat P: ..." errors, a bare "not a directory" and "EvalSymlinks: too many
//! links"), Rel, and Glob for a folder and a `*.json` pattern.

use crate::sys;

/// filepath.EvalSymlinks (walkSymlinks).
pub fn eval_symlinks(path: &str) -> Result<String, String> {
    let mut path = path.to_string();
    let mut vol_len = usize::from(path.starts_with('/'));
    let mut vol = path[..vol_len].to_string();
    let mut dest = vol.clone();
    let mut links = 0;
    let mut start = vol_len;
    while start < path.len() {
        let b = path.as_bytes();
        while start < b.len() && b[start] == b'/' {
            start += 1;
        }
        let mut end = start;
        while end < b.len() && b[end] != b'/' {
            end += 1;
        }
        let comp = &path[start..end];
        if end == start {
            break;
        }
        if comp == "." {
            start = end;
            continue;
        }
        if comp == ".." {
            // back up to the previous component if possible; keep a ".." there is nothing to back up over
            match dest.rfind('/').filter(|&r| r >= vol_len) {
                Some(r) if &dest[r + 1..] != ".." => dest.truncate(r),
                _ => {
                    if dest.len() > vol_len {
                        dest.push('/');
                    }
                    dest.push_str("..");
                }
            }
            start = end;
            continue;
        }
        if !dest.is_empty() && !dest.ends_with('/') {
            dest.push('/');
        }
        dest.push_str(comp);
        let m = std::fs::symlink_metadata(&dest).map_err(|e| sys::go_path_error("lstat", &dest, &e))?;
        if !m.file_type().is_symlink() {
            if !m.is_dir() && end < path.len() {
                return Err("not a directory".into());
            }
            start = end;
            continue;
        }
        links += 1;
        if links > 255 {
            return Err("EvalSymlinks: too many links".into());
        }
        let link = std::fs::read_link(&dest).map_err(|e| sys::go_path_error("readlink", &dest, &e))?;
        let link = link.to_string_lossy().into_owned();
        path = format!("{link}{}", &path[end..]);
        if link.starts_with('/') {
            dest = "/".into();
            vol = "/".into();
            vol_len = 1;
            start = 1;
        } else {
            match dest.rfind('/').filter(|&r| r >= vol_len) {
                Some(r) => dest.truncate(r),
                None => dest = vol.clone(),
            }
            start = 0;
        }
    }
    Ok(sys::clean(&dest))
}

/// filepath.Rel.
pub fn rel(base_path: &str, targ_path: &str) -> Result<String, String> {
    let base = sys::clean(base_path);
    let targ = sys::clean(targ_path);
    if targ == base {
        return Ok(".".into());
    }
    let base = if base == "." { String::new() } else { base };
    let base_slashed = base.starts_with('/');
    let targ_slashed = targ.starts_with('/');
    let fail = || Err(format!("Rel: can't make {targ_path} relative to {base_path}"));
    if base_slashed != targ_slashed {
        return fail();
    }
    let (b, t) = (base.as_bytes(), targ.as_bytes());
    let (bl, tl) = (b.len(), t.len());
    let (mut b0, mut bi, mut t0, mut ti) = (0, 0, 0, 0);
    loop {
        while bi < bl && b[bi] != b'/' {
            bi += 1;
        }
        while ti < tl && t[ti] != b'/' {
            ti += 1;
        }
        if targ[t0..ti] != base[b0..bi] {
            break;
        }
        if bi < bl {
            bi += 1;
        }
        if ti < tl {
            ti += 1;
        }
        b0 = bi;
        t0 = ti;
    }
    if &base[b0..bi] == ".." {
        return fail();
    }
    if b0 != bl {
        let seps = base[b0..bl].matches('/').count();
        let mut out = String::from("..");
        for _ in 0..seps {
            out.push_str("/..");
        }
        if t0 != tl {
            out.push('/');
            out.push_str(&targ[t0..]);
        }
        return Ok(sys::clean(&out));
    }
    Ok(targ[t0..].to_string())
}

/// filepath.Glob(dir + "/*" + suffix) for a folder name without pattern characters: the entries whose names end in
/// `suffix`, sorted (Go's `*` matches any name, a leading dot too); nothing when the folder cannot be read.
pub fn glob_suffix(dir: &str, suffix: &str) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(suffix) && !n.contains('/'))
        .collect();
    names.sort();
    names.into_iter().map(|n| sys::join(&[dir, &n])).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel_is_go() {
        for (b, t, want) in [
            ("/a/b", "/a/b/c", "c"),
            ("/a/b", "/a", ".."),
            ("/a/b", "/x/y", "../../x/y"),
            ("/", "/x", "x"),
            ("/a", "/a", "."),
            ("/home/ada", "/home/adam", "../adam"),
            ("a", "a/b", "b"),
            (".", "a", "a"),
        ] {
            assert_eq!(rel(b, t), Ok(want.to_string()), "{b} {t}");
        }
        assert!(rel("/a", "b").is_err());
        assert!(rel("../a", "b").is_err());
    }
}
