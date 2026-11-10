//! Small system helpers with Go's semantics where the Go code relied on them (os.MkdirAll, os.WriteFile, os.CreateTemp,
//! flock, posix_fadvise, statfs).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// os.MkdirAll(path, perm): every missing folder made with `perm` (less the umask); an existing one is left as it is.
pub fn mkdir_all(path: impl AsRef<Path>, perm: u32) -> io::Result<()> {
    let p = path.as_ref();
    if p.as_os_str().is_empty() {
        return Ok(());
    }
    match fs::metadata(p) {
        Ok(m) if m.is_dir() => return Ok(()),
        Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("mkdir {}: not a directory", p.display()))),
        Err(_) => {}
    }
    fs::DirBuilder::new().recursive(true).mode(perm).create(p)
}

/// os.WriteFile: create or truncate, `perm` for a new file.
pub fn write_file(path: impl AsRef<Path>, data: &[u8], perm: u32) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(perm).open(path)?;
    f.write_all(data)
}

/// chmod.
pub fn chmod(path: impl AsRef<Path>, mode: u32) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

/// Random bytes from the kernel, as hex.
pub fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match rustix::rand::getrandom(&mut b[got..], rustix::rand::GetRandomFlags::empty()) {
            Ok(k) => got += k,
            Err(_) => break,
        }
    }
    hex(&b)
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// os.CreateTemp(dir, pattern): a new file 0600 named by the pattern with its `*` replaced by random digits.
pub fn create_temp(dir: &str, pattern: &str) -> io::Result<(File, String)> {
    for _ in 0..10_000 {
        let r = rand_hex(5);
        let name = match pattern.rsplit_once('*') {
            Some((a, b)) => format!("{a}{r}{b}"),
            None => format!("{pattern}{r}"),
        };
        let path = Path::new(dir).join(name).to_string_lossy().into_owned();
        match OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path) {
            Ok(f) => return Ok((f, path)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("create_temp: no free name"))
}

/// An exclusive flock on `path` (made 0600, never through a link), held until the guard drops.
pub struct FileLock(#[allow(dead_code)] File);

pub fn lock_file(path: &str) -> io::Result<FileLock> {
    let f = OpenOptions::new().read(true).write(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)?;
    rustix::fs::flock(&f, rustix::fs::FlockOperation::LockExclusive)?;
    Ok(FileLock(f))
}

/// What Go's syscall.Stat_t gave the Go code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub size: i64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub uid: u32,
    pub mode: u32,
    pub blocks: i64,
}

impl Stat {
    pub fn of(m: &fs::Metadata) -> Stat {
        Stat {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size() as i64,
            mtime_ns: m.mtime() * 1_000_000_000 + m.mtime_nsec(),
            ctime_ns: m.ctime() * 1_000_000_000 + m.ctime_nsec(),
            uid: m.uid(),
            mode: m.mode(),
            blocks: m.blocks() as i64,
        }
    }
    pub fn perm(&self) -> u32 {
        self.mode & 0o777
    }
    pub fn is_regular(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
    }
    pub fn is_dir(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFDIR
    }
}

/// posix_fadvise; advice is a hint, so its error is ignored.
pub fn fadvise(f: &File, off: u64, len: u64, advice: rustix::fs::Advice) {
    let _ = rustix::fs::fadvise(f, off, std::num::NonZeroU64::new(len), advice);
}

/// The mount of `path` forbids setuid programs and device nodes (ST_NOSUID and ST_NODEV).
pub fn mount_nosuid_nodev(path: &str) -> io::Result<bool> {
    let st = rustix::fs::statvfs(path)?;
    let f = st.f_flag;
    Ok(f.contains(rustix::fs::StatVfsMountFlags::NOSUID) && f.contains(rustix::fs::StatVfsMountFlags::NODEV))
}

/// Go's filepath.Clean.
pub fn clean(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|l| *l != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            s => parts.push(s),
        }
    }
    let body = parts.join("/");
    match (rooted, body.is_empty()) {
        (true, _) => format!("/{body}"),
        (false, true) => ".".into(),
        (false, false) => body,
    }
}

/// Go's filepath.Join (cleaned, empty elements skipped).
pub fn join(parts: &[&str]) -> String {
    let v: Vec<&str> = parts.iter().copied().filter(|s| !s.is_empty()).collect();
    if v.is_empty() {
        return String::new();
    }
    clean(&v.join("/"))
}

/// Go's filepath.Dir.
pub fn dir(p: &str) -> String {
    match p.rfind('/') {
        Some(i) => clean(&p[..=i]),
        None => ".".into(),
    }
}

/// Go's filepath.Base.
pub fn base(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return "/".into();
    }
    match t.rfind('/') {
        Some(i) => t[i + 1..].to_string(),
        None => t.to_string(),
    }
}

/// Lists a folder's entry names, sorted (Go's os.ReadDir order).
pub fn read_dir_sorted(dir: &str) -> io::Result<Vec<(String, fs::FileType)>> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir)? {
        let e = e?;
        out.push((e.file_name().to_string_lossy().into_owned(), e.file_type()?));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// An OS error as Go writes it: the C library's text with its first letter lower-cased ("no such file or directory").
pub fn go_err(e: &io::Error) -> String {
    let s = e.to_string();
    let s = match (e.raw_os_error(), s.rfind(" (os error ")) {
        (Some(_), Some(i)) => s[..i].to_string(),
        _ => s,
    };
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => s,
    }
}

/// Go's *fs.PathError text: "open /x: no such file or directory".
pub fn go_path_error(op: &str, path: &str, e: &io::Error) -> String {
    format!("{op} {path}: {}", go_err(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_is_go() {
        for (i, o) in [("", "."), ("/", "/"), ("a//b/../c/.", "a/c"), ("/../x", "/x"), ("../../a", "../../a"), ("/a/b/", "/a/b")] {
            assert_eq!(clean(i), o, "{i}");
        }
        assert_eq!(dir("/a/b"), "/a");
        assert_eq!(dir("a"), ".");
        assert_eq!(base("/a/b.json"), "b.json");
    }
}
