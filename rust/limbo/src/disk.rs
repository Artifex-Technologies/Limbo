//! What a guest's disk files take and look like, without running anything (Go: internal/disk).

use std::io::Read;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};

/// The space a file takes on the host's disk (allocated blocks); 0 for a missing file or one that is not regular.
pub fn allocated(path: &str) -> i64 {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => m.blocks() as i64 * 512,
        _ => 0,
    }
}

pub const ERR_NOT_QCOW2: &str = "disk: not a qcow2 image";

fn open_nofollow(path: &str) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
}

/// The size the guest sees, from a qcow2 header. Never follows a link.
pub fn virtual_size(path: &str) -> Result<i64, String> {
    let mut f = open_nofollow(path).map_err(|e| crate::sys::go_path_error("open", path, &e))?;
    let mut h = [0u8; 32];
    if f.read_exact(&mut h).is_err() || &h[0..4] != b"QFI\xfb" {
        return Err(ERR_NOT_QCOW2.into());
    }
    Ok(u64::from_be_bytes(h[24..32].try_into().unwrap_or_default()) as i64)
}

/// The backing file a qcow2 header records ("" when none). Never follows a link.
pub fn backing_file(path: &str) -> Result<String, String> {
    let mut f = open_nofollow(path).map_err(|e| crate::sys::go_path_error("open", path, &e))?;
    let mut h = [0u8; 20];
    if f.read_exact(&mut h).is_err() || &h[0..4] != b"QFI\xfb" {
        return Err(ERR_NOT_QCOW2.into());
    }
    let off = u64::from_be_bytes(h[8..16].try_into().unwrap_or_default());
    let n = u32::from_be_bytes(h[16..20].try_into().unwrap_or_default());
    if off == 0 || n == 0 {
        return Ok(String::new());
    }
    if n > 1023 || off > 1 << 40 {
        return Err(ERR_NOT_QCOW2.into());
    }
    let mut name = vec![0u8; n as usize];
    if f.read_exact_at(&mut name, off).is_err() {
        return Err(ERR_NOT_QCOW2.into());
    }
    Ok(crate::gotext::lossy_owned(name))
}

const MAX_WALK: usize = 100_000;

/// The allocated space of every regular file under `dir`, links not followed; a missing folder is 0.
pub fn usage(dir: &str) -> i64 {
    let mut total = 0i64;
    let mut n = 0usize;
    // Go's WalkDir visits the root too (it counts toward the bound)
    fn walk(p: &std::path::Path, total: &mut i64, n: &mut usize) -> bool {
        let Ok(rd) = std::fs::read_dir(p) else { return true };
        let mut ents: Vec<_> = rd.filter_map(|e| e.ok()).collect();
        ents.sort_by_key(|e| e.file_name());
        for e in ents {
            *n += 1;
            if *n > MAX_WALK {
                return false;
            }
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_file() {
                *total += allocated(&e.path().to_string_lossy());
            } else if ft.is_dir() && !walk(&e.path(), total, n) {
                return false;
            }
        }
        true
    }
    let p = std::path::Path::new(dir);
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            n += 1;
            walk(p, &mut total, &mut n);
        }
        Ok(m) if m.is_file() => total += allocated(dir),
        _ => {}
    }
    total
}
