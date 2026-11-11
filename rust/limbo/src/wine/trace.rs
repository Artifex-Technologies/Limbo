//! A traced run's behaviour trace (Go: internal/wine/trace.go): Wine's debug lines go to the trace file (up to a limit,
//! then one line saying so), everything else on the program's error output goes on to the terminal. Lines are read as
//! Go's bufio.Reader (64 KiB) ReadSlice gives them, so a long line is judged by its first 64 KiB chunk as in Go.

use std::io::{Read, Write};

/// WINEDEBUG for a traced run.
pub const TRACE_CHANNELS: &str = "fixme-all,+timestamp,+pid,+process,+exec,+loaddll,+seh,+service,+winsock,+winhttp,+wininet";

/// The cap on a run's trace file.
pub const TRACE_LIMIT: i64 = 16 << 20;

const CUT: &str = "[limbo: trace cut here, at its limit]\n";

/// traceLine: `^(?:[0-9]+\.[0-9]+:)?(?:[0-9a-f]{4,8}:){1,2}(?:trace|warn|err|fixme):` at the start of `b`.
pub fn trace_line(b: &[u8]) -> bool {
    fn ids(b: &[u8], i: usize) -> bool {
        // one or two groups of 4 to 8 lowercase hex digits, each followed by ':', then the class
        let group = |at: usize| -> Option<usize> {
            let n = b[at..].iter().take_while(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)).count();
            ((4..=8).contains(&n) && b.get(at + n) == Some(&b':')).then_some(at + n + 1)
        };
        let class = |at: usize| ["trace:", "warn:", "err:", "fixme:"].iter().any(|c| b[at..].starts_with(c.as_bytes()));
        let Some(one) = group(i) else { return false };
        class(one) || group(one).is_some_and(class)
    }
    // the optional time stamp: digits, '.', digits, ':'
    let d1 = b.iter().take_while(|c| c.is_ascii_digit()).count();
    if d1 > 0 && b.get(d1) == Some(&b'.') {
        let d2 = b[d1 + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if d2 > 0 && b.get(d1 + 1 + d2) == Some(&b':') && ids(b, d1 + d2 + 2) {
            return true;
        }
    }
    ids(b, 0)
}

/// Go's bufio.Reader (64 KiB) as ReadSlice('\n') reads it: a line with its newline, the buffer when 64 KiB hold none,
/// and what is left at the end.
struct Slicer<R: Read> {
    r: R,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
}

const BUF: usize = 64 << 10;

impl<R: Read> Slicer<R> {
    /// The next chunk and whether the stream ended with it (Go's err != nil and not ErrBufferFull).
    fn next(&mut self) -> (Vec<u8>, bool) {
        let mut scanned = 0;
        loop {
            if let Some(i) = self.buf[self.start + scanned..self.end].iter().position(|&c| c == b'\n') {
                let stop = self.start + scanned + i + 1;
                let line = self.buf[self.start..stop].to_vec();
                self.start = stop;
                return (line, false);
            }
            if self.eof {
                let line = self.buf[self.start..self.end].to_vec();
                self.start = self.end;
                return (line, true);
            }
            if self.end - self.start >= BUF {
                let line = self.buf[self.start..self.end].to_vec();
                self.start = self.end;
                return (line, false);
            }
            scanned = self.end - self.start;
            // fill: slide what is unread to the front, then one read
            if self.start > 0 {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            loop {
                match self.r.read(&mut self.buf[self.end..]) {
                    Ok(0) => {
                        self.eof = true;
                        break;
                    }
                    Ok(n) => {
                        self.end += n;
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        self.eof = true;
                        break;
                    }
                }
            }
        }
    }
}

/// splitTrace: returns the bytes written to the trace and whether it was cut.
pub fn split_trace(src: impl Read, trace: &mut dyn Write, other: &mut dyn Write, limit: i64) -> (i64, bool) {
    let mut s = Slicer { r: src, buf: vec![0; BUF], start: 0, end: 0, eof: false };
    let (mut n, mut cut, mut to_trace, mut start) = (0i64, false, false, true);
    loop {
        let (chunk, done) = s.next();
        if !chunk.is_empty() {
            if start {
                to_trace = trace_line(&chunk);
            }
            start = chunk[chunk.len() - 1] == b'\n';
            if !to_trace {
                let _ = other.write_all(&chunk);
            } else if cut {
            } else if n + chunk.len() as i64 > limit {
                cut = true;
                if trace.write_all(CUT.as_bytes()).is_ok() {
                    n += CUT.len() as i64;
                }
            } else if trace.write_all(&chunk).is_ok() {
                n += chunk.len() as i64;
            }
        }
        if done {
            return (n, cut);
        }
    }
}
