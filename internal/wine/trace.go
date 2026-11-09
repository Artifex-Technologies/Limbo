package wine

import (
	"bufio"
	"io"
	"regexp"
)

// TraceChannels is WINEDEBUG for a traced run: what a program does, at a volume a person or a detector can still read.
// Processes it starts and their command lines (process, and exec for ShellExecute), every DLL it loads (loaddll),
// exceptions (seh), services it creates (service, persistence), and its network use, attempted or not (winsock, winhttp,
// wininet: with the network off a connect attempt shows up as a failed one). fixme noise is off; err lines stay. Left
// out on purpose: reg and file, which trace every registry and file call (millions of lines for an ordinary program),
// and relay. +timestamp and +pid make each line attributable.
const TraceChannels = "fixme-all,+timestamp,+pid,+process,+exec,+loaddll,+seh,+service,+winsock,+winhttp,+wininet"

// TraceLimit caps a run's trace file.
const TraceLimit = 16 << 20

// traceLine is the start of one of Wine's debug lines: [seconds.millis:][pid:]tid:class:channel:...
var traceLine = regexp.MustCompile(`^(?:[0-9]+\.[0-9]+:)?(?:[0-9a-f]{4,8}:){1,2}(?:trace|warn|err|fixme):`)

// splitTrace copies src line by line: Wine's debug lines to trace (until limit bytes, then a last line saying so),
// everything else to other (the program's own error output). It returns the bytes written to trace and whether the
// trace was cut.
func splitTrace(src io.Reader, trace, other io.Writer, limit int64) (int64, bool) {
	r := bufio.NewReaderSize(src, 64<<10)
	var n int64
	cut := false
	toTrace := false
	start := true
	for {
		chunk, err := r.ReadSlice('\n')
		if len(chunk) > 0 {
			if start {
				toTrace = traceLine.Match(chunk)
			}
			start = chunk[len(chunk)-1] == '\n'
			switch {
			case !toTrace:
				_, _ = other.Write(chunk)
			case cut:
			case n+int64(len(chunk)) > limit:
				cut = true
				m, _ := io.WriteString(trace, "[limbo: trace cut here, at its limit]\n")
				n += int64(m)
			default:
				m, _ := trace.Write(chunk)
				n += int64(m)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return n, cut
		}
	}
}
