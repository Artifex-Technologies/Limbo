//go:build linux

package wine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/events"
)

type memLog struct {
	mu  sync.Mutex
	evs []events.Event
}

func (l *memLog) Emit(kind, guest string, d map[string]string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evs = append(l.evs, events.Event{Kind: kind, Guest: guest, Detail: d})
	return nil
}

func (l *memLog) since(n int) []events.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]events.Event(nil), l.evs[n:]...)
}

func (l *memLog) len() int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.evs) }

// watchWriter keeps what is written and closes seen the first time it contains want.
type watchWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	want string
	seen chan struct{}
	once sync.Once
}

func (w *watchWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if w.want != "" && strings.Contains(w.buf.String(), w.want) {
		w.once.Do(func() { close(w.seen) })
	}
	return len(p), nil
}

func (w *watchWriter) String() string { w.mu.Lock(); defer w.mu.Unlock(); return w.buf.String() }

// TestRealWineRun is the real thing: bubblewrap and Wine on this machine, and only Wine's own built-in programs (cmd,
// cscript), never a third-party Windows program. Headless (no display, no sound), so nothing appears on a screen. It
// takes about a minute, most of it Wine making the prefix; skipped with -short, without bwrap or Wine, as root, or where
// unprivileged user namespaces are off.
func TestRealWineRun(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: the real Wine run makes a prefix (about a minute)")
	}
	if os.Geteuid() == 0 {
		t.Skip("limbo wine refuses root")
	}
	if !executable(BwrapPath) || !executable(WinePath) || !executable(WineserverPath) {
		t.Skip("bubblewrap or Wine is not installed")
	}
	if out, err := exec.Command(BwrapPath, "--unshare-user", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib64", "--", "/usr/bin/true").CombinedOutput(); err != nil {
		t.Skipf("bwrap cannot make a sandbox here: %v %s", err, out)
	}
	h, err := Probe()
	if err != nil {
		t.Fatal(err)
	}
	// A stand-in for the person's home: the sandbox's home has the same path, and the file in it must stay invisible.
	tmp := t.TempDir()
	h.Home = filepath.Join(tmp, "home")
	if err := os.MkdirAll(filepath.Join(h.Home, "Downloads"), 0o700); err != nil {
		t.Fatal(err)
	}
	const secret = "the-real-home-is-not-here"
	if err := os.WriteFile(filepath.Join(h.Home, "marker.txt"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	h.Env = map[string]string{"LANG": "C.UTF-8", "WINEDLLOVERRIDES": "mscoree=;mshtml=", "WINEDEBUG": "-all"}
	d := DefaultDirs(func(string) string { return "" }, h.Home, filepath.Join(h.Home, ".local", "state", "limbo"))
	log := &memLog{}
	base := Options{Prefix: "test", Network: NetNone, GPU: true, Env: map[string]string{}} // headless: no display, no sound

	type outcome struct {
		stdout, stderr string
		code           int
		err            error
		evs            []events.Event
		rec            Record
	}
	run := func(o Options, stdout *watchWriter, prog string, args ...string) outcome {
		t.Helper()
		if stdout == nil {
			stdout = &watchWriter{}
		}
		var stderr bytes.Buffer
		n := log.len()
		r := &Run{Options: o, Host: h, Dirs: d, Program: prog, Args: args, Cwd: h.Home, Log: log, Stdout: stdout, Stderr: &stderr, StopGrace: 10 * time.Second}
		start := time.Now()
		code, err := r.Do()
		res := outcome{stdout: stdout.String(), stderr: stderr.String(), code: code, err: err, evs: log.since(n)}
		for _, e := range res.evs {
			if e.Kind == events.WineStop && e.Detail["record"] != "" {
				b, rerr := os.ReadFile(e.Detail["record"])
				if rerr != nil || json.Unmarshal(b, &res.rec) != nil {
					t.Errorf("run record %s: %v", e.Detail["record"], rerr)
				}
			}
		}
		t.Logf("$ wine %s %s  (%.1fs, exit %d, err %v)\n%s%s", prog, strings.Join(args, " "), time.Since(start).Seconds(), code, err, res.stdout, res.stderr)
		return res
	}
	kinds := func(evs []events.Event) string {
		var k []string
		for _, e := range evs {
			k = append(k, e.Kind)
		}
		return strings.Join(k, " ")
	}

	// 1. The first run makes the prefix (64-bit, reporting Windows 10), then prints hello.
	r := run(base, nil, "cmd", "/c", "echo", "hello")
	if r.err != nil || r.code != 0 || !strings.Contains(r.stdout, "hello") {
		t.Fatalf("hello: %+v", r)
	}
	if got := kinds(r.evs); got != "wine.setup wine.start wine.stop" {
		t.Fatalf("events %q", got)
	}
	if s := r.evs[0].Detail; s["step"] != "create" || s["arch"] != ArchWin64 || s["windows"] != DefaultWindows || r.evs[1].Guest != "wine:test" {
		t.Fatalf("setup event %v", r.evs[0])
	}
	if st := r.evs[1].Detail; st["network"] != NetNone || st["display"] != "none" || st["audio"] != "none" || st["share"] != "" || st["program"] != "cmd" {
		t.Fatalf("start event %v", st)
	}
	if prefixArch(d.Prefix("test")) != ArchWin64 {
		t.Fatalf("prefix arch %q", prefixArch(d.Prefix("test")))
	}
	if pr, ok := readPrefixRecord(d.recordFile("test")); !ok || pr.Windows != DefaultWindows || pr.Arch != ArchWin64 {
		t.Fatalf("prefix record %+v", pr)
	}
	if r.rec.Status != "exited" || r.rec.ExitCode == nil || *r.rec.ExitCode != 0 || r.rec.Allowed.Network != NetNone ||
		len(r.rec.Allowed.Display) != 0 || r.rec.Allowed.Audio != "none" || r.rec.Arch != ArchWin64 || r.rec.Windows != DefaultWindows || r.rec.Ended == nil {
		t.Fatalf("run record %+v", r.rec)
	}

	// 2. Windows 10 is what the prefix reports; the program's exit status comes back unchanged.
	if r = run(base, nil, "cmd", "/c", "ver"); !strings.Contains(r.stdout, "10.0.") {
		t.Fatalf("ver: %q", r.stdout)
	}
	if r = run(base, nil, "cmd", "/c", "exit", "7"); r.code != 7 || r.err != nil || *r.rec.ExitCode != 7 {
		t.Fatalf("exit 7: %d %v", r.code, r.err)
	}

	// 3. The real home is not there: the marker beside the sandbox's home path is invisible. A share is.
	winPath := func(p string) string { return `Z:` + strings.ReplaceAll(p, "/", `\`) }
	r = run(base, nil, "cmd", "/c", "type", winPath(filepath.Join(h.Home, "marker.txt")))
	if strings.Contains(r.stdout+r.stderr, secret) || r.code == 0 {
		t.Fatalf("the home's marker was readable: %+v", r)
	}
	shared := filepath.Join(tmp, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "note.txt"), []byte("shared-on-purpose"), 0o600); err != nil {
		t.Fatal(err)
	}
	withShare := base
	withShare.Shares = []Share{{Path: shared, Source: shared}}
	if r = run(withShare, nil, "cmd", "/c", "type", winPath(filepath.Join(shared, "note.txt"))); !strings.Contains(r.stdout, "shared-on-purpose") {
		t.Fatalf("a share was not readable: %+v", r)
	}
	if r = run(withShare, nil, "cmd", "/c", "echo x > "+winPath(filepath.Join(shared, "written.txt"))); exists(filepath.Join(shared, "written.txt")) {
		t.Fatal("a read-only share was written to")
	}

	// 4. No network by default: Wine's own script host cannot reach a listener on the host's loopback. With
	// --network it can.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "reached-the-host") })}
	go srv.Serve(ln)
	defer srv.Close()
	js := fmt.Sprintf(`try { var r = new ActiveXObject("WinHttp.WinHttpRequest.5.1"); r.SetTimeouts(3000, 3000, 3000, 3000);
r.Open("GET", "http://127.0.0.1:%d/", false); r.Send(); WScript.Echo("status " + r.Status + " " + r.ResponseText); }
catch (e) { WScript.Echo("error " + e.message); }`, ln.Addr().(*net.TCPAddr).Port)
	if err := os.WriteFile(filepath.Join(d.Prefix("test"), "drive_c", "limbo-net.js"), []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	if r = run(base, nil, "cscript", "//nologo", `C:\limbo-net.js`); !strings.Contains(r.stdout, "error") || strings.Contains(r.stdout, "reached-the-host") {
		t.Fatalf("the host was reachable without --network: %q", r.stdout)
	}
	withNet := base
	withNet.Network = NetHost
	if r = run(withNet, nil, "cscript", "//nologo", `C:\limbo-net.js`); !strings.Contains(r.stdout, "status 200 reached-the-host") || r.evs[0].Detail["network"] != NetHost {
		t.Fatalf("--network did not reach the host: %q", r.stdout)
	}

	// 5. A traced run leaves Wine's behaviour trace in its run folder; the program's output is untouched.
	traced := base
	traced.Trace = true
	r = run(traced, nil, "cmd", "/c", "echo", "traced")
	if !strings.Contains(r.stdout, "traced") || r.rec.Trace == nil || r.rec.Trace.Bytes == 0 || r.rec.Trace.Truncated {
		t.Fatalf("trace: %+v", r.rec.Trace)
	}
	if b, err := os.ReadFile(r.rec.Trace.File); err != nil || !bytes.Contains(b, []byte(":loaddll:")) || !bytes.Contains(b, []byte(":process:")) {
		t.Fatalf("trace file %v: %.300s", err, b)
	}

	// 6. Another Windows version on request: set once, recorded, reported.
	old := base
	old.Windows = "win7"
	if r = run(old, nil, "cmd", "/c", "ver"); !strings.Contains(r.stdout, "6.1.") || r.evs[0].Kind != events.WineSetup || r.evs[0].Detail["step"] != "windows" {
		t.Fatalf("win7: %q %v", r.stdout, kinds(r.evs))
	}
	if r = run(old, nil, "cmd", "/c", "ver"); r.evs[0].Kind != events.WineStart {
		t.Fatalf("the version was set again although Limbo had set it: %v", kinds(r.evs))
	}

	// 7. A prefix already running in another limbo wine is refused, not shared.
	lock, err := lockPrefix(d, "test")
	if err != nil {
		t.Fatal(err)
	}
	r = run(base, nil, "cmd", "/c", "echo", "busy")
	lock.Close()
	if !errors.Is(r.err, ErrBusy) || kinds(r.evs) != "wine.refused" {
		t.Fatalf("busy prefix: %v %v", r.err, kinds(r.evs))
	}

	// 8. A program outside the sandbox is refused with the fix, not left for Wine to fail on.
	outside := filepath.Join(h.Home, "Downloads", "setup.exe")
	if err := os.WriteFile(outside, []byte("not a real program"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r = run(base, nil, outside); r.err == nil || !strings.Contains(r.err.Error(), "--share") || kinds(r.evs) != "wine.refused" {
		t.Fatalf("outside program: %v %v", r.err, kinds(r.evs))
	}

	// 9. Ctrl+C stops the program cleanly through the wineserver, and the run says so.
	if err := os.WriteFile(filepath.Join(d.Prefix("test"), "drive_c", "limbo-sleep.js"), []byte(`WScript.Echo("sleeping"); WScript.Sleep(60000); WScript.Echo("woke");`), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &watchWriter{want: "sleeping", seen: make(chan struct{})}
	go func() {
		select {
		case <-w.seen:
			_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		case <-time.After(90 * time.Second):
		}
	}()
	start := time.Now()
	r = run(base, w, "cscript", "//nologo", `C:\limbo-sleep.js`)
	if r.rec.Status != "stopped" || r.rec.Stopped != "interrupt" || strings.Contains(r.stdout, "woke") || time.Since(start) > 40*time.Second {
		t.Fatalf("stop: %+v after %v", r.rec, time.Since(start))
	}

	// The sandbox's shape, seen from inside the very sandbox Build makes (a native shell instead of Wine, the same
	// options): its own host name, no machine ID, no network devices' details, an empty home but for the prefix and
	// its cache, no capabilities, no new privileges.
	sb, err := Build(base, h, d)
	if err != nil {
		t.Fatal(err)
	}
	inside := func(cmd string, env []string) (string, string) {
		var out, errb bytes.Buffer
		rr := &Run{Options: base, Host: h, Dirs: d, Stderr: &errb}
		res := rr.exec(sb, "printf x >&4; exec 4>&- 5<&- 6<&- 7<&- 8<&- 9<&-; "+cmd, nil, env, nil, &out, nil)
		if res.err != nil || !res.started {
			t.Fatalf("%s: %+v %s", cmd, res, errb.String())
		}
		return out.String(), errb.String()
	}
	out, _ := inside(`cat /proc/sys/kernel/hostname; ls /etc/machine-id /etc/hostname /sys/class/net /run/dbus 2>&1 | wc -l; `+
		`ls -A "$HOME" | tr '\n' ' '; echo; grep -E '^(CapEff|NoNewPrivs)' /proc/self/status | tr -s '\t' ' '`, sb.Env)
	want := "limbo\n4\n.cache .local \nCapEff: 0000000000000000\nNoNewPrivs: 1\n"
	if out != want {
		t.Fatalf("the sandbox's shape:\n%s\nwant:\n%s", out, want)
	}

	// The graphics card is usable inside, with the system's Vulkan layers (the Kairos frame-generation layer loads
	// when it is installed and switched on).
	if len(h.GPUNodes) > 0 && executable("/usr/bin/vulkaninfo") {
		env := append(sb.WithEnv("ENABLE_KAIROS", "1"), "VK_LOADER_DEBUG=layer")
		out, errOut := inside("/usr/bin/vulkaninfo --summary", env)
		if !strings.Contains(out, "deviceName") {
			t.Fatalf("no Vulkan device in the sandbox:\n%s\n%.2000s", out, errOut)
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "deviceName") {
				t.Log("inside the sandbox:" + line)
			}
		}
		if exists("/usr/share/vulkan/implicit_layer.d/kairos.x86_64.json") && !strings.Contains(out+errOut, `Insert instance layer "VK_LAYER_KAIROS_x86_64"`) {
			t.Fatalf("the Kairos layer did not load in the sandbox:\n%.3000s", errOut)
		}
	}
}
