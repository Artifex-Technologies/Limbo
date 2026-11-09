//go:build linux

package wine

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/events"
)

// Emitter writes Limbo's events (an *events.Logger).
type Emitter interface {
	Emit(kind, guest string, detail map[string]string) error
}

// Run is one `limbo wine` run.
type Run struct {
	Options    Options
	Host       Host
	Dirs       Dirs
	Program    string
	Args       []string
	Cwd        string
	Via        string // "cli", or "path" through Limbo's wine command on PATH
	Parent     string // the program that ran Limbo's wine command, when Via is "path"
	Profile    string // the profile file used, or ""
	ProfileSHA string
	Log        Emitter
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	// StopGrace is how long a stop request may take before the sandbox is killed (default 10 s).
	StopGrace time.Duration
}

// The in-sandbox script (sh -c with a fixed text: the program and its arguments are its positional parameters, "$@",
// and no shell ever parses them). It tells limbo it is running (one byte on descriptor 4), closes the descriptors only
// bwrap needed, starts the prefix's wineserver with no persistence (so the sandbox ends when the last Windows process
// does, not three seconds later), runs body, then waits for the wineserver to finish: it writes the registry out as it
// goes, and ending the sandbox first would lose those changes (and a launcher that started a game and returned would
// take the game with it). Meanwhile it waits for a line on descriptor 3, limbo's stop request, and answers it by ending
// every Windows process in the prefix through the wineserver (wineserver -k).
func script(body string) string {
	return "printf x >&4; exec 4>&- 5<&- 6<&- 7<&- 8<&- 9<&-; " +
		"{ read -r x <&3 && " + WineserverPath + " -k; } & " +
		WineserverPath + " -p0 3<&-; " +
		body + "; s=$?; " +
		WineserverPath + " -w 3<&-; exit $s"
}

const (
	bodyRun     = WinePath + ` "$@" 3<&-`
	bodyCreate  = WinePath + ` wineboot --init 3<&- && ` + WinePath + ` winecfg -v "$1" 3<&-`
	bodyWindows = WinePath + ` winecfg -v "$1" 3<&-`
)

// Do runs the program and returns its exit status. Every run is recorded: wine.start before the sandbox starts (a run
// that cannot be logged does not happen), wine.stop after, and each refusal as wine.refused.
func (r *Run) Do() (int, error) {
	if r.Via == "" {
		r.Via = "cli"
	}
	if r.Log == nil {
		return 1, errors.New("wine: no event log, so nothing was run")
	}
	guest := Guest(r.Options.Prefix)
	refuse := func(err error) (int, error) {
		_ = r.Log.Emit(events.WineRefused, guest, r.detail(map[string]string{"reason": clean(err.Error(), 300)}))
		return 1, err
	}
	if os.Geteuid() == 0 {
		return refuse(errors.New("wine: refusing to run Windows programs as root; run limbo wine as yourself"))
	}
	if !executable(BwrapPath) {
		return refuse(errors.New("wine: bubblewrap is not installed (" + BwrapPath + "); Limbo runs Wine only inside it: sudo pacman -S bubblewrap"))
	}
	if !executable(WinePath) {
		return refuse(errors.New("wine: Wine is not installed (" + WinePath + "): sudo pacman -S wine (or wine-staging)"))
	}
	if err := r.check(); err != nil {
		return refuse(err)
	}
	if err := ensureDir(r.Dirs.Root); err != nil {
		return refuse(err)
	}
	lock, err := lockPrefix(r.Dirs, r.Options.Prefix)
	if err != nil {
		return refuse(err)
	}
	defer lock.Close()
	for _, dir := range []string{r.Dirs.Prefix(r.Options.Prefix), r.Dirs.Cache, r.Dirs.PrefixCache(r.Options.Prefix)} {
		if err := ensureDir(dir); err != nil {
			return refuse(err)
		}
	}
	s, err := Build(r.Options, r.Host, r.Dirs)
	if err != nil {
		return refuse(err)
	}
	if cwd, err := filepath.EvalSymlinks(r.Cwd); err == nil && visible(cwd, r.Options, r.Dirs) && visible(r.Cwd, r.Options, r.Dirs) {
		s.SetChdir(r.Cwd)
	}

	start := time.Now().UTC()
	id, dir, err := newRunDir(r.Dirs.State, start)
	if err != nil {
		return refuse(fmt.Errorf("wine: the run folder: %w", err))
	}
	rec := &Record{ID: id, Prefix: r.Options.Prefix, Via: r.Via, Parent: r.Parent, Profile: r.Profile, ProfileSHA256: r.ProfileSHA,
		Program: r.Program, Args: append([]string{}, r.Args...), Cwd: s.Chdir, Started: start, Status: "running", Allowed: allowed(r.Options, s)}
	if pf := r.programFile(); pf != "" {
		if sum, size, err := hashFile(pf); err == nil {
			rec.ProgramPath, rec.ProgramSHA256, rec.ProgramSize = pf, sum, size
		}
	}
	if code, err := r.setup(s, rec, id, filepath.Join(dir, "run.json")); err != nil {
		end := time.Now().UTC()
		rec.Ended, rec.ExitCode, rec.Status = &end, &code, "setup_failed"
		_ = rec.save(dir)
		return code, err
	}
	if r.Options.Trace {
		rec.Trace = &Trace{File: filepath.Join(dir, "trace.log"), Channels: TraceChannels, Limit: TraceLimit}
	}

	startDetail := r.detail(map[string]string{
		"run": id, "record": filepath.Join(dir, "run.json"), "network": r.Options.Network, "gpu": onOff(s.GPU),
		"display": orNone(strings.Join(s.Display, ",")), "audio": orNone(s.Audio),
		"share": pathList(sharePaths(r.Options.Shares, false)), "share_rw": pathList(sharePaths(r.Options.Shares, true)),
	})
	if rec.ProgramSHA256 != "" {
		startDetail["sha256"] = rec.ProgramSHA256
	}
	if r.Options.Trace {
		startDetail["trace"] = "on"
	}
	if err := rec.save(dir); err != nil {
		return 1, fmt.Errorf("wine: the run record could not be written, so nothing was run: %w", err)
	}
	if err := r.Log.Emit(events.WineStart, guest, startDetail); err != nil {
		rec.Status = "not_started"
		_ = rec.save(dir)
		return 1, fmt.Errorf("wine: the event log could not be written, so nothing was run: %w", err)
	}

	env := s.Env
	if r.Options.Trace {
		env = s.WithEnv("WINEDEBUG", TraceChannels)
	}
	res := r.exec(s, script(bodyRun), append([]string{r.Program}, r.Args...), env, r.Stdin, r.Stdout, rec.Trace)
	end := time.Now().UTC()
	rec.Ended, rec.ExitCode, rec.Stopped = &end, &res.code, res.stopped
	switch {
	case res.err != nil || !res.started:
		rec.Status = "sandbox_failed"
	case res.stopped != "":
		rec.Status = "stopped"
	default:
		rec.Status = "exited"
	}
	saveErr := rec.save(dir)
	stop := r.detail(map[string]string{"run": id, "record": filepath.Join(dir, "run.json"), "exit_code": strconv.Itoa(res.code),
		"seconds": strconv.FormatFloat(end.Sub(start).Seconds(), 'f', 1, 64), "status": rec.Status})
	if res.stopped != "" {
		stop["stopped"] = res.stopped
	}
	if err := r.Log.Emit(events.WineStop, guest, stop); err != nil && res.err == nil {
		res.err = fmt.Errorf("wine: the program ran, but its end could not be logged: %w", err)
	}
	if res.err == nil && !res.started {
		res.err = fmt.Errorf("wine: the sandbox could not be set up (bwrap exit status %d; its message is above)", res.code)
	}
	if res.err == nil {
		res.err = saveErr
	}
	return res.code, res.err
}

// check refuses what Limbo will not run: bad names, shares it will not give, a program outside the sandbox.
func (r *Run) check() error {
	o := r.Options
	if err := ValidName(o.Prefix); err != nil {
		return err
	}
	if o.Windows != "" {
		if err := ValidWindows(o.Windows); err != nil {
			return err
		}
	}
	if o.Arch != "" {
		if err := ValidArch(o.Arch); err != nil {
			return err
		}
	}
	if o.Network != NetNone && o.Network != NetHost {
		return fmt.Errorf("wine: network must be %q or %q", NetNone, NetHost)
	}
	if len(o.Shares) > maxShares {
		return fmt.Errorf("wine: more than %d shares", maxShares)
	}
	seen := map[string]bool{}
	for _, sh := range o.Shares {
		if seen[sh.Path] {
			return fmt.Errorf("wine: %s is shared twice", sh.Path)
		}
		seen[sh.Path] = true
		if err := CheckShare(sh, r.Host.Home, r.Dirs); err != nil {
			return err
		}
	}
	if r.Program == "" {
		return errors.New("wine: no program to run (limbo wine [options] -- PROGRAM [ARGS], or a profile's \"program\")")
	}
	if strings.Contains(r.Program, "/") {
		p := r.unixProgram()
		if _, err := os.Stat(p); err == nil && !visible(p, o, r.Dirs) {
			return fmt.Errorf("wine: %s is outside the sandbox, so Wine would not find it: share its folder read-only (--share %s) "+
				"or copy it into the prefix (%s)", p, filepath.Dir(p), filepath.Join(r.Dirs.Prefix(o.Prefix), "drive_c"))
		}
	}
	return nil
}

func (r *Run) unixProgram() string {
	p := r.Program
	if !filepath.IsAbs(p) {
		p = filepath.Join(r.Cwd, p)
	}
	return filepath.Clean(p)
}

// programFile is the host file the program names when Limbo can tell: a unix path, or a C:\ path in the prefix; and
// only when it (with its symlinks resolved) is inside the sandbox.
func (r *Run) programFile() string {
	var p string
	switch prog := r.Program; {
	case strings.Contains(prog, "/"):
		p = r.unixProgram()
	case len(prog) > 3 && (prog[0] == 'c' || prog[0] == 'C') && prog[1] == ':' && prog[2] == '\\':
		driveC := filepath.Join(r.Dirs.Prefix(r.Options.Prefix), "drive_c")
		p = filepath.Join(driveC, strings.ReplaceAll(prog[3:], `\`, "/"))
		if !within(p, driveC) {
			return ""
		}
	default:
		return ""
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil || !visible(p, r.Options, r.Dirs) || !visible(real, r.Options, r.Dirs) {
		return ""
	}
	return real
}

// setup makes a new prefix (64-bit unless asked otherwise, reporting DefaultWindows unless asked otherwise), or sets
// an existing prefix's Windows version when one is asked for that differs from what Limbo last set. A prefix whose
// making was interrupted (its marker is still there) is made again: wineboot finishes it.
func (r *Run) setup(s *Sandbox, rec *Record, id, record string) (int, error) {
	name, prefix := r.Options.Prefix, r.Dirs.Prefix(r.Options.Prefix)
	guest := Guest(name)
	last, _ := readPrefixRecord(r.Dirs.recordFile(name))
	creating := r.Dirs.creatingFile(name)
	fail := func(step string, res result, hint string) (int, error) {
		d := r.detail(map[string]string{"run": id, "record": record, "during": "setup", "step": step, "exit_code": strconv.Itoa(res.code), "status": "setup_failed"})
		if res.stopped != "" {
			d["stopped"] = res.stopped
		}
		_ = r.Log.Emit(events.WineStop, guest, d)
		if res.err != nil {
			return 1, res.err
		}
		if res.stopped != "" {
			return max(res.code, 1), fmt.Errorf("wine: stopped while setting up prefix %q", name)
		}
		return max(res.code, 1), fmt.Errorf("wine: setting up prefix %q (%s) failed with exit status %d%s", name, step, res.code, hint)
	}
	if !prefixExists(prefix) || exists(creating) {
		arch, win := r.Options.Arch, r.Options.Windows
		if arch == "" {
			arch = ArchWin64
		}
		if win == "" {
			win = DefaultWindows
		}
		if err := r.Log.Emit(events.WineSetup, guest, map[string]string{"run": id, "step": "create", "arch": arch, "windows": win}); err != nil {
			return 1, fmt.Errorf("wine: the event log could not be written, so nothing was run: %w", err)
		}
		fmt.Fprintf(r.Stderr, "limbo wine: making prefix %q (%s, reporting %s) in %s...\n", name, arch, win, prefix)
		if err := os.WriteFile(creating, nil, 0o600); err != nil {
			return 1, err
		}
		res := r.exec(s, script(bodyCreate), []string{win}, s.WithEnv("WINEARCH", arch), nil, r.Stderr, nil)
		if res.err != nil || res.code != 0 || res.stopped != "" || !res.started {
			hint := ""
			if arch == ArchWin32 {
				hint = "; this Wine may not make 32-bit prefixes at all (a WoW64-only build, as Arch's Wine 11 is): a 64-bit prefix runs 32-bit programs too"
			}
			return fail("create", res, hint)
		}
		if err := writePrefixRecord(r.Dirs.recordFile(name), prefixRecord{Arch: arch, Windows: win, Updated: time.Now().UTC()}); err != nil {
			return 1, err
		}
		if err := os.Remove(creating); err != nil {
			return 1, err
		}
		rec.Arch, rec.Windows = arch, win
		return 0, nil
	}
	arch := prefixArch(prefix)
	if r.Options.Arch != "" && arch != "" && r.Options.Arch != arch {
		return 1, fmt.Errorf("wine: prefix %q is %s, and a prefix's architecture is fixed when it is made; use another --prefix for %s", name, arch, r.Options.Arch)
	}
	rec.Arch, rec.Windows = arch, last.Windows
	if want := r.Options.Windows; want != "" && want != last.Windows {
		if err := r.Log.Emit(events.WineSetup, guest, map[string]string{"run": id, "step": "windows", "windows": want}); err != nil {
			return 1, fmt.Errorf("wine: the event log could not be written, so nothing was run: %w", err)
		}
		res := r.exec(s, script(bodyWindows), []string{want}, s.Env, nil, r.Stderr, nil)
		if res.err != nil || res.code != 0 || res.stopped != "" || !res.started {
			return fail("windows", res, "")
		}
		if err := writePrefixRecord(r.Dirs.recordFile(name), prefixRecord{Arch: arch, Windows: want, Updated: time.Now().UTC()}); err != nil {
			return 1, err
		}
		rec.Windows = want
	}
	return 0, nil
}

type result struct {
	code    int
	started bool   // bwrap set the sandbox up and started the script
	stopped string // the signal limbo stopped the sandbox on, or ""
	err     error  // limbo's own failure (not the program's exit status)
}

// exec runs one sandbox to its end. A first SIGINT, SIGTERM or SIGHUP asks the sandbox to stop (the script ends the
// prefix's Windows processes through the wineserver); a second one, or StopGrace without an end, kills it (bwrap runs
// in its own process group so a terminal's Ctrl+C reaches limbo alone, and --die-with-parent takes the sandbox along).
func (r *Run) exec(s *Sandbox, script string, args, env []string, stdin io.Reader, stdout io.Writer, tr *Trace) (res result) {
	argv := s.Command(script, args)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, r.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var closeAfterStart, closeAfterWait []*os.File
	defer func() {
		for _, f := range closeAfterWait {
			f.Close()
		}
	}()
	pipe := func() (*os.File, *os.File, bool) {
		pr, pw, err := os.Pipe()
		if err != nil {
			res.err = err
			return nil, nil, false
		}
		return pr, pw, true
	}
	stopR, stopW, ok := pipe()
	if !ok {
		return res
	}
	statR, statW, ok := pipe()
	if !ok {
		stopR.Close()
		stopW.Close()
		return res
	}
	closeAfterStart = append(closeAfterStart, stopR, statW)
	closeAfterWait = append(closeAfterWait, stopW, statR)
	cmd.ExtraFiles = []*os.File{stopR, statW}
	for _, d := range s.Data {
		pr, pw, ok := pipe()
		if !ok {
			for _, f := range closeAfterStart {
				f.Close()
			}
			return res
		}
		go func(content []byte) { _, _ = pw.Write(content); pw.Close() }(d.Content)
		cmd.ExtraFiles = append(cmd.ExtraFiles, pr)
		closeAfterStart = append(closeAfterStart, pr)
	}
	traced := make(chan struct{})
	if tr != nil {
		tf, err := os.OpenFile(tr.File, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			res.err = err
			for _, f := range closeAfterStart {
				f.Close()
			}
			return res
		}
		pr, pw, ok := pipe()
		if !ok {
			tf.Close()
			for _, f := range closeAfterStart {
				f.Close()
			}
			return res
		}
		cmd.Stderr = pw
		closeAfterStart = append(closeAfterStart, pw)
		go func() {
			tr.Bytes, tr.Truncated = splitTrace(pr, tf, r.Stderr, tr.Limit)
			tf.Close()
			pr.Close()
			close(traced)
		}()
	} else {
		close(traced)
	}

	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	err := cmd.Start()
	for _, f := range closeAfterStart {
		f.Close()
	}
	if err != nil {
		res.err = fmt.Errorf("wine: starting bwrap: %w", err)
		<-traced
		return res
	}
	started := make(chan bool, 1)
	go func() {
		b := make([]byte, 1)
		n, _ := statR.Read(b)
		started <- n == 1
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	grace := r.StopGrace
	if grace <= 0 {
		grace = 10 * time.Second
	}
	var deadline <-chan time.Time
	kill := func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
wait:
	for {
		select {
		case <-done:
			break wait
		case sig := <-sigs:
			if res.stopped != "" {
				kill()
				continue
			}
			res.stopped = sig.String()
			fmt.Fprintf(r.Stderr, "limbo wine: %s: stopping the program (again to kill it at once)\n", sig)
			_, _ = stopW.Write([]byte("stop\n"))
			deadline = time.After(grace)
		case <-deadline:
			kill()
		}
	}
	<-traced
	res.started = <-started
	res.code = cmd.ProcessState.ExitCode()
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		res.code = 128 + int(ws.Signal())
	}
	return res
}

// detail adds what every Wine event carries about the run's origin.
func (r *Run) detail(d map[string]string) map[string]string {
	d["prefix"] = r.Options.Prefix
	d["program"] = clean(r.Program, 200)
	d["via"] = r.Via
	if r.Parent != "" {
		d["parent"] = clean(r.Parent, 64)
	}
	return d
}

// DryRun prints what a run would do (the checks, the sandbox, the steps) and changes nothing.
func (r *Run) DryRun(w io.Writer) error {
	if err := r.check(); err != nil {
		return err
	}
	s, err := Build(r.Options, r.Host, r.Dirs)
	if err != nil {
		return err
	}
	if visible(r.Cwd, r.Options, r.Dirs) {
		s.SetChdir(r.Cwd)
	}
	prefix := r.Dirs.Prefix(r.Options.Prefix)
	fmt.Fprintf(w, "# prefix %s: %s\n", r.Options.Prefix, prefix)
	if !prefixExists(prefix) || exists(r.Dirs.creatingFile(r.Options.Prefix)) {
		arch, win := r.Options.Arch, r.Options.Windows
		if arch == "" {
			arch = ArchWin64
		}
		if win == "" {
			win = DefaultWindows
		}
		fmt.Fprintf(w, "# it does not exist yet: it would first be made %s, reporting Windows version %s (wineboot --init; winecfg -v %s)\n", arch, win, win)
	} else if r.Options.Windows != "" {
		fmt.Fprintf(w, "# its Windows version would be set to %s if Limbo last set another\n", r.Options.Windows)
	}
	shares := "none"
	if len(r.Options.Shares) > 0 {
		var parts []string
		for _, sh := range r.Options.Shares {
			mode := "read-only"
			if sh.Writable {
				mode = "writable"
			}
			parts = append(parts, sh.Path+" ("+mode+")")
		}
		shares = strings.Join(parts, ", ")
	}
	fmt.Fprintf(w, "# network %s; graphics card %s; display %s; sound %s; shares: %s\n", r.Options.Network, onOff(s.GPU),
		orNone(strings.Join(s.Display, ",")), orNone(s.Audio), shares)
	if r.Options.Trace {
		fmt.Fprintf(w, "# traced: WINEDEBUG=%s, into the run folder (at most %d MiB)\n", TraceChannels, TraceLimit>>20)
	}
	fmt.Fprintln(w, "# environment:")
	for _, kv := range s.Env {
		fmt.Fprintln(w, "#   "+kv)
	}
	for i, d := range s.Data {
		fmt.Fprintf(w, "# descriptor %d becomes %s:\n", fdData+i, d.Dest)
		if strings.Contains(d.Dest, "Xauthority") || strings.Contains(d.Dest, "cookie") {
			fmt.Fprintf(w, "#   (%d bytes, not shown)\n", len(d.Content))
			continue
		}
		for _, line := range strings.Split(strings.TrimRight(string(d.Content), "\n"), "\n") {
			fmt.Fprintln(w, "#   "+line)
		}
	}
	// One bwrap option and its arguments per line; the command after "--" on the last.
	argv := s.Command(script(bodyRun), append([]string{r.Program}, r.Args...))
	var lines [][]string
	command := false
	for i, a := range argv {
		if i == 0 || (!command && strings.HasPrefix(a, "--")) {
			lines = append(lines, nil)
		}
		command = command || a == "--"
		lines[len(lines)-1] = append(lines[len(lines)-1], quote(a))
	}
	for i, l := range lines {
		end := " \\"
		if i == len(lines)-1 {
			end = ""
		}
		fmt.Fprintln(w, strings.Join(l, " ")+end)
	}
	return nil
}

func quote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=,+@%") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func sharePaths(shares []Share, writable bool) []string {
	var out []string
	for _, sh := range shares {
		if sh.Writable == writable {
			out = append(out, sh.Path)
		}
	}
	return out
}

func executable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
