package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
)

// The commands the Settings page (docs/SETTINGS_PAGE.md) can use instead of speaking HTTP itself. As a member of
// limbo-users they talk to user.sock; as root (sudo, pkexec) to admin.sock, which is how "use the password" works:
// the page runs `pkexec limbo instance start NAME` when the switch asks for the password.
//
// --json prints the server's answer exactly as the socket gives it (the shapes in docs/SETTINGS_PAGE.md), and on
// failure the error object ({"error","code","message","remedy"}) on stdout with exit status 1.

const (
	adminSock = "/run/limbo/admin.sock"
	userSock  = "/run/limbo/user.sock"
)

func defaultSocket() string {
	if geteuid() == 0 {
		return adminSock
	}
	return userSock
}

type cli struct {
	sock   string
	asJSON bool
	out    io.Writer
}

// apiFail is a refusal from the server, kept whole for --json.
type apiFail struct {
	status int
	raw    []byte
	msg    string
}

func (e *apiFail) Error() string { return e.msg }

func (c *cli) do(method, path string, in any) ([]byte, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://limbo"+path, body)
	if err != nil {
		return nil, err
	}
	resp, err := unixClient(c.sock).Do(req)
	if err != nil {
		if c.sock == userSock {
			return nil, fmt.Errorf("%w (is Limbo running, and are you in the limbo-users group?)", err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		msg := "server returned " + resp.Status
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return nil, &apiFail{status: resp.StatusCode, raw: raw, msg: msg}
	}
	return raw, nil
}

// emit prints raw JSON with --json, otherwise calls human.
func (c *cli) emit(raw []byte, human func(raw []byte) error) error {
	if c.asJSON || human == nil {
		var buf bytes.Buffer
		if json.Indent(&buf, raw, "", "  ") == nil {
			raw = buf.Bytes()
		}
		fmt.Fprintln(c.out, strings.TrimSpace(string(raw)))
		return nil
	}
	return human(raw)
}

// finish turns a refusal into --json output when asked.
func (c *cli) finish(err error) error {
	var f *apiFail
	if c.asJSON && errors.As(err, &f) && len(f.raw) > 0 {
		fmt.Fprintln(c.out, strings.TrimSpace(string(f.raw)))
		return errSilent
	}
	return err
}

// cliOut is where these commands print; tests replace it.
var cliOut io.Writer = os.Stdout

// errSilent: the error was already printed (as JSON); exit 1 without another line.
var errSilent = errors.New("")

func newCLI(name string) (*cli, *flag.FlagSet) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	c := &cli{out: cliOut}
	fs.StringVar(&c.sock, "socket", defaultSocket(), "socket: admin.sock as root, user.sock otherwise")
	fs.BoolVar(&c.asJSON, "json", false, "print the server's JSON answer")
	return c, fs
}

// settingsCmd: limbo settings show [--json] | password on|off
func settingsCmd(args []string) error {
	c, fs := newCLI("settings")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return errors.New("usage: limbo settings show [--json] | limbo settings password on|off (root)")
	}
	switch pos[0] {
	case "show":
		// One call for the whole page: status, instances, licenses.
		out := map[string]json.RawMessage{}
		// in a fixed order, so the first refusal is always the same one (a map's order changes from run to run)
		for _, kp := range [][2]string{{"status", "/v1/status"}, {"instances", "/v1/instances"}, {"licenses", "/v1/licenses"}} {
			key, path := kp[0], kp[1]
			raw, err := c.do("GET", path, nil)
			if err != nil {
				return c.finish(err)
			}
			if key != "status" {
				var wrap map[string]json.RawMessage
				if json.Unmarshal(raw, &wrap) == nil {
					raw = wrap[key]
				}
			}
			out[key] = raw
		}
		b, _ := json.Marshal(out)
		return c.emit(b, func([]byte) error {
			var st struct {
				Version     string `json:"version"`
				KVM         bool   `json:"kvm"`
				AskPassword bool   `json:"ask_password"`
				Space       struct {
					TotalBytes int64 `json:"total_bytes"`
				} `json:"space"`
			}
			_ = json.Unmarshal(out["status"], &st)
			fmt.Fprintf(c.out, "Limbo %s: running; KVM %s; space used %s; ask for password: %s\n\n",
				st.Version, yesNo(st.KVM), size(st.Space.TotalBytes), onOff(st.AskPassword))
			return printInstances(c.out, out["instances"])
		})
	case "password":
		if len(pos) != 2 || (pos[1] != "on" && pos[1] != "off") {
			return errors.New("usage: limbo settings password on|off (needs root: sudo or pkexec)")
		}
		if c.sock == userSock {
			return errors.New("settings password: needs root (sudo or pkexec)")
		}
		raw, err := c.do("POST", "/v1/settings", map[string]bool{"ask_password": pos[1] == "on"})
		if err != nil {
			return c.finish(err)
		}
		return c.emit(raw, func([]byte) error {
			fmt.Fprintf(c.out, "Ask for my password for Limbo changes: %s\n", pos[1])
			return nil
		})
	}
	return fmt.Errorf("unknown settings subcommand %q", pos[0])
}

func yesNo(b bool) string {
	if b {
		return "available"
	}
	return "not available"
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func size(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d KiB", n>>10)
}

type viewRow struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	OS       string `json:"os"`
	State    string `json:"state"`
	CPUs     int    `json:"cpus"`
	MemoryMB int    `json:"memory_mb"`
	Network  string `json:"network"`
	Disk     struct {
		OwnBytes  int64 `json:"own_bytes"`
		BaseBytes int64 `json:"base_bytes"`
	} `json:"disk"`
	HeldByHeimdall bool   `json:"held_by_heimdall"`
	Owner          string `json:"owner"`
	Pending        bool   `json:"pending"`
}

func printInstances(w io.Writer, raw []byte) error {
	var rows []viewRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		var wrap struct {
			Instances []viewRow `json:"instances"`
		}
		if err := json.Unmarshal(raw, &wrap); err != nil {
			return err
		}
		rows = wrap.Instances
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tKIND\tSYSTEM\tSTATE\tCPUS\tMEMORY\tNETWORK\tOWN DISK\tBASE\tOWNER")
	for _, r := range rows {
		st := r.State
		if r.HeldByHeimdall {
			st = "held by Heimdall"
		}
		if r.Pending {
			st += " (changes at next start)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d MiB\t%s\t%s\t%s\t%s\n", r.Name, r.Kind, r.OS, st, r.CPUs, r.MemoryMB, r.Network,
			size(r.Disk.OwnBytes), size(r.Disk.BaseBytes), r.Owner)
	}
	return tw.Flush()
}

// instanceCmd: limbo instance list|show|start|stop|set|free-space|add|remove
func instanceCmd(args []string) error {
	c, fs := newCLI("instance")
	cpus := fs.Int("cpus", 0, "set: processors")
	mem := fs.Int("memory-mb", 0, "set: memory in MiB")
	diskGB := fs.Int("disk-gb", 0, "set: disk size in GiB (grows only)")
	shared := fs.String("shared-folder", "", "set: on|off")
	clip := fs.String("clipboard", "", "set: off|text")
	devices := fs.String("devices", "\x00", "set: comma-separated PCI addresses or USB IDs (vendor:product), from the manifest's own list; empty for none")
	network := fs.String("network", "", "set (root): none, internet-only, or allowlist (with --allow); from the guest's next start")
	allow := fs.String("allow", "", "set --network allowlist: comma-separated ADDRESS[/BITS]:tcp|udp:PORT, e.g. 1.2.3.4:tcp:443")
	owner := fs.String("owner", "", "add: the account that may change it without the password (default: the sudo user)")
	deleteDisk := fs.Bool("delete-disk", false, "remove: also delete the guest's own disk")
	yes := fs.Bool("yes", false, "free-space: do not ask")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	usage := errors.New("usage: limbo instance list | show NAME | start NAME | stop NAME | set NAME [--cpus N] [--memory-mb N] [--disk-gb N] [--shared-folder on|off] [--clipboard off|text] [--devices A,B] [--network none|internet-only|allowlist --allow A:tcp:443,...] | free-space NAME [--yes] | add MANIFEST [--owner USER] (root) | remove NAME [--delete-disk] (root)")
	if len(pos) == 0 {
		return usage
	}
	need := func(n int) error {
		if len(pos) != n {
			return usage
		}
		return nil
	}
	var raw []byte
	switch pos[0] {
	case "list":
		raw, err = c.do("GET", "/v1/instances", nil)
		if err != nil {
			return c.finish(err)
		}
		return c.emit(raw, func(b []byte) error { return printInstances(c.out, b) })
	case "show":
		if err := need(2); err != nil {
			return err
		}
		raw, err = c.do("GET", "/v1/instances/"+pos[1], nil)
	case "start", "stop":
		if err := need(2); err != nil {
			return err
		}
		raw, err = c.do("POST", "/v1/instances/"+pos[1]+"/"+pos[0], nil)
	case "set":
		if err := need(2); err != nil {
			return err
		}
		ch := map[string]any{}
		if *cpus != 0 {
			ch["cpus"] = *cpus
		}
		if *mem != 0 {
			ch["memory_mb"] = *mem
		}
		if *diskGB != 0 {
			ch["disk_gb"] = *diskGB
		}
		if *shared != "" {
			ch["shared_folder"] = *shared
		}
		if *clip != "" {
			ch["clipboard"] = *clip
		}
		if *devices != "\x00" {
			list := []string{}
			for _, d := range strings.Split(*devices, ",") {
				if d = strings.TrimSpace(d); d != "" {
					list = append(list, d)
				}
			}
			ch["devices"] = list
		}
		if *network != "" {
			n, err := networkChange(*network, *allow)
			if err != nil {
				return err
			}
			ch["network"] = n
		} else if *allow != "" {
			return errors.New("set: --allow goes with --network allowlist")
		}
		raw, err = c.do("POST", "/v1/instances/"+pos[1]+"/settings", ch)
	case "free-space":
		if err := need(2); err != nil {
			return err
		}
		if !*yes {
			fmt.Fprintf(os.Stderr, "This deletes everything %s changed since its base image. Type yes to go on: ", pos[1])
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.TrimSpace(line) != "yes" {
				return errors.New("free-space: not confirmed")
			}
		}
		raw, err = c.do("POST", "/v1/instances/"+pos[1]+"/free-space", map[string]bool{"confirm": true})
	case "add":
		if err := need(2); err != nil {
			return err
		}
		m, lerr := manifest.Load(pos[1])
		if lerr != nil {
			return lerr
		}
		o := *owner
		if o == "" {
			o = os.Getenv("SUDO_USER")
			if o == "" {
				o = os.Getenv("PKEXEC_UID")
				if o != "" {
					o = lookupUserName(o)
				}
			}
		}
		raw, err = c.do("POST", "/v1/instances", map[string]any{"manifest": m, "owner": o})
	case "remove":
		if err := need(2); err != nil {
			return err
		}
		raw, err = c.do("DELETE", "/v1/instances/"+pos[1], map[string]bool{"delete_disk": *deleteDisk})
	default:
		return usage
	}
	if err != nil {
		return c.finish(err)
	}
	return c.emit(raw, func(b []byte) error {
		if bytes.Contains(b, []byte(`"freed_bytes"`)) || bytes.Contains(b, []byte(`"removed"`)) {
			fmt.Fprintln(c.out, strings.TrimSpace(string(b)))
			return nil
		}
		return printInstances(c.out, append(append([]byte("["), b...), ']'))
	})
}

// licenseCmd: limbo license list | add --name N (key on stdin) | remove ID | reveal ID | assign ID GUEST | unassign ID GUEST
func licenseCmd(args []string) error {
	c, fs := newCLI("license")
	name := fs.String("name", "", "add: a name for the license, e.g. \"Windows 11 Pro, old PC\"")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	usage := errors.New("usage: limbo license list | add --name NAME (the key is read from stdin, never from the command line) | remove ID | reveal ID | assign ID GUEST | unassign ID GUEST")
	if len(pos) == 0 {
		return usage
	}
	var raw []byte
	switch pos[0] {
	case "list":
		raw, err = c.do("GET", "/v1/licenses", nil)
		if err != nil {
			return c.finish(err)
		}
		return c.emit(raw, func(b []byte) error {
			var w struct {
				Licenses []struct {
					ID, Name, Masked string
					Assigned         []string
				} `json:"licenses"`
			}
			if err := json.Unmarshal(b, &w); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(c.out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tKEY\tGUESTS")
			for _, l := range w.Licenses {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", l.ID, l.Name, l.Masked, strings.Join(l.Assigned, ","))
			}
			return tw.Flush()
		})
	case "add":
		if len(pos) != 1 {
			return usage
		}
		if fi, _ := os.Stdin.Stat(); fi != nil && fi.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprint(os.Stderr, "Product key: ")
		}
		line, _ := bufio.NewReader(io.LimitReader(os.Stdin, 256)).ReadString('\n')
		raw, err = c.do("POST", "/v1/licenses", map[string]string{"name": *name, "key": strings.TrimSpace(line)})
	case "remove":
		if len(pos) != 2 {
			return usage
		}
		raw, err = c.do("DELETE", "/v1/licenses/"+pos[1], nil)
	case "reveal":
		if len(pos) != 2 {
			return usage
		}
		raw, err = c.do("GET", "/v1/licenses/"+pos[1]+"/key", nil)
	case "assign", "unassign":
		if len(pos) != 3 {
			return usage
		}
		raw, err = c.do("POST", "/v1/licenses/"+pos[1]+"/"+pos[0], map[string]string{"guest": pos[2]})
	default:
		return usage
	}
	if err != nil {
		return c.finish(err)
	}
	return c.emit(raw, nil)
}

// exchangeCmd: limbo exchange list GUEST | take GUEST PATH DEST
func exchangeCmd(args []string) error {
	c, fs := newCLI("exchange")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	usage := errors.New("usage: limbo exchange list GUEST | take GUEST PATH DEST (ClamAV scans it first; DEST must not exist)")
	if len(pos) < 2 {
		return usage
	}
	switch pos[0] {
	case "list":
		raw, err := c.do("GET", "/v1/exchange/"+pos[1], nil)
		if err != nil {
			return c.finish(err)
		}
		return c.emit(raw, func(b []byte) error {
			var l struct {
				Files []struct {
					Path string `json:"path"`
					Size int64  `json:"size"`
				} `json:"files"`
				Unlisted int `json:"unlisted"`
			}
			if err := json.Unmarshal(b, &l); err != nil {
				return err
			}
			fmt.Fprintf(c.out, "Files the guest %s left (names come from the guest: untrusted):\n", pos[1])
			for _, f := range l.Files {
				fmt.Fprintf(c.out, "  %q  %s\n", f.Path, size(f.Size))
			}
			if l.Unlisted > 0 {
				fmt.Fprintf(c.out, "  (%d entries not shown: not plain files, or unsafe names)\n", l.Unlisted)
			}
			return nil
		})
	case "take":
		if len(pos) != 4 {
			return usage
		}
		return c.take(pos[1], pos[2], pos[3])
	}
	return usage
}

// take asks the daemon for one scanned file and writes it to dest as the caller, never executable, never over an
// existing file or through a link. Under sudo the file is given to the person who ran sudo.
func (c *cli) take(guest, rel, dest string) error {
	b, _ := json.Marshal(map[string]string{"path": rel})
	req, err := http.NewRequest("POST", "http://limbo/v1/exchange/"+guest+"/take", bytes.NewReader(b))
	if err != nil {
		return err // a guest name the URL cannot carry ("%zz"); this was a nil request and a panic
	}
	resp, err := unixClient(c.sock).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var e struct {
			Error string `json:"error"`
		}
		msg := resp.Status
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return c.finish(&apiFail{status: resp.StatusCode, raw: raw, msg: msg})
	}
	want := resp.Header.Get("X-Limbo-Sha256")
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, cerr := io.Copy(io.MultiWriter(f, h), resp.Body)
	if err := f.Chmod(0o644); err != nil && cerr == nil {
		cerr = err
	}
	if err := f.Close(); err != nil && cerr == nil {
		cerr = err
	}
	if got := hex.EncodeToString(h.Sum(nil)); cerr == nil && got != want {
		cerr = fmt.Errorf("the file arrived damaged (sha256 %s, expected %s)", got, want)
	}
	if cerr != nil {
		os.Remove(dest)
		return cerr
	}
	if geteuid() == 0 {
		if uid, gid, ok := sudoIDs(); ok {
			_ = os.Lchown(dest, uid, gid)
		}
	}
	if c.asJSON {
		out, _ := json.Marshal(map[string]string{"path": filepath.Clean(dest), "sha256": want, "scan": resp.Header.Get("X-Limbo-Scan")})
		fmt.Fprintln(c.out, string(out))
		return nil
	}
	fmt.Fprintf(c.out, "%s: scanned clean by ClamAV, sha256 %s\n", dest, want)
	return nil
}

// sudoIDs is the person behind sudo or pkexec.
func sudoIDs() (int, int, bool) {
	u, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	g, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 == nil && err2 == nil {
		return u, g, true
	}
	if pu := os.Getenv("PKEXEC_UID"); pu != "" {
		if usr, err := user.LookupId(pu); err == nil {
			u, err1 := strconv.Atoi(usr.Uid)
			g, err2 := strconv.Atoi(usr.Gid)
			if err1 == nil && err2 == nil {
				return u, g, true
			}
		}
	}
	return 0, 0, false
}

func lookupUserName(uid string) string {
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return ""
}

// networkChange reads --network and --allow ("1.2.3.4:tcp:443,10.0.0.0/24:udp:53") into the network a guest may reach; the
// service validates it again.
func networkChange(mode, allow string) (map[string]any, error) {
	list := []map[string]any{}
	for _, a := range strings.Split(allow, ",") {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		i := strings.LastIndex(a, ":")
		j := strings.LastIndex(a[:max(i, 0)], ":")
		if i < 0 || j < 0 {
			return nil, fmt.Errorf("--allow %q: write ADDRESS:tcp|udp:PORT", a)
		}
		port, err := strconv.Atoi(a[i+1:])
		if err != nil {
			return nil, fmt.Errorf("--allow %q: the port is not a number", a)
		}
		list = append(list, map[string]any{"addr": a[:j], "proto": a[j+1 : i], "port": port})
	}
	return map[string]any{"mode": mode, "allow": list}, nil
}
