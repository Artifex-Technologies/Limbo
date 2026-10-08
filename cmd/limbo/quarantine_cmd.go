package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
)

// unixClient talks HTTP over a unix socket. The admin socket is root-only, so
// these commands need sudo; that is the point: a verdict requires a human with
// that authority.
func unixClient(sock string) *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}},
	}
}

func doJSON(c *http.Client, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://limbo"+path, body)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("server returned %s", resp.Status)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// parseInterspersed lets flags appear after positional arguments
// ("verdict ID safe --note x"), which Go's flag package otherwise treats as
// more positionals: a verdict command that silently ignored --note, or worse,
// refused to run, is not acceptable for the one action that needs a human.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// whoAmI is the identity claimed in a verdict. It is a convenience for the
// record; the server separately records the connecting process's uid and pid.
func whoAmI() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	return os.Getenv("USER")
}

func quarantineCmd(args []string) error {
	fs := flag.NewFlagSet("quarantine", flag.ContinueOnError)
	sock := fs.String("socket", "/run/limbo/admin.sock", "admin socket (root only)")
	note := fs.String("note", "", "verdict: a note for the record")
	reason := fs.String("reason", "manually quarantined", "restrict: why")
	level := fs.String("level", "restrict", "restrict: restrict or isolate")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: limbo quarantine [--socket S] list | show ID | restrict GUEST | verdict ID safe|dangerous [--note N] | close ID")
	}
	c := unixClient(*sock)
	switch sub := pos[0]; sub {
	case "list":
		var recs []quarantine.Record
		if err := doJSON(c, "GET", "/v1/quarantine", nil, &recs); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tGUEST\tSTATUS\tLEVEL\tOPENED\tSOURCE\tREASON")
		for _, r := range recs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Guest, r.Status, r.Level, r.Opened.Format(time.RFC3339), r.Source, r.Reason)
		}
		return tw.Flush()
	case "show":
		if len(pos) != 2 {
			return errors.New("show: record id required")
		}
		var r quarantine.Record
		if err := doJSON(c, "GET", "/v1/quarantine/"+pos[1], nil, &r); err != nil {
			return err
		}
		printRecord(r)
		return nil
	case "restrict":
		if len(pos) != 2 {
			return errors.New("restrict: guest name required")
		}
		var res map[string]any
		in := map[string]any{"guest": pos[1], "reason": *reason, "level": *level, "source": "human:" + whoAmI()}
		if err := doJSON(c, "POST", "/v1/quarantine", in, &res); err != nil {
			return err
		}
		fmt.Printf("applied=%v\n", res["applied"])
		if e, ok := res["error"].(string); ok && e != "" {
			fmt.Println("note:", e)
		}
		return nil
	case "verdict":
		if len(pos) != 3 {
			return errors.New("verdict: usage: verdict ID safe|dangerous")
		}
		v := pos[2]
		if v != "safe" && v != "dangerous" {
			return errors.New("verdict must be exactly 'safe' or 'dangerous'")
		}
		// Show the record first so the decision is made looking at the evidence.
		var r quarantine.Record
		if err := doJSON(c, "GET", "/v1/quarantine/"+pos[1], nil, &r); err != nil {
			return err
		}
		printRecord(r)
		fmt.Printf("\nMarking guest %q as %s.\n", r.Guest, strings.ToUpper(v))
		var res map[string]any
		in := map[string]any{"verdict": v, "by": whoAmI(), "note": *note}
		if err := doJSON(c, "POST", "/v1/quarantine/"+pos[1]+"/verdict", in, &res); err != nil {
			return err
		}
		fmt.Println("recorded.")
		return nil
	case "close":
		if len(pos) != 2 {
			return errors.New("close: record id required")
		}
		return doJSON(c, "POST", "/v1/quarantine/"+pos[1]+"/close", map[string]string{"by": whoAmI()}, nil)
	}
	return fmt.Errorf("unknown quarantine subcommand %q", pos[0])
}

func printRecord(r quarantine.Record) {
	fmt.Printf("%s  guest=%s  status=%s  level=%s\n", r.ID, r.Guest, r.Status, r.Level)
	fmt.Printf("opened %s by %s\nreason: %s\n", r.Opened.Format(time.RFC3339), r.Source, r.Reason)
	for k, v := range r.Evidence {
		fmt.Printf("evidence %s: %s\n", k, v)
	}
	for _, a := range r.Advisory {
		fmt.Printf("\n--- ADVISORY from %s (%s) ---\n", a.Source, a.Time.Format(time.RFC3339))
		fmt.Println("This is an automated opinion produced from guest-derived data. It is untrusted,")
		fmt.Println("informational only, and has not changed anything.")
		fmt.Println(a.Text)
		fmt.Println("--- end advisory ---")
	}
	if r.Verdict != nil {
		fmt.Printf("\nverdict: %s by %s at %s\nnote: %s\n", r.Verdict.Value, r.Verdict.By, r.Verdict.Time.Format(time.RFC3339), r.Verdict.Note)
	}
}
