package main

import (
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
	"path/filepath"
	"strings"
	"time"
)

// DefaultAnalysis is what a sample run does when no command is given: the triage of the image's limbo-decompile wrapper (file type,
// hashes, imports, sections, strings, YARA when installed), then its function list. Both only read the sample.
const DefaultAnalysis = "limbo-decompile triage sample; echo; echo '== functions'; limbo-decompile functions sample"

// analyzeCmd: limbo analyze [--profile P] [--timeout S] [--json] FILE [COMMAND]: one file analysed in a sealed guest (no network, no
// sudo, no shared folder), as root, through the admin socket. The file is copied into Limbo's inbox, sent into a fresh guest on its
// ssh input, left there read-only and never run; the guest is destroyed afterwards. Prints what the analysis printed.
func analyzeCmd(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	profile := fs.String("profile", "malware-analysis", "a sealed profile with allow_sample")
	timeout := fs.Int("timeout", 900, "seconds the analysis may take (the profile's limit applies)")
	inbox := fs.String("inbox", "/var/lib/limbo/inbox", "Limbo's inbox (as for limbo serve)")
	sock := fs.String("socket", "/run/limbo/admin.sock", "admin socket (root only)")
	asJSON := fs.Bool("json", false, "print the whole result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return errors.New("usage: limbo analyze [--profile P] [--timeout S] [--json] FILE [COMMAND]")
	}
	command := DefaultAnalysis
	if fs.NArg() == 2 {
		command = fs.Arg(1)
	}
	src, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer src.Close()
	h := sha256.New()
	tmp, err := os.CreateTemp(*inbox, ".incoming-")
	if err != nil {
		return fmt.Errorf("the inbox %s: %w (is limbo serve running, and are you root?)", *inbox, err)
	}
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, 64<<20+1)); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()
	name := hex.EncodeToString(h.Sum(nil)) + ".sample"
	final := filepath.Join(*inbox, name)
	if err := os.Rename(tmp.Name(), final); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	defer os.Remove(final)

	c := unixClient(*sock)
	body, _ := json.Marshal(map[string]any{"profile": *profile, "command": command, "sample": name, "timeout_seconds": *timeout})
	resp, err := c.Post("http://limbo/v1/sample-runs", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	var started map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&started)
	resp.Body.Close()
	id, _ := started["id"].(string)
	if resp.StatusCode != http.StatusAccepted || id == "" {
		return fmt.Errorf("refused: %v", started["error"])
	}
	fmt.Fprintf(os.Stderr, "limbo analyze: run %s (%s, sha256 %s); booting a sealed guest...\n", id, *profile, strings.TrimSuffix(name, ".sample"))
	deadline := time.Now().Add(time.Duration(*timeout+400) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		r, err := c.Get("http://limbo/v1/runs/" + id)
		if err != nil {
			return err
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		var res map[string]any
		_ = json.Unmarshal(raw, &res)
		if res["status"] == "running" {
			continue
		}
		if *asJSON {
			fmt.Println(string(raw))
		} else {
			fmt.Print(res["stdout"])
			if e, _ := res["stderr"].(string); e != "" {
				fmt.Fprint(os.Stderr, e)
			}
			if e, _ := res["error"].(string); e != "" {
				return errors.New(e)
			}
		}
		return nil
	}
	return errors.New("the run did not finish in time")
}
