package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
	"github.com/Artifex-Technologies/Limbo/internal/report"
)

// reportCmd writes a Markdown evidence report from the audit log and the
// quarantine records. It reads files directly, so it works with or without the
// daemon running, and needs whatever read access those files require (root, for
// the quarantine records).
func reportCmd(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	state := fs.String("state-dir", defaultStateDir(), "directory holding events.jsonl and quarantine/")
	guest := fs.String("guest", "", "only this guest")
	since := fs.String("since", "", "only this period: a duration like 24h or 7d, or a date like 2026-10-01")
	out := fs.String("out", "", "write to this file instead of stdout")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}

	in := report.Input{Guest: *guest, Now: time.Now().UTC()}
	if *since != "" {
		t, err := parseSince(*since, in.Now)
		if err != nil {
			return err
		}
		in.Since = t
	}
	evs, skipped, err := events.Read(filepath.Join(*state, "events.jsonl"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	in.Events, in.Skipped = evs, skipped

	// Opening the store read-only would be nicer, but it never writes on Open
	// beyond creating its directory, which a report run as root can afford.
	store, err := quarantine.Open(filepath.Join(*state, "quarantine"))
	if err != nil {
		return err
	}
	in.Records = store.List()

	doc := report.Render(in)
	if *out == "" {
		_, err := fmt.Print(doc)
		return err
	}
	return os.WriteFile(*out, []byte(doc), 0o644)
}

// parseSince accepts "36h", "7d" (days are not a time.Duration unit, so handle
// them here) or a calendar date.
func parseSince(s string, now time.Time) (time.Time, error) {
	if n := len(s); n > 1 && s[n-1] == 'd' {
		var days int
		if _, err := fmt.Sscanf(s[:n-1], "%d", &days); err == nil && days > 0 {
			return now.Add(-time.Duration(days) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, errors.New("--since must be a duration (24h, 7d) or a date (2026-10-01)")
}
