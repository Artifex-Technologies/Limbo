// Package report turns Limbo's audit log and quarantine records into a document
// a person can read, file or attach to an assessment: what ran, what it was
// allowed to do, what was held and why, and who decided.
//
// Everything in the log that originated inside a guest, or in a model reading
// guest data, is untrusted, and a report is exactly where such text gets
// rendered for a human. So all of it goes through the escaping here: control
// characters removed, table and markdown syntax neutralised, and advisories shown
// inside a code fence long enough that their content cannot close it.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
)

// Input is everything a report is built from.
type Input struct {
	Events  []events.Event
	Skipped int // unparseable log lines, reported so a damaged log is not silent
	Records []quarantine.Record
	Guest   string    // if set, only this guest
	Since   time.Time // if non-zero, only events and records on or after this
	Now     time.Time
}

// Render produces the report as Markdown.
func Render(in Input) string {
	evs := filterEvents(in)
	recs := filterRecords(in)

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("# Limbo activity report")
	w("")
	w("Generated %s.", in.Now.UTC().Format(time.RFC3339))
	scope := "all guests"
	if in.Guest != "" {
		scope = "guest `" + md(in.Guest) + "`"
	}
	period := "the whole log"
	if !in.Since.IsZero() {
		period = "since " + in.Since.UTC().Format(time.RFC3339)
	}
	w("Scope: %s, %s.", scope, period)
	if in.Skipped > 0 {
		w("")
		w("> **%d line(s) in the event log could not be read and are not reflected here.** The log may be damaged or written by something else.", in.Skipped)
	}

	c := count(evs, recs)
	w("")
	w("## Summary")
	w("")
	w("| | |")
	w("| --- | --- |")
	w("| Guests started | %d |", c.starts)
	w("| Validation runs | %d (%d completed, %d failed, %d timed out) |", c.runs, c.runDone, c.runFailed, c.runTimeout)
	w("| Quarantines | %d (%d open, %d safe, %d dangerous, %d closed) |", len(recs), c.open, c.safe, c.dangerous, c.closed)
	w("| Starts blocked (license gate or quarantine) | %d |", c.gate)
	w("| Image checksum rejections | %d |", c.imageRejected)
	if c.open > 0 {
		w("")
		w("> **%d quarantine(s) are still open and awaiting a human verdict.**", c.open)
	}

	w("")
	w("## Quarantines")
	if len(recs) == 0 {
		w("")
		w("None in this period.")
	}
	for _, r := range recs {
		w("")
		w("### %s — guest `%s` — %s", md(r.ID), md(r.Guest), strings.ToUpper(string(r.Status)))
		w("")
		w("- Opened: %s by `%s`", r.Opened.UTC().Format(time.RFC3339), md(r.Source))
		w("- Hold level: %s", md(string(r.Level)))
		w("- Reason: %s", md(r.Reason))
		for _, k := range sortedKeys(r.Evidence) {
			w("- Evidence `%s`: %s", md(k), md(r.Evidence[k]))
		}
		if r.Verdict != nil {
			w("- **Verdict: %s** by %s at %s. Note: %s", md(string(r.Verdict.Value)), md(r.Verdict.By), r.Verdict.Time.UTC().Format(time.RFC3339), md(r.Verdict.Note))
		} else {
			w("- **No verdict yet.** A human must decide.")
		}
		for _, a := range r.Advisory {
			w("")
			w("Advisory from `%s` at %s. **Untrusted**: produced from guest-derived data by an automated reader, shown for information only. It did not change this record.", md(a.Source), a.Time.UTC().Format(time.RFC3339))
			w("")
			w("%s", fence(a.Text))
		}
	}

	w("")
	w("## Validation runs")
	runs := runRows(evs)
	if len(runs) == 0 {
		w("")
		w("None in this period.")
	} else {
		w("")
		w("| Run | Started | Result | Command (first 80 bytes) |")
		w("| --- | --- | --- | --- |")
		for _, r := range runs {
			w("| %s | %s | %s | `%s` |", md(r.id), r.started, md(r.result), md(clip(r.command, 80)))
		}
	}

	w("")
	w("## Integrity and policy events")
	notable := 0
	for _, e := range evs {
		switch e.Kind {
		case events.ImageRejected, events.GateBlocked, events.PolicyRestrict, events.PolicyRelease, events.LinkDown, events.LinkUp:
			if notable == 0 {
				w("")
				w("| Time | Guest | Event | Detail |")
				w("| --- | --- | --- | --- |")
			}
			notable++
			w("| %s | %s | %s | %s |", e.Time.UTC().Format(time.RFC3339), md(e.Guest), md(e.Kind), md(detail(e.Detail)))
		}
	}
	if notable == 0 {
		w("")
		w("None in this period.")
	}

	w("")
	w("## Timeline")
	if len(evs) == 0 {
		w("")
		w("No events in this period.")
	} else {
		w("")
		w("| Time | Guest | Event | Detail |")
		w("| --- | --- | --- | --- |")
		for _, e := range evs {
			w("| %s | %s | %s | %s |", e.Time.UTC().Format(time.RFC3339), md(e.Guest), md(e.Kind), md(clip(detail(e.Detail), 160)))
		}
	}
	return b.String()
}

type tally struct {
	starts, runs, runDone, runFailed, runTimeout, gate, imageRejected int
	open, safe, dangerous, closed                                     int
}

func count(evs []events.Event, recs []quarantine.Record) (t tally) {
	for _, e := range evs {
		switch e.Kind {
		case events.GuestStart:
			t.starts++
		case events.RunStart:
			t.runs++
		case events.RunEnd:
			switch e.Detail["status"] {
			case "done":
				t.runDone++
			case "timeout":
				t.runTimeout++
			default:
				t.runFailed++
			}
		case events.GateBlocked:
			t.gate++
		case events.ImageRejected:
			t.imageRejected++
		}
	}
	for _, r := range recs {
		switch r.Status {
		case quarantine.StatusOpen:
			t.open++
		case quarantine.StatusSafe:
			t.safe++
		case quarantine.StatusDangerous:
			t.dangerous++
		case quarantine.StatusClosed:
			t.closed++
		}
	}
	return t
}

type runRow struct{ id, started, result, command string }

func runRows(evs []events.Event) []runRow {
	idx := map[string]int{}
	var rows []runRow
	for _, e := range evs {
		switch e.Kind {
		case events.RunStart:
			idx[e.Guest] = len(rows)
			rows = append(rows, runRow{id: e.Guest, started: e.Time.UTC().Format(time.RFC3339), result: "unfinished", command: e.Detail["command"]})
		case events.RunEnd:
			if i, ok := idx[e.Guest]; ok {
				rows[i].result = e.Detail["status"]
				if code, ok := e.Detail["exit_code"]; ok {
					rows[i].result += " (exit " + code + ")"
				}
			}
		}
	}
	return rows
}

func filterEvents(in Input) []events.Event {
	var out []events.Event
	for _, e := range in.Events {
		if in.Guest != "" && e.Guest != in.Guest {
			continue
		}
		if !in.Since.IsZero() && e.Time.Before(in.Since) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

func filterRecords(in Input) []quarantine.Record {
	var out []quarantine.Record
	for _, r := range in.Records {
		if in.Guest != "" && r.Guest != in.Guest {
			continue
		}
		if !in.Since.IsZero() && r.Opened.Before(in.Since) {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Opened.Before(out[j].Opened) })
	return out
}

func detail(m map[string]string) string {
	keys := sortedKeys(m)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, " ")
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// md makes untrusted text safe to put in a Markdown line or table cell: control
// characters and newlines become spaces, and the characters that can change
// structure are escaped. Newlines are gone, so nothing can start a heading or a
// list; escaping "]" and "!" means no link or image can form; escaping "<" and
// ">" blocks HTML; escaping "|" keeps text inside its table cell. Ordinary
// punctuation is left alone so the report stays readable.
func md(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r), r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			// dropped: invisible or terminal-affecting
		case strings.ContainsRune("\\`*_[]<>#!|~", r):
			b.WriteRune('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// fence puts text in a code block whose fence is longer than any run of
// backticks inside it, so the text cannot close the block and write Markdown of
// its own. Control characters are dropped; newlines are kept for readability.
func fence(s string) string {
	var clean strings.Builder
	longest, run := 0, 0
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' || r >= 0x200b && r <= 0x200f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
			continue
		}
		clean.WriteRune(r)
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	f := strings.Repeat("`", max(3, longest+1))
	return f + "text\n" + strings.TrimRight(clean.String(), "\n") + "\n" + f
}
