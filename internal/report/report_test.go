package report

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/quarantine"
)

var t0 = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func ev(min int, kind, guest string, d map[string]string) events.Event {
	return events.Event{Time: t0.Add(time.Duration(min) * time.Minute), Kind: kind, Guest: guest, Detail: d}
}

func sample() Input {
	return Input{
		Now: t0.Add(time.Hour),
		Events: []events.Event{
			ev(0, events.GuestStart, "lab", nil),
			ev(1, events.RunStart, "r1", map[string]string{"command": "pacman -Syu"}),
			ev(2, events.RunEnd, "r1", map[string]string{"status": "done", "exit_code": "0"}),
			ev(3, events.RunStart, "r2", map[string]string{"command": "sleep 999"}),
			ev(4, events.RunEnd, "r2", map[string]string{"status": "timeout"}),
			ev(5, events.RunStart, "r3", map[string]string{"command": "never finished"}),
			ev(6, events.ImageRejected, "bad", map[string]string{"reason": "checksum mismatch"}),
			ev(7, events.PolicyRestrict, "lab", map[string]string{"table": "limbo_lab"}),
		},
		Records: []quarantine.Record{
			{ID: "q-1", Guest: "lab", Status: quarantine.StatusOpen, Level: quarantine.LevelRestrict, Source: "heimdall:limbo-guest", Reason: "started with no firewall policy", Opened: t0.Add(7 * time.Minute)},
			{ID: "q-2", Guest: "old", Status: quarantine.StatusSafe, Level: quarantine.LevelRestrict, Source: "human", Reason: "x", Opened: t0.Add(-48 * time.Hour),
				Verdict: &quarantine.Verdict{Value: quarantine.StatusSafe, By: "greg", Note: "false alarm", Time: t0.Add(-47 * time.Hour)}},
		},
	}
}

func TestSummaryCountsAndOpenBanner(t *testing.T) {
	out := Render(sample())
	for _, want := range []string{
		"| Guests started | 1 |",
		"| Validation runs | 3 (1 completed, 0 failed, 1 timed out) |",
		"| Quarantines | 2 (1 open, 1 safe, 0 dangerous, 0 closed) |",
		"| Image checksum rejections | 1 |",
		"1 quarantine(s) are still open and awaiting a human verdict",
		"**No verdict yet.** A human must decide.",
		"**Verdict: safe**",
		"unfinished",
		"done (exit 0)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestFilters(t *testing.T) {
	in := sample()
	in.Guest = "lab"
	out := Render(in)
	if strings.Contains(out, "q-2") || strings.Contains(out, "checksum mismatch") {
		t.Errorf("guest filter leaked other guests:\n%s", out)
	}
	in = sample()
	in.Since = t0.Add(-time.Hour)
	if out := Render(in); strings.Contains(out, "q-2") {
		t.Errorf("since filter kept an old record")
	}
}

func TestDamagedLogIsFlagged(t *testing.T) {
	in := sample()
	in.Skipped = 3
	if !strings.Contains(Render(in), "3 line(s) in the event log could not be read") {
		t.Error("a damaged log must not be silent")
	}
}

// A report is where guest-originated text meets a human's eyes, so hostile text
// must not be able to change the document's structure.
func TestHostileTextCannotChangeTheDocument(t *testing.T) {
	hostile := "x |\n# INJECTED HEADING\n[click](http://evil.example)\n<script>alert(1)</script>\n![i](http://evil/p.png)\x1b[2J\u202e`code`"
	in := sample()
	in.Events = append(in.Events, ev(8, events.GateBlocked, "lab", map[string]string{"reason": hostile}))
	in.Records[0].Reason = hostile
	in.Records[0].Evidence = map[string]string{"k": hostile}
	out := Render(in)

	for _, bad := range []string{"\n# INJECTED", "<script>", "\x1b", "\u202e", "\n[click"} {
		if strings.Contains(out, bad) {
			t.Errorf("hostile text survived as %q", bad)
		}
	}
	// A link or image needs an UNESCAPED "](" or "![". The escaped forms render as
	// literal text, which is the point.
	if regexp.MustCompile(`(^|[^\\])\]\(`).MatchString(out) || regexp.MustCompile(`(^|[^\\])!\[`).MatchString(out) {
		t.Error("an unescaped link or image opener survived")
	}
	// Every timeline row must be exactly one line: the newline in the text did not
	// start a new row or a new block.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| 2026-10-04T12:08") && strings.Count(line, "\n") != 0 {
			t.Errorf("row broke across lines: %q", line)
		}
	}
	if strings.Count(out, "INJECTED HEADING") == 0 {
		t.Error("the text should still be visible, just inert")
	}
}

func TestAdvisoryCannotCloseItsFence(t *testing.T) {
	in := sample()
	in.Records[0].Advisory = []quarantine.Advisory{{
		Source: "sarina", Time: t0,
		Text: "SUSPICIOUS\n```\n# PWNED\n```\n````\n## ALSO PWNED\n````\x1b[2J",
	}}
	out := Render(in)
	lines := strings.Split(out, "\n")
	open, close := -1, -1
	for i, l := range lines {
		if strings.HasSuffix(l, "text") && strings.HasPrefix(l, "```") {
			open = i
		}
	}
	if open < 0 {
		t.Fatalf("no fence opened:\n%s", out)
	}
	fenceStr := strings.TrimSuffix(lines[open], "text")
	for i := open + 1; i < len(lines); i++ {
		if lines[i] == fenceStr {
			close = i
			break
		}
	}
	if close < 0 {
		t.Fatal("fence never closed")
	}
	if len(fenceStr) < 5 {
		t.Errorf("fence %q is not longer than the longest backtick run inside", fenceStr)
	}
	inside := strings.Join(lines[open+1:close], "\n")
	if !strings.Contains(inside, "# PWNED") || !strings.Contains(inside, "## ALSO PWNED") {
		t.Errorf("hostile advisory text escaped its fence; inside=%q", inside)
	}
	if strings.Contains(out, "\x1b") {
		t.Error("control characters survived")
	}
	if !strings.Contains(out, "**Untrusted**") {
		t.Error("advisory not labelled untrusted")
	}
}

func TestEmptyInput(t *testing.T) {
	out := Render(Input{Now: t0})
	for _, want := range []string{"# Limbo activity report", "None in this period.", "No events in this period."} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}
