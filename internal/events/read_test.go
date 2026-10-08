package events

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSkipsAndCountsDamagedLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	body := `{"time":"2026-10-04T12:00:00Z","kind":"guest.start","guest":"lab"}` + "\n" +
		"not json\n" +
		`{"time":"2026-10-04T12:00:01Z","guest":"lab"}` + "\n" + // no kind
		"\n" +
		`{"time":"2026-10-04T12:00:02Z","kind":"guest.stop","guest":"lab"}` + "\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	evs, skipped, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || skipped != 2 {
		t.Fatalf("events=%d skipped=%d", len(evs), skipped)
	}
	if evs[0].Kind != GuestStart || evs[1].Kind != GuestStop {
		t.Fatalf("%+v", evs)
	}
}

func TestReadMissingFileIsNotExist(t *testing.T) {
	_, _, err := Read(filepath.Join(t.TempDir(), "nope"))
	if !os.IsNotExist(err) {
		t.Fatalf("%v", err)
	}
}
