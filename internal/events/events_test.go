package events

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEmitAppendsAcrossOpens(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state", "events.jsonl")
	fixed := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	for _, kind := range []string{GuestDefine, GuestStart} {
		l, err := Open(p)
		if err != nil {
			t.Fatal(err)
		}
		l.now = func() time.Time { return fixed }
		if err := l.Emit(kind, "lab", map[string]string{"k": "v"}); err != nil {
			t.Fatal(err)
		}
		l.Close()
	}

	f, _ := os.Open(p)
	defer f.Close()
	var got []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line is not JSON: %v", err)
		}
		got = append(got, e)
	}
	if len(got) != 2 || got[0].Kind != GuestDefine || got[1].Kind != GuestStart || !got[0].Time.Equal(fixed) {
		t.Fatalf("unexpected log: %+v", got)
	}
}
