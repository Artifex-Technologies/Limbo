package quarantine

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/parity"
)

var parityTexts = []string{
	"", "plain", "a\nb\tc", "\x1b[31mred\x1b[0m", "nul\x00here", "del\x7f", "c1\u0085\u009b", "é€😀", "zero​width",
	"bidi‮evil", strings.Repeat("x", 600), strings.Repeat("é", 300), strings.Repeat("😀", 200), "\xff\xfe bad", "a\r\nb",
}

// TestParityQuarantine: clean() and a store's answers to generated request sequences (ids and times normalised).
func TestParityQuarantine(t *testing.T) {
	var cases []parity.Case
	for _, s := range parityTexts {
		for _, n := range []int{0, 1, 3, 64, 512, 8 << 10} {
			cases = append(cases, parity.Case{Fn: "clean", In: map[string]any{"s": s, "max": n}, Out: clean(s, n)})
		}
	}
	r := rand.New(rand.NewSource(1010))
	levels := []string{"restrict", "isolate", "", "lower", "ISOLATE"}
	verdicts := []string{"safe", "dangerous", "open", "closed", ""}
	for seq := 0; seq < 25; seq++ {
		dir := t.TempDir()
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		clock := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
		s.now = func() time.Time { clock = clock.Add(1500 * time.Millisecond); return clock }
		var steps []map[string]any
		var ids []string
		pick := func() string {
			if len(ids) == 0 || r.Intn(8) == 0 {
				return "q-000000000000"
			}
			return ids[r.Intn(len(ids))]
		}
		for i := 0; i < 40; i++ {
			guest := []string{"lab", "web", "r1234abcd"}[r.Intn(3)]
			var rec Record
			var created bool
			var err error
			op := map[string]any{}
			switch r.Intn(6) {
			case 0, 1:
				ev := map[string]string{}
				for j := 0; j < r.Intn(4); j++ {
					ev[parityTexts[r.Intn(len(parityTexts))]] = parityTexts[r.Intn(len(parityTexts))]
				}
				if r.Intn(5) == 0 {
					ev = nil
				}
				reason, source, level := parityTexts[r.Intn(len(parityTexts))], []string{"heimdall:limbo-guest", "", "human"}[r.Intn(3)], levels[r.Intn(len(levels))]
				op = map[string]any{"op": "quarantine", "guest": guest, "reason": reason, "source": source, "level": level, "evidence": ev}
				rec, created, err = s.Quarantine(guest, reason, source, Level(level), ev)
				if err == nil && created {
					ids = append(ids, rec.ID)
				}
			case 2:
				id, level := pick(), levels[r.Intn(len(levels))]
				op = map[string]any{"op": "raise", "id": id, "level": level}
				rec, err = s.Raise(id, Level(level))
			case 3:
				id, src, text := pick(), parityTexts[r.Intn(len(parityTexts))], parityTexts[r.Intn(len(parityTexts))]
				op = map[string]any{"op": "advisory", "id": id, "source": src, "text": text}
				before := r.Intn(20)
				for k := 0; k < before; k++ {
					_, _ = s.AddAdvisory(id, src, text)
				}
				rec, err = s.AddAdvisory(id, src, text)
				op["before"] = before
			case 4:
				id, v := pick(), verdicts[r.Intn(len(verdicts))]
				op = map[string]any{"op": "decide", "id": id, "verdict": v, "by": "root (peer uid=0 pid=1)", "note": parityTexts[r.Intn(len(parityTexts))]}
				rec, err = s.Decide(id, Status(v), "root (peer uid=0 pid=1)", op["note"].(string))
			case 5:
				id := pick()
				op = map[string]any{"op": "close", "id": id, "by": "root"}
				rec, err = s.Close(id, "root")
			}
			b, _ := json.Marshal(rec)
			_, held := s.Holding(guest)
			steps = append(steps, map[string]any{"step": op, "record": string(b), "created": created, "error": parity.Err(err), "holding": held})
		}
		list, _ := json.Marshal(s.List())
		var files []string
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			files = append(files, e.Name()+"\n"+string(b))
		}
		// ids are random: each becomes q-<its creation number> (the same length), and the files are sorted after
		norm := func(x string) string {
			for i, id := range ids {
				x = strings.ReplaceAll(x, id, fmt.Sprintf("q-%012d", i+1))
			}
			return x
		}
		for _, st := range steps {
			st["record"] = norm(st["record"].(string))
			op := st["step"].(map[string]any)
			if id, ok := op["id"].(string); ok {
				op["id"] = norm(id)
			}
		}
		for i := range files {
			files[i] = norm(files[i])
		}
		sort.Strings(files)
		cases = append(cases, parity.Case{Fn: "Store", In: seq, Out: map[string]any{"steps": steps, "list": norm(string(list)), "files": files}})
	}
	parity.Fixture(t, "quarantine", cases)
}
