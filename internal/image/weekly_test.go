package image

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func verifyAll(t *testing.T, w *world) []Outcome {
	t.Helper()
	outs, err := w.p.VerifyAll(nil)
	if err != nil {
		t.Fatal(err)
	}
	return outs
}

func one(t *testing.T, outs []Outcome) Outcome {
	t.Helper()
	if len(outs) != 1 {
		t.Fatalf("outcomes %+v", outs)
	}
	return outs[0]
}

func TestWeeklyRenewsAnUnchangedImage(t *testing.T) {
	w := newWorld(t)
	w.check(ByHash)
	first := w.records()[w.img].HashedAt
	w.p.now = func() time.Time { return first.Add(7 * 24 * time.Hour) }
	before := w.hashes
	if o := one(t, verifyAll(t, w)); o.Result != ResultOK || w.hashes != before+1 {
		t.Fatalf("%+v (hashes %d)", o, w.hashes-before)
	}
	if r := w.records()[w.img]; !r.HashedAt.After(first) || r.Refused() {
		t.Fatalf("record not renewed: %+v", r)
	}
	w.check(ByRecord)
}

// The case the weekly check exists for: the file's content changed while everything the quick check looks at stayed the
// same (damage on the disk, or a write below the filesystem). Staged by changing the content and then making the
// record vouch for the new metadata with the old digest.
func TestWeeklyCatchesASilentlyChangedImage(t *testing.T) {
	w := newWorld(t)
	w.check(ByHash)
	proven := w.sum
	w.write("a base image, quietly damaged")
	r := w.records()[w.img]
	r.Sig = sigFor(t, w.img)
	w.setRecord(r)
	if how, err := w.p.Check(w.img, proven); how != ByRecord || err != nil {
		t.Fatalf("staging: the record should vouch for it now: %q %v", how, err)
	}

	var reported []Outcome
	outs, err := w.p.VerifyAll(func(o Outcome) { reported = append(reported, o) })
	if err != nil {
		t.Fatal(err)
	}
	o := one(t, outs)
	if o.Result != ResultChanged || !o.StatSame || !o.NewlyRefused || o.Found != w.sum || o.Recorded != proven || len(reported) != 1 {
		t.Fatalf("%+v", o)
	}
	if r := w.records()[w.img]; !r.Refused() || r.Found != w.sum || r.SHA256 != proven {
		t.Fatalf("not refused: %+v", r)
	}
	// Refused: a start hashes it in full against its manifest, which no longer matches.
	before := w.hashes
	if how, err := w.p.Check(w.img, proven); how != ByHash || !errors.Is(err, ErrMismatch) || w.hashes != before+1 {
		t.Fatalf("a refused image: %q %v", how, err)
	}
	// Reported once: the next week finds the same thing and does not report it as new.
	if o := one(t, verifyAll(t, w)); o.Result != ResultChanged || o.NewlyRefused {
		t.Fatalf("second week: %+v", o)
	}
}

// An image rewritten with other content (its metadata changed too) is caught as well.
func TestWeeklyCatchesARewrittenImage(t *testing.T) {
	w := newWorld(t)
	w.check(ByHash)
	proven := w.sum
	time.Sleep(10 * time.Millisecond)
	w.write("another image")
	o := one(t, verifyAll(t, w))
	if o.Result != ResultChanged || o.StatSame || o.Recorded != proven || o.Found != w.sum {
		t.Fatalf("%+v", o)
	}
	// A manifest updated for the new content proves it afresh and replaces the refused record.
	w.check(ByHash)
	if r := w.records()[w.img]; r.Refused() || r.SHA256 != w.sum {
		t.Fatalf("record after a fresh proof: %+v", r)
	}
	w.check(ByRecord)
}

func TestWeeklyDropsGoneAndIneligibleImages(t *testing.T) {
	w := newWorld(t)
	w.check(ByHash)
	other := filepath.Join(filepath.Dir(w.img), "other.qcow2")
	if err := os.WriteFile(other, []byte("a base image"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(other, 0o644); err != nil {
		t.Fatal(err)
	}
	if how, err := w.p.Check(other, w.sum); how != ByHash || err != nil {
		t.Fatal(how, err)
	}
	if err := os.Remove(w.img); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(other, 0o666); err != nil {
		t.Fatal(err)
	}
	outs := verifyAll(t, w)
	got := map[string]Result{}
	for _, o := range outs {
		got[o.Path] = o.Result
	}
	if got[w.img] != ResultGone || got[other] != ResultDropped {
		t.Fatalf("%+v", outs)
	}
	if recs := w.records(); len(recs) != 0 {
		t.Fatalf("records left: %+v", recs)
	}
}

// A start that proves the image itself while the weekly check is reading it wins: the check does not overwrite a
// record it did not read.
func TestWeeklyLeavesANewerRecordAlone(t *testing.T) {
	w := newWorld(t)
	w.check(ByHash)
	r := w.records()[w.img]
	r.Sig = sigFor(t, w.img)
	r.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000" // will look changed
	w.setRecord(r)
	newer := Record{Path: w.img, Sig: sigFor(t, w.img), SHA256: w.sum, HashedAt: time.Now().UTC().Add(time.Second)}
	if _, err := w.p.VerifyAll(func(Outcome) { w.setRecord(newer) }); err != nil {
		t.Fatal(err)
	}
	if got := w.records()[w.img]; got.Refused() || got.SHA256 != w.sum {
		t.Fatalf("the newer record was overwritten: %+v", got)
	}
}

func TestWeeklyRefusesAnUntrustedRecordFile(t *testing.T) {
	w := newWorld(t)
	if outs, err := w.p.VerifyAll(nil); err != nil || len(outs) != 0 { // no file yet: nothing to do
		t.Fatalf("%v %v", outs, err)
	}
	if err := os.WriteFile(w.p.Path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.p.VerifyAll(nil); !errors.Is(err, ErrRecordsIgnored) {
		t.Fatalf("damaged record file: %v", err)
	}
}
