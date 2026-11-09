package image

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"time"
)

// Result is what the weekly check found for one recorded image.
type Result string

const (
	// ResultOK: hashed in full, still what was proven; the record is renewed.
	ResultOK Result = "ok"
	// ResultDropped: still what was proven, but no longer eligible for the quick check (Detail says why) or it changed
	// while it was read; the record is dropped, so the next start hashes it in full.
	ResultDropped Result = "dropped"
	// ResultChanged: it no longer hashes to what was proven. The record is kept, marked refused: no start skips the hash
	// for it again, and a start hashes it against its manifest as before (which refuses it unless a manifest asks for
	// exactly what it is now).
	ResultChanged Result = "changed"
	// ResultGone: the file is not there any more; the record is dropped (a start would fail on the missing file).
	ResultGone Result = "gone"
	// ResultError: it could not be read (Detail); the record is left as it was.
	ResultError Result = "error"
)

// Outcome is one recorded image's result.
type Outcome struct {
	Path   string
	Result Result
	Detail string
	// Recorded is the SHA-256 the record proved; Found what the file hashed to (ResultChanged).
	Recorded, Found string
	// StatSame (ResultChanged) says the file's device, inode, size and times were still those recorded: it changed
	// without leaving a trace in its metadata (damage on the disk, or a write below the filesystem).
	StatSame bool
	// NewlyRefused (ResultChanged) is false when an earlier weekly check had already refused it for the same content,
	// so the event is not repeated every week.
	NewlyRefused bool
	Took         time.Duration
}

// ErrRecordsIgnored is returned by VerifyAll when the record file exists but cannot be trusted (damaged, or not
// Owner's): there is nothing it can vouch for, so nothing is checked. The next proof rewrites the file.
var ErrRecordsIgnored = errors.New("image proofs: the record file was ignored")

// VerifyAll is the weekly check: it hashes every recorded image in full (as Check would, without the page cache) and
// compares it with its record. It reports each image to report as soon as it is done, then writes the results back:
// a record is changed only if nobody replaced it meanwhile (a start that hashed the image itself wins). It must run as
// Owner to write anything; the caller emits events for ResultChanged.
func (p *Proofs) VerifyAll(report func(Outcome)) ([]Outcome, error) {
	if p == nil || p.Path == "" {
		return nil, errors.New("image proofs: no record file")
	}
	recs, state, why := p.loadWhy()
	if state == FileIgnored {
		return nil, fmt.Errorf("%w: %v", ErrRecordsIgnored, why)
	}
	paths := make([]string, 0, len(recs))
	for path := range recs {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var outs []Outcome
	apply := map[string]func(map[string]Record){}
	for _, path := range paths {
		rec := recs[path]
		start := time.Now()
		o := Outcome{Path: path, Recorded: rec.SHA256}
		sum, before, stable, err := hashFile(path)
		o.Took = time.Since(start)
		switch {
		case errors.Is(err, os.ErrNotExist):
			o.Result, o.Detail = ResultGone, "the file is not there any more"
			apply[path] = drop(rec)
		case err != nil:
			o.Result, o.Detail = ResultError, err.Error()
		case !stable:
			// Someone (root: nobody else can write an eligible image) wrote it during the hash, so the sum is of
			// neither version. No verdict; the change moved its change time, so the next start hashes it in full.
			o.Result, o.Detail = ResultDropped, "it changed while it was read"
			apply[path] = drop(rec)
		case sum == rec.SHA256:
			if sig, eerr := p.eligible(path); eerr != nil {
				o.Result, o.Detail = ResultDropped, "not eligible for the quick check: "+eerr.Error()
				apply[path] = drop(rec)
			} else if sig != before {
				o.Result, o.Detail = ResultDropped, "the path names another file than the one read"
				apply[path] = drop(rec)
			} else {
				o.Result = ResultOK
				renewed := Record{Path: path, Sig: before, SHA256: sum, HashedAt: p.clock().UTC()}
				apply[path] = replace(rec, renewed)
			}
		default:
			o.Result, o.Found = ResultChanged, sum
			o.StatSame = before == rec.Sig
			o.NewlyRefused = !rec.Refused() || rec.Found != sum
			o.Detail = fmt.Sprintf("it hashes to %s, not to the %s it was proven to have", sum, rec.SHA256)
			refused := rec
			if o.NewlyRefused {
				t := p.clock().UTC()
				refused.RefusedAt, refused.Found = &t, sum
			}
			apply[path] = replace(rec, refused)
		}
		outs = append(outs, o)
		if report != nil {
			report(o)
		}
	}
	if len(apply) == 0 {
		return outs, nil
	}
	err := p.update(func(cur map[string]Record) {
		for _, f := range apply {
			f(cur)
		}
	})
	return outs, err
}

// drop removes the record if it is still the one that was checked.
func drop(was Record) func(map[string]Record) {
	return func(cur map[string]Record) {
		if r, ok := cur[was.Path]; ok && sameRecord(r, was) {
			delete(cur, was.Path)
		}
	}
}

// replace swaps the record for now if it is still the one that was checked.
func replace(was, now Record) func(map[string]Record) {
	return func(cur map[string]Record) {
		if r, ok := cur[was.Path]; ok && sameRecord(r, was) {
			cur[was.Path] = now
		}
	}
}

func sameRecord(a, b Record) bool {
	if (a.RefusedAt == nil) != (b.RefusedAt == nil) || (a.RefusedAt != nil && !a.RefusedAt.Equal(*b.RefusedAt)) {
		return false
	}
	return a.Path == b.Path && a.Sig == b.Sig && a.SHA256 == b.SHA256 && a.HashedAt.Equal(b.HashedAt) && a.Found == b.Found
}
