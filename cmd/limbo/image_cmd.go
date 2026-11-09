package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/image"
)

// imageCmd: limbo image list | verify. The record of base images proven by a full hash (package image) lives in the
// state folder; `verify` is the weekly re-check (limbo-image-verify.timer runs it in the background).
func imageCmd(args []string) error {
	fs := flag.NewFlagSet("image", flag.ContinueOnError)
	state := fs.String("state-dir", defaultStateDir(), "Limbo's state folder: the record of proven images and the event log")
	iKnow := fs.Bool("i-know", false, "as root, allow a state folder other than the daemon's")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	const usage = "usage: limbo image list | verify   (list: the base images proven by a full hash, and whether a start skips the hash now; " +
		"verify: hash each of them in full again and refuse any that changed; root)"
	if len(pos) != 1 {
		return errors.New(usage)
	}
	if err := checkRootStateDir(*state, *iKnow); err != nil {
		return err
	}
	p := &image.Proofs{Path: filepath.Join(*state, image.ProofsFile)}
	switch pos[0] {
	case "list":
		return imageList(p, os.Stdout)
	case "verify":
		if geteuid() != 0 {
			return errors.New("image verify: must run as root (the record of proven images is root's)")
		}
		log, err := events.Open(filepath.Join(*state, "events.jsonl"))
		if err != nil {
			return err
		}
		defer log.Close()
		return imageVerify(p, log, os.Stdout)
	}
	return errors.New(usage)
}

func imageList(p *image.Proofs, out io.Writer) error {
	recs, st, why := p.List()
	switch st {
	case image.FileMissing:
		fmt.Fprintln(out, "No base image has been proven yet: the first start of each hashes it in full and records it.")
		return nil
	case image.FileIgnored:
		return fmt.Errorf("the record of proven images is not used (%v); every start hashes in full until the next proof rewrites it (as root)", why)
	}
	if len(recs) == 0 {
		fmt.Fprintln(out, "No base image is recorded.")
	}
	for _, r := range recs {
		fmt.Fprintf(out, "%s\n  sha256 %s, %s, hashed in full %s\n", r.Path, r.SHA256, size(r.Size), r.HashedAt.Local().Format("2006-01-02 15:04"))
		if r.Quick {
			fmt.Fprintln(out, "  a start skips the hash (nothing about the file has changed)")
		} else {
			fmt.Fprintf(out, "  a start hashes it in full: %s\n", r.Why)
		}
	}
	return nil
}

// imageVerify is the weekly check: every recorded image hashed in full again. An image that changed is refused (its
// record stops vouching for it) and reported as image.rejected, which Heimdall reads; the command then fails, so the
// unit shows as failed.
func imageVerify(p *image.Proofs, log engineEmitter, out io.Writer) error {
	var changed, failed int
	var logErr error
	outs, err := p.VerifyAll(func(o image.Outcome) {
		switch o.Result {
		case image.ResultOK:
			fmt.Fprintf(out, "ok       %s (hashed in %s)\n", o.Path, o.Took.Round(100*time.Millisecond))
		case image.ResultDropped:
			fmt.Fprintf(out, "dropped  %s: %s; the next start hashes it in full\n", o.Path, o.Detail)
		case image.ResultGone:
			fmt.Fprintf(out, "gone     %s: %s; its record is dropped\n", o.Path, o.Detail)
		case image.ResultError:
			failed++
			fmt.Fprintf(out, "ERROR    %s: %s\n", o.Path, o.Detail)
		case image.ResultChanged:
			changed++
			trace := "changed"
			fmt.Fprintf(out, "CHANGED  %s: %s. Refused: every start hashes it against its manifest.\n", o.Path, o.Detail)
			if o.StatSame {
				trace = "unchanged"
				fmt.Fprintln(out, "         Its inode, size and times are what they were: the change left no trace in its metadata "+
					"(damage on the disk, or a write below the filesystem).")
			}
			if !o.NewlyRefused {
				return // reported when it was first found
			}
			if err := log.Emit(events.ImageRejected, "", map[string]string{
				"reason": fmt.Sprintf("weekly check: %s no longer hashes to the sha256 it was proven to have", o.Path),
				"during": "weekly check", "path": o.Path, "sha256": o.Recorded, "found": o.Found, "stat": trace,
			}); err != nil && logErr == nil {
				logErr = err
			}
		}
	})
	if errors.Is(err, image.ErrRecordsIgnored) {
		return fmt.Errorf("image verify: %w; nothing to re-check (the next start hashes in full and rewrites it)", err)
	}
	if err != nil {
		return fmt.Errorf("image verify: %w", err)
	}
	if len(outs) == 0 {
		fmt.Fprintln(out, "No base image has been proven yet: nothing to re-check.")
	}
	if logErr != nil {
		return fmt.Errorf("image verify: the audit log: %w", logErr)
	}
	if changed > 0 || failed > 0 {
		return fmt.Errorf("image verify: %d of %d images changed, %d could not be read", changed, len(outs), failed)
	}
	return nil
}

// engineEmitter is the audit log as image verify uses it.
type engineEmitter interface {
	Emit(kind, guest string, detail map[string]string) error
}
