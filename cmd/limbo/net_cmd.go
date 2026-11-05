package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/flows"
	"github.com/Artifex-Technologies/Limbo/internal/policy"
)

// netCmd: limbo net watch [--seconds N] prints guests' flows and refusals as they happen, as JSON lines in the form
// the audit log uses (root; only while limbo serve is not reading them itself: one reader per kernel log group).
func netCmd(args []string) error {
	fs := flag.NewFlagSet("net", flag.ContinueOnError)
	secs := fs.Int("seconds", 0, "stop after this many seconds (0: until interrupted)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || pos[0] != "watch" {
		return errors.New("usage: limbo net watch [--seconds N]   (root; limbo serve normally reads these into its log)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *secs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(*secs)*time.Second)
		defer cancel()
	}
	enc := json.NewEncoder(os.Stdout)
	agg := &flows.Aggregator{Events: emitFunc(func(kind, guest string, d map[string]string) error {
		return enc.Encode(map[string]any{"time": time.Now().UTC(), "kind": kind, "guest": guest, "detail": d})
	})}
	if err := flows.Listen(ctx, policy.NFLogGroup, agg.Handle); err != nil {
		return fmt.Errorf("%w (limbo serve may be reading them already: see its log, events.jsonl)", err)
	}
	return nil
}

type emitFunc func(kind, guest string, d map[string]string) error

func (f emitFunc) Emit(kind, guest string, d map[string]string) error { return f(kind, guest, d) }
