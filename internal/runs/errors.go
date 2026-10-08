package runs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unicode/utf8"

	"github.com/Artifex-Technologies/Limbo/internal/image"
)

// Stable, machine-readable failure codes. A code means "Limbo could not run
// the command" (or, for output_truncated and teardown_failed, "it ran, with a
// caveat"); a command that ran and exited non-zero is never an error, it is a
// Result with an exit code. docs/INTEGRATION-FAILURES.md is the runbook.
const (
	CodeBadRequest     = "bad_request"      // malformed request, empty/oversized command
	CodeProfileInvalid = "profile_invalid"  // name rejected, or the profile file is malformed or refused
	CodeProfileUnknown = "profile_unknown"  // no such profile
	CodeBusy           = "busy"             // concurrency limit reached
	CodeImageMissing   = "image_missing"    // the profile's base image is not on disk
	CodeImageMismatch  = "image_mismatch"   // image checksum differs from the profile's
	CodeBootFailed     = "boot_failed"      // guest could not be built or started, or never answered
	CodeBootTimeout    = "boot_timeout"     // boot budget exhausted
	CodeCommandTimeout = "command_timeout"  // command exceeded its limit and was killed
	CodeGuestKilled    = "guest_killed"     // guest went away while the command ran
	CodeHostResources  = "host_resources"   // host out of disk or memory
	CodeVirtUnavail    = "virt_unavailable" // libvirt/QEMU/nft/xorriso/ssh unusable
	CodeRunUnknown     = "run_unknown"      // no such run (expired, or Limbo restarted)
	CodeRunFailed      = "run_failed"       // Limbo could not execute the command in a ready guest
	CodeOutputTrunc    = "output_truncated" // informational: the command ran, output was cut
	CodeTeardownFailed = "teardown_failed"  // informational: the command ran, cleanup did not finish
)

// Error is a failure Limbo reports. Its text is safe to show a model: a code,
// a short plain message, and a one-line remedy, with no host paths.
type Error struct {
	Code, Message, Remedy string
	short                 string // fixed sentence for the profile "skipped" list
}

func (e *Error) Error() string { return e.Code + ": " + e.Message + ". Remedy: " + e.Remedy }

// ErrCode and ErrRemedy let the API shape the response without importing this package.
func (e *Error) ErrCode() string    { return e.Code }
func (e *Error) ErrMessage() string { return e.Message }
func (e *Error) ErrRemedy() string  { return e.Remedy }

func newErr(code, remedy, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...), Remedy: remedy}
}

// errConnection marks an ssh failure (exit 255) as opposed to a command's own exit.
var errConnection = errors.New("ssh connection failed")

// classify turns what went wrong at a stage of a run into a coded error.
// ctxErr is the context error of the stage's own deadline, if any. Raw error
// text (which can hold host paths) is never copied into the message.
func classify(stage string, err, ctxErr error) *Error {
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(ctxErr, context.DeadlineExceeded) && stage != "command":
		return newErr(CodeBootTimeout, "retry once; if it repeats, check the host load and the guest image", "the guest did not become ready within its boot budget")
	case errors.Is(err, os.ErrNotExist) && stage == "up":
		return newErr(CodeImageMissing, "ask the operator to restore the profile's base image", "the profile's base image is missing")
	case errors.Is(err, image.ErrMismatch):
		return newErr(CodeImageMismatch, "ask the operator to re-verify the image and update the profile's sha256", "the profile's base image does not match its recorded checksum")
	case strings.Contains(text, "no space left") || strings.Contains(text, "cannot allocate memory") || strings.Contains(text, "out of memory"):
		return newErr(CodeHostResources, "ask the operator to free disk space or memory, then retry", "the host ran out of disk space or memory")
	case errors.Is(err, exec.ErrNotFound) || strings.Contains(text, "failed to connect to the hypervisor") || strings.Contains(text, "failed to connect socket"):
		return newErr(CodeVirtUnavail, "ask the operator to check that libvirtd and QEMU are running", "the virtualization stack is unavailable on the host")
	case errors.Is(err, errConnection) && stage == "command":
		return newErr(CodeGuestKilled, "retry; if it repeats the command may be crashing or powering off the guest", "the guest stopped responding while the command was running")
	case stage == "command":
		return newErr(CodeRunFailed, "retry; if it repeats, ask the operator to read the Limbo logs", "Limbo could not run the command in the guest (this is not the command failing)")
	}
	return newErr(CodeBootFailed, "retry once; if it repeats, ask the operator to read the Limbo logs", "the guest could not be started or never became reachable")
}

// sanitize makes guest output safe to put in JSON and in front of a model:
// valid UTF-8, no control characters other than newline and tab.
func sanitize(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func badProfile(short, format string, a ...any) *Error {
	e := newErr(CodeProfileInvalid, "ask the operator to fix the profile file", format, a...)
	e.short = short
	return e
}
