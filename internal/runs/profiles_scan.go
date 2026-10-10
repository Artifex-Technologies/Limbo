package runs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Artifex-Technologies/Limbo/internal/events"
	"github.com/Artifex-Technologies/Limbo/internal/image"
)

// maxSkipped caps the "skipped" list on the agent socket; the rest is a count.
const maxSkipped = 20

// CodeMore marks the final "skipped" entry that stands for the profiles past the cap.
const CodeMore = "more"

// SkippedProfile says why a profile file is not offered. Reason is one fixed
// sentence (no host path, no raw parser or libvirt text) and Name is empty unless
// the file name is a valid profile name. Read-only: nothing in it can change policy.
type SkippedProfile struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
	Remedy string `json:"remedy"`
}

// imgSig identifies an image file's state at the time its checksum was verified,
// so a multi-gigabyte image is hashed once, not on every listing.
type imgSig struct {
	size int64
	mod  time.Time
	want string
}

type scanned struct {
	name    string
	profile *Profile
}

// scan reads the profile directory and sorts every profile file into usable or
// skipped (with the reason). A failure is written to the event log once per
// distinct code, and forgotten once the profile is usable or gone, so a later
// regression is logged again.
func (m *Manager) scan() ([]scanned, []SkippedProfile) {
	m.scanMu.Lock()
	defer m.scanMu.Unlock()
	if m.seen == nil {
		m.seen = map[string]string{}
		m.imgOK = map[string]imgSig{}
	}
	ents, err := os.ReadDir(m.ProfileDir)
	if err != nil {
		return nil, []SkippedProfile{}
	}
	var ok []scanned
	skipped := []SkippedProfile{}
	now := map[string]string{}
	for _, e := range ents {
		file := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(file, ".json") {
			continue
		}
		n := strings.TrimSuffix(file, ".json")
		var sk *SkippedProfile
		if !profileRe.MatchString(n) {
			sk = &SkippedProfile{Code: CodeProfileInvalid, Reason: "the profile file name is not a valid profile name", Remedy: "rename it: lowercase letters, digits and hyphens"}
		} else if p, err := m.loadProfile(n); err != nil {
			sk = skipFor(n, err)
		} else if err := m.checkImage(p); err != nil {
			sk = skipFor(n, err)
		} else if err := m.Engine.CheckHardware(&p.Manifest); err != nil {
			sk = skipFor(n, hardwareErr(err))
		} else {
			ok = append(ok, scanned{n, p})
			continue
		}
		if sk.Name == "" && profileRe.MatchString(n) {
			sk.Name = n
		}
		skipped = append(skipped, *sk)
		now[file] = sk.Code
		if m.seen[file] != sk.Code && m.Events != nil {
			guest := ""
			if profileRe.MatchString(n) {
				guest = n
			}
			_ = m.Events.Emit(events.RunError, guest, map[string]string{"code": sk.Code, "during": "profile scan"})
		}
	}
	m.seen = now
	sort.Slice(ok, func(i, j int) bool { return ok[i].name < ok[j].name })
	sort.SliceStable(skipped, func(i, j int) bool { return skipped[i].Name < skipped[j].Name })
	return ok, skipped
}

// skipFor turns a load or image failure into the fixed public sentence.
func skipFor(name string, err error) *SkippedProfile {
	var re *Error
	if !errors.As(err, &re) {
		return &SkippedProfile{Code: CodeProfileInvalid, Reason: "the profile could not be checked", Remedy: "ask the operator to fix the profile file"}
	}
	s := &SkippedProfile{Code: re.Code, Reason: re.short, Remedy: re.Remedy}
	if s.Reason == "" {
		switch re.Code {
		case CodeImageMissing:
			s.Reason = "the profile's base image is missing"
		case CodeImageMismatch:
			s.Reason = "the profile's base image does not match its recorded checksum"
		default: // the file existed in the listing but could not be read
			s.Code, s.Reason, s.Remedy = CodeProfileInvalid, "the profile file could not be read", "ask the operator to fix the profile file"
		}
	}
	return s
}

// checkImage reports a missing or altered base image. The checksum is cached by
// the image's size and modification time (it is re-hashed if either changes).
func (m *Manager) checkImage(p *Profile) error {
	img := p.Manifest.Image
	fi, err := os.Stat(img.Path)
	if err != nil {
		return newErr(CodeImageMissing, "ask the operator to restore the profile's base image", "the profile's base image is missing")
	}
	sig := imgSig{fi.Size(), fi.ModTime(), img.SHA256}
	if m.imgOK[filepath.ToSlash(img.Path)] == sig {
		return nil
	}
	if err := image.Verify(img.Path, img.SHA256); err != nil {
		if errors.Is(err, image.ErrMismatch) {
			return newErr(CodeImageMismatch, "ask the operator to re-verify the image and update the profile's sha256", "the profile's base image does not match its recorded checksum")
		}
		return newErr(CodeImageMissing, "ask the operator to restore the profile's base image", "the profile's base image is missing")
	}
	m.imgOK[filepath.ToSlash(img.Path)] = sig
	return nil
}

// Profiles lists the usable profile names.
func (m *Manager) Profiles() []string {
	ok, _ := m.scan()
	out := []string{}
	for _, s := range ok {
		out = append(out, s.name)
	}
	return out
}

// Details describes the usable profiles. It exists because a model offered a
// profile by name alone ran `pacman` without sudo on a profile that granted it,
// then blamed the profile: it had no way to know.
func (m *Manager) Details() any {
	ok, _ := m.scan()
	out := []ProfileInfo{}
	for _, s := range ok {
		out = append(out, ProfileInfo{Name: s.name, Network: s.profile.Manifest.Network.Mode, Sudo: s.profile.Manifest.Access.Sudo, Passthrough: len(s.profile.Manifest.Devices.PCI) > 0, MaxSeconds: s.profile.MaxSeconds})
	}
	return out
}

// Skipped lists profile files that exist but are not offered, with why: at most
// maxSkipped entries, then one "more" entry carrying the count. Never nil.
func (m *Manager) Skipped() any {
	_, sk := m.scan()
	if len(sk) > maxSkipped {
		more := len(sk) - maxSkipped
		sk = append(sk[:maxSkipped:maxSkipped], SkippedProfile{
			Code: CodeMore, Reason: fmt.Sprintf("%d more profiles skipped", more),
			Remedy: "see the Limbo log or 'limbo doctor'",
		})
	}
	return sk
}

// SkippedAll is the uncapped list, for `limbo doctor`.
func (m *Manager) SkippedAll() []SkippedProfile {
	_, sk := m.scan()
	return sk
}
