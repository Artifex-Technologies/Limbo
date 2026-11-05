package virt

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// Subnets hands each guest its own 10.213.X.0/24 and records it, so two guests can never be given the same one.
// Before 2026-11-05 X came from a hash of the name, and two names could collide (one run in 254 failed to start).
//
// The record is one small JSON file in the state folder (mode 0644: guest names and their subnets are not secret,
// and `limbo launch` run by a person reads it to find the guest). Every change holds an exclusive lock on a file
// beside it, so the daemon and a `limbo up` from the command line never hand out the same subnet.
type Subnets struct {
	Path string // <state>/subnets.json
	// InUse lists subnets some host interface already has an address in (a guest started by an older Limbo, or anything
	// else); they are skipped. Nil means the real interfaces.
	InUse func() map[int]bool
}

// ErrNoSubnet is returned when all 254 are taken.
var ErrNoSubnet = errors.New("virt: all 254 guest subnets (10.213.1-254.0/24) are in use")

func (s Subnets) lock() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func (s Subnets) read() map[string]int {
	out := map[string]int{}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		return out
	}
	var raw map[string]int
	if json.Unmarshal(b, &raw) != nil {
		return out
	}
	for name, x := range raw {
		if x >= 1 && x <= 254 && nameOK(name) {
			out[name] = x
		}
	}
	return out
}

func (s Subnets) write(m map[string]int) error {
	b, _ := json.MarshalIndent(m, "", "  ")
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// Allocate returns the guest's subnet number X, recording a new one (the lowest free) if it has none.
func (s Subnets) Allocate(name string) (int, error) {
	if !nameOK(name) {
		return 0, fmt.Errorf("virt: bad guest name %q", name)
	}
	unlock, err := s.lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	m := s.read()
	if x, ok := m[name]; ok {
		return x, nil
	}
	taken := map[int]bool{}
	for _, x := range m {
		taken[x] = true
	}
	inUse := s.InUse
	if inUse == nil {
		inUse = hostSubnets
	}
	for x := range inUse() {
		taken[x] = true
	}
	for x := 1; x <= 254; x++ {
		if !taken[x] {
			m[name] = x
			return x, s.write(m)
		}
	}
	return 0, ErrNoSubnet
}

// Lookup returns the subnet recorded for a guest.
func (s Subnets) Lookup(name string) (int, bool) {
	x, ok := s.read()[name]
	return x, ok
}

// Release forgets a guest's subnet (after its network is gone).
func (s Subnets) Release(name string) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	m := s.read()
	if _, ok := m[name]; !ok {
		return nil
	}
	delete(m, name)
	return s.write(m)
}

// Names lists the guests holding a subnet, sorted.
func (s Subnets) Names() []string {
	var out []string
	for n := range s.read() {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// hostSubnets: the X of every 10.213.X.0/24 a host interface has an address in.
func hostSubnets() map[int]bool {
	out := map[int]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := p.Addr().Unmap()
		if ip.Is4() {
			b := ip.As4()
			if b[0] == 10 && b[1] == 213 {
				out[int(b[2])] = true
			}
		}
	}
	return out
}

func nameOK(n string) bool {
	if len(n) == 0 || len(n) > 12 || n[0] < 'a' || n[0] > 'z' {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
