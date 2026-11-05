// Package launch builds the host-side command that shows a guest application
// as an ordinary window. This is Limbo's equivalent of Parallels' Coherence:
// Windows guests use FreeRDP's RemoteApp mode (the mechanism WinApps uses),
// Linux guests use waypipe over ssh.
//
// Commands are returned as argument vectors, never shell strings, so nothing in
// a manifest is ever interpreted by a shell on the host.
package launch

import (
	"fmt"
	"strings"

	"github.com/Artifex-Technologies/Limbo/internal/manifest"
	"github.com/Artifex-Technologies/Limbo/internal/virt"
)

// Command is a program to run on the host.
type Command struct {
	Args []string
	// PasswordPrompt is true when the program must be given the guest password
	// on stdin. Passwords are never placed in Args, where any local user could
	// read them from the process table.
	PasswordPrompt bool
}

// KnownHostsLine is the one line of the known_hosts file Build's ssh is pointed at: the guest's pinned key under a
// name that is the guest's, not its address, so the pin follows the guest whatever subnet it is given.
func KnownHostsLine(m *manifest.Manifest) (string, error) {
	f := strings.Fields(m.Provision.HostKey)
	if len(f) < 2 || !manifest.HostKeyRe.MatchString(m.Provision.HostKey) {
		return "", fmt.Errorf("launch: %s has no pinned host key: run `limbo seed` for it, add the provision.host_key line it prints "+
			"to the manifest, and rebuild the guest from that seed (launch never trusts a key on first use)", m.Name)
	}
	return hostAlias(m) + " " + f[0] + " " + f[1] + "\n", nil
}

func hostAlias(m *manifest.Manifest) string { return "limbo-" + m.Name }

// Build returns the launch command for the manifest's application. knownHosts is a file holding KnownHostsLine (the
// caller writes it); m.Subnet must be the one the guest was given at up.
//
// Windows output is UNVERIFIED: the /app syntax follows FreeRDP 3's documented
// form but has not been run against a real Windows guest. Every optional
// channel (clipboard, drives, sound, microphone) is switched off explicitly
// rather than left to the client's defaults, which vary by version.
func Build(m *manifest.Manifest, knownHosts string) (Command, error) {
	ip := virt.Addr(m).Guest.String()
	switch m.OS {
	case manifest.OSLinux:
		// waypipe forwards the whole Wayland connection, clipboard included (every type, not only text), and has no way
		// to leave it out. Until the window comes through a filtering compositor, "off" would be a promise not kept.
		if m.Clipboard != manifest.ClipText {
			return Command{}, fmt.Errorf("launch: a Linux app's window comes through waypipe, which shares the clipboard and "+
				"cannot switch it off; set \"clipboard\": %q in %s's manifest to accept that", manifest.ClipText, m.Name)
		}
		if _, err := KnownHostsLine(m); err != nil {
			return Command{}, err
		}
		// The guest's key is pinned at provisioning: any other key is refused, there is no first-use trust, and the
		// person's own known_hosts files are neither read nor written.
		return Command{Args: []string{
			"waypipe", "ssh",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=yes",
			"-o", "UserKnownHostsFile=" + knownHosts,
			"-o", "GlobalKnownHostsFile=/dev/null",
			"-o", "HostKeyAlias=" + hostAlias(m),
			"-o", "CheckHostIP=no",
			m.Access.User + "@" + ip,
			m.App.Exec,
		}}, nil
	case manifest.OSWindows:
		clip := "-clipboard"
		if m.Clipboard == manifest.ClipText {
			clip = "+clipboard"
		}
		return Command{
			Args: []string{
				"xfreerdp3",
				"/v:" + ip,
				"/u:" + m.Access.User,
				"/from-stdin",
				"/cert:tofu",
				"/app:program:" + m.App.Exec + ",name:" + m.App.Name,
				clip, "-drives", "-sound", "-microphone",
			},
			PasswordPrompt: true,
		}, nil
	}
	return Command{}, fmt.Errorf("launch: unsupported os %q", m.OS)
}

// WithIdentity makes a Linux launch use one ssh private key (and only that one) instead of the person's defaults.
func WithIdentity(c Command, identity string) Command {
	if identity == "" || len(c.Args) < 2 || c.Args[0] != "waypipe" || c.Args[1] != "ssh" {
		return c
	}
	args := append([]string{"waypipe", "ssh", "-i", identity, "-o", "IdentitiesOnly=yes"}, c.Args[2:]...)
	return Command{Args: args, PasswordPrompt: c.PasswordPrompt}
}

// CheckArgs turns a Linux launch into a plain ssh that runs remote instead of the application, with exactly the same
// options (the pinned key, the same user and address): `limbo launch --check` uses it to prove everything but the
// window works, without a display.
func CheckArgs(c Command, remote string) ([]string, error) {
	if len(c.Args) < 4 || c.Args[0] != "waypipe" || c.Args[1] != "ssh" {
		return nil, fmt.Errorf("launch: only a Linux (waypipe) launch can be checked this way")
	}
	args := append([]string{"ssh"}, c.Args[2:len(c.Args)-1]...)
	return append(args, remote), nil
}
