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

// Build returns the launch command for the manifest's application.
//
// Windows output is UNVERIFIED: the /app syntax follows FreeRDP 3's documented
// form but has not been run against a real Windows guest. Every optional
// channel (clipboard, drives, sound, microphone) is switched off explicitly
// rather than left to the client's defaults, which vary by version.
func Build(m *manifest.Manifest) (Command, error) {
	ip := virt.Addr(m).Guest.String()
	switch m.OS {
	case manifest.OSLinux:
		return Command{Args: []string{
			"waypipe", "ssh",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=accept-new",
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
