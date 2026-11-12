// Package limbo holds what belongs to the repository as a whole: Limbo's version.
package limbo

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// Version is Limbo's own version: the VERSION file at the top of this repository, read when the program is built
// (Labyrinth_OS's docs/VERSIONING.md; its scripts/release.sh writes the file). `limbo version` prints it and GET /v1/status
// reports it; limbo-rs reads the same file.
var Version = strings.TrimSpace(versionFile)
