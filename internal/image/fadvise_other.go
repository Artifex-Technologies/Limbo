//go:build !(linux && (amd64 || arm64 || riscv64 || loong64))

package image

const (
	fadvSequential = 2
	fadvDontNeed   = 4
)

// fadvise does nothing here: 32-bit Linux splits the 64-bit arguments differently, and nothing else is a target.
// The hash is the same; only the page cache is not spared.
func fadvise(int, int64, int64, int) {}
