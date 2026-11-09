//go:build linux && (amd64 || arm64 || riscv64 || loong64)

package image

import "syscall"

// posix_fadvise advice values (linux/fadvise.h).
const (
	fadvSequential = 2
	fadvDontNeed   = 4
)

// fadvise is posix_fadvise(2): on these 64-bit architectures fadvise64 takes the offset and length as whole
// registers. Advice is a hint, so its error is ignored (a filesystem that does not take it still reads correctly).
func fadvise(fd int, off, n int64, advice int) {
	_, _, _ = syscall.Syscall6(syscall.SYS_FADVISE64, uintptr(fd), uintptr(off), uintptr(n), uintptr(advice), 0, 0)
}
