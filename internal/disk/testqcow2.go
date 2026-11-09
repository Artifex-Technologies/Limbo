package disk

import (
	"encoding/binary"
	"os"
)

// WriteTestQcow2 writes the start of a qcow2 header naming backing (none if empty), enough for VirtualSize and
// BackingFile: for tests in other packages that stand in for a disk qemu-img would have made.
func WriteTestQcow2(path, backing string) error {
	h := make([]byte, 512)
	copy(h, "QFI\xfb")
	binary.BigEndian.PutUint32(h[4:], 3)
	binary.BigEndian.PutUint64(h[24:], 1<<30)
	if backing != "" {
		binary.BigEndian.PutUint64(h[8:], 112)
		binary.BigEndian.PutUint32(h[16:], uint32(len(backing)))
		copy(h[112:], backing)
	}
	return os.WriteFile(path, h, 0o600)
}
