package usbcap

import (
	"context"
	"fmt"
	"io"
	"syscall"
	"time"
	"unsafe"
)

// monBinGet is struct mon_bin_get: where MON_IOCX_GETX puts the next event's header and data.
type monBinGet struct {
	hdr   uintptr
	data  uintptr
	alloc uintptr
}

// MON_IOCX_GETX = _IOW(0x92, 10, struct mon_bin_get): the next event, with the 64-byte header.
const monIocxGetx = 0x40000000 | (uint32(unsafe.Sizeof(monBinGet{})) << 16) | (0x92 << 8) | 10

// Capture records the devices' events (all on one bus) into w as pcap until ctx ends, and returns how many it kept.
// usbmon must be loaded (/dev/usbmonN exists).
func Capture(ctx context.Context, devs []Device, w io.Writer) (int, error) {
	if len(devs) == 0 {
		return 0, fmt.Errorf("usbcap: no devices")
	}
	bus := devs[0].Bus
	for _, d := range devs {
		if d.Bus != bus {
			return 0, fmt.Errorf("usbcap: the devices are on different buses (%d and %d); record one at a time", bus, d.Bus)
		}
	}
	// non-blocking: with no event waiting, the read says so at once, and the loop checks ctx between tries
	fd, err := syscall.Open(fmt.Sprintf("/dev/usbmon%d", bus), syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("usbcap: /dev/usbmon%d: %w (is the usbmon module loaded? modprobe usbmon)", bus, err)
	}
	defer syscall.Close(fd)
	if err := WriteHeader(w); err != nil {
		return 0, err
	}
	data := make([]byte, 65536)
	kept := 0
	for ctx.Err() == nil {
		var e Event
		arg := monBinGet{hdr: uintptr(unsafe.Pointer(&e.Header[0])), data: uintptr(unsafe.Pointer(&data[0])), alloc: uintptr(len(data))}
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(monIocxGetx), uintptr(unsafe.Pointer(&arg)))
		switch errno {
		case 0:
		case syscall.EAGAIN, syscall.EINTR:
			time.Sleep(5 * time.Millisecond)
			continue
		default:
			return kept, fmt.Errorf("usbcap: reading usbmon: %w", errno)
		}
		if !Keep(&e, devs) {
			continue // another device on the bus: never written
		}
		capLen := int(e.Header[36]) | int(e.Header[37])<<8 | int(e.Header[38])<<16 | int(e.Header[39])<<24
		if capLen > len(data) {
			capLen = len(data)
		}
		e.Data = data[:capLen]
		if err := WriteEvent(w, &e); err != nil {
			return kept, err
		}
		kept++
	}
	return kept, nil
}
