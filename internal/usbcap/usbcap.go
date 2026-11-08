// Package usbcap records a passed-through USB device's traffic into a pcap file Wireshark opens: how the conversation
// between a maker's program in a guest and its device (a vehicle tuner) is learned from outside the guest.
//
// It reads Linux's usbmon binary interface (/dev/usbmonN for the device's bus; the text interface keeps only the first 32
// bytes of each transfer), and keeps only the events of the named devices: everything else on that bus (a keyboard, a
// mouse) is read by the kernel interface but never written anywhere. Records are usbmon's own 64-byte header plus the
// data, which is pcap's LINKTYPE_USB_LINUX_MMAPPED (220). Root only, like the rest of passthrough.
package usbcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LinkType is pcap's link type for usbmon's 64-byte header followed by the data.
const LinkType = 220

// HeaderLen is the size of usbmon's binary header (struct mon_bin_hdr, the MON_IOCX_GETX form).
const HeaderLen = 64

// Device is where a USB device is on the host.
type Device struct {
	ID       string // vendor:product
	Bus, Dev int
}

// Find returns where each USB ID is plugged in (root: /sys/bus/usb/devices as an fs.FS, "" names for real sysfs). An ID
// that is not plugged in, or plugged in more than once, is an error.
func Find(sys fs.FS, ids []string) ([]Device, error) {
	if sys == nil {
		sys = os.DirFS("/sys/bus/usb/devices")
	}
	ents, err := fs.ReadDir(sys, ".")
	if err != nil {
		return nil, err
	}
	read := func(dir, f string) string {
		b, _ := fs.ReadFile(sys, filepath.Join(dir, f))
		return strings.TrimSpace(string(b))
	}
	var out []Device
	for _, id := range ids {
		vendor, product, _ := strings.Cut(id, ":")
		var found []Device
		for _, e := range ents {
			n := e.Name()
			if strings.Contains(n, ":") || strings.ToLower(read(n, "idVendor")) != vendor || strings.ToLower(read(n, "idProduct")) != product {
				continue
			}
			bus, err1 := strconv.Atoi(read(n, "busnum"))
			dev, err2 := strconv.Atoi(read(n, "devnum"))
			if err1 == nil && err2 == nil {
				found = append(found, Device{ID: id, Bus: bus, Dev: dev})
			}
		}
		switch len(found) {
		case 0:
			return nil, fmt.Errorf("usbcap: %s is not plugged in", id)
		case 1:
			out = append(out, found[0])
		default:
			return nil, fmt.Errorf("usbcap: %d devices with ID %s are plugged in", len(found), id)
		}
	}
	return out, nil
}

// WriteHeader writes pcap's global header for LinkType records.
func WriteHeader(w io.Writer) error {
	var h [24]byte
	binary.LittleEndian.PutUint32(h[0:], 0xa1b2c3d4)       // microsecond timestamps
	binary.LittleEndian.PutUint16(h[4:], 2)                // version 2.4
	binary.LittleEndian.PutUint16(h[6:], 4)                //
	binary.LittleEndian.PutUint32(h[16:], HeaderLen+65536) // snapshot length
	binary.LittleEndian.PutUint32(h[20:], LinkType)
	_, err := w.Write(h[:])
	return err
}

// Event is one usbmon record: its header and the data captured with it.
type Event struct {
	Header [HeaderLen]byte
	Data   []byte
}

// Bus and Dev are where the event's device is.
func (e *Event) Bus() int { return int(binary.LittleEndian.Uint16(e.Header[12:])) }
func (e *Event) Dev() int { return int(e.Header[11]) }

// Time is when usbmon saw the event.
func (e *Event) Time() time.Time {
	sec := int64(binary.LittleEndian.Uint64(e.Header[16:]))
	usec := int64(int32(binary.LittleEndian.Uint32(e.Header[24:])))
	return time.Unix(sec, usec*1000)
}

// WriteEvent writes one pcap record: usbmon's header as it is, then the data.
func WriteEvent(w io.Writer, e *Event) error {
	n := uint32(HeaderLen + len(e.Data))
	t := e.Time()
	var r [16]byte
	binary.LittleEndian.PutUint32(r[0:], uint32(t.Unix()))
	binary.LittleEndian.PutUint32(r[4:], uint32(t.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(r[8:], n)
	binary.LittleEndian.PutUint32(r[12:], n)
	if _, err := w.Write(r[:]); err != nil {
		return err
	}
	if _, err := w.Write(e.Header[:]); err != nil {
		return err
	}
	_, err := w.Write(e.Data)
	return err
}

// Keep says whether an event belongs to one of the devices.
func Keep(e *Event, devs []Device) bool {
	for _, d := range devs {
		if e.Bus() == d.Bus && e.Dev() == d.Dev {
			return true
		}
	}
	return false
}
