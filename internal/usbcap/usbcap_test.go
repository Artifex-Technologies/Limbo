package usbcap

import (
	"bytes"
	"encoding/binary"
	"testing"
	"testing/fstest"
)

func TestFindByID(t *testing.T) {
	sys := fstest.MapFS{
		"1-9/idVendor": {Data: []byte("5059\n")}, "1-9/idProduct": {Data: []byte("4040\n")}, "1-9/busnum": {Data: []byte("1\n")}, "1-9/devnum": {Data: []byte("8\n")},
		"1-9:1.0/bInterfaceClass": {Data: []byte("ff\n")},
		"1-4/idVendor":            {Data: []byte("046d\n")}, "1-4/idProduct": {Data: []byte("c52b\n")}, "1-4/busnum": {Data: []byte("1\n")}, "1-4/devnum": {Data: []byte("3\n")},
	}
	d, err := Find(sys, []string{"5059:4040"})
	if err != nil || len(d) != 1 || d[0].Bus != 1 || d[0].Dev != 8 {
		t.Fatalf("%v %v", d, err)
	}
	if _, err := Find(sys, []string{"0403:cc4c"}); err == nil {
		t.Fatal("a device that is not plugged in was found")
	}
}

func ev(bus, dev int, data []byte) *Event {
	var e Event
	e.Header[8] = 'C'
	e.Header[11] = byte(dev)
	binary.LittleEndian.PutUint16(e.Header[12:], uint16(bus))
	binary.LittleEndian.PutUint64(e.Header[16:], 1762646400)
	binary.LittleEndian.PutUint32(e.Header[24:], 250000)
	binary.LittleEndian.PutUint32(e.Header[36:], uint32(len(data)))
	e.Data = data
	return &e
}

func TestOnlyTheDevicesTrafficIsKeptAndWrittenAsPcap(t *testing.T) {
	x4 := []Device{{ID: "5059:4040", Bus: 1, Dev: 8}}
	keyboard := ev(1, 3, []byte{0, 0, 4, 0})
	tuner := ev(1, 8, []byte{0xAA, 0x55, 0x01})
	if Keep(keyboard, x4) || !Keep(tuner, x4) {
		t.Fatal("kept the wrong device")
	}
	var b bytes.Buffer
	if err := WriteHeader(&b); err != nil {
		t.Fatal(err)
	}
	if err := WriteEvent(&b, tuner); err != nil {
		t.Fatal(err)
	}
	out := b.Bytes()
	if binary.LittleEndian.Uint32(out[0:]) != 0xa1b2c3d4 || binary.LittleEndian.Uint32(out[20:]) != LinkType {
		t.Fatal("bad pcap header")
	}
	rec := out[24:]
	if sec, usec, n := binary.LittleEndian.Uint32(rec[0:]), binary.LittleEndian.Uint32(rec[4:]), binary.LittleEndian.Uint32(rec[8:]); sec != 1762646400 || usec != 250000 || n != HeaderLen+3 {
		t.Fatalf("record header %d %d %d", sec, usec, n)
	}
	if !bytes.Equal(rec[16+HeaderLen:], []byte{0xAA, 0x55, 0x01}) || rec[16+11] != 8 {
		t.Fatal("record body")
	}
}

func TestTheIoctlNumber(t *testing.T) {
	// _IOW(0x92, 10, struct mon_bin_get) on 64-bit Linux: three pointer-sized fields
	if monIocxGetx != 0x4018920a {
		t.Fatalf("MON_IOCX_GETX is %#x", monIocxGetx)
	}
}
