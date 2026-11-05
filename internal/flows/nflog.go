package flows

import (
	"encoding/binary"
	"errors"
)

// Netlink and NFLOG constants (linux/netlink.h, linux/netfilter/nfnetlink.h, nfnetlink_log.h). Written out here so
// the parsing can be tested on any system.
const (
	nlmsgHdrLen   = 16
	nfgenHdrLen   = 4
	nfnlSubsysLog = 4
	nfulnlMsgPkt  = 0
	nfulnlMsgCfg  = 1
	nlmsgError    = 2
	nlmsgDone     = 3

	nfulaPayload = 9
	nfulaPrefix  = 10

	nfulaCfgCmd  = 1
	nfulaCfgMode = 2
	nfulaCfgQthr = 5

	nfulnlCfgCmdBind = 1
	nfulnlCopyPacket = 2

	nlmFRequest = 0x1
	nlmFAck     = 0x4
)

// copyRange is how much of each packet the kernel copies to us: the IP header and the start of TCP/UDP, enough for
// the addresses and ports. Nothing of what the guest sends beyond that is ever read.
const copyRange = 96

// logged is one NFLOG packet message: its prefix and the start of the packet.
type logged struct {
	prefix  string
	payload []byte
}

func align4(n int) int { return (n + 3) &^ 3 }

// parseMessages splits one netlink read into NFLOG packet messages. Anything else (errors, acks) is skipped; a
// truncated message ends the parse.
func parseMessages(buf []byte) []logged {
	var out []logged
	for len(buf) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(buf[0:4]))
		typ := binary.NativeEndian.Uint16(buf[4:6])
		if l < nlmsgHdrLen || l > len(buf) {
			break
		}
		msg := buf[nlmsgHdrLen:l]
		if typ == nfnlSubsysLog<<8|nfulnlMsgPkt && len(msg) >= nfgenHdrLen {
			var p logged
			attrs := msg[nfgenHdrLen:]
			for len(attrs) >= 4 {
				al := int(binary.NativeEndian.Uint16(attrs[0:2]))
				at := binary.NativeEndian.Uint16(attrs[2:4]) & 0x3fff
				if al < 4 || al > len(attrs) {
					break
				}
				val := attrs[4:al]
				switch at {
				case nfulaPrefix:
					p.prefix = string(trimNul(val))
				case nfulaPayload:
					p.payload = append([]byte(nil), val...)
				}
				attrs = attrs[min(align4(al), len(attrs)):]
			}
			if p.prefix != "" && len(p.payload) > 0 {
				out = append(out, p)
			}
		}
		buf = buf[min(align4(l), len(buf)):]
	}
	return out
}

func trimNul(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

// attr encodes one netlink attribute.
func attr(typ uint16, val []byte) []byte {
	b := make([]byte, align4(4+len(val)))
	binary.NativeEndian.PutUint16(b[0:2], uint16(4+len(val)))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[4:], val)
	return b
}

// configMsg builds an NFULNL_MSG_CONFIG request for group with the given attributes.
func configMsg(group uint16, seq uint32, family uint8, attrs ...[]byte) []byte {
	body := []byte{family, 0, byte(group >> 8), byte(group)} // nfgenmsg: family, version 0, res_id (big-endian)
	for _, a := range attrs {
		body = append(body, a...)
	}
	b := make([]byte, nlmsgHdrLen+len(body))
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:6], nfnlSubsysLog<<8|nfulnlMsgCfg)
	binary.NativeEndian.PutUint16(b[6:8], nlmFRequest|nlmFAck)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	copy(b[nlmsgHdrLen:], body)
	return b
}

// bindRequests are the two messages that bind a group and ask for packet copies of copyRange bytes, delivered at once.
func bindRequests(group uint16) [][]byte {
	mode := make([]byte, 6)
	binary.BigEndian.PutUint32(mode[0:4], copyRange)
	mode[4] = nfulnlCopyPacket
	qthr := make([]byte, 4)
	binary.BigEndian.PutUint32(qthr, 1)
	return [][]byte{
		configMsg(group, 1, 0, attr(nfulaCfgCmd, []byte{nfulnlCfgCmdBind})),
		configMsg(group, 2, 0, attr(nfulaCfgMode, mode), attr(nfulaCfgQthr, qthr)),
	}
}

// ackError reads a netlink error/ack message; nil for a positive ack.
func ackError(buf []byte) error {
	for len(buf) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(buf[0:4]))
		typ := binary.NativeEndian.Uint16(buf[4:6])
		if l < nlmsgHdrLen || l > len(buf) {
			return errors.New("flows: malformed netlink answer")
		}
		if typ == nlmsgError && l >= nlmsgHdrLen+4 {
			code := int32(binary.NativeEndian.Uint32(buf[nlmsgHdrLen : nlmsgHdrLen+4]))
			if code != 0 {
				return errnoError(-code)
			}
			return nil
		}
		buf = buf[min(align4(l), len(buf)):]
	}
	return nil
}

// Decode turns a logged packet into a Packet; ok is false for anything that is not one of Limbo's.
func decode(l logged) (Packet, bool) {
	g, v, ok := ParsePrefix(l.prefix)
	if !ok {
		return Packet{}, false
	}
	proto, dst, dport, icmp, err := ParseIP(l.payload)
	if err != nil {
		return Packet{}, false
	}
	return Packet{Guest: g, Verdict: v, Proto: proto, Dst: dst, DPort: dport, ICMP: icmp}, true
}
