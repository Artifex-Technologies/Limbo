package wine

import (
	"encoding/binary"
	"strconv"
)

// X authority families (Xau): a local (unix socket) entry names the host it was made on; a wild entry matches any.
const (
	xauthLocal = 256
	xauthWild  = 0xffff
)

// FilterXauth keeps the X authority entries a client inside the sandbox needs for display n, and rewrites each as a
// "wild" entry with no address. The sandbox has its own host name ("limbo"), so a local entry naming the real host
// would never match there; and the real host name is not something the sandbox needs to learn. Entries for other
// displays, and for displays reached over the network, are dropped. A damaged file yields what parsed before the
// damage.
func FilterXauth(b []byte, n int) []byte {
	want := strconv.Itoa(n)
	var out []byte
	field := func(p []byte) ([]byte, []byte, bool) {
		if len(p) < 2 {
			return nil, nil, false
		}
		l := int(binary.BigEndian.Uint16(p))
		if len(p) < 2+l {
			return nil, nil, false
		}
		return p[2 : 2+l], p[2+l:], true
	}
	put := func(f []byte) {
		out = binary.BigEndian.AppendUint16(out, uint16(len(f)))
		out = append(out, f...)
	}
	for len(b) >= 2 {
		family := binary.BigEndian.Uint16(b)
		rest := b[2:]
		var addr, num, name, data []byte
		var ok bool
		if addr, rest, ok = field(rest); !ok {
			break
		}
		if num, rest, ok = field(rest); !ok {
			break
		}
		if name, rest, ok = field(rest); !ok {
			break
		}
		if data, rest, ok = field(rest); !ok {
			break
		}
		b = rest
		_ = addr
		if (family == xauthLocal || family == xauthWild) && (len(num) == 0 || string(num) == want) {
			out = binary.BigEndian.AppendUint16(out, xauthWild)
			put(nil)
			put(num)
			put(name)
			put(data)
		}
	}
	return out
}
