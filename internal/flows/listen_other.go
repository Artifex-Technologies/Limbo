//go:build !linux

package flows

import (
	"context"
	"errors"
	"fmt"
)

type errnoError int

func (e errnoError) Error() string { return fmt.Sprintf("flows: netlink error %d", int(e)) }

// Listen is Linux-only.
func Listen(context.Context, uint16, func(Packet)) error {
	return errors.New("flows: NFLOG needs a Linux host")
}
