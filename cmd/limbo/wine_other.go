//go:build !linux

package main

import "errors"

func wineCmd([]string) error {
	return errors.New("wine: requires a Linux host (bubblewrap)")
}
