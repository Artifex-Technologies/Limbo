//go:build !linux

package main

import "errors"

func serve([]string) error {
	return errors.New("serve: requires a Linux host")
}
