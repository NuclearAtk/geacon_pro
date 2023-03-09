//go:build windows && 386
// +build windows,386

package packet

import (
	"errors"
	"main/config"
)

func FullUnhook() error {
	if config.Unhook {
		return errors.New("Unhooking is not supported on windows x86 now.")
	}
	return nil
}
