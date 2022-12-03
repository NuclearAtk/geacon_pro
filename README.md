# geacon_pro


## [中文说明在这里](https://github.com/H4de5-7/geacon_pro/blob/master/README_zh.md)


## Introduction
geacon_pro is an Anti-Virus bypassing CobaltStrike Beacon written in Golang based on  [geacon](https://github.com/darkr4y/geacon) project.

geacon_pro supports CobaltStrike version 4.1+

geacon_pro has implemented most functions of Beacon.

**We will continue to follow up the method of bypassing Anti-Virus and keep geacon_pro from being detected by Anti-Virus. We will also integrate the pen test tools which can bypass Anti-Virus. We hope that geacon_pro can be made into a cross-platform bypass Anti-Virus tool that is not limited to CobaltStrike native functions in the future. Discussions are welcome if you have relevant needs or ideas. your support and discussion is the driving force for us to move forward.**

**!!! If you don’t want to use the exe compiled by geacon_pro, you can use this [project](https://github.com/WBGlIl/go-ReflectiveDLL) to convert geacon_pro into reflective dll/shellcode and then use the loader to load it. You can find the detail below. !!!**

**This project is only for learning CobaltStrike protocol. Please do not use it for any illegal purpose, and the consequences arising therefrom shall be borne by yourself.**

This project is developed by me and Z3ratu1. He has implemented a version of [geacon_plus](https://github.com/Z3ratu1/geacon_plus) that supports CobaltStrike version 4.0. geacon_pro supports version 4.1 and above. Functions of these two projects are almost same while encapsulation is slightly different.

**Loading the shellcode of Beacon through various loaders is the traditional method to bypass Anti-Virus. However, some Anti-Virus check the memory characteristics of Beacon strictly, especially Kaspersky, so it is better to rebuild one by yourself.**

The core of bypassing Anti-Virus can be reflected in three aspects:

* There is no CobaltStrike Beacon feature.
* Viruses written in Golang can bypass the detection of antivirus software to a certain extent.
* Some dangerous functions which can be easily detected by antivirus software has been changed to more stealthy implementations.

**The currently implemented functions can pass Defender, 360 core crystal (except powershell, you can use the tool I provide below), Kaspersky (except memory operations, such as injecting native CobaltStrike dll), and Huorong. Other antivirus software has not been tested yet, please contact me if you have relevant requirements.**

In order to avoid 360's monitoring of the fork&&run operation, geacon_pro currently injects CobaltStrike native dll into itself rather than into the temporary process. However, we found that the CobaltStrike native powerpick function sometimes fails to get the echo when it is injected into geacon_pro itself, while is works well in the fork&&run mode. Therefore, you can use `execute-assembly` to execute this [powershell-bypass tool](https://github.com/H4de5-7/powershell-bypass), which can bypass Defender, 360, etc.

If you want to make bypassUAC avoid the detection of antivirus software, please using `execute-assembly` to execute the Csharp version of [this project](https://github.com/0xlane/BypassUAC/). Although the Csharp program will be detected by 360 when it is on the disk, it can bypass Defender and 360 by executing in memory using `execute-assembly`. The dll version of this project can bypass Anti-Virus, but it needs to be uploaded and executed with rundll32.

If you want to find an Anti-Virus bundler, one my [project](https://github.com/H4de5-7/Bundler-bypass) may help you.

**geacon_pro is still in development, the current version may have some incomplete functions. Please contact me if you have any needs.**

**If you have a good solution for heap memory encryption, welcome to discuss, my implementation ideas are in the implementation details.**

## How to use geacon_pro
geacon_pro supports Windows, Linux and Mac.

### Method one: Compile and execute

For the basic usage, please refer to the original project geacon. Adding `-ldflags "-H windowsgui -s -w"` when compiling binary can reduce the program size and hide the cmd window. When compiling for linux and mac, adding `-ldflags "-s -w"` can reduce the size of the program, and then run it in the background.

The simplest way to use geacon_pro is to modify the public key and C2 server address in config.go, and then replace the C2profile with the following example.

The function of hiding the console has been realized, this function depends on the parameter "HideConsole" in config.go, but there is still a transient console currently.

**geacon_pro supports domain fronting. you need change the C2 address to the domain name and corresponding port, and then change the host of req.Header in config.go to the domain, The C2profile does not need to be changed.**

**At present, the project has some console output content, you can delete the related code to remove it.**

If your CobaltStrike's magic number changed from 48879 to other number before, it may cause the authentication to fail. In that case you can try to change the 0xBEEF in meta.go to the value you have changed.

### Method two: Convert to reflective dll/shellcode and use loader to load

You can use this [project](https://github.com/WBGlIl/go-ReflectiveDLL) to convert geacon_pro into reflective dll/shellcode and then use the loader to load it. After moving the files in the geacon_pro's directory to this project's directory, rename the original main function of main.go to OnPorcessAttach and mark it as the export function. Then add ```import "C"``` and add the main() function. Finally, use x64.bat to compile (you can customize the compilation parameters) and generate reflective dll. One example of main.go can be found below:

```
package main

import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"main/config"
	"main/crypt"
	"main/packet"
	"main/services"
	"os"
	"strings"
	"time"
)

func main() {
    //fmt.Println("123")
}
//export OnProcessAttach
func OnProcessAttach() {
	......//original code in main function
	......
	......
}
```

## Functions

### Windows platform:

sleep, shell, upload, download, exit, cd, pwd, file_browse, ps, kill, getuid, mkdir, rm, cp, mv, run, execute, drives, powershell-import, powershell, execute-assembly, Multiple thread injection methods (you can replace the source code yourself), inject, shinject, dllinject, pipe, Various CobaltStrike native reflection dll injection (mimikatz, portscan, screenshot, keylogger, etc.), steal_token, rev2self, make_token, getprivs, proxy, delete self, timestomp, etc. Supports reflectiveDll, execute-assembly, powershell, powerpick, upload and execute and other functions of cna custom plugins.

### Linux, Mac platform:

sleep, shell, upload, download, exit, cd, pwd, file_browse, ps, kill, getuid, mkdir, rm, cp, mv, delete self, etc.

The process management and the file management support graphical interaction.

### C2profile:

geacon_pro adapts the settings on the flow of C2profile and some settings on the host. The supported encoding algorithms are base64, base64url, mask, netbios, netbiosu. Details can be found in config.go. Here is an example C2profile.
**IMPORTANT!!! After modifying the C2profile, do not forget to sync the changes in config.go:**
```
# default sleep time is 60s
set sleeptime "3000";
set jitter "7";

https-certificate {
    set C "KZ";
    set CN "foren.zik";
    set O "NN Fern Sub";
    set OU "NN Fern";
    set ST "KZ";
    set validity "365";
}

# define indicators for an HTTP GET
http-get {

	set uri "/www/handle/doc";

	client {
		#header "Host" "aliyun.com";
		# base64 encode session metadata and store it in the Cookie header.
		metadata {
			base64url;
			prepend "SESSIONID=";
			header "Cookie";
		}
	}

	server {
		# server should send output with no changes
		#header "Content-Type" "application/octet-stream";
		header "Server" "nginx/1.10.3 (Ubuntu)";
    		header "Content-Type" "application/octet-stream";
        	header "Connection" "keep-alive";
        	header "Vary" "Accept";
        	header "Pragma" "public";
        	header "Expires" "0";
        	header "Cache-Control" "must-revalidate, post-check=0, pre-check=0";

		output {
			mask;
			netbios;
			prepend "data=";
			append "%%";
			print;
		}
	}
}

# define indicators for an HTTP 
http-post {
	# Same as above, Beacon will randomly choose from this pool of URIs [if multiple URIs are provided]
	set uri "/IMXo";
	client {
		#header "Content-Type" "application/octet-stream";				

		# transmit our session identifier as /submit.php?id=[identifier]
		
		id {				
			mask;
			netbiosu;
			prepend "user=";
			append "%%";
			header "User";
		}

		# post our output with no real changes
		output {
			mask;
			base64url;
			prepend "data=";
			append "%%";		
			print;
		}
	}

	# The server's response to our HTTP POST
	server {
		header "Server" "nginx/1.10.3 (Ubuntu)";
    		header "Content-Type" "application/octet-stream";
        	header "Connection" "keep-alive";
       	 	header "Vary" "Accept";
        	header "Pragma" "public";
        	header "Expires" "0";
        	header "Cache-Control" "must-revalidate, post-check=0, pre-check=0";

		# this will just print an empty string, meh...
		output {
			mask;
			netbios;
			prepend "data=";
			append "%%";
			print;
		}
	}
}

post-ex {
    set spawnto_x86 "c:\\windows\\syswow64\\rundll32.exe";
    set spawnto_x64 "c:\\windows\\system32\\rundll32.exe";
    
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x1000";
    set pipename "DserNamePipe##, PGMessagePipe##, MsFteWds##";
    set keylogger "SetWindowsHookEx";
}

```

### custom settings

There are some custom settings in config.go:

* Remark can be used to remark the machine, which is convenient for distinguishing different application scenarios. That is, if Remark="test", the name of the online machine will be set as ComputerName [test].
* ExecuteKey can perform simple anti-sandbox. If the key value is “password”, ```geacon_pro.exe password``` is required to execute after setting. The sandbox or blue team members cannot execute because they do not know the key.
* DeleteSelf sets whether to delete itself.
* HideConsole sets whether to hide the console.

### Functions need to be improved

* ~~The bug in dllinject function.~~
* Heap memory encryption is currently unstable and has not been officially used.
* ~~Modify the problem of Chinese display error under some functions.~~
* ~~Some functions do not support x86 system yet (I am too busy recently, and I will modify it as soon as possible).~~

### To do in the future

* Implement more functions.
* Integrate the pen test tools which can bypass Anti-Virus.
* Implement more functions under Linux and Mac.
* Implement the function of code obfuscation.
* Hook cobaltstrike.jar to custom flow characteristics (just like Behinder4.0)
* Add flow obfuscation.
* Obfuscate reflective dll in memory.
* Simplify configuration and encrypt configuration file.

### Code structure

#### config

* Public key, C2 server address, https communication, timeout time, proxy and other settings
* C2profile settings

#### crypt

* AES, RSA encryption algorithm required for communication
* Implementation of C2profile Encryption Algorithm

#### packet

* charset: The implementation of changing GBK to UTF-8
* Commands: The implementation of some functions under each platform
* execute_assembly: The implementation of executing c# in memory under the windows platform
* heap: The implementation of heap memory encryption under the windows platform
* http: The implementation of sending the package
* inject: The implementation of injecting your shellcode/reflective dll into the process under the windows platform
* Jobs: The implementation of injecting the CobaltStrike native reflection dll under the windows platform and using namedpipe to return result
* Packet: The implementation of the function required for communication
* Token: The implementation of the token-related functions under the windows platform

#### services

Implement the Cross-platform encapsulation of the functions in packet, which is convenient for main.go to use
#### sysinfo

* meta: The implementation of processing the meta information
* sysinfo: The implementation of obtaining the information of related processes and systems under different platforms
#### main.go

The main function parses and executes each command, then returns results or errors

## Implementation details of some functions

### shell

The shell command called golang's os/exec library directly before, and now it is changed to the implementation of the winapi CreateProcess. The only difference from run command is that the shell calls cmd and run does not.

### run && execute

The difference between run and execute is that run can return the result of execution while execute does not. The underlying implementation difference is that run returns the result of execution through the pipeline while execute does not.

The implementations of shell, run, and execute call CreateProcess without stealing the token, and call CreateProcessWithTokenW after stealing the token to execute the command with the token privilege.

### powershell-import

The implementation of the powershell-import is the same as of CobaltStrike. First, save the input powershell module, then open a port locally and put the module on it when executing the powershell command. Powershell directly requests the port to load the powershell module without landing. Without loading the powershell module on the ground, some anti-virus software can not detect malicious powershell module.

### powershell

The powershell command directly invokes powershell and will be monitored by 360. You can try to execute it with the tool mentioned earlier.

### execute-assembly

The implementation of execute-assembly is not the same as the native implementation of CobaltStrike. The main part of the content CobaltStrike's beacon receives from the server is the program of c# and the dll used to open the .net environment. The beacon of CobaltStrike first opens a process(the default is rundll32), then injects the dll used to open the environment into the process, and finally injects the c# program into this process to execute it. Considering that the steps are too complete and it is difficult to get the result of execution, we directly use [this project](https://github.com/timwhitez/Doge-CLRLoad) to implement the function of execute-assembly, but we have not tested it on all versions of windows.

### process injection

The implementation of shinject and dllinject all use remote injection.

### reflective dll injection

CobaltStrike's beacon first opens a rundll32 process then injects reflective dll in it and execute. However, it will be detected by the 360 core crystal. I tried to use methods such as native or unhook and failed, and finally found that injecting dll into geacon_pro itself will not be detected, so I consider changing the fork&run method of CobaltStrike to the method of injecting geacon_pro itself. Since CobaltStrike inject reflective dll in the form of fork&&run, some dlls need to execute ExitProcess at the end of job.

![1666934161850](https://user-images.githubusercontent.com/48757788/198508271-5be424b8-f34c-404b-9646-0e1027713476.png)

However, if we inject geacon_pro itself, the main thread of geacon_pro will be exited, so we need to make simple modifications to the delivered dll. We replace the ExitProcess string in the dll with ExitThread+\x00.

The dll sends the result back to the server asynchronously through the pipe. The current reflective dll injection adopts the method of injecting geacon_pro itself, and we are going to make user choose the injection method through the config.go.

### token

The part of the token currently implements steal_token, make_token, rev2self and getprivs.

### the connection of server and hosts on the intranet

It is a common case that the intranet hosts need to connect to C2 server. If the edge host connects internet while the intranet hosts doesn't, geacon_pro can connect to server through the proxy of the edge host by setting the configuration in config.go. That is, if a http proxy is opened on port 8080 of the edge host, then setting ProxyOn to true in config.go and Proxy to ```http://ip:8080``` can make the hosts on the intranet connect to our C2 server.

### heap memory encryption

The implementation of heap memory encryption refers to [this project](https://github.com/waldo-irc/LockdExeDemo). Suspend threads other than the main thread before sleep, and then traverse the heap to encrypt the heap memory. Decrypt and resume the thread after sleep. However, the implementation is relatively unstable, sometimes it will suddenly get stuck or exit directly during heap traversal, and considering that there may be persistent jobs such as keylogger or portscan in the background, it seems inappropriate to suspend all threads. If you have Good ideas about heap memory encryption, welcome to discuss. At the same time, I do not quite understand why Golang's time.Sleep function will sleep forever after other threads are suspended, but calling windows.SleepEx works fine, I hope you can answer it.

### charset

Since Golang processes string as UTF-8 by default, we decide to hardcode the communication charset between geacon_pro and CS server to UTF-8. Since Linux and macOS also use UTF-8 as default charset, we only need to convert the output of windows. Now we only convert GBK charset to UTF8, avoiding the problem of Chinese garbled.

### self deletion

CobaltStrike seems not implement self deletion function. We have implemented a cross-platform self deletion function. Under the windows platform, it is not allowed to delete itself when the process has not exited. Commonly used methods include using bat and using remote thread injection. The disadvantage of remote thread injection is mentioned before that it is easy to be detected by Anti-Virus. Thus, we use CreateProcess to create a new self-deletion process and set it to execute in idle time, then the self-deletion process will be executed after the geacon_pro process finished. At that time, geacon_pro can be deleted by this self-deletion process. Under the Linux platform, the geacon_pro process can be deleted directly.

## 404Starlink
![image](https://github.com/knownsec/404StarLink-Project/raw/master/logo.png)

geacon_pro has joined [404Starlink](https://github.com/knownsec/404StarLink)








