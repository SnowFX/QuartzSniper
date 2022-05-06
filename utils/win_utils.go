// +build windows

package utils

import (
	"fmt"
	"os/exec"
	"os"
	"syscall"
	"strings"
	"time"
)

func AntiCrack() {
	programs := []string{"HTTPDebuggerSvc.exe", "Fiddler.exe", "x64dbg.exe", "x32dbg.exe", "PETools.exe", "MegaDumper.exe", "ExtremeDumper-x86.exe", "ExtremeDumper.exe"}
	cmd := exec.Command("tasklist.exe", "/fo", "csv", "/nh")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.Output()
	for _, program := range programs {
		if strings.Contains(string(out), program) {
			fmt.Println("Nice skid tools..\nClosing Program!")
			time.Sleep(2 * time.Second)
			os.Exit(3)
		}
	}
}