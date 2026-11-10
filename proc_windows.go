//go:build windows

package main

import (
	"os"
	"syscall"
)

func isLockOwnerProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	const (
		processQueryLimitedInformation = 0x1000
		stillActive                    = 259
	)
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var exitCode uint32
	if err := syscall.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	return exitCode == stillActive
}

func openControllingTerminal() (*os.File, error) {
	return os.OpenFile("CONOUT$", os.O_WRONLY, 0)
}

