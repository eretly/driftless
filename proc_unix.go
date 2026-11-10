//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

func isLockOwnerProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil || errors.Is(err, syscall.EPERM) {
		return true
	}
	return false
}

func openControllingTerminal() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_WRONLY, 0)
}

