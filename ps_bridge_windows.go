//go:build windows

// ps_bridge_windows.go — Windows syscall helpers for the PS execution bridge.
//
// Kept in a separate build-tagged file so ps_bridge.go stays cross-platform
// at the type level. On Windows both files compile together as package main.

package main

import (
	"os/exec"
	"syscall"
)

const (
	createNoWindow   uint32 = 0x08000000 // hide spawned PS console window
	createNewConsole uint32 = 0x00000010 // open a new visible console window
)

// setHideWindow sets CREATE_NO_WINDOW on the process so spawned
// PS scripts don't flash a black console at the user.
func setHideWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags = createNoWindow
}

// getNewWindowAttr returns a SysProcAttr that opens a new visible
// console window — used by OpenScriptWindow for the dashboard / rollback.
func getNewWindowAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: createNewConsole}
}
