//go:build windows

// instance_windows.go — Single-instance enforcement via a named Windows mutex.

package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
)

// _instanceMutex holds the Windows named mutex handle for the lifetime
// of the process. Storing it in a package-level var prevents it from
// being optimised away. The OS releases the handle automatically on exit.
var _instanceMutex uintptr

// checkSingleInstance creates a named Windows mutex.
// If the mutex already exists, another DevShield is running → exit.
func checkSingleInstance() {
	mutexName, _ := syscall.UTF16PtrFromString("DevShield_SingleInstance_v0")

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	create := kernel32.NewProc("CreateMutexW")

	handle, _, err := create.Call(
		0, // default security
		1, // bInitialOwner = true
		uintptr(unsafe.Pointer(mutexName)),
	)

	// ERROR_ALREADY_EXISTS = 183
	if err.(syscall.Errno) == 183 {
		fmt.Println("DevShield is already running. Check the system tray.")
		os.Exit(0)
	}
	if handle == 0 {
		log.Printf("main: mutex warning: %v", err)
	}
	_instanceMutex = handle // prevent GC / optimisation
}
