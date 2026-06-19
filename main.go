// main.go — DevShield entry point
//
// Initialises all subsystems in strict dependency order.
// Enforces single instance via Windows named mutex.
// systray.Run() is called last — it blocks the main goroutine
// for the lifetime of the application (required by fyne-io/systray).

package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"fyne.io/systray"
)

// ── VERSION ──────────────────────────────────────────────────

const dsVersion = "0.1.0"

// ── SINGLE INSTANCE ───────────────────────────────────────────

// _instanceMutex holds the Windows named mutex handle for the lifetime
// of the process. Storing it in a package-level var prevents it from
// being optimised away. The OS releases the handle automatically on exit.
var _instanceMutex uintptr

// checkSingleInstance creates a named Windows mutex.
// If the mutex already exists, another DevShield is running → exit.
func checkSingleInstance() {
	mutexName, _ := syscall.UTF16PtrFromString("DevShield_SingleInstance_v0")

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	create   := kernel32.NewProc("CreateMutexW")

	handle, _, err := create.Call(
		0,                                    // default security
		1,                                    // bInitialOwner = true
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

// ── MAIN ─────────────────────────────────────────────────────

func main() {
	// 0. Configure logger
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Printf("DevShield v%s starting", dsVersion)

	// 1. Single instance guard (exits early if already running)
	checkSingleInstance()

	// 2. Language — must be first so all subsequent log/UI uses correct lang
	initLang()

	// 3. Audit — opens SQLite + starts event file watcher goroutine
	if err := initAudit(); err != nil {
		// Non-fatal: log and continue. Audit failures should not prevent tray from loading.
		log.Printf("main: audit init warning: %v", err)
	}

	// 4. Thermal — loads current mode from state.json, starts state watcher
	initThermal()

	// 5. Watchdog — polls audit.db for new guardian alerts every 30s
	initWatchdog()

	// 6. Context watcher — auto mode switching (optional, user-controlled)
	initContextWatcher()

	// 7. Update checker — polls GitHub Releases every 24h, non-blocking
	initUpdater()

	// 8. systray.Run — MUST be last, blocks the main goroutine forever.
	//    onTrayReady is called on the same goroutine once the tray is initialised.
	//    onTrayExit  is called when systray.Quit() is triggered.
	systray.Run(onTrayReady, onTrayExit)

	log.Println("DevShield exited cleanly.")
}
