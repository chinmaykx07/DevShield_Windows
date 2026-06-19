// main.go — DevShield entry point
//
// Initialises all subsystems in strict dependency order.
// Enforces single instance via checkSingleInstance() — implemented per
// platform in instance_windows.go (real mutex) and instance_other.go
// (compile-only stub for non-Windows dev/CI machines).
// systray.Run() is called last — it blocks the main goroutine
// for the lifetime of the application (required by fyne-io/systray).

package main

import (
	"log"

	"fyne.io/systray"
)

// ── VERSION ──────────────────────────────────────────────────

const dsVersion = "0.1.0"

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
