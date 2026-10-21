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
	"fmt"
	"log"
	"os"
	"runtime"

	"fyne.io/systray"
)

// ── VERSION ──────────────────────────────────────────────────

// dsVersion is a variable so the build can stamp it (-ldflags "-X main.dsVersion=…");
// the linker silently ignores -X on a constant.
var dsVersion = "0.1.0"

// ── MAIN ─────────────────────────────────────────────────────

func main() {
	// Any arguments → command-line mode (daemon, status, agents, …).
	if len(os.Args) > 1 {
		os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
	}
	if runtime.GOOS != "windows" {
		// The tray drives the Windows PowerShell scripts; elsewhere those are
		// compile-only stubs, so starting it would only pretend to work.
		fmt.Fprint(os.Stderr, "The DevShield tray is Windows-only for now (a Linux tray is planned).\nOn Linux, run the daemon and use the commands below.\n\n"+cliUsage)
		os.Exit(2)
	}

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

	// 6b. Agent Watch — inventories running AI agents, alerts on unsanctioned ones
	initAgentWatch()

	// 7. Update checker — polls GitHub Releases every 24h, non-blocking
	initUpdater()

	// 8. systray.Run — MUST be last, blocks the main goroutine forever.
	//    onTrayReady is called on the same goroutine once the tray is initialised.
	//    onTrayExit  is called when systray.Quit() is triggered.
	systray.Run(onTrayReady, onTrayExit)

	log.Println("DevShield exited cleanly.")
}
