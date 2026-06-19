// watchdog.go — Alert poller for the network guardian
//
// Polls audit.db every 30 seconds for new guardian alerts.
// Fires registered callbacks when the count changes so tray.go
// can update the badge without polling the DB itself.
//
// The network_guardian.ps1 background job writes alert events
// to the events queue → audit.go inserts them into SQLite →
// this file surfaces the count to the tray UI.

package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ── WATCHDOG STATE ───────────────────────────────────────────

type AlertWatchdog struct {
	mu           sync.RWMutex
	lastCount    int
	callbacks    []func(int)  // fired when count changes
	stopCh       chan struct{}
	guardianUp   bool         // mirrors state.json guardian_running
}

var watchdog = &AlertWatchdog{
	stopCh: make(chan struct{}),
}

// ── INIT / SHUTDOWN ───────────────────────────────────────────

func initWatchdog() {
	// Seed with current count so first tick doesn't false-fire
	watchdog.mu.Lock()
	watchdog.lastCount = GetAlertCount()
	watchdog.mu.Unlock()

	go watchdog.runAlertPoller()
	log.Printf("watchdog: started (seed count=%d)", watchdog.lastCount)
}

func shutdownWatchdog() {
	select {
	case <-watchdog.stopCh: // already closed
	default:
		close(watchdog.stopCh)
	}
}

// ── POLLER GOROUTINE ──────────────────────────────────────────

func (w *AlertWatchdog) runAlertPoller() {
	// First tick quickly — gives tray accurate badge on startup
	w.poll()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			log.Println("watchdog: stopped")
			return
		case <-ticker.C:
			w.poll()
		}
	}
}

func (w *AlertWatchdog) poll() {
	newCount := GetAlertCount()

	// Also sync guardian running state from state.json
	s := ReadCurrentState()
	guardianUp := s != nil && s.GuardianRunning

	w.mu.Lock()
	countChanged   := newCount != w.lastCount
	guardianChanged := guardianUp != w.guardianUp
	w.lastCount   = newCount
	w.guardianUp  = guardianUp
	cbs           := w.callbacks
	w.mu.Unlock()

	if countChanged {
		log.Printf("watchdog: alert count changed → %d", newCount)
		WriteGoEvent("WATCHDOG_ALERT_COUNT",
			fmt.Sprintf("count:%d", newCount), "ok")
		for _, cb := range cbs {
			go cb(newCount)
		}
	}

	if guardianChanged {
		log.Printf("watchdog: guardian state changed → running=%v", guardianUp)
	}
}

// ── PUBLIC API ────────────────────────────────────────────────

// OnNewAlert registers a callback that fires whenever the alert count changes.
// Called by tray.go to update the badge label.
func OnNewAlert(cb func(int)) {
	watchdog.mu.Lock()
	defer watchdog.mu.Unlock()
	watchdog.callbacks = append(watchdog.callbacks, cb)
}

// GetCurrentAlertCount returns the last polled alert count.
// Safe to call from any goroutine.
func GetCurrentAlertCount() int {
	watchdog.mu.RLock()
	defer watchdog.mu.RUnlock()
	return watchdog.lastCount
}

// IsGuardianRunning returns whether network_guardian.ps1 is active.
func IsGuardianRunning() bool {
	watchdog.mu.RLock()
	defer watchdog.mu.RUnlock()
	return watchdog.guardianUp
}

// FormatAlertBadge returns a short string for the tray menu item.
// Returns "" when there are no alerts so the menu item shows cleanly.
func FormatAlertBadge() string {
	n := GetCurrentAlertCount()
	switch n {
	case 0:
		return bilingual("No alerts", "चेतावनी नहीं")
	case 1:
		return bilingual("1 alert ⚠", "1 चेतावनी ⚠")
	default:
		return bilingual(
			fmt.Sprintf("%d alerts ⚠", n),
			fmt.Sprintf("%d चेतावनियां ⚠", n),
		)
	}
}

// FormatGuardianStatus returns the guardian's current running state.
func FormatGuardianStatus() string {
	if IsGuardianRunning() {
		return bilingual("🟢 Guardian running", "🟢 रक्षक सक्रिय")
	}
	return bilingual("⬜ Guardian stopped", "⬜ रक्षक निष्क्रिय")
}

// RecentAlertLines returns up to n alert detail strings
// formatted for a tooltip or sub-menu.
func RecentAlertLines(n int) []string {
	events := GetGuardianAlerts(n)
	lines  := make([]string, 0, len(events))
	for _, e := range events {
		ts := ""
		if len(e.Timestamp) >= 19 {
			ts = e.Timestamp[11:19] // HH:MM:SS
		}
		if e.Detail != "" {
			lines = append(lines, fmt.Sprintf("%s  %s", ts, e.Detail))
		}
	}
	return lines
}
