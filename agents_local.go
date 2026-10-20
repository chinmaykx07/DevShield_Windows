// agents_local.go — Agent Watch running inside the tray process.
//
// This is the Windows arrangement until the Windows service exists
// (roadmap Phase W): the tray scans in-process and keeps sanctions in the
// user's audit.db. That store is writable by the same user an agent runs
// as, so on Windows a rogue agent could still tamper with it — see
// docs/COMPETITIVE_LANDSCAPE.md §4A. On Linux the root daemon
// (`devshield daemon`) owns the store instead.

package main

import (
	"log"

	"github.com/chinmaykx07/DevShield_Windows/internal/agentwatch"
)

var agentWatcher *agentwatch.Watcher

func initAgentWatch() {
	auditMu.RLock()
	db := auditDB
	auditMu.RUnlock()

	// No user-writable catalog override here: whoever can edit the
	// catalog decides what counts as an agent.
	w, err := agentwatch.New(agentwatch.Config{DB: db, Emit: WriteGoEvent})
	if err != nil {
		log.Printf("agentwatch: disabled: %v", err)
		return
	}
	agentWatcher = w
	w.Start()
}

func shutdownAgentWatch() {
	if agentWatcher != nil {
		agentWatcher.Stop()
	}
}

func RunningAgents() []agentwatch.RunningAgent {
	if agentWatcher == nil {
		return nil
	}
	return agentWatcher.Running()
}

func SanctionAgent(fingerprint string) error {
	if agentWatcher == nil {
		return nil
	}
	return agentWatcher.Sanction(fingerprint)
}

func OnAgentsChanged(cb func()) {
	if agentWatcher != nil {
		agentWatcher.OnChange(cb)
	}
}
