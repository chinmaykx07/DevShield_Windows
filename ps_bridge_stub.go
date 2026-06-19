//go:build !windows

// ps_bridge_stub.go — Non-Windows stub for the PowerShell execution bridge.
//
// This file exists so that go build / go vet / gopls can still type-check
// the repository in Linux/macOS development and CI environments.

package main

import (
	"fmt"
	"time"
)

// ── TASK NAME CONSTANTS ───────────────────────────────────────
// Must match ps_bridge.go exactly.

const (
	TaskSilentSummer = `DevShield\DS_SilentSummer`
	TaskGamingGear   = `DevShield\DS_GamingGear`
	TaskDevMode      = `DevShield\DS_DevMode`
	TaskPrivacy      = `DevShield\DS_Privacy`
	TaskTorHarden    = `DevShield\DS_TorHarden`
	TaskGuardian     = `DevShield\DS_Guardian`
	TaskDashboard    = `DevShield\DS_Dashboard`
	TaskRollback     = `DevShield\DS_Rollback`
)

// ── PS RESULT ────────────────────────────────────────────────

type PSResult struct {
	Status    string `json:"status"`
	Mode      string `json:"mode"`
	Detail    string `json:"detail"`
	Verified  bool   `json:"verified"`
	Timestamp string `json:"timestamp"`

	BeforeCPU float64 `json:"before_cpu_c"`
	AfterCPU  float64 `json:"after_cpu_c"`
	DeltaCPU  float64 `json:"delta_cpu_c"`
	FreqMHz   float64 `json:"freq_actual_mhz"`
	BoostOn   bool    `json:"boost_active"`

	DomainsAdded int `json:"domains_added"`
	RegApplied   int `json:"reg_applied"`

	RollbackID  string `json:"rollback_id"`
	MACChanged  int    `json:"mac_changed"`
	RulesActive int    `json:"rules_active"`
}

// ── STATE.JSON ────────────────────────────────────────────────

type DSState struct {
	ThermalMode       string `json:"thermal_mode"`
	ThermalAppliedAt  string `json:"thermal_applied_at"`
	GuardianRunning   bool   `json:"guardian_running"`
	GuardianStartedAt string `json:"guardian_started_at"`
	PrivacyActive     bool   `json:"privacy_active"`
	PrivacyAppliedAt  string `json:"privacy_applied_at"`
	TorActive         bool   `json:"tor_active"`
	TorAppliedAt      string `json:"tor_applied_at"`
	LHMRunning        bool   `json:"lhm_running"`
	LastHWCheck       string `json:"last_hw_check"`
	UpdatedAt         string `json:"updated_at"`
}

var errUnsupported = fmt.Errorf("ps_bridge: not supported on this platform " +
	"(DevShield is Windows-only — this is a non-Windows compile stub)")

// RunTask is a no-op stub.
func RunTask(taskName string) error {
	return errUnsupported
}

// RunTaskAndWait is a no-op stub returning a zero-value state and an error.
func RunTaskAndWait(taskName string, timeout time.Duration) (*DSState, error) {
	return &DSState{}, errUnsupported
}

// RunScriptDirect is a no-op stub.
func RunScriptDirect(relPath string, args ...string) (*PSResult, error) {
	return nil, errUnsupported
}

// OpenScriptWindow is a no-op stub.
func OpenScriptWindow(relPath string, args ...string) error {
	return errUnsupported
}

// PollStateChange is a no-op stub.
func PollStateChange(key, expected string, timeout time.Duration) (*DSState, error) {
	return nil, errUnsupported
}

// ReadCurrentState always returns a zero-value (non-nil) state.
func ReadCurrentState() *DSState {
	return &DSState{}
}

// IsTaskRegistered always returns false.
func IsTaskRegistered(taskName string) bool {
	return false
}

// AreTasksRegistered always reports zero of the expected six registered.
func AreTasksRegistered() (int, int) {
	return 0, 6
}
