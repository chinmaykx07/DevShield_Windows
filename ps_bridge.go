// ps_bridge.go — PowerShell execution bridge
//
// Two execution paths (from the plan):
//
//   PRIMARY  — Task Scheduler (RunLevel=Highest, no UAC prompt)
//              Used for: thermal profiles, privacy, tor hardening
//              schtasks /Run /TN "DevShield\DS_SilentSummer"
//              Output read from state.json after task completes.
//
//   DIRECT   — pwsh.exe with stdout capture (no admin needed)
//              Used for: dashboard, profile manager, read-only ops
//              Stdout parsed as JSON or streamed to terminal.
//
//   OPENER   — Start-Process (new visible terminal window)
//              Used for: dashboard, profile manager interactive mode

//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// ── TASK NAME CONSTANTS ───────────────────────────────────────
// Must match the task names registered by 01_first_run.ps1

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

// Task → thermal mode it sets in state.json (for state polling)
var taskModeMap = map[string]string{
	TaskSilentSummer: "silent",
	TaskGamingGear:   "gaming",
	TaskDevMode:      "dev",
}

// ── PS RESULT ────────────────────────────────────────────────
// Mirrors the JSON written by PS scripts on their last stdout line

type PSResult struct {
	Status    string `json:"status"` // "ok" | "warn" | "fail" | "cancelled"
	Mode      string `json:"mode"`
	Detail    string `json:"detail"`
	Verified  bool   `json:"verified"`
	Timestamp string `json:"timestamp"`
	// Thermal-specific
	BeforeCPU float64 `json:"before_cpu_c"`
	AfterCPU  float64 `json:"after_cpu_c"`
	DeltaCPU  float64 `json:"delta_cpu_c"`
	FreqMHz   float64 `json:"freq_actual_mhz"`
	BoostOn   bool    `json:"boost_active"`
	// Privacy-specific
	DomainsAdded int `json:"domains_added"`
	RegApplied   int `json:"reg_applied"`
	// Tor-specific
	RollbackID  string `json:"rollback_id"`
	MACChanged  int    `json:"mac_changed"`
	RulesActive int    `json:"rules_active"`
}

// ── SCRIPT PATH RESOLVER ──────────────────────────────────────

// scriptRoot returns the scripts/ directory relative to the running .exe
func scriptRoot() string {
	exe, err := os.Executable()
	if err != nil {
		return "scripts"
	}
	return filepath.Join(filepath.Dir(exe), "scripts")
}

// scriptPath builds the full path for a PS1 script
func scriptPath(rel string) string {
	return filepath.Join(scriptRoot(), rel)
}

// ── TASK SCHEDULER RUNNER ─────────────────────────────────────

// RunTask triggers a DevShield Task Scheduler task (RunLevel=Highest).
// Returns when schtasks confirms the trigger (not when the task completes).
// Use PollStateChange afterwards to detect completion.
func RunTask(taskName string) error {
	cmd := exec.Command("schtasks",
		"/Run",
		"/TN", taskName,
		"/I", // run immediately even if already running (override)
	)

	// Hide the schtasks console window
	hideWindow(cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /Run %q: %w\n%s", taskName, err, string(out))
	}

	log.Printf("ps_bridge: task triggered: %s", taskName)
	WriteGoEvent("TASK_TRIGGERED", taskName, "ok")
	return nil
}

// RunTaskAndWait triggers a task and waits for state.json to reflect
// the expected mode change. Timeout is typically 45 seconds (profile
// scripts wait 15s for thermal stabilisation before updating state).
func RunTaskAndWait(taskName string, timeout time.Duration) (*DSState, error) {
	expectedMode, hasMode := taskModeMap[taskName]

	if err := RunTask(taskName); err != nil {
		// Task Scheduler failed → fall back to direct execution
		log.Printf("ps_bridge: task trigger failed, trying direct: %v", err)
		return runTaskDirect(taskName, timeout)
	}

	if !hasMode {
		// Non-thermal task (privacy, guardian, etc.) — just wait briefly
		time.Sleep(3 * time.Second)
		return ReadCurrentState(), nil
	}

	// Poll state.json until thermal_mode matches
	s, err := PollStateChange("thermal_mode", expectedMode, timeout)
	if err != nil {
		log.Printf("ps_bridge: state poll timeout for %s: %v", taskName, err)
		// Return whatever state we have — task may have partially run
		return ReadCurrentState(), nil
	}
	return s, nil
}

// runTaskDirect is the fallback when Task Scheduler is unavailable.
// Runs the PS script directly with highest-privilege prompt (UAC).
func runTaskDirect(taskName string, timeout time.Duration) (*DSState, error) {
	scriptMap := map[string]string{
		TaskSilentSummer: "profiles/silent_summer.ps1",
		TaskGamingGear:   "profiles/gaming_gear.ps1",
		TaskDevMode:      "profiles/dev_mode.ps1",
		TaskPrivacy:      "hardening/privacy_enforcer.ps1",
		TaskTorHarden:    "hardening/tor_hardening.ps1",
		TaskGuardian:     "monitor/network_guardian.ps1",
		TaskRollback:     "hardening/rollback.ps1",
	}

	rel, ok := scriptMap[taskName]
	if !ok {
		return nil, fmt.Errorf("no script mapping for task: %s", taskName)
	}
	path := scriptPath(rel)

	// Elevate via PowerShell's Start-Process -Verb RunAs
	elevateCmd := fmt.Sprintf(
		`Start-Process pwsh -ArgumentList '-NonInteractive -WindowStyle Hidden -File \"%s\" -NoConfirm' -Verb RunAs -Wait`,
		strings.ReplaceAll(path, `\`, `\\`),
	)
	cmd := exec.Command("pwsh", "-NonInteractive", "-Command", elevateCmd)
	hideWindow(cmd)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("direct elevation failed: %w", err)
	}

	expectedMode := taskModeMap[taskName]
	if expectedMode != "" {
		return PollStateChange("thermal_mode", expectedMode, timeout)
	}
	time.Sleep(5 * time.Second)
	return ReadCurrentState(), nil
}

// ── DIRECT RUNNER (non-admin scripts, stdout captured) ────────

// RunScriptDirect runs a PS script without elevation and returns
// the parsed JSON result from the last stdout line.
// Used for read-only operations and informational scripts.
func RunScriptDirect(relPath string, args ...string) (*PSResult, error) {
	path := scriptPath(relPath)
	psArgs := []string{"-NonInteractive", "-WindowStyle", "Hidden", "-File", path}
	psArgs = append(psArgs, args...)

	cmd := exec.Command("pwsh", psArgs...)
	hideWindow(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("script %s exit %d: %s", relPath, cmd.ProcessState.ExitCode(), stderr.String())
	}

	return parseLastJSONLine(stdout.String()), nil
}

// parseLastJSONLine finds the last line of output that looks like JSON
// and unmarshals it into PSResult. PS scripts emit JSON as their last line.
func parseLastJSONLine(output string) *PSResult {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			var r PSResult
			if err := json.Unmarshal([]byte(line), &r); err == nil {
				return &r
			}
		}
	}
	return &PSResult{Status: "ok"} // no JSON found — treat as success
}

// ── OPENER (new visible terminal window) ─────────────────────

// OpenScriptWindow opens a PS script in a new visible Windows Terminal
// window. Used for dashboard, profile manager, rollback interactive mode.
func OpenScriptWindow(relPath string, args ...string) error {
	path := scriptPath(relPath)
	psArgs := append([]string{"-File", path}, args...)

	// Try Windows Terminal first (better Unicode/Devanagari rendering)
	wtArgs := []string{"new-tab", "powershell.exe",
		"-NonInteractive", "-File", path}
	wtArgs = append(wtArgs, args...)
	wt := exec.Command("wt", wtArgs...)
	if err := wt.Start(); err == nil {
		log.Printf("ps_bridge: opened in WT: %s", relPath)
		return nil
	}

	// Fallback: plain pwsh in new window
	cmd := exec.Command("pwsh", append([]string{"-NonInteractive"}, psArgs...)...)
	cmd.SysProcAttr = newWindowAttr() // forces a new visible console window
	return cmd.Start()
}

// ── STATE POLLER ──────────────────────────────────────────────

// PollStateChange polls state.json every second until the given key
// equals the expected value, or timeout is reached.
func PollStateChange(key, expected string, timeout time.Duration) (*DSState, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s := ReadCurrentState()
		if s != nil {
			var actual string
			switch key {
			case "thermal_mode":
				actual = s.ThermalMode
			case "guardian_running":
				actual = fmt.Sprintf("%v", s.GuardianRunning)
			case "privacy_active":
				actual = fmt.Sprintf("%v", s.PrivacyActive)
			case "tor_active":
				actual = fmt.Sprintf("%v", s.TorActive)
			}
			if actual == expected {
				return s, nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return nil, fmt.Errorf("timeout waiting for state.%s = %q", key, expected)
}

// ── STATE.JSON ────────────────────────────────────────────────

// DSState mirrors the state.json written by PS scripts
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

// ReadCurrentState reads state.json and returns the parsed struct.
// Returns a zero-value DSState (not nil) if the file is missing.
func ReadCurrentState() *DSState {
	home, err := os.UserHomeDir()
	if err != nil {
		return &DSState{}
	}
	path := filepath.Join(home, ".devshield", "state.json")

	data, err := os.ReadFile(path)
	if err != nil {
		return &DSState{}
	}

	var s DSState
	if err := json.Unmarshal(data, &s); err != nil {
		return &DSState{}
	}
	return &s
}

// ── PLATFORM HELPERS ─────────────────────────────────────────

// hideWindow sets the CREATE_NO_WINDOW flag on Windows so that
// spawned PS processes don't flash a console window.
func hideWindow(cmd *exec.Cmd) {
	if runtime.GOOS == "windows" {
		setHideWindow(cmd) // implemented in ps_bridge_windows.go
	}
}

// newWindowAttr returns a SysProcAttr that opens a new visible
// console window (used for OpenScriptWindow).
func newWindowAttr() *syscall.SysProcAttr {
	return getNewWindowAttr() // implemented in ps_bridge_windows.go
}

// ── TASK STATUS CHECK ─────────────────────────────────────────

// IsTaskRegistered checks if a DevShield task exists in Task Scheduler.
func IsTaskRegistered(taskName string) bool {
	cmd := exec.Command("schtasks",
		"/Query",
		"/TN", taskName,
		"/FO", "LIST",
	)
	hideWindow(cmd)
	return cmd.Run() == nil
}

// AreTasksRegistered checks if all required DevShield tasks are registered.
// Returns (registered count, total count).
func AreTasksRegistered() (int, int) {
	tasks := []string{
		TaskSilentSummer, TaskGamingGear, TaskDevMode,
		TaskPrivacy, TaskTorHarden, TaskGuardian,
	}
	ok := 0
	for _, t := range tasks {
		if IsTaskRegistered(t) {
			ok++
		}
	}
	return ok, len(tasks)
}
