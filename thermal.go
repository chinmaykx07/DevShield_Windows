// thermal.go — Thermal profile coordinator
//
// Sits between the tray menu and the PS bridge.
// Applies profiles, tracks current mode, fires callbacks
// when mode changes so the tray icon updates itself.

package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ── TYPES ────────────────────────────────────────────────────

type ThermalMode string

const (
	ModeUnknown ThermalMode = "unknown"
	ModeSilent  ThermalMode = "silent"
	ModeGaming  ThermalMode = "gaming"
	ModeDev     ThermalMode = "dev"
)

// ModeInfo holds display data for one thermal mode
type ModeInfo struct {
	Mode     ThermalMode
	Icon     string
	LabelEN  string
	LabelSA  string
	TaskName string
}

var allModes = []ModeInfo{
	{ModeSilent, "🔇", "Silent Summer", "मौन-ग्रीष्म", TaskSilentSummer},
	{ModeGaming, "🎮", "Gaming Gear", "क्रीडा-आवृत्ति", TaskGamingGear},
	{ModeDev, "💻", "Dev Mode", "विकास-अवस्था", TaskDevMode},
}

// ── THERMAL MANAGER ──────────────────────────────────────────

type ThermalManager struct {
	mu          sync.RWMutex
	currentMode ThermalMode
	applying    bool // true while a profile is being applied
	onChange    []func(ThermalMode)
	stopWatcher chan struct{}
}

var thermal = &ThermalManager{
	currentMode: ModeUnknown,
	stopWatcher: make(chan struct{}),
}

// ── INIT / SHUTDOWN ───────────────────────────────────────────

func initThermal() {
	// Read current mode from state.json on startup
	s := ReadCurrentState()
	if s != nil && s.ThermalMode != "" {
		thermal.mu.Lock()
		thermal.currentMode = ThermalMode(s.ThermalMode)
		thermal.mu.Unlock()
	}
	// Start background watcher — detects external mode changes
	// (e.g., user ran a PS script directly from terminal)
	go thermal.runStateWatcher()
}

func shutdownThermal() {
	close(thermal.stopWatcher)
}

// ── APPLY PROFILE ─────────────────────────────────────────────

// ApplyProfile triggers the given thermal profile via Task Scheduler.
// Returns immediately — the profile applies asynchronously.
// The tray calls OnChange callbacks once state.json confirms the change.
func ApplyProfile(mode ThermalMode) error {
	thermal.mu.Lock()
	if thermal.applying {
		thermal.mu.Unlock()
		return fmt.Errorf("a profile is already being applied — please wait")
	}
	thermal.applying = true
	thermal.mu.Unlock()

	taskName := modeToTask(mode)
	if taskName == "" {
		thermal.mu.Lock()
		thermal.applying = false
		thermal.mu.Unlock()
		return fmt.Errorf("unknown thermal mode: %s", mode)
	}

	log.Printf("thermal: applying profile %s via task %s", mode, taskName)
	WriteGoEvent("PROFILE_APPLY_START",
		fmt.Sprintf("mode:%s task:%s", mode, taskName), "ok")

	// Run asynchronously so the tray stays responsive
	go func() {
		defer func() {
			thermal.mu.Lock()
			thermal.applying = false
			thermal.mu.Unlock()
		}()

		const applyTimeout = 60 * time.Second
		state, err := RunTaskAndWait(taskName, applyTimeout)

		if err != nil {
			log.Printf("thermal: apply %s failed: %v", mode, err)
			WriteGoEvent("PROFILE_APPLY_FAIL",
				fmt.Sprintf("mode:%s err:%v", mode, err), "fail")
			return
		}

		newMode := ThermalMode(state.ThermalMode)
		thermal.setMode(newMode)

		WriteGoEvent("PROFILE_APPLY_DONE",
			fmt.Sprintf("mode:%s confirmed:%s", mode, newMode), "ok")
	}()

	return nil
}

// ── MODE ACCESS ───────────────────────────────────────────────

func (tm *ThermalManager) getMode() ThermalMode {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.currentMode
}

func (tm *ThermalManager) setMode(m ThermalMode) {
	tm.mu.Lock()
	changed := tm.currentMode != m
	tm.currentMode = m
	cbs := tm.onChange
	tm.mu.Unlock()

	if changed {
		log.Printf("thermal: mode changed → %s", m)
		for _, cb := range cbs {
			go cb(m)
		}
	}
}

func (tm *ThermalManager) isApplying() bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.applying
}

// OnModeChange registers a callback fired when the thermal mode changes.
// Used by tray.go to update menu labels and icon tooltip.
func (tm *ThermalManager) OnModeChange(cb func(ThermalMode)) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.onChange = append(tm.onChange, cb)
}

// ── STATE WATCHER ─────────────────────────────────────────────

// runStateWatcher polls state.json every 5 seconds.
// Detects mode changes made outside the tray app
// (e.g., user ran a PS script directly in terminal).
func (tm *ThermalManager) runStateWatcher() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tm.stopWatcher:
			return
		case <-ticker.C:
			s := ReadCurrentState()
			if s == nil {
				continue
			}
			newMode := ThermalMode(s.ThermalMode)
			if newMode == "" {
				newMode = ModeUnknown
			}
			tm.setMode(newMode)
		}
	}
}

// ── LABEL HELPERS ────────────────────────────────────────────

// ModeLabel returns the display label for a mode in the current language.
func ModeLabel(mode ThermalMode) string {
	info := getModeInfo(mode)
	if info == nil {
		return string(mode)
	}
	return bilingual(info.LabelEN, info.LabelSA)
}

// ModeIcon returns the emoji for a mode.
func ModeIcon(mode ThermalMode) string {
	info := getModeInfo(mode)
	if info == nil {
		return "⬜"
	}
	return info.Icon
}

// ModeFullLabel returns "🔇 Silent Summer · मौन-ग्रीष्म"
func ModeFullLabel(mode ThermalMode) string {
	info := getModeInfo(mode)
	if info == nil {
		return string(mode)
	}
	return fmt.Sprintf("%s %s", info.Icon, bilingual(info.LabelEN, info.LabelSA))
}

// CurrentModeStatus returns a one-line status for the tray tooltip.
//
//	e.g. "🔇 Silent Summer  ·  Applied 14m ago"
func CurrentModeStatus() string {
	mode := thermal.getMode()
	if mode == ModeUnknown {
		return bilingual("No profile active", "कोई आकृति नहीं")
	}

	s := ReadCurrentState()
	sinceStr := ""
	if s != nil && s.ThermalAppliedAt != "" {
		t, err := time.Parse(time.RFC3339, s.ThermalAppliedAt)
		if err == nil {
			diff := time.Since(t)
			switch {
			case diff < time.Minute:
				sinceStr = bilingual("just now", "अभी")
			case diff < time.Hour:
				sinceStr = bilingual(
					fmt.Sprintf("%dm ago", int(diff.Minutes())),
					fmt.Sprintf("%d मिनट पहले", int(diff.Minutes())))
			default:
				sinceStr = bilingual(
					fmt.Sprintf("%dh ago", int(diff.Hours())),
					fmt.Sprintf("%d घंटे पहले", int(diff.Hours())))
			}
		}
	}

	label := ModeFullLabel(mode)
	if sinceStr != "" {
		return fmt.Sprintf("%s  —  %s", label, sinceStr)
	}
	return label
}

// ApplyingStatus returns a user-visible message while a profile is applying.
func ApplyingStatus() string {
	return bilingual("Applying profile…  Please wait.", "आकृति लागू हो रही है… प्रतीक्षा करें।")
}

// AllModes returns the ordered list of ModeInfo for building menus.
func AllModes() []ModeInfo { return allModes }

// ── INTERNAL HELPERS ─────────────────────────────────────────

func getModeInfo(mode ThermalMode) *ModeInfo {
	for i := range allModes {
		if allModes[i].Mode == mode {
			return &allModes[i]
		}
	}
	return nil
}

func modeToTask(mode ThermalMode) string {
	info := getModeInfo(mode)
	if info == nil {
		return ""
	}
	return info.TaskName
}

// bilingual returns "EN · SA", "EN only", or "SA only"
// depending on the current language setting.
func bilingual(en, sa string) string {
	switch lang.Get() {
	case LangEN:
		return en
	case LangSA:
		if sa != "" {
			return sa
		}
		return en
	default: // BOTH
		if sa != "" {
			return en + "  ·  " + sa
		}
		return en
	}
}
