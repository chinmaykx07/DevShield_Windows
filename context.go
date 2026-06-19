// context.go — Process-aware automatic mode switching
//
// Polls running processes every 60 seconds via gopsutil.
// Maps detected applications to the best thermal mode.
// Only switches automatically when the user has enabled
// auto-switch in config.json (default: OFF — user controls).
//
// Priority: gaming > dev > silent (quiet hours) > current mode
//
// The user can always override by clicking a tray menu item.
// Manual overrides suppress auto-switch for 30 minutes.

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// ── PROCESS → MODE MAP ────────────────────────────────────────

// gameProcesses — any match triggers gaming mode
// Keep lowercase — we compare after ToLower()
var gameProcesses = []string{
	// Common game launchers + engines
	"steam", "epicgameslauncher", "gogalaxy", "origin",
	"battlenet", "riotclientservices", "leagueclient",
	"valorant-win64-shipping", "fortnite",
	"eldenring", "sekiro", "witcher3",
	"cyberpunk2077", "gtav", "rdr2",
	"minecraft", "javaw", // Minecraft Java
	"destiny2", "apex_legends",
	"cs2", "csgo", "dota2",
	"overwatch", "overwatch2", "battlenet",
}

// devProcesses — any match triggers dev mode
var devProcesses = []string{
	"code", // VS Code
	"code - insiders",
	"cursor",
	"idea64", // IntelliJ
	"webstorm64",
	"pycharm64",
	"rider64",
	"clion64",
	"devenv", // Visual Studio
	"sublime_text",
	"atom",
	// Runtimes that imply active dev work
	"node",
	"cargo", // Rust building
	"go",    // Go build
	"python",
	"python3",
	// Build/container tools
	"docker desktop",
	"com.docker.backend",
	"gradle",
	"mvn",
	"msbuild",
}

// quiet hours: 23:00–07:00 → prefer silent if nothing else matches
const quietHourStart = 23
const quietHourEnd = 7

// ── CONTEXT DETECTOR STATE ────────────────────────────────────

type ContextDetector struct {
	mu               sync.RWMutex
	enabled          bool
	lastDetected     ThermalMode
	manualOverride   time.Time // suppress auto-switch until this time
	overrideDuration time.Duration
	stopCh           chan struct{}
}

var ctx = &ContextDetector{
	enabled:          false, // OFF by default — user opts in
	overrideDuration: 30 * time.Minute,
	stopCh:           make(chan struct{}),
}

// ── INIT / SHUTDOWN ───────────────────────────────────────────

func initContextWatcher() {
	// Load auto-switch preference from config.json
	cfg := GetDSConfig()
	if cfg != nil {
		if v, ok := cfg["auto_switch"].(bool); ok {
			ctx.mu.Lock()
			ctx.enabled = v
			ctx.mu.Unlock()
		}
	}

	go ctx.runDetector()
	log.Printf("context: watcher started (auto-switch=%v)", ctx.isEnabled())
}

func shutdownContextWatcher() {
	select {
	case <-ctx.stopCh:
	default:
		close(ctx.stopCh)
	}
}

// ── DETECTOR GOROUTINE ────────────────────────────────────────

func (c *ContextDetector) runDetector() {
	// First check after 10s to let system settle on startup
	time.Sleep(10 * time.Second)
	c.detect()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			log.Println("context: watcher stopped")
			return
		case <-ticker.C:
			c.detect()
		}
	}
}

func (c *ContextDetector) detect() {
	if !c.isEnabled() {
		return
	}

	// Respect manual override window
	c.mu.RLock()
	overrideActive := time.Now().Before(c.manualOverride)
	c.mu.RUnlock()
	if overrideActive {
		return
	}

	best := c.detectBestMode()

	c.mu.Lock()
	changed := best != c.lastDetected && best != ModeUnknown
	c.lastDetected = best
	c.mu.Unlock()

	if changed {
		current := thermal.getMode()
		if current == best {
			return // already in the right mode
		}
		log.Printf("context: auto-switch → %s (was %s)", best, current)
		WriteGoEvent("CONTEXT_AUTO_SWITCH",
			string(best), "ok")
		if err := ApplyProfile(best); err != nil {
			log.Printf("context: auto-switch failed: %v", err)
		}
	}
}

// detectBestMode scans running processes and returns the most
// appropriate thermal mode. Priority: gaming > dev > quiet > dev.
func (c *ContextDetector) detectBestMode() ThermalMode {
	procs, err := process.Processes()
	if err != nil {
		log.Printf("context: process scan failed: %v", err)
		return ModeUnknown
	}

	hasGame := false
	hasDev := false

	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}
		nameLower := strings.ToLower(name)

		if !hasGame {
			for _, g := range gameProcesses {
				if strings.Contains(nameLower, g) {
					hasGame = true
					break
				}
			}
		}
		if !hasDev && !hasGame {
			for _, d := range devProcesses {
				if strings.Contains(nameLower, d) {
					hasDev = true
					break
				}
			}
		}
		if hasGame {
			break
		} // gaming wins — no need to scan further
	}

	switch {
	case hasGame:
		return ModeGaming
	case hasDev:
		return ModeDev
	case isQuietHours():
		return ModeSilent
	default:
		return ModeDev // sensible fallback for typical dev machine
	}
}

func isQuietHours() bool {
	h := time.Now().Hour()
	return h >= quietHourStart || h < quietHourEnd
}

// ── PUBLIC API ────────────────────────────────────────────────

// EnableAutoSwitch toggles automatic mode switching on/off.
// Persists to config.json so the setting survives restarts.
func EnableAutoSwitch(on bool) {
	ctx.mu.Lock()
	ctx.enabled = on
	ctx.mu.Unlock()

	SetDSConfigKey("auto_switch", on)
	WriteGoEvent("AUTO_SWITCH_TOGGLED",
		map[bool]string{true: "enabled", false: "disabled"}[on], "ok")
	log.Printf("context: auto-switch → %v", on)
}

// IsAutoSwitchEnabled returns the current toggle state.
func IsAutoSwitchEnabled() bool { return ctx.isEnabled() }

func (c *ContextDetector) isEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

// SuppressAutoSwitch pauses auto-switching for the override duration.
// Called by tray.go when the user manually selects a profile,
// so a game or IDE launch doesn't immediately override their choice.
func SuppressAutoSwitch() {
	ctx.mu.Lock()
	ctx.manualOverride = time.Now().Add(ctx.overrideDuration)
	ctx.mu.Unlock()
	log.Printf("context: auto-switch suppressed for %v", ctx.overrideDuration)
}

// GetDSConfig reads config.json and returns it as a map.
// Returns nil if the file is missing or malformed.
func GetDSConfig() map[string]interface{} {
	home, _ := os.UserHomeDir()
	data, err := os.ReadFile(filepath.Join(home, ".devshield", "config.json"))
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}

// SetDSConfigKey writes a single key to config.json.
func SetDSConfigKey(key string, value interface{}) {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".devshield", "config.json")

	m := GetDSConfig()
	if m == nil {
		m = map[string]interface{}{}
	}
	m[key] = value

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0644)
}
