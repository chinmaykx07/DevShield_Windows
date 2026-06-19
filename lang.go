// lang.go — Language system for the Go tray app
//
// Reads from ~/.devshield/config.json (same file as PS scripts).
// Both the Go app and PS scripts share ONE source of truth.
//
// Three modes: EN | SA | BOTH
// Toggle via tray submenu, or PS: devshield-lang toggle
// watchConfigFile polls every 3s so PS-side changes update the tray live.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ── TYPES ────────────────────────────────────────────────────

type LangMode string

const (
	LangEN   LangMode = "EN"
	LangSA   LangMode = "SA"
	LangBOTH LangMode = "BOTH"
)

// LabelKey identifies a UI string
type LabelKey string

const (
	LblAppTitle  LabelKey = "app_title"
	LblStatus    LabelKey = "status"
	LblModeSilent LabelKey = "mode_silent"
	LblModeGaming LabelKey = "mode_gaming"
	LblModeDev   LabelKey = "mode_dev"
	LblPrivacy   LabelKey = "privacy"
	LblNetwork   LabelKey = "network"
	LblAuditLog  LabelKey = "audit_log"
	LblLanguage  LabelKey = "language"
	LblLangEN    LabelKey = "lang_en"
	LblLangSA    LabelKey = "lang_sa"
	LblLangBOTH  LabelKey = "lang_both"
	LblQuit      LabelKey = "quit"
	LblAlertCount LabelKey = "alert_count"
	LblNoAlerts  LabelKey = "no_alerts"
	LblApplying  LabelKey = "applying"
	LblVerified  LabelKey = "verified"
)

// ── LABEL DICTIONARY ─────────────────────────────────────────
// All UI strings defined once. No hardcoded strings elsewhere.

var labels = map[LabelKey]map[LangMode]string{

	LblAppTitle: {
		LangEN:   "DevShield",
		LangSA:   "कवच-यन्त्र",
		LangBOTH: "DevShield · कवच-यन्त्र",
	},
	LblStatus: {
		LangEN:   "Status",
		LangSA:   "अवस्था",
		LangBOTH: "Status · अवस्था",
	},
	LblModeSilent: {
		LangEN:   "🔇 Silent Summer",
		LangSA:   "🔇 मौन-ग्रीष्म",
		LangBOTH: "🔇 Silent Summer · मौन-ग्रीष्म",
	},
	LblModeGaming: {
		LangEN:   "🎮 Gaming Gear",
		LangSA:   "🎮 क्रीडा-आवृत्ति",
		LangBOTH: "🎮 Gaming Gear · क्रीडा-आवृत्ति",
	},
	LblModeDev: {
		LangEN:   "💻 Dev Mode",
		LangSA:   "💻 विकास-अवस्था",
		LangBOTH: "💻 Dev Mode · विकास-अवस्था",
	},
	LblPrivacy: {
		LangEN:   "🔒 Privacy",
		LangSA:   "🔒 गोपनीयता",
		LangBOTH: "🔒 Privacy · गोपनीयता",
	},
	LblNetwork: {
		LangEN:   "🌐 Network Guardian",
		LangSA:   "🌐 जाल-रक्षक",
		LangBOTH: "🌐 Network · जाल-रक्षक",
	},
	LblAuditLog: {
		LangEN:   "📋 View Audit Log",
		LangSA:   "📋 लेखा-दर्शन",
		LangBOTH: "📋 Audit Log · लेखा-दर्शन",
	},
	LblLanguage: {
		LangEN:   "🌐 Language",
		LangSA:   "🌐 भाषा",
		LangBOTH: "🌐 Language · भाषा",
	},
	LblLangEN: {
		LangEN:   "English only",
		LangSA:   "English only",
		LangBOTH: "English only",
	},
	LblLangSA: {
		LangEN:   "संस्कृत केवलम्",
		LangSA:   "संस्कृत केवलम्",
		LangBOTH: "संस्कृत केवलम्",
	},
	LblLangBOTH: {
		LangEN:   "English + Sanskrit (Both)",
		LangSA:   "English + Sanskrit (Both)",
		LangBOTH: "English + Sanskrit (Both)",
	},
	LblQuit: {
		LangEN:   "✕ Quit",
		LangSA:   "✕ विराम",
		LangBOTH: "✕ Quit · विराम",
	},
	LblAlertCount: {
		LangEN:   "%d alerts",
		LangSA:   "%d चेतावनी",
		LangBOTH: "%d alerts · %d चेतावनी",
	},
	LblNoAlerts: {
		LangEN:   "No alerts",
		LangSA:   "चेतावनी नास्ति",
		LangBOTH: "No alerts · चेतावनी नास्ति",
	},
	LblApplying: {
		LangEN:   "Applying...",
		LangSA:   "प्रयोग चालु...",
		LangBOTH: "Applying · प्रयोग चालु...",
	},
	LblVerified: {
		LangEN:   "✅ Verified",
		LangSA:   "✅ प्रमाणित",
		LangBOTH: "✅ Verified · प्रमाणित",
	},
}

// ── LANGUAGE MANAGER ─────────────────────────────────────────

type LangManager struct {
	mu         sync.RWMutex
	current    LangMode
	configPath string
	onChange   []func(LangMode) // callbacks — tray rebuilds on change
}

var lang = &LangManager{}

// initLang loads the language from config.json and starts the file
// watcher goroutine so PS-side language changes update the tray live.
// Must be called before any other subsystem that calls T() or bilingual().
func initLang() {
	home, _ := os.UserHomeDir()
	lang.configPath = filepath.Join(home, ".devshield", "config.json")
	lang.current = lang.readFromDisk()

	// Watch for external changes (e.g. user ran `devshield-lang SA` in PS)
	go watchConfigFile()
}

// ── TRANSLATION ──────────────────────────────────────────────

// T translates a label key to the current language.
// Falls back to BOTH (bilingual) if the specific mode has no entry.
func T(key LabelKey) string {
	lang.mu.RLock()
	defer lang.mu.RUnlock()

	m, ok := labels[key]
	if !ok {
		return string(key) // fallback: return the key itself
	}
	s, ok := m[lang.current]
	if !ok {
		return m[LangBOTH] // fallback: bilingual
	}
	return s
}

// TFmt translates a key and applies fmt.Sprintf substitution.
// Useful for labels with dynamic values (e.g. alert counts).
func TFmt(key LabelKey, args ...any) string {
	return fmt.Sprintf(T(key), args...)
}

// ── LANG MANAGER METHODS ─────────────────────────────────────

func (l *LangManager) Get() LangMode {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.current
}

// Set writes the new language to disk and fires all registered callbacks.
func (l *LangManager) Set(m LangMode) {
	l.mu.Lock()
	l.current = m
	l.mu.Unlock()

	l.writeToDisk(m)

	// Fire callbacks — tray.go registered updateMenuLabels via lang.OnChange
	l.mu.RLock()
	cbs := l.onChange
	l.mu.RUnlock()
	for _, cb := range cbs {
		go cb(m)
	}
}

// Toggle cycles BOTH → EN → SA → BOTH.
func (l *LangManager) Toggle() LangMode {
	l.mu.RLock()
	cur := l.current
	l.mu.RUnlock()

	next := map[LangMode]LangMode{
		LangBOTH: LangEN,
		LangEN:   LangSA,
		LangSA:   LangBOTH,
	}[cur]

	l.Set(next)
	return next
}

// OnChange registers a callback fired when language changes.
// tray.go registers updateMenuLabels() here on startup.
func (l *LangManager) OnChange(cb func(LangMode)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onChange = append(l.onChange, cb)
}

// ── DISK I/O ─────────────────────────────────────────────────

// readFromDisk parses config.json and returns the language setting.
// Uses map[string]interface{} so any unknown keys are left untouched.
func (l *LangManager) readFromDisk() LangMode {
	data, err := os.ReadFile(l.configPath)
	if err != nil {
		return LangBOTH // safe default — file may not exist on first run
	}
	var m map[string]interface{}
	if err = json.Unmarshal(data, &m); err != nil {
		return LangBOTH
	}
	if langStr, ok := m["language"].(string); ok {
		switch LangMode(langStr) {
		case LangEN, LangSA, LangBOTH:
			return LangMode(langStr)
		}
	}
	return LangBOTH
}

// writeToDisk persists the language change.
// Reads the full config first so keys written by other subsystems
// (e.g. auto_switch from context.go) are preserved in the round-trip.
func (l *LangManager) writeToDisk(m LangMode) {
	// Read full config into a generic map to preserve every key
	cfg := make(map[string]interface{})
	if data, err := os.ReadFile(l.configPath); err == nil {
		json.Unmarshal(data, &cfg)
	}

	// Update only the language fields
	cfg["language"]         = string(m)
	cfg["language_changed"] = time.Now().Format(time.RFC3339)

	if b, err := json.MarshalIndent(cfg, "", "  "); err == nil {
		os.WriteFile(l.configPath, b, 0644)
	}
}

// ── CONFIG FILE WATCHER ───────────────────────────────────────

// watchConfigFile polls config.json every 3 seconds for external changes.
// Covers the case where a PS script changes the language (devshield-lang SA)
// and the tray needs to reflect it without a restart.
// Started by initLang() as a goroutine.
func watchConfigFile() {
	lastLang := lang.Get()
	for {
		time.Sleep(3 * time.Second)
		newLang := lang.readFromDisk()
		if newLang != lastLang {
			lastLang = newLang

			lang.mu.Lock()
			lang.current = newLang
			cbs := lang.onChange
			lang.mu.Unlock()

			// Fire callbacks — tray.go's updateMenuLabels() is registered here
			for _, cb := range cbs {
				go cb(newLang)
			}
		}
	}
}
