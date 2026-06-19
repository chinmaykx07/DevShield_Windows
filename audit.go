// audit.go — DevShield audit log system
//
// Architecture (from the plan):
//   PS scripts write JSON files → ~/.devshield/events/evt_*.json
//   This goroutine watches that folder every 2 seconds
//   Reads each file → inserts into SQLite → deletes the file
//   PS scripts never touch SQLite directly — zero PS-side dependency
//
// The tray app, dashboard, and profile manager all read from
// this database for alert counts, history, and state.

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	// Pure Go SQLite — no CGO required beyond systray's needs
	_ "modernc.org/sqlite"
)

// ── SCHEMA ───────────────────────────────────────────────────

const createEventsTable = `
CREATE TABLE IF NOT EXISTS events (
    id           TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    action       TEXT NOT NULL,
    detail       TEXT,
    mode         TEXT,
    rollback_json TEXT,
    status       TEXT DEFAULT 'ok',
    source       TEXT DEFAULT 'powershell',
    inserted_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_action    ON events(action);
CREATE INDEX IF NOT EXISTS idx_events_status    ON events(status);
`

// ── TYPES ────────────────────────────────────────────────────

// AuditEvent mirrors the JSON written by PS scripts
type AuditEvent struct {
	ID           string `json:"id"`
	Timestamp    string `json:"timestamp"`
	Action       string `json:"action"`
	Detail       string `json:"detail"`
	Mode         string `json:"mode"`
	RollbackJSON string `json:"rollback_json"`
	Status       string `json:"status"`
	Source       string `json:"source"`
}

// ── MODULE STATE ─────────────────────────────────────────────

var (
	auditDB      *sql.DB
	auditMu      sync.RWMutex
	auditReady   bool
	eventsDir    string
	auditDBPath  string
)

// ── INIT ─────────────────────────────────────────────────────

// initAudit opens (or creates) the SQLite database and starts
// the event watcher goroutine.
func initAudit() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("audit: cannot find home dir: %w", err)
	}

	dsHome      := filepath.Join(home, ".devshield")
	eventsDir    = filepath.Join(dsHome, "events")
	auditDBPath  = filepath.Join(dsHome, "audit.db")

	// Ensure directories exist
	for _, d := range []string{dsHome, eventsDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("audit: mkdir %s: %w", d, err)
		}
	}

	// Open SQLite
	db, err := sql.Open("sqlite", auditDBPath)
	if err != nil {
		return fmt.Errorf("audit: open db: %w", err)
	}

	// Tuning: WAL mode for concurrent readers, busy timeout for writes
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=3000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			log.Printf("audit: pragma warning (%s): %v", pragma, err)
		}
	}

	// Create schema
	if _, err := db.Exec(createEventsTable); err != nil {
		return fmt.Errorf("audit: create table: %w", err)
	}

	auditMu.Lock()
	auditDB    = db
	auditReady = true
	auditMu.Unlock()

	// Write our own startup event
	writeAuditDirect(AuditEvent{
		ID:        generateID(),
		Timestamp: nowISO(),
		Action:    "TRAY_STARTED",
		Detail:    fmt.Sprintf("DevShield tray v%s", dsVersion),
		Status:    "ok",
		Source:    "go",
	})

	// Start event watcher goroutine
	go runEventWatcher()

	return nil
}

// closeAudit flushes and closes the database.
func closeAudit() {
	auditMu.Lock()
	defer auditMu.Unlock()
	if auditDB != nil {
		writeAuditDirect(AuditEvent{
			ID:        generateID(),
			Timestamp: nowISO(),
			Action:    "TRAY_STOPPED",
			Status:    "ok",
			Source:    "go",
		})
		_ = auditDB.Close()
		auditDB    = nil
		auditReady = false
	}
}

// ── EVENT FILE WATCHER ────────────────────────────────────────

// runEventWatcher polls eventsDir every 2 seconds.
// Picks up any evt_*.json files written by PS scripts,
// inserts them into SQLite, then deletes the file.
func runEventWatcher() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		auditMu.RLock()
		ready := auditReady
		auditMu.RUnlock()
		if !ready { continue }

		processEventQueue()
	}
}

func processEventQueue() {
	matches, err := filepath.Glob(filepath.Join(eventsDir, "evt_*.json"))
	if err != nil || len(matches) == 0 { return }

	for _, path := range matches {
		if err := processEventFile(path); err != nil {
			log.Printf("audit: process %s: %v", filepath.Base(path), err)
		}
	}
}

func processEventFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil { return err }

	var evt AuditEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		// File may still be mid-write by PS — skip this tick, retry next
		return nil
	}

	// Ensure required fields
	if evt.ID        == "" { evt.ID        = generateID() }
	if evt.Timestamp == "" { evt.Timestamp = nowISO() }
	if evt.Status    == "" { evt.Status    = "ok" }
	if evt.Source    == "" { evt.Source    = "powershell" }

	if err := writeAuditDirect(evt); err != nil {
		return fmt.Errorf("insert: %w", err)
	}

	// Delete the source file — it is now in SQLite
	return os.Remove(path)
}

// ── WRITE ─────────────────────────────────────────────────────

// writeAuditDirect inserts one event. Safe to call from any goroutine.
func writeAuditDirect(evt AuditEvent) error {
	auditMu.RLock()
	db := auditDB
	auditMu.RUnlock()
	if db == nil { return nil }

	_, err := db.Exec(`
		INSERT OR REPLACE INTO events
			(id, timestamp, action, detail, mode, rollback_json, status, source, inserted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		evt.ID, evt.Timestamp, evt.Action,
		evt.Detail, evt.Mode, evt.RollbackJSON,
		evt.Status, evt.Source, nowISO(),
	)
	return err
}

// WriteGoEvent writes a Go-side event directly (no JSON file needed).
func WriteGoEvent(action, detail, status string) {
	_ = writeAuditDirect(AuditEvent{
		ID:        generateID(),
		Timestamp: nowISO(),
		Action:    action,
		Detail:    detail,
		Status:    status,
		Source:    "go",
	})
}

// ── QUERY API ─────────────────────────────────────────────────

// GetRecentEvents returns the N most recent events, newest first.
func GetRecentEvents(n int) []AuditEvent {
	return queryEvents(`
		SELECT id, timestamp, action, detail, mode, rollback_json, status, source
		FROM events
		ORDER BY timestamp DESC
		LIMIT ?`, n)
}

// GetAlertCount returns the count of unacknowledged guardian alerts.
func GetAlertCount() int {
	auditMu.RLock()
	db := auditDB
	auditMu.RUnlock()
	if db == nil { return 0 }

	var count int
	_ = db.QueryRow(`
		SELECT COUNT(*) FROM events
		WHERE action LIKE 'GUARDIAN_%ALERT%'
		  AND status = 'warn'
		  AND date(timestamp) = date('now')
	`).Scan(&count)
	return count
}

// GetGuardianAlerts returns recent network guardian alerts.
func GetGuardianAlerts(n int) []AuditEvent {
	return queryEvents(`
		SELECT id, timestamp, action, detail, mode, rollback_json, status, source
		FROM events
		WHERE action LIKE 'GUARDIAN_%'
		  AND status IN ('warn', 'fail')
		ORDER BY timestamp DESC
		LIMIT ?`, n)
}

// GetThermalHistory returns recent thermal profile changes.
func GetThermalHistory(n int) []AuditEvent {
	return queryEvents(`
		SELECT id, timestamp, action, detail, mode, rollback_json, status, source
		FROM events
		WHERE action IN (
			'SILENT_SUMMER_APPLIED','GAMING_GEAR_APPLIED',
			'DEV_MODE_APPLIED','ROLLBACK_POWERCFG_SILENT',
			'ROLLBACK_POWERCFG_GAMING','ROLLBACK_POWERCFG_DEV'
		)
		ORDER BY timestamp DESC
		LIMIT ?`, n)
}

// GetLatestModeChange returns the most recent thermal profile event.
func GetLatestModeChange() *AuditEvent {
	evts := GetThermalHistory(1)
	if len(evts) == 0 { return nil }
	return &evts[0]
}

// GetTodayAlertSummary returns a human-readable summary of today's alerts.
// Used for the tray tooltip.
func GetTodayAlertSummary() string {
	n := GetAlertCount()
	switch {
	case n == 0:
		return "No alerts today"
	case n == 1:
		return "1 network alert today"
	default:
		return fmt.Sprintf("%d network alerts today", n)
	}
}

// ── QUERY HELPER ──────────────────────────────────────────────

func queryEvents(query string, args ...any) []AuditEvent {
	auditMu.RLock()
	db := auditDB
	auditMu.RUnlock()
	if db == nil { return nil }

	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("audit: query: %v", err)
		return nil
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var detail, mode, rollback, source sql.NullString
		if err := rows.Scan(
			&e.ID, &e.Timestamp, &e.Action,
			&detail, &mode, &rollback,
			&e.Status, &source,
		); err != nil {
			continue
		}
		e.Detail       = detail.String
		e.Mode         = mode.String
		e.RollbackJSON = rollback.String
		e.Source       = source.String
		events = append(events, e)
	}
	return events
}

// ── UTILITIES ─────────────────────────────────────────────────

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func generateID() string {
	// 12-char hex from current nanoseconds — matches PS script format
	return fmt.Sprintf("%012x", time.Now().UnixNano()&0xFFFFFFFFFFFF)
}
