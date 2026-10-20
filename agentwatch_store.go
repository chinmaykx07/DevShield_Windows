// agentwatch_store.go — Persistent agent register (SQLite, audit.db)
//
// One row per agent installation (agent name + exe path). The status
// column is the sanction decision the user made from the tray:
//
//   unsanctioned — seen, never approved (default for anything new)
//   sanctioned   — approved by the user; no alerts while unchanged
//
// A sanctioned agent whose executable hash changes drops back to
// unsanctioned, so a replaced binary cannot inherit the approval.
//
// Functions take *sql.DB explicitly so they can be tested against a
// throwaway database.

package main

import (
	"database/sql"
	"strings"
)

const (
	AgentUnsanctioned = "unsanctioned"
	AgentSanctioned   = "sanctioned"
)

const createAgentsTable = `
CREATE TABLE IF NOT EXISTS agents (
    fingerprint TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    vendor      TEXT,
    kind        TEXT,
    exe_path    TEXT,
    sha256      TEXT,
    status      TEXT NOT NULL DEFAULT 'unsanctioned',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    last_pid    INTEGER,
    reasons     TEXT
);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
`

// SightingChange tells the caller whether a sighting needs an alert.
type SightingChange int

const (
	SightingSeenBefore  SightingChange = iota // nothing new
	SightingNew                               // first time this agent was ever seen
	SightingHashChanged                       // executable changed since last seen
)

// AgentRecord is one row of the agents table.
type AgentRecord struct {
	Fingerprint string
	Name        string
	Vendor      string
	Kind        string
	ExePath     string
	SHA256      string
	Status      string
	FirstSeen   string
	LastSeen    string
}

func ensureAgentSchema(db *sql.DB) error {
	_, err := db.Exec(createAgentsTable)
	return err
}

// recordSighting upserts one detection and reports whether it is new
// or its executable changed. hash may be empty when the file could not
// be read; an empty hash never counts as a change.
func recordSighting(db *sql.DB, d Detection, hash, now string) (SightingChange, string, error) {
	fp := AgentFingerprint(d)
	reasons := strings.Join(d.Reasons, "; ")

	var status, storedHash string
	err := db.QueryRow(`SELECT status, COALESCE(sha256, '') FROM agents WHERE fingerprint = ?`, fp).
		Scan(&status, &storedHash)

	if err == sql.ErrNoRows {
		_, err = db.Exec(`
			INSERT INTO agents (fingerprint, name, vendor, kind, exe_path, sha256, status,
			                    first_seen, last_seen, last_pid, reasons)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fp, d.Name, d.Vendor, d.Kind, d.Exe, hash, AgentUnsanctioned,
			now, now, d.PID, reasons)
		return SightingNew, AgentUnsanctioned, err
	}
	if err != nil {
		return SightingSeenBefore, "", err
	}

	change := SightingSeenBefore
	if hash != "" && storedHash != "" && hash != storedHash {
		change = SightingHashChanged
		status = AgentUnsanctioned // approval was for the old binary
	}
	if hash == "" {
		hash = storedHash
	}

	_, err = db.Exec(`
		UPDATE agents SET sha256 = ?, status = ?, last_seen = ?, last_pid = ?, reasons = ?
		WHERE fingerprint = ?`,
		hash, status, now, d.PID, reasons, fp)
	return change, status, err
}

// setAgentStatus records the user's sanction decision.
func setAgentStatus(db *sql.DB, fingerprint, status string) error {
	_, err := db.Exec(`UPDATE agents SET status = ? WHERE fingerprint = ?`, status, fingerprint)
	return err
}

// listAgents returns every agent ever seen, most recently seen first.
func listAgents(db *sql.DB) ([]AgentRecord, error) {
	rows, err := db.Query(`
		SELECT fingerprint, name, COALESCE(vendor,''), COALESCE(kind,''), COALESCE(exe_path,''),
		       COALESCE(sha256,''), status, first_seen, last_seen
		FROM agents ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AgentRecord
	for rows.Next() {
		var r AgentRecord
		if err := rows.Scan(&r.Fingerprint, &r.Name, &r.Vendor, &r.Kind, &r.ExePath,
			&r.SHA256, &r.Status, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
