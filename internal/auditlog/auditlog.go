// Package auditlog is DevShield's tamper-evident audit log.
//
// Each event is one JSON line carrying a sequence number and the SHA-256
// of the previous line's hash plus its own content. Editing, deleting,
// reordering or inserting any line breaks the chain at that point, and
// Verify reports where. A separate head file records the latest sequence
// number and hash, so cutting lines off the END is detected too.
//
// What this does NOT protect against: someone who can rewrite both files
// consistently (root, in the Linux daemon's setup). The files are created
// 0600 inside a root-only directory, so a user-level agent can neither
// read nor change them. Signing the head with a key outside the machine
// would close that gap and is a later step.
package auditlog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// genesis is the "previous hash" of the first record.
const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Record is one audit event.
type Record struct {
	Seq    uint64 `json:"seq"`
	Time   string `json:"time"`
	Action string `json:"action"`
	Detail string `json:"detail,omitempty"`
	Status string `json:"status"`
	Source string `json:"source,omitempty"`
	Prev   string `json:"prev"`
	Hash   string `json:"hash"`
}

// computeHash covers every field except Hash itself, in a fixed order.
func computeHash(r Record) string {
	r.Hash = ""
	body, _ := json.Marshal(r) // struct field order is fixed → deterministic
	sum := sha256.Sum256(append([]byte(r.Prev+"\n"), body...))
	return hex.EncodeToString(sum[:])
}

// ChainError says where and why verification failed.
type ChainError struct {
	Line   int    // 1-based line number in the log file (0 = head file)
	Seq    uint64 // sequence number expected at that point
	Reason string
}

func (e *ChainError) Error() string {
	if e.Line == 0 {
		return fmt.Sprintf("audit log tampered: %s", e.Reason)
	}
	return fmt.Sprintf("audit log tampered at line %d (expected seq %d): %s", e.Line, e.Seq, e.Reason)
}

// Log is an open, append-only audit log. Safe for concurrent use.
type Log struct {
	mu   sync.Mutex
	path string
	f    *os.File
	seq  uint64
	head string
}

func headPath(path string) string { return path + ".head" }

// Open opens (or creates) the log at path and verifies it. When the chain
// is broken it still returns a usable Log — appending continues from the
// last stored record — together with a *ChainError, so the caller can
// record the tampering instead of going blind.
func Open(path string) (*Log, error) {
	n, last, verr := verify(path)
	if verr != nil && !errors.As(verr, new(*ChainError)) {
		return nil, verr // I/O error, not tampering
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Log{path: path, f: f, seq: 0, head: genesis}
	if n > 0 {
		l.seq, l.head = last.Seq, last.Hash
	}
	return l, verr
}

// Append writes one event and makes it durable before returning.
func (l *Log) Append(action, detail, status, source string) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	r := Record{
		Seq:    l.seq + 1,
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		Action: action,
		Detail: detail,
		Status: status,
		Source: source,
		Prev:   l.head,
	}
	r.Hash = computeHash(r)
	line, err := json.Marshal(r)
	if err != nil {
		return Record{}, err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return Record{}, err
	}
	if err := l.f.Sync(); err != nil {
		return Record{}, err
	}
	if err := writeHead(l.path, r.Seq, r.Hash); err != nil {
		return Record{}, err
	}
	l.seq, l.head = r.Seq, r.Hash
	return r, nil
}

// Close closes the log file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// writeHead atomically replaces the head file ("seq hash").
func writeHead(path string, seq uint64, hash string) error {
	tmp := headPath(path) + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d %s\n", seq, hash)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, headPath(path))
}

func readHead(path string) (uint64, string, bool) {
	data, err := os.ReadFile(headPath(path))
	if err != nil {
		return 0, "", false
	}
	var seq uint64
	var hash string
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d %s", &seq, &hash); err != nil {
		return 0, "", false
	}
	return seq, hash, true
}

// Verify checks the whole chain and returns how many records are valid.
// A nil error means the log is intact.
func Verify(path string) (int, error) {
	n, _, err := verify(path)
	return n, err
}

func verify(path string) (int, Record, error) {
	var last Record
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		if seq, _, ok := readHead(path); ok && seq > 0 {
			return 0, last, &ChainError{Reason: fmt.Sprintf("log file missing but head says %d records", seq)}
		}
		return 0, last, nil
	}
	if err != nil {
		return 0, last, err
	}
	defer f.Close()

	prev, n := genesis, 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		lineNo := n + 1
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return n, last, &ChainError{Line: lineNo, Seq: uint64(lineNo), Reason: "unparseable record"}
		}
		switch {
		case r.Seq != uint64(lineNo):
			return n, last, &ChainError{Line: lineNo, Seq: uint64(lineNo), Reason: fmt.Sprintf("sequence %d out of order (record missing or inserted)", r.Seq)}
		case r.Prev != prev:
			return n, last, &ChainError{Line: lineNo, Seq: uint64(lineNo), Reason: "does not link to the previous record (record removed, reordered or edited)"}
		case computeHash(r) != r.Hash:
			return n, last, &ChainError{Line: lineNo, Seq: uint64(lineNo), Reason: "content does not match its hash (record edited)"}
		}
		prev, last, n = r.Hash, r, n+1
	}
	if err := sc.Err(); err != nil {
		return n, last, err
	}

	if seq, hash, ok := readHead(path); ok {
		if seq > uint64(n) {
			return n, last, &ChainError{Reason: fmt.Sprintf("log truncated: head says %d records, file has %d", seq, n)}
		}
		if seq == uint64(n) && n > 0 && hash != last.Hash {
			return n, last, &ChainError{Reason: "last record does not match the head (log rewritten)"}
		}
	}
	return n, last, nil
}

// Tail returns up to n most recent records (without verifying).
func Tail(path string, n int) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var ring []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var r Record
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		ring = append(ring, r)
		if len(ring) > n {
			ring = ring[1:]
		}
	}
	return ring, sc.Err()
}
