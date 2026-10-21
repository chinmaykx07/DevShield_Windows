package auditlog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newLog(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := l.Append("EVENT", "detail "+string(rune('a'+i)), "ok", "test"); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	return path
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func wantTamper(t *testing.T, path, fragment string) {
	t.Helper()
	_, err := Verify(path)
	var ce *ChainError
	if !errors.As(err, &ce) {
		t.Fatalf("tampering not detected (err=%v)", err)
	}
	if !strings.Contains(ce.Error(), fragment) {
		t.Fatalf("unexpected reason %q, want it to mention %q", ce.Error(), fragment)
	}
}

func TestIntactLogVerifiesAndSurvivesReopen(t *testing.T) {
	path := newLog(t, 5)
	l, _, err := Open(path)
	if err != nil {
		t.Fatalf("reopen of intact log: %v", err)
	}
	r, _ := l.Append("MORE", "", "ok", "test")
	l.Close()
	if r.Seq != 6 {
		t.Fatalf("chain did not continue after reopen: seq %d", r.Seq)
	}
	if n, err := Verify(path); err != nil || n != 6 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("log file mode %v, want 0600", info.Mode().Perm())
	}
}

func TestEditedRecordIsDetected(t *testing.T) {
	path := newLog(t, 5)
	lines := readLines(t, path)
	lines[2] = strings.Replace(lines[2], `"detail c"`, `"detail innocent"`, 1)
	writeLines(t, path, lines)
	wantTamper(t, path, "line 3")
}

func TestDeletedRecordIsDetected(t *testing.T) {
	path := newLog(t, 5)
	lines := readLines(t, path)
	writeLines(t, path, append(lines[:3:3], lines[4:]...)) // drop record 4
	wantTamper(t, path, "line 4")
}

func TestReorderedRecordsAreDetected(t *testing.T) {
	path := newLog(t, 5)
	lines := readLines(t, path)
	lines[1], lines[2] = lines[2], lines[1]
	writeLines(t, path, lines)
	wantTamper(t, path, "line 2")
}

func TestTruncatedTailIsDetected(t *testing.T) {
	path := newLog(t, 5)
	writeLines(t, path, readLines(t, path)[:3]) // cut the last two
	wantTamper(t, path, "truncated")
}

func TestDeletedFileIsDetected(t *testing.T) {
	path := newLog(t, 3)
	os.Remove(path)
	wantTamper(t, path, "missing")
}

func TestRecomputedHashStillBreaksTheChain(t *testing.T) {
	// An attacker who edits a record AND recomputes its hash still breaks
	// the link from the next record.
	path := newLog(t, 4)
	lines := readLines(t, path)
	r := mustParse(t, lines[1])
	r.Detail = "rewritten"
	r.Hash = computeHash(r)
	lines[1] = mustMarshal(t, r)
	writeLines(t, path, lines)
	wantTamper(t, path, "line 3")
}

// A broken log is kept aside as evidence and a fresh log is started, so
// records written afterwards verify (appending onto the broken file used to
// reuse sequence numbers and could never verify again).
func TestOpenOnTamperedLogStartsFreshAndKeepsEvidence(t *testing.T) {
	path := newLog(t, 3)
	lines := readLines(t, path)
	lines[0] = strings.Replace(lines[0], `"detail a"`, `"detail x"`, 1)
	writeLines(t, path, lines)

	l, info, err := Open(path)
	if err != nil || l == nil || info.Broken == nil || info.Aside == "" {
		t.Fatalf("Open = %v, %+v, %v", l, info, err)
	}
	if _, err := l.Append("AUDIT_TAMPER_DETECTED", info.Broken.Error(), "fail", "test"); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if n, err := Verify(path); err != nil || n != 1 {
		t.Fatalf("new log after a break does not verify: %d %v", n, err)
	}
	if _, err := Verify(info.Aside); err == nil {
		t.Fatal("the evidence file no longer shows the break")
	}
}

// Verifying while another goroutine appends must never report tampering
// (found in review: 1 false report in 3000 runs).
func TestVerifyDuringAppendsIsNotTamper(t *testing.T) {
	path := newLog(t, 1)
	l, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 400; i++ {
			l.Append("X", strings.Repeat("d", i%50), "ok", "test")
		}
	}()
	for {
		select {
		case <-done:
			l.Close()
			return
		default:
			if _, err := Verify(path); err != nil {
				t.Fatalf("false tamper report during appends: %v", err)
			}
		}
	}
}

// A record cut short by a crash (never confirmed by the head) is removed
// on open instead of breaking the log forever.
func TestTornFinalRecordIsTrimmed(t *testing.T) {
	path := newLog(t, 3)
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"seq":4,"time":"2026-`)
	f.Close()
	l, info, err := Open(path)
	if err != nil || info.Broken != nil || info.TornBytes == 0 {
		t.Fatalf("Open = %+v, %v", info, err)
	}
	if r, _ := l.Append("NEXT", "", "ok", "test"); r.Seq != 4 {
		t.Fatalf("next seq %d, want 4", r.Seq)
	}
	l.Close()
	if n, err := Verify(path); err != nil || n != 4 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
}

func TestTail(t *testing.T) {
	path := newLog(t, 5)
	recs, err := Tail(path, 2)
	if err != nil || len(recs) != 2 || recs[0].Seq != 4 || recs[1].Seq != 5 {
		t.Fatalf("Tail = %+v, %v", recs, err)
	}
}

func mustParse(t *testing.T, line string) Record {
	t.Helper()
	var r Record
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func mustMarshal(t *testing.T, r Record) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Deleting the last records AND the head must not verify as intact (found
// in the 2026-10-21 self-review).
func TestMissingHeadIsReported(t *testing.T) {
	path := newLog(t, 4)
	lines := readLines(t, path)
	writeLines(t, path, lines[:2]) // truncate...
	os.Remove(path + ".head")      // ...and hide it
	wantTamper(t, path, "head file missing")
}

// The innocent case: verifying while the very first records are written
// (the record lands before the head) must not be reported as tampering.
func TestVerifyDuringFirstAppendsIsNotTamper(t *testing.T) {
	for round := 0; round < 50; round++ {
		path := filepath.Join(t.TempDir(), "audit.log")
		l, _, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; i < 3; i++ {
				l.Append("X", "", "ok", "test")
			}
		}()
		for running := true; running; {
			select {
			case <-done:
				running = false
			default:
				if _, err := Verify(path); err != nil {
					t.Fatalf("round %d: false tamper report during first appends: %v", round, err)
				}
			}
		}
		l.Close()
	}
}

// Deterministic version of the race: a record is appended exactly between
// verify's two reads. Reading the head first makes this harmless; reading
// the log first would see a head newer than the file ("truncated").
func TestAppendBetweenVerifyReadsIsNotTamper(t *testing.T) {
	path := newLog(t, 2)
	l, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	betweenReads = func() { l.Append("BETWEEN", "", "ok", "test") }
	defer func() { betweenReads = nil }()
	if _, err := Verify(path); err != nil {
		t.Fatalf("append between reads reported as tampering: %v", err)
	}
}

// A write that fails midway (disk full) must not leave half a record that
// the next append continues on the same line: that made a full disk look
// like tampering.
func TestFailedWriteLeavesNoPartialRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Append("EVENT", "first", "ok", "test"); err != nil {
		t.Fatal(err)
	}
	old := writeRecord
	writeRecord = func(f *os.File, b []byte) (int, error) {
		n, _ := f.Write(b[:len(b)/2])
		return n, errors.New("no space left on device")
	}
	_, err = l.Append("EVENT", "lost", "ok", "test")
	writeRecord = old
	if err == nil {
		t.Fatal("failed write reported as success")
	}
	if _, err := l.Append("EVENT", "after", "ok", "test"); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(path); err != nil || n != 2 {
		t.Fatalf("Verify = %d, %v (want 2 intact records)", n, err)
	}
}
