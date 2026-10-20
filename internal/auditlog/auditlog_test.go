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
	l, err := Open(path)
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
	l, err := Open(path)
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

func TestOpenOnTamperedLogStillAppends(t *testing.T) {
	path := newLog(t, 3)
	lines := readLines(t, path)
	lines[0] = strings.Replace(lines[0], `"detail a"`, `"detail x"`, 1)
	writeLines(t, path, lines)

	l, err := Open(path)
	var ce *ChainError
	if !errors.As(err, &ce) || l == nil {
		t.Fatalf("Open should return the log AND a ChainError, got l=%v err=%v", l, err)
	}
	if _, err := l.Append("AUDIT_TAMPER_DETECTED", ce.Error(), "fail", "test"); err != nil {
		t.Fatal(err)
	}
	l.Close()
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
