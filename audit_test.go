package main

import (
	"testing"
	"time"
)

// closeAudit used to take auditMu.Lock and then call writeAuditDirect,
// which takes auditMu.RLock — a self-deadlock that froze Quit.
func TestCloseAuditDoesNotDeadlock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := initAudit(); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() { closeAudit(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("closeAudit deadlocked")
	}
}
