package daemon

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/chinmaykx07/DevShield_Windows/internal/egress"
	"github.com/chinmaykx07/DevShield_Windows/internal/ipc"
)

func withAccounts(t *testing.T, accounts map[string]int) {
	old := lookupUser
	lookupUser = func(s string) (int, error) {
		if uid, ok := accounts[s]; ok {
			return uid, nil
		}
		return 0, errors.New("unknown user " + s)
	}
	t.Cleanup(func() { lookupUser = old })
}

func TestTorFindsTheDaemonAccount(t *testing.T) {
	withAccounts(t, map[string]int{"tor": 107, "alice": 1000})
	l, err := lockdownFrom(&ipc.LockdownRequest{Tor: true, Users: []string{"alice"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(l.Users, []int{1000, 107}) {
		t.Fatalf("users = %v, want alice then the tor account", l.Users)
	}
}

func TestTorPrefersTheFirstKnownName(t *testing.T) {
	withAccounts(t, map[string]int{"debian-tor": 120, "tor": 107})
	l, err := lockdownFrom(&ipc.LockdownRequest{Tor: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(l.Users, []int{120}) {
		t.Fatalf("users = %v, want only debian-tor's uid", l.Users)
	}
}

func TestTorWithoutAccountIsRefused(t *testing.T) {
	withAccounts(t, map[string]int{})
	_, err := lockdownFrom(&ipc.LockdownRequest{Tor: true})
	if err == nil || !strings.Contains(err.Error(), "no Tor daemon account") {
		t.Fatalf("err = %v, want a refusal naming the missing Tor account", err)
	}
}

func TestLockdownUnknownUserIsRefused(t *testing.T) {
	withAccounts(t, map[string]int{})
	if _, err := lockdownFrom(&ipc.LockdownRequest{Users: []string{"ghost"}}); err == nil {
		t.Fatal("an unknown user was accepted")
	}
	if _, err := lockdownFrom(&ipc.LockdownRequest{}); err == nil {
		t.Fatal("a lockdown that lets nothing out was accepted")
	}
}

// A lasting problem is logged once, not every 10 s; a new error, a
// recovery and a later relapse are each logged.
func TestRulesHealthLogsChangesOnly(t *testing.T) {
	var h rulesHealth
	broken, other := errors.New("nft: not found"), errors.New("nft: permission denied")
	steps := []struct {
		again bool
		err   error
		want  string
	}{
		{true, broken, "EGRESS_RULES_MISSING"},
		{true, broken, ""},
		{true, broken, ""},
		{true, other, "EGRESS_RULES_MISSING"},
		{true, nil, "EGRESS_RULES_RESTORED"},
		{false, nil, ""},
		{false, egress.ErrUnverifiable, "EGRESS_RULES_UNVERIFIABLE"},
		{false, egress.ErrUnverifiable, ""},
		{true, broken, "EGRESS_RULES_MISSING"},
		{false, nil, ""},
		{true, broken, "EGRESS_RULES_MISSING"},
	}
	for i, s := range steps {
		if got, _, _ := h.next(s.again, s.err); got != s.want {
			t.Fatalf("step %d: got %q, want %q", i, got, s.want)
		}
	}
}
