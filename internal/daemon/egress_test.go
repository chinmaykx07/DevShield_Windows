package daemon

import (
	"errors"
	"reflect"
	"strings"
	"testing"

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
