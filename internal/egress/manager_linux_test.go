package egress

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNft records loaded scripts; check fails when reject is set.
type fakeNft struct {
	mu     sync.Mutex
	loaded []string
	reject bool
}

func (f *fakeNft) run(script string, check bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(script, "list ") {
		if len(f.loaded) > 0 && strings.Contains(f.loaded[len(f.loaded)-1], "chain egress") {
			return nil
		}
		return errors.New("no such table")
	}
	if check {
		if f.reject {
			return errors.New("syntax error")
		}
		return nil
	}
	f.loaded = append(f.loaded, script)
	return nil
}

func (f *fakeNft) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.loaded) == 0 {
		return ""
	}
	return f.loaded[len(f.loaded)-1]
}

func newTestManager(t *testing.T, nft *fakeNft, dir string) *Manager {
	t.Helper()
	m, err := New(Config{StateDir: dir, ProcRoot: t.TempDir(), CgroupRoot: "", Nft: nft.run})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

var wg0 = Lockdown{Interfaces: []string{"wg0"}, Endpoints: []string{"203.0.113.5:51820/udp"}}

func TestUnconfirmedLockdownReverts(t *testing.T) {
	nft, dir := &fakeNft{}, t.TempDir()
	m := newTestManager(t, nft, dir)
	if err := m.LockdownOn(wg0, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nft.last(), `oifname "wg0"`) || m.Status().ConfirmBy.IsZero() {
		t.Fatal("lockdown not applied as pending")
	}
	// A restart during the window must not bring the unconfirmed change back.
	if data, _ := os.ReadFile(filepath.Join(dir, "egress.json")); strings.Contains(string(data), "wg0") {
		t.Fatal("unconfirmed lockdown was persisted")
	}
	time.Sleep(300 * time.Millisecond)
	if strings.Contains(nft.last(), "wg0") || m.Status().Lockdown != nil {
		t.Fatalf("lockdown did not revert:\n%s", nft.last())
	}
}

func TestConfirmedLockdownSurvivesRestart(t *testing.T) {
	nft, dir := &fakeNft{}, t.TempDir()
	m := newTestManager(t, nft, dir)
	if err := m.LockdownOn(wg0, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := m.Confirm(); err != nil {
		t.Fatal(err)
	}
	nft2 := &fakeNft{}
	m2 := newTestManager(t, nft2, dir)
	if m2.Status().Lockdown == nil || !strings.Contains(nft2.last(), `oifname "wg0"`) {
		t.Fatal("confirmed lockdown not re-applied on start")
	}
	if err := m2.LockdownOff(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(nft2.last(), "chain egress") {
		t.Fatal("rules left after lockdown off")
	}
}

func TestRejectedRulesetChangesNothing(t *testing.T) {
	nft := &fakeNft{}
	m := newTestManager(t, nft, t.TempDir())
	nft.reject = true
	before := len(nft.loaded)
	if err := m.LockdownOn(wg0, 0); err == nil {
		t.Fatal("expected error")
	}
	if len(nft.loaded) != before || m.Status().Lockdown != nil {
		t.Fatal("a rejected ruleset changed state")
	}
}

func TestBlockNeedsCgroup2(t *testing.T) {
	m := newTestManager(t, &fakeNft{}, t.TempDir())
	if _, _, err := m.Block("fp", "abcd1234", "x", []int{1}); err == nil || !strings.Contains(err.Error(), "cgroup v2") {
		t.Fatalf("got %v", err)
	}
}

func TestEnsureLoadedRestoresFlushedRules(t *testing.T) {
	nft := &fakeNft{}
	m := newTestManager(t, nft, t.TempDir())
	m.LockdownOn(wg0, 0)
	if again, _ := m.EnsureLoaded(); again {
		t.Fatal("re-applied although rules were loaded")
	}
	nft.loaded = append(nft.loaded, "flush ruleset") // someone else wiped it
	if again, err := m.EnsureLoaded(); !again || err != nil || !strings.Contains(nft.last(), "wg0") {
		t.Fatalf("rules not restored (again=%v err=%v)", again, err)
	}
}

func TestFindCgroup2AndDescendants(t *testing.T) {
	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "self"), 0o755)
	os.WriteFile(filepath.Join(proc, "self", "mountinfo"), []byte(
		"37 24 0:29 / /sys/fs/cgroup rw - tmpfs tmpfs rw\n"+
			"50 37 0:40 / /sys/fs/cgroup/unified rw - cgroup2 cgroup2 rw\n"+
			"51 37 0:40 / /mnt/elsewhere rw - cgroup2 cgroup2 rw\n"), 0o644)
	// Hybrid layout, made reachable under the fake /proc/self/root.
	os.MkdirAll(filepath.Join(proc, "self", "root", "sys/fs/cgroup/unified"), 0o755)
	os.WriteFile(filepath.Join(proc, "self", "root", "sys/fs/cgroup/unified/cgroup.procs"), nil, 0o644)
	if got := findCgroup2(proc); got != "/sys/fs/cgroup/unified" {
		t.Fatalf("cgroup2 mount = %q", got)
	}
	for pid, stat := range map[string]string{
		"100": "100 (agent) S 1 ...",
		"101": "101 (bash) S 100 ...",
		"102": "102 (curl) S 101 ...",
		"200": "200 (weird ) name) S 1 ...",
	} {
		os.MkdirAll(filepath.Join(proc, pid), 0o755)
		os.WriteFile(filepath.Join(proc, pid, "stat"), []byte(stat), 0o644)
	}
	d := descendants(proc, []int{100})
	if len(d) != 2 || !d[101] || !d[102] {
		t.Fatalf("descendants = %v", d)
	}
	if o, ok := originFor(proc, 102, map[int]string{100: "/user.slice"}); !ok || o != "/user.slice" {
		t.Fatalf("origin = %q %v", o, ok)
	}
}
