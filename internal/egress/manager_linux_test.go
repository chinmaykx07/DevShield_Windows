package egress

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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
	if check {
		if f.reject {
			return errors.New("syntax error")
		}
		return nil
	}
	f.loaded = append(f.loaded, script)
	return nil
}

// list returns what the kernel would hold: the last loaded script.
func (f *fakeNft) list() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.loaded) == 0 || !strings.Contains(f.loaded[len(f.loaded)-1], "chain egress") {
		return "", errors.New("no such table")
	}
	return f.loaded[len(f.loaded)-1], nil
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
	m, err := New(Config{StateDir: dir, ProcRoot: t.TempDir(), CgroupRoot: "", Nft: nft.run, NftList: nft.list})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

var wg0 = Lockdown{Interfaces: []string{"wg0"}, Endpoints: []string{"203.0.113.5:51820/udp"}}

func TestUnconfirmedLockdownReverts(t *testing.T) {
	MinConfirm = 0
	defer func() { MinConfirm = 10 * time.Second }()
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
	if _, _, err := m.Block("fp", "abcd1234", "x", []Proc{{PID: 1}}); err == nil || !strings.Contains(err.Error(), "cgroup v2") {
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
	// Removing just the final drop (table still there) is caught too.
	nft.loaded = append(nft.loaded, strings.Replace(nft.last(), "counter drop comment \"devshield lockdown: everything else\"", "", 1))
	if again, _ := m.EnsureLoaded(); !again {
		t.Fatal("a removed rule inside the table went unnoticed")
	}
}

// testdata holds a ruleset DevShield rendered and the same ruleset as nft
// 1.0.9 listed it back from the kernel (counters, sorted sets, reordered
// matches): they must compare equal, and any real edit must not.
func TestCanonRulesMatchRealNftListing(t *testing.T) {
	r, _ := os.ReadFile("testdata/rendered.nft")
	l, _ := os.ReadFile("testdata/listed-by-nft-1.0.9.nft")
	want, have := canonRules(string(r)), canonRules(string(l))
	if len(want) < 20 || !slices.Equal(want, have) {
		t.Fatalf("rendered and listed differ:\n%v\n%v", want, have)
	}
	for _, edit := range [][2]string{
		{`oifname "wg0" accept`, `oifname "eth0" accept`},            // tunnel swapped
		{"203.0.113.5", "203.0.113.6"},                               // endpoint moved
		{"meta skuid 65534", "meta skuid 0"},                         // allowed user changed
		{"devshield lockdown: everything else\"", "x\""},             // comment is part of the rule too
		{"ct original proto-dst 22 ", "ct original proto-dst 8000 "}, // reply port widened
	} {
		tampered := strings.Replace(string(l), edit[0], edit[1], 1)
		if tampered == string(l) {
			t.Fatalf("test edit %q not found", edit[0])
		}
		if slices.Equal(want, canonRules(tampered)) {
			t.Errorf("edit %q -> %q not detected", edit[0], edit[1])
		}
	}
}

func TestTidyKeepsOnlyFlowsOwnedByQuarantinedProcesses(t *testing.T) {
	proc, cg := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(proc, "net"), 0o755)
	os.MkdirAll(filepath.Join(proc, "4242", "fd"), 0o755)
	os.MkdirAll(filepath.Join(cg, QuarantineCgroup), 0o755)
	os.WriteFile(filepath.Join(cg, QuarantineCgroup, "cgroup.procs"), []byte("4242\n"), 0o644)
	// 127.0.0.1:631 is owned by quarantined 4242 (socket inode 18311);
	// 8080 is now some other program's (inode 99) and must lose the rule.
	os.Symlink("socket:[18311]", filepath.Join(proc, "4242", "fd", "3"))
	os.WriteFile(filepath.Join(proc, "net", "tcp"), []byte("  sl  local_address rem_address   st\n"+
		"   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18311 1\n"+
		"   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99 1\n"), 0o644)
	m := &Manager{cfg: Config{ProcRoot: proc}, cgRoot: cg, st: state{Blocked: map[string]*Member{"fp": {
		Origins: map[int]string{4242: "/a", 999999: "/b"},
		Flows:   []Flow{{Proto: "tcp", LocalIP: "127.0.0.1", LocalPort: 631}, {Proto: "tcp", LocalPort: 8080}},
	}}}}
	if !m.tidy() {
		t.Fatal("tidy reported no change")
	}
	b := m.st.Blocked["fp"]
	if len(b.Flows) != 1 || b.Flows[0].LocalPort != 631 || len(b.Origins) != 1 || b.Origins[4242] != "/a" {
		t.Fatalf("after tidy: %+v", b)
	}
}

// An unconfirmed lockdown must never reach disk, whatever else saves
// meanwhile, and the revert must be saved (found in review).
func TestUnconfirmedLockdownNeverPersisted(t *testing.T) {
	MinConfirm = 0
	defer func() { MinConfirm = 10 * time.Second }()
	nft, dir := &fakeNft{}, t.TempDir()
	m := newTestManager(t, nft, dir)
	if err := m.LockdownOn(wg0, 80*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.save() // e.g. Reconcile or Block saving during the window
	m.mu.Unlock()
	if data, _ := os.ReadFile(filepath.Join(dir, "egress.json")); strings.Contains(string(data), "wg0") {
		t.Fatal("unconfirmed lockdown persisted by a later save")
	}
	time.Sleep(300 * time.Millisecond)
	if m2 := newTestManager(t, &fakeNft{}, dir); m2.Status().Lockdown != nil {
		t.Fatal("reverted lockdown came back after restart")
	}
}

// A timer that already fired must not revert a newer lockdown. The late
// timer is simulated directly (its revert runs with the old generation),
// so this fails deterministically without the generation check.
func TestStaleTimerDoesNotRevertNewerLockdown(t *testing.T) {
	nft := &fakeNft{}
	m := newTestManager(t, nft, t.TempDir())
	if err := m.LockdownOn(wg0, time.Hour); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	staleGen := m.gen
	m.mu.Unlock()
	if err := m.LockdownOn(Lockdown{Interfaces: []string{"tun0"}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	m.revertPending(staleGen, "not confirmed in time") // the first window's timer, arriving late
	if l := m.Status().Lockdown; l == nil || l.Interfaces[0] != "tun0" {
		t.Fatalf("newer lockdown reverted by a stale timer: %+v", l)
	}
	m.LockdownOff()
}

func TestConfirmWindowTooShortRefused(t *testing.T) {
	m := newTestManager(t, &fakeNft{}, t.TempDir())
	for _, d := range []time.Duration{-time.Second, 500 * time.Millisecond} {
		if err := m.LockdownOn(wg0, d); err == nil {
			t.Errorf("confirm window %s accepted", d)
		}
	}
}

// If nft refuses, memory must keep matching the kernel.
func TestFailedOffKeepsLockdownState(t *testing.T) {
	nft := &fakeNft{}
	m := newTestManager(t, nft, t.TempDir())
	m.LockdownOn(wg0, 0)
	nft.reject = true
	if err := m.LockdownOff(); err == nil {
		t.Fatal("expected error")
	}
	if m.Status().Lockdown == nil {
		t.Fatal("status says off while the kernel still enforces the lockdown")
	}
}

// With nothing to enforce, a leftover table is drift too.
func TestLeftoverTableWithEmptyPolicyIsDetected(t *testing.T) {
	nft := &fakeNft{}
	m := newTestManager(t, nft, t.TempDir())
	nft.loaded = append(nft.loaded, "table inet devshield {\n\tchain egress {\n\t\tcounter drop\n\t}\n}\n")
	if again, _ := m.EnsureLoaded(); !again || strings.Contains(nft.last(), "chain egress") {
		t.Fatal("leftover table not removed")
	}
}

// An unreadable state file must not open a lockdown: the kernel is left
// alone and only restore-all may proceed.
func TestCorruptStateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "egress.json"), []byte("{not json"), 0o600)
	nft := &fakeNft{}
	m, err := New(Config{StateDir: dir, ProcRoot: t.TempDir(), Nft: nft.run, NftList: nft.list})
	if err == nil || m == nil {
		t.Fatalf("New = %v, %v", m, err)
	}
	if len(nft.loaded) != 0 {
		t.Fatal("kernel rules changed despite unreadable state")
	}
	if again, _ := m.EnsureLoaded(); again {
		t.Fatal("EnsureLoaded acted on unreadable state")
	}
	if err := m.LockdownOff(); err == nil {
		t.Fatal("change allowed while state is unreadable")
	}
	if m.Status().Problem == "" {
		t.Fatal("status hides the problem")
	}
	if _, err := m.Reset(); err != nil || m.Status().Problem != "" {
		t.Fatalf("restore-all could not start clean: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "egress.json.corrupt-*"))
	if len(matches) != 1 {
		t.Fatal("unreadable file not kept for inspection")
	}
}

// Disallow must not leave an untraceable helper with the allowance.
func TestDisallowRemovesOrphans(t *testing.T) {
	proc, cg := t.TempDir(), t.TempDir()
	for pid, stat := range map[string]string{"100": "100 (agent) S 1 x", "200": "200 (helper) S 1 x"} {
		os.MkdirAll(filepath.Join(proc, pid), 0o755)
		os.WriteFile(filepath.Join(proc, pid, "stat"), []byte(stat), 0o644)
	}
	os.MkdirAll(filepath.Join(cg, AllowedCgroup), 0o755)
	os.MkdirAll(filepath.Join(cg, "a"), 0o755)
	os.WriteFile(filepath.Join(cg, AllowedCgroup, "cgroup.procs"), []byte("100\n200\n"), 0o644)
	var events []string
	nft := &fakeNft{}
	m := &Manager{cfg: Config{ProcRoot: proc, Nft: nft.run, NftList: nft.list, StateDir: t.TempDir(),
		Emit: func(a, d, s string) { events = append(events, a) }}, cgRoot: cg, nftBase: cg,
		st: state{Blocked: map[string]*Member{}, Allowed: map[string]*Member{"fp": {ID: "x", Origins: map[int]string{100: "/a"}}}}}
	if _, err := m.Disallow("fp"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(cg, "a", "cgroup.procs")); string(got) != "100" {
		t.Errorf("agent not returned to its origin: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(cg, "cgroup.procs")); string(got) != "200" {
		t.Errorf("orphan helper kept the allowance: root got %q", got)
	}
	if !slices.Contains(events, "EGRESS_RELEASE_ORPHANS") {
		t.Errorf("orphans not reported: %v", events)
	}
}

// Agent Watch's process list can be seconds old. A PID that exited and was
// reused by another program must not be quarantined or allowed (found live:
// a block right after the agent stopped acted on its zombie).
func TestStalePIDIsNeverMoved(t *testing.T) {
	proc, cg := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(proc, "4242"), 0o755)
	os.WriteFile(filepath.Join(proc, "4242", "cgroup"), []byte("0::/user.slice\n"), 0o644)
	os.WriteFile(filepath.Join(proc, "4242", "stat"), []byte("4242 (python3) S 1 ..."), 0o644)
	nft := &fakeNft{}
	m, err := New(Config{StateDir: t.TempDir(), ProcRoot: proc, CgroupRoot: cg, Nft: nft.run, NftList: nft.list,
		ProcStart: func(pid int) (int64, bool) { return 2000, pid == 4242 }})
	if err != nil {
		t.Fatal(err)
	}
	m.nftBase = cg
	moved, _, err := m.Block("fp", "abcd1234", "x", []Proc{{PID: 4242, Start: 1000}}) // scan saw an older process
	if err != nil || moved != 0 {
		t.Fatalf("stale PID moved: moved=%d err=%v", moved, err)
	}
	if data, _ := os.ReadFile(filepath.Join(cg, QuarantineCgroup, "cgroup.procs")); len(data) != 0 {
		t.Fatalf("wrote %q to the quarantine group", data)
	}
	if moved, _, _ := m.Block("fp", "abcd1234", "x", []Proc{{PID: 4242, Start: 2000}}); moved != 1 {
		t.Fatalf("same process not moved: %d", moved)
	}
	if moved, _ := m.Allow("fp2", "ef", "y", []Proc{{PID: 4243, Start: 2000}}); moved != 0 {
		t.Fatalf("exited PID allowed: %d", moved)
	}
}

func TestResetUndoesEverything(t *testing.T) {
	nft, dir := &fakeNft{}, t.TempDir()
	m := newTestManager(t, nft, dir)
	m.LockdownOn(wg0, time.Minute) // pending, too
	did, err := m.Reset()
	if err != nil || len(did) != 1 || strings.Contains(nft.last(), "chain egress") || !m.Status().ConfirmBy.IsZero() {
		t.Fatalf("reset: %v %v\n%s", did, err, nft.last())
	}
}

// If nft lists rules in a form DevShield can't compare, that must be said
// instead of blaming another program (and re-loading) every 10 s. A change
// after loading must still be caught.
func TestIncomparableListingIsUnverifiable(t *testing.T) {
	nft := &fakeNft{}
	listing := "table inet devshield {\n\tchain egress {\n\t\tsomething else\n\t}\n}\n"
	var mu sync.Mutex
	m, err := New(Config{StateDir: t.TempDir(), ProcRoot: t.TempDir(), Nft: nft.run,
		NftList: func() (string, error) { mu.Lock(); defer mu.Unlock(); return listing, nil }})
	if err != nil {
		t.Fatal(err)
	}
	m.LockdownOn(wg0, 0)
	loads := len(nft.loaded)
	if again, err := m.EnsureLoaded(); again || !errors.Is(err, ErrUnverifiable) {
		t.Fatalf("unchanged: EnsureLoaded = %v, %v", again, err)
	}
	if len(nft.loaded) != loads {
		t.Fatal("re-loaded rules that had not changed")
	}
	if st := m.Status(); !st.RulesLoaded || !st.Unverifiable {
		t.Fatalf("status: loaded=%v unverifiable=%v", st.RulesLoaded, st.Unverifiable)
	}
	mu.Lock()
	listing = strings.Replace(listing, "something else", "something changed", 1) // tampered
	mu.Unlock()
	if st := m.Status(); st.RulesLoaded {
		t.Fatal("a change after loading was not noticed")
	}
	if again, err := m.EnsureLoaded(); !again || err != nil || len(nft.loaded) != loads+1 {
		t.Fatalf("changed: EnsureLoaded = %v, %v (loads %d)", again, err, len(nft.loaded)-loads)
	}
}

// fakeCgroups builds a cgroup tree in a temp dir. A real kernel empties a
// group as processes leave; here cgroup.procs is static, so a group that
// had members always looks "still holding" them to Reset.
func fakeCgroups(t *testing.T, groups map[string]string) (proc, cg string) {
	proc, cg = t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(cg, "a"), 0o755)
	for g, procs := range groups {
		os.MkdirAll(filepath.Join(cg, g), 0o755)
		if procs != "" {
			os.WriteFile(filepath.Join(cg, g, "cgroup.procs"), []byte(procs), 0o644)
		}
	}
	for _, pid := range []string{"100", "200", "300"} {
		os.MkdirAll(filepath.Join(proc, pid), 0o755)
		os.WriteFile(filepath.Join(proc, pid, "stat"), []byte(pid+" (x) S 1 x"), 0o644)
	}
	return proc, cg
}

// Reset must release blocked and allowed agents to where they came from,
// say what it could not trace, and refuse to report success while a
// quarantine group (and so its cut-off rule) remains.
func TestResetReleasesAgentsAndReportsStuckQuarantine(t *testing.T) {
	proc, cg := fakeCgroups(t, map[string]string{QuarantineCgroup: "100\n300\n", AllowedCgroup: ""})
	var events []string
	nft := &fakeNft{}
	m := &Manager{cfg: Config{ProcRoot: proc, Nft: nft.run, NftList: nft.list, StateDir: t.TempDir(),
		Emit: func(a, d, s string) { events = append(events, a) }}, cgRoot: cg, nftBase: cg,
		st: state{
			Blocked: map[string]*Member{"fp1": {ID: "blk1", Origins: map[int]string{100: "/a"}}},
			Allowed: map[string]*Member{"fp2": {ID: "alw1", Origins: map[int]string{200: "/a"}}},
		}}
	did, err := m.Reset()
	joined := strings.Join(did, " | ")
	if !strings.Contains(joined, "unblocked blk1 (1 untraceable process(es) stay quarantined)") || !strings.Contains(joined, "disallowed alw1") {
		t.Errorf("did = %q", did)
	}
	if got, _ := os.ReadFile(filepath.Join(cg, "a", "cgroup.procs")); string(got) != "100" {
		t.Errorf("blocked agent not returned to its origin: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(cg, "cgroup.procs")); len(got) != 0 {
		t.Errorf("untraceable quarantined process was let out to the root group: %q", got)
	}
	if !slices.Contains(events, "EGRESS_RELEASE_KEPT") {
		t.Errorf("kept process not reported: %v", events)
	}
	if _, statErr := os.Stat(filepath.Join(cg, AllowedCgroup)); statErr == nil {
		t.Error("empty allowed group was not removed")
	}
	if err == nil || !strings.Contains(err.Error(), QuarantineCgroup+" still holds") || !strings.Contains(err.Error(), "stay cut off") {
		t.Fatalf("stuck quarantine not reported as a failure: %v", err)
	}
	if !strings.Contains(nft.last(), "cgroupv2") {
		t.Errorf("quarantine rule dropped while the group still holds processes:\n%s", nft.last())
	}
	if len(m.st.Blocked) != 0 || len(m.st.Allowed) != 0 {
		t.Errorf("state not cleared: %+v", m.st)
	}
}

// A group left behind with no state (crash, deleted state file) is
// removed when empty and reported.
func TestResetRemovesLeftoverGroups(t *testing.T) {
	proc, cg := fakeCgroups(t, map[string]string{QuarantineCgroup: "", AllowedCgroup: ""})
	nft := &fakeNft{}
	m := &Manager{cfg: Config{ProcRoot: proc, Nft: nft.run, NftList: nft.list, StateDir: t.TempDir(),
		Emit: func(a, d, s string) {}}, cgRoot: cg, nftBase: cg,
		st: state{Blocked: map[string]*Member{}, Allowed: map[string]*Member{}}}
	did, err := m.Reset()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(did, "removed leftover group "+QuarantineCgroup) || !slices.Contains(did, "removed leftover group "+AllowedCgroup) {
		t.Fatalf("did = %q", did)
	}
	if strings.Contains(nft.last(), "chain egress") {
		t.Errorf("rules still loaded after a clean reset:\n%s", nft.last())
	}
}

// Stopping the daemon kills the revert timer, so an unconfirmed lockdown
// must be reverted then; a confirmed one must stay.
func TestStopRevertsUnconfirmedLockdown(t *testing.T) {
	nft := &fakeNft{}
	m := newTestManager(t, nft, t.TempDir())
	if err := m.LockdownOn(wg0, time.Minute); err != nil {
		t.Fatal(err)
	}
	m.Stop()
	if st := m.Status(); st.Lockdown != nil || !st.ConfirmBy.IsZero() || strings.Contains(nft.last(), "chain egress") {
		t.Fatalf("unconfirmed lockdown survived stop: %+v\n%s", st, nft.last())
	}
	if err := m.LockdownOn(wg0, time.Minute); err != nil {
		t.Fatal(err)
	}
	m.Confirm()
	m.Stop()
	if m.Status().Lockdown == nil {
		t.Fatal("confirmed lockdown removed on stop")
	}
}

// When the rules load but saving fails, the error must say the change is
// in force (it used to read like nothing happened).
func TestSaveFailureSaysChangeIsInForce(t *testing.T) {
	nft := &fakeNft{}
	m := newTestManager(t, nft, t.TempDir())
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, nil, 0o600)
	m.cfg.StateDir = filepath.Join(blocker, "state") // can't be created: saving fails, even as root
	err := m.LockdownOn(wg0, 0)
	if err == nil || !strings.Contains(err.Error(), "in force now") {
		t.Fatalf("err = %v", err)
	}
	if m.Status().Lockdown == nil || !strings.Contains(nft.last(), "chain egress") {
		t.Fatal("status no longer matches the kernel")
	}
}

// fixturePolicy uses every kind of rule DevShield renders. testdata/ holds
// its rendering and how real nft lists it back; regenerate both with
//
//	DEVSHIELD_WRITE_FIXTURE=1 go test -run TestWriteFixture ./internal/egress/
//
// then load rendered.nft into nft (with both groups present) and save
// "nft list table inet devshield" as listed-by-nft-<version>.nft.
var fixturePolicy = Policy{
	Quarantine: true, CgroupPath: QuarantineCgroup, AllowedPath: AllowedCgroup,
	KillFlows: []Flow{
		{Proto: "tcp", LocalIP: "10.0.0.2", LocalPort: 51000, RemoteIP: "2.2.2.2", RemotePort: 443},
		{Proto: "udp", LocalPort: 5353},
	},
	Lockdown: &Lockdown{Interfaces: []string{"wg0"}, Endpoints: []string{"203.0.113.5:51820/udp", "[2001:db8::1]:443"},
		Users: []int{65534}, AllowLAN: true, Inbound: []string{"22/tcp", "53/udp"}},
	BlockDoH: true,
}

func TestWriteFixture(t *testing.T) {
	if os.Getenv("DEVSHIELD_WRITE_FIXTURE") == "" {
		t.Skip("set DEVSHIELD_WRITE_FIXTURE=1 to regenerate testdata/rendered.nft")
	}
	s, err := Render(fixturePolicy)
	if err != nil {
		t.Fatal(err)
	}
	s = strings.TrimPrefix(s, "table inet "+TableName+"\ndelete table inet "+TableName+"\n")
	if err := os.WriteFile("testdata/rendered.nft", []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The fixture must still be what Render produces, or the comparison with
// real nft output proves nothing about today's rules.
func TestFixtureIsCurrentRendering(t *testing.T) {
	s, err := Render(fixturePolicy)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := os.ReadFile("testdata/rendered.nft")
	if strings.TrimPrefix(s, "table inet "+TableName+"\ndelete table inet "+TableName+"\n") != string(r) {
		t.Fatal("testdata/rendered.nft is stale: regenerate it (see fixturePolicy)")
	}
}

// The encrypted-DNS block survives a restart and restore-all ends it.
func TestBlockDoHPersistsAndResets(t *testing.T) {
	nft, dir := &fakeNft{}, t.TempDir()
	m := newTestManager(t, nft, dir)
	if err := m.SetBlockDoH(true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nft.last(), "th dport 853") {
		t.Fatal("rules not loaded")
	}
	m2 := newTestManager(t, nft, dir) // daemon restart / boot
	if !m2.BlockingDoH() || !m2.Status().BlockDoH {
		t.Fatal("block lost on restart")
	}
	if did, err := m2.Reset(); err != nil || !slices.Contains(did, "encrypted-DNS blocking ended") || m2.BlockingDoH() || strings.Contains(nft.last(), "th dport 853") {
		t.Fatalf("reset: %v %v\n%s", did, err, nft.last())
	}
}
