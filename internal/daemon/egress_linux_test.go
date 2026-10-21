//go:build linux

package daemon

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/chinmaykx07/DevShield_Windows/internal/agentwatch"
	"github.com/chinmaykx07/DevShield_Windows/internal/auditlog"
	"github.com/chinmaykx07/DevShield_Windows/internal/egress"
	"github.com/chinmaykx07/DevShield_Windows/internal/ipc"
)

// withAllowedAgent gives d an egress manager on a fake cgroup tree and fake
// nft, with agent "fpX" (id abcd1234, not running) allowed. The agent has
// no record in the agent database, so it counts as no longer sanctioned.
func withAllowedAgent(t *testing.T, d *Daemon) *egress.Manager {
	t.Helper()
	proc, cg := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(proc, "4242"), 0o755)
	os.WriteFile(filepath.Join(proc, "4242", "cgroup"), []byte("0::/a\n"), 0o644)
	os.WriteFile(filepath.Join(proc, "4242", "stat"), []byte("4242 (x) S 1 x"), 0o644)
	os.MkdirAll(filepath.Join(cg, "a"), 0o755)
	var mu sync.Mutex
	last := ""
	m, err := egress.New(egress.Config{
		StateDir: t.TempDir(), ProcRoot: proc, CgroupRoot: cg, NftBase: cg,
		Nft: func(s string, check bool) error {
			if !check {
				mu.Lock()
				last = s
				mu.Unlock()
			}
			return nil
		},
		NftList: func() (string, error) {
			mu.Lock()
			defer mu.Unlock()
			if !strings.Contains(last, "chain egress") {
				return "", errors.New("no table")
			}
			return last, nil
		},
		ProcStart: func(int) (int64, bool) { return 0, true },
		Emit:      func(a, det, s string) { d.eventFrom(a, det, s, "egress") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if moved, err := m.Allow("fpX", "abcd1234", "x", []egress.Proc{{PID: 4242}}); err != nil || moved != 1 {
		t.Fatalf("allow: %d %v", moved, err)
	}
	d.recMu.Lock()
	d.egress = m
	d.recMu.Unlock()
	return m
}

// bareDaemon has a log, a database and an Agent Watch that never scans,
// so no background check can act before the test does.
func bareDaemon(t *testing.T) *Daemon {
	t.Helper()
	dir := t.TempDir()
	d := &Daemon{cfg: Config{StateDir: dir}, logPath: filepath.Join(dir, "audit.log"),
		limited: map[denyKey]*window{}, stop: make(chan struct{})}
	al, _, err := auditlog.Open(d.logPath)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "agents.db"))
	if err != nil {
		t.Fatal(err)
	}
	w, err := agentwatch.New(agentwatch.Config{DB: db})
	if err != nil {
		t.Fatal(err)
	}
	d.log, d.db, d.watcher = al, db, w
	t.Cleanup(func() { d.stopBackground(); d.closeStores() })
	return d
}

func actions(t *testing.T, d *Daemon) []string {
	t.Helper()
	recs, err := auditlog.Tail(d.logPath, 200)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range recs {
		out = append(out, r.Action)
	}
	return out
}

// A database error must not be read as "sanction revoked": that withdrew
// an allowance silently and for good (e.g. while the daemon was stopping).
func TestDatabaseErrorKeepsAllowance(t *testing.T) {
	d := bareDaemon(t)
	m := withAllowedAgent(t, d)
	d.db.Close()
	d.reconcileEgress()
	if !m.IsAllowed("fpX") {
		t.Fatal("allowance withdrawn because the database could not be read")
	}
	if got := actions(t, d); !slices.Contains(got, "EGRESS_CHECK_FAILED") || slices.Contains(got, "AGENT_ALLOW_SUSPENDED") {
		t.Fatalf("events: %v", got)
	}
}

// Once the daemon is stopping, a late Agent Watch callback must not change
// network policy (its event could no longer be logged).
func TestNoReconcileAfterStop(t *testing.T) {
	d := bareDaemon(t)
	m := withAllowedAgent(t, d)
	d.stopBackground()
	d.reconcileEgress()
	if !m.IsAllowed("fpX") {
		t.Fatal("allowance changed after the daemon began stopping")
	}
}

// A user's "disallow" landing between a reconcile reading the allowed
// agents and withdrawing one is not a failure.
func TestDisallowDuringReconcileLogsNoFailure(t *testing.T) {
	d := bareDaemon(t)
	m := withAllowedAgent(t, d)
	beforeWithdraw = func(string) { d.setAllow("disallow", "abcd1234", ipc.Peer{UID: 0}) }
	t.Cleanup(func() { beforeWithdraw = func(string) {} })
	d.reconcileEgress()
	if m.IsAllowed("fpX") {
		t.Fatal("allowance not withdrawn")
	}
	if got := actions(t, d); slices.Contains(got, "EGRESS_FAILED") || !slices.Contains(got, "AGENT_DISALLOWED") {
		t.Fatalf("events: %v", got)
	}
}

// Reconciles run from the ticker and from callbacks, alongside a user's
// "disallow". Whoever withdraws first wins; nobody may log a failure.
func TestConcurrentWithdrawalsLogNoFailure(t *testing.T) {
	d := bareDaemon(t)
	m := withAllowedAgent(t, d)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); d.reconcileEgress() }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); d.setAllow("disallow", "abcd1234", ipc.Peer{UID: 0}) }()
	wg.Wait()
	if m.IsAllowed("fpX") {
		t.Fatal("allowance not withdrawn")
	}
	if got := actions(t, d); slices.Contains(got, "EGRESS_FAILED") {
		t.Fatalf("false failure logged: %v", got)
	}
}

// Events that can't be written are not dropped silently: status counts
// them and the log says so as soon as writing works again.
func TestLostEventsAreReported(t *testing.T) {
	d := bareDaemon(t)
	d.log.Close() // every append now fails, as on a full disk
	d.event("SOMETHING", "happened", "ok")
	al, _, err := auditlog.Open(d.logPath)
	if err != nil {
		t.Fatal(err)
	}
	d.log = al
	d.event("LATER", "event", "ok")
	got := actions(t, d)
	if !slices.Contains(got, "AUDIT_EVENTS_LOST") || slices.Contains(got, "SOMETHING") {
		t.Fatalf("events: %v", got)
	}
	if n := d.status().LostEvents; n != 1 {
		t.Fatalf("status LostEvents = %d", n)
	}
}
