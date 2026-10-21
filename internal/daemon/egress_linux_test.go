//go:build linux

package daemon

import (
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

// With the sinkhole on, block-doh adds the DoH resolvers' names to it (and
// takes them out again); with it off, it says that browsers are not stopped.
func TestBlockDoHKeepsSinkholeInStep(t *testing.T) {
	d := bareDaemon(t)
	withAllowedAgent(t, d) // any egress manager on fake nft
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/hosts"), []byte("127.0.0.1 localhost\n"), 0o644)
	os.WriteFile(filepath.Join(root, "etc/nsswitch.conf"), []byte("hosts: files dns\n"), 0o644)
	d.cfg.SysRoot = root
	hostsFile := func() string { b, _ := os.ReadFile(filepath.Join(root, "etc/hosts")); return string(b) }
	root0 := ipc.Peer{UID: 0}

	if r := d.setBlockDoH("on", root0); !r.OK || !strings.Contains(r.Note, "sinkhole is off") || !r.Egress.BlockDoH {
		t.Fatalf("on with sinkhole off: %+v", r)
	}
	if r := d.setSinkhole("on", root0); !r.OK || !strings.Contains(hostsFile(), "dns.google") {
		t.Fatalf("sinkhole on did not include the DoH names:\n%s", hostsFile())
	}
	if r := d.setBlockDoH("off", root0); !r.OK || strings.Contains(hostsFile(), "dns.google") || !strings.Contains(hostsFile(), "metrics.ubuntu.com") {
		t.Fatalf("block-doh off left the DoH names or dropped the telemetry ones:\n%s", hostsFile())
	}
	if r := d.setBlockDoH("on", root0); !r.OK || r.Note != "" || !strings.Contains(hostsFile(), "dns.google") {
		t.Fatalf("on with sinkhole on: note %q\n%s", r.Note, hostsFile())
	}
}

// End to end in this (host) network namespace, where the kernel's process
// events exist: a blocked program that starts again is quarantined from
// its exec event alone, long before any scan (this daemon never scans).
func TestBlockedProgramIsCaughtAtExec(t *testing.T) {
	d := bareDaemon(t)
	if os.Geteuid() != 0 {
		t.Skip("needs root (proc connector)")
	}
	cg := t.TempDir()
	var mu sync.Mutex
	last := ""
	m, err := egress.New(egress.Config{
		StateDir: t.TempDir(), CgroupRoot: cg, NftBase: cg, // real /proc, fake cgroup tree
		Nft: func(s string, check bool) error {
			if !check {
				mu.Lock()
				last = s
				mu.Unlock()
			}
			return nil
		},
		NftList: func() (string, error) { mu.Lock(); defer mu.Unlock(); return last, nil },
		Emit:    func(a, det, s string) { d.eventFrom(a, det, s, "egress") },
	})
	if err != nil {
		t.Fatal(err)
	}
	fp := d.watcher.Catalog().Fingerprint(agentwatch.ProcInfo{Name: "sleep", Exe: "/usr/bin/sleep", Cmdline: "sleep 30"})
	if _, _, err := m.Block(fp, "abcd1234", "test program", nil); err != nil { // blocked while not running
		t.Fatal(err)
	}
	d.egress = m
	d.watcher.OnExec(d.execStarted)
	d.watcher.Start()
	if err := d.watcher.ExecEvents(); err != nil {
		t.Skipf("no kernel exec events here: %v", err)
	}
	cmd := exec.Command("/usr/bin/sleep", "30")
	began := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	want := strconv.Itoa(cmd.Process.Pid)
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, _ := os.ReadFile(filepath.Join(cg, egress.QuarantineCgroup, "cgroup.procs"))
		if strings.Contains(string(got), want) {
			t.Logf("quarantined %v after start", time.Since(began).Round(time.Millisecond))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %s not quarantined within 2 s of starting (events: %v)", want, actions(t, d))
		}
		time.Sleep(10 * time.Millisecond)
	}
	for !slices.Contains(actions(t, d), "AGENT_REQUARANTINED") {
		if time.Now().After(deadline.Add(time.Second)) {
			t.Fatalf("not logged: %v", actions(t, d))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
