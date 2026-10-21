//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chinmaykx07/DevShield_Windows/internal/auditlog"
	"github.com/chinmaykx07/DevShield_Windows/internal/ipc"
)

func TestAuthorize(t *testing.T) {
	owners := map[int]bool{1000: true}
	root := ipc.Peer{UID: 0}
	owner := ipc.Peer{UID: 1000}
	other := ipc.Peer{UID: 1001}

	cases := []struct {
		peer          ipc.Peer
		op            string
		allow, tamper bool
	}{
		{root, "status", true, false},
		{root, "sanction", true, false},
		{root, "bogus", false, false},
		{owner, "agents", true, false},
		{owner, "events", true, false},
		{owner, "sanction", false, true}, // the owner's own user-level processes (incl. agents!) can't change policy
		{owner, "revoke", false, true},
		{other, "agents", false, false}, // other local users can't read
		{other, "sanction", false, true},
	}
	for _, c := range cases {
		allow, tamper := authorize(c.peer, c.op, owners)
		if allow != c.allow || tamper != c.tamper {
			t.Errorf("uid %d op %s: allow=%v tamper=%v, want %v %v", c.peer.UID, c.op, allow, tamper, c.allow, c.tamper)
		}
	}
}

func startTestDaemon(t *testing.T) (*Daemon, string) {
	t.Helper()
	dir := t.TempDir()
	d, err := start(Config{StateDir: filepath.Join(dir, "state"), Owners: []int{1000}, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.close)
	return d, dir
}

func lastActions(t *testing.T, d *Daemon, n int) []string {
	t.Helper()
	recs, err := auditlog.Tail(d.logPath, n)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range recs {
		out = append(out, r.Action+": "+r.Detail)
	}
	return out
}

func TestStateIsRootOnly(t *testing.T) {
	d, _ := startTestDaemon(t)
	for path, want := range map[string]os.FileMode{
		d.cfg.StateDir: 0o700,
		d.logPath:      0o600,
		filepath.Join(d.cfg.StateDir, "agents.db"): 0o600,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v", path, fi.Mode().Perm(), want)
		}
	}
}

func TestSelfSanctionAttemptIsRefusedAndLogged(t *testing.T) {
	d, _ := startTestDaemon(t)
	agentPeer := ipc.Peer{UID: 1000, PID: 4242, Exe: "/tmp/rogue/svc-update"}

	resp := d.handle(agentPeer, ipc.Request{Op: "sanction", ID: "deadbeef"})
	if resp.OK || !strings.Contains(resp.Error, "requires root") {
		t.Fatalf("non-root sanction must be refused, got %+v", resp)
	}
	got := strings.Join(lastActions(t, d, 1), "\n")
	if !strings.Contains(got, "AGENT_TAMPER_ATTEMPT") || !strings.Contains(got, "/tmp/rogue/svc-update") {
		t.Fatalf("tamper attempt not logged with the offending program: %s", got)
	}
}

func TestDeniedEventsAreRateLimited(t *testing.T) {
	d, _ := startTestDaemon(t)
	before, _ := auditlog.Verify(d.logPath)
	for i := 0; i < 50; i++ {
		d.handle(ipc.Peer{UID: 1001}, ipc.Request{Op: "agents"})
	}
	after, err := auditlog.Verify(d.logPath)
	if err != nil {
		t.Fatal(err)
	}
	if logged := after - before; logged != deniedPerMinute {
		t.Fatalf("50 denied requests produced %d log records, want %d", logged, deniedPerMinute)
	}
}

func TestRequestsOverRealSocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the test client must be uid 0")
	}
	d, dir := startTestDaemon(t)
	sock := filepath.Join(dir, "run", "devshield.sock")
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go ipc.Serve(l, d.handle)

	fi, _ := os.Stat(sock)
	if fi.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}

	resp, err := ipc.Call(sock, ipc.Request{Op: "status"})
	if err != nil || !resp.OK || resp.Status == nil || !resp.Status.LogIntact {
		t.Fatalf("status over socket: %+v %v", resp, err)
	}
	resp, _ = ipc.Call(sock, ipc.Request{Op: "sanction", ID: "nonexistent"})
	if resp.OK || !strings.Contains(resp.Error, "no running agent") {
		t.Fatalf("sanction of unknown id: %+v", resp)
	}
}

func TestUncleanStopAndTamperAreReportedOnNextStart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: filepath.Join(dir, "state"), Version: "test"}

	d, err := start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate being killed: no close(), so no DAEMON_STOPPED record.
	d.watcher.Stop()
	d.log.Close()
	d.db.Close()

	d2, err := start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(lastActions(t, d2, 3), "\n"); !strings.Contains(got, "DAEMON_UNCLEAN_STOP") {
		t.Fatalf("unclean stop not reported: %s", got)
	}
	d2.close()

	// Now tamper with the log between runs.
	data, _ := os.ReadFile(d2.logPath)
	os.WriteFile(d2.logPath, []byte(strings.Replace(string(data), "DAEMON_STARTED", "NOTHING_HAPPENED", 1)), 0o600)

	d3, err := start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer d3.close()
	if got := strings.Join(lastActions(t, d3, 3), "\n"); !strings.Contains(got, "AUDIT_TAMPER_DETECTED") {
		t.Fatalf("tampering not reported on start: %s", got)
	}
	if !d3.status().TamperSince {
		t.Fatal("status should report tampering detected this run")
	}
}

func TestThermalProfileThroughDaemon(t *testing.T) {
	sys := t.TempDir()
	for rel, v := range map[string]string{
		"sys/devices/system/cpu/cpufreq/boost":                    "1",
		"sys/devices/system/cpu/cpufreq/policy0/cpuinfo_min_freq": "400000",
		"sys/devices/system/cpu/cpufreq/policy0/cpuinfo_max_freq": "4000000",
		"sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq": "4000000",
	} {
		p := filepath.Join(sys, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(v+"\n"), 0o644)
	}
	d, err := start(Config{StateDir: filepath.Join(t.TempDir(), "state"), Owners: []int{1000}, Version: "test", SysRoot: sys})
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	readSys := func(rel string) string {
		b, _ := os.ReadFile(filepath.Join(sys, rel))
		return strings.TrimSpace(string(b))
	}

	// The owner can read thermal status but not change the profile.
	if r := d.handle(ipc.Peer{UID: 1000}, ipc.Request{Op: "thermal"}); !r.OK || !r.Thermal.Supported {
		t.Fatalf("owner thermal read: %+v", r)
	}
	if r := d.handle(ipc.Peer{UID: 1000, Exe: "/usr/bin/python3"}, ipc.Request{Op: "profile", Profile: "gaming"}); r.OK {
		t.Fatal("non-root profile change must be refused")
	}
	if !strings.Contains(strings.Join(lastActions(t, d, 1), ""), "AGENT_TAMPER_ATTEMPT") {
		t.Fatal("non-root profile change not logged as tamper attempt")
	}

	r := d.handle(ipc.Peer{UID: 0}, ipc.Request{Op: "profile", Profile: "silent"})
	if !r.OK || r.Thermal.Active != "silent" || readSys("sys/devices/system/cpu/cpufreq/boost") != "0" ||
		readSys("sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq") != "2800000" {
		t.Fatalf("silent via daemon: %+v", r)
	}
	r = d.handle(ipc.Peer{UID: 0}, ipc.Request{Op: "profile", Profile: "off"})
	if !r.OK || readSys("sys/devices/system/cpu/cpufreq/boost") != "1" || readSys("sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq") != "4000000" {
		t.Fatalf("off via daemon: %+v", r)
	}
	got := strings.Join(lastActions(t, d, 3), "\n")
	if !strings.Contains(got, "THERMAL_PROFILE_APPLIED") || !strings.Contains(got, "THERMAL_RESTORED") {
		t.Fatalf("thermal changes not in the audit log:\n%s", got)
	}
	if fi, _ := os.Stat(d.thermalDir()); fi.Mode().Perm() != 0o700 {
		t.Fatalf("thermal state dir mode %v", fi.Mode().Perm())
	}
}

// Found in review: refused reads shared one budget with tamper attempts
// (10 harmless refusals hid the next tamper attempt), and the summary of
// suppressed denials was only written if another denial came later.
func TestDenialLoggingCannotBeDrowned(t *testing.T) {
	d, err := start(Config{StateDir: filepath.Join(t.TempDir(), "state"), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	peer := ipc.Peer{UID: 4242, PID: 1, Exe: "/tmp/rogue"}
	for i := 0; i < 15; i++ {
		d.handle(peer, ipc.Request{Op: "status"}) // not an owner: refused read
	}
	d.handle(peer, ipc.Request{Op: "sanction", ID: "abcd1234"})
	for i := 0; i < 12; i++ {
		d.handle(peer, ipc.Request{Op: "revoke", ID: "abcd1234"})
	}
	d.close() // attempts stop: the pending summaries must still be written
	recs, _ := auditlog.Tail(d.logPath, 200)
	var tamper, summaries int
	for _, r := range recs {
		switch r.Action {
		case "AGENT_TAMPER_ATTEMPT":
			tamper++
		case "IPC_DENIED_SUPPRESSED":
			summaries++
		}
	}
	if tamper != deniedPerMinute {
		t.Errorf("tamper attempts logged = %d, want %d (refused reads must not use up their budget)", tamper, deniedPerMinute)
	}
	if summaries != 2 {
		t.Errorf("summaries = %d, want 2 (one per kind)", summaries)
	}
}
