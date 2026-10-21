package agentwatch

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A process's Fingerprint, computed from it alone at exec time, must equal
// the fingerprint a scan lists it under — or a restarted blocked agent
// would not be recognised until the next scan.
func TestFingerprintMatchesScan(t *testing.T) {
	cat, err := LoadAgentCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	procs := []ProcInfo{
		{PID: 10, Name: "claude", Exe: "/home/u/.local/share/claude/versions/2.1.0/claude", Cmdline: "claude"},
		{PID: 11, Name: "node", Exe: "/usr/bin/node", Cmdline: "node /usr/lib/node_modules/@openai/codex/bin/codex.js", Cwd: "/home/u"},
		{PID: 12, Name: "node", Exe: "/usr/bin/node", Cmdline: "node /usr/lib/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js /tmp", Cwd: "/"},
		{PID: 13, Name: "python3", Exe: "/usr/bin/python3.12", Cmdline: "python3 serve.py", Cwd: "/srv/model"},
	}
	s := Snapshot{Procs: procs, ListenPorts: map[int32][]int{13: {11434}}}
	dets := cat.Classify(s, nil)
	if len(dets) != len(procs) {
		t.Fatalf("classified %d of %d", len(dets), len(procs))
	}
	for _, d := range dets {
		for _, p := range procs {
			if p.PID == d.PID {
				if got, want := cat.Fingerprint(p), AgentFingerprint(d); got != want {
					t.Errorf("pid %d: Fingerprint %q, scan lists it as %q", p.PID, got, want)
				}
			}
		}
	}
}

// A command that exits before the next 0.5 s sample is counted from its
// exec event, credited through a non-interactive shell to the agent, and
// not counted a second time when the next sample sees it.
func TestExecEventCountsShortCommandOnce(t *testing.T) {
	tr := newSpawnTracker(time.Minute)
	isTool := func(n string) bool { return n == "whoami" || n == "bash" }
	isShell := func(n string) bool { return n == "bash" }
	now := time.Now()
	agent := fastProc{PID: 100, PPID: 1, Name: "agent"}
	shell := fastProc{PID: 101, PPID: 100, Name: "bash"}
	tr.observe([]fastProc{agent, shell}, now, isTool, isShell) // primes
	whoami := fastProc{PID: 102, PPID: 101, Name: "whoami"}
	tr.recordExec(whoami, now, isTool, isShell, nil)
	if got := tr.recent(100); len(got) != 1 || got[0] != "whoami" {
		t.Fatalf("agent credited with %v, want [whoami]", got)
	}
	tr.observe([]fastProc{agent, shell, whoami}, now, isTool, isShell) // the sample also sees it
	tr.observe([]fastProc{agent, shell}, now, isTool, isShell)         // then it is gone
	if got := tr.recent(100); len(got) != 1 {
		t.Fatalf("counted %d times: %v", len(got), got)
	}

	// The other order: the sample counts a command first, and its exec
	// event arrives afterwards.
	id := fastProc{PID: 103, PPID: 101, Name: "whoami"}
	tr.observe([]fastProc{agent, shell, id}, now, isTool, isShell)
	tr.recordExec(id, now, isTool, isShell, nil)
	if got := tr.recent(100); len(got) != 2 {
		t.Fatalf("late exec event counted again: %v", got)
	}
}

// A process that runs a new program (exec) keeps its PID and start time.
// The scan must see the new program, not keep the old identity: launchers
// exec agents, and a rogue could start as something innocent and exec
// itself just after a scan.
func TestScanSeesProgramReplacedByExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no exec-in-place on Windows")
	}
	cmd := exec.Command("/bin/sh", "-c", "sleep 0.4; exec /bin/sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	pid := int32(cmd.Process.Pid)
	w, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	find := func() ProcInfo {
		snap, err := w.collect(w.Catalog())
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range snap.Procs {
			if p.PID == pid {
				return p
			}
		}
		t.Fatalf("pid %d not in scan", pid)
		return ProcInfo{}
	}
	if p := find(); !strings.Contains(p.Cmdline, "sh -c") {
		t.Fatalf("before exec: %+v", p)
	}
	time.Sleep(time.Second)
	if p := find(); p.Name != "sleep" || p.Cmdline != "/bin/sleep 30" {
		t.Fatalf("after exec the scan still reports the old program: %+v", p)
	}
}
