// agentwatch_behavior.go — Behaviour trackers for Agent Watch (pure logic)
//
// spawnTracker watches the process list every couple of seconds and
// remembers which tools/shells each process launched recently. This is
// the "agent loop" signal: an AI agent keeps launching commands, and a
// rogue one tends to launch recon/persistence tools. The main 10-second
// scan would miss most of these short-lived children, so the tracker
// runs on its own fast tick (see agentwatch_collect.go).
//
// llmEnvValues/envHitsIntroduced find LLM credentials/endpoints introduced
// when a process was launched, ignoring ones it merely inherited.

package agentwatch

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// fastProc is the cheap per-process data the fast tick reads.
type fastProc struct {
	PID  int32
	PPID int32
	Name string
	// Interactive: the process has a controlling terminal (Linux: a tty).
	// A shell like that is a human typing, not an agent running commands.
	Interactive bool
}

type spawnEvent struct {
	at   time.Time
	name string
}

type spawnTracker struct {
	mu      sync.Mutex
	window  time.Duration
	known   map[int32]fastProc // processes in the previous observation
	exited  map[int32]fastProc // processes that exited just before that
	primed  bool
	spawned map[int32][]spawnEvent // ancestor PID → tool children launched
}

func newSpawnTracker(window time.Duration) *spawnTracker {
	return &spawnTracker{
		window:  window,
		known:   map[int32]fastProc{},
		spawned: map[int32][]spawnEvent{},
	}
}

// maxShellHops bounds how far a tool is attributed up through shells
// (agent → pwsh → cmd → tool is two hops).
const maxShellHops = 3

// observe records every tool/shell process that appeared since the
// previous call. Agents run commands THROUGH shells (agent → pwsh -c
// "whoami" → whoami), so a new process is credited to its parent and,
// while that parent is a non-interactive shell, to the shell's parent too
// — up to the first non-shell ancestor, which is the process that decided
// to run it. An interactive shell (a human at a terminal, e.g. in an IDE's
// built-in terminal) stops the climb: what a person types is not the
// IDE's doing. A process whose name changed since the last call (fork,
// then exec) counts as new.
//
// The first call only learns what already exists — processes running
// before DevShield started are not counted as spawns.
func (t *spawnTracker) observe(procs []fastProc, now time.Time, isTool, isShell func(string) bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	current := make(map[int32]fastProc, len(procs))
	for _, p := range procs {
		current[p.PID] = p
	}
	lookup := func(pid int32) (fastProc, bool) {
		if p, ok := current[pid]; ok {
			return p, true
		}
		if p, ok := t.known[pid]; ok { // seen last round, exited since
			return p, true
		}
		p, ok := t.exited[pid]
		return p, ok
	}

	if t.primed {
		for _, p := range procs {
			if old, seen := t.known[p.PID]; (seen && strings.EqualFold(old.Name, p.Name)) || !isTool(strings.ToLower(p.Name)) {
				continue
			}
			t.credit(p, now, lookup, isShell)
		}
	}
	// Remember processes that just exited for one more round, so the
	// grandchildren of a short-lived shell can still be attributed.
	t.exited = map[int32]fastProc{}
	for pid, p := range t.known {
		if _, ok := current[pid]; !ok {
			t.exited[pid] = p
		}
	}
	t.known = current
	t.primed = true

	cutoff := now.Add(-t.window)
	for ppid, evs := range t.spawned {
		kept := evs[:0]
		for _, e := range evs {
			if e.at.After(cutoff) {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(t.spawned, ppid)
		} else {
			t.spawned[ppid] = kept
		}
	}
}

// credit records tool p as launched by its parent and, while that parent
// is a non-interactive shell, by the shell's parent too (see observe).
func (t *spawnTracker) credit(p fastProc, now time.Time, lookup func(int32) (fastProc, bool), isShell func(string) bool) {
	ev := spawnEvent{at: now, name: strings.ToLower(p.Name)}
	ancestor := p.PPID
	for hop := 0; hop < maxShellHops && ancestor != 0; hop++ {
		t.spawned[ancestor] = append(t.spawned[ancestor], ev)
		parent, ok := lookup(ancestor)
		if !ok || !isShell(strings.ToLower(parent.Name)) || parent.Interactive {
			break
		}
		ancestor = parent.PPID
	}
}

// recordExec counts a program start reported by a kernel exec event, so a
// command that exits before the next sample is still seen. The process is
// remembered under its new name, so the next sample doesn't count it again.
// parent reads a process that is not in the last sample (nil: none).
func (t *spawnTracker) recordExec(p fastProc, now time.Time, isTool, isShell func(string) bool, parent func(int32) (fastProc, bool)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.primed {
		return // the first sample has not run: it would not count this either
	}
	if old, seen := t.known[p.PID]; seen && strings.EqualFold(old.Name, p.Name) {
		return // already counted (e.g. the sample caught it first)
	}
	if isTool(strings.ToLower(p.Name)) {
		lookup := func(pid int32) (fastProc, bool) {
			if q, ok := t.known[pid]; ok {
				return q, true
			}
			if q, ok := t.exited[pid]; ok {
				return q, true
			}
			if parent != nil {
				return parent(pid)
			}
			return fastProc{}, false
		}
		t.credit(p, now, lookup, isShell)
	}
	t.known[p.PID] = p
}

// recent returns the tool/shell names pid launched within the window.
func (t *spawnTracker) recent(pid int32) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	evs := t.spawned[pid]
	if len(evs) == 0 {
		return nil
	}
	names := make([]string, len(evs))
	for i, e := range evs {
		names[i] = e.name
	}
	return names
}

// llmEnvValues returns the LLM-related variables in env as
// name → short hash of the value. Only the hash is kept (in memory, for
// the process's lifetime) and nothing is written anywhere; the full
// environment is read into memory briefly to compute it. A pattern ending
// in "*" is a prefix.
func llmEnvValues(env []string, patterns []string) map[string]string {
	out := map[string]string{}
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		name, val := strings.ToUpper(kv[:i]), kv[i+1:]
		if val == "" || !envNameMatches(name, patterns) {
			continue
		}
		sum := sha256.Sum256([]byte(val))
		out[name] = hex.EncodeToString(sum[:8])
	}
	return out
}

// envHitsIntroduced returns the sorted names of LLM variables that were
// INTRODUCED when this process was launched: present in vars, but not with
// the same value in its parent. Inherited variables say nothing about the
// process, wherever they came from — and this cannot be gamed by spawning
// children, which only inherit.
//
// Variables introduced under a shell or terminal are skipped: that is
// usually a person running `KEY=… cmd` or `export KEY`. (Known gap: a rogue
// started through `sh -c` hides its key this way; its other behaviour still
// counts.) also lists variables to ignore, e.g. DevShield's own environment.
func envHitsIntroduced(vars, parentVars map[string]string, parentIsShell bool, also map[string]string) []string {
	if parentIsShell {
		return nil
	}
	var hits []string
	for name, h := range vars {
		if parentVars[name] == h || also[name] == h {
			continue
		}
		hits = append(hits, name)
	}
	sort.Strings(hits)
	return hits
}

func envNameMatches(name string, patterns []string) bool {
	up := strings.ToUpper(name)
	for _, p := range patterns {
		p = strings.ToUpper(p)
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(up, strings.TrimSuffix(p, "*")) {
				return true
			}
		} else if up == p {
			return true
		}
	}
	return false
}

// exeFromCommand extracts the executable path from a command string such
// as a Run-key value: `"C:\x y\app.exe" --flag` or `C:\app\app.exe -x`.
func exeFromCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			return cmd[1 : end+1]
		}
		return ""
	}
	low := strings.ToLower(cmd)
	if i := strings.Index(low, ".exe"); i >= 0 {
		return cmd[:i+4]
	}
	if f := strings.Fields(cmd); len(f) > 0 {
		return f[0]
	}
	return ""
}

// exePathsInBytes finds absolute Windows paths ending in .exe inside raw
// bytes (ANSI or UTF-16LE). Used to read shortcut (.lnk) targets without COM.
func exePathsInBytes(data []byte) []string {
	isText := func(b byte) bool { return b >= 0x20 && b < 0x7f }

	// ANSI view: every non-printable byte is a string boundary.
	ansi := make([]byte, len(data))
	for i, b := range data {
		if isText(b) {
			ansi[i] = b
		} else {
			ansi[i] = '\n'
		}
	}
	views := []string{string(ansi)}

	// UTF-16LE views (both byte alignments): printable char + 0x00 pairs.
	for off := 0; off < 2; off++ {
		var u []byte
		for i := off; i+1 < len(data); i += 2 {
			if data[i+1] == 0 && isText(data[i]) {
				u = append(u, data[i])
			} else {
				u = append(u, '\n')
			}
		}
		views = append(views, string(u))
	}

	var out []string
	for _, v := range views {
		for _, m := range exePathRe.FindAllString(v, -1) {
			if !containsString(out, m) {
				out = append(out, m)
			}
		}
	}
	return out
}

var exePathRe = regexp.MustCompile(`(?i)[a-z]:\\[^\n"<>|*?]*?\.exe`)
