// agentwatch_behavior.go — Behaviour trackers for Agent Watch (pure logic)
//
// spawnTracker watches the process list every couple of seconds and
// remembers which tools/shells each process launched recently. This is
// the "agent loop" signal: an AI agent keeps launching commands, and a
// rogue one tends to launch recon/persistence tools. The main 10-second
// scan would miss most of these short-lived children, so the tracker
// runs on its own fast tick (see agentwatch_collect.go).
//
// llmEnvHits finds LLM credentials/endpoints that were set specifically
// for one process, ignoring variables every process inherits.

package main

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// fastProc is the cheap per-process data the fast tick reads.
type fastProc struct {
	PID  int32
	PPID int32
	Name string
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
// while that parent is a shell, to the shell's parent too — up to the
// first non-shell ancestor, which is the process that decided to run it.
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
			name := strings.ToLower(p.Name)
			if _, seen := t.known[p.PID]; seen || !isTool(name) {
				continue
			}
			ev := spawnEvent{at: now, name: name}
			ancestor := p.PPID
			for hop := 0; hop < maxShellHops && ancestor != 0; hop++ {
				t.spawned[ancestor] = append(t.spawned[ancestor], ev)
				parent, ok := lookup(ancestor)
				if !ok || !isShell(strings.ToLower(parent.Name)) {
					break
				}
				ancestor = parent.PPID
			}
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

// llmEnvHits returns the NAMES of LLM-related variables in procEnv that are
// not simply inherited from the user's global environment (baseline, i.e.
// DevShield's own environment). Values are compared and then discarded —
// they are never stored or logged. A pattern ending in "*" is a prefix.
func llmEnvHits(procEnv []string, baseline map[string]string, patterns []string) []string {
	var hits []string
	for _, kv := range procEnv {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		name, val := kv[:i], kv[i+1:]
		if val == "" || !envNameMatches(name, patterns) {
			continue
		}
		if global, ok := baseline[strings.ToUpper(name)]; ok && global == val {
			continue // inherited by every process — says nothing about this one
		}
		if !containsString(hits, strings.ToUpper(name)) {
			hits = append(hits, strings.ToUpper(name))
		}
	}
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

// envBaseline indexes an environment ("K=V" list) by upper-case name.
func envBaseline(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			m[strings.ToUpper(kv[:i])] = kv[i+1:]
		}
	}
	return m
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
