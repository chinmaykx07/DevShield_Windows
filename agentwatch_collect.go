// agentwatch_collect.go — Agent Watch scanner (runs inside the tray)
//
// Two loops:
//   fast tick (0.5s) — cheap process list → remembers which tools/shells each
//                     process launched (the "agent loop" signal)
//   scan (10s)      — full snapshot: processes, command lines, TCP
//                     connections, LLM env vars, loaded AI libraries,
//                     auto-start entries → classify → verdict → alerts
//
// Audit events written:
//   AGENT_NEW / AGENT_UNKNOWN    — first sighting (catalogued / undocumented)
//   AGENT_CHANGED                — executable or script changed (approval revoked)
//   AGENT_ROGUE_SUSPECT          — unsanctioned + undocumented or suspicious behaviour
//   AGENT_RISKY                  — sanctioned agent now showing rogue indicators
//   AGENT_UNSANCTIONED_START     — a known, unsanctioned agent started running
//
// Alert only: Agent Watch never kills or blocks a process. No admin needed;
// processes of other users / elevated processes are only partly visible.

package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	gnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

const (
	agentScanInterval    = 10 * time.Second
	spawnTickInterval    = 500 * time.Millisecond // shorter misses fewer quick commands; see notes on ETW
	spawnWindow          = 5 * time.Minute
	llmResolveInterval   = 15 * time.Minute
	autostartInterval    = 2 * time.Minute
	moduleRefreshAge     = 2 * time.Minute
	moduleRefreshPerScan = 40        // spread module reads across scans
	maxHashFileSize      = 512 << 20 // skip hashing files above 512 MB
	agentDetailMaxLength = 400
)

// RunningAgent is one agent currently running, merged across all of its
// processes (an IDE can have dozens of helper processes).
type RunningAgent struct {
	Detection
	Fingerprint string
	Status      string // sanction status from the store
	Verdict     string // sanctioned | unsanctioned | risky | rogue
	ActiveRisks []string
	Processes   int
}

type cachedProc struct {
	createTime int64
	info       ProcInfo
	envHits    []string
	modules    []string
	modulesAt  time.Time
}

type hashEntry struct {
	size    int64
	modTime time.Time
	sum     string
}

type AgentWatcher struct {
	mu        sync.RWMutex
	catalog   *AgentCatalog
	running   []RunningAgent
	callbacks []func()

	llmIPs      map[string]string // ip → LLM API host
	resolvedAt  time.Time
	autostart   map[string]string
	autostartAt time.Time

	envBase   map[string]string
	procCache map[int32]cachedProc
	hashCache map[string]hashEntry
	spawns    *spawnTracker
	alerted   map[string]string // fingerprint → verdict+risks last alerted

	stopCh chan struct{}
}

var agentWatch = &AgentWatcher{
	procCache: map[int32]cachedProc{},
	hashCache: map[string]hashEntry{},
	llmIPs:    map[string]string{},
	autostart: map[string]string{},
	spawns:    newSpawnTracker(spawnWindow),
	alerted:   map[string]string{},
	stopCh:    make(chan struct{}),
}

// ── INIT / SHUTDOWN ───────────────────────────────────────────

func initAgentWatch() {
	cat, err := LoadAgentCatalog()
	if err != nil {
		log.Printf("agentwatch: catalog warning: %v", err)
		WriteGoEvent("AGENT_CATALOG_WARNING", err.Error(), "warn")
	}
	if cat == nil {
		log.Printf("agentwatch: disabled — no usable catalog")
		return
	}

	if db := agentDB(); db != nil {
		if err := ensureAgentSchema(db); err != nil {
			log.Printf("agentwatch: schema: %v", err)
		}
	}

	agentWatch.mu.Lock()
	agentWatch.catalog = cat
	agentWatch.envBase = envBaseline(os.Environ())
	agentWatch.mu.Unlock()

	go agentWatch.runSpawnTicker()
	go agentWatch.run()
	log.Printf("agentwatch: started (catalog %s, %d agents)", cat.Version, len(cat.Agents))
}

func shutdownAgentWatch() {
	select {
	case <-agentWatch.stopCh:
	default:
		close(agentWatch.stopCh)
	}
}

func agentDB() *sql.DB {
	auditMu.RLock()
	defer auditMu.RUnlock()
	return auditDB
}

// ── LOOPS ─────────────────────────────────────────────────────

func (w *AgentWatcher) runSpawnTicker() {
	ticker := time.NewTicker(spawnTickInterval)
	defer ticker.Stop()
	for {
		w.mu.RLock()
		cat := w.catalog
		w.mu.RUnlock()
		if procs, err := fastProcList(); err == nil && cat != nil {
			w.spawns.observe(procs, time.Now(),
				func(n string) bool { return cat.tools[n] },
				func(n string) bool { return cat.shells[n] })
		}
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
		}
	}
}

func (w *AgentWatcher) run() {
	w.scan()

	ticker := time.NewTicker(agentScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			log.Println("agentwatch: stopped")
			return
		case <-ticker.C:
			w.scan()
		}
	}
}

func (w *AgentWatcher) scan() {
	w.mu.RLock()
	cat := w.catalog
	w.mu.RUnlock()
	if cat == nil {
		return
	}

	w.refreshLLMIPs(cat)
	w.refreshAutostart()
	snap, err := w.collect(cat)
	if err != nil {
		log.Printf("agentwatch: scan failed: %v", err)
		return
	}

	w.mu.RLock()
	llmIPs := w.llmIPs
	prev := map[string]bool{}
	for _, a := range w.running {
		prev[a.Fingerprint] = true
	}
	w.mu.RUnlock()

	running := mergeDetections(cat.Classify(snap, llmIPs))
	db := agentDB()
	now := nowISO()

	for i := range running {
		a := &running[i]
		a.Status = AgentUnsanctioned
		change := SightingSeenBefore

		if db != nil {
			ch, status, err := recordSighting(db, a.Detection, w.hashFile(hashTarget(a)), now)
			if err != nil {
				log.Printf("agentwatch: record %s: %v", a.Name, err)
			} else {
				change, a.Status = ch, status
			}
		}
		a.Verdict, a.ActiveRisks = AgentVerdict(a.Status, a.Risks)

		switch change {
		case SightingNew:
			if a.Known {
				WriteGoEvent("AGENT_NEW", agentDetail(a), "warn")
			} else {
				WriteGoEvent("AGENT_UNKNOWN", agentDetail(a), "warn")
			}
		case SightingHashChanged:
			WriteGoEvent("AGENT_CHANGED", agentDetail(a), "warn")
		}

		w.alertVerdict(a, prev[a.Fingerprint])
	}

	// Forget alert state for agents that stopped, so a rogue agent that
	// comes back later raises a fresh alert.
	current := make(map[string]bool, len(running))
	for _, a := range running {
		current[a.Fingerprint] = true
	}
	for fp := range w.alerted {
		if !current[fp] {
			delete(w.alerted, fp)
		}
	}

	w.mu.Lock()
	changed := !sameRunning(w.running, running)
	w.running = running
	cbs := w.callbacks
	w.mu.Unlock()

	if changed {
		for _, cb := range cbs {
			go cb()
		}
	}
}

// alertVerdict raises a verdict alert once per (agent, verdict, risk set),
// so a rogue agent that keeps running doesn't flood the log, but a NEW
// risk on the same agent alerts again.
func (w *AgentWatcher) alertVerdict(a *RunningAgent, wasRunning bool) {
	key := a.Verdict + "|" + strings.Join(a.ActiveRisks, "|")
	if w.alerted[a.Fingerprint] == key {
		return
	}
	w.alerted[a.Fingerprint] = key

	switch a.Verdict {
	case VerdictRogue:
		WriteGoEvent("AGENT_ROGUE_SUSPECT", agentDetail(a), "warn")
	case VerdictRisky:
		WriteGoEvent("AGENT_RISKY", agentDetail(a), "warn")
	case VerdictUnsanctioned:
		if !wasRunning {
			WriteGoEvent("AGENT_UNSANCTIONED_START", agentDetail(a), "warn")
		}
	}
}

// hashTarget picks the file whose change should revoke approval: the
// script for node/python/uvx agents, otherwise the executable.
func hashTarget(a *RunningAgent) string {
	if a.Target != "" {
		if st, err := os.Stat(a.Target); err == nil && !st.IsDir() {
			return a.Target
		}
	}
	return a.Exe
}

// mergeDetections collapses many processes of one agent into one entry,
// keeping the union of reasons and risks (a single helper process doing
// something suspicious makes the whole agent suspicious).
func mergeDetections(dets []Detection) []RunningAgent {
	byFP := map[string]int{}
	var out []RunningAgent
	for _, d := range dets {
		fp := AgentFingerprint(d)
		i, ok := byFP[fp]
		if !ok {
			byFP[fp] = len(out)
			d.Reasons = append([]string(nil), d.Reasons...)
			d.Risks = append([]string(nil), d.Risks...)
			out = append(out, RunningAgent{Detection: d, Fingerprint: fp, Processes: 1})
			continue
		}
		a := &out[i]
		a.Processes++
		if d.AgentScore > a.AgentScore {
			a.AgentScore = d.AgentScore
		}
		for _, r := range d.Reasons {
			if !containsString(a.Reasons, r) {
				a.Reasons = append(a.Reasons, r)
			}
		}
		for _, r := range d.Risks {
			if !containsString(a.Risks, r) {
				a.Risks = append(a.Risks, r)
			}
		}
	}
	return out
}

func sameRunning(a, b []RunningAgent) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(r []RunningAgent) []string {
		ks := make([]string, len(r))
		for i, x := range r {
			ks[i] = x.Fingerprint + "|" + x.Verdict + "|" + strings.Join(x.ActiveRisks, ";")
		}
		sort.Strings(ks)
		return ks
	}
	ka, kb := key(a), key(b)
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

func agentDetail(a *RunningAgent) string {
	d := fmt.Sprintf("%s · %s · verdict:%s", a.Name, a.Exe, a.Verdict)
	if len(a.ActiveRisks) > 0 {
		d += " · risks: " + strings.Join(a.ActiveRisks, "; ")
	}
	d += " · why agent: " + strings.Join(a.Reasons, "; ")
	if a.Cmdline != "" {
		d += " · cmd: " + redactSecrets(a.Cmdline)
	}
	if len(d) > agentDetailMaxLength {
		d = d[:agentDetailMaxLength] + "…"
	}
	return d
}

// ── COLLECTION ────────────────────────────────────────────────

func (w *AgentWatcher) collect(cat *AgentCatalog) (Snapshot, error) {
	procs, err := process.Processes()
	if err != nil {
		return Snapshot{}, err
	}

	w.mu.RLock()
	envBase := w.envBase
	autostart := w.autostart
	w.mu.RUnlock()

	// DevShield itself is NOT skipped here: it must stay in the process
	// list so its children don't look orphaned. It is excluded from
	// classification by name via the catalog's ignore_processes.
	seen := make(map[int32]bool, len(procs))
	snap := Snapshot{
		ListenPorts:     map[int32][]int{},
		RemoteEndpoints: map[int32][]string{},
		Behavior:        map[int32]*ProcBehavior{},
		Autostart:       autostart,
	}
	now := time.Now()
	moduleBudget := moduleRefreshPerScan

	for _, p := range procs {
		if p.Pid == 0 {
			continue
		}
		seen[p.Pid] = true
		ct, _ := p.CreateTime()

		// Cmdline/exe/user/env lookups are expensive on Windows — do them
		// once per process lifetime (PID + create time).
		c, ok := w.procCache[p.Pid]
		if !ok || c.createTime != ct {
			c = cachedProc{createTime: ct, info: ProcInfo{PID: p.Pid}}
			c.info.Name, _ = p.Name()
			c.info.PPID, _ = p.Ppid()
			c.info.Exe, _ = p.Exe()
			c.info.Cmdline, _ = p.Cmdline()
			c.info.User, _ = p.Username()
			if env, err := p.Environ(); err == nil {
				c.envHits = llmEnvHits(env, envBase, cat.LLMEnvVars)
			}
		}
		// Libraries load lazily, so module lists are refreshed periodically,
		// a limited number per scan to keep each scan cheap.
		if !cat.ignore[strings.ToLower(c.info.Name)] && moduleBudget > 0 &&
			now.Sub(c.modulesAt) > moduleRefreshAge {
			c.modules = processModules(p.Pid)
			c.modulesAt = now
			moduleBudget--
		}
		w.procCache[p.Pid] = c

		snap.Procs = append(snap.Procs, c.info)
		snap.Behavior[p.Pid] = &ProcBehavior{
			EnvHits:    c.envHits,
			Modules:    c.modules,
			ToolSpawns: w.spawns.recent(p.Pid),
		}
	}
	for pid := range w.procCache {
		if !seen[pid] {
			delete(w.procCache, pid)
		}
	}

	conns, err := gnet.Connections("tcp")
	if err != nil {
		log.Printf("agentwatch: connections: %v", err)
		return snap, nil // process data alone is still useful
	}
	for _, c := range conns {
		switch c.Status {
		case "LISTEN":
			snap.ListenPorts[c.Pid] = append(snap.ListenPorts[c.Pid], int(c.Laddr.Port))
		case "ESTABLISHED":
			snap.RemoteEndpoints[c.Pid] = append(snap.RemoteEndpoints[c.Pid],
				net.JoinHostPort(c.Raddr.IP, fmt.Sprint(c.Raddr.Port)))
		}
	}
	return snap, nil
}

// refreshLLMIPs resolves the catalog's LLM API hosts so connections can be
// matched by IP. Shared CDN IPs make this a weak signal on its own, which
// is why it only adds 2 points in agentScore.
func (w *AgentWatcher) refreshLLMIPs(cat *AgentCatalog) {
	w.mu.RLock()
	fresh := time.Since(w.resolvedAt) < llmResolveInterval
	w.mu.RUnlock()
	if fresh {
		return
	}

	ips := map[string]string{}
	for _, host := range cat.LLMAPIHosts {
		addrs, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ips[a] = host
		}
	}

	w.mu.Lock()
	w.resolvedAt = time.Now()
	if len(ips) > 0 { // offline → keep the last good set
		w.llmIPs = ips
	}
	w.mu.Unlock()
}

func (w *AgentWatcher) refreshAutostart() {
	w.mu.RLock()
	fresh := time.Since(w.autostartAt) < autostartInterval
	w.mu.RUnlock()
	if fresh {
		return
	}
	entries := autostartEntries()
	w.mu.Lock()
	w.autostart = entries
	w.autostartAt = time.Now()
	w.mu.Unlock()
}

// hashFile returns the SHA-256 of a file, cached by size + mtime.
func (w *AgentWatcher) hashFile(path string) string {
	if path == "" {
		return ""
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() > maxHashFileSize {
		return ""
	}
	if h, ok := w.hashCache[path]; ok && h.size == st.Size() && h.modTime.Equal(st.ModTime()) {
		return h.sum
	}

	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return ""
	}
	h := hex.EncodeToString(sum.Sum(nil))
	w.hashCache[path] = hashEntry{size: st.Size(), modTime: st.ModTime(), sum: h}
	return h
}

// ── PUBLIC API ────────────────────────────────────────────────

// verdictRank orders the menu: rogue first, then risky, unsanctioned, sanctioned.
var verdictRank = map[string]int{VerdictRogue: 0, VerdictRisky: 1, VerdictUnsanctioned: 2, VerdictSanctioned: 3}

// RunningAgents returns the agents seen in the latest scan, most urgent first.
func RunningAgents() []RunningAgent {
	agentWatch.mu.RLock()
	defer agentWatch.mu.RUnlock()
	out := make([]RunningAgent, len(agentWatch.running))
	copy(out, agentWatch.running)
	sort.SliceStable(out, func(i, j int) bool {
		return verdictRank[out[i].Verdict] < verdictRank[out[j].Verdict]
	})
	return out
}

// SanctionAgent records the user's approval of one agent installation.
// Behavioural risks still alert after sanctioning (verdict becomes "risky").
func SanctionAgent(fingerprint string) error {
	db := agentDB()
	if db == nil {
		return fmt.Errorf("audit database unavailable")
	}
	if err := setAgentStatus(db, fingerprint, AgentSanctioned); err != nil {
		return err
	}

	agentWatch.mu.Lock()
	name := fingerprint
	for i := range agentWatch.running {
		a := &agentWatch.running[i]
		if a.Fingerprint == fingerprint {
			a.Status = AgentSanctioned
			a.Verdict, a.ActiveRisks = AgentVerdict(a.Status, a.Risks)
			name = a.Name
		}
	}
	cbs := agentWatch.callbacks
	agentWatch.mu.Unlock()

	WriteGoEvent("AGENT_SANCTIONED", name, "ok")
	for _, cb := range cbs {
		go cb()
	}
	return nil
}

// OnAgentsChanged registers a callback fired when the running set, a
// verdict or a sanction status changes. tray.go refreshes its menu here.
func OnAgentsChanged(cb func()) {
	agentWatch.mu.Lock()
	defer agentWatch.mu.Unlock()
	agentWatch.callbacks = append(agentWatch.callbacks, cb)
}
