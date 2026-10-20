// watcher.go — Agent Watch scanner (runs in the root daemon on Linux, in the tray on Windows)
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

package agentwatch

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
	ID          string // short stable id for humans (first 8 hex of sha256(fingerprint))
	Status      string // sanction status from the store
	Verdict     string // sanctioned | unsanctioned | risky | rogue
	ActiveRisks []string
	Processes   int
}

type cachedProc struct {
	createTime int64
	info       ProcInfo
	envLLM     map[string]string // LLM env var name → short hash of its value (never the value)
	envRead    bool              // environment was readable
	modules    []string
	modulesAt  time.Time
}

type hashEntry struct {
	size    int64
	modTime time.Time
	sum     string
}

// Config wires a Watcher to its surroundings.
type Config struct {
	// DB stores sightings and sanction decisions. In the Linux daemon it is a
	// root-only database, so an agent running as the user cannot sanction
	// itself. nil keeps everything in memory (every agent unsanctioned).
	DB *sql.DB
	// Emit receives audit events (action, detail, status). nil discards them.
	Emit func(action, detail, status string)
	// CatalogOverride is an optional catalog file that replaces the built-in
	// one. It must only be writable by a trusted user (root in the daemon).
	CatalogOverride string
}

// Watcher scans processes for AI agents and judges them.
type Watcher struct {
	cfg Config

	mu        sync.RWMutex
	catalog   *AgentCatalog
	running   []RunningAgent
	callbacks []func()

	llmIPs      map[string]string // ip → LLM API host
	resolvedAt  time.Time
	autostart   map[string]string
	autostartAt time.Time

	ownEnv    map[string]string // our own LLM env (name → value hash)
	procCache map[int32]cachedProc
	hashCache map[string]hashEntry
	spawns    *spawnTracker
	alerted   map[string]string // fingerprint → verdict+risks last alerted

	stopOnce sync.Once
	stopCh   chan struct{}
}

// New loads the catalog and prepares the store. Call Start to begin scanning.
// A broken catalog override is reported through Emit and the built-in
// catalog is used instead.
func New(cfg Config) (*Watcher, error) {
	w := &Watcher{
		cfg:       cfg,
		procCache: map[int32]cachedProc{},
		hashCache: map[string]hashEntry{},
		llmIPs:    map[string]string{},
		autostart: map[string]string{},
		spawns:    newSpawnTracker(spawnWindow),
		alerted:   map[string]string{},
		stopCh:    make(chan struct{}),
	}
	cat, err := LoadAgentCatalog(cfg.CatalogOverride)
	if cat == nil {
		return nil, err
	}
	if err != nil {
		w.emit("AGENT_CATALOG_WARNING", err.Error(), "warn")
	}
	if cfg.DB != nil {
		if err := ensureAgentSchema(cfg.DB); err != nil {
			return nil, fmt.Errorf("agentwatch: schema: %w", err)
		}
	}
	w.catalog = cat
	w.ownEnv = llmEnvValues(os.Environ(), cat.LLMEnvVars)
	return w, nil
}

// Start begins the fast spawn tick and the periodic scan.
func (w *Watcher) Start() {
	go w.runSpawnTicker()
	go w.run()
	log.Printf("agentwatch: started (catalog %s, %d agents)", w.catalog.Version, len(w.catalog.Agents))
}

// Stop ends scanning. Safe to call more than once.
func (w *Watcher) Stop() {
	w.stopOnce.Do(func() { close(w.stopCh) })
}

// Catalog returns the catalog in use.
func (w *Watcher) Catalog() *AgentCatalog { return w.catalog }

func (w *Watcher) emit(action, detail, status string) {
	if w.cfg.Emit != nil {
		w.cfg.Emit(action, detail, status)
	}
}

func nowISO() string { return time.Now().UTC().Format(time.RFC3339) }

// ── LOOPS ─────────────────────────────────────────────────────

func (w *Watcher) runSpawnTicker() {
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

func (w *Watcher) run() {
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

func (w *Watcher) scan() {
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
	db := w.cfg.DB
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
				w.emit("AGENT_NEW", agentDetail(a), "warn")
			} else {
				w.emit("AGENT_UNKNOWN", agentDetail(a), "warn")
			}
		case SightingHashChanged:
			w.emit("AGENT_CHANGED", agentDetail(a), "warn")
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
func (w *Watcher) alertVerdict(a *RunningAgent, wasRunning bool) {
	key := a.Verdict + "|" + strings.Join(a.ActiveRisks, "|")
	if w.alerted[a.Fingerprint] == key {
		return
	}
	w.alerted[a.Fingerprint] = key

	switch a.Verdict {
	case VerdictRogue:
		w.emit("AGENT_ROGUE_SUSPECT", agentDetail(a), "warn")
	case VerdictRisky:
		w.emit("AGENT_RISKY", agentDetail(a), "warn")
	case VerdictUnsanctioned:
		if !wasRunning {
			w.emit("AGENT_UNSANCTIONED_START", agentDetail(a), "warn")
		}
	}
}

func shortID(fingerprint string) string {
	sum := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(sum[:4])
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
			out = append(out, RunningAgent{Detection: d, Fingerprint: fp, ID: shortID(fp), Processes: 1})
			continue
		}
		a := &out[i]
		a.Processes++
		if d.AgentScore > a.AgentScore {
			a.AgentScore = d.AgentScore
		}
		for _, r := range d.Reasons {
			if !hasReasonKind(a.Reasons, r) {
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

// hasReasonKind reports whether list already has a reason of the same kind
// as r, ignoring counts ("ran 26 shells…" and "ran 24 shells…" are one kind),
// so merging an agent's processes doesn't repeat itself.
func hasReasonKind(list []string, r string) bool {
	k := reasonKind(r)
	for _, x := range list {
		if reasonKind(x) == k {
			return true
		}
	}
	return false
}

func reasonKind(r string) string {
	if i := strings.IndexByte(r, '('); i > 0 {
		r = r[:i]
	}
	return strings.Map(func(c rune) rune {
		if c >= '0' && c <= '9' {
			return -1
		}
		return c
	}, r)
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

func (w *Watcher) collect(cat *AgentCatalog) (Snapshot, error) {
	procs, err := process.Processes()
	if err != nil {
		return Snapshot{}, err
	}

	w.mu.RLock()
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
				c.envLLM = llmEnvValues(env, cat.LLMEnvVars)
				c.envRead = true
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
			Modules:    c.modules,
			ToolSpawns: w.spawns.recent(p.Pid),
		}
	}
	for pid := range w.procCache {
		if !seen[pid] {
			delete(w.procCache, pid)
		}
	}

	// An LLM key only counts for the process that INTRODUCED it (parent
	// lacks the same key+value). Children inherit; they don't count.
	for pid, c := range w.procCache {
		b := snap.Behavior[pid]
		if b == nil || len(c.envLLM) == 0 {
			continue
		}
		parent, ok := w.procCache[c.info.PPID]
		var parentVars map[string]string
		if ok && parent.envRead {
			parentVars = parent.envLLM
		}
		parentName := strings.ToLower(parent.info.Name)
		parentIsShell := ok && (cat.shells[parentName] || cat.termHosts[parentName])
		b.EnvHits = envHitsIntroduced(c.envLLM, parentVars, parentIsShell, w.ownEnv)
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
func (w *Watcher) refreshLLMIPs(cat *AgentCatalog) {
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

func (w *Watcher) refreshAutostart() {
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
func (w *Watcher) hashFile(path string) string {
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

// Running returns the agents seen in the latest scan, most urgent first.
func (w *Watcher) Running() []RunningAgent {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]RunningAgent, len(w.running))
	copy(out, w.running)
	sort.SliceStable(out, func(i, j int) bool {
		return verdictRank[out[i].Verdict] < verdictRank[out[j].Verdict]
	})
	return out
}

// Sanction records the owner's approval of one agent installation.
// Behavioural risks still alert afterwards (verdict becomes "risky").
// In the daemon, callers must already have verified the request comes
// from the owner (root); the Watcher itself does not authenticate.
func (w *Watcher) Sanction(fingerprint string) error {
	return w.setStatus(fingerprint, AgentSanctioned, "AGENT_SANCTIONED")
}

// Revoke withdraws a sanction.
func (w *Watcher) Revoke(fingerprint string) error {
	return w.setStatus(fingerprint, AgentUnsanctioned, "AGENT_REVOKED")
}

func (w *Watcher) setStatus(fingerprint, status, event string) error {
	if w.cfg.DB == nil {
		return fmt.Errorf("no agent database configured")
	}
	n, err := setAgentStatus(w.cfg.DB, fingerprint, status)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("unknown agent %q", fingerprint)
	}

	w.mu.Lock()
	name := fingerprint
	for i := range w.running {
		a := &w.running[i]
		if a.Fingerprint == fingerprint {
			a.Status = status
			a.Verdict, a.ActiveRisks = AgentVerdict(a.Status, a.Risks)
			name = a.Name
		}
	}
	cbs := w.callbacks
	w.mu.Unlock()

	w.emit(event, name, "ok")
	for _, cb := range cbs {
		go cb()
	}
	return nil
}

// ResolveID maps a short agent ID (as shown by the CLI) or a full
// fingerprint to a fingerprint among the running agents.
func (w *Watcher) ResolveID(id string) (string, error) {
	var match []string
	for _, a := range w.Running() {
		if a.Fingerprint == id || strings.HasPrefix(a.ID, strings.ToLower(id)) {
			match = append(match, a.Fingerprint)
		}
	}
	switch len(match) {
	case 0:
		return "", fmt.Errorf("no running agent with id %q", id)
	case 1:
		return match[0], nil
	}
	return "", fmt.Errorf("id %q is ambiguous (%d agents)", id, len(match))
}

// OnChange registers a callback fired when the running set, a verdict or
// a sanction status changes.
func (w *Watcher) OnChange(cb func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.callbacks = append(w.callbacks, cb)
}
