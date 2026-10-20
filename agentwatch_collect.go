// agentwatch_collect.go — Agent Watch scanner (runs inside the tray)
//
// Every scanInterval it:
//   1. snapshots processes + TCP connections via gopsutil (no admin needed)
//   2. classifies them against the agent catalog (agentwatch.go)
//   3. records each agent in audit.db (agentwatch_store.go)
//   4. writes an audit event when something needs attention:
//        AGENT_NEW                 — an agent never seen before
//        AGENT_UNKNOWN             — a non-catalog process that behaves like an AI agent
//        AGENT_CHANGED             — an agent's executable changed (approval revoked)
//        AGENT_UNSANCTIONED_START  — an unsanctioned agent started running again
//
// Alert only: Agent Watch never kills or blocks a process.

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
	llmResolveInterval   = 15 * time.Minute
	maxHashFileSize      = 512 << 20 // skip hashing executables above 512 MB
	agentDetailMaxLength = 300
)

// RunningAgent is one agent currently running, merged across all of its
// processes (an IDE can have dozens of helper processes).
type RunningAgent struct {
	Detection
	Fingerprint string
	Status      string
	Processes   int
}

type cachedProc struct {
	createTime int64
	info       ProcInfo
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

	llmIPs     map[string]string // ip → LLM API host
	resolvedAt time.Time

	procCache map[int32]cachedProc
	hashCache map[string]hashEntry

	stopCh chan struct{}
}

var agentWatch = &AgentWatcher{
	procCache: map[int32]cachedProc{},
	hashCache: map[string]hashEntry{},
	llmIPs:    map[string]string{},
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
	agentWatch.mu.Unlock()

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

// ── SCANNER GOROUTINE ─────────────────────────────────────────

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
	snap, err := w.collect()
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
		if db == nil {
			continue
		}
		// For script-run agents the script is what can be swapped out,
		// so hash it when it is a file; otherwise hash the executable.
		hashPath := a.Exe
		if a.Target != "" {
			if st, err := os.Stat(a.Target); err == nil && !st.IsDir() {
				hashPath = a.Target
			}
		}
		change, status, err := recordSighting(db, a.Detection, w.hashFile(hashPath), now)
		if err != nil {
			log.Printf("agentwatch: record %s: %v", a.Name, err)
			continue
		}
		a.Status = status

		switch {
		case change == SightingNew && !a.Known:
			WriteGoEvent("AGENT_UNKNOWN", agentDetail(a), "warn")
		case change == SightingNew:
			WriteGoEvent("AGENT_NEW", agentDetail(a), "warn")
		case change == SightingHashChanged:
			WriteGoEvent("AGENT_CHANGED", agentDetail(a), "warn")
		case !prev[a.Fingerprint] && status == AgentUnsanctioned:
			WriteGoEvent("AGENT_UNSANCTIONED_START", agentDetail(a), "warn")
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

// mergeDetections collapses many processes of one agent into one entry.
func mergeDetections(dets []Detection) []RunningAgent {
	byFP := map[string]int{}
	var out []RunningAgent
	for _, d := range dets {
		fp := AgentFingerprint(d)
		if i, ok := byFP[fp]; ok {
			out[i].Processes++
			continue
		}
		byFP[fp] = len(out)
		out = append(out, RunningAgent{Detection: d, Fingerprint: fp, Processes: 1})
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
			ks[i] = x.Fingerprint + "|" + x.Status
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
	d := fmt.Sprintf("%s · %s · %s", a.Name, a.Exe, strings.Join(a.Reasons, "; "))
	if a.Cmdline != "" {
		d += " · cmd: " + redactSecrets(a.Cmdline)
	}
	if len(d) > agentDetailMaxLength {
		d = d[:agentDetailMaxLength] + "…"
	}
	return d
}

// ── COLLECTION ────────────────────────────────────────────────

func (w *AgentWatcher) collect() (Snapshot, error) {
	procs, err := process.Processes()
	if err != nil {
		return Snapshot{}, err
	}

	self := int32(os.Getpid())
	seen := make(map[int32]bool, len(procs))
	snap := Snapshot{
		ListenPorts:     map[int32][]int{},
		RemoteEndpoints: map[int32][]string{},
	}

	for _, p := range procs {
		if p.Pid == self || p.Pid == 0 {
			continue
		}
		seen[p.Pid] = true
		ct, _ := p.CreateTime()

		// Cmdline/exe/user lookups are expensive on Windows — reuse them
		// while the PID still belongs to the same process.
		if c, ok := w.procCache[p.Pid]; ok && c.createTime == ct {
			snap.Procs = append(snap.Procs, c.info)
			continue
		}
		info := ProcInfo{PID: p.Pid}
		info.Name, _ = p.Name()
		info.PPID, _ = p.Ppid()
		info.Exe, _ = p.Exe()
		info.Cmdline, _ = p.Cmdline()
		info.User, _ = p.Username()
		w.procCache[p.Pid] = cachedProc{createTime: ct, info: info}
		snap.Procs = append(snap.Procs, info)
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
// is why it only adds 2 points in scoreUnknown.
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

// hashFile returns the SHA-256 of an executable, cached by size + mtime.
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

// RunningAgents returns the agents seen in the latest scan,
// unknown and unsanctioned ones first.
func RunningAgents() []RunningAgent {
	agentWatch.mu.RLock()
	defer agentWatch.mu.RUnlock()
	out := make([]RunningAgent, len(agentWatch.running))
	copy(out, agentWatch.running)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := out[i].Status == AgentSanctioned, out[j].Status == AgentSanctioned
		if ri != rj {
			return !ri
		}
		return false
	})
	return out
}

// UnsanctionedAgentCount is the number of running agents not yet approved.
func UnsanctionedAgentCount() int {
	n := 0
	for _, a := range RunningAgents() {
		if a.Status != AgentSanctioned {
			n++
		}
	}
	return n
}

// SanctionAgent records the user's approval of one agent installation.
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
		if agentWatch.running[i].Fingerprint == fingerprint {
			agentWatch.running[i].Status = AgentSanctioned
			name = agentWatch.running[i].Name
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

// OnAgentsChanged registers a callback fired when the running set or a
// sanction status changes. tray.go uses it to refresh the agents menu.
func OnAgentsChanged(cb func()) {
	agentWatch.mu.Lock()
	defer agentWatch.mu.Unlock()
	agentWatch.callbacks = append(agentWatch.callbacks, cb)
}
