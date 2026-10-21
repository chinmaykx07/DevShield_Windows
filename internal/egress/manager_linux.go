package egress

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config for a Manager.
type Config struct {
	StateDir   string // root-only; egress.json lives here
	ProcRoot   string // "" = /proc
	CgroupRoot string // "" = find the cgroup2 mount in /proc/self/mountinfo
	// Nft runs an nft script (check=true: validate only). nil = the nft binary.
	Nft func(script string, check bool) error
	// NftList prints DevShield's chain as the kernel has it. nil = nft.
	NftList func() (string, error)
	Emit    func(action, detail, status string)
}

// Member is one agent DevShield placed in its quarantine or allowed group.
type Member struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Since   time.Time      `json:"since"`
	Origins map[int]string `json:"origins"`         // pid → cgroup it came from, to put it back on release
	Flows   []Flow         `json:"flows,omitempty"` // quarantine only: sockets that predate the block
}

type state struct {
	Blocked  map[string]*Member `json:"blocked"`           // by agent fingerprint
	Allowed  map[string]*Member `json:"allowed,omitempty"` // by agent fingerprint
	Lockdown *Lockdown          `json:"lockdown,omitempty"`
}

// Manager owns DevShield's nftables table and quarantine cgroup.
type Manager struct {
	mu        sync.Mutex
	cfg       Config
	cgRoot    string // "" = no cgroup v2 (quarantine unavailable)
	st        state
	pending   *time.Timer // lockdown awaiting confirmation
	pendingBy time.Time
	prevLock  *Lockdown // restored if a pending lockdown is not confirmed
}

// Status is what the egress controls look like right now.
type Status struct {
	CgroupV2         bool        `json:"cgroup_v2"`
	RulesLoaded      bool        `json:"rules_loaded"`
	Blocked          []BlockInfo `json:"blocked,omitempty"`
	Lockdown         *Lockdown   `json:"lockdown,omitempty"`
	ConfirmBy        time.Time   `json:"confirm_by,omitempty"`
	QuarantinedProcs int         `json:"quarantined_processes"`
	Allowed          []BlockInfo `json:"allowed,omitempty"`
	AllowedProcs     int         `json:"allowed_processes"`
}

// BlockInfo is the client view of one blocked agent.
type BlockInfo struct {
	ID    string    `json:"id"`
	Name  string    `json:"name"`
	Since time.Time `json:"since"`
	Flows int       `json:"flows_cut"`
}

// New loads the saved policy and re-applies it: rules and cgroups do not
// survive a reboot, the owner's decisions do.
func New(cfg Config) (*Manager, error) {
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	if cfg.Nft == nil {
		cfg.Nft = runNft
	}
	if cfg.NftList == nil {
		cfg.NftList = listNft
	}
	if cfg.Emit == nil {
		cfg.Emit = func(string, string, string) {}
	}
	m := &Manager{cfg: cfg, st: state{Blocked: map[string]*Member{}, Allowed: map[string]*Member{}}}
	m.cgRoot = cfg.CgroupRoot
	if m.cgRoot == "" {
		m.cgRoot = findCgroup2(cfg.ProcRoot)
	}
	data, err := os.ReadFile(m.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return m, nil // never used: don't touch the firewall at all
	}
	if err == nil {
		if err := json.Unmarshal(data, &m.st); err != nil {
			return nil, fmt.Errorf("egress state %s: %w", m.statePath(), err)
		}
		if m.st.Blocked == nil {
			m.st.Blocked = map[string]*Member{}
		}
		if m.st.Allowed == nil {
			m.st.Allowed = map[string]*Member{}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tidy() // after a reboot, saved processes and sockets are long gone
	if len(m.st.Blocked) > 0 && m.cgRoot != "" {
		if err := os.MkdirAll(m.quarantineDir(), 0o755); err != nil {
			return nil, err
		}
	}
	if len(m.st.Allowed) > 0 && m.cgRoot != "" {
		if err := os.MkdirAll(m.groupDir(AllowedCgroup), 0o755); err != nil {
			return nil, err
		}
	}
	if err := m.apply(); err != nil {
		return m, err
	}
	return m, nil
}

func (m *Manager) statePath() string        { return filepath.Join(m.cfg.StateDir, "egress.json") }
func (m *Manager) quarantineDir() string    { return m.groupDir(QuarantineCgroup) }
func (m *Manager) groupDir(g string) string { return filepath.Join(m.cgRoot, g) }

// nftCgroupBase is where nft resolves "socket cgroupv2" paths (hardcoded
// in nftables), so the rule names the group relative to it.
const nftCgroupBase = "/sys/fs/cgroup"

// findCgroup2 returns the cgroup v2 mount point usable for quarantine, or
// "". Unified systems mount it at /sys/fs/cgroup; "hybrid" ones (cgroup v1
// for controllers) at /sys/fs/cgroup/unified. Only mounts under
// /sys/fs/cgroup work, because that is where nft looks the group up.
func findCgroup2(procRoot string) string {
	f, err := os.Open(filepath.Join(procRoot, "self", "mountinfo"))
	if err != nil {
		return ""
	}
	defer f.Close()
	var found []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// "36 25 0:30 / /sys/fs/cgroup rw,... - cgroup2 cgroup2 rw"
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		pf, qf := strings.Fields(pre), strings.Fields(post)
		if ok && len(pf) >= 5 && len(qf) >= 1 && qf[0] == "cgroup2" && pf[3] == "/" {
			found = append(found, pf[4])
		}
	}
	for _, want := range []string{nftCgroupBase, nftCgroupBase + "/unified"} {
		for _, mnt := range found {
			// A later mount can hide an earlier one: check it is reachable.
			if mnt == want && fileExists(filepath.Join(procRoot, "self", "root", mnt, "cgroup.procs"), filepath.Join(mnt, "cgroup.procs")) {
				return mnt
			}
		}
	}
	return ""
}

// fileExists reports whether any of paths exists.
func fileExists(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// policy builds the ruleset for the current state. The quarantine rule is
// present whenever the group exists, so leftover members stay cut off.
func (m *Manager) policy() Policy {
	p := Policy{Lockdown: m.st.Lockdown}
	if m.cgRoot != "" {
		if _, err := os.Stat(m.quarantineDir()); err == nil {
			p.Quarantine = true
			p.CgroupPath, _ = filepath.Rel(nftCgroupBase, m.quarantineDir())
		}
		if _, err := os.Stat(m.groupDir(AllowedCgroup)); err == nil && p.Lockdown != nil {
			p.AllowedPath, _ = filepath.Rel(nftCgroupBase, m.groupDir(AllowedCgroup))
		}
	}
	fps := make([]string, 0, len(m.st.Blocked))
	for fp := range m.st.Blocked {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	for _, fp := range fps {
		p.KillFlows = append(p.KillFlows, m.st.Blocked[fp].Flows...)
	}
	return p
}

// apply validates then atomically loads the ruleset (caller holds mu).
func (m *Manager) apply() error {
	script, err := Render(m.policy())
	if err != nil {
		return err
	}
	if err := m.cfg.Nft(script, true); err != nil {
		return fmt.Errorf("nft rejected the ruleset, nothing changed: %w", err)
	}
	return m.cfg.Nft(script, false)
}

func (m *Manager) save() error {
	data, err := json.MarshalIndent(m.st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.cfg.StateDir, 0o700); err != nil {
		return err
	}
	tmp := m.statePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.statePath())
}

// ── Quarantine ──

// Block cuts an agent (and everything it spawns) off the network, loopback
// included, without affecting other programs. pids may be empty when the
// agent is not running: it is then quarantined as soon as it appears.
func (m *Manager) Block(fp, id, name string, pids []int) (moved, flows int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cgRoot == "" {
		return 0, 0, errors.New("network quarantine needs the cgroup v2 hierarchy (unified cgroups), which is not mounted on this system")
	}
	_, statErr := os.Stat(m.quarantineDir())
	created := statErr != nil
	if err := os.MkdirAll(m.quarantineDir(), 0o755); err != nil {
		return 0, 0, err
	}
	if m.st.Allowed[fp] != nil {
		m.release(m.st.Allowed, fp, AllowedCgroup) // block wins over an earlier allow
	}
	b := m.st.Blocked[fp]
	isNew := b == nil
	if isNew {
		b = &Member{ID: id, Name: name, Since: time.Now().UTC(), Origins: map[int]string{}}
		m.st.Blocked[fp] = b
	}
	// Load the quarantine rule BEFORE moving anyone: every socket created
	// after the move is then blocked from its first packet.
	if err := m.apply(); err != nil {
		if isNew {
			delete(m.st.Blocked, fp)
		}
		if created {
			os.Remove(m.quarantineDir()) // or every later ruleset would carry the failing rule
		}
		return 0, 0, err
	}
	moved = m.capture(b, pids, QuarantineCgroup)
	n := len(b.Flows)
	m.refreshFlows(b)
	if err := m.apply(); err != nil {
		return moved, 0, fmt.Errorf("processes are quarantined but cutting their existing connections failed: %w", err)
	}
	if err := m.save(); err != nil {
		return moved, len(b.Flows) - n, err
	}
	return moved, len(b.Flows) - n, nil
}

// capture moves pids and all their descendants into group, recording
// where each came from. It repeats until no new child appears, since a
// process can fork while its parent is being moved.
func (m *Manager) capture(b *Member, pids []int, group string) int {
	moved := 0
	want := map[int]bool{}
	for _, p := range pids {
		want[p] = true
	}
	for round := 0; round < 5 && len(want) > 0; round++ {
		for pid := range want {
			if pid <= 1 || pid == os.Getpid() {
				continue // never init or DevShield itself
			}
			cur := m.cgroupOf(pid)
			if cur == "" || cur == "/"+group {
				continue
			}
			if err := os.WriteFile(filepath.Join(m.groupDir(group), "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
				continue // exited, or a kernel thread
			}
			if !isDevShieldGroup(cur) { // keep the true origin when moving between our groups
				b.Origins[pid] = cur
			}
			moved++
		}
		next := map[int]bool{}
		for pid := range descendants(m.cfg.ProcRoot, keys(b.Origins)) {
			if _, done := b.Origins[pid]; !done && m.cgroupOf(pid) != "/"+group {
				next[pid] = true
			}
		}
		want = next
	}
	return moved
}

// refreshFlows records the agent's sockets that predate the quarantine.
func (m *Manager) refreshFlows(b *Member) {
	have := map[Flow]bool{}
	for _, f := range b.Flows {
		have[f] = true
	}
	for _, f := range OpenFlows(m.cfg.ProcRoot, keys(b.Origins)) {
		if !have[f] {
			have[f] = true
			b.Flows = append(b.Flows, f)
		}
	}
}

// Unblock restores the agent's network access and moves its processes
// back to the groups they came from.
func (m *Manager) Unblock(fp string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st.Blocked[fp] == nil {
		return errors.New("that agent is not blocked")
	}
	m.release(m.st.Blocked, fp, QuarantineCgroup)
	if err := m.apply(); err != nil {
		return err
	}
	return m.save()
}

// release moves fp's processes out of group back to where they came from
// and forgets it (caller holds mu, then applies and saves).
func (m *Manager) release(set map[string]*Member, fp, group string) {
	b := set[fp]
	if m.cgRoot != "" {
		pp := parents(m.cfg.ProcRoot)
		for _, pid := range m.members(group) {
			if origin, ok := originFor(pp, pid, b.Origins); ok {
				m.moveTo(pid, origin)
			}
		}
	}
	delete(set, fp)
	if len(set) == 0 && m.cgRoot != "" {
		os.Remove(m.groupDir(group)) // fails (and the rule stays) while anything is still inside
	}
}

// ── Allow ──

// Allow lets an agent (and what it spawns) reach the network during a
// lockdown. The caller decides whether the agent deserves it (DevShield's
// daemon requires a sanctioned agent with a clean verdict).
func (m *Manager) Allow(fp, id, name string, pids []int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cgRoot == "" {
		return 0, errors.New("allowing single agents needs the cgroup v2 hierarchy (unified cgroups), which is not mounted on this system")
	}
	if m.st.Blocked[fp] != nil {
		return 0, errors.New("that agent is blocked; unblock it first")
	}
	if err := os.MkdirAll(m.groupDir(AllowedCgroup), 0o755); err != nil {
		return 0, err
	}
	b := m.st.Allowed[fp]
	if b == nil {
		b = &Member{ID: id, Name: name, Since: time.Now().UTC(), Origins: map[int]string{}}
		m.st.Allowed[fp] = b
	}
	// The accept rule must exist before members are added (nft resolves
	// the group when loading); moving first would only drop more, never less.
	if err := m.apply(); err != nil {
		delete(m.st.Allowed, fp)
		if len(m.st.Allowed) == 0 {
			os.Remove(m.groupDir(AllowedCgroup))
		}
		return 0, err
	}
	moved := m.capture(b, pids, AllowedCgroup)
	return moved, m.save()
}

// Disallow withdraws an allow.
func (m *Manager) Disallow(fp string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st.Allowed[fp] == nil {
		return errors.New("that agent is not allowed")
	}
	m.release(m.st.Allowed, fp, AllowedCgroup)
	if err := m.apply(); err != nil {
		return err
	}
	return m.save()
}

// IsAllowed reports whether fp is allowed.
func (m *Manager) IsAllowed(fp string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st.Allowed[fp] != nil
}

// AllowedFingerprints lists allowed agents.
func (m *Manager) AllowedFingerprints() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.st.Allowed))
	for fp := range m.st.Allowed {
		out = append(out, fp)
	}
	return out
}

func isDevShieldGroup(cg string) bool {
	return cg == "/"+QuarantineCgroup || cg == "/"+AllowedCgroup
}

// moveTo puts pid back into origin, or the root group if origin is gone.
func (m *Manager) moveTo(pid int, origin string) {
	dir := filepath.Join(m.cgRoot, filepath.Clean("/"+origin))
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
		os.WriteFile(filepath.Join(m.cgRoot, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0)
	}
}

// Reconcile re-quarantines blocked agents whose processes (re)appeared
// outside the group — e.g. the agent was restarted. running maps agent
// fingerprint → current pids. It returns the ids that were re-captured.
func (m *Manager) Reconcile(running map[string][]int) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cgRoot == "" {
		return nil
	}
	changed := m.tidy()
	var caught []string
	for fp, b := range m.st.Blocked {
		var loose []int
		for _, pid := range running[fp] {
			if c := m.cgroupOf(pid); c != "" && c != "/"+QuarantineCgroup {
				loose = append(loose, pid)
			}
		}
		if len(loose) == 0 {
			continue
		}
		if err := os.MkdirAll(m.quarantineDir(), 0o755); err != nil {
			continue
		}
		if m.capture(b, loose, QuarantineCgroup) > 0 {
			m.refreshFlows(b)
			caught = append(caught, b.ID)
		}
	}
	for fp, b := range m.st.Allowed {
		var loose []int
		for _, pid := range running[fp] {
			if c := m.cgroupOf(pid); c != "" && c != "/"+AllowedCgroup {
				loose = append(loose, pid)
			}
		}
		if len(loose) > 0 && os.MkdirAll(m.groupDir(AllowedCgroup), 0o755) == nil && m.capture(b, loose, AllowedCgroup) > 0 {
			changed = true // a restarted allowed agent may go out again
		}
	}
	if len(caught) > 0 || changed {
		if err := m.apply(); err != nil {
			m.cfg.Emit("EGRESS_APPLY_FAILED", err.Error(), "fail")
		}
		if err := m.save(); err != nil {
			m.cfg.Emit("EGRESS_SAVE_FAILED", err.Error(), "fail")
		}
	}
	return caught
}

// tidy forgets processes that have exited (so a reused PID is never
// mistaken for the agent) and drops the rules of sockets that no longer
// exist (so a port the agent once listened on is not blocked for the next
// program that uses it). It reports whether the ruleset needs reloading.
// Caller holds mu.
func (m *Manager) tidy() bool {
	live := liveFlows(m.cfg.ProcRoot)
	changed := false
	for _, b := range m.st.Allowed {
		for pid := range b.Origins {
			if _, err := os.Stat(filepath.Join(m.cfg.ProcRoot, strconv.Itoa(pid))); err != nil {
				delete(b.Origins, pid)
			}
		}
	}
	for _, b := range m.st.Blocked {
		for pid := range b.Origins {
			if _, err := os.Stat(filepath.Join(m.cfg.ProcRoot, strconv.Itoa(pid))); err != nil {
				delete(b.Origins, pid)
			}
		}
		kept := b.Flows[:0]
		for _, f := range b.Flows {
			if live[f] {
				kept = append(kept, f)
			}
		}
		if len(kept) != len(b.Flows) {
			changed = true
		}
		b.Flows = kept
	}
	return changed
}

// IsBlocked reports whether fp is quarantined.
func (m *Manager) IsBlocked(fp string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st.Blocked[fp] != nil
}

// ResolveBlocked maps a short id (prefix) to the fingerprint of a blocked
// agent, so agents that are not running can still be unblocked.
func (m *Manager) ResolveBlocked(id string) (string, bool) {
	return m.resolveIn(id, false)
}

// ResolveAllowed is ResolveBlocked for allowed agents.
func (m *Manager) ResolveAllowed(id string) (string, bool) {
	return m.resolveIn(id, true)
}

func (m *Manager) resolveIn(id string, allowed bool) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.st.Blocked
	if allowed {
		set = m.st.Allowed
	}
	var hit []string
	for fp, b := range set {
		if fp == id || (id != "" && strings.HasPrefix(b.ID, strings.ToLower(id))) {
			hit = append(hit, fp)
		}
	}
	if len(hit) == 1 {
		return hit[0], true
	}
	return "", false
}

// members lists pids currently in group.
func (m *Manager) members(group string) []int {
	data, err := os.ReadFile(filepath.Join(m.groupDir(group), "cgroup.procs"))
	if err != nil {
		return nil
	}
	var out []int
	for _, f := range strings.Fields(string(data)) {
		if n, err := strconv.Atoi(f); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// cgroupOf returns pid's cgroup v2 path ("/user.slice/…"), "" if unknown.
func (m *Manager) cgroupOf(pid int) string {
	data, err := os.ReadFile(filepath.Join(m.cfg.ProcRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return rest
		}
	}
	return ""
}

// ── Lockdown ──

// LockdownOn restricts all outbound traffic to l. With confirmWithin > 0
// the change reverts by itself unless Confirm is called in time (a
// dead-man switch for remote sessions and untested tunnels).
func (m *Manager) LockdownOn(l Lockdown, confirmWithin time.Duration) error {
	if err := l.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := m.st.Lockdown
	if m.pending != nil {
		m.pending.Stop()
		prev = m.prevLock
	}
	m.st.Lockdown = &l
	if err := m.apply(); err != nil {
		m.st.Lockdown = prev
		return err
	}
	if confirmWithin <= 0 {
		m.pending = nil
		return m.save()
	}
	m.prevLock, m.pendingBy = prev, time.Now().Add(confirmWithin)
	m.pending = time.AfterFunc(confirmWithin, m.revertPending)
	// Persist the PREVIOUS lockdown: if the daemon restarts before the
	// confirmation, the unconfirmed change must not come back.
	cur := m.st.Lockdown
	m.st.Lockdown = prev
	err := m.save()
	m.st.Lockdown = cur
	return err
}

func (m *Manager) revertPending() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return
	}
	m.pending = nil
	m.st.Lockdown = m.prevLock
	if err := m.apply(); err != nil {
		m.cfg.Emit("LOCKDOWN_REVERT_FAILED", err.Error(), "fail")
		return
	}
	m.cfg.Emit("LOCKDOWN_REVERTED", "not confirmed in time; previous network policy restored", "warn")
}

// Confirm keeps a pending lockdown.
func (m *Manager) Confirm() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return errors.New("no lockdown is waiting for confirmation")
	}
	m.pending.Stop()
	m.pending = nil
	return m.save()
}

// LockdownOff removes the lockdown (quarantine stays).
func (m *Manager) LockdownOff() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending != nil {
		m.pending.Stop()
		m.pending = nil
	}
	m.st.Lockdown = nil
	if err := m.apply(); err != nil {
		return err
	}
	return m.save()
}

// ── Health ──

// Status reports the saved policy and whether the kernel still has it.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{CgroupV2: m.cgRoot != "", Lockdown: m.st.Lockdown, RulesLoaded: m.rulesLoaded()}
	if m.pending != nil {
		st.ConfirmBy = m.pendingBy
	}
	for _, b := range m.st.Blocked {
		st.Blocked = append(st.Blocked, BlockInfo{ID: b.ID, Name: b.Name, Since: b.Since, Flows: len(b.Flows)})
	}
	for _, b := range m.st.Allowed {
		st.Allowed = append(st.Allowed, BlockInfo{ID: b.ID, Name: b.Name, Since: b.Since})
	}
	sort.Slice(st.Blocked, func(i, j int) bool { return st.Blocked[i].ID < st.Blocked[j].ID })
	sort.Slice(st.Allowed, func(i, j int) bool { return st.Allowed[i].ID < st.Allowed[j].ID })
	if m.cgRoot != "" {
		st.QuarantinedProcs = len(m.members(QuarantineCgroup))
		st.AllowedProcs = len(m.members(AllowedCgroup))
	}
	return st
}

// rulesLoaded checks the kernel has exactly our rules: not only that the
// table exists, but that no rule in it was removed, added, reordered or
// had its verdict changed.
func (m *Manager) rulesLoaded() bool {
	p := m.policy()
	if p.Empty() {
		return true
	}
	want, err := Render(p)
	if err != nil {
		return false
	}
	have, err := m.cfg.NftList()
	if err != nil {
		return false
	}
	return slices.Equal(ruleShape(want), ruleShape(have))
}

// ruleShape reduces a chain to one "first-word verdict" entry per rule.
// It reads both our rendered script and nft's listing (which adds counter
// values and limit bursts but keeps each rule on one line, in order).
func ruleShape(chain string) []string {
	var out []string
	in := false
	for _, line := range strings.Split(chain, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "chain egress"):
			in = true
			continue
		case !in || line == "" || strings.HasPrefix(line, "type "):
			continue
		case line == "}":
			return out
		}
		if i := strings.Index(line, ` comment "`); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		verdict := f[len(f)-1]
		if verdict != "accept" && verdict != "drop" {
			verdict = "-"
		}
		out = append(out, f[0]+" "+verdict)
	}
	return out
}

// EnsureLoaded re-applies the ruleset if something removed or altered it
// (e.g. a firewall service ran "flush ruleset"). It reports whether it had to.
func (m *Manager) EnsureLoaded() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rulesLoaded() {
		return false, nil
	}
	return true, m.apply()
}

// ── helpers ──

func nftBinary() string {
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "nft"
}

// listNft prints DevShield's chain from the kernel.
func listNft() (string, error) {
	out, err := exec.Command(nftBinary(), "list", "chain", "inet", TableName, "egress").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// runNft feeds a script to the nft binary.
func runNft(script string, check bool) error {
	bin := nftBinary()
	args := []string{"-f", "-"}
	if check {
		args = []string{"-c", "-f", "-"}
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

func keys(m map[int]string) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// parents maps every pid under procRoot to its parent pid.
func parents(procRoot string) map[int]int {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	out := map[int]int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "stat"))
		if err != nil {
			continue
		}
		// "pid (comm) state ppid ..." — comm may contain spaces and ')'.
		s := string(data)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) >= 2 {
			if pp, err := strconv.Atoi(f[1]); err == nil {
				out[pid] = pp
			}
		}
	}
	return out
}

// descendants returns every live process below roots (roots excluded).
func descendants(procRoot string, roots []int) map[int]bool {
	pp := parents(procRoot)
	in := map[int]bool{}
	for _, r := range roots {
		in[r] = true
	}
	out := map[int]bool{}
	for changed := true; changed; {
		changed = false
		for pid, parent := range pp {
			if in[parent] && !in[pid] {
				in[pid], out[pid], changed = true, true, true
			}
		}
	}
	return out
}

// originFor finds where pid should return to: its own recorded origin, or
// that of its nearest recorded ancestor (children born in quarantine).
func originFor(pp map[int]int, pid int, origins map[int]string) (string, bool) {
	for hops := 0; pid > 1 && hops < 64; hops++ {
		if o, ok := origins[pid]; ok {
			return o, true
		}
		pid = pp[pid]
	}
	return "", false
}
