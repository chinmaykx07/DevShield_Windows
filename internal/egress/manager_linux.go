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
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
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
	// ProcStart returns a live (non-zombie) process's creation time as
	// gopsutil reports it; ok=false if it is gone. nil = gopsutil.
	ProcStart func(pid int) (start int64, ok bool)
	Emit      func(action, detail, status string)
}

// Proc is a process to act on, as identified by Agent Watch. Start (its
// creation time; 0 = unknown) is re-checked before anything is done, so a
// PID reused since the scan is never touched.
type Proc struct {
	PID   int
	Start int64
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
	nftBase   string // where nft resolves cgroup paths (nftCgroupBase; tests change it)
	st        state
	pending   *time.Timer // lockdown awaiting confirmation
	pendingBy time.Time
	prevLock  *Lockdown // restored if a pending lockdown is not confirmed
	gen       int       // bumped on every lockdown change; a stale timer must not revert a newer one
	corrupt   error     // the saved state could not be read: keep the kernel as it is
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
	Problem          string      `json:"problem,omitempty"` // e.g. unreadable saved state
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
	if cfg.ProcStart == nil {
		cfg.ProcStart = procStart
	}
	if cfg.Emit == nil {
		cfg.Emit = func(string, string, string) {}
	}
	m := &Manager{cfg: cfg, st: state{Blocked: map[string]*Member{}, Allowed: map[string]*Member{}}}
	m.cgRoot, m.nftBase = cfg.CgroupRoot, nftCgroupBase
	if m.cgRoot == "" {
		m.cgRoot = findCgroup2(cfg.ProcRoot)
	}
	data, err := os.ReadFile(m.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return m, nil // never used: don't touch the firewall at all
	}
	if err == nil {
		if err := json.Unmarshal(data, &m.st); err != nil {
			// Fail closed: whatever rules the kernel holds stay as they are
			// (a lockdown must not silently open), and every change except
			// restore-all is refused until the owner decides.
			aside := fmt.Sprintf("%s.corrupt-%d", m.statePath(), time.Now().Unix())
			kept := "kept as " + aside
			if rerr := os.Rename(m.statePath(), aside); rerr != nil {
				aside, kept = m.statePath(), "left in place: "+rerr.Error()
			}
			m.st = state{Blocked: map[string]*Member{}, Allowed: map[string]*Member{}}
			m.corrupt = fmt.Errorf("network state file was unreadable (%v; %s). DevShield doesn't know which lockdown or blocks you had: the rules already in the kernel (if any) stay as they are, but after a reboot none are loaded. Run 'sudo devshield restore-all' to start clean", err, kept)
			return m, m.corrupt
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
			p.CgroupPath, _ = filepath.Rel(m.nftBase, m.quarantineDir())
		}
		if _, err := os.Stat(m.groupDir(AllowedCgroup)); err == nil && p.Lockdown != nil {
			p.AllowedPath, _ = filepath.Rel(m.nftBase, m.groupDir(AllowedCgroup))
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
	st := m.st
	if m.pending != nil {
		// An unconfirmed lockdown is never persisted: after a restart or
		// reboot the previous, confirmed policy must come back, not it.
		st.Lockdown = m.prevLock
	}
	data, err := json.MarshalIndent(st, "", "  ")
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
func (m *Manager) Block(fp, id, name string, pids []Proc) (moved, flows int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.corrupt != nil {
		return 0, 0, m.corrupt
	}
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
	moved = m.capture(b, pids, QuarantineCgroup, true)
	n := len(b.Flows)
	m.refreshFlows(b)
	if err := m.apply(); err != nil {
		m.save() // the block itself holds (the group's rule is loaded): remember it
		return moved, 0, fmt.Errorf("processes are quarantined but cutting their existing connections failed: %w", err)
	}
	if err := m.save(); err != nil {
		return moved, len(b.Flows) - n, err
	}
	return moved, len(b.Flows) - n, nil
}

// capture moves pids into group, recording where each came from. With
// descendants it also sweeps in every existing child, repeating until no
// new one appears (a process can fork while its parent is being moved).
// Blocking sweeps (cutting too much is the safe side); allowing does not,
// since it grants a privilege: only the processes Agent Watch identified
// get it, plus whatever they start later (children inherit the group).
func (m *Manager) capture(b *Member, procs []Proc, group string, descend bool) int {
	moved := 0
	want := map[int]bool{}
	for _, p := range procs {
		// The scan may be seconds old: only act on the very same process.
		if start, ok := m.cfg.ProcStart(p.PID); ok && (p.Start == 0 || start == p.Start) {
			want[p.PID] = true
		}
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
		if !descend {
			break
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
// It returns a note when some processes could not be put back cleanly.
func (m *Manager) Unblock(fp string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.corrupt != nil {
		return "", m.corrupt
	}
	if m.st.Blocked[fp] == nil {
		return "", errors.New("that agent is not blocked")
	}
	note := releaseNote(m.release(m.st.Blocked, fp, QuarantineCgroup))
	if err := m.apply(); err != nil {
		return note, err
	}
	return note, m.save()
}

// release moves fp's processes out of group back to where they came from
// and forgets it (caller holds mu, then applies and saves).
func (m *Manager) release(set map[string]*Member, fp, group string) (fellBack, orphans, kept int) {
	b := set[fp]
	delete(set, fp)
	if m.cgRoot == "" {
		return
	}
	pp := parents(m.cfg.ProcRoot)
	for _, pid := range m.members(group) {
		if origin, ok := originFor(pp, pid, b.Origins); ok {
			if !m.moveTo(pid, origin) {
				fellBack++
			}
			continue
		}
		if group != AllowedCgroup {
			kept++ // untraceable: stays quarantined (fail closed)
			continue
		}
		// In the allowed group an untraceable process (e.g. a helper that
		// daemonized) must not keep the allowance unless another allowed
		// agent accounts for it.
		owned := false
		for _, other := range set {
			if _, ok := originFor(pp, pid, other.Origins); ok {
				owned = true
				break
			}
		}
		if !owned {
			m.moveTo(pid, "/")
			orphans++
		}
	}
	if fellBack > 0 {
		m.cfg.Emit("EGRESS_RELEASE_FALLBACK", fmt.Sprintf("%d process(es) of %s could not return to their original cgroup and were placed in the root cgroup (outside their session's limits)", fellBack, b.ID), "warn")
	}
	if orphans > 0 {
		m.cfg.Emit("EGRESS_RELEASE_ORPHANS", fmt.Sprintf("%d untraceable process(es) left the allowed group with %s and lost the allowance", orphans, b.ID), "warn")
	}
	if kept > 0 {
		m.cfg.Emit("EGRESS_RELEASE_KEPT", fmt.Sprintf("%d process(es) still in quarantine could not be traced to %s and stay cut off (end them, or run restore-all)", kept, b.ID), "warn")
	}
	if len(set) == 0 {
		os.Remove(m.groupDir(group)) // fails (and the rule stays) while anything is still inside
	}
	return fellBack, orphans, kept
}

// releaseNote describes what a release could not do cleanly ("" if all went back).
func releaseNote(fellBack, orphans, kept int) string {
	var parts []string
	if fellBack > 0 {
		parts = append(parts, fmt.Sprintf("%d process(es) went to the root cgroup instead of their own", fellBack))
	}
	if orphans > 0 {
		parts = append(parts, fmt.Sprintf("%d untraceable process(es) lost the allowance", orphans))
	}
	if kept > 0 {
		parts = append(parts, fmt.Sprintf("%d untraceable process(es) stay quarantined", kept))
	}
	return strings.Join(parts, "; ")
}

// ── Allow ──

// Allow lets an agent (and what it spawns) reach the network during a
// lockdown. The caller decides whether the agent deserves it (DevShield's
// daemon requires a sanctioned agent with a clean verdict).
func (m *Manager) Allow(fp, id, name string, pids []Proc) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.corrupt != nil {
		return 0, m.corrupt
	}
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
	moved := m.capture(b, pids, AllowedCgroup, false)
	return moved, m.save()
}

// Disallow withdraws an allow.
func (m *Manager) Disallow(fp string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.corrupt != nil {
		return "", m.corrupt
	}
	if m.st.Allowed[fp] == nil {
		return "", errors.New("that agent is not allowed")
	}
	note := releaseNote(m.release(m.st.Allowed, fp, AllowedCgroup))
	if err := m.apply(); err != nil {
		return note, err
	}
	return note, m.save()
}

// NotQuarantined counts pids that are NOT inside the quarantine group, so
// "blocked" can be shown as a fact, not just a decision.
func (m *Manager) NotQuarantined(pids []int) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, pid := range pids {
		if c := m.cgroupOf(pid); c != "" && c != "/"+QuarantineCgroup {
			n++
		}
	}
	return n
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
// moveTo puts pid back into origin; if that fails (the group is gone, or
// owned by the user and not writable), into the root group. It reports
// whether the process reached origin.
func (m *Manager) moveTo(pid int, origin string) bool {
	dir := filepath.Join(m.cgRoot, filepath.Clean("/"+origin))
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
		os.WriteFile(filepath.Join(m.cgRoot, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0)
		return false
	}
	return true
}

// Reconcile re-quarantines blocked agents whose processes (re)appeared
// outside the group — e.g. the agent was restarted. running maps agent
// fingerprint → current pids. It returns the ids that were re-captured.
func (m *Manager) Reconcile(running map[string][]Proc) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cgRoot == "" || m.corrupt != nil {
		return nil
	}
	changed := m.tidy()
	var caught []string
	for fp, b := range m.st.Blocked {
		var loose []Proc
		for _, p := range running[fp] {
			if c := m.cgroupOf(p.PID); c != "" && c != "/"+QuarantineCgroup {
				loose = append(loose, p)
			}
		}
		if len(loose) == 0 {
			continue
		}
		if err := os.MkdirAll(m.quarantineDir(), 0o755); err != nil {
			continue
		}
		if m.capture(b, loose, QuarantineCgroup, true) > 0 {
			m.refreshFlows(b)
			caught = append(caught, b.ID)
		}
	}
	for fp, b := range m.st.Allowed {
		var loose []Proc
		for _, p := range running[fp] {
			if c := m.cgroupOf(p.PID); c != "" && c != "/"+AllowedCgroup {
				loose = append(loose, p)
			}
		}
		if len(loose) > 0 && os.MkdirAll(m.groupDir(AllowedCgroup), 0o755) == nil && m.capture(b, loose, AllowedCgroup, false) > 0 {
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
	// A flow stays only while a quarantined process still owns that socket
	// (an unrelated program reusing the port must not inherit the rule).
	live := map[Flow]bool{}
	if m.cgRoot != "" {
		for _, f := range OpenFlows(m.cfg.ProcRoot, m.members(QuarantineCgroup)) {
			live[f] = true
		}
	}
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
// dead-man switch for remote sessions and untested tunnels). The pending
// change is never written to disk, so a restart also reverts it.
func (m *Manager) LockdownOn(l Lockdown, confirmWithin time.Duration) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if confirmWithin < 0 || (confirmWithin > 0 && confirmWithin < MinConfirm) {
		return fmt.Errorf("--confirm-within must be at least %s", MinConfirm)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.corrupt != nil {
		return m.corrupt
	}
	durable := m.st.Lockdown // what survives a restart
	if m.pending != nil {
		durable = m.prevLock
	}
	inKernel := m.st.Lockdown
	m.st.Lockdown = &l
	if err := m.apply(); err != nil {
		m.st.Lockdown = inKernel // nft is atomic: the kernel still has this; any pending timer stays armed
		return err
	}
	if m.pending != nil {
		m.pending.Stop()
		m.pending = nil
	}
	m.gen++
	if confirmWithin > 0 {
		m.prevLock, m.pendingBy = durable, time.Now().Add(confirmWithin)
		gen := m.gen
		m.pending = time.AfterFunc(confirmWithin, func() { m.revertPending(gen) })
	}
	return m.save()
}

func (m *Manager) revertPending(gen int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil || m.gen != gen {
		return // confirmed, replaced or switched off meanwhile
	}
	cur := m.st.Lockdown
	m.st.Lockdown = m.prevLock
	if err := m.apply(); err != nil {
		m.st.Lockdown = cur
		m.cfg.Emit("LOCKDOWN_REVERT_FAILED", err.Error()+" — the unconfirmed lockdown is still active; run 'sudo devshield lockdown off'", "fail")
		return
	}
	m.pending = nil
	m.gen++
	if err := m.save(); err != nil {
		m.cfg.Emit("EGRESS_SAVE_FAILED", err.Error(), "fail")
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
	m.gen++
	return m.save()
}

// LockdownOff removes the lockdown (quarantine stays).
func (m *Manager) LockdownOff() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.corrupt != nil {
		return m.corrupt
	}
	cur := m.st.Lockdown
	m.st.Lockdown = nil
	if err := m.apply(); err != nil {
		m.st.Lockdown = cur // still in the kernel: say so rather than pretend
		return err
	}
	if m.pending != nil {
		m.pending.Stop()
		m.pending = nil
	}
	m.gen++
	return m.save()
}

// Reset undoes everything: releases blocked and allowed agents back to
// their own groups, ends any lockdown and removes DevShield's table. It
// reports what it undid.
func (m *Manager) Reset() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var did []string
	cur := m.st.Lockdown
	if m.st.Lockdown != nil {
		m.st.Lockdown = nil
		did = append(did, "lockdown ended")
	}
	for fp, b := range m.st.Blocked {
		msg := "unblocked " + b.ID
		if note := releaseNote(m.release(m.st.Blocked, fp, QuarantineCgroup)); note != "" {
			msg += " (" + note + ")"
		}
		did = append(did, msg)
	}
	for fp, b := range m.st.Allowed {
		msg := "disallowed " + b.ID
		if note := releaseNote(m.release(m.st.Allowed, fp, AllowedCgroup)); note != "" {
			msg += " (" + note + ")"
		}
		did = append(did, msg)
	}
	// A group can outlive the state that explains it (crash, deleted state
	// file, a process that could not be moved back). Its rule would keep
	// cutting traffic, so try to remove it and say so if that fails.
	var stuck []string
	if m.cgRoot != "" {
		for _, g := range []string{QuarantineCgroup, AllowedCgroup} {
			if _, err := os.Stat(m.groupDir(g)); err != nil {
				continue
			}
			if os.Remove(m.groupDir(g)) == nil {
				did = append(did, "removed leftover group "+g)
			} else {
				what := "its rule stays loaded, so they stay cut off (fail closed)"
				if g == AllowedCgroup {
					what = "with no lockdown it grants nothing"
				}
				stuck = append(stuck, fmt.Sprintf("%s still holds %d process(es); %s", g, len(m.members(g)), what))
			}
		}
	}
	if err := m.apply(); err != nil {
		m.st.Lockdown = cur // the kernel still enforces it
		return did, err
	}
	if m.pending != nil {
		m.pending.Stop()
		m.pending = nil
	}
	m.gen++
	if m.corrupt != nil {
		did = append(did, "unreadable network state replaced")
		m.corrupt = nil
	}
	if err := m.save(); err != nil {
		return did, err
	}
	if len(stuck) > 0 {
		return did, fmt.Errorf("%s — end or move those processes and run again", strings.Join(stuck, "; "))
	}
	return did, nil
}

// ── Health ──

// Status reports the saved policy and whether the kernel still has it.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{CgroupV2: m.cgRoot != "", Lockdown: m.st.Lockdown, RulesLoaded: m.rulesLoaded()}
	if m.corrupt != nil {
		st.Problem, st.RulesLoaded = m.corrupt.Error(), false
	}
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

// rulesLoaded checks the kernel holds exactly the rules DevShield wants:
// every rule of every chain, in order, compared as canonical token sets
// (see canonRules), so a deleted, added, reordered or edited rule —
// address, port, group, user or verdict — is noticed. With nothing to
// enforce, the table must be absent.
func (m *Manager) rulesLoaded() bool {
	p := m.policy()
	have, listErr := m.cfg.NftList()
	if p.Empty() {
		return listErr != nil // no table expected
	}
	want, err := Render(p)
	if err != nil || listErr != nil {
		return false
	}
	return slices.Equal(canonRules(want), canonRules(have))
}

var (
	reCounter = regexp.MustCompile(`counter packets \d+ bytes \d+`)
	reBurst   = regexp.MustCompile(`burst \d+ packets`)
)

// canonRules reduces a table to one entry per chain header and per rule.
// It reads both DevShield's script and nft's listing, which differs only
// in ways that do not change meaning: counter values, the default limit
// burst, set elements sorted, and matches within a rule reordered (see
// testdata/). Each rule becomes its sorted tokens.
func canonRules(table string) []string {
	var out []string
	inTable := false
	for _, line := range strings.Split(table, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "table inet "+TableName+" {"):
			inTable = true
			continue
		case !inTable || line == "" || line == "}" || strings.HasPrefix(line, "type "):
			continue
		case strings.HasPrefix(line, "chain "):
			out = append(out, line)
			continue
		}
		line = reCounter.ReplaceAllString(line, "counter")
		line = reBurst.ReplaceAllString(line, "")
		f := strings.Fields(strings.NewReplacer("{", " ", "}", " ", ",", " ").Replace(line))
		sort.Strings(f)
		out = append(out, strings.Join(f, " "))
	}
	return out
}

// EnsureLoaded re-applies the ruleset if something removed or altered it
// (e.g. a firewall service ran "flush ruleset"). It reports whether it had to.
func (m *Manager) EnsureLoaded() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.corrupt != nil || m.rulesLoaded() {
		return false, nil
	}
	if err := m.apply(); err != nil {
		return true, err
	}
	if !m.rulesLoaded() {
		// Just loaded, still "different": nft lists them in a form this
		// version of DevShield can't compare, so tampering can't be judged.
		return true, ErrUnverifiable
	}
	return true, nil
}

// ErrUnverifiable: the rules are loaded but can't be compared with nft's
// listing (e.g. a different nft version prints them differently).
var ErrUnverifiable = errors.New("the rules were loaded, but this nft version lists them in a form DevShield can't compare, so tampering can't be detected here")

// ── helpers ──

// procStart reads a process's creation time the same way Agent Watch
// does (gopsutil), so the two compare exactly. Zombies count as gone.
func procStart(pid int) (int64, bool) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0, false
	}
	if st, err := p.Status(); err == nil && len(st) > 0 && st[0] == process.Zombie {
		return 0, false
	}
	ct, err := p.CreateTime()
	return ct, err == nil
}

func nftBinary() string {
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "nft"
}

// listNft prints DevShield's table from the kernel.
func listNft() (string, error) {
	out, err := exec.Command(nftBinary(), "list", "table", "inet", TableName).CombinedOutput()
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
