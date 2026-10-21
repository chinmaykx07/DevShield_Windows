// Package daemon is DevShield's privileged service (Linux: run as root by
// systemd). It owns everything an AI agent must not be able to change —
// the sanction list, the agent database and the audit log — and runs
// Agent Watch with full visibility of every user's processes.
//
// Clients (CLI, tray) talk to it over internal/ipc. The kernel tells the
// daemon who is calling; the rules are:
//
//	read  (status, agents, events, verify,  root or a configured owner uid
//	       thermal, privacy, egress, net,
//	       lan-privacy)
//	write (sanction, revoke, profile,       root only — i.e. the owner via sudo
//	       sinkhole, block, unblock,
//	       lockdown, allow, disallow,
//	       set-lan-privacy, restore-all)
//
// A non-root process trying to change policy is recorded as
// AGENT_TAMPER_ATTEMPT, naming the program that tried.
package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chinmaykx07/DevShield_Windows/internal/agentwatch"
	"github.com/chinmaykx07/DevShield_Windows/internal/auditlog"
	"github.com/chinmaykx07/DevShield_Windows/internal/egress"
	"github.com/chinmaykx07/DevShield_Windows/internal/hosts"
	"github.com/chinmaykx07/DevShield_Windows/internal/ipc"
	"github.com/chinmaykx07/DevShield_Windows/internal/lanprivacy"
	"github.com/chinmaykx07/DevShield_Windows/internal/netwatch"
	"github.com/chinmaykx07/DevShield_Windows/internal/sensors"
	"github.com/chinmaykx07/DevShield_Windows/internal/thermal"

	_ "modernc.org/sqlite"
)

// Defaults for a packaged Linux install.
const (
	DefaultStateDir = "/var/lib/devshield"
	DefaultCatalog  = "/etc/devshield/agent_catalog.json"
	DefaultHostList = "/etc/devshield/hosts_blocklist.json"
)

// Config for one daemon run.
type Config struct {
	StateDir         string // root-only directory for the database and audit log
	Socket           string // ipc socket path
	CatalogOverride  string // optional root-owned catalog override
	Owners           []int  // non-root uids allowed to READ status/agents/events
	Version          string
	SysRoot          string // filesystem prefix for /sys and /etc ("" = real system; tests use a fake tree)
	HostListOverride string // optional root-owned sinkhole list
}

var readOps = map[string]bool{"status": true, "agents": true, "events": true, "verify": true, "thermal": true, "privacy": true, "egress": true, "lan-privacy": true, "net": true}
var writeOps = map[string]bool{"sanction": true, "revoke": true, "profile": true, "sinkhole": true,
	"block": true, "unblock": true, "lockdown": true, "allow": true, "disallow": true, "set-lan-privacy": true, "restore-all": true}

// authorize decides whether peer may run op. tamper is true when a
// non-root process attempted a policy change — worth an alert of its own.
func authorize(peer ipc.Peer, op string, owners map[int]bool) (allowed, tamper bool) {
	switch {
	case peer.UID == 0:
		return readOps[op] || writeOps[op], false
	case readOps[op]:
		return owners[peer.UID], false
	case writeOps[op]:
		return false, true
	}
	return false, false
}

// Daemon is one running instance.
type Daemon struct {
	cfg     Config
	owners  map[int]bool
	log     *auditlog.Log
	logPath string
	db      *sql.DB
	watcher *agentwatch.Watcher
	egress  *egress.Manager // nil when unavailable
	netRes  *netwatch.Resolver
	netSeen *netwatch.Dedupe
	stop    chan struct{}
	closing atomic.Bool
	lost    atomic.Int64 // events that could not be written since the last summary
	lostAll atomic.Int64 // and in this run
	started time.Time
	tamper  bool
	lock    *os.File // held while running: one daemon per state directory

	bg             sync.WaitGroup // background loops, waited for before the log and database close
	recMu          sync.Mutex     // one egress reconcile at a time
	halted         bool           // under recMu: stopping, no more reconciles
	storeErrLogged bool           // under recMu
	stopOnce       sync.Once

	limMu   sync.Mutex
	limited map[denyKey]*window // per uid and kind: denied-event rate window
}

type window struct {
	start      time.Time
	count      int
	suppressed int
}

// denyKey separates tamper attempts from ordinary refused reads, so a
// flood of harmless refusals can never hide a tamper attempt.
type denyKey struct {
	uid    int
	tamper bool
}

// Denied/tamper events are rate-limited per uid so a hostile process
// cannot fill the disk by hammering the socket.
const (
	deniedPerMinute = 10
)

// Run starts the daemon and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	d, err := start(cfg)
	if err != nil {
		return err
	}

	l, err := ipc.Listen(cfg.Socket)
	if err != nil {
		err = fmt.Errorf("listen on %s: %w", cfg.Socket, err)
		d.event("DAEMON_START_FAILED", err.Error(), "fail")
		d.stopWith("stopped after a failed start", "fail")
		return err
	}
	defer d.close()
	go func() {
		if err := ipc.Serve(l, d.handle); err != nil {
			log.Printf("daemon: ipc: %v", err)
		}
	}()
	log.Printf("daemon: listening on %s, state in %s", cfg.Socket, cfg.StateDir)

	<-ctx.Done()
	l.Close()
	return nil
}

func start(cfg Config) (*Daemon, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}

	d := &Daemon{
		cfg:     cfg,
		owners:  map[int]bool{},
		logPath: filepath.Join(cfg.StateDir, "audit.log"),
		started: time.Now(),
		limited: map[denyKey]*window{},
		stop:    make(chan struct{}),
	}
	for _, uid := range cfg.Owners {
		d.owners[uid] = true
	}
	// Before anything is written: a second daemon must not touch the log.
	lock, err := lockState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	d.lock = lock

	// ── Audit log: verify, and record tampering instead of going blind ──
	al, info, err := auditlog.Open(d.logPath)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	d.log = al
	if info.Broken != nil {
		d.tamper = true
		d.event("AUDIT_TAMPER_DETECTED", fmt.Sprintf("%s — the broken log was kept as %s and a new log started", info.Broken.Error(), info.Aside), "fail")
	}
	if info.TornBytes > 0 {
		d.event("AUDIT_TORN_RECORD_REMOVED", fmt.Sprintf("an unfinished final record (%d bytes, never confirmed) was removed — a crash or power loss cut a write short", info.TornBytes), "warn")
	}
	// After a break, the last valid record says nothing about how the
	// previous run ended, so no guess is logged.
	if info.Broken == nil && info.Last != nil && info.Last.Action != "DAEMON_STOPPED" {
		d.event("DAEMON_UNCLEAN_STOP", "previous run ended without a clean stop (killed, crashed or power loss) after "+info.Last.Action, "warn")
	}
	if os.Geteuid() != 0 {
		d.event("DAEMON_NOT_ROOT", "running without root: other users' processes are partly hidden and the state directory is only as safe as this account", "warn")
	}

	// ── Agent database (root-only file) ──
	dbPath := filepath.Join(cfg.StateDir, "agents.db")
	if f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0o600); err == nil {
		f.Close()
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	d.db = db

	w, err := agentwatch.New(agentwatch.Config{
		DB:              db,
		Emit:            func(a, det, s string) { d.eventFrom(a, det, s, "agentwatch") },
		CatalogOverride: cfg.CatalogOverride,
	})
	if err != nil {
		return nil, err
	}
	d.watcher = w
	w.Start()
	d.startEgress()
	d.startNetwatch()

	d.event("DAEMON_STARTED", fmt.Sprintf("version %s, owners %v, uid %d", cfg.Version, cfg.Owners, os.Geteuid()), "ok")
	return d, nil
}

func (d *Daemon) close() { d.stopWith("clean shutdown", "ok") }

// stopWith stops background work first (so nothing changes policy or uses
// the database mid-stop), then records DAEMON_STOPPED as the last event.
func (d *Daemon) stopWith(detail, status string) {
	d.stopBackground()
	d.flushAllSuppressed()
	d.closing.Store(true) // later events would make the next start report an unclean stop
	d.event("DAEMON_STOPPED", detail, status)
	d.closeStores()
}

// shutdown stops everything without claiming a clean stop.
func (d *Daemon) shutdown() {
	d.stopBackground()
	d.closeStores()
}

func (d *Daemon) stopBackground() {
	d.stopOnce.Do(func() {
		close(d.stop)
		d.watcher.Stop() // waits for a scan in progress
		d.recMu.Lock()   // waits for a reconcile in progress
		d.halted = true  // callbacks still in flight return at once
		d.recMu.Unlock()
		d.bg.Wait()
	})
}

func (d *Daemon) closeStores() {
	d.log.Close()
	d.db.Close()
	if d.lock != nil {
		d.lock.Close()
	}
}

func (d *Daemon) event(action, detail, status string) {
	d.eventFrom(action, detail, status, "daemon")
}

func (d *Daemon) eventFrom(action, detail, status, source string) {
	if d.closing.Load() && action != "DAEMON_STOPPED" {
		log.Printf("daemon: event after stop not recorded: %s %s", action, detail)
		return
	}
	if _, err := d.log.Append(action, detail, status, source); err != nil {
		d.lost.Add(1)
		d.lostAll.Add(1)
		log.Printf("daemon: audit append failed, event lost: %s %s: %v", action, detail, err)
		return
	}
	if n := d.lost.Swap(0); n > 0 {
		if _, err := d.log.Append("AUDIT_EVENTS_LOST", fmt.Sprintf("%d event(s) before this one could not be written to the audit log (e.g. the disk was full) and are missing", n), "fail", "daemon"); err != nil {
			d.lost.Add(n)
		}
	}
}

// allowDeniedEvent applies the per-uid, per-kind rate limit. Refusals
// beyond the limit are counted and summarised once when their minute ends
// (IPC_DENIED_SUPPRESSED), whether or not anything else arrives.
func (d *Daemon) allowDeniedEvent(k denyKey) bool {
	d.limMu.Lock()
	defer d.limMu.Unlock()
	w := d.limited[k]
	now := time.Now()
	if w == nil || now.Sub(w.start) > time.Minute {
		d.limited[k] = &window{start: now, count: 1}
		return true
	}
	if w.count < deniedPerMinute {
		w.count++
		return true
	}
	w.suppressed++
	if w.suppressed == 1 {
		time.AfterFunc(time.Minute-now.Sub(w.start), func() { d.flushSuppressed(k) })
	}
	return false
}

// flushSuppressed writes the summary for one window and closes it.
func (d *Daemon) flushSuppressed(k denyKey) {
	d.limMu.Lock()
	w := d.limited[k]
	n := 0
	if w != nil {
		n = w.suppressed
		delete(d.limited, k)
	}
	d.limMu.Unlock()
	if n == 0 {
		return
	}
	kind := "refused reads"
	if k.tamper {
		kind = "policy-change attempts (AGENT_TAMPER_ATTEMPT)"
	}
	d.event("IPC_DENIED_SUPPRESSED", fmt.Sprintf("%d further %s from uid %d within a minute were refused but not logged one by one", n, kind, k.uid), "warn")
}

// flushAllSuppressed writes every pending summary (before a stop).
func (d *Daemon) flushAllSuppressed() {
	d.limMu.Lock()
	var keys []denyKey
	for k := range d.limited {
		keys = append(keys, k)
	}
	d.limMu.Unlock()
	for _, k := range keys {
		d.flushSuppressed(k)
	}
}

// handle answers one request from a kernel-identified peer.
func (d *Daemon) handle(peer ipc.Peer, req ipc.Request) ipc.Response {
	allowed, tamper := authorize(peer, req.Op, d.owners)
	if !allowed {
		if d.allowDeniedEvent(denyKey{peer.UID, tamper}) {
			if tamper {
				d.event("AGENT_TAMPER_ATTEMPT", fmt.Sprintf("non-root process tried %q (id %q): %s", req.Op, req.ID, peer), "fail")
			} else {
				d.event("IPC_DENIED", fmt.Sprintf("%q refused for %s", req.Op, peer), "warn")
			}
		}
		if tamper {
			return ipc.Response{Error: "changing DevShield policy requires root (run with sudo)"}
		}
		return ipc.Response{Error: "not authorized"}
	}

	switch req.Op {
	case "status":
		return ipc.Response{OK: true, Status: d.status()}
	case "agents":
		return ipc.Response{OK: true, Agents: d.agents()}
	case "events":
		n := req.Limit
		switch {
		case n <= 0:
			n = 20
		case n > 500:
			n = 500 // the most one answer carries; asking for more is not an error
		}
		recs, err := auditlog.Tail(d.logPath, n)
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		return ipc.Response{OK: true, Events: recs}
	case "verify":
		st := d.status()
		if !st.LogIntact {
			return ipc.Response{Error: st.LogProblem, Status: st}
		}
		return ipc.Response{OK: true, Status: st}
	case "sanction", "revoke":
		fp, err := d.watcher.ResolveID(req.ID)
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		if req.Op == "sanction" {
			err = d.watcher.Sanction(fp)
		} else {
			err = d.watcher.Revoke(fp)
		}
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		d.event("OWNER_ACTION", fmt.Sprintf("%s %s by %s", req.Op, req.ID, peer), "ok")
		return ipc.Response{OK: true}
	case "thermal":
		return ipc.Response{OK: true, Thermal: d.thermalStatus()}
	case "profile":
		return d.applyProfile(req.Profile, peer)
	case "privacy":
		return d.sinkholeStatus()
	case "sinkhole":
		return d.setSinkhole(req.Profile, peer)
	case "egress":
		return d.egressStatus()
	case "block", "unblock":
		return d.setBlock(req.Op, req.ID, peer)
	case "lockdown":
		return d.setLockdown(req.Profile, req.Lockdown, peer)
	case "allow", "disallow":
		return d.setAllow(req.Op, req.ID, peer)
	case "restore-all":
		return d.restoreAll(peer)
	case "net":
		return ipc.Response{OK: true, Net: d.netEntries()}
	case "lan-privacy":
		return ipc.Response{OK: true, LAN: &ipc.LANPrivacy{Status: d.lanSystem().Check()}}
	case "set-lan-privacy":
		return d.setLANPrivacy(req.Profile, peer)
	}
	return ipc.Response{Error: "unknown operation"}
}

func (d *Daemon) thermalDir() string { return filepath.Join(d.cfg.StateDir, "thermal") }

func (d *Daemon) thermalStatus() *ipc.Thermal {
	c := thermal.Detect(d.cfg.SysRoot)
	t := &ipc.Thermal{Supported: c.Supported(), Active: thermal.Active(d.thermalDir())}
	if c.BoostPath != "" || anyBoost(c) {
		t.Controls = append(t.Controls, "CPU boost")
	}
	if len(c.Policies) > 0 {
		t.Controls = append(t.Controls, fmt.Sprintf("max CPU frequency (%d policies)", len(c.Policies)))
	}
	if len(c.Policies) > 0 && c.Policies[0].HasEPP {
		t.Controls = append(t.Controls, "energy/performance preference")
	}
	if c.PlatformProfile {
		t.Controls = append(t.Controls, "platform profile: "+strings.Join(c.PlatformChoices, " "))
	}
	s := sensors.Read(d.cfg.SysRoot).Summary
	t.CPUTempC, t.GPUTempC, t.MaxFanRPM = s.CPUTempC, s.GPUTempC, s.MaxFanRPM
	return t
}

func anyBoost(c thermal.Caps) bool {
	for _, p := range c.Policies {
		if p.HasBoost {
			return true
		}
	}
	return false
}

func (d *Daemon) applyProfile(profile string, peer ipc.Peer) ipc.Response {
	if profile == "off" {
		if thermal.Active(d.thermalDir()) == "" {
			if _, err := os.Stat(filepath.Join(d.thermalDir(), "thermal-baseline.json")); err != nil {
				return ipc.Response{OK: true, Thermal: d.thermalStatus()} // nothing was changed: nothing to restore
			}
		}
		failed, err := thermal.Off(d.thermalDir())
		if err != nil {
			d.event("THERMAL_RESTORE_FAILED", fmt.Sprintf("%v %v by %s", err, failed, peer), "fail")
			return ipc.Response{Error: err.Error(), Thermal: &ipc.Thermal{Notes: failed}}
		}
		d.event("THERMAL_RESTORED", "original thermal settings restored by "+peer.String(), "ok")
		return ipc.Response{OK: true, Thermal: d.thermalStatus()}
	}
	res, err := thermal.Apply(thermal.Detect(d.cfg.SysRoot), profile, d.thermalDir())
	if err != nil {
		d.event("THERMAL_PROFILE_FAILED", fmt.Sprintf("%s: %v (by %s)", profile, err, peer), "fail")
		return ipc.Response{Error: err.Error()}
	}
	status := "ok"
	if len(res.Mismatch) > 0 {
		status = "warn"
	}
	d.event("THERMAL_PROFILE_APPLIED", fmt.Sprintf("%s by %s: %d applied, %d skipped, %d mismatched",
		profile, peer, len(res.Applied), len(res.Skipped), len(res.Mismatch)), status)
	t := d.thermalStatus()
	t.Applied, t.Skipped, t.Mismatch, t.Notes = res.Applied, res.Skipped, res.Mismatch, res.Notes
	return ipc.Response{OK: true, Thermal: t}
}

func (d *Daemon) status() *ipc.Status {
	st := &ipc.Status{
		Version:     d.cfg.Version,
		UptimeSec:   int64(time.Since(d.started).Seconds()),
		TamperSince: d.tamper,
		LostEvents:  d.lostAll.Load(),
	}
	for _, a := range d.watcher.Running() {
		st.Agents++
		switch a.Verdict {
		case agentwatch.VerdictRogue:
			st.Rogue++
		case agentwatch.VerdictRisky:
			st.Risky++
		}
	}
	n, err := auditlog.Verify(d.logPath)
	st.LogRecords, st.LogIntact = n, err == nil
	if err != nil {
		st.LogProblem = err.Error()
		var chainErr *auditlog.ChainError
		st.LogUnchecked = !errors.As(err, &chainErr) // could not read it, not evidence of tampering
	}
	return st
}

func (d *Daemon) agents() []ipc.Agent {
	running := d.watcher.Running()
	out := make([]ipc.Agent, 0, len(running))
	for _, a := range running {
		out = append(out, ipc.Agent{
			ID: a.ID, Name: a.Name, Vendor: a.Vendor, Kind: a.Kind,
			Verdict: a.Verdict, Status: a.Status, PID: a.PID, Processes: a.Processes,
			User: a.User, Exe: a.Exe, Reasons: a.Reasons, Risks: a.ActiveRisks,
			Blocked:   d.egress != nil && d.egress.IsBlocked(a.Fingerprint),
			NotYetCut: d.notYetCut(a),
			Allowed:   d.egress != nil && d.egress.IsAllowed(a.Fingerprint),
		})
	}
	return out
}

// notYetCut counts a blocked agent's processes still outside quarantine.
func (d *Daemon) notYetCut(a agentwatch.RunningAgent) int {
	if d.egress == nil || !d.egress.IsBlocked(a.Fingerprint) {
		return 0
	}
	var pids []int
	for _, p := range a.Procs {
		pids = append(pids, int(p.PID))
	}
	return d.egress.NotQuarantined(pids)
}

// ParseOwners turns "alice,1000" into uids (names resolved via lookup).
func ParseOwners(spec string, lookup func(string) (int, error)) ([]int, error) {
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		uid, err := lookup(part)
		if err != nil {
			return nil, fmt.Errorf("owner %q: %w", part, err)
		}
		out = append(out, uid)
	}
	return out, nil
}

func (d *Daemon) lanSystem() lanprivacy.System {
	return lanprivacy.System{Root: d.cfg.SysRoot, Run: lanprivacy.ExecRunner}
}

func (d *Daemon) setLANPrivacy(mode string, peer ipc.Peer) ipc.Response {
	s := d.lanSystem()
	var r lanprivacy.Result
	var err error
	switch mode {
	case "on":
		r, err = s.Apply()
	case "off":
		r, err = s.Off()
	default:
		return ipc.Response{Error: "lan-privacy takes on or off"}
	}
	if err != nil {
		d.event("LAN_PRIVACY_FAILED", fmt.Sprintf("%s: %v (by %s)", mode, err, peer), "fail")
		return ipc.Response{Error: err.Error()}
	}
	d.event("LAN_PRIVACY_"+strings.ToUpper(mode), fmt.Sprintf("%s (by %s)", strings.Join(r.Changed, "; "), peer), "ok")
	return ipc.Response{OK: true, LAN: &ipc.LANPrivacy{Status: s.Check(), Result: &r}}
}

func (d *Daemon) sinkholeStatus() ipc.Response {
	l, err := hosts.LoadList(d.cfg.HostListOverride)
	if err != nil {
		return ipc.Response{Error: err.Error()}
	}
	st := hosts.Check(d.cfg.SysRoot, l)
	out := &ipc.Sinkhole{
		Active: st.Active, Damaged: st.Damaged, Blocked: st.Blocked, Expected: st.Expected, Missing: st.Missing,
		FilesInNSS: st.FilesInNSS, Warnings: st.Warnings, ListVersion: st.ListVersion,
	}
	for _, g := range l.Groups {
		out.Groups = append(out.Groups, fmt.Sprintf("%s (%d): %s", g.Name, len(g.Domains), g.Why))
	}
	return ipc.Response{OK: true, Sinkhole: out}
}

func (d *Daemon) setSinkhole(mode string, peer ipc.Peer) ipc.Response {
	switch mode {
	case "on":
		l, err := hosts.LoadList(d.cfg.HostListOverride)
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		n, err := hosts.Apply(d.cfg.SysRoot, filepath.Join(d.cfg.StateDir, "privacy"), l)
		if err != nil {
			d.event("SINKHOLE_FAILED", fmt.Sprintf("%v (by %s)", err, peer), "fail")
			return ipc.Response{Error: err.Error()}
		}
		d.event("SINKHOLE_APPLIED", fmt.Sprintf("%d domains, list %s, by %s", n, l.Version, peer), "ok")
	case "off":
		removed, err := hosts.Off(d.cfg.SysRoot)
		if err != nil {
			d.event("SINKHOLE_FAILED", fmt.Sprintf("off: %v (by %s)", err, peer), "fail")
			return ipc.Response{Error: err.Error()}
		}
		if removed {
			d.event("SINKHOLE_REMOVED", "managed block removed by "+peer.String(), "ok")
		}
	default:
		return ipc.Response{Error: "sinkhole takes on or off"}
	}
	return d.sinkholeStatus()
}
