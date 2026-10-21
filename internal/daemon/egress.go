package daemon

import (
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/chinmaykx07/DevShield_Windows/internal/agentwatch"
	"github.com/chinmaykx07/DevShield_Windows/internal/egress"
	"github.com/chinmaykx07/DevShield_Windows/internal/ipc"
)

// egressInterval is how often blocked agents are re-checked (restarts)
// and the kernel ruleset is verified (another tool may have flushed it).
const egressInterval = 10 * time.Second

// torUsers are the Tor daemon's account names across distributions.
var torUsers = []string{"debian-tor", "tor", "toranon", "_tor"}

func (d *Daemon) startEgress() {
	m, err := egress.New(egress.Config{
		StateDir: d.cfg.StateDir,
		Emit:     func(a, det, s string) { d.eventFrom(a, det, s, "egress") },
	})
	if err != nil {
		d.event("EGRESS_UNAVAILABLE", err.Error(), "warn")
	}
	d.egress = m // may be non-nil with an error: state loaded, apply failed
	if m == nil {
		return
	}
	d.watcher.OnChange(d.reconcileEgress)
	go func() {
		t := time.NewTicker(egressInterval)
		defer t.Stop()
		unverifiable := false
		for {
			select {
			case <-d.stop:
				return
			case <-t.C:
				d.reconcileEgress()
				again, err := m.EnsureLoaded()
				switch {
				case !again:
					unverifiable = false
				case errors.Is(err, egress.ErrUnverifiable):
					if !unverifiable { // say it once, not every 10 s
						d.event("EGRESS_RULES_UNVERIFIABLE", err.Error(), "warn")
						unverifiable = true
					}
				case err != nil:
					d.event("EGRESS_RULES_MISSING", "DevShield's firewall rules did not match what it loaded and could not be re-applied: "+err.Error(), "fail")
				default:
					d.event("EGRESS_RULES_RESTORED", "DevShield's firewall rules did not match what it loaded (removed or changed by another program or by hand) and were re-applied", "warn")
				}
			}
		}
	}()
}

// reconcileEgress re-quarantines blocked agents that were restarted, and
// suspends the network allowance of any allowed agent that no longer
// deserves it (sanction revoked, binary replaced, or rogue behaviour).
func (d *Daemon) reconcileEgress() {
	running := map[string][]egress.Proc{}
	verdict := map[string]string{}
	for _, a := range d.watcher.Running() {
		verdict[a.Fingerprint] = a.Verdict
		running[a.Fingerprint] = procsOf(a)
	}
	for _, fp := range d.egress.AllowedFingerprints() {
		why := ""
		if v, ok := verdict[fp]; ok && v != agentwatch.VerdictSanctioned {
			why = "its verdict is now " + v
		} else if !ok && d.watcher.StoredStatus(fp) != agentwatch.AgentSanctioned {
			why = "it is no longer sanctioned"
		}
		if why == "" {
			continue
		}
		note, err := d.egress.Disallow(fp)
		if err != nil {
			d.event("EGRESS_FAILED", fmt.Sprintf("could not withdraw the network allowance of %s (%s): %v — it may still go out during a lockdown", agentwatch.ShortID(fp), why, err), "fail")
			continue
		}
		detail := fmt.Sprintf("network allowance of %s withdrawn: %s", agentwatch.ShortID(fp), why)
		if note != "" {
			detail += " (" + note + ")"
		}
		d.event("AGENT_ALLOW_SUSPENDED", detail, "warn")
	}
	for _, id := range d.egress.Reconcile(running) {
		d.event("AGENT_REQUARANTINED", "blocked agent "+id+" came back (restarted or new process) and was cut off again", "warn")
	}
}

// procsOf converts Agent Watch's process list for the egress manager.
func procsOf(a agentwatch.RunningAgent) []egress.Proc {
	out := make([]egress.Proc, 0, len(a.Procs))
	for _, p := range a.Procs {
		out = append(out, egress.Proc{PID: int(p.PID), Start: p.Start})
	}
	return out
}

// setAllow lets a sanctioned, well-behaved agent out during a lockdown.
func (d *Daemon) setAllow(op, id string, peer ipc.Peer) ipc.Response {
	if d.egress == nil {
		return ipc.Response{Error: "network controls are not available on this system"}
	}
	if op == "disallow" {
		fp, ok := d.egress.ResolveAllowed(id)
		if !ok {
			return ipc.Response{Error: fmt.Sprintf("no allowed agent matches %q (see: devshield egress)", id)}
		}
		note, err := d.egress.Disallow(fp)
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		d.event("AGENT_DISALLOWED", withNote(fmt.Sprintf("%s may no longer go out during lockdown (by %s)", id, peer), note), "ok")
		resp := d.egressStatus()
		resp.Note = note
		return resp
	}
	fp, name, short, err := d.watcher.ResolveKnown(id)
	if err != nil {
		return ipc.Response{Error: err.Error()}
	}
	var pids []egress.Proc
	for _, a := range d.watcher.Running() {
		if a.Fingerprint != fp {
			continue
		}
		if a.Verdict != agentwatch.VerdictSanctioned {
			return ipc.Response{Error: fmt.Sprintf("%s is %s: only a sanctioned agent with no risk signs can be allowed (sudo devshield sanction %s first)", short, a.Verdict, short)}
		}
		pids = procsOf(a)
	}
	if pids == nil && d.watcher.StoredStatus(fp) != agentwatch.AgentSanctioned {
		return ipc.Response{Error: fmt.Sprintf("%s is not sanctioned: sudo devshield sanction %s first", short, short)}
	}
	moved, err := d.egress.Allow(fp, short, name, pids)
	if err != nil {
		d.event("EGRESS_FAILED", fmt.Sprintf("allow %s: %v (by %s)", id, err, peer), "fail")
		return ipc.Response{Error: err.Error()}
	}
	d.event("AGENT_ALLOWED", fmt.Sprintf("%s (%s) may go out during lockdown: %d processes (by %s)", short, name, moved, peer), "ok")
	return d.egressStatus()
}

func (d *Daemon) egressStatus() ipc.Response {
	if d.egress == nil {
		return ipc.Response{Error: "network controls are not available on this system"}
	}
	st := d.egress.Status()
	return ipc.Response{OK: true, Egress: &st}
}

func (d *Daemon) setBlock(op, id string, peer ipc.Peer) ipc.Response {
	if d.egress == nil {
		return ipc.Response{Error: "network controls are not available on this system"}
	}
	if op == "unblock" {
		fp, ok := d.egress.ResolveBlocked(id)
		if !ok {
			return ipc.Response{Error: fmt.Sprintf("no blocked agent matches %q (see: devshield egress)", id)}
		}
		note, err := d.egress.Unblock(fp)
		if err != nil {
			d.event("EGRESS_FAILED", fmt.Sprintf("unblock %s: %v (by %s)", id, err, peer), "fail")
			return ipc.Response{Error: err.Error()}
		}
		d.event("AGENT_UNBLOCKED", withNote(fmt.Sprintf("%s may use the network again (by %s)", id, peer), note), "ok")
		resp := d.egressStatus()
		resp.Note = note
		return resp
	}

	// Agents seen before but not running now can be blocked too: they are
	// cut off at the next scan after they reappear (within about 10 s).
	fp, name, short, err := d.watcher.ResolveKnown(id)
	if err != nil {
		return ipc.Response{Error: err.Error()}
	}
	var pids []egress.Proc
	for _, a := range d.watcher.Running() {
		if a.Fingerprint == fp {
			pids = procsOf(a)
		}
	}
	moved, flows, err := d.egress.Block(fp, short, name, pids)
	if err != nil {
		d.event("EGRESS_FAILED", fmt.Sprintf("block %s: %v (by %s)", id, err, peer), "fail")
		return ipc.Response{Error: err.Error()}
	}
	d.event("AGENT_BLOCKED", fmt.Sprintf("%s (%s) cut off the network: %d processes quarantined, %d existing connections dropped (by %s)",
		short, name, moved, flows, peer), "ok")
	return d.egressStatus()
}

func (d *Daemon) setLockdown(mode string, req *ipc.LockdownRequest, peer ipc.Peer) ipc.Response {
	if d.egress == nil {
		return ipc.Response{Error: "network controls are not available on this system"}
	}
	var err error
	detail := ""
	switch mode {
	case "on":
		if req == nil {
			return ipc.Response{Error: "lockdown on needs --via, --user or --tor"}
		}
		var l egress.Lockdown
		l, err = lockdownFrom(req)
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		confirm := time.Duration(req.ConfirmSec) * time.Second
		err = d.egress.LockdownOn(l, confirm)
		detail = fmt.Sprintf("via %v, endpoints %v, users %v, allowed agents only %v, lan %v, strict %v", l.Interfaces, l.Endpoints, l.Users, l.OnlyAllowed, l.AllowLAN, l.NoReplies)
		if confirm > 0 {
			detail += fmt.Sprintf(", reverts in %s unless confirmed", confirm)
		}
	case "off":
		err = d.egress.LockdownOff()
	case "confirm":
		err = d.egress.Confirm()
	default:
		return ipc.Response{Error: "lockdown takes on, off or confirm"}
	}
	if err != nil {
		d.event("EGRESS_FAILED", fmt.Sprintf("lockdown %s: %v (by %s)", mode, err, peer), "fail")
		return ipc.Response{Error: err.Error()}
	}
	d.event("LOCKDOWN_"+strings.ToUpper(mode), strings.TrimPrefix(detail+" (by "+peer.String()+")", " "), "ok")
	return d.egressStatus()
}

func withNote(s, note string) string {
	if note == "" {
		return s
	}
	return s + " — but " + note
}

// lockdownFrom resolves user names (as root, so the answer is the
// system's, not the caller's).
func lockdownFrom(r *ipc.LockdownRequest) (egress.Lockdown, error) {
	l := egress.Lockdown{Interfaces: r.Via, Endpoints: r.Endpoints, AllowLAN: r.LAN, NoReplies: r.Strict, OnlyAllowed: r.OnlyAllowed}
	for _, u := range r.Users {
		uid, err := lookupUser(u)
		if err != nil {
			return l, fmt.Errorf("user %q: %w", u, err)
		}
		l.Users = append(l.Users, uid)
	}
	if r.Tor {
		found := false
		for _, name := range torUsers {
			if uid, err := lookupUser(name); err == nil {
				l.Users, found = append(l.Users, uid), true
				break
			}
		}
		if !found {
			return l, fmt.Errorf("no Tor daemon account found (looked for %s); install tor or name its user with --user", strings.Join(torUsers, ", "))
		}
	}
	return l, l.Validate()
}

func lookupUser(s string) (int, error) {
	if uid, err := strconv.Atoi(s); err == nil {
		return uid, nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}
