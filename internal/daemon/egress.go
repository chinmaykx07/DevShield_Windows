package daemon

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"time"

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
		for {
			select {
			case <-d.stop:
				return
			case <-t.C:
				d.reconcileEgress()
				if again, err := m.EnsureLoaded(); again {
					if err != nil {
						d.event("EGRESS_RULES_MISSING", "DevShield's firewall rules were removed or altered and could not be restored: "+err.Error(), "fail")
					} else {
						d.event("EGRESS_RULES_RESTORED", "DevShield's firewall rules had been removed or altered by something else; restored", "warn")
					}
				}
			}
		}
	}()
}

// reconcileEgress re-quarantines blocked agents that were restarted.
func (d *Daemon) reconcileEgress() {
	running := map[string][]int{}
	for _, a := range d.watcher.Running() {
		for _, p := range a.PIDs {
			running[a.Fingerprint] = append(running[a.Fingerprint], int(p))
		}
	}
	for _, id := range d.egress.Reconcile(running) {
		d.event("AGENT_REQUARANTINED", "blocked agent "+id+" came back (restarted or new process) and was cut off again", "warn")
	}
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
		if err := d.egress.Unblock(fp); err != nil {
			d.event("EGRESS_FAILED", fmt.Sprintf("unblock %s: %v (by %s)", id, err, peer), "fail")
			return ipc.Response{Error: err.Error()}
		}
		d.event("AGENT_UNBLOCKED", fmt.Sprintf("%s may use the network again (by %s)", id, peer), "ok")
		return d.egressStatus()
	}

	// Agents seen before but not running now can be blocked too: they are
	// cut off the moment they reappear.
	fp, name, short, err := d.watcher.ResolveKnown(id)
	if err != nil {
		return ipc.Response{Error: err.Error()}
	}
	var pids []int
	for _, a := range d.watcher.Running() {
		if a.Fingerprint == fp {
			for _, p := range a.PIDs {
				pids = append(pids, int(p))
			}
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
		detail = fmt.Sprintf("via %v, endpoints %v, users %v, lan %v, strict %v", l.Interfaces, l.Endpoints, l.Users, l.AllowLAN, l.NoReplies)
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

// lockdownFrom resolves user names (as root, so the answer is the
// system's, not the caller's).
func lockdownFrom(r *ipc.LockdownRequest) (egress.Lockdown, error) {
	l := egress.Lockdown{Interfaces: r.Via, Endpoints: r.Endpoints, AllowLAN: r.LAN, NoReplies: r.Strict}
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
