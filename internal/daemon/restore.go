package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chinmaykx07/DevShield_Windows/internal/hosts"
	"github.com/chinmaykx07/DevShield_Windows/internal/ipc"
	"github.com/chinmaykx07/DevShield_Windows/internal/thermal"
)

// restoreAll undoes every change DevShield made to the system: network
// rules and quarantine, thermal settings, the hosts sinkhole and LAN
// privacy drop-ins. It carries on past a failed step and reports each one.
// The owner's decisions (agent sanctions) and the audit log are kept.
func (d *Daemon) restoreAll(peer ipc.Peer) ipc.Response {
	var steps []ipc.RestoreStep
	add := func(what string, err error, detail ...string) {
		s := ipc.RestoreStep{What: what, OK: err == nil, Detail: strings.Join(detail, "; ")}
		if err != nil {
			s.Detail = err.Error()
		}
		steps = append(steps, s)
	}

	if d.egress != nil {
		did, err := d.egress.Reset()
		if len(did) == 0 && err == nil {
			did = []string{"nothing was active"}
		}
		add("network: lockdown, blocked and allowed agents", err, did...)
	}

	if _, err := os.Stat(filepath.Join(d.thermalDir(), "thermal-baseline.json")); err == nil {
		failed, err := thermal.Off(d.thermalDir())
		if err != nil && len(failed) > 0 {
			err = fmt.Errorf("%v: %s", err, strings.Join(failed, "; "))
		}
		add("thermal: original CPU settings", err, "restored")
	} else {
		add("thermal: original CPU settings", nil, "nothing was changed")
	}

	removed, err := hosts.Off(d.cfg.SysRoot)
	detail := "nothing was active"
	if removed {
		detail = "managed block removed from /etc/hosts"
	}
	add("telemetry sinkhole", err, detail)

	r, err := d.lanSystem().Off()
	if len(r.Changed) == 0 {
		r.Changed = []string{"nothing was active"}
	}
	add("LAN privacy", err, r.Changed...)

	failed := 0
	for _, s := range steps {
		if !s.OK {
			failed++
		}
	}
	status := "ok"
	if failed > 0 {
		status = "fail"
	}
	d.event("RESTORE_ALL", fmt.Sprintf("%d of %d steps succeeded (by %s)", len(steps)-failed, len(steps), peer), status)
	resp := ipc.Response{OK: failed == 0, Restore: steps}
	if failed > 0 {
		resp.Error = fmt.Sprintf("%d step(s) could not be undone; see above and run again", failed)
	}
	return resp
}
