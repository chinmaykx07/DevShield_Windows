package daemon

import (
	"fmt"
	"time"

	"github.com/chinmaykx07/DevShield_Windows/internal/hosts"
	"github.com/chinmaykx07/DevShield_Windows/internal/netwatch"
)

const (
	netInterval      = 30 * time.Second
	telemetryResolve = 30 * time.Minute
	telemetryRepeat  = 24 * time.Hour // log each program→host pair at most daily
)

func (d *Daemon) startNetwatch() {
	d.netRes = &netwatch.Resolver{Interval: telemetryResolve}
	d.netSeen = &netwatch.Dedupe{Window: telemetryRepeat}
	d.bg.Add(1)
	go func() {
		defer d.bg.Done()
		t := time.NewTicker(netInterval)
		defer t.Stop()
		for {
			select {
			case <-d.stop:
				return
			case <-t.C:
				d.logTelemetry()
			}
		}
	}()
}

// netEntries classifies the connections Agent Watch saw in its last scan.
func (d *Daemon) netEntries() []netwatch.Entry {
	var conns []netwatch.Conn
	for _, c := range d.watcher.Connections() {
		conns = append(conns, netwatch.Conn{PID: c.PID, Name: c.Name, Exe: c.Exe, User: c.User, Remote: c.Remote})
	}
	return netwatch.Classify(conns, d.watcher.LLMHost, d.telemetryIPs())
}

// telemetryIPs resolves the sinkhole's telemetry domains, but only while
// the sinkhole is off: when it is on those names resolve to 0.0.0.0 here,
// and connecting to them by name is already impossible.
func (d *Daemon) telemetryIPs() map[string]string {
	l, err := hosts.LoadList(d.cfg.HostListOverride)
	if err != nil || hosts.Check(d.cfg.SysRoot, l).Active {
		return nil
	}
	return d.netRes.IPs(l.Domains())
}

func (d *Daemon) logTelemetry() {
	now := time.Now()
	for _, e := range d.netEntries() {
		if e.Category != "telemetry" || !d.netSeen.First(e.Exe+"|"+e.Host, now) {
			continue
		}
		d.eventFrom("NET_TELEMETRY", fmt.Sprintf("%s (pid %d, user %s, %s) is sending to %s (%s) — likely telemetry; block it with: sudo devshield sinkhole on",
			e.Program, e.PID, e.User, e.Exe, e.Host, e.Remote), "warn", "netwatch")
	}
}
