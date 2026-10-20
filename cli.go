// cli.go — command-line interface.
//
//	devshield                      start the tray (Windows today)
//	devshield daemon [flags]       run the privileged service (Linux, as root)
//	devshield status               daemon health and audit-log integrity
//	devshield agents               running AI agents and verdicts
//	devshield events [-n 20]       recent audit events
//	sudo devshield sanction <id>   approve an agent (root only)
//	sudo devshield revoke <id>     withdraw an approval (root only)
//	devshield verify-log [path]    check the audit log's hash chain offline
//	devshield sensors [--json]     temperatures, fans, power (no daemon needed)
//	devshield profile              thermal controls, active profile, temps
//	sudo devshield profile <name>  silent | gaming | dev | off (root only)
//	devshield sinkhole [on|off]    telemetry sinkhole in /etc/hosts (changes need root)

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chinmaykx07/DevShield_Windows/internal/auditlog"
	"github.com/chinmaykx07/DevShield_Windows/internal/daemon"
	"github.com/chinmaykx07/DevShield_Windows/internal/ipc"
	"github.com/chinmaykx07/DevShield_Windows/internal/sensors"
)

const cliUsage = `DevShield — keeps the machine under its owner's control

Usage:
  devshield                       start the tray app
  devshield daemon [flags]        run the privileged service (Linux, as root)
  devshield status                daemon health and audit-log integrity
  devshield agents [--json]       running AI agents and their verdicts
  devshield events [-n N]         recent audit events
  sudo devshield sanction <id>    approve an agent (requires root)
  sudo devshield revoke <id>      withdraw an approval (requires root)
  devshield verify-log [path]     verify an audit log's hash chain offline
  devshield sensors [--json]      temperatures, fans and power (no daemon needed)
  devshield profile               thermal controls, active profile and temperatures
  sudo devshield profile <name>   silent | gaming | dev | off (off = original settings)
  devshield sinkhole              telemetry sinkhole status and what it blocks
  sudo devshield sinkhole on|off  block / unblock telemetry domains in /etc/hosts
  devshield version

Global flag (before or after the command): --socket PATH (default ` + ipc.DefaultSocket + `)
`

// runCLI returns a process exit code.
func runCLI(args []string, stdout, stderr io.Writer) int {
	socket := ipc.DefaultSocket
	// Pull a global --socket out of anywhere in the arguments.
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--socket" && i+1 < len(args):
			socket = args[i+1]
			i++
		case strings.HasPrefix(a, "--socket="):
			socket = strings.TrimPrefix(a, "--socket=")
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) == 0 {
		fmt.Fprint(stderr, cliUsage)
		return 2
	}

	cmd, cargs := rest[0], rest[1:]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, cliUsage)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "devshield %s\n", dsVersion)
		return 0
	case "daemon":
		return cliDaemon(cargs, socket, stderr)
	case "status":
		return cliStatus(socket, stdout, stderr)
	case "agents":
		return cliAgents(cargs, socket, stdout, stderr)
	case "events":
		return cliEvents(cargs, socket, stdout, stderr)
	case "sanction", "revoke":
		if len(cargs) != 1 {
			fmt.Fprintf(stderr, "usage: sudo devshield %s <agent-id>\n", cmd)
			return 2
		}
		return cliPolicy(cmd, cargs[0], socket, stdout, stderr)
	case "sensors":
		return cliSensors(cargs, stdout)
	case "profile":
		if len(cargs) == 0 {
			return cliThermal(socket, stdout, stderr)
		}
		return cliProfile(cargs[0], socket, stdout, stderr)
	case "sinkhole":
		op, mode := "privacy", ""
		if len(cargs) > 0 {
			op, mode = "sinkhole", cargs[0]
		}
		resp, ok := call(socket, ipc.Request{Op: op, Profile: mode}, stderr)
		if !ok {
			return 1
		}
		printSinkhole(resp.Sinkhole, stdout)
		if len(resp.Sinkhole.Missing) > 0 || !resp.Sinkhole.FilesInNSS {
			return 3
		}
		return 0
	case "verify-log":
		path := daemon.DefaultStateDir + "/audit.log"
		if len(cargs) > 0 {
			path = cargs[0]
		}
		return cliVerify(path, stdout, stderr)
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, cliUsage)
	return 2
}

func cliDaemon(args []string, socket string, stderr io.Writer) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", daemon.DefaultStateDir, "root-only state directory")
	sysRoot := fs.String("sys-root", "", "testing only: read/write a fake /sys and /etc tree under this prefix")
	hostList := fs.String("hosts-list", daemon.DefaultHostList, "root-owned sinkhole list override (optional)")
	catalog := fs.String("catalog", daemon.DefaultCatalog, "root-owned agent catalog override (optional)")
	owners := fs.String("owner", "", "comma-separated users/uids allowed to read status (e.g. alice)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	uids, err := daemon.ParseOwners(*owners, lookupUID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err = daemon.Run(ctx, daemon.Config{
		StateDir:         *stateDir,
		Socket:           socket,
		CatalogOverride:  *catalog,
		Owners:           uids,
		Version:          dsVersion,
		SysRoot:          *sysRoot,
		HostListOverride: *hostList,
	})
	if err != nil {
		fmt.Fprintf(stderr, "devshield daemon: %v\n", err)
		return 1
	}
	return 0
}

func lookupUID(s string) (int, error) {
	if uid, err := strconv.Atoi(s); err == nil {
		return uid, nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

func call(socket string, req ipc.Request, stderr io.Writer) (ipc.Response, bool) {
	resp, err := ipc.Call(socket, req)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return resp, false
	}
	if !resp.OK {
		fmt.Fprintf(stderr, "devshield: %s\n", resp.Error)
		return resp, false
	}
	return resp, true
}

func cliStatus(socket string, stdout, stderr io.Writer) int {
	resp, ok := call(socket, ipc.Request{Op: "status"}, stderr)
	if !ok {
		return 1
	}
	s := resp.Status
	fmt.Fprintf(stdout, "DevShield daemon %s — up %s\n", s.Version, time.Duration(s.UptimeSec)*time.Second)
	fmt.Fprintf(stdout, "AI agents running: %d  (rogue suspects: %d, risky: %d)\n", s.Agents, s.Rogue, s.Risky)
	if s.LogIntact {
		fmt.Fprintf(stdout, "Audit log: intact, %d records\n", s.LogRecords)
	} else {
		fmt.Fprintf(stdout, "Audit log: TAMPERED — %s\n", s.LogProblem)
	}
	if s.TamperSince {
		fmt.Fprintln(stdout, "Warning: tampering with the audit log was detected when the daemon started.")
	}
	if s.Rogue > 0 || s.Risky > 0 || !s.LogIntact || s.TamperSince {
		return 3 // scripts/monitoring can alert on this
	}
	return 0
}

var verdictIcon = map[string]string{"rogue": "🚨", "risky": "⚠ ", "unsanctioned": "⚠ ", "sanctioned": "✅"}

func cliAgents(args []string, socket string, stdout, stderr io.Writer) int {
	asJSON := len(args) > 0 && args[0] == "--json"
	resp, ok := call(socket, ipc.Request{Op: "agents"}, stderr)
	if !ok {
		return 1
	}
	if asJSON {
		b, _ := json.MarshalIndent(resp.Agents, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	if len(resp.Agents) == 0 {
		fmt.Fprintln(stdout, "No AI agents running.")
		return 0
	}
	alert := 0
	fmt.Fprintf(stdout, "%-9s %-14s %-34s %7s %5s  %s\n", "ID", "VERDICT", "AGENT", "PID", "PROCS", "USER")
	for _, a := range resp.Agents {
		if a.Verdict == "rogue" || a.Verdict == "risky" {
			alert++
		}
		fmt.Fprintf(stdout, "%-9s %s %-11s %-34s %7d %5d  %s\n",
			a.ID, verdictIcon[a.Verdict], a.Verdict, truncate(a.Name, 34), a.PID, a.Processes, a.User)
		if a.Exe != "" {
			fmt.Fprintf(stdout, "          program: %s\n", a.Exe)
		}
		for _, r := range a.Risks {
			fmt.Fprintf(stdout, "          ⚠ %s\n", r)
		}
		if len(a.Reasons) > 0 {
			fmt.Fprintf(stdout, "          why: %s\n", strings.Join(a.Reasons, "; "))
		}
	}
	fmt.Fprintln(stdout, "\nApprove an agent with: sudo devshield sanction <ID>")
	if alert > 0 {
		return 3
	}
	return 0
}

func cliEvents(args []string, socket string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("events", flag.ContinueOnError)
	fs.SetOutput(stderr)
	n := fs.Int("n", 20, "number of events")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	resp, ok := call(socket, ipc.Request{Op: "events", Limit: *n}, stderr)
	if !ok {
		return 1
	}
	for _, e := range resp.Events {
		fmt.Fprintf(stdout, "%6d  %s  %-4s  %-26s %s\n", e.Seq, e.Time[:19], e.Status, e.Action, e.Detail)
	}
	return 0
}

func cliPolicy(op, id, socket string, stdout, stderr io.Writer) int {
	if _, ok := call(socket, ipc.Request{Op: op, ID: id}, stderr); !ok {
		return 1
	}
	fmt.Fprintf(stdout, "%s: %s done.\n", op, id)
	return 0
}

func cliVerify(path string, stdout, stderr io.Writer) int {
	n, err := auditlog.Verify(path)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v (first %d records are intact)\n", path, err, n)
		return 3
	}
	fmt.Fprintf(stdout, "%s: intact, %d records\n", path, n)
	return 0
}

func cliSensors(args []string, stdout io.Writer) int {
	snap := sensors.Read(os.Getenv("DEVSHIELD_SYS_ROOT")) // env override only for testing
	if len(args) > 0 && args[0] == "--json" {
		b, _ := json.MarshalIndent(snap, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	if snap.Summary.Source == "none" {
		fmt.Fprintln(stdout, "No hardware sensors exposed by this kernel (common in VMs and containers).")
		return 0
	}
	sm := snap.Summary
	fmt.Fprintf(stdout, "CPU %s   GPU %s   NVMe %s   Fan %s   (source: %s)\n\n",
		orUnknown(sm.CPUTempC, "°C"), orUnknown(sm.GPUTempC, "°C"), orUnknown(sm.NVMeTempC, "°C"), orUnknown(sm.MaxFanRPM, " RPM"), sm.Source)
	for _, r := range snap.Readings {
		crit := ""
		if r.Crit > 0 {
			crit = fmt.Sprintf("  (critical %.0f%s)", r.Crit, r.Unit)
		}
		fmt.Fprintf(stdout, "  %-14s %-18s %8.1f %s%s\n", r.Chip, truncate(r.Label, 18), r.Value, r.Unit, crit)
	}
	return 0
}

func orUnknown(v float64, unit string) string {
	if v == 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f%s", v, unit)
}

func printThermal(t *ipc.Thermal, stdout io.Writer) {
	active := t.Active
	if active == "" {
		active = "none (original settings)"
	}
	fmt.Fprintf(stdout, "Active profile: %s\n", active)
	fmt.Fprintf(stdout, "CPU %s   GPU %s   Fan %s\n", orUnknown(t.CPUTempC, "°C"), orUnknown(t.GPUTempC, "°C"), orUnknown(t.MaxFanRPM, " RPM"))
	if !t.Supported {
		fmt.Fprintln(stdout, "This machine exposes no thermal controls DevShield can change.")
	} else {
		fmt.Fprintf(stdout, "Controls: %s\n", strings.Join(t.Controls, "; "))
	}
	for _, a := range t.Applied {
		fmt.Fprintf(stdout, "  ✅ %s\n", a)
	}
	for _, s := range t.Skipped {
		fmt.Fprintf(stdout, "  ⏭  skipped (system refused): %s\n", s)
	}
	for _, m := range t.Mismatch {
		fmt.Fprintf(stdout, "  ⚠  %s\n", m)
	}
	for _, n := range t.Notes {
		fmt.Fprintf(stdout, "  ·  %s\n", n)
	}
}

func cliThermal(socket string, stdout, stderr io.Writer) int {
	resp, ok := call(socket, ipc.Request{Op: "thermal"}, stderr)
	if !ok {
		return 1
	}
	printThermal(resp.Thermal, stdout)
	fmt.Fprintln(stdout, "\nChange it with: sudo devshield profile silent|gaming|dev|off")
	return 0
}

func cliProfile(name, socket string, stdout, stderr io.Writer) int {
	resp, ok := call(socket, ipc.Request{Op: "profile", Profile: name}, stderr)
	if !ok {
		if resp.Thermal != nil {
			printThermal(resp.Thermal, stderr)
		}
		return 1
	}
	printThermal(resp.Thermal, stdout)
	if len(resp.Thermal.Mismatch) > 0 {
		return 3
	}
	return 0
}

func printSinkhole(s *ipc.Sinkhole, stdout io.Writer) {
	if s.Active {
		fmt.Fprintf(stdout, "Telemetry sinkhole: ON — %d domains blocked in /etc/hosts (list %s)\n", s.Blocked, s.ListVersion)
	} else {
		fmt.Fprintf(stdout, "Telemetry sinkhole: off (list %s has %d domains)\n", s.ListVersion, s.Expected)
	}
	for _, g := range s.Groups {
		fmt.Fprintf(stdout, "  · %s\n", g)
	}
	for _, m := range s.Missing {
		fmt.Fprintf(stdout, "  ⚠ in the list but missing from /etc/hosts: %s\n", m)
	}
	for _, w := range s.Warnings {
		fmt.Fprintf(stdout, "  note: %s\n", w)
	}
}

func truncate(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
