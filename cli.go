// cli.go — command-line interface. The full, current command list is
// cliUsage below (printed by "devshield help"); keep it the only list.
// Everything except "help", "version" and "verify-log" talks to the Linux
// daemon; there is no Windows daemon yet.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chinmaykx07/DevShield_Windows/internal/auditlog"
	"github.com/chinmaykx07/DevShield_Windows/internal/daemon"
	"github.com/chinmaykx07/DevShield_Windows/internal/egress"
	"github.com/chinmaykx07/DevShield_Windows/internal/ipc"
	"github.com/chinmaykx07/DevShield_Windows/internal/sensors"
)

const cliUsage = `DevShield — keeps the machine under its owner's control

Usage:
  devshield                       start the tray app (Windows only for now)
  devshield daemon [flags]        run the privileged service (Linux, as root)
  devshield status                daemon health and audit-log integrity
  devshield agents [--json]       running AI agents and their verdicts
  devshield events [-n N]         recent audit events
  sudo devshield sanction <id>    approve an agent (requires root)
  sudo devshield revoke <id>      withdraw an approval (requires root)
  sudo devshield verify-log [path] verify an audit log's hash chain offline
                                  (exit 3 = tampered, 1 = could not read it)
  devshield sensors [--json]      temperatures, fans and power (no daemon needed)
  devshield profile               thermal controls, active profile and temperatures
  sudo devshield profile <name>   silent | gaming | dev | off (off = original settings)
  devshield sinkhole              telemetry sinkhole status and what it blocks
  sudo devshield sinkhole on|off  block / unblock telemetry domains in /etc/hosts
  devshield net [--all] [--json]  which program talks to whom (telemetry, LLM APIs, …);
                                  --all includes loopback and local-network connections
  devshield lan-privacy [--json]  what this machine reveals on local networks
  sudo devshield lan-privacy on|off
                                  LLMNR/mDNS off, random Wi-Fi MAC per network, IPv6
                                  privacy addresses (off removes only DevShield's files)
  devshield egress [--json]       network quarantine and lockdown status
  sudo devshield block <id>       cut one agent (and its children) off the network
  sudo devshield unblock <id>     give it its network access back
  sudo devshield allow <id>       let a sanctioned agent out during lockdown (withdrawn
                                  automatically if it turns risky or loses its sanction)
  sudo devshield disallow <id>
  sudo devshield lockdown on [--via IFACE]... [--endpoint IP:PORT/PROTO]...
                    [--user NAME]... [--tor] [--only-allowed] [--lan] [--strict]
                    [--confirm-within 2m]
                                  nothing leaves except through the tunnel, the
                                  tunnel's servers and the users you name
  sudo devshield lockdown confirm keep a lockdown started with --confirm-within
  sudo devshield lockdown off
  sudo devshield restore-all      undo every system change DevShield made (network rules,
                                  thermal, sinkhole, LAN privacy); approvals and log are kept
  devshield egress-restore        load the saved network rules and exit (run at boot,
                                  before the network starts, by devshield-egress.service)
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
		if runtime.GOOS != "linux" {
			fmt.Fprintln(stderr, "devshield sensors reads Linux's hardware sensors (/sys); on Windows use the tray's dashboard")
			return 2
		}
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
	case "egress":
		return cliEgress(cargs, socket, stdout, stderr)
	case "block", "unblock", "allow", "disallow":
		if len(cargs) != 1 {
			fmt.Fprintf(stderr, "usage: sudo devshield %s <agent id>\n", cmd)
			return 2
		}
		resp, ok := call(socket, ipc.Request{Op: cmd, ID: cargs[0]}, stderr)
		if !ok {
			return 1
		}
		printEgress(resp.Egress, stdout)
		return 0
	case "lockdown":
		return cliLockdown(cargs, socket, stdout, stderr)
	case "restore-all":
		resp, err := ipc.Call(socket, ipc.Request{Op: "restore-all"})
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		for _, s := range resp.Restore {
			mark := "✅"
			if !s.OK {
				mark = "❌"
			}
			fmt.Fprintf(stdout, "%s %-45s %s\n", mark, s.What, s.Detail)
		}
		if !resp.OK {
			fmt.Fprintf(stderr, "devshield: %s\n", resp.Error)
			return 1
		}
		fmt.Fprintln(stdout, "\nThe system is back to how it was before DevShield changed it. Agent approvals and the audit log are kept.")
		return 0
	case "net":
		return cliNet(cargs, socket, stdout, stderr)
	case "lan-privacy":
		return cliLANPrivacy(cargs, socket, stdout, stderr)
	case "egress-restore":
		return cliEgressRestore(cargs, stdout, stderr)
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
		if a.Blocked {
			fmt.Fprintln(stdout, "          🔒 network blocked")
		}
		if a.Allowed {
			fmt.Fprintln(stdout, "          🌐 allowed out during lockdown")
		}
		for _, r := range a.Risks {
			fmt.Fprintf(stdout, "          ⚠ %s\n", r)
		}
		if len(a.Reasons) > 0 {
			fmt.Fprintf(stdout, "          why: %s\n", strings.Join(a.Reasons, "; "))
		}
	}
	fmt.Fprintln(stdout, "\nApprove an agent with: sudo devshield sanction <ID>   cut it off with: sudo devshield block <ID>")
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
		ts := e.Time
		if len(ts) > 19 {
			ts = ts[:19]
		}
		fmt.Fprintf(stdout, "%6d  %-19s  %-4s  %-26s %s\n", e.Seq, ts, e.Status, e.Action, e.Detail)
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
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrPermission) {
			fmt.Fprintf(stderr, "%s: cannot read it (the state directory is root-only): run with sudo\n", path)
		} else {
			fmt.Fprintf(stderr, "%s: no audit log there (%v)\n", path, err)
		}
		return 1 // not evidence of tampering either way
	}
	n, err := auditlog.Verify(path)
	var chainErr *auditlog.ChainError
	switch {
	case errors.As(err, &chainErr):
		fmt.Fprintf(stderr, "%s: %v (first %d records are intact)\n", path, err, n)
		return 3
	case errors.Is(err, os.ErrPermission):
		fmt.Fprintf(stderr, "%s: cannot read it: run with sudo\n", path)
		return 1
	case err != nil:
		fmt.Fprintf(stderr, "%s: could not check it: %v\n", path, err)
		return 1
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

// multiFlag collects a repeatable flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cliLockdown(args []string, socket string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return cliEgress(nil, socket, stdout, stderr)
	}
	mode := args[0]
	req := ipc.Request{Op: "lockdown", Profile: mode}
	if mode == "on" {
		fs := flag.NewFlagSet("lockdown on", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var via, eps, users multiFlag
		fs.Var(&via, "via", "tunnel interface allowed out (repeatable), e.g. wg0")
		fs.Var(&eps, "endpoint", "tunnel server IP:PORT/PROTO reachable directly (repeatable)")
		fs.Var(&users, "user", "user (name or uid) allowed out directly, e.g. a VPN client's account (repeatable)")
		tor := fs.Bool("tor", false, "allow the Tor daemon's user (programs then reach the internet only through Tor)")
		only := fs.Bool("only-allowed", false, "no tunnel at all: only agents you allowed (devshield allow) may go out")
		lan := fs.Bool("lan", false, "also allow the local network (printers, NAS); DNS still must use the tunnel")
		strict := fs.Bool("strict", false, "also block replies to inbound connections (breaks SSH into this machine)")
		confirm := fs.Duration("confirm-within", 0, "revert automatically unless 'devshield lockdown confirm' is run in time")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *confirm < 0 || (*confirm > 0 && *confirm < egress.MinConfirm) {
			fmt.Fprintf(stderr, "--confirm-within must be at least %s\n", egress.MinConfirm)
			return 2
		}
		req.Lockdown = &ipc.LockdownRequest{Via: via, Endpoints: eps, Users: users, Tor: *tor, OnlyAllowed: *only,
			LAN: *lan, Strict: *strict, ConfirmSec: int(math.Ceil(confirm.Seconds()))}
	}
	resp, ok := call(socket, req, stderr)
	if !ok {
		return 1
	}
	printEgress(resp.Egress, stdout)
	return 0
}

func cliEgress(args []string, socket string, stdout, stderr io.Writer) int {
	resp, ok := call(socket, ipc.Request{Op: "egress"}, stderr)
	if !ok {
		return 1
	}
	if len(args) > 0 && args[0] == "--json" {
		b, _ := json.MarshalIndent(resp.Egress, "", "  ")
		fmt.Fprintln(stdout, string(b))
	} else {
		printEgress(resp.Egress, stdout)
	}
	if !resp.Egress.RulesLoaded {
		return 3
	}
	return 0
}

func printEgress(e *egress.Status, stdout io.Writer) {
	if e == nil {
		return
	}
	if l := e.Lockdown; l != nil {
		fmt.Fprintln(stdout, "Lockdown: ON — nothing leaves except:")
		for _, i := range l.Interfaces {
			fmt.Fprintf(stdout, "  · traffic through %s\n", i)
		}
		for _, ep := range l.Endpoints {
			fmt.Fprintf(stdout, "  · the tunnel server %s\n", ep)
		}
		for _, u := range l.Users {
			fmt.Fprintf(stdout, "  · programs of uid %d\n", u)
		}
		if len(e.Allowed) > 0 {
			fmt.Fprintln(stdout, "  · the allowed agents listed below")
		}
		if l.AllowLAN {
			fmt.Fprintln(stdout, "  · the local network (except DNS)")
		}
		if !l.NoReplies {
			fmt.Fprintln(stdout, "  · replies to connections made TO this machine (e.g. SSH); --strict blocks them")
		}
		if !e.ConfirmBy.IsZero() {
			fmt.Fprintf(stdout, "  ⏳ reverts at %s unless you run: sudo devshield lockdown confirm\n", e.ConfirmBy.Local().Format("15:04:05"))
		}
	} else {
		fmt.Fprintln(stdout, "Lockdown: off")
	}
	if len(e.Blocked) == 0 {
		fmt.Fprintln(stdout, "Blocked agents: none")
	} else {
		fmt.Fprintf(stdout, "Blocked agents (%d processes quarantined):\n", e.QuarantinedProcs)
		for _, b := range e.Blocked {
			fmt.Fprintf(stdout, "  🔒 %-9s %-30s since %s, %d earlier connections cut\n", b.ID, truncate(b.Name, 30), b.Since.Local().Format("2006-01-02 15:04"), b.Flows)
		}
	}
	if len(e.Allowed) > 0 {
		note := ""
		if e.Lockdown == nil {
			note = " — takes effect during a lockdown"
		}
		fmt.Fprintf(stdout, "Allowed agents (%d processes)%s:\n", e.AllowedProcs, note)
		for _, b := range e.Allowed {
			fmt.Fprintf(stdout, "  ✅ %-9s %-30s since %s\n", b.ID, truncate(b.Name, 30), b.Since.Local().Format("2006-01-02 15:04"))
		}
	}
	if !e.CgroupV2 {
		fmt.Fprintln(stdout, "  note: cgroup v2 is not mounted, so per-agent blocking is unavailable here")
	}
	if e.Problem != "" {
		fmt.Fprintf(stdout, "  ⚠ %s\n", e.Problem)
	}
	if !e.RulesLoaded && e.Problem == "" {
		fmt.Fprintln(stdout, "  ⚠ the kernel does not have DevShield's firewall table loaded (the daemon re-applies it within 10 s)")
	}
}

// cliEgressRestore loads the saved network policy into the kernel without
// starting the daemon, so a lockdown is in force before any network
// interface comes up at boot.
func cliEgressRestore(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("egress-restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", daemon.DefaultStateDir, "root-only state directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	m, err := egress.New(egress.Config{StateDir: *stateDir})
	if err != nil {
		fmt.Fprintf(stderr, "devshield egress-restore: %v\n", err)
		return 1
	}
	st := m.Status()
	fmt.Fprintf(stdout, "network policy restored: lockdown %v, %d blocked agents\n", st.Lockdown != nil, len(st.Blocked))
	return 0
}

func cliLANPrivacy(args []string, socket string, stdout, stderr io.Writer) int {
	req := ipc.Request{Op: "lan-privacy"}
	asJSON := false
	for _, a := range args {
		switch a {
		case "on", "off":
			req = ipc.Request{Op: "set-lan-privacy", Profile: a}
		case "--json":
			asJSON = true
		default:
			fmt.Fprintln(stderr, "usage: devshield lan-privacy [on|off] [--json]")
			return 2
		}
	}
	resp, ok := call(socket, req, stderr)
	if !ok {
		return 1
	}
	l := resp.LAN
	if asJSON {
		b, _ := json.MarshalIndent(l, "", "  ")
		fmt.Fprintln(stdout, string(b))
	} else {
		if r := l.Result; r != nil {
			for _, c := range r.Changed {
				fmt.Fprintf(stdout, "  ✅ %s\n", c)
			}
			for _, s := range r.Skipped {
				fmt.Fprintf(stdout, "  ⏭  %s\n", s)
			}
			for _, n := range r.Notes {
				fmt.Fprintf(stdout, "  ·  %s\n", n)
			}
			fmt.Fprintln(stdout)
		}
		mark := func(bad bool) string {
			if bad {
				return "🔴"
			}
			return "🟢"
		}
		state := func(v string, bad bool) string { // unknown is never shown as good
			if v == "unknown" || v == "n/a" {
				return "❔"
			}
			return mark(bad)
		}
		fmt.Fprintf(stdout, "%s LLMNR: %s   %s mDNS: %s   %s IPv6 privacy addresses: %s\n",
			state(l.LLMNR, l.LLMNR == "on"), l.LLMNR, state(l.MDNS, l.MDNS == "on"), l.MDNS,
			state(l.IPv6Privacy, l.IPv6Privacy == "off"), l.IPv6Privacy)
		for _, w := range l.WiFi {
			state := "random address in use"
			if w.Hardware {
				state = "HARDWARE address — trackable across networks"
			}
			fmt.Fprintf(stdout, "%s Wi-Fi %s: %s (%s)\n", mark(w.Hardware), w.Name, w.MAC, state)
		}
		for _, w := range l.Warnings {
			fmt.Fprintf(stdout, "  ⚠ %s\n", w)
		}
		if l.Partial {
			fmt.Fprintln(stdout, "  ⚠ only some of DevShield's LAN-privacy files are present: run 'sudo devshield lan-privacy on' again")
		}
		if !l.Applied && l.Result == nil {
			fmt.Fprintln(stdout, "\nTurn on with: sudo devshield lan-privacy on")
		}
	}
	for _, w := range l.WiFi {
		if w.Hardware {
			return 3
		}
	}
	if l.LLMNR == "on" || l.MDNS == "on" {
		return 3
	}
	return 0
}

var netIcon = map[string]string{"telemetry": "📡", "llm": "🤖", "other": "🌐", "lan": "🏠", "loopback": "↩ "}

func cliNet(args []string, socket string, stdout, stderr io.Writer) int {
	all, asJSON := false, false
	for _, a := range args {
		switch a {
		case "--all":
			all = true
		case "--json":
			asJSON = true
		default:
			fmt.Fprintln(stderr, "usage: devshield net [--all] [--json]")
			return 2
		}
	}
	resp, ok := call(socket, ipc.Request{Op: "net"}, stderr)
	if !ok {
		return 1
	}
	if asJSON {
		b, _ := json.MarshalIndent(resp.Net, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	shown, telemetry := 0, 0
	fmt.Fprintf(stdout, "%-10s %-20s %7s  %-24s %4s  %s\n", "KIND", "PROGRAM", "PID", "REMOTE", "CONN", "LIKELY")
	for _, e := range resp.Net {
		if e.Category == "telemetry" {
			telemetry++
		}
		if !all && (e.Category == "loopback" || e.Category == "lan") {
			continue
		}
		shown++
		fmt.Fprintf(stdout, "%s %-7s %-20s %7d  %-24s %4d  %s\n", netIcon[e.Category], e.Category, truncate(e.Program, 20), e.PID, e.Remote, e.Count, e.Host)
	}
	if shown == 0 {
		fmt.Fprintln(stdout, "No outbound connections right now.")
	}
	fmt.Fprintln(stdout, "\nLabels come from IP addresses (shared CDNs can mislead). Updated every 10 s.")
	if telemetry > 0 {
		return 3
	}
	return 0
}
