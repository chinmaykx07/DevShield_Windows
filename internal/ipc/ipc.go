// Package ipc is the local channel between the DevShield daemon (root)
// and its clients (CLI, tray) running as the user.
//
// Who is calling is decided by the KERNEL, not by the caller: on Linux the
// server reads the peer's uid/pid with SO_PEERCRED, so a process cannot
// claim to be root. Authorization (which uid may do what) belongs to the
// daemon; this package only transports one JSON request and one JSON
// response per connection, with size limits and deadlines.
package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/chinmaykx07/DevShield_Windows/internal/auditlog"
	"github.com/chinmaykx07/DevShield_Windows/internal/egress"
	"github.com/chinmaykx07/DevShield_Windows/internal/lanprivacy"
	"github.com/chinmaykx07/DevShield_Windows/internal/netwatch"
)

// DefaultSocket is where the Linux daemon listens.
const DefaultSocket = "/run/devshield/devshield.sock"

const (
	maxRequestBytes = 64 << 10
	ioTimeout       = 10 * time.Second
)

// Request is what a client asks for.
type Request struct {
	Op       string           `json:"op"`                // see daemon.readOps / daemon.writeOps
	ID       string           `json:"id,omitempty"`      // agent id for sanction/revoke/block/unblock
	Limit    int              `json:"limit,omitempty"`   // for events
	Profile  string           `json:"profile,omitempty"` // silent|gaming|dev|off for profile; on|off for sinkhole; on|off|confirm for lockdown
	Lockdown *LockdownRequest `json:"lockdown,omitempty"`
}

// LockdownRequest describes the allowed outbound paths. Users are names
// or uids; the daemon resolves them.
type LockdownRequest struct {
	Via         []string `json:"via,omitempty"`       // tunnel interfaces
	Endpoints   []string `json:"endpoints,omitempty"` // "ip:port/proto" of the tunnel servers
	Users       []string `json:"users,omitempty"`
	Tor         bool     `json:"tor,omitempty"`          // allow the Tor daemon's user
	OnlyAllowed bool     `json:"only_allowed,omitempty"` // no tunnel: only allowed agents go out
	LAN         bool     `json:"lan,omitempty"`
	Strict      bool     `json:"strict,omitempty"`
	ConfirmSec  int      `json:"confirm_sec,omitempty"`
}

// Agent is the client-facing view of one running agent.
type Agent struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Vendor    string   `json:"vendor,omitempty"`
	Kind      string   `json:"kind"`
	Verdict   string   `json:"verdict"`
	Status    string   `json:"status"`
	PID       int32    `json:"pid"`
	Processes int      `json:"processes"`
	User      string   `json:"user,omitempty"`
	Exe       string   `json:"exe,omitempty"`
	Reasons   []string `json:"reasons,omitempty"`
	Risks     []string `json:"risks,omitempty"`
	Blocked   bool     `json:"network_blocked,omitempty"`
	// NotYetCut: blocked, but this many of its processes are not inside the
	// quarantine yet (caught at the next scan).
	NotYetCut int  `json:"not_yet_cut,omitempty"`
	Allowed   bool `json:"network_allowed,omitempty"`
}

// Status summarises the daemon's health.
type Status struct {
	Version    string `json:"version"`
	UptimeSec  int64  `json:"uptime_sec"`
	Agents     int    `json:"agents"`
	Rogue      int    `json:"rogue"`
	Risky      int    `json:"risky"`
	LogRecords int    `json:"log_records"`
	LogIntact  bool   `json:"log_intact"`
	LogProblem string `json:"log_problem,omitempty"`
	// LogUnchecked: verification could not run (I/O error): not a tamper finding.
	LogUnchecked bool `json:"log_unchecked,omitempty"`
	// LostEvents: events this daemon run could not write to the log (e.g.
	// disk full). They are gone; the log itself is still intact.
	LostEvents  int64 `json:"lost_events,omitempty"`
	TamperSince bool  `json:"tamper_detected_this_run"`
}

// Thermal describes thermal controls and state.
type Thermal struct {
	Supported bool     `json:"supported"`
	Active    string   `json:"active"`   // profile DevShield applied, "" = original settings
	Controls  []string `json:"controls"` // what this machine lets DevShield change
	CPUTempC  float64  `json:"cpu_temp_c"`
	GPUTempC  float64  `json:"gpu_temp_c"`
	MaxFanRPM float64  `json:"max_fan_rpm"`
	// Result of a profile change
	Applied  []string `json:"applied,omitempty"`
	Skipped  []string `json:"skipped,omitempty"`
	Mismatch []string `json:"mismatch,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

// Sinkhole describes the /etc/hosts telemetry sinkhole.
type Sinkhole struct {
	Active      bool     `json:"active"`
	Damaged     bool     `json:"damaged,omitempty"`
	Blocked     int      `json:"blocked"`
	Expected    int      `json:"expected"`
	Missing     []string `json:"missing,omitempty"`
	FilesInNSS  bool     `json:"files_in_nss"`
	Warnings    []string `json:"warnings,omitempty"`
	ListVersion string   `json:"list_version"`
	Groups      []string `json:"groups,omitempty"`
}

// Response is the daemon's answer.
type Response struct {
	OK       bool              `json:"ok"`
	Error    string            `json:"error,omitempty"`
	Status   *Status           `json:"status,omitempty"`
	Agents   []Agent           `json:"agents,omitempty"`
	Events   []auditlog.Record `json:"events,omitempty"`
	Thermal  *Thermal          `json:"thermal,omitempty"`
	Sinkhole *Sinkhole         `json:"sinkhole,omitempty"`
	Egress   *egress.Status    `json:"egress,omitempty"`
	LAN      *LANPrivacy       `json:"lan_privacy,omitempty"`
	Net      []netwatch.Entry  `json:"net,omitempty"`
	Restore  []RestoreStep     `json:"restore,omitempty"`
	Note     string            `json:"note,omitempty"` // a success with a caveat the user must see
}

// RestoreStep is one part of undoing DevShield's changes.
type RestoreStep struct {
	What   string   `json:"what"`
	OK     bool     `json:"ok"`
	Detail string   `json:"detail,omitempty"`
	Notes  []string `json:"notes,omitempty"` // done, but with a caveat
}

// LANPrivacy is the local-network privacy state, and what a change did.
type LANPrivacy struct {
	lanprivacy.Status
	Result *lanprivacy.Result `json:"result,omitempty"`
}

// Peer identifies the process on the other end, as reported by the kernel.
type Peer struct {
	UID int
	PID int
	Exe string // best effort, from /proc/<pid>/exe
}

func (p Peer) String() string {
	return fmt.Sprintf("uid=%d pid=%d exe=%s", p.UID, p.PID, p.Exe)
}

// Handler answers one authenticated request.
type Handler func(peer Peer, req Request) Response

// ErrUnsupported is returned where the daemon channel isn't implemented yet.
var ErrUnsupported = errors.New("the DevShield daemon is not available on this platform yet")

// Serve accepts connections until the listener is closed.
// maxConcurrent bounds how many requests are served at once, so a local
// process opening many idle connections cannot exhaust the daemon.
const maxConcurrent = 32

func Serve(l net.Listener, h Handler) error {
	slots := make(chan struct{}, maxConcurrent)
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				handle(conn, h)
			}()
		default:
			conn.Close() // busy: refuse rather than queue without limit
		}
	}
}

func handle(conn net.Conn, h Handler) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))

	peer, err := peerOf(conn)
	if err != nil {
		// Without kernel-verified identity nothing is answered.
		log.Printf("ipc: rejecting connection without peer credentials: %v", err)
		writeResponse(conn, Response{Error: "cannot verify caller identity"})
		return
	}

	line, err := bufio.NewReader(io.LimitReader(conn, maxRequestBytes)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		writeResponse(conn, Response{Error: "malformed request"})
		return
	}
	writeResponse(conn, h(peer, req))
}

func writeResponse(w io.Writer, r Response) {
	b, _ := json.Marshal(r)
	_, _ = w.Write(append(b, '\n'))
}

// Call sends one request to the daemon at socketPath and returns its answer.
func Call(socketPath string, req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return Response{}, fmt.Errorf("cannot reach the DevShield daemon at %s: %w", socketPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))

	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return Response{}, err
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 16<<20)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return Response{}, fmt.Errorf("no answer from daemon: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("bad answer from daemon: %w", err)
	}
	return resp, nil
}
