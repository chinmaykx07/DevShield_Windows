package egress

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Socket is one entry from /proc/net/{tcp,tcp6,udp,udp6}.
type Socket struct {
	Proto      string
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      string // kernel state code in hex, e.g. "01" = TCP ESTABLISHED
	Inode      uint64
}

// tcpEstablished etc. are the kernel's TCP state codes.
const (
	tcpEstablished = "01"
	tcpSynSent     = "02"
	tcpListen      = "0A"
)

// parseProcNet parses the kernel's socket table text.
func parseProcNet(proto, content string) []Socket {
	var out []Socket
	sc := bufio.NewScanner(strings.NewReader(content))
	first := true
	for sc.Scan() {
		if first { // header line
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		lip, lport, err1 := parseAddr(f[1])
		rip, rport, err2 := parseAddr(f[2])
		inode, err3 := strconv.ParseUint(f[9], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		out = append(out, Socket{Proto: proto, LocalIP: lip, LocalPort: lport, RemoteIP: rip, RemotePort: rport, State: f[3], Inode: inode})
	}
	return out
}

// parseAddr decodes "0100007F:0035" (IPv4) or the 32-hex-digit IPv6 form.
// The kernel prints each 32-bit word in host (little-endian) byte order.
func parseAddr(s string) (net.IP, int, error) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(s[:i])
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	port, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return nil, 0, err
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 { // reverse each 4-byte word
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	if v4 := ip.To4(); v4 != nil && len(raw) == 16 {
		ip = v4 // IPv4-mapped IPv6
	}
	return ip, int(port), nil
}

// readSockets reads all four socket tables under procRoot (normally "/proc").
func readSockets(procRoot string) []Socket {
	var out []Socket
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := os.ReadFile(filepath.Join(procRoot, "net", proto))
		if err != nil {
			continue
		}
		out = append(out, parseProcNet(strings.TrimSuffix(proto, "6"), string(data))...)
	}
	return out
}

// socketInodes returns the socket inodes open in process pid.
func socketInodes(procRoot string, pid int) map[uint64]bool {
	fds, err := os.ReadDir(filepath.Join(procRoot, strconv.Itoa(pid), "fd"))
	if err != nil {
		return nil
	}
	out := map[uint64]bool{}
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "fd", fd.Name()))
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		if n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64); err == nil {
			out[n] = true
		}
	}
	return out
}

// flowOf turns a socket into the flow that would cut it: connected sockets
// by 5-tuple, listeners and unconnected UDP sockets by local address
// (connections accepted later on an old listener would otherwise inherit
// its pre-quarantine cgroup). ok is false for sockets with nothing left
// to send (closing, time-wait) or no local port.
func flowOf(s Socket) (Flow, bool) {
	if s.LocalPort == 0 {
		return Flow{}, false
	}
	f := Flow{Proto: s.Proto, LocalPort: s.LocalPort}
	if !s.LocalIP.IsUnspecified() {
		f.LocalIP = s.LocalIP.String()
	}
	connected := s.RemotePort != 0 && !s.RemoteIP.IsUnspecified()
	switch {
	case connected && (s.Proto == "udp" || s.State == tcpEstablished || s.State == tcpSynSent):
		f.RemoteIP, f.RemotePort = s.RemoteIP.String(), s.RemotePort
		return f, true
	case !connected && (s.Proto == "udp" || s.State == tcpListen):
		return f, true
	}
	return Flow{}, false
}

// OpenFlows lists the sockets owned by any of pids as flows to cut on
// quarantine.
func OpenFlows(procRoot string, pids []int) []Flow {
	owned := map[uint64]bool{}
	for _, pid := range pids {
		for in := range socketInodes(procRoot, pid) {
			owned[in] = true
		}
	}
	if len(owned) == 0 {
		return nil
	}
	var out []Flow
	seen := map[Flow]bool{}
	for _, s := range readSockets(procRoot) {
		if !owned[s.Inode] {
			continue
		}
		if f, ok := flowOf(s); ok && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// liveFlows is every flow that still has a socket on the system.
func liveFlows(procRoot string) map[Flow]bool {
	out := map[Flow]bool{}
	for _, s := range readSockets(procRoot) {
		if f, ok := flowOf(s); ok {
			out[f] = true
		}
	}
	return out
}
