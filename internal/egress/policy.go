// Package egress is DevShield's outbound-traffic control: the owner decides
// what may leave the machine. It renders an nftables ruleset into its own
// table ("inet devshield") and never touches other tables.
//
// Two kernel-enforced mechanisms (no userspace in the packet path, so they
// keep working — fail closed — even if DevShield stops):
//
//   - Quarantine: processes moved into the cgroup v2 group
//     "devshield-quarantine" (and everything they spawn, which inherits the
//     group) cannot send anything, loopback included.
//   - Lockdown (the Tor alternative): nothing leaves except through the
//     owner's chosen tunnel interfaces (WireGuard/OpenVPN/…), to the
//     tunnel's own endpoints, from approved service users (e.g. the Tor
//     daemon's user), and optionally the local network. DNS and IPv6 cannot
//     leak around the tunnel because nothing else is allowed out.
//
// What it cannot stop is listed in docs/USER_MANUAL.md (out-of-band
// management engines such as Intel AMT, root-level malware, data hidden
// inside traffic of an allowed program).
package egress

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// QuarantineCgroup is the cgroup v2 group (directly under the root) whose
// members may not send any traffic.
const QuarantineCgroup = "devshield-quarantine"

// AllowedCgroup holds agents the owner allowed out during a lockdown.
const AllowedCgroup = "devshield-allowed"

// TableName is DevShield's own nftables table.
const TableName = "devshield"

// MinConfirm is the shortest dead-man window: shorter ones cannot be
// confirmed in time and would only look like protection. (A variable so
// tests can shorten it.)
var MinConfirm = 10 * time.Second

// Lockdown restricts all outbound traffic to approved paths.
type Lockdown struct {
	Interfaces []string `json:"interfaces"`           // tunnel interfaces, e.g. wg0, tun0
	Endpoints  []string `json:"endpoints"`            // tunnel servers reachable directly: "203.0.113.5:51820/udp"
	Users      []int    `json:"users,omitempty"`      // uids allowed out directly (e.g. the tor daemon user)
	AllowLAN   bool     `json:"allow_lan"`            // private/link-local ranges
	NoReplies  bool     `json:"no_replies,omitempty"` // strict: also block replies to inbound connections (breaks SSH into this machine)
	// Inbound lists the local services ("22/tcp") whose replies to
	// connections made TO this machine may leave; "all" allows every
	// reply. Empty = DefaultInbound. Replies to other inbound connections
	// are dropped: a program serving on another port can't answer
	// whoever connects to it from outside.
	Inbound []string `json:"inbound,omitempty"`
	// OnlyAllowed: no tunnel or user at all — only allowed agents go out.
	OnlyAllowed bool `json:"only_allowed,omitempty"`
}

// Flow is one existing socket to cut: sockets keep the cgroup they were
// created in, so sockets a process opened BEFORE quarantine are not matched
// by the cgroup rule and must be dropped by address. A connected socket is
// a full 5-tuple; a listener or unconnected UDP socket has no remote side
// (RemoteIP "" and RemotePort 0) and is matched by its local port — and
// local IP when bound to one.
type Flow struct {
	Proto      string `json:"proto"` // tcp | udp
	LocalIP    string `json:"local_ip,omitempty"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
}

// rule renders f as nft match expressions, validating every field.
func (f Flow) rule() (string, error) {
	bad := fmt.Errorf("invalid flow %+v", f)
	if (f.Proto != "tcp" && f.Proto != "udp") || f.LocalPort < 1 || f.LocalPort > 65535 ||
		f.RemotePort < 0 || f.RemotePort > 65535 || (f.RemoteIP == "") != (f.RemotePort == 0) {
		return "", bad
	}
	fam := ""
	var parts []string
	addr := func(dir, s string) error {
		if s == "" {
			return nil
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return bad
		}
		this := "ip"
		if ip.To4() == nil {
			this = "ip6"
		}
		if fam != "" && fam != this {
			return bad // mixed families
		}
		fam = this
		parts = append(parts, fmt.Sprintf("%s %s %s", fam, dir, ip))
		return nil
	}
	if err := addr("saddr", f.LocalIP); err != nil {
		return "", err
	}
	parts = append(parts, fmt.Sprintf("%s sport %d", f.Proto, f.LocalPort))
	if err := addr("daddr", f.RemoteIP); err != nil {
		return "", err
	}
	if f.RemotePort != 0 {
		parts = append(parts, fmt.Sprintf("%s dport %d", f.Proto, f.RemotePort))
	}
	return strings.Join(parts, " "), nil
}

// Policy is the full egress configuration.
type Policy struct {
	Quarantine bool      `json:"quarantine"` // install the quarantine rule (cgroup v2 present)
	KillFlows  []Flow    `json:"kill_flows,omitempty"`
	Lockdown   *Lockdown `json:"lockdown,omitempty"`
	// CgroupPath is the quarantine group relative to /sys/fs/cgroup, as nft
	// resolves it ("" = QuarantineCgroup; hybrid systems: "unified/…").
	CgroupPath string `json:"-"`
	// AllowedPath is the allowed-agents group relative to /sys/fs/cgroup;
	// "" = no allowed agents. Only used during a lockdown.
	AllowedPath string `json:"-"`
	// SkipLoopback is for tests only: lockdown normally always allows lo.
	SkipLoopback bool `json:"-"`
	// BlockDoH drops DNS over TLS/QUIC (port 853) and HTTPS to the
	// well-known public DoH resolvers, for every program.
	BlockDoH bool `json:"-"`
}

// Empty reports whether the policy needs no rules at all.
func (p Policy) Empty() bool {
	return !p.Quarantine && p.Lockdown == nil && len(p.KillFlows) == 0 && !p.BlockDoH
}

// Endpoint is a parsed "ip:port/proto".
type Endpoint struct {
	IP    net.IP
	Port  int
	Proto string // udp | tcp
}

// ParseEndpoint accepts "203.0.113.5:51820/udp", "[2001:db8::1]:443/tcp"
// or "203.0.113.5:443" (tcp). Only literal IPs: resolving a name would
// itself need traffic outside the tunnel.
func ParseEndpoint(s string) (Endpoint, error) {
	proto := "tcp"
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		proto = strings.ToLower(s[i+1:])
		s = s[:i]
	}
	if proto != "udp" && proto != "tcp" {
		return Endpoint{}, fmt.Errorf("endpoint protocol %q: want udp or tcp", proto)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return Endpoint{}, fmt.Errorf("endpoint %q: %w (use ip:port/proto)", s, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return Endpoint{}, fmt.Errorf("endpoint %q: use an IP address, not a name (resolving it would leak)", host)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return Endpoint{}, fmt.Errorf("endpoint port %q invalid", port)
	}
	return Endpoint{IP: ip, Port: p, Proto: proto}, nil
}

// validIface accepts kernel interface names only (no nft syntax injection).
func validIface(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// Validate checks a lockdown configuration before anything is applied.
// DefaultInbound keeps SSH into this machine working during a lockdown.
var DefaultInbound = []string{"22/tcp"}

// Service is one local port whose replies may leave.
type Service struct {
	Port  int
	Proto string // tcp | udp
}

// ParseService reads "22/tcp", "53/udp" or "22" (tcp).
func ParseService(s string) (Service, error) {
	port, proto, _ := strings.Cut(strings.ToLower(strings.TrimSpace(s)), "/")
	if proto == "" {
		proto = "tcp"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || (proto != "tcp" && proto != "udp") {
		return Service{}, fmt.Errorf("invalid inbound service %q (want PORT/tcp or PORT/udp, or all)", s)
	}
	return Service{Port: n, Proto: proto}, nil
}

// ReplyServices says which replies to inbound connections may leave:
// all of them, or those of the listed services (none with --strict).
func (l *Lockdown) ReplyServices() (all bool, svcs []Service) {
	if l.NoReplies {
		return false, nil
	}
	in := l.Inbound
	if len(in) == 0 {
		in = DefaultInbound
	}
	seen := map[Service]bool{}
	for _, s := range in {
		if strings.EqualFold(strings.TrimSpace(s), "all") {
			return true, nil
		}
		if sv, err := ParseService(s); err == nil && !seen[sv] {
			seen[sv] = true
			svcs = append(svcs, sv)
		}
	}
	sort.Slice(svcs, func(i, j int) bool {
		if svcs[i].Proto != svcs[j].Proto {
			return svcs[i].Proto < svcs[j].Proto
		}
		return svcs[i].Port < svcs[j].Port
	})
	return false, svcs
}

func (l *Lockdown) Validate() error {
	if len(l.Interfaces) == 0 && len(l.Users) == 0 && !l.OnlyAllowed {
		return fmt.Errorf("lockdown needs at least one tunnel interface (--via) or allowed user (--user), or --only-allowed; otherwise nothing could reach the internet")
	}
	for _, i := range l.Interfaces {
		if !validIface(i) {
			return fmt.Errorf("invalid interface name %q", i)
		}
	}
	for _, e := range l.Endpoints {
		if _, err := ParseEndpoint(e); err != nil {
			return err
		}
	}
	for _, u := range l.Users {
		if u < 0 {
			return fmt.Errorf("invalid uid %d", u)
		}
	}
	for _, s := range l.Inbound {
		if strings.EqualFold(strings.TrimSpace(s), "all") {
			continue
		}
		if _, err := ParseService(s); err != nil {
			return err
		}
	}
	if l.NoReplies && len(l.Inbound) > 0 {
		return fmt.Errorf("--strict blocks all replies to inbound connections; it can't be combined with --inbound")
	}
	return nil
}

// checkGroupPath accepts only DevShield's own group, so nothing can be
// injected into the rule.
func checkGroupPath(path, group string) error {
	if strings.ContainsAny(path, "\"\\\n") || strings.HasPrefix(path, "..") || filepath.Base(path) != group {
		return fmt.Errorf("unexpected cgroup path %q", path)
	}
	return nil
}

// Render produces an nftables script that atomically replaces DevShield's
// table with p (or removes it when p is empty). Other tables are untouched.
func Render(p Policy) (string, error) {
	var b strings.Builder
	// Create-then-delete makes the delete safe when the table doesn't exist;
	// the whole script is one atomic transaction in nft -f.
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\n", TableName, TableName)
	if p.Empty() {
		return b.String(), nil
	}
	if p.Lockdown != nil {
		if err := p.Lockdown.Validate(); err != nil {
			return "", err
		}
	}

	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	b.WriteString("\tchain egress {\n\t\ttype filter hook output priority filter; policy accept;\n")

	if p.Quarantine {
		// First rule: quarantined processes get nothing, loopback included
		// (a local proxy could otherwise carry their traffic out).
		path := p.CgroupPath
		if path == "" {
			path = QuarantineCgroup
		}
		if err := checkGroupPath(path, QuarantineCgroup); err != nil {
			return "", err
		}
		// The group sits directly under the hierarchy root (level 1) wherever
		// the hierarchy is mounted.
		fmt.Fprintf(&b, "\t\tsocket cgroupv2 level 1 %q counter drop comment \"devshield quarantine\"\n", path)
	}

	for _, f := range p.KillFlows {
		r, err := f.rule()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "\t\t%s counter drop comment \"quarantined socket\"\n", r)
	}

	if p.BlockDoH {
		writeDoH(&b) // before the lockdown's accepts: also through the tunnel
	}

	if l := p.Lockdown; l != nil {
		if !p.SkipLoopback {
			b.WriteString("\t\toifname \"lo\" accept\n")
		}
		writeReplies(&b, l)
		if p.AllowedPath != "" {
			if err := checkGroupPath(p.AllowedPath, AllowedCgroup); err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "\t\tsocket cgroupv2 level 1 %q accept comment \"allowed agents\"\n", p.AllowedPath)
		}
		ifaces := append([]string(nil), l.Interfaces...)
		sort.Strings(ifaces)
		for _, i := range ifaces {
			fmt.Fprintf(&b, "\t\toifname %q accept comment \"tunnel\"\n", i)
		}
		for _, e := range l.Endpoints {
			ep, _ := ParseEndpoint(e)
			fam := "ip"
			if ep.IP.To4() == nil {
				fam = "ip6"
			}
			fmt.Fprintf(&b, "\t\t%s daddr %s %s dport %d accept comment \"tunnel endpoint\"\n", fam, ep.IP, ep.Proto, ep.Port)
		}
		users := append([]int(nil), l.Users...)
		sort.Ints(users)
		for _, u := range users {
			fmt.Fprintf(&b, "\t\tmeta skuid %d accept comment \"allowed service user\"\n", u)
		}
		// Keep the link itself working, and nothing more: DHCP to the
		// local network only (a public DHCP server's unicast renewal falls
		// back to a broadcast rebind), and IPv6 neighbour discovery to
		// link-local and multicast addresses. Unrestricted, these ports
		// would be a way out for any program.
		b.WriteString("\t\tudp sport 68 udp dport 67 ip daddr { 255.255.255.255, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } accept comment \"dhcp\"\n")
		b.WriteString("\t\tudp sport 546 udp dport 547 ip6 daddr { ff02::1:2, fe80::/10 } accept comment \"dhcpv6\"\n")
		b.WriteString("\t\ticmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } ip6 daddr { fe80::/10, ff02::/16 } accept comment \"ipv6 neighbour discovery\"\n")
		writeLAN(&b, l)
		writeFinalDrop(&b, "devshield-lockdown-drop ", "devshield lockdown: everything else")
	}
	b.WriteString("\t}\n")
	if l := p.Lockdown; l != nil {
		// Traffic this machine forwards for containers and VMs (Docker,
		// libvirt, network namespaces) never passes the output hook: without
		// this chain it would leave outside the tunnel.
		b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n")
		writeReplies(&b, l)
		if p.BlockDoH {
			writeDoH(&b)
		}
		ifaces := append([]string(nil), l.Interfaces...)
		sort.Strings(ifaces)
		for _, i := range ifaces {
			fmt.Fprintf(&b, "\t\toifname %q accept comment \"tunnel\"\n", i)
		}
		writeLAN(&b, l)
		writeFinalDrop(&b, "devshield-forward-drop ", "devshield lockdown: forwarded traffic outside the tunnel")
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}

// writeDoH drops encrypted DNS that would bypass /etc/hosts: DNS over TLS
// and over QUIC (port 853) to anyone, and HTTPS to the public DoH
// resolvers in DoHResolversV4/V6.
func writeDoH(b *strings.Builder) {
	b.WriteString("\t\tmeta l4proto { tcp, udp } th dport 853 counter drop comment \"devshield: dns over tls/quic\"\n")
	fmt.Fprintf(b, "\t\tip daddr { %s } meta l4proto { tcp, udp } th dport 443 counter drop comment \"devshield: public doh resolvers\"\n", strings.Join(DoHResolversV4, ", "))
	fmt.Fprintf(b, "\t\tip6 daddr { %s } meta l4proto { tcp, udp } th dport 443 counter drop comment \"devshield: public doh resolvers\"\n", strings.Join(DoHResolversV6, ", "))
}

// writeReplies lets out answers to connections someone else opened (e.g.
// SSH into this machine), only for the services named: "ct original
// proto-dst" is the local port the connection was made to. This never
// allows a NEW outbound connection.
func writeReplies(b *strings.Builder, l *Lockdown) {
	all, svcs := l.ReplyServices()
	if all {
		b.WriteString("\t\tct direction reply accept comment \"replies to inbound connections\"\n")
		return
	}
	for _, s := range svcs {
		fmt.Fprintf(b, "\t\tct direction reply meta l4proto %s ct original proto-dst %d accept comment \"replies to inbound %d/%s\"\n", s.Proto, s.Port, s.Port, s.Proto)
	}
}

// writeLAN allows the local network when asked, but never name lookups:
// DNS, and the local-name protocols (mDNS, LLMNR, NetBIOS) that would
// announce or ask for names in clear on the LAN. Printers found by name
// over mDNS are therefore not discovered; use their IP address.
func writeLAN(b *strings.Builder, l *Lockdown) {
	if !l.AllowLAN {
		return
	}
	b.WriteString("\t\tudp dport { 53, 137, 138, 5353, 5355 } drop comment \"no name lookups outside the tunnel\"\n")
	b.WriteString("\t\ttcp dport { 53, 853, 5355 } drop comment \"no name lookups outside the tunnel\"\n")
	b.WriteString("\t\tip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept comment \"local network\"\n")
	b.WriteString("\t\tip6 daddr { fe80::/10, fc00::/7, ff00::/8 } accept comment \"local network\"\n")
}

// writeFinalDrop logs a sample of drops (the limit comes first: nft runs
// statements left to right, so "log … limit" would log every packet) and
// drops everything that reached the end of the chain.
func writeFinalDrop(b *strings.Builder, prefix, comment string) {
	fmt.Fprintf(b, "\t\tlimit rate 5/minute log prefix %q level info\n", prefix)
	fmt.Fprintf(b, "\t\tcounter drop comment %q\n", comment)
}
