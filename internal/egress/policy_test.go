package egress

import (
	"strings"
	"testing"
)

func TestRenderEmptyRemovesOnlyOurTable(t *testing.T) {
	s, err := Render(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if s != "table inet devshield\ndelete table inet devshield\n" {
		t.Fatalf("unexpected removal script:\n%s", s)
	}
}

func TestRenderLockdown(t *testing.T) {
	s, err := Render(Policy{Lockdown: &Lockdown{
		Interfaces: []string{"wg0"}, Endpoints: []string{"203.0.113.5:51820/udp", "[2001:db8::1]:443"}, Users: []int{108},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`oifname "lo" accept`,
		`ct direction reply accept`, // SSH into the box keeps working
		`oifname "wg0" accept`,
		`ip daddr 203.0.113.5 udp dport 51820 accept`,
		`ip6 daddr 2001:db8::1 tcp dport 443 accept`,
		`meta skuid 108 accept`,
		`counter drop comment "devshield lockdown: everything else"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, `comment "local network"`) {
		t.Error("LAN allowed without AllowLAN")
	}
	// The final drop must come after every accept of its chain.
	egress := s[:strings.Index(s, "chain forward")]
	if strings.LastIndex(egress, "accept") > strings.Index(egress, "counter drop comment \"devshield lockdown") {
		t.Error("an accept rule follows the final drop")
	}
	// Forwarded traffic (containers, VMs) is locked down too.
	fwd := s[strings.Index(s, "chain forward"):]
	if !strings.Contains(fwd, "hook forward") || !strings.Contains(fwd, `oifname "wg0" accept`) || !strings.Contains(fwd, "forwarded traffic outside the tunnel") {
		t.Errorf("forward chain missing or incomplete:\n%s", fwd)
	}
	// DHCP and neighbour discovery only to the local link, never anywhere.
	if strings.Contains(s, "udp dport { 67, 547 } accept") || !strings.Contains(s, "udp sport 68 udp dport 67 ip daddr {") ||
		!strings.Contains(s, "ip6 daddr { fe80::/10, ff02::/16 } accept") {
		t.Error("DHCP/ND rules are not restricted to the local link")
	}
	// Sampled logging: the limit must come before the log statement.
	if !strings.Contains(s, "limit rate 5/minute log prefix") {
		t.Error("log is not rate limited (statement order)")
	}
}

func TestLANDoesNotLeakDNS(t *testing.T) {
	s, _ := Render(Policy{Lockdown: &Lockdown{Interfaces: []string{"wg0"}, AllowLAN: true}})
	dns, lan := strings.Index(s, "udp dport { 53, 137, 138, 5353, 5355 } drop"), strings.Index(s, `comment "local network"`)
	if dns < 0 || lan < 0 || dns > lan || strings.Index(s, `oifname "wg0"`) > dns {
		t.Fatalf("DNS must be dropped after the tunnel accept and before the LAN accept:\n%s", s)
	}
}

func TestStrictLockdownBlocksReplies(t *testing.T) {
	s, _ := Render(Policy{Lockdown: &Lockdown{Interfaces: []string{"wg0"}, NoReplies: true}})
	if strings.Contains(s, "ct direction reply") {
		t.Fatal("strict lockdown must not accept replies")
	}
}

func TestQuarantineRuleComesFirst(t *testing.T) {
	s, _ := Render(Policy{Quarantine: true, Lockdown: &Lockdown{Interfaces: []string{"wg0"}}})
	q, lo := strings.Index(s, "socket cgroupv2"), strings.Index(s, `oifname "lo"`)
	if q < 0 || q > lo {
		t.Fatal("quarantine drop must precede the loopback accept (a local proxy could carry traffic out)")
	}
}

func TestHybridCgroupPath(t *testing.T) {
	s, err := Render(Policy{Quarantine: true, CgroupPath: "unified/devshield-quarantine"})
	if err != nil || !strings.Contains(s, `socket cgroupv2 level 1 "unified/devshield-quarantine"`) {
		t.Fatalf("hybrid path not rendered (%v):\n%s", err, s)
	}
	for _, bad := range []string{"../etc", `x" accept`, "unified/other"} {
		if _, err := Render(Policy{Quarantine: true, CgroupPath: bad}); err == nil {
			t.Errorf("accepted cgroup path %q", bad)
		}
	}
}

func TestAllowedAgentsOnlyDuringLockdown(t *testing.T) {
	s, err := Render(Policy{Quarantine: true, AllowedPath: AllowedCgroup, Lockdown: &Lockdown{OnlyAllowed: true}})
	if err != nil {
		t.Fatal(err)
	}
	q, a, d := strings.Index(s, `"devshield-quarantine" counter drop`), strings.Index(s, `"devshield-allowed" accept`), strings.Index(s, "everything else")
	if q < 0 || a < 0 || !(q < a && a < d) {
		t.Fatalf("want quarantine drop < allowed accept < final drop:\n%s", s)
	}
	if s, _ := Render(Policy{AllowedPath: AllowedCgroup, KillFlows: []Flow{{Proto: "tcp", LocalPort: 1}}}); strings.Contains(s, "devshield-allowed") {
		t.Fatal("allowed rule rendered without a lockdown")
	}
	if _, err := Render(Policy{AllowedPath: "devshield-quarantine", Lockdown: &Lockdown{OnlyAllowed: true}}); err == nil {
		t.Fatal("wrong group accepted as the allowed group")
	}
}

func TestRenderKillFlows(t *testing.T) {
	s, err := Render(Policy{KillFlows: []Flow{
		{Proto: "tcp", LocalIP: "10.0.0.2", LocalPort: 51000, RemoteIP: "160.79.104.10", RemotePort: 443},
		{Proto: "udp", LocalIP: "2001:db8::2", LocalPort: 5353, RemoteIP: "2001:db8::53", RemotePort: 53},
		{Proto: "tcp", LocalPort: 8080}, // listener on all addresses
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "ip saddr 10.0.0.2 tcp sport 51000 ip daddr 160.79.104.10 tcp dport 443 counter drop") ||
		!strings.Contains(s, "ip6 saddr 2001:db8::2 udp sport 5353 ip6 daddr 2001:db8::53 udp dport 53 counter drop") ||
		!strings.Contains(s, "\ttcp sport 8080 counter drop") {
		t.Fatalf("flows not rendered:\n%s", s)
	}
}

func TestValidationRejectsUnsafeInput(t *testing.T) {
	bad := []Policy{
		{Lockdown: &Lockdown{}}, // nothing allowed out at all
		{Lockdown: &Lockdown{Interfaces: []string{`wg0" accept; drop #`}}},
		{Lockdown: &Lockdown{Interfaces: []string{"wg0"}, Endpoints: []string{"vpn.example.com:51820/udp"}}}, // name would leak a DNS query
		{Lockdown: &Lockdown{Interfaces: []string{"wg0"}, Endpoints: []string{"203.0.113.5:70000/udp"}}},
		{Lockdown: &Lockdown{Interfaces: []string{"wg0"}, Endpoints: []string{"203.0.113.5:443/icmp"}}},
		{KillFlows: []Flow{{Proto: "tcp", LocalIP: "10.0.0.2", LocalPort: 1, RemoteIP: "2001:db8::1", RemotePort: 2}}}, // mixed families
		{KillFlows: []Flow{{Proto: "tcp", LocalIP: "not-an-ip", LocalPort: 1, RemoteIP: "1.2.3.4", RemotePort: 2}}},
		{KillFlows: []Flow{{Proto: "tcp", LocalPort: 1, RemoteIP: "1.2.3.4"}}}, // remote IP without port
		{KillFlows: []Flow{{Proto: "tcp", LocalPort: 0}}},
	}
	for i, p := range bad {
		if _, err := Render(p); err == nil {
			t.Errorf("case %d: unsafe policy accepted: %+v", i, p)
		}
	}
}

// Lines in the exact format the kernel prints.
func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18311 1 0000000000000000 100 0 0 10 0
   1: 0200000A:C738 0A684FA0:01BB 01 00000000:00000000 02:0000A1B6 00000000  1000        0 99881 2 0000000000000000 20 4 30 10 -1
`
	ss := parseProcNet("tcp", tcp)
	if len(ss) != 2 {
		t.Fatalf("parsed %d sockets", len(ss))
	}
	if ss[0].LocalIP.String() != "127.0.0.1" || ss[0].LocalPort != 631 || ss[0].State != "0A" {
		t.Errorf("listener parsed as %+v", ss[0])
	}
	e := ss[1]
	if e.LocalIP.String() != "10.0.0.2" || e.LocalPort != 51000 || e.RemoteIP.String() != "160.79.104.10" || e.RemotePort != 443 || e.Inode != 99881 {
		t.Errorf("established parsed as %+v", e)
	}

	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000200000A:C739 0000000000000000FFFF00000A684FA0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 99882 1
   1: B80D0120000000000000000002000000:D431 B80D0120000000000000000001000000:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 99883 1
`
	s6 := parseProcNet("tcp", tcp6)
	if len(s6) != 2 || s6[0].RemoteIP.String() != "160.79.104.10" || s6[1].LocalIP.String() != "2001:db8::2" || s6[1].RemoteIP.String() != "2001:db8::1" {
		t.Fatalf("tcp6 parsed as %+v", s6)
	}
}
