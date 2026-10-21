package lanprivacy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSystem builds a root with systemd-resolved and NetworkManager
// installed, one Wi-Fi card with its hardware MAC, IPv6 privacy off and
// avahi running. resolvectl reports whatever *protos holds.
func fakeSystem(t *testing.T, protos *string) (System, *[]string) {
	t.Helper()
	root := t.TempDir()
	mk := func(p, content string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(content), 0o644)
	}
	mk("/usr/lib/systemd/systemd-resolved", "")
	os.MkdirAll(filepath.Join(root, "/etc/NetworkManager/conf.d"), 0o755)
	mk("/etc/NetworkManager/conf.d/00-user.conf", "[main]\n") // the user's own file
	mk("/sys/class/net/wlp2s0/address", "a4:c3:f0:11:22:33\n")
	mk("/sys/class/net/wlp2s0/addr_assign_type", "0\n")
	os.MkdirAll(filepath.Join(root, "/sys/class/net/wlp2s0/wireless"), 0o755)
	mk("/sys/class/net/eth0/address", "00:11:22:33:44:55\n")
	mk("/proc/sys/net/ipv6/conf/all/use_tempaddr", "0\n")
	mk("/proc/sys/net/ipv6/conf/default/use_tempaddr", "0\n")
	mk("/proc/812/comm", "avahi-daemon\n")
	var calls []string
	run := func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "resolvectl" {
			return "Global\n       Protocols: " + *protos + " -DNSOverTLS DNSSEC=no/unsupported\n", nil
		}
		return "", nil
	}
	return System{Root: root, Run: run}, &calls
}

func TestApplyCheckOff(t *testing.T) {
	protos := "+LLMNR +mDNS"
	s, calls := fakeSystem(t, &protos)

	before := s.Check()
	if before.Applied || before.LLMNR != "on" || before.MDNS != "on" || before.IPv6Privacy != "off" ||
		len(before.WiFi) != 1 || !before.WiFi[0].Hardware || len(before.Warnings) != 1 {
		t.Fatalf("before: %+v", before)
	}

	r, err := s.Apply()
	if err != nil || len(r.Changed) != 3 {
		t.Fatalf("apply: %+v %v", r, err)
	}
	if got := strings.Join(*calls, "|"); !strings.Contains(got, "systemctl try-reload-or-restart systemd-resolved") || !strings.Contains(got, "nmcli general reload conf") {
		t.Fatalf("reloads not requested: %s", got)
	}
	data, _ := os.ReadFile(filepath.Join(s.Root, NMDropIn))
	if !strings.Contains(string(data), "wifi.cloned-mac-address=stable") || !strings.Contains(string(data), "connection.llmnr=0") {
		t.Fatalf("NM drop-in: %s", data)
	}

	// Status trusts what the system reports, not what was written.
	protos = "-LLMNR -mDNS"
	after := s.Check()
	if !after.Applied || after.LLMNR != "off" || after.MDNS != "off" || after.IPv6Privacy != "preferred" {
		t.Fatalf("after: %+v", after)
	}

	// A second "on" must not record DevShield's own values as the originals.
	if _, err := s.Apply(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Off(); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"all", "default"} {
		if v, _ := os.ReadFile(filepath.Join(s.Root, "/proc/sys/net/ipv6/conf", k, "use_tempaddr")); strings.TrimSpace(string(v)) != "0" {
			t.Errorf("live use_tempaddr (%s) = %q after off, want the original 0", k, v)
		}
	}
	for _, f := range []string{ResolvedDropIn, NMDropIn, SysctlDropIn} {
		if _, err := os.Stat(filepath.Join(s.Root, f)); err == nil {
			t.Errorf("%s left behind", f)
		}
	}
	if _, err := os.Stat(filepath.Join(s.Root, "/etc/NetworkManager/conf.d/00-user.conf")); err != nil {
		t.Fatal("the user's own NetworkManager file was touched")
	}
	if r, _ := s.Off(); len(r.Changed) != 0 {
		t.Fatal("second off claimed changes")
	}
}

func TestOnlyInstalledComponentsAreConfigured(t *testing.T) {
	root := t.TempDir()
	s := System{Root: root, Run: func(string, ...string) (string, error) { return "", errors.New("not found") }}
	r, err := s.Apply()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, NMDropIn)); err == nil {
		t.Fatal("NetworkManager config written without NetworkManager")
	}
	if _, err := os.Stat(filepath.Join(root, ResolvedDropIn)); err == nil {
		t.Fatal("resolved config written without systemd-resolved")
	}
	if len(r.Skipped) != 2 {
		t.Fatalf("skipped: %v", r.Skipped)
	}
	if st := s.Check(); st.LLMNR != "unknown" || len(st.Warnings) == 0 {
		t.Fatalf("unknown resolver must be reported honestly: %+v", st)
	}
}

func TestProtocolsPerLinkOverride(t *testing.T) {
	out := "Global\n  Protocols: -LLMNR -mDNS\nLink 3 (wlp2s0)\n  Protocols: +DefaultRoute +LLMNR -mDNS\n"
	if l, m := protocols(out); l != "on" || m != "off" {
		t.Fatalf("got llmnr=%s mdns=%s", l, m)
	}
}
