// Package lanprivacy stops the machine announcing itself on local networks
// (Linux counterpart of the Windows LLMNR/NetBIOS/MAC hardening).
//
// What leaks on a LAN, and what DevShield does about it:
//   - LLMNR and mDNS answer "who is <name>?" broadcasts, revealing the
//     hostname and inviting spoofing (LLMNR poisoning is a classic way to
//     steal credentials). → systemd-resolved and NetworkManager are told
//     not to use them.
//   - A fixed Wi-Fi MAC address lets every network (and every Wi-Fi
//     scanner in a shop or station) track the device. → NetworkManager uses
//     a random address per network and while scanning.
//   - A stable IPv6 address built from the MAC tracks the device across the
//     internet. → IPv6 privacy (temporary) addresses are preferred.
//
// DevShield only creates and deletes its OWN drop-in files; it never edits
// a system or user configuration file, so "off" restores exactly what was
// there. Status reports the effective state read back from the system,
// not what was written.
//
// Root is a filesystem prefix ("" = real system) for testing.
package lanprivacy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Drop-in files DevShield owns.
const (
	ResolvedDropIn = "/etc/systemd/resolved.conf.d/90-devshield-privacy.conf"
	NMDropIn       = "/etc/NetworkManager/conf.d/90-devshield-privacy.conf"
	SysctlDropIn   = "/etc/sysctl.d/90-devshield-privacy.conf"
)

const header = "# Written by DevShield (devshield lan-privacy on). Removed by: sudo devshield lan-privacy off\n"

const resolvedConf = header + `[Resolve]
LLMNR=no
MulticastDNS=no
`

// stable = a random MAC per Wi-Fi network that stays the same for that
// network (captive portals and DHCP leases keep working), unlike the
// hardware address which is the same everywhere.
const nmConf = header + `[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=stable
connection.llmnr=0
connection.mdns=0
`

var sysctls = map[string]string{
	"net/ipv6/conf/all/use_tempaddr":     "2",
	"net/ipv6/conf/default/use_tempaddr": "2",
}

// originalTag marks the live values that were in force before DevShield
// changed them, kept inside its own drop-in so "off" can put them back.
const originalTag = "# devshield-original "

func sysctlConf(originals map[string]string) string {
	var b strings.Builder
	b.WriteString(header)
	keys := make([]string, 0, len(sysctls))
	for k := range sysctls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v, ok := originals[k]; ok {
			fmt.Fprintf(&b, "%s%s=%s\n", originalTag, k, v)
		}
	}
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %s\n", strings.ReplaceAll(k, "/", "."), sysctls[k])
	}
	return b.String()
}

// savedOriginals reads the originals recorded in an existing drop-in.
func (s System) savedOriginals() map[string]string {
	data, err := os.ReadFile(s.path(SysctlDropIn))
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, originalTag); ok {
			if k, v, ok := strings.Cut(rest, "="); ok && sysctls[k] != "" {
				out[k] = v
			}
		}
	}
	return out
}

// Runner runs a system command; tests replace it.
type Runner func(name string, args ...string) (string, error)

// ExecRunner runs real commands.
func ExecRunner(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// System is the machine being changed.
type System struct {
	Root string // "" = real system
	Run  Runner
}

func (s System) path(p string) string { return filepath.Join(s.Root, p) }

func (s System) exists(p string) bool {
	_, err := os.Stat(s.path(p))
	return err == nil
}

// hasResolved / hasNM: only configure what is installed.
func (s System) hasResolved() bool {
	for _, p := range []string{"/usr/lib/systemd/systemd-resolved", "/lib/systemd/systemd-resolved"} {
		if s.exists(p) {
			return true
		}
	}
	return false
}

func (s System) hasNM() bool { return s.exists("/etc/NetworkManager") }

// Result describes what Apply or Off did.
type Result struct {
	Changed []string `json:"changed,omitempty"`
	Skipped []string `json:"skipped,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// Apply writes DevShield's drop-ins for the components that are installed
// and asks them to reload.
func (s System) Apply() (Result, error) {
	var r Result
	write := func(p, content string) error {
		if err := os.MkdirAll(filepath.Dir(s.path(p)), 0o755); err != nil {
			return err
		}
		return os.WriteFile(s.path(p), []byte(content), 0o644)
	}

	if s.hasResolved() {
		if err := write(ResolvedDropIn, resolvedConf); err != nil {
			return r, fmt.Errorf("%s: %w", ResolvedDropIn, err)
		}
		r.Changed = append(r.Changed, "systemd-resolved configured: LLMNR and mDNS off")
		if out, err := s.Run("systemctl", "try-reload-or-restart", "systemd-resolved"); err != nil {
			r.Notes = append(r.Notes, "systemd-resolved did not reload ("+why(out, err)+"); takes effect after reboot")
		}
	} else {
		r.Skipped = append(r.Skipped, "systemd-resolved not installed (LLMNR/mDNS then depend on your resolver; see warnings)")
	}

	if s.hasNM() {
		if err := write(NMDropIn, nmConf); err != nil {
			return r, fmt.Errorf("%s: %w", NMDropIn, err)
		}
		r.Changed = append(r.Changed, "NetworkManager configured: random MAC per Wi-Fi network and while scanning; LLMNR/mDNS off per connection")
		if out, err := s.Run("nmcli", "general", "reload", "conf"); err != nil {
			r.Notes = append(r.Notes, "NetworkManager did not reload ("+why(out, err)+"); takes effect after reboot")
		}
		r.Notes = append(r.Notes, "the new Wi-Fi MAC is used from the next connection (reconnect Wi-Fi to apply now)")
	} else {
		r.Skipped = append(r.Skipped, "NetworkManager not installed (MAC randomisation must be set in your network tool)")
	}

	// Record the live values before the first change; a repeated "on"
	// keeps the first record (the live values are DevShield's by then).
	originals := s.savedOriginals()
	if originals == nil {
		originals = map[string]string{}
		for k := range sysctls {
			if v, err := os.ReadFile(s.path("/proc/sys/" + k)); err == nil {
				originals[k] = strings.TrimSpace(string(v))
			}
		}
	}
	if err := write(SysctlDropIn, sysctlConf(originals)); err != nil {
		return r, fmt.Errorf("%s: %w", SysctlDropIn, err)
	}
	applied := 0
	for k, v := range sysctls {
		if err := os.WriteFile(s.path("/proc/sys/"+k), []byte(v), 0); err == nil {
			applied++
		}
	}
	if applied == len(sysctls) {
		r.Changed = append(r.Changed, "IPv6 privacy addresses preferred")
	} else {
		r.Notes = append(r.Notes, "IPv6 privacy addresses: saved for next boot (IPv6 is off or not changeable right now)")
	}
	return r, nil
}

// why is the most useful one-line reason a command failed.
func why(out string, err error) string {
	if line, _, _ := strings.Cut(strings.TrimSpace(out), "\n"); line != "" {
		return line
	}
	return err.Error()
}

// Off removes DevShield's drop-ins and reloads, restoring the system's own
// configuration, and puts the live IPv6 settings back to their recorded
// original values.
func (s System) Off() (Result, error) {
	var r Result
	restored := 0
	originals := s.savedOriginals()
	for k, v := range originals {
		if err := os.WriteFile(s.path("/proc/sys/"+k), []byte(v), 0); err == nil {
			restored++
		}
	}
	if len(originals) > 0 && restored < len(originals) {
		r.Notes = append(r.Notes, "IPv6 privacy setting could not be reset live; the original returns at reboot")
	}
	for _, f := range []struct{ path, what, cmd string }{
		{ResolvedDropIn, "systemd-resolved settings removed", "resolved"},
		{NMDropIn, "NetworkManager settings removed", "nm"},
		{SysctlDropIn, "IPv6 privacy setting removed and original value restored", ""},
	} {
		err := os.Remove(s.path(f.path))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return r, fmt.Errorf("%s: %w", f.path, err)
		}
		r.Changed = append(r.Changed, f.what)
		switch f.cmd {
		case "resolved":
			s.Run("systemctl", "try-reload-or-restart", "systemd-resolved")
		case "nm":
			s.Run("nmcli", "general", "reload", "conf")
		}
	}
	return r, nil
}

// Iface is one Wi-Fi interface.
type Iface struct {
	Name     string `json:"name"`
	MAC      string `json:"mac"`
	Hardware bool   `json:"hardware_address"` // the burned-in address is in use
}

// Status is the effective LAN-privacy state.
type Status struct {
	Applied     bool     `json:"applied"` // DevShield's drop-ins are present
	LLMNR       string   `json:"llmnr"`   // on | off | unknown
	MDNS        string   `json:"mdns"`
	IPv6Privacy string   `json:"ipv6_privacy"` // preferred | on | off | n/a
	WiFi        []Iface  `json:"wifi,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

// Check reads the effective state.
func (s System) Check() Status {
	st := Status{LLMNR: "unknown", MDNS: "unknown", IPv6Privacy: "n/a"}
	st.Applied = s.exists(ResolvedDropIn) || s.exists(NMDropIn) || s.exists(SysctlDropIn)

	if out, err := s.Run("resolvectl", "status"); err == nil {
		st.LLMNR, st.MDNS = protocols(out)
	} else if !s.hasResolved() {
		st.Warnings = append(st.Warnings, "not using systemd-resolved: LLMNR/mDNS state unknown")
	}

	if v, err := os.ReadFile(s.path("/proc/sys/net/ipv6/conf/all/use_tempaddr")); err == nil {
		st.IPv6Privacy = map[string]string{"0": "off", "1": "on", "2": "preferred"}[strings.TrimSpace(string(v))]
	}

	ents, _ := os.ReadDir(s.path("/sys/class/net"))
	for _, e := range ents {
		dir := "/sys/class/net/" + e.Name()
		if !s.exists(dir+"/wireless") && !s.exists(dir+"/phy80211") {
			continue
		}
		mac, _ := os.ReadFile(s.path(dir + "/address"))
		typ, _ := os.ReadFile(s.path(dir + "/addr_assign_type"))
		// 0 = permanent (burned-in); 1 random, 3 set by software.
		st.WiFi = append(st.WiFi, Iface{Name: e.Name(), MAC: strings.TrimSpace(string(mac)), Hardware: strings.TrimSpace(string(typ)) == "0"})
	}

	for name, warn := range map[string]string{
		"avahi-daemon": "avahi-daemon is running and announces this machine via mDNS (disable: sudo systemctl disable --now avahi-daemon.socket avahi-daemon; network printer discovery stops)",
		"nmbd":         "Samba's nmbd is running and answers NetBIOS name queries (disable it if you don't share files: sudo systemctl disable --now nmbd)",
	} {
		if running(s.path("/proc"), name) {
			st.Warnings = append(st.Warnings, warn)
		}
	}
	return st
}

// protocols reads LLMNR and mDNS from "resolvectl status": its Global
// section has e.g. "Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported"
// (+ = on). Per-link lines can turn them on for one interface, so any "+"
// anywhere counts as on.
func protocols(out string) (llmnr, mdns string) {
	llmnr, mdns = "unknown", "unknown"
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "Protocols:") {
			continue
		}
		for _, f := range strings.Fields(line) {
			switch {
			case f == "+LLMNR":
				llmnr = "on"
			case f == "-LLMNR" && llmnr != "on":
				llmnr = "off"
			case strings.HasPrefix(f, "+mDNS"):
				mdns = "on"
			case f == "-mDNS" && mdns != "on":
				mdns = "off"
			}
		}
	}
	return llmnr, mdns
}

// running reports whether a process with this exact name exists.
func running(procRoot, name string) bool {
	ents, _ := os.ReadDir(procRoot)
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if comm, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm")); err == nil && strings.TrimSpace(string(comm)) == name {
			return true
		}
	}
	return false
}
