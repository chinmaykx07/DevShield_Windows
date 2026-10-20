// Package hosts manages DevShield's telemetry sinkhole in /etc/hosts.
//
// Only a clearly marked block is ever touched; the user's own entries are
// preserved byte for byte. Applying always rewrites the WHOLE managed
// block from the current list (the Windows script's bug of replacing the
// block with only newly added domains cannot happen here). Off() removes
// just the block, so edits the user made in the meantime are kept.
//
// Status is honest: it re-reads the file rather than trusting the write,
// warns when name resolution doesn't consult /etc/hosts at all, and never
// counts a DNS failure as "blocked".
//
// Root is a filesystem prefix ("" = real system) for testing.
package hosts

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

//go:embed blocklist.json
var defaultList []byte

const (
	beginMark = "# >>> DevShield telemetry sinkhole — managed block, do not edit >>>"
	endMark   = "# <<< DevShield telemetry sinkhole <<<"
	sinkIP    = "0.0.0.0"
)

// List is the parsed blocklist.
type List struct {
	Version    string   `json:"version"`
	Groups     []Group  `json:"groups"`
	NeverBlock []string `json:"never_block"`
}

// Group is a documented set of domains.
type Group struct {
	Name    string   `json:"name"`
	Why     string   `json:"why"`
	Domains []string `json:"domains"`
}

// LoadList uses overridePath if it exists (root-owned in production), else
// the built-in list. A broken override is an error, not a silent fallback:
// a security tool must not quietly block something different.
func LoadList(overridePath string) (List, error) {
	data := defaultList
	if overridePath != "" {
		if b, err := os.ReadFile(overridePath); err == nil {
			data = b
		}
	}
	var l List
	if err := json.Unmarshal(data, &l); err != nil {
		return l, fmt.Errorf("blocklist: %w", err)
	}
	return l, nil
}

// Domains returns the de-duplicated, sorted domains to block, excluding
// anything on the never-block list (or a subdomain of it).
func (l List) Domains() []string {
	never := map[string]bool{}
	for _, d := range l.NeverBlock {
		never[strings.ToLower(d)] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range l.Groups {
		for _, d := range g.Domains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" || seen[d] || protected(d, never) || !validDomain(d) {
				continue
			}
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

func protected(d string, never map[string]bool) bool {
	for n := range never {
		if d == n || strings.HasSuffix(d, "."+n) {
			return true
		}
	}
	return false
}

// validDomain rejects anything that could inject extra hosts-file syntax.
func validDomain(d string) bool {
	if len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func hostsPath(root string) string { return filepath.Join(root, "/etc/hosts") }

// splitManaged returns the file without the managed block, and the domains
// currently inside the block.
func splitManaged(content string) (outside string, managed []string, present bool) {
	var keep []string
	in := false
	for _, line := range strings.Split(content, "\n") {
		switch {
		case strings.TrimSpace(line) == beginMark:
			in, present = true, true
		case strings.TrimSpace(line) == endMark:
			in = false
		case in:
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == sinkIP {
				managed = append(managed, f[1])
			}
		default:
			keep = append(keep, line)
		}
	}
	return strings.TrimRight(strings.Join(keep, "\n"), "\n"), managed, present
}

// Apply installs (or refreshes) the managed block. stateDir (root-only)
// receives a one-time copy of the original file before the first change.
func Apply(root, stateDir string, l List) (int, error) {
	path := hostsPath(root)
	orig, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if err := backupOnce(stateDir, orig); err != nil {
		return 0, fmt.Errorf("could not back up %s, nothing changed: %w", path, err)
	}
	outside, _, _ := splitManaged(string(orig))
	domains := l.Domains()

	var b strings.Builder
	b.WriteString(outside)
	b.WriteString("\n\n" + beginMark + "\n")
	fmt.Fprintf(&b, "# list %s, applied %s — remove with: sudo devshield sinkhole off\n", l.Version, time.Now().UTC().Format(time.RFC3339))
	for _, d := range domains {
		fmt.Fprintf(&b, "%s %s\n", sinkIP, d)
	}
	b.WriteString(endMark + "\n")

	if err := writeInPlace(path, b.String()); err != nil {
		return 0, err
	}
	return len(domains), nil
}

// Off removes the managed block and nothing else.
func Off(root string) (bool, error) {
	path := hostsPath(root)
	orig, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	outside, _, present := splitManaged(string(orig))
	if !present {
		return false, nil
	}
	return true, writeInPlace(path, outside+"\n")
}

// Status is what the sinkhole looks like right now, read from disk.
type Status struct {
	Active      bool     `json:"active"`
	Blocked     int      `json:"blocked"`           // domains in the managed block
	Expected    int      `json:"expected"`          // domains the current list wants
	Missing     []string `json:"missing,omitempty"` // in the list, not in the file
	FilesInNSS  bool     `json:"files_in_nss"`      // /etc/nsswitch.conf consults /etc/hosts
	Warnings    []string `json:"warnings,omitempty"`
	ListVersion string   `json:"list_version"`
}

// Check reads the real file and resolver configuration.
func Check(root string, l List) Status {
	st := Status{ListVersion: l.Version, FilesInNSS: nssUsesFiles(root)}
	data, err := os.ReadFile(hostsPath(root))
	if err != nil {
		st.Warnings = append(st.Warnings, "cannot read /etc/hosts: "+err.Error())
		return st
	}
	_, managed, present := splitManaged(string(data))
	st.Active, st.Blocked = present, len(managed)
	want := l.Domains()
	st.Expected = len(want)
	have := map[string]bool{}
	for _, d := range managed {
		have[d] = true
	}
	for _, d := range want {
		if present && !have[d] {
			st.Missing = append(st.Missing, d)
		}
	}
	if !st.FilesInNSS {
		st.Warnings = append(st.Warnings, "/etc/nsswitch.conf does not list 'files' for hosts — the sinkhole has no effect")
	}
	st.Warnings = append(st.Warnings, "programs using DNS-over-HTTPS (some browsers) bypass /etc/hosts")
	return st
}

func nssUsesFiles(root string) bool {
	data, err := os.ReadFile(filepath.Join(root, "/etc/nsswitch.conf"))
	if err != nil {
		return true // glibc default when the file is absent is "files dns"
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "hosts:" {
			for _, src := range f[1:] {
				if src == "files" {
					return true
				}
			}
			return false
		}
	}
	return true
}

func backupOnce(stateDir string, orig []byte) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(stateDir, "hosts.original")
	if _, err := os.Stat(path); err == nil {
		return nil // keep the pre-DevShield original forever
	}
	return os.WriteFile(path, orig, 0o600)
}

// writeInPlace rewrites path keeping its inode, owner and mode. (Renaming a
// temp file over /etc/hosts fails when it is a bind mount, as in
// containers.) The content is fully prepared first, so the window with a
// partial file is a single write.
func writeInPlace(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return errors.New("permission denied writing /etc/hosts (needs root)")
		}
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
