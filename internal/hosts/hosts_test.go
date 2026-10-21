package hosts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const userHosts = "127.0.0.1 localhost\n::1 localhost\n192.168.1.20 nas.home   # my NAS\n"

func setup(t *testing.T, hostsContent, nss string) string {
	t.Helper()
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/hosts"), []byte(hostsContent), 0o644)
	if nss != "" {
		os.WriteFile(filepath.Join(root, "etc/nsswitch.conf"), []byte(nss), 0o644)
	}
	return root
}

func readHosts(t *testing.T, root string) string {
	b, err := os.ReadFile(filepath.Join(root, "etc/hosts"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustList(t *testing.T) List {
	l, err := LoadList("")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestApplyPreservesUserEntriesAndOffRemovesOnlyTheBlock(t *testing.T) {
	root, state := setup(t, userHosts, "hosts: files mdns4_minimal dns\n"), t.TempDir()
	l := mustList(t)
	n, err := Apply(root, state, l)
	if err != nil || n != len(l.Domains()) || n == 0 {
		t.Fatalf("Apply = %d, %v", n, err)
	}
	got := readHosts(t, root)
	if !strings.HasPrefix(got, strings.TrimRight(userHosts, "\n")) || !strings.Contains(got, "0.0.0.0 metrics.ubuntu.com") {
		t.Fatalf("unexpected hosts file:\n%s", got)
	}
	st := Check(root, l)
	if !st.Active || st.Blocked != n || len(st.Missing) != 0 || !st.FilesInNSS {
		t.Fatalf("status %+v", st)
	}

	// The user adds an entry after DevShield; Off must keep it.
	os.WriteFile(filepath.Join(root, "etc/hosts"), []byte(got+"10.0.0.9 printer.home\n"), 0o644)
	removed, err := Off(root)
	if err != nil || !removed {
		t.Fatalf("Off = %v %v", removed, err)
	}
	after := readHosts(t, root)
	if strings.Contains(after, "DevShield") || strings.Contains(after, "metrics.ubuntu.com") {
		t.Fatalf("block not removed:\n%s", after)
	}
	if !strings.Contains(after, "nas.home") || !strings.Contains(after, "printer.home") {
		t.Fatalf("user entries lost:\n%s", after)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "hosts.original")); string(b) != userHosts {
		t.Fatal("original not backed up exactly")
	}
}

// The Windows script replaced the block with only NEW domains on re-apply;
// here the block is always complete.
func TestReapplyKeepsTheWholeList(t *testing.T) {
	root, state := setup(t, userHosts, ""), t.TempDir()
	l := mustList(t)
	Apply(root, state, l)
	l.Groups = append(l.Groups, Group{Name: "extra", Domains: []string{"telemetry.example.org"}})
	n, err := Apply(root, state, l)
	if err != nil {
		t.Fatal(err)
	}
	st := Check(root, l)
	if st.Blocked != n || len(st.Missing) != 0 || !strings.Contains(readHosts(t, root), "metrics.ubuntu.com") {
		t.Fatalf("re-apply lost domains: %+v", st)
	}
	if strings.Count(readHosts(t, root), beginMark) != 1 {
		t.Fatal("managed block duplicated")
	}
}

func TestNeverBlockAndInjectionAreRefused(t *testing.T) {
	l := List{
		Groups: []Group{{Domains: []string{
			"security.ubuntu.com", "cdn.api.github.com", "evil.example.com\n1.2.3.4 bank.com",
			"good.example.com", "GOOD.example.com", "localhost",
		}}},
		NeverBlock: []string{"security.ubuntu.com", "api.github.com"},
	}
	got := l.Domains()
	if len(got) != 1 || got[0] != "good.example.com" {
		t.Fatalf("Domains() = %v", got)
	}
}

func TestStatusIsHonest(t *testing.T) {
	root := setup(t, userHosts, "hosts: dns\n") // hosts file ignored
	st := Check(root, mustList(t))
	if st.Active || st.FilesInNSS {
		t.Fatalf("status %+v", st)
	}
	if !strings.Contains(strings.Join(st.Warnings, ";"), "no effect") {
		t.Fatalf("missing nsswitch warning: %v", st.Warnings)
	}
	// Someone removed a line from the block by hand → reported as missing.
	root2, state := setup(t, userHosts, ""), t.TempDir()
	l := mustList(t)
	Apply(root2, state, l)
	edited := strings.Replace(readHosts(t, root2), "0.0.0.0 popcon.ubuntu.com\n", "", 1)
	os.WriteFile(filepath.Join(root2, "etc/hosts"), []byte(edited), 0o644)
	if st := Check(root2, l); len(st.Missing) != 1 || st.Missing[0] != "popcon.ubuntu.com" {
		t.Fatalf("hand-removed domain not reported: %+v", st)
	}
}

func TestOffWithoutBlockIsANoOp(t *testing.T) {
	root := setup(t, userHosts, "")
	removed, err := Off(root)
	if err != nil || removed || readHosts(t, root) != userHosts {
		t.Fatalf("Off on clean file: removed=%v err=%v", removed, err)
	}
}

// Found in review: with the end marker missing, every line after the start
// marker counted as managed and was deleted.
func TestMissingEndMarkerRefusesToEdit(t *testing.T) {
	content := userHosts + beginMark + "\n0.0.0.0 x.example\n10.0.0.9 printer.home\n"
	root := setup(t, content, "")
	if _, err := Apply(root, t.TempDir(), mustList(t)); err == nil {
		t.Fatal("applied to a file with an unterminated block")
	}
	if _, err := Off(root); err == nil {
		t.Fatal("removed an unterminated block")
	}
	if readHosts(t, root) != content {
		t.Fatal("file changed although DevShield refused")
	}
	if st := Check(root, mustList(t)); !strings.Contains(strings.Join(st.Warnings, " "), "no end marker") {
		t.Errorf("status hides the problem: %v", st.Warnings)
	}
}

// A line the user added inside DevShield's block is theirs: kept, not dropped.
func TestUserLineInsideBlockIsKept(t *testing.T) {
	root, state := setup(t, userHosts, ""), t.TempDir()
	if _, err := Apply(root, state, mustList(t)); err != nil {
		t.Fatal(err)
	}
	withUser := strings.Replace(readHosts(t, root), endMark, "10.0.0.9 printer.home\n"+endMark, 1)
	os.WriteFile(filepath.Join(root, "etc/hosts"), []byte(withUser), 0o644)
	if _, err := Apply(root, state, mustList(t)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readHosts(t, root), "10.0.0.9 printer.home") {
		t.Fatal("re-apply dropped the user's line")
	}
	Off(root)
	if !strings.Contains(readHosts(t, root), "10.0.0.9 printer.home") {
		t.Fatal("off dropped the user's line")
	}
}

func TestUnreadableOverrideIsAnError(t *testing.T) {
	dir := t.TempDir() // a directory: exists but cannot be read as a file
	if _, err := LoadList(dir); err == nil {
		t.Fatal("unreadable override silently replaced by the built-in list")
	}
	if _, err := LoadList(filepath.Join(dir, "absent.json")); err != nil {
		t.Fatalf("absent override must fall back to the built-in list: %v", err)
	}
}
