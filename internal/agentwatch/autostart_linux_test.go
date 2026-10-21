//go:build linux

package agentwatch

import (
	"os"
	"path/filepath"
	"testing"
)

// Places an agent can register itself to start that the scan used to miss:
// a home outside /home, /etc/systemd/user, a service override, and cron
// (user crontab, /etc/crontab with its user field, /etc/cron.d).
func TestAutostartCoversCronAndAllHomes(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"etc/passwd": "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/srv/alice:/bin/sh\n",
		"srv/alice/.config/systemd/user/a.service":     "[Service]\nExecStart=/opt/agent-a/run\n",
		"etc/systemd/user/b.service":                   "[Service]\nExecStart=-/opt/agent-b/run --x\n",
		"etc/systemd/system/c.service.d/override.conf": "[Service]\nExecStart=\nExecStart=/opt/agent-c/run\n",
		"var/spool/cron/crontabs/alice":                "# m h dom mon dow command\nSHELL=/bin/sh\nMAILTO=\"ops team at example dot org\"\n@reboot /opt/agent-d/run\n*/5 * * * * /opt/agent-e/run -q\n",
		"etc/crontab":                                  "17 * * * * root /opt/agent-f/run\n",
		"etc/cron.d/g":                                 "@reboot alice /opt/agent-g/run\n",
	}
	for rel, data := range files {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(data), 0o644)
	}
	got := autostartEntriesIn(root)
	for _, exe := range []string{"/opt/agent-a/run", "/opt/agent-b/run", "/opt/agent-c/run", "/opt/agent-d/run", "/opt/agent-e/run", "/opt/agent-f/run", "/opt/agent-g/run"} {
		found := false
		for k := range got {
			if k == autostartKey(exe, exe) || len(k) >= len(exe) && k[:len(exe)] == exe {
				found = true
			}
		}
		if !found {
			t.Errorf("%s not found; got %v", exe, got)
		}
	}
	for k := range got {
		if !filepath.IsAbs(k) { // a variable line, or a user name taken as the command
			t.Errorf("parsed a non-command as one: %q", k)
		}
	}
}
