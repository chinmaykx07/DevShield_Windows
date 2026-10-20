package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func mustCatalog(t *testing.T) *AgentCatalog {
	t.Helper()
	c, err := ParseAgentCatalog(defaultAgentCatalog)
	if err != nil {
		t.Fatalf("embedded catalog does not parse: %v", err)
	}
	return c
}

func TestCatalogMatch(t *testing.T) {
	c := mustCatalog(t)
	cases := []struct {
		proc ProcInfo
		want string // "" = no match
	}{
		{ProcInfo{Name: "claude.exe", Exe: `C:\Users\dev\.local\bin\claude.exe`}, "Claude Code"},
		{ProcInfo{Name: "claude.exe", Exe: `C:\Users\dev\AppData\Local\AnthropicClaude\app-1.0\claude.exe`}, "Claude Desktop"},
		{ProcInfo{Name: "node.exe", Exe: `C:\Program Files\nodejs\node.exe`,
			Cmdline: `"node" C:\Users\dev\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js`}, "Claude Code"},
		{ProcInfo{Name: "node.exe", Cmdline: `node C:\Users\dev\AppData\Roaming\npm\node_modules\@openai\codex\bin\codex.js`}, "Codex"},
		{ProcInfo{Name: "node.exe", Cmdline: `node /usr/lib/node_modules/@google/gemini-cli/dist/index.js`}, "Gemini CLI"},
		{ProcInfo{Name: "claude.exe", Exe: `C:\Users\dev\.vscode\extensions\anthropic.claude-code-2.0.1-win32-x64\resources\native-binary\claude.exe`,
			Cmdline: `C:\Users\dev\.vscode\extensions\anthropic.claude-code-2.0.1-win32-x64\resources\native-binary\claude.exe --output-format stream-json`}, "VS Code Claude Code Extension"},
		{ProcInfo{Name: "Cursor.exe", Exe: `C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe`}, "Cursor"},
		{ProcInfo{Name: "ollama.exe"}, "Ollama"},
		{ProcInfo{Name: "node.exe", Cmdline: `node C:\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js C:\code`}, "MCP server"},
		{ProcInfo{Name: "uvx.exe", Cmdline: `uvx mcp-server-git --repository C:\code`}, "MCP server"},
		{ProcInfo{Name: "Code.exe", Exe: `C:\Program Files\Microsoft VS Code\Code.exe`}, ""},
		{ProcInfo{Name: "node.exe", Cmdline: `node server.js`}, ""},
		{ProcInfo{Name: "notepad.exe"}, ""},
	}
	for _, tc := range cases {
		got := ""
		if sig := c.Match(tc.proc); sig != nil {
			got = sig.Name
		}
		if got != tc.want {
			t.Errorf("Match(%s %q) = %q, want %q", tc.proc.Name, tc.proc.Cmdline, got, tc.want)
		}
	}
}

func TestClassifyUnknownHeuristics(t *testing.T) {
	c := mustCatalog(t)
	llmIPs := map[string]string{"160.79.104.10": "api.anthropic.com"}

	snap := Snapshot{
		Procs: []ProcInfo{
			// LLM API connection + agent framework in cmdline → flagged (2+2)
			{PID: 10, Name: "python.exe", Cmdline: `python my_bot.py --use langgraph`},
			// Only spawns a shell → not enough (1)
			{PID: 20, Name: "python.exe", Cmdline: `python build.py`},
			{PID: 21, PPID: 20, Name: "cmd.exe"},
			// Unknown binary listening on Ollama's port → flagged (3)
			{PID: 30, Name: "mystery.exe"},
			// Browser talking to an LLM API is ignored (web chat is out of scope)
			{PID: 40, Name: "chrome.exe", Cmdline: `chrome.exe --type=renderer langchain`},
			// Known agent is reported as known, not scored
			{PID: 50, Name: "ollama.exe"},
			// Client of a local LLM + shell child → flagged (2+1)
			{PID: 60, Name: "helper.exe"},
			{PID: 61, PPID: 60, Name: "pwsh.exe"},
		},
		ListenPorts: map[int32][]int{30: {11434}},
		RemoteEndpoints: map[int32][]string{
			10: {"160.79.104.10:443"},
			40: {"160.79.104.10:443"},
			60: {"127.0.0.1:11434"},
		},
	}

	got := map[int32]Detection{}
	for _, d := range c.Classify(snap, llmIPs) {
		got[d.PID] = d
	}

	for _, pid := range []int32{10, 30, 60} {
		d, ok := got[pid]
		if !ok {
			t.Errorf("pid %d should be flagged as unknown AI process", pid)
			continue
		}
		if d.Known || d.Score < UnknownAgentThreshold || len(d.Reasons) == 0 {
			t.Errorf("pid %d: unexpected detection %+v", pid, d)
		}
	}
	for _, pid := range []int32{20, 21, 40} {
		if _, ok := got[pid]; ok {
			t.Errorf("pid %d should not be flagged", pid)
		}
	}
	if d, ok := got[50]; !ok || !d.Known || d.Name != "Ollama" {
		t.Errorf("ollama should be a known agent, got %+v (found=%v)", d, ok)
	}
}

func TestMergeDetections(t *testing.T) {
	dets := []Detection{
		{Name: "Cursor", Exe: `C:\cursor\Cursor.exe`, PID: 1},
		{Name: "Cursor", Exe: `C:\cursor\Cursor.exe`, PID: 2},
		{Name: "Ollama", Exe: `C:\ollama\ollama.exe`, PID: 3},
	}
	got := mergeDetections(dets)
	if len(got) != 2 || got[0].Processes != 2 || got[1].Processes != 1 {
		t.Fatalf("unexpected merge result: %+v", got)
	}
}

func TestSightingLifecycle(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ensureAgentSchema(db); err != nil {
		t.Fatal(err)
	}

	d := Detection{Name: "Claude Code", Vendor: "Anthropic", Exe: `C:\bin\claude.exe`, PID: 7}
	fp := AgentFingerprint(d)

	step := func(hash string, wantChange SightingChange, wantStatus string) {
		t.Helper()
		change, status, err := recordSighting(db, d, hash, nowISO())
		if err != nil {
			t.Fatal(err)
		}
		if change != wantChange || status != wantStatus {
			t.Fatalf("hash %q: got change=%d status=%s, want change=%d status=%s",
				hash, change, status, wantChange, wantStatus)
		}
	}

	step("aaa", SightingNew, AgentUnsanctioned)        // first sighting
	step("aaa", SightingSeenBefore, AgentUnsanctioned) // same binary
	if err := setAgentStatus(db, fp, AgentSanctioned); err != nil {
		t.Fatal(err)
	}
	step("aaa", SightingSeenBefore, AgentSanctioned)    // approval sticks
	step("", SightingSeenBefore, AgentSanctioned)       // unreadable file is not a change
	step("bbb", SightingHashChanged, AgentUnsanctioned) // replaced binary loses approval

	recs, err := listAgents(db)
	if err != nil || len(recs) != 1 || recs[0].SHA256 != "bbb" {
		t.Fatalf("listAgents = %+v, %v", recs, err)
	}
}

func TestRedactSecrets(t *testing.T) {
	in := `agent.exe --api-key=sk-abcdef1234567890 --token "ghp_ABCDEFGH12345678" TOKEN=hunter22 --model gpt`
	out := redactSecrets(in)
	for _, secret := range []string{"sk-abcdef1234567890", "ghp_ABCDEFGH12345678", "hunter22"} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q not redacted: %s", secret, out)
		}
	}
	if !strings.Contains(out, "--model gpt") {
		t.Errorf("non-secret text was damaged: %s", out)
	}
}

func TestBrokenCatalogRegexIsReported(t *testing.T) {
	_, err := ParseAgentCatalog([]byte(`{"agents":[{"name":"x","cmdline_patterns":["notepad++"]}]}`))
	if err == nil {
		t.Fatal("invalid regex should be reported")
	}
}

func TestScriptRunAgentsAreTrackedSeparately(t *testing.T) {
	c := mustCatalog(t)
	snap := Snapshot{Procs: []ProcInfo{
		{PID: 1, Name: "node.exe", Exe: `C:\nodejs\node.exe`,
			Cmdline: `"C:\nodejs\node.exe" C:\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js C:\code`},
		{PID: 2, Name: "node.exe", Exe: `C:\nodejs\node.exe`,
			Cmdline: `"C:\nodejs\node.exe" C:\npm\node_modules\@modelcontextprotocol\server-github\dist\index.js`},
		{PID: 3, Name: "uvx.exe", Exe: `C:\uv\uvx.exe`, Cmdline: `uvx --from x mcp-server-git --repository C:\code`},
	}}
	dets := c.Classify(snap, nil)
	if len(dets) != 3 {
		t.Fatalf("want 3 detections, got %d: %+v", len(dets), dets)
	}
	seen := map[string]bool{}
	for _, d := range dets {
		fp := AgentFingerprint(d)
		if seen[fp] {
			t.Fatalf("two different MCP servers share fingerprint %q — sanctioning one would sanction both", fp)
		}
		seen[fp] = true
	}
	if got := mergeDetections(dets); len(got) != 3 {
		t.Fatalf("distinct MCP servers were merged: %+v", got)
	}
}

func TestLaunchTarget(t *testing.T) {
	cases := []struct {
		p    ProcInfo
		want string
	}{
		{ProcInfo{Name: "node.exe", Cmdline: `"C:\Program Files\nodejs\node.exe" --no-warnings "C:\a b\cli.js" --x`}, `C:\a b\cli.js`},
		{ProcInfo{Name: "python.exe", Cmdline: `python -u -m aider --model x`}, "aider"},
		{ProcInfo{Name: "uvx.exe", Cmdline: `uvx mcp-server-git`}, "mcp-server-git"},
		{ProcInfo{Name: "Cursor.exe", Cmdline: `Cursor.exe --type=renderer`}, ""},
	}
	for _, tc := range cases {
		if got := launchTarget(tc.p); got != tc.want {
			t.Errorf("launchTarget(%q) = %q, want %q", tc.p.Cmdline, got, tc.want)
		}
	}
}
