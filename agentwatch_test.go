package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	_ "modernc.org/sqlite"
)

const testLLMIP = "160.79.104.10"

var testLLMIPs = map[string]string{testLLMIP: "api.anthropic.com"}

func mustCatalog(t *testing.T) *AgentCatalog {
	t.Helper()
	c, err := ParseAgentCatalog(defaultAgentCatalog)
	if err != nil {
		t.Fatalf("embedded catalog does not parse: %v", err)
	}
	return c
}

// classifyOne runs Classify on a snapshot and returns the detection for pid.
func classifyOne(t *testing.T, s Snapshot, pid int32) (Detection, bool) {
	t.Helper()
	for _, d := range mustCatalog(t).Classify(s, testLLMIPs) {
		if d.PID == pid {
			return d, true
		}
	}
	return Detection{}, false
}

func hasRisk(d Detection, fragment string) bool {
	for _, r := range d.Risks {
		if strings.Contains(r, fragment) {
			return true
		}
	}
	return false
}

// ── Rogue detection: behaviour, not names ────────────────────

// The core requirement: an agent that is in NO list, under an innocent
// name, is still caught by what it does — and judged a rogue suspect.
func TestRenamedUndocumentedAgentIsCaughtByBehaviour(t *testing.T) {
	s := Snapshot{
		Procs: []ProcInfo{
			{PID: 1, Name: "explorer.exe"},
			{PID: 100, PPID: 1, Name: "svc-update.exe",
				Exe: `C:\Users\dev\AppData\Local\Temp\x7\svc-update.exe`},
		},
		RemoteEndpoints: map[int32][]string{100: {testLLMIP + ":443"}},
		Behavior: map[int32]*ProcBehavior{100: {
			EnvHits:    []string{"OPENROUTER_API_KEY"},
			ToolSpawns: []string{"cmd.exe", "whoami.exe", "cmd.exe", "schtasks.exe"},
		}},
	}
	d, ok := classifyOne(t, s, 100)
	if !ok {
		t.Fatal("renamed agent with no catalog entry was not detected")
	}
	if d.Known {
		t.Errorf("should not be attributed to any catalog agent: %+v", d)
	}
	for _, want := range []string{"undocumented", "unusual location", "recon/persistence"} {
		if !hasRisk(d, want) {
			t.Errorf("missing rogue indicator %q in %v", want, d.Risks)
		}
	}
	if v, _ := AgentVerdict(AgentUnsanctioned, d.Risks); v != VerdictRogue {
		t.Errorf("verdict = %s, want rogue", v)
	}
}

// An undocumented agent with nothing else suspicious is still a rogue
// suspect until someone sanctions it — "never documented" is the point.
func TestUndocumentedAgentIsRogueUntilSanctioned(t *testing.T) {
	s := Snapshot{
		Procs:           []ProcInfo{{PID: 10, Name: "python.exe", Cmdline: `python bot.py`}},
		RemoteEndpoints: map[int32][]string{10: {testLLMIP + ":443"}},
		Behavior:        map[int32]*ProcBehavior{10: {ToolSpawns: []string{"git.exe"}, EnvHits: []string{"OPENAI_API_KEY"}}},
	}
	d, ok := classifyOne(t, s, 10)
	if !ok {
		t.Fatal("not detected")
	}
	if v, _ := AgentVerdict(AgentUnsanctioned, d.Risks); v != VerdictRogue {
		t.Errorf("unsanctioned undocumented agent: verdict %s, want rogue", v)
	}
	if v, risks := AgentVerdict(AgentSanctioned, d.Risks); v != VerdictSanctioned || len(risks) != 0 {
		t.Errorf("after sanction: verdict %s risks %v, want sanctioned", v, risks)
	}
}

// A bad actor naming their binary claude.exe gets the label, but not a pass.
func TestMasqueradingAsKnownAgentIsStillFlagged(t *testing.T) {
	s := Snapshot{Procs: []ProcInfo{{PID: 5, Name: "claude.exe",
		Exe: `C:\Users\dev\Downloads\claude.exe`}}}
	d, ok := classifyOne(t, s, 5)
	if !ok || d.Name != "Claude Code" {
		t.Fatalf("expected identity label Claude Code, got %+v", d)
	}
	if !hasRisk(d, "unusual location") {
		t.Fatalf("masquerading binary in Downloads not flagged: %v", d.Risks)
	}
	if v, _ := AgentVerdict(AgentSanctioned, d.Risks); v != VerdictRisky {
		t.Errorf("even a sanctioned fingerprint must show risky, got %s", v)
	}
}

// A legitimate, sanctioned agent that starts doing recon is reported.
func TestSanctionedAgentTurningBadBecomesRisky(t *testing.T) {
	s := Snapshot{
		Procs: []ProcInfo{
			{PID: 1, Name: "WindowsTerminal.exe"},
			{PID: 7, PPID: 1, Name: "claude.exe", Exe: `C:\Users\dev\.local\bin\claude.exe`,
				Cmdline: `claude --dangerously-skip-permissions`},
		},
		Behavior: map[int32]*ProcBehavior{7: {ToolSpawns: []string{"pwsh.exe", "net.exe", "cmdkey.exe"}}},
	}
	d, _ := classifyOne(t, s, 7)
	if !hasRisk(d, "approvals disabled") || !hasRisk(d, "recon/persistence") {
		t.Fatalf("risks not raised: %v", d.Risks)
	}
	if v, _ := AgentVerdict(AgentSanctioned, d.Risks); v != VerdictRisky {
		t.Errorf("verdict %s, want risky", v)
	}
}

func TestSanctionedAgentDoingNormalWorkStaysQuiet(t *testing.T) {
	s := Snapshot{
		Procs: []ProcInfo{
			{PID: 1, Name: "WindowsTerminal.exe"},
			{PID: 7, PPID: 1, Name: "claude.exe", Exe: `C:\Users\dev\.local\bin\claude.exe`},
		},
		Behavior: map[int32]*ProcBehavior{7: {ToolSpawns: []string{"pwsh.exe", "git.exe", "rg.exe", "git.exe"}}},
	}
	d, _ := classifyOne(t, s, 7)
	if v, risks := AgentVerdict(AgentSanctioned, d.Risks); v != VerdictSanctioned {
		t.Errorf("verdict %s (risks %v), want sanctioned", v, risks)
	}
}

func TestAutostartAndDetachedAreRiskIndicators(t *testing.T) {
	exe := `C:\Users\dev\AppData\Roaming\helper\agent.exe`
	s := Snapshot{
		Procs: []ProcInfo{{PID: 9, PPID: 4444, Name: "agent.exe", Exe: exe}}, // parent 4444 gone
		Behavior: map[int32]*ProcBehavior{9: {
			EnvHits: []string{"ANTHROPIC_API_KEY"}, ToolSpawns: []string{"cmd.exe", "cmd.exe", "curl.exe"},
		}},
		Autostart: map[string]string{strings.ToLower(exe): `HKCU\...\Run "helper"`},
	}
	d, ok := classifyOne(t, s, 9)
	if !ok {
		t.Fatal("not detected")
	}
	if !hasRisk(d, "start automatically") || !hasRisk(d, "detached") {
		t.Errorf("missing autostart/detached risk: %v", d.Risks)
	}
}

func TestLocalModelUsersAndServersAreDetected(t *testing.T) {
	s := Snapshot{
		Procs: []ProcInfo{
			{PID: 30, Name: "mystery.exe"},
			{PID: 60, Name: "helper.exe"},
			{PID: 70, Name: "inference.exe"},
		},
		ListenPorts:     map[int32][]int{30: {11434}},
		RemoteEndpoints: map[int32][]string{60: {"127.0.0.1:11434"}},
		Behavior: map[int32]*ProcBehavior{
			60: {ToolSpawns: []string{"pwsh.exe"}},
			70: {Modules: []string{"kernel32.dll", "ggml-cuda.dll"}},
		},
	}
	for _, pid := range []int32{30, 60, 70} {
		if _, ok := classifyOne(t, s, pid); !ok {
			t.Errorf("pid %d should be detected as an AI agent", pid)
		}
	}
}

// False-positive guard: everyday developer activity must not be flagged.
func TestBenignActivityIsNotFlagged(t *testing.T) {
	s := Snapshot{
		Procs: []ProcInfo{
			{PID: 1, Name: "explorer.exe"},
			// A human typing in a shell runs lots of tools
			{PID: 2, PPID: 1, Name: "pwsh.exe"},
			// VS Code's terminal runs tools; no LLM signal on its own
			{PID: 3, PPID: 1, Name: "Code.exe", Exe: `C:\Program Files\Microsoft VS Code\Code.exe`},
			// A build script with one shell child
			{PID: 4, PPID: 2, Name: "python.exe", Cmdline: `python build.py`},
			// A chat app using ONNX Runtime for noise suppression
			{PID: 5, PPID: 1, Name: "ms-teams.exe"},
			// Browser talking to an LLM web app (out of scope)
			{PID: 6, PPID: 1, Name: "chrome.exe"},
			// A global key in the user's environment is inherited, so it
			// is filtered out before reaching Classify (see llmEnvHits)
			{PID: 7, PPID: 1, Name: "notepad.exe"},
		},
		RemoteEndpoints: map[int32][]string{6: {testLLMIP + ":443"}},
		Behavior: map[int32]*ProcBehavior{
			2: {ToolSpawns: []string{"git.exe", "git.exe", "whoami.exe", "rg.exe", "curl.exe"}},
			3: {ToolSpawns: []string{"pwsh.exe", "git.exe", "node.exe"}},
			4: {ToolSpawns: []string{"cmd.exe"}},
			5: {Modules: []string{"onnxruntime.dll"}},
		},
	}
	for _, d := range mustCatalog(t).Classify(s, testLLMIPs) {
		t.Errorf("false positive: %s (pid %d) score=%d reasons=%v", d.Name, d.PID, d.AgentScore, d.Reasons)
	}
}

// ── Catalog identity ─────────────────────────────────────────

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

func TestScriptRunAgentsAreTrackedSeparately(t *testing.T) {
	c := mustCatalog(t)
	snap := Snapshot{Procs: []ProcInfo{
		{PID: 1, Name: "node.exe", Exe: `C:\nodejs\node.exe`,
			Cmdline: `"C:\nodejs\node.exe" C:\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js C:\code`},
		{PID: 2, Name: "node.exe", Exe: `C:\nodejs\node.exe`,
			Cmdline: `"C:\nodejs\node.exe" C:\npm\node_modules\@modelcontextprotocol\server-github\dist\index.js`},
		{PID: 3, Name: "uvx.exe", Exe: `C:\uv\uvx.exe`, Cmdline: `uvx mcp-server-git --repository C:\code`},
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

func TestMergeKeepsRisksFromAnyProcess(t *testing.T) {
	dets := []Detection{
		{Name: "Cursor", Exe: `C:\cursor\Cursor.exe`, PID: 1},
		{Name: "Cursor", Exe: `C:\cursor\Cursor.exe`, PID: 2, Risks: []string{"launched recon/persistence/credential tools (whoami.exe)"}},
		{Name: "Ollama", Exe: `C:\ollama\ollama.exe`, PID: 3},
	}
	got := mergeDetections(dets)
	if len(got) != 2 || got[0].Processes != 2 || got[1].Processes != 1 {
		t.Fatalf("unexpected merge result: %+v", got)
	}
	if len(got[0].Risks) != 1 {
		t.Fatalf("a risk seen in one helper process must apply to the whole agent: %+v", got[0])
	}
}

// ── Behaviour trackers ───────────────────────────────────────

func TestSpawnTrackerCountsOnlyNewToolsWithinWindow(t *testing.T) {
	tr := newSpawnTracker(time.Minute)
	isTool := func(n string) bool { return n == "cmd.exe" || n == "git.exe" }
	isShell := func(n string) bool { return n == "cmd.exe" }
	t0 := time.Now()

	// Already running at start → not a spawn
	tr.observe([]fastProc{{PID: 10, PPID: 1, Name: "agent.exe"}, {PID: 11, PPID: 10, Name: "cmd.exe"}}, t0, isTool, isShell)
	if n := len(tr.recent(10)); n != 0 {
		t.Fatalf("pre-existing child counted as spawn: %d", n)
	}

	tr.observe([]fastProc{
		{PID: 10, PPID: 1, Name: "agent.exe"},
		{PID: 12, PPID: 10, Name: "git.exe"},
		{PID: 13, PPID: 10, Name: "notepad.exe"}, // not a tool
	}, t0.Add(2*time.Second), isTool, isShell)
	if got := tr.recent(10); len(got) != 1 || got[0] != "git.exe" {
		t.Fatalf("recent = %v, want [git.exe]", got)
	}

	tr.observe([]fastProc{{PID: 10, PPID: 1, Name: "agent.exe"}}, t0.Add(2*time.Minute), isTool, isShell)
	if n := len(tr.recent(10)); n != 0 {
		t.Fatalf("spawn older than window still counted: %d", n)
	}
}

// Agents run commands through a shell: agent → pwsh -c "whoami" → whoami.
// The tool must be credited to the agent, even if the shell already exited.
func TestSpawnTrackerAttributesToolsThroughShells(t *testing.T) {
	tr := newSpawnTracker(time.Minute)
	isTool := func(n string) bool { return n == "pwsh.exe" || n == "whoami.exe" }
	isShell := func(n string) bool { return n == "pwsh.exe" }
	t0 := time.Now()

	tr.observe([]fastProc{{PID: 10, PPID: 1, Name: "agent.exe"}}, t0, isTool, isShell)
	tr.observe([]fastProc{
		{PID: 10, PPID: 1, Name: "agent.exe"},
		{PID: 20, PPID: 10, Name: "pwsh.exe"},
	}, t0.Add(500*time.Millisecond), isTool, isShell)
	// The shell has exited by the time its child is observed
	tr.observe([]fastProc{
		{PID: 10, PPID: 1, Name: "agent.exe"},
		{PID: 21, PPID: 20, Name: "whoami.exe"},
	}, t0.Add(time.Second), isTool, isShell)

	got := tr.recent(10)
	if !containsString(got, "pwsh.exe") || !containsString(got, "whoami.exe") {
		t.Fatalf("agent should be credited with the shell and its tool, got %v", got)
	}
}

func TestLLMEnvHitsIgnoresInheritedGlobals(t *testing.T) {
	c := mustCatalog(t)
	baseline := envBaseline([]string{"OPENAI_API_KEY=sk-global", "PATH=x"})

	inherited := []string{"OPENAI_API_KEY=sk-global", "PATH=x"}
	if hits := llmEnvHits(inherited, baseline, c.LLMEnvVars); len(hits) != 0 {
		t.Errorf("inherited global key counted: %v", hits)
	}

	specific := []string{"OPENAI_API_KEY=sk-other", "LITELLM_PROXY=1", "ANTHROPIC_BASE_URL=http://10.0.0.5", "EMPTY_KEY="}
	hits := llmEnvHits(specific, baseline, c.LLMEnvVars)
	for _, want := range []string{"OPENAI_API_KEY", "LITELLM_PROXY", "ANTHROPIC_BASE_URL"} {
		if !containsString(hits, want) {
			t.Errorf("missing %s in %v", want, hits)
		}
	}
	for _, h := range hits {
		if strings.Contains(h, "sk-") || strings.Contains(h, "10.0.0.5") {
			t.Errorf("env value leaked into hits: %v", hits)
		}
	}
}

func TestExeFromCommand(t *testing.T) {
	cases := map[string]string{
		`"C:\Program Files\App\app.exe" --min`: `C:\Program Files\App\app.exe`,
		`C:\Tools\agent.exe -silent`:           `C:\Tools\agent.exe`,
		`C:\Tools\run.bat arg`:                 `C:\Tools\run.bat`,
	}
	for in, want := range cases {
		if got := exeFromCommand(in); got != want {
			t.Errorf("exeFromCommand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExePathsInShortcutBytes(t *testing.T) {
	// .lnk files store the target both as ANSI and UTF-16LE strings
	var data []byte
	data = append(data, 0x4c, 0x00, 0x00, 0x00, 0x01)
	data = append(data, []byte("junk C:\\Users\\dev\\AppData\\Local\\Temp\\agent.exe\x00more")...)
	for _, r := range utf16.Encode([]rune(`C:\Tools\other.exe`)) {
		data = append(data, byte(r), byte(r>>8))
	}
	got := exePathsInBytes(data)
	for _, want := range []string{`C:\Users\dev\AppData\Local\Temp\agent.exe`, `C:\Tools\other.exe`} {
		if !containsString(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
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

// ── Store + misc ─────────────────────────────────────────────

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
