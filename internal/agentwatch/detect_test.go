package agentwatch

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

func TestMergeDoesNotRepeatReasonsWithDifferentCounts(t *testing.T) {
	dets := []Detection{
		{Name: "X", Exe: "/x", PID: 1, Reasons: []string{"ran 26 shells/tools recently (sh ×13)"}},
		{Name: "X", Exe: "/x", PID: 2, Reasons: []string{"ran 24 shells/tools recently (sh ×12)", "connected to LLM API (api.openai.com)"}},
	}
	got := mergeDetections(dets)
	if len(got) != 1 || len(got[0].Reasons) != 2 {
		t.Fatalf("reasons not de-duplicated by kind: %v", got[0].Reasons)
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

// A key only counts for the process that introduced it. Children inherit
// it, so a rogue cannot "launder" its key by spawning many children (the
// flaw a majority-based baseline had). Values are hashed, never kept.
func TestLLMEnvKeyCountsWhereIntroduced(t *testing.T) {
	c := mustCatalog(t)
	rogue := llmEnvValues([]string{"OPENAI_API_KEY=sk-rogue", "LITELLM_PROXY=1", "EMPTY_KEY=", "PATH=/bin"}, c.LLMEnvVars)
	for name, h := range rogue {
		if strings.Contains(h, "sk-") || len(h) != 16 {
			t.Fatalf("value not hashed for %s: %q", name, h)
		}
	}
	if _, ok := rogue["EMPTY_KEY"]; ok {
		t.Fatal("non-LLM variable captured")
	}

	launcher := map[string]string{} // e.g. runuser, cron, systemd: no key
	hits := envHitsIntroduced(rogue, launcher, false, nil)
	if !containsString(hits, "OPENAI_API_KEY") || !containsString(hits, "LITELLM_PROXY") {
		t.Fatalf("key introduced by the rogue not flagged: %v", hits)
	}
	// Its children (any number of them) inherit the same values → not flagged,
	// and that does not affect the rogue's own result above.
	if h := envHitsIntroduced(rogue, rogue, false, nil); len(h) != 0 {
		t.Fatalf("inherited key flagged on child: %v", h)
	}
	// A key the parent has with a DIFFERENT value was re-introduced → flagged.
	other := llmEnvValues([]string{"OPENAI_API_KEY=sk-different"}, c.LLMEnvVars)
	if h := envHitsIntroduced(other, rogue, false, nil); len(h) != 1 {
		t.Fatalf("changed key not flagged: %v", h)
	}
	// Introduced under a human shell (export / KEY=… cmd) → not a signal.
	if h := envHitsIntroduced(rogue, launcher, true, nil); len(h) != 0 {
		t.Fatalf("key set from a shell should not count: %v", h)
	}
	// Same as DevShield's own environment → ignored (tray mode).
	if h := envHitsIntroduced(rogue, launcher, false, rogue); len(h) != 0 {
		t.Fatalf("own-environment key flagged: %v", h)
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
		if got, _ := launchTarget(tc.p); got != tc.want {
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
		change, status, err := recordSighting(db, d, hash, time.Now().UTC().Format(time.RFC3339))
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
	if n, err := setAgentStatus(db, fp, AgentSanctioned); err != nil || n != 1 {
		t.Fatalf("setAgentStatus: n=%d err=%v", n, err)
	}
	step("aaa", SightingSeenBefore, AgentSanctioned)    // approval sticks
	step("", SightingSeenBefore, AgentSanctioned)       // unreadable file is not a change
	step("bbb", SightingHashChanged, AgentUnsanctioned) // replaced binary loses approval

	recs, err := listAgents(db)
	if err != nil || len(recs) != 1 || recs[0].SHA256 != "bbb" {
		t.Fatalf("listAgents = %+v, %v", recs, err)
	}

	// An agent that is not running can still be resolved from the database.
	w := &Watcher{cfg: Config{DB: db}}
	gotFP, _, short, err := w.ResolveKnown(shortID(fp)[:6])
	if err != nil || gotFP != fp || short != shortID(fp) {
		t.Fatalf("ResolveKnown = %q %q %v", gotFP, short, err)
	}
	if _, _, _, err := w.ResolveKnown("ffffffff"); err == nil {
		t.Fatal("unknown id resolved")
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

// A shell whose inline command merely mentions an agent is not that agent
// (found live: a test harness's own shell was identified as the agent).
func TestShellInlineCommandIsNotTheAgent(t *testing.T) {
	cat, err := ParseAgentCatalog([]byte(`{"agents":[{"name":"Test","cmdline_patterns":["fake-rogue-agent"]}],
		"shell_names":["bash","cmd.exe","pwsh"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, cmdline string
		want          bool
	}{
		{"bash", `bash -c "python3 agent.py fake-rogue-agent"`, false},
		{"bash", `bash -lc "fake-rogue-agent --run"`, false},
		{"cmd.exe", `cmd.exe /c fake-rogue-agent.exe`, false},
		{"pwsh", `pwsh -NoProfile -Command "fake-rogue-agent"`, false},
		{"bash", `bash /opt/fake-rogue-agent/run.sh`, true},         // a script file is what the shell IS
		{"python3", `python3 agent.py fake-rogue-agent`, false},     // an argument, not what runs
		{"python3", `python3 /opt/fake-rogue-agent/agent.py`, true}, // the script it runs
	} {
		got := cat.Match(ProcInfo{Name: tc.name, Cmdline: tc.cmdline}) != nil
		if got != tc.want {
			t.Errorf("%s %q matched=%v, want %v", tc.name, tc.cmdline, got, tc.want)
		}
	}
}

// ── Regressions from the 2026-10-21 audit: each case was reproduced on the
// previous code before being fixed.

func auditSnap(p ProcInfo, b *ProcBehavior, listen []int, remote []string, auto map[string]string) Snapshot {
	if b == nil {
		b = &ProcBehavior{}
	}
	s := Snapshot{Procs: []ProcInfo{{PID: 1, Name: "systemd"}, p}, ListenPorts: map[int32][]int{},
		RemoteEndpoints: map[int32][]string{}, Behavior: map[int32]*ProcBehavior{p.PID: b}, Autostart: auto}
	if listen != nil {
		s.ListenPorts[p.PID] = listen
	}
	if remote != nil {
		s.RemoteEndpoints[p.PID] = remote
	}
	return s
}

func TestAuditOrdinaryProgramsAreNotAgents(t *testing.T) {
	c := mustCatalog(t)
	for _, tc := range []struct {
		name string
		snap Snapshot
	}{
		{"python http.server on 8080", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "python3", Exe: "/usr/bin/python3.12", Cmdline: "python3 -m http.server 8080"}, nil, []int{8080}, nil, nil)},
		{"go run web app on 8080", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "main", Exe: "/tmp/go-build1/b001/exe/main", Cmdline: "/tmp/go-build1/b001/exe/main"}, nil, []int{8080}, nil, nil)},
		{"IDE calling localhost:8080 + git", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "java", Exe: "/usr/bin/java", Cmdline: "java -jar idea.jar"}, &ProcBehavior{ToolSpawns: []string{"git"}}, nil, []string{"127.0.0.1:8080"}, nil)},
		{"PyTorch training with data-loader workers", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "python3", Exe: "/usr/bin/python3.12", Cmdline: "python3 train.py"}, &ProcBehavior{Modules: []string{"libtorch_cpu.so"}, ToolSpawns: []string{"python3", "python3", "python3", "python3"}}, nil, nil, nil)},
		{"nodemon in an 'agentic' project folder", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "node", Exe: "/usr/bin/node", Cmdline: "node /home/u/agentic-rag/node_modules/.bin/nodemon index.js"}, &ProcBehavior{ToolSpawns: []string{"sh", "sh", "sh"}}, nil, nil, nil)},
		{"npm installing the MCP SDK", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "npm", Exe: "/usr/bin/node", Cmdline: "npm install @modelcontextprotocol/sdk"}, nil, nil, nil, nil)},
		{"language server in an *-mcp folder", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "node", Exe: "/usr/bin/node", Cmdline: "node /home/u/src/weather-mcp/node_modules/.bin/typescript-language-server --stdio"}, nil, nil, nil, nil)},
		{"VS Code opening a folder named opencode", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "code", Exe: "/usr/share/code/code", Cmdline: "/usr/share/code/code /home/u/src/opencode"}, nil, nil, nil, nil)},
		{"grep for openclaw", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "rg", Exe: "/usr/bin/rg", Cmdline: "rg -i openclaw docs/"}, nil, nil, nil, nil)},
		{"tail of an mcp-server log", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "tail", Exe: "/usr/bin/tail", Cmdline: "tail -f /var/log/mcp-server.log"}, nil, nil, nil, nil)},
		{"Copilot language server in Neovim", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "node", Exe: "/usr/bin/node", Cmdline: "node /home/u/.local/share/nvim/lazy/copilot.lua/copilot/js/node_modules/@github/copilot-language-server/dist/language-server.js --stdio"}, nil, nil, nil, nil)},
	} {
		if dets := c.Classify(tc.snap, nil); len(dets) > 0 {
			t.Errorf("%s: reported as %q (score %d, reasons %v)", tc.name, dets[0].Name, dets[0].AgentScore, dets[0].Reasons)
		}
	}
}

func TestAuditRealAgentsStillDetected(t *testing.T) {
	c := mustCatalog(t)
	llm := map[string]string{"1.2.3.4": "api.openai.com"}
	for _, tc := range []struct {
		name, want string
		snap       Snapshot
	}{
		{"llama-server", "llama.cpp server", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "llama-server", Exe: "/usr/local/bin/llama-server", Cmdline: "llama-server -m model.gguf"}, nil, []int{8080}, nil, nil)},
		{"Ollama on its own port", "Ollama", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "ollama", Exe: "/usr/local/bin/ollama", Cmdline: "ollama serve"}, nil, []int{11434}, nil, nil)},
		{"unknown program on Ollama's port", "Unknown AI agent (srv)", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "srv", Exe: "/opt/srv"}, nil, []int{11434}, nil, nil)},
		{"Claude Code via node", "Claude Code", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "node", Exe: "/usr/bin/node", Cmdline: "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"}, nil, nil, nil, nil)},
		{"MCP server via npx", "MCP server: server-filesystem", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "npx", Exe: "/usr/bin/node", Cmdline: "npx -y @modelcontextprotocol/server-filesystem /home"}, nil, nil, nil, nil)},
		{"MCP server via uvx", "MCP server: mcp-server-fetch", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "uvx", Exe: "/home/u/.local/bin/uvx", Cmdline: "uvx mcp-server-fetch"}, nil, nil, nil, nil)},
		{"aider via python -m", "Aider", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "python3", Exe: "/usr/bin/python3", Cmdline: "python3 -m aider --model x"}, nil, nil, nil, nil)},
		{"unnamed agent: LLM API + tools", "Unknown AI agent (x)", auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "x", Exe: "/home/u/.local/bin/x", Cmdline: "x"}, &ProcBehavior{ToolSpawns: []string{"bash", "git", "curl"}}, nil, []string{"1.2.3.4:443"}, nil)},
	} {
		dets := c.Classify(tc.snap, llm)
		if len(dets) == 0 || dets[0].Name != tc.want {
			t.Errorf("%s: got %+v, want %q", tc.name, dets, tc.want)
		}
	}
}

func TestAuditVerdicts(t *testing.T) {
	c := mustCatalog(t)
	// Ollama installed as a systemd service: after the owner sanctions it,
	// it is simply sanctioned, not "risky" forever.
	d := c.Classify(auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "ollama", Exe: "/usr/local/bin/ollama", Cmdline: "/usr/local/bin/ollama serve"}, nil, []int{11434}, nil,
		map[string]string{"/usr/local/bin/ollama": "systemd unit (ollama.service)"}), nil)
	if v, r := AgentVerdict(AgentSanctioned, d[0].Risks); v != VerdictSanctioned {
		t.Errorf("sanctioned Ollama service: %s %v", v, r)
	}
	// One "node app.js" service must not mark every node program auto-started.
	d = c.Classify(auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "node", Exe: "/usr/bin/node", Cmdline: "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"}, nil, nil, nil,
		map[string]string{autostartKey("/usr/bin/node", "/usr/bin/node /srv/app.js"): "systemd unit (myapp.service)"}), nil)
	if len(d[0].Risks) != 0 {
		t.Errorf("node service marked Claude Code as auto-started: %v", d[0].Risks)
	}
	// A script agent run from Downloads/tmp is flagged like an executable.
	d = c.Classify(auditSnap(ProcInfo{PID: 10, PPID: 1, Name: "python3", Exe: "/usr/bin/python3", Cmdline: "python3 /tmp/x/agent.py"},
		&ProcBehavior{ToolSpawns: []string{"bash", "git", "curl"}}, nil, []string{"1.2.3.4:443"}, nil), map[string]string{"1.2.3.4": "api.openai.com"})
	if len(d) == 0 || !strings.Contains(strings.Join(d[0].Risks, ";"), "unusual location (/tmp/x/agent.py)") {
		t.Errorf("script in /tmp not flagged: %+v", d)
	}
}

func TestAuditFingerprintsSeparateDifferentCode(t *testing.T) {
	c := mustCatalog(t)
	fp := func(p ProcInfo) string {
		d := c.Classify(auditSnap(p, &ProcBehavior{ToolSpawns: []string{"bash", "git", "curl"}}, nil, []string{"1.2.3.4:443"}, nil), map[string]string{"1.2.3.4": "api.openai.com"})
		if len(d) == 0 {
			t.Fatalf("%q not detected", p.Cmdline)
		}
		return AgentFingerprint(d[0])
	}
	for _, pair := range [][2]ProcInfo{
		{{PID: 10, Name: "node", Exe: "/usr/bin/node", Cmdline: "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"},
			{PID: 10, Name: "node", Exe: "/usr/bin/node", Cmdline: "node --require=/tmp/evil.js /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"}},
		{{PID: 10, Name: "uvx", Exe: "/u/uvx", Cmdline: "uvx mcp-server-fetch"}, {PID: 10, Name: "uvx", Exe: "/u/uvx", Cmdline: "uvx mcp-server-git"}},
		{{PID: 10, Name: "java", Exe: "/usr/bin/java", Cmdline: "java -jar /opt/a/agent.jar"}, {PID: 10, Name: "java", Exe: "/usr/bin/java", Cmdline: "java -jar /tmp/evil.jar"}},
		{{PID: 10, Name: "python3", Exe: "/usr/bin/python3", Cmdline: "python3 -X utf8 /opt/agent.py"}, {PID: 10, Name: "python3", Exe: "/usr/bin/python3", Cmdline: "python3 -X utf8 /srv/evil.py"}},
		{{PID: 10, Name: "python3", Exe: "/usr/bin/python3", Cmdline: "python3 agent.py", Cwd: "/home/a/proj1"}, {PID: 10, Name: "python3", Exe: "/usr/bin/python3", Cmdline: "python3 agent.py", Cwd: "/home/a/proj2"}},
	} {
		if a, b := fp(pair[0]), fp(pair[1]); a == b {
			t.Errorf("different code shares a fingerprint: %q", a)
		}
	}
}

func TestAuditRedaction(t *testing.T) {
	for _, s := range []string{"aider --api-key gsk_abcdefghijkl", `curl -H "Authorization: Bearer abcdefghijklmnop" x`,
		"x --hf hf_abcdefghijklmnop", "x github_pat_11ABCDEFGHIJ", "x --openai-api-key=sk-proj-abcdefghij"} {
		out := redactSecrets(s)
		for _, secret := range []string{"gsk_abcdefghijkl", "abcdefghijklmnop", "hf_abcdefghijklmnop", "github_pat_11ABCDEFGHIJ", "sk-proj-abcdefghij"} {
			if strings.Contains(s, secret) && strings.Contains(out, secret) {
				t.Errorf("%q not redacted: %q", secret, out)
			}
		}
	}
}

// A human typing in an IDE's built-in terminal (interactive shell) is not
// the IDE's agent loop; an agent's non-interactive "bash -c" still is.
func TestInteractiveShellStopsCredit(t *testing.T) {
	isTool := func(n string) bool { return n == "whoami" || n == "bash" }
	isShell := func(n string) bool { return n == "bash" }
	tr := newSpawnTracker(time.Minute)
	t0 := time.Now()
	tr.observe([]fastProc{{PID: 10, PPID: 1, Name: "cursor"}, {PID: 11, PPID: 10, Name: "bash", Interactive: true},
		{PID: 20, PPID: 1, Name: "agent"}, {PID: 21, PPID: 20, Name: "bash"}}, t0, isTool, isShell)
	tr.observe([]fastProc{{PID: 10, PPID: 1, Name: "cursor"}, {PID: 11, PPID: 10, Name: "bash", Interactive: true},
		{PID: 12, PPID: 11, Name: "whoami"}, {PID: 20, PPID: 1, Name: "agent"}, {PID: 21, PPID: 20, Name: "bash"},
		{PID: 22, PPID: 21, Name: "whoami"}}, t0.Add(time.Second), isTool, isShell)
	if got := tr.recent(10); len(got) != 0 {
		t.Errorf("IDE credited with a human's terminal commands: %v", got)
	}
	if got := tr.recent(20); len(got) != 1 {
		t.Errorf("agent's non-interactive shell command not credited: %v", got)
	}
}

// fork, pause, exec: the child first carries its parent's name.
func TestRenamedChildIsCounted(t *testing.T) {
	isTool := func(n string) bool { return n == "id" }
	tr := newSpawnTracker(time.Minute)
	t0 := time.Now()
	tr.observe([]fastProc{{PID: 20, PPID: 1, Name: "agent"}}, t0, isTool, func(string) bool { return false })
	tr.observe([]fastProc{{PID: 20, PPID: 1, Name: "agent"}, {PID: 21, PPID: 20, Name: "agent"}}, t0.Add(time.Second), isTool, func(string) bool { return false })
	tr.observe([]fastProc{{PID: 20, PPID: 1, Name: "agent"}, {PID: 21, PPID: 20, Name: "id"}}, t0.Add(2*time.Second), isTool, func(string) bool { return false })
	if got := tr.recent(20); len(got) != 1 || got[0] != "id" {
		t.Errorf("exec'd tool hidden behind its parent's name: %v", got)
	}
}

// An update must be "this agent changed", not "a new agent" (found in the
// 2026-10-21 self-review): version numbers in paths don't split identity.
func TestUpdatedAgentKeepsItsIdentity(t *testing.T) {
	fp := func(exe, target string) string {
		return AgentFingerprint(Detection{Name: "Claude Code", Exe: exe, Target: target})
	}
	if fp("/home/u/.vscode/extensions/anthropic.claude-code-2.0.14-linux-x64/resources/claude", "") !=
		fp("/home/u/.vscode/extensions/anthropic.claude-code-2.1.0-linux-x64/resources/claude", "") {
		t.Error("extension update produced a new identity")
	}
	if fp("/home/u/.local/share/claude/versions/2.0.14", "") != fp("/home/u/.local/share/claude/versions/2.1.3", "") {
		t.Error("native update produced a new identity")
	}
	if fp("/usr/bin/node", "/opt/a/agent.js") == fp("/usr/bin/node", "/opt/b/agent.js") {
		t.Error("different scripts merged")
	}
}
