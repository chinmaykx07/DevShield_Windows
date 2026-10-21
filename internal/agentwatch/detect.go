// agentwatch.go — AI agent detection rules (platform-independent)
//
// Agent Watch answers two questions:
//   1. Which AI agents are running on this machine right now?
//   2. Is any of them a rogue — undocumented, or behaving like an attacker?
//
// Detection is BEHAVIOUR-FIRST. A rogue agent will never be in a list,
// and a bad actor can rename a known agent, so names decide nothing:
//
//   Agent-likeness score — what makes a process an AI agent, by behaviour:
//     talks to an LLM API or local model server · LLM keys/endpoints set
//     for that process · AI inference libraries loaded · runs a loop of
//     shells and command-line tools · (weak) agent framework in cmdline
//
//   Rogue indicators — what makes an agent suspicious:
//     undocumented (not in the catalog) · runs from Temp/Downloads ·
//     "skip permissions" flags · launches recon/persistence/credential
//     tools · registered to auto-start · parent gone (detached)
//
// The catalog only adds an identity label ("this looks like Claude Code").
// It never suppresses rogue indicators.
//
// This file is pure logic with no OS calls, so it is unit-tested on any
// platform. Collection: agentwatch_collect.go + agentwatch_{windows,other}.go.
// Persistence: agentwatch_store.go. Design: docs/RESEARCH_AI_AGENT_MONITORING.md

package agentwatch

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

//go:embed catalog.json
var defaultAgentCatalog []byte

// ── CATALOG TYPES ────────────────────────────────────────────

// AgentSignature describes one known agent in agent_catalog.json.
type AgentSignature struct {
	Name            string   `json:"name"`
	Vendor          string   `json:"vendor"`
	Kind            string   `json:"kind"` // cli | ide | desktop | extension | runtime | mcp_server
	ProcessNames    []string `json:"process_names"`
	PathPatterns    []string `json:"path_patterns"`
	CmdlinePatterns []string `json:"cmdline_patterns"`
	Ports           []int    `json:"ports"`

	pathRe    []*regexp.Regexp
	cmdlineRe []*regexp.Regexp
}

// AILibrary is a DLL/shared-object name fragment that indicates in-process
// model inference, with how much it says about the process.
type AILibrary struct {
	Pattern string `json:"pattern"`
	Label   string `json:"label"`
	Weight  int    `json:"weight"`
}

// AgentCatalog is the parsed agent_catalog.json.
type AgentCatalog struct {
	Version         string           `json:"version"`
	Agents          []AgentSignature `json:"agents"`
	LLMAPIHosts     []string         `json:"llm_api_hosts"`
	LLMEnvVars      []string         `json:"llm_env_vars"`
	AILibraries     []AILibrary      `json:"ai_libraries"`
	AgentKeywords   []string         `json:"agent_keywords"`
	ShellNames      []string         `json:"shell_names"`
	ToolProcesses   []string         `json:"tool_processes"`
	SensitiveTools  []string         `json:"sensitive_tools"`
	TerminalHosts   []string         `json:"terminal_hosts"`
	RiskyFlags      []string         `json:"risky_flags"`
	UnusualPaths    []string         `json:"unusual_paths"`
	IgnoreProcesses []string         `json:"ignore_processes"`

	ignore    map[string]bool
	shells    map[string]bool
	tools     map[string]bool
	sensitive map[string]bool
	termHosts map[string]bool
	llmPorts  map[int]string // port → agent name that owns it
	keywordRe *regexp.Regexp
	riskyRe   *regexp.Regexp
	unusualRe []*regexp.Regexp
}

// ParseAgentCatalog parses and compiles a catalog. Every regex must
// compile — a bad user override is reported, not silently skipped.
func ParseAgentCatalog(data []byte) (*AgentCatalog, error) {
	var c AgentCatalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("agent catalog: %w", err)
	}

	for i := range c.Agents {
		a := &c.Agents[i]
		for j, n := range a.ProcessNames {
			a.ProcessNames[j] = strings.ToLower(n)
		}
		for _, p := range a.PathPatterns {
			re, err := regexp.Compile("(?i)" + p)
			if err != nil {
				return nil, fmt.Errorf("agent catalog: %s path pattern %q: %w", a.Name, p, err)
			}
			a.pathRe = append(a.pathRe, re)
		}
		for _, p := range a.CmdlinePatterns {
			re, err := regexp.Compile("(?i)" + p)
			if err != nil {
				return nil, fmt.Errorf("agent catalog: %s cmdline pattern %q: %w", a.Name, p, err)
			}
			a.cmdlineRe = append(a.cmdlineRe, re)
		}
	}
	for _, p := range c.UnusualPaths {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("agent catalog: unusual path %q: %w", p, err)
		}
		c.unusualRe = append(c.unusualRe, re)
	}

	c.ignore = lowerSet(c.IgnoreProcesses)
	c.shells = lowerSet(c.ShellNames)
	c.tools = lowerSet(append(append([]string{}, c.ToolProcesses...), c.ShellNames...))
	c.sensitive = lowerSet(c.SensitiveTools)
	c.termHosts = lowerSet(c.TerminalHosts)

	c.llmPorts = map[int]string{}
	for _, a := range c.Agents {
		for _, p := range a.Ports {
			c.llmPorts[p] = a.Name
		}
	}
	c.keywordRe = alternation(c.AgentKeywords)
	c.riskyRe = alternation(c.RiskyFlags)
	return &c, nil
}

func alternation(words []string) *regexp.Regexp {
	if len(words) == 0 {
		return nil
	}
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = regexp.QuoteMeta(w)
	}
	return regexp.MustCompile("(?i)(" + strings.Join(quoted, "|") + ")")
}

// LoadAgentCatalog uses overridePath when it is set and readable, and
// otherwise the catalog embedded in the binary. A broken override falls
// back to the built-in catalog and returns a non-nil error describing why.
// The override must only be writable by a trusted user: whoever can edit
// it decides what counts as an agent.
func LoadAgentCatalog(overridePath string) (*AgentCatalog, error) {
	if overridePath != "" {
		if data, err := os.ReadFile(overridePath); err == nil {
			c, err := ParseAgentCatalog(data)
			if err == nil {
				return c, nil
			}
			def, defErr := ParseAgentCatalog(defaultAgentCatalog)
			if defErr != nil {
				return nil, defErr
			}
			return def, fmt.Errorf("using built-in catalog, override %s ignored: %w", overridePath, err)
		}
	}
	return ParseAgentCatalog(defaultAgentCatalog)
}

func lowerSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[strings.ToLower(s)] = true
	}
	return m
}

// ── SNAPSHOT TYPES ───────────────────────────────────────────

// ProcInfo is one process as seen by a single scan.
type ProcInfo struct {
	PID     int32
	PPID    int32
	Name    string // e.g. "node.exe"
	Exe     string // full path, may be empty without permission
	Cmdline string
	User    string
	Start   int64  // creation time (ms); with PID, identifies the process across PID reuse
	Cwd     string // working directory (generic runtimes only), to resolve relative scripts
}

// ProcBehavior holds the expensive, OS-specific observations about one
// process. The collector fills it; Classify only reads it.
type ProcBehavior struct {
	EnvHits    []string // LLM env var NAMES set for this process (never values)
	Modules    []string // loaded module file names (lower case)
	ToolSpawns []string // tool/shell children started in the recent window
}

// Snapshot is everything one scan collected.
type Snapshot struct {
	Procs []ProcInfo
	// ListenPorts maps PID → local TCP ports it listens on
	ListenPorts map[int32][]int
	// RemoteEndpoints maps PID → "ip:port" of established TCP connections
	// (both directions)
	RemoteEndpoints map[int32][]string
	// Outbound is the subset of RemoteEndpoints this machine initiated
	// (the local port is not a listening port, so it was not accepted)
	Outbound map[int32][]string
	// Behavior maps PID → extra observations (may be missing for a PID)
	Behavior map[int32]*ProcBehavior
	// Autostart maps a lower-case exe path → where it is registered to auto-start
	Autostart map[string]string
}

// ── CLASSIFICATION ───────────────────────────────────────────

// Detection is one process that is an AI agent by identity or behaviour.
type Detection struct {
	Name       string
	Vendor     string
	Kind       string
	Known      bool // identity matched the catalog (a label, not a verdict)
	PID        int32
	Start      int64  // process creation time (ms), see ProcInfo.Start
	Script     string // the script/jar a runtime runs, hashed to notice changes
	Exe        string
	Cmdline    string
	User       string
	Target     string   // script/package run by a generic runtime (node, python, uvx…)
	AgentScore int      // behaviour-based agent-likeness
	Reasons    []string // why it is considered an agent
	Risks      []string // rogue indicators, independent of identity
}

// UnknownAgentThreshold is the behaviour score at which a process that is
// not in the catalog is reported as an AI agent. No single weak signal
// reaches it on its own.
const UnknownAgentThreshold = 3

// riskAutostart starts the auto-start indicator (cleared by a sanction).
const riskAutostart = "registered to start automatically"

// RiskUndocumented is the rogue indicator for an agent that matches no
// catalog entry. It is dropped once the user sanctions that agent.
const RiskUndocumented = "undocumented agent — not in any catalog"

// Match returns the first catalog signature that matches p, or nil.
func (c *AgentCatalog) Match(p ProcInfo) *AgentSignature {
	name := strings.ToLower(p.Name)
	// Patterns see only what the program IS, never its other arguments.
	cmdline := identity(p)
	if c.shells[name] {
		// A shell's inline command is text it runs, not what it is:
		// "bash -c 'cat claude-code-notes'" is not Claude Code. The real
		// agent it launches is matched as its own process.
		cmdline = shellIdentity(name, p.Cmdline)
	}
	for i := range c.Agents {
		a := &c.Agents[i]
		for _, re := range a.cmdlineRe {
			if cmdline != "" && re.MatchString(cmdline) {
				return a
			}
		}
		if !containsString(a.ProcessNames, name) {
			continue
		}
		if len(a.pathRe) == 0 {
			return a
		}
		for _, re := range a.pathRe {
			if re.MatchString(p.Exe) {
				return a
			}
		}
	}
	return nil
}

// Classify finds every process that is an AI agent by catalog identity or
// by behaviour, and attaches rogue indicators to each. llmIPs is the set of
// IPs that the catalog's LLM API hosts currently resolve to.
func (c *AgentCatalog) Classify(s Snapshot, llmIPs map[string]string) []Detection {
	alive := make(map[int32]bool, len(s.Procs))
	for _, p := range s.Procs {
		alive[p.PID] = true
	}

	var out []Detection
	for _, p := range s.Procs {
		if c.ignore[strings.ToLower(p.Name)] {
			continue
		}
		b := s.Behavior[p.PID]
		if b == nil {
			b = &ProcBehavior{}
		}
		score, reasons := c.agentScore(p, s, b, llmIPs)
		sig := c.Match(p)
		if sig == nil && score < UnknownAgentThreshold {
			continue
		}

		target, script := launchTarget(p)
		d := Detection{
			PID: p.PID, Start: p.Start, Exe: p.Exe, Cmdline: p.Cmdline, User: p.User, Target: target, Script: script,
			AgentScore: score, Reasons: reasons,
		}
		if sig != nil {
			d.Name, d.Vendor, d.Kind, d.Known = sig.Name, sig.Vendor, sig.Kind, true
			if sig.Kind == "mcp_server" && target != "" {
				d.Name = "MCP server: " + filepath.Base(strings.ReplaceAll(target, `\`, "/"))
			}
			d.Reasons = append([]string{"identified as " + sig.Name}, d.Reasons...)
		} else {
			d.Name, d.Kind = "Unknown AI agent ("+p.Name+")", "unknown"
		}
		d.Risks = c.rogueIndicators(p, s, b, sig == nil, alive)
		out = append(out, d)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if (len(out[i].Risks) > 0) != (len(out[j].Risks) > 0) {
			return len(out[i].Risks) > 0 // risky first — they need attention
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// agentScore measures how much a process BEHAVES like an AI agent. It
// ignores the process name entirely. Weights are conservative so that a
// single weak signal never reaches UnknownAgentThreshold by itself.
func (c *AgentCatalog) agentScore(p ProcInfo, s Snapshot, b *ProcBehavior, llmIPs map[string]string) (int, []string) {
	score := 0
	var reasons []string
	add := func(n int, why string) { score += n; reasons = append(reasons, why) }

	// A distinctive model port (Ollama's 11434) is strong evidence; a
	// port every web framework also uses (8080, 1234, 1337) is barely any.
	for _, port := range s.ListenPorts[p.PID] {
		if owner, ok := c.llmPorts[port]; ok {
			if commonPorts[port] {
				add(1, fmt.Sprintf("listens on port %d (also used by %s, and by many web servers)", port, owner))
			} else {
				add(3, fmt.Sprintf("serves a model on local LLM port %d (usually %s)", port, owner))
			}
			break
		}
	}

	apiHit, localHit := "", 0
	for _, ep := range s.RemoteEndpoints[p.PID] {
		ip, port := splitEndpoint(ep)
		if host, ok := llmIPs[ip]; ok && apiHit == "" {
			apiHit = host
		}
		if isLoopback(ip) {
			if _, ok := c.llmPorts[port]; ok && localHit == 0 {
				localHit = port
			}
		}
	}
	if apiHit != "" {
		add(2, "connected to LLM API ("+apiHit+")")
	}
	if localHit != 0 {
		if commonPorts[localHit] {
			add(1, fmt.Sprintf("talks to local port %d (a model server port, but common)", localHit))
		} else {
			add(2, fmt.Sprintf("talks to a local model server on port %d", localHit))
		}
	}

	if len(b.EnvHits) > 0 {
		add(2, "LLM credentials/endpoint set for this process ("+strings.Join(b.EnvHits, ", ")+")")
	}

	best, label := 0, ""
	for _, lib := range c.AILibraries {
		pat := strings.ToLower(lib.Pattern)
		for _, m := range b.Modules {
			if strings.Contains(m, pat) && lib.Weight > best {
				best, label = lib.Weight, lib.Label
			}
		}
	}
	if best > 0 {
		add(best, "runs AI models in-process ("+label+")")
	}

	// The agent loop: a process that keeps launching shells and tools.
	// Shells and terminals launching tools is just a human typing.
	name := strings.ToLower(p.Name)
	if !c.shells[name] && !c.termHosts[name] {
		switch n := len(otherPrograms(b.ToolSpawns, name)); {
		case n >= 3:
			add(2, fmt.Sprintf("ran %d shells/tools recently (%s)", n, summarizeNames(otherPrograms(b.ToolSpawns, name))))
		case n > 0:
			add(1, fmt.Sprintf("ran %s", summarizeNames(otherPrograms(b.ToolSpawns, name))))
		}
	}

	// Weak on purpose: trivially added or removed by an author.
	if c.keywordRe != nil {
		if kw := c.keywordRe.FindString(identityNames(p)); kw != "" {
			add(1, "command line mentions "+strings.ToLower(kw))
		}
	}
	return score, reasons
}

// rogueIndicators lists signs that an agent is undocumented or behaving
// like an attacker's tool. Applied to EVERY agent, catalogued or not.
func (c *AgentCatalog) rogueIndicators(p ProcInfo, s Snapshot, b *ProcBehavior, undocumented bool, alive map[int32]bool) []string {
	var risks []string
	if undocumented {
		risks = append(risks, RiskUndocumented)
	}
	_, script := launchTarget(p)
	for _, where := range []string{p.Exe, script} {
		found := false
		for _, re := range c.unusualRe {
			if where != "" && re.MatchString(where) {
				risks = append(risks, "runs from an unusual location ("+where+")")
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if c.riskyRe != nil {
		if f := c.riskyRe.FindString(p.Cmdline); f != "" {
			risks = append(risks, "started with approvals disabled ("+f+")")
		}
	}
	var sens []string
	for _, t := range b.ToolSpawns {
		if c.sensitive[strings.ToLower(t)] && !containsString(sens, t) {
			sens = append(sens, t)
		}
	}
	if len(sens) > 0 {
		risks = append(risks, "launched recon/persistence/credential tools ("+strings.Join(sens, ", ")+")")
	}
	if where, ok := s.Autostart[autostartKey(p.Exe, p.Cmdline)]; ok && p.Exe != "" {
		risks = append(risks, riskAutostart+" ("+where+")")
	}
	if p.PPID != 0 && !alive[p.PPID] && len(b.ToolSpawns) > 0 {
		risks = append(risks, "running detached — its parent process is gone")
	}
	return risks
}

// ── VERDICT ──────────────────────────────────────────────────

const (
	VerdictSanctioned   = "sanctioned"   // approved, nothing suspicious
	VerdictUnsanctioned = "unsanctioned" // known agent, not approved, nothing suspicious
	VerdictRisky        = "risky"        // approved, but now showing rogue indicators
	VerdictRogue        = "rogue"        // not approved AND undocumented or suspicious
)

// AgentVerdict combines the user's sanction decision with rogue indicators.
// Sanctioning an undocumented agent clears only the "undocumented" risk —
// any behavioural risk still raises an alert.
func AgentVerdict(status string, risks []string) (string, []string) {
	if status == AgentSanctioned {
		var remaining []string
		for _, r := range risks {
			// The owner's approval covers what the agent is and how it is
			// installed to start; behaviour (tools it runs, flags, where it
			// runs from) still counts.
			if r != RiskUndocumented && !strings.HasPrefix(r, riskAutostart) {
				remaining = append(remaining, r)
			}
		}
		if len(remaining) > 0 {
			return VerdictRisky, remaining
		}
		return VerdictSanctioned, nil
	}
	if len(risks) > 0 {
		return VerdictRogue, risks
	}
	return VerdictUnsanctioned, nil
}

// ── HELPERS ──────────────────────────────────────────────────

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// summarizeNames turns ["cmd.exe","git.exe","cmd.exe"] into "cmd.exe ×2, git.exe".
func summarizeNames(names []string) string {
	counts := map[string]int{}
	var order []string
	for _, n := range names {
		if counts[n] == 0 {
			order = append(order, n)
		}
		counts[n]++
	}
	parts := make([]string, len(order))
	for i, n := range order {
		if counts[n] > 1 {
			parts[i] = fmt.Sprintf("%s ×%d", n, counts[n])
		} else {
			parts[i] = n
		}
	}
	return strings.Join(parts, ", ")
}

// splitEndpoint splits "ip:port" (IPv6 may be bracketed) into ip and port.
func splitEndpoint(ep string) (string, int) {
	i := strings.LastIndex(ep, ":")
	if i < 0 {
		return ep, 0
	}
	port := 0
	fmt.Sscanf(ep[i+1:], "%d", &port)
	return strings.Trim(ep[:i], "[]"), port
}

// commonPorts are also used by countless ordinary programs.
var commonPorts = map[int]bool{80: true, 443: true, 1234: true, 1337: true, 3000: true, 5000: true, 8000: true, 8080: true, 8443: true, 8888: true}

// otherPrograms drops children with the program's own name: worker
// processes it forks (PyTorch data loaders, multiprocessing pools) are not
// an agent launching tools.
func otherPrograms(spawns []string, self string) []string {
	self = strings.TrimSuffix(self, ".exe")
	var out []string
	for _, s := range spawns {
		if strings.TrimSuffix(s, ".exe") != self {
			out = append(out, s)
		}
	}
	return out
}

func isLoopback(ip string) bool {
	return strings.HasPrefix(ip, "127.") || ip == "::1"
}

// isGenericRuntime reports whether a program runs someone else's code, so
// the program that matters is the script or package it was given, not the
// runtime executable (node, python3.12, uvx, java, …, on any OS).
func isGenericRuntime(name string) bool {
	n := strings.ToLower(name)
	n = strings.TrimSuffix(strings.TrimSuffix(n, ".exe"), ".cmd")
	switch n {
	case "node", "bun", "deno", "npx", "uvx", "uv", "pipx", "java", "javaw", "dotnet", "pythonw":
		return true
	case "cmd":
		return strings.HasSuffix(strings.ToLower(name), ".exe")
	}
	if rest, ok := strings.CutPrefix(n, "python"); ok {
		return strings.Trim(rest, "0123456789.") == ""
	}
	return false
}

// valueFlags take a separate value that is not the program to run
// ("python3 -X utf8 agent.py", "java -cp lib -jar x.jar").
var valueFlags = map[string]bool{
	"-X": true, "-W": true, "-Q": true, "--check-hash-based-pycs": true,
	"-cp": true, "-classpath": true, "--class-path": true,
	"--title": true, "--inspect-port": true, "--with": true, "--from": true, "--python": true,
}

// codeFlags load or run extra code; their values become part of the
// identity, so "node --require=evil.js cli.js" is not the approved cli.js.
var codeFlags = map[string]bool{
	"-r": true, "--require": true, "--import": true, "--loader": true, "--experimental-loader": true,
	"-e": true, "--eval": true, "-c": true, "-javaagent": true,
}

// launchTarget returns what a generic runtime runs: target identifies it
// (script or package, plus any extra code it loads) and script is the
// file to hash when it exists. Relative paths are resolved against the
// process's working directory. Ordinary executables return "", "".
func launchTarget(p ProcInfo) (target, script string) {
	if !isGenericRuntime(p.Name) {
		return "", ""
	}
	args := splitCmdline(p.Cmdline)
	var extra []string
loop:
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-m" && i+1 < len(args): // python -m module
			target = args[i+1]
			break loop
		case strings.HasPrefix(a, "-"):
			flag, val, hasEq := strings.Cut(a, "=")
			if strings.HasPrefix(flag, "-javaagent:") {
				flag, val, hasEq = "-javaagent", strings.TrimPrefix(a, "-javaagent:"), true
			}
			switch {
			case codeFlags[flag]:
				if !hasEq && i+1 < len(args) {
					i++
					val = args[i]
				}
				extra = append(extra, flag+" "+val)
				if flag == "-c" || flag == "-e" || flag == "--eval" {
					break loop // inline code: the rest is its arguments
				}
			case valueFlags[flag] && !hasEq:
				i++
			}
		case strings.EqualFold(a, "run") || strings.EqualFold(a, "exec") || strings.EqualFold(a, "/c"):
			// "uv run x", "npx exec x", "cmd /c x" — the target follows
		default:
			target = a
			break loop
		}
	}
	if target != "" && p.Cwd != "" && looksLikePath(target) && !isAbs(target) {
		target = filepath.Join(p.Cwd, target)
	}
	if looksLikePath(target) {
		script = target
	}
	if len(extra) > 0 {
		target = strings.TrimSpace(target + " [" + strings.Join(extra, "; ") + "]")
	}
	return target, script
}

func looksLikePath(s string) bool {
	if strings.ContainsAny(s, `/\`) {
		return true
	}
	switch strings.ToLower(filepath.Ext(s)) {
	case ".py", ".js", ".mjs", ".cjs", ".ts", ".jar", ".dll", ".pyz":
		return true
	}
	return false
}

func isAbs(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) || (len(p) > 2 && p[1] == ':')
}

// autostartKey is how auto-start entries and running processes are
// matched: the executable, plus the script for generic runtimes — one
// "node app.js" service must not mark every node program as auto-started.
func autostartKey(exe, command string) string {
	name := filepath.Base(strings.ReplaceAll(exe, `\`, "/"))
	if !isGenericRuntime(name) {
		return strings.ToLower(exe)
	}
	t, _ := launchTarget(ProcInfo{Name: name, Cmdline: command})
	return strings.ToLower(exe + "|" + t)
}

// identityNames is the program's file name plus its script's or module's
// name — not the folders they sit in ("~/agentic-rag/…/nodemon" is not
// about agents).
func identityNames(p ProcInfo) string {
	args := splitCmdline(p.Cmdline)
	out := filepath.Base(strings.ReplaceAll(p.Exe, `\`, "/"))
	if len(args) > 0 {
		out = filepath.Base(strings.ReplaceAll(args[0], `\`, "/"))
	}
	if t, script := launchTarget(p); script != "" {
		out += " " + filepath.Base(strings.ReplaceAll(script, `\`, "/"))
	} else if t != "" {
		out += " " + t
	}
	return out
}

// identity is the part of a command line that says what a program IS:
// its executable plus, for runtimes, what it runs. Arguments such as files
// it reads, folders it opens or packages it installs are excluded, so
// "rg openclaw", "code ~/src/opencode" or "npm install @modelcontextprotocol/sdk"
// are not those agents.
func identity(p ProcInfo) string {
	args := splitCmdline(p.Cmdline)
	if len(args) == 0 {
		return p.Exe
	}
	t, _ := launchTarget(p)
	return strings.TrimSpace(args[0] + " " + t)
}

// shellIdentity is the part of a shell's command line that says what the
// shell is running: everything before an inline-command flag (-c, /c,
// -Command, -EncodedCommand). A script path ("bash /opt/x/run.sh") is kept.
func shellIdentity(shell, cmdline string) string {
	args := splitCmdline(cmdline)
	ps := strings.Contains(shell, "pwsh") || strings.Contains(shell, "powershell")
	for i, a := range args {
		if i == 0 {
			continue
		}
		l := strings.ToLower(a)
		inline := false
		switch {
		case l == "/c" || l == "/k" || l == "/r": // cmd.exe
			inline = true
		case ps && strings.HasPrefix(l, "-"):
			o := strings.TrimLeft(l, "-")
			inline = o == "c" || strings.HasPrefix(o, "command") || o == "e" || o == "ec" || strings.HasPrefix(o, "enc")
		case !ps && len(l) > 1 && l[0] == '-' && l[1] != '-':
			inline = strings.Contains(l[1:], "c") // -c, -lc, -ec …
		}
		if inline {
			return strings.Join(args[:i], " ")
		}
	}
	return cmdline
}

// splitCmdline splits a Windows-style command line on spaces, keeping
// double-quoted sections together. Good enough for identification.
func splitCmdline(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// AgentFingerprint identifies one agent installation across scans:
// same agent name + same executable + same launch target = same agent.
// The target matters for node/python/uvx: otherwise sanctioning one MCP
// server would silently sanction every script that runtime ever runs.
func AgentFingerprint(d Detection) string {
	fp := d.Name + "|" + d.Exe
	if d.Target != "" {
		fp += "|" + d.Target
	}
	return strings.ToLower(fp)
}

// redactSecrets masks values that look like API keys or tokens before a
// command line is stored or shown. Command lines often carry secrets.
var secretRe = regexp.MustCompile(`(?i)((?:(?:api[_-]?key|token|secret|password|passwd)["']?(?:\s*[=:]\s*|\s+)|authorization["']?\s*[=:]\s*|\b(?:bearer|basic)\s+)["']?(?:(?:bearer|basic)\s+)?)[^\s"']+|\b(sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|gh[ousr]_[A-Za-z0-9]{8,}|glpat-[A-Za-z0-9_-]{8,}|hf_[A-Za-z0-9]{8,}|gsk_[A-Za-z0-9]{8,}|xox[abprs]-[A-Za-z0-9-]{8,}|AKIA[A-Z0-9]{12,}|AIza[A-Za-z0-9_-]{8,})`)

func redactSecrets(s string) string {
	return secretRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := secretRe.FindStringSubmatch(m)
		if sub[1] != "" {
			return sub[1] + "***"
		}
		return "***"
	})
}
