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

package main

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

//go:embed assets/agent_catalog.json
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

// LoadAgentCatalog prefers ~/.devshield/agent_catalog.json (user override)
// and falls back to the catalog embedded in the binary.
func LoadAgentCatalog() (*AgentCatalog, error) {
	if home, err := os.UserHomeDir(); err == nil {
		override := filepath.Join(home, ".devshield", "agent_catalog.json")
		if data, err := os.ReadFile(override); err == nil {
			c, err := ParseAgentCatalog(data)
			if err == nil {
				return c, nil
			}
			// Broken override → fall back, but surface the reason
			def, defErr := ParseAgentCatalog(defaultAgentCatalog)
			if defErr != nil {
				return nil, defErr
			}
			return def, fmt.Errorf("using built-in catalog, override ignored: %w", err)
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
	RemoteEndpoints map[int32][]string
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

// RiskUndocumented is the rogue indicator for an agent that matches no
// catalog entry. It is dropped once the user sanctions that agent.
const RiskUndocumented = "undocumented agent — not in any catalog"

// Match returns the first catalog signature that matches p, or nil.
func (c *AgentCatalog) Match(p ProcInfo) *AgentSignature {
	name := strings.ToLower(p.Name)
	for i := range c.Agents {
		a := &c.Agents[i]
		for _, re := range a.cmdlineRe {
			if p.Cmdline != "" && re.MatchString(p.Cmdline) {
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

		target := launchTarget(p)
		d := Detection{
			PID: p.PID, Exe: p.Exe, Cmdline: p.Cmdline, User: p.User, Target: target,
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

	for _, port := range s.ListenPorts[p.PID] {
		if owner, ok := c.llmPorts[port]; ok {
			add(3, fmt.Sprintf("serves a model on local LLM port %d (usually %s)", port, owner))
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
		add(2, fmt.Sprintf("talks to a local model server on port %d", localHit))
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
		switch n := len(b.ToolSpawns); {
		case n >= 3:
			add(2, fmt.Sprintf("ran %d shells/tools recently (%s)", n, summarizeNames(b.ToolSpawns)))
		case n > 0:
			add(1, fmt.Sprintf("ran %s", summarizeNames(b.ToolSpawns)))
		}
	}

	// Weak on purpose: trivially added or removed by an author.
	if c.keywordRe != nil {
		if kw := c.keywordRe.FindString(p.Cmdline); kw != "" {
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
	for _, re := range c.unusualRe {
		if p.Exe != "" && re.MatchString(p.Exe) {
			risks = append(risks, "runs from an unusual location ("+p.Exe+")")
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
	if where, ok := s.Autostart[strings.ToLower(p.Exe)]; ok && p.Exe != "" {
		risks = append(risks, "registered to start automatically ("+where+")")
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
			if r != RiskUndocumented {
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

func isLoopback(ip string) bool {
	return strings.HasPrefix(ip, "127.") || ip == "::1"
}

// genericRuntimes run someone else's code, so the program that matters is
// the script or package they were given, not the runtime executable.
var genericRuntimes = map[string]bool{
	"node.exe": true, "node": true, "bun.exe": true, "deno.exe": true,
	"python.exe": true, "python3.exe": true, "pythonw.exe": true, "python": true, "python3": true,
	"npx.exe": true, "npx.cmd": true, "uvx.exe": true, "uv.exe": true, "pipx.exe": true,
	"java.exe": true, "javaw.exe": true, "dotnet.exe": true, "cmd.exe": true,
}

// launchTarget returns the first non-flag argument of a generic runtime's
// command line, e.g. the .js file node runs or the package uvx starts.
// It returns "" for ordinary executables.
func launchTarget(p ProcInfo) string {
	if !genericRuntimes[strings.ToLower(p.Name)] {
		return ""
	}
	args := splitCmdline(p.Cmdline)
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "-"):
			if a == "-m" && i+1 < len(args) { // python -m module
				return args[i+1]
			}
		case strings.EqualFold(a, "run") || strings.EqualFold(a, "exec") || strings.EqualFold(a, "/c"):
			// "uv run x", "npx exec x", "cmd /c x" — the target follows
		default:
			return a
		}
	}
	return ""
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
var secretRe = regexp.MustCompile(`(?i)((?:api[_-]?key|token|secret|password|authorization)["']?\s*[=:]\s*["']?)[^\s"']+|\b(sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|AIza[A-Za-z0-9_-]{8,})`)

func redactSecrets(s string) string {
	return secretRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := secretRe.FindStringSubmatch(m)
		if sub[1] != "" {
			return sub[1] + "***"
		}
		return "***"
	})
}
