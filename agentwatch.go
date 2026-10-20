// agentwatch.go — AI agent detection rules (platform-independent)
//
// Agent Watch answers two questions:
//   1. Which AI agents are running on this machine right now?
//   2. Has an unknown or unsanctioned agent appeared?
//
// This file holds the pure logic: catalog loading, catalog matching and
// the heuristic score for unknown AI processes. It never touches the OS,
// so it is unit-tested on any platform. Process collection lives in
// agentwatch_collect.go, persistence in agentwatch_store.go.
//
// Design notes: docs/RESEARCH_AI_AGENT_MONITORING.md

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

// AgentCatalog is the parsed agent_catalog.json.
type AgentCatalog struct {
	Version         string           `json:"version"`
	Agents          []AgentSignature `json:"agents"`
	LLMAPIHosts     []string         `json:"llm_api_hosts"`
	AgentKeywords   []string         `json:"agent_keywords"`
	ShellNames      []string         `json:"shell_names"`
	IgnoreProcesses []string         `json:"ignore_processes"`

	ignore    map[string]bool
	shells    map[string]bool
	llmPorts  map[int]string // port → agent name that owns it
	keywordRe *regexp.Regexp
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

	c.ignore = lowerSet(c.IgnoreProcesses)
	c.shells = lowerSet(c.ShellNames)

	c.llmPorts = map[int]string{}
	for _, a := range c.Agents {
		for _, p := range a.Ports {
			c.llmPorts[p] = a.Name
		}
	}

	if len(c.AgentKeywords) > 0 {
		quoted := make([]string, len(c.AgentKeywords))
		for i, k := range c.AgentKeywords {
			quoted[i] = regexp.QuoteMeta(k)
		}
		c.keywordRe = regexp.MustCompile("(?i)(" + strings.Join(quoted, "|") + ")")
	}
	return &c, nil
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

// Snapshot is everything one scan collected.
type Snapshot struct {
	Procs []ProcInfo
	// ListenPorts maps PID → local TCP ports it listens on
	ListenPorts map[int32][]int
	// RemoteEndpoints maps PID → "ip:port" of established TCP connections
	RemoteEndpoints map[int32][]string
}

// ── CLASSIFICATION ───────────────────────────────────────────

// Detection is one AI agent (known or suspected) found in a snapshot.
type Detection struct {
	Name    string
	Vendor  string
	Kind    string
	Known   bool // true = catalog match, false = heuristic only
	PID     int32
	Exe     string
	Cmdline string
	User    string
	Target  string   // script/package run by a generic runtime (node, python, uvx…)
	Score   int      // heuristic score (unknown agents only)
	Reasons []string // why it was flagged
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

// UnknownAgentThreshold is the heuristic score at which a process that
// is not in the catalog is reported as a possible AI agent. No single
// weak signal reaches it on its own.
const UnknownAgentThreshold = 3

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

// Classify finds every known agent and every suspected unknown AI
// process in a snapshot. llmIPs is the set of IPs that the catalog's
// LLM API hosts currently resolve to.
func (c *AgentCatalog) Classify(s Snapshot, llmIPs map[string]string) []Detection {
	children := map[int32][]string{}
	for _, p := range s.Procs {
		children[p.PPID] = append(children[p.PPID], strings.ToLower(p.Name))
	}

	var out []Detection
	for _, p := range s.Procs {
		if c.ignore[strings.ToLower(p.Name)] {
			continue
		}
		target := launchTarget(p)
		if sig := c.Match(p); sig != nil {
			name := sig.Name
			if sig.Kind == "mcp_server" && target != "" {
				name = "MCP server: " + filepath.Base(strings.ReplaceAll(target, `\`, "/"))
			}
			out = append(out, Detection{
				Name: name, Vendor: sig.Vendor, Kind: sig.Kind, Known: true,
				PID: p.PID, Exe: p.Exe, Cmdline: p.Cmdline, User: p.User, Target: target,
				Reasons: []string{"matches catalog entry"},
			})
			continue
		}
		if d, ok := c.scoreUnknown(p, s, children[p.PID], llmIPs); ok {
			d.Target = target
			out = append(out, d)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Known != out[j].Known {
			return !out[i].Known // unknown first — they need attention
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// scoreUnknown adds up weak signals for a process that is not in the
// catalog. Weights are deliberately conservative: browsers and generic
// runtimes are common, so two independent signals are needed.
func (c *AgentCatalog) scoreUnknown(p ProcInfo, s Snapshot, kids []string, llmIPs map[string]string) (Detection, bool) {
	score := 0
	var reasons []string

	for _, port := range s.ListenPorts[p.PID] {
		if owner, ok := c.llmPorts[port]; ok {
			score += 3
			reasons = append(reasons, fmt.Sprintf("listens on local LLM port %d (usually %s)", port, owner))
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
		score += 2
		reasons = append(reasons, "connected to LLM API ("+apiHit+")")
	}
	if localHit != 0 {
		score += 2
		reasons = append(reasons, fmt.Sprintf("talks to local LLM on port %d", localHit))
	}

	if c.keywordRe != nil {
		if kw := c.keywordRe.FindString(p.Cmdline); kw != "" {
			score += 2
			reasons = append(reasons, "command line mentions "+strings.ToLower(kw))
		}
	}

	shells := 0
	for _, k := range kids {
		if c.shells[k] {
			shells++
		}
	}
	if shells > 0 {
		score++
		reasons = append(reasons, fmt.Sprintf("running %d shell(s)", shells))
	}

	if score < UnknownAgentThreshold {
		return Detection{}, false
	}
	return Detection{
		Name: "Unknown AI process (" + p.Name + ")", Kind: "unknown", Known: false,
		PID: p.PID, Exe: p.Exe, Cmdline: p.Cmdline, User: p.User,
		Score: score, Reasons: reasons,
	}, true
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
