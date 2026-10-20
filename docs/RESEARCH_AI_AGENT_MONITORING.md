# Research: Monitoring AI Agents on Windows with DevShield

Date: 2026-10-20
Goal (kept deliberately simple):
1. **Know every AI agent running on this machine.**
2. **Alert when an unknown or new agent / AI process appears.**

**Status:** Phase 1 ("Agent Watch") is implemented in `agentwatch*.go`, `tray_agents.go` and `assets/agent_catalog.json`, with unit tests in `agentwatch_test.go`. It is not yet tested on Windows. The catalog's process names and paths still need confirming on a real machine. Not built yet: the MCP config-file scan (S4), Phase 2 and Phase 3.

---

## 1. What counts as an "AI agent" on a Windows PC today

Agents show up in five shapes. A detector has to handle all of them, because they look very different at the process level.

| Shape | Examples | What you see in Task Manager |
|---|---|---|
| **CLI agents** | Claude Code, Codex CLI, Gemini CLI, GitHub Copilot CLI, OpenCode, Goose, Aider | `claude.exe` / `codex.exe`, **or** a generic `node.exe` / `python.exe` whose command line names the package. They spawn `pwsh`, `cmd`, `git` and `bash` as children. |
| **Desktop / IDE agents** | Cursor, Windsurf, Kiro, Trae, Claude Desktop, ChatGPT Desktop, Copilot app, Warp | Their own branded `.exe` (Electron), with many helper processes |
| **IDE extensions** | Copilot, Claude Code, Cline, Roo Code, Codex and Gemini extensions in VS Code | **Only `Code.exe`** (the extension host). The agent is visible only through the command line or the extensions folder. |
| **Local model runtimes** | Ollama, LM Studio, llama.cpp server, Foundry Local, Jan | `ollama.exe`, `LM Studio.exe`, etc., listening on a localhost port |
| **Windows' own agents** | Copilot Actions in the new *agent workspace* | Run under a **separate agent user account** in a separate Windows session. Tools ("agent connectors") are MCP servers registered in the Windows **On-Device Registry (ODR)**. |

There are also **MCP servers**: small helper processes, usually `node`, `npx`, `uvx` or `python`, that an agent launches to get tools (files, browser, database, shell). An agent's power comes from its MCP servers, so they are worth inventorying too.

The industry framing: **OWASP Top 10 for Agentic Applications (Dec 2025), ASI10 "Rogue Agents"**, covers agents operating outside their intended scope, including orphaned and unmonitored "shadow" agents. That is exactly the problem described here.

## 2. What the big vendors do (so we don't reinvent it)

**Microsoft Defender for Endpoint, "Local AI agent discovery"** (preview, Plan 2 license) is the closest thing to what DevShield wants:
- It inventories agents per **user + device + agent type**, with fields: vendor, version, host process (e.g. `code.exe`), whether the host process is *trusted*, whether the agent **auto-approves its own actions**, configured **MCP servers** (remote endpoints, plus the *command* that starts each local MCP server), and *first seen*.
- Its Windows support list (about 60 agents) is a ready-made **starting catalog** for DevShield, for example Claude Code, Claude Desktop, Codex CLI/Desktop, Cursor, Windsurf, Gemini CLI, GitHub Copilot CLI/App, the VS Code extensions (Copilot, Claude Code, Cline, Roo Code, Codex, Gemini), Kiro, Trae, Warp, OpenCode, Goose, LM Studio, Ollama Desktop, Foundry Local, Qwen Code and OpenClaw. The full list is in the Microsoft source below.
- Two lessons worth copying:
  - Discovery is **activity-based**: an installed but unused agent may not show.
  - The two risk flags that matter most are **"acts without approval"** and **"host process not trusted"**.

**Other approaches seen in the field:**
- **EDR process trees** (Sysmon/EDR) show the chain explorer → terminal → shell → `claude` → `node` → child shells. That is enough to see *that* an agent ran, but not *why*.
- **Agent-native telemetry**: Claude Code, Codex and Copilot CLI support hooks or OpenTelemetry. Open-source tools (Agent Beacon, ATEN) use these to log every tool call. This is very rich, but only works for cooperating, known agents.
- **Network/DNS matching** of known LLM API hosts (`api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`, …). This is useful for catching *unknown* agents. It is weak on its own (relays, private gateways, local models).
- **Warning from Sophos/EDR reports (2026):** coding agents already trip "attacker" rules, such as DPAPI credential decryption, Credential Manager enumeration and startup-folder writes. So *behaviour* is a strong signal, but blanket-allowlisting agents would hide real attacks.

## 3. Signals DevShield can use, ranked by value vs. effort

| # | Signal | Catches | Admin? | Effort |
|---|---|---|---|---|
| S1 | **Process name + exe path + signer** matched against an agent catalog | Known agents with their own exe | No | Low |
| S2 | **Command line** patterns (e.g. `node … @anthropic-ai/claude-code`, `@openai/codex`, `@google/gemini-cli`, `mcp`, `--stdio`, `modelcontextprotocol`) | CLI agents hidden inside `node`/`python`, MCP servers, VS Code extensions | No (own user's processes); admin for other users' | Low |
| S3 | **Process tree**: AI host → spawns shells (`pwsh`, `cmd`, `bash`, `git`) repeatedly | Agents actively executing commands | No | Low |
| S4 | **Config-file scan** for agents and their MCP servers (`%APPDATA%\Claude\claude_desktop_config.json`, `~\.claude.json` + project `.mcp.json`, `~\.codex\config.toml` (`mcp_servers`), `~\.gemini\settings.json`, `~\.cursor\mcp.json` + project `.cursor\mcp.json`, `.vscode\mcp.json` (`servers`)) | Installed agents, their MCP servers, **auto-approve settings** | No | Low |
| S5 | **Listening ports** of local model runtimes (Ollama 11434, LM Studio 1234, llama.cpp 8080, Jan 1337 (unconfirmed)) plus who connects to them | Local LLMs and any process using them | No | Low |
| S6 | **Connections to known LLM API hosts** (resolve the host list periodically and match `Get-NetTCPConnection` remote IPs, or use DNS events) | **Unknown** agents calling cloud LLMs | No (polling); admin for DNS ETW | Medium |
| S7 | **Windows agent accounts / ODR**: new agent user accounts (Windows' agent accounts), `odr.exe mcp …` registered connectors, Security-log logons by agent accounts | Windows' own agents and registered MCP connectors | Yes for the Security log | Medium |
| S8 | **Real-time process start events** (ETW `Microsoft-Windows-Kernel-Process`, or Sysmon Event 1/3/22 if installed) | Short-lived agents that polling misses | Yes | Medium/High |
| S9 | **Agent hooks / OpenTelemetry** (opt-in) | Exact tool calls of cooperating agents | No | Medium |
| S10 | Loaded AI libraries (`onnxruntime`, `llama`, `ggml`, CUDA/DirectML) and GPU/NPU use | Embedded or unknown local-model apps | Partly | Medium |

## 4. Recommended design (simple first, upgradeable)

### Phase 1: "Agent Watch" in the Go tray (no admin, no new dependencies)
Run it in **Go** with **gopsutil** (already used by `context.go`), *not* as a PowerShell `Start-Job`. That also avoids the guardian lifetime bug found in the code review (C5).

1. **Agent catalog**: a `scripts/monitor/agent_catalog.json` (same idea as the blocklist), one entry per agent:
   ```json
   { "name": "Claude Code", "vendor": "Anthropic", "kind": "cli",
     "process_names": ["claude.exe"],
     "cmdline_patterns": ["@anthropic-ai[\\\\/]claude-code"],
     "path_hints": ["\\.local\\bin\\claude.exe"],
     "config_files": ["~/.claude.json", "~/.claude/settings.json"],
     "ports": [] }
   ```
   Seed it from Defender's Windows list. Every process name and path in it must be **verified on a real Windows machine**: several names collide (e.g. Claude Desktop and Claude Code can both be `claude.exe`, distinguished only by install path).
2. **Scanner loop (every ~5s):** walk processes, recording name, exe, cmdline, parent, user, start time and SHA-256 of the exe (cached). Then:
   - Match against the catalog (S1/S2) → **known agent**.
   - Otherwise score heuristics (S3 spawns shells, S5 local-LLM port, S6 LLM API connection, cmdline mentions MCP or LLM SDKs). A score ≥ threshold → **unknown possible agent**.
3. **First-seen database:** a new SQLite table in the existing `audit.db`:
   `agents(id, name, vendor, exe_path, sha256, signer, user, first_seen, last_seen, status: approved|unknown|blocked)`.
   - New exe+hash **not seen before** → alert **"New AI agent detected"**.
   - Known agent whose **hash changed** → alert "Agent updated/changed" (catches a replaced binary).
4. **Config scan (every few minutes, S4):** list each agent's MCP servers and flag **auto-approve / skip-permissions** modes. Defender treats those as the main risk indicator.
5. **UI:** a tray submenu **"🤖 AI Agents (N running)"** listing what's running, with an alert toast for new or unknown ones. Actions: *Approve* (trust this exe+hash), *Ignore*, and *Open file location*. **No auto-kill** in phase 1: alert only, as Defender's discovery does.

### Phase 2: real-time and Windows-native (admin, via the scheduled task)
- **Process start events:** Kernel-Process ETW, so short-lived agents aren't missed. Alternatives:
  - **Sysmon**: read its event log if installed. This is the least code.
  - **WMI** `__InstanceCreationEvent` via go-ole, already an indirect dependency.
- **DNS attribution:** Sysmon Event 22 (has ProcessId + QueryName) or DNS-Client ETW. This gives a precise "which process talked to which LLM host" (S6).
- **Windows agentic features:** watch for agent accounts and the ODR (`odr.exe mcp`) list of registered connectors (S7).

### Phase 3 (optional)
- Opt-in hooks for Claude Code / Copilot CLI that write each tool call to DevShield's events folder (S9).
- Policy: per-agent *allow / alert / block*, with block meaning a firewall rule on the exe or killing the process after confirmation.

## 5. Important caveats
- **Licensing:** the pure-Go ETW library `0xrawsec/golang-etw` is reportedly **GPL-3.0**. DevShield is **Apache-2.0**, so linking it would force GPL. The other popular one, `bi-zone/etw`, needs **CGO**. The options are to write a small ETW consumer with `golang.org/x/sys/windows`, use Sysmon, or use WMI. Verify both licences before choosing.
- **False positives:** `node.exe`, `python.exe` and `Code.exe` run lots of non-agent work, so always decide on the **command line + parent + behaviour**, never the name alone. Start with *alert*, not *block*.
- **Blind spots:**
  - Agents inside **WSL** (only `wsl.exe`/`vmmem` are visible; Defender covers some WSL agents in preview).
  - Agents inside **Docker**.
  - **Browser-extension** agents (they run inside `chrome.exe`/`msedge.exe`).
  - **Renamed binaries** (caught only by hash + behaviour).
  - Remote agents driving the PC over RDP/SSH.
- **Privacy:** command lines can contain secrets (API keys, tokens). Store them locally only, and redact key-like strings before writing to `audit.db`.
- **Unverified details to check on Windows:** exact process names and paths per agent, the Cursor global MCP path, Jan's port, `odr.exe` command syntax, and DNS-Client ETW event IDs and fields.

## 6. How this fits the current DevShield code
- It *replaces* the broken PowerShell guardian loop for agent work, in the more robust Go process (see the review notes, C5).
- It reuses what exists: gopsutil (`context.go`), SQLite `audit.db` (`audit.go`), the tray badge and callbacks (`watchdog.go`, `tray.go`), and the JSON-catalog pattern (`blocklist_bundled.json`).
- It should come **after** the step-1 fixes from `docs/REVIEW_NOTES_2026-10-20.md`, especially C7 (Quit deadlock) and the audit timestamp issue, since this feature writes to the same DB.

---

## Sources
- Microsoft Learn: [Discover local AI agents with Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents)
- Microsoft Learn: [Local AI agent discovery overview](https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview)
- Microsoft Learn: [Defender for Endpoint AI agent support matrix](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix)
- Microsoft Learn: [AI agent runtime protection (preview)](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview)
- Microsoft Support: [Experimental agentic features (agent workspace, agent accounts, ODR)](https://support.microsoft.com/en-us/windows/ai/ai-features/experimental-agentic-features)
- [Windows On-Device Registry for AI agents explained](https://www.paperclipped.de/en/blog/windows-on-device-registry-ai-agents-mcp/), [Getting started with MCP on Windows](https://nicksnettravels.builttoroam.com/getting-started-with-mcp-on-windows/), [Petri: Windows 11 agentic computing](https://petri.com/windows-11-agentic-computing-workspaces/)
- OWASP Agentic Top 10 summaries: [ASI10 Rogue Agents](https://guptadeepak.com/agent-security/threats/asi10/), [Cycode overview](https://cycode.com/blog/owasp-top-10-agentic-applications/), [HUMAN Security](https://www.humansecurity.com/learn/blog/owasp-top-10-agentic-applications/)
- [Pillar Security: AI coding agent security tools (2026)](https://www.pillar.security/blog/best-ai-coding-agent-security-tools-for-the-enterprise-2026), [Langfuse: tracing coding agents](https://langfuse.com/resources/engineering/coding-agent-tracing), [Help Net Security: Agent Beacon](https://www.helpnetsecurity.com/2026/06/22/agent-beacon-open-source-telemetry-layer-ai-agents/), [ATEN](https://www.antonlovesdnb.com/blog/aten), [Monad: Codex OTel detection](https://www.monad.com/blog/detection-engineering-for-openai-codex-otel)
- [GBHackers: coding agents trigger cyberattack-like telemetry](https://gbhackers.com/claude-code-cursor-and-openai-codex-trigger-cyberattack/), [DEV: your coding agent trips EDR rules](https://dev.to/terminalblog/beware-your-coding-agent-trips-the-same-edr-rules-built-to-catch-attackers-5055), [DPAPI abuse in Claude Code and Cursor triggers EDR](https://gridthegrey.com/posts/ai-coding-agents-trigger-edr-rules-via-dpapi-and-lolbas/)
- ETW / process monitoring: [Velociraptor process-creation artifact](https://docs.velociraptor.app/artifact_references/pages/windows.events.processcreation), [Velociraptor Kernel-Process ETW](https://docs.velociraptor.app/artifact_references/pages/windows.etw.kernelprocess), [Microsoft Process_V2 class](https://learn.microsoft.com/en-us/windows/win32/etw/process-v2), [0xrawsec/golang-etw](https://github.com/0xrawsec/golang-etw), [bi-zone/etw fork (Nubeva)](https://pkg.go.dev/github.com/Nubeva/etw)
- DNS attribution: [Sysmon Event ID 22](https://system32.eventsentry.com/sysmon/event/22), [Velociraptor Windows.ETW.DNS](https://docs.velociraptor.app/artifact_references/pages/windows.etw.dns/)
- MCP config locations: [MCP client configuration guide](https://glama.ai/mcp/servers/@ethanolivertroy/fedramp-docs-mcp/blob/9894fdf8b2e0437f7ac9dd1eef3361cf01462ec2/docs/guides/mcp-clients.md), [Add MCP server to AI coding CLIs](https://inventivehq.com/blog/add-mcp-server-to-ai-coding-cli)
- Local LLM ports: [Ollama port 11434](https://pinggy.io/know_your_port/localhost_11434/), [Ollama vs LM Studio vs llama.cpp](https://www.centron.de/tutorials/ollama-vs-lm-studio-vs-llama-cpp)
- LLM endpoint detection: [Aurva shadow AI detection](https://docs.aurva.io/v1.0/product/ai-security/shadow-ai-detection), [BeyondTrust LLM endpoint visibility](https://docs.beyondtrust.com/bt-docs/docs/visibility-llm-endpoints)
