# DevShield: Competitive Landscape, the Frontier, and a Path to "Best"

Date: 2026-10-20. Based on web research (sources at the end) plus checks run on this repo. Vendor comparisons are often self-serving and are marked as such.

## 1. Is there a product like DevShield?

**No single product combines what DevShield aims to do:** owner-controlled monitoring of AI agents + telemetry/privacy hardening + network control + system tuning, for an individual developer, on their own machine. Strong products exist in **each piece separately**:

| Area | Best in class (2026) | Platforms | Model | What it means for DevShield |
|---|---|---|---|---|
| **AI agent inventory** | **Microsoft Defender for Endpoint, local AI agent discovery** (~60 agents, MCP servers, auto-approve risk) | Windows, macOS (preview) | Enterprise licence (Plan 2 / E7). Reports to the *company*, not the machine's owner | Proves the need. Out of reach for individuals, and identifies agents mostly from a known list |
| **AI agent tool-call visibility** | **Falco "Prempti"** (May 2026; Falco meets coding agents); AgentSight + Cilium Tetragon (eBPF, independent of agent self-report) | Linux | Open source | The technical frontier: kernel-level, can't be lied to by the agent. Linux/server-oriented, needs expertise |
| **Agent sandboxing / confinement** | Nono, Zerobox (built on Codex's sandbox), Sandlock (research: unprivileged Linux primitives) | Linux/macOS mainly | Open source, young | *Prevention* rather than detection. Complements DevShield |
| **MCP / agent gateways** | Bifrost (Apache 2.0), MCPX (MIT), IBM ContextForge, Obot, Pipelock (agent egress firewall) | Server-side | Open source + enterprise tiers | Policy on what agents can call. Relevant to the future "Allow/Charge" gateway |
| **Per-app network firewall** | **Portmaster** (Safing; open source; free + paid ~€4+/month; v2.x 2026), OpenSnitch (Linux, eBPF), LuLu (macOS) | Win+Linux / Linux / macOS | Free/OSS, Portmaster freemium | Mature and polished. DevShield should **not** try to out-build them; integrate or stay complementary |
| **Windows telemetry/privacy tweaks** | **privacy.sexy** (open source, cross-platform), O&O ShutUp10++ (polished, closed source), WindowsSpyBlocker (network level); WPD is stale | Windows (privacy.sexy also Linux/macOS) | Free | Crowded and mature. DevShield's sinkhole is a small part of this space |
| **Persistence (auto-start) monitoring** | Objective-See **BlockBlock**, KnockKnock (macOS); Autoruns (Windows) | macOS / Windows | Free/OSS | DevShield's auto-start rogue indicator is a narrow version. Good model for macOS later |
| **Thermal/power tuning** | ThrottleStop, Fan Control (Windows); TLP, auto-cpufreq, power-profiles-daemon (Linux) | — | Free | Mature. DevShield's profiles are convenience, not differentiation |

**Closest overall analog:** **Portmaster.** It's open source, Windows + Linux, sovereignty-flavoured, and funded by paid tiers, which is a realistic business-model reference for DevShield. But it is a network firewall, with no AI-agent awareness.

**Which is "best"?** It depends on the job:
- For **agent inventory**: Defender (enterprise).
- For **ground-truth agent behaviour**: Falco/Tetragon (Linux).
- For **network control**: Portmaster / OpenSnitch / LuLu.
- For **privacy tweaks**: privacy.sexy.

## 2. DevShield's honest position

**What's genuinely distinctive:**
1. **Behaviour-first rogue-agent detection for individuals**: works on undocumented/renamed agents, no licence, no fleet, decisions owned by the machine owner.
2. **Owner-sovereignty model** (Block → Allow with signed permission → Charge). Nobody packages this for a single developer.
3. **Linux + Windows from one Go core, light footprint** (measured 0.37% of one core, ~1.8 MB heap).

**What's weak today (must be fixed before claiming "best"):**
- The Windows PowerShell features mostly don't work as wired (see `REVIEW_NOTES_2026-10-20.md`).
- Nothing has run on real Windows yet.
- Detection polls every 0.5 s and can miss very short commands. Kernel-level tools (eBPF/ETW) don't have this gap.
- **Tamper exposure (important).** The sanction list, catalog override and audit log live in `~/.devshield`, writable by the same user any agent runs as. **A rogue agent could sanction itself, edit the catalog, delete its own alerts, or simply kill DevShield.** A security tool must not let the thing it watches change its rules.
- **Build hygiene.** The scanner `govulncheck` reports **35 reachable Go standard-library vulnerabilities**, because the code is built with Go 1.24.7 here and the release pipeline pins **Go 1.22 (out of support)**. Shipping today would ship known CVEs. The race detector is clean.

## 3. The frontier (where the best products are heading)
1. **Ground truth from the kernel, not self-reports**: eBPF on Linux (Falco Prempti, Tetragon, AgentSight), ETW on Windows, Endpoint Security framework on macOS. Agents' own telemetry/hooks are useful but can be wrong or disabled.
2. **Prevention, not just detection**: sandboxed agent launch (Landlock/seccomp/namespaces on Linux, AppContainer on Windows, Seatbelt on macOS), per-agent egress control.
3. **Pre-action authorization**: a policy decision *before* each tool call or sensitive action. MCP gateways and research such as deterministic pre-action authorization.
4. **Agent identity**: signed agent identity (Web Bot Auth, hardware-backed keys) and signed user mandates (AP2), so "who allowed this agent to do that" is provable.
5. **OS-native agent governance**: Windows agent workspace, agent accounts and the On-Device Registry for MCP connectors.

## 4. How to push DevShield to the most secure and robust version

Ordered by value. Each item has a test or measurable check.

**A. Make DevShield tamper-resistant (highest priority)**
1. **Split privilege.** A root/SYSTEM daemon owns the policy (sanctions, catalog, audit log) in a root-only location (`/var/lib/devshield`, `%ProgramData%` with tight ACLs). The tray/CLI runs as the user and *requests* changes over an authenticated local channel: a Unix socket checked with `SO_PEERCRED`, or a Windows named pipe with an ACL. A user-level agent can then no longer approve itself.
2. **Sanctioning needs the human.** Approval goes through a prompt that only the interactive user can answer (polkit on Linux, the secure desktop/UAC on Windows). An agent can't click it for itself.
3. **Tamper-evident audit log.** Hash-chain every event (each record includes the hash of the previous one), and optionally sign it. Deletion or edits become detectable.
4. **Self-protection.** The daemon is a supervised service (systemd `Restart=always` / Windows service recovery). The UI alerts if the daemon stops. Unexpected stops are themselves audit events.

**B. See everything (close the detection gaps)**
5. **Event-based process capture.** On Linux, use the netlink process connector or fanotify (no eBPF needed), then eBPF for syscalls and network. On Windows, use ETW Kernel-Process. This catches commands shorter than 0.5 s. Optionally ingest Falco/Sysmon events when they are installed, rather than reinventing them.
6. **Identify shells and terminals by path and hash, not by name**, so a rogue named `bash` can't hide its agent loop.
7. **DNS attribution** (which process resolved which LLM/payment host) instead of IP matching alone.

**C. Prevent, opt-in**
8. **Enforcement modes per agent: alert → block network → block run.** Linux: nftables per-cgroup/UID egress rules. Windows: firewall rules per program. Every block is reversible and logged.
9. **`devshield run -- <agent>`**: launch sanctioned agents in a least-privilege sandbox (Landlock + seccomp on Linux; AppContainer/job objects on Windows) with only the project folder writable.

**D. Supply chain and build integrity**
10. **Build with a current, patched Go**, and add `govulncheck`, `go vet`, `staticcheck` and `go test -race` to CI on Linux and Windows. The release fails on reachable vulnerabilities.
11. **Signed releases and signed catalog/blocklist updates** (cosign/minisign, ed25519). The app refuses unsigned updates. Add an SBOM and reproducible builds.
12. **Fuzz the parsers** that read attacker-influenced data: the catalog JSON, `/proc/<pid>/stat`, `.lnk` bytes, command-line splitting, autostart files.

**E. Proof, not promises**
13. An **adversarial test suite** in CI: renamed agents, masquerading binaries, shell-laundered recon, self-sanction attempts, killing DevShield, LD_PRELOAD tricks. Every rogue technique we claim to catch has a test that runs it.
14. **Resource budgets enforced in CI**: idle CPU < 0.5% of one core, RSS < 30 MB, measured on every change.
15. Publish a **threat model** (what DevShield defends against, and what it doesn't: kernel-level malware, root-level attackers, agents in VMs) so users can trust the claims.

**Realistic verdict:** DevShield can become **the best owner-controlled AI-agent shield for individual developers on Linux and Windows**, a niche nobody currently serves well. It should **not** try to beat Portmaster, Falco or privacy.sexy at their own jobs. Interoperate with them where useful. Items A1–A4 and D10 should come first, because a security tool that can be switched off or rewritten by what it watches can't honestly claim to be secure.

---

## Sources
- Microsoft Learn: [Discover local AI agents (Defender for Endpoint)](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents), [AI agent support matrix](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix)
- Falco: [Falco turns 10 (Prempti announcement)](https://www.sysdig.com/blog/falco-turns-10-congratulations-from-sysdig), [falco.org](https://falco.org/tags/syscalls/)
- [eBPF runtime observability for Codex CLI: AgentSight, Tetragon](https://codex.danielvaughan.com/2026/06/09/ebpf-runtime-observability-codex-cli-agentsight-tetragon-kernel-level-agent-monitoring/) (single blog post)
- [AppScale: what the kernel sees that agents cannot (Falco, Tetragon 2026)](https://appscale.blog/he/blog/ebpf-runtime-security-what-kernel-sees-that-agents-cannot-falco-tetragon-2026)
- Agent sandboxes and gateways: [Sandlock (arXiv)](https://arxiv.org/pdf/2605.26298), [Deterministic pre-action authorization (arXiv)](https://arxiv.org/pdf/2603.20953), [Formal security framework for MCP agents (arXiv)](https://arxiv.org/pdf/2604.05969), [Maxim: open-source MCP gateways](https://www.getmaxim.ai/articles/best-open-source-mcp-gateway-for-secure-ai-agent-access-2026/), [Obot: 13 MCP gateways compared](https://obot.ai/blog/the-13-best-mcp-gateways-for-enterprise-teams/) (vendor), [Lunar: open-source MCP gateways](https://www.lunar.dev/post/the-best-open-source-mcp-gateways-in-2026) (vendor), [GitHub topic: mcp-security](https://github.com/topics/mcp-security)
- Portmaster: [The New Stack](https://thenewstack.io/portmaster-an-open-source-firewall-for-the-desktop/), [LinuxLinks](https://www.linuxlinks.com/portmaster-application-firewall/), [Portmaster 2026 release](https://www.warp2search.net/story/safing-portmaster-2026-released/), [comss.ru catalog (2.1.19, pricing)](https://www.comss.ru/page.php?id=11111)
- OpenSnitch: [2026 review](https://www.kunalganglani.com/blog/littlesnitch-linux-opensnitch-review.md), [Debian eBPF modules manpage](https://dyn.manpages.debian.org/testing/opensnitch-ebpf-modules/opensnitch-ebpf-modules.1)
- Objective-See: [Tools](https://objective-see.org/tools.html), [LuLu](https://objective-see.org/products/lulu.html)
- Windows privacy tools: [Privacy Guides discussion](https://discuss.privacyguides.net/t/best-tool-to-disable-telemetry-on-win11/18516?page=2), [AlternativeTo: ShutUp10++ alternatives](https://alternativeto.net/software/shutup10/), [AlternativeTo: WPD](https://www.alternativeto.net/software/wpd/)
- Agent security vendors: [Pillar Security 2026 overview](https://www.pillar.security/blog/best-ai-coding-agent-security-tools-for-the-enterprise-2026) (vendor)
