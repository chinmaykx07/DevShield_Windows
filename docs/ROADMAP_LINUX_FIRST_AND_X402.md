# DevShield Roadmap: Linux-first, Windows + Linux variants, x402

Date: 2026-10-20
Status: decisions taken 2026-10-20 (section 7). Section 8 covers the owner-sovereignty / "they pay us" vision.

---

## 1. Ground rules (so the project stays honest and accurate)

1. **No claim without evidence.** A feature is "done" only with a test, plus a real-machine check on each OS it claims to support. Docs say "not tested on X" until it is. (Today: nothing has been run on real Windows. See `REVIEW_NOTES_2026-10-20.md`.)
2. **Fix before extending.** The critical review findings (C1–C8) block their features. New features don't paper over broken ones.
3. **Measure, don't guess.** Every background loop has a measured CPU/memory cost, and a budget it must stay under (section 3).
4. **Alert, don't act, by default.** Anything that changes the system must be reversible, with rollback tested, and opt-in.
5. **User data stays on the machine.** No telemetry, ever. This matters for any x402 idea (section 6).

## 2. Where the project actually is

| Area | State |
|---|---|
| Go tray core | Builds and vets for Windows and Linux. 21 unit tests. Quit deadlock fixed. |
| Agent Watch (AI/rogue agents) | Built behaviour-first. Tested on Linux, live rogue test passes. **Not run on Windows.** |
| PowerShell features (profiles, privacy, Tor, guardian, rollback, dashboard) | **Windows-only and largely non-functional as wired.** Tasks never register, prompts block, rollback restores nothing, the guardian crashes, the Tor kill-switch blocks nothing. See the review notes. |
| Linux support | Agent Watch collectors only. Everything else is Windows-specific. |
| Packaging | Windows Inno Setup + winget manifests (installer is never built by CI). Nothing for Linux. |

## 3. Efficiency: measured, with budgets

Measured in this container (78 processes):

| What | Before | After | Note |
|---|---|---|---|
| Agent Watch avg CPU | 2.9% of one core | **0.37%** | Linux fast tick reads `/proc/<pid>/stat` only for new PIDs |
| Agent Watch fast tick (every 0.5 s) | 13.7 ms | **0.31 ms** | ~44× less work |
| Agent Watch full scan (every 10 s) | — | 25.7 ms | cmdline/env/user cached per process lifetime |
| Go heap | — | **1.8 MB** | 13.5 MB reserved from the OS |
| **One PowerShell action** | — | **~400 ms warm, ~6.5 s cold, ~94 MB RAM** | Paid on *every* tray click, plus the script's own work |

**Budgets for the tray/daemon at idle:** < 0.5% of one core, < 30 MB RSS, no process spawned in steady state.

**Biggest efficiency win available:** move the PowerShell features into Go. Each action drops from hundreds of ms and ~94 MB to a few ms and no extra process. It also makes the Linux port possible, because the PowerShell scripts call Windows-only APIs throughout.

## 4. Architecture: one Go codebase, two variants

```
cmd/devshield/            tray app + headless daemon/CLI (same binary)
internal/agentwatch/      detection (pure, shared) — today's agentwatch*.go
internal/audit/           SQLite audit log — today's audit.go
internal/platform/        one interface per capability, two backends:
    thermal   sensors   hosts   firewall   autostart   privileged-helper
    ├── linux/    sysfs, /etc/hosts, nftables, systemd
    └── windows/  powercfg, LHM/WMI, hosts, Windows Firewall, Task Scheduler
packaging/                .deb/.rpm/tarball + systemd units (Linux);
                          Inno Setup + winget (Windows)
```

- **Shared:** detection logic, audit log, rollback format, catalog, UI strings.
- **Per-OS:** only the thin backend that touches the system, selected with Go build tags (the pattern `agentwatch_linux.go` / `agentwatch_windows.go` already uses).
- **Headless mode matters on Linux.** Rogue agents are most likely on dev boxes, CI runners and servers, which have no tray. So `devshield daemon` (a systemd service) plus `devshield agents` / `devshield status` (CLI) come first. The tray is a front-end to the daemon.
- **Privilege model:** a small root helper (systemd service on Linux; on Windows, today's scheduled-task idea, fixed) does privileged actions on request. The tray/CLI runs as the user. That replaces the PowerShell + UAC fallback mess.

### Linux equivalents, feature by feature

| Feature | Windows today | Linux backend | Difficulty |
|---|---|---|---|
| Agent Watch | ✅ (untested) | ✅ built: `/proc`, maps, systemd/XDG autostart | Done; tune |
| Sensors | LibreHardwareMonitor (downloaded) | `/sys/class/hwmon`: native, **no download** | Low |
| Thermal profiles | powercfg via PowerShell | cpufreq sysfs (`scaling_max_freq`, boost / `intel_pstate/no_turbo`), or power-profiles-daemon over D-Bus | Medium (needs root helper) |
| Network monitor | PowerShell job (broken) | Go: already in Agent Watch's connection scan | Low |
| Hosts sinkhole | hosts file | `/etc/hosts`, same format, same code | Low |
| Telemetry tweaks | Registry | Distro-specific (apport, ubuntu-report, popcon); small scope | Low |
| Tor kill-switch | Allow rules only (doesn't block) | **nftables with owner match.** A real kill-switch is easier on Linux | Medium |
| MAC randomisation / LLMNR | Registry | NetworkManager settings, systemd-resolved `LLMNR=no` | Low |
| Rollback | JSON + PowerShell (broken) | Same JSON format, restore in Go, shared | Medium |
| Dashboard | PowerShell TUI | Go TUI/CLI, shared | Medium |
| Tray | fyne systray | StatusNotifierItem (KDE, most desktops; GNOME needs the AppIndicator extension) | Low |
| Packaging | Inno Setup / winget | GoReleaser + nfpm → .deb/.rpm/tar.gz, systemd units | Low |

### Suggested phases
1. **L1 (Linux core):** restructure into packages. Ship `devshield daemon` + CLI with Agent Watch, network view, sensors and the audit log. Package as .deb/.rpm. CI runs tests on Linux and Windows. **This is a usable product: rogue-agent monitoring for Linux dev machines and servers.**
2. **L2 (Linux hardening):** root helper; hosts sinkhole; nftables kill-switch; thermal via sysfs; rollback in Go with tests.
3. **W1 (Windows parity):** Windows backends in Go behind the same interfaces. Retire the PowerShell scripts one by one, which fixes C1–C8 by replacement. Then real-Windows testing.
4. **Both:** event-based process capture for Agent Watch: Linux fanotify/netlink proc connector or eBPF; Windows ETW. That catches commands shorter than 0.5 s.

## 5. Known detection gaps (stated plainly)
- Polling misses very short commands (Phase 4 fixes this).
- An agent using an unknown relay, with no keys in its environment and no tool loop, stays below threshold.
- Shells and terminals are recognised by **name**, so a rogue named `bash` evades the agent-loop signal. Its other signals still count. Fix by checking the executable path or hash, not just the name.
- Agents inside containers/VMs/WSL and inside browsers are not visible.

## 6. x402: what it is, realistic earning, and the honest fit

**What it is.** An open protocol that revives HTTP `402 Payment Required`:
1. The server replies 402 with a price.
2. The client signs a stablecoin payment authorization (mostly USDC, mostly on Base or Solana) and retries.
3. A *facilitator* verifies and settles on-chain.

It was started by Coinbase and is now governed by an x402 foundation. It has Go seller middleware (`github.com/coinbase/x402/go`, Gin/Echo adapters), and its main audience is **AI agents paying for APIs**.

**The market, honestly:**
- Headline counts are large: ~138–191M transactions. But dollar volume is small (~$15M–$42M cumulative, depending on filtering).
- An estimated 25–50% of activity is leaderboard/"gamified".
- One 30-day snapshot: ~1,400 active sellers sharing ~$65K, about **$47 per seller per month** on average, with revenue concentrated in a few sellers.

**Risks:**
- Payments are irreversible.
- A May 2026 preprint describes five attacks on the protocol.
- Prompt injection can push agents to pay attacker wallets.
- Holding keys or funds adds custody, tax and regulatory questions.
- A privacy/security tool that adds crypto payments can lose user trust.

**Options for DevShield, ranked:**

| # | Idea | Fit with mission | Earning potential | Recommendation |
|---|---|---|---|---|
| A | **Agent Spend Watch:** extend Agent Watch to detect agents that can *spend money*. Signals: wallet keys/x402 SDK in env or cmdline, connections to facilitators and chain RPCs, x402 libraries loaded. Flag unsanctioned spenders as rogue. | **Excellent.** "A rogue agent draining a wallet" is exactly this product's problem. | Indirect. A strong differentiator for a paid/pro tier or sponsorship. | **Do first.** Small, defensive, no money handling. |
| B | **Sell a curated feed via x402:** agent catalog + rogue indicators + telemetry blocklist updates, pay-per-call (e.g. $0.001–$0.01) from a small hosted API using the Go middleware. | OK, if it sells *our curated data* and **never user data**. | Low (see averages above); needs hosting and upkeep. | Experiment later. Keep it optional; the app must work fully without it. |
| C | DevShield itself paying via x402 (e.g. for premium feeds) | Weak; brings wallets into a security tool | None | **Don't.** |
| D | Donations/pro licence via x402 | Possible | Low; GitHub Sponsors is simpler | Optional, low priority |

**Bottom line:** x402 is a better **security problem to solve** (agents with wallets) than a **revenue stream**. Option A fits DevShield's purpose and costs little. Option B can be tried later as a small experiment with honest expectations: tens of dollars a month unless the feed becomes widely used.

## 7. Decisions (taken 2026-10-20)
1. **Linux v1 = full feature parity before release.** All features get Linux backends in Go (thermal, sensors, network monitor, hosts sinkhole, a real nftables kill-switch, rollback, dashboard/CLI, tray + headless daemon). Phases L1 and L2 above merge into one release.
2. **Windows keeps PowerShell, fixed in place.** The review findings C1–C8 get fixed in the existing scripts. Linux gets its own Go backends, so there are two implementations of the system-changing features. The shared Go core (Agent Watch, audit, tray) stays common.
3. **Order: Linux → Windows → macOS.** The repo keeps its name `DevShield_Windows`.
4. **x402: see section 8.** The goal is owner sovereignty, not x402 for its own sake.

### Progress (2026-10-20)
- ✅ Foundation: patched Go toolchain + CI verify job (vet, race tests, govulncheck; 35 → 0 reachable vulnerabilities).
- ✅ Hash-chained audit log (`internal/auditlog`).
- ✅ Root daemon + kernel-authenticated socket + CLI (`internal/daemon`, `internal/ipc`, `cli.go`). A non-root self-sanction is refused and logged. Verified live with real users.
- ✅ Hardened systemd unit (`packaging/linux/devshield.service`). Not yet run under systemd.
- ✅ Sensors from hwmon/thermal zones (`internal/sensors`, `devshield sensors`): no download, no root.
- ✅ Thermal profiles via cpufreq/boost/EPP/platform_profile (`internal/thermal`, `sudo devshield profile …`), with a pre-change baseline, all-or-nothing apply, read-back verification and exact restore. Tested on simulated sysfs layouts and through the daemon. **Not yet on real hardware.**
- ✅ Telemetry sinkhole (`internal/hosts`, `devshield sinkhole on|off`): managed block only, user entries preserved, whole-list re-apply (fixes the Windows drop bug), honest status. Verified live on a real resolver.
- ⏭ Next: nftables kill-switch (a real one: per-program egress block) → Linux tray → .deb/.rpm.

### Revised phases
- **Phase L (Linux, full parity):** root helper (systemd) · sensors (hwmon) · thermal (cpufreq/boost) · hosts sinkhole · nftables kill-switch + LLMNR/MAC · network monitor · rollback in Go with tests · Agent Watch · daemon + CLI + tray · .deb/.rpm packaging · CI on Linux.
- **Phase W (Windows):** fix C1–C8 in the PowerShell scripts, run on a real Windows machine/VM, test Agent Watch on Windows, ship the installer from CI.
- **Phase M (macOS):** later. Note the tray library needs CGO on macOS.

## 8. The vision: the owner is the sole sovereign of the machine

> Everything that runs on the system runs by the owner's permission. Even Microsoft and other enterprises must not run agents or take control without it, and if they want to, they should pay.

**The honest technical truth:** a payment protocol only works when the *payer chooses to pay*. x402, L402 and Cloudflare's pay-per-crawl all work the same way: someone **asks your server for something**, and you answer "402: pay first", or refuse. That gives two very different cases:

| Situation | Can we make them pay? | What actually works |
|---|---|---|
| Code **already running on your machine** (Windows telemetry, Copilot/agent features, vendor updaters, a rogue agent) | **No.** It isn't asking you for anything; it's sending data out or acting locally. No protocol can bill it. | **Deny by default**: detect, alert, block (hosts, firewall, disabling services/agents, Agent Watch). Sovereignty is enforced by *refusing*, not by *charging*. |
| An **outside agent that wants something from your machine**: your files, tools (MCP), data, GPU/compute, an API you run | **Yes, if it goes through a gate you control.** | A DevShield **gateway** in front of those resources: per agent, **Allow / Charge / Block** (the same model Cloudflare uses for crawlers). "Charge" answers 402 with an x402 price. |

So DevShield can deliver the vision as a **permission model with three answers**:
1. **Block**: anything unsanctioned (today's Agent Watch, telemetry sinkhole, firewall).
2. **Allow**: what the owner sanctioned, with proof (see AP2 below).
3. **Charge**: outside agents that want access to resources the owner chooses to expose, paid per request via x402.

**Is there something better than x402?** (Researched October 2026; most comparisons are vendor-written.)
- **x402** (Linux Foundation governance since April 2026, USDC on Base/Solana): **the best fit for "Charge"**. Per-request, machine-to-machine, the most adoption, Go middleware exists, and Vercel's `x402-mcp` already paywalls MCP tool calls.
- **L402** (Lightning/Bitcoin): same idea in sats, far less activity. An optional second rail at most.
- **AP2** (Google, moved to the FIDO Alliance in 2026): moves **no money**. It produces *signed mandates proving a user authorized an agent's action*. This is the closest match to **"runs by the owner's permission"**: DevShield could issue signed, revocable permission mandates to sanctioned agents, and treat any agent action without one as unsanctioned. Worth adopting for **Allow**.
- **ACP** (OpenAI/Stripe) and **Stripe MPP / Visa TAP**: shopping checkout and card-network agent identity. Not a fit for charging agents per access.
- **Web Bot Auth** (signed agent identity, used with pay-per-crawl): useful so a "Charge"/"Allow" decision can't be dodged by an agent pretending to be another.
- **Paid-consent data marketplaces** (Killi, PolySwarm-style): the only route where vendors pay *users* for telemetry, and only if the vendor joins voluntarily. Microsoft won't pay individuals, so blocking remains the realistic answer for OS telemetry.

**Where money can realistically come from:**
1. **People and companies paying for the shield itself.** A Pro tier, and especially **team/fleet monitoring of rogue agents** on dev machines, CI runners and servers. Organisations already pay for agent governance (Microsoft sells exactly this inside Defender for Endpoint Plan 2 / E7). This is the strongest, most dependable revenue.
2. **The Charge gateway (x402).** Real but small per seller today (≈$47/month average). It grows only if the owner exposes something valuable, such as GPU compute or curated data. DevShield could take a small fee on payments through its gateway, or sell the gateway in the Pro tier.
3. **Curated threat-intel feed via x402** (option B above): optional, small.

**Proposed build order for the vision:** Block (Linux parity, Phase L) → Allow with signed permission mandates (AP2-style) → Charge gateway for MCP/API/compute with x402. Each step stands on its own, so nothing depends on x402 volume growing.

---

## Sources (x402)
- [Wikipedia: x402](https://en.wikipedia.org/wiki/X402)
- [Allium: x402 explained](https://www.allium.so/blog/x402-explained-the-internet-native-payments-standard-for-apis-data-and-agent-commerce/)
- [Eco: x402 protocol explained](https://eco.com/support/en/articles/14839402-x402-protocol-explained)
- [Wavect: x402 payments in 2026 compared](https://wavect.io/blog/x402-payments-comparison-2026/)
- [Coinbase CDP: x402 quickstart for sellers](https://docs.cdp.coinbase.com/x402/quickstart-for-sellers)
- [pkg.go.dev: coinbase/x402 Go Echo middleware](https://pkg.go.dev/github.com/coinbase/x402/go/http/echo)
- [Agent Economy: x402 settlement tracker](https://agenteconomy.to/x402)
- [CURB: the x402 economy, July 2026](https://curb.numetal.xyz/dispatch/x402-economy-july-2026)
- [Daniel McGlynn: x402 volume numbers are wrong](https://www.danielmcglynn.com/the-x402-counter-has-shown-the-same-four-numbers-since-march/)
- [x402 Inc.: 3.69M transactions and $1.11M volume breakdown](https://note.com/x402inc/n/nfd6227f13b55?hl=en-US)
- [CoinCentral: x402 passes 138M transactions](https://coincentral.com/ai-agents-gain-ground-as-x402-passes-138-million-transactions214628-2)
- [Halborn: x402 security risks and controls](https://www.halborn.com/blog/post/x402-explained-security-risks-and-controls-for-http-402-micropayments)
- [CryptoDaily: x402 AI-agent payment bugs](https://cryptodaily.co.uk/2026/06/x402-security-ai-agent-payment-bugs)
- [DEV: x402/AP2/UCP are not your spending policy](https://dev.to/suraj_khaitan_f893c243958/your-ai-agent-can-pay-now-x402-ap2-and-ucp-are-not-your-spending-policy-3l25)

## Sources (alternatives and the "charge" model)
- [Agent payment protocols tracker: x402 vs AP2 vs ACP vs L402](https://github.com/Pink-Agentic-Payments/agent-payment-protocols-tracker)
- [ArchitectureDiagram.ai: AP2, x402 and ACP compared](https://architecturediagram.ai/blog/agent-payment-protocols-architecture)
- [Pondero: x402 vs ACP vs AP2 (October 2026)](https://pondero.ai/agents/guides/x402-vs-acp-vs-ap2-agent-payment-protocols-october-2026/)
- [AgentLux: x402 vs AP2 vs MPP vs ACP](https://agentlux.ai/blog/the-agent-payments-showdown-x402-vs-ap2-vs-mpp-vs-acp-in-2026)
- [HyperTrends: x402 vs ACP vs AP2 vs TAP](https://www.hypertrends.com/2026/04/agentic-payments-x402-acp-ap2-tap-comparison/)
- [Wikipedia: Agentic commerce](https://en.wikipedia.org/wiki/Agentic_commerce)
- [Vercel: x402-mcp, x402 payments in MCP](https://vercel.com/changelog/402-mcp-enables-x402-payments-in-mcp)
- [Engadget: Cloudflare will block AI scrapers unless they pay](https://engadget.com/ai/cloudflare-experiment-will-block-ai-bot-scrapers-unless-they-pay-a-fee-121523327.html)
- [Measure Minds: Cloudflare pay per crawl](https://measuremindsgroup.com/cloudflare-pay-per-crawl)
- [PolySwarm: paying users for telemetry](https://blog.polyswarm.io/telemetry-new-utility-use-for-nectar-nct)
- [Future Agenda: data dividend](https://futureagenda.org/insights/data-dividend)
