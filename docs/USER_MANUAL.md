# DevShield User Manual

This is the complete reference for using DevShield safely and, once you're comfortable, powerfully. Read Section 1 and 2 fully before your first real use. Sections 3 and 4 are there when you need them.

---

## 1. Before You Start

### What DevShield changes on your system

| Area | What changes | Controlled by |
|---|---|---|
| Power plan | Boost on/off, frequency cap, processor efficiency class | Thermal profiles |
| Fan curve | Vendor-specific WMI calls where supported | Thermal profiles |
| Hosts file | Telemetry domains redirected to 0.0.0.0 | Privacy enforcer |
| Registry | Privacy-related keys including telemetry and feedback settings | Privacy enforcer |
| Services | DiagTrack (disabled, not deleted) | Privacy enforcer |
| Windows Firewall | Tor kill-switch rules (only if you run Tor hardening) | Tor hardening |
| Task Scheduler | Six tasks under a `DevShield` folder | First run |
| Network monitoring | Read-only monitoring of connections | Network guardian |

Every single one of these is reversible. See Section 4.

### What DevShield will never touch

- Boot configuration
- Driver stack
- WinPE or Recovery partition
- Windows Update infrastructure, which is explicitly whitelisted in the privacy enforcer

---

## 2. Safe Use

### First-run walkthrough

When you first open the tray menu, you will see the main menu with thermal profile choices, privacy, network guardian, dashboard, rollback, language, and quit options.

Recommended first action: open the Dashboard, not a profile. This shows you live sensor data with zero system changes.

```powershell
pwsh -File scripts\monitor\hardware_dashboard.ps1
```

Recommended second action: try one thermal profile. DevShield reads your sensors before and after applying so you are not just trusting that it worked.

### How to read the audit log

Every action DevShield takes is logged. From PowerShell:

```powershell
pwsh -File scripts\profiles\profile_manager.ps1 -History
```

### How to use rollback safely — always dry-run first

```powershell
pwsh -File scripts\hardening\rollback.ps1 -DryRun -All
pwsh -File scripts\hardening\rollback.ps1 -All
pwsh -File scripts\hardening\rollback.ps1 -Last
pwsh -File scripts\hardening\rollback.ps1 -Type privacy
```

### What to do if a profile doesn't apply

1. Check whether the dashboard shows sensor values.
2. Check the audit log for a failed entry.
3. If a profile partially applied, run rollback for the most recent action.

### What to do if you see a guardian alert you don't understand

A guardian alert means a process made a network connection that is neither trusted nor known. This is informational, not a block.

### Watching AI agents and catching rogue ones (Agent Watch)

The tray menu **🤖 AI Agents** lists every AI agent running on this PC, and flags **rogue suspects**. It scans continuously without admin rights.

**Detection is based on behaviour, not names.** A rogue agent won't be in any list, and a bad actor can rename a known one. So a process counts as an AI agent because of what it does:
- it talks to an LLM API or a local model server (Ollama, LM Studio…)
- it has LLM API keys or endpoints set specifically for it (keys set for your whole account are ignored)
- it loads AI model libraries (llama.cpp/ggml, PyTorch, ONNX Runtime…)
- it keeps launching shells and command-line tools: the "agent loop". Tools run through a shell (`agent → pwsh → tool`) count for the agent.

The built-in catalog (Claude Code, Codex, Cursor, Ollama…) only adds a name label. It never makes an agent trusted.

**Rogue indicators** apply to every agent, named or not:
- **undocumented**: matches no catalog entry
- runs from Temp, Downloads, Public or the Recycle Bin
- started with approvals switched off (`--dangerously-skip-permissions`, `--yolo`, `--full-auto`…)
- launched recon, persistence or credential tools (`whoami`, `net`, `schtasks`, `reg`, `certutil`, `cmdkey`…)
- registered to start automatically (Run keys, Startup folder)
- detached: still launching tools after its parent process is gone

| Icon | Verdict | Meaning |
|---|---|---|
| 🚨 | **Rogue suspect** | Not sanctioned, and undocumented or showing rogue indicators. Investigate. |
| ⚠ | **Risky** | You sanctioned it, but it is now showing rogue indicators (e.g. a trusted agent misused). |
| ⚠ | **Unsanctioned** | Known agent, nothing suspicious, not yet approved. |
| ✅ | **Sanctioned** | Approved and behaving normally. |

Hover an entry to see *why* it is considered an agent and which rogue indicators it shows. **Sanction this agent** approves that exact program. Sanctioning clears only the "undocumented" indicator: behavioural indicators still alert, and a changed program file revokes the approval.

Audit events: `AGENT_ROGUE_SUSPECT`, `AGENT_RISKY`, `AGENT_NEW`, `AGENT_UNKNOWN`, `AGENT_CHANGED`, `AGENT_UNSANCTIONED_START`, `AGENT_SANCTIONED`.

**Limits:**
- Agent Watch only alerts. It never stops or blocks anything.
- Without admin it can't fully inspect other users' or elevated processes.
- Commands that finish in well under half a second may be missed, because the process list is sampled every 0.5 s. Event-based capture that catches every process is planned for the admin-mode phase.
- Command lines are redacted (keys and tokens masked) before logging, and environment variable *values* are never stored.

---|---|
| ✅ | Sanctioned. No alerts while its program file stays the same. |
| ⚠ | Known agent, not yet sanctioned. |
| ❓ | Not in the catalog, but behaving like an AI agent (e.g. calling an LLM API and running shells). Check it. |

To approve an agent, open its entry and select **Sanction this agent**. Agent Watch writes an audit event (visible in the audit log) when:
- an agent appears for the first time (`AGENT_NEW`, or `AGENT_UNKNOWN` for ❓ processes)
- a sanctioned agent's program file changes, which removes its approval (`AGENT_CHANGED`)
- an unsanctioned agent starts running again (`AGENT_UNSANCTIONED_START`)

Agent Watch only alerts. It never stops or blocks a process. To recognise an agent it doesn't know yet, copy the built-in catalog to `~/.devshield/agent_catalog.json` and add an entry; that file then replaces the built-in one. Command lines are redacted (API keys and tokens masked) before they are logged.

---

## 2b. Linux: the DevShield daemon (in development)

On Linux, DevShield runs as a **root service** that owns everything an AI agent must not be able to change: the sanction list, the agent database and the **tamper-evident audit log**. All of these live in `/var/lib/devshield`, readable by root only. You use it from the command line:

```bash
devshield status                 # daemon health + audit-log integrity
devshield agents                 # running AI agents and verdicts (🚨 rogue, ⚠ risky/unsanctioned, ✅)
devshield events -n 30           # recent audit events
sudo devshield sanction <ID>     # approve an agent  — needs root
sudo devshield revoke <ID>       # withdraw approval — needs root
sudo devshield verify-log        # check the audit log's hash chain
```

- **Why approving needs `sudo`:** an AI agent runs as *you*. If your user could change the rules, so could the agent. Any non-root attempt to sanction or revoke is refused and logged as `AGENT_TAMPER_ATTEMPT`, naming the program that tried.
- **Who can read:** root, plus the owner set in `/etc/devshield/daemon.env` (`DEVSHIELD_OWNER=alice`). Other local users are refused.
- **The audit log is hash-chained.** Editing, deleting, reordering or truncating records is detected and reported with the exact line. Tampering found at start-up is logged as `AUDIT_TAMPER_DETECTED`. A daemon that was killed, rather than stopped cleanly, shows up as `DAEMON_UNCLEAN_STOP` on its next start.
- **Exit codes for scripts and monitoring:** `status` and `agents` exit with **3** when a rogue or risky agent is running or the log is tampered with.

**Sensors and thermal profiles (Linux):**

```bash
devshield sensors                  # CPU/GPU/NVMe temperatures, fans, power, read straight from the kernel
devshield profile                  # what this machine can control, active profile, temperatures
sudo devshield profile silent      # boost off, 2800 MHz cap, energy-saving preference, quiet/low-power fan mode
sudo devshield profile gaming      # boost on, full frequency, performance preference/fan mode
sudo devshield profile dev         # boost on, 90% max frequency, balanced
sudo devshield profile off         # restore the original settings exactly
```

These use standard kernel interfaces (cpufreq, intel_pstate/amd-pstate boost, energy-performance preference, ACPI `platform_profile`), with no vendor tools or downloads.
- **Backup first.** Before DevShield's first change, the original values are saved in the root-only state directory.
- **All or nothing.** If a required change fails midway, everything from that attempt is undone.
- **Checked afterwards.** Every value is read back to confirm it took.

What a profile can do depends on the hardware. `devshield profile` lists the controls this machine actually has.

**Telemetry sinkhole (Linux):**

```bash
devshield sinkhole               # status: on/off, what is blocked and why
sudo devshield sinkhole on       # add DevShield's managed block to /etc/hosts
sudo devshield sinkhole off      # remove only that block
```

The list is deliberately small and documented, so every entry is a pure telemetry endpoint: Ubuntu usage reporting, VS Code/.NET telemetry, Next.js telemetry. Update servers are on a never-block list. Root can supply its own list in `/etc/devshield/hosts_blocklist.json`.
- **Your entries are safe.** Your own lines in `/etc/hosts` are never touched, and `off` removes only DevShield's block, keeping edits you made since. A one-time copy of the original file is kept in the root-only state directory.
- **Status warns you** if the sinkhole can't work: name resolution that ignores `/etc/hosts`, or entries removed by hand. Browsers using DNS-over-HTTPS bypass hosts-file blocking.

**Network monitor (Linux)**: which program is talking to whom.

```bash
devshield net          # outbound connections: 📡 telemetry, 🤖 LLM APIs, 🌐 other (exit 3 if telemetry)
devshield net --all    # also local network and this machine
```

- It reuses the data Agent Watch already collects every 10 seconds, so it adds no scanning of its own.
- Telemetry is recognised by the sinkhole's list of telemetry domains, resolved to addresses every 30 minutes while the sinkhole is off (when it's on, those names can't be reached by name anyway). Each program that sends to one is logged once a day as `NET_TELEMETRY`.
- Only connections this machine *started* are shown. Connections other machines open *to* it (for example SSH) are left out.
- Labels come from IP addresses. Big providers share addresses, so a label means "likely", not proof. TCP only for now.

**Local-network privacy (Linux)**: what your machine reveals to everyone on the same Wi-Fi.

```bash
devshield lan-privacy              # what leaks right now (exit code 3 if something does)
sudo devshield lan-privacy on      # stop it
sudo devshield lan-privacy off     # undo: removes only DevShield's own files
```

- **LLMNR and mDNS off.** These answer "who is <name>?" on the local network. They reveal your hostname, and LLMNR answers are a classic way for an attacker on the same network to steal login hashes. DevShield configures systemd-resolved and NetworkManager.
- **A random Wi-Fi MAC address per network.** Each network sees a different address; it stays stable for that network so logins and captive portals keep working. Wi-Fi scans also use random addresses, so shops and stations can't track the device from scan to scan. The new address is used from the next connection.
- **IPv6 privacy addresses**, so your IPv6 address doesn't identify the device across the internet.
- Status shows the **effective** state as the system reports it, not what DevShield wrote. Anything it can't confirm shows as ❔, never as safe.
- It also **warns** about services that announce the machine and that DevShield won't silently stop, because you may need them: Avahi (mDNS, used for network printer discovery) and Samba's nmbd (NetBIOS).
- Only components that are installed are configured. Without NetworkManager, set MAC randomisation in your own network tool.

**Network controls (Linux): block one agent, or lock the whole machine down**

DevShield writes its rules into its own nftables table (`inet devshield`) and never touches other tables. The rules live in the kernel, so they **keep working if DevShield stops** (fail closed). Every 10 seconds the daemon compares the kernel's rules with what they should be. If another tool removed or changed them (for example a firewall service running `flush ruleset`, or a single rule deleted), it puts them back and logs `EGRESS_RULES_RESTORED`. At boot, `devshield-egress.service` loads the saved rules **before the network starts**, so a lockdown has no unprotected window. Needs the `nft` tool (package `nftables`).

*Block one agent* (the "Block" step of Block → Allow → Charge):

```bash
devshield agents                 # find the agent's ID
sudo devshield block 17d4a1d7    # cut it (and everything it starts) off the network
devshield egress                 # what is blocked, lockdown state
sudo devshield unblock 17d4a1d7  # give it its network access back
```

- Everything else keeps working. Only that agent's processes lose the network, and so does anything they launch (shells, curl, child tools), **loopback included**, so it can't hand traffic to a local proxy.
- **Connections it already had are cut too.** Those sockets were opened before the block, so DevShield drops them by their exact addresses.
- **It stays blocked.** If the agent restarts, it is caught again at the next scan (up to about 10 seconds; logged as `AGENT_REQUARANTINED`). The block survives reboots. You can also block an agent DevShield has seen before that isn't running now: it is cut off as soon as it starts.
- Rules for the agent's old connections are removed once those sockets close, so a port it once used is never blocked for another program.
- Uses a cgroup v2 group (`devshield-quarantine`). Works on unified and on "hybrid" cgroup layouts. If cgroup v2 isn't mounted at all, `devshield egress` says so.

*Allow one agent out during a lockdown* (the "Allow" step):

```bash
sudo devshield sanction 6120139f   # approve it first
sudo devshield allow 6120139f      # it (and the tools it starts) may go out during lockdown
sudo devshield lockdown on --only-allowed   # nothing else goes out at all
sudo devshield disallow 6120139f
```

- Only a **sanctioned** agent with **no risk signs** can be allowed.
- The allowance is **withdrawn automatically** (`AGENT_ALLOW_SUSPENDED`) the moment that stops being true: the sanction is revoked, the program file is replaced, or Agent Watch sees rogue behaviour.
- A restarted allowed agent is allowed again at the next scan. Blocking always wins over allowing.
- Outside a lockdown, allowing changes nothing, because everything may go out anyway.
- Allowing is narrow on purpose: only the processes Agent Watch identifies as the agent are allowed, plus whatever they start afterwards. Programs the agent started *before* you allowed it stay blocked. (Blocking is broad: it takes the agent's existing children too.)
- DevShield checks each process is still the same one before acting on it (same PID *and* same start time), so a process ID reused by another program after a scan is never blocked or allowed by mistake.

*Lockdown: nothing leaves except the way you choose.* This is the alternative to a Tor-only kill switch, for networks that block Tor:

```bash
# Only through your WireGuard tunnel (and to its server, so the tunnel can connect):
sudo devshield lockdown on --via wg0 --endpoint 203.0.113.5:51820/udp
# Only through Tor (programs reach the internet only via Tor's SOCKS port):
sudo devshield lockdown on --tor
# Through any tunnel/proxy client that runs as its own user (obfuscated VPNs, Tor bridges, …):
sudo devshield lockdown on --user sing-box
# Keep printers/NAS reachable (DNS still must go through the tunnel):
sudo devshield lockdown on --via wg0 --endpoint 203.0.113.5:51820/udp --lan
# Trying a new tunnel? Auto-revert unless you confirm:
sudo devshield lockdown on --via wg0 --endpoint 203.0.113.5:51820/udp --confirm-within 2m
sudo devshield lockdown confirm
sudo devshield lockdown off
```

- **No leaks around the tunnel.** DNS, IPv6, and programs that ignore proxy settings can't go around it, because nothing else is allowed out. If the tunnel drops, traffic stops instead of falling back to your normal connection.
- **Telemetry needs your permission.** With the sinkhole on and lockdown on, telemetry from any vendor (operating system, drivers, editors) can only leave through the path you chose, and only if its domain isn't blocked. Every drop is counted, and samples are logged (`devshield-lockdown-drop` in the kernel log).
- **With `--tor`, name lookups need Tor too.** Point programs at Tor's SOCKS port with remote DNS, or set Tor's `DNSPort` as the resolver; ordinary DNS is blocked, which is what prevents the leak.
- **SSH into this machine keeps working.** Replies to connections someone makes *to* this machine are allowed. `--strict` blocks those too, but it also cuts SSH.
- Endpoints must be IP addresses: looking up a name would itself need traffic outside the tunnel.
- When Tor is blocked: any tunnel works with `--via`/`--user`. That includes WireGuard or OpenVPN to a server you control, obfuscated protocols, and Tor with bridges, which still runs as the Tor user. DevShield doesn't get around censorship itself. It makes sure **only** the path you picked is used.

*What these controls cannot stop (the honest list):*
- **Out-of-band management hardware.** Intel AMT/vPro (and similar features on some business machines) has its own network stack below the operating system. No OS firewall can see that traffic; it has been abused this way in the wild. Turn AMT off in the firmware setup, and/or block TCP 16992–16995 and 623/664 on your router.
- **Malware that already has root.** It can remove any rule. DevShield notices and restores the rules within 10 seconds, and logs it, but root is root.
- **Data hidden inside traffic you allowed.** If a program is allowed out, DevShield can't tell what it sends.
- **Programs that set up their own route** through a tunnel you allowed. Lockdown controls *how* traffic leaves, not which program sends it.
- **Blocking works per process.** An agent that runs *inside* another program, such as an editor extension, shares that program's process. Blocking it also cuts the host program (for example the editor's extension host) off the network.
- **A gap of up to about 10 seconds** when a blocked agent restarts, until the next scan catches it.
- **Old-style cgroup v1 network controllers** (net_cls/net_prio) in use on a hybrid system disable the per-agent match. This is rare on modern distributions.
- **Allowing arbitrary programs (a browser, a game)** and **ask-before-connect prompts** (like simplewall or OpenSnitch) are not built yet; today you allow agents, tunnels and users. See the roadmap.

**Undo everything (Linux):**

```bash
sudo devshield restore-all
```

This undoes every system change DevShield made: it ends any lockdown, unblocks and disallows agents, and restores the original thermal settings, `/etc/hosts`, the LAN-privacy files and the live IPv6 setting. Each step is reported as ✅ or ❌, and a failed step doesn't stop the others. Your agent approvals and the audit log are kept, because they are your decisions and your record, not system changes. If a process can't be moved out of the quarantine group, `restore-all` says so and leaves its rule loaded (fail closed) instead of claiming success.

**Install, by hand for now** (packages come later):

```bash
sudo install -m 0755 devshield /usr/bin/devshield
sudo install -D -m 0644 packaging/linux/devshield.service /etc/systemd/system/devshield.service
sudo install -D -m 0644 packaging/linux/devshield-egress.service /etc/systemd/system/devshield-egress.service
echo "DEVSHIELD_OWNER=$USER" | sudo install -D -m 0644 /dev/stdin /etc/devshield/daemon.env
sudo systemctl daemon-reload && sudo systemctl enable --now devshield
sudo systemctl enable devshield-egress   # network rules at boot, before the network starts
```

Status: tested by unit tests and a live run with real users on Linux (owner/other user, a rogue attempting self-sanction, `kill -9`, log tampering). **Not yet tested under systemd itself**, so the unit's hardening settings still need a real-machine check. The sinkhole was tested live on a real Linux system: the resolver returned 0.0.0.0 for blocked domains, update servers kept resolving, and `/etc/hosts` came back byte-for-byte identical after `off`. Sensors and thermal profiles are tested on simulated kernel layouts (Intel/AMD, laptop and desktop) and through the real daemon socket, but **not yet on real hardware**. The network monitor was tested live in a namespace: a real connection to an address standing in for a telemetry domain was labelled and logged once, and the server side of the same connection was correctly left out. LAN privacy was tested through the real daemon on a simulated system tree. It was **not yet** tested with real systemd-resolved, NetworkManager or Wi-Fi hardware. Network controls are tested live by `test/linux-live/run.sh` (see its README), through the real daemon, kernel and nft, in an isolated network namespace with both unified and hybrid cgroup layouts. The tests covered: blocking a running agent and its child (held and new connections stopped, other programs unaffected), re-blocking after a restart, unblocking, lockdown via a tunnel interface, an endpoint or an allowed user, the auto-revert, restoring a deleted table, keeping lockdown across a daemon restart, blocking an agent before it starts, removing rules for closed sockets, detecting one deleted rule inside the table, and `egress-restore` with no daemon running; allowing a sanctioned agent out of an allowed-only lockdown (other programs stayed blocked), automatic withdrawal on revoke, re-allow after restart, and block overriding allow. They were **not yet** run with a real WireGuard/Tor setup, or under systemd. The Linux tray comes next.

## 3. Pro Use

### CLI reference

**Language toggle**:
```powershell
devshield-lang
```

**Thermal profiles**:
```powershell
pwsh -File scripts\profiles\silent_summer.ps1
pwsh -File scripts\profiles\gaming_gear.ps1
pwsh -File scripts\profiles\dev_mode.ps1
```

**Privacy enforcer**:
```powershell
pwsh -File scripts\hardening\privacy_enforcer.ps1
pwsh -File scripts\hardening\privacy_enforcer.ps1 -Rollback
```

**Network guardian**:
```powershell
pwsh -File scripts\monitor\network_guardian.ps1 -Start
pwsh -File scripts\monitor\network_guardian.ps1 -Status
pwsh -File scripts\monitor\network_guardian.ps1 -Alerts
pwsh -File scripts\monitor\network_guardian.ps1 -Stop
```

**Rollback**:
```powershell
pwsh -File scripts\hardening\rollback.ps1
pwsh -File scripts\hardening\rollback.ps1 -Last
pwsh -File scripts\hardening\rollback.ps1 -All
pwsh -File scripts\hardening\rollback.ps1 -DryRun -All
```

### Editing the bundled blocklist

The offline-fallback telemetry blocklist lives at `scripts/monitor/blocklist_bundled.json`. To add a domain, append it to the `domains` array, and re-run the privacy enforcer.

### Adding custom guardian allowlist entries

Open `scripts/monitor/network_guardian.ps1` and add the process name to `$ALLOWED_PROCESSES`.

### Reading state.json / config.json directly

```powershell
Get-Content "$env:USERPROFILE\.devshield\state.json" | ConvertFrom-Json
Get-Content "$env:USERPROFILE\.devshield\config.json" | ConvertFrom-Json
```

---

## 4. Emergency Recovery

### If DevShield is suspected of causing an issue

```powershell
pwsh -File scripts\hardening\rollback.ps1 -DryRun -All
pwsh -File scripts\hardening\rollback.ps1 -All
```

### If rollback itself fails

Every rollback backup is stored in `%USERPROFILE%\.devshield\backups\`. If the script cannot restore something automatically, use the backup files directly or review the recovery steps in the troubleshooting guide.

### How to fully disable DevShield without uninstalling

```powershell
pwsh -File scripts\monitor\network_guardian.ps1 -Stop
schtasks /Change /TN "DevShield\DS_SilentSummer" /DISABLE
schtasks /Change /TN "DevShield\DS_GamingGear" /DISABLE
schtasks /Change /TN "DevShield\DS_DevMode" /DISABLE
schtasks /Change /TN "DevShield\DS_Privacy" /DISABLE
schtasks /Change /TN "DevShield\DS_TorHarden" /DISABLE
schtasks /Change /TN "DevShield\DS_Guardian" /DISABLE
```
