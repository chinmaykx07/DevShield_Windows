# DevShield User Manual

This is the complete reference for using DevShield safely and, once you're comfortable, powerfully. Read Section 1 and 2 fully before your first real use. Sections 3 and 4 are there when you need them.

> **Status, honestly.** Sections 1–4 describe the **Windows** variant, which has never been run on a real Windows machine and has known-broken core features: scheduled-task setup (C1, C2), tray actions (C3), rollback (C4), the network guardian (C5) and the Tor kill switch (C6). See `docs/REVIEW_NOTES_2026-10-20.md`. Section 2b describes the **Linux** daemon, where development is focused now. Each Linux feature there states how it was tested.

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
| Windows Firewall | Tor rules (only if you run Tor hardening). **Currently only *allow* rules: nothing is blocked (C6)** | Tor hardening |
| Network adapters, LLMNR/NetBIOS | Tor hardening also turns off LLMNR/NetBIOS and randomises the Wi-Fi MAC. **Its undo is unreliable:** it can leave an LLMNR policy that wasn't there before, and its MAC backups can be overwritten or record the random address as the original (review notes, "Tor hardening rollback") | Tor hardening |
| Task Scheduler | Eight tasks under a `DevShield` folder. **Registration currently always fails (C1)** | First run |
| Network monitoring | Read-only monitoring of connections | Network guardian |

These are designed to be reversible, but **the Windows rollback script is currently broken**: it restores nothing and still reports success (C4). Create a Windows restore point before using DevShield on Windows.

### What DevShield will never touch

- Boot configuration
- Driver stack
- WinPE or Recovery partition
- Windows Update infrastructure, which is explicitly whitelisted in the privacy enforcer

---

## 2. Safe Use

### First-run walkthrough

When you first open the tray menu, you will see the main menu with thermal profile choices, privacy, network guardian, dashboard, rollback, language, and quit options.

Recommended first action: open the Dashboard, not a profile. This shows you live sensor data with zero system changes. (Not tested on Windows; known dashboard bugs are listed in the review notes, and without admin rights LibreHardwareMonitor can't run, so it falls back to limited data.)

```powershell
pwsh -File scripts\monitor\hardware_dashboard.ps1
```

Recommended second action: try one thermal profile. DevShield is designed to read your sensors before and after applying. Without LibreHardwareMonitor these checks currently pass with no data (they should say "no sensor data"), so a pass is not proof yet. Dev Mode changes the display timeout and nothing restores it today (C4).

### How to read the audit log

Every action DevShield takes is logged. From PowerShell:

```powershell
pwsh -File scripts\profiles\profile_manager.ps1 -History
```

**Currently shows nothing while the tray is running:** the tray deletes event files about 2 seconds after storing them in `audit.db`, and `-History` reads those files.

### How to use rollback safely — always dry-run first

> **Currently broken (C4):** rollback restores nothing and still reports success. A dry run won't reveal this. Until it's fixed, rely on a Windows restore point.

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

A guardian alert means a process made a network connection that is neither trusted nor known. This is informational, not a block. **Currently broken (C5):** the guardian's main loop crashes on the first unknown process, so these alerts never fire.

### Watching AI agents and catching rogue ones (Agent Watch)

On Windows, the tray menu **🤖 AI Agents** lists the AI agents running on this PC and flags **rogue suspects** (not yet tested on Windows). On Linux, use `devshield agents` (section 2b). It scans continuously.

**How a process becomes "an AI agent".** Either way below is enough:
1. **Behaviour** (a score of 3 or more). This catches agents no list knows about:
   - it talks to an LLM API (+2) or a local model server (+2; only +1 on ports every web server also uses, such as 8080)
   - it serves a model on a distinctive model port such as Ollama's 11434 (+3); 8080, 1234 and 1337 count only +1
   - it has LLM API keys or endpoints set specifically for it (+2). Keys set for your whole account are ignored, and if its parent can't be read this signal is skipped rather than guessed
   - it loads AI model libraries such as llama.cpp/ggml, PyTorch or ONNX Runtime (+1 to +3)
   - it keeps launching shells and command-line tools, the "agent loop" (+1 or +2). Tools run through a non-interactive shell (`agent → bash -c → tool`) count for the agent. On Linux, what a person types in a terminal, including an IDE's built-in terminal, does not, and neither do worker copies of the program itself (such as PyTorch data loaders)
   - its program or script name contains a known agent keyword (+1)
2. **Catalog identity**: its program, or the script or package a runtime such as node, python, uvx or java runs, matches a built-in entry (Claude Code, Codex, Ollama, MCP servers…). Only what the program *is* counts: arguments such as a file it greps, a folder it opens or a package it installs never do.

A catalog name never makes an agent trusted. It does, however, remove the "undocumented" indicator, so a rogue program that names itself `claude` shows as "Claude Code — ⚠ unsanctioned" rather than 🚨 rogue. Approval is tied to the exact program file and location, so such an impostor is never ✅ unless you approve that exact file.

**Rogue indicators** apply to every agent, named or not:
- **undocumented**: matches no catalog entry
- runs from Temp, Downloads, Public, the Recycle Bin, `/tmp`, `/var/tmp` or `/dev/shm`. This applies to the program and to the script it runs
- started with approvals switched off (`--dangerously-skip-permissions`, `--yolo`, `--full-auto`…)
- launched recon, persistence or credential tools (`whoami`, `net`, `schtasks`, `reg`, `certutil`, `cmdkey`, `id`, `sudo`, `crontab`…). These are recognised by name, so a renamed copy is not
- registered to start automatically: Windows Run keys and the Startup folder, or on Linux, systemd units and XDG autostart for every user. For node, python and the like, the entry must start the same script
- detached: still launching tools after its parent process is gone (a weak signal: a double-forked process can avoid it)

| Icon | Verdict | Meaning |
|---|---|---|
| 🚨 | **Rogue suspect** | Not sanctioned, and undocumented or showing rogue indicators. Investigate. |
| ⚠ | **Risky** | You sanctioned it, but it is now showing rogue indicators (e.g. a trusted agent misused). |
| ⚠ | **Unsanctioned** | Known agent, nothing suspicious, not yet approved. |
| ✅ | **Sanctioned** | Approved and behaving normally. |

Hover an entry to see *why* it is considered an agent and which rogue indicators it shows. **Sanction this agent** approves that exact program (on Windows, a known bug, W4, can approve a different agent if the menu refreshes between opening and clicking): the same executable, plus for runtimes the same script and the same extra code options (so `node --require=other.js cli.js` is not the approved `cli.js`).

Sanctioning clears the "undocumented" and "auto-start" indicators, since you approved what the agent is and how it is installed. Behavioural indicators still alert. A changed program file revokes the approval. The check hashes **one** file: for node, python and other runtimes the script, otherwise the executable. It is re-read when the file's size or modification time changes. Not covered: the runtime itself (a replaced `python3`), other files the program loads (modules, libraries), and a file that can't be read or is over 512 MB (such a sanctioned agent is shown as risky, saying so).

The trade-off: if an approved agent *later* adds itself to auto-start, this indicator won't flag it.

Audit events: `AGENT_ROGUE_SUSPECT`, `AGENT_RISKY`, `AGENT_NEW`, `AGENT_UNKNOWN`, `AGENT_CHANGED`, `AGENT_UNSANCTIONED_START`, `AGENT_SANCTIONED`.

**Limits:**
- Agent Watch only alerts. To cut an agent off the network on Linux, use `sudo devshield block <ID>` (section 2b).
- Without admin (or root) it can't fully inspect other users' or elevated processes.
- On Windows it has never been run on a real machine.
- Commands that finish in well under half a second may be missed, because the process list is sampled every 0.5 s. Event-based capture that catches every process is planned for the admin-mode phase.
- Command lines are redacted (keys and tokens masked) before logging, and environment variable *values* are never stored.

To recognise an agent the catalog doesn't know yet: on Linux, root can put a catalog in `/etc/devshield/agent_catalog.json`, which replaces the built-in one. On Windows there is deliberately no per-user override, because an agent running as you could edit it.

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

- **Why approving needs `sudo`:** an AI agent runs as *you*. If your user could change the rules, so could the agent. Any non-root attempt to change policy is refused and logged as `AGENT_TAMPER_ATTEMPT`, naming the program that tried. Logging is limited to 10 per minute per user, counted separately for refused reads and for policy-change attempts, so floods of one can't hide the other. Further ones in that minute are still refused, and are counted in one `IPC_DENIED_SUPPRESSED` summary event at the end of the minute (or when the daemon stops).
- **Who can read:** root, plus the owner set in `/etc/devshield/daemon.env` (`DEVSHIELD_OWNER=alice`). Other local users are refused.
- **The audit log is hash-chained.** Editing, deleting, reordering or truncating records is detected and reported with the exact line. Tampering found at start-up is logged as `AUDIT_TAMPER_DETECTED`. A daemon that was killed, rather than stopped cleanly, shows up as `DAEMON_UNCLEAN_STOP` on its next start.
- **Exit codes for scripts and monitoring:** **3** means "something needs your attention", 1 means the command failed, 0 means all clear.
  - `status` exits 3 when a rogue or risky agent is running, or the audit log is tampered with or could not be checked.
  - `agents` exits 3 when a rogue or risky agent is running (`agents --json` always exits 0).
  - `verify-log` exits 3 only for a broken hash chain; a missing or unreadable log is 1.
  - `net` exits 3 while telemetry is flowing (`net --json` always exits 0); `egress` when the kernel's rules aren't confirmed to match, which includes "UNKNOWN" (they can't be compared) and an unreadable state file; `lan-privacy` when LLMNR/mDNS is on or a hardware Wi-Fi address is in use; `profile` when a setting didn't read back; `sinkhole` when entries are missing, the resolver ignores `/etc/hosts`, or DevShield's block in it is damaged (a start marker without an end marker: DevShield then refuses to change the file until you fix it).
  - `block`, `unblock`, `allow`, `disallow` and `restore-all` exit 3 when they worked but with a caveat, printed as a ⚠ note (for example a process that could not be moved back).

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
- Telemetry is recognised by the sinkhole's list of telemetry domains, resolved to addresses every 30 minutes (these DNS lookups go through your normal resolver) while the sinkhole is off (when it's on, those names can't be reached by name anyway). Connections are checked every 30 seconds, against Agent Watch's latest scan, so a connection shorter than that can be missed. Each program+domain pair is logged as `NET_TELEMETRY` at most once per 24 hours while the daemon runs; a daemon restart resets that.
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

DevShield writes its rules into its own nftables table (`inet devshield`) and never touches other tables. The rules live in the kernel, so they **keep working if DevShield stops** (fail closed). Every 10 seconds the daemon compares the kernel's rules with what they should be. If another tool removed or changed them (for example a firewall service running `flush ruleset`, or a single rule deleted), it puts them back and logs `EGRESS_RULES_RESTORED`. If the kernel lists them in a form DevShield can't compare (a different nft version, for example), it says so once (`EGRESS_RULES_UNVERIFIABLE`) and `egress` shows the state as UNKNOWN instead of claiming a match; this comparison has been checked against nft 1.0.9 only. At boot, `devshield-egress.service` is ordered to load the saved rules **before the network starts**, so a lockdown has no unprotected window (this ordering has not yet been checked on a real systemd boot). If the saved state can't be read, DevShield leaves the kernel's rules exactly as they are and refuses changes until you run `sudo devshield restore-all`. That only fails closed **until the next reboot**: the rules live in the kernel, and after a reboot none are loaded, because DevShield no longer knows which ones you had. Needs the `nft` tool (package `nftables`).

*Block one agent* (the "Block" step of Block → Allow → Charge):

```bash
devshield agents                 # find the agent's ID
sudo devshield block 17d4a1d7    # cut it (and everything it starts) off the network
devshield egress                 # what is blocked, lockdown state
sudo devshield unblock 17d4a1d7  # give it its network access back
```

- Everything else keeps working. Only that agent's processes lose the network, and so does anything they launch (shells, curl, child tools), **loopback included**, so it can't hand traffic to a local proxy.
- **Connections it already had are cut too.** Those sockets were opened before the block, so DevShield drops them by their exact addresses.
- **It stays blocked.** If the agent restarts, it is caught again at the next scan (up to about 10 seconds; logged as `AGENT_REQUARANTINED`). Until then `devshield agents` shows it with ⏳ (blocked, not yet cut off). The block survives reboots. You can also block an agent DevShield has seen before that isn't running now: it is cut off at the first scan after it starts (again up to about 10 seconds).
- Rules for the agent's old connections are removed at the next scan after those sockets close (up to about 10 seconds), so a port it once used isn't left blocked for another program.
- Uses a cgroup v2 group (`devshield-quarantine`). Tested on unified and "hybrid" cgroup layouts in namespaces, not yet on a real distribution under systemd. If cgroup v2 isn't mounted at all, `devshield egress` says so.
- When unblocked, processes go back to the cgroup they came from. If that fails, they are placed in the root cgroup (outside their session's limits) and DevShield logs `EGRESS_RELEASE_FALLBACK`. A process in the quarantine that DevShield can't trace back to the agent (for example a helper that detached from it) **stays cut off** (fail closed): `unblock` says so, logs `EGRESS_RELEASE_KEPT`, and you can end that process or run `restore-all`.

*Allow one agent out during a lockdown* (the "Allow" step):

```bash
sudo devshield sanction 6120139f   # approve it first
sudo devshield allow 6120139f      # it (and the tools it starts) may go out during lockdown
sudo devshield lockdown on --only-allowed   # nothing else goes out at all
sudo devshield disallow 6120139f
```

- Only a **sanctioned** agent with **no risk signs** can be allowed.
- The allowance is **withdrawn automatically** (`AGENT_ALLOW_SUSPENDED`) at the first scan after that stops being true (up to about 10 seconds): the sanction is revoked, the program file is replaced, or Agent Watch sees rogue behaviour.
- A restarted allowed agent is allowed again at the next scan. Blocking always wins over allowing.
- Outside a lockdown, allowing changes nothing, because everything may go out anyway.
- Allowing is narrow on purpose: only the processes Agent Watch identifies as the agent are allowed, plus whatever they start afterwards. Programs the agent started *before* you allowed it stay blocked. (Blocking is broad: it takes the agent's existing children too.)
- DevShield checks each process is still the same one before acting on it (same PID *and* same start time), so a process ID reused by another program after a scan is not blocked or allowed by mistake. (When Agent Watch could not read a process's start time, the PID alone is used.)

*Lockdown: nothing leaves except the way you choose.* This is the alternative to a Tor-only kill switch, for networks that block Tor:

```bash
# Only through your WireGuard tunnel (and to its server, so the tunnel can connect):
sudo devshield lockdown on --via wg0 --endpoint 203.0.113.5:51820/udp
# Only through Tor (programs reach the internet only via Tor's SOCKS port):
sudo devshield lockdown on --tor
# Through any tunnel/proxy client that runs as its own user (obfuscated VPNs, Tor bridges, …):
sudo devshield lockdown on --user sing-box
# Keep printers/NAS reachable by IP (name lookups still must go through the tunnel):
sudo devshield lockdown on --via wg0 --endpoint 203.0.113.5:51820/udp --lan
# Trying a new tunnel? Auto-revert unless you confirm:
sudo devshield lockdown on --via wg0 --endpoint 203.0.113.5:51820/udp --confirm-within 2m
sudo devshield lockdown confirm
sudo devshield lockdown off
```

- **Nothing else leaves.** That covers DNS, IPv6, programs that ignore proxy settings, **and traffic the machine forwards for containers and VMs** (Docker, libvirt). If the tunnel drops, traffic stops instead of falling back to your normal connection. A few exceptions keep the network link itself working:
  - DHCP to the local network only (DHCP to a public address is dropped)
  - IPv6 neighbour discovery to link-local and multicast addresses only
  - loopback

  This is live-tested against the kernel in namespaces: a forwarded packet, and a send to UDP port 67 at a public address, were dropped. DNS and IPv6 blocking follow from the final drop rule; they are not separately live-probed.
- **Telemetry needs your permission.** With the sinkhole on and lockdown on, telemetry from any vendor (operating system, drivers, editors) can only leave through the path you chose, and only if its domain isn't blocked. Every drop is counted, and samples are logged (`devshield-lockdown-drop` in the kernel log).
- **With `--tor`, name lookups need Tor too.** Point programs at Tor's SOCKS port with remote DNS, or set Tor's `DNSPort` as the resolver; ordinary DNS is blocked, which is what prevents the leak.
- **SSH into this machine keeps working.** Replies to connections someone makes *to* this machine are allowed. This is also a way out: a program that runs a server which someone outside connects to can send data back through it. `--strict` blocks those replies too, but it also cuts SSH.
- **With `--lan`**, name lookups and announcements on the local network are dropped too: DNS, mDNS, LLMNR and NetBIOS. Printers that are found by name won't be discovered; use their IP address.
- **`--confirm-within`** must be at least 10 seconds. An unconfirmed lockdown is never saved to disk, so a restart or reboot also reverts it.
- Endpoints must be IP addresses: looking up a name would itself need traffic outside the tunnel. `--endpoint` on its own is refused: it needs `--via`, `--user`, `--tor` or `--only-allowed`, because a tunnel server alone gives programs no way out.
- When Tor is blocked: any tunnel works with `--via`/`--user`. That includes WireGuard or OpenVPN to a server you control, obfuscated protocols, and Tor with bridges, which still runs as the Tor user. DevShield doesn't get around censorship itself. It makes sure **only** the path you picked is used.

*What these controls cannot stop (the honest list):*
- **Out-of-band management hardware.** Intel AMT/vPro (and similar features on some business machines) has its own network stack below the operating system. No OS firewall can see that traffic; it has been abused this way in the wild. Turn AMT off in the firmware setup, and/or block TCP 16992–16995 and 623/664 on your router.
- **Malware that already has root.** It can remove any rule. DevShield notices and restores the rules within 10 seconds, and logs it, but root is root.
- **Data hidden inside traffic you allowed.** If a program is allowed out, DevShield can't tell what it sends.
- **Programs that set up their own route** through a tunnel you allowed. Lockdown controls *how* traffic leaves, not which program sends it.
- **Blocking works per process.** An agent that runs *inside* another program, such as an editor extension, shares that program's process. Blocking it also cuts the host program (for example the editor's extension host) off the network.
- **A gap of up to about 10 seconds** when a blocked agent restarts, until the next scan catches it.
- **Work done through a helper that is already running.** A blocked agent that asks a privileged service to act for it (for example `docker run …` through the Docker daemon, `systemd-run --user`, `at`, or a new tmux window) has that work done by a process outside the quarantine group. Lockdown still covers what such helpers send, including forwarded container traffic; a per-agent block does not.
- **Old-style cgroup v1 network controllers** (net_cls/net_prio) in use on a hybrid system disable the per-agent match. This is rare on modern distributions.
- **Allowing arbitrary programs (a browser, a game)** and **ask-before-connect prompts** (like simplewall or OpenSnitch) are not built yet; today you allow agents, tunnels and users. See the roadmap.

**Undo everything (Linux):**

```bash
sudo devshield restore-all
```

This undoes every system change DevShield made: it ends any lockdown, unblocks and disallows agents, and restores the original thermal settings, `/etc/hosts`, the LAN-privacy files and the live IPv6 setting. Each step is reported as ✅ or ❌, with ⚠ notes for anything only partly undone, and a failed step doesn't stop the others; with any ❌ or ⚠ it exits non-zero. Your agent approvals and the audit log are kept, because they are your decisions and your record, not system changes. If a process can't be moved out of the quarantine group, `restore-all` says so and leaves its rule loaded (fail closed) instead of claiming success.

What it can't cover: settings whose original value DevShield never recorded (its root-only state directory was deleted, or the state file was unreadable), and what networks already saw (the randomised Wi-Fi addresses used so far; the hardware address returns from the next connection). Live-tested: thermal, `/etc/hosts` and LAN privacy on a simulated system tree; lockdown and allowed and blocked agents on the real kernel in namespaces.

**Install, by hand for now** (packages come later):

```bash
sudo install -m 0755 devshield /usr/bin/devshield
sudo install -D -m 0644 packaging/linux/devshield.service /etc/systemd/system/devshield.service
sudo install -D -m 0644 packaging/linux/devshield-egress.service /etc/systemd/system/devshield-egress.service
echo "DEVSHIELD_OWNER=$USER" | sudo install -D -m 0644 /dev/stdin /etc/devshield/daemon.env
sudo systemctl daemon-reload && sudo systemctl enable --now devshield
sudo systemctl enable devshield-egress   # network rules at boot, before the network starts
```

**How the Linux side is tested.** Unit tests (with the race detector) cover the internal packages; the CLI and the IPC message types have no unit tests of their own and are exercised by the live checks. And `test/linux-live/run.sh` re-runs the live checks in throwaway namespaces, on fresh and on the host's cgroup layout. The live checks drive the real kernel, nftables, daemon, socket and resolver. They cover:
- real users: the owner can read, other users can't, and non-root changes are refused and logged
- the sinkhole on the real resolver (0.0.0.0 while on, `/etc/hosts` byte-identical after off, on a private copy of the file)
- Agent Watch detection: a catalogued agent (matched by its script), and an uncatalogued program detected by behaviour alone (serving on Ollama's port 11434) and shown as 🚨 rogue. The other behaviour signals (LLM API connections, keys, AI libraries, the agent loop) are unit-tested only
- block, allow and lockdown, including forwarded container/VM traffic and the DHCP port. `--tor` is lockdown for the Tor daemon's account: the account lookup is unit-tested and per-user lockdown is live-tested, but never with a real Tor daemon
- tamper restoration, the dead-man switch and persistence
- `restore-all` (with an allowed and then a blocked agent running) and the network monitor

**Not yet tested:**
- under systemd on a real distribution, including the units' hardening and boot ordering
- on real hardware (sensors, thermal profiles, Wi-Fi MAC randomisation)
- with real systemd-resolved, NetworkManager, WireGuard or Tor

The Linux tray comes next.

## 3. Pro Use

### CLI reference

**Language toggle** (there is no `devshield-lang` command; use the tray menu, or):
```powershell
. scripts\core\00_core.ps1
Set-DSLanguage -Lang EN    # EN | SA | BOTH
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
pwsh -File scripts\hardening\privacy_enforcer.ps1 -Rollback   # removes the hosts block only; registry and DiagTrack stay changed
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

`scripts/monitor/blocklist_bundled.json` is currently **not read by any script**: the network guardian uses its own built-in list, and the privacy enforcer has its own list inside `privacy_enforcer.ps1`. To add a domain today, edit `$TELEMETRY_DOMAINS` in `scripts/hardening/privacy_enforcer.ps1`. On Linux, root can put a list in `/etc/devshield/hosts_blocklist.json`.

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
schtasks /Change /TN "DevShield\DS_Dashboard" /DISABLE
schtasks /Change /TN "DevShield\DS_Rollback" /DISABLE
```
