# Changelog

All notable changes to DevShield are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Agent Watch: behaviour-first detection of AI agents and rogue agents.
  A process is classed as an agent by behaviour (LLM traffic, LLM keys
  set for it, AI libraries loaded, shell/tool agent loop), or by matching
  a catalog entry by identity (its program or the script it runs).
  Rogue indicators (undocumented, Temp/Downloads location,
  approvals-disabled flags, recon/persistence tools, auto-start, detached)
  give 🚨 rogue-suspect and ⚠ risky verdicts. Sanction approved agents from
  the tray. Alert-only, no admin needed. Not yet tested on Windows. See
  `docs/RESEARCH_AI_AGENT_MONITORING.md`.

- Linux root daemon (`devshield daemon`) + CLI (`status`, `agents`,
  `events`, `sanction`, `revoke`, `verify-log`). It owns the sanction list,
  agent database and audit log in a root-only directory, and talks to
  clients over a Unix socket whose callers are identified by the kernel
  (SO_PEERCRED). Policy changes require root, so an agent cannot sanction
  itself; attempts are logged as AGENT_TAMPER_ATTEMPT. Hardened systemd
  unit in `packaging/linux/` (not yet tested under systemd).
- Linux sensors (`devshield sensors`) from the kernel's hwmon/thermal zones,
  replacing the need for LibreHardwareMonitor on Linux.
- Linux thermal profiles (`sudo devshield profile silent|gaming|dev|off`)
  via cpufreq, boost, energy-performance preference and ACPI
  platform_profile, with an original-state baseline, all-or-nothing apply,
  read-back verification and exact restore. Root-only, audit-logged.
  Tested on simulated sysfs; not yet on real hardware.
- Linux telemetry sinkhole (`sudo devshield sinkhole on|off`): managed
  /etc/hosts block with a small documented list and a never-block list;
  user entries preserved; re-apply always writes the full list; status
  flags missing entries and resolvers that ignore /etc/hosts. Verified
  live on a real resolver.
- Linux network controls (`internal/egress`), in DevShield's own nftables
  table, enforced in the kernel (fail closed):
  `sudo devshield block|unblock <agent>` cuts one agent and everything it
  spawns off the network (loopback included) through a cgroup v2 group.
  Its pre-existing connections and listeners are dropped by address, and
  it is re-quarantined after a restart.
  `sudo devshield lockdown on --via IFACE | --endpoint IP:PORT/PROTO |
  --user NAME | --tor [--lan] [--strict] [--confirm-within D]` allows
  outbound traffic only through the chosen tunnel/users. With `--tor` it
  is a Tor kill switch (never yet tried with a real Tor daemon), and the
  other options are its alternative for networks that block Tor: DNS and
  IPv6 can't leave except that way (by the final drop rule, not probed
  separately), `--lan` stops DNS going to the LAN, and replies to inbound SSH still
  work unless `--strict` is set. There is a dead-man auto-revert. A
  removed or altered rule is detected (the kernel's rules are compared
  with the expected ones) and restored within 10 s, and logged.
  `devshield-egress.service` loads the saved rules at boot before the
  network starts. Agents seen before can be blocked while not running.
  Rules for closed sockets are dropped automatically.
  `sudo devshield allow|disallow <agent>` (the "Allow" step) lets a
  sanctioned, clean agent out during a lockdown, including
  `lockdown on --only-allowed`. The allow is withdrawn automatically if
  the sanction is revoked, the binary changes or rogue behaviour appears.
  Tested live in
  network namespaces (unified and hybrid cgroups); not yet with a real
  VPN/Tor setup or under systemd.
- Linux LAN privacy (`sudo devshield lan-privacy on|off`): LLMNR and mDNS
  off (systemd-resolved, NetworkManager), a random Wi-Fi MAC per network
  and while scanning, and IPv6 privacy addresses. Only DevShield's own
  drop-in files are written, plus the live IPv6 privacy setting, whose
  original value `off` writes back. Status reports the
  effective state and warns about Avahi and nmbd. Tested on a simulated
  system tree; not yet with real resolved, NetworkManager or Wi-Fi.
- Linux network monitor (`devshield net`): outbound TCP connections per
  program, labelled telemetry / LLM API / LAN / other from the data Agent
  Watch already collects, with no second scan. Each program+telemetry-host
  pair is logged once a day (`NET_TELEMETRY`). Inbound connections are not
  reported as outbound.
- `sudo devshield restore-all`: undoes every system change DevShield made
  (network rules and groups, thermal, sinkhole, LAN privacy including the
  live IPv6 value), reporting each step. Approvals and the log are kept.
  Live-tested: thermal, /etc/hosts and LAN privacy on a simulated tree
  (every value back to the original); lockdown and allowed and blocked
  agents on the real kernel in namespaces.
- `test/linux-live/run.sh`: repeatable live tests of the network controls
  against the real kernel, nftables and daemon, inside namespaces.
- Tamper-evident, hash-chained audit log: edits, deletions, reordering and
  truncation are detected; unclean daemon stops are reported.

### Changed
- Agent Watch moved to `internal/agentwatch` as a configurable Watcher.
- An LLM key now counts only for the process that introduced it at launch.
  Inherited keys don't count, so a rogue can't launder its key by spawning
  children (a flaw found in live testing of the previous majority rule).
- Built with patched Go 1.27.3: reachable known vulnerabilities went from
  35 to 0. CI now runs vet, race tests and govulncheck on Linux and Windows.

### Fixed
- Messages that claimed more than happened (found in a second audit of
  every user-visible message): unblock/disallow/restore-all now say when
  a process stayed quarantined, lost its allowance or went to the root
  cgroup instead of its own, and exit 3; `lan-privacy off` says whether
  the original IPv6 value was really written back and reports failed
  service reloads; rules DevShield can't compare are reported as UNKNOWN
  (`EGRESS_RULES_UNVERIFIABLE`), not as tampering; a damaged sinkhole
  block, an audit log that couldn't be checked and blocked agents not yet
  cut off (⏳) are shown; refused-request summaries are per user and kind,
  and are written before `DAEMON_STOPPED`; a thermal setting that appears
  after the first profile is restored too; a sanctioned agent whose file
  can't be hashed is flagged risky; a stuck allowed group is no longer
  said to keep a rule loaded.
- 2026-10-21 independent audit (four reviewers; every finding was
  reproduced or traced before fixing; regression tests added):
  - Lockdown ignored traffic forwarded for containers/VMs (added a forward
    chain). Its DHCP rule let any program send UDP to port 67/547 anywhere
    (now only to private address ranges and broadcast). Logging wasn't rate-limited (statement order).
    `--lan` let mDNS/LLMNR/NetBIOS out.
  - An unconfirmed `--confirm-within` lockdown could be saved to disk by
    other saves and come back after a restart; a stale timer could revert
    a newer lockdown. Off/reset/apply failures left memory out of step
    with the kernel. An empty policy never checked for a leftover table,
    and tamper checks compared only "first word + verdict" of each rule
    (now the whole rule, against real nft output in testdata).
  - Disallow left untraceable helpers in the allowed group. A corrupt
    state file silently disabled the network controls (now fails closed).
    Rules for a blocked agent's sockets were kept by address, not owner.
  - Agent Watch false positives: anything listening on 8080/1234/1337 was
    a "rogue AI agent"; PyTorch workers, nodemon in an "agentic" folder,
    `rg openclaw`, `tail mcp-server.log`, `npm install
    @modelcontextprotocol/sdk`, VS Code opening a folder named opencode and
    Neovim's Copilot server were all flagged; a human typing in an IDE
    terminal counted as the IDE's agent loop. Matching now uses the
    program's identity, not its arguments.
  - Agent Watch identity gaps: `--require=evil.js`, relative scripts,
    `-X utf8`, Linux `uvx`/`java` all collided with approved agents'
    fingerprints. Scripts in /tmp weren't flagged. Sanctioned Ollama
    services stayed "risky" forever. One `node app.js` service marked every
    node agent auto-started. Root's daemon scanned only root's autostart
    entries. A forked-then-exec'd tool was hidden behind its parent's name.
    More secret formats are redacted.
  - The audit log reported tampering while appends were in progress, and a
    crash-torn last line broke it forever. A broken log is now kept as
    evidence and a fresh one started.
  - The sinkhole could delete user lines (missing end marker, user lines
    inside the block) and leave /etc/hosts empty after a failed write.
  - `verify-log` reported "tampered" for a permission error and "intact"
    for a missing file. `devshield net` could hang on DNS during a
    lockdown. LAN-privacy "on" could be left half-applied. Thermal
    rollback errors were ignored. A data race on Agent Watch's shared
    process cache. Unlimited concurrent IPC connections.
  - The tray contacted GitHub automatically (now manual), and running
    `devshield` without arguments on Linux started stubbed Windows code.
  - Docs claimed several things that weren't true (see the README's
    status table, the manual and `docs/REVIEW_NOTES_2026-10-20.md` §7).
- `lan-privacy off` left the live IPv6 privacy setting changed until
  reboot. The original value is now recorded (in DevShield's own drop-in,
  kept across repeated `on`) and written back.
- Agent Watch identified a shell as an agent when its inline command
  (`bash -c "…"`) merely mentioned the agent. Inline commands of shells
  are no longer matched against catalog patterns; script files still are.
- Network block/allow could act on a PID from a scan up to 10 s old: a
  zombie, or a PID reused by another program. Each process is now
  re-checked (same PID and start time, not a zombie) before it is moved.
- `allow` swept in the agent's pre-existing child processes, granting
  network access to programs that were never identified as the agent. It
  now allows only identified processes (and what they start later).
- systemd unit: `ProtectSystem=strict` left `/etc/hosts` read-only, so the
  sinkhole could not have worked under systemd. `ReadWritePaths` now
  lists it with the LAN-privacy directories (`/etc/systemd/resolved.conf.d`,
  `/etc/sysctl.d`, and `/etc/NetworkManager/conf.d` if present). `ProtectControlGroups` is dropped (quarantine
  writes `/sys/fs/cgroup`) and `CAP_NET_ADMIN` added (nftables).
- App froze on Quit (`closeAudit` self-deadlock on `auditMu`).

### Pending before v0.1.0 tag
- Project status: experimental / intermediate development; not yet rigorously tested in real-world environments
- Phase B local build verification (see `docs/SHIP_PLAN.md`)
- Phase C VM-based safety testing — full bricking-risk matrix
- Phase D real hardware compatibility testing
- Windows: fix C1–C6 and C8 (`docs/REVIEW_NOTES_2026-10-20.md`) and run on a real Windows machine
- Linux: run under systemd on a real distribution, with real hardware, a real VPN/Tor setup, systemd-resolved and NetworkManager
- WinGet manifest PR submission to `microsoft/winget-pkgs`
- GitHub repository path updated to `chinmaykx07/DevShield_Windows` in the app metadata and packaging files

## [0.1.0] — unreleased

### Added
(As first written. Several of these do not work today: automatic rollback
and full rollback (C4), the Tor kill-switch (C6), the network guardian's
alerts (C5) and single-UAC setup (C1–C3), and LibreHardwareMonitor's
download is not hash-verified. See the README's status table and
`docs/REVIEW_NOTES_2026-10-20.md`.)
- Thermal profiles: Silent Summer, Gaming Gear, Dev Mode — each with
  before/after sensor verification and automatic rollback on failure
- Privacy enforcer: telemetry hosts-file sinkhole (51 domains),
  registry hardening, Windows Recall and Copilot Runtime blocking
- Network guardian: per-process background monitor with developer-aware
  allowlist (VS Code, Docker, Node, WSL2, etc.) and Windows Toast alerts
- Tor hardening with dynamic install-path detection and firewall kill-switch
- Full rollback system — undo any single action or everything, with
  `-DryRun` preview mode
- Live hardware dashboard (2s refresh) with bilingual HWiNFO-style display
- Bilingual interface throughout: English + Sanskrit (द्विभाषिक)
- System tray app (Go) with Task Scheduler-based elevation — single UAC
  prompt at first run, never again afterward
- SQLite audit log (WAL mode) of every action taken
- Process-aware auto mode switching (optional, off by default)
- Auto-update checker — notifies via tray, never auto-installs
- Cryptographically verifiable releases: Sigstore signing + GitHub
  Artifact Attestation + SHA256 checksums

### Known limitations (tracked for v0.5)
- GPU power/thermal control not yet implemented (CPU only)
- ARM64 build is best-effort (`continue-on-error` in CI)
- No profile export/import yet
- No Scoop bucket yet

[Unreleased]: https://github.com/chinmaykx07/DevShield_Windows/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/chinmaykx07/DevShield_Windows/releases/tag/v0.1.0
