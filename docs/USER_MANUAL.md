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
