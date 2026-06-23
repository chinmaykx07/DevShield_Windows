#Requires -Version 7.0
<#
.SYNOPSIS  DevShield — Universal Rollback System
.DESCRIPTION
    Undoes any action DevShield has ever performed.
    Reads backup files from ~/.devshield/backups/ and restores
    the exact system state that existed before each operation.

    This is the feature that makes enterprises trust the tool:
    "I can always undo it" removes every adoption barrier.

    Supported rollback types:
      powercfg_silent   → Restore CPU boost + freq cap before Silent Summer
      powercfg_gaming   → Restore power settings before Gaming Gear
      powercfg_dev      → Restore power settings + display sleep before Dev Mode
      privacy_enforcer  → Remove hosts sinkhole + restore registry telemetry settings
      tor_hardening     → Remove kill-switch rules, re-enable LLMNR, restore MAC

    Usage:
      rollback.ps1                    → show all available rollbacks + menu
      rollback.ps1 -Last              → undo most recent action
      rollback.ps1 -Index <N>         → undo action at position N in the list
      rollback.ps1 -Type thermal      → undo all thermal profile changes
      rollback.ps1 -Type hardening    → undo all hardening changes
      rollback.ps1 -All               → undo everything DevShield has done
      rollback.ps1 -DryRun -All       → preview what -All would undo

.PARAMETER Last     Undo most recent action
.PARAMETER Index    Undo action at list position N
.PARAMETER Type     Undo all actions of a type: thermal | hardening | privacy | tor | all
.PARAMETER All      Undo all DevShield actions
.PARAMETER DryRun   Preview without applying
#>
param(
    [switch]$Last,
    [int]$Index      = -1,
    [string]$Type    = "",
    [switch]$All,
    [switch]$DryRun
)

. "$PSScriptRoot\..\core\00_core.ps1"

Initialize-DevShield -ScriptName "rollback.ps1"

# ══════════════════════════════════════════════════════════════
# SECTION 1 — BACKUP DISCOVERY
# Reads backup files, matches to event queue entries, builds
# a sorted list of rollbackable operations newest-first.
# ══════════════════════════════════════════════════════════════
$PROC_SUB   = "54533251-82be-4824-96c1-47b60b740d00"
$BOOST_MODE = "be337238-0d82-4146-a38c-c378f404fcbf"
$FREQ_MAX   = "75b0ae3f-bce0-45a7-8c89-c9611c25e100"
$PROC_MAX   = "bc5038f7-23e0-4960-96da-33abaf5935ec"
$COOLING    = "94d3a615-a899-4ac5-ae2b-e4d8f634367f"
$DISP_SUB   = "7516b95f-f776-4464-8c53-06167f40cc99"
$DISP_SLEEP = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"

# Type → category mapping for -Type filter
$TYPE_CATEGORIES = @{
    "thermal"  = @("powercfg_silent","powercfg_gaming","powercfg_dev")
    "hardening"= @("privacy_enforcer","tor_hardening")
    "privacy"  = @("privacy_enforcer")
    "tor"      = @("tor_hardening")
}

function Get-RollbackableActions {
    $backups = Get-ChildItem $DS_BACKUPS -Filter "*.json" -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending

    $actions = @()
    foreach ($file in $backups) {
        try {
            $data    = Get-Content $file.FullName -Raw | ConvertFrom-Json
            $typePart = ($file.Name -split "_\d{8}")[0]  # e.g. "powercfg_silent"

            $actions += @{
                Index      = 0           # set after sorting
                File       = $file.FullName
                FileName   = $file.Name
                Type       = $typePart
                AppliedAt  = $data.applied_at ?? $file.LastWriteTime.ToString("o")
                Data       = $data
                Timestamp  = $file.LastWriteTime
            }
        } catch { <# skip malformed backup files #> }
    }

    # Number them 1..N newest-first
    for ($i = 0; $i -lt $actions.Count; $i++) {
        $actions[$i].Index = $i + 1
    }
    return $actions
}

# ══════════════════════════════════════════════════════════════
# SECTION 2 — ROLLBACK TABLE DISPLAY
# ══════════════════════════════════════════════════════════════
function Show-RollbackTable {
    param([array]$Actions)

    $lang = Get-DSLanguage
    Write-DSBanner -Subtitle "Rollback System · पुनःस्थापना-प्रणाली"

    if ($Actions.Count -eq 0) {
        Write-DS -EN "No rollbackable actions found. DevShield has not made any changes yet." `
                 -SA "कोई पुनःस्थापन-योग्य क्रिया नहीं। DevShield ने अभी कोई बदलाव नहीं किया।" `
                 -Level INFO
        return
    }

    Write-DS -EN "AVAILABLE ROLLBACKS ($($Actions.Count) actions)" `
             -SA "उपलब्ध पुनःस्थापनाएं ($($Actions.Count) क्रियाएं)" -Level HEADER
    Write-DSSeparator

    # Table header
    $hdr = "  {0,-4} {1,-17} {2,-26} {3}" -f "#", "Time", "Type", "File"
    Write-Host $hdr -ForegroundColor DarkGray

    foreach ($a in $Actions) {
        $ts      = try { ([datetime]$a.AppliedAt).ToString("MMM dd  HH:mm:ss") } catch { "???" }
        $typeCol = switch -Wildcard ($a.Type) {
            "powercfg_silent" { "🔇 powercfg_silent" }
            "powercfg_gaming" { "🎮 powercfg_gaming" }
            "powercfg_dev"    { "💻 powercfg_dev" }
            "privacy_enforcer"{ "🔒 privacy_enforcer" }
            "tor_hardening"   { "🧅 tor_hardening" }
            default           { "·  $($a.Type)" }
        }
        $color = switch -Wildcard ($a.Type) {
            "powercfg*" { "Cyan" }
            "privacy*"  { "Magenta" }
            "tor*"      { "Yellow" }
            default     { "White" }
        }
        $line = "  {0,-4} {1,-17} {2,-26} {3}" -f "#$($a.Index)", $ts, $typeCol, $a.FileName
        Write-Host $line -ForegroundColor $color
    }

    Write-DS -BLANK
    Write-DS -EN "USAGE" -SA "उपयोग" -Level HEADER

    $usageLines = @(
        "  rollback.ps1 -Last              → undo #1 (most recent)"
        "  rollback.ps1 -Index <N>         → undo specific action"
        "  rollback.ps1 -Type thermal      → undo all thermal profile changes"
        "  rollback.ps1 -Type hardening    → undo all hardening changes"
        "  rollback.ps1 -All               → undo everything DevShield has done"
        "  rollback.ps1 -DryRun -All       → preview what -All would undo"
    )
    $usageLines | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
    Write-DS -BLANK
}

# ══════════════════════════════════════════════════════════════
# SECTION 3 — RESTORE FUNCTIONS (one per backup type)
# Each function is standalone — no dependencies on the original script
# ══════════════════════════════════════════════════════════════
function Restore-Powercfg {
    param([hashtable]$Action, [switch]$DryRunMode)

    $d          = $Action.Data
    $schemeGuid = $d.scheme_guid ?? (Get-DSPowercfgGuid)
    $typeName   = $Action.Type

    if (-not $schemeGuid) {
        Write-DS -EN "Cannot restore: no power scheme GUID in backup or active scheme." -Level CRITICAL
        return $false
    }

    $settings = @(
        @{ Setting = $BOOST_MODE;  Value = $d.boost_mode;    Name = "Boost Mode" }
        @{ Setting = $FREQ_MAX;    Value = $d.freq_max_mhz;  Name = "Max Frequency" }
        @{ Setting = $PROC_MAX;    Value = $d.proc_max_pct;  Name = "Max Processor %" }
        @{ Setting = $COOLING;     Value = $d.cooling_pol;   Name = "Cooling Policy" }
    ) | Where-Object { $null -ne $_.Value }

    # Dev mode also saved display timeout
    if ($typeName -eq "powercfg_dev" -and $null -ne $d.display_timeout) {
        $settings += @{ Setting = $DISP_SLEEP; Value = $d.display_timeout
                         Name = "Display Timeout"; Subgroup = $DISP_SUB }
    }

    if ($DryRunMode) {
        Write-DS -EN "DRY RUN — Would restore $($settings.Count) powercfg settings on scheme $schemeGuid" `
                 -SA "परीक्षण — $($settings.Count) powercfg सेटिंग्स पुनःस्थापित होतीं" -Level WARN
        $settings | ForEach-Object {
            Write-DS -EN "  · $($_.Name): → $($_.Value)" -Level DEBUG -NoIcon
        }
        return $true
    }

    $ok = 0; $fail = 0
    foreach ($s in $settings) {
        $sub = $s.Subgroup ?? $PROC_SUB
        try {
            powercfg -setacvalueindex $schemeGuid $sub $s.Setting $s.Value 2>$null
            if ($LASTEXITCODE -eq 0) { $ok++ } else { $fail++ }
        } catch { $fail++ }
    }
    powercfg -setactive $schemeGuid 2>$null

    Set-DSStateKey -Key "thermal_mode" -Value "unknown"

    Write-DS -EN "Power settings restored: $ok ok  $fail failed  (scheme: $schemeGuid)" `
             -SA "पावर-सेटिंग्स: $ok ठीक  $fail विफल" `
             -Level $(if ($fail -eq 0) {"SUCCESS"} else {"WARN"})
    return ($fail -eq 0)
}

function Restore-Privacy {
    param([hashtable]$Action, [switch]$DryRunMode)

    $d = $Action.Data

    if ($DryRunMode) {
        $domainCount = ($d.hosts_content -split "`n" |
                        Where-Object { $_ -match "0\.0\.0\.0" }).Count
        Write-DS -EN "DRY RUN — Would restore hosts file ($domainCount sinkhole lines removed)" `
                 -SA "परीक्षण — Hosts फ़ाइल पुनःस्थापित होती ($domainCount लाइनें हटतीं)" -Level WARN
        Write-DS -EN "         Would restore $($d.registry_before.PSObject.Properties.Count) registry values" `
                 -Level WARN -NoIcon
        return $true
    }

    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
    $ok = $true

    # Restore hosts file from saved content
    if ($d.hosts_content) {
        try {
            Set-Content -Path $hostsPath -Value $d.hosts_content -Encoding UTF8 -NoNewline
            ipconfig /flushdns 2>$null | Out-Null
            Write-DS -EN "Hosts file restored from backup." `
                     -SA "Hosts फ़ाइल बैकअप से पुनःस्थापित।" -Level SUCCESS
        } catch {
            Write-DS -EN "Hosts restore failed: $_" -Level CRITICAL
            $ok = $false
        }
    }

    # Restore registry values
    if ($d.registry_before) {
        $registryTweakPaths = @(
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry" }
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "DoNotShowFeedbackNotifications" }
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry" }
            @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy";  Name = "TailoredExperiencesWithDiagnosticDataEnabled" }
            @{ Path = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules";                      Name = "NumberOfSIUFInPeriod" }
        )

        foreach ($t in $registryTweakPaths) {
            $key   = "$($t.Path)|$($t.Name)"
            $saved = $d.registry_before.$key

            try {
                if ($null -eq $saved) {
                    # Key didn't exist before — remove it
                    Remove-ItemProperty -Path $t.Path -Name $t.Name -ErrorAction SilentlyContinue
                } else {
                    Set-ItemProperty -Path $t.Path -Name $t.Name -Value $saved -Force
                }
            } catch { <# non-fatal — log and continue #> }
        }
        Write-DS -EN "Registry values restored." -SA "रजिस्ट्री मान पुनःस्थापित।" -Level SUCCESS
    }

    # Restore DiagTrack service start type
    if ($d.diagtrack_start) {
        try {
            $startType = [System.ServiceProcess.ServiceStartMode]$d.diagtrack_start
            Set-Service -Name "DiagTrack" -StartupType $startType -ErrorAction SilentlyContinue
            Write-DS -EN "DiagTrack service restored to: $($d.diagtrack_start)" -Level SUCCESS
        } catch {}
    }

    Set-DSStateKey -Key "privacy_active"     -Value $false
    Set-DSStateKey -Key "privacy_applied_at" -Value $null
    return $ok
}

function Restore-TorHardening {
    param([hashtable]$Action, [switch]$DryRunMode)

    $d = $Action.Data

    if ($DryRunMode) {
        $ruleCount = (Get-NetFirewallRule -DisplayName "DEVSHIELD_TOR_*" -EA SilentlyContinue).Count
        Write-DS -EN "DRY RUN — Would remove $ruleCount DEVSHIELD_TOR_* firewall rules" `
                 -SA "परीक्षण — $ruleCount फ़ायरवॉल नियम हटते" -Level WARN
        Write-DS -EN "         Would re-enable LLMNR (was: $($d.llmnr_was))" -Level WARN -NoIcon
        if ($d.adapters) {
            $d.adapters | Where-Object { $_.type -eq "wifi" } | ForEach-Object {
                Write-DS -EN "         Would restore MAC for $($_.name): $($_.original_mac)" -Level WARN -NoIcon
            }
        }
        return $true
    }

    $ok = $true

    # Remove all tagged firewall rules
    $rules = Get-NetFirewallRule -DisplayName "DEVSHIELD_TOR_*" -ErrorAction SilentlyContinue
    if ($rules) {
        $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-DS -EN "$($rules.Count) Tor firewall rules removed." `
                 -SA "$($rules.Count) Tor फ़ायरवॉल नियम हटाए।" -Level SUCCESS
    }

    # Re-enable LLMNR
    try {
        $llmnrPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
        $origVal   = $d.llmnr_was ?? 1
        Set-ItemProperty $llmnrPath -Name "EnableMulticast" -Value $origVal -Type DWord -Force
        Write-DS -EN "LLMNR restored to: $origVal" -SA "LLMNR पुनःस्थापित: $origVal" -Level SUCCESS
    } catch {
        Write-DS -EN "LLMNR restore failed: $_" -Level WARN
        $ok = $false
    }

    # Re-enable NetBIOS (set back to 0 = default/DHCP)
    if ($d.adapters) {
        foreach ($a in $d.adapters) {
            try {
                $nbPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($a.adapter_guid)"
                if (Test-Path $nbPath) {
                    Set-ItemProperty $nbPath -Name "NetbiosOptions" -Value ($a.netbios_was ?? 0) -Type DWord -Force
                }
            } catch {}
        }
        Write-DS -EN "NetBIOS settings restored." -SA "NetBIOS सेटिंग्स पुनःस्थापित।" -Level SUCCESS
    }

    # Restore MAC addresses for Wi-Fi adapters
    if ($d.adapters) {
        foreach ($a in ($d.adapters | Where-Object { $_.type -eq "wifi" -and $_.original_mac })) {
            try {
                $regKey = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" `
                              -ErrorAction SilentlyContinue | Where-Object {
                    (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetCfgInstanceId -eq $a.adapter_guid
                } | Select-Object -First 1

                if ($regKey) {
                    $cleanMac = $a.original_mac -replace "-",""
                    if ($cleanMac -and $cleanMac -ne "") {
                        Set-ItemProperty $regKey.PSPath -Name "NetworkAddress" -Value $cleanMac -Force
                    } else {
                        Remove-ItemProperty $regKey.PSPath -Name "NetworkAddress" -ErrorAction SilentlyContinue
                    }
                    # Restart adapter to apply
                    $adapterName = (Get-NetAdapter | Where-Object {
                        $_.InterfaceGuid -eq "{$($a.adapter_guid)}" -or
                        $_.InterfaceGuid -eq $a.adapter_guid
                    } | Select-Object -First 1)?.Name ?? $a.name

                    if ($adapterName) {
                        Disable-NetAdapter -Name $adapterName -Confirm:$false -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 1500
                        Enable-NetAdapter  -Name $adapterName -Confirm:$false -ErrorAction SilentlyContinue
                        Write-DS -EN "MAC restored for $adapterName → $($a.original_mac)" `
                                 -SA "$adapterName का MAC पुनःस्थापित → $($a.original_mac)" -Level SUCCESS
                    }
                }
            } catch {
                Write-DS -EN "MAC restore for $($a.name) failed: $_" -Level WARN
            }
        }
    }

    Set-DSStateKey -Key "tor_active"     -Value $false
    Set-DSStateKey -Key "tor_applied_at" -Value $null
    return $ok
}

# ══════════════════════════════════════════════════════════════
# SECTION 4 — UNIFIED RESTORE DISPATCHER
# Routes a backup action to the correct restore function
# ══════════════════════════════════════════════════════════════
function Invoke-RestoreAction {
    param([hashtable]$Action, [switch]$DryRunMode)

    if (-not $DryRunMode -and -not (Assert-DSAdmin)) {
        Write-DS -EN "Admin required for rollback." -SA "रोलबैक के लिए प्रशासक-अधिकार आवश्यक।" -Level CRITICAL
        return $false
    }

    $lang    = Get-DSLanguage
    $ts      = try { ([datetime]$Action.AppliedAt).ToString("MMM dd HH:mm:ss") } catch { "unknown" }
    $dryTag  = if ($DryRunMode) { " [DRY RUN]" } else { "" }

    Write-DS -EN "Restoring${dryTag}: $($Action.Type)  (applied $ts)" `
             -SA "पुनःस्थापन${dryTag}: $($Action.Type)  (लागू $ts)" -Level WARN
    Write-DSSeparator

    $result = switch -Wildcard ($Action.Type) {
        "powercfg_*" {
            Restore-Powercfg -Action $Action -DryRunMode:$DryRunMode
        }
        "privacy_enforcer" {
            Restore-Privacy  -Action $Action -DryRunMode:$DryRunMode
        }
        "tor_hardening" {
            Restore-TorHardening -Action $Action -DryRunMode:$DryRunMode
        }
        default {
            Write-DS -EN "Unknown backup type: $($Action.Type). Cannot restore automatically." `
                     -SA "अज्ञात बैकअप प्रकार: $($Action.Type)।" -Level WARN
            $false
        }
    }

    if ($result -and -not $DryRunMode) {
        # Archive the backup file (rename to .restored) so it doesn't show up again
        $newName = $Action.FileName -replace "\.json$", ".restored.json"
        Rename-Item -Path $Action.File -NewName $newName -ErrorAction SilentlyContinue

        Write-DSAudit `
            -Action  "ROLLBACK_$(($Action.Type).ToUpper())" `
            -Detail  "Restored from: $($Action.FileName)" `
            -Status  "ok"

        Write-DS -EN "Rollback complete. Backup archived: $newName" `
                 -SA "पुनःस्थापना सम्पूर्ण। बैकअप संग्रहीत: $newName" -Level SUCCESS
    }
    return $result
}

# ══════════════════════════════════════════════════════════════
# SECTION 5 — MAIN ROUTER
# ══════════════════════════════════════════════════════════════
function Invoke-Rollback {
    $actions = Get-RollbackableActions

    # ── -Last : undo most recent ──────────────────────────────
    if ($Last) {
        if ($actions.Count -eq 0) {
            Write-DS -EN "No actions to rollback." -SA "पुनःस्थापन-योग्य कुछ नहीं।" -Level INFO
            return
        }
        Write-DS -EN "Rolling back most recent action: $($actions[0].Type)..." `
                 -SA "सबसे हाल की क्रिया पुनःस्थापित: $($actions[0].Type)..." -Level WARN
        Invoke-RestoreAction -Action $actions[0] -DryRunMode:$DryRun
        return
    }

    # ── -Index N : undo specific numbered action ──────────────
    if ($Index -gt 0) {
        $target = $actions | Where-Object { $_.Index -eq $Index } | Select-Object -First 1
        if (-not $target) {
            Write-DS -EN "No action found at index $Index. Run rollback.ps1 to see the list." -Level WARN
            return
        }
        Invoke-RestoreAction -Action $target -DryRunMode:$DryRun
        return
    }

    # ── -Type <category> : undo all of a category ─────────────
    if ($Type) {
        $typeFilter = $TYPE_CATEGORIES[$Type.ToLower()]
        if (-not $typeFilter) {
            Write-DS -EN "Unknown type: '$Type'. Valid: thermal, hardening, privacy, tor" -Level WARN
            return
        }
        $targets = $actions | Where-Object { $_.Type -in $typeFilter }
        if ($targets.Count -eq 0) {
            Write-DS -EN "No '$Type' actions found to rollback." -Level INFO
            return
        }
        Write-DS -EN "Rolling back $($targets.Count) '$Type' action(s)..." `
                 -SA "$($targets.Count) '$Type' क्रियाएं पुनःस्थापित..." -Level WARN
        foreach ($t in $targets) { Invoke-RestoreAction -Action $t -DryRunMode:$DryRun }
        return
    }

    # ── -All : undo everything ────────────────────────────────
    if ($All) {
        if ($actions.Count -eq 0) {
            Write-DS -EN "No DevShield actions to rollback. System is clean." -Level SUCCESS
            return
        }
        Write-DS -EN "$(if($DryRun){'DRY RUN: Would rollback'}else{'Rolling back'}) ALL $($actions.Count) DevShield actions..." `
                 -SA "$(if($DryRun){'परीक्षण: '}else{''})सभी $($actions.Count) क्रियाएं पुनःस्थापित..." `
                 -Level WARN
        Write-DS -BLANK

        $ok = 0; $fail = 0
        foreach ($a in $actions) {
            $result = Invoke-RestoreAction -Action $a -DryRunMode:$DryRun
            if ($result) { $ok++ } else { $fail++ }
            Write-DS -BLANK
        }

        Write-DSSeparator
        Write-DS -EN "$(if($DryRun){'DRY RUN complete'}else{'Rollback complete'}): $ok succeeded, $fail failed." `
                 -SA "$(if($DryRun){'परीक्षण सम्पूर्ण'}else{'पुनःस्थापना सम्पूर्ण'}): $ok सफल, $fail विफल।" `
                 -Level $(if ($fail -eq 0) {"SUCCESS"} else {"WARN"})

        if (-not $DryRun) {
            Write-DSAudit -Action "ROLLBACK_ALL" `
                          -Detail "Actions:$($actions.Count) OK:$ok Fail:$fail" -Status "ok"
        }
        return
    }

    # ── No flags : show table + interactive menu ───────────────
    Show-RollbackTable -Actions $actions

    if ($actions.Count -gt 0) {
        Write-DS -EN "Enter action number to rollback, or [Q] to quit:" `
                 -SA "पुनःस्थापन के लिए क्रिया संख्या दर्ज करें, या [Q] बाहर:" -Level INFO
        $choice = Read-Host "  Choice"

        if ($choice.ToUpper() -eq "Q") {
            Write-DS -EN "No changes made." -SA "कोई बदलाव नहीं।" -Level INFO
            return
        }

        $choiceInt = try { [int]$choice } catch { -1 }
        if ($choiceInt -gt 0) {
            $target = $actions | Where-Object { $_.Index -eq $choiceInt } | Select-Object -First 1
            if ($target) {
                Write-DS -EN "Confirm: rollback $($target.Type) applied at $($target.AppliedAt)?" `
                         -SA "पुष्टि करें: $($target.Type) को पुनःस्थापित करें?" -Level WARN
                $confirm = Read-Host "  [Y] Confirm  [N] Cancel"
                if ($confirm.ToUpper() -eq "Y") {
                    Invoke-RestoreAction -Action $target -DryRunMode:$DryRun
                } else {
                    Write-DS -EN "Cancelled." -SA "रद्द।" -Level INFO
                }
            } else {
                Write-DS -EN "Invalid selection: $choiceInt" -Level WARN
            }
        } else {
            Write-DS -EN "Invalid input. Enter a number from the list." -Level WARN
        }
    }
}

# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
Invoke-Rollback
