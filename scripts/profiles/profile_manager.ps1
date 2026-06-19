#Requires -Version 7.0
<#
.SYNOPSIS  DevShield — Profile Manager
.DESCRIPTION
    Central command point for all thermal profiles.
    Shows current state, compares profiles, switches between them.

    Called by:
      Go tray   → schtasks /Run /TN "DevShield\DS_ProfileManager"
      Terminal  → pwsh -File profile_manager.ps1 [-Switch <mode>] [-Show] [-History]

.PARAMETER Switch   Apply a profile directly: silent | gaming | dev
.PARAMETER Show     Show current status and comparison table, then exit
.PARAMETER History  Show recent profile change history from audit log
#>
param(
    [ValidateSet("silent","gaming","dev","")]
    [string]$Switch   = "",
    [switch]$Show,
    [switch]$History
)

. "$PSScriptRoot\..\core\00_core.ps1"
. "$PSScriptRoot\..\core\02_lhm_bridge.ps1"

Initialize-DevShield -ScriptName "profile_manager.ps1"

# ══════════════════════════════════════════════════════════════
# SECTION 1 — PROFILE DEFINITIONS
# Single source of truth for what each profile does
# ══════════════════════════════════════════════════════════════
$PROFILES = [ordered]@{
    silent = @{
        name        = "Silent Summer"
        name_sa     = "मौन-ग्रीष्म"
        icon        = "🔇"
        boost       = "Disabled"
        boost_sa    = "अक्षम"
        freq_cap    = "2800 MHz"
        cooling     = "Passive"
        cooling_sa  = "निष्क्रिय"
        fan_noise   = "Low"
        fan_sa      = "शांत"
        best_for    = "Writing, calls, quiet work"
        best_sa     = "लेखन, कॉल, शांत कार्य"
        color       = "Cyan"
    }
    gaming = @{
        name        = "Gaming Gear"
        name_sa     = "क्रीडा-आवृत्ति"
        icon        = "🎮"
        boost       = "Aggressive"
        boost_sa    = "आक्रामक"
        freq_cap    = "Unlimited"
        cooling     = "Active Turbo"
        cooling_sa  = "सक्रिय-टर्बो"
        fan_noise   = "High"
        fan_sa      = "तेज़"
        best_for    = "Games, benchmarks, rendering"
        best_sa     = "खेल, बेंचमार्क, रेंडरिंग"
        color       = "Magenta"
    }
    dev    = @{
        name        = "Dev Mode"
        name_sa     = "विकास-अवस्था"
        icon        = "💻"
        boost       = "Efficient Aggressive"
        boost_sa    = "कुशल-आक्रामक"
        freq_cap    = "90% state cap"
        cooling     = "Active Balanced"
        cooling_sa  = "सक्रिय-संतुलित"
        fan_noise   = "Medium"
        fan_sa      = "मध्यम"
        best_for    = "Coding, compiling, Docker"
        best_sa     = "कोडिंग, संकलन, Docker"
        color       = "Green"
    }
}

# ══════════════════════════════════════════════════════════════
# SECTION 2 — CURRENT STATE READER
# ══════════════════════════════════════════════════════════════
function Get-CurrentProfileInfo {
    $state   = Get-DSState
    $mode    = $state.thermal_mode ?? "unknown"
    $applied = $state.thermal_applied_at
    $profile = $PROFILES[$mode]

    $sinceStr = if ($applied) {
        $ts   = [datetime]$applied
        $diff = (Get-Date) - $ts
        if     ($diff.TotalMinutes -lt 1)  { "just now" }
        elseif ($diff.TotalMinutes -lt 60) { "$([int]$diff.TotalMinutes)m ago" }
        elseif ($diff.TotalHours   -lt 24) { "$([int]$diff.TotalHours)h ago" }
        else                               { "$([int]$diff.TotalDays)d ago" }
    } else { "never" }

    return @{
        mode    = $mode
        profile = $profile
        applied = $applied
        since   = $sinceStr
        state   = $state
    }
}

# ══════════════════════════════════════════════════════════════
# SECTION 3 — CURRENT STATUS DISPLAY (live sensors + mode)
# ══════════════════════════════════════════════════════════════
function Show-CurrentStatus {
    $info    = Get-CurrentProfileInfo
    $sensors = Get-DSAllSensors
    $lang    = Get-DSLanguage

    Write-DSBanner -Subtitle "Profile Manager · आकृति-प्रबंधक"

    # Current mode block
    Write-DS -EN "CURRENT MODE" -SA "वर्तमान-अवस्था" -Level HEADER
    Write-DSSeparator

    if ($info.mode -eq "unknown" -or -not $info.profile) {
        Write-DS -EN "No profile active. DevShield has not applied a thermal profile yet." `
                 -SA "कोई आकृति सक्रिय नहीं। DevShield ने अभी तक कोई तापीय-आकृति नहीं लगाई।" `
                 -Level WARN
    } else {
        $p = $info.profile
        $nameDisplay = switch ($lang) {
            "EN"   { "$($p.icon) $($p.name)" }
            "SA"   { "$($p.icon) $($p.name_sa)" }
            "BOTH" { "$($p.icon) $($p.name)  ·  $($p.name_sa)" }
        }
        Write-Host "  $nameDisplay" -ForegroundColor $p.color
        Write-DS -EN "Applied: $($info.since)  ($($info.applied ?? 'N/A'))" `
                 -SA "लागू: $($info.since)" -Level INFO
        Write-DS -EN "Best for: $($p.best_for)" -SA "उपयुक्त: $($p.best_sa)" -Level INFO
    }
    Write-DS -BLANK

    # Live sensor snapshot
    Write-DS -EN "LIVE SENSORS" -SA "सक्रिय-सेंसर" -Level HEADER
    if ($sensors.available) {
        $rows = Format-SensorAsTableRows -Snap $sensors
        Write-DSTable -Title "Current · वर्तमान" -Rows $rows
    } else {
        Write-DS -EN "Limited Mode: CPU load $($sensors.basic_wmi.cpu_load_pct)%  Zone $($sensors.basic_wmi.thermal_zone_c)°C" `
                 -SA "सीमित-मोड: CPU लोड $($sensors.basic_wmi.cpu_load_pct)%  क्षेत्र $($sensors.basic_wmi.thermal_zone_c)°C" `
                 -Level WARN
    }
}

# ══════════════════════════════════════════════════════════════
# SECTION 4 — PROFILE COMPARISON TABLE
# Side-by-side view of all three profiles
# ══════════════════════════════════════════════════════════════
function Show-ProfileComparison {
    $lang = Get-DSLanguage
    $info = Get-CurrentProfileInfo
    $W    = 20

    Write-DS -EN "PROFILE COMPARISON" -SA "आकृति-तुलना" -Level HEADER

    $header = "  {0,-6} {1,-$W} {2,-$W} {3,-$W}" -f "", "SILENT SUMMER","GAMING GEAR","DEV MODE"
    $sub    = "  {0,-6} {1,-$W} {2,-$W} {3,-$W}" -f "", "मौन-ग्रीष्म","क्रीडा-आवृत्ति","विकास-अवस्था"

    Write-Host $header -ForegroundColor White
    if ($lang -ne "EN") { Write-Host $sub -ForegroundColor DarkGray }
    Write-Host ("  " + ("─" * (6 + $W*3 + 2))) -ForegroundColor DarkGray

    $rows = @(
        @{ Label="Boost"; LabSA="बूस्ट";    S="Disabled"; G="Aggressive";    D="Efficient Agg." }
        @{ Label="Freq";  LabSA="आवृत्ति";  S="2800 MHz";  G="Unlimited";     D="Unlimited (90%)" }
        @{ Label="Cooling";LabSA="शीतलन";   S="Passive";   G="Active Turbo";  D="Active Balanced" }
        @{ Label="Fans";  LabSA="पंखे";     S="🔇 Quiet";  G="🔊 Loud";       D="🔈 Medium" }
        @{ Label="Best";  LabSA="उपयुक्त";  S="Quiet work";G="Games";         D="Coding" }
    )

    foreach ($r in $rows) {
        $lbl = switch ($lang) {
            "EN"   { $r.Label }
            "SA"   { $r.LabSA }
            "BOTH" { "$($r.Label) · $($r.LabSA)" }
        }
        $line = "  {0,-6} {1,-$W} {2,-$W} {3,-$W}" -f $lbl, $r.S, $r.G, $r.D
        Write-Host $line -ForegroundColor DarkGray
    }

    Write-Host ("  " + ("─" * (6 + $W*3 + 2))) -ForegroundColor DarkGray

    # Mark current profile with ●
    $markers = @("","","")
    $idx     = @("silent","gaming","dev").IndexOf($info.mode)
    if ($idx -ge 0) { $markers[$idx] = "● ACTIVE" }

    $activeLine = "  {0,-6} {1,-$W} {2,-$W} {3,-$W}" -f "", $markers[0], $markers[1], $markers[2]
    Write-Host $activeLine -ForegroundColor Cyan
    Write-DS -BLANK
}

# ══════════════════════════════════════════════════════════════
# SECTION 5 — RECENT HISTORY (reads event queue + audit)
# ══════════════════════════════════════════════════════════════
function Show-ProfileHistory {
    param([int]$Count = 10)

    Write-DS -EN "RECENT PROFILE HISTORY ($Count events)" `
             -SA "हाल का इतिहास ($Count घटनाएं)" -Level HEADER
    Write-DSSeparator

    # Read from events directory (JSON queue files written by PS scripts)
    $events = Get-ChildItem $DS_EVENTS_DIR -Filter "evt_*.json" -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First $Count |
              ForEach-Object {
                  try { Get-Content $_.FullName -Raw | ConvertFrom-Json }
                  catch { $null }
              } |
              Where-Object { $_ -and $_.action -match "APPLIED|ROLLBACK|FIRST_RUN" }

    if (-not $events -or $events.Count -eq 0) {
        Write-DS -EN "No profile events recorded yet." `
                 -SA "अभी तक कोई आकृति-घटना नहीं।" -Level INFO
        return
    }

    foreach ($evt in $events) {
        $ts      = if ($evt.timestamp) { [datetime]$evt.timestamp } else { Get-Date }
        $timeStr = $ts.ToString("MMM dd  HH:mm:ss")
        $icon    = switch -Wildcard ($evt.action) {
            "*SILENT*"  { "🔇" }
            "*GAMING*"  { "🎮" }
            "*DEV*"     { "💻" }
            "*ROLLBACK*"{ "↩" }
            "*FIRST*"   { "🛡" }
            default     { "·" }
        }
        $statusColor = switch ($evt.status) {
            "ok"   { "Green" }
            "warn" { "Yellow" }
            "fail" { "Red" }
            default{ "DarkGray" }
        }
        Write-Host "  $timeStr  $icon  " -NoNewline -ForegroundColor DarkGray
        Write-Host $evt.action.PadRight(30) -NoNewline -ForegroundColor White
        Write-Host " $($evt.status ?? '')" -ForegroundColor $statusColor
        if ($evt.detail -and $evt.detail.Length -gt 0) {
            Write-Host "           $($evt.detail)" -ForegroundColor DarkGray
        }
    }
    Write-DS -BLANK
}

# ══════════════════════════════════════════════════════════════
# SECTION 6 — INTERACTIVE MENU
# Shown when no flags are passed
# ══════════════════════════════════════════════════════════════
function Show-ProfileMenu {
    Write-DS -EN "SELECT A PROFILE" -SA "आकृति चुनें" -Level HEADER
    Write-DSSeparator

    $lang = Get-DSLanguage
    foreach ($key in $PROFILES.Keys) {
        $p      = $PROFILES[$key]
        $label  = switch ($lang) {
            "EN"   { "$($p.icon) $($p.name)" }
            "SA"   { "$($p.icon) $($p.name_sa)" }
            "BOTH" { "$($p.icon) $($p.name)  ·  $($p.name_sa)" }
        }
        $bestFor = switch ($lang) {
            "EN"   { $p.best_for }
            "SA"   { $p.best_sa }
            "BOTH" { "$($p.best_for)  ·  $($p.best_sa)" }
        }
        Write-Host "  [$($key.Substring(0,1).ToUpper())] $label" `
                   -ForegroundColor $p.color -NoNewline
        Write-Host "  —  $bestFor" -ForegroundColor DarkGray
    }
    Write-Host "  [H] History" -ForegroundColor DarkGray
    Write-Host "  [Q] Quit" -ForegroundColor DarkGray
    Write-DS -BLANK

    $choice = Read-Host "  Choice"
    return $choice.ToUpper()
}

# ══════════════════════════════════════════════════════════════
# SECTION 7 — PROFILE SWITCHER
# Calls the correct script via Task Scheduler task
# (RunLevel=Highest, no UAC prompt after first-run setup)
# ══════════════════════════════════════════════════════════════
function Invoke-ProfileSwitch {
    param([string]$Mode)

    $taskMap = @{
        silent = "DevShield\DS_SilentSummer"
        gaming = "DevShield\DS_GamingGear"
        dev    = "DevShield\DS_DevMode"
    }

    $taskName = $taskMap[$Mode]
    if (-not $taskName) {
        Write-DS -EN "Unknown profile: $Mode" -Level CRITICAL
        return $false
    }

    $p = $PROFILES[$Mode]
    Write-DS -EN "Switching to $($p.name)..." `
             -SA "$($p.name_sa) पर स्विच कर रहे हैं..." -Level INFO

    # Verify task exists before running
    $task = Get-ScheduledTask -TaskPath "\DevShield\" `
                              -TaskName ($taskName -split "\\")[-1] `
                              -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-DS -EN "Task not found: $taskName" `
                 -SA "कार्य नहीं मिला: $taskName" -Level CRITICAL
        Write-DS -EN "Run first-run setup to register tasks." `
                 -SA "कार्य पंजीकरण के लिए प्रथम-रन सेटअप चलाएं।" -Level INFO
        return $false
    }

    # Trigger the task (RunLevel=Highest — no UAC)
    $result = schtasks /Run /TN $taskName /I 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-DS -EN "$($p.name) profile is now being applied..." `
                 -SA "$($p.name_sa) आकृति लागू हो रही है..." -Level SUCCESS
        return $true
    } else {
        Write-DS -EN "Task trigger failed: $result" `
                 -SA "कार्य ट्रिगर विफल: $result" -Level CRITICAL
        Write-DS -EN "Falling back to direct script execution..." `
                 -SA "प्रत्यक्ष स्क्रिप्ट निष्पादन पर वापस..." -Level WARN

        # Fallback: run the script directly with self-elevation
        $scriptPath = switch ($Mode) {
            "silent" { Join-Path $PSScriptRoot "silent_summer.ps1" }
            "gaming" { Join-Path $PSScriptRoot "gaming_gear.ps1" }
            "dev"    { Join-Path $PSScriptRoot "dev_mode.ps1" }
        }
        Start-Process pwsh `
            -ArgumentList "-NonInteractive -File `"$scriptPath`" -NoConfirm" `
            -Verb RunAs `
            -Wait
        return $true
    }
}

# ══════════════════════════════════════════════════════════════
# SECTION 8 — JSON OUTPUT (for Go tray)
# ══════════════════════════════════════════════════════════════
function Write-PMOutputJSON {
    param([string]$Status = "ok", [string]$Mode = "", [string]$Detail = "")
    $info = Get-CurrentProfileInfo
    @{
        status       = $Status
        current_mode = $info.mode
        since        = $info.since
        detail       = $Detail
        timestamp    = (Get-Date -Format "o")
    } | ConvertTo-Json -Compress
}

# ══════════════════════════════════════════════════════════════
# ENTRY POINT — routes based on parameters
# ══════════════════════════════════════════════════════════════
function Invoke-ProfileManager {

    # Direct switch (from Go tray or CLI: -Switch silent/gaming/dev)
    if ($Switch) {
        Show-CurrentStatus
        $ok = Invoke-ProfileSwitch -Mode $Switch
        Write-PMOutputJSON -Status $(if($ok){"ok"}else{"fail"}) -Mode $Switch
        return
    }

    # Show-only mode (no interaction)
    if ($Show) {
        Show-CurrentStatus
        Show-ProfileComparison
        Write-PMOutputJSON -Status "ok"
        return
    }

    # History mode
    if ($History) {
        Write-DSBanner -Subtitle "Profile History · आकृति-इतिहास"
        Show-ProfileHistory -Count 20
        return
    }

    # Interactive mode — full dashboard + menu
    Show-CurrentStatus
    Show-ProfileComparison

    :menuLoop while ($true) {
        $choice = Show-ProfileMenu

        switch ($choice) {
            "S" { Invoke-ProfileSwitch -Mode "silent"; break menuLoop }
            "G" { Invoke-ProfileSwitch -Mode "gaming"; break menuLoop }
            "D" { Invoke-ProfileSwitch -Mode "dev";    break menuLoop }
            "H" { Show-ProfileHistory; continue menuLoop }
            "Q" {
                Write-DS -EN "No changes made." -SA "कोई बदलाव नहीं।" -Level INFO
                break menuLoop
            }
            default {
                Write-DS -EN "Invalid choice. Enter S, G, D, H or Q." `
                         -SA "अमान्य विकल्प। S, G, D, H या Q दर्ज करें।" -Level WARN
            }
        }
    }

    Write-PMOutputJSON -Status "ok"
}

Invoke-ProfileManager
