#Requires -Version 7.0
<#
.SYNOPSIS  DevShield Core Foundation Module
.DESCRIPTION
    Shared functions for every DevShield script.
    Dot-source this first: . "$PSScriptRoot\..\core\00_core.ps1"
    Never run this file directly.
.NOTES
    Version : 0.1.0
    License : Apache 2.0
    Authors : DevShield Project
#>

# ══════════════════════════════════════════════════════════════
# SECTION 1 — ENCODING  (must be first, before any Write-Host)
# ══════════════════════════════════════════════════════════════
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

# ══════════════════════════════════════════════════════════════
# SECTION 2 — GLOBAL CONSTANTS
# ══════════════════════════════════════════════════════════════
$DS_VERSION    = "0.1.0"
$DS_HOME       = Join-Path $env:USERPROFILE ".devshield"
$DS_CONFIG     = Join-Path $DS_HOME "config.json"
$DS_STATE      = Join-Path $DS_HOME "state.json"
$DS_HW_PROFILE = Join-Path $DS_HOME "hardware_profile.json"
$DS_EVENTS_DIR = Join-Path $DS_HOME "events"     # audit queue (JSON files)
$DS_TOOLS_DIR  = Join-Path $DS_HOME "tools"
$DS_BACKUPS    = Join-Path $DS_HOME "backups"
$DS_SCRIPTS    = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

# Temperature thresholds (°C)
$DS_TEMP = @{ Safe = 60; Warm = 75; Hot = 85; Danger = 95 }

# ══════════════════════════════════════════════════════════════
# SECTION 3 — DIRECTORY BOOTSTRAP
# ══════════════════════════════════════════════════════════════
function Initialize-DSDirectories {
    @($DS_HOME, $DS_EVENTS_DIR, $DS_TOOLS_DIR, $DS_BACKUPS) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Force -Path $_ | Out-Null
        }
    }
}

# ══════════════════════════════════════════════════════════════
# SECTION 4 — CONFIG MANAGEMENT
# ══════════════════════════════════════════════════════════════
function Initialize-DSConfig {
    Initialize-DSDirectories
    if (Test-Path $DS_CONFIG) { return }
    [ordered]@{
        language             = "BOTH"
        language_changed     = (Get-Date -Format "o")
        theme                = "dark"
        dashboard_refresh_ms = 2000
        blocklist_auto_update = $true
        created_at           = (Get-Date -Format "o")
        version              = $DS_VERSION
    } | ConvertTo-Json | Set-Content -Path $DS_CONFIG -Encoding UTF8
}

function Get-DSConfig {
    # Returns the full config object. Falls back to safe defaults on any error.
    try {
        $c = Get-Content $DS_CONFIG -Raw -ErrorAction Stop | ConvertFrom-Json
        return $c
    } catch {
        Initialize-DSConfig
        return Get-Content $DS_CONFIG -Raw | ConvertFrom-Json
    }
}

function Set-DSConfigKey {
    param([string]$Key, $Value)
    $c = Get-DSConfig
    $c | Add-Member -NotePropertyName $Key -NotePropertyValue $Value -Force
    $c | ConvertTo-Json | Set-Content -Path $DS_CONFIG -Encoding UTF8
}

# ══════════════════════════════════════════════════════════════
# SECTION 5 — STATE MANAGEMENT
# Shared between PS scripts and Go tray app via state.json
# ══════════════════════════════════════════════════════════════
$DS_STATE_DEFAULTS = [ordered]@{
    thermal_mode        = "unknown"
    thermal_applied_at  = $null
    guardian_running    = $false
    guardian_started_at = $null
    privacy_active      = $false
    privacy_applied_at  = $null
    tor_active          = $false
    tor_applied_at      = $null
    lhm_running         = $false
    last_hw_check       = $null
    updated_at          = $null
}

function Get-DSState {
    try {
        if (Test-Path $DS_STATE) {
            return Get-Content $DS_STATE -Raw | ConvertFrom-Json
        }
    } catch {}
    return $DS_STATE_DEFAULTS | ConvertTo-Json | ConvertFrom-Json
}

function Set-DSStateKey {
    param([string]$Key, $Value)
    $s = Get-DSState
    $s | Add-Member -NotePropertyName $Key -NotePropertyValue $Value -Force
    $s | Add-Member -NotePropertyName "updated_at" -NotePropertyValue (Get-Date -Format "o") -Force
    $s | ConvertTo-Json | Set-Content -Path $DS_STATE -Encoding UTF8
}

# ══════════════════════════════════════════════════════════════
# SECTION 6 — LANGUAGE SYSTEM
# Three modes: EN | SA | BOTH
# Persists in config.json (shared with Go tray app)
# ══════════════════════════════════════════════════════════════
function Get-DSLanguage {
    try {
        $lang = (Get-DSConfig).language
        if ($lang -in @("EN","SA","BOTH")) { return $lang }
    } catch {}
    return "BOTH"
}

function Set-DSLanguage {
    param([ValidateSet("EN","SA","BOTH")][string]$Lang)
    Set-DSConfigKey -Key "language" -Value $Lang
    Set-DSConfigKey -Key "language_changed" -Value (Get-Date -Format "o")
    # Always show bilingual confirmation once so user knows what changed
    $msg = @{ EN = "Language → English only"
              SA = "भाषा → संस्कृत केवलम्"
              BOTH = "Language → English + Sanskrit  ·  भाषा → द्विभाषिक" }
    Write-Host "`n  🌐  $($msg[$Lang])`n" -ForegroundColor Cyan
}

function Switch-DSLanguage {
    # Cycles BOTH → EN → SA → BOTH
    $next = @{ BOTH = "EN"; EN = "SA"; SA = "BOTH" }[(Get-DSLanguage)]
    Set-DSLanguage -Lang $next
    return $next
}

# ══════════════════════════════════════════════════════════════
# SECTION 7 — BILINGUAL OUTPUT ENGINE
# Write-DS is the single output function used by ALL scripts.
# It reads language preference on every call — live toggle works.
# ══════════════════════════════════════════════════════════════
function Write-DS {
    param(
        [string]$EN,
        [string]$SA        = "",
        [ValidateSet("INFO","WARN","SUCCESS","CRITICAL","DEBUG","BLANK")]
        [string]$Level     = "INFO",
        [switch]$NoNewline,
        [switch]$NoIcon
    )

    if ($Level -eq "BLANK") { Write-Host ""; return }

    $cfg = @{
        INFO     = @{ Color = "Cyan";    Icon = "  ·  " }
        WARN     = @{ Color = "Yellow";  Icon = "  ⚠  " }
        SUCCESS  = @{ Color = "Green";   Icon = "  ✅ " }
        CRITICAL = @{ Color = "Red";     Icon = "  🚨 " }
        DEBUG    = @{ Color = "DarkGray";Icon = "  ⬡  " }
    }[$Level]

    $icon = if ($NoIcon) { "     " } else { $cfg.Icon }
    $lang = Get-DSLanguage

    # Fallback: if no SA provided, show EN regardless of language setting
    $showEN = ($lang -in @("EN","BOTH")) -or (-not $SA)
    $showSA = ($lang -in @("SA","BOTH")) -and ($SA -ne "")

    Write-Host $icon -NoNewline -ForegroundColor $cfg.Color

    if ($showEN -and $showSA) {
        Write-Host $EN -NoNewline -ForegroundColor White
        Write-Host "  ·  " -NoNewline -ForegroundColor DarkGray
        if ($NoNewline) { Write-Host $SA -NoNewline -ForegroundColor DarkGray }
        else            { Write-Host $SA -ForegroundColor DarkGray }
    } elseif ($showSA) {
        if ($NoNewline) { Write-Host $SA -NoNewline -ForegroundColor White }
        else            { Write-Host $SA -ForegroundColor White }
    } else {
        if ($NoNewline) { Write-Host $EN -NoNewline -ForegroundColor White }
        else            { Write-Host $EN -ForegroundColor White }
    }
}

function Write-DSSeparator {
    param([int]$Width = 58)
    Write-Host ("  " + ("─" * $Width)) -ForegroundColor DarkGray
}

# ══════════════════════════════════════════════════════════════
# SECTION 8 — BANNER
# ══════════════════════════════════════════════════════════════
function Write-DSBanner {
    param([string]$Subtitle = "")
    $lang = Get-DSLanguage
    $W    = 60

    $title = switch ($lang) {
        "EN"   { "DEVSHIELD" }
        "SA"   { "कवच-यन्त्र" }
        "BOTH" { "DEVSHIELD  ·  कवच-यन्त्र" }
    }
    $tag = switch ($lang) {
        "EN"   { "Privacy · Thermal · Network Intelligence" }
        "SA"   { "गोपनीयता · तापनियंत्रण · जाल-निरीक्षण" }
        "BOTH" { "Privacy · गोपनीयता  ·  Thermal · तापनियंत्रण  ·  Network · जाल-निरीक्षण" }
    }
    $bar = "═" * $W

    Write-Host ""
    Write-Host "  ╔$bar╗"                              -ForegroundColor DarkCyan
    Write-Host "  ║  🛡  $($title.PadRight($W - 6))║"  -ForegroundColor Cyan
    Write-Host "  ║  $($tag.PadRight($W - 2))║"        -ForegroundColor DarkGray
    if ($Subtitle) {
        Write-Host "  ║  $($Subtitle.PadRight($W - 2))║" -ForegroundColor Yellow
    }
    Write-Host "  ╚$bar╝"                              -ForegroundColor DarkCyan

    $langLabel = @{
        EN   = "Language: English"
        SA   = "भाषा: संस्कृत"
        BOTH = "Language: English + Sanskrit  ·  भाषा: द्विभाषिक"
    }[$lang]
    Write-Host "  v$DS_VERSION  ·  $langLabel  ·  [L] toggle  ·  Apache 2.0`n" `
               -ForegroundColor DarkGray
}

# ══════════════════════════════════════════════════════════════
# SECTION 9 — TABLE RENDERER (HWiNFO-style)
# Usage:
#   $rows = @(
#     @{ Sensor = "CPU Package"; Value = "48°C"; Icon = "🟢"; Extra = "28W" },
#     @{ Sensor = "GPU Core";    Value = "38°C"; Icon = "🟢"; Extra = "15%" }
#   )
#   Write-DSTable -Title "Thermal State" -TitleSA "तापीय-अवस्था" -Rows $rows
# ══════════════════════════════════════════════════════════════
function Write-DSTable {
    param(
        [string]$Title,
        [string]$TitleSA = "",
        [array]$Rows,
        [array]$Headers = @("Sensor","Value","Extra"),
        [int]$Col1 = 24, [int]$Col2 = 12, [int]$Col3 = 14
    )

    $lang  = Get-DSLanguage
    $label = if ($TitleSA -and $lang -ne "EN") {
                 if ($lang -eq "SA") { $TitleSA } else { "$Title  ·  $TitleSA" }
             } else { $Title }

    $hl = "─" * $Col1
    $hr = "─" * $Col2
    $hx = "─" * $Col3

    Write-Host "  ┌$hl┬$hr┬$hx┐"                                       -ForegroundColor DarkGray
    Write-Host "  │ $($label.PadRight($Col1 - 1))│ $($Headers[1].PadRight($Col2 - 1))│ $($Headers[2].PadRight($Col3 - 1))│" -ForegroundColor White
    Write-Host "  ├$hl┼$hr┼$hx┤"                                       -ForegroundColor DarkGray

    foreach ($row in $Rows) {
        if ($row.Divider) {
            Write-Host "  ├$hl┼$hr┼$hx┤" -ForegroundColor DarkGray
            continue
        }
        $sensor = $row.Sensor.PadRight($Col1 - 1)
        $val    = "$($row.Icon) $($row.Value)".PadRight($Col2 - 1)
        $extra  = ($row.Extra ?? "").PadRight($Col3 - 1)
        $delta  = if ($row.Delta) { "  $($row.Delta)" } else { "" }

        Write-Host "  │ " -NoNewline -ForegroundColor DarkGray
        Write-Host $sensor  -NoNewline -ForegroundColor White
        Write-Host "│ "    -NoNewline -ForegroundColor DarkGray
        Write-Host $val     -NoNewline -ForegroundColor (Get-TempColor $row.RawTemp)
        Write-Host "│ "    -NoNewline -ForegroundColor DarkGray
        Write-Host $extra   -NoNewline -ForegroundColor DarkGray
        if ($delta) {
            Write-Host $delta -NoNewline -ForegroundColor (if ($row.Delta -match "↓") {"Green"} else {"Red"})
        }
        Write-Host "│" -ForegroundColor DarkGray
    }
    Write-Host "  └$hl┴$hr┴$hx┘" -ForegroundColor DarkGray
    Write-Host ""
}

# ══════════════════════════════════════════════════════════════
# SECTION 10 — TEMPERATURE COLOR HELPER
# ══════════════════════════════════════════════════════════════
function Get-TempIcon {
    param([double]$C)
    if ($null -eq $C -or $C -le 0) { return "⬜" }
    if ($C -lt $DS_TEMP.Safe)      { return "🟢" }
    if ($C -lt $DS_TEMP.Warm)      { return "🟡" }
    if ($C -lt $DS_TEMP.Hot)       { return "🔴" }
    return "🚨"
}

function Get-TempColor {
    param([double]$C)
    if ($null -eq $C -or $C -le 0) { return "DarkGray" }
    if ($C -lt $DS_TEMP.Safe)      { return "Green" }
    if ($C -lt $DS_TEMP.Warm)      { return "Yellow" }
    if ($C -lt $DS_TEMP.Hot)       { return "Red" }
    return "Magenta"
}

# ══════════════════════════════════════════════════════════════
# SECTION 11 — PROGRESS BAR
# ══════════════════════════════════════════════════════════════
function Write-DSProgress {
    param(
        [string]$EN,
        [string]$SA    = "",
        [int]$Step,
        [int]$Total,
        [int]$Width    = 28
    )
    $pct   = [int](($Step / $Total) * 100)
    $filled = [int](($Step / $Total) * $Width)
    $bar   = ("█" * $filled) + ("░" * ($Width - $filled))

    $lang  = Get-DSLanguage
    $label = switch ($lang) {
        "EN"   { $EN }
        "SA"   { if ($SA) { $SA } else { $EN } }
        "BOTH" { if ($SA) { "$EN  ·  $SA" } else { $EN } }
    }
    Write-Host "  [" -NoNewline -ForegroundColor DarkGray
    Write-Host $bar  -NoNewline -ForegroundColor Cyan
    Write-Host "] " -NoNewline  -ForegroundColor DarkGray
    Write-Host "$pct%  " -NoNewline -ForegroundColor White
    Write-Host $label   -ForegroundColor DarkGray
}

# ══════════════════════════════════════════════════════════════
# SECTION 12 — BEFORE / AFTER DELTA DISPLAY
# ══════════════════════════════════════════════════════════════
function Write-DSBeforeAfter {
    param(
        [string]$Label,
        [string]$LabelSA    = "",
        [double]$Before,
        [double]$After,
        [string]$Unit       = "°C",
        [switch]$LowerIsBetter   # temp: lower after = good; freq: higher after = good
    )
    $delta   = $After - $Before
    $absDelta = [math]::Abs($delta)
    $improved = if ($LowerIsBetter) { $delta -lt 0 } else { $delta -gt 0 }
    $arrow    = if ($delta -lt 0) { "↓" } elseif ($delta -gt 0) { "↑" } else { "=" }
    $color    = if ($improved) { "Green" } elseif ($delta -eq 0) { "DarkGray" } else { "Red" }

    $lang   = Get-DSLanguage
    $lbl    = switch ($lang) {
        "EN"   { $Label }
        "SA"   { if ($LabelSA) { $LabelSA } else { $Label } }
        "BOTH" { if ($LabelSA) { "$Label · $LabelSA" } else { $Label } }
    }

    Write-Host "  $lbl".PadRight(30) -NoNewline -ForegroundColor White
    Write-Host "$Before$Unit  →  $After$Unit  " -NoNewline -ForegroundColor DarkGray
    Write-Host "$arrow$absDelta$Unit" -ForegroundColor $color
}

# ══════════════════════════════════════════════════════════════
# SECTION 13 — ADMIN / ELEVATION GUARD
# DevShield uses Task Scheduler (SYSTEM) after first run.
# This function checks + gives clear guidance if not elevated.
# ══════════════════════════════════════════════════════════════
function Assert-DSAdmin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
    if ($isAdmin) { return $true }

    Write-DS -EN "Administrator rights required for this operation." `
             -SA "इस क्रिया के लिए प्रशासक-अधिकार आवश्यक।" -Level WARN
    Write-DS -EN "DevShield should run via Task Scheduler (set up on first run)." `
             -SA "DevShield को Task Scheduler द्वारा चलाएं।" -Level INFO
    Write-DS -EN "To run manually: Right-click → Run as administrator" `
             -SA "मैन्युअल: दायां-क्लिक → प्रशासक के रूप में चलाएं" -Level INFO
    return $false
}

# ══════════════════════════════════════════════════════════════
# SECTION 14 — AUDIT LOG  (JSON event queue)
# PS scripts write JSON files to $DS_EVENTS_DIR
# Go tray app reads + inserts into SQLite + deletes the files
# This keeps PS free of SQLite dependencies entirely
# ══════════════════════════════════════════════════════════════
function Write-DSAudit {
    param(
        [string]$Action,                   # e.g. "THERMAL_SILENT_APPLIED"
        [string]$Detail       = "",        # human-readable description
        [string]$Mode         = "",        # current thermal mode
        [hashtable]$Rollback  = $null,     # undo payload (if destructive)
        [ValidateSet("ok","warn","fail")]
        [string]$Status       = "ok"
    )
    $evt = [ordered]@{
        id           = [System.Guid]::NewGuid().ToString("N").Substring(0,12)
        timestamp    = (Get-Date -Format "o")
        action       = $Action
        detail       = $Detail
        mode         = $Mode
        rollback_json = if ($Rollback) { $Rollback | ConvertTo-Json -Compress } else { $null }
        status       = $Status
        source       = "powershell"
    }
    $file = Join-Path $DS_EVENTS_DIR "evt_$($evt.id).json"
    $evt | ConvertTo-Json | Set-Content -Path $file -Encoding UTF8
}

# ══════════════════════════════════════════════════════════════
# SECTION 15 — HARDWARE PROFILE READER
# ══════════════════════════════════════════════════════════════
function Get-DSHwProfile {
    if (-not (Test-Path $DS_HW_PROFILE)) { return $null }
    try   { return Get-Content $DS_HW_PROFILE -Raw | ConvertFrom-Json }
    catch { return $null }
}

function Get-DSPowercfgGuid {
    # NEVER hardcode this GUID — always read it dynamically
    $line = powercfg /getactivescheme 2>$null
    if ($line -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') {
        return $matches[1]
    }
    return $null
}

# ══════════════════════════════════════════════════════════════
# SECTION 16 — NASA OPERATION PATTERN HELPERS
# Every destructive operation wraps these three calls:
#   1. $backup = New-DSBackup -Type "hosts" -Data $currentContent
#   2. ... do the work ...
#   3. Confirm-DSOperation -Action "SINKHOLE" -Backup $backup
# On failure, Invoke-DSRollback -Backup $backup runs automatically
# ══════════════════════════════════════════════════════════════
function New-DSBackup {
    param(
        [string]$Type,    # e.g. "hosts", "powercfg", "firewall", "registry"
        [object]$Data     # the before-state to preserve
    )
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $file  = Join-Path $DS_BACKUPS "${Type}_${stamp}.json"
    @{
        type      = $Type
        timestamp = (Get-Date -Format "o")
        file      = $file
        data      = $Data
    } | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
    return @{ type = $Type; file = $file; data = $Data }
}

function Confirm-DSOperation {
    param(
        [string]$Action,
        [hashtable]$Backup,
        [hashtable]$Before,
        [hashtable]$After
    )
    Write-DSAudit -Action "${Action}_OK" `
                  -Detail "Backup: $($Backup.file)" `
                  -Rollback @{ file = $Backup.file; type = $Backup.type } `
                  -Status "ok"

    if ($Before -and $After) {
        Write-DS -EN "Verification passed." -SA "सत्यापन सफल।" -Level SUCCESS
        Write-DS -EN "Backup saved: $($Backup.file)" `
                 -SA "बैकअप सहेजा: $($Backup.file)" -Level INFO
    }
}

function Invoke-DSRollback {
    param([hashtable]$Backup)
    if (-not $Backup -or -not (Test-Path $Backup.file)) {
        Write-DS -EN "Rollback failed: no backup found." `
                 -SA "पुनःस्थापना विफल: बैकअप नहीं मिला।" -Level CRITICAL
        return $false
    }
    $saved = Get-Content $Backup.file -Raw | ConvertFrom-Json
    Write-DS -EN "Rolling back $($Backup.type)..." `
             -SA "पुनःस्थापना: $($Backup.type)..." -Level WARN
    Write-DSAudit -Action "ROLLBACK_$($Backup.type.ToUpper())" `
                  -Detail "Restoring from: $($Backup.file)" -Status "warn"
    return $saved
}

# ══════════════════════════════════════════════════════════════
# SECTION 17 — ENTRY POINT
# All scripts call Initialize-DevShield as their first action.
# It ensures directories exist, config is present, PS version OK.
# ══════════════════════════════════════════════════════════════
function Initialize-DevShield {
    param([string]$ScriptName = "Unknown")

    # 1. Verify PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Host "  🚨  DevShield requires PowerShell 7+. Current: $($PSVersionTable.PSVersion)" `
                   -ForegroundColor Red
        Write-Host "  Install: winget install Microsoft.PowerShell" -ForegroundColor Yellow
        exit 1
    }

    # 2. Ensure all directories and config exist
    Initialize-DSDirectories
    Initialize-DSConfig

    # 3. Check if first run (no hardware profile)
    if (-not (Test-Path $DS_HW_PROFILE)) {
        Write-DS -EN "First run detected. Hardware discovery required." `
                 -SA "प्रथम-प्रवेश। यन्त्र-परीक्षण आवश्यक।" -Level WARN
        . "$PSScriptRoot\01_first_run.ps1"
        Invoke-DevShieldFirstRun
    }

    # 4. Log script startup (DEBUG level — not shown to user unless debug mode)
    Write-DSAudit -Action "SCRIPT_START" -Detail $ScriptName -Status "ok"
}
