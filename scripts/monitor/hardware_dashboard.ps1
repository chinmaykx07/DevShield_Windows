#Requires -Version 7.0
<#
.SYNOPSIS  DevShield — Live Hardware Dashboard
.DESCRIPTION
    HWiNFO-style real-time terminal dashboard.
    Refreshes every 2 seconds using cursor-overwrite (zero flicker).
    Reads all sensors via LHM bridge. Falls back to basic WMI gracefully.

    Controls (while running):
      [L] — toggle language (EN / SA / BOTH)
      [P] — open profile manager
      [Q] or [Escape] — quit cleanly

.PARAMETER RefreshMs  Refresh interval in milliseconds (default 2000)
.PARAMETER NoClear    Do not clear screen on exit (useful for piped output)
#>
param(
    [int]$RefreshMs = 2000,
    [switch]$NoClear
)

. "$PSScriptRoot\..\core\00_core.ps1"
. "$PSScriptRoot\..\core\02_lhm_bridge.ps1"

Initialize-DevShield -ScriptName "hardware_dashboard.ps1"

# ══════════════════════════════════════════════════════════════
# SECTION 1 — DASHBOARD STATE
# Module-level vars persist across render ticks
# ══════════════════════════════════════════════════════════════
$script:lastNetStats  = $null
$script:lastNetTime   = $null
$script:lastLineCount = 0
$script:renderLines   = [System.Collections.Generic.List[string]]::new()
$script:renderColors  = [System.Collections.Generic.List[string]]::new()
$script:startTime     = Get-Date
$script:tickCount     = 0

# ══════════════════════════════════════════════════════════════
# SECTION 2 — BUFFERED WRITER
# All render functions write to a buffer.
# Flush() writes everything at once — minimises flicker.
# ══════════════════════════════════════════════════════════════
function Clear-RenderBuffer {
    $script:renderLines.Clear()
    $script:renderColors.Clear()
}

function Add-RenderLine {
    param(
        [string]$Text  = "",
        [string]$Color = "White"
    )
    $script:renderLines.Add($Text)
    $script:renderColors.Add($Color)
}

function Flush-RenderBuffer {
    $consoleW = [Math]::Max([Console]::WindowWidth - 1, 40)
    [Console]::SetCursorPosition(0, 0)

    for ($i = 0; $i -lt $script:renderLines.Count; $i++) {
        $raw  = $script:renderLines[$i]
        $col  = $script:renderColors[$i]
        # Pad to console width to overwrite any leftover chars from previous tick
        # Note: emoji/Devanagari chars are wider — we use a soft pad, not truncate
        $line = if ($raw.Length -lt $consoleW) { $raw.PadRight($consoleW) } else { $raw }
        Write-Host $line -ForegroundColor $col -NoNewline
        Write-Host ""   # newline only (avoids double-width issues with PadRight)
    }

    # Clear any lines from a previous taller render
    $overflow = $script:lastLineCount - $script:renderLines.Count
    if ($overflow -gt 0) {
        $blank = " " * $consoleW
        for ($i = 0; $i -lt $overflow; $i++) {
            Write-Host $blank
        }
    }
    $script:lastLineCount = $script:renderLines.Count
}

# ══════════════════════════════════════════════════════════════
# SECTION 3 — RENDER HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════
function Add-Separator { param([char]$Char = "─", [int]$Width = 64)
    Add-RenderLine ("  " + ([string]$Char * $Width)) "DarkGray"
}

function Add-SectionHeader { param([string]$EN, [string]$SA = "")
    $lang  = Get-DSLanguage
    $label = switch ($lang) {
        "EN"   { $EN }
        "SA"   { if ($SA) { $SA } else { $EN } }
        "BOTH" { if ($SA) { "$EN  ·  $SA" } else { $EN } }
    }
    Add-Separator
    Add-RenderLine "  $label" "White"
}

function Get-LoadBar {
    param([double]$Pct, [int]$Width = 10)
    if ($null -eq $Pct -or $Pct -le 0) { return "░" * $Width }
    $filled = [Math]::Min([int](($Pct / 100) * $Width), $Width)
    return ("█" * $filled) + ("░" * ($Width - $filled))
}

function Format-Mhz { param([double]$MHz)
    if (-not $MHz -or $MHz -le 0) { return "?.?? GHz" }
    "$([math]::Round($MHz/1000, 2)) GHz"
}

function Format-BandwidthMBs { param([double]$MBs)
    if ($MBs -lt 0.01) { return "< 0.01 MB/s" }
    "$([math]::Round($MBs, 2)) MB/s"
}

# ══════════════════════════════════════════════════════════════
# SECTION 4 — NETWORK BANDWIDTH (delta between ticks)
# ══════════════════════════════════════════════════════════════
function Get-NetworkBandwidth {
    $now   = Get-Date
    $stats = Get-NetAdapterStatistics -ErrorAction SilentlyContinue |
             Where-Object { $_.InterfaceDescription -notmatch "Loopback|Pseudo|Tunnel|Virtual" }

    $upMBps = 0; $downMBps = 0

    if ($script:lastNetStats -and $script:lastNetTime) {
        $elapsed = ($now - $script:lastNetTime).TotalSeconds
        if ($elapsed -gt 0.1) {
            $sentNow    = ($stats             | Measure-Object SentBytes     -Sum).Sum
            $recvNow    = ($stats             | Measure-Object ReceivedBytes -Sum).Sum
            $sentBefore = ($script:lastNetStats | Measure-Object SentBytes     -Sum).Sum
            $recvBefore = ($script:lastNetStats | Measure-Object ReceivedBytes -Sum).Sum
            $upMBps   = [math]::Max(0, [math]::Round(($sentNow - $sentBefore) / $elapsed / 1MB, 2))
            $downMBps = [math]::Max(0, [math]::Round(($recvNow - $recvBefore) / $elapsed / 1MB, 2))
        }
    }
    $script:lastNetStats = $stats
    $script:lastNetTime  = $now
    return @{ Up = $upMBps; Down = $downMBps }
}

function Get-FlaggedConnections {
    # Lightweight telemetry check — not the full guardian
    # Just surfaces obviously suspicious connections for the dashboard
    $telemetryRanges = @(
        "13.107","52.114","52.184","20.42","40.76",  # Microsoft telemetry
        "telemetry","vortex-win","data.microsoft",
        "auep.amd","events.gfe.nvidia","telemetry.asus"
    )
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction Stop |
                 Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)" }
        $flagged = @()
        foreach ($c in $conns) {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            $suspicious = $telemetryRanges | Where-Object {
                $c.RemoteAddress -match $_ -or $proc.Name -match $_
            }
            if ($suspicious -and $proc) {
                $flagged += "$($proc.Name) → $($c.RemoteAddress)"
            }
        }
        return $flagged | Select-Object -Unique -First 3
    } catch { return @() }
}

function Get-ActiveConnectionCount {
    try {
        return (Get-NetTCPConnection -State Established -ErrorAction Stop |
                Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.)" }).Count
    } catch { return 0 }
}

# ══════════════════════════════════════════════════════════════
# SECTION 5 — RENDER: HEADER
# ══════════════════════════════════════════════════════════════
function Render-Header {
    param([object]$State, [hashtable]$Snap)
    $lang    = Get-DSLanguage
    $mode    = $State.thermal_mode ?? "unknown"
    $uptime  = (Get-Date) - $script:startTime
    $sysUp   = try {
        $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        $diff = (Get-Date) - $boot
        if ($diff.TotalHours -lt 24) { "$([int]$diff.TotalHours)h $($diff.Minutes)m" }
        else                         { "$([int]$diff.TotalDays)d $($diff.Hours)h" }
    } catch { "?" }

    $modeIcons = @{ silent="🔇 Silent Summer  ·  मौन-ग्रीष्म"
                    gaming="🎮 Gaming Gear  ·  क्रीडा-आवृत्ति"
                    dev   ="💻 Dev Mode  ·  विकास-अवस्था"
                    unknown="⬜ No profile set  ·  कोई आकृति नहीं" }
    $modeLabel = $modeIcons[$mode] ?? $mode

    $W   = 64
    $bar = "═" * $W
    $titleEN = "DEVSHIELD HARDWARE DASHBOARD"
    $titleSA = "यन्त्र-निरीक्षण-पट"
    $title   = switch ($lang) {
        "EN"   { $titleEN }
        "SA"   { $titleSA }
        "BOTH" { "$titleEN  ·  $titleSA" }
    }

    Add-RenderLine ""
    Add-RenderLine "  ╔$bar╗" "DarkCyan"
    Add-RenderLine "  ║  🛡  $($title.PadRight($W - 6))║" "Cyan"
    Add-RenderLine "  ╚$bar╝" "DarkCyan"
    Add-RenderLine ""

    Add-RenderLine "  MODE:   $modeLabel" "Cyan"
    Add-RenderLine "  Uptime: $sysUp  ·  Session: $([int]$uptime.TotalMinutes)m  ·  Tick #$($script:tickCount)" "DarkGray"
    $srcLabel = if ($Snap.available) { "LHM (full sensors)" } else { "WMI (limited)" }
    Add-RenderLine "  Source: $srcLabel  ·  [L] language  [P] profiles  [Q] quit" "DarkGray"
    Add-RenderLine ""
}

# ══════════════════════════════════════════════════════════════
# SECTION 6 — RENDER: CPU
# ══════════════════════════════════════════════════════════════
function Render-CPU {
    param([hashtable]$Snap)
    $lang = Get-DSLanguage

    $cpuLabel = switch ($lang) {
        "EN"   { "CPU" }
        "SA"   { "संसाधक" }
        "BOTH" { "CPU · संसाधक" }
    }
    Add-SectionHeader -EN "CPU" -SA "संसाधक"

    if (-not $Snap.available -or $Snap.cpu.Count -eq 0) {
        $load = $Snap.basic_wmi.cpu_load_pct
        Add-RenderLine "  Limited Mode — Load: $load%  $(Get-LoadBar $load)" "DarkGray"
        Add-RenderLine ""
        return
    }

    foreach ($cpu in $Snap.cpu) {
        $pkgTemp  = $cpu.temp_package.current
        $pkgIcon  = $cpu.temp_package.icon
        $load     = $cpu.load_total_pct
        $bar      = Get-LoadBar $load
        $clk      = Format-Mhz $cpu.clock_avg_mhz
        $power    = if ($cpu.power_package_w) { "$($cpu.power_package_w)W" } else { "" }
        $vcore    = if ($cpu.voltage_vcore)   { "Vcore $($cpu.voltage_vcore)V" } else { "" }
        $fan      = if ($cpu.fan_rpm)         { "Fan: $($cpu.fan_rpm) RPM" } else { "" }

        $cpuShort = ($cpu.name -split " " | Select-Object -Last 2) -join " "
        Add-RenderLine "  $cpuShort" "White"
        Add-RenderLine "  Package  $pkgIcon $($pkgTemp)°C  [$bar]  $([int]$load)%  $clk  $power" `
                       (Get-TempColor $pkgTemp)

        # Core grid — 3 per row
        $cores = $cpu.temp_cores
        for ($i = 0; $i -lt $cores.Count; $i += 3) {
            $row = ""
            for ($j = $i; $j -lt [Math]::Min($i+3, $cores.Count); $j++) {
                $c   = $cores[$j]
                $num = ($c.name -replace ".*#","").PadLeft(2)
                $row += "  Core$num $($c.icon) $($c.current)°C"
            }
            Add-RenderLine $row "DarkGray"
        }

        if ($fan -or $vcore) {
            Add-RenderLine "  $fan  $vcore" "DarkGray"
        }
        Add-RenderLine ""
    }
}

# ══════════════════════════════════════════════════════════════
# SECTION 7 — RENDER: GPU(S)
# ══════════════════════════════════════════════════════════════
function Render-GPU {
    param([hashtable]$Snap)

    Add-SectionHeader -EN "GPU" -SA "प्रदर्शन-संसाधक"

    if (-not $Snap.available -or $Snap.gpu.Count -eq 0) {
        Add-RenderLine "  No GPU sensor data (LHM required)" "DarkGray"
        Add-RenderLine ""
        return
    }

    foreach ($gpu in $Snap.gpu) {
        $coreTemp = $gpu.temp_core.current
        $coreIcon = $gpu.temp_core.icon
        $load     = $gpu.load_core_pct
        $bar      = Get-LoadBar $load
        $clk      = if ($gpu.clock_core_mhz) { "$($gpu.clock_core_mhz) MHz" } else { "" }
        $power    = if ($gpu.power_w) { "$($gpu.power_w)W" } else { "" }
        $fan      = if ($gpu.fan_rpm) { "Fan: $($gpu.fan_rpm) RPM ($($gpu.fan_pct)%)" } else { "" }
        $typeTag  = "[$($gpu.vendor.ToUpper()) · $($gpu.type)]"

        $gpuShort = ($gpu.name -split " " | Select-Object -Last 3) -join " "
        Add-RenderLine "  GPU$($gpu.index) · $gpuShort $typeTag" "White"
        Add-RenderLine "  Core   $coreIcon $($coreTemp)°C  [$bar]  $([int]$load)%  $clk  $power" `
                       (Get-TempColor $coreTemp)

        if ($gpu.temp_hotspot.current) {
            $hs = $gpu.temp_hotspot.current
            Add-RenderLine "  Hotspot $($gpu.temp_hotspot.icon) $($hs)°C $(if($gpu.temp_vram.current){"  VRAM $($gpu.temp_vram.icon) $($gpu.temp_vram.current)°C  Load $($gpu.load_vram_pct)%"})" `
                           (Get-TempColor $hs)
        }
        if ($fan) { Add-RenderLine "  $fan" "DarkGray" }
        Add-RenderLine ""
    }
}

# ══════════════════════════════════════════════════════════════
# SECTION 8 — RENDER: FANS
# ══════════════════════════════════════════════════════════════
function Render-Fans {
    param([hashtable]$Snap)
    if (-not $Snap.available -or $Snap.fans.Count -eq 0) { return }

    Add-SectionHeader -EN "FANS" -SA "पंखे"

    foreach ($f in $Snap.fans | Where-Object { $_.rpm -gt 0 }) {
        $bar = Get-LoadBar ([math]::Min(($f.rpm / 3000.0) * 100, 100)) 8
        Add-RenderLine "  $($f.name.PadRight(20)) $($f.rpm) RPM  [$bar]" "DarkGray"
    }
    Add-RenderLine ""
}

# ══════════════════════════════════════════════════════════════
# SECTION 9 — RENDER: DRIVES
# ══════════════════════════════════════════════════════════════
function Render-Drives {
    param([hashtable]$Snap)
    if (-not $Snap.available -or $Snap.drives.Count -eq 0) { return }

    Add-SectionHeader -EN "DRIVES" -SA "संग्रहण"

    foreach ($d in $Snap.drives) {
        $temp    = if ($d.temp_c) { "$($d.temp_c)°C $($d.temp_icon)" } else { "N/A  " }
        $health  = if ($null -ne $d.health_pct) { "Health: $($d.health_pct)%" } else { "" }
        $nameShort = if ($d.name.Length -gt 28) { $d.name.Substring(0,25) + "..." } else { $d.name }
        Add-RenderLine "  $($nameShort.PadRight(30)) $temp  $health" `
                       (if ($d.temp_c) { Get-TempColor $d.temp_c } else { "DarkGray" })
    }
    Add-RenderLine ""
}

# ══════════════════════════════════════════════════════════════
# SECTION 10 — RENDER: NETWORK
# ══════════════════════════════════════════════════════════════
function Render-Network {
    param([hashtable]$BW, [array]$Flagged, [int]$Connections)

    Add-SectionHeader -EN "NETWORK" -SA "जाल-निरीक्षण"

    $upColor   = if ($BW.Up   -gt 5) { "Yellow" } else { "DarkGray" }
    $downColor = if ($BW.Down -gt 5) { "Yellow" } else { "DarkGray" }

    Add-RenderLine "  ↑ $(Format-BandwidthMBs $BW.Up)  ↓ $(Format-BandwidthMBs $BW.Down)  ·  Active: $Connections connections" "DarkGray"

    if ($Flagged.Count -gt 0) {
        foreach ($f in $Flagged) {
            Add-RenderLine "  ⚠  $f" "Yellow"
        }
    } else {
        Add-RenderLine "  ✓  No suspicious connections detected" "DarkGray"
    }
    Add-RenderLine ""
}

# ══════════════════════════════════════════════════════════════
# SECTION 11 — RENDER: AUDIT TAIL
# Shows the 4 most recent events from the event queue
# ══════════════════════════════════════════════════════════════
function Render-AuditTail {
    Add-SectionHeader -EN "RECENT EVENTS" -SA "अन्तिम घटनाएं"

    $events = Get-ChildItem $DS_EVENTS_DIR -Filter "evt_*.json" -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 4 |
              ForEach-Object {
                  try { Get-Content $_.FullName -Raw | ConvertFrom-Json } catch { $null }
              } | Where-Object { $_ }

    if (-not $events -or $events.Count -eq 0) {
        Add-RenderLine "  No events yet." "DarkGray"
    } else {
        foreach ($e in $events) {
            $ts  = try { ([datetime]$e.timestamp).ToString("HH:mm:ss") } catch { "??:??:??" }
            $col = switch ($e.status) {
                "ok"   { "DarkGray" }
                "warn" { "Yellow" }
                "fail" { "Red" }
                default{ "DarkGray" }
            }
            $act = ($e.action ?? "").Replace("_"," ").ToLower()
            Add-RenderLine "  $ts  $act  $($e.detail ?? '')" $col
        }
    }
    Add-RenderLine ""
}

# ══════════════════════════════════════════════════════════════
# SECTION 12 — RENDER: FOOTER
# ══════════════════════════════════════════════════════════════
function Render-Footer {
    Add-Separator
    $now = Get-Date -Format "HH:mm:ss"
    Add-RenderLine "  Updated: $now  ·  Refresh: $($RefreshMs/1000)s  ·  Events: $DS_EVENTS_DIR" "DarkGray"
    Add-RenderLine ""
}

# ══════════════════════════════════════════════════════════════
# SECTION 13 — FULL RENDER TICK
# One complete dashboard frame
# ══════════════════════════════════════════════════════════════
function Invoke-RenderTick {
    $snap    = Get-DSAllSensors
    $state   = Get-DSState
    $bw      = Get-NetworkBandwidth
    $flagged = if ($script:tickCount % 5 -eq 0) { Get-FlaggedConnections } else { @() }
    $connCt  = if ($script:tickCount % 3 -eq 0) { Get-ActiveConnectionCount } else { 0 }

    Clear-RenderBuffer
    Render-Header  -State $state  -Snap $snap
    Render-CPU     -Snap $snap
    Render-GPU     -Snap $snap
    Render-Fans    -Snap $snap
    Render-Drives  -Snap $snap
    Render-Network -BW $bw -Flagged $flagged -Connections $connCt
    Render-AuditTail
    Render-Footer
    Flush-RenderBuffer

    $script:tickCount++
}

# ══════════════════════════════════════════════════════════════
# SECTION 14 — TERMINAL SIZE GUARD
# ══════════════════════════════════════════════════════════════
function Test-TerminalSize {
    $minW = 80; $minH = 30
    $w    = [Console]::WindowWidth
    $h    = [Console]::WindowHeight
    if ($w -lt $minW -or $h -lt $minH) {
        Write-Host "  Terminal too small: ${w}x${h}. Minimum: ${minW}x${minH}." -ForegroundColor Red
        Write-Host "  Please resize your terminal window." -ForegroundColor Yellow
        return $false
    }
    return $true
}

# ══════════════════════════════════════════════════════════════
# SECTION 15 — MAIN LOOP
# ══════════════════════════════════════════════════════════════
function Start-Dashboard {
    # Terminal size check
    if (-not (Test-TerminalSize)) {
        Write-Host "  Press any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }

    # Setup
    Clear-Host
    [Console]::CursorVisible = $false

    Write-DS -EN "LHM starting up..." -SA "LHM आरंभ..." -Level INFO
    Start-DSLHM | Out-Null   # warm up LHM before first tick

    Write-DSAudit -Action "DASHBOARD_STARTED" -Status "ok"

    try {
        while ($true) {
            # Non-blocking key check
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                switch ($key.Key) {
                    "L" {
                        # Toggle language — next tick will re-render with new language
                        Switch-DSLanguage | Out-Null
                    }
                    "P" {
                        # Open profile manager in a new window
                        [Console]::CursorVisible = $true
                        Start-Process pwsh -ArgumentList `
                            "-File `"$PSScriptRoot\profile_manager.ps1`""
                        [Console]::CursorVisible = $false
                    }
                    { $_ -in "Q","Escape" } {
                        Write-DSAudit -Action "DASHBOARD_STOPPED" -Status "ok"
                        return
                    }
                }
            }

            Invoke-RenderTick

            # Split the sleep into small chunks for responsive key detection
            $chunks = [int]($RefreshMs / 100)
            for ($i = 0; $i -lt $chunks; $i++) {
                if ([Console]::KeyAvailable) { break }
                Start-Sleep -Milliseconds 100
            }
        }
    } finally {
        # Always restore cursor even on Ctrl+C
        [Console]::CursorVisible = $true
        if (-not $NoClear) {
            # Move cursor below last render, print exit message
            [Console]::SetCursorPosition(0, $script:lastLineCount + 1)
        }
        Write-DS -EN "Dashboard closed. Sensors still available via profile scripts." `
                 -SA "निरीक्षण-पट बंद। सेंसर प्रोफ़ाइल स्क्रिप्ट से उपलब्ध।" -Level INFO
        Write-DSAudit -Action "DASHBOARD_EXIT" -Status "ok"
    }
}

# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
Start-Dashboard
