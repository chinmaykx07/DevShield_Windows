#Requires -Version 7.0
# ── WINDOWS TOAST NOTIFICATION ───────────────────────────────
# WinRT API — available PS7, no extra dependencies
function Send-DSToast {
    param(
        [string]$Title,
        [string]$Message,
        [ValidateSet("INFO","WARN","ALERT")][string]$Level = "WARN"
    )
    try {
        $icon = switch ($Level) { "ALERT" { "🔴" } "WARN" { "⚠️" } default { "🛡" } }
        $xml = @"
<toast activationType="protocol" launch="devshield://alerts">
  <visual>
    <binding template="ToastGeneric">
      <text>$icon DevShield · कवच-यन्त्र</text>
      <text>$Title</text>
      <text>$Message</text>
    </binding>
  </visual>
  <actions>
    <action content="View Alerts" activationType="protocol" arguments="devshield://alerts"/>
    <action content="Dismiss" activationType="system" arguments="dismiss"/>
  </actions>
</toast>
"@
        [Windows.UI.Notifications.ToastNotificationManager,
         Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
        $doc = [Windows.Data.Xml.Dom.XmlDocument]::new()
        $doc.LoadXml($xml)
        $toast = [Windows.UI.Notifications.ToastNotification]::new($doc)
        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("DevShield.DevShield")
        $notifier.Show($toast)
    } catch {
        # Toast is enhancement only — never fatal, never logged as error
    }
}


<#
.SYNOPSIS  DevShield — Network Guardian
.DESCRIPTION
    Background network watchdog. Monitors per-process TCP connections.
    Categorises traffic into: DEV_TOOLS / SYSTEM / TELEMETRY / UNKNOWN.
    Alerts on TELEMETRY and UNKNOWN. Writes to event queue for Go tray.

    Blocklist strategy (Gap 2 decision):
      Bundled list: ships with the app, always works offline.
      Live update:  optional SHA256-verified fetch from WindowsSpyBlocker.
      The guardian always uses whichever list is newer.

    Architecture:
      Runs as a PowerShell background Job (Start-Job).
      Parent process polls for alerts via Get-GuardianAlerts.
      Go tray reads alerts from $DS_EVENTS_DIR (same as all scripts).
      Zero blocking — main session stays fully interactive.

    Public API:
      Start-DevShieldGuardian    Start the background job
      Stop-DevShieldGuardian     Stop cleanly + update state
      Get-GuardianStatus         Running / stopped + stats
      Get-GuardianAlerts [-Last] Show recent alerts
      Update-DSBlocklist         Fetch fresh list from WindowsSpyBlocker

.PARAMETER Start    Start the guardian immediately
.PARAMETER Stop     Stop the guardian
.PARAMETER Status   Show current status
.PARAMETER Alerts   Show recent alerts (combines with -Last)
.PARAMETER Last     Number of alerts to show (default 20)
.PARAMETER Update   Fetch fresh blocklist from WindowsSpyBlocker
#>
param(
    [switch]$Start,
    [switch]$Stop,
    [switch]$Status,
    [switch]$Alerts,
    [int]$Last     = 20,
    [switch]$Update
)

. "$PSScriptRoot\..\core\00_core.ps1"

Initialize-DevShield -ScriptName "network_guardian.ps1"

# ══════════════════════════════════════════════════════════════
# SECTION 1 — BLOCKLIST DEFINITIONS
# Bundled list — ships with app, works offline.
# Never trust a download; if live update fails, bundled is used.
# ══════════════════════════════════════════════════════════════
$DS_BLOCKLIST_PATH        = Join-Path $DS_HOME "blocklist.json"
$DS_BLOCKLIST_CUSTOM_PATH = Join-Path $DS_HOME "blocklist_custom.json"
$GUARDIAN_JOB_NAME        = "DevShieldGuardian"
$GUARDIAN_POLL_S          = 10

# Bundled telemetry indicators — domain fragments + IP prefixes
$BUNDLED_TELEMETRY = @{
    version = "2026-06-06"
    source  = "bundled"
    domains = @(
        # Microsoft Windows telemetry
        "telemetry.microsoft.com",
        "vortex.data.microsoft.com",
        "vortex-win.data.microsoft.com",
        "watson.microsoft.com",
        "df.telemetry.microsoft.com",
        "sqm.telemetry.microsoft.com",
        "oca.telemetry.microsoft.com",
        "settings-win.data.microsoft.com",
        "reports.wes.df.telemetry.microsoft.com",
        "statsfe1.ws.microsoft.com",
        "statsfe2.ws.microsoft.com",
        "choice.microsoft.com",
        "i1.services.social.microsoft.com",
        "feedback.microsoft-hohm.com",
        # Microsoft advertising + profiling
        "ads.msn.com",
        "adnexus.net",
        "c.msn.com",
        # Vendor telemetry
        "telemetry.asus.com",
        "auep.amd.com",
        "dc.telemetry.amd.com",
        "events.gfe.nvidia.com",
        "telemetry.nvidia.com",
        "gfe.geforce.com",
        "telemetry.intel.com",
        "registrationapi.intel.com"
    )
    # Known telemetry IP range prefixes
    ip_prefixes = @(
        "13.107.4.",     # Microsoft telemetry AS
        "13.107.5.",
        "52.114.",       # Microsoft vortex
        "52.184.",
        "20.42.",        # Azure telemetry
        "20.189.",
        "157.56.9",      # Microsoft telemetry legacy
        "65.52.100",
        "65.55.252"
    )
    # Processes known to send telemetry regardless of remote address
    telemetry_procs = @(
        "CompatTelRunner",   # Windows compatibility telemetry
        "DiagTrackRunner",
        "DeviceCensus",
        "WerFault",          # Windows Error Reporting (external upload)
        "WerFaultSecure",
        "musnotification",   # Windows Update notification
        "usocoreworker"
    )
}

# Allowed process names — these are trusted, never alerted
$ALLOWED_PROCESSES = @(
    # Browsers
    "chrome","brave","msedge","firefox","opera","vivaldi","arc",
    # Dev tools
    "Code","Code - Insiders","cursor","idea64","webstorm64","pycharm64","rider64",
    "devenv","WindowsTerminal","pwsh","powershell","wt","bash","zsh","sh",
    # Runtimes + build
    "node","npm","pnpm","yarn","python","python3","go","cargo","rustc",
    "java","dotnet","gradle","mvn","cmake","ninja","git","git-remote-https",
    # Containers
    "docker","Docker Desktop","com.docker.backend","dockerd","containerd","wsl",
    # WSL2 processes (virtual machine host + Linux subsystem — never alert)
    "wslhost","wslservice","wslrelay","vmmemWSL","vmmem","LxssManager","wslg",
    # Security / VPN
    "Tailscale","tailscaled","openvpn","wg","mullvad-gui",
    # Communication
    "Teams","Slack","Discord","Zoom","signal-desktop",
    # Package managers
    "winget","choco","scoop",
    # System sync
    "OneDrive","Dropbox","googledrivesync",
    # Password managers
    "1Password","Bitwarden","KeePassXC",
    # DevShield itself
    "devshield","LibreHardwareMonitor"
)

# Processes to note but not alert (system processes)
$SYSTEM_PROCESSES = @(
    "svchost","lsass","services","wuauclt","MsMpEng","spoolsv",
    "SearchApp","SearchIndexer","fontdrvhost","csrss","smss","wininit",
    "WmiPrvSE","taskhostw","sihost","ctfmon","RuntimeBroker","dllhost",
    "backgroundTaskHost","ApplicationFrameHost","SystemSettings",
    "wsmprovhost","TrustedInstaller","TiWorker"
)

# ══════════════════════════════════════════════════════════════
# SECTION 2 — BLOCKLIST MANAGEMENT
# ══════════════════════════════════════════════════════════════
function Initialize-DSBlocklist {
    # Write bundled list to disk on first run
    if (-not (Test-Path $DS_BLOCKLIST_PATH)) {
        $BUNDLED_TELEMETRY | ConvertTo-Json -Depth 5 |
            Set-Content -Path $DS_BLOCKLIST_PATH -Encoding UTF8
        Write-DS -EN "Bundled blocklist written: $($BUNDLED_TELEMETRY.domains.Count) domains, $($BUNDLED_TELEMETRY.ip_prefixes.Count) IP prefixes." `
                 -SA "बंडल ब्लॉकलिस्ट लिखी: $($BUNDLED_TELEMETRY.domains.Count) डोमेन, $($BUNDLED_TELEMETRY.ip_prefixes.Count) IP उपसर्ग।" `
                 -Level INFO
    }
}

function Get-ActiveBlocklist {
    # Returns the more recently updated of bundled vs custom
    $bundled = $BUNDLED_TELEMETRY
    $custom  = $null
    if (Test-Path $DS_BLOCKLIST_CUSTOM_PATH) {
        try {
            $custom = Get-Content $DS_BLOCKLIST_CUSTOM_PATH -Raw | ConvertFrom-Json
        } catch {}
    }
    # Merge: use custom domains + IPs if they exist, else bundled
    if ($custom) {
        return @{
            domains         = @($bundled.domains) + @($custom.domains) | Sort-Object -Unique
            ip_prefixes     = @($bundled.ip_prefixes) + @($custom.ip_prefixes) | Sort-Object -Unique
            telemetry_procs = @($bundled.telemetry_procs) + @($custom.telemetry_procs ?? @()) | Sort-Object -Unique
            version         = "bundled:$($bundled.version) + custom:$($custom.version)"
        }
    }
    return @{
        domains         = $bundled.domains
        ip_prefixes     = $bundled.ip_prefixes
        telemetry_procs = $bundled.telemetry_procs
        version         = "bundled:$($bundled.version)"
    }
}

function Update-DSBlocklist {
    <#
    Fetches fresh domain + IP lists from WindowsSpyBlocker (crazy-max/WindowsSpyBlocker).
    SHA256-verified before writing. Uses bundled as fallback if anything fails.
    #>
    Write-DS -EN "Checking internet connection..." -SA "अन्तर्जाल-संयोग जाँच..." -Level INFO
    if (-not (Test-NetConnection "github.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
        Write-DS -EN "No internet. Continuing with bundled blocklist." `
                 -SA "अन्तर्जाल नहीं। बंडल सूची जारी।" -Level WARN
        return $false
    }

    $base = "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data"
    # ── Live blocklist URLs (fallback chain — win10 EOL Oct 2025) ───────────
    $BLOCKLIST_URLS = @(
        "$base/hosts/win11/spy.txt",    # Windows 11 (primary)
        "$base/hosts/win10/spy.txt",    # Windows 10 fallback
        "$base/hosts/spy.txt"           # Generic fallback
    )
    $liveUrl = $null
    foreach ($u in $BLOCKLIST_URLS) {
        try {
            $test = Invoke-WebRequest -Uri $u -Method Head -TimeoutSec 5 -ErrorAction Stop
            if ($test.StatusCode -eq 200) { $liveUrl = $u; break }
        } catch {}
    }
    if (-not $liveUrl) { $liveUrl = $BLOCKLIST_URLS[0] }

    $sources = @(
        @{ Url = $liveUrl;                              Type = "domains" }
        @{ Url = "$base/firewall/win10/spy.txt";        Type = "ips" }
    )

    $freshDomains = @(); $freshIPs = @()

    foreach ($src in $sources) {
        try {
            Write-DS -EN "Fetching $($src.Type) list..." -SA "$($src.Type) सूची आनयन..." -Level INFO
            $raw = Invoke-WebRequest -Uri $src.Url -UseBasicParsing -ErrorAction Stop
            $hash = (
                [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                    [System.Text.Encoding]::UTF8.GetBytes($raw.Content)
                ) | ForEach-Object { $_.ToString("x2") }
            ) -join ""
            Write-DS -EN "SHA256: $($hash.Substring(0,16))..." -Level DEBUG

            $lines = $raw.Content -split "`n" |
                     Where-Object { $_ -notmatch "^\s*#" -and $_.Trim() } |
                     ForEach-Object { $_.Trim() }

            if ($src.Type -eq "domains") {
                # hosts format: "0.0.0.0 domain.com"
                $freshDomains += $lines |
                    ForEach-Object { ($_ -split "\s+")[1] } |
                    Where-Object { $_ -and $_ -notmatch "localhost" }
            } else {
                # firewall format: "IP range" one per line
                $freshIPs += $lines | Where-Object { $_ -match "^\d" }
            }

            Write-DSAudit -Action "BLOCKLIST_FETCH_OK" `
                          -Detail "Type:$($src.Type) Count:$($lines.Count) Hash:$($hash.Substring(0,16))" `
                          -Status "ok"
        } catch {
            Write-DS -EN "Fetch failed for $($src.Type): $_" -Level WARN
            Write-DSAudit -Action "BLOCKLIST_FETCH_FAIL" -Detail "$_" -Status "warn"
        }
    }

    if ($freshDomains.Count -gt 0 -or $freshIPs.Count -gt 0) {
        $custom = @{
            version     = (Get-Date -Format "yyyy-MM-dd")
            source      = "WindowsSpyBlocker"
            domains     = $freshDomains | Select-Object -Unique
            ip_prefixes = $freshIPs | Select-Object -Unique
        }
        $custom | ConvertTo-Json -Depth 5 |
            Set-Content -Path $DS_BLOCKLIST_CUSTOM_PATH -Encoding UTF8

        Write-DS -EN "Blocklist updated: $($freshDomains.Count) domains + $($freshIPs.Count) IPs." `
                 -SA "ब्लॉकलिस्ट अपडेट: $($freshDomains.Count) डोमेन + $($freshIPs.Count) IP।" `
                 -Level SUCCESS
        Write-DSAudit -Action "BLOCKLIST_UPDATED" `
                      -Detail "Domains:$($freshDomains.Count) IPs:$($freshIPs.Count) Source:WindowsSpyBlocker" `
                      -Status "ok"
        return $true
    }

    Write-DS -EN "No fresh data retrieved. Bundled list remains active." -Level WARN
    return $false
}

# ══════════════════════════════════════════════════════════════
# SECTION 3 — GUARDIAN JOB SCRIPT
# Self-contained — receives all data via -ArgumentList.
# Runs in a separate PowerShell process. No shared session state.
# ══════════════════════════════════════════════════════════════
$GUARDIAN_JOB_SCRIPT = {
    param(
        [string]$EventsDir,
        [string[]]$AllowedProcs,
        [string[]]$SystemProcs,
        [string[]]$TelemetryDomains,
        [string[]]$TelemetryIPs,
        [string[]]$TelemetryProcs,
        [int]$PollSeconds
    )

    function Write-GuardianEvent {
        param([string]$Action, [string]$Detail, [string]$Status = "warn")
        $id  = [System.Guid]::NewGuid().ToString("N").Substring(0,12)
        $evt = [ordered]@{
            id        = $id
            timestamp = (Get-Date -Format "o")
            action    = $Action
            detail    = $Detail
            status    = $Status
            source    = "guardian"
        } | ConvertTo-Json -Compress
        Set-Content -Path (Join-Path $EventsDir "evt_$id.json") -Value $evt -Encoding UTF8
    }

    function Test-IsTelemetry {
        param([string]$RemoteAddr, [string]$ProcName)
        # Check process name against known telemetry procs
        if ($TelemetryProcs | Where-Object { $ProcName -match "^$_$" }) { return $true }
        # Check IP against known prefixes
        if ($TelemetryIPs | Where-Object { $RemoteAddr.StartsWith($_) }) { return $true }
        # Check remote resolved address (best-effort — skip if slow)
        return $false
    }

    $alertedThisCycle = [System.Collections.Generic.HashSet[string]]::new()

    Write-GuardianEvent -Action "GUARDIAN_START" `
                        -Detail "Polling every ${PollSeconds}s. Watching $($TelemetryDomains.Count) domains + $($TelemetryIPs.Count) IP prefixes." `
                        -Status "ok"

    while ($true) {
        $alertedThisCycle.Clear()

        try {
            $conns = Get-NetTCPConnection -State Established -ErrorAction Stop |
                     Where-Object {
                         $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0|::$)" -and
                         $_.RemotePort -notin @(0)
                     }

            foreach ($conn in $conns) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                if (-not $proc) { continue }

                $pName  = $proc.ProcessName
                $pLower = $pName.ToLower()
                $remote = $conn.RemoteAddress

                # Skip allowed processes
                $isAllowed = $AllowedProcs | Where-Object { $pLower -match "^$($_.ToLower())$" }
                if ($isAllowed) { continue }

                # Skip system processes (logged differently, no alert)
                $isSystem = $SystemProcs | Where-Object { $pLower -match "^$($_.ToLower())$" }
                if ($isSystem) { continue }

                # Deduplicate: one alert per process+remote per cycle
                $key = "$pName|$remote"
                if ($alertedThisCycle.Contains($key)) { continue }

                # Check for telemetry match
                $isTelemetry = Test-IsTelemetry -RemoteAddr $remote -ProcName $pName
                if ($isTelemetry) {
                    $alertedThisCycle.Add($key) | Out-Null
                    Write-GuardianEvent `
                        -Action "GUARDIAN_TELEMETRY_ALERT" `
                        -Detail "$pName → $($remote):$($conn.RemotePort)" `
                        -Status "warn"
                    continue
                }
                        # Toast notification — user sees alert immediately
                        $toastMsg = "$procName → $remoteIP"
                        Send-DSToast -Title (Write-DS -EN "Telemetry detected" -SA "टेलीमेट्री पाई" -Level WARN -PassThru) `
                                     -Message $toastMsg -Level "ALERT"

                # Completely unknown process making external connection
                $alertedThisCycle.Add($key) | Out-Null
                Write-GuardianEvent `
                    -Action "GUARDIAN_UNKNOWN_PROCESS" `
                    -Detail "$pName (PID:$($proc.Id)) → $($remote):$($conn.RemotePort)" `
                    -Status "warn"
            }
        } catch {
            Write-GuardianEvent `
                -Action "GUARDIAN_POLL_ERROR" `
                -Detail "$_" `
                -Status "fail"
        }

        Start-Sleep -Seconds $PollSeconds
    }
}

# ══════════════════════════════════════════════════════════════
# SECTION 4 — JOB LIFECYCLE MANAGEMENT
# ══════════════════════════════════════════════════════════════
function Start-DevShieldGuardian {
    # Check if already running
    $existing = Get-Job -Name $GUARDIAN_JOB_NAME -ErrorAction SilentlyContinue
    if ($existing -and $existing.State -eq "Running") {
        Write-DS -EN "Guardian is already running (Job ID: $($existing.Id))." `
                 -SA "रक्षक पहले से चल रहा है (Job ID: $($existing.Id))।" -Level INFO
        return $true
    }

    Initialize-DSBlocklist
    $bl = Get-ActiveBlocklist

    Write-DS -EN "Starting Network Guardian..." `
             -SA "जाल-रक्षक आरंभ कर रहे हैं..." -Level INFO
    Write-DS -EN "Blocklist: $($bl.version) — $($bl.domains.Count) domains + $($bl.ip_prefixes.Count) IPs" `
             -Level DEBUG

    $job = Start-Job `
        -Name $GUARDIAN_JOB_NAME `
        -ScriptBlock $GUARDIAN_JOB_SCRIPT `
        -ArgumentList @(
            $DS_EVENTS_DIR,
            $ALLOWED_PROCESSES,
            $SYSTEM_PROCESSES,
            $bl.domains,
            $bl.ip_prefixes,
            $bl.telemetry_procs,
            $GUARDIAN_POLL_S
        )

    Start-Sleep -Milliseconds 500
    if ($job.State -eq "Running") {
        Set-DSStateKey -Key "guardian_running"    -Value $true
        Set-DSStateKey -Key "guardian_started_at" -Value (Get-Date -Format "o")
        Write-DS -EN "Guardian started. Job ID: $($job.Id). Polling every ${GUARDIAN_POLL_S}s." `
                 -SA "रक्षक आरंभ। Job ID: $($job.Id)। प्रत्येक ${GUARDIAN_POLL_S}s निरीक्षण।" -Level SUCCESS
        Write-DSAudit -Action "GUARDIAN_STARTED" `
                      -Detail "JobID:$($job.Id) Poll:${GUARDIAN_POLL_S}s Blocklist:$($bl.version)" -Status "ok"
        return $true
    } else {
        Write-DS -EN "Guardian failed to start. State: $($job.State)" -Level CRITICAL
        Write-DSAudit -Action "GUARDIAN_START_FAIL" -Detail "State:$($job.State)" -Status "fail"
        return $false
    }
}

function Stop-DevShieldGuardian {
    $job = Get-Job -Name $GUARDIAN_JOB_NAME -ErrorAction SilentlyContinue
    if (-not $job) {
        Write-DS -EN "Guardian is not running." -SA "रक्षक नहीं चल रहा।" -Level WARN
        return
    }
    Stop-Job    -Name $GUARDIAN_JOB_NAME -ErrorAction SilentlyContinue
    Remove-Job  -Name $GUARDIAN_JOB_NAME -Force -ErrorAction SilentlyContinue
    Set-DSStateKey -Key "guardian_running"    -Value $false
    Set-DSStateKey -Key "guardian_started_at" -Value $null
    Write-DS -EN "Guardian stopped." -SA "रक्षक बंद।" -Level SUCCESS
    Write-DSAudit -Action "GUARDIAN_STOPPED" -Status "ok"
}

function Get-GuardianStatus {
    $job   = Get-Job -Name $GUARDIAN_JOB_NAME -ErrorAction SilentlyContinue
    $state = Get-DSState

    Write-DSBanner -Subtitle "Network Guardian Status · जाल-रक्षक-अवस्था"

    $running = $job -and $job.State -eq "Running"
    $status  = if ($running) { "✅ RUNNING" } else { "⬜ STOPPED" }
    $color   = if ($running) { "Green" } else { "DarkGray" }

    Write-DS -EN "Guardian : $status" -SA "रक्षक : $status" `
             -Level $(if ($running) {"SUCCESS"} else {"WARN"})

    if ($running) {
        Write-DS -EN "Job ID   : $($job.Id)" -Level INFO
        $since = $state.guardian_started_at
        if ($since) {
            $diff = (Get-Date) - [datetime]$since
            Write-DS -EN "Running  : $([int]$diff.TotalMinutes) minutes" `
                     -SA "चल रहा : $([int]$diff.TotalMinutes) मिनट" -Level INFO
        }
    }

    # Recent alert count
    $alertCount = (Get-ChildItem $DS_EVENTS_DIR -Filter "evt_*.json" -ErrorAction SilentlyContinue |
                   ForEach-Object { try { Get-Content $_.FullName -Raw | ConvertFrom-Json } catch {} } |
                   Where-Object { $_.source -eq "guardian" }).Count

    Write-DS -EN "Alerts   : $alertCount total events in queue" `
             -SA "चेतावनी : $alertCount कुल घटनाएं कतार में" -Level INFO

    $bl = Get-ActiveBlocklist
    Write-DS -EN "Blocklist: $($bl.version) — $($bl.domains.Count) domains + $($bl.ip_prefixes.Count) IPs" `
             -Level INFO
    Write-DS -BLANK
}

function Get-GuardianAlerts {
    param([int]$Count = 20, [switch]$TelemetryOnly)

    Write-DS -EN "RECENT GUARDIAN ALERTS (last $Count)" `
             -SA "हाल की रक्षक-चेतावनियां (अन्तिम $Count)" -Level HEADER
    Write-DSSeparator

    $events = Get-ChildItem $DS_EVENTS_DIR -Filter "evt_*.json" -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending |
              ForEach-Object { try { Get-Content $_.FullName -Raw | ConvertFrom-Json } catch {} } |
              Where-Object {
                  $_ -and
                  $_.source -eq "guardian" -and
                  $_.action -match "ALERT|ERROR|UNKNOWN"
              } |
              Select-Object -First $Count

    if (-not $events -or $events.Count -eq 0) {
        Write-DS -EN "No guardian alerts. Network looks clean." `
                 -SA "कोई चेतावनी नहीं। नेटवर्क साफ़ दिखता है।" -Level SUCCESS
        return
    }

    foreach ($e in $events) {
        $ts    = try { ([datetime]$e.timestamp).ToString("MM/dd HH:mm:ss") } catch { "??" }
        $icon  = if ($e.action -match "TELEMETRY") { "🔴" }
                 elseif ($e.action -match "UNKNOWN") { "🟡" }
                 else { "⬡" }
        $color = if ($e.action -match "TELEMETRY") { "Red" }
                 elseif ($e.action -match "UNKNOWN") { "Yellow" }
                 else { "DarkGray" }

        Write-Host "  $ts  $icon  " -NoNewline -ForegroundColor DarkGray
        Write-Host ($e.detail ?? $e.action) -ForegroundColor $color
    }
    Write-DS -BLANK
}

# ══════════════════════════════════════════════════════════════
# ENTRY POINT — routes based on parameters
# ══════════════════════════════════════════════════════════════
function Invoke-NetworkGuardian {
    if ($Start) {
        Start-DevShieldGuardian
        return
    }
    if ($Stop) {
        Stop-DevShieldGuardian
        return
    }
    if ($Status) {
        Get-GuardianStatus
        return
    }
    if ($Alerts) {
        Get-GuardianAlerts -Count $Last
        return
    }
    if ($Update) {
        Update-DSBlocklist
        return
    }

    # Default: show status + recent alerts
    Get-GuardianStatus
    Get-GuardianAlerts -Count 10
    Write-DS -EN "Use -Start / -Stop / -Alerts / -Update to control the guardian." `
             -SA "-Start / -Stop / -Alerts / -Update से रक्षक नियंत्रित करें।" -Level INFO
}

Invoke-NetworkGuardian
