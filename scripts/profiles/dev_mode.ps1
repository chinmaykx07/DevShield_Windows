#Requires -Version 7.0
<#
.SYNOPSIS  DevShield — Dev Mode Profile
.DESCRIPTION
    Balanced profile optimised specifically for software development:
      · Boost mode: Efficient Aggressive (Win11) / Enabled (Win10)
        High single-thread burst for compilation, then steps down quietly
      · Processor state capped at 90% — full speed without thermal spikes
      · Display sleep disabled — screen stays on while coding
      · Cooling: Active (responsive) but Efficient Aggressive naturally
        produces less heat than Gaming Gear so fans stay quieter
      · Dev context report: detects active IDEs, runtimes, servers, containers

    Unique to Dev Mode — DEV CONTEXT REPORT:
      Scans running processes and open ports to show exactly what's
      running before applying the profile. This gives the developer a
      full picture of their environment — IDE, runtimes, servers, containers.

    NASA 8-step pattern:
      Pre-flight → Assert → Backup → Act → Verify → Report → Log → Fault-safe

.PARAMETER NoConfirm    Skip confirmation (Go tray via Task Scheduler)
.PARAMETER DryRun       Show actions without applying
.PARAMETER NoSleep      Keep display-sleep setting unchanged
#>
param(
    [switch]$NoConfirm,
    [switch]$DryRun,
    [switch]$NoSleep
)

. "$PSScriptRoot\..\core\00_core.ps1"
. "$PSScriptRoot\..\core\02_lhm_bridge.ps1"

Initialize-DevShield -ScriptName "dev_mode.ps1"

# ══════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════
$PROC_SUB    = "54533251-82be-4824-96c1-47b60b740d00"
$BOOST_MODE  = "be337238-0d82-4146-a38c-c378f404fcbf"
$FREQ_MAX    = "75b0ae3f-bce0-45a7-8c89-c9611c25e100"
$PROC_MAX    = "bc5038f7-23e0-4960-96da-33abaf5935ec"
$COOLING     = "94d3a615-a899-4ac5-ae2b-e4d8f634367f"
$DISP_SUB    = "7516b95f-f776-4464-8c53-06167f40cc99"  # SUB_VIDEO
$DISP_SLEEP  = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"  # Display timeout AC

# Dev mode target values
$BOOST_EFFICIENT = 4   # Efficient Aggressive — Win11 only
$BOOST_ENABLED   = 1   # Enabled — Win10 fallback
$PROC_MAX_DEV    = 90  # 90% processor state — performance without thermal spikes
$FREQ_UNLIMITED  = 0   # No frequency cap — Efficient Aggressive self-regulates
$COOLING_ACTIVE  = 1   # Active cooling — responsive but not turbo
$DISPLAY_NEVER   = 0   # Display sleep = never (while Dev Mode is active)

$VERIFY_WAIT_SEC = 4

# ══════════════════════════════════════════════════════════════
# SECTION 1 — DEV ENVIRONMENT DETECTOR
# The feature unique to Dev Mode.
# Scans processes and ports — returns a rich context object.
# ══════════════════════════════════════════════════════════════

# Process name → display label + category
$DEV_PROCESS_MAP = [ordered]@{
    # IDEs
    "Code"               = @{ Label = "VS Code";           Cat = "IDE" }
    "code - insiders"    = @{ Label = "VS Code Insiders";  Cat = "IDE" }
    "idea64"             = @{ Label = "IntelliJ IDEA";     Cat = "IDE" }
    "webstorm64"         = @{ Label = "WebStorm";          Cat = "IDE" }
    "pycharm64"          = @{ Label = "PyCharm";           Cat = "IDE" }
    "rider64"            = @{ Label = "Rider";             Cat = "IDE" }
    "clion64"            = @{ Label = "CLion";             Cat = "IDE" }
    "devenv"             = @{ Label = "Visual Studio";     Cat = "IDE" }
    "sublime_text"       = @{ Label = "Sublime Text";      Cat = "IDE" }
    "notepad++"          = @{ Label = "Notepad++";         Cat = "IDE" }
    "cursor"             = @{ Label = "Cursor";            Cat = "IDE" }
    # Runtimes
    "node"               = @{ Label = "Node.js";           Cat = "Runtime" }
    "python"             = @{ Label = "Python";            Cat = "Runtime" }
    "python3"            = @{ Label = "Python 3";          Cat = "Runtime" }
    "go"                 = @{ Label = "Go";                Cat = "Runtime" }
    "cargo"              = @{ Label = "Rust/Cargo";        Cat = "Runtime" }
    "java"               = @{ Label = "JVM (Java)";        Cat = "Runtime" }
    "dotnet"             = @{ Label = ".NET";              Cat = "Runtime" }
    "ruby"               = @{ Label = "Ruby";              Cat = "Runtime" }
    "php"                = @{ Label = "PHP";               Cat = "Runtime" }
    # Build tools
    "npm"                = @{ Label = "npm";               Cat = "Build" }
    "pnpm"               = @{ Label = "pnpm";              Cat = "Build" }
    "yarn"               = @{ Label = "Yarn";              Cat = "Build" }
    "gradle"             = @{ Label = "Gradle";            Cat = "Build" }
    "mvn"                = @{ Label = "Maven";             Cat = "Build" }
    "msbuild"            = @{ Label = "MSBuild";           Cat = "Build" }
    "cmake"              = @{ Label = "CMake";             Cat = "Build" }
    "ninja"              = @{ Label = "Ninja";             Cat = "Build" }
    "make"               = @{ Label = "Make";              Cat = "Build" }
    # Containers + VMs
    "Docker Desktop"     = @{ Label = "Docker Desktop";   Cat = "Container" }
    "com.docker.backend" = @{ Label = "Docker Engine";    Cat = "Container" }
    "wsl"                = @{ Label = "WSL2";              Cat = "Container" }
    "VBoxHeadless"       = @{ Label = "VirtualBox VM";    Cat = "Container" }
    "vmware-vmx"         = @{ Label = "VMware VM";        Cat = "Container" }
    # Version control
    "git"                = @{ Label = "Git";               Cat = "VCS" }
    "git-gui"            = @{ Label = "Git GUI";           Cat = "VCS" }
    "GitKraken"          = @{ Label = "GitKraken";         Cat = "VCS" }
    "SourceTree"         = @{ Label = "SourceTree";        Cat = "VCS" }
    # Database clients
    "dbeaver"            = @{ Label = "DBeaver";           Cat = "Database" }
    "DataGrip"           = @{ Label = "DataGrip";          Cat = "Database" }
    "TablePlus"          = @{ Label = "TablePlus";         Cat = "Database" }
    "mysql"              = @{ Label = "MySQL";             Cat = "Database" }
    "postgres"           = @{ Label = "PostgreSQL";        Cat = "Database" }
    "redis-server"       = @{ Label = "Redis";             Cat = "Database" }
    # API tools
    "Postman"            = @{ Label = "Postman";           Cat = "API" }
    "insomnia"           = @{ Label = "Insomnia";          Cat = "API" }
    # Shells
    "pwsh"               = @{ Label = "PowerShell 7";      Cat = "Shell" }
    "WindowsTerminal"    = @{ Label = "Windows Terminal";  Cat = "Shell" }
    "wt"                 = @{ Label = "Windows Terminal";  Cat = "Shell" }
    "bash"               = @{ Label = "Bash (WSL)";        Cat = "Shell" }
    "zsh"                = @{ Label = "Zsh";               Cat = "Shell" }
}

# Common dev server ports → what they likely are
$DEV_PORT_MAP = @{
    3000 = "React/Next.js dev server"
    3001 = "React alternate"
    4000 = "GraphQL / Rails"
    4200 = "Angular dev server"
    5000 = "Flask / ASP.NET"
    5173 = "Vite dev server"
    5432 = "PostgreSQL"
    6379 = "Redis"
    8000 = "Django / FastAPI"
    8080 = "Generic HTTP dev"
    8443 = "HTTPS dev"
    8888 = "Jupyter Notebook"
    9000 = "PHP-FPM / SonarQube"
    9200 = "Elasticsearch"
    9229 = "Node.js debugger"
    27017 = "MongoDB"
}

function Get-DevContext {
    <#
    Returns a structured dev environment snapshot:
    @{
        ides       = @("VS Code", "IntelliJ IDEA")
        runtimes   = @("Node.js v20", "Python 3.12")
        containers = @("Docker Engine")
        build      = @("npm", "Webpack")
        vcs        = @("Git")
        db         = @("PostgreSQL", "Redis")
        servers    = @( @{port=3000; likely="React dev server"} )
        summary    = "VS Code + Node.js + Docker — full-stack dev environment"
    }
    #>
    $procs = Get-Process -ErrorAction SilentlyContinue
    $procNames = $procs | ForEach-Object { $_.ProcessName.ToLower() } | Sort-Object -Unique

    $found = [ordered]@{
        IDE       = @()
        Runtime   = @()
        Build     = @()
        Container = @()
        VCS       = @()
        Database  = @()
        Shell     = @()
        API       = @()
    }

    foreach ($pn in $procNames) {
        foreach ($key in $DEV_PROCESS_MAP.Keys) {
            if ($pn -eq $key.ToLower() -or $pn -match "^$($key.ToLower())") {
                $entry = $DEV_PROCESS_MAP[$key]
                if ($found[$entry.Cat] -notcontains $entry.Label) {
                    $found[$entry.Cat] += $entry.Label
                }
                break
            }
        }
    }

    # Detect local dev servers via open TCP ports
    $servers = @()
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                     Where-Object { $_.LocalAddress -in @("127.0.0.1","0.0.0.0","::1","::") }
        foreach ($l in $listeners) {
            $desc = $DEV_PORT_MAP[[int]$l.LocalPort]
            if ($desc) {
                $ownerProc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
                $servers += @{
                    port   = $l.LocalPort
                    likely = $desc
                    proc   = $ownerProc?.ProcessName ?? "unknown"
                }
            }
        }
    } catch {}

    # Build a human-readable summary
    $topItems = @()
    if ($found.IDE)       { $topItems += $found.IDE[0] }
    if ($found.Runtime)   { $topItems += $found.Runtime[0] }
    if ($found.Container) { $topItems += $found.Container[0] }
    if ($servers.Count)   { $topItems += "$($servers.Count) dev server(s)" }
    $summary = if ($topItems) { $topItems -join " + " } else { "No dev tools detected" }

    return @{
        ides       = $found.IDE
        runtimes   = $found.Runtime
        build      = $found.Build
        containers = $found.Container
        vcs        = $found.VCS
        databases  = $found.Database
        shells     = $found.Shell
        api_tools  = $found.API
        servers    = $servers
        summary    = $summary
        any_found  = ($found.Values | ForEach-Object { $_.Count } |
                      Measure-Object -Sum).Sum -gt 0
    }
}

function Show-DevContextReport {
    param([hashtable]$Ctx)

    Write-DS -EN "DEV ENVIRONMENT" -SA "विकास-पर्यावरण" -Level HEADER
    Write-DSSeparator

    $categories = [ordered]@{
        "IDEs"       = @{ Key = "ides";       SA = "IDE"         }
        "Runtimes"   = @{ Key = "runtimes";   SA = "रनटाइम"      }
        "Containers" = @{ Key = "containers"; SA = "कंटेनर"      }
        "Build"      = @{ Key = "build";      SA = "बिल्ड-उपकरण"  }
        "VCS"        = @{ Key = "vcs";        SA = "संस्करण-नियंत्रण" }
        "Databases"  = @{ Key = "databases";  SA = "डेटाबेस"     }
        "API Tools"  = @{ Key = "api_tools";  SA = "API-उपकरण"   }
    }

    $any = $false
    foreach ($catName in $categories.Keys) {
        $meta  = $categories[$catName]
        $items = $Ctx[$meta.Key]
        if ($items -and $items.Count -gt 0) {
            $any = $true
            $list = $items -join "  ·  "
            Write-DS -EN "$($catName.PadRight(12)): $list" `
                     -SA "$($meta.SA.PadRight(12)): $list" -Level INFO
        }
    }

    if ($Ctx.servers -and $Ctx.servers.Count -gt 0) {
        $any = $true
        Write-DS -EN "Dev Servers  : " -SA "देव-सर्वर    : " -Level INFO -NoNewline
        foreach ($s in $Ctx.servers) {
            Write-Host "  :$($s.port) → $($s.likely) ($($s.proc))" `
                       -ForegroundColor DarkGray
        }
    }

    if (-not $any) {
        Write-DS -EN "No recognised dev tools detected. Dev Mode still useful for general work." `
                 -SA "कोई ज्ञात विकास-उपकरण नहीं मिला। Dev Mode सामान्य कार्य के लिए उपयोगी।" `
                 -Level WARN
    }

    Write-DSSeparator
    Write-DS -EN "Summary: $($Ctx.summary)" -SA "सारांश: $($Ctx.summary)" -Level INFO
    Write-DS -BLANK
}

# ══════════════════════════════════════════════════════════════
# SHARED HELPERS (mirror of silent_summer.ps1 / gaming_gear.ps1)
# ══════════════════════════════════════════════════════════════
function Get-PowerSetting {
    param([string]$SchemeGuid, [string]$Subgroup, [string]$Setting)
    $out = powercfg /query $SchemeGuid $Subgroup $Setting 2>$null
    if ($out -match "Current AC Power Setting Index:\s*(0x[0-9A-Fa-f]+)") {
        return [Convert]::ToInt32($matches[1], 16)
    }
    return $null
}

function Get-WindowsBuild {
    return [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
}

function Write-OutputJSON {
    param(
        [string]$Status     = "ok",
        [string]$Mode       = "dev",
        [string]$Detail     = "",
        [bool]$Verified     = $false,
        [int]$BoostMode     = 0,
        [int]$ProcMax       = 0,
        [bool]$DisplaySleep = $false,
        [string]$DevSummary = ""
    )
    @{
        status          = $Status
        mode            = $Mode
        detail          = $Detail
        verified        = $Verified
        boost_mode      = $BoostMode
        proc_max_pct    = $ProcMax
        display_sleep   = $DisplaySleep
        dev_summary     = $DevSummary
        timestamp       = (Get-Date -Format "o")
    } | ConvertTo-Json -Compress
}

function Invoke-PowercfgRestore {
    param([hashtable]$Rollback, [string]$SchemeGuid)
    Write-DS -EN "Restoring power settings..." -SA "पावर-सेटिंग्स पुनःस्थापित..." -Level WARN
    @(
        @{ Setting = $BOOST_MODE;  Value = $Rollback.boost_mode }
        @{ Setting = $FREQ_MAX;    Value = $Rollback.freq_max_mhz }
        @{ Setting = $PROC_MAX;    Value = $Rollback.proc_max_pct }
        @{ Setting = $COOLING;     Value = $Rollback.cooling_pol }
        @{ Setting = $DISP_SLEEP;  Subgroup = $DISP_SUB; Value = $Rollback.display_timeout }
    ) | Where-Object { $null -ne $_.Value } | ForEach-Object {
        $sub = $_.Subgroup ?? $PROC_SUB
        powercfg -setacvalueindex $SchemeGuid $sub $_.Setting $_.Value 2>$null
    }
    powercfg -setactive $SchemeGuid 2>$null
    Set-DSStateKey -Key "thermal_mode" -Value "unknown"
    Write-DS -EN "Restored." -SA "पुनःस्थापित।" -Level SUCCESS
}

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
function Invoke-DevMode {
    Write-DSBanner -Subtitle "Dev Mode · विकास-अवस्था"
    $hw      = Get-DSHwProfile
    $winBuild = Get-WindowsBuild

    # ── STEP 1: PRE-FLIGHT ────────────────────────────────────
    Write-DS -EN "Scanning dev environment and hardware state..." `
             -SA "विकास-पर्यावरण और यन्त्र-अवस्था स्कैन..." -Level INFO

    # Run dev context detection and sensor read concurrently
    $ctxJob    = Start-Job { Get-DevContext } -ErrorAction SilentlyContinue
    $sensors   = Get-DSAllSensors
    $devCtx    = if ($ctxJob) {
        $ctxJob | Wait-Job | Receive-Job
    } else {
        Get-DevContext
    }

    $cpuTemp = ($sensors.cpu | ForEach-Object { $_.temp_package.current } |
                Where-Object { $_ } | Measure-Object -Maximum).Maximum ?? 0

    # Show what's running
    Show-DevContextReport -Ctx $devCtx

    # Thermal check: Dev Mode is generally safe but warn if very hot
    if ($cpuTemp -gt 80) {
        Write-DS -EN "CPU is at $cpuTemp°C. Dev Mode (90% cap) will help reduce this. Proceeding." `
                 -SA "CPU $cpuTemp°C पर है। Dev Mode (90% सीमा) इसे घटाएगा। जारी है।" -Level WARN
    }

    # Determine correct boost mode for this Windows version
    # PERFBOOSTMODE=4 (Efficient Aggressive) requires Windows 11 Build 22000+
    $boostTarget = if ($winBuild -ge 22000) { $BOOST_EFFICIENT } else { $BOOST_ENABLED }
    $boostLabel  = if ($winBuild -ge 22000) { "Efficient Aggressive (Win11)" } else { "Enabled (Win10 fallback)" }
    Write-DS -EN "Windows Build $winBuild — using boost mode: $boostLabel" `
             -SA "Windows Build $winBuild — बूस्ट मोड: $boostLabel" -Level INFO

    # ── STEP 2: ASSERT ────────────────────────────────────────
    if (-not (Assert-DSAdmin)) {
        Write-OutputJSON -Status "fail" -Detail "Not admin"
        exit 1
    }
    $schemeGuid = Get-DSPowercfgGuid
    if (-not $schemeGuid) {
        Write-DS -EN "Could not read active power scheme GUID." -Level CRITICAL
        Write-OutputJSON -Status "fail" -Detail "No power scheme GUID"
        exit 1
    }

    # ── STEP 3: CONFIRMATION ──────────────────────────────────
    if (-not $NoConfirm -and -not $DryRun) {
        Write-DS -EN "Apply Dev Mode? Boost: $boostLabel. Proc max: $PROC_MAX_DEV%." `
                 -SA "Dev Mode लागू करें? बूस्ट: $boostLabel। संसाधक-सीमा: $PROC_MAX_DEV%।" -Level WARN
        $ans = Read-Host "  [Y] Apply  [N] Cancel"
        if ($ans.ToUpper() -ne "Y") {
            Write-DS -EN "Cancelled." -SA "रद्द।" -Level INFO
            Write-OutputJSON -Status "cancelled"
            exit 0
        }
    }

    if ($DryRun) {
        Write-DS -EN "DRY RUN: Would apply — Boost $boostLabel, ProcMax $PROC_MAX_DEV%, Display never sleep." `
                 -SA "परीक्षण-मोड: बूस्ट $boostLabel, संसाधक-सीमा $PROC_MAX_DEV%, डिस्प्ले सदा जागृत।" -Level WARN
        Write-OutputJSON -Status "dry_run"
        exit 0
    }

    # ── STEP 4: BACKUP ────────────────────────────────────────
    Write-DS -EN "Saving rollback state..." -SA "रोलबैक-अवस्था सहेज रहे हैं..." -Level INFO
    $rollback = @{
        scheme_guid     = $schemeGuid
        boost_mode      = Get-PowerSetting $schemeGuid $PROC_SUB $BOOST_MODE
        freq_max_mhz    = Get-PowerSetting $schemeGuid $PROC_SUB $FREQ_MAX
        proc_max_pct    = Get-PowerSetting $schemeGuid $PROC_SUB $PROC_MAX
        cooling_pol     = Get-PowerSetting $schemeGuid $PROC_SUB $COOLING
        display_timeout = Get-PowerSetting $schemeGuid $DISP_SUB $DISP_SLEEP
        applied_at      = (Get-Date -Format "o")
        win_build       = $winBuild
    }
    $backup = New-DSBackup -Type "powercfg_dev" -Data $rollback
    Write-DS -EN "Rollback saved. ID: $($backup.file | Split-Path -Leaf)" `
             -SA "रोलबैक सहेजा।" -Level SUCCESS

    # ── STEP 5: ACT ───────────────────────────────────────────
    Write-DS -BLANK
    Write-DS -EN "Applying Dev Mode profile..." `
             -SA "विकास-अवस्था आकृति लागू कर रहे हैं..." -Level INFO
    $errors = @()
    $displayDisabled = $false

    try {
        # [1/4] Boost mode (version-aware)
        Write-DSProgress -EN "Setting boost: $boostLabel..." `
                         -SA "बूस्ट सेट: $boostLabel..." -Step 1 -Total 4
        powercfg -setacvalueindex $schemeGuid $PROC_SUB $BOOST_MODE $boostTarget
        if ($LASTEXITCODE -ne 0) { $errors += "BOOST_MODE set failed" }

        # [2/4] Processor state cap (90%)
        Write-DSProgress -EN "Capping processor state at $PROC_MAX_DEV%..." `
                         -SA "संसाधक-अवस्था $PROC_MAX_DEV% पर सीमित..." -Step 2 -Total 4
        powercfg -setacvalueindex $schemeGuid $PROC_SUB $PROC_MAX $PROC_MAX_DEV
        powercfg -setacvalueindex $schemeGuid $PROC_SUB $FREQ_MAX $FREQ_UNLIMITED
        if ($LASTEXITCODE -ne 0) { $errors += "PROC_MAX set failed" }

        # [3/4] Active cooling + apply
        Write-DSProgress -EN "Setting active cooling + activating scheme..." `
                         -SA "सक्रिय शीतलन + योजना सक्रिय..." -Step 3 -Total 4
        powercfg -setacvalueindex $schemeGuid $PROC_SUB $COOLING $COOLING_ACTIVE
        powercfg -setactive $schemeGuid
        if ($LASTEXITCODE -ne 0) { $errors += "Scheme activation failed" }

        # [4/4] Disable display sleep (optional, can be skipped)
        if (-not $NoSleep) {
            Write-DSProgress -EN "Disabling display sleep (Dev Mode keeps screen on)..." `
                             -SA "डिस्प्ले-नींद अक्षम (Dev Mode स्क्रीन जागृत रखता है)..." `
                             -Step 4 -Total 4
            powercfg -setacvalueindex $schemeGuid $DISP_SUB $DISP_SLEEP $DISPLAY_NEVER
            powercfg -setactive $schemeGuid   # re-apply to pick up display change
            $displayDisabled = $true
            Write-DS -EN "Display sleep disabled. Screen will stay on while Dev Mode is active." `
                     -SA "डिस्प्ले-नींद अक्षम। Dev Mode में स्क्रीन जागृत रहेगी।" -Level SUCCESS
        } else {
            Write-DSProgress -EN "Skipping display sleep change (-NoSleep flag)..." `
                             -Step 4 -Total 4
        }
    } catch {
        Write-DS -EN "Exception during apply: $_" -Level CRITICAL
        Invoke-PowercfgRestore -Rollback $rollback -SchemeGuid $schemeGuid
        Write-DSAudit -Action "DEV_MODE_APPLY_EXCEPTION" -Detail "$_" -Status "fail" `
                      -Rollback @{ file = $backup.file; type = "powercfg_dev" }
        Write-OutputJSON -Status "fail" -Detail "Exception: $_"
        exit 1
    }

    if ($errors) {
        $errors | ForEach-Object {
            Write-DS -EN "Partial apply: $_" -Level WARN
        }
    }

    Set-DSStateKey -Key "thermal_mode"       -Value "dev"
    Set-DSStateKey -Key "thermal_applied_at" -Value (Get-Date -Format "o")

    # ── STEP 6: VERIFY ────────────────────────────────────────
    Write-DS -BLANK
    Write-DS -EN "Verifying settings (${VERIFY_WAIT_SEC}s)..." `
             -SA "सेटिंग्स सत्यापन (${VERIFY_WAIT_SEC}s)..." -Level INFO
    Start-Sleep -Seconds $VERIFY_WAIT_SEC

    $newBoost    = Get-PowerSetting $schemeGuid $PROC_SUB $BOOST_MODE
    $newProcMax  = Get-PowerSetting $schemeGuid $PROC_SUB $PROC_MAX
    $newDisplay  = Get-PowerSetting $schemeGuid $DISP_SUB $DISP_SLEEP
    $newCooling  = Get-PowerSetting $schemeGuid $PROC_SUB $COOLING

    $boostOk    = ($newBoost   -eq $boostTarget)
    $procMaxOk  = ($newProcMax -eq $PROC_MAX_DEV)
    $displayOk  = ($NoSleep -or $newDisplay -eq $DISPLAY_NEVER)
    $coolingOk  = ($newCooling  -eq $COOLING_ACTIVE)
    $verified   = $boostOk -and $procMaxOk


    # ── Windows 11 24H2 compatibility ────────────────────────
    # 24H2 added PROCESSOREFFICIENCYCLASSCODE — set explicitly
    # 0 = prefer efficiency, ensures scheduler respects our profile intent
    try {
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCESSOREFFICIENCYCLASSCODE 0
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCESSOREFFICIENCYCLASSCODE 0
    } catch {}  # GUID absent on pre-24H2 — safe to ignore

    # Detect Energy Saver (new in 24H2 — distinct from Power Saver)
    # Energy Saver can override fan curves and frequency caps without warning
    try {
        $esProp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power" `
            -Name "EnergySaverStatus" -ErrorAction SilentlyContinue
        if ($esProp -and $esProp.EnergySaverStatus -eq 1) {
            Write-DS -EN "Note: Windows Energy Saver active — may override fan control." `
                     -SA "नोट: Windows ऊर्जा-बचत सक्रिय — पंखा नियंत्रण प्रभावित।" -Level WARN
        }
    } catch {}

    # ── STEP 7: REPORT ────────────────────────────────────────
    Write-DS -EN "DEV MODE — APPLIED SETTINGS" `
             -SA "विकास-अवस्था — लागू सेटिंग्स" -Level HEADER
    Write-DSSeparator

    Write-DS -EN "Boost Mode   : $(if($boostOk){"✅ $boostLabel"}else{"❌ set $boostTarget, got $newBoost"})" `
             -SA "बूस्ट मोड    : $(if($boostOk){"✅ $boostLabel"}else{"❌ विफल"})" `
             -Level $(if ($boostOk) {"SUCCESS"} else {"CRITICAL"})

    Write-DS -EN "Proc Max     : $(if($procMaxOk){"✅ $PROC_MAX_DEV% (compile fast, no thermal spikes)"}else{"❌ got $newProcMax%"})" `
             -SA "संसाधक-सीमा  : $(if($procMaxOk){"✅ $PROC_MAX_DEV% (संकलन तेज़, ताप-स्पाइक नहीं)"}else{"❌ विफल"})" `
             -Level $(if ($procMaxOk) {"SUCCESS"} else {"CRITICAL"})

    Write-DS -EN "Display Sleep: $(if($displayOk){"✅ Disabled — screen stays on"}else{"⚠ Could not disable"})" `
             -SA "डिस्प्ले-नींद : $(if($displayOk){"✅ अक्षम — स्क्रीन जागृत"}else{"⚠ अक्षम नहीं हो सका"})" `
             -Level $(if ($displayOk) {"SUCCESS"} else {"WARN"})

    Write-DS -EN "Cooling      : $(if($coolingOk){"✅ Active (fan responds to load)"}else{"⚠ Not confirmed"})" `
             -Level $(if ($coolingOk) {"SUCCESS"} else {"WARN"})

    Write-DSSeparator
    Write-DS -BLANK

    # Dev context reminder
    if ($devCtx.any_found) {
        Write-DS -EN "Active dev environment: $($devCtx.summary)" `
                 -SA "सक्रिय विकास-पर्यावरण: $($devCtx.summary)" -Level SUCCESS
    }

    # Explain the 90% proc cap benefit for devs
    Write-DS -EN "90% processor cap: eliminates voltage spikes that cause fan surges during builds." `
             -SA "90% संसाधक-सीमा: बिल्ड के दौरान वोल्टेज-स्पाइक और पंखे की उछाल समाप्त।" -Level INFO
    Write-DS -EN "Efficient Aggressive boost: high burst for compilation, steps down quietly at idle." `
             -SA "Efficient Aggressive बूस्ट: संकलन में तेज़ बर्स्ट, निष्क्रिय में शांत।" -Level INFO

    if ($verified) {
        Write-DS -EN "Dev Mode is active. Happy coding." `
                 -SA "विकास-अवस्था सक्रिय। सुखद कोडिंग।" -Level SUCCESS
    } else {
        Write-DS -EN "Partial apply. Manual check recommended." -Level WARN
    }

    # ── STEP 8: LOG ───────────────────────────────────────────
    Confirm-DSOperation -Action "DEV_MODE" -Backup $backup

    Write-DSAudit `
        -Action   "DEV_MODE_APPLIED" `
        -Detail   "Boost:$newBoost ProcMax:$newProcMax% Display:$($displayDisabled) WinBuild:$winBuild DevEnv:$($devCtx.summary) Verified:$verified" `
        -Mode     "dev" `
        -Rollback @{ file = $backup.file; type = "powercfg_dev" } `
        -Status   $(if ($verified) {"ok"} else {"warn"})

    Write-OutputJSON `
        -Status      $(if ($verified) {"ok"} else {"warn"}) `
        -Mode        "dev" `
        -Verified    $verified `
        -BoostMode   $newBoost `
        -ProcMax     $newProcMax `
        -DisplaySleep $displayDisabled `
        -DevSummary  $devCtx.summary
}

# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
Invoke-DevMode
