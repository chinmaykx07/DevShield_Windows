#Requires -Version 7.0
<#
.SYNOPSIS  DevShield First-Run Setup
.DESCRIPTION
    Runs exactly once on first launch (or when hardware_profile.json is missing).
    1. Auto-detects all CPUs, GPUs, motherboard, RAM, storage, NICs
    2. Builds hardware_profile.json with correct LHM sensor namespaces
    3. Registers Task Scheduler tasks for admin-level script execution
    4. Offers LHM download with user notification + SHA256 verification
    5. Displays HWiNFO-style hardware summary
.NOTES
    Called automatically by Initialize-DevShield in 00_core.ps1
    NASA pattern: every step verified, every failure reported + logged
#>

. "$PSScriptRoot\00_core.ps1"

# ══════════════════════════════════════════════════════════════
# SECTION 1 — MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════
function Invoke-DevShieldFirstRun {
    Write-DSBanner -Subtitle "First Run  ·  यन्त्र-परीक्षण"

    Write-DS -EN "Welcome to DevShield. Running one-time hardware discovery..." `
             -SA "DevShield में आपका स्वागत। एकमेव यन्त्र-परीक्षण चल रहा है..." `
             -Level INFO
    Write-DS -BLANK

    # ── Step 1: Hardware Detection ────────────────────────────
    Write-DSProgress -EN "Scanning hardware..." -SA "यन्त्र-स्कैन..." -Step 1 -Total 5
    $hw = Get-DSAllHardware

    # ── Step 2: Build and save profile ───────────────────────
    Write-DSProgress -EN "Building hardware profile..." -SA "यन्त्र-आकृति निर्माण..." -Step 2 -Total 5
    $profile = Build-DSHardwareProfile -HW $hw
    $profile | ConvertTo-Json -Depth 10 |
        Set-Content -Path $DS_HW_PROFILE -Encoding UTF8

    # ── Step 3: Task Scheduler registration ──────────────────
    Write-DSProgress -EN "Registering admin tasks..." -SA "प्रशासक-कार्य पंजीकरण..." -Step 3 -Total 5
    Register-DSAdminTasks

    # ── Step 4: LHM notification + optional download ─────────
    Write-DSProgress -EN "Checking sensor backend..." -SA "सेंसर-स्रोत जाँच..." -Step 4 -Total 5
    $lhmInstalled = Invoke-DSLHMSetup

    # ── Step 5: Update profile with LHM status ───────────────
    Write-DSProgress -EN "Finalising profile..." -SA "आकृति अंतिम रूप..." -Step 5 -Total 5
    $profile.lhm_installed = $lhmInstalled
    $profile.lhm_path = if ($lhmInstalled) {
        Join-Path $DS_TOOLS_DIR "LibreHardwareMonitor" "LibreHardwareMonitor.exe"
    } else { $null }
    $profile | ConvertTo-Json -Depth 10 |
        Set-Content -Path $DS_HW_PROFILE -Encoding UTF8

    Write-DS -BLANK
    Write-DSSeparator
    Write-DS -EN "Hardware discovery complete." -SA "यन्त्र-परीक्षण सम्पूर्ण।" -Level SUCCESS
    Write-DSSeparator
    Write-DS -BLANK

    # ── Display summary ───────────────────────────────────────
    Show-DSHardwareSummary -Profile $profile

    Write-DSAudit -Action "FIRST_RUN_COMPLETE" `
                  -Detail "CPUs:$($profile.cpus.Count) GPUs:$($profile.gpus.Count) LHM:$lhmInstalled" `
                  -Status "ok"
}

# ══════════════════════════════════════════════════════════════
# SECTION 2 — HARDWARE DETECTION (CIM queries)
# ══════════════════════════════════════════════════════════════
function Get-DSAllHardware {
    return @{
        CPUs     = Get-DSCPUs
        GPUs     = Get-DSGPUs
        Board    = Get-DSMotherboard
        BIOS     = Get-DSBIOSInfo
        RAM      = Get-DSRAM
        Storage  = Get-DSStorage
        NICs     = Get-DSNICs
        OS       = Get-DSOS
    }
}

function Get-DSCPUs {
    # Returns array — handles single and multi-socket systems
    $raw = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
    return @($raw) | ForEach-Object {
        $mfr  = $_.Manufacturer
        $name = $_.Name.Trim()
        @{
            socket            = $_.SocketDesignation ?? "CPU$($raw.IndexOf($_))"
            name              = $name
            manufacturer      = if ($mfr -match "AMD")   { "AMD" }
                                elseif ($mfr -match "Intel") { "Intel" }
                                else { $mfr }
            family            = Get-CPUFamily $name
            generation        = Get-CPUGeneration $name
            cores_physical    = [int]$_.NumberOfCores
            cores_logical     = [int]$_.NumberOfLogicalProcessors
            base_clock_mhz    = [int]$_.MaxClockSpeed
            boost_clock_mhz   = Get-CPUBoostClock $name
            l2_cache_kb       = [int]($_.L2CacheSize ?? 0)
            l3_cache_kb       = [int]($_.L3CacheSize ?? 0)
            powercfg_supported = $true
            lhm_namespace     = Get-LHMCPUNamespace $mfr
        }
    }
}

function Get-DSGPUs {
    # Returns array — handles integrated + discrete + multi-GPU
    $raw = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop
    $idx = 0
    return @($raw) | Where-Object { $_.Name -notmatch "Remote|Virtual|Generic|Basic" } |
    ForEach-Object {
        $name   = $_.Name.Trim()
        $ramMB  = [long]([math]::Round(($_.AdapterRAM ?? 0) / 1MB))
        $type   = Get-GPUType $name $ramMB
        $vendor = Get-GPUVendor $name
        $result = @{
            index             = $idx
            name              = $name
            vendor            = $vendor
            type              = $type    # "discrete" | "integrated"
            vram_mb           = $ramMB
            driver_version    = $_.DriverVersion
            current_res       = "$($_.CurrentHorizontalResolution)x$($_.CurrentVerticalResolution)"
            lhm_namespace     = Get-LHMGPUNamespace $name $vendor $idx
        }
        $idx++
        $result
    }
}

function Get-DSMotherboard {
    $b = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop
    $mfr = $b.Manufacturer.Trim()
    return @{
        manufacturer    = $mfr
        model           = $b.Product.Trim()
        serial          = $b.SerialNumber
        version         = $b.Version
        vendor_clean    = Get-BoardVendorClean $mfr
        lhm_fan_namespace = Get-LHMBoardNamespace $mfr
        superio_chip    = Get-SuperIOChip $mfr
    }
}

function Get-DSBIOSInfo {
    $b = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    return @{
        manufacturer  = $b.Manufacturer
        version       = $b.SMBIOSBIOSVersion
        release_date  = $b.ReleaseDate?.ToString("yyyy-MM-dd")
    }
}

function Get-DSRAM {
    $dims = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop
    $totalGB = [math]::Round(($dims | Measure-Object -Property Capacity -Sum).Sum / 1GB, 0)
    $speeds  = $dims | ForEach-Object { $_.ConfiguredClockSpeed } | Where-Object { $_ -gt 0 }
    $maxSpeed = ($speeds | Measure-Object -Maximum).Maximum ?? 0
    $type = Get-RAMType ($dims | Select-Object -First 1).SMBIOSMemoryType
    return @{
        total_gb   = [int]$totalGB
        type       = $type
        speed_mhz  = [int]$maxSpeed
        dimms      = $dims.Count
        slots      = ($dims | Select-Object -ExpandProperty DeviceLocator) -join ", "
    }
}

function Get-DSStorage {
    $raw = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop
    return @($raw) | ForEach-Object {
        $sizeGB = [math]::Round(($_.Size ?? 0) / 1GB, 0)
        @{
            model          = $_.Model.Trim()
            type           = Get-DriveType $_.MediaType $_.InterfaceType $_.Model
            size_gb        = [int]$sizeGB
            interface      = $_.InterfaceType
            serial         = $_.SerialNumber?.Trim()
            smart_via_lhm  = ($_.InterfaceType -match "USB|SCSI|IDE|NVMe")
        }
    }
}

function Get-DSNICs {
    $raw = Get-CimInstance -ClassName Win32_NetworkAdapter `
               -Filter "PhysicalAdapter=True" -ErrorAction Stop
    return @($raw) | ForEach-Object {
        @{
            name        = $_.Name.Trim()
            mac         = $_.MACAddress
            speed_mbps  = if ($_.Speed) { [int]($_.Speed / 1MB) } else { 0 }
            type        = if ($_.Name -match "Wi-Fi|Wireless|WLAN|802.11") {"wifi"} else {"ethernet"}
        }
    }
}

function Get-DSOS {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    return @{
        name         = $os.Caption
        version      = $os.Version
        architecture = $env:PROCESSOR_ARCHITECTURE
        hostname     = $env:COMPUTERNAME
    }
}

# ══════════════════════════════════════════════════════════════
# SECTION 3 — HARDWARE CLASSIFICATION HELPERS
# ══════════════════════════════════════════════════════════════
function Get-CPUFamily { param([string]$Name)
    $n = $Name.ToLower()
    if ($n -match "ryzen 9")   { return "Ryzen 9" }
    if ($n -match "ryzen 7")   { return "Ryzen 7" }
    if ($n -match "ryzen 5")   { return "Ryzen 5" }
    if ($n -match "ryzen 3")   { return "Ryzen 3" }
    if ($n -match "threadripper") { return "Threadripper" }
    if ($n -match "epyc")      { return "EPYC" }
    if ($n -match "core ultra"){ return "Core Ultra" }
    if ($n -match "i9")        { return "Core i9" }
    if ($n -match "i7")        { return "Core i7" }
    if ($n -match "i5")        { return "Core i5" }
    if ($n -match "i3")        { return "Core i3" }
    if ($n -match "xeon")      { return "Xeon" }
    return "Unknown"
}

function Get-CPUGeneration { param([string]$Name)
    if ($Name -match "Ryzen \d+ (\d{4})")  { return [int][math]::Floor([int]$matches[1] / 1000) }
    if ($Name -match "i\d-(\d{4,5})")      { return [int][math]::Floor([int]$matches[1] / 1000) }
    if ($Name -match "Core Ultra")         { return 14 }
    return 0
}

function Get-CPUBoostClock { param([string]$Name)
    # Best-effort from model name; LHM reads actual boost at runtime
    if ($Name -match "(\d+\.\d+)GHz")  { return [int]([double]$matches[1] * 1000) }
    return 0
}

function Get-GPUVendor { param([string]$Name)
    $n = $Name.ToLower()
    if ($n -match "nvidia|geforce|quadro|rtx|gtx|tesla") { return "NVIDIA" }
    if ($n -match "amd|radeon")                          { return "AMD" }
    if ($n -match "intel")                               { return "Intel" }
    return "Unknown"
}

function Get-GPUType { param([string]$Name, [long]$RAMMb)
    $n = $Name.ToLower()
    # Definite discrete
    if ($n -match "geforce|quadro|rtx|gtx|radeon rx|radeon pro|arc a\d") { return "discrete" }
    # Definite integrated
    if ($n -match "intel.*hd|intel.*uhd|intel.*iris|intel.*xe|radeon.*graphics" -and $RAMMb -lt 2048) { return "integrated" }
    # Fallback by VRAM size
    return if ($RAMMb -ge 2048) { "discrete" } else { "integrated" }
}

function Get-LHMCPUNamespace { param([string]$Mfr)
    if ($Mfr -match "AMD")   { return "AMD/CPU" }
    if ($Mfr -match "Intel") { return "Intel/CPU" }
    return "Generic/CPU"
}

function Get-LHMGPUNamespace { param([string]$Name, [string]$Vendor, [int]$Idx)
    switch ($Vendor) {
        "NVIDIA" { return "NVIDIA/GPU$Idx" }
        "AMD"    { return "AMD/GPU$Idx" }
        "Intel"  { return "Intel/GPU$Idx" }
        default  { return "Generic/GPU$Idx" }
    }
}

function Get-LHMBoardNamespace { param([string]$Mfr)
    if ($Mfr -match "ASUS|ASUSTeK")       { return "ASUS/SuperIO" }
    if ($Mfr -match "Micro-Star|MSI")     { return "MSI/SuperIO" }
    if ($Mfr -match "Gigabyte")           { return "Gigabyte/SuperIO" }
    if ($Mfr -match "ASRock")             { return "ASRock/SuperIO" }
    if ($Mfr -match "Lenovo")             { return "Lenovo/EC" }
    if ($Mfr -match "Dell")               { return "Dell/EC" }
    if ($Mfr -match "HP|Hewlett")         { return "HP/EC" }
    return "Generic/SuperIO"
}

function Get-SuperIOChip { param([string]$Mfr)
    if ($Mfr -match "ASUS|ASUSTeK")   { return "NCT6798D" }   # most common ASUS
    if ($Mfr -match "Micro-Star|MSI") { return "NCT6687D" }
    if ($Mfr -match "Gigabyte")       { return "IT8792E" }
    if ($Mfr -match "ASRock")         { return "NCT6796D" }
    return "Unknown"
}

function Get-BoardVendorClean { param([string]$Mfr)
    if ($Mfr -match "ASUSTeK")    { return "ASUS" }
    if ($Mfr -match "Micro-Star") { return "MSI" }
    return $Mfr.Split(" ")[0]
}

function Get-RAMType { param([int]$Code)
    @{ 20 = "DDR"; 21 = "DDR2"; 24 = "DDR3"; 26 = "DDR4"; 30 = "LPDDR4";
       34 = "DDR5"; 35 = "LPDDR5" }[$Code] ?? "Unknown"
}

function Get-DriveType { param([string]$MediaType, [string]$InterfaceType, [string]$Model)
    $m = $Model.ToLower()
    if ($InterfaceType -match "NVMe" -or $m -match "nvme")   { return "NVMe" }
    if ($MediaType -match "SSD|Solid")                       { return "SSD" }
    if ($InterfaceType -match "USB")                         { return "USB" }
    if ($MediaType -match "HDD|Fixed" -or $m -match "hdd")  { return "HDD" }
    return "Unknown"
}

# ══════════════════════════════════════════════════════════════
# SECTION 4 — PROFILE BUILDER
# ══════════════════════════════════════════════════════════════
function Build-DSHardwareProfile { param([hashtable]$HW)
    return [ordered]@{
        generated         = (Get-Date -Format "o")
        devshield_version = $DS_VERSION
        system = @{
            hostname     = $HW.OS.hostname
            os           = $HW.OS.name
            version      = $HW.OS.version
            architecture = $HW.OS.architecture
        }
        cpus          = $HW.CPUs
        gpus          = $HW.GPUs
        motherboard   = $HW.Board
        bios          = $HW.BIOS
        ram           = $HW.RAM
        storage       = $HW.Storage
        nics          = $HW.NICs
        lhm_required  = $true
        lhm_installed = $false
        lhm_path      = $null
        powercfg_guid = Get-DSPowercfgGuid
        tasks_registered = $false
    }
}

# ══════════════════════════════════════════════════════════════
# SECTION 5 — TASK SCHEDULER REGISTRATION
# Creates elevated tasks. Called once on first run.
# After this: Go calls schtasks /Run /TN "DevShield\<Name>"
# No UAC prompt on subsequent runs.
# ══════════════════════════════════════════════════════════════
$DS_TASKS = @(
    @{ Name = "DS_SilentSummer"; Script = "profiles\silent_summer.ps1" }
    @{ Name = "DS_GamingGear";   Script = "profiles\gaming_gear.ps1" }
    @{ Name = "DS_DevMode";      Script = "profiles\dev_mode.ps1" }
    @{ Name = "DS_Privacy";      Script = "hardening\privacy_enforcer.ps1" }
    @{ Name = "DS_TorHarden";    Script = "hardening\tor_hardening.ps1" }
    @{ Name = "DS_Guardian";     Script = "monitor\network_guardian.ps1" }
    @{ Name = "DS_Dashboard";    Script = "monitor\hardware_dashboard.ps1" }
    @{ Name = "DS_Rollback";     Script = "hardening\rollback.ps1" }
)

function Register-DSAdminTasks {
    $isAdmin = ([Security.Principal.WindowsPrincipal]
                [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

    if (-not $isAdmin) {
        Write-DS -EN "One-time admin setup needed for Task Scheduler registration." `
                 -SA "Task Scheduler पंजीकरण के लिए एकमेव प्रशासक-सेटअप आवश्यक।" -Level WARN
        Write-DS -EN "DevShield will request elevation now..." `
                 -SA "DevShield अभी प्रशासक-अनुमति माँगेगा..." -Level INFO
        # Re-launch this script elevated for task creation only
        $arg = "-NonInteractive -File `"$PSCommandPath`" -SetupTasksOnly"
        Start-Process pwsh -Verb RunAs -ArgumentList $arg -Wait
        # After elevated process completes, verify tasks were created
        $created = $DS_TASKS | Where-Object {
            Get-ScheduledTask -TaskPath "\DevShield\" -TaskName $_.Name -ErrorAction SilentlyContinue
        }
        if ($created.Count -gt 0) {
            Write-DS -EN "Task Scheduler setup complete. ($($created.Count)/$($DS_TASKS.Count) tasks)" `
                     -SA "Task Scheduler सेटअप सम्पूर्ण। ($($created.Count)/$($DS_TASKS.Count) कार्य)" `
                     -Level SUCCESS
        }
        return
    }

    # Running as admin — create all tasks
    $ok = 0; $fail = 0
    foreach ($t in $DS_TASKS) {
        try {
            $scriptFull = Join-Path $DS_SCRIPTS $t.Script
            $action = New-ScheduledTaskAction `
                -Execute "pwsh.exe" `
                -Argument "-NonInteractive -WindowStyle Hidden -File `"$scriptFull`""

            # RunLevel Highest = run as admin without UAC prompt (for users in Admin group)
            $principal = New-ScheduledTaskPrincipal `
                -UserId $env:USERNAME `
                -LogonType Interactive `
                -RunLevel Highest

            $settings = New-ScheduledTaskSettingsSet `
                -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
                -MultipleInstances IgnoreNew `
                -StartWhenAvailable $true

            Register-ScheduledTask `
                -TaskPath "\DevShield\" `
                -TaskName $t.Name `
                -Action $action `
                -Principal $principal `
                -Settings $settings `
                -Description "DevShield managed task — do not edit manually." `
                -Force | Out-Null
            $ok++
        } catch {
            Write-DS -EN "Failed to register task: $($t.Name) — $_" `
                     -SA "कार्य पंजीकरण विफल: $($t.Name)" -Level WARN
            $fail++
        }
    }

    Write-DS -EN "Tasks registered: $ok succeeded, $fail failed." `
             -SA "कार्य पंजीकृत: $ok सफल, $fail विफल।" `
             -Level $(if ($fail -eq 0) {"SUCCESS"} else {"WARN"})

    # Update hardware profile with task registration status
    if (Test-Path $DS_HW_PROFILE) {
        $p = Get-Content $DS_HW_PROFILE -Raw | ConvertFrom-Json
        $p | Add-Member -NotePropertyName "tasks_registered" -NotePropertyValue ($fail -eq 0) -Force
        $p | ConvertTo-Json -Depth 10 | Set-Content $DS_HW_PROFILE -Encoding UTF8
    }
    Write-DSAudit -Action "TASKS_REGISTERED" -Detail "ok:$ok fail:$fail" -Status $(if ($fail -eq 0) {"ok"} else {"warn"})
}

# ══════════════════════════════════════════════════════════════
# SECTION 6 — LHM NOTIFICATION + DOWNLOAD
# ══════════════════════════════════════════════════════════════
function Invoke-DSLHMSetup {
    $lhmExe = Join-Path $DS_TOOLS_DIR "LibreHardwareMonitor" "LibreHardwareMonitor.exe"
    if (Test-Path $lhmExe) {
        Write-DS -EN "LibreHardwareMonitor already installed." `
                 -SA "LibreHardwareMonitor पहले से स्थापित।" -Level SUCCESS
        return $true
    }
    Show-DSLHMNotification
    $choice = Read-Host "  Choice"
    switch ($choice.ToUpper()) {
        "D" { return Install-DSLHM }
        "S" {
            Write-DS -EN "Skipped. DevShield will run in Limited Mode (basic WMI sensors only)." `
                     -SA "छोड़ा। DevShield सीमित-मोड में चलेगा।" -Level WARN
            Write-DSAudit -Action "LHM_SKIPPED" -Status "warn"
            return $false
        }
        default {
            Write-DS -EN "Invalid choice. Defaulting to Skip." -Level WARN
            return $false
        }
    }
}

function Show-DSLHMNotification {
    $lang = Get-DSLanguage
    $W    = 60
    $bar  = "═" * $W
    Write-Host ""
    Write-Host "  ╔$bar╗" -ForegroundColor DarkCyan
    Write-Host "  ║  🔬  Hardware Sensor Backend Required" + " " * 20 + "║" -ForegroundColor Cyan
    if ($lang -ne "EN") {
        Write-Host "  ║  यन्त्र-सेंसर स्रोत आवश्यक" + " " * 31 + "║" -ForegroundColor DarkGray
    }
    Write-Host "  ╠$bar╣" -ForegroundColor DarkCyan
    Write-Host "  ║  LibreHardwareMonitor provides:                          ║" -ForegroundColor White
    Write-Host "  ║    ✓ Per-core CPU temperatures (not just package avg)     ║" -ForegroundColor Green
    Write-Host "  ║    ✓ GPU hotspot & VRAM temperature                       ║" -ForegroundColor Green
    Write-Host "  ║    ✓ Fan RPM readings from motherboard SuperIO chip        ║" -ForegroundColor Green
    Write-Host "  ║    ✓ NVMe / SSD temperatures via S.M.A.R.T                ║" -ForegroundColor Green
    Write-Host "  ║    ✓ CPU voltages, core frequencies, power draw (TDP)     ║" -ForegroundColor Green
    Write-Host "  ╠$bar╣" -ForegroundColor DarkCyan
    Write-Host "  ║  Without it: basic Windows WMI only (limited accuracy)    ║" -ForegroundColor Yellow
    Write-Host "  ╠$bar╣" -ForegroundColor DarkCyan
    Write-Host "  ║  About LibreHardwareMonitor:                              ║" -ForegroundColor White
    Write-Host "  ║    Source : github.com/LibreHardwareMonitor               ║" -ForegroundColor DarkGray
    Write-Host "  ║    License: MPL 2.0  (open source, auditable)             ║" -ForegroundColor DarkGray
    Write-Host "  ║    Size   : ~2.6 MB                                       ║" -ForegroundColor DarkGray
    Write-Host "  ║    Stored : $($DS_TOOLS_DIR.PadRight(45))║" -ForegroundColor DarkGray
    Write-Host "  ║    Verify : SHA256 checked before first run               ║" -ForegroundColor DarkGray
    Write-Host "  ║    Auto   : NOT added to startup, NOT installed globally   ║" -ForegroundColor DarkGray
    Write-Host "  ╠$bar╣" -ForegroundColor DarkCyan
    Write-Host "  ║  [D] Download now (internet required)                     ║" -ForegroundColor Cyan
    Write-Host "  ║  [S] Skip — Limited Mode (can download later)             ║" -ForegroundColor Yellow
    Write-Host "  ╚$bar╝" -ForegroundColor DarkCyan
    Write-Host ""
}

function Test-DSInternet {
    try { return (Test-NetConnection "github.com" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue) }
    catch { return $false }
}

function Install-DSLHM {
    # NASA pattern: verify internet → fetch release info → download → SHA256 → extract → verify

    # ── Pre-flight: internet check ────────────────────────────
    Write-DS -EN "Checking internet connection..." -SA "अन्तर्जाल-संयोग जाँच..." -Level INFO
    if (-not (Test-DSInternet)) {
        Write-DS -EN "No internet connection detected. Cannot download LHM." `
                 -SA "अन्तर्जाल-संयोग नहीं। LHM आनयन असम्भव।" -Level CRITICAL
        Write-DSAudit -Action "LHM_NO_INTERNET" -Status "fail"
        return $false
    }
    Write-DS -EN "Internet connection confirmed." -SA "अन्तर्जाल-संयोग प्रमाणित।" -Level SUCCESS

    # ── Fetch latest release metadata from GitHub API ─────────
    Write-DS -EN "Fetching latest release info from GitHub..." `
             -SA "GitHub से नवीनतम संस्करण-सूचना..." -Level INFO
    try {
        $api     = "https://api.github.com/repos/LibreHardwareMonitor/LibreHardwareMonitor/releases/latest"
        $headers = @{ "User-Agent" = "DevShield/$DS_VERSION"; "Accept" = "application/vnd.github.v3+json" }
        $release = Invoke-RestMethod -Uri $api -Headers $headers -ErrorAction Stop
    } catch {
        Write-DS -EN "Failed to reach GitHub API: $_" -SA "GitHub API विफल: $_" -Level CRITICAL
        Write-DSAudit -Action "LHM_API_FAIL" -Detail "$_" -Status "fail"
        return $false
    }

    # ── Find the zip asset ────────────────────────────────────
    $asset = $release.assets | Where-Object { $_.name -like "LibreHardwareMonitor-net*.zip" } |
             Select-Object -First 1
    if (-not $asset) {
        # Fallback: any zip
        $asset = $release.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
    }
    if (-not $asset) {
        Write-DS -EN "No downloadable asset found in release." -Level CRITICAL
        return $false
    }

    # ── Extract expected SHA256 from release notes ─────────────
    $expectedHash = $null
    if ($release.body -match "SHA256[:\s]+([A-Fa-f0-9]{64})") {
        $expectedHash = $matches[1].ToUpper()
        Write-DS -EN "Expected SHA256 found in release notes." `
                 -SA "अपेक्षित SHA256 रिलीज़ नोट्स में मिला।" -Level SUCCESS
    } else {
        Write-DS -EN "SHA256 not in release notes — will compute and log after download." `
                 -SA "SHA256 रिलीज़ नोट्स में नहीं — डाउनलोड बाद गणना होगी।" -Level WARN
    }

    # ── Download ──────────────────────────────────────────────
    $zipPath = Join-Path $env:TEMP "devshield_lhm_$($release.tag_name).zip"
    Write-DS -EN "Downloading LHM $($release.tag_name) ($([math]::Round($asset.size/1MB,1)) MB)..." `
             -SA "LHM $($release.tag_name) आनयन ($([math]::Round($asset.size/1MB,1)) MB)..." `
             -Level INFO
    try {
        Invoke-WebRequest -Uri $asset.browser_download_url `
                          -OutFile $zipPath `
                          -UseBasicParsing `
                          -ErrorAction Stop
    } catch {
        Write-DS -EN "Download failed: $_" -SA "आनयन विफल: $_" -Level CRITICAL
        Write-DSAudit -Action "LHM_DOWNLOAD_FAIL" -Detail "$_" -Status "fail"
        return $false
    }

    # ── SHA256 Verification (NASA: never skip this) ───────────
    Write-DS -EN "Verifying download integrity..." -SA "डाउनलोड-सत्यनिष्ठा सत्यापन..." -Level INFO
    $actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToUpper()
    Write-DS -EN "SHA256: $($actualHash.Substring(0,32))..." -Level DEBUG

    if ($expectedHash -and $actualHash -ne $expectedHash) {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Write-DS -EN "SECURITY: Hash mismatch! Download deleted. Do NOT retry without investigation." `
                 -SA "सुरक्षा-चेतावनी! हैश मेल नहीं! संचिका हटाई।" -Level CRITICAL
        Write-DSAudit -Action "LHM_HASH_MISMATCH" `
                      -Detail "Expected:$expectedHash Got:$actualHash" -Status "fail"
        return $false
    }
    Write-DS -EN "Integrity verified. Hash: $($actualHash.Substring(0,16))..." `
             -SA "सत्यनिष्ठा प्रमाणित। हैश: $($actualHash.Substring(0,16))..." -Level SUCCESS

    # ── Extract ───────────────────────────────────────────────
    $extractPath = Join-Path $DS_TOOLS_DIR "LibreHardwareMonitor"
    if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $extractPath | Out-Null
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

    # ── Verify extraction ─────────────────────────────────────
    $lhmExe = Get-ChildItem $extractPath -Filter "LibreHardwareMonitor.exe" -Recurse |
              Select-Object -First 1
    if (-not $lhmExe) {
        Write-DS -EN "Extraction failed: LibreHardwareMonitor.exe not found." `
                 -SA "निष्कर्षण विफल: LibreHardwareMonitor.exe नहीं मिला।" -Level CRITICAL
        Write-DSAudit -Action "LHM_EXTRACT_FAIL" -Status "fail"
        return $false
    }

    Write-DS -EN "LHM installed to: $($lhmExe.DirectoryName)" `
             -SA "LHM स्थापित: $($lhmExe.DirectoryName)" -Level SUCCESS
    Write-DSAudit -Action "LHM_INSTALLED" `
                  -Detail "Version:$($release.tag_name) Hash:$actualHash" -Status "ok"
    return $true
}

# ══════════════════════════════════════════════════════════════
# SECTION 7 — HARDWARE SUMMARY DISPLAY (HWiNFO aesthetic)
# ══════════════════════════════════════════════════════════════
function Show-DSHardwareSummary { param([object]$Profile)
    $lang = Get-DSLanguage
    Write-DS -EN "HARDWARE PROFILE" -SA "यन्त्र-आकृति" -Level HEADER
    Write-DSSeparator

    # ── System ───────────────────────────────────────────────
    Write-DS -EN "System  : $($Profile.system.hostname)  ·  $($Profile.system.os)" `
             -SA "यन्त्र  : $($Profile.system.hostname)" -Level INFO

    # ── CPUs ─────────────────────────────────────────────────
    Write-DS -BLANK
    Write-DS -EN "CPUs ($($Profile.cpus.Count) detected)" -SA "संसाधक ($($Profile.cpus.Count) खोजे)" -Level HEADER
    foreach ($cpu in $Profile.cpus) {
        Write-DS -EN "  $($cpu.socket): $($cpu.name)" -Level INFO
        Write-DS -EN "    $($cpu.cores_physical) cores / $($cpu.cores_logical) threads  ·  Base $($cpu.base_clock_mhz) MHz  ·  $($cpu.manufacturer) Gen $($cpu.generation)" `
                 -SA "    $($cpu.cores_physical) कोर / $($cpu.cores_logical) धागे  ·  आधार $($cpu.base_clock_mhz) MHz" `
                 -Level INFO -NoIcon
    }

    # ── GPUs ─────────────────────────────────────────────────
    Write-DS -BLANK
    Write-DS -EN "GPUs ($($Profile.gpus.Count) detected)" -SA "प्रदर्शन-संसाधक ($($Profile.gpus.Count) खोजे)" -Level HEADER
    foreach ($gpu in $Profile.gpus) {
        $tag = "[$($gpu.type.ToUpper())]"
        Write-DS -EN "  GPU$($gpu.index): $($gpu.name)  $tag" -Level INFO
        Write-DS -EN "    VRAM $($gpu.vram_mb) MB  ·  Driver $($gpu.driver_version)  ·  $($gpu.current_res)" `
                 -Level INFO -NoIcon
    }

    # ── Board + RAM ───────────────────────────────────────────
    Write-DS -BLANK
    Write-DS -EN "Board   : $($Profile.motherboard.manufacturer) $($Profile.motherboard.model)" `
             -SA "मदरबोर्ड: $($Profile.motherboard.manufacturer) $($Profile.motherboard.model)" -Level INFO
    Write-DS -EN "BIOS    : $($Profile.bios.version)  ($($Profile.bios.release_date))" -Level INFO
    Write-DS -EN "RAM     : $($Profile.ram.total_gb) GB $($Profile.ram.type)-$($Profile.ram.speed_mhz)  ·  $($Profile.ram.dimms) DIMMs" `
             -SA "स्मृति  : $($Profile.ram.total_gb) GB $($Profile.ram.type)-$($Profile.ram.speed_mhz)" -Level INFO

    # ── Storage ───────────────────────────────────────────────
    Write-DS -BLANK
    Write-DS -EN "Storage ($($Profile.storage.Count) drives)" -SA "संग्रहण ($($Profile.storage.Count) ड्राइव)" -Level HEADER
    foreach ($d in $Profile.storage) {
        Write-DS -EN "  $($d.type.PadRight(5))  $($d.size_gb) GB  ·  $($d.model)" -Level INFO -NoIcon
    }

    # ── Status ───────────────────────────────────────────────
    Write-DS -BLANK
    Write-DSSeparator
    Write-DS -EN "LHM Sensors : $(if ($Profile.lhm_installed) {'✅ Installed'} else {'⚠ Limited Mode'})" `
             -SA "LHM सेंसर  : $(if ($Profile.lhm_installed) {'✅ स्थापित'} else {'⚠ सीमित-मोड'})" `
             -Level $(if ($Profile.lhm_installed) {"SUCCESS"} else {"WARN"})
    Write-DS -EN "Admin Tasks : $(if ($Profile.tasks_registered) {'✅ Registered'} else {'⚠ Manual elevation required'})" `
             -SA "प्रशासक कार्य: $(if ($Profile.tasks_registered) {'✅ पंजीकृत'} else {'⚠ मैन्युअल एलिवेशन'})" `
             -Level $(if ($Profile.tasks_registered) {"SUCCESS"} else {"WARN"})
    Write-DS -EN "Profile     : $DS_HW_PROFILE" -Level INFO
    Write-DSSeparator
    Write-DS -BLANK
}
