# byovd_scan.ps1 — BYOVD post-incident detection collector
# Invoked via external_exec (ext_byovd_scan). Requires: byovd_db.json in same dir or -DbPath.
# Outputs: full JSON to file, summary (<15K) to stdout.

param(
    [string]$DbPath = "",
    [string]$OutputDir = "",
    [int]$TimeoutSecs = 180
)

$ErrorActionPreference = "SilentlyContinue"
$scriptStart = Get-Date

# --- Resolve paths ---
if (-not $DbPath) {
    $DbPath = Join-Path $PSScriptRoot "byovd_db.json"
    if (-not (Test-Path $DbPath)) {
        $DbPath = Join-Path (Split-Path $PSScriptRoot) "knowledge\byovd_db.json"
    }
}
if (-not $OutputDir) { $OutputDir = $PSScriptRoot }
$resultFile = Join-Path $OutputDir "byovd_result.json"

# --- Load hash database ---
if (-not (Test-Path $DbPath)) {
    Write-Output '{"success":false,"error":"byovd_db.json not found. Run byovd_db_extract first."}'
    exit 1
}
$db = Get-Content $DbPath -Raw | ConvertFrom-Json
$sha256Set = @{}
$imphashSet = @{}
foreach ($e in $db) {
    if ($e.sha256) { $sha256Set[$e.sha256] = $e }
    if ($e.imphash) { $imphashSet[$e.imphash] = $e }
}
Write-Host "[*] DB loaded: $($sha256Set.Count) SHA256, $($imphashSet.Count) imphash entries" -ForegroundColor DarkGray

$findings = @()
$stats = @{ loaded_drivers = 0; files_scanned = 0; services_checked = 0; events_checked = 0; matches = 0 }

# ============================================================
# Phase 1: Loaded driver hash matching
# ============================================================
Write-Host "[1/4] Scanning loaded drivers..." -ForegroundColor Cyan

$driverCsv = & driverquery /v /fo csv 2>$null | Select-Object -Skip 1
$loadedDrivers = @()
foreach ($line in $driverCsv) {
    if (-not $line) { continue }
    # CSV: "Name","Description","Driver Type","Link Date","Path","Size"
    $parts = $line -split '","'
    if ($parts.Count -lt 5) { continue }
    $name = $parts[0].Trim('"')
    $path = $parts[4].Trim('"')
    if (-not $path -or $path -eq "N/A") { continue }
    # Normalize path
    $path = $path -replace '\\SystemRoot\\', "$env:WINDIR\"
    $path = $path -replace '^\\\?\?\\', ''
    $loadedDrivers += @{ name = $name; path = $path }
}
$stats.loaded_drivers = $loadedDrivers.Count

$hashCache = @{}
foreach ($drv in $loadedDrivers) {
    $fp = $drv.path
    if (-not (Test-Path $fp)) { continue }
    if ($hashCache.ContainsKey($fp)) { $hash = $hashCache[$fp] }
    else {
        $hash = (Get-FileHash -Path $fp -Algorithm SHA256).Hash.ToLower()
        $hashCache[$fp] = $hash
    }
    if ($sha256Set.ContainsKey($hash)) {
        $match = $sha256Set[$hash]
        $findings += @{
            source = "loaded_driver"
            severity = "critical"
            driver_name = $drv.name
            file_path = $fp
            sha256 = $hash
            db_filename = $match.filename
            db_category = $match.category
            db_company = $match.company
            db_product = $match.product
            mitre_id = $match.mitre_id
            hvci_bypass = $match.hvci_bypass
        }
        $stats.matches++
    }
}

# ============================================================
# Phase 2: Non-standard path .sys file scan
# ============================================================
Write-Host "[2/4] Scanning non-standard paths for .sys files..." -ForegroundColor Cyan

$scanPaths = @(
    "$env:TEMP",
    "$env:USERPROFILE\Downloads",
    "$env:PUBLIC",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp",
    "C:\ProgramData",
    "$env:WINDIR\Temp"
)
# Also check driverquery paths not in System32\drivers
foreach ($drv in $loadedDrivers) {
    $dir = Split-Path $drv.path -Parent
    if ($dir -and $dir -notmatch 'System32\\drivers|SysWOW64\\drivers|WinSxS') {
        if ($scanPaths -notcontains $dir) { $scanPaths += $dir }
    }
}

$scannedFiles = @{}
foreach ($sp in $scanPaths) {
    if (-not (Test-Path $sp)) { continue }
    $sysFiles = Get-ChildItem -Path $sp -Filter "*.sys" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 200
    foreach ($f in $sysFiles) {
        $fp = $f.FullName.ToLower()
        if ($scannedFiles.ContainsKey($fp)) { continue }
        $scannedFiles[$fp] = $true
        $stats.files_scanned++

        $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
        $hashCache[$f.FullName] = $hash
        if ($sha256Set.ContainsKey($hash)) {
            $match = $sha256Set[$hash]
            $findings += @{
                source = "file_scan"
                severity = "high"
                file_path = $f.FullName
                file_size = $f.Length
                last_write = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                sha256 = $hash
                db_filename = $match.filename
                db_category = $match.category
                db_company = $match.company
                db_product = $match.product
                mitre_id = $match.mitre_id
                hvci_bypass = $match.hvci_bypass
            }
            $stats.matches++
        }
    }
}

# ============================================================
# Phase 3: Kernel driver service audit (Type=1)
# ============================================================
Write-Host "[3/4] Auditing kernel driver services..." -ForegroundColor Cyan

$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services"
$suspiciousServices = @()
Get-ChildItem $svcKey -ErrorAction SilentlyContinue | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($props.Type -ne 1 -and $props.Type -ne 2) { return }  # kernel driver or filesystem driver
    $stats.services_checked++
    $imagePath = $props.ImagePath
    if (-not $imagePath) { return }
    # Flag non-standard paths
    $isSuspicious = $false
    $reason = ""
    if ($imagePath -match '\\Temp\\|\\Downloads\\|\\Public\\|\\AppData\\|\\ProgramData\\|\\Users\\') {
        $isSuspicious = $true; $reason = "non-standard path"
    }
    elseif ($imagePath -notmatch '\\SystemRoot\\|\\Windows\\|system32\\drivers') {
        $isSuspicious = $true; $reason = "unusual ImagePath"
    }
    # Check if file exists and hash-match
    $resolvedPath = $imagePath -replace '\\SystemRoot\\', "$env:WINDIR\" -replace '^\\\?\?\\', '' -replace '\\\?\?\\', ''
    if ($isSuspicious -and (Test-Path $resolvedPath)) {
        $hash = if ($hashCache.ContainsKey($resolvedPath)) { $hashCache[$resolvedPath] }
                else { (Get-FileHash -Path $resolvedPath -Algorithm SHA256).Hash.ToLower() }
        if ($sha256Set.ContainsKey($hash)) {
            $match = $sha256Set[$hash]
            $findings += @{
                source = "service_registry"
                severity = "critical"
                service_name = $_.PSChildName
                image_path = $imagePath
                start_type = $props.Start
                sha256 = $hash
                db_filename = $match.filename
                db_category = $match.category
                db_company = $match.company
                mitre_id = $match.mitre_id
            }
            $stats.matches++
        }
    }
    if ($isSuspicious) {
        $suspiciousServices += @{
            name = $_.PSChildName
            image_path = $imagePath
            start = $props.Start
            reason = $reason
            hash_match = $sha256Set.ContainsKey($(if (Test-Path $resolvedPath) { $hash } else { "" }))
        }
    }
}

# ============================================================
# Phase 4: Event ID 7045 (service/driver install) with type
# ============================================================
Write-Host "[4/4] Querying Event 7045 (last 30 days)..." -ForegroundColor Cyan

$events7045 = @()
try {
    $rawEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-30)} -MaxEvents 200 -ErrorAction Stop
    foreach ($evt in $rawEvents) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        $stats.events_checked++
        $svcType = $data['Service Type']
        $imagePath = $data['ImagePath']
        # Only care about kernel drivers
        if ($svcType -match 'kernel|driver') {
            $entry = @{
                time = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                service_name = $data['Service Name']
                image_path = $imagePath
                start_type = $data['Start Type']
                service_type = $svcType
                account = $data['Account Name']
            }
            $events7045 += $entry
            # Cross-check hash if file still exists
            $rp = $imagePath -replace '\\SystemRoot\\', "$env:WINDIR\" -replace '^\\\?\?\\', '' -replace '\\\?\?\\', ''
            if ($rp -and (Test-Path $rp)) {
                $hash = if ($hashCache.ContainsKey($rp)) { $hashCache[$rp] }
                        else { (Get-FileHash -Path $rp -Algorithm SHA256).Hash.ToLower() }
                if ($sha256Set.ContainsKey($hash)) {
                    $match = $sha256Set[$hash]
                    $findings += @{
                        source = "event_7045"
                        severity = "critical"
                        event_time = $entry.time
                        service_name = $entry.service_name
                        image_path = $imagePath
                        sha256 = $hash
                        db_filename = $match.filename
                        db_category = $match.category
                        mitre_id = $match.mitre_id
                    }
                    $stats.matches++
                }
            }
        }
    }
} catch {
    Write-Host "  [!] 7045 query failed: $_" -ForegroundColor Yellow
}

# ============================================================
# Output
# ============================================================
$elapsed = ((Get-Date) - $scriptStart).TotalSeconds

$result = @{
    success = $true
    scan_time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    elapsed_seconds = [math]::Round($elapsed, 1)
    db_entries = $sha256Set.Count
    stats = $stats
    findings = $findings
    suspicious_services = $suspiciousServices | Select-Object -First 30
    kernel_driver_installs_30d = $events7045 | Select-Object -First 50
}

# Write full result to file
$result | ConvertTo-Json -Depth 5 | Set-Content $resultFile -Encoding UTF8

# --- Stdout summary (must be <15K chars) ---
$summary = @{
    success = $true
    elapsed_seconds = [math]::Round($elapsed, 1)
    db_entries = $sha256Set.Count
    stats = $stats
    findings_count = $findings.Count
    findings = $findings | Select-Object -First 20
    suspicious_services_count = $suspiciousServices.Count
    suspicious_services = $suspiciousServices | Select-Object -First 10
    kernel_driver_installs_30d_count = $events7045.Count
    kernel_driver_installs_30d = $events7045 | Select-Object -First 15
    result_file = $resultFile
}
$summary | ConvertTo-Json -Depth 4 -Compress
