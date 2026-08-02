# driver_triage.ps1 — Static triage of a suspicious .sys driver file
# Determines if a driver has BYOVD process-kill capability via PE analysis.
# Usage: driver_triage.ps1 -FilePath "C:\path\to\suspicious.sys" [-DbPath "byovd_db.json"]

param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,
    [string]$DbPath = ""
)

$ErrorActionPreference = "SilentlyContinue"

if (-not (Test-Path $FilePath)) {
    Write-Output (@{ success=$false; error="File not found: $FilePath" } | ConvertTo-Json -Compress)
    exit 1
}

$fileInfo = Get-Item $FilePath
$result = @{
    success = $true
    file_path = $fileInfo.FullName
    file_size = $fileInfo.Length
    last_write = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
}

# ============================================================
# 1. Hash computation + DB matching
# ============================================================
$sha256 = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
$md5 = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash.ToLower()
$result["sha256"] = $sha256
$result["md5"] = $md5

# Load DB if available
$dbMatch = $null
if (-not $DbPath) {
    $DbPath = Join-Path $PSScriptRoot "byovd_db.json"
    if (-not (Test-Path $DbPath)) { $DbPath = Join-Path (Split-Path $PSScriptRoot) "knowledge\byovd_db.json" }
}
if (Test-Path $DbPath) {
    $db = Get-Content $DbPath -Raw | ConvertFrom-Json
    foreach ($e in $db) {
        if ($e.sha256 -eq $sha256 -or ($e.md5 -and $e.md5 -eq $md5)) {
            $dbMatch = $e
            break
        }
    }
}
if ($dbMatch) {
    $result["db_match"] = @{
        known = $true
        filename = $dbMatch.filename
        category = $dbMatch.category
        company = $dbMatch.company
        product = $dbMatch.product
        mitre_id = $dbMatch.mitre_id
        hvci_bypass = $dbMatch.hvci_bypass
    }
} else {
    $result["db_match"] = @{ known = $false }
}

# ============================================================
# 2. Authenticode signature analysis
# ============================================================
$sig = Get-AuthenticodeSignature -FilePath $FilePath
$result["signature"] = @{
    status = $sig.Status.ToString()
    signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
    issuer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { "" }
    serial = if ($sig.SignerCertificate) { $sig.SignerCertificate.SerialNumber } else { "" }
    not_after = if ($sig.SignerCertificate) { $sig.SignerCertificate.NotAfter.ToString("yyyy-MM-dd") } else { "" }
    is_expired = if ($sig.SignerCertificate) { $sig.SignerCertificate.NotAfter -lt (Get-Date) } else { $null }
    thumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { "" }
}

# ============================================================
# 3. PE Import Table analysis (key BYOVD indicator)
# ============================================================
$bytes = [System.IO.File]::ReadAllBytes($FilePath)
$imports = @()
$hasOpenProcess = $false
$hasTerminateProcess = $false
$hasDeviceIoControl = $false
$dangerousImports = @()

try {
    # Parse PE headers
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    $result["arch"] = if ($machine -eq 0x8664) { "x64" } elseif ($machine -eq 0x14c) { "x86" } elseif ($machine -eq 0xAA64) { "ARM64" } else { "unknown" }

    $numSections = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
    $timestamp = [BitConverter]::ToUInt32($bytes, $peOffset + 8)
    $result["compile_time"] = ([DateTimeOffset]::FromUnixTimeSeconds($timestamp)).ToString("yyyy-MM-dd HH:mm:ss")

    # Optional header
    $optOffset = $peOffset + 24
    $magic = [BitConverter]::ToUInt16($bytes, $optOffset)
    $is64 = ($magic -eq 0x20b)

    if ($is64) {
        $importRVA = [BitConverter]::ToUInt32($bytes, $optOffset + 120)
        $importSize = [BitConverter]::ToUInt32($bytes, $optOffset + 124)
    } else {
        $importRVA = [BitConverter]::ToUInt32($bytes, $optOffset + 104)
        $importSize = [BitConverter]::ToUInt32($bytes, $optOffset + 108)
    }

    # Section headers for RVA→offset conversion
    $sectionOffset = $optOffset + $(if ($is64) { 240 } else { 224 })
    $sections = @()
    for ($i = 0; $i -lt $numSections; $i++) {
        $so = $sectionOffset + ($i * 40)
        $sections += @{
            name = [System.Text.Encoding]::ASCII.GetString($bytes, $so, 8).TrimEnd([char]0)
            vsize = [BitConverter]::ToUInt32($bytes, $so + 8)
            vaddr = [BitConverter]::ToUInt32($bytes, $so + 12)
            rawsize = [BitConverter]::ToUInt32($bytes, $so + 16)
            rawaddr = [BitConverter]::ToUInt32($bytes, $so + 20)
        }
    }

    function RvaToOffset($rva) {
        foreach ($s in $sections) {
            if ($rva -ge $s.vaddr -and $rva -lt ($s.vaddr + [Math]::Max($s.vsize, $s.rawsize))) {
                return $rva - $s.vaddr + $s.rawaddr
            }
        }
        return -1
    }

    # Parse import directory
    if ($importRVA -gt 0) {
        $importOff = RvaToOffset $importRVA
        if ($importOff -gt 0) {
            $idx = 0
            while ($true) {
                $descOff = $importOff + ($idx * 20)
                if ($descOff + 20 -gt $bytes.Length) { break }
                $iltRVA = [BitConverter]::ToUInt32($bytes, $descOff)
                $nameRVA = [BitConverter]::ToUInt32($bytes, $descOff + 12)
                if ($iltRVA -eq 0 -and $nameRVA -eq 0) { break }

                # DLL name
                $nameOff = RvaToOffset $nameRVA
                $dllName = ""
                if ($nameOff -gt 0 -and $nameOff -lt $bytes.Length) {
                    $end = $nameOff
                    while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
                    $dllName = [System.Text.Encoding]::ASCII.GetString($bytes, $nameOff, $end - $nameOff)
                }

                # Parse ILT/IAT entries
                $funcs = @()
                $thunkRVA = if ($iltRVA -ne 0) { $iltRVA } else { [BitConverter]::ToUInt32($bytes, $descOff + 16) }
                $thunkOff = RvaToOffset $thunkRVA
                if ($thunkOff -gt 0) {
                    $entrySize = if ($is64) { 8 } else { 4 }
                    $ordinalFlag = if ($is64) { 0x8000000000000000 } else { 0x80000000 }
                    $fi = 0
                    while ($fi -lt 500) {
                        $funcOff = $thunkOff + ($fi * $entrySize)
                        if ($funcOff + $entrySize -gt $bytes.Length) { break }
                        $thunkVal = if ($is64) { [BitConverter]::ToUInt64($bytes, $funcOff) } else { [BitConverter]::ToUInt32($bytes, $funcOff) }
                        if ($thunkVal -eq 0) { break }
                        if (($thunkVal -band $ordinalFlag) -eq 0) {
                            $hintRVA = [uint32]($thunkVal -band 0x7FFFFFFF)
                            $hintOff = RvaToOffset $hintRVA
                            if ($hintOff -gt 0 -and ($hintOff + 2) -lt $bytes.Length) {
                                $fend = $hintOff + 2
                                while ($fend -lt $bytes.Length -and $bytes[$fend] -ne 0 -and ($fend - $hintOff - 2) -lt 200) { $fend++ }
                                $funcName = [System.Text.Encoding]::ASCII.GetString($bytes, $hintOff + 2, $fend - $hintOff - 2)
                                $funcs += $funcName
                            }
                        }
                        $fi++
                    }
                }

                if ($dllName) { $imports += @{ dll = $dllName; functions = $funcs } }
                $idx++
                if ($idx -gt 100) { break }
            }
        }
    }
} catch {
    $result["pe_parse_error"] = $_.Exception.Message
}

# Check for BYOVD-critical imports
$allFuncs = $imports | ForEach-Object { $_.functions } | Where-Object { $_ }
$hasOpenProcess = ($allFuncs | Where-Object { $_ -match '^(Zw|Nt)OpenProcess$' }).Count -gt 0
$hasTerminateProcess = ($allFuncs | Where-Object { $_ -match '^(Zw|Nt)TerminateProcess$' }).Count -gt 0
$hasCreateDevice = ($allFuncs | Where-Object { $_ -match '^IoCreateDevice$' }).Count -gt 0
$hasDeviceIoControl = ($allFuncs | Where-Object { $_ -match 'ZwDeviceIoControlFile|IoBuildDeviceIoControlRequest' }).Count -gt 0

# Additional dangerous imports
$dangerPatterns = @('ZwTerminateProcess', 'NtTerminateProcess', 'PsTerminateSystemThread',
                    'ZwOpenProcess', 'NtOpenProcess', 'ObOpenObjectByPointer',
                    'ZwWriteVirtualMemory', 'NtWriteVirtualMemory', 'MmMapLockedPagesSpecifyCache',
                    'ZwLoadDriver', 'NtLoadDriver', 'KeStackAttachProcess')
foreach ($f in $allFuncs) {
    if ($dangerPatterns -contains $f) { $dangerousImports += $f }
}

$result["import_analysis"] = @{
    total_dlls = $imports.Count
    total_functions = $allFuncs.Count
    has_open_process = $hasOpenProcess
    has_terminate_process = $hasTerminateProcess
    has_create_device = $hasCreateDevice
    has_device_io_control = $hasDeviceIoControl
    dangerous_imports = ($dangerousImports | Select-Object -Unique)
    dlls = ($imports | ForEach-Object { $_.dll })
}

# ============================================================
# 4. String extraction (device names, registry paths)
# ============================================================
$asciiStr = [System.Text.Encoding]::ASCII.GetString($bytes)
$unicodeStr = [System.Text.Encoding]::Unicode.GetString($bytes)
$allStrings = $asciiStr + $unicodeStr

$deviceNames = [regex]::Matches($allStrings, '\\\\?\\[A-Za-z0-9_]+|\\Device\\[A-Za-z0-9_]+|\\DosDevices\\[A-Za-z0-9_]+') |
    ForEach-Object { $_.Value } | Select-Object -Unique | Select-Object -First 20

$ioctlPatterns = [regex]::Matches($asciiStr, 'CTL_CODE|DeviceIoControl|IRP_MJ_DEVICE_CONTROL') |
    ForEach-Object { $_.Value } | Select-Object -Unique

$result["strings_analysis"] = @{
    device_names = $deviceNames
    ioctl_references = $ioctlPatterns
}

# ============================================================
# 5. Version info
# ============================================================
$vi = $fileInfo.VersionInfo
$result["version_info"] = @{
    original_filename = $vi.OriginalFilename
    company = $vi.CompanyName
    product = $vi.ProductName
    description = $vi.FileDescription
    file_version = $vi.FileVersion
    internal_name = $vi.InternalName
}

# ============================================================
# 6. Risk assessment
# ============================================================
$riskScore = 0
$reasons = @()

if ($dbMatch) {
    $riskScore += 100
    $reasons += "KNOWN vulnerable/malicious driver in loldrivers DB ($($dbMatch.category))"
}
if ($hasOpenProcess -and $hasTerminateProcess) {
    $riskScore += 60
    $reasons += "Imports BOTH OpenProcess + TerminateProcess (process-kill capability)"
}
if ($hasCreateDevice -and ($hasOpenProcess -or $hasTerminateProcess)) {
    $riskScore += 20
    $reasons += "Creates device object + process manipulation (IOCTL-accessible kill primitive)"
}
if ($sig.Status -ne "Valid") {
    $riskScore += 15
    $reasons += "Signature status: $($sig.Status)"
}
if ($sig.SignerCertificate -and $sig.SignerCertificate.NotAfter -lt (Get-Date)) {
    $riskScore += 10
    $reasons += "Signing certificate EXPIRED ($($sig.SignerCertificate.NotAfter.ToString('yyyy-MM-dd')))"
}
if ($deviceNames.Count -gt 0) {
    $riskScore += 5
    $reasons += "Exposes device interface: $($deviceNames -join ', ')"
}
if ($dangerousImports.Count -gt 3) {
    $riskScore += 10
    $reasons += "Multiple dangerous kernel imports ($($dangerousImports.Count))"
}

$riskLevel = if ($riskScore -ge 100) { "critical" }
             elseif ($riskScore -ge 60) { "high" }
             elseif ($riskScore -ge 30) { "medium" }
             else { "low" }

$result["risk_assessment"] = @{
    score = $riskScore
    level = $riskLevel
    reasons = $reasons
    recommendation = switch ($riskLevel) {
        "critical" { "CONFIRMED BYOVD threat. Isolate host, collect memory dump, check lateral movement." }
        "high"     { "Strong BYOVD indicators. Treat as hostile until proven otherwise. Block driver load via WDAC." }
        "medium"   { "Suspicious capabilities. Investigate provenance and deployment context." }
        default    { "Low risk. Standard driver capabilities, no BYOVD-specific indicators." }
    }
}

# Output
$result | ConvertTo-Json -Depth 5 -Compress
