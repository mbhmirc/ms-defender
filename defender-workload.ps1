<#
.SYNOPSIS
    Generates synthetic file I/O workload to trigger Windows Defender scanning.
    Designed to run during a Defender performance recording to produce meaningful results.

.PARAMETER DurationSeconds
    How long to generate workload. Should match or slightly exceed the recording duration.

.PARAMETER WorkDir
    Temporary directory for workload files. Created and cleaned up automatically.
#>
[CmdletBinding()]
param(
    [int]$DurationSeconds = 30,
    [string]$WorkDir = (Join-Path $env:TEMP "DefenderWorkload_$(Get-Date -Format 'yyyyMMdd_HHmmss')"),
    [ValidateSet('Mixed', 'PowerShell', 'NativeExe')]
    [string]$Mode = 'Mixed'
)

$ErrorActionPreference = 'SilentlyContinue'

# ── Setup ────────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
Write-Host "[workload] Started - generating Defender scan activity for ${DurationSeconds}s" -ForegroundColor Magenta
Write-Host "[workload] WorkDir: $WorkDir" -ForegroundColor DarkGray
Write-Host "[workload] Mode   : $Mode" -ForegroundColor DarkGray

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$fileCount = 0
$procCount = 0

# ── Focus on trusted project/build/cache folders rather than random file types ─
$projectExtensions = @('.config', '.log', '.cs', '.csproj', '.targets', '.props', '.tmp')
$archiveExtensions = @('.zip', '.nupkg')
$allExtensions     = $projectExtensions + $archiveExtensions

# ── Content templates (benign but varied enough to trigger content scanning) ──
$contentTemplates = @(
    # Structured data
    '{"users":[{"id":{0},"name":"user{0}","email":"user{0}@example.com","role":"admin","token":"abc{0}xyz"}],"config":{{"debug":true,"logLevel":"verbose"}}}'
    # XML-like
    '<?xml version="1.0"?><root><item id="{0}"><name>Record {0}</name><data type="binary">SGVsbG8gV29ybGQ=</data><settings enabled="true"/></item></root>'
    # Code-like
    'import os, sys, subprocess{1}def process_data_{0}(input_path):{1}    with open(input_path, "rb") as f:{1}        data = f.read(){1}    result = subprocess.run(["echo", str(len(data))], capture_output=True){1}    return result.stdout'
    # Config-like
    '[server]{1}host = 0.0.0.0{1}port = 808{0}{1}ssl_cert = /etc/ssl/cert.pem{1}db_connection = postgresql://user:pass@db:5432/app{1}secret_key = sk_live_randomstring{0}abc'
    # Log-like
    '[{2}] INFO  RequestHandler - Processing request #{0} from 192.168.1.{0} user-agent: Mozilla/5.0{1}[{2}] WARN  AuthService - Failed login attempt #{0} for user admin@corp.local{1}[{2}] ERROR PoolManager - Connection pool exhausted, {0} pending requests'
    # HTML-like
    '<!DOCTYPE html><html><head><title>Page {0}</title><script>var config={{api:"/api/v{0}",key:"token{0}"}};</script></head><body><form action="/submit" method="POST"><input name="csrf" value="tok{0}"/></form></body></html>'
    # CSV-like
    'id,name,email,ssn,credit_card,balance{1}{0},John Doe,jdoe@example.com,123-45-{0},4111-1111-1111-{0},${0}000.00{1}{0},Jane Smith,jsmith@example.com,987-65-{0},5500-0000-0000-{0},${0}500.00'
)

# ── Helper: create a file with varied content ────────────────────────────────
function New-WorkloadFile {
    param([string]$Path, [int]$Index)

    $template = $contentTemplates[$Index % $contentTemplates.Count]
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $content = $template -f $Index, "`n", $timestamp

    # Vary file size: repeat content to create files from 1KB to 500KB
    $repeats = 1 + ($Index % 50)
    $fullContent = ($content + "`n") * $repeats

    [System.IO.File]::WriteAllText($Path, $fullContent)
}

function Read-WorkloadFile {
    param([string]$Path)

    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $buffer = New-Object byte[] 4096
        [void]$stream.Read($buffer, 0, $buffer.Length)
    }
    finally {
        if ($stream) { $stream.Dispose() }
    }
}

function Get-CSharpCompilerPath {
    $candidates = @(
        'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe',
        'C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe'
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
}

function Get-WorkloadHelperExecutable {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $sourcePath = Join-Path $scriptDir 'defender-workload-helper.cs'
    $exePath = Join-Path $scriptDir 'defender-workload-helper.exe'

    $hasExe = Test-Path -LiteralPath $exePath
    $hasSource = Test-Path -LiteralPath $sourcePath

    if ($hasExe -and -not $hasSource) {
        return $exePath
    }

    if (-not $hasSource) {
        Write-Host "[workload] Native helper source not found, falling back to PowerShell child workload" -ForegroundColor Yellow
        return $null
    }

    $needsBuild = -not $hasExe
    if (-not $needsBuild) {
        $needsBuild = (Get-Item -LiteralPath $sourcePath).LastWriteTimeUtc -gt (Get-Item -LiteralPath $exePath).LastWriteTimeUtc
    }

    if (-not $needsBuild) {
        return $exePath
    }

    $compiler = Get-CSharpCompilerPath
    if (-not $compiler) {
        if ($hasExe) {
            Write-Host "[workload] csc.exe not found; using existing native workload helper" -ForegroundColor Yellow
            return $exePath
        }

        Write-Host "[workload] csc.exe not found, falling back to PowerShell child workload" -ForegroundColor Yellow
        return $null
    }

    if ($needsBuild) {
        Write-Host "[workload] Building native workload helper..." -ForegroundColor DarkGray
        & $compiler '/nologo' '/target:exe' '/optimize+' "/out:$exePath" $sourcePath | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exePath)) {
            if ($hasExe) {
                Write-Host "[workload] Failed to rebuild native workload helper, using existing helper executable" -ForegroundColor Yellow
                return $exePath
            }

            Write-Host "[workload] Failed to build native workload helper, falling back to PowerShell child workload" -ForegroundColor Yellow
            return $null
        }
    }

    return $exePath
}

# ── Phase 1: Rapid creation in stable build/cache folders ────────────────────
Write-Host "[workload] Phase 1: Create hot build/cache/log files" -ForegroundColor Magenta

# Create subdirectory structure that resembles a developer/build workload.
$subDirs = @(
    'project\src',
    'project\obj\Debug\net8.0',
    'project\bin\Debug\net8.0',
    'cache\nuget\packages',
    'cache\restore',
    'logs',
    'staging'
)
foreach ($d in $subDirs) {
    New-Item -ItemType Directory -Path (Join-Path $WorkDir $d) -Force | Out-Null
}

$useNativeOnly = $Mode -eq 'NativeExe'
$usePowerShellOnly = $Mode -eq 'PowerShell'
$nativeHelperExe = $null

if ($Mode -in @('Mixed', 'NativeExe')) {
    $nativeHelperExe = Get-WorkloadHelperExecutable
    if ($Mode -eq 'NativeExe' -and -not $nativeHelperExe) {
        throw "NativeExe mode was requested, but defender-workload-helper.exe could not be built."
    }
}

if ($nativeHelperExe) {
    Write-Host "[workload] Native helper ready: $nativeHelperExe" -ForegroundColor DarkGray
}
elseif ($usePowerShellOnly) {
    Write-Host "[workload] PowerShell-only mode selected" -ForegroundColor DarkGray
}

if ($useNativeOnly) {
    while ($stopwatch.Elapsed.TotalSeconds -lt ($DurationSeconds * 0.35)) {
        $procCount++
        & $nativeHelperExe '--objDir' (Join-Path $WorkDir 'project\obj\Debug\net8.0') '--cacheDir' (Join-Path $WorkDir 'cache\restore') '--tag' ("phase1_{0:D5}" -f $procCount) '--repeat' '4' | Out-Null
        $fileCount += 16
        Start-Sleep -Milliseconds 50
    }
}
else {
    while ($stopwatch.Elapsed.TotalSeconds -lt ($DurationSeconds * 0.35)) {
        $ext = $allExtensions[$fileCount % $allExtensions.Count]
        $subDir = $subDirs[$fileCount % $subDirs.Count]
        $filePath = Join-Path $WorkDir "$subDir\artifact_$($fileCount.ToString('D5'))$ext"

        New-WorkloadFile -Path $filePath -Index $fileCount
        if ($fileCount % 3 -eq 0) {
            Read-WorkloadFile -Path $filePath
        }
        $fileCount++

        # Every 20 files, burst inside obj/restore to create repeated folder+process pairs.
        if ($fileCount % 20 -eq 0) {
            $manifestDir = Join-Path $WorkDir 'project\obj\Debug\net8.0'
            for ($i = 0; $i -lt 10; $i++) {
                $burstExt = @('.config', '.props', '.tmp')[$i % 3]
                $burstPath = Join-Path $manifestDir "build_manifest_$($fileCount)_$i$burstExt"
                New-WorkloadFile -Path $burstPath -Index ($fileCount + $i)
                Read-WorkloadFile -Path $burstPath
            }
        }

        Start-Sleep -Milliseconds 10
    }
}

Write-Host "[workload] Phase 1 complete: $fileCount files created" -ForegroundColor DarkGray

# ── Phase 2: Re-open and rewrite hot files in the same folders ───────────────
Write-Host "[workload] Phase 2: Re-open, append, and mirror hot files" -ForegroundColor Magenta

$existingFiles = Get-ChildItem -Path $WorkDir -Recurse -File | Select-Object -First 200
$modCount = 0

if ($useNativeOnly) {
    while ($stopwatch.Elapsed.TotalSeconds -lt ($DurationSeconds * 0.65)) {
        $procCount++
        & $nativeHelperExe '--objDir' (Join-Path $WorkDir 'project\obj\Debug\net8.0') '--cacheDir' (Join-Path $WorkDir 'cache\restore') '--tag' ("phase2_{0:D5}" -f $procCount) '--repeat' '6' | Out-Null
        $fileCount += 24
        $modCount += 6
        Start-Sleep -Milliseconds 40
    }
}
else {
    while ($stopwatch.Elapsed.TotalSeconds -lt ($DurationSeconds * 0.65)) {
        if ($existingFiles.Count -eq 0) { break }

        $target = $existingFiles[$modCount % $existingFiles.Count]

        Read-WorkloadFile -Path $target.FullName
        Add-Content -Path $target.FullName -Value "`n# Modified at $(Get-Date -Format 'HH:mm:ss.fff') iteration $modCount"

        if ($modCount % 4 -eq 0) {
            $stagingPath = Join-Path $WorkDir "staging\copied_$($modCount.ToString('D5'))$($target.Extension)"
            Copy-Item -Path $target.FullName -Destination $stagingPath -Force
            Read-WorkloadFile -Path $stagingPath
            $fileCount++
        }

        if ($modCount % 6 -eq 0) {
            $rebuiltPath = Join-Path $WorkDir "project\obj\Debug\net8.0\rebuilt_$($modCount.ToString('D5'))$($target.Extension)"
            Copy-Item -Path $target.FullName -Destination $rebuiltPath -Force
            Add-Content -Path $rebuiltPath -Value "`n# Rebuilt at $(Get-Date -Format 'HH:mm:ss.fff')"
            Read-WorkloadFile -Path $rebuiltPath
            $fileCount++
        }

        $modCount++
        Start-Sleep -Milliseconds 10
    }
}

Write-Host "[workload] Phase 2 complete: $modCount modifications" -ForegroundColor DarkGray

# ── Phase 3: Child processes write into the same hot folders repeatedly ──────
Write-Host "[workload] Phase 3: Child processes writing build/cache outputs" -ForegroundColor Magenta

while ($stopwatch.Elapsed.TotalSeconds -lt ($DurationSeconds * 0.85)) {
    $childObjDir = Join-Path $WorkDir 'project\obj\Debug\net8.0'
    $childCacheDir = Join-Path $WorkDir 'cache\restore'
    $procCount++

    if ($nativeHelperExe) {
        & $nativeHelperExe '--objDir' $childObjDir '--cacheDir' $childCacheDir '--tag' ($procCount.ToString('D5')) '--repeat' '8' | Out-Null
        $fileCount += 32
    }
    else {
        $miniScript = @"
`$objDir = '$($childObjDir -replace "'", "''")'
`$cacheDir = '$($childCacheDir -replace "'", "''")'
1..6 | ForEach-Object {
    `$pdbPath = Join-Path `$objDir ('symbols_${procCount}_' + `$_ + '.pdb')
    `$jsonPath = Join-Path `$cacheDir ('restore_${procCount}_' + `$_ + '.json')
    Set-Content -Path `$pdbPath -Value ('pdb' * 1024)
    Add-Content -Path `$jsonPath -Value ('{""iteration"":' + `$_ + ',""kind"":""restore""}')
    Get-Content -Path `$pdbPath -TotalCount 1 | Out-Null
    Get-Content -Path `$jsonPath -TotalCount 1 | Out-Null
}
"@
        & powershell.exe -NoProfile -Command $miniScript | Out-Null
        $fileCount += 12
    }

    Start-Sleep -Milliseconds 90
}

Write-Host "[workload] Phase 3 complete: $procCount processes spawned" -ForegroundColor DarkGray

# ── Phase 4: Rotate restore manifests and package archives ───────────────────
Write-Host "[workload] Phase 4: Restore/package churn" -ForegroundColor Magenta

while ($stopwatch.Elapsed.TotalSeconds -lt $DurationSeconds) {
    if ($nativeHelperExe) {
        & $nativeHelperExe '--objDir' (Join-Path $WorkDir 'project\obj\Debug\net8.0') '--cacheDir' (Join-Path $WorkDir 'cache\restore') '--tag' ("phase4_{0:D5}" -f $fileCount) '--repeat' '3' | Out-Null
        $fileCount += 12
    }
    else {
        $restoreManifest = Join-Path $WorkDir "cache\restore\restore_$fileCount.json"
        New-WorkloadFile -Path $restoreManifest -Index $fileCount
        Read-WorkloadFile -Path $restoreManifest
        $fileCount++
    }

    if (-not $useNativeOnly -and $fileCount % 2 -eq 0) {
        $zipSource = Join-Path $WorkDir "project\obj\Debug\net8.0"
        $zipPath = Join-Path $WorkDir "cache\restore\package_$fileCount.nupkg"
        Compress-Archive -Path "$zipSource\*" -DestinationPath $zipPath -Force -CompressionLevel Fastest
        Read-WorkloadFile -Path $zipPath
        $fileCount++
    }

    Start-Sleep -Milliseconds 25
}

$stopwatch.Stop()

# ── Summary ──────────────────────────────────────────────────────────────────
$totalFiles = (Get-ChildItem -Path $WorkDir -Recurse -File).Count
$totalSize = [math]::Round(((Get-ChildItem -Path $WorkDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB), 2)

Write-Host "[workload] Complete:" -ForegroundColor Magenta
Write-Host "[workload]   Files created/modified : $fileCount" -ForegroundColor DarkGray
Write-Host "[workload]   Processes spawned      : $procCount" -ForegroundColor DarkGray
Write-Host "[workload]   Total files on disk    : $totalFiles" -ForegroundColor DarkGray
Write-Host "[workload]   Total size             : $totalSize MB" -ForegroundColor DarkGray
Write-Host "[workload]   Elapsed                : $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s" -ForegroundColor DarkGray

# ── Cleanup ──────────────────────────────────────────────────────────────────
Write-Host "[workload] Cleaning up workload files..." -ForegroundColor DarkGray

$cleanupError = $null
for ($attempt = 1; $attempt -le 5; $attempt++) {
    if (-not (Test-Path -LiteralPath $WorkDir)) {
        break
    }

    try {
        Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction Stop
    }
    catch {
        $cleanupError = $_
        Start-Sleep -Milliseconds (200 * $attempt)
    }
}

if (Test-Path -LiteralPath $WorkDir) {
    Write-Host "[workload] Cleanup incomplete - workload files remain at $WorkDir" -ForegroundColor Yellow
    if ($cleanupError) {
        Write-Host "[workload] Cleanup error: $($cleanupError.Exception.Message)" -ForegroundColor DarkGray
    }
}
else {
    Write-Host "[workload] Cleanup complete" -ForegroundColor Magenta
}
