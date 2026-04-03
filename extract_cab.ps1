# Extract MpSupportFiles.cab and inventory contents
# Runs elevated
[CmdletBinding()]
param(
    [string]$CabPath = "C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab",
    [string]$LogPath
)

Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$cabPath = $CabPath
$tempDir = Join-Path $env:TEMP "MpSupportFiles_Extract_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$logPath = if ($LogPath) { $LogPath } else { Join-Path $scriptDir 'cab_contents.log' }

New-Item -ItemType Directory -Path (Split-Path -Parent $logPath) -Force | Out-Null

# Start capturing output
$output = [System.Text.StringBuilder]::new()

function Log($msg) {
    [void]$output.AppendLine($msg)
    Write-Host $msg
}

try {
    Log "=== MpSupportFiles.cab Extraction Report ==="
    Log "Date: $(Get-Date)"
    Log "CAB Path: $cabPath"
    Log ""

    if (-not (Test-Path $cabPath)) {
        Log "ERROR: CAB file not found at $cabPath"
        throw "CAB file not found at $cabPath"
    }

    Log "CAB file size: $([math]::Round((Get-Item $cabPath).Length / 1MB, 2)) MB"
    Log ""

    # Step 1: Extract CAB to temp dir
    Log "--- Extracting to: $tempDir ---"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    expand.exe $cabPath -F:* $tempDir | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "expand.exe failed with exit code $LASTEXITCODE"
    }
    Log "Extraction complete."
    Log ""

    # Step 2: Recursively list all files with sizes
    Log "=== FILE LISTING (all files, recursive) ==="
    Log ("{0,-80} {1,15}" -f "FILE", "SIZE (bytes)")
    Log ("-" * 96)

    $files = Get-ChildItem -Path $tempDir -Recurse -File | Sort-Object FullName
    $totalSize = 0
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($tempDir.Length + 1)
        Log ("{0,-80} {1,15:N0}" -f $rel, $f.Length)
        $totalSize += $f.Length
    }
    Log ("-" * 96)
    Log "Total files: $($files.Count)    Total size: $([math]::Round($totalSize / 1MB, 2)) MB"
    Log ""

    # Step 3: For .txt and .log files, read first 20 lines
    $textFiles = $files | Where-Object { $_.Extension -match '^\.(txt|log)$' }
    if ($textFiles) {
        Log "=== PREVIEW OF .TXT AND .LOG FILES (first 20 lines each) ==="
        foreach ($tf in $textFiles) {
            $rel = $tf.FullName.Substring($tempDir.Length + 1)
            Log ""
            Log "--- $rel ---"
            $lines = Get-Content -Path $tf.FullName -TotalCount 20 -ErrorAction SilentlyContinue
            if ($lines) {
                foreach ($line in $lines) { Log $line }
            } else {
                Log "(empty or unreadable)"
            }
        }
    } else {
        Log "No .txt or .log files found in CAB."
    }

    Log ""
    Log "=== END OF REPORT ==="

} catch {
    Log "ERROR: $_"
} finally {
    # Step 5: Clean up
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        Log "Cleaned up temp directory."
    }

    # Step 4: Save output
    $output.ToString() | Out-File -FilePath $logPath -Encoding UTF8
    Write-Host "Log saved to: $logPath"
}
