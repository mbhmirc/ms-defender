#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fully automated test harness for defender.ps1.
    Runs the script, validates all outputs, reports pass/fail.
    Writes a machine-readable validation summary for external tools to consume.
#>
[CmdletBinding()]
param(
    [int]$RecordingSeconds = 20,
    [int]$TopN = 15,
    [string]$OutputRoot,
    [switch]$AIMode,
    [switch]$NoAutoClose,
    [switch]$NoOpenReport
)

$ErrorActionPreference = 'Continue'
$scriptDir  = Split-Path $MyInvocation.MyCommand.Path -Parent
$OutputRoot = if ($OutputRoot) { $OutputRoot } else { $scriptDir }
$runId      = Get-Date -Format 'yyyyMMdd_HHmmss'
$logFile    = Join-Path $OutputRoot "test_run_$runId.log"
$reportDir  = Join-Path $OutputRoot "test_reports_$runId"
$resultFile = Join-Path $OutputRoot "test_result_$runId.json"
$defenderScript = Join-Path $scriptDir 'defender.ps1'
$defenderSource = if (Test-Path -LiteralPath $defenderScript) {
    Get-Content -LiteralPath $defenderScript -Raw -ErrorAction SilentlyContinue
}
else {
    $null
}

# Force UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['Tee-Object:Encoding'] = 'utf8'

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

# ═══════════════════════════════════════════════════════════════════════════════
#  TIMER + PROGRESS
# ═══════════════════════════════════════════════════════════════════════════════
$totalTimer = [System.Diagnostics.Stopwatch]::StartNew()

function Write-Phase([string]$phase, [string]$msg) {
    $elapsed = $totalTimer.Elapsed.ToString('mm\:ss')
    Write-Host "[$elapsed] " -NoNewline -ForegroundColor DarkGray
    Write-Host "[$phase] " -NoNewline -ForegroundColor Cyan
    Write-Host $msg
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — RUN MAIN SCRIPT
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  DEFENDER PERFORMANCE TEST HARNESS" -ForegroundColor Cyan
Write-Host "  Run ID     : $runId" -ForegroundColor Gray
Write-Host "  Recording  : ${RecordingSeconds}s" -ForegroundColor Gray
Write-Host "  Log        : $logFile" -ForegroundColor Gray
Write-Host "  Reports    : $reportDir" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Phase "RUN" "Executing defender.ps1 with -ValidateLoad -ValidateExclusions$(if($AIMode){' -AIMode'}else{''})..."
Write-Phase "RUN" "Estimated time: ~$([math]::Ceiling($RecordingSeconds * 2.5))s (recording + analysis + CAB)"
Write-Host ""

$scriptError = $null
try {
    $defenderParams = @{
        RecordingSeconds   = $RecordingSeconds
        TopN               = $TopN
        ReportPath         = $reportDir
        ValidateLoad       = $true
        ValidateExclusions = $true
        NoOpenReport       = $NoOpenReport
    }
    if ($AIMode) {
        $defenderParams['AIMode'] = $true
    }

    & $defenderScript @defenderParams *>&1 | Tee-Object -FilePath $logFile
}
catch {
    $scriptError = $_.ToString()
    Write-Host "SCRIPT ERROR: $_" -ForegroundColor Red
}

$scriptElapsed = $totalTimer.Elapsed.TotalSeconds

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — AUTOMATED VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "  VALIDATION PHASE" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host ""

$tests = [System.Collections.Generic.List[PSObject]]::new()
$pass = 0
$fail = 0
$warn = 0

function Add-Test([string]$Name, [string]$Result, [string]$Details) {
    $colour = switch ($Result) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'WARN' { 'Yellow' } default { 'Gray' } }
    $icon   = switch ($Result) { 'PASS' { '[+]' } 'FAIL' { '[X]' } 'WARN' { '[!]' } default { '[?]' } }

    Write-Host "  $icon " -NoNewline -ForegroundColor $colour
    Write-Host "$Name" -NoNewline
    if ($Details) { Write-Host " -- $Details" -ForegroundColor DarkGray } else { Write-Host "" }

    $script:tests.Add([PSCustomObject]@{ Name = $Name; Result = $Result; Details = $Details })
    switch ($Result) { 'PASS' { $script:pass++ } 'FAIL' { $script:fail++ } 'WARN' { $script:warn++ } }
}

# ── Test 1: Script completed without fatal error ────────────────────────────
if (-not $scriptError) {
    Add-Test "Script execution" "PASS" "Completed in $([math]::Round($scriptElapsed, 1))s"
}
else {
    Add-Test "Script execution" "FAIL" $scriptError
}

# ── Test 2: Log file exists and has content ─────────────────────────────────
if ((Test-Path $logFile) -and (Get-Item $logFile).Length -gt 100) {
    Add-Test "Log file created" "PASS" "$([math]::Round((Get-Item $logFile).Length / 1KB, 1)) KB"
}
else {
    Add-Test "Log file created" "FAIL" "Missing or empty"
}

if ($defenderSource) {
    Add-Test "Portable exclusion validation path" $(if ($defenderSource -notmatch 'C:\\DefenderPerfTest_') { "PASS" } else { "FAIL" }) ""

    $safeBlockMatch = [regex]::Match($defenderSource, '(?s)\$safeExtensions\s*=\s*@\((.*?)\)\s*\r?\n')
    $cautionBlockMatch = [regex]::Match($defenderSource, '(?s)\$cautionExtensions\s*=\s*@\((.*?)\)\s*\r?\n')
    if ($safeBlockMatch.Success -and $cautionBlockMatch.Success) {
        $safeBlock = $safeBlockMatch.Groups[1].Value
        $cautionBlock = $cautionBlockMatch.Groups[1].Value
        $forbiddenSafe = @('py', 'java', 'jar') | Where-Object { $safeBlock -match "'$_'" }
        $missingCaution = @('py', 'java', 'jar') | Where-Object { $cautionBlock -notmatch "'$_'" }
        Add-Test "Extension tier guardrails" $(if ($forbiddenSafe.Count -eq 0 -and $missingCaution.Count -eq 0) { "PASS" } else { "FAIL" }) $(if ($forbiddenSafe.Count -eq 0 -and $missingCaution.Count -eq 0) { "" } else { "Safe overlap: $($forbiddenSafe -join ', ') Missing caution: $($missingCaution -join ', ')" })
    }
    else {
        Add-Test "Extension tier guardrails" "WARN" "Could not parse extension tier blocks"
    }
}

# ── Test 3: JSON report exists and is valid ─────────────────────────────────
$jsonFiles = Get-ChildItem $reportDir -Filter "*.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike '*.ai-export.json' }
if ($jsonFiles -and $jsonFiles.Count -gt 0) {
    $jsonFile = $jsonFiles | Select-Object -First 1
    try {
        $jsonContent = Get-Content $jsonFile.FullName -Raw | ConvertFrom-Json
        Add-Test "JSON report valid" "PASS" "$([math]::Round($jsonFile.Length / 1KB, 1)) KB"
    }
    catch {
        Add-Test "JSON report valid" "FAIL" "JSON parse error: $_"
        $jsonContent = $null
    }
}
else {
    Add-Test "JSON report valid" "FAIL" "No JSON file in report directory"
    $jsonContent = $null
}

# ── Test 4: HTML report exists ──────────────────────────────────────────────
$htmlFiles = Get-ChildItem $reportDir -Filter "*.html" -ErrorAction SilentlyContinue
if ($htmlFiles -and $htmlFiles.Count -gt 0) {
    Add-Test "HTML report created" "PASS" "$([math]::Round(($htmlFiles | Select-Object -First 1).Length / 1KB, 1)) KB"
}
else {
    Add-Test "HTML report created" "FAIL" "No HTML file in report directory"
}

# ── Test 5: JSON has required top-level keys ────────────────────────────────
if ($jsonContent) {
    $requiredKeys = @('ReportMetadata', 'ExclusionDiscovery', 'TopFiles', 'TopProcesses',
                      'TopExtensions', 'TopScans', 'TopScanContexts', 'ExtensionHotspots',
                      'ExclusionSuggestions', 'SuppressedCandidates', 'PerformanceImpactTable',
                      'CABIntelligence', 'ExclusionValidationDetails')
    $missingKeys = @()
    foreach ($key in $requiredKeys) {
        if (-not $jsonContent.PSObject.Properties[$key]) { $missingKeys += $key }
    }
    if ($missingKeys.Count -eq 0) {
        Add-Test "JSON structure complete" "PASS" "All $($requiredKeys.Count) top-level keys present"
    }
    else {
        Add-Test "JSON structure complete" "FAIL" "Missing: $($missingKeys -join ', ')"
    }
}

if ($AIMode) {
    $aiExportFiles = Get-ChildItem $reportDir -Filter "*.ai-export.json" -ErrorAction SilentlyContinue
    if ($aiExportFiles -and $aiExportFiles.Count -gt 0) {
        Add-Test "AI export created" "PASS" "$([math]::Round(($aiExportFiles | Select-Object -First 1).Length / 1KB, 1)) KB"
        try {
            $aiExportContent = Get-Content ($aiExportFiles | Select-Object -First 1).FullName -Raw | ConvertFrom-Json
            $hasRules = @($aiExportContent.ReviewRules).Count -gt 0
            $hasPurpose = -not [string]::IsNullOrWhiteSpace([string]$aiExportContent.Purpose)
            $hasSuppressedField = [bool]$aiExportContent.PSObject.Properties['SuppressedCandidates']
            Add-Test "AI export structure valid" $(if ($hasRules -and $hasPurpose -and $hasSuppressedField) { "PASS" } else { "FAIL" }) ""
        }
        catch {
            Add-Test "AI export structure valid" "FAIL" "JSON parse error: $_"
        }
    }
    else {
        Add-Test "AI export created" "FAIL" "No AI export file in report directory"
    }

    $aiPromptFiles = Get-ChildItem $reportDir -Filter "*.ai-prompt.md" -ErrorAction SilentlyContinue
    if ($aiPromptFiles -and $aiPromptFiles.Count -gt 0) {
        $aiPromptFile = $aiPromptFiles | Select-Object -First 1
        Add-Test "AI prompt created" "PASS" "$([math]::Round($aiPromptFile.Length / 1KB, 1)) KB"
        $aiPromptContent = Get-Content $aiPromptFile.FullName -Raw -ErrorAction SilentlyContinue
        $promptIsUseful = $aiPromptContent -match 'Validate whether each Microsoft Defender Antivirus exclusion suggestion is appropriate' -and
            $aiPromptContent -match 'file-pattern'
        Add-Test "AI prompt includes exclusion-review guidance" $(if ($promptIsUseful) { "PASS" } else { "FAIL" }) ""
    }
    else {
        Add-Test "AI prompt created" "FAIL" "No AI prompt file in report directory"
    }
}

# ── Test 6: Performance data was captured ───────────────────────────────────
if ($jsonContent -and $jsonContent.TopFiles) {
    $fileCount = @($jsonContent.TopFiles).Count
    if ($fileCount -gt 0) {
        Add-Test "Top files captured" "PASS" "$fileCount files in report"
    }
    else {
        Add-Test "Top files captured" "WARN" "No files captured (recording too short?)"
    }
}

if ($jsonContent -and $jsonContent.TopProcesses) {
    $procCount = @($jsonContent.TopProcesses).Count
    Add-Test "Top processes captured" $(if ($procCount -gt 0) { "PASS" } else { "WARN" }) "$procCount processes"
}

if ($jsonContent -and $jsonContent.TopExtensions) {
    $extCount = @($jsonContent.TopExtensions).Count
    Add-Test "Top extensions captured" $(if ($extCount -gt 0) { "PASS" } else { "WARN" }) "$extCount extensions"
}

if ($jsonContent -and $jsonContent.TopScans) {
    $scanCount = @($jsonContent.TopScans).Count
    Add-Test "Top scans captured" $(if ($scanCount -gt 0) { "PASS" } else { "WARN" }) "$scanCount scans"

    $workloadScans = @($jsonContent.TopScans | Where-Object {
            $_.Path -match 'DefenderWorkload_' -and
            $_.ProcessPath -match '^[A-Za-z]:\\.*\.exe$'
        })
    if ($workloadScans.Count -gt 0) {
        $clusters = $workloadScans | Group-Object {
            $scanFolder = if ($_.Path) { [System.IO.Path]::GetDirectoryName([string]$_.Path) } else { '' }
            '{0}|{1}' -f $scanFolder, [string]$_.ProcessPath
        }
        $strongClusters = @($clusters | Where-Object { $_.Count -ge 3 })
        Add-Test "Synthetic workload produced contextual clusters" $(if ($strongClusters.Count -gt 0) { "PASS" } else { "WARN" }) "$($strongClusters.Count) folder/process cluster(s)"
    }
    else {
        Add-Test "Synthetic workload produced contextual clusters" "WARN" "No workload scans with executable process paths"
    }
}

# ── Test 7: Exclusion suggestions have risk tiers ───────────────────────────
if ($jsonContent -and $jsonContent.ExclusionSuggestions) {
    $suggestions = @($jsonContent.ExclusionSuggestions)
    if ($suggestions.Count -gt 0) {
        $withRisk = @($suggestions | Where-Object { $_.Risk })
        if ($withRisk.Count -eq $suggestions.Count) {
            $riskBreakdown = $withRisk | Group-Object Risk | ForEach-Object { "$($_.Name):$($_.Count)" }
            Add-Test "Risk tiers on suggestions" "PASS" "$($suggestions.Count) suggestions ($($riskBreakdown -join ', '))"
        }
        else {
            Add-Test "Risk tiers on suggestions" "FAIL" "$($withRisk.Count)/$($suggestions.Count) have Risk field"
        }

        # Check no BLOCKED extensions leaked through
        $blocked = @($suggestions | Where-Object { $_.Risk -eq 'BLOCKED' })
        if ($blocked.Count -eq 0) {
            Add-Test "No blocked extensions suggested" "PASS" "Safety filter working"
        }
        else {
            Add-Test "No blocked extensions suggested" "FAIL" "$($blocked.Count) blocked extension(s) leaked through"
        }

        # Check CAUTION extensions have advisory
        $caution = @($suggestions | Where-Object { $_.Risk -eq 'CAUTION' })
        if ($caution.Count -gt 0) {
            $withAdvisory = @($caution | Where-Object { $_.Advisory })
            Add-Test "CAUTION items have advisories" $(if ($withAdvisory.Count -eq $caution.Count) { "PASS" } else { "FAIL" }) "$($withAdvisory.Count)/$($caution.Count)"
        }

        # Check no workload temp paths in suggestions
        $workloadPaths = @($suggestions | Where-Object {
                $_.Value -match 'DefenderWorkload_' -or
                $_.Command -match 'DefenderWorkload_' -or
                $_.Advisory -match 'DefenderWorkload_'
            })
        if ($workloadPaths.Count -eq 0) {
            Add-Test "No workload paths in suggestions" "PASS" "Workload filter working"
        }
        else {
            Add-Test "No workload paths in suggestions" "FAIL" "$($workloadPaths.Count) workload path(s) leaked"
        }

        $invalidProcessSuggestions = @($suggestions | Where-Object {
                $_.Type -eq 'Process' -and (
                    $_.Value -notmatch '^[A-Za-z]:\\' -or
                    [System.IO.Path]::GetExtension($_.Value).ToLowerInvariant() -ne '.exe'
                )
            })
        if ($invalidProcessSuggestions.Count -eq 0) {
            Add-Test "Process suggestions look like executable paths" "PASS" ""
        }
        else {
            Add-Test "Process suggestions look like executable paths" "FAIL" "$($invalidProcessSuggestions.Count) invalid process suggestion(s)"
        }

        $contextualSuggestions = @($suggestions | Where-Object { $_.Type -eq 'ContextualPath' })
        if ($contextualSuggestions.Count -gt 0) {
            $invalidContextual = @($contextualSuggestions | Where-Object {
                    $_.Command -notmatch 'ScanTrigger:OnAccess' -and $_.Command -notmatch 'Process:"'
                })
            Add-Test "Contextual suggestions use scoped syntax" $(if ($invalidContextual.Count -eq 0) { "PASS" } else { "FAIL" }) "$($contextualSuggestions.Count) contextual suggestion(s)"
        }

        $extensionHotspotSuggestions = @($suggestions | Where-Object { $_.Type -eq 'ExtensionHotspot' })
        if ($extensionHotspotSuggestions.Count -gt 0) {
            $invalidHotspotSuggestions = @($extensionHotspotSuggestions | Where-Object {
                    $_.Value -notmatch ' @ [A-Za-z]:\\' -or
                    $_.Command -notmatch '-ExclusionPath' -or
                    $_.Command -notmatch '\\\*\.[^''"\r\n]+'
                })
            Add-Test "Extension hotspot suggestions are file-pattern scoped" $(if ($invalidHotspotSuggestions.Count -eq 0) { "PASS" } else { "FAIL" }) "$($extensionHotspotSuggestions.Count) hotspot suggestion(s)"
        }

        $placeholderSuggestions = @($suggestions | Where-Object {
                $_.Command -match '<your-trusted-folder>' -or
                $_.Command -match 'your trusted directory' -or
                $_.Advisory -match 'your trusted directory'
            })
        Add-Test "No placeholder exclusion paths in suggestions" $(if ($placeholderSuggestions.Count -eq 0) { "PASS" } else { "FAIL" }) "$($placeholderSuggestions.Count) placeholder suggestion(s)"

        $missingCommandSuggestions = @($suggestions | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.Command) })
        Add-Test "All suggestions include a command" $(if ($missingCommandSuggestions.Count -eq 0) { "PASS" } else { "FAIL" }) "$($missingCommandSuggestions.Count) missing command(s)"

        $systemFolderProcessSuggestions = @($suggestions | Where-Object {
                ($_.Type -eq 'Process' -and $_.Value -match '^[A-Za-z]:\\Windows(\\|$)') -or
                ($_.Type -eq 'ContextualPath' -and $_.Command -match 'Process:\"[A-Za-z]:\\Windows(\\|$)')
            })
        Add-Test "No system-folder process exclusions suggested" $(if ($systemFolderProcessSuggestions.Count -eq 0) { "PASS" } else { "FAIL" }) "$($systemFolderProcessSuggestions.Count) unsafe process suggestion(s)"
    }
    else {
        Add-Test "Exclusion suggestions generated" "WARN" "No suggestions (may be expected)"
    }
}

# ── Test 7b: Scan context and extension hotspot models ─────────────────────
if ($jsonContent -and $jsonContent.TopScanContexts) {
    $scanContexts = @($jsonContent.TopScanContexts)
    Add-Test "Top scan contexts generated" $(if ($scanContexts.Count -gt 0) { "PASS" } else { "WARN" }) "$($scanContexts.Count) context rows"

    if ($scanContexts.Count -gt 0) {
        $missingProcessOrTime = @($scanContexts | Where-Object {
                -not $_.ProcessImage -or -not $_.StartTimeLocal
            })
        Add-Test "  Scan contexts include time and process image" $(if ($missingProcessOrTime.Count -eq 0) { "PASS" } else { "WARN" }) "$($scanContexts.Count - $missingProcessOrTime.Count)/$($scanContexts.Count)"
    }
}
else {
    Add-Test "Top scan contexts generated" "FAIL" "Missing from JSON"
}

if ($jsonContent -and $jsonContent.ExtensionHotspots) {
    $extensionHotspots = @($jsonContent.ExtensionHotspots)
    Add-Test "Extension hotspot analysis generated" $(if ($extensionHotspots.Count -gt 0) { "PASS" } else { "WARN" }) "$($extensionHotspots.Count) hotspot rows"

    if ($extensionHotspots.Count -gt 0) {
        $withFolderHotspots = @($extensionHotspots | Where-Object { @($_.HotspotFolders).Count -gt 0 })
        Add-Test "  Extension hotspots include folder breakdowns" $(if ($withFolderHotspots.Count -eq $extensionHotspots.Count) { "PASS" } else { "WARN" }) "$($withFolderHotspots.Count)/$($extensionHotspots.Count)"
    }
}
else {
    Add-Test "Extension hotspot analysis generated" "FAIL" "Missing from JSON"
}

# ── Test 7c: Suppressed validation-only candidates ──────────────────────────
if ($jsonContent -and $jsonContent.PSObject.Properties['SuppressedCandidates']) {
    $suppressedCandidates = @($jsonContent.SuppressedCandidates)
    Add-Test "Suppressed candidate model present" "PASS" "$($suppressedCandidates.Count) candidate(s)"

    if ($suppressedCandidates.Count -gt 0) {
        $missingSuppressedCommands = @($suppressedCandidates | Where-Object { @($_.Commands).Count -eq 0 })
        Add-Test "Suppressed candidates include commands" $(if ($missingSuppressedCommands.Count -eq 0) { "PASS" } else { "FAIL" }) "$($missingSuppressedCommands.Count) missing command set(s)"

        $invalidSuppressedPatterns = @($suppressedCandidates | Where-Object {
                @($_.Commands | Where-Object {
                        $_ -notmatch '-ExclusionPath' -or
                        $_ -notmatch '\\\*\.[^''"\r\n]+'
                    }).Count -gt 0
            })
        Add-Test "Suppressed candidates are file-pattern scoped" $(if ($invalidSuppressedPatterns.Count -eq 0) { "PASS" } else { "FAIL" }) "$($invalidSuppressedPatterns.Count) invalid candidate(s)"
    }
    elseif ($ValidateLoad) {
        Add-Test "Suppressed candidates captured during validation load" "WARN" "No suppressed candidates recorded"
    }
}
else {
    Add-Test "Suppressed candidate model present" "FAIL" "Missing from JSON"
}

# ── Test 8: CAB intelligence populated ──────────────────────────────────────
if ($jsonContent -and $jsonContent.CABIntelligence) {
    $intel = $jsonContent.CABIntelligence
    $intelKeys = @($intel.PSObject.Properties).Count
    if ($intelKeys -gt 0) {
        Add-Test "CAB intelligence extracted" "PASS" "$intelKeys data categories"

        if ($intel.EffectiveConfig) {
            Add-Test "  Effective config parsed" "PASS" ""

            $requiredEffKeys = @('RealTimeProtectionEnabled', 'BehaviorMonitoringEnabled', 'IOAVProtectionEnabled', 'ScriptScanningEnabled')
            $missingEffKeys = @($requiredEffKeys | Where-Object { -not $intel.EffectiveConfig.PSObject.Properties[$_] })
            if ($missingEffKeys.Count -eq 0) {
                Add-Test "  Effective config enablement flags" "PASS" ($requiredEffKeys -join ', ')
            }
            else {
                Add-Test "  Effective config enablement flags" "FAIL" "Missing: $($missingEffKeys -join ', ')"
            }
        }
        if ($intel.PlatformVersions) {
            Add-Test "  Platform versions parsed" "PASS" "$($intel.PlatformVersions.DefenderPlatformVersion)"
        }
        if ($intel.HealthState) {
            Add-Test "  Product health parsed" "PASS" "$($intel.HealthState.OverallProductStatus)"
        }
        if ($intel.NetworkProtection) {
            Add-Test "  Network protection state" "PASS" "$($intel.NetworkProtection.Mode) mode"
        }
        if ($intel.DeviceControl) {
            Add-Test "  Device control parsed" "PASS" "$($intel.DeviceControl.State)"
        }
        if ($intel.SecurityCenterProducts) {
            Add-Test "  Security Center products" "PASS" "$(@($intel.SecurityCenterProducts).Count) products"
        }
        if ($intel.MDEOnboarding) {
            Add-Test "  MDE onboarding hints" "PASS" "$($intel.MDEOnboarding.OrgId)"
        }
        if ($intel.MPLogHighlights) {
            Add-Test "  MPLog highlights parsed" "PASS" "$($intel.MPLogHighlights.FileCount) log(s)"
            if ($intel.MPLogHighlights.PSObject.Properties['RecentDynamicSignatureEvents']) {
                Add-Test "  MPLog dynamic signature events" "PASS" "$(@($intel.MPLogHighlights.RecentDynamicSignatureEvents).Count) events"
            }
        }
        if ($intel.SignatureUpdateStub) {
            Add-Test "  Signature update stub parsed" "PASS" "$($intel.SignatureUpdateStub.StartTime)"
        }
        if ($intel.FilterDrivers) {
            $driverCount = @($intel.FilterDrivers).Count
            Add-Test "  Filter drivers enumerated" "PASS" "$driverCount drivers"
        }
        if ($intel.PSObject.Properties['ScanSkips']) {
            Add-Test "  Scan skip analysis" "PASS" "$($intel.ScanSkips.TotalSkipped) skips found"
        }
        if ($intel.PSObject.Properties['IFEODebuggerHijacks']) {
            $hijacks = @($intel.IFEODebuggerHijacks).Count
            Add-Test "  IFEO hijack check" $(if ($hijacks -eq 0) { "PASS" } else { "WARN" }) "$hijacks entries"
        }
        else {
            Add-Test "  IFEO hijack check" "PASS" "No hijacks"
        }
    }
    else {
        Add-Test "CAB intelligence extracted" "WARN" "Empty (CAB may not be available)"
    }
}
else {
    Add-Test "CAB intelligence extracted" "FAIL" "Missing from JSON"
}

# ── Test 9: Exclusion guidance metadata populated ───────────────────────────
if ($jsonContent -and $jsonContent.ExclusionGuidance) {
    $guidance = $jsonContent.ExclusionGuidance
    $requiredGuidanceKeys = @('ContextualExclusionsSupported', 'Principles', 'Sources')
    $missingGuidanceKeys = @($requiredGuidanceKeys | Where-Object { -not $guidance.PSObject.Properties[$_] })
    Add-Test "Exclusion guidance metadata" $(if ($missingGuidanceKeys.Count -eq 0) { "PASS" } else { "FAIL" }) $(if ($missingGuidanceKeys.Count -eq 0) { "$($guidance.Principles.Count) principles" } else { "Missing: $($missingGuidanceKeys -join ', ')" })
    $guidanceText = @($guidance.Principles) -join ' '
    Add-Test "Guidance mentions ACL protection" $(if ($guidanceText -match 'ACL') { "PASS" } else { "FAIL" }) ""
    Add-Test "Guidance mentions automated investigation" $(if ($guidanceText -match 'automated investigation') { "PASS" } else { "FAIL" }) ""
}
else {
    Add-Test "Exclusion guidance metadata" "FAIL" "Missing from JSON"
}

# ── Test 10: Exclusion validation results (check log) ───────────────────────
if ($jsonContent -and $jsonContent.ExclusionValidationDetails) {
    $validationDetails = $jsonContent.ExclusionValidationDetails
    $requiredValidationKeys = @('Requested', 'Executed', 'Results', 'CleanupVerified')
    $missingValidationKeys = @($requiredValidationKeys | Where-Object { -not $validationDetails.PSObject.Properties[$_] })
    Add-Test "Structured exclusion validation details" $(if ($missingValidationKeys.Count -eq 0) { "PASS" } else { "FAIL" }) $(if ($missingValidationKeys.Count -eq 0) { "" } else { "Missing: $($missingValidationKeys -join ', ')" })

    if ($validationDetails.Executed) {
        $cabResultRecorded = [bool]$validationDetails.Results.PSObject.Properties['CAB-MpRegistry']
        Add-Test "  CAB validation result recorded" $(if ($cabResultRecorded) { "PASS" } else { "FAIL" }) ""
        Add-Test "  Test exclusion cleanup verified" $(if ($validationDetails.CleanupVerified -eq $true) { "PASS" } elseif ($validationDetails.CleanupVerified -eq $false) { "FAIL" } else { "WARN" }) ""
    }
    elseif ($validationDetails.Requested) {
        Add-Test "  Structured exclusion validation" "WARN" "$($validationDetails.SkippedReason)"
    }
}
else {
    Add-Test "Structured exclusion validation details" "FAIL" "Missing from JSON"
}

if (Test-Path $logFile) {
    $logContent = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
    if ($logContent -match 'Exclusion validation:.*(\d+)/(\d+)') {
        $working = [int]$Matches[1]
        $total = [int]$Matches[2]
        if ($working -gt 0) {
            Add-Test "Exclusion validation" "PASS" "$working/$total discovery methods working"
        }
        else {
            Add-Test "Exclusion validation" "WARN" "No discovery methods could detect test exclusion"
        }
    }
    elseif ($logContent -match 'Test exclusion removed') {
        Add-Test "Exclusion validation" "PASS" "Test exclusion lifecycle completed"
    }
    elseif ($logContent -match 'MANUAL CLEANUP NEEDED') {
        Add-Test "Exclusion validation" "FAIL" "Test exclusion was not cleaned up!"
    }
    elseif ($logContent -match 'Exclusion validation skipped') {
        Add-Test "Exclusion validation" "WARN" "Skipped (Tamper Protection blocking)"
    }
    else {
        Add-Test "Exclusion validation" "WARN" "Could not find validation results in log"
    }

    # ── Test 11: No unresolved placeholder values in output ─────────────────
    if ($logContent -match '<unresolved file path>|<unresolved scan target>|<no process path>') {
        Add-Test "No unresolved placeholders in output" "FAIL" "Found unresolved output placeholder(s)"
    }
    else {
        Add-Test "No unresolved placeholders in output" "PASS" ""
    }

    # ── Test 12: No double-dot extensions ───────────────────────────────────
    if ($logContent -match '\.\.[a-z]{2,5}\b' -and $logContent -notmatch '\.\.\.' ) {
        Add-Test "No double-dot extensions" "FAIL" "Found '..ext' in output"
    }
    else {
        Add-Test "No double-dot extensions" "PASS" ""
    }

    # ── Test 13: Check for script errors in log ─────────────────────────────
    $errorLines = @(($logContent -split '\r?\n') | Where-Object { $_ -match '^\s*(ERROR|Exception|FAIL.*:.*\$_)' -and $_ -notmatch '\[FAIL\]\s+\d+\s+HIGH' })
    if ($errorLines.Count -eq 0) {
        Add-Test "No script errors in log" "PASS" ""
    }
    else {
        Add-Test "No script errors in log" "WARN" "$($errorLines.Count) potential error line(s)"
    }
}

# ── Test 14: Log is UTF-8 (not UTF-16 double-spaced) ───────────────────────
if (Test-Path $logFile) {
    $rawBytes = [System.IO.File]::ReadAllBytes($logFile)
    $hasNullBytes = $false
    for ($i = 0; $i -lt [math]::Min(200, $rawBytes.Length); $i++) {
        if ($rawBytes[$i] -eq 0) { $hasNullBytes = $true; break }
    }
    if (-not $hasNullBytes) {
        Add-Test "Log encoding is UTF-8" "PASS" ""
    }
    else {
        Add-Test "Log encoding is UTF-8" "FAIL" "Contains null bytes (UTF-16?)"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — RESULTS SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
$totalTimer.Stop()
$totalElapsed = $totalTimer.Elapsed

Write-Host ""
Write-Host "================================================================" -ForegroundColor $(if ($fail -gt 0) { 'Red' } elseif ($warn -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  TEST RESULTS" -ForegroundColor White
Write-Host "  Total time : $($totalElapsed.ToString('mm\:ss'))" -ForegroundColor Gray
Write-Host "  Tests run  : $($tests.Count)" -ForegroundColor Gray
Write-Host "  PASS       : $pass" -ForegroundColor Green
if ($warn -gt 0) { Write-Host "  WARN       : $warn" -ForegroundColor Yellow }
if ($fail -gt 0) { Write-Host "  FAIL       : $fail" -ForegroundColor Red }
Write-Host "  Verdict    : $(if ($fail -eq 0) { 'ALL CLEAR' } else { 'ISSUES FOUND' })" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host "================================================================" -ForegroundColor $(if ($fail -gt 0) { 'Red' } elseif ($warn -gt 0) { 'Yellow' } else { 'Green' })

# ── Save machine-readable result ────────────────────────────────────────────
$resultData = [ordered]@{
    RunId        = $runId
    Timestamp    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    ElapsedSec   = [math]::Round($totalElapsed.TotalSeconds, 1)
    TotalTests   = $tests.Count
    Passed       = $pass
    Warned       = $warn
    Failed       = $fail
    Verdict      = if ($fail -eq 0) { 'PASS' } else { 'FAIL' }
    LogFile      = $logFile
    ReportDir    = $reportDir
    Tests        = @($tests | ForEach-Object {
        [ordered]@{ Name = $_.Name; Result = $_.Result; Details = $_.Details }
    })
}
$resultData | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8

Write-Host ""
Write-Host "  Results JSON : $resultFile" -ForegroundColor Gray
Write-Host "  Full log     : $logFile" -ForegroundColor Gray
Write-Host ""

$exitCode = if ($fail -gt 0) { 1 } else { 0 }

if (-not $NoAutoClose) {
    Write-Host "  Auto-closing in 10 seconds..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 10
}

exit $exitCode
