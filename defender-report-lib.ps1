Set-StrictMode -Version Latest

function Get-Prop($Object, [string]$Name) {
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Format-Duration([double]$Milliseconds) {
    if ($Milliseconds -lt 1) { return ("{0:N3} ms" -f $Milliseconds) }
    if ($Milliseconds -lt 1000) { return ("{0:N1} ms" -f $Milliseconds) }
    if ($Milliseconds -lt 60000) { return ("{0:N2} s" -f ($Milliseconds / 1000)) }
    return ("{0:N1} min" -f ($Milliseconds / 60000))
}

function Normalize-Extension([string]$Extension) {
    if ([string]::IsNullOrWhiteSpace($Extension)) { return $null }
    return $Extension.Trim().TrimStart('.').ToLowerInvariant()
}

function Format-ExtensionDisplay([string]$Extension) {
    $normalized = Normalize-Extension $Extension
    if (-not $normalized) { return $null }
    return ".$normalized"
}

function Convert-DisabledFlagToEnabled($Value) {
    if ($null -eq $Value) { return $null }
    return (-not [bool]$Value)
}

function Get-PathDirectory([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try {
        return [System.IO.Path]::GetDirectoryName($Path)
    }
    catch {
        return $null
    }
}

function Join-PatternPath([string]$FolderPath, [string]$LeafPattern) {
    if ([string]::IsNullOrWhiteSpace($FolderPath)) { return $LeafPattern }
    if ([string]::IsNullOrWhiteSpace($LeafPattern)) { return $FolderPath }
    return ('{0}\{1}' -f $FolderPath.TrimEnd('\'), $LeafPattern.TrimStart('\'))
}

function Get-DurationMs($Item) {
    if ($null -eq $Item) { return 0 }

    $value = $null
    if ($Item.PSObject.Properties['TotalDuration']) {
        $value = $Item.TotalDuration
    }
    elseif ($Item.PSObject.Properties['Duration']) {
        $value = $Item.Duration
    }

    if ($null -eq $value) { return 0 }
    if ($value -is [TimeSpan]) { return $value.TotalMilliseconds }
    if ($value -is [double] -or $value -is [single] -or $value -is [decimal]) { return [double]$value }
    if ($value -is [byte] -or $value -is [int16] -or $value -is [int32] -or $value -is [int64] -or $value -is [uint16] -or $value -is [uint32] -or $value -is [uint64]) {
        return [double]$value
    }
    if ($value.PSObject -and $value.PSObject.Properties['TotalMilliseconds']) {
        return [double]$value.TotalMilliseconds
    }
    return 0
}

function Convert-FileTimeValueToLocalText($Value) {
    if ($null -eq $Value) { return $null }
    try {
        return ([DateTime]::FromFileTimeUtc([int64]$Value).ToLocalTime()).ToString('yyyy-MM-dd HH:mm:ss')
    }
    catch {
        return $null
    }
}

function Convert-TraceDurationValueToMs($Value) {
    if ($null -eq $Value) { return 0 }
    if ($Value -is [TimeSpan]) { return $Value.TotalMilliseconds }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) { return [double]$Value }
    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64]) {
        return ([double]$Value) / 10000.0
    }
    try {
        return ([double]$Value) / 10000.0
    }
    catch {
        return 0
    }
}

function Parse-ScanComment([string]$Comment) {
    if ([string]::IsNullOrWhiteSpace($Comment)) { return $null }

    if ($Comment -match '^(?<scanType>\w+)\s+(?<path>[A-Za-z]:\\.+?)\s+lasted\s+(?<duration>\d+)$') {
        $commentPath = $Matches['path']
        return [PSCustomObject]@{
            ScanType   = $Matches['scanType']
            Path       = $commentPath
            FolderPath = Get-PathDirectory $commentPath
            Extension  = Normalize-Extension ([System.IO.Path]::GetExtension($commentPath))
            DurationMs = Convert-TraceDurationValueToMs ([int64]$Matches['duration'])
        }
    }

    return $null
}

function Add-FolderAggregateObservation {
    param(
        [Parameter(Mandatory)][hashtable]$Map,
        [string]$FolderPath,
        [double]$DurationMs,
        [string]$ProcessPath,
        [string]$Image,
        [string]$ExamplePath
    )

    if ([string]::IsNullOrWhiteSpace($FolderPath)) { return }

    if (-not $Map.ContainsKey($FolderPath)) {
        $Map[$FolderPath] = [ordered]@{
            FolderPath       = $FolderPath
            TotalDurationMs  = [double]0
            Count            = 0
            ProcessDurations = @{}
            ExamplePaths     = [System.Collections.Generic.List[string]]::new()
            SyntheticOnly    = $true
        }
    }

    $entry = $Map[$FolderPath]
    $entry.TotalDurationMs += $DurationMs
    $entry.Count++

    $processKey = if (-not [string]::IsNullOrWhiteSpace($ProcessPath)) { $ProcessPath } elseif (-not [string]::IsNullOrWhiteSpace($Image)) { "Image:$Image" } else { $null }
    if ($processKey) {
        if (-not $entry.ProcessDurations.ContainsKey($processKey)) {
            $entry.ProcessDurations[$processKey] = [double]0
        }
        $entry.ProcessDurations[$processKey] = [double]$entry.ProcessDurations[$processKey] + $DurationMs
    }

    if (-not [string]::IsNullOrWhiteSpace($ExamplePath) -and -not $entry.ExamplePaths.Contains($ExamplePath) -and $entry.ExamplePaths.Count -lt 3) {
        [void]$entry.ExamplePaths.Add($ExamplePath)
    }

    if (($FolderPath -notmatch 'DefenderWorkload_') -and ($ExamplePath -notmatch 'DefenderWorkload_')) {
        $entry.SyntheticOnly = $false
    }
}

function Convert-FolderAggregateMapToRows {
    param(
        [Parameter(Mandatory)][hashtable]$Map,
        [double]$ObservedDurationMs
    )

    $rows = foreach ($entry in $Map.Values) {
        $topProcessEntry = @($entry.ProcessDurations.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1)
        $topProcessKey = if ($topProcessEntry.Count -gt 0) { [string]$topProcessEntry[0].Key } else { $null }
        $topProcessPath = if ($topProcessKey -and -not $topProcessKey.StartsWith('Image:', [System.StringComparison]::OrdinalIgnoreCase)) { $topProcessKey } else { $null }
        $topProcessImage = if ($topProcessPath) { Split-Path $topProcessPath -Leaf -ErrorAction SilentlyContinue } elseif ($topProcessKey) { $topProcessKey.Substring(6) } else { $null }
        $shareOfObserved = if ($ObservedDurationMs -gt 0) { [math]::Round(($entry.TotalDurationMs / $ObservedDurationMs) * 100, 1) } else { 0 }

        [PSCustomObject]@{
            FolderPath              = $entry.FolderPath
            TotalDurationMs         = [math]::Round($entry.TotalDurationMs, 2)
            Duration                = Format-Duration $entry.TotalDurationMs
            Count                   = $entry.Count
            ShareOfObservedDuration = $shareOfObserved
            TopProcessPath          = $topProcessPath
            TopProcessImage         = $topProcessImage
            ExamplePaths            = @($entry.ExamplePaths)
            SyntheticOnly           = [bool]$entry.SyntheticOnly
        }
    }

    return @($rows | Sort-Object TotalDurationMs -Descending)
}

function Format-ContextualExclusionPath([string]$Path, [string]$PathType, [string]$ScanTrigger, [string]$ProcessPath) {
    $cleanPath = $Path.TrimEnd('\')
    $escapedProcess = $ProcessPath -replace '"', '\"'
    return "{0}\:{{PathType:{1},ScanTrigger:{2},Process:""{3}""}}" -f $cleanPath, $PathType, $ScanTrigger, $escapedProcess
}

function Format-ExclusionProcessCommand([string]$ProcessPath) {
    if ([string]::IsNullOrWhiteSpace($ProcessPath)) { return $null }
    return "Add-MpPreference -ExclusionProcess '$($ProcessPath -replace "'", "''")'"
}

function New-RankedFallback {
    param(
        [int]$TierOrder,
        [string]$Label,
        [string]$Command
    )

    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    return "Tier $TierOrder - ${Label}: $Command"
}

function Get-ImpactOrder([string]$Impact) {
    switch ($Impact) {
        'HIGH' { return 0 }
        'MEDIUM' { return 1 }
        'LOW' { return 2 }
        default { return 3 }
    }
}

function Get-RelativeSharePercent([double]$DurationMs, [double]$TotalMs) {
    if ($TotalMs -le 0) { return $null }
    return [math]::Round(($DurationMs / $TotalMs) * 100, 1)
}

function Get-ImpactLevel {
    param(
        [double]$DurationMs,
        [double]$HighThresholdMs = 5000,
        [double]$MediumThresholdMs = 1000
    )

    if ($DurationMs -ge $HighThresholdMs) { return 'HIGH' }
    if ($DurationMs -ge $MediumThresholdMs) { return 'MEDIUM' }
    return 'LOW'
}

function Test-PathStartsWithAnyPrefix([string]$Path, [string[]]$Prefixes) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    foreach ($prefix in @($Prefixes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        if ($Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Test-SafeSuggestedFolderPath {
    param(
        [string]$Path,
        [string[]]$DangerousPathPrefixes
    )

    return (-not (Test-PathStartsWithAnyPrefix -Path $Path -Prefixes $DangerousPathPrefixes))
}

function Test-SafeSuggestedProcessPath {
    param(
        [string]$Path,
        [string[]]$SystemProcessPathPrefixes
    )

    return (-not (Test-PathStartsWithAnyPrefix -Path $Path -Prefixes $SystemProcessPathPrefixes))
}

function Test-EligibleProcessPath {
    param(
        [string]$Path,
        [switch]$RequireExistingPath
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path -notmatch '^[A-Za-z]:\\') { return $false }

    $extension = [System.IO.Path]::GetExtension($Path)
    if ([string]::IsNullOrWhiteSpace($extension) -or $extension.ToLowerInvariant() -ne '.exe') {
        return $false
    }

    if ($RequireExistingPath) {
        return [bool](Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue)
    }

    return $true
}

function Get-DefenderRiskCatalog {
    param(
        [string]$SystemRoot = $env:SystemRoot,
        [string]$TempPath = $env:TEMP,
        [string]$TmpPath = $env:TMP
    )

    return [ordered]@{
        BlockedExtensions = @(
            'exe', 'dll', 'ps1', 'bat', 'cmd', 'vbs', 'js', 'wsf', 'msi', 'scr',
            'com', 'hta', 'inf', 'reg', 'sys', 'cpl', 'lnk', 'pif', 'ocx', 'drv'
        )
        CautionExtensions = @(
            'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pptm',
            'pdf', 'rtf', 'html', 'htm', 'xml', 'svg', 'zip', 'rar', '7z', 'cab',
            'iso', 'img', 'vhd', 'vhdx', 'tar', 'gz', 'bz2', 'jar',
            'txt', 'csv', 'json', 'yaml', 'yml', 'ini', 'cfg', 'conf', 'log',
            'tmp', 'bak', 'dat', 'bin', 'db', 'cache', 'py', 'java'
        )
        SafeExtensions = @(
            'pyc', 'pyo', 'rb', 'go', 'rs', 'class',
            'cs', 'cpp', 'c', 'h', 'hpp', 'ts', 'tsx', 'jsx', 'vue', 'svelte',
            'css', 'scss', 'less', 'sass', 'md', 'rst', 'lock', 'sum',
            'o', 'obj', 'lib', 'a', 'so', 'pdb', 'idb', 'map',
            'wasm', 'whl', 'egg', 'gem', 'nupkg', 'crate'
        )
        DangerousProcesses = @(
            'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
            'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'msiexec.exe',
            'svchost.exe', 'explorer.exe', 'taskhostw.exe', 'conhost.exe',
            'dllhost.exe', 'wmic.exe', 'certutil.exe', 'bitsadmin.exe'
        )
        ValidationOnlyProcesses = @(
            'defender-workload-helper.exe'
        )
        DangerousPathPrefixes = @(
            "$SystemRoot\System32",
            "$SystemRoot\SysWOW64",
            "$SystemRoot\Temp",
            $TempPath,
            $TmpPath
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        SystemProcessPathPrefixes = @(
            $SystemRoot,
            "$SystemRoot\System32",
            "$SystemRoot\SysWOW64",
            "$SystemRoot\WinSxS",
            "$SystemRoot\servicing"
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }
}

function Get-ExtensionRisk {
    param(
        [string]$Extension,
        [Parameter(Mandatory)]$RiskCatalog
    )

    $normalized = Normalize-Extension $Extension
    if (-not $normalized) { return 'UNKNOWN' }
    if ($RiskCatalog.BlockedExtensions -contains $normalized) { return 'BLOCKED' }
    if ($RiskCatalog.CautionExtensions -contains $normalized) { return 'CAUTION' }
    if ($RiskCatalog.SafeExtensions -contains $normalized) { return 'SAFE' }
    return 'UNKNOWN'
}

function Get-DefenderTopScanContexts {
    param(
        [object[]]$TopScans,
        [double]$HighThresholdMs = 5000,
        [double]$MediumThresholdMs = 1000
    )

    if (-not $TopScans) { return @() }

    return @(
        foreach ($scan in $TopScans) {
            $durationMs = Get-DurationMs $scan
            $scanPath = if (Get-Prop $scan 'Path') { $scan.Path } elseif (Get-Prop $scan 'File') { $scan.File } elseif (Get-Prop $scan 'Process') { $scan.Process } else { '<unresolved scan target>' }
            $processPath = if (Get-Prop $scan 'ProcessPath') { $scan.ProcessPath } elseif (Get-Prop $scan 'Process') { $scan.Process } else { $null }
            $image = if (Get-Prop $scan 'Image') { $scan.Image } elseif ($processPath) { Split-Path $processPath -Leaf -ErrorAction SilentlyContinue } else { $null }
            $relatedFolderMap = @{}
            $commentSamples = [System.Collections.Generic.List[string]]::new()
            $scanComments = @()

            foreach ($rawComment in @(Get-Prop $scan 'Comments')) {
                if (-not [string]::IsNullOrWhiteSpace($rawComment)) {
                    $scanComments += $rawComment
                }
            }

            foreach ($comment in $scanComments) {
                if (-not [string]::IsNullOrWhiteSpace($comment) -and $commentSamples.Count -lt 5) {
                    [void]$commentSamples.Add($comment)
                }

                $parsedComment = Parse-ScanComment $comment
                if (-not $parsedComment) { continue }

                Add-FolderAggregateObservation -Map $relatedFolderMap `
                    -FolderPath $parsedComment.FolderPath `
                    -DurationMs $parsedComment.DurationMs `
                    -ProcessPath $processPath `
                    -Image $image `
                    -ExamplePath $parsedComment.Path
            }

            $relatedFolders = if ($relatedFolderMap.Count -gt 0) {
                $observedRelatedDurationMs = 0.0
                foreach ($folderEntry in $relatedFolderMap.Values) {
                    $observedRelatedDurationMs += [double]$folderEntry['TotalDurationMs']
                }
                Convert-FolderAggregateMapToRows -Map $relatedFolderMap -ObservedDurationMs $observedRelatedDurationMs | Select-Object -First 5
            }
            else {
                @()
            }

            [PSCustomObject]@{
                EstimatedImpact  = Get-ImpactLevel -DurationMs $durationMs -HighThresholdMs $HighThresholdMs -MediumThresholdMs $MediumThresholdMs
                DurationMs       = [math]::Round($durationMs, 2)
                Duration         = Format-Duration $durationMs
                StartTimeLocal   = Convert-FileTimeValueToLocalText (Get-Prop $scan 'StartTime')
                ScanType         = if (Get-Prop $scan 'ScanType') { $scan.ScanType } else { 'n/a' }
                Reason           = Get-Prop $scan 'Reason'
                SkipReason       = Get-Prop $scan 'SkipReason'
                TargetPath       = $scanPath
                ProcessPath      = $processPath
                ProcessImage     = $image
                ProcessName      = Get-Prop $scan 'ProcessName'
                RelatedFileCount = $scanComments.Count
                RelatedFolders   = @($relatedFolders)
                CommentSamples   = @($commentSamples)
            }
        }
    )
}

function Get-DefenderExtensionHotspots {
    param(
        [object[]]$TopExtensions,
        [object[]]$TopScanContexts,
        [double]$HighThresholdMs = 5000,
        [double]$MediumThresholdMs = 1000
    )

    if (-not $TopExtensions) { return @() }

    return @(
        foreach ($extensionEntry in $TopExtensions) {
            $rawExtension = Normalize-Extension (Get-Prop $extensionEntry 'Extension')
            if (-not $rawExtension) { continue }

            $folderMap = @{}
            $totalDurationMs = Get-DurationMs $extensionEntry
            $commentMatches = 0

            foreach ($scan in @(Get-Prop $extensionEntry 'Scans')) {
                $scanPath = Get-Prop $scan 'Path'
                $folderPath = Get-PathDirectory $scanPath
                Add-FolderAggregateObservation -Map $folderMap `
                    -FolderPath $folderPath `
                    -DurationMs (Get-DurationMs $scan) `
                    -ProcessPath (Get-Prop $scan 'ProcessPath') `
                    -Image (Get-Prop $scan 'Image') `
                    -ExamplePath $scanPath
            }

            foreach ($scanContext in @($TopScanContexts)) {
                $hasExtensionComment = $false
                foreach ($comment in @($scanContext.CommentSamples)) {
                    $parsedComment = Parse-ScanComment $comment
                    if (-not $parsedComment -or $parsedComment.Extension -ne $rawExtension) { continue }

                    $hasExtensionComment = $true
                    $commentMatches++
                    Add-FolderAggregateObservation -Map $folderMap `
                        -FolderPath $parsedComment.FolderPath `
                        -DurationMs $parsedComment.DurationMs `
                        -ProcessPath $scanContext.ProcessPath `
                        -Image $scanContext.ProcessImage `
                        -ExamplePath $parsedComment.Path
                }

                if (-not $hasExtensionComment -and $scanContext.TargetPath) {
                    $scanContextExtension = Normalize-Extension ([System.IO.Path]::GetExtension([string]$scanContext.TargetPath))
                    if ($scanContextExtension -eq $rawExtension) {
                        Add-FolderAggregateObservation -Map $folderMap `
                            -FolderPath (Get-PathDirectory ([string]$scanContext.TargetPath)) `
                            -DurationMs ([double]$scanContext.DurationMs) `
                            -ProcessPath $scanContext.ProcessPath `
                            -Image $scanContext.ProcessImage `
                            -ExamplePath ([string]$scanContext.TargetPath)
                    }
                }
            }

            $observedDurationMs = 0.0
            foreach ($entry in $folderMap.Values) {
                $observedDurationMs += [double]$entry.TotalDurationMs
            }

            $hotspotFolders = if ($folderMap.Count -gt 0) {
                Convert-FolderAggregateMapToRows -Map $folderMap -ObservedDurationMs $observedDurationMs | Select-Object -First 5
            }
            else {
                @()
            }

            $dominantFolder = @($hotspotFolders | Select-Object -First 1)
            $observedCoveragePercent = if ($totalDurationMs -gt 0) { [math]::Round(($observedDurationMs / $totalDurationMs) * 100, 1) } else { 0 }

            [PSCustomObject]@{
                Extension               = Format-ExtensionDisplay $rawExtension
                RawExtension            = $rawExtension
                EstimatedImpact         = Get-ImpactLevel -DurationMs $totalDurationMs -HighThresholdMs $HighThresholdMs -MediumThresholdMs $MediumThresholdMs
                TotalDurationMs         = [math]::Round($totalDurationMs, 2)
                Duration                = Format-Duration $totalDurationMs
                Count                   = if (Get-Prop $extensionEntry 'Count') { [int]$extensionEntry.Count } else { 1 }
                ObservedDurationMs      = [math]::Round($observedDurationMs, 2)
                ObservedDuration        = Format-Duration $observedDurationMs
                ObservedCoveragePercent = $observedCoveragePercent
                CommentMatchCount       = $commentMatches
                DominantFolderPath      = if ($dominantFolder.Count -gt 0) { $dominantFolder[0].FolderPath } else { $null }
                DominantFolderShare     = if ($dominantFolder.Count -gt 0) { $dominantFolder[0].ShareOfObservedDuration } else { $null }
                DominantProcessPath     = if ($dominantFolder.Count -gt 0) { $dominantFolder[0].TopProcessPath } else { $null }
                DominantProcessImage    = if ($dominantFolder.Count -gt 0) { $dominantFolder[0].TopProcessImage } else { $null }
                HotspotFolders          = @($hotspotFolders)
            }
        }
    ) | Sort-Object TotalDurationMs -Descending
}

function Get-DefenderRecommendationResult {
    param(
        [Parameter(Mandatory)]$PerfReport,
        [Parameter(Mandatory)]$DiscoveredExclusions,
        [bool]$ContextualExclusionsSupported,
        [bool]$ValidateLoad,
        [double]$HighThresholdMs = 5000,
        [double]$MediumThresholdMs = 1000,
        [switch]$RequireExistingProcessPath
    )

    $riskCatalog = Get-DefenderRiskCatalog
    $topScanContexts = Get-DefenderTopScanContexts -TopScans $PerfReport.TopScans -HighThresholdMs $HighThresholdMs -MediumThresholdMs $MediumThresholdMs
    $extensionHotspots = Get-DefenderExtensionHotspots -TopExtensions $PerfReport.TopExtensions -TopScanContexts $topScanContexts -HighThresholdMs $HighThresholdMs -MediumThresholdMs $MediumThresholdMs

    $suggestions = [System.Collections.Generic.List[object]]::new()
    $suppressedCandidates = [System.Collections.Generic.List[object]]::new()
    $suggestedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $suggestedContextualKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $suggestedProcesses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $coveredProcessPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $existingPathsLower = @($DiscoveredExclusions.Paths | ForEach-Object { [string]$_ } | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    $existingProcsLower = @($DiscoveredExclusions.Processes | ForEach-Object { [string]$_ } | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    $existingExtsLower = @($DiscoveredExclusions.Extensions | ForEach-Object { Normalize-Extension $_ } | Where-Object { $_ })
    $totalTopScanMs = [double](@($PerfReport.TopScans | ForEach-Object { Get-DurationMs $_ }) | Measure-Object -Sum).Sum
    $totalTopProcessMs = [double](@($PerfReport.TopProcesses | ForEach-Object { Get-DurationMs $_ }) | Measure-Object -Sum).Sum
    $totalTopExtensionMs = [double](@($PerfReport.TopExtensions | ForEach-Object { Get-DurationMs $_ }) | Measure-Object -Sum).Sum

    if ($ContextualExclusionsSupported -and $PerfReport.TopScans) {
        foreach ($scan in $PerfReport.TopScans) {
            $ms = Get-DurationMs $scan
            if ($ms -lt $MediumThresholdMs) { continue }
            $scanPath = if (Get-Prop $scan 'Path') { $scan.Path } elseif (Get-Prop $scan 'File') { $scan.File } else { $null }
            $procPath = if ((Get-Prop $scan 'ProcessPath') -and $scan.ProcessPath) { $scan.ProcessPath } elseif ((Get-Prop $scan 'Process') -and $scan.Process) { $scan.Process } else { $null }
            if (-not $scanPath -or -not (Test-EligibleProcessPath -Path $procPath -RequireExistingPath:$RequireExistingProcessPath)) { continue }

            $procName = Split-Path $procPath -Leaf -ErrorAction SilentlyContinue
            if (-not $procName) { $procName = $procPath }
            if ($riskCatalog.DangerousProcesses -contains $procName.ToLowerInvariant()) { continue }
            if (-not (Test-SafeSuggestedProcessPath -Path $procPath -SystemProcessPathPrefixes $riskCatalog.SystemProcessPathPrefixes)) { continue }

            $target = Split-Path $scanPath -Parent -ErrorAction SilentlyContinue
            if (-not $target) { continue }
            if (-not (Test-SafeSuggestedFolderPath -Path $target -DangerousPathPrefixes $riskCatalog.DangerousPathPrefixes)) { continue }
            if ($ValidateLoad -and $target -match 'DefenderWorkload_') { continue }
            if ($existingPathsLower -contains $target.ToLowerInvariant()) { continue }

            $contextKey = "{0}|{1}" -f $target.ToLowerInvariant(), $procPath.ToLowerInvariant()
            if (-not $suggestedContextualKeys.Add($contextKey)) { continue }
            if (-not $suggestedPaths.Add($target)) { continue }

            $contextualPath = Format-ContextualExclusionPath -Path $target -PathType 'folder' -ScanTrigger 'OnAccess' -ProcessPath $procPath
            $processFallback = New-RankedFallback -TierOrder 4 -Label 'Exact process fallback' -Command (Format-ExclusionProcessCommand -ProcessPath $procPath)
            $relativeShare = Get-RelativeSharePercent -DurationMs $ms -TotalMs $totalTopScanMs
            $suggestions.Add([PSCustomObject]@{
                    Type     = 'ContextualPath'
                    Value    = "$target <= $procName"
                    Reason   = "On-access scans in this folder by $procName consumed $(Format-Duration $ms)"
                    Impact   = Get-ImpactLevel -DurationMs $ms -HighThresholdMs $HighThresholdMs -MediumThresholdMs $MediumThresholdMs
                    Command  = "Add-MpPreference -ExclusionPath '$($contextualPath -replace "'", "''")'"
                    Risk     = 'CAUTION'
                    Advisory = 'Start with this process-scoped folder exclusion before considering a broader process exclusion.'
                    Scope    = 'MDAV on-access only for this folder and exact process path'
                    Preference = 'Tier 2 - Contextual folder recommendation'
                    TierOrder = 2
                    Fallbacks = @($processFallback | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    RelatedProcessPath = $procPath
                    RelativeSharePercent = $relativeShare
                    RelativeShareBasis = 'of observed top-scan duration in this run'
                    ConcentrationPercent = $null
                    ConcentrationBasis = $null
                })
            [void]$coveredProcessPaths.Add($procPath)
        }
    }

    if ($PerfReport.TopProcesses) {
        foreach ($processEntry in $PerfReport.TopProcesses) {
            $ms = Get-DurationMs $processEntry
            if ($ms -lt $MediumThresholdMs) { continue }
            $procPath = if ((Get-Prop $processEntry 'Process') -and $processEntry.Process) { $processEntry.Process } elseif ((Get-Prop $processEntry 'ProcessPath') -and $processEntry.ProcessPath) { $processEntry.ProcessPath } else { continue }
            if (-not (Test-EligibleProcessPath -Path $procPath -RequireExistingPath:$RequireExistingProcessPath)) { continue }

            $procName = Split-Path $procPath -Leaf -ErrorAction SilentlyContinue
            if (-not $procName) { $procName = $procPath }
            if ($ValidateLoad -and ($riskCatalog.ValidationOnlyProcesses -contains $procName.ToLowerInvariant())) { continue }
            if ($riskCatalog.DangerousProcesses -contains $procName.ToLowerInvariant()) { continue }
            if (-not (Test-SafeSuggestedProcessPath -Path $procPath -SystemProcessPathPrefixes $riskCatalog.SystemProcessPathPrefixes)) { continue }
            if ($existingProcsLower -contains $procPath.ToLowerInvariant()) { continue }
            if (-not $suggestedProcesses.Add($procPath)) { continue }
            $relativeShare = Get-RelativeSharePercent -DurationMs $ms -TotalMs $totalTopProcessMs

            $suggestions.Add([PSCustomObject]@{
                    Type     = 'Process'
                    Value    = $procPath
                    Reason   = "Process consumed $(Format-Duration $ms) of scan time"
                    Impact   = Get-ImpactLevel -DurationMs $ms -HighThresholdMs $HighThresholdMs -MediumThresholdMs $MediumThresholdMs
                    Command  = Format-ExclusionProcessCommand -ProcessPath $procPath
                    Risk     = 'CAUTION'
                    Advisory = 'Fallback only after narrower contextual or file-pattern options have been ruled out. The process image itself is still scanned and scheduled or on-demand scans can still inspect those files.'
                    Scope    = 'MDAV real-time opened-file exclusion for this process'
                    Preference = 'Tier 4 - Exact process fallback recommendation'
                    TierOrder = 4
                    Fallbacks = @()
                    RelatedProcessPath = $procPath
                    RelativeSharePercent = $relativeShare
                    RelativeShareBasis = 'of observed top-process scan duration in this run'
                    ConcentrationPercent = $null
                    ConcentrationBasis = $null
                })
        }
    }

    if ($PerfReport.TopExtensions) {
        foreach ($extensionEntry in $PerfReport.TopExtensions) {
            $ms = Get-DurationMs $extensionEntry
            if ($ms -lt $MediumThresholdMs) { continue }

            $ext = Normalize-Extension (Get-Prop $extensionEntry 'Extension')
            if (-not $ext) { continue }

            $extensionDisplay = Format-ExtensionDisplay $ext
            $hotspot = @($extensionHotspots | Where-Object { $_.RawExtension -eq $ext } | Select-Object -First 1)
            $risk = Get-ExtensionRisk -Extension $ext -RiskCatalog $riskCatalog

            if ($risk -eq 'BLOCKED') { continue }
            if ($existingExtsLower -contains $ext) { continue }

            $recommendedFolder = $null
            $safeObservedFolders = @()
            $allObservedFolders = @()
            $hotspotIsSyntheticOnly = $false
            $allObservedPatternExamples = @()

            if ($hotspot.Count -gt 0 -and $hotspot[0].HotspotFolders) {
                $allObservedFolders = @($hotspot[0].HotspotFolders)
                $hotspotIsSyntheticOnly = (@($allObservedFolders).Count -gt 0) -and (@($allObservedFolders | Where-Object { -not $_.SyntheticOnly }).Count -eq 0)
                $allObservedPatternExamples = @($allObservedFolders | Select-Object -First 3 | ForEach-Object { Join-PatternPath $_.FolderPath "*$extensionDisplay" })

                $safeObservedFolders = @(
                    $allObservedFolders |
                    Where-Object {
                        (Test-SafeSuggestedFolderPath -Path $_.FolderPath -DangerousPathPrefixes $riskCatalog.DangerousPathPrefixes) -and
                        -not ($ValidateLoad -and $_.FolderPath -match 'DefenderWorkload_')
                    } |
                    Select-Object -First 3
                )

                if ($safeObservedFolders.Count -gt 0) {
                    $recommendedFolder = $safeObservedFolders[0]
                }
            }

            $advisory = ''
            $command = ''
            $suggestionType = 'Extension'
            $suggestionValue = $extensionDisplay
            $reason = "Extension scans consumed $(Format-Duration $ms)"
            $scope = "MDAV broad extension exclusion across real-time, scheduled, and on-demand scans"
            $safeObservedPatternExamples = @($safeObservedFolders | ForEach-Object { Join-PatternPath $_.FolderPath "*$extensionDisplay" })
            $preference = ''
            $tierOrder = 90
            $fallbacks = @()
            $relatedProcessPath = $null
            $contextualProcessPath = $null
            $relativeShare = Get-RelativeSharePercent -DurationMs $ms -TotalMs $totalTopExtensionMs
            $concentrationPercent = $null
            $concentrationBasis = $null

            if ($recommendedFolder) {
                $folderPath = $recommendedFolder.FolderPath
                $patternPath = Join-PatternPath $folderPath "*$extensionDisplay"
                $shareText = if ($recommendedFolder.ShareOfObservedDuration) { "$($recommendedFolder.ShareOfObservedDuration)% of observed hotspot duration" } else { 'the heaviest observed hotspot activity' }

                if ($recommendedFolder.TopProcessPath -and
                    (Test-EligibleProcessPath -Path $recommendedFolder.TopProcessPath -RequireExistingPath:$RequireExistingProcessPath) -and
                    (Test-SafeSuggestedProcessPath -Path $recommendedFolder.TopProcessPath -SystemProcessPathPrefixes $riskCatalog.SystemProcessPathPrefixes)) {
                    $topProcessName = Split-Path $recommendedFolder.TopProcessPath -Leaf -ErrorAction SilentlyContinue
                    if ($topProcessName -and ($riskCatalog.DangerousProcesses -notcontains $topProcessName.ToLowerInvariant())) {
                        $contextualProcessPath = $recommendedFolder.TopProcessPath
                    }
                }

                $processText = if ($contextualProcessPath) {
                    $contextualProcessPath
                }
                elseif ($recommendedFolder.TopProcessPath) {
                    $recommendedFolder.TopProcessPath
                }
                elseif ($recommendedFolder.TopProcessImage) {
                    $recommendedFolder.TopProcessImage
                }
                else {
                    'n/a'
                }

                $suggestionType = 'ExtensionHotspot'
                $suggestionValue = "$extensionDisplay @ $folderPath"
                $reason = "The heaviest observed $extensionDisplay scans clustered in this folder ($shareText)"
                $scope = "Prefer file-pattern scoping for this extension hotspot; broader global extension exclusions remain a fallback"
                $relatedProcessPath = $contextualProcessPath
                $concentrationPercent = if ($recommendedFolder.ShareOfObservedDuration) { [double]$recommendedFolder.ShareOfObservedDuration } else { $null }
                $concentrationBasis = 'of observed folder-attributed duration for this extension'
                $processFallbackCommand = Format-ExclusionProcessCommand -ProcessPath $contextualProcessPath
                $contextualFolderFallbackCommand = if ($contextualProcessPath) {
                    "Add-MpPreference -ExclusionPath '$((Format-ContextualExclusionPath -Path $folderPath -PathType 'folder' -ScanTrigger 'OnAccess' -ProcessPath $contextualProcessPath) -replace "'", "''")'"
                }
                else {
                    $null
                }
                $patternFallbackCommand = "Add-MpPreference -ExclusionPath '$($patternPath -replace "'", "''")'"

                if ($ContextualExclusionsSupported -and $contextualProcessPath) {
                    $contextualPattern = Format-ContextualExclusionPath -Path $patternPath -PathType 'file' -ScanTrigger 'OnAccess' -ProcessPath $contextualProcessPath
                    $command = "Add-MpPreference -ExclusionPath '$($contextualPattern -replace "'", "''")'"
                    $scope = "MDAV on-access only for $extensionDisplay files in this folder and exact process path"
                    $preference = 'Tier 1 - Preferred contextual file-pattern recommendation'
                    $tierOrder = 1
                    $fallbacks = @(
                        New-RankedFallback -TierOrder 2 -Label 'Contextual folder fallback' -Command $contextualFolderFallbackCommand
                        New-RankedFallback -TierOrder 3 -Label 'File-pattern path fallback' -Command $patternFallbackCommand
                        New-RankedFallback -TierOrder 4 -Label 'Exact process fallback' -Command $processFallbackCommand
                    )
                    [void]$coveredProcessPaths.Add($contextualProcessPath)
                }
                else {
                    $command = $patternFallbackCommand
                    $scope = "MDAV file-pattern exclusion for $extensionDisplay files in this folder across scan types"
                    $preference = 'Tier 3 - Preferred file-pattern recommendation'
                    $tierOrder = 3
                    $fallbacks = @(
                        New-RankedFallback -TierOrder 4 -Label 'Exact process fallback' -Command $processFallbackCommand
                    )
                }

                if ($risk -ne 'SAFE') {
                    $command += "`n     # Global fallback only if truly necessary: Add-MpPreference -ExclusionExtension '$extensionDisplay'"
                    $fallbacks += New-RankedFallback -TierOrder 6 -Label 'Global extension fallback only if truly necessary' -Command "Add-MpPreference -ExclusionExtension '$extensionDisplay'"
                }

                $advisory = "Start with the narrowest folder-scoped option here. Dominant observed process: $processText. Protect that folder with restrictive ACLs."
            }
            elseif ($safeObservedPatternExamples.Count -gt 0) {
                $suggestionType = 'ExtensionHotspot'
                $suggestionValue = "$extensionDisplay @ multiple folders"
                $reason = "Observed $extensionDisplay scans clustered in multiple safe folders"
                $scope = "MDAV file-pattern exclusions for $extensionDisplay files in the observed folders across scan types"
                $patternCommands = @($safeObservedPatternExamples | ForEach-Object { "Add-MpPreference -ExclusionPath '$($_ -replace "'", "''")'" })
                $command = ($patternCommands -join "`n")
                $preference = 'Tier 3 - Preferred file-pattern recommendation'
                $tierOrder = 3
                $concentrationPercent = if ($hotspot[0].DominantFolderShare) { [double]$hotspot[0].DominantFolderShare } else { $null }
                $concentrationBasis = 'of observed folder-attributed duration for this extension'
                if ($risk -ne 'SAFE') {
                    $command += "`n     # Global fallback only if truly necessary: Add-MpPreference -ExclusionExtension '$extensionDisplay'"
                    $fallbacks += New-RankedFallback -TierOrder 6 -Label 'Global extension fallback only if truly necessary' -Command "Add-MpPreference -ExclusionExtension '$extensionDisplay'"
                }
                $advisory = "Prefer these concrete file-pattern exclusions over a global $extensionDisplay exclusion."
            }
            elseif ($hotspotIsSyntheticOnly) {
                $suppressedBecause = 'Validation-only evidence: observed folders are synthetic workload paths and the dominant process is a Windows/system scripting engine, so this was not promoted into a live exclusion recommendation.'
                $evidenceText = if ($hotspot[0].DominantProcessPath) { "Dominant process: $($hotspot[0].DominantProcessPath)" } else { "Dominant folder: $($hotspot[0].DominantFolderPath)" }
                $suppressedCommands = @()
                $suppressedType = 'ValidationOnlyPattern'
                $suppressedScope = "Validation-only file-pattern candidates for $extensionDisplay"
                $suppressedPreference = ''

                if ($ContextualExclusionsSupported -and
                    $hotspot[0].DominantProcessPath -and
                    (Test-EligibleProcessPath -Path $hotspot[0].DominantProcessPath -RequireExistingPath:$RequireExistingProcessPath) -and
                    (Test-SafeSuggestedProcessPath -Path $hotspot[0].DominantProcessPath -SystemProcessPathPrefixes $riskCatalog.SystemProcessPathPrefixes)) {
                    $suppressedCommands = @(
                        $allObservedFolders |
                        Select-Object -First 3 |
                        ForEach-Object {
                            $contextualSyntheticPattern = Format-ContextualExclusionPath -Path (Join-PatternPath $_.FolderPath "*$extensionDisplay") -PathType 'file' -ScanTrigger 'OnAccess' -ProcessPath $hotspot[0].DominantProcessPath
                            "Add-MpPreference -ExclusionPath '$($contextualSyntheticPattern -replace "'", "''")'"
                        }
                    )
                    $suppressedType = 'ValidationOnlyContextualPattern'
                    $suppressedScope = "Validation-only MDAV on-access contextual file-pattern candidates for $extensionDisplay and the exact helper process"
                    $suppressedPreference = 'Tier 1 - Validation-only preferred contextual file-pattern recommendation'
                    $suppressedBecause = 'Validation-only evidence: this contextual file-pattern candidate came from the synthetic workload, so it was captured for proof but not promoted into a live recommendation.'
                }
                else {
                    $suppressedCommands = @($allObservedPatternExamples | ForEach-Object { "Add-MpPreference -ExclusionPath '$($_ -replace "'", "''")'" })
                }

                $suppressedCandidates.Add([PSCustomObject]@{
                        Type              = $suppressedType
                        Value             = "$extensionDisplay @ synthetic workload folders"
                        Impact            = Get-ImpactLevel -DurationMs $ms -HighThresholdMs $HighThresholdMs -MediumThresholdMs $MediumThresholdMs
                        Reason            = "Observed $extensionDisplay scans clustered in synthetic validation folders"
                        SuppressedBecause = $suppressedBecause
                        Commands          = @($suppressedCommands | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                        Scope             = $suppressedScope
                        Evidence          = $evidenceText
                        Preference        = $suppressedPreference
                        RelativeSharePercent = $relativeShare
                        RelativeShareBasis = 'of observed extension scan duration in this run'
                        ConcentrationPercent = if ($hotspot[0].DominantFolderShare) { [double]$hotspot[0].DominantFolderShare } else { $null }
                        ConcentrationBasis = 'of observed folder-attributed duration for this extension'
                    })
                continue
            }

            if ([string]::IsNullOrWhiteSpace($command)) { continue }

            $suggestions.Add([PSCustomObject]@{
                    Type     = $suggestionType
                    Value    = $suggestionValue
                    Reason   = $reason
                    Impact   = Get-ImpactLevel -DurationMs $ms -HighThresholdMs $HighThresholdMs -MediumThresholdMs $MediumThresholdMs
                    Command  = $command
                    Risk     = $risk
                    Advisory = $advisory
                    Scope    = $scope
                    Preference = $preference
                    TierOrder = $tierOrder
                    Fallbacks = @($fallbacks | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
                    RelatedProcessPath = $relatedProcessPath
                    RelativeSharePercent = $relativeShare
                    RelativeShareBasis = 'of observed extension scan duration in this run'
                    ConcentrationPercent = $concentrationPercent
                    ConcentrationBasis = $concentrationBasis
                })
        }
    }

    if ($suggestions.Count -gt 0) {
        foreach ($suggestion in @($suggestions)) {
            if ($suggestion.Type -eq 'Process') { continue }
            if ([string]::IsNullOrWhiteSpace([string]$suggestion.RelatedProcessPath)) { continue }

            $processFallback = New-RankedFallback -TierOrder 4 -Label 'Exact process fallback' -Command (Format-ExclusionProcessCommand -ProcessPath $suggestion.RelatedProcessPath)
            if ([string]::IsNullOrWhiteSpace($processFallback)) { continue }

            $existingFallbacks = @($suggestion.Fallbacks)
            if ($existingFallbacks -notcontains $processFallback) {
                $suggestion.Fallbacks = @($existingFallbacks + $processFallback | Select-Object -Unique)
            }
        }

        $retainedSuggestions = [System.Collections.Generic.List[object]]::new()
        foreach ($suggestion in @($suggestions)) {
            if ($suggestion.Type -eq 'Process' -and
                -not [string]::IsNullOrWhiteSpace([string]$suggestion.RelatedProcessPath) -and
                $coveredProcessPaths.Contains([string]$suggestion.RelatedProcessPath)) {
                continue
            }

            $retainedSuggestions.Add($suggestion)
        }

        $suggestions = $retainedSuggestions
    }

    $sortedSuggestions = @(
        $suggestions |
        Sort-Object `
            @{ Expression = { if (Get-Prop $_ 'TierOrder') { [int]$_.TierOrder } else { 99 } } }, `
            @{ Expression = { Get-ImpactOrder -Impact (Get-Prop $_ 'Impact') } }, `
            @{ Expression = { if ($null -ne (Get-Prop $_ 'RelativeSharePercent')) { -1 * [double](Get-Prop $_ 'RelativeSharePercent') } else { 0 } } }, `
            @{ Expression = { if ($null -ne (Get-Prop $_ 'ConcentrationPercent')) { -1 * [double](Get-Prop $_ 'ConcentrationPercent') } else { 0 } } }, `
            @{ Expression = { [string](Get-Prop $_ 'Value') } }
    )

    return [PSCustomObject]@{
        Suggestions          = @($sortedSuggestions)
        SuppressedCandidates = @($suppressedCandidates)
        TopScanContexts      = @($topScanContexts)
        ExtensionHotspots    = @($extensionHotspots)
    }
}

function Read-NormalizedTextFile([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }

    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ($null -eq $raw) { return $null }

    return ($raw -replace "`0", '')
}

function Get-NormalizedTextLines([string]$Path) {
    $content = Read-NormalizedTextFile $Path
    if ($null -eq $content) { return @() }
    return @($content -split '\r?\n')
}

function Get-DefenderCabIntelligenceFromExtractedDirectory {
    param(
        [Parameter(Mandatory)][string]$ExtractedDirectory
    )

    if (-not (Test-Path -LiteralPath $ExtractedDirectory -PathType Container)) {
        throw "Extracted CAB directory not found: $ExtractedDirectory"
    }

    $cabIntel = [ordered]@{}

    $fileVersionsFile = Get-ChildItem -Path $ExtractedDirectory -Filter 'FileVersions.txt' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($fileVersionsFile) {
        $fileVersionsContent = Read-NormalizedTextFile $fileVersionsFile.FullName
        $platformVersions = [ordered]@{}

        if ($fileVersionsContent -match 'OS Build/Branch info:\s*([^\r\n]+)') {
            $platformVersions['OSBuildBranch'] = $Matches[1].Trim()
        }
        if ($fileVersionsContent -match 'GetOsVersion\(\)\s*reports:\s*([^\r\n]+)') {
            $platformVersions['ReportedOSVersion'] = $Matches[1].Trim()
        }
        if ($fileVersionsContent -match 'Windows Defender\\Platform\\([0-9A-Za-z\.\-]+)') {
            $platformVersions['DefenderPlatformVersion'] = $Matches[1].Trim()
        }

        if ($platformVersions.Count -gt 0) {
            $cabIntel['PlatformVersions'] = [PSCustomObject]$platformVersions
        }
    }

    $mpStateFile = Get-ChildItem -Path $ExtractedDirectory -Filter 'MPStateInfo.txt' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($mpStateFile) {
        $mpStateContent = Read-NormalizedTextFile $mpStateFile.FullName
        $healthState = [ordered]@{}

        if ($mpStateContent -match 'Threat Stats\s*:\s*Threats\((\d+)\)\s*Suspicious\((\d+)\)') {
            $healthState['ThreatCount'] = [int]$Matches[1]
            $healthState['SuspiciousCount'] = [int]$Matches[2]
        }
        if ($mpStateContent -match 'Overall product status\s*:\s*(0x[0-9A-Fa-f]+)') {
            $healthState['OverallProductStatus'] = $Matches[1]
        }

        $statusPhrases = [ordered]@{
            AutoScanEnabled            = 'Auto scan enabled'
            AutoSignatureUpdateEnabled = 'Auto sigupdate enabled'
            RealtimeMonitorEnabled     = 'Realtime monitor enabled'
            OnAccessProtectionEnabled  = 'OnAccess protection enabled'
            IOAVProtectionEnabled      = 'IOAV protection enabled'
        }

        foreach ($statusEntry in $statusPhrases.GetEnumerator()) {
            $healthState[$statusEntry.Key] = $mpStateContent -match [regex]::Escape($statusEntry.Value)
        }

        if ($healthState.Count -gt 0) {
            $cabIntel['HealthState'] = [PSCustomObject]$healthState
        }
    }

    $networkProtectionFile = Get-ChildItem -Path $ExtractedDirectory -Filter 'NetworkProtectionState.txt' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($networkProtectionFile) {
        $networkProtectionContent = Read-NormalizedTextFile $networkProtectionFile.FullName
        $networkProtection = [ordered]@{}
        $networkFlags = [ordered]@{}
        $disabledFeatures = @()

        if ($networkProtectionContent -match 'Network Protection is currently set in ([^\r\n]+?) mode') {
            $networkProtection['Mode'] = $Matches[1].Trim()
        }

        foreach ($match in [regex]::Matches($networkProtectionContent, '"([^"]+)":(true|false)')) {
            $flagName = $match.Groups[1].Value
            $flagValue = $match.Groups[2].Value -eq 'true'
            $networkFlags[$flagName] = $flagValue
            if ($flagName -like 'disable*' -and $flagValue) {
                $disabledFeatures += $flagName
            }
        }

        if ($networkFlags.Count -gt 0) {
            $networkProtection['Flags'] = [PSCustomObject]$networkFlags
            $networkProtection['DisabledFeatures'] = @($disabledFeatures)
            $networkProtection['DisabledFeatureCount'] = $disabledFeatures.Count
        }

        if ($networkProtection.Count -gt 0) {
            $cabIntel['NetworkProtection'] = [PSCustomObject]$networkProtection
        }
    }

    $deviceControlFile = Get-ChildItem -Path $ExtractedDirectory -Filter 'DeviceControlInfo.txt' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($deviceControlFile) {
        $deviceControlContent = Read-NormalizedTextFile $deviceControlFile.FullName
        $deviceControl = [ordered]@{}

        if ($deviceControlContent -match 'Defender service running mode:\s*([^\r\n]+)') {
            $deviceControl['ServiceMode'] = $Matches[1].Trim()
        }
        if ($deviceControlContent -match 'PackageVersion:\s*([^\r\n]+)') {
            $deviceControl['PackageVersion'] = $Matches[1].Trim()
        }
        if ($deviceControlContent -match 'State:\s*([^\r\n]+)') {
            $deviceControl['State'] = $Matches[1].Trim()
        }
        if ($deviceControlContent -match 'DefaultEnforcement:\s*([^\r\n]+)') {
            $deviceControl['DefaultEnforcement'] = $Matches[1].Trim()
        }
        if ($deviceControlContent -match 'PoliciesLastUpdated:\s*([^\r\n]+)') {
            $deviceControl['PoliciesLastUpdated'] = $Matches[1].Trim()
        }

        $deviceControlLog = Get-ChildItem -Path $ExtractedDirectory -Filter 'MPDeviceControl-*.log' -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($deviceControlLog) {
            $deviceControlLogContent = Read-NormalizedTextFile $deviceControlLog.FullName
            if ($deviceControlLogContent -match 'IsAvailable\[(\d+)\]') {
                $deviceControl['Available'] = ([int]$Matches[1] -ne 0)
            }
            if ($deviceControlLogContent -match 'fDeviceControlEnabled\[(\d+)\]') {
                $deviceControl['EnabledByPolicy'] = ([int]$Matches[1] -ne 0)
            }
            if ($deviceControlLogContent -match 'fDeviceControlPolicyPresent\[(\d+)\]') {
                $deviceControl['PolicyPresent'] = ([int]$Matches[1] -ne 0)
            }
        }

        if ($deviceControl.Count -gt 0) {
            $cabIntel['DeviceControl'] = [PSCustomObject]$deviceControl
        }
    }

    $operationalEventsFile = Get-ChildItem -Path $ExtractedDirectory -Filter 'MPOperationalEvents.txt' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($operationalEventsFile) {
        $operationalEventsContent = Read-NormalizedTextFile $operationalEventsFile.FullName
        $cloudOperationalEvents = [ordered]@{}
        $cloudEventCount = [regex]::Matches($operationalEventsContent, 'used cloud protection to get additional security intelligence', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Count
        $recentCloudEvents = [System.Collections.Generic.List[object]]::new()

        if ($cloudEventCount -gt 0) {
            $cloudOperationalEvents['CloudProtectionEventCount'] = $cloudEventCount
        }
        if ($operationalEventsContent -match 'Current security intelligence Version:\s*([^\r\n]+)') {
            $cloudOperationalEvents['LatestSecurityIntelligenceVersion'] = $Matches[1].Trim()
        }
        if ($operationalEventsContent -match 'Current Engine Version:\s*([^\r\n]+)') {
            $cloudOperationalEvents['LatestEngineVersion'] = $Matches[1].Trim()
        }

        foreach ($eventChunk in ($operationalEventsContent -split '(?=\*{20,})')) {
            if ($recentCloudEvents.Count -ge 5) { break }
            if ($eventChunk -notmatch 'used cloud protection to get additional security intelligence') { continue }

            $eventInfo = [ordered]@{}
            if ($eventChunk -match '(?m)^(?<timestamp>\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)\s+') {
                $eventInfo['Timestamp'] = $Matches['timestamp'].Trim()
            }
            if ($eventChunk -match 'Current security intelligence Version:\s*([^\r\n]+)') {
                $eventInfo['SecurityIntelligenceVersion'] = $Matches[1].Trim()
            }
            if ($eventChunk -match 'Current Engine Version:\s*([^\r\n]+)') {
                $eventInfo['EngineVersion'] = $Matches[1].Trim()
            }
            if ($eventChunk -match 'Cloud protection intelligence Type:\s*([^\r\n]+)') {
                $eventInfo['IntelligenceType'] = $Matches[1].Trim()
            }
            if ($eventChunk -match 'Persistence Path:\s*([^\r\n]+)') {
                $eventInfo['PersistencePath'] = $Matches[1].Trim()
            }
            if ($eventChunk -match 'Cloud protection intelligence Compilation Timestamp:\s*([^\r\n]+)') {
                $eventInfo['CompilationTimestamp'] = $Matches[1].Trim()
            }
            if ($eventChunk -match 'Persistence Limit Type:\s*([^\r\n]+)') {
                $eventInfo['PersistenceLimitType'] = $Matches[1].Trim()
            }
            if ($eventChunk -match 'Persistence Limit:\s*([^\r\n]+)') {
                $eventInfo['PersistenceLimit'] = $Matches[1].Trim()
            }

            if ($eventInfo.Count -gt 0) {
                $recentCloudEvents.Add([PSCustomObject]$eventInfo)
            }
        }

        if ($recentCloudEvents.Count -gt 0) {
            $cloudOperationalEvents['RecentCloudEvents'] = @($recentCloudEvents)
        }

        if ($cloudOperationalEvents.Count -gt 0) {
            $cabIntel['CloudOperationalEvents'] = [PSCustomObject]$cloudOperationalEvents
        }
    }

    $wscInfoFile = Get-ChildItem -Path $ExtractedDirectory -Filter 'WSCInfo.txt' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($wscInfoFile) {
        $wscLines = Get-NormalizedTextLines $wscInfoFile.FullName
        $rawProducts = [System.Collections.Generic.List[object]]::new()
        $currentProduct = [ordered]@{}

        foreach ($line in $wscLines) {
            $trimmedLine = $line.Trim()

            if ($trimmedLine -match '^displayName = \[(.+)\]$') {
                if ($currentProduct.Count -gt 0 -and $currentProduct['DisplayName']) {
                    $rawProducts.Add([PSCustomObject]$currentProduct)
                }
                $currentProduct = [ordered]@{ DisplayName = $Matches[1].Trim() }
                continue
            }

            if ($trimmedLine -match '^pathToSignedProductExe = \[(.*)\]$') {
                if ($currentProduct.Count -gt 0) {
                    $currentProduct['ProductPath'] = $Matches[1].Trim()
                }
                continue
            }

            if ($trimmedLine -match '^productState = \[(\d+)\]$') {
                if ($currentProduct.Count -gt 0) {
                    $currentProduct['ProductState'] = [int]$Matches[1]
                    $rawProducts.Add([PSCustomObject]$currentProduct)
                    $currentProduct = [ordered]@{}
                }
            }
        }

        if ($currentProduct.Count -gt 0 -and $currentProduct['DisplayName']) {
            $rawProducts.Add([PSCustomObject]$currentProduct)
        }

        $uniqueProducts = [System.Collections.Generic.List[object]]::new()
        $seenProducts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($product in $rawProducts) {
            $productKey = '{0}|{1}|{2}' -f $product.DisplayName, $product.ProductPath, $product.ProductState
            if ($seenProducts.Add($productKey)) {
                $uniqueProducts.Add($product)
            }
        }

        if ($uniqueProducts.Count -gt 0) {
            $cabIntel['SecurityCenterProducts'] = @($uniqueProducts)
        }
    }

    $senseSource = Get-ChildItem -Path $ExtractedDirectory -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @('.txt', '.log', '.json') } |
        Select-String -Pattern 'OnboardedInfo|MdeAadTenantIdMapping' -List -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($senseSource) {
        $senseContent = Read-NormalizedTextFile $senseSource.Path
        $mdeOnboarding = [ordered]@{}

        if ($senseContent -match '"orgId":"([^"]+)"') {
            $mdeOnboarding['OrgId'] = $Matches[1]
        }
        if ($senseContent -match '"datacenter":"([^"]+)"') {
            $mdeOnboarding['Datacenter'] = $Matches[1]
        }
        if ($senseContent -match '"vortexGeoLocation":"([^"]+)"') {
            $mdeOnboarding['VortexGeoLocation'] = $Matches[1]
        }
        if ($senseContent -match '"mdeAadTenantId":"([^"]+)"') {
            $mdeOnboarding['MdeAadTenantId'] = $Matches[1]
        }
        if ($senseContent -match '"version":"([^"]+)"') {
            $mdeOnboarding['Version'] = $Matches[1]
        }

        if ($mdeOnboarding.Count -gt 0) {
            $mdeOnboarding['Onboarded'] = $true
            $cabIntel['MDEOnboarding'] = [PSCustomObject]$mdeOnboarding
        }
    }

    $mpLogFiles = @(Get-ChildItem -Path $ExtractedDirectory -Filter 'MPLog-*.log' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($mpLogFiles) {
        $mpLogHighlights = [ordered]@{
            FileCount           = $mpLogFiles.Count
            LatestFile          = $mpLogFiles[0].Name
            LatestFileWriteTime = $mpLogFiles[0].LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        $dynamicSignatureEvents = [System.Collections.Generic.List[object]]::new()
        $impactRecords = [System.Collections.Generic.List[object]]::new()
        $pathExclusions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $processExclusions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $extensionExclusions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($mpLogFile in $mpLogFiles | Select-Object -First 3) {
            $mpLogLines = Get-NormalizedTextLines $mpLogFile.FullName
            $currentImpactRecord = $null
            $currentTimestamp = $null

            for ($i = 0; $i -lt $mpLogLines.Count; $i++) {
                $line = $mpLogLines[$i]
                if ([string]::IsNullOrWhiteSpace($line)) {
                    if ($currentImpactRecord -and $currentImpactRecord.Count -gt 1) {
                        $impactRecords.Add([PSCustomObject]$currentImpactRecord)
                    }
                    $currentImpactRecord = $null
                    continue
                }

                $trimmedLine = $line.Trim()
                if ($trimmedLine -match '^(?<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)') {
                    $currentTimestamp = $Matches['timestamp']
                }

                if ($trimmedLine -match '^PathExclusion:\s*(.+)$') {
                    [void]$pathExclusions.Add($Matches[1].Trim())
                }
                elseif ($trimmedLine -match '^ProcessExclusion:\s*(.+)$') {
                    [void]$processExclusions.Add($Matches[1].Trim())
                }
                elseif ($trimmedLine -match '^ExtensionExclusion:\s*(.+)$') {
                    $normalizedExtension = Normalize-Extension $Matches[1]
                    if ($normalizedExtension) {
                        [void]$extensionExclusions.Add($normalizedExtension)
                    }
                }

                if ($trimmedLine -match 'Dynamic signature dropped$') {
                    $event = [ordered]@{
                        Timestamp = $currentTimestamp
                        SourceLog = $mpLogFile.Name
                    }

                    for ($j = $i + 1; $j -lt [Math]::Min($mpLogLines.Count, $i + 8); $j++) {
                        $detailLine = $mpLogLines[$j].Trim()
                        if ([string]::IsNullOrWhiteSpace($detailLine)) { break }
                        if ($detailLine -match '^\d{4}-\d{2}-\d{2}T') { break }
                        if ($detailLine -match '^Dynamic Signature Type:\s*(.+)$') {
                            $event['SignatureType'] = $Matches[1].Trim()
                        }
                        elseif ($detailLine -match '^Signature Path:\s*(.+)$') {
                            $event['SignaturePath'] = $Matches[1].Trim()
                        }
                        elseif ($detailLine -match '^Dynamic Signature Compilation Timestamp:\s*(.+)$') {
                            $event['CompilationTimestamp'] = $Matches[1].Trim()
                        }
                        elseif ($detailLine -match '^Persistence Type:\s*(.+)$') {
                            $event['PersistenceType'] = $Matches[1].Trim()
                        }
                        elseif ($detailLine -match '^Time remaining:\s*(.+)$') {
                            $event['TimeRemaining'] = $Matches[1].Trim()
                        }
                    }

                    $dynamicSignatureEvents.Add([PSCustomObject]$event)
                }

                if ($trimmedLine -match '^(ProcessImageName|ProcessPath|ProcessName|ImageName|EstimatedImpact|Estimated impact)\s*[:=]\s*(.+)$') {
                    if (-not $currentImpactRecord) {
                        $currentImpactRecord = [ordered]@{
                            Timestamp = $currentTimestamp
                            SourceLog = $mpLogFile.Name
                        }
                    }

                    $fieldName = ($Matches[1] -replace '\s+', '')
                    $fieldValue = $Matches[2].Trim()
                    switch -Regex ($fieldName) {
                        '^ProcessImageName$' { $currentImpactRecord['ProcessImageName'] = $fieldValue }
                        '^ProcessPath$'      { $currentImpactRecord['ProcessPath'] = $fieldValue }
                        '^ProcessName$'      { $currentImpactRecord['ProcessName'] = $fieldValue }
                        '^ImageName$'        { $currentImpactRecord['ImageName'] = $fieldValue }
                        '^EstimatedImpact$'  { $currentImpactRecord['EstimatedImpact'] = $fieldValue }
                    }
                }
            }

            if ($currentImpactRecord -and $currentImpactRecord.Count -gt 1) {
                $impactRecords.Add([PSCustomObject]$currentImpactRecord)
            }
        }

        if ($dynamicSignatureEvents.Count -gt 0) {
            $mpLogHighlights['DynamicSignatureDropCount'] = $dynamicSignatureEvents.Count
            $mpLogHighlights['RecentDynamicSignatureEvents'] = @($dynamicSignatureEvents | Select-Object -First 5)
        }

        if ($pathExclusions.Count -gt 0 -or $processExclusions.Count -gt 0 -or $extensionExclusions.Count -gt 0) {
            $mpLogHighlights['ExclusionMentions'] = [PSCustomObject][ordered]@{
                Paths      = @($pathExclusions)
                Processes  = @($processExclusions)
                Extensions = @($extensionExclusions | ForEach-Object { Format-ExtensionDisplay $_ })
            }
        }

        if ($impactRecords.Count -gt 0) {
            $mpLogHighlights['ImpactRecords'] = @($impactRecords | Select-Object -First 10)
        }

        if ($mpLogHighlights.Count -gt 0) {
            $cabIntel['MPLogHighlights'] = [PSCustomObject]$mpLogHighlights
        }
    }

    $mpSigStubFile = Get-ChildItem -Path $ExtractedDirectory -Filter 'MpSigStub.log' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($mpSigStubFile) {
        $mpSigStubContent = Read-NormalizedTextFile $mpSigStubFile.FullName
        $signatureUpdateStub = [ordered]@{}

        if ($mpSigStubContent -match 'Start time:\s*([^\r\n]+)') {
            $signatureUpdateStub['StartTime'] = $Matches[1].Trim()
        }
        if ($mpSigStubContent -match 'Command:\s*([^\r\n]+)') {
            $signatureUpdateStub['Command'] = $Matches[1].Trim()
        }
        if ($mpSigStubContent -match 'Administrator:\s*([^\r\n]+)') {
            $signatureUpdateStub['Administrator'] = $Matches[1].Trim()
        }
        if ($mpSigStubContent -match 'Version:\s*([^\r\n]+)') {
            $signatureUpdateStub['StubVersion'] = $Matches[1].Trim()
        }
        if ($mpSigStubContent -match 'Status:\s*([^\r\n]+)') {
            $signatureUpdateStub['ProductStatus'] = $Matches[1].Trim()
        }
        if ($mpSigStubContent -match 'Engine:\s*[0-9a-fA-F]+\s+([^\r\n]+)') {
            $signatureUpdateStub['ProductEngineVersion'] = $Matches[1].Trim()
        }

        if ($signatureUpdateStub.Count -gt 0) {
            $cabIntel['SignatureUpdateStub'] = [PSCustomObject]$signatureUpdateStub
        }
    }

    $scanSkipFiles = Get-ChildItem -Path $ExtractedDirectory -Filter 'MPScanSkip-*.log' -Recurse -ErrorAction SilentlyContinue
    if ($scanSkipFiles) {
        $skipReasons = @{}
        $totalSkips = 0
        foreach ($scanSkipFile in $scanSkipFiles) {
            foreach ($line in (Get-Content $scanSkipFile.FullName -ErrorAction SilentlyContinue)) {
                if ($line -match 'Reason\[(.+?)\]') {
                    $reason = $Matches[1]
                    if (-not $skipReasons.ContainsKey($reason)) { $skipReasons[$reason] = 0 }
                    $skipReasons[$reason]++
                    $totalSkips++
                }
            }
        }

        if ($totalSkips -gt 0) {
            $cabIntel['ScanSkips'] = [PSCustomObject][ordered]@{
                TotalSkipped = $totalSkips
                ByReason     = [PSCustomObject]$skipReasons
            }
        }
    }

    $detectionFiles = Get-ChildItem -Path $ExtractedDirectory -Filter 'MPDetection-*.log' -Recurse -ErrorAction SilentlyContinue
    if ($detectionFiles) {
        $detections = [System.Collections.Generic.List[string]]::new()
        foreach ($detectionFile in $detectionFiles) {
            foreach ($line in (Get-Content $detectionFile.FullName -ErrorAction SilentlyContinue)) {
                if ($line -match 'threat|detection|quarantine' -and $line -notmatch '^[\d-]+T[\d:.]+ (Version|Service started)') {
                    $detections.Add($line.Trim())
                }
            }
        }
        $cabIntel['RecentDetections'] = @($detections)
    }

    $fltmcFile = Get-ChildItem -Path $ExtractedDirectory -Filter 'FltmcInfo.txt' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($fltmcFile) {
        $drivers = [System.Collections.Generic.List[object]]::new()
        foreach ($line in (Get-Content $fltmcFile.FullName -ErrorAction SilentlyContinue)) {
            if ($line -match '^\S+\s+\d+\s+\d+') {
                $parts = $line.Trim() -split '\s+'
                $drivers.Add([PSCustomObject][ordered]@{
                        Name      = $parts[0]
                        Instances = [int]$parts[1]
                        Altitude  = $parts[2]
                    })
            }
        }

        if ($drivers.Count -gt 0) {
            $cabIntel['FilterDrivers'] = @($drivers)
        }
    }

    $ifeoFile = Get-ChildItem -Path $ExtractedDirectory -Filter 'IFEO.txt' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($ifeoFile) {
        $ifeoContent = Get-Content $ifeoFile.FullName -Raw -ErrorAction SilentlyContinue
        $debuggerHijacks = [System.Collections.Generic.List[string]]::new()
        if ($ifeoContent -match 'Debugger') {
            foreach ($ifeoLine in ($ifeoContent -split '\r?\n')) {
                if ($ifeoLine -match 'Debugger.*=.*\S') {
                    $debuggerHijacks.Add($ifeoLine.Trim())
                }
            }
        }

        if ($debuggerHijacks.Count -gt 0) {
            $cabIntel['IFEODebuggerHijacks'] = @($debuggerHijacks)
        }
    }

    return [PSCustomObject]$cabIntel
}
