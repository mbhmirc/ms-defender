# ms-defender

PowerShell tooling for Microsoft Defender Antivirus performance analysis, exclusion discovery, configuration review, and validation.

The main script is [defender.ps1](./defender.ps1). It is designed to run as Administrator on Windows and helps answer four practical questions:

1. Is Defender configured and running as expected?
2. Which files, processes, extensions, and scan contexts are driving scan overhead?
3. What exclusions already exist, and can they be discovered reliably?
4. If exclusions are needed, what is the narrowest reasonable Microsoft Defender Antivirus recommendation?

The preferred use case is an active workload or performance issue on the affected machine, especially on servers where the goal is to diagnose Defender impact first and avoid exclusions unless the evidence clearly supports a narrow, justified change.

## What The Project Does

`defender.ps1` performs an end-to-end Defender audit:

1. Optionally validates exclusion discovery by creating a temporary exclusion and checking whether each discovery method can find it.
2. Discovers current exclusions from `Get-MpPreference`, direct registry reads, and `MpCmdRun.exe -GetFiles` CAB extraction.
3. Extracts useful intelligence from `MpSupportFiles.cab`, including effective config, product health, network protection, scan skips, MPLog highlights, device control state, Security Center registrations, and related diagnostics.
4. Records a Defender performance trace with `New-MpPerformanceRecording`.
5. Optionally generates synthetic load during the recording to exercise the scan pipeline.
6. Analyzes the trace with `Get-MpPerformanceReport -Raw`.
7. Produces console output plus JSON and HTML reports.
8. Generates exclusion recommendations using a narrow-first approach:
   file-pattern path exclusions before broader folder or global extension exclusions
9. Suppresses unsafe or validation-only recommendations instead of promoting them into live exclusions.

## Design Intent

This is a Defender performance advisor, not a generic exclusion wizard.

- It is intended to be run during the real workload issue when possible, not only as an offline lab exercise.
- It is especially useful on servers where clients want to avoid exclusions unless there is strong evidence for a tightly scoped exception.
- Exclusions are treated as a last resort.
- Narrow path or file-pattern exclusions are preferred over broad folder or extension exclusions.
- Process or contextual exclusions are not recommended for Windows or other system binaries.
- Synthetic validation workload results can be surfaced for review, but not promoted into live recommendations.
- The tool is intended to support Microsoft Defender Antivirus tuning, not replace controls such as ASR, CFA, indicators, or Defender for Endpoint automation exclusions.

## Best Time To Run It

For the highest-value results, run the tool while the real issue is happening:

- during a backup, restore, compile, build, package, indexing, or archive-heavy workload
- during the actual server-side performance complaint, not only after the fact
- before adding exclusions, so you capture evidence first

Use `-ValidateLoad` when you are testing the tool itself, validating the reporting pipeline, or building confidence in a lab. For production troubleshooting, real workload evidence is preferred. When validating synthetic attribution, you can choose `-SyntheticWorkloadMode Mixed`, `PowerShell`, or `NativeExe`.

If your goal is to prove contextual recommendations end to end, prefer `-SyntheticWorkloadMode NativeExe`. That mode drives the synthetic file churn from the bundled helper executable instead of `powershell.exe`, which makes it much easier to validate contextual file-pattern recommendations without a Windows scripting host dominating the attribution.

Recommendation ladder:

1. Tier 1: contextual file-pattern recommendation
2. Tier 2: contextual folder recommendation
3. Tier 3: file-pattern path recommendation
4. Tier 4: exact process fallback recommendation
5. Broad folder exclusions stay manual and exceptional
6. Tier 6: global extension fallback only if truly necessary

The report now shows the preferred recommendation first and then lists fallbacks in order, so a process exclusion is treated as a later fallback instead of the default first answer.

The recommendation output also shows:

- `Share`: how much of the observed activity for that category happened in this run
- `Focus`: how concentrated the activity was in the dominant folder for that extension

Absolute duration is still used as the safety floor, so a tiny quiet-run spike does not get promoted just because its percentage is high.

## Repository Contents

- [defender.ps1](./defender.ps1): main script
- [defender-workload.ps1](./defender-workload.ps1): synthetic build/cache/log style workload generator used by `-ValidateLoad`
- [defender-test.ps1](./defender-test.ps1): automated validation harness for the main script
- [defender-single-run.ps1](./defender-single-run.ps1): self-elevating one-shot runner that captures logs and a run summary
- [defender-validation-loop.ps1](./defender-validation-loop.ps1): self-elevating repeat-run loop harness
- [defender-compare.ps1](./defender-compare.ps1): compare mode for diffing two saved report JSON files
- [defender-offline-fixture-tests.ps1](./defender-offline-fixture-tests.ps1): offline fixture suite for CAB parsing, recommendation ranking, and compare-mode checks
- [MSDefender](./MSDefender): PowerShell module manifest and reusable command entrypoints
- [extract_cab.ps1](./extract_cab.ps1): standalone `MpSupportFiles.cab` extraction and inventory helper
- [tests/fixtures](./tests/fixtures): deterministic offline samples used by the fixture suite

## Requirements

- Windows 10, Windows 11, or Windows Server with Microsoft Defender Antivirus available
- Administrator rights for the main analysis flow
- Microsoft Defender Antivirus cmdlets and support tooling available on the machine
- PowerShell 5.1 or later

## PowerShell Module

The repository also ships a reusable PowerShell module in [MSDefender](./MSDefender).

Import it from the repo root:

```powershell
Import-Module .\MSDefender\MSDefender.psd1
Get-Command -Module MSDefender
```

Example module usage:

```powershell
Invoke-MsDefenderPerformanceAudit -RecordingSeconds 300 -TopN 30
Invoke-MsDefenderSingleRun -RecordingSeconds 180 -ValidateLoad -SyntheticWorkloadMode NativeExe
Compare-MsDefenderPerformanceReport -BaselineReport .\before.json -CurrentReport .\after.json
Test-MsDefenderOfflineFixtures
```

The script entrypoints remain supported and are still the easiest choice for UAC-driven interactive runs. The module is useful when you want reusable commands for your own automation, scheduled tasks, or test pipelines.

## Main Usage

Run the main script from an elevated PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\defender.ps1
```

For scheduled starts, the easiest path is usually [defender-single-run.ps1](./defender-single-run.ps1). It prompts for UAC immediately, then keeps the elevated PowerShell window open until the scheduled start time.

Recommended real-world server workflow:

```powershell
# Start this while the workload issue is actually happening.
Set-ExecutionPolicy -Scope Process Bypass
.\defender.ps1 -RecordingSeconds 300 -TopN 30 -ReportPath "C:\DefenderReports"
```

Scheduled overnight example:

```powershell
# Elevate now, then begin at the next 23:30 local time.
.\defender-single-run.ps1 -StartAtTime "23:30" -RecordingSeconds 300 -TopN 30 -OutputRoot "C:\DefenderRuns\Night"
```

Validation workflow:

```powershell
# Use this when validating the tool and proving contextual recommendation handling.
.\defender.ps1 -RecordingSeconds 180 -ValidateLoad -ValidateExclusions -SyntheticWorkloadMode NativeExe -TopN 100
```

Useful examples:

```powershell
.\defender.ps1 -RecordingSeconds 300 -TopN 30
.\defender.ps1 -ValidateLoad -ValidateExclusions -VerboseCAB
.\defender.ps1 -ValidateLoad -ValidateExclusions -SyntheticWorkloadMode PowerShell -TopN 100 -NoOpenReport
.\defender.ps1 -ValidateLoad -ValidateExclusions -SyntheticWorkloadMode NativeExe -TopN 100
.\defender.ps1 -RecordingSeconds 120 -ReportPath "C:\Reports"
.\defender.ps1 -StartAt "2026-04-03 23:30" -RecordingSeconds 300 -ReportPath "C:\Reports"
.\defender.ps1 -StartAtTime "23:30" -RecordingSeconds 300 -ReportPath "C:\Reports"
.\defender.ps1 -StrictCAB -RecordingSeconds 300 -ReportPath "C:\Reports"
.\defender.ps1 -RecordingSeconds 120 -AIMode
.\defender.ps1 -RecordingSeconds 180 -ValidateLoad -ValidateExclusions -NoOpenReport
.\defender-compare.ps1 -BaselineReport C:\Reports\RunA.json -CurrentReport C:\Reports\RunB.json -OutputPath C:\Reports\Compare
.\defender-offline-fixture-tests.ps1
```

Scheduling notes:

- Use `-StartAt` for a one-off future local date and time.
- Use `-StartAtTime` for the next daily occurrence of a local time such as `23:30`.
- If you use the self-elevating helper wrappers, UAC is prompted immediately and the elevated window waits until the scheduled start.
- For fully unattended overnight execution without leaving a PowerShell window open, use Windows Task Scheduler with the same script parameters.

Typical console flow:

```text
+==================================================================+
|  1 - Discovering Existing Exclusions                             |
+==================================================================+
  [OK]   Exclusions discovered via Get-MpPreference

+==================================================================+
|  5 - Recording Defender Performance                              |
+==================================================================+
  [info] Recording started for 180 seconds
  [info] Waiting for live workload activity

+==================================================================+
|  COMPLETE                                                       |
+==================================================================+
  [info] JSON report             : C:\Reports\DefenderPerf_20260403_171252.json
  [info] HTML report             : C:\Reports\DefenderPerf_20260403_171252.html
  [info] Transcript log          : C:\Reports\DefenderPerf_20260403_171252.transcript.log
```

## Main Script Options

### `defender.ps1`

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-RecordingSeconds` | `int` | `600` | Length of the Defender performance recording in seconds. Valid range: `10` to `900`. |
| `-TopN` | `int` | `25` | Number of top items to show in each impact category. Valid range: `5` to `100`. |
| `-ReportPath` | `string` | script directory | Directory where JSON, HTML, transcript, and related outputs are written. |
| `-StartAt` | `datetime` | immediate | Exact future local date and time for a one-off scheduled start. |
| `-StartAtTime` | `string` | immediate | Daily local time-of-day for the next occurrence, such as `23:30`. |
| `-StrictCAB` | `switch` | off | Forces the run to bind itself to one fresh `MpSupportFiles.cab` snapshot and stop if only stale CAB data is available. |
| `-ValidateLoad` | `switch` | off | Runs the synthetic workload during the recording so the tool has meaningful test data. |
| `-SyntheticWorkloadMode` | `string` | `Mixed` | Selects the synthetic workload type used with `-ValidateLoad`: `Mixed`, `PowerShell`, or `NativeExe`. Prefer `NativeExe` when you want to validate contextual recommendation logic. |
| `-ValidateExclusions` | `switch` | off | Creates a temporary exclusion, checks discovery methods, and verifies cleanup. |
| `-VerboseCAB` | `switch` | off | Includes fuller `MpSupportFiles.cab` diagnostic extraction and display. |
| `-NoOpenReport` | `switch` | off | Prevents the generated HTML report from opening automatically. |
| `-AIMode` | `switch` | off | Generates an AI export JSON and review prompt alongside the normal report outputs. |

Typical output files:

```text
DefenderPerf_20260403_171252.json
DefenderPerf_20260403_171252.html
DefenderPerf_20260403_171252.transcript.log
DefenderPerf_20260403_171252.ai-export.json
DefenderPerf_20260403_171252.ai-prompt.md
```

Example JSON fields:

```json
{
  "ReportMetadata": {
    "GeneratedAt": "2026-04-03 17:12:52",
    "RecordDuration": 180,
    "SyntheticWorkload": true,
    "ExclusionValidation": true
  },
  "ExclusionSuggestions": [],
  "SuppressedCandidates": [
    {
      "Type": "ValidationOnlyContextualPattern",
      "Value": ".json @ synthetic workload folders",
      "Commands": [
        "Add-MpPreference -ExclusionPath 'C:\\Users\\User\\AppData\\Local\\Temp\\DefenderWorkload_...\\cache\\restore\\*.json\\:{PathType:file,ScanTrigger:OnAccess,Process:\"C:\\Tools\\defender-workload-helper.exe\"}'"
      ],
      "Preference": "Tier 1 - Validation-only preferred contextual file-pattern recommendation",
      "Fallbacks": [
        "Tier 4 - Exact process fallback: Add-MpPreference -ExclusionProcess 'C:\\Tools\\defender-workload-helper.exe'"
      ]
    }
  ]
}
```

## Helper Script Options

### `defender-single-run.ps1`

Self-elevating wrapper around `defender.ps1` that launches one run, captures a UTF-8 log, and writes a `run_summary.json`.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-RecordingSeconds` | `int` | `120` | Recording duration passed to `defender.ps1`. |
| `-TopN` | `int` | `25` | Top item count passed to `defender.ps1`. |
| `-OutputRoot` | `string` | timestamped folder under script directory | Root folder for the run log, summary, and reports. |
| `-StartAt` | `datetime` | immediate | Exact future local date and time to pass into the main script. |
| `-StartAtTime` | `string` | immediate | Daily local time-of-day for the next scheduled run, such as `23:30`. |
| `-StrictCAB` | `switch` | off | Passes `-StrictCAB` through to the main script. |
| `-ValidateLoad` | `switch` | off | Enables synthetic workload during the run. |
| `-SyntheticWorkloadMode` | `string` | `Mixed` | Passes the synthetic workload profile through to `defender.ps1`. |
| `-ValidateExclusions` | `switch` | off | Enables structured exclusion validation during the run. |
| `-AIMode` | `switch` | off | Enables AI export and AI prompt generation. |
| `-NoOpenReport` | `switch` | off | Prevents the final HTML report from opening automatically. |

Example:

```powershell
.\defender-single-run.ps1 -RecordingSeconds 180 -ValidateLoad -ValidateExclusions -SyntheticWorkloadMode NativeExe -TopN 100
.\defender-single-run.ps1 -RecordingSeconds 180 -ValidateLoad -SyntheticWorkloadMode PowerShell -TopN 100 -NoOpenReport
.\defender-single-run.ps1 -StartAtTime "23:30" -RecordingSeconds 300 -TopN 30
```

Typical output:

```text
[2026-04-03 17:08:47] [START] Output root: C:\Runs\single_run_20260403_170847
[2026-04-03 17:08:47] [RUN] Launching defender.ps1 for 180s
[2026-04-03 17:12:53] [DONE] Summary written: C:\Runs\single_run_20260403_170847\run_summary.json
```

Example `run_summary.json`:

```json
{
  "RecordingSeconds": 180,
  "ValidateLoad": true,
  "SyntheticWorkloadMode": "NativeExe",
  "ValidateExclusions": true,
  "ExitCode": 0,
  "JsonReport": "C:\\Runs\\single_run_20260403_170847\\DefenderPerf_20260403_171252.json",
  "HtmlReport": "C:\\Runs\\single_run_20260403_170847\\DefenderPerf_20260403_171252.html"
}
```

### `defender-validation-loop.ps1`

Self-elevating loop harness that repeatedly calls `defender-test.ps1` and maintains a `loop_summary.json`.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-Iterations` | `int` | `2` | Number of validation cycles to run. Valid range: `1` to `20`. |
| `-RecordingSeconds` | `int` | `180` | Recording duration per cycle. |
| `-TopN` | `int` | `25` | Top item count per cycle. |
| `-WaitMinutes` | `int` | `15` | Delay between validation runs. Valid range: `0` to `240`. |
| `-OutputRoot` | `string` | timestamped loop folder | Folder where cycle subfolders and `loop_summary.json` are written. |
| `-StartAt` | `datetime` | immediate | Exact future local date and time for the first validation cycle. |
| `-StartAtTime` | `string` | immediate | Daily local time-of-day for the next first-cycle start. |
| `-StrictCAB` | `switch` | off | Passes `-StrictCAB` through to each validation cycle. |
| `-SyntheticWorkloadMode` | `string` | `Mixed` | Passes the synthetic workload profile through to each validation cycle. |
| `-StopOnFailure` | `switch` | off | Stops the loop after the first failed cycle. |

Example:

```powershell
.\defender-validation-loop.ps1 -Iterations 3 -RecordingSeconds 180 -WaitMinutes 3
.\defender-validation-loop.ps1 -Iterations 1 -RecordingSeconds 180 -TopN 100 -SyntheticWorkloadMode PowerShell -WaitMinutes 0
.\defender-validation-loop.ps1 -Iterations 1 -RecordingSeconds 180 -TopN 100 -SyntheticWorkloadMode NativeExe -WaitMinutes 0
.\defender-validation-loop.ps1 -StartAtTime "23:30" -Iterations 2 -RecordingSeconds 180 -WaitMinutes 3
```

Typical output:

```text
[2026-04-03 13:47:20] [START] Running 3 cycle(s) with a 3 minute pause between runs.
[2026-04-03 13:47:20] [CYCLE] Starting cycle 1 of 3
[2026-04-03 13:55:10] [CYCLE] Starting cycle 2 of 3
[2026-04-03 14:03:02] [CYCLE] Starting cycle 3 of 3
```

Example output structure:

```text
validation_loop_20260403_134720\
  loop_summary.json
  cycle_01_20260403_134723\
  cycle_02_20260403_135110\
  cycle_03_20260403_135502\
```

### `defender-test.ps1`

Automated harness that runs `defender.ps1` with validation flags enabled, then checks the generated outputs and JSON structure.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-RecordingSeconds` | `int` | `20` | Recording duration for the test run. |
| `-TopN` | `int` | `15` | Top item count for the test run. |
| `-OutputRoot` | `string` | script directory | Root folder for test logs, reports, and validation result JSON. |
| `-StartAt` | `datetime` | immediate | Exact future local date and time to pass into the main script. |
| `-StartAtTime` | `string` | immediate | Daily local time-of-day for the next scheduled validation run. |
| `-StrictCAB` | `switch` | off | Runs the validation harness against strict fresh-CAB enforcement. |
| `-SyntheticWorkloadMode` | `string` | `Mixed` | Selects the synthetic workload profile to pass into `defender.ps1`. |
| `-AIMode` | `switch` | off | Enables AI export generation during the test run. |
| `-NoAutoClose` | `switch` | off | Keeps the harness window open at the end. |
| `-NoOpenReport` | `switch` | off | Prevents the generated HTML report from opening. |

Example:

```powershell
.\defender-test.ps1 -RecordingSeconds 180 -TopN 25 -OutputRoot C:\DefenderTestRuns -NoOpenReport
.\defender-test.ps1 -RecordingSeconds 180 -TopN 100 -SyntheticWorkloadMode PowerShell -OutputRoot C:\DefenderTestRuns -NoOpenReport
.\defender-test.ps1 -RecordingSeconds 180 -TopN 100 -SyntheticWorkloadMode NativeExe -OutputRoot C:\DefenderTestRuns -NoOpenReport
.\defender-test.ps1 -StartAtTime "23:30" -RecordingSeconds 180 -TopN 25 -NoOpenReport
```

Typical output:

```text
================================================================
  DEFENDER PERFORMANCE TEST HARNESS
================================================================
  [+] Script execution -- Completed in 246.1s
  [+] JSON report valid -- 180.4 KB
  [+] HTML report created -- 46.8 KB
  [+] Structured exclusion validation details
```

Typical generated files:

```text
test_run_20260403_171252.log
test_result_20260403_171252.json
test_reports_20260403_171252\
```

### `defender-workload.ps1`

Synthetic workload generator used to create build, cache, archive, and log churn while Defender recording is active.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-DurationSeconds` | `int` | `30` | Length of the synthetic workload run. |
| `-WorkDir` | `string` | temp folder under `%TEMP%` | Root temporary directory for generated workload files. |
| `-Mode` | `string` | `Mixed` | Chooses the synthetic workload profile: `Mixed`, `PowerShell`, or `NativeExe`. |

Example:

```powershell
.\defender-workload.ps1 -DurationSeconds 180
.\defender-workload.ps1 -DurationSeconds 180 -Mode PowerShell
.\defender-workload.ps1 -DurationSeconds 180 -Mode NativeExe
```

Typical output:

```text
[workload] Started - generating Defender scan activity for 180s
[workload] WorkDir: C:\Users\<User>\AppData\Local\Temp\DefenderWorkload_20260403_170947
[workload] Phase 1: Create hot build/cache/log files
[workload] Phase 2: Re-open, append, and mirror hot files
[workload] Phase 3: Child processes writing build/cache outputs
```

### `extract_cab.ps1`

Standalone helper for extracting and inventorying `MpSupportFiles.cab`.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-CabPath` | `string` | `C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab` | CAB file to extract. |
| `-LogPath` | `string` | `cab_contents.log` in script directory | Output log file for the extraction report. |

Example:

```powershell
.\extract_cab.ps1
.\extract_cab.ps1 -LogPath C:\Temp\cab_contents.log
```

Typical output:

```text
=== MpSupportFiles.cab Extraction Report ===
Date: 04/03/2026 17:09:18
CAB Path: C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab
--- Extracting to: C:\Users\<User>\AppData\Local\Temp\MpSupportFiles_Extract_20260403_170918 ---
Extraction complete.
Log saved to: C:\Temp\cab_contents.log
```

### `defender-compare.ps1`

Compare mode for two saved `DefenderPerf_*.json` reports. It highlights changes in discovered exclusions, recommendation output, extension hotspots, scan contexts, and CAB-derived intelligence, then writes a JSON and HTML comparison report.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-BaselineReport` | `string` | required | Older or reference report JSON file. |
| `-CurrentReport` | `string` | required | Newer report JSON file to compare against the baseline. |
| `-OutputPath` | `string` | current report folder | Folder where compare JSON and HTML outputs are written. |
| `-NoOpenReport` | `switch` | off | Prevents the generated HTML compare report from opening automatically. |

Example:

```powershell
.\defender-compare.ps1 -BaselineReport C:\Reports\DefenderPerf_A.json -CurrentReport C:\Reports\DefenderPerf_B.json -OutputPath C:\Reports\Compare
```

Typical output:

```text
JSON compare report: C:\Reports\Compare\DefenderPerfCompare_20260403_201804.json
HTML compare report: C:\Reports\Compare\DefenderPerfCompare_20260403_201804.html
```

### `defender-offline-fixture-tests.ps1`

Runs the deterministic offline fixture suite. This validates CAB parsing, recommendation ranking, and compare mode without needing a live Defender trace, admin rights, or a fresh support CAB.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-OutputRoot` | `string` | timestamped folder under `tests\results` | Folder where the fixture result JSON and compare-mode outputs are written. |

Example:

```powershell
.\defender-offline-fixture-tests.ps1
.\defender-offline-fixture-tests.ps1 -OutputRoot C:\Temp\DefenderOfflineTests
```

## Outputs

The main script produces some or all of the following files in the report folder:

- `DefenderPerf_<timestamp>.json`
- `DefenderPerf_<timestamp>.html`
- `DefenderPerf_<timestamp>.transcript.log`
- `DefenderPerf_<timestamp>.ai-export.json`
- `DefenderPerf_<timestamp>.ai-prompt.md`

The helper wrappers can also produce:

- `single_run_<timestamp>.log`
- `run_summary.json`
- `test_run_<timestamp>.log`
- `test_result_<timestamp>.json`
- `loop_summary.json`
- `DefenderPerfCompare_<timestamp>.json`
- `DefenderPerfCompare_<timestamp>.html`
- `tests\results\offline_<timestamp>\offline_fixture_test_result.json`

Example output folder layout:

```text
powershell-work\
  defender.ps1
  defender-test.ps1
  single_run_ai_mode_20260403_163700\
    DefenderPerf_20260403_163709.json
    DefenderPerf_20260403_163709.html
    DefenderPerf_20260403_163709.ai-export.json
    DefenderPerf_20260403_163709.ai-prompt.md
    run_summary.json
```

## Report Content

Depending on the run mode and available diagnostics, the generated report can include:

- current exclusion discovery results
- exclusion validation results
- Defender performance impact tables
- top scan contexts
- extension hotspots by folder and process
- live exclusion suggestions
- suppressed validation-only candidates
- effective configuration and product health
- network protection details
- device control state
- MPLog highlights
- scan skip analysis
- Security Center product registrations

## Notes On Recommendations

- Prefer capturing real workload evidence before considering exclusions.
- On servers, use the tool to justify avoiding exclusions unless there is a strong, narrow, defensible recommendation.
- Review every suggested exclusion before applying it.
- Prefer exact path or file-pattern scoping over broader exclusions.
- Avoid excluding system directories, scripting engines, or executable file types.
- Treat synthetic workload results as validation data, not production recommendations.
- Protect excluded folders with restrictive NTFS ACLs.

## Review Subagents

Reusable review briefs live in [subagents](./subagents/README.md).

They provide a structured improvement workflow for:

- code audit
- latest-guidance validation
- documentation validation
- testing and validation review
- next-step idea generation

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
