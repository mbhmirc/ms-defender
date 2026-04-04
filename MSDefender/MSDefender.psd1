@{
    RootModule        = 'MSDefender.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '7d7b8e47-d5d0-4fa8-a7cb-dcd0e6d2c52b'
    Author            = 'MS Defender contributors'
    CompanyName       = 'Open source'
    Copyright         = '(c) 2026 MS Defender contributors. Released under the MIT License.'
    Description       = 'Windows Defender performance analysis, exclusion discovery, recommendation ranking, report comparison, and validation tooling.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Invoke-MsDefenderPerformanceAudit',
        'Invoke-MsDefenderSingleRun',
        'Invoke-MsDefenderValidationLoop',
        'Invoke-MsDefenderSyntheticWorkload',
        'Test-MsDefenderPerformanceAudit',
        'Compare-MsDefenderPerformanceReport',
        'Test-MsDefenderOfflineFixtures',
        'Get-MsDefenderRecommendationResult',
        'Get-MsDefenderCabIntelligence'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('Defender', 'WindowsDefender', 'Antivirus', 'Performance', 'Exclusions', 'Troubleshooting')
            ProjectUri = 'https://github.com/mbhmirc/ms-defender'
            LicenseUri = 'https://github.com/mbhmirc/ms-defender/blob/main/LICENSE'
        }
    }
}
