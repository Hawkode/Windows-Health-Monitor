@{
    RootModule           = 'WindowsHealthMonitor.psm1'
    ModuleVersion        = '2.0.0'
    GUID                 = 'dd8b0068-d7f8-4904-bb6f-075d57cf421c'
    Author               = 'Alex Mateescu'
    CompanyName          = 'Hawkode'
    Copyright            = '(c) 2026 Hawkode. MIT License.'
    Description          = 'Windows endpoint health and security posture checks: resources, Defender, firewall, patch age, pending reboot, BitLocker and event log clearing. Writes JSONL, CSV and Application event log entries for a SIEM.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
        'Get-HealthSnapshot'
        'Test-HealthSnapshot'
        'Get-HealthThreshold'
        'Start-HealthMonitor'
        'Register-HealthMonitorTask'
        'Unregister-HealthMonitorTask'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('Windows', 'Monitoring', 'Security', 'Defender', 'Firewall', 'BitLocker', 'SIEM')
            LicenseUri   = 'https://github.com/Hawkode/Windows-Health-Monitor/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/Hawkode/Windows-Health-Monitor'
            ReleaseNotes = 'https://github.com/Hawkode/Windows-Health-Monitor/blob/main/CHANGELOG.md'
        }
    }
}
