function Get-HealthThreshold {
    <#
    .SYNOPSIS
    Returns the threshold set used to judge a health snapshot.

    .DESCRIPTION
    Loads Config\DefaultThresholds.psd1 from the module. With -Path, merges an
    override file on top: keys in the override win, nested keys merge one by
    one, and unknown keys throw so a typo cannot silently disable a check.

    .PARAMETER Path
    Optional .psd1 override file, for example C:\ProgramData\WindowsHealthMonitor\thresholds.psd1.

    .EXAMPLE
    Get-HealthThreshold

    .EXAMPLE
    Get-HealthThreshold -Path .\thresholds.local.psd1
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([string]$Path)

    $configDir = Join-Path -Path $script:WhmModuleRoot -ChildPath 'Config'
    $defaults = Import-PowerShellDataFile -Path (Join-Path -Path $configDir -ChildPath 'DefaultThresholds.psd1')
    if (-not $Path) { return $defaults }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Threshold file not found: $Path"
    }
    $override = Import-PowerShellDataFile -Path $Path
    Merge-WhmHashtable -Base $defaults -Override $override
}
