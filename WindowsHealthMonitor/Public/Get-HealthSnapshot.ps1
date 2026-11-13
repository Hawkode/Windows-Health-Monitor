function Get-HealthSnapshot {
    <#
    .SYNOPSIS
    Collects one point-in-time health and security posture snapshot.

    .DESCRIPTION
    Read-only. Collects CPU, memory, fixed disks, uptime, physical network
    links, top processes, Defender status, effective firewall profiles,
    pending reboot, last patch date, event log clearing and BitLocker status.

    Each collector runs independently. If one fails (missing module, access
    denied, not elevated), its section is $null and the reason is recorded in
    CollectorErrors. Test-HealthSnapshot reports those checks as Unknown.

    The Security log and BitLocker checks need an elevated session.

    .PARAMETER TopProcessCount
    How many processes to list, by working set. 0 skips the list.

    .PARAMETER LogClearLookbackHours
    Window for the event log clearing check (EID 1102 and 104).

    .EXAMPLE
    Get-HealthSnapshot | Test-HealthSnapshot | Format-Table Check, Target, Status, Message -AutoSize
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateRange(0, 50)][int]$TopProcessCount = 5,
        [ValidateRange(1, 720)][int]$LogClearLookbackHours = 24
    )

    if (-not (Test-WhmWindowsHost)) { throw 'Get-HealthSnapshot runs on Windows only.' }

    $collectorErrors = New-Object -TypeName 'System.Collections.Generic.List[object]'

    $cpu = Invoke-WhmCollector -Name 'Cpu' -ErrorList $collectorErrors -ScriptBlock { Get-WhmCpu }
    $memory = Invoke-WhmCollector -Name 'Memory' -ErrorList $collectorErrors -ScriptBlock { Get-WhmMemory }
    $disks = Invoke-WhmCollector -Name 'Disks' -ErrorList $collectorErrors -ScriptBlock { Get-WhmDisk }
    $uptime = Invoke-WhmCollector -Name 'Uptime' -ErrorList $collectorErrors -ScriptBlock { Get-WhmUptime }
    $network = Invoke-WhmCollector -Name 'Network' -ErrorList $collectorErrors -ScriptBlock { Get-WhmNetwork }
    $defender = Invoke-WhmCollector -Name 'Defender' -ErrorList $collectorErrors -ScriptBlock { Get-WhmDefender }
    $firewall = Invoke-WhmCollector -Name 'Firewall' -ErrorList $collectorErrors -ScriptBlock { Get-WhmFirewall }
    $pendingReboot = Invoke-WhmCollector -Name 'PendingReboot' -ErrorList $collectorErrors -ScriptBlock { Get-WhmPendingReboot }
    $patch = Invoke-WhmCollector -Name 'Patch' -ErrorList $collectorErrors -ScriptBlock { Get-WhmPatch }
    $logClear = Invoke-WhmCollector -Name 'LogClear' -ErrorList $collectorErrors -ScriptBlock { param($Hours) Get-WhmLogClear -LookbackHours $Hours } -ArgumentList $LogClearLookbackHours
    $bitLocker = Invoke-WhmCollector -Name 'BitLocker' -ErrorList $collectorErrors -ScriptBlock { Get-WhmBitLocker }

    $topProcesses = @()
    if ($TopProcessCount -gt 0) {
        $topProcesses = Invoke-WhmCollector -Name 'TopProcesses' -ErrorList $collectorErrors -ScriptBlock { param($N) Get-WhmTopProcess -Count $N } -ArgumentList $TopProcessCount
    }

    # Collectors that emit several objects come back unrolled. Force arrays,
    # but keep $null as $null so "failed" stays distinguishable from "none".
    if ($null -ne $disks) { $disks = @($disks) }
    if ($null -ne $firewall) { $firewall = @($firewall) }
    if ($null -ne $topProcesses) { $topProcesses = @($topProcesses) }

    $timestampUtc = ConvertTo-WhmIsoTime -Value (Get-Date)
    $isElevated = [bool](Test-WhmElevated)
    # ToArray(), not @($collectorErrors): @() over this generic List threw
    # "Argument types do not match" in CI on both 5.1 and 7.
    $errorsOut = $collectorErrors.ToArray()

    [pscustomobject]@{
        SchemaVersion   = 1
        TimestampUtc    = $timestampUtc
        ComputerName    = $env:COMPUTERNAME
        IsElevated      = $isElevated
        Cpu             = $cpu
        Memory          = $memory
        Disks           = $disks
        Uptime          = $uptime
        Network         = $network
        TopProcesses    = $topProcesses
        Defender        = $defender
        Firewall        = $firewall
        PendingReboot   = $pendingReboot
        Patch           = $patch
        LogClear        = $logClear
        BitLocker       = $bitLocker
        CollectorErrors = $errorsOut
    }
}
