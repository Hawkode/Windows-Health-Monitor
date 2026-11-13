function Unregister-HealthMonitorTask {
    <#
    .SYNOPSIS
    Removes the scheduled task. Output files are kept.

    .PARAMETER TaskName
    Scheduled task name.

    .PARAMETER RemoveEventSource
    Also delete the WindowsHealthMonitor Application event log source.

    .EXAMPLE
    Unregister-HealthMonitorTask -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidatePattern('^[A-Za-z0-9 ._-]+$')][string]$TaskName = 'WindowsHealthMonitor',
        [switch]$RemoveEventSource
    )

    if (-not (Test-WhmElevated)) { throw 'Unregister-HealthMonitorTask must run from an elevated session.' }

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        Write-Warning "Scheduled task '$TaskName' not found."
    }
    elseif ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    if ($RemoveEventSource -and (Test-WhmEventSource -Source $script:WhmEventSource)) {
        if ($PSCmdlet.ShouldProcess($script:WhmEventSource, 'Delete event log source')) {
            [System.Diagnostics.EventLog]::DeleteEventSource($script:WhmEventSource)
        }
    }
}
