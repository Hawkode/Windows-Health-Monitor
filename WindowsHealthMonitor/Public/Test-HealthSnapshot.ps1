function Test-HealthSnapshot {
    <#
    .SYNOPSIS
    Judges a snapshot against thresholds and returns one finding per check.

    .DESCRIPTION
    Pure logic, no system calls, so it runs on any platform and against saved
    snapshots (for example a line from a JSONL file passed through
    ConvertFrom-Json).

    Each finding has Check, Target, Status (OK, Warning, Critical, Unknown),
    Value, EventId and Message. A check whose collector failed is Unknown,
    never OK.

    .PARAMETER Snapshot
    Output of Get-HealthSnapshot, or the Snapshot property of a saved record.

    .PARAMETER Threshold
    Hashtable from Get-HealthThreshold. Defaults to the module defaults.

    .EXAMPLE
    Get-HealthSnapshot | Test-HealthSnapshot | Where-Object Status -ne 'OK'

    .EXAMPLE
    Get-Content .\health-20261113.jsonl | ConvertFrom-Json | ForEach-Object { Test-HealthSnapshot -Snapshot $_.Snapshot }
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][psobject]$Snapshot,
        [hashtable]$Threshold
    )

    begin {
        if (-not $PSBoundParameters.ContainsKey('Threshold')) {
            $Threshold = Get-HealthThreshold
        }
    }

    process {
        $t = $Threshold
        $findings = New-Object -TypeName 'System.Collections.Generic.List[object]'

        # 1. CPU
        if ($null -eq $Snapshot.Cpu) {
            Add-WhmFinding -List $findings -Check 'Cpu' -Status 'Unknown' -Message (Get-WhmCollectorMessage -Snapshot $Snapshot -Collector 'Cpu')
        }
        else {
            $v = [double]$Snapshot.Cpu.Percent
            $s = Get-WhmBand -Value $v -Warning $t.CpuPercent.Warning -Critical $t.CpuPercent.Critical
            Add-WhmFinding -List $findings -Check 'Cpu' -Status $s -Value $v -Message "CPU load $v% (1-second sample; one high reading is not a trend)."
        }

        # 2. Memory
        if ($null -eq $Snapshot.Memory) {
            Add-WhmFinding -List $findings -Check 'Memory' -Status 'Unknown' -Message (Get-WhmCollectorMessage -Snapshot $Snapshot -Collector 'Memory')
        }
        else {
            $v = [double]$Snapshot.Memory.UsedPercent
            $s = Get-WhmBand -Value $v -Warning $t.MemoryUsedPercent.Warning -Critical $t.MemoryUsedPercent.Critical
            Add-WhmFinding -List $findings -Check 'Memory' -Status $s -Value $v -Message "Memory $v% used ($($Snapshot.Memory.FreeGB) GB free of $($Snapshot.Memory.TotalGB) GB)."
        }

        # 3. Disks, one finding per fixed volume
        $disks = @()
        if ($null -ne $Snapshot.Disks) { $disks = @($Snapshot.Disks | Where-Object { $null -ne $_ }) }
        if ($disks.Count -eq 0) {
            Add-WhmFinding -List $findings -Check 'Disk' -Status 'Unknown' -Message (Get-WhmCollectorMessage -Snapshot $Snapshot -Collector 'Disks')
        }
        else {
            foreach ($d in $disks) {
                $v = [double]$d.FreePercent
                $s = Get-WhmBand -Value $v -Warning $t.DiskFreePercent.Warning -Critical $t.DiskFreePercent.Critical -LowerIsWorse
                Add-WhmFinding -List $findings -Check 'Disk' -Target ([string]$d.Drive) -Status $s -Value $v -Message "$($d.Drive) $v% free ($($d.FreeGB) GB of $($d.SizeGB) GB)."
            }
        }

        # 4. Uptime
        if ($null -eq $Snapshot.Uptime) {
            Add-WhmFinding -List $findings -Check 'Uptime' -Status 'Unknown' -Message (Get-WhmCollectorMessage -Snapshot $Snapshot -Collector 'Uptime')
        }
        else {
            $v = [double]$Snapshot.Uptime.Days
            $s = Get-WhmBand -Value $v -Warning $t.UptimeDays.Warning -Critical $t.UptimeDays.Critical
            $msg = "Up $v days since $($Snapshot.Uptime.LastBootUtc)."
            if ($s -ne 'OK') { $msg += ' Updates that need a restart are not applied until it reboots.' }
            Add-WhmFinding -List $findings -Check 'Uptime' -Status $s -Value $v -Message $msg
        }

        # 5. Network
        if ($null -eq $Snapshot.Network) {
            Add-WhmFinding -List $findings -Check 'Network' -Status 'Unknown' -Message (Get-WhmCollectorMessage -Snapshot $Snapshot -Collector 'Network')
        }
        else {
            $v = [int]$Snapshot.Network.PhysicalUp
            if ($v -gt 0) {
                $names = @($Snapshot.Network.Adapters) -join ', '
                Add-WhmFinding -List $findings -Check 'Network' -Status 'OK' -Value $v -Message "$v physical adapter(s) up: $names."
            }
            else {
                Add-WhmFinding -List $findings -Check 'Network' -Status 'Warning' -Value $v -Message 'No physical network adapter is up.'
            }
        }

        # 6 and 7. Defender
        $def = $Snapshot.Defender
        if ($null -eq $def) {
            $why = Get-WhmCollectorMessage -Snapshot $Snapshot -Collector 'Defender'
            Add-WhmFinding -List $findings -Check 'DefenderRealTime' -Status 'Unknown' -Message $why
            Add-WhmFinding -List $findings -Check 'DefenderSignature' -Status 'Unknown' -Message $why
        }
        else {
            $mode = [string]$def.RunningMode
            if (-not $t.RequireDefenderRealTime) {
                Add-WhmFinding -List $findings -Check 'DefenderRealTime' -Status 'OK' -Value ([bool]$def.RealTimeProtectionEnabled) -Message "Not required by threshold config (mode: $mode). Check the primary AV/EDR in its own console."
                Add-WhmFinding -List $findings -Check 'DefenderSignature' -Status 'OK' -Value ([int]$def.SignatureAgeDays) -Message 'Not required by threshold config.'
            }
            else {
                if (-not $def.RealTimeProtectionEnabled) {
                    Add-WhmFinding -List $findings -Check 'DefenderRealTime' -Status 'Critical' -Value $false -Message "Defender real-time protection is OFF (mode: $mode). Check Defender Operational log EID 5001 and 5007 for when and how."
                }
                elseif ($t.RequireTamperProtection -and -not $def.TamperProtected) {
                    Add-WhmFinding -List $findings -Check 'DefenderRealTime' -Status 'Warning' -Value $true -Message "Real-time protection is on but Tamper Protection is off, so a local admin can disable it with Set-MpPreference (mode: $mode)."
                }
                else {
                    Add-WhmFinding -List $findings -Check 'DefenderRealTime' -Status 'OK' -Value $true -Message "Real-time protection on, Tamper Protection $([bool]$def.TamperProtected) (mode: $mode)."
                }

                $v = [int]$def.SignatureAgeDays
                $s = Get-WhmBand -Value $v -Warning $t.DefenderSignatureAgeDays.Warning -Critical $t.DefenderSignatureAgeDays.Critical
                Add-WhmFinding -List $findings -Check 'DefenderSignature' -Status $s -Value $v -Message "Antivirus signatures are $v day(s) old."
            }
        }

        # 8. Firewall
        $fw = @()
        if ($null -ne $Snapshot.Firewall) { $fw = @($Snapshot.Firewall | Where-Object { $null -ne $_ }) }
        if ($fw.Count -eq 0) {
            Add-WhmFinding -List $findings -Check 'Firewall' -Status 'Unknown' -Message (Get-WhmCollectorMessage -Snapshot $Snapshot -Collector 'Firewall')
        }
        else {
            $off = @($fw | Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Profile })
            if ($off.Count -eq 0) {
                Add-WhmFinding -List $findings -Check 'Firewall' -Status 'OK' -Value $true -Message 'All firewall profiles enabled (effective policy).'
            }
            else {
                $s = 'Warning'
                if ($t.RequireAllFirewallProfiles) { $s = 'Critical' }
                Add-WhmFinding -List $findings -Check 'Firewall' -Status $s -Value $false -Message "Firewall profile(s) OFF: $($off -join ', '). Security log EID 4950 records the change if MPSSVC policy change auditing is on."
            }
        }

        # 9. Pending reboot
        if ($null -eq $Snapshot.PendingReboot) {
            Add-WhmFinding -List $findings -Check 'PendingReboot' -Status 'Unknown' -Message (Get-WhmCollectorMessage -Snapshot $Snapshot -Collector 'PendingReboot')
        }
        else {
            $reasons = @($Snapshot.PendingReboot.Reasons | Where-Object {
                    $null -ne $_ -and -not ($t.IgnorePendingFileRename -and [string]$_ -eq 'PendingFileRename')
                })
            if ($reasons.Count -gt 0) {
                Add-WhmFinding -List $findings -Check 'PendingReboot' -Status 'Warning' -Value $true -Message "Reboot pending: $($reasons -join ', ')."
            }
            else {
                Add-WhmFinding -List $findings -Check 'PendingReboot' -Status 'OK' -Value $false -Message 'No reboot pending.'
            }
        }

        # 10. Patch age
        if ($null -eq $Snapshot.Patch) {
            Add-WhmFinding -List $findings -Check 'PatchAge' -Status 'Unknown' -Message (Get-WhmCollectorMessage -Snapshot $Snapshot -Collector 'Patch')
        }
        else {
            $v = [int]$Snapshot.Patch.DaysSinceLastPatch
            $s = Get-WhmBand -Value $v -Warning $t.PatchAgeDays.Warning -Critical $t.PatchAgeDays.Critical
            Add-WhmFinding -List $findings -Check 'PatchAge' -Status $s -Value $v -Message "Last update $($Snapshot.Patch.LatestHotFixId) installed $v day(s) ago."
        }

        # 11. Event log clearing
        if ($null -eq $Snapshot.LogClear) {
            Add-WhmFinding -List $findings -Check 'LogCleared' -Status 'Unknown' -Message (Get-WhmCollectorMessage -Snapshot $Snapshot -Collector 'LogClear')
        }
        else {
            $sec = [int]$Snapshot.LogClear.SecurityLogCleared
            $other = [int]$Snapshot.LogClear.OtherLogCleared
            $hours = [int]$Snapshot.LogClear.LookbackHours
            $v = $sec + $other
            if ($v -gt 0) {
                Add-WhmFinding -List $findings -Check 'LogCleared' -Status 'Critical' -Value $v -Message "Event logs cleared in the last $hours h: Security $sec (EID 1102), other $other (EID 104). Treat as possible anti-forensics until explained."
            }
            else {
                Add-WhmFinding -List $findings -Check 'LogCleared' -Status 'OK' -Value 0 -Message "No event log clearing in the last $hours h."
            }
        }

        # 12. BitLocker
        if (-not $t.RequireBitLocker) {
            Add-WhmFinding -List $findings -Check 'BitLocker' -Status 'OK' -Value (Get-WhmValue -InputObject $Snapshot.BitLocker -Name 'ProtectionOn') -Message 'Not required by threshold config.'
        }
        elseif ($null -eq $Snapshot.BitLocker) {
            Add-WhmFinding -List $findings -Check 'BitLocker' -Status 'Unknown' -Message (Get-WhmCollectorMessage -Snapshot $Snapshot -Collector 'BitLocker')
        }
        elseif ($Snapshot.BitLocker.ProtectionOn) {
            Add-WhmFinding -List $findings -Check 'BitLocker' -Status 'OK' -Value $true -Message "BitLocker protection on for $($Snapshot.BitLocker.Drive)."
        }
        else {
            Add-WhmFinding -List $findings -Check 'BitLocker' -Status 'Critical' -Value $false -Message "BitLocker protection OFF for $($Snapshot.BitLocker.Drive) (off, or suspended for an update)."
        }

        $findings
    }
}
