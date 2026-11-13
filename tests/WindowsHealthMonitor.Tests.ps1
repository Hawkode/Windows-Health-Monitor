#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeDiscovery {
    $script:onWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    $script:elevated = $false
    if ($script:onWindows) {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $identity
        $script:elevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

BeforeAll {
    $script:repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $script:manifestPath = Join-Path -Path (Join-Path -Path $script:repoRoot -ChildPath 'WindowsHealthMonitor') -ChildPath 'WindowsHealthMonitor.psd1'
    Import-Module -Name $script:manifestPath -Force

    $fixtureDir = Join-Path -Path $PSScriptRoot -ChildPath 'fixtures'
    $script:healthy = Get-Content -Raw -LiteralPath (Join-Path -Path $fixtureDir -ChildPath 'snapshot-healthy.json') | ConvertFrom-Json
    $script:degraded = Get-Content -Raw -LiteralPath (Join-Path -Path $fixtureDir -ChildPath 'snapshot-degraded.json') | ConvertFrom-Json
    $script:failures = Get-Content -Raw -LiteralPath (Join-Path -Path $fixtureDir -ChildPath 'snapshot-collector-failures.json') | ConvertFrom-Json
    $script:fixtureDir = $fixtureDir
}

AfterAll {
    Remove-Module -Name WindowsHealthMonitor -Force -ErrorAction SilentlyContinue
}

Describe 'Module' {
    It 'exports exactly the six public functions' {
        $exported = @((Get-Module -Name WindowsHealthMonitor).ExportedFunctions.Keys | Sort-Object) -join ','
        $exported | Should -Be 'Get-HealthSnapshot,Get-HealthThreshold,Register-HealthMonitorTask,Start-HealthMonitor,Test-HealthSnapshot,Unregister-HealthMonitorTask'
    }

    It 'has a valid manifest' {
        { Test-ModuleManifest -Path $script:manifestPath -ErrorAction Stop } | Should -Not -Throw
    }
}

Describe 'Get-HealthThreshold' {
    It 'loads the defaults' {
        $t = Get-HealthThreshold
        $t.CpuPercent.Warning | Should -Be 85
        $t.DiskFreePercent.Critical | Should -Be 5
        $t.RequireDefenderRealTime | Should -BeTrue
    }

    It 'merges an override file key by key' {
        $path = Join-Path -Path $TestDrive -ChildPath 'override.psd1'
        Set-Content -LiteralPath $path -Value "@{ CpuPercent = @{ Warning = 70 }; RequireBitLocker = `$false }"
        $t = Get-HealthThreshold -Path $path
        $t.CpuPercent.Warning | Should -Be 70
        $t.CpuPercent.Critical | Should -Be 95
        $t.RequireBitLocker | Should -BeFalse
        $t.RetentionDays | Should -Be 14
    }

    It 'rejects an unknown top-level key' {
        $path = Join-Path -Path $TestDrive -ChildPath 'typo.psd1'
        Set-Content -LiteralPath $path -Value '@{ CpuPercnt = @{ Warning = 70 } }'
        { Get-HealthThreshold -Path $path } | Should -Throw "*Unknown threshold key 'CpuPercnt'*"
    }

    It 'rejects an unknown nested key' {
        $path = Join-Path -Path $TestDrive -ChildPath 'nested.psd1'
        Set-Content -LiteralPath $path -Value '@{ CpuPercent = @{ Warnng = 70 } }'
        { Get-HealthThreshold -Path $path } | Should -Throw "*Unknown threshold key 'CpuPercent.Warnng'*"
    }

    It 'throws when the file is missing' {
        { Get-HealthThreshold -Path (Join-Path -Path $TestDrive -ChildPath 'missing.psd1') } | Should -Throw '*not found*'
    }
}

Describe 'Test-HealthSnapshot' {
    Context 'healthy host' {
        BeforeAll {
            $script:result = @(Test-HealthSnapshot -Snapshot $script:healthy)
        }

        It 'returns one finding per check plus one per extra disk' {
            $script:result.Count | Should -Be 13
        }

        It 'reports every check OK' {
            @($script:result | Where-Object { $_.Status -ne 'OK' }) | Should -BeNullOrEmpty
        }

        It 'uses 1000-range event IDs for OK' {
            ($script:result | Where-Object { $_.Check -eq 'Firewall' }).EventId | Should -Be 1008
        }
    }

    Context 'degraded host' {
        BeforeAll {
            $script:result = @(Test-HealthSnapshot -Snapshot $script:degraded)
            $script:byCheck = @{}
            foreach ($f in $script:result) { $script:byCheck["$($f.Check)|$($f.Target)"] = $f }
        }

        It 'flags <Key> as <Status> with event ID <EventId>' -ForEach @(
            @{ Key = 'Cpu|'; Status = 'OK'; EventId = 1001 }
            @{ Key = 'Memory|'; Status = 'Warning'; EventId = 2002 }
            @{ Key = 'Disk|C:'; Status = 'Critical'; EventId = 3003 }
            @{ Key = 'Disk|D:'; Status = 'Warning'; EventId = 2003 }
            @{ Key = 'Uptime|'; Status = 'Warning'; EventId = 2004 }
            @{ Key = 'Network|'; Status = 'OK'; EventId = 1005 }
            @{ Key = 'DefenderRealTime|'; Status = 'Critical'; EventId = 3006 }
            @{ Key = 'DefenderSignature|'; Status = 'Critical'; EventId = 3007 }
            @{ Key = 'Firewall|'; Status = 'Critical'; EventId = 3008 }
            @{ Key = 'PendingReboot|'; Status = 'Warning'; EventId = 2009 }
            @{ Key = 'PatchAge|'; Status = 'Critical'; EventId = 3010 }
            @{ Key = 'LogCleared|'; Status = 'Critical'; EventId = 3011 }
            @{ Key = 'BitLocker|'; Status = 'Critical'; EventId = 3012 }
        ) {
            $script:byCheck[$Key].Status | Should -Be $Status
            $script:byCheck[$Key].EventId | Should -Be $EventId
        }

        It 'names the disabled firewall profile' {
            $script:byCheck['Firewall|'].Message | Should -BeLike '*Public*'
        }

        It 'ignores PendingFileRename but keeps WindowsUpdate as the reboot reason' {
            $script:byCheck['PendingReboot|'].Message | Should -BeLike '*WindowsUpdate*'
            $script:byCheck['PendingReboot|'].Message | Should -Not -BeLike '*PendingFileRename*'
        }
    }

    Context 'collectors that failed' {
        BeforeAll {
            $script:result = @(Test-HealthSnapshot -Snapshot $script:failures)
        }

        It 'reports <Check> as Unknown, never OK' -ForEach @(
            @{ Check = 'DefenderRealTime'; EventId = 4006 }
            @{ Check = 'DefenderSignature'; EventId = 4007 }
            @{ Check = 'LogCleared'; EventId = 4011 }
            @{ Check = 'BitLocker'; EventId = 4012 }
        ) {
            $f = $script:result | Where-Object { $_.Check -eq $Check }
            $f.Status | Should -Be 'Unknown'
            $f.EventId | Should -Be $EventId
        }

        It 'carries the collector error into the message' {
            ($script:result | Where-Object { $_.Check -eq 'LogCleared' }).Message | Should -BeLike '*requires an elevated session*'
        }

        It 'reports a missing section with no recorded error as Unknown' {
            $snap = $script:healthy | ConvertTo-Json -Depth 6 | ConvertFrom-Json
            $snap.Cpu = $null
            (@(Test-HealthSnapshot -Snapshot $snap) | Where-Object { $_.Check -eq 'Cpu' }).Status | Should -Be 'Unknown'
        }
    }

    Context 'threshold switches' {
        It 'accepts third-party AV when RequireDefenderRealTime is false' {
            $t = Get-HealthThreshold
            $t.RequireDefenderRealTime = $false
            $r = @(Test-HealthSnapshot -Snapshot $script:degraded -Threshold $t)
            ($r | Where-Object { $_.Check -eq 'DefenderRealTime' }).Status | Should -Be 'OK'
        }

        It 'warns when real-time protection is on but Tamper Protection is off' {
            $snap = $script:healthy | ConvertTo-Json -Depth 6 | ConvertFrom-Json
            $snap.Defender.TamperProtected = $false
            (@(Test-HealthSnapshot -Snapshot $snap) | Where-Object { $_.Check -eq 'DefenderRealTime' }).Status | Should -Be 'Warning'
        }

        It 'treats PendingFileRename alone as no reboot pending by default' {
            $snap = $script:healthy | ConvertTo-Json -Depth 6 | ConvertFrom-Json
            $snap.PendingReboot = [pscustomobject]@{ Pending = $true; Reasons = @('PendingFileRename') }
            (@(Test-HealthSnapshot -Snapshot $snap) | Where-Object { $_.Check -eq 'PendingReboot' }).Status | Should -Be 'OK'
        }
    }

    It 'accepts snapshots from the pipeline' {
        @($script:healthy, $script:degraded | Test-HealthSnapshot).Count | Should -Be 26
    }
}

Describe 'Private helpers' {
    It 'bands <Value> as <Expected> (higher is worse)' -ForEach @(
        @{ Value = 84.9; Expected = 'OK' }
        @{ Value = 85; Expected = 'Warning' }
        @{ Value = 95; Expected = 'Critical' }
    ) {
        InModuleScope WindowsHealthMonitor -Parameters @{ V = $Value; E = $Expected } {
            param($V, $E)
            Get-WhmBand -Value $V -Warning 85 -Critical 95 | Should -Be $E
        }
    }

    It 'bands <Value> as <Expected> (lower is worse)' -ForEach @(
        @{ Value = 15.1; Expected = 'OK' }
        @{ Value = 15; Expected = 'Warning' }
        @{ Value = 5; Expected = 'Critical' }
    ) {
        InModuleScope WindowsHealthMonitor -Parameters @{ V = $Value; E = $Expected } {
            param($V, $E)
            Get-WhmBand -Value $V -Warning 15 -Critical 5 -LowerIsWorse | Should -Be $E
        }
    }

    It 'ranks Unknown above OK and below Warning' {
        InModuleScope WindowsHealthMonitor {
            Get-WhmWorstSeverity -Finding @([pscustomobject]@{ Status = 'OK' }, [pscustomobject]@{ Status = 'Unknown' }) | Should -Be 'Unknown'
            Get-WhmWorstSeverity -Finding @([pscustomobject]@{ Status = 'Unknown' }, [pscustomobject]@{ Status = 'Warning' }) | Should -Be 'Warning'
        }
    }

    It 'flattens a degraded record into one CSV row' {
        InModuleScope WindowsHealthMonitor -Parameters @{ Snap = $script:degraded } {
            param($Snap)
            $findings = @(Test-HealthSnapshot -Snapshot $Snap)
            $row = ConvertTo-WhmCsvRow -Record ([pscustomobject]@{
                    Snapshot    = $Snap
                    Findings    = $findings
                    WorstStatus = Get-WhmWorstSeverity -Finding $findings
                })
            $row.WorstStatus | Should -Be 'Critical'
            $row.CriticalCount | Should -Be 7
            $row.WarningCount | Should -Be 4
            $row.LowestDiskFreePercent | Should -Be 3
            $row.FirewallAllOn | Should -BeFalse
            $row.LogClearedCount | Should -Be 1
        }
    }
}

Describe 'Windows host' -Skip:(-not $script:onWindows) {
    It 'collects a snapshot with every section present or explained' {
        $snap = Get-HealthSnapshot -TopProcessCount 3
        $snap.SchemaVersion | Should -Be 1
        $snap.ComputerName | Should -Be $env:COMPUTERNAME
        $snap.Memory.TotalGB | Should -BeGreaterThan 0.5
        foreach ($section in 'Cpu', 'Memory', 'Disks', 'Uptime', 'Network', 'Defender', 'Firewall', 'PendingReboot', 'Patch', 'LogClear', 'BitLocker') {
            if ($null -eq $snap.$section) {
                @($snap.CollectorErrors | Where-Object { $_.Collector -eq $section }).Count | Should -Be 1 -Because "$section is null, so its failure must be recorded"
            }
        }
    }

    It 'writes one JSONL line and one CSV row per run' {
        $out = Join-Path -Path $TestDrive -ChildPath 'out'
        Start-HealthMonitor -Count 1 -OutputPath $out
        $json = @(Get-ChildItem -LiteralPath $out -Filter 'health-*.jsonl')
        $csv = @(Get-ChildItem -LiteralPath $out -Filter 'health-*.csv')
        $json.Count | Should -Be 1
        $csv.Count | Should -Be 1
        $record = Get-Content -LiteralPath $json[0].FullName -TotalCount 1 | ConvertFrom-Json
        $record.Snapshot.ComputerName | Should -Be $env:COMPUTERNAME
        @($record.Findings).Count | Should -BeGreaterOrEqual 12
        @(Import-Csv -LiteralPath $csv[0].FullName).Count | Should -Be 1
    }

    It 'writes nothing with -WhatIf and returns the record instead' {
        $out = Join-Path -Path $TestDrive -ChildPath 'whatif'
        $record = Start-HealthMonitor -Count 1 -OutputPath $out -WhatIf
        Test-Path -LiteralPath $out | Should -BeFalse
        $record.WorstStatus | Should -BeIn @('OK', 'Unknown', 'Warning', 'Critical')
    }
}

Describe 'Windows host, elevated' -Skip:(-not $script:elevated) {
    It 'writes a heartbeat to the Application log' {
        $since = (Get-Date).AddSeconds(-5)
        Start-HealthMonitor -Count 1 -OutputPath (Join-Path -Path $TestDrive -ChildPath 'evt') -WriteEventLog
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'WindowsHealthMonitor'; Id = 1000; StartTime = $since } -ErrorAction SilentlyContinue)
        $events.Count | Should -BeGreaterOrEqual 1
    }

    It 'finds write access for BUILTIN\Users' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'acl'
        $null = New-Item -Path $dir -ItemType Directory -Force
        $null = & icacls.exe $dir /grant '*S-1-5-32-545:(OI)(CI)M'
        InModuleScope WindowsHealthMonitor -Parameters @{ Dir = $dir } {
            param($Dir)
            $hits = @(Get-WhmUntrustedWriteAccess -Path $Dir)
            @($hits | Where-Object { $_.Identity -like '*Users*' -and $_.Rights -like '*Modify*' }).Count | Should -BeGreaterOrEqual 1
        }
    }

    It 'refuses to register a SYSTEM task when Users can write to the module folder' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'module-weak'
        $null = New-Item -Path $dir -ItemType Directory -Force
        $null = & icacls.exe $dir /grant '*S-1-5-32-545:(OI)(CI)M'
        InModuleScope WindowsHealthMonitor -Parameters @{ Dir = $dir } {
            param($Dir)
            $saved = $script:WhmModuleRoot
            try {
                $script:WhmModuleRoot = $Dir
                { Register-HealthMonitorTask -WhatIf } | Should -Throw '*Refusing to register*'
            }
            finally {
                $script:WhmModuleRoot = $saved
            }
        }
    }

    It 'accepts an admin-only, admin-owned module folder (-WhatIf, nothing registered)' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'module-strong'
        $null = New-Item -Path $dir -ItemType Directory -Force
        # A child with an explicit Users grant, which Protect-WhmPath must remove.
        $child = Join-Path -Path $dir -ChildPath 'Private'
        $null = New-Item -Path $child -ItemType Directory -Force
        $null = & icacls.exe $child /grant '*S-1-5-32-545:(OI)(CI)M'
        InModuleScope WindowsHealthMonitor -Parameters @{ Dir = $dir } {
            param($Dir)
            Protect-WhmPath -Path $Dir
            $left = @(Get-WhmUntrustedWriteAccess -Path $Dir)
            $aclNow = & icacls.exe $Dir /T 2>&1 | Out-String
            $left.Count | Should -Be 0 -Because "nothing untrusted should remain. ACL: $aclNow"
            $saved = $script:WhmModuleRoot
            try {
                $script:WhmModuleRoot = $Dir
                { Register-HealthMonitorTask -WhatIf -OutputPath (Join-Path -Path $Dir -ChildPath 'out') } | Should -Not -Throw
            }
            finally {
                $script:WhmModuleRoot = $saved
            }
        }
        Get-ScheduledTask -TaskName 'WindowsHealthMonitor' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}
