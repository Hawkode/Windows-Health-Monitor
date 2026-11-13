# Shared helpers. Nothing in this file touches Windows-only APIs at load time,
# so the module imports on any platform and the evaluation logic is testable
# without a Windows host.

# Check number per finding type. Event ID = severity base + check number,
# so 3006 always means "Defender real-time protection, Critical".
$script:WhmCheckCatalog = @{
    Cpu               = 1
    Memory            = 2
    Disk              = 3
    Uptime            = 4
    Network           = 5
    DefenderRealTime  = 6
    DefenderSignature = 7
    Firewall          = 8
    PendingReboot     = 9
    PatchAge          = 10
    LogCleared        = 11
    BitLocker         = 12
}

$script:WhmSeverityBase = @{
    OK       = 1000
    Warning  = 2000
    Critical = 3000
    Unknown  = 4000
}

# Unknown ranks above OK: a check that did not run is never reported as healthy.
$script:WhmSeverityRank = @{
    OK       = 0
    Unknown  = 1
    Warning  = 2
    Critical = 3
}

$script:WhmEventSource = 'WindowsHealthMonitor'
$script:WhmHeartbeatEventId = 1000

function Test-WhmWindowsHost {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

function Test-WhmElevated {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if (-not (Test-WhmWindowsHost)) { return $false }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $identity
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-WhmIsoTime {
    # ISO 8601 UTC strings serialise the same way in Windows PowerShell 5.1 and
    # PowerShell 7. Raw [datetime] becomes "\/Date(...)\/" in 5.1 JSON.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][datetime]$Value)
    $Value.ToUniversalTime().ToString('o')
}

function Get-WhmValue {
    # Property read that returns $null when the parent object is missing.
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    $InputObject.$Name
}

function Invoke-WhmCollector {
    # Runs one collector. A failure is recorded in the error list and returns
    # $null, so the matching check reports Unknown instead of a false OK.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$ErrorList,
        [object[]]$ArgumentList = @()
    )
    $ErrorActionPreference = 'Stop'
    try {
        & $ScriptBlock @ArgumentList
    }
    catch {
        $ErrorList.Add([pscustomobject]@{
                Collector = $Name
                Message   = $_.Exception.Message
            })
        Write-Verbose "Collector '$Name' failed: $($_.Exception.Message)"
        $null
    }
}

function Get-WhmBand {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][double]$Value,
        [Parameter(Mandatory)][double]$Warning,
        [Parameter(Mandatory)][double]$Critical,
        [switch]$LowerIsWorse
    )
    if ($LowerIsWorse) {
        if ($Value -le $Critical) { return 'Critical' }
        if ($Value -le $Warning) { return 'Warning' }
        return 'OK'
    }
    if ($Value -ge $Critical) { return 'Critical' }
    if ($Value -ge $Warning) { return 'Warning' }
    'OK'
}

function Get-WhmWorstSeverity {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyCollection()][object[]]$Finding)
    $worst = 'OK'
    foreach ($f in @($Finding)) {
        if ($null -eq $f) { continue }
        if ($script:WhmSeverityRank[[string]$f.Status] -gt $script:WhmSeverityRank[$worst]) {
            $worst = [string]$f.Status
        }
    }
    $worst
}

function Merge-WhmHashtable {
    # Override wins. Nested hashtables merge key by key. Keys that do not
    # exist in the base are rejected so a typo in an override file fails.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][hashtable]$Base,
        [Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$Override,
        [string]$KeyPath = ''
    )
    $result = @{}
    foreach ($key in $Base.Keys) { $result[$key] = $Base[$key] }
    foreach ($key in $Override.Keys) {
        $fullKey = $key
        if ($KeyPath) { $fullKey = "$KeyPath.$key" }
        if (-not $Base.ContainsKey($key)) {
            $valid = ($Base.Keys | Sort-Object) -join ', '
            throw "Unknown threshold key '$fullKey'. Valid keys: $valid"
        }
        if ($Base[$key] -is [hashtable] -and $Override[$key] -is [hashtable]) {
            $result[$key] = Merge-WhmHashtable -Base $Base[$key] -Override $Override[$key] -KeyPath $fullKey
        }
        else {
            $result[$key] = $Override[$key]
        }
    }
    $result
}

function Get-WhmCollectorMessage {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][psobject]$Snapshot,
        [Parameter(Mandatory)][string]$Collector
    )
    $match = @($Snapshot.CollectorErrors) |
        Where-Object { $null -ne $_ -and $_.Collector -eq $Collector } |
        Select-Object -First 1
    if ($null -ne $match) { return "Check did not run: $($match.Message)" }
    'Check did not run: no data collected.'
}

function Add-WhmFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$List,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('OK', 'Warning', 'Critical', 'Unknown')][string]$Status,
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$Message,
        [string]$Target = ''
    )
    $List.Add([pscustomobject]@{
            Check   = $Check
            Target  = $Target
            Status  = $Status
            Value   = $Value
            EventId = $script:WhmSeverityBase[$Status] + $script:WhmCheckCatalog[$Check]
            Message = $Message
        })
}

function ConvertTo-WhmCsvRow {
    # One flat row per run, for Excel or a quick trend chart. The JSONL file
    # holds the full detail.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][psobject]$Record)

    $s = $Record.Snapshot
    $findings = @($Record.Findings)

    $lowestDisk = $null
    $disks = @($s.Disks | Where-Object { $null -ne $_ })
    if ($disks.Count -gt 0) {
        $lowestDisk = ($disks | Measure-Object -Property FreePercent -Minimum).Minimum
    }

    $firewallAllOn = $null
    $profiles = @($s.Firewall | Where-Object { $null -ne $_ })
    if ($profiles.Count -gt 0) {
        $firewallAllOn = -not ($profiles | Where-Object { -not $_.Enabled })
    }

    $logCleared = $null
    if ($null -ne $s.LogClear) {
        $logCleared = [int]$s.LogClear.SecurityLogCleared + [int]$s.LogClear.OtherLogCleared
    }

    [pscustomobject]@{
        TimestampUtc          = $s.TimestampUtc
        ComputerName          = $s.ComputerName
        WorstStatus           = $Record.WorstStatus
        CriticalCount         = @($findings | Where-Object { $_.Status -eq 'Critical' }).Count
        WarningCount          = @($findings | Where-Object { $_.Status -eq 'Warning' }).Count
        UnknownCount          = @($findings | Where-Object { $_.Status -eq 'Unknown' }).Count
        CpuPercent            = Get-WhmValue -InputObject $s.Cpu -Name 'Percent'
        MemoryUsedPercent     = Get-WhmValue -InputObject $s.Memory -Name 'UsedPercent'
        LowestDiskFreePercent = $lowestDisk
        UptimeDays            = Get-WhmValue -InputObject $s.Uptime -Name 'Days'
        DefenderRealTime      = Get-WhmValue -InputObject $s.Defender -Name 'RealTimeProtectionEnabled'
        SignatureAgeDays      = Get-WhmValue -InputObject $s.Defender -Name 'SignatureAgeDays'
        FirewallAllOn         = $firewallAllOn
        RebootPending         = Get-WhmValue -InputObject $s.PendingReboot -Name 'Pending'
        DaysSinceLastPatch    = Get-WhmValue -InputObject $s.Patch -Name 'DaysSinceLastPatch'
        LogClearedCount       = $logCleared
        BitLockerOn           = Get-WhmValue -InputObject $s.BitLocker -Name 'ProtectionOn'
    }
}

function Get-WhmUntrustedWriteAccess {
    # Returns every way someone other than SYSTEM, Administrators or
    # TrustedInstaller can change $Path or anything under it: an Allow ACE with
    # write-type rights, or ownership (owners get implicit WRITE_DAC and can
    # grant themselves anything). A SYSTEM task that loads code from such a
    # path is a local privilege escalation: swap the file, wait for the task.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Path)

    $trustedSids = @(
        'S-1-5-18'                                                     # SYSTEM
        'S-1-5-32-544'                                                 # BUILTIN\Administrators
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
        'S-1-3-0'                                                      # CREATOR OWNER (inherit-only template)
    )

    # WriteData/CreateFiles, AppendData/CreateDirectories, DeleteSubdirectoriesAndFiles,
    # Delete, ChangePermissions, TakeOwnership, GENERIC_ALL, GENERIC_WRITE.
    $dangerousMask = 0x2 -bor 0x4 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000

    $items = @(Get-Item -LiteralPath $Path -Force -ErrorAction Stop)
    if ($items[0].PSIsContainer) {
        $items += @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction Stop)
    }

    foreach ($item in $items) {
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop

        $ownerSid = $null
        try {
            $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            Write-Verbose "Could not read the owner of '$($item.FullName)': $($_.Exception.Message)"
        }
        if ($trustedSids -notcontains $ownerSid) {
            [pscustomobject]@{
                Path     = $item.FullName
                Identity = [string]$acl.Owner
                Rights   = 'Owner (implicit WRITE_DAC)'
            }
        }

        foreach ($rule in $acl.Access) {
            if ([string]$rule.AccessControlType -ne 'Allow') { continue }
            if (([int64]$rule.FileSystemRights -band $dangerousMask) -eq 0) { continue }
            $sid = $null
            try {
                $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            }
            catch {
                Write-Verbose "Could not resolve '$($rule.IdentityReference)' to a SID: $($_.Exception.Message)"
            }
            if ($trustedSids -notcontains $sid) {
                [pscustomobject]@{
                    Path     = $item.FullName
                    Identity = [string]$rule.IdentityReference
                    Rights   = [string]$rule.FileSystemRights
                }
            }
        }
    }
}

function Test-WhmEventSource {
    # Registry check instead of [EventLog]::SourceExists, which throws for
    # non-admins because it also searches the Security log.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Source)
    Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$Source"
}

function Register-WhmEventSource {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Source)
    if (Test-WhmEventSource -Source $Source) { return }
    if (-not (Test-WhmElevated)) {
        throw "Event source '$Source' is not registered. Run Register-HealthMonitorTask, or Start-HealthMonitor -WriteEventLog once, from an elevated session."
    }
    [System.Diagnostics.EventLog]::CreateEventSource($Source, 'Application')
}

function Write-WhmEvent {
    # One heartbeat per run (ID 1000) plus one entry per non-OK finding.
    # The heartbeat matters: a host that stops sending it has a monitor that
    # was stopped, removed or broken.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [Parameter(Mandatory)][string]$WorstStatus,
        [Parameter(Mandatory)][string]$Source
    )
    $critical = @($Finding | Where-Object { $_.Status -eq 'Critical' }).Count
    $warning = @($Finding | Where-Object { $_.Status -eq 'Warning' }).Count
    $unknown = @($Finding | Where-Object { $_.Status -eq 'Unknown' }).Count
    $summary = "Health run complete. Worst status: $WorstStatus. Critical: $critical, Warning: $warning, Unknown: $unknown."
    [System.Diagnostics.EventLog]::WriteEntry($Source, $summary, [System.Diagnostics.EventLogEntryType]::Information, $script:WhmHeartbeatEventId)

    foreach ($f in $Finding) {
        if ($f.Status -eq 'OK') { continue }
        $entryType = [System.Diagnostics.EventLogEntryType]::Warning
        if ($f.Status -eq 'Critical') { $entryType = [System.Diagnostics.EventLogEntryType]::Error }
        $label = $f.Check
        if ($f.Target) { $label = "$($f.Check) [$($f.Target)]" }
        $message = "$label $($f.Status): $($f.Message)"
        [System.Diagnostics.EventLog]::WriteEntry($Source, $message, $entryType, [int]$f.EventId)
    }
}

function Write-WhmRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Record,
        [Parameter(Mandatory)][string]$OutputPath
    )
    $day = (Get-Date).ToString('yyyyMMdd')
    $jsonPath = Join-Path -Path $OutputPath -ChildPath "health-$day.jsonl"
    $csvPath = Join-Path -Path $OutputPath -ChildPath "health-$day.csv"

    # UTF-8 without BOM in both editions, one JSON object per line.
    $line = ConvertTo-Json -InputObject $Record -Depth 6 -Compress
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::AppendAllText($jsonPath, $line + [System.Environment]::NewLine, $utf8NoBom)

    ConvertTo-WhmCsvRow -Record $Record |
        Export-Csv -LiteralPath $csvPath -Append -NoTypeInformation -Encoding UTF8
}
