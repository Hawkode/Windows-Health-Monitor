#Requires -RunAsAdministrator
<#
.SYNOPSIS
Installs the WindowsHealthMonitor module for all users with an admin-only ACL.

.DESCRIPTION
Copies .\WindowsHealthMonitor to
C:\Program Files\WindowsPowerShell\Modules\WindowsHealthMonitor\<version>\
(found by both Windows PowerShell 5.1 and PowerShell 7), removes the
downloaded-from-internet mark, then sets:

- Owner: BUILTIN\Administrators on every file and folder. A file copied by an
  admin account is owned by that account, and owners can rewrite the ACL from
  an unelevated process.
- ACL: SYSTEM and Administrators full control, Users read and execute, no
  inherited entries. Program Files grants CREATOR OWNER full control, which
  would otherwise give the copying account write access.

Register-HealthMonitorTask refuses to run from a folder that fails these
checks, because a SYSTEM task loading user-writable code is a privilege
escalation.

.PARAMETER ThresholdPath
Optional threshold override file to copy in as
...\Modules\WindowsHealthMonitor\thresholds.psd1, under the same ACL.

.EXAMPLE
.\Install.ps1

.EXAMPLE
.\Install.ps1 -ThresholdPath .\thresholds.local.psd1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ThresholdPath
)

$ErrorActionPreference = 'Stop'

$source = Join-Path -Path $PSScriptRoot -ChildPath 'WindowsHealthMonitor'
$manifest = Import-PowerShellDataFile -Path (Join-Path -Path $source -ChildPath 'WindowsHealthMonitor.psd1')
$root = Join-Path -Path $env:ProgramFiles -ChildPath 'WindowsPowerShell\Modules\WindowsHealthMonitor'
$target = Join-Path -Path $root -ChildPath $manifest.ModuleVersion

if ($ThresholdPath -and -not (Test-Path -LiteralPath $ThresholdPath -PathType Leaf)) {
    throw "Threshold file not found: $ThresholdPath"
}

if (-not $PSCmdlet.ShouldProcess($target, "Install WindowsHealthMonitor $($manifest.ModuleVersion)")) { return }

if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
$null = New-Item -Path $target -ItemType Directory -Force
Copy-Item -Path (Join-Path -Path $source -ChildPath '*') -Destination $target -Recurse -Force

if ($ThresholdPath) {
    Copy-Item -LiteralPath $ThresholdPath -Destination (Join-Path -Path $root -ChildPath 'thresholds.psd1') -Force
}

# Files from a downloaded zip carry Zone.Identifier, which RemoteSigned blocks.
Get-ChildItem -LiteralPath $root -Recurse -File | Unblock-File

# Same ACL code the module uses for its output folder, and the code CI tests:
# owner Administrators everywhere, exact protected DACL on the root, children
# inherit only from it. Runs in the module's scope because it is private.
$installed = Import-Module -Name (Join-Path -Path $target -ChildPath 'WindowsHealthMonitor.psd1') -Force -PassThru
& $installed { param($p) Protect-WhmPath -Path $p } $root

Write-Output "Installed to $target"
Write-Output 'Next: Import-Module WindowsHealthMonitor; Get-HealthSnapshot | Test-HealthSnapshot | Format-Table Check, Target, Status, Message -AutoSize'
