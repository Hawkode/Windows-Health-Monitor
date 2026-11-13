# Module root, used to find Config\ from inside dot-sourced files.
$script:WhmModuleRoot = $PSScriptRoot

# Private helpers first, then public functions. Each public file is named after
# the function it defines, so the file names are the export list.
$privateFiles = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Private') -Filter '*.ps1' -File -ErrorAction SilentlyContinue)
$publicFiles = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Public') -Filter '*.ps1' -File -ErrorAction SilentlyContinue)

foreach ($file in @($privateFiles + $publicFiles)) {
    . $file.FullName
}

Export-ModuleMember -Function @($publicFiles | ForEach-Object { $_.BaseName })
