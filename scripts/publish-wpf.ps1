param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [switch]$BundleFFmpeg,
    [switch]$DownloadFFmpeg
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

$publishDir = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) 'publish\wpf'))
$running = Get-Process FluxForm.WPF -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and $_.Path.StartsWith($publishDir, [System.StringComparison]::OrdinalIgnoreCase)
}

if ($running) {
    throw 'publish/wpf/FluxForm.WPF.exe is running. Close it before publishing again.'
}

$publishArgs = @(
    '.\FluxForm.WPF\FluxForm.WPF.csproj',
    '-c', $Configuration,
    '-r', $Runtime,
    '--self-contained', 'true',
    '-p:PublishSingleFile=true',
    '-p:RestorePackagesWithLockFile=false',
    '-p:NuGetLockFilePath=.\FluxForm.WPF\obj\publish.packages.lock.json',
    '-o', '.\publish\wpf'
)

$bundleFFmpegValue = ($BundleFFmpeg -or $DownloadFFmpeg).ToString().ToLowerInvariant()
$downloadFFmpegValue = $DownloadFFmpeg.ToString().ToLowerInvariant()
if ($BundleFFmpeg -or $DownloadFFmpeg) {
    $publishArgs += "-p:BundleFFmpeg=$bundleFFmpegValue"
    $publishArgs += "-p:DownloadFFmpegDuringPublish=$downloadFFmpegValue"
}

dotnet publish @publishArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
