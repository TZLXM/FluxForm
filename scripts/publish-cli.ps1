param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [switch]$BundleFFmpeg,
    [switch]$DownloadFFmpeg
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

$publishArgs = @(
    '.\FluxForm.CLI\FluxForm.CLI.csproj',
    '-c', $Configuration,
    '-r', $Runtime,
    '--self-contained', 'true',
    '-p:PublishSingleFile=true',
    '-p:RestorePackagesWithLockFile=false',
    '-p:NuGetLockFilePath=.\FluxForm.CLI\obj\publish.packages.lock.json',
    '-o', '.\publish\cli'
)

$bundleFFmpegValue = ($BundleFFmpeg -or $DownloadFFmpeg).ToString().ToLowerInvariant()
$downloadFFmpegValue = $DownloadFFmpeg.ToString().ToLowerInvariant()
if ($BundleFFmpeg -or $DownloadFFmpeg) {
    $publishArgs += "-p:BundleFFmpeg=$bundleFFmpegValue"
    $publishArgs += "-p:DownloadFFmpegDuringPublish=$downloadFFmpegValue"
}

dotnet publish @publishArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
