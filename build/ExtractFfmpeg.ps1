param(
    [Parameter(Mandatory = $true)]
    [string]$PublishDir
)

$ErrorActionPreference = 'Stop'

$ffmpegDir = [System.IO.Path]::Combine($PublishDir, 'tools', 'ffmpeg')

$exe = Get-ChildItem -Path $ffmpegDir -Recurse -Filter 'ffmpeg.exe' | Select-Object -First 1
if (-not $exe) {
    Write-Error "ffmpeg.exe not found after extraction in $ffmpegDir"
    exit 1
}

$binDir = $exe.DirectoryName
Get-ChildItem -Path $binDir -File | Move-Item -Destination $ffmpegDir -Force
Get-ChildItem -Path $ffmpegDir -Directory -Recurse | Sort-Object FullName -Descending | Remove-Item -Recurse -Force

Write-Host "ffmpeg files moved to $ffmpegDir"
