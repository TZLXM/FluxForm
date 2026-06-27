param(
    [Parameter(Mandatory = $true)]
    [string]$PublishDir,

    [Parameter(Mandatory = $true)]
    [string]$CachePath,

    [Parameter(Mandatory = $true)]
    [string]$DownloadUrl,

    [switch]$AllowDownload
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.IO.Compression.FileSystem

function Test-ZipArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
        $zip.Dispose()
        return $true
    }
    catch {
        return $false
    }
}

$publishRoot = [System.IO.Path]::GetFullPath($PublishDir)
$ffmpegDir = [System.IO.Path]::Combine($publishRoot, 'tools', 'ffmpeg')
$ffmpegExe = [System.IO.Path]::Combine($ffmpegDir, 'ffmpeg.exe')

if (Test-Path -LiteralPath $ffmpegExe) {
    Write-Host "[FluxForm] ffmpeg already exists at $ffmpegExe; skipping bundle step."
    exit 0
}

New-Item -ItemType Directory -Force -Path $ffmpegDir | Out-Null

$cacheDir = Split-Path -Parent $CachePath
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null

if (Test-Path -LiteralPath $CachePath) {
    if (-not (Test-ZipArchive -Path $CachePath)) {
        throw "FFmpeg cache archive is invalid: $CachePath. Delete it or rerun publish with -DownloadFFmpeg."
    }
}
elseif ($AllowDownload) {
    $tempDownloadPath = "$CachePath.download"
    if (Test-Path -LiteralPath $tempDownloadPath) {
        Remove-Item -LiteralPath $tempDownloadPath -Force
    }

    Write-Host "[FluxForm] Downloading ffmpeg to temporary cache: $tempDownloadPath"
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $tempDownloadPath -UseBasicParsing

    if (-not (Test-ZipArchive -Path $tempDownloadPath)) {
        Remove-Item -LiteralPath $tempDownloadPath -Force -ErrorAction SilentlyContinue
        throw "Downloaded FFmpeg archive is invalid. Publish output was left unchanged."
    }

    Move-Item -LiteralPath $tempDownloadPath -Destination $CachePath -Force
}
else {
    throw "FFmpeg cache not found: $CachePath. Run publish without -BundleFFmpeg for a fast app-only build, place ffmpeg-release-essentials.zip in tools-cache, or add -DownloadFFmpeg to allow network download."
}

$extractDir = [System.IO.Path]::Combine($ffmpegDir, "_extract_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $extractDir | Out-Null

try {
    [System.IO.Compression.ZipFile]::ExtractToDirectory($CachePath, $extractDir)

    $exe = Get-ChildItem -Path $extractDir -Recurse -Filter 'ffmpeg.exe' | Select-Object -First 1
    if (-not $exe) {
        throw "ffmpeg.exe not found in archive: $CachePath"
    }

    Get-ChildItem -Path $ffmpegDir -Force | Remove-Item -Recurse -Force
    New-Item -ItemType Directory -Force -Path $ffmpegDir | Out-Null

    $binDir = $exe.DirectoryName
    Get-ChildItem -Path $binDir -File | Copy-Item -Destination $ffmpegDir -Force

    Write-Host "[FluxForm] ffmpeg files copied to $ffmpegDir"
}
finally {
    if (Test-Path -LiteralPath $extractDir) {
        Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
