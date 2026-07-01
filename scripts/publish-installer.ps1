param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [string]$InnoSetupCompilerPath,
    [switch]$DownloadFFmpeg,
    [switch]$PauseOnError
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

$installerDir = Join-Path (Get-Location) 'publish\installer'
New-Item -ItemType Directory -Force -Path $installerDir | Out-Null
$logPath = Join-Path $installerDir 'publish-installer.log'

try {
    Start-Transcript -LiteralPath $logPath -Force | Out-Null

    & .\scripts\publish-wpf.ps1 -Configuration $Configuration -Runtime $Runtime -BundleFFmpeg -DownloadFFmpeg:$DownloadFFmpeg
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($InnoSetupCompilerPath)) {
        $candidates += $InnoSetupCompilerPath
    }

    $candidates += @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "${env:LOCALAPPDATA}\Programs\Inno Setup 6\ISCC.exe"
    )

    $compiler = $candidates | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_)
    } | Select-Object -First 1

    if (-not $compiler) {
        throw 'Inno Setup compiler was not found. Install Inno Setup 6 or pass -InnoSetupCompilerPath with the full path to ISCC.exe.'
    }

    & $compiler ".\installer\FluxForm.iss"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
catch {
    Write-Host ''
    Write-Host "Installer publish failed. See log: $logPath" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    if ($PauseOnError) {
        Read-Host 'Press Enter to close'
    }
    exit 1
}
finally {
    try {
        Stop-Transcript | Out-Null
    }
    catch {
        # Transcript may not have started if PowerShell failed very early.
    }
}
