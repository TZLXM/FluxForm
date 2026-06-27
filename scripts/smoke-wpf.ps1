param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [string]$ExecutablePath = '',
    [int]$TimeoutSeconds = 10
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
    dotnet build .\FluxForm.WPF\FluxForm.WPF.csproj -c $Configuration
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $ExecutablePath = Join-Path $root "FluxForm.WPF\bin\$Configuration\net9.0-windows\FluxForm.WPF.exe"
}
else {
    $ExecutablePath = [System.IO.Path]::GetFullPath((Join-Path $root $ExecutablePath))
}

if (-not (Test-Path -LiteralPath $ExecutablePath)) {
    throw "WPF executable not found: $ExecutablePath"
}

$workDir = Split-Path -Parent $ExecutablePath
$process = Start-Process -FilePath $ExecutablePath -WorkingDirectory $workDir -PassThru
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)

try {
    do {
        Start-Sleep -Milliseconds 250
        $process.Refresh()

        if ($process.HasExited) {
            throw "FluxForm.WPF exited before showing a window. ExitCode=$($process.ExitCode)"
        }

        if ($process.MainWindowHandle -ne 0) {
            Write-Host "[FluxForm] WPF smoke passed. Window='$($process.MainWindowTitle)' Handle=$($process.MainWindowHandle)"
            exit 0
        }
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "FluxForm.WPF did not show a main window within $TimeoutSeconds seconds."
}
finally {
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
    }
}
