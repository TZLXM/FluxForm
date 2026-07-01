param(
    [string]$Runtime = 'win-x64',
    [switch]$RunWpfSmoke,
    [switch]$BuildInstaller
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

& .\scripts\build.ps1 -Configuration Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\scripts\test.ps1 -Configuration Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\scripts\publish-cli.ps1 -Configuration Release -Runtime $Runtime
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& .\scripts\publish-wpf.ps1 -Configuration Release -Runtime $Runtime
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($BuildInstaller) {
    & .\scripts\publish-installer.ps1 -Configuration Release -Runtime $Runtime
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

if ($RunWpfSmoke) {
    & .\scripts\smoke-wpf.ps1 -ExecutablePath '.\publish\wpf\FluxForm.WPF.exe'
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
