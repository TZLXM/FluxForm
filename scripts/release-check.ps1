param(
    [string]$Runtime = 'win-x64'
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
