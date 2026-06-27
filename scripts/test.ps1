param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug'
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

dotnet test .\FluxForm.sln -c $Configuration
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
