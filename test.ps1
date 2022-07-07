# JSON configuration file.
param (
    [Parameter(Mandatory, Position=1)] [String] $ConfigurationJsonFile
)

Write-Host "Configuration file is $ConfigurationJsonFile"

$script:Configuration = ConvertFrom-Json -InputObject $ConfigurationJsonFile

Write-Host "Configuration is $Configuration"