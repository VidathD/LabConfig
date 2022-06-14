$CurrentLocation = Get-Location
$PwshPath  = '$env:ProgramFiles\PowerShell\7\pwsh.exe'
$TestParams = "Test-Path -Path `"$PwshPath`" -PathType Leaf"
$Installer = Get-ChildItem | Where-Object {$_.Name -like 'PowerShell-*-win-x64.msi'} | Select-Object Name

if (-Not (Invoke-Expression $TestParams))  {
    Write-Host 'Powershell not installed!'
    while (-Not (Invoke-Expression $TestParams)) {
        Write-Host 'Do you want to install the included Powershell version? (Yes[Y]/No[N])'
        $InstallIncluded = Read-Host

        if ($InstallIncluded -eq 'Y' -or $InstallIncluded -eq 'Yes') {
            if (-Not ("$CurrentLocation\Setups\$Installer")) {
                Write-Host 'Included Powershell installer not found. Please install powershell manually and run the script again.'
            }
            else {
                Set-Location "$CurrentLocation\Setups"
                Write-Host 'Installing...'
                msiexec.exe /package $Installer /passive ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1
                while (-Not ($Test)) {
                    Start-Sleep -Seconds 1
                    $Test = Invoke-Expression $TestParams
                }
                Start-Sleep -Seconds 10
                Set-Location $CurrentLocation
            }
        }
        elseif ($InstallIncluded -eq 'N' -or $InstallIncluded -eq 'No') {
            Write-Host 'Install Powershell and run the script again.'
            exit
        }
        else {
            Write-Host 'Please enter Yes/Y or No/N only.'
        }
    }
}

Invoke-Expression "& `"$PwshPath`" -ExecutionPolicy Bypass .\Invoke-ComputerSetup.ps1"