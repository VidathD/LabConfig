function Install-PowerShell {
    $WorkingDirectory = Get-Location
    $PwshPath  = '$env:ProgramFiles\PowerShell\7\pwsh.exe'
    $TestParams = "Test-Path -Path `"$PwshPath`" -PathType Leaf"
    $InstallerDirectory = "$WorkingDirectory\Setups"
    $Installer = 'PowerShell-7.2.4-win-x64.msi'
    #$InstallerDirectory = Get-ChildItem -Recurse | Where-Object {$_.Name -like 'PowerShell-*-win-x64.msi'} | Select-Object Directory
    #$Installer = Get-ChildItem -Recurse | Where-Object {$_.Name -like 'PowerShell-*-win-x64.msi'} | Select-Object Name

    while (-Not (Invoke-Expression $TestParams)) {
        Write-Host 'Do you want to install the included PowerShell version? (Yes[Y]/No[N])'
        $InstallIncluded = Read-Host

        if ($InstallIncluded -eq 'Y' -or $InstallIncluded -eq 'Yes') {
            if (-Not ("$InstallerDirectory\$Installer")) {
                while (-Not ($IsValid)) {
                    Write-Host 'Included PowerShell installer not found. Do you want to download and install PowerShell? (Yes[Y]/No[N])'
                    $DownloadPS = Read-Host
                
                    if ($DownloadPS -eq 'Y' -or $DownloadPS -eq 'Yes') {
                        $IsValid = $True
                        Write-Host 'Downloading and installing PowerShell...'
                        winget install --name PowerShell --id Microsoft.PowerShell --source winget
                        while (-Not ($Test)) {
                            Start-Sleep -Seconds 1
                            $Test = Invoke-Expression $TestParams
                        }
                        Start-Sleep -Seconds 15
                    }
                    elseif ($DownloadPS -eq 'N' -or $DownloadPS -eq 'No') {
                        $IsValid = $True
                        Write-Host 'Please install PowerShell manually and run the script again.'
                        exit
                    }
                    else {
                        $IsValid = $False
                        Write-Host 'Please enter Yes/Y or No/N only.'
                    }
                }
            }
            else {
                Set-Location $InstallerDirectory
                Write-Host 'Installing...'
                msiexec.exe /package $Installer /passive ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1
                while (-Not ($Test)) {
                    Start-Sleep -Seconds 1
                    $Test = Invoke-Expression $TestParams
                }
                Start-Sleep -Seconds 15
                Set-Location $WorkingDirectory
            }
        }
        elseif ($InstallIncluded -eq 'N' -or $InstallIncluded -eq 'No') {
            Write-Host 'Install PowerShell and run the script again.'
            exit
        }
        else {
            Write-Host 'Please enter Yes/Y or No/N only.'
        }
    }
}


if (-Not (Invoke-Expression $TestParams))  {
    Write-Host 'PowerShell not installed!'
    Install-Powershell
}


Invoke-Expression "& `"$PwshPath`" -ExecutionPolicy Bypass .\Invoke-ComputerSetup.ps1"