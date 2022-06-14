function Get-Info {
    Write-Host "Enter BCCS password:"
    $script:BCCSPassword = Read-Host -AsSecureString
    Write-Host "Enter Student password:"
    $script:StudentPassword = Read-Host -AsSecureString
    Write-Host "Enter ComputerName:"
    $script:ComputerName = Read-Host
}


function Test-Activation {
    if (Get-CIMInstance -query "select Name, LicenseStatus from SoftwareLicensingProduct where LicenseStatus=1" | Where-Object Name -like '*Windows*' |Select-Object LicenseStatus) {
        $True
    }
    else {
        $False
    }
}


function Set-WindowsActivation {
    Set-MpPreference -DisableBehaviorMonitoring $True -DisableRealtimeMonitoring $True -DisableRemovableDriveScanning $True
    Write-Host 'Activating Windows...'
    if (Test-Activation) {
        Write-Host 'Windows already activated!'
    }
    else{
        ./KMS.bat
    }

    while (-NOT (Test-Activation)) {
        Write-Host 'Windows activation failed. Do you want to try again? (Yes[Y]/No[N])'
        $Activate = Read-Host
        if ($Activate -eq 'Y' -or $Activate -eq 'Yes') {
            ./KMS.bat
        }

        elseif ($Activate -eq 'N' -or $Activate -eq 'No') {
            Write-Host 'Windows not activated. Do you want to continue? (Yes[Y]/No[N])'
            $Continue = Read-Host
            while ($True) {
                if ($Continue -eq 'Y' -or $Continue -eq 'Yes') {
                    Write-Host 'Continuing...'
                    break
                }
                elseif ($Continue -eq 'N' -or $Continue -eq 'No') {
                    Write-Host 'Exitting...'
                    exit

                }
                else {
                    Write-Host 'Please enter Yes/Y or No/N only.'
                }
            }
            break
        }

        else {
            Write-Host 'Please enter Yes/Y or No/N only.'
        }
    }
    Set-MpPreference -DisableBehaviorMonitoring $False -DisableRealtimeMonitoring $False -DisableRemovableDriveScanning $False
}


function Set-Users {
    New-LocalUser -Name 'Student' -Password $StudentPassword -FullName 'Student' -Description 'Student account with low privileges.' -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
    Add-LocalGroupMember -Group 'Users' -Member 'Student'
    Set-StudentPermissions
    Remove-LocalGroupMember -Group 'Users' -Member 'Student'
    Add-LocalGroupMember -Group 'Guests' -Member 'Student'
    Set-LocalUser -Name 'BCCS' -Password $BCCSPassword -FullName 'BCCS' -Description 'Main admin account of BCCS.' -PasswordNeverExpires $True -UserMayChangePassword $True
}


function Set-StudentPermissions {

    Copy-Item -Path "$CurrentLocation\CSImages\Background.jpg" -Destination 'C:\Windows\Web\Wallpaper\Theme1\Background.jpg'
    Copy-Item -Path "$CurrentLocation\CSImages\LockScreen.jpg" -Destination 'C:\Windows\Web\Screen\LockScreen.jpg'

    Write-Host 'Set the lock screen for BCCS account. It is located at C:\Windows\Web\Screen\LockScreen.jpg.'
    Write-Host 'Log into Student account and similarly set the lock screen'
    Write-Host 'Log back into BCCS account and press enter. Do NOT sign out of Student account! Use Win + L to lock screen.'
    Read-Host

    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'WallPaper' -Value 'C:\Windows\Web\Wallpaper\Theme1\Background.jpg'
    if (-Not (Test-Path 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent')) {
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent' -Force
    }
    New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsSpotlightFeatures' -Value '1' -PropertyType 'DWORD'

    $StudentAcc = New-Object System.Security.Principal.NTAccount('Student')
    $StudentSID = $StudentAcc.Translate([System.Security.Principal.SecurityIdentifier])

    New-PSDrive HKU Registry HKEY_USERS

    $RegistryPathPolicies = "HKU:\$StudentSID\Software\Microsoft\Windows\CurrentVersion\Policies"
    $RegistryPathRSD = "HKU:\$StudentSID\Software\Policies\Microsoft\Windows\RemovableStorageDevices"
    $RegistryPathCloudContent = "HKU:\$StudentSID\Software\Policies\Microsoft\Windows\CloudContent"
    $Keys = 'Explorer', 'ActiveDesktop', 'System', 'System', 'Explorer'

    foreach ($i in $Keys) {
        if (-NOT (Test-Path "$RegistryPathPolicies\$i")) {
            New-Item -Path "$RegistryPathPolicies\$i" -Force
        }
    }

    if (-Not (Test-Path $RegistryPathRSD)) {
        New-Item -Path $RegistryPathRSD -Force
    }

    if (-Not (Test-Path $RegistryPathCloudContent)) {
        New-Item -Path $RegistryPathCloudContent -Force
    }

    New-ItemProperty -Path "$RegistryPathPolicies\Explorer" -Name 'NoControlPanel' -Value '1' -PropertyType 'DWORD'
    New-ItemProperty -Path "$RegistryPathPolicies\ActiveDesktop" -Name 'NoChangingWallPaper' -Value '1' -PropertyType 'DWORD'
    New-ItemProperty -Path "$RegistryPathPolicies\System" -Name 'Wallpaper' -Value 'C:\Windows\Web\Wallpaper\Theme1\Background.jpg' -PropertyType 'String'
    New-ItemProperty -Path "$RegistryPathPolicies\System" -Name 'WallpaperStyle' -Value '4' -PropertyType 'DWORD'
    New-ItemProperty -Path "$RegistryPathPolicies\Explorer" -Name 'DisablePersonalDirChange' -Value '1' -PropertyType 'DWORD'
    New-ItemProperty -Path $RegistryPathRSD -Name 'Deny_All' -Value '1' -PropertyType 'DWORD'
    New-ItemProperty -Path $RegistryPathCloudContent -Name 'DisableWindowsSpotlightFeatures' -Value '1' -PropertyType 'DWORD'
}


function Set-MachinePermissions {
    $RegistryPathPersonalization = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'

    if (-NOT (Test-Path $RegistryPathPersonalization)) {
        New-Item -Path $RegistryPathPersonalization -Force
    }

    New-ItemProperty -Path $RegistryPathPersonalization -Name 'LockScreenImage' -Value 'C:\Windows\Web\Screen\LockScreen.jpg' -PropertyType 'String'
    New-ItemProperty -Path $RegistryPathPersonalization -Name 'LockScreenOverlaysDisabled' -Value '1' -PropertyType 'DWORD'
    New-ItemProperty -Path $RegistryPathPersonalization -Name 'NoChangingLockScreen' -Value '1' -PropertyType 'DWORD'
    New-ItemProperty -Path $RegistryPathPersonalization -Name 'NoLockScreenSlideshow' -Value '1' -PropertyType 'DWORD'
}


function Set-ComputerName {
    Rename-Computer -NewName $ComputerName    
}


$script:CurrentLocation = Get-Location

Get-Info
Set-WindowsActivation
Set-Users
Set-MachinePermissions
Set-ComputerName

Write-Host "Restarting in 10 seconds..."
Start-Sleep -Seconds 10
Restart-Computer -Force