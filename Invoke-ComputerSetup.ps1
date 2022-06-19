function Get-Info {
    while (-Not ($BCCSMatch)) {
        Write-Host "Enter BCCS password:"
        $script:BCCSPassword = Read-Host -AsSecureString
        Write-Host "Confirm BCCS password:"
        $BCCSConfirm = Read-Host -AsSecureString
        if ($BCCSPassword -eq $BCCSConfirm) {
            $BCCSMatch = $True
        }
        else {
            Write-Host "Passwords do not match. Please enter them again."
            $BCCSMatch = $False
        }
    }
    while (-Not ($StudentMatch)) {
        Write-Host "Enter Student password:"
        $script:StudentPassword = Read-Host -AsSecureString
        Write-Host "Confirm Student password:"
        $StudentConfirm = Read-Host -AsSecureString
        if ($StudentPassword -eq $StudentConfirm) {
            $StudentMatch = $True
        }
        else {
            Write-Host "Passwords do not match. Please enter them again."
            $StudentMatch = $False
        }
    }
    Write-Host "Enter ComputerName:"
    $script:ComputerName = Read-Host
}


function Test-Activation {
    if (Get-CIMInstance -query "select Name, LicenseStatus from SoftwareLicensingProduct where LicenseStatus=1" | Where-Object Name -like '*Windows*' | Select-Object LicenseStatus) {
        $True
    }
    else {
        $False
    }
}


function Invoke-WindowsActivation {
    cmd.exe /C cscript C:\Windows\System32\slmgr.vbs /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX
    cmd.exe /C cscript C:\Windows\System32\slmgr.vbs /skms kms.lotro.cc
    cmd.exe /C cscript C:\Windows\System32\slmgr.vbs /ato
}


function Set-WindowsActivation {
    Set-MpPreference -DisableBehaviorMonitoring $True -DisableRealtimeMonitoring $True -DisableRemovableDriveScanning $True
    Write-Host 'Activating Windows...'
    if (Test-Activation) {
        Write-Host 'Windows already activated!'
    }
    else{
        Invoke-WindowsActivation
        # ./KMS.bat
        while (-NOT (Test-Activation)) {
            Write-Host 'Windows activation failed. Do you want to try again? (Yes[Y]/No[N])'
            $Activate = Read-Host
            if ($Activate -eq 'Y' -or $Activate -eq 'Yes') {
                Invoke-WindowsActivation
                # ./KMS.bat
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
    }
    Set-MpPreference -DisableBehaviorMonitoring $False -DisableRealtimeMonitoring $False -DisableRemovableDriveScanning $False
}


function Set-Users {
    New-LocalUser -Name 'Student' -Password $StudentPassword -FullName 'Student' -Description 'Student account with low privileges.' -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
    Add-LocalGroupMember -Group 'Users' -Member 'Student'
    Set-UserPermissions
    Remove-LocalGroupMember -Group 'Users' -Member 'Student'
    Add-LocalGroupMember -Group 'Guests' -Member 'Student'
    Set-LocalUser -Name 'BCCS' -Password $BCCSPassword -FullName 'BCCS' -Description 'Main admin account of BCCS.' -PasswordNeverExpires $True -UserMayChangePassword $True
}


function Set-UserPermissions {
    $WorkingDirectory = Get-Location
    $ImageSource = "$WorkingDirectory\CSImages"
    $ImageDestination = 'C:\Users\Public\Pictures\CSImages', 'C:\Users\BCCS\Pictures\CSImages', 'C:\Users\Student\Pictures\CSImages', 'C:\Windows\Web\CSImages'
    Copy-Item -Path $ImageSource -Destination $ImageDestination -Recurse -Force

    Write-Host 'Set the lock screen for BCCS account. It is located in the Pictures folder.'
    Write-Host 'Log into Student account and similarly set the lock screen'
    Write-Host 'Log back into BCCS account and press enter. Do NOT sign out of Student account! Use Win + L to lock screen.'
    Write-Host -NoNewLine "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'WallPaper' -Value 'C:\Windows\Web\CSImages\Background.jpg'
    if (-Not (Test-Path 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent')) {
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent' -Force
    }
    New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsSpotlightFeatures' -Value '1' -PropertyType 'DWORD'

    $StudentAcc = New-Object System.Security.Principal.NTAccount('Student')
    $StudentSID = $StudentAcc.Translate([System.Security.Principal.SecurityIdentifier])

    New-PSDrive HKU Registry "HKEY_USERS\$StudentSID"

    $RegistryPathPolicies = 'HKU:\Software\Microsoft\Windows\CurrentVersion\Policies'
    $RegistryPathRSD = 'HKU:\Software\Policies\Microsoft\Windows\RemovableStorageDevices'
    $RegistryPathCloudContent = 'HKU:\Software\Policies\Microsoft\Windows\CloudContent'
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
    New-ItemProperty -Path "$RegistryPathPolicies\System" -Name 'Wallpaper' -Value 'C:\Windows\Web\CSImages\Background.jpg' -PropertyType 'String'
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

    New-ItemProperty -Path $RegistryPathPersonalization -Name 'LockScreenImage' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String'
    New-ItemProperty -Path $RegistryPathPersonalization -Name 'LockScreenOverlaysDisabled' -Value '1' -PropertyType 'DWORD'
    New-ItemProperty -Path $RegistryPathPersonalization -Name 'NoChangingLockScreen' -Value '1' -PropertyType 'DWORD'
    New-ItemProperty -Path $RegistryPathPersonalization -Name 'NoLockScreenSlideshow' -Value '1' -PropertyType 'DWORD'
}


function Set-ComputerName {
    Rename-Computer -NewName $ComputerName    
}


function Undo-RegistryChanges {
    $StudentAcc = New-Object System.Security.Principal.NTAccount('Student')
    $StudentSID = $StudentAcc.Translate([System.Security.Principal.SecurityIdentifier])
    New-PSDrive HKU Registry "HKEY_USERS\$StudentSID"
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'WallPaper' -Value 'C:\Windows\web\wallpaper\Windows\img0.jpg'
    $DeleteRegistryEntries = 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent\', 'HKU:\Software\Microsoft\Windows\CurrentVersion\Policies\', 'HKU:\Software\Policies\Microsoft\Windows\CloudContent\'
    $DeleteRegistryKeys = 'HKU:\Software\Policies\Microsoft\Windows\RemovableStorageDevices', 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
    Remove-Item -Path $DeleteRegistryKeys
    Remove-Item -Path $DeleteRegistryEntries -Exclude '(Default)'
}


function Invoke-ComputerSetup {
    Get-Info
    Set-WindowsActivation
    Set-Users
    Set-MachinePermissions
    Set-ComputerName

    Write-Host "Restarting in 10 seconds..."
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}


if (-Not ($MyInvocation.InvocationName -eq '.')) {
    try {
        Invoke-ComputerSetup
    }
    finally {
        PowerShell.exe
    }
}