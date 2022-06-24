# Function to get and confirm password from user.
function Get-Password {
    param (
        [string]$UserName
    )
    # Get the password for user.
    while (-Not ($Match)) {
        # Read the password from user input as a secure string.
        Write-Host "Enter $UserName password:"
        $Password = Read-Host -AsSecureString
        # Read the password confirmation from user input and save as a secure string.
        Write-Host "Confirm $UserName password:"
        $Confirm = Read-Host -AsSecureString

        # Convert password and confirmation to plaintext.
        $PasswordText = ConvertFrom-SecureString -SecureString $Password -AsPlainText
        $ConfirmText = ConvertFrom-SecureString -SecureString $Confirm -AsPlainText

        # Check if password and confirmation match
        if (($PasswordText -ceq $ConfirmText) -and (($PasswordText -or $ConfirmText) -ne '')) {
            $Match = $True
            return $Password
        }

        # If the password and confirmation don't match, run the loop till they do.
        else {
            Write-Host "Passwords do not match. Please enter them again."
            $Match = $False
        }
    }
}




# Function to get user input needed to run the script.
function Get-Info {
    # Get the password for BCCS user.
    $script:BCCSPassword = Get-Password -UserName 'BCCS'

    # Get the password for Student user.
    $script:StudentPassword = Get-Password -UserName 'Student'

    # Get the hostname (computer name) for the computer.
    Write-Host "Enter ComputerName:"
    $script:ComputerName = Read-Host
}




# Function to test the activation status of Windows.
function Test-WindowsActivation {
    # Check whether software with an active licence and a name that inclue "Windows" exists.

    # If it does, return $True.
    if (Get-CIMInstance -query "select Name, LicenseStatus from SoftwareLicensingProduct where LicenseStatus=1" | Where-Object Name -like '*Windows*' | Select-Object -ExpandProperty LicenseStatus) {
        $True
    }

    # If it doesn't return $False
    else {
        $False
    }
}




# Function to activate Windows.
function Invoke-WindowsActivation {
    # Add the product key to software licence manager.
    Start-Process -FilePath 'cmd.exe' -ArgumentList '/C cscript C:\Windows\System32\slmgr.vbs /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX' -WindowStyle 'Minimized'

    # Set the KMS host.
    Start-Process -FilePath 'cmd.exe' -ArgumentList '/C cscript C:\Windows\System32\slmgr.vbs /skms kms.lotro.cc' -WindowStyle 'Minimized'

    # Force online activation.
    Start-Process 'cmd.exe' -ArgumentList '/C cscript C:\Windows\System32\slmgr.vbs /ato' -WindowStyle 'Minimized'
}




# Function to manage Windows activation.
function Set-WindowsActivation {
    # Disable Windows Defender settings that might interfere with activation.
    Set-MpPreference -DisableBehaviorMonitoring $True -DisableRealtimeMonitoring $True -DisableRemovableDriveScanning $True

    Write-Host 'Activating Windows...'

    # If Windows is already activated,
    if (Test-WindowsActivation) {
        # Skip activation and continue the script.
        Write-Host 'Windows already activated!'
    }

    # If windows isn't activated,
    else{
        # Activate windows.
        Invoke-WindowsActivation

        # If activation failed,
        while (-Not (Test-WindowsActivation)) {
            # Ask user whether to try again.
            Write-Host 'Windows activation failed. Do you want to try again? (Yes[Y]/No[N])'
            $Activate = Read-Host

            # If user wants to retry activation,
            if ($Activate -eq 'Y' -or $Activate -eq 'Yes') {
                # Try to activate windows again.
                Write-Host 'Retrying Windows activation...'
                Invoke-WindowsActivation
            }
            
            # If the user doesn't want to retry activation,
            elseif ($Activate -eq 'N' -or $Activate -eq 'No') {
                # Ask user whether to continue the script.
                Write-Host 'Windows not activated. Do you want to continue? (Yes[Y]/No[N])'
                $Continue = Read-Host

                # Run the loop till user gives a valid answer.
                while ($True) {
                    # If user wants to continue,
                    if ($Continue -eq 'Y' -or $Continue -eq 'Yes') {
                        # Continue the script.
                        Write-Host 'Continuing...'
                        break
                    }

                    # If user doesn't want to continue,
                    elseif ($Continue -eq 'N' -or $Continue -eq 'No') {
                        # Exit the script.
                        Write-Host 'Exitting...'
                        exit
    
                    }

                    # If user input isn't valid,
                    else {
                        # Ask user to input a valid answer.
                        Write-Host 'Please enter Yes/Y or No/N only.'
                    }
                }
            }
    
            # If user input isn't valid,
            else {
                # Ask user to input a valid answer.
                Write-Host 'Please enter Yes/Y or No/N only.'
            }
        }
    }

    # Enable the Windows Defender settings that were previously disabled.
    Set-MpPreference -DisableBehaviorMonitoring $False -DisableRealtimeMonitoring $False -DisableRemovableDriveScanning $False
}




# Function to create drive to access user registry.
function New-UsersRegistryDrive {
    # Create a new object with the user profile of the user "Student".
    $StudentAcc = New-Object System.Security.Principal.NTAccount('Student')

    # Get the security identifier of the user "Student".
    $script:StudentSID = $StudentAcc.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty 'Value'

    # Create a new drive that gives us access to the registry of all users.
    New-PSDrive -Name 'HKU' -PSProvider 'Registry' -Root 'HKEY_USERS' -Scope 'script'
}




# Function to create necessary registry paths.
function Add-RegistryPaths {
    param (
        [string]$Variable
    )
    # Create registry keys if they are missing.
    foreach ($path in $Variable) {
        if (-Not (Test-Path $path)) {
            New-Item -Path $path -Force
        }
    }
}




# Function to change the registry to set user permissions.
function Set-UserPermissions {
    # Get the present working directory.
    $WorkingDirectory = Get-Location

    # Set the location of CSImages folder.
    $ImageSource = "$WorkingDirectory\CSImages"

    # Set the destinations to where the CSImages folder should be copied.
    $ImageDestination = "$env:USERPROFILE\Pictures\CSImages", 'C:\Windows\Web\CSImages'

    # Copy the CSImages folder to the destinations.
    foreach ($i in $ImageDestination) {
        Copy-Item -Path $ImageSource -Destination $i -Recurse -Force
    }

    # Print instructions to change the lock screen. Logging into the "Student" account also is essential as it will load the registry for that users, allowing us to change it.
    Write-Host 'Set the lock screen for BCCS account. It is located in the Pictures folder.'
    Write-Host 'Log into Student account and similarly set the lock screen'
    Write-Host 'Log back into BCCS account and press enter. Do NOT sign out of Student account! Use Win + L to lock screen.'
    Write-Host 'Press Enter to continue...'
    Read-Host | Out-Null
    # Continue when user presses any key.
    # Write-Host -NoNewLine "Press any key to continue..."
    # $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    # Create necessary registry paths for current user.
    Add-RegistryPaths -Variable $RegistryPathHKCU

    # Change the desktop wallpaper of current user.
    Set-ItemProperty -Path $RegistryPathHKCU[0] -Name 'WallPaper' -Value 'C:\Windows\Web\CSImages\Background.jpg' -Force

    # Disalble Windows Spotlight features for user "BCCS".
    New-ItemProperty -Path $RegistryPathHKCU[1] -Name 'DisableWindowsSpotlightFeatures' -Value '1' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight on lock screen for user "BCCS".
    New-ItemProperty -Path $RegistryPathHKCU[1] -Name 'ConfigureWindowsSpotlight' -Value '2' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathHKCU[1] -Name 'IncludeEnterpriseSpotlight' -Value '0' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight in settings for user "BCCS".
    New-ItemProperty -Path $RegistryPathHKCU[1] -Name 'DisableWindowsSpotlightOnSettings' -Value '1' -PropertyType 'DWORD' -Force
    Set-ItemProperty -Path $RegistryPathHKCU[2] -Name "RotatingLockScreenEnabled" -Value '0' -PropertyType 'DWORD' -Force
    Set-ItemProperty -Path $RegistryPathHKCU[2] -Name "RotatingLockScreenOverlayEnabled" -Value '0' -PropertyType 'DWORD' -Force
    Set-ItemProperty -Path $RegistryPathHKCU[2] -Name "ContentDeliveryAllowed" -Value '0' -PropertyType 'DWORD' -Force
    Set-ItemProperty -Path $RegistryPathHKCU[2] -Name "SubscribedContent-338388Enabled" -Value '0' -PropertyType 'DWORD' -Force
    Set-ItemProperty -Path $RegistryPathHKCU[2] -Name "SubscribedContent-338389Enabled" -Value '0' -PropertyType 'DWORD' -Force

    # Set lock screen for user "BCCS".
    New-ItemProperty -Path $RegistryPathHKCU[3] -Name 'LockImageFlags' -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathHKCU[3] -Name 'PortraitAssetPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHKCU[3] -Name 'LandscapeAssetPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHKCU[3] -Name 'HotspotImageFolderPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force

    # Create necessary registry paths for user "Student".
    Add-RegistryPaths -Variable $RegistryPathHKU
    
    # Disable Control Panel access by user "Student".
    New-ItemProperty -Path $RegistryPathHCU[0] -Name 'NoControlPanel' -Value '1' -PropertyType 'DWORD' -Force

    # Disable changing locations of personal directories (Desktop, Documents, Downloads, Picures, Videos, etc...)  by user "Student".
    New-ItemProperty -Path $RegistryPathHCU[0] -Name 'DisablePersonalDirChange' -Value '1' -PropertyType 'DWORD' -Force
    
    # Disable changing wallpaper by user "Student".
    New-ItemProperty -Path $RegistryPathHCU[1] -Name 'NoChangingWallPaper' -Value '1' -PropertyType 'DWORD' -Force

    # Set the wallpaper of user "Student".
    New-ItemProperty -Path $RegistryPathHCU[2] -Name 'Wallpaper' -Value 'C:\Windows\Web\CSImages\Background.jpg' -PropertyType 'String' -Force

    # Set the wallpaper style to "Fit".
    New-ItemProperty -Path $RegistryPathHCU[2] -Name 'WallpaperStyle' -Value '4' -PropertyType 'DWORD' -Force

    # Disable access to removable storage media  by user "Student".
    New-ItemProperty -Path $RegistryPathHCU[3] -Name 'Deny_All' -Value '1' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight features for user "Student.
    New-ItemProperty -Path $RegistryPathHCU[4] -Name 'DisableWindowsSpotlightFeatures' -Value '1' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight on lock screen for user "Student".
    New-ItemProperty -Path $RegistryPathHCU[4] -Name 'ConfigureWindowsSpotlight' -Value '2' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathHCU[4] -Name 'IncludeEnterpriseSpotlight' -Value '0' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight in settings for user "Student".
    New-ItemProperty -Path $RegistryPathHCU[4] -Name 'DisableWindowsSpotlightOnSettings' -Value '1' -PropertyType 'DWORD' -Force
    
    # Disable rotating lock screen and lock screen overlay by Content Delivary Manager for user "Student".
    New-ItemProperty -Path $RegistryPathHCU[5] -Name 'RotatingLockScreenEnabled' -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathHCU[5] -Name 'RotatingLockScreenOverlayEnabled' -Value '0' -PropertyType 'DWORD' -Force
    Set-ItemProperty -Path $RegistryPathHCU[5] -Name "ContentDeliveryAllowed" -Value '0' -PropertyType 'DWORD' -Force
    Set-ItemProperty -Path $RegistryPathHCU[5] -Name "SubscribedContent-338388Enabled" -Value '0' -PropertyType 'DWORD' -Force
    Set-ItemProperty -Path $RegistryPathHCU[5] -Name "SubscribedContent-338389Enabled" -Value '0' -PropertyType 'DWORD' -Force

    # Set lock screen for user "Student".
    New-ItemProperty -Path $RegistryPathHCU[6] -Name 'LockImageFlags' -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathHCU[6] -Name 'PortraitAssetPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHCU[6] -Name 'LandscapeAssetPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHCU[6] -Name 'HotspotImageFolderPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
}




# Function to create, modify and set permissions of users.
function Set-Users {
    # If the user "BCCS" doesn't exist,
    if (-Not (Get-LocalUser -Name 'BCCS')) {
        # Rename the current user to "BCCS".
        Rename-LocalUser -Name "$env:USERNAME" -NewName 'BCCS'
    }

    # Modify the user "BCCS" with the password taken from user input and add necessary permissions.
    Set-LocalUser -Name 'BCCS' -Password $BCCSPassword -FullName 'BCCS' -Description 'Main admin account of BCCS.' -AccountNeverExpires -PasswordNeverExpires $True -UserMayChangePassword $True

    # If the user "Student" doesn't exist,
    if (-Not (Get-LocalUser -Name 'Student')) {
        # Create the new user "Student" with the password taken from user input with necessary permissions.
        New-LocalUser -Name 'Student' -Password $StudentPassword
    }

    # Modify the user "Student" with the password taken from user input and add necessary permissions.
    Set-LocalUser -Name 'Student' -Password $StudentPassword -FullName 'Student' -Description 'Student account with low privileges.' -AccountNeverExpires -PasswordNeverExpires $True -UserMayChangePassword $False

    # Add the user "Student" to the localgroup "Users".
    Add-LocalGroupMember -Group 'Users' -Member 'Student'

    # Change the registry to set user permissions.
    Set-UserPermissions

    # Remove the user "Student" from the localgroup "Users".
    Remove-LocalGroupMember -Group 'Users' -Member 'Student'

    # Add the user "Student" to the localgroup "Guests".
    Add-LocalGroupMember -Group 'Guests' -Member 'Student'
}




# Function to change the registry to set machine permissions.
function Set-MachinePermissions {
    # Create necessary registry paths for local machine.
    Add-RegistryPaths -Variable $RegistryPathHKLM

    # Disable cloud optimized content.
    New-ItemProperty -Path $RegistryPathHKLM[0] -Name 'DisableCloudOptimizedContent' -Value '1' -PropertyType 'DWORD' -Force

    # Set the default lock screen image.
    New-ItemProperty -Path $RegistryPathHKLM[1] -Name 'LockScreenImage' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force

    # Disable overlays on the lock screen.
    New-ItemProperty -Path $RegistryPathHKLM[1] -Name 'LockScreenOverlaysDisabled' -Value '1' -PropertyType 'DWORD' -Force

    # Prevent changing of the lock screen.
    New-ItemProperty -Path $RegistryPathHKLM[1] -Name 'NoChangingLockScreen' -Value '1' -PropertyType 'DWORD' -Force

    # Prevent using slideshow in lock screen.
    New-ItemProperty -Path $RegistryPathHKLM[1] -Name 'NoLockScreenSlideshow' -Value '1' -PropertyType 'DWORD' -Force

    # Set Edu Policies
    New-ItemProperty -Path $RegistryPathHKLM[2] -Name "SetEduPolicies" -Value 1 -PropertyType DWORD -Force
    
    # Set the default lock screen image in Personalization CSP.
    New-ItemProperty -Path $RegistryPathHKLM[3] -Name 'LockScreenImageUrl' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHKLM[3] -Name 'LockScreenImagePath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHKLM[3] -Name 'LockScreenImageStatus' -Value '1' -PropertyType 'DWORD' -Force

    # Set the default desktop background in Personalization CSP.
    New-ItemProperty -Path $RegistryPathHKLM[3] -Name 'DesktopImageUrl' -Value 'C:\Windows\Web\CSImages\Background.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHKLM[3] -Name 'DesktopImagePath' -Value 'C:\Windows\Web\CSImages\Background.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHKLM[3] -Name 'DesktopImageStatus' -Value '1' -PropertyType 'DWORD' -Force
}




function Set-LockScreenBackground {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC" -Name "SetEduPolicies" -Value 1 -PropertyType DWORD -Force | Out-Null
    $RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
    if (!(Test-Path $RegKeyPath)) {
        New-Item -Path $RegKeyPath -Force | Out-Null
    }
    New-ItemProperty -Path $RegKeyPath -Name "LockScreenImageStatus" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $RegKeyPath -Name "LockScreenImagePath" -Value $LockScreenImage -PropertyType STRING -Force | Out-Null
    New-ItemProperty -Path $RegKeyPath -Name "LockScreenImageUrl" -Value $LockScreenImage -PropertyType STRING -Force | Out-Null
        # In case you want to force a corporate desktop image
        # $DesktopImageValue = "C:\Users\Public\Pictures\$ImageWithDimensions"
        # New-ItemProperty -Path $RegKeyPath -Name "DesktopImageStatus" -Value 1 -PropertyType DWORD -Force | Out-Null
        # New-ItemProperty -Path $RegKeyPath -Name "DesktopImagePath" -Value $DesktopImageValue -PropertyType STRING -Force | Out-Null
        # New-ItemProperty -Path $RegKeyPath -Name "DesktopImageUrl" -Value $DesktopImageValue -PropertyType STRING -Force | Out-Null
    # Disable Windows 10 Spotlight for all users
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
    $RegArray = Get-ChildItem -Directory -Name "HKU:"
    foreach ($RegItem in $RegArray) {
        $RegPath = "HKU:\$RegItem\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        Set-ItemProperty -Path $RegPath -Name "RotatingLockScreenEnabled" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $RegPath -Name "RotatingLockScreenOverlayEnabled" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $RegPath -Name "ContentDeliveryAllowed" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $RegPath -Name "SubscribedContent-338388Enabled" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $RegPath -Name "SubscribedContent-338389Enabled" -Value 0 -Force -ErrorAction SilentlyContinue
    }
    # Disable Windows 10 Spotlight for current user (in case the 'all users' portion skipped the current user due to a permissions error)
    $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-ItemProperty -Path $RegPath -Name "RotatingLockScreenEnabled" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $RegPath -Name "RotatingLockScreenOverlayEnabled" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $RegPath -Name "ContentDeliveryAllowed" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $RegPath -Name "SubscribedContent-338388Enabled" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $RegPath -Name "SubscribedContent-338389Enabled" -Value 0 -Force -ErrorAction SilentlyContinue
}
Write-Output "Used $Image for this display."
$Screen
$VideoController




# Function to rename the computer.
function Set-ComputerName {
    # Set the hostname (computer name) to the name taken from user input.
    Rename-Computer -NewName $ComputerName    
}




# Function to undo registry changes.
function Undo-RegistryChanges {
    # Create drive to access user registry.
    New-UsersRegistryDrive

    # Change the desktop wallpaper of current user to default value.
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'WallPaper' -Value 'C:\Windows\web\wallpaper\Windows\img0.jpg'

    # Set the registry keys that need to be deleted to a variable.
    $DeleteRegistryKeys = 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent\', "HKU:\$StudentSID\Software\Microsoft\Windows\CurrentVersion\Policies\", "HKU:\$StudentSID\Software\Policies\Microsoft\Windows\CloudContent\", "HKU:\$StudentSID\Software\Policies\Microsoft\Windows\RemovableStorageDevices", 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
    
    # Delete the registry keys.
    Remove-Item -Path $DeleteRegistryKeys
}




# Function to set up the computer.
function Invoke-ComputerSetup {
    # Get user input needed to run the script.
    # Get-Info

    $script:BCCSPassword = ConvertTo-SecureString -String 'BCCS' -AsPlainText -Force
    $script:StudentPassword = ConvertTo-SecureString -String 'student' -AsPlainText -Force
    $script:ComputerName = 'MTL-01'

    # Clear the screen.
    # Clear-Host

    # Manage Windows activation.
    # Set-WindowsActivation

    # Clear the screen.
    # Clear-Host

    # Create, modify and set permissions of users.
    Set-Users

    # Change the registry to set machine permissions.
    Set-MachinePermissions

    # Rename the computer.
    Set-ComputerName

    # Restart the computer after 10 seconds.
    Write-Host "Restarting in 10 seconds..."
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}




# Put all registry paths for current user into a variable.
$script:RegistryPathHKCU = @(
    'HKCU:\Control Panel\Desktop'
    'HKCU:\Software\Policies\Microsoft\Windows\CloudContent'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lock Screen\Creative'
)

# Create drive to access user registry.
New-UsersRegistryDrive

# Put all registry paths for user "Student" into a variable.
$script:RegistryPathHKU = @(
    "HKU:\$StudentSID\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    "HKU:\$StudentSID\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"
    "HKU:\$StudentSID\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    "HKU:\$StudentSID\Software\Policies\Microsoft\Windows\RemovableStorageDevices"
    "HKU:\$StudentSID\Software\Policies\Microsoft\Windows\CloudContent"
    "HKU:\$StudentSID\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    "HKU:\$StudentSID\Software\Microsoft\Windows\CurrentVersion\Lock Screen\Creative"
)

# Put all registry paths for local machine into a variable.
$script:RegistryPathHKLM = @(
    'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'
    'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC'
    'HKLM:\Software\Policies\Microsoft\Windows\PersonalizationCSP'
)




# If the script was not dot sourced, set up the computer.
if (-Not ($MyInvocation.InvocationName -eq '.')) {
        Invoke-ComputerSetup
}
