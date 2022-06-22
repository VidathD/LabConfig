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
        $PasswordText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
        $ConfirmText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Confirm))

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
function Test-Activation {
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
    if (Test-Activation) {
        # Skip activation and continue the script.
        Write-Host 'Windows already activated!'
    }

    # If windows isn't activated,
    else{
        # Activate windows.
        Invoke-WindowsActivation

        # If activation failed,
        while (-Not (Test-Activation)) {
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
    $script:StudentSID = $StudentAcc.Translate([System.Security.Principal.SecurityIdentifier])

    # Create a new drive that gives us access to the registry of all users.
    New-PSDrive HKU Registry "HKEY_USERS"
}




# Function to change the registry to set user permissions.
function Set-UserPermissions {
    # Get the present working directory.
    $WorkingDirectory = Get-Location

    # Set the location of CSImages folder.
    $ImageSource = "$WorkingDirectory\CSImages"

    # Set the destinations to where the CSImages folder should be copied.
    $ImageDestination = "$env:USERPROFILE\Pictures\CSImages", 'C:\Users\Student\Pictures\CSImages', 'C:\Windows\Web\CSImages'

    # Copy the CSImages folder to the destinations.
    foreach ($i in $ImageDestination) {
        Copy-Item -Path $ImageSource -Destination $i -Recurse -Force
    }

    # Print instructions to change the lock screen. Logging into the "Student" account also is essential as it will load the registry for that users, allowing us to change it.
    Write-Host 'Set the lock screen for BCCS account. It is located in the Pictures folder.'
    Write-Host 'Log into Student account and similarly set the lock screen'
    Write-Host 'Log back into BCCS account and press enter. Do NOT sign out of Student account! Use Win + L to lock screen.'

    # Continue when user presses any key.
    Write-Host -NoNewLine "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    # Change the desktop wallpaper of current user.
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'WallPaper' -Value 'C:\Windows\Web\CSImages\Background.jpg'

    # Create the registry path to needed to disable Windows Spotlight if it doesn't exist.
    if (-Not (Test-Path 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent')) {
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent' -Force
    }

    # Disalble Windows Spotlight features for user "BCCS".
    New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsSpotlightFeatures' -Value '1' -PropertyType 'DWORD'

    # Create drive to access user registry.
    New-UsersRegistryDrive

    # Set the registry paths that we need to change to variables.
    $RegistryPathPolicies = "HKU:\$StudentSID\Software\Microsoft\Windows\CurrentVersion\Policies"
    $RegistryPathRSD = "HKU:\$StudentSID\Software\Policies\Microsoft\Windows\RemovableStorageDevices"
    $RegistryPathCloudContent = "HKU:\$StudentSID\Software\Policies\Microsoft\Windows\CloudContent"

    # Set the registry keys that we need to change to an array.
    $Keys = 'Explorer', 'ActiveDesktop', 'System'

    # Create registry keys if they are missing.
    foreach ($i in $Keys) {
        if (-Not (Test-Path "$RegistryPathPolicies\$i")) {
            New-Item -Path "$RegistryPathPolicies\$i" -Force
        }
    }

    # Create registry keys if they are missing.
    if (-Not (Test-Path $RegistryPathRSD)) {
        New-Item -Path $RegistryPathRSD -Force
    }

    # Create registry keys if they are missing.
    if (-Not (Test-Path $RegistryPathCloudContent)) {
        New-Item -Path $RegistryPathCloudContent -Force
    }

    # Disable Control Panel access by user "Student".
    New-ItemProperty -Path "$RegistryPathPolicies\Explorer" -Name 'NoControlPanel' -Value '1' -PropertyType 'DWORD'

    # Disable changing wallpaper by user "Student".
    New-ItemProperty -Path "$RegistryPathPolicies\ActiveDesktop" -Name 'NoChangingWallPaper' -Value '1' -PropertyType 'DWORD'

    # Set the wallpaper of user "Student".
    New-ItemProperty -Path "$RegistryPathPolicies\System" -Name 'Wallpaper' -Value 'C:\Windows\Web\CSImages\Background.jpg' -PropertyType 'String'

    # Set the wallpaper style to "Fit".
    New-ItemProperty -Path "$RegistryPathPolicies\System" -Name 'WallpaperStyle' -Value '4' -PropertyType 'DWORD'

    # Disable changing locations of personal directories (Desktop, Documents, Downloads, Picures, Videos, etc...)  by user "Student".
    New-ItemProperty -Path "$RegistryPathPolicies\Explorer" -Name 'DisablePersonalDirChange' -Value '1' -PropertyType 'DWORD'

    # Disable access to removable storage media  by user "Student".
    New-ItemProperty -Path $RegistryPathRSD -Name 'Deny_All' -Value '1' -PropertyType 'DWORD'

    # Disable Windows Spotlight features for user "Student.
    New-ItemProperty -Path $RegistryPathCloudContent -Name 'DisableWindowsSpotlightFeatures' -Value '1' -PropertyType 'DWORD'
}




# Function to create, modify and set permissions of users.
function Set-Users {
    # Create the new user "Student" with the password taken from user input with necessary permissions.
    New-LocalUser -Name 'Student' -Password $StudentPassword -FullName 'Student' -Description 'Student account with low privileges.' -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
    
    # Add the user "Student" to the localgroup "Users".
    Add-LocalGroupMember -Group 'Users' -Member 'Student'

    # Change the registry to set user permissions.
    Set-UserPermissions

    # Remove the user "Student" from the localgroup "Users".
    Remove-LocalGroupMember -Group 'Users' -Member 'Student'

    # Add the user "Student" to the localgroup "Guests".
    Add-LocalGroupMember -Group 'Guests' -Member 'Student'

    # If the user "BCCS" doesn't exist,
    if (-Not (Get-LocalUser -Name 'BCCS')) {
        # Rename the current user to "BCCS".
        Rename-LocalUser -Name $env:USERNAME -NewName 'BCCS'
    }

    # Modify the user "BCCS" with the password taken from user input and add necessary permissions.
    Set-LocalUser -Name 'BCCS' -Password $BCCSPassword -FullName 'BCCS' -Description 'Main admin account of BCCS.' -PasswordNeverExpires $True -UserMayChangePassword $True
}




# Function to change the registry to set machine permissions.
function Set-MachinePermissions {
    # Set the registry key that we need to change to a variable.
    $RegistryPathPersonalization = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'

    # If the registry key we need doesn't exist, create it.
    if (-NOT (Test-Path $RegistryPathPersonalization)) {
        New-Item -Path $RegistryPathPersonalization -Force
    }

    # Set the default lock screen image.
    New-ItemProperty -Path $RegistryPathPersonalization -Name 'LockScreenImage' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String'

    # Disable overlays on the lock screen.
    New-ItemProperty -Path $RegistryPathPersonalization -Name 'LockScreenOverlaysDisabled' -Value '1' -PropertyType 'DWORD'

    # Prevent changing of the lock screen.
    New-ItemProperty -Path $RegistryPathPersonalization -Name 'NoChangingLockScreen' -Value '1' -PropertyType 'DWORD'

    # Prevent using slideshow in lock screen.
    New-ItemProperty -Path $RegistryPathPersonalization -Name 'NoLockScreenSlideshow' -Value '1' -PropertyType 'DWORD'
}




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
    Get-Info

    # Clear the screen.
    Clear-Host

    # Manage Windows activation.
    Set-WindowsActivation

    # Clear the screen.
    Clear-Host

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




# If the script was not dot sourced, set up the computer.
if (-Not ($MyInvocation.InvocationName -eq '.')) {
        Invoke-ComputerSetup
}
