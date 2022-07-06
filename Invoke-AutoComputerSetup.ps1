# JSON configuration file.
param (
    [Parameter(Mandatory)] [string] $ConfigurationFile
)

$script:ConfigJson = Get-Content $ConfigurationFile | ConvertFrom-Json

# Function to create necessary registry paths.
function Add-RegistryPaths {
    param (
        [array]$Variable
    )
    # Create registry keys if they are missing.
    foreach ($path in $Variable) {
        if (-Not (Test-Path $path)) {
            New-Item -Path $path -Force
        }
    }
}




# Function to copy the images to necessary destinations.
function Copy-Images {
    # Set the location of CSImages folder.
    if ($ConfigJson.Config.LiteralImageSource) 
    {
        $ImageSource = $ConfigJson.Config.LiteralImageSource
    } 
    elseif ($ConfigJson.Config.RelativeImageSource) 
    {
        $ImageSource = $ConfigJson.Config.RelativeImageSource
    }
    else 
    {
        Write-Host "Image source not set. Please set it and try again."
        exit
    }

    # Set the destinations to where the CSImages folder should be copied.
    $ImageDestination = "$env:USERPROFILE\Pictures\CSImages", 'C:\Windows\Web\CSImages'

    # Copy the CSImages folder to the destinations.
    foreach ($i in $ImageDestination) 
    {
        Copy-Item -Path $ImageSource -Destination $i -Recurse -Force
    }
}




# Function to change the registry to set permissions for user "BCCS".
function Set-BCCSUserPermissions {
    # Create necessary registry paths for current user.
    Add-RegistryPaths -Variable $RegistryPathHKCU

    # Change the desktop wallpaper of current user.
    Set-ItemProperty -Path $RegistryPathHKCU[0] -Name 'WallPaper' -Value 'C:\Windows\Web\CSImages\Background.jpg' -Force

    # Disalble Windows Spotlight features for user "BCCS".
    New-ItemProperty -Path $RegistryPathHKCU[1] -Name 'DisableWindowsSpotlightFeatures' -Value '1' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight on lock screen for user "BCCS".
    New-ItemProperty -Path $RegistryPathHKCU[1] -Name 'ConfigureWindowsSpotlight' -Value '2' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight in settings for user "BCCS".
    New-ItemProperty -Path $RegistryPathHKCU[2] -Name "RotatingLockScreenEnabled" -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathHKCU[2] -Name "RotatingLockScreenOverlayEnabled" -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathHKCU[2] -Name "ContentDeliveryAllowed" -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathHKCU[2] -Name "SubscribedContent-338388Enabled" -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathHKCU[2] -Name "SubscribedContent-338389Enabled" -Value '0' -PropertyType 'DWORD' -Force

    # Set lock screen for user "BCCS".
    New-ItemProperty -Path $RegistryPathHKCU[3] -Name 'LockImageFlags' -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathHKCU[3] -Name 'PortraitAssetPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHKCU[3] -Name 'LandscapeAssetPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHKCU[3] -Name 'HotspotImageFolderPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
}




# Function to change the registry to set permissions for user "Student".
function Set-StudentUserPermissions {
    # Create necessary registry paths for user "Student".
    Add-RegistryPaths -Variable $RegistryPathStudent
    
    # Disable Control Panel access by user "Student".
    New-ItemProperty -Path $RegistryPathStudent[0] -Name 'NoControlPanel' -Value '1' -PropertyType 'DWORD' -Force

    # Disable changing locations of personal directories (Desktop, Documents, Downloads, Picures, Videos, etc...)  by user "Student".
    New-ItemProperty -Path $RegistryPathStudent[0] -Name 'DisablePersonalDirChange' -Value '1' -PropertyType 'DWORD' -Force
    
    # Disable changing wallpaper by user "Student".
    New-ItemProperty -Path $RegistryPathStudent[1] -Name 'NoChangingWallPaper' -Value '1' -PropertyType 'DWORD' -Force

    # Set the wallpaper of user "Student".
    New-ItemProperty -Path $RegistryPathStudent[2] -Name 'Wallpaper' -Value 'C:\Windows\Web\CSImages\Background.jpg' -PropertyType 'String' -Force

    # Set the wallpaper style to "Fit".
    New-ItemProperty -Path $RegistryPathStudent[2] -Name 'WallpaperStyle' -Value '4' -PropertyType 'DWORD' -Force

    # Disable access to removable storage media  by user "Student".
    New-ItemProperty -Path $RegistryPathStudent[3] -Name 'Deny_All' -Value '1' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight features for user "Student.
    New-ItemProperty -Path $RegistryPathStudent[4] -Name 'DisableWindowsSpotlightFeatures' -Value '1' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight on lock screen for user "Student".
    New-ItemProperty -Path $RegistryPathStudent[4] -Name 'ConfigureWindowsSpotlight' -Value '2' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathStudent[4] -Name 'IncludeEnterpriseSpotlight' -Value '0' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight in settings for user "Student".
    New-ItemProperty -Path $RegistryPathStudent[4] -Name 'DisableWindowsSpotlightOnSettings' -Value '1' -PropertyType 'DWORD' -Force
    
    # Disable rotating lock screen and lock screen overlay by Content Delivary Manager for user "Student".
    New-ItemProperty -Path $RegistryPathStudent[5] -Name 'RotatingLockScreenEnabled' -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathStudent[5] -Name 'RotatingLockScreenOverlayEnabled' -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathStudent[5] -Name "ContentDeliveryAllowed" -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathStudent[5] -Name "SubscribedContent-338388Enabled" -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathStudent[5] -Name "SubscribedContent-338389Enabled" -Value '0' -PropertyType 'DWORD' -Force

    # Set lock screen for user "Student".
    New-ItemProperty -Path $RegistryPathStudent[6] -Name 'LockImageFlags' -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathStudent[6] -Name 'PortraitAssetPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathStudent[6] -Name 'LandscapeAssetPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathStudent[6] -Name 'HotspotImageFolderPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
}




# Function to change the registry to set default user permissions.
function Set-DefaultUserPermissions {
    # Create necessary registry paths for user "Student".
    Add-RegistryPaths -Variable $RegistryPathDefault
    
    # Disable Control Panel access by default user.
    New-ItemProperty -Path $RegistryPathDefault[0] -Name 'NoControlPanel' -Value '1' -PropertyType 'DWORD' -Force

    # Disable changing locations of personal directories (Desktop, Documents, Downloads, Picures, Videos, etc...)  by default user.
    New-ItemProperty -Path $RegistryPathDefault[0] -Name 'DisablePersonalDirChange' -Value '1' -PropertyType 'DWORD' -Force
    
    # Disable changing wallpaper by default user.
    New-ItemProperty -Path $RegistryPathDefault[1] -Name 'NoChangingWallPaper' -Value '1' -PropertyType 'DWORD' -Force

    # Set the wallpaper of default user.
    New-ItemProperty -Path $RegistryPathDefault[2] -Name 'Wallpaper' -Value 'C:\Windows\Web\CSImages\Background.jpg' -PropertyType 'String' -Force

    # Set the wallpaper style to "Fit".
    New-ItemProperty -Path $RegistryPathDefault[2] -Name 'WallpaperStyle' -Value '4' -PropertyType 'DWORD' -Force

    # Disable access to removable storage media  by default user.
    New-ItemProperty -Path $RegistryPathDefault[3] -Name 'Deny_All' -Value '1' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight features for user "Student.
    New-ItemProperty -Path $RegistryPathDefault[4] -Name 'DisableWindowsSpotlightFeatures' -Value '1' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight on lock screen for default user.
    New-ItemProperty -Path $RegistryPathDefault[4] -Name 'ConfigureWindowsSpotlight' -Value '2' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathDefault[4] -Name 'IncludeEnterpriseSpotlight' -Value '0' -PropertyType 'DWORD' -Force

    # Disable Windows Spotlight in settings for default user.
    New-ItemProperty -Path $RegistryPathDefault[4] -Name 'DisableWindowsSpotlightOnSettings' -Value '1' -PropertyType 'DWORD' -Force
    
    # Disable rotating lock screen and lock screen overlay by Content Delivary Manager for default user.
    New-ItemProperty -Path $RegistryPathDefault[5] -Name 'RotatingLockScreenEnabled' -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathDefault[5] -Name 'RotatingLockScreenOverlayEnabled' -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathDefault[5] -Name "ContentDeliveryAllowed" -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathDefault[5] -Name "SubscribedContent-338388Enabled" -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathDefault[5] -Name "SubscribedContent-338389Enabled" -Value '0' -PropertyType 'DWORD' -Force

    # Set lock screen for default user.
    New-ItemProperty -Path $RegistryPathDefault[6] -Name 'LockImageFlags' -Value '0' -PropertyType 'DWORD' -Force
    New-ItemProperty -Path $RegistryPathDefault[6] -Name 'PortraitAssetPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathDefault[6] -Name 'LandscapeAssetPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathDefault[6] -Name 'HotspotImageFolderPath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
}




# Function to create, modify and set permissions of users.
function Set-Users {
    # If the user "BCCS" doesn't exist,
    if (-Not (Get-LocalUser -Name 'BCCS' -ErrorAction SilentlyContinue)) {
        # Rename the current user to "BCCS".
        Rename-LocalUser -Name "$env:USERNAME" -NewName 'BCCS'
    }

    # Modify the user "BCCS" with the password taken from user input and add necessary permissions.
    Set-LocalUser -Name 'BCCS' -Password $BCCSPassword -FullName 'BCCS' -Description 'Main admin account of BCCS.' -AccountNeverExpires -PasswordNeverExpires $True -UserMayChangePassword $True

    Set-BCCSUserPermissions

    # If the user "Student" doesn't exist,
    if (-Not (Get-LocalUser -Name 'Student' -ErrorAction SilentlyContinue)) {
        Set-DefaultUserPermissions

        # Create the new user "Student" with the password taken from user input with necessary permissions.
        New-LocalUser -Name 'Student' -Password $StudentPassword
    }
    else {
        Set-StudentUserPermissions
    }

    # Modify the user "Student" with the password taken from user input and add necessary permissions.
    Set-LocalUser -Name 'Student' -Password $StudentPassword -FullName 'Student' -Description 'Student account with low privileges.' -AccountNeverExpires -PasswordNeverExpires $True -UserMayChangePassword $False

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
    New-ItemProperty -Path $RegistryPathHKLM[2] -Name "SetEduPolicies" -Value '1' -PropertyType 'DWORD' -Force
    
    # Set the default lock screen image in Personalization CSP.
    New-ItemProperty -Path $RegistryPathHKLM[3] -Name 'LockScreenImageUrl' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHKLM[3] -Name 'LockScreenImagePath' -Value 'C:\Windows\Web\CSImages\LockScreen.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHKLM[3] -Name 'LockScreenImageStatus' -Value '1' -PropertyType 'DWORD' -Force

    # Set the default desktop background in Personalization CSP.
    New-ItemProperty -Path $RegistryPathHKLM[3] -Name 'DesktopImageUrl' -Value 'C:\Windows\Web\CSImages\Background.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHKLM[3] -Name 'DesktopImagePath' -Value 'C:\Windows\Web\CSImages\Background.jpg' -PropertyType 'String' -Force
    New-ItemProperty -Path $RegistryPathHKLM[3] -Name 'DesktopImageStatus' -Value '1' -PropertyType 'DWORD' -Force
}




# Function to rename the computer.
function Set-ComputerName {
    # Set the hostname (computer name) to the name taken from user input.
    Rename-Computer -NewName $ComputerName    
}




# Function to set up the computer.
function Invoke-ComputerSetup {
    # Get user input needed to run the script.
    # Get-Info

    $script:BCCSPassword = ConvertTo-SecureString -String 'BCCS' -AsPlainText -Force
    $script:StudentPassword = ConvertTo-SecureString -String 'student' -AsPlainText -Force
    $script:ComputerName = 'MTL-01'

    # Clear the screen.
    Clear-Host

    # Copy the images to necessary destinations.
    #Copy-Images

    # Create, modify and set permissions of users.
    #Set-Users

    # Change the registry to set machine permissions.
    #Set-MachinePermissions

    # Rename the computer.
    #Set-ComputerName

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
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
)

# Create a new drive that gives us access to the registry of all users.
New-PSDrive -Name 'HKU' -PSProvider 'Registry' -Root 'HKEY_USERS' -Scope 'script'

# If user "Student" exists,
if (Get-LocalUser -Name 'Student' -ErrorAction SilentlyContinue) {
    # Load registry of student user.
    reg load 'HKU\Temp' 'C:\Users\Student\NTUSER.DAT'
}    
# If user "Student" doesn't exisit,
else {
    # Load registry of default user.
    reg load 'HKU\Temp' 'C:\Users\Default\NTUSER.DAT'
}




# If the script was not dot sourced, set up the computer.
if (-Not ($MyInvocation.InvocationName -eq '.')) {
    # Set up the computer.
    Invoke-ComputerSetup

    # After the script runs,
    finally {
        # If Student registry hive is loaded,
        if (Test-Path 'HKU:\Student') {
            # Unload Student registry hive.
            reg unload 'HKU\Student'
        }

        # If default user registry hive is loaded,
        elseif (Test-Path 'HKU:\Default') {
            # Unload default user registry hive.
            reg unload 'HKU\Default'
        }

        # Remove the 'HKU:' PpowerShell Drive.
        Remove-PSDrive -Name 'HKU'
    }
}
