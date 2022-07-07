# JSON configuration file.
param (
    [Parameter(Mandatory, Position=1)] [System.Object] $ConfigurationJsonFile
)

$script:Configuration = Get-Content $ConfigurationJsonFile | ConvertFrom-Json




# Function to get and confirm password from user.
function Get-UserInfo {
    param (
        [Parameter(Mandatory)] [String] $Type
    )
    if ($Configuration.Configuration.Credentials.$Type.UserName) {
        $Type = $Configuration.Configuration.Credentials.$Type.UserName
    }
    else {
        $Type = Read-Host -Prompt "Enter username of $Type account"
    }

    if ($Configuration.Configuration.Credentials.$Type.FullName) {
        $Type = $Configuration.Configuration.Credentials.$Type.FullName
    }
    else {
        $Type = Read-Host -Prompt "Enter full name of $Type account"
    }

    if ($Configuration.Configuration.Credentials.$Type.Password) {
        $Password = ConvertTo-SecureString -String $Configuration.Configuration.Credentials.$Type.Password -AsPlainText
    }
    else {
        # Get the password for user.
        while (-Not ($Match)) {
            # Read the password from user input as a secure string.
            $Password = Read-Host -Prompt "Enter $UserName password" -AsSecureString
            # Read the password confirmation from user input and save as a secure string.
            $Confirm = Read-Host -Prompt "Confirm $UserName password" -AsSecureString

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
                Write-Error -Message "Passwords do not match. Please enter them again."
                $Match = $False
            }
        }
    }

    return $UserName, $FullName, $Password
}




# Function to add registry entries.
function Add-RegistryEntries {
    param (
        [string[]] $RegistryEntries
    )

    for ($i = 0; $i -lt $RegistryEntries.Path.Count; $i++) {
        # Create registry keys if they are missing.
        if (-Not (Test-Path $RegistryEntries.Path[$i])) {
            New-Item -Path $RegistryEntries.Path[$i] -Force
        }

        # Create registry entry.
        New-ItemProperty -Path $RegistryEntries.Path[$i]\$RegistryEntries.Key[$i] -Name $RegistryEntries.Name[$i] -Value $RegistryEntries.Value[$i]
    }
}




# Function to copy the images to necessary destinations.
function Copy-Images {
    # Set the location of CSImages folder.
    if ($Configuration.Configuration.ImageSource) {
        $ImageSource = $Configuration.Configuration.ImageSource
    } 
    else {
        Write-Error -Message "Image source not set. Please enter the image source."
        $ImageSource = Read-Host -Prompt "Image source"
    }

    # Set the destinations to where the CSImages folder should be copied.
    if ($Configuration.Configuration.ImageDestination) {
        $ImageDestination = $Configuration.Configuration.ImageDestination
    }
    else {
        $ImageDestination = "$env:USERPROFILE\Pictures\CSImages", 'C:\Windows\Web\CSImages'
    }
    
    # Copy the CSImages folder to the destinations.
    foreach ($i in $ImageDestination) {
        Copy-Item -Path $ImageSource -Destination $i -Recurse -Force
    }
}




# Function to create, modify and set permissions of users.
function Set-AdminUser {
    $AdministratorUserName, $AdministratorFullName, $AdministratorPassword = Get-UserInfo -Type 'Administrator'
    # If the user "BCCS" doesn't exist,
    if (-Not (Get-LocalUser -Name $AdministratorUserName -ErrorAction SilentlyContinue)) {
        # Rename the current user to "BCCS".
        Rename-LocalUser -Name $env:USERNAME -NewName $AdministratorUserName
    }

    # Modify the user "BCCS" with the password taken from user input and add necessary permissions.
    Set-LocalUser -Name $AdministratorUserName -Password $AdministratorPassword -FullName $AdministratorFullName -Description 'Main admin account.' -AccountNeverExpires -PasswordNeverExpires $True -UserMayChangePassword $True

    if (-Not (Get-LocalGroupMember -Group 'Administrators' -Member $AdministratorUserName)) {
        Add-LocalGroupMember -Group 'Administrators' -Member $AdministratorUserName
    }

    if ($Configuration.Registry.HKCU) {
        $HKCURegistryEntries =  $Configuration.Registry.HKCU
    }
    else {
        $HKCUJson = 
        '[
            {
                "Path" : "HKCU:\\Control Panel\\Desktop",
                "Key" : "WallPaper",
                "Value" : "C:\\Windows\\Web\\CSImages\\Background.jpg"
            },
            {
                "Path" : "HKCU:\\Software\\Policies\\Microsoft\\Windows\\CloudContent",
                "Key" : ["DisableWindowsSpotlightFeatures", "ConfigureWindowsSpotlight"],
                "Value" : [1, 2]
            },
            {
                "Path" : "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
                "Key" : ["RotatingLockScreenEnabled", "RotatingLockScreenOverlayEnabled", "ContentDeliveryAllowed", "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled"],
                "Value" : [0, 0, 0, 0, 0]
            },
            {
                "Path" : "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel",
                "Key" : "{20D04FE0-3AEA-1069-A2D8-08002B30309D}",
                "Value" : 0
            }
        ]'
        $HKCURegistryEntries = ConvertFrom-Json -InputObject $HKCUJson
    }
    Add-RegistryEntries -RegistryEntries $HKCURegistryEntries
}

function Set-GuestUser {
    $GuestUserName, $GuestFullName, $GuestPassword = Get-UserInfo -Type 'Guest'

    # If user "Student" exists,
    if (Get-LocalUser -Name $GuestUserName -ErrorAction SilentlyContinue) {
        # Get the security identifier of the user "Student".
        $script:GuestSID =(Get-LocalUser -Name 'Student').SID.Value
        # Load registry of student user.
        reg load "HKU\$GuestSID" "C:\Users\$GuestUserName\NTUSER.DAT"
        # Create a new drive that gives us access to the registry of student.
        New-PSDrive -Name 'HKU' -PSProvider 'Registry' -Root "HKEY_USERS\$GuestSID" -Scope 'Script'
    }
    # If user "Student" doesn't exisit,
    else {
        # Load registry of default user.
        reg load 'HKU\Default' 'C:\Users\Default\NTUSER.DAT'
        New-PSDrive -Name 'HKU' -PSProvider 'Registry' -Root 'HKEY_USERS\Default' -Scope 'Script'

        # Create the new user "Student" with the password taken from user input with necessary permissions.
        New-LocalUser -Name $GuestUserName -Password $GuestPassword
    }

    # Modify the user "Student" with the password taken from user input and add necessary permissions.
    Set-LocalUser -Name $GuestUserName -Password $GuestPassword -FullName $GuestFullName -Description 'Account with low privileges.' -AccountNeverExpires -PasswordNeverExpires $True -UserMayChangePassword $False

    # Add the user "Student" to the localgroup "Guests".
    if (-Not (Get-LocalGroupMember -Group 'Guests' -Member $GuestUserName)) {
        Add-LocalGroupMember -Group 'Guests' -Member $GuestUserName
    }

    if ($Configuration.Registry.HKU) {
        $HKURegistryEntries =  $Configuration.Registry.HKU
    }
    else {
        $HKUJson = 
        '[
            {
                "Path" : "HKU:\\Temp\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                "Key" : ["NoControlPanel", "DisablePersonalDirChange"],
                "Value" : [1, 1]
            },
            {
                "Path" : "HKU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop",
                "Key" : "NoChangingWallPaper",
                "Value" : 1
            },
            {
                "Path" : "HKU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "Key" : ["Wallpaper", "WallpaperStyle"],
                "Value" : ["C:\\Windows\\Web\\CSImages\\Background.jpg", 4]
            },
            {
                "Path" : "HKU:\\Software\\Policies\\Microsoft\\Windows\\RemovableStorageDevices",
                "Key" : "Deny_All",
                "Value" : 1
            },
            {
                "Path" : "HKU:\\Software\\Policies\\Microsoft\\Windows\\CloudContent",
                "Key" : ["DisableWindowsSpotlightFeatures", "ConfigureWindowsSpotlight"],
                "Value" : [1, 2]
            },
            {
                "Path" : "HKU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
                "Key" : ["RotatingLockScreenEnabled", "RotatingLockScreenOverlayEnabled", "ContentDeliveryAllowed", "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled"],
                "Value" : [0, 0, 0, 0, 0]
            },
            {
                "Path" : "HKU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel",
                "Key" : "{20D04FE0-3AEA-1069-A2D8-08002B30309D}",
                "Value" : 0
            }
        ]'
        $HKURegistryEntries = ConvertFrom-Json -InputObject $HKUJson
    }
    Add-RegistryEntries -RegistryEntries $HKURegistryEntries
}




# Function to change the registry to set machine permissions.
function Set-MachinePermissions {
    if ($Configuration.Registry.HKLM) {
        $HKLMRegistryEntries =  $Configuration.Registry.HKLM
    }
    else {
        $HKLMJson =
        '[
            {
                "Path" : "HKLM:\\Software\\Policies\\Microsoft\\Windows\\CloudContent",
                "Key" : "DisableCloudOptimizedContent",
                "Value" : 1
            },
            {
                "Path" : "HKLM:\\Software\\Policies\\Microsoft\\Windows\\Personalization",
                "Key" : ["LockScreenImage", "LockScreenOverlaysDisabled", "NoChangingLockScreen", "NoLockScreenSlideshow"],
                "Value" : ["C:\\Windows\\Web\\CSImages\\LockScreen.jpg", 1, 1, 1]
            }
        ]'
        $HKLMRegistryEntries = ConvertFrom-Json -InputObject $HKLMJson
    }
    Add-RegistryEntries -RegistryEntries $HKLMRegistryEntries
}




# Function to rename the computer.
function Set-ComputerName {
    if ($Configuration.Config.Hostname) {
        $ComputerName = $Configuration.Config.Hostname
    }
    else {
        $ComputerName = Read-Host -Prompt "Enter ComputerName"
    }
    # Set the hostname (computer name) to the name taken from user input.
    Rename-Computer -NewName $ComputerName    
}




# Function to set up the computer.
function Invoke-ComputerSetup {
    # Copy the images to necessary destinations.
    Copy-Images

    # Create, modify and set permissions of users.
    Set-AdminUser
    Set-GuestUser

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
    try {
        # Set up the computer.
        Invoke-ComputerSetup
    }
    catch { 
        $_  
    }
    # After the script runs,
    finally {
        # If Student registry hive is loaded,
        if (Test-Path -Path "Registry::HKEY_USERS\$GuestSID" -PathType Container) {
            # Unload Student registry hive.
            reg unload "HKU\$GuestSID"
        }

        # If default user registry hive is loaded,
        else {
            # Unload default user registry hive.
            reg unload 'HKU\Default'
        }

        # Remove the 'HKU:' PpowerShell Drive.
        Remove-PSDrive -Name 'HKU'
    }
}
