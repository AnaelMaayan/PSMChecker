########################################################################################################################
#                       PSMChecker POWERSHELL SCRIPT
#                    -------------------------------
# General : This script helps identifying and fixing PSM common issues.
#
# Version : 2.0.0
# Created : April 2024
# Cyber-Ark Software Ltd.
# A.M
########################################################################################################################

########################################################################################################################
# Constants Declaration
########################################################################################################################
#Requires -RunAsAdministrator
. .\PSMCheckerConfig.ps1
$PSM_SHADOW_USERS_GROUP = "PSMShadowUsers"
$LOG_FILE = ".\Logs\PSMChecker-$(Get-Date -Format "dd-MM-yyyy - HH-mm").log"
$ARTICLES_TEXT_FILE = ".\Recommended Articles - $(Get-Date -Format "dd-MM-yyyy - HH-mm").txt"
########################################################################################################################




#Global variables for tracking issues and fixes.
$global:fixcount = 0
$global:issuescount = 0

###########################################################################################
# Functions
###########################################################################################

#Asks if the user willing to fix the identified issue.
function PromptForConfirmation {
    $input = Read-Host "Would you like to fix the identified issue? Yes/No"
    switch ($input) {
        'Yes' { 
            return $true
        }
        'No' {
            return $false
        }
        Default {
            Write-Host "You can answer in Yes or No only."
            PromptForConfirmation
        }
    }
    
}

#Checking if the user account is disabled or locked out on the AD or the local machine.
function DisabledOrLockedOut {
    param (
        $user
    )
    if ($DOMAIN_ACCOUNTS) {
        ((Get-ADUser -Identity $user).Enabled -eq $false -or (Get-ADUser -Identity $user -Properties * | Select-Object -ExpandProperty LockedOut) -eq $true)
    }
    else {
        ((Get-LocalUser -Name $user).Enabled -eq $false -or (Get-LocalUser -Name $user).LockoutEnabled -eq $true)
    }
}

#Unlocking and enabling the user on the AD or the local machine.
function FixDisabledOrLockedOut {
    param (
        $user
    )
    if ($DOMAIN_ACCOUNTS) {
        Unlock-ADAccount -Identity $user
        Enable-ADAccount -Identity $user
    }
    else {
        Enable-LocalUser -Name $user
    }
}

#The whole process of testing and fixing if account is disabled or locked out.
function RunDisabledOrLockedOut {
    param (
        $user
    )
    $isDisabledOrLockedOut = DisabledOrLockedOut -user $user
    if ($isDisabledOrLockedOut) {
        Write-Host "User $user is locked out or disabled." -ForegroundColor Red
        $global:issuescount++
        if (PromptForConfirmation) {
            Write-Host "Fixing user $user."
            FixDisabledOrLockedOut -user $user
            $isDisabledOrLockedOut = DisabledOrLockedOut -user $user
            If ($isDisabledOrLockedOut) {
                Write-Host "User not fixed." -ForegroundColor Red
            }
            else {
                Write-Host "User fixed." -ForegroundColor Green
                $global:fixcount++
            }
        }
    }
    else {
        Write-Host "User $user is not locked out or disabled." -ForegroundColor Green
    }

}

#The whole process of testing and fixing if account is set to change password on the next logon.
function ChangeOnNextLogon {
    param (
        $user
    )
    
    if (PasswordChangeRequiredOrNotNeverExpired -user $user) {
        Write-Host "User $user is set to change password on next logon." -ForegroundColor Red
        $global:issuescount++
        if (PromptForConfirmation) {
            Write-Host "Fixing user $user."
            FixChangeOnNextLogon -user $user
            If (PasswordChangeRequiredOrNotNeverExpired -user $user) {
                Write-Host "User not fixed." -ForegroundColor Red
            }
            else {
                Write-Host "User fixed." -ForegroundColor Green
                $global:fixcount++
            }
        }
    }
    else {
        Write-Host "User $user is not set to change password on next logon." -ForegroundColor Green
    }
}

#Checking if the user account is set to change password on the next logon on the AD or the local machine.
function PasswordChangeRequiredOrNotNeverExpired {
    param (
        $user
    )
    if ($DOMAIN_ACCOUNTS) {
        $userProperties = Get-ADUser -Identity $user -Properties pwdLastSet, PasswordNeverExpires
        return ($userProperties.pwdLastSet -eq $true -or $userProperties.PasswordNeverExpires -eq $false)
    }
    else {
        $userProperties = Get-LocalUser -Name $user
        $nullvar = $null
        return ($userProperties.PasswordExpires -ne $nullvar -or $userProperties.PasswordLastSet -eq $nullvar)
    }
}

#Removing the "Change password on next logon" and enabling "Password never expires" on the user on the AD or the local machine.
function FixChangeOnNextLogon {
    param (
        $user
    )
    if ($DOMAIN_ACCOUNTS) {
        Set-ADUser -Identity $user -ChangePasswordAtLogon $false -PasswordNeverExpires $true
    }
    else {
        Net user $user /logonpasswordchg:no  | Out-Null
        Set-LocalUser -Name $user -PasswordNeverExpires $true
    }
}

#Checks if the PSM service is running.
#If not - runs the service.
function PSMService {
    If (Get-Service -Name "Cyber-Ark Privileged Session Manager" -ErrorAction SilentlyContinue) {
        $serviceName = "Cyber-Ark Privileged Session Manager"
    }
    If (Get-Service -Name "CyberArk Privileged Session Manager" -ErrorAction SilentlyContinue) {
        $serviceName = "CyberArk Privileged Session Manager"
    }
    if ((Get-Service -Name $serviceName).Status -ne "Running") {
        Write-Host "The service '$serviceName' is not running." -ForegroundColor Red
        $global:issuescount++
        if (PromptForConfirmation) {
            Start-Service -Name $serviceName
            if ((Get-Service -Name $serviceName).Status -ne "Running") {
                Write-Host "Failed to run service '$serviceName'." -ForegroundColor Red
            }
            else {
                Write-Host "The service '$serviceName' was not running and has been started." -ForegroundColor Green
                $global:fixcount++
            }
        }
    }
    else {
        Write-Host "The service '$serviceName' is already running." -ForegroundColor Green
    }   
}

#Checks if the service set to Log on with an account
#If it does then changing it to "Local System account" and runs the service.
function PSMServiceLocalSystem {
    If (Get-Service -Name "Cyber-Ark Privileged Session Manager" -ErrorAction SilentlyContinue) {
        $serviceName = "Cyber-Ark Privileged Session Manager"
    }
    If (Get-Service -Name "CyberArk Privileged Session Manager" -ErrorAction SilentlyContinue) {
        $serviceName = "CyberArk Privileged Session Manager"
    }
    $currentLogonAccount = (Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'").StartName

    if ($currentLogonAccount -eq "LocalSystem") {
        Write-Host "The service '$serviceName' is already set to log on with the Local System Account." -ForegroundColor Green
    }
    else {
        $global:issuescount++
        Write-Host "The service '$serviceName' is not set to log on with the Local System Account." -ForegroundColor Red
        if (PromptForConfirmation) {
            sc.exe config $serviceName obj= "LocalSystem" | Out-Null
            $currentLogonAccount = (Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'").StartName
            if ($currentLogonAccount -eq "LocalSystem") {
                Write-Host "The service '$serviceName' has been set to log on with the Local System Account." -ForegroundColor Green
                $global:fixcount++
                PSMService
            }
            else {
                Write-Host "Failed to set the service '$serviceName' to log on with the Local System Account." -ForegroundColor Red        
            }
        }
    }
    
}

#Checks if there is any pending windows updates and providing number of pending updates.
function WindowsUpdates {
    $wuSession = New-Object -ComObject Microsoft.Update.Session
    $searcher = $wuSession.CreateUpdateSearcher()
    $pendingUpdates = $searcher.Search("IsInstalled=0").Updates

    if ($pendingUpdates.Count -gt 0) {
        Write-Host "There are $($pendingUpdates.Count) pending Windows updates. Let the updates finish and rerun the script."-ForegroundColor Red
        $global:issuescount++
    }
    else {
        Write-Host "There are no pending Windows updates." -ForegroundColor Green
    }   
}

#Checks if the PSM is on the account "Log On To" list on the AD.
#If not - inserting it.
function LogOnTo {
    param (
        $user
    )

    $computerName = $env:COMPUTERNAME
    $userprop = Get-ADUser -Identity $user -Properties userWorkstations
    if ($userprop.userWorkstations) {
        Write-Host "List of allowed computers for user $user :"
        $allowedComputers = $userprop.userWorkstations -split ','
        foreach ($allowedComputer in $allowedComputers) {
            Write-Host " - $allowedComputer"
        }
        
        if ($allowedComputers -notcontains $computerName) {
            Write-Host "Computer $computerName is not in the list of allowed computers of user $user." -ForegroundColor Red
            $global:issuescount++
            if (PromptForConfirmation) {
                $userprop.userWorkstations += ",$computerName"
                Set-ADUser -Identity $user -Replace @{userWorkstations = $userprop.userWorkstations }
                Write-Host "Computer $computerName has been added to the list of allowed computers of user $user." -ForegroundColor Green
                $global:fixcount++
            }
        }
        else {
            Write-Host "Computer $computerName is already in the list of allowed computers of user $user." -ForegroundColor Green
        }
    }
    else {
        Write-Host "User $user is allowed to connect to all computers." -ForegroundColor Green
    }
}

#Checks if the user is part of the local "Remote Desktop Users" group on the PSM.
#If not - inserting it.
function RDUGroup {
    param (
        $user
    )
    $group = "Remote Desktop Users"
    if ($DOMAIN_ACCOUNTS) {
        $domain = $env:USERDOMAIN
        $userprop = "$domain\$user"
    }
    else {
        $userprop = $user
    }
    

    if (-not (Get-LocalGroupMember -Group $group -Member $userprop -ErrorAction SilentlyContinue)) {
        $global:issuescount++
        Write-Host "User $userprop is not part of the $group" -ForegroundColor Red
        if (PromptForConfirmation) {
            Add-LocalGroupMember -Group $group -Member $userprop
            if (-not (Get-LocalGroupMember -Group $group -Member $userprop -ErrorAction SilentlyContinue)) {
                Write-Host "Failed to add User $userprop to the $group group." -ForegroundColor Red
            }
            else {
                $global:fixcount++
                Write-Host "User $userprop added to the $group group." -ForegroundColor Green 
            }
        }
       
    }
    else {
        Write-Host "User $userprop is already a member of the $group group." -ForegroundColor Green
    }
}

#Checks if the user that running the script is Domain Administrator or Local Administrator
function IsUserAdmin {

    if ($DOMAIN_ACCOUNTS) {
        $principal = New-Object Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
        return $principal.IsInRole("Domain Admins") 
        
    }
    else {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)   
    }
}


#Checks and fixing the Environment tab of the user on the AD or the local machine.
function PSMinitSession {
    param (
        $user
    )
    $initsession = "$PSM_COMPONENTS_FOLDER\PSMInitSession.exe"
    $program = "TerminalServicesInitialProgram"
    $folder = "TerminalServicesWorkDirectory"
    
    RunPSMInitFix -origin $program -correct $initsession -valuename "Program file name"
    RunPSMInitFix -origin $folder -correct $PSM_COMPONENTS_FOLDER -valuename "Start in"
}

#Checking and fixing each line on the Environment tab of the user on the AD or the local machine.
function RunPSMInitFix {
    param (
        $origin,
        $correct,
        [string]$valuename
    )
    if ($DOMAIN_ACCOUNTS) {
        $dn = (Get-ADUser $user).DistinguishedName 
        $ext = [ADSI]"LDAP://$dn"
    }
    else {
        $ou = [adsi]"WinNT://127.0.0.1"
        $ext = $ou.psbase.get_children().find("$user")
    }
    if (CheckIfEqualInit -extuse $ext -parm $origin -path $correct) {
        $currentvalue = $ext.PSBase.InvokeGet($origin)
        Write-Host "The ''$valuename'' is not configured correctly for the user $user . The current value is: $currentvalue"  -ForegroundColor Red
        $global:issuescount++
        if (PromptForConfirmation) {
            Write-Host "Fixing the ''$valuename'' value."
            $ext.PSBase.InvokeSet("$origin" , "$correct")
            $ext.SetInfo()
            if (CheckIfEqualInit -extuse $ext -parm $origin -path $correct) {
                Write-Host "''$valuename'' value not fixed."  -ForegroundColor Red
            }
            else {
                $global:fixcount++
                Write-Host "''$valuename'' value fixed."  -ForegroundColor Green
            }
        }
    }
    else {
        Write-Host "The ''$valuename'' is configured correctly for the user $user ."  -ForegroundColor Green

    }
    
}

#Checks if the line in the Environment tab configured as needed.
function CheckIfEqualInit {
    param (
        $extuse,
        $parm,
        $path
    )
    return ($extuse.PSBase.InvokeGet($parm) -ne $path)
}

#Checking and fixing the Components folder permissions for each PSM user and Shadow Users group.
function FolderPermissions {
    param (
        $user
    )
    if ($DOMAIN_ACCOUNTS -and $user -ne $PSM_SHADOW_USERS_GROUP) {
        $domain = $env:USERDOMAIN
        $userprop = "$domain\$user"
    }
    else {
        $computer = $env:COMPUTERNAME
        $userprop = "$computer\$user"
    }
    if (CheckPermissions -user $userprop -path $PSM_COMPONENTS_FOLDER) {
        Write-Host "The user $userprop doesn't have the right permissions on the Components folder." -ForegroundColor Red
        $global:issuescount++
        if (PromptForConfirmation) {
            Write-Host "Fixing permissions."
            PermissionsFix -user $userprop -path $PSM_COMPONENTS_FOLDER
            if (CheckPermissions -user $userprop -path $PSM_COMPONENTS_FOLDER) {
                Write-Host "The permissions was not granted for user $userprop." -ForegroundColor Red

            }
            else {
                $global:fixcount++
                Write-Host "The right permissions was granted for user $userprop." -ForegroundColor Green            
            }
        }
    }
    else {
        Write-Host "The user $userprop already have the right permissions on the Components folder." -ForegroundColor Green
    }
}

#Checking if the right permissions are granted and denied.
function CheckPermissions {
    param (
        $user,
        $path
    )
    $acl1 = (get-acl $path).access | Where-Object identityreference -eq $user | Where-Object FileSystemRights -eq ReadAndExecute, Synchronize | Where-Object -FilterScript { $_.AccessControlType -eq 'Allow' }
    $acl2 = (get-acl $path).access | Where-Object identityreference -eq $user | Where-Object FileSystemRights -eq DeleteSubdirectoriesAndFiles, Write, Delete, ChangePermissions, TakeOwnership | Where-Object -FilterScript { $_.AccessControlType -eq 'Deny' }
    return ($acl1 -eq $null -and $acl2 -eq $null) 
    
}

#Granting and denying the folder permissions.
function PermissionsFix {
    param (
        $user,
        $path
    )
    $acl = Get-ACL $path
    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule ($user, "FullControl", "ContainerInherit,ObjectInherit", "None", "Deny")
    $acl.RemoveAccessRule($ace)  | Out-Null
    Set-ACL -Path $path -AclObject $acl
    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule ($user, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.RemoveAccessRule($ace)  | Out-Null
    Set-ACL -Path $path -AclObject $acl
    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule ($user, "DeleteSubdirectoriesAndFiles,Write,Delete,ChangePermissions,TakeOwnership", "ContainerInherit,ObjectInherit", "None", "Deny")
    $acl.AddAccessRule($ace)
    Set-ACL -Path $path -AclObject $acl
    $acl = Get-ACL $path
    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule ($user, "ReadAndExecute, Synchronize , ReadPermissions", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($ace)
    Set-ACL -Path $path -AclObject $acl

    
}

#Checking if NLA is disabled.
#If not, disabling it.
function NLA {
    $NLARegPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    $UserAuthenticationValue = Get-ItemPropertyValue -Path $NLARegPath -Name "UserAuthentication"
    if ($UserAuthenticationValue -eq 1) {
        $global:issuescount++
        Write-Host "The NLA is enabled on the PSM." -ForegroundColor Red
        if (PromptForConfirmation) {
            Write-Host "Disabling NLA."
            Set-ItemProperty -Path $NLARegPath -Name "UserAuthentication" -Value 0
            $UserAuthenticationValue = Get-ItemPropertyValue -Path $NLARegPath -Name "UserAuthentication"
            if ($UserAuthenticationValue -eq 1) {
                Write-Host "NLA is Still enabled." -ForegroundColor Red
            }
            else {
                $global:fixcount++
                Write-Host "Disabled NLA on the PSM." -ForegroundColor Green
            }
        }
    }
    else {
        Write-Host "The NLA was disabled." -ForegroundColor Green
    }

}

#Checking and fixing the Path and ShortPath of the PSMInitSession registry key under TSAppAllowList.
function RegistryTSAppAllowList {
    $psminitsession = "$PSM_COMPONENTS_FOLDER\PSMInitSession.exe"
    $key = "Path"
    RegistryPathsFix -CorrectPath $psminitsession -value $key
    $tempObject = New-Object -ComObject Scripting.FileSystemObject 
    $shortPathGetter = $tempObject.GetFile("$psminitsession")
    $shortPath = $shortPathGetter.ShortPath
    $key = "ShortPath"
    RegistryPathsFix -CorrectPath $shortPath -value $key
}
#Fixing the registry values.
function RegistryPathsFix {
    param (
        $CorrectPath,
        $value
    )
    $KeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList\Applications\PSMInitSession"
    try {
        $path = Get-ItemPropertyValue -Path $KeyPath -Name $value 
    }
    catch {
        $path = "The key doesn't exist."
    }
    if ($path -ne $CorrectPath) {
        $global:issuescount++
        Write-Host "The value of $value in the registry is wrong. Current value: $path" -ForegroundColor Red
        if (PromptForConfirmation) {
            Write-Host "Fixing path value."
            Set-ItemProperty -Path $KeyPath -Name $value -Value $CorrectPath
            $path = Get-ItemPropertyValue -Path $KeyPath -Name $value
            if ($path -eq $CorrectPath) {
                $global:fixcount++
                Write-Host "The value of $value in the registry was fixed." -ForegroundColor Green
            }
            else {
                Write-Host "Unable to fix the value of $value in the registry." -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host "The $value of Path in the registry is correct." -ForegroundColor Green
    }
} 

#Check "Start a program on connection" GPO.
function CheckGPO {
    
    GPOtest -source "HKLM:"
    GPOtest -source "HKCU:"
    
}

#Test if there is "Start a program on connection" GPO applied.
function GPOtest {
    param (
        $source
    )
    $path = "$source\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $iniProgram = "InitialProgram"
    $workDir = "WorkDirectory"
    if ((TestRegistryValue -Path $path -Value $iniProgram) -or (TestRegistryValue -Path $path -Value $workDir)) {
        $global:issuescount++
        if ($source -eq "HKLM:") {
            Write-Host "There is Applied GPO on the following path:" -ForegroundColor Red
            Write-host "Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Remote Session Environment\Start a program on connection" -ForegroundColor Red
            Write-host "Please set it to ''Not Configured''" -ForegroundColor Red
        }
        else {
            Write-Host "There is Applied GPO on the following path:" -ForegroundColor Red
            Write-host "User Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Remote Session Environment\Start a program on connection" -ForegroundColor Red
            Write-host "Please set it to ''Not Configured''" -ForegroundColor Red
        }
    }
    else {
        if ($source -eq "HKLM:") {
            Write-Host "There is no ''Start a program on connection'' GPO applied for Computer Configuration." -ForegroundColor Green
        }
        else {
            Write-Host "There is no ''Start a program on connection'' GPO applied for User Configuration." -ForegroundColor Green
        }
    }
}

#Checking if Registry vaule exist.
function TestRegistryValue {

    param (
        $Path,
        $Value
    )
    try {
        Get-ItemProperty -Path $Path -ErrorAction Stop | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

#Check if the users is in Allow log on through Remote Desktop Services under User Rights Assignment.
function AllowLogonPolicy {
    param (
        $user
    )

    if ($DOMAIN_ACCOUNTS -and $user) {
        $userprop = (Get-AdUser -Identity $user | Select SID) -replace '@{SID=', '*' -replace '}', ''
        CheckAllowPolicy -user $user -sid $userprop  
    }
    else {
        CheckAllowPolicy -user $user -sid $user
    } 
}
#Check if the Allow log on through Remote Desktop Services policyfor specific user.
function CheckAllowPolicy {
    param (
        $user,
        $sid
    )

    $policy = "SeRemoteInteractiveLogonRight"
    $policyExplicitName = "Allow log on through Remote Desktop Services"
    $temp = New-TemporaryFile
    $allowed = $false
    secedit /export /cfg "$temp" /areas user_rights | out-null
    $output = (((Select-String "$temp" -Pattern "$policy" -Encoding unicode) -split '=', 2) -split ",").trim()
    foreach ($element in $output) {
        if ($element -eq $sid) {
            
            $allowed = $true
            Write-Host "The user $user is part of the ''$policyExplicitName'' policy." -ForegroundColor Green
            
        }
    }
    if (!$allowed) {
        $global:issuescount++
        Write-Host "The user $user is not part of the ''$policyExplicitName'' policy." -ForegroundColor Red
        Write-Host "The policy path is: " -ForegroundColor Red
        Write-Host "Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment" -ForegroundColor Red
    }
}

#Runs the tests for RDP-TCP registry keys values
function RDPTCPRegistry {
    $regPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    $keys = "fInheritAutoLogon" , "fInheritInitialProgram" , "fQueryUserConfigFromDC" , "fPromptForPassword"
    for ($i = 0; $i -lt 4; $i++) {
        $value = 1
        if ($i -eq 3) {
            $value = 0
        }
        RDPTCPCheckAndFix -regPath $regPath -key $keys[$i] -value $value
        
    }
}

#Checking and fixing the RDP-TCP registry keys values
function RDPTCPCheckAndFix {
    param (
        $regPath,
        $key,
        $value
    )
    $currentvalue = Get-ItemPropertyValue -Path $regPath -Name $key
    if ($currentvalue -ne $value) {
        $global:issuescount++
        Write-Host "The value of $key is not configured as needed." -ForegroundColor Red
        if (PromptForConfirmation) {
            Write-Host "Fixing value."
            Set-ItemProperty -Path $regPath -Name $key -Value $value
            $currentvalue = Get-ItemPropertyValue -Path $regPath -Name $key
            if ($currentvalue -ne $value) {
                Write-Host "The value of $key is still not configured as needed." -ForegroundColor Red
            }
            else {
                $global:fixcount++
                Write-Host "The value of $key was configured as needed." -ForegroundColor Green
            }
        }
    }
    else {
        Write-Host "The value of $key is configured as needed." -ForegroundColor Green
    }
    
}

#Run compare between brwoser and driver versions.
function DriverAndBrowserVersion {
    $chromeVersion = CheckBrowserVersion -browser "chrome"
    $edgeVersion = CheckBrowserVersion -browser "edge"
    if ($chromeVersion -ne "Not instlled") {
        Write-Host "The version of Chrome is: $chromeVersion"
        CheckDriverVersion -driverName "chromedriver.exe" -browserVersion $chromeVersion
    }
    else {
        Write-Host "Chrome isn't installed"    
    }

    if ($edgeVersion -ne "Not instlled") {
        Write-Host "The version of Edge is: $edgeVersion"
        CheckDriverVersion -driverName "msedgedriver.exe" -browserVersion $edgeVersion 
    }
    else {
        Write-Host "Edge isn't installed"    
    }
}
#Check if Chrome\Edge installed and the version.
function CheckBrowserVersion {
    param(
        $browser
    )
    if ($browser -eq "chrome") {
        if ((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe') -eq $true) {
            $chromeVersion = (((Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe').'(Default)').VersionInfo.ProductVersion) -split '\.')[0..2] -join '.'
            return $chromeVersion
        }
        else {
            return "Not instlled"
        }
    }
    if ($browser -eq "edge") {
        if ((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe') -eq $true) {
            $edgeVersion = (((Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe').'(Default)').VersionInfo.ProductVersion) -split '\.')[0..2] -join '.'
            return $edgeVersion
        }
        else {
            return "Not instlled"

        }
    }
}

#Check if chromedriver\msedgedriver exist in the PSM Components folder and the version.
function CheckDriverVersion {
    param (
        $driverName,
        $browserVersion
    )
    if ((Test-Path "$PSM_COMPONENTS_FOLDER\$driverName") -eq $true) {
        $versionString = & "$PSM_COMPONENTS_FOLDER\$driverName" --version
        #Regular expression to find a version number in the format of x.y.z where x, y, and z are numbers.
        $regexPattern = '\b\d+\.\d+\.\d+\b'
        if ($versionString -match $regexPattern) {
            $driverVersion = $matches[0]
            Write-Host "The version of $driverName is: $driverVersion"
            if ($driverVersion -eq $browserVersion) {
                Write-Host "The $driverName version is matched to browser version." -ForegroundColor Green
            }
            else {
                Write-Host "The $driverName version is not matched to browser version." -ForegroundColor Red
                Write-Host "Please update the $driverName driver." -ForegroundColor Red
                Write-Host "Link to an article about how to update the driver is on Recommended Articles.txt file." -ForegroundColor Yellow
                "How to download or update browser (Chrome\Edge) driver:`nhttps://cyberark.my.site.com/s/article/How-to-download-or-update-browser-Chrome-Edge-driver`n" | Out-File $ARTICLES_TEXT_FILE -Append
      
                $global:issuescount++      
            }
        }
        else {
            Write-Host "The $driverName version not found."  -ForegroundColor Red
            $global:issuescount++
        }
    }
    else {
        Write-Host "The $driverName is not exist in the PSM Components folder."  -ForegroundColor Red
        $global:issuescount++
    }
}

#Check if UAC is enabled on the PSM and disable it.
function UAC {
    
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $value = "EnableLUA"
    
    if ((Get-ItemPropertyValue -Path $path -Name $value) -eq 1) {
        $global:issuescount++
        Write-Host "The UAC is enabled on the PSM." -ForegroundColor Red
        if (PromptForConfirmation) {
            Write-Host "Disabling the UAC."
            Set-ItemProperty -Path $path -Name $value -Value 0
            if ((Get-ItemPropertyValue -Path $path -Name $value) -eq 1) {
                Write-Host "The UAC is still enabled on the PSM." -ForegroundColor Red
            }
            else {
                $global:fixcount++
                Write-Host "The UAC was disabled on the PSM." -ForegroundColor Green
            }
        }

    }
    else {
        Write-Host "The UAC is disabled on the PSM." -ForegroundColor Green
    }
}

#Run test on driver Bit.
function Browser64Bit {
    $chromeVersion = CheckBrowserVersion -browser "chrome"
    $edgeVersion = CheckBrowserVersion -browser "edge"
    if ($chromeVersion -ne "Not instlled") {
        $browserPath = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe').'(default)'
        $is32Bit = getBrowserBit -path $browserPath -process "chrome"
        if ($is32Bit) {
            Write-Host "The Chrome browser is 32-bit." -ForegroundColor Green
        }
        else {
            $global:issuescount++
            Write-Host "The Chrome browser is 64-bit - Not supported by CyberArk." -ForegroundColor Red
            Write-Host "Please download 32-bit Chrome browser." -ForegroundColor Red
            Write-Host "Download link for Google Chrome is on Recommended Articles.txt file." -ForegroundColor Yellow
            "Download link for Google Chrome (32-bit):`nhttps://chromeenterprise.google/intl/en_US/download`n" | Out-File $ARTICLES_TEXT_FILE -Append
        }
    }
    else {
        Write-Host "Chrome isn't installed"    
    }

    if ($edgeVersion -ne "Not instlled") {
        $browserPath = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe').'(default)'
        $is32Bit = getBrowserBit -path $browserPath -process "msedge"
        if ($is32Bit) {
            Write-Host "The Edge browser is 32-bit." -ForegroundColor Green
        }
        else {
            $global:issuescount++
            Write-Host "The Edge browser is 64-bit - Not supported by CyberArk." -ForegroundColor Red
            Write-Host "Please download 32-bit Edge browser." -ForegroundColor Red
            Write-Host "Download link for Microsoft Edge is on Recommended Articles.txt file." -ForegroundColor Yellow
            "Download link for Microsoft Edge (32-bit):`nhttps://www.microsoft.com/en-us/edge/business/download?form=MA13FJ`n" | Out-File $ARTICLES_TEXT_FILE -Append
        }
    }
    else {
        Write-Host "Edge isn't installed"    
    }
}

#Checks the browser Bit.
function getBrowserBit {
    param (
        $path,
        $process
    )
    Get-Process -Name $process -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 500
    Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool IsWow64Process(
    [In] System.IntPtr hProcess,
    [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
'@ -Name NativeMethods -Namespace Kernel32
    Start-Process $path -WindowStyle Hidden
    Get-Process -name $process | Foreach {
        $is32Bit = [int]0 
        if ([Kernel32.NativeMethods]::IsWow64Process($_.Handle, [ref]$is32Bit)) { 
            return $is32Bit 
            Stop-Process -Name $process -Force
        } 
        else { 
            Write-Host "Failed to get browser Bit" -ForegroundColor Red
        }
    }
    Stop-Process -Name $process -Force
    
}

#Checks the WebDispatcher version.
function WebDispatcherVersion {
    
    $dispatcherVer = (Get-Item "$PSM_COMPONENTS_FOLDER\CyberArk.PSM.WebAppDispatcher.exe").VersionInfo.ProductVersion
    Write-Host "The Web Dispatcher version is: $dispatcherVer"
    Write-Host "Please update the Dispatcher if there is a newer version."
    Write-Host "Link to the download of the latest Dispatcher is on Recommended Articles.txt file." -ForegroundColor Yellow
    "Latest Web Dispatcher download:`nhttps://cyberark.my.site.com/mplace/s/#a3550000000EiCMAA0-a3950000000jjUwAAI`n" | Out-File $ARTICLES_TEXT_FILE -Append


}

#Checkes if the PSMHardening.ps1 was run without supporting Web Apps.
function WebAppHardeningFalse {

    $computer = $env:COMPUTERNAME
    $userprop = "$computer\$PSM_SHADOW_USERS_GROUP" 
    $IE86 = "C:\Program Files (x86)\Internet Explorer\iexplore.exe"
    $IE64 = "C:\Program Files\internet explorer\iexplore.exe"
    if ((CheckPermissions -user $userprop -path $IE86) -or (CheckPermissions -user $userprop -path $IE64)) {
        Write-Host "The value for the SUPPORT_WEB_APPLICATIONS on the Hardening is set to false." -ForegroundColor Red
        Write-Host "Please set the SUPPORT_WEB_APPLICATIONS value to true on the PSMHardening.ps1 script on the Hardening folder and run the Hardening script." -ForegroundColor Red
        $global:issuescount++
    }
    else {
        Write-Host "The value for the SUPPORT_WEB_APPLICATIONS on the Hardening is set to true." -ForegroundColor Green
    }
}

#Strating the output to the log file.
Start-Transcript -Path $LOG_FILE  | Out-Null

#The running process.
if ($DOMAIN_ACCOUNTS) {

    #Installing the Active Directory module for Windows PowerShell.
    Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature | Out-Null
    write-host ""
    $IsAdmin = IsUserAdmin
    Write-Host "Connected with Domain Administrator:$IsAdmin"  -ForegroundColor Yellow
}
else {
    $IsAdmin = IsUserAdmin
    write-host ""
    Write-Host "Connected with Local Administrator:$IsAdmin"  -ForegroundColor Yellow
}
    
if ($IsAdmin) {
    $stepsCounter = 0
    write-host ""
    if ($DOMAIN_ACCOUNTS) {
        Write-Host "The configured PSM users are domain users." -ForegroundColor Black -BackgroundColor White
    }
    else {
        Write-Host "The configured PSM users are local users." -ForegroundColor Black -BackgroundColor White
    }
    Write-Host "The configured PSMConnect user name is: $PSM_CONNECT_USER." -ForegroundColor Black -BackgroundColor White
    Write-Host "The configured PSMAdminConnect user name is: $PSM_ADMIN_CONNECT_USER." -ForegroundColor Black -BackgroundColor White
    write-host ""

    $stepsCounter++
    Write-Host "Step $stepsCounter) Checking if the PSM users are locked or disabled." -ForegroundColor Yellow
    RunDisabledOrLockedOut -user $PSM_CONNECT_USER
    RunDisabledOrLockedOut -user $PSM_ADMIN_CONNECT_USER
    Write-Host ""

    $stepsCounter++
    Write-Host "Step $stepsCounter) Checking if the PSM users are set to change password on next logon." -ForegroundColor Yellow
    ChangeOnNextLogon -user $PSM_CONNECT_USER
    ChangeOnNextLogon -user $PSM_ADMIN_CONNECT_USER
    Write-Host ""

    $stepsCounter++
    Write-Host "Step $stepsCounter) Checking if the PSM service is not set to run as Local System user." -ForegroundColor Yellow
    PSMServiceLocalSystem
    Write-Host ""

    $stepsCounter++
    Write-Host "Step $stepsCounter) Checking if the PSM service is down." -ForegroundColor Yellow
    PSMService
    Write-Host ""

    if ($DOMAIN_ACCOUNTS) {
        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking if the PSM users has no ''Log On To'' permissions." -ForegroundColor Yellow
        LogOnTo -user $PSM_CONNECT_USER
        LogOnTo -user $PSM_ADMIN_CONNECT_USER
        Write-Host ""
    }

    $stepsCounter++
    Write-Host "Step $stepsCounter) Checking if the PSM users are not part of the Remote Desktop Users local group." -ForegroundColor Yellow
    RDUGroup -user $PSM_CONNECT_USER
    RDUGroup -user $PSM_ADMIN_CONNECT_USER
    Write-Host ""

    $stepsCounter++
    Write-Host "Step $stepsCounter) Checking if the  Environment tab isn't configured correctly." -ForegroundColor Yellow
    PSMinitSession -user $PSM_CONNECT_USER
    PSMinitSession -user $PSM_ADMIN_CONNECT_USER
    Write-Host ""

    $stepsCounter++
    Write-Host "Step $stepsCounter) Checking if the PSM users doesn't have permissions on the Components folder." -ForegroundColor Yellow
    FolderPermissions -user $PSM_CONNECT_USER
    FolderPermissions -user $PSM_ADMIN_CONNECT_USER
    FolderPermissions -user $PSM_SHADOW_USERS_GROUP
    Write-Host ""

    $stepsCounter++
    Write-Host "Step $stepsCounter) Checking if the NLA is enabled on the PSM." -ForegroundColor Yellow
    NLA
    Write-Host ""

    $stepsCounter++
    Write-Host "Step $stepsCounter) Checking if the TSAppAllowList registry keys are not pointing to the correct location for the PSMInitSession.exe." -ForegroundColor Yellow
    RegistryTSAppAllowList
    Write-Host ""

    $stepsCounter++
    Write-Host "Step $stepsCounter) Checking if there is ''Start a program on connection'' GPO applied on the PSM." -ForegroundColor Yellow
    CheckGPO
    Write-Host ""

    $stepsCounter++
    Write-Host "Step $stepsCounter) Checking if the PSM users are not part of the ''Allow log on through Remote Desktop Services'' policy." -ForegroundColor Yellow
    AllowLogonPolicy -user $PSM_CONNECT_USER
    AllowLogonPolicy -user $PSM_ADMIN_CONNECT_USER
    Write-Host ""

    $stepsCounter++
    Write-Host "Step $stepsCounter) Checking if the registry keys of RDP-TCP isn't configured as needed." -ForegroundColor Yellow
    RDPTCPRegistry
    Write-Host ""

    if ($WINDOWS_UPDATES_CHECK) {
        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking if the PSM server has pending Windows updates." -ForegroundColor Yellow
        WindowsUpdates
        Write-Host ""
    }
     
    if ($CHECK_WEB_APPS) {
        Write-Host ""
        Write-Host "Checking Web Apps issues:" -ForegroundColor Yellow
        Write-Host ""

        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking if the Web Driver is not updated." -ForegroundColor Yellow
        DriverAndBrowserVersion
        Write-Host ""

        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking if the UAC is enabled on the PSM." -ForegroundColor Yellow
        UAC
        Write-Host ""

        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking if the installed browser version is 32-bit." -ForegroundColor Yellow
        Browser64Bit
        Write-Host ""

        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking if the Web Dispatcher needs to be updated." -ForegroundColor Yellow
        WebDispatcherVersion
        Write-Host ""

        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking if the Hardening is set to not support Web Apps." -ForegroundColor Yellow
        WebAppHardeningFalse
        Write-Host ""
    }
   
}
else {
    if ($DOMAIN_ACCOUNTS) {
        Write-Host "Need to be connected with Domain Administrator" -ForegroundColor Red
    }
    else {
        Write-Host "Need to be connected with local Administrator" -ForegroundColor Red    
    }
}

Write-Host ""
Write-Host "CyberArk PSMFix script ended successfully." -ForegroundColor Yellow
Write-Host "The script was able to identify $issuescount issues and fix $fixcount issues." -ForegroundColor Yellow

#Stoping the output to the log file.
Stop-Transcript  | Out-Null

#Further troubleshooting recommendations.
Write-Host ""
Write-Host ""
Write-Host "If the issue persists after running the script please do the following:" -ForegroundColor Yellow -BackgroundColor Black
Write-Host "" -ForegroundColor Yellow -BackgroundColor Black
Write-Host "1) Verify proper configuration of both Object and AdminObject:"-ForegroundColor Yellow -BackgroundColor Black
Write-Host "   In the PVWA web interface go to Configurations > Privileged Session Management > Configured PSM Servers > {Server Name} > Connection Details." -ForegroundColor White -BackgroundColor Black
Write-Host "   Under Connection Details, for each PSM server defined, edit the following properties:" -ForegroundColor White -BackgroundColor Black
Write-Host "   Object - Enter the object name of the PSMConnect account, as defined in the Account Name field in the Account Details page in the PVWA." -ForegroundColor White -BackgroundColor Black
Write-Host "   AdminObject - Enter the object name of the PSMAdminConnect account, as defined in the Account Name field in the Account Details page in the PVWA." -ForegroundColor White -BackgroundColor Black
Write-Host ""-ForegroundColor Yellow -BackgroundColor Black

If ($DOMAIN_ACCOUNTS) {
    Write-Host "2) Ensure synchronization of the PSMConnect and PSMAdminConnect passwords with the vault:"-ForegroundColor Yellow -BackgroundColor Black
    Write-Host "   a. Log into the PVWA web interface with an administrator account and copy the PSMConnect password"-ForegroundColor White -BackgroundColor Black
    Write-Host "   b. Using normal Windows processes, reset the PSMConnect password in Active Directory."-ForegroundColor White -BackgroundColor Black
    Write-Host "      Users > right-click on PSMConnect > Set password > Paste the password you copied in the previous step."-ForegroundColor White -BackgroundColor Black
    Write-Host "   c. Repeat the process for the PSMAdminConnect user."-ForegroundColor White -BackgroundColor Black
    Write-Host "   d. Restart the PSM service."-ForegroundColor White -BackgroundColor Black
    Write-Host ""-ForegroundColor Yellow -BackgroundColor Black
    $domain = $env:USERDOMAIN
    Write-Host "3) Execute the Hardening script for the correct users:"-ForegroundColor Yellow -BackgroundColor Black
    Write-Host "   Run the PSMHardening.ps1 script from the Hardening folder of the PSM for the following domain users: "-ForegroundColor White -BackgroundColor Black
    Write-Host "   PSMConnect:       $domain\$PSM_CONNECT_USER"-ForegroundColor White -BackgroundColor Black
    Write-Host "   PSMAdminConnect:  $domain\$PSM_ADMIN_CONNECT_USER"-ForegroundColor White -BackgroundColor Black
}
else {
    Write-Host "2) Ensure synchronization of the PSMConnect and PSMAdminConnect passwords with the vault:"-ForegroundColor Yellow -BackgroundColor Black
    Write-Host "   a. Log into the PVWA web interface with an administrator account and copy the PSMConnect password"-ForegroundColor White -BackgroundColor Black
    Write-Host "   b. Using normal Windows processes, reset the PSMConnect password in the PSM Local users."-ForegroundColor White -BackgroundColor Black
    Write-Host "      Users > right-click on PSMConnect > Set password > Paste the password you copied in the previous step."-ForegroundColor White -BackgroundColor Black
    Write-Host "   c. Repeat the process for the PSMAdminConnect user."-ForegroundColor White -BackgroundColor Black
    Write-Host "   d. Restart the PSM service."-ForegroundColor White -BackgroundColor Black
    Write-Host ""-ForegroundColor Yellow -BackgroundColor Black
    Write-Host "3) Execute the Hardening script for the correct users:"-ForegroundColor Yellow -BackgroundColor Black
    Write-Host "   Run the PSMHardening.ps1 script from the Hardening folder of the PSM for the following local users: "-ForegroundColor White -BackgroundColor Black
    Write-Host "   PSMConnect:       $PSM_CONNECT_USER"-ForegroundColor White -BackgroundColor Black
    Write-Host "   PSMAdminConnect:  $PSM_ADMIN_CONNECT_USER"-ForegroundColor White -BackgroundColor Black
}
