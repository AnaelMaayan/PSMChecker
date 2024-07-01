########################################################################################################################
#                            PSMChecker Tool
#                          --------------------
# General : This script helps identifying and fixing PSM common issues.
#
# Version : 2.0
# Cyber-Ark Software Ltd.
# Anael Maayan
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
$global:PSM_COMPONENTS_FOLDER = ""

###########################################################################################
# Functions
###########################################################################################

#Finding the PSM Components folder. 
function ComponentsFolder {
    $regPath = "HKLM:\SOFTWARE\WOW6432Node\CyberArk\CyberArk Privileged Session Manager"
    if ((Test-Path $regpath) -eq $true) {
        $homeDir = (Get-Item (Get-ItemProperty $regpath).'HomeDirectory')
        $global:PSM_COMPONENTS_FOLDER = "$homeDir\Components"
        return $true
    }
    else {
        return $false
    }
    
}

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
            Write-Host "Answer with Yes or No only."
            PromptForConfirmation
        }
    }
    
}


#Checking if the user account is disabled or locked out on the AD or the local machine.
function DisabledOrLockedOut {
    param (
        $user
    )
    if ($DOMAIN_ACCOUNTS -eq $true) {
        $ldapFilter = "(&(objectCategory=User)(sAMAccountName=$user))"
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = $ldapFilter
        $searcher.PropertiesToLoad.Add("userAccountControl")
        $searchResult = $searcher.FindOne()
        if ($searchResult -ne $null) {
            $uac = $searchResult.Properties["useraccountcontrol"][0]
            $accountEnabled = -not [Convert]::ToBoolean($uac -band 2)
            $lockoutTime = $searchResult.Properties["lockoutTime"][0]
            $accountNotLockedOut = $lockoutTime -ne 0
        }
        if (($accountEnabled -eq $false) -or ($accountNotLockedOut -eq $false))
        {
            return $true
        }
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
    if ($DOMAIN_ACCOUNTS -eq $true) {
        $ldapFilter = "(&(objectCategory=User)(sAMAccountName=$user))"
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = $ldapFilter
        $searchResult = $searcher.FindOne()
        if ($searchResult -ne $null) {
            $userDN = $searchResult.Properties["distinguishedName"][0]
            $userEntry = [ADSI]"LDAP://$userDN"
            $userEntry.Properties["lockoutTime"].Value = 0
            $userEntry.CommitChanges()
            $uac = $userEntry.Properties["userAccountControl"][0]
            $uac = $uac -band (-bnot 2)  #
            $userEntry.Properties["userAccountControl"].Value = $uac
            $userEntry.CommitChanges()
        }

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
            try {
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
            catch {
                Write-Host "Run the tool with a Domain user account that has Read/Write permissions on $user to fix the issue." -ForegroundColor Yellow
                Write-Host "User not fixed." -ForegroundColor Red

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
            try {
         
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
            catch {
                Write-Host "Run the tool with a Domain user account that has Read/Write permissions on $user to fix the issue." -ForegroundColor Yellow
                Write-Host "User not fixed." -ForegroundColor Red
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
    if ($DOMAIN_ACCOUNTS -eq $true) {
        $ldapFilter = "(&(objectCategory=User)(sAMAccountName=$user))"
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = $ldapFilter
        $searcher.PropertiesToLoad.Add("pwdLastSet") | Out-Null
        $searcher.PropertiesToLoad.Add("userAccountControl") | Out-Null
        $searchResult = $searcher.FindOne()
        if ($searchResult -ne $null) {
            $userAccountControl = $searchResult.Properties["userAccountControl"][0]
            $passwordNeverExpires = [bool]($userAccountControl -band 0x10000)
            $pwdLastSet = $searchResult.Properties["pwdLastSet"][0]
            $passwordMustChange = $pwdLastSet -eq 0
        }
        return (($passwordMustChange -eq $true) -or ($passwordNeverExpires -eq $false))
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
    if ($DOMAIN_ACCOUNTS -eq $true) {
        $ldapFilter = "(&(objectCategory=User)(sAMAccountName=$user))"
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = $ldapFilter
        $searchResult = $searcher.FindOne()
        if ($searchResult -ne $null) {
            $userDN = $searchResult.Properties["distinguishedName"][0]
            $userEntry = [ADSI]"LDAP://$userDN"
            $userEntry.Properties["pwdLastSet"].Value = -1
            $userEntry.Properties["userAccountControl"].Value = $userEntry.Properties["userAccountControl"].Value -bor 0x10000
            $userEntry.CommitChanges()
        }

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
                Write-Host "Failed to start service '$serviceName'." -ForegroundColor Red
            }
            else {
                Write-Host "Started service '$serviceName'." -ForegroundColor Green
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
        Write-Host "There are $($pendingUpdates.Count) pending Windows updates. Let them finish and restart the PSM."-ForegroundColor Red
        $global:issuescount++
    }
    else {
        Write-Host "No pending Windows updates." -ForegroundColor Green
    }   
}

#Checks if the PSM is on the account "Log On To" list on the AD.
#If not - inserting it.
function LogOnTo {
    param (
        $user
    )

    $computerName = $env:COMPUTERNAME
    $ldapFilter = "(&(objectCategory=User)(sAMAccountName=$user))"
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = $ldapFilter
    $searchResult = $searcher.FindOne()
    if ($searchResult -ne $null) {
        $userProps = $searchResult.Properties
        $userWorkstations = $userProps["userWorkstations"]    
    }
    if ($userWorkstations -ne "") {
        Write-Host "Allowed computers for user $user :"
        $allowedComputers = $userWorkstations -split ','
        foreach ($allowedComputer in $allowedComputers) {
            Write-Host " - $allowedComputer"
        }
        
        if ($allowedComputers -notcontains $computerName) {
            Write-Host "Computer $computerName is not in the list of allowed computers of user $user." -ForegroundColor Red
            $global:issuescount++
            if (PromptForConfirmation) {
                try {
                    $userWorkstationsFixed = "$userWorkstations,$computerName"
                    $ldapFilter = "(&(objectCategory=User)(sAMAccountName=$user))"
                    $searcher = New-Object DirectoryServices.DirectorySearcher
                    $searcher.Filter = $ldapFilter
                    $searchResult = $searcher.FindOne()
                    if ($searchResult -ne $null) {
                        $dn = $searchResult.Properties["distinguishedName"][0]
                    }
                    $userProps = [ADSI]"LDAP://$dn"
                    $userProps.Properties["userWorkstations"].Value = $userWorkstationsFixed
                    $userProps.CommitChanges()
                    Write-Host "Computer $computerName added to the list of allowed computers of user $user." -ForegroundColor Green
                    $global:fixcount++
                }
                catch {
                    Write-Host "Run the tool with a Domain user account that has Read/Write permissions on $user to fix the issue." -ForegroundColor Yellow
                    Write-Host "Computer $computerName not added to the list of allowed computers of user $user." -ForegroundColor Red
                }
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
    if ($DOMAIN_ACCOUNTS -eq $true) {
        $domain = $env:USERDOMAIN
        $userprop = "$domain\$user"
    }
    else {
        $userprop = $user
    }
    

    if (-not (Get-LocalGroupMember -Group $group -Member $userprop -ErrorAction SilentlyContinue)) {
        $global:issuescount++
        Write-Host "User $userprop is not part of $group group." -ForegroundColor Red
        if (PromptForConfirmation) {
            Add-LocalGroupMember -Group $group -Member $userprop
            if (-not (Get-LocalGroupMember -Group $group -Member $userprop -ErrorAction SilentlyContinue)) {
                Write-Host "Failed to add user $userprop to the $group group." -ForegroundColor Red
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


    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)   
    
}


#Checks and fixing the Environment tab of the user on the AD or the local machine.
function PSMinitSession {
    param (
        $user
    )
    $initsession = "$global:PSM_COMPONENTS_FOLDER\PSMInitSession.exe"
    $program = "TerminalServicesInitialProgram"
    $folder = "TerminalServicesWorkDirectory"
    
    RunPSMInitFix -origin $program -correct $initsession -valuename "Program file name"
    RunPSMInitFix -origin $folder -correct $global:PSM_COMPONENTS_FOLDER -valuename "Start in"
}

#Checking and fixing each line on the Environment tab of the user on the AD or the local machine.
function RunPSMInitFix {
    param (
        $origin,
        $correct,
        [string]$valuename
    )
    if ($DOMAIN_ACCOUNTS -eq $true) {
        $ldapFilter = "(&(objectCategory=User)(sAMAccountName=$user))"
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = $ldapFilter
        $searchResult = $searcher.FindOne()
        if ($searchResult -ne $null) {
            $dn = $searchResult.Properties["distinguishedName"][0]
        }

        $ext = [ADSI]"LDAP://$dn"
    }
    else {
        $ou = [adsi]"WinNT://127.0.0.1"
        $ext = $ou.psbase.get_children().find("$user")
    }
    if (CheckIfEqualInit -extuse $ext -parm $origin -path $correct) {
        $currentvalue = $ext.PSBase.InvokeGet($origin)
        Write-Host "The ''$valuename'' is not configured correctly for the user $user . Current value: $currentvalue"  -ForegroundColor Red
        $global:issuescount++
        if (PromptForConfirmation) {
            try {
                Write-Host "Fixing ''$valuename'' value."
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
            catch {
                Write-Host "Run the tool with a Domain user account that has Read/Write permissions on $user to fix the issue." -ForegroundColor Yellow
                Write-Host "''$valuename'' value not fixed."  -ForegroundColor Red

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
function ComponentsFolderPermissions {
    param (
        $user
    )
    if (($DOMAIN_ACCOUNTS -eq $true) -and $user -ne $PSM_SHADOW_USERS_GROUP) {
        $domain = $env:USERDOMAIN
        $userprop = "$domain\$user"
    }
    else {
        $computer = $env:COMPUTERNAME
        $userprop = "$computer\$user"
    }
    if (ComponentsCheckPermissions -user $userprop -path $global:PSM_COMPONENTS_FOLDER) {
        Write-Host "User $userprop doesn't have the right permissions on the Components folder." -ForegroundColor Red
        $global:issuescount++
        if (PromptForConfirmation) {
            Write-Host "Fixing permissions."
            ComponentsPermissionsFix -user $userprop -path $global:PSM_COMPONENTS_FOLDER
            if (ComponentsCheckPermissions -user $userprop -path $global:PSM_COMPONENTS_FOLDER) {
                Write-Host "Permissions not granted for user $userprop on the Components folder." -ForegroundColor Red

            }
            else {
                $global:fixcount++
                Write-Host "Permissions granted for user $userprop on the Components folder." -ForegroundColor Green            
            }
        }
    }
    else {
        Write-Host "User $userprop already has the right permissions on the Components folder." -ForegroundColor Green
    }
}

#Checking if the right Components folder permissions are granted and denied.
function ComponentsCheckPermissions {
    param (
        $user,
        $path
    )
    $acl1 = (get-acl $path).access | Where-Object identityreference -eq $user | Where-Object FileSystemRights -eq ReadAndExecute, Synchronize | Where-Object -FilterScript { $_.AccessControlType -eq 'Allow' }
    $acl2 = (get-acl $path).access | Where-Object identityreference -eq $user | Where-Object FileSystemRights -eq DeleteSubdirectoriesAndFiles, Write, Delete, ChangePermissions, TakeOwnership | Where-Object -FilterScript { $_.AccessControlType -eq 'Deny' }
    return ($acl1 -eq $null -and $acl2 -eq $null) 
    
}

#Granting and denying the Components folder permissions.
function ComponentsPermissionsFix {
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

#Checking and fixing the Recordings folder permissions for PSMConnect user and Shadow Users group.
function RecordingsFolderPermissions {
    param (
        $user
    )
    $regPath = "HKLM:\SOFTWARE\WOW6432Node\CyberArk\CyberArk Privileged Session Manager"
    if ((Test-Path $regpath) -eq $true) {
        $homeDir = (Get-Item (Get-ItemProperty $regpath).'HomeDirectory')
        $PSMRecordingsFolder = "$homeDir\Recordings"
    }
    if (($DOMAIN_ACCOUNTS -eq $true) -and $user -ne $PSM_SHADOW_USERS_GROUP) {
        $domain = $env:USERDOMAIN
        $userprop = "$domain\$user"
    }
    else {
        $computer = $env:COMPUTERNAME
        $userprop = "$computer\$user"
    }
    if (RecordingsCheckPermissions -user $userprop -path $PSMRecordingsFolder) {
        Write-Host "User $userprop doesn't have the right permissions on the Recordings folder." -ForegroundColor Red
        $global:issuescount++
        if (PromptForConfirmation) {
            Write-Host "Fixing permissions."
            RecordingsPermissionsFix -user $userprop -path $PSMRecordingsFolder
            if (RecordingsCheckPermissions -user $userprop -path $PSMRecordingsFolder) {
                Write-Host "Permissions not granted for user $userprop on the Recordings folder." -ForegroundColor Red

            }
            else {
                $global:fixcount++
                Write-Host "Permissions granted for user $userprop  on the Recordings folder." -ForegroundColor Green            
            }
        }
    }
    else {
        Write-Host "User $userprop already has the right permissions on the Recordings folder." -ForegroundColor Green
    }
}

#Checking if the right Recordings folder permissions are granted and denied.
function RecordingsCheckPermissions {
    param (
        $user,
        $path
    )
    $acl1 = (get-acl $path).access | Where-Object identityreference -eq $user | Where-Object FileSystemRights -eq CreateFiles, Synchronize, ReadData | Where-Object -FilterScript { $_.AccessControlType -eq 'Allow' }
    $acl2 = (get-acl $path).access | Where-Object identityreference -eq $user | Where-Object FileSystemRights -eq AppendData, ReadExtendedAttributes, WriteExtendedAttributes, ExecuteFile, DeleteSubdirectoriesAndFiles, ReadAttributes, WriteAttributes, Delete, ReadPermissions, ChangePermissions, TakeOwnership | Where-Object -FilterScript { $_.AccessControlType -eq 'Deny' }
    return ($acl1 -eq $null -and $acl2 -eq $null) 
}

#Granting and denying the Recordings folder permissions.
function RecordingsPermissionsFix {
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
    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule ($user, "AppendData,ReadExtendedAttributes,WriteExtendedAttributes,ExecuteFile,DeleteSubdirectoriesAndFiles,ReadAttributes,WriteAttributes,Delete,ReadPermissions,ChangePermissions,TakeOwnership", "ContainerInherit,ObjectInherit", "None", "Deny")
    $acl.AddAccessRule($ace)
    Set-ACL -Path $path -AclObject $acl
    $acl = Get-ACL $path
    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule ($user, "CreateFiles, Synchronize, ReadData", "ObjectInherit", "NoPropagateInherit", "Allow")
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
        Write-Host "NLA is enabled on the PSM." -ForegroundColor Red
        if (PromptForConfirmation) {
            Write-Host "Disabling NLA."
            Set-ItemProperty -Path $NLARegPath -Name "UserAuthentication" -Value 0
            $UserAuthenticationValue = Get-ItemPropertyValue -Path $NLARegPath -Name "UserAuthentication"
            if ($UserAuthenticationValue -eq 1) {
                Write-Host "Failed to disable, NLA is still enabled." -ForegroundColor Red
            }
            else {
                $global:fixcount++
                Write-Host "Disabled NLA on the PSM." -ForegroundColor Green
            }
        }
    }
    else {
        Write-Host "The NLA is disabled." -ForegroundColor Green
    }

}

#Checking and fixing the Path and ShortPath of the PSMInitSession registry key under TSAppAllowList.
function RegistryTSAppAllowList {
    $psminitsession = "$global:PSM_COMPONENTS_FOLDER\PSMInitSession.exe"
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
        Write-Host "The value of $value in the registry is incorrect. Current value: $path" -ForegroundColor Red
        if (PromptForConfirmation) {
            Write-Host "Fixing $key value."
            Set-ItemProperty -Path $KeyPath -Name $value -Value $CorrectPath
            $path = Get-ItemPropertyValue -Path $KeyPath -Name $value
            if ($path -eq $CorrectPath) {
                $global:fixcount++
                Write-Host "The value of $value in the registry fixed." -ForegroundColor Green
            }
            else {
                Write-Host "Failed to fix the value of $value in the registry." -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host "The value of $value in the registry is correct." -ForegroundColor Green
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
            Write-Host "GPO applied at path:" -ForegroundColor Red
            Write-host "Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Remote Session Environment\Start a program on connection" -ForegroundColor Red
            Write-host "Set it to ''Not Configured''" -ForegroundColor Red
        }
        else {
            Write-Host "GPO applied at path:" -ForegroundColor Red
            Write-host "User Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Remote Session Environment\Start a program on connection" -ForegroundColor Red
            Write-host "Please set it to ''Not Configured''" -ForegroundColor Red
        }
    }
    else {
        if ($source -eq "HKLM:") {
            Write-Host "No ''Start a program on connection'' GPO applied for Computer Configuration." -ForegroundColor Green
        }
        else {
            Write-Host "No ''Start a program on connection'' GPO applied for User Configuration." -ForegroundColor Green
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

    if (($DOMAIN_ACCOUNTS -eq $true) -and $user) {
        
        $ldapFilter = "(&(objectCategory=User)(sAMAccountName=$user))"
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = $ldapFilter
        $searchResult = $searcher.FindOne()
        if ($searchResult -ne $null) {
            $userSID = $searchResult.Properties["objectsid"][0]
            $userSIDString = (New-Object System.Security.Principal.SecurityIdentifier($userSID, 0)).Value

            $modifiedSID = $userSIDString -replace 'S-', '*S-' -replace '}', ''
        }
        CheckAllowPolicy -user $user -sid $modifiedSID  
    }
    else {
        CheckAllowPolicy -user $user -sid $user
    } 
}
#Check if the Allow log on through Remote Desktop Services policy for specific user.
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
            Write-Host "User $user is part of the ''$policyExplicitName'' policy." -ForegroundColor Green
            
        }
    }
    if (!$allowed) {
        $global:issuescount++
        Write-Host "User $user is not part of the ''$policyExplicitName'' policy." -ForegroundColor Red
        Write-Host "Add user $user to the policy. Policy path: " -ForegroundColor Red
        Write-Host "Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment" -ForegroundColor Red
    }
}

#Runs the tests for RDP-TCP registry keys values.
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

#Checking and fixing the RDP-TCP registry keys values.
function RDPTCPCheckAndFix {
    param (
        $regPath,
        $key,
        $value
    )
    $currentvalue = Get-ItemPropertyValue -Path $regPath -Name $key
    if ($currentvalue -ne $value) {
        $global:issuescount++
        Write-Host "The value of $key is incorrect." -ForegroundColor Red
        if (PromptForConfirmation) {
            Write-Host "Fixing value."
            Set-ItemProperty -Path $regPath -Name $key -Value $value
            $currentvalue = Get-ItemPropertyValue -Path $regPath -Name $key
            if ($currentvalue -ne $value) {
                Write-Host "Failed to fix the value of $keu in the registry." -ForegroundColor Red
            }
            else {
                $global:fixcount++
                Write-Host "The value of $key fixed." -ForegroundColor Green
            }
        }
    }
    else {
        Write-Host "The value of $key is configured correctly." -ForegroundColor Green
    }
    
}

#Checking if the PSMInitSession.exe is published as RemoteApp.
function CheckIfPublished {
    $init = "$global:PSM_COMPONENTS_FOLDER\PSMInitSession.exe"
    if ((Get-RDRemoteApp | select-object -ExpandProperty FilePath) -contains $init) {
        Write-Host "PSMInitSession.exe is published as a RemoteApp Program." -ForegroundColor Green
        return $true
    }
    else {
        $global:issuescount++
        Write-Host "PSMInitSession.exe is not published as a RemoteApp Program." -ForegroundColor Red
        Write-Host "Link to publish PSMInitSession as RemoteApp Program in Recommended Articles.txt." -ForegroundColor Yellow
        "How to publish PSMInitSession as a RemoteApp Program:`nhttps://cyberark.my.site.com/s/article/Publish-PSMInitSession-as-a-RemoteApp-Program`n" | Out-File $ARTICLES_TEXT_FILE -Append
        return $false
    }
}

#Run compare between brwoser and driver versions.
function DriverAndBrowserVersion {
    $chromeVersion = CheckBrowserVersion -browser "chrome"
    $edgeVersion = CheckBrowserVersion -browser "edge"
    if ($chromeVersion -ne "Not instlled") {
        Write-Host "Chrome version: $chromeVersion"
        CheckDriverVersion -driverName "chromedriver.exe" -browserVersion $chromeVersion
    }
    else {
        Write-Host "Chrome isn't installed"    
    }

    if ($edgeVersion -ne "Not instlled") {
        Write-Host "Edge version: $edgeVersion"
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
    if ((Test-Path "$global:PSM_COMPONENTS_FOLDER\$driverName") -eq $true) {
        $versionString = & "$global:PSM_COMPONENTS_FOLDER\$driverName" --version
        #Regular expression to find a version number in the format of x.y.z where x, y, and z are numbers.
        $regexPattern = '\b\d+\.\d+\.\d+\b'
        if ($versionString -match $regexPattern) {
            $driverVersion = $matches[0]
            Write-Host "$driverName version: $driverVersion"
            if ($driverVersion -eq $browserVersion) {
                Write-Host "$driverName version matches browser version." -ForegroundColor Green
            }
            else {
                Write-Host "$driverName version doesn't match browser version." -ForegroundColor Red
                Write-Host "Update the $driverName driver." -ForegroundColor Red
                Write-Host "Link to an article about how to update the driver in Recommended Articles.txt file." -ForegroundColor Yellow
                "How to download or update browser (Chrome\Edge) driver:`nhttps://cyberark.my.site.com/s/article/How-to-download-or-update-browser-Chrome-Edge-driver`n" | Out-File $ARTICLES_TEXT_FILE -Append
      
                $global:issuescount++      
            }
        }
        else {
            Write-Host "$driverName version not found."  -ForegroundColor Red
            $global:issuescount++
        }
    }
    else {
        Write-Host "$driverName not found PSM Components folder."  -ForegroundColor Red
        Write-Host "Download the $driverName driver." -ForegroundColor Red
        Write-Host "Link to an article about how to download the driver in Recommended Articles.txt file." -ForegroundColor Yellow
        "How to download or update browser (Chrome\Edge) driver:`nhttps://cyberark.my.site.com/s/article/How-to-download-or-update-browser-Chrome-Edge-driver`n" | Out-File $ARTICLES_TEXT_FILE -Append
        $global:issuescount++
    }
}

#Check if UAC is enabled on the PSM and disable it.
function UAC {
    
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $value = "EnableLUA"
    
    if ((Get-ItemPropertyValue -Path $path -Name $value) -eq 1) {
        $global:issuescount++
        Write-Host "UAC is enabled on the PSM." -ForegroundColor Red
        if (PromptForConfirmation) {
            Write-Host "Disablin UAC."
            Set-ItemProperty -Path $path -Name $value -Value 0
            if ((Get-ItemPropertyValue -Path $path -Name $value) -eq 1) {
                Write-Host "UAC is still enabled on the PSM." -ForegroundColor Red
            }
            else {
                $global:fixcount++
                Write-Host "UAC was disabled on the PSM." -ForegroundColor Green
            }
        }

    }
    else {
        Write-Host "UAC is disabled on the PSM." -ForegroundColor Green
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
            Write-Host "Chrome browser is 32-bit." -ForegroundColor Green
        }
        else {
            $global:issuescount++
            Write-Host "Chrome browser is 64-bit - Not supported by CyberArk." -ForegroundColor Red
            Write-Host "Download 32-bit Chrome browser." -ForegroundColor Red
            Write-Host "Download link for Google Chrome in Recommended Articles.txt file." -ForegroundColor Yellow
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
            Write-Host "Edge browser is 32-bit." -ForegroundColor Green
        }
        else {
            $global:issuescount++
            Write-Host "Edge browser is 64-bit - Not supported by CyberArk." -ForegroundColor Red
            Write-Host "Download 32-bit Edge browser." -ForegroundColor Red
            Write-Host "Download link for Microsoft Edge in Recommended Articles.txt file." -ForegroundColor Yellow
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
            Write-Host "Failed to get browser bit." -ForegroundColor Red
        }
    }
    Stop-Process -Name $process -Force
    
}

#Checks the WebDispatcher version.
function WebDispatcherVersion {
    
    $dispatcherVer = (Get-Item "$global:PSM_COMPONENTS_FOLDER\CyberArk.PSM.WebAppDispatcher.exe").VersionInfo.ProductVersion
    Write-Host "Web Dispatcher version is: $dispatcherVer"
    Write-Host "Update the Dispatcher if there is a newer version."
    Write-Host "Download link for latest Dispatcher in Recommended Articles.txt." -ForegroundColor Yellow
    "Latest Web Dispatcher download:`nhttps://cyberark.my.site.com/mplace/s/#a3550000000EiCMAA0-a3950000000jjUwAAI`n" | Out-File $ARTICLES_TEXT_FILE -Append


}

#Checkes if the PSMHardening.ps1 was run without supporting Web Apps.
function WebAppHardeningFalse {

    $computer = $env:COMPUTERNAME
    $userprop = "$computer\$PSM_SHADOW_USERS_GROUP" 
    $IE86 = "C:\Program Files (x86)\Internet Explorer\iexplore.exe"
    $IE64 = "C:\Program Files\internet explorer\iexplore.exe"
    if ((ComponentsCheckPermissions -user $userprop -path $IE86) -or (ComponentsCheckPermissions -user $userprop -path $IE64)) {
        Write-Host "Hardening ran with SUPPORT_WEB_APPLICATIONS set to false." -ForegroundColor Red
        Write-Host "Set SUPPORT_WEB_APPLICATIONS to true in PSMHardening.ps1 and run the Hardening script." -ForegroundColor Red
        $global:issuescount++
    }
    else {
        Write-Host "Hardening ran with SUPPORT_WEB_APPLICATIONS set to true." -ForegroundColor Green
    }
}

#Checkes if the AppLocker denied Chrome or Edge or the related drivers.
function WebAppAppLocker {
    $isBlocked = $false
    $logPath = "Microsoft-Windows-AppLocker/EXE and DLL"
    $specificFiles = @("chrome.exe", "chromedriver.exe", "msedge.exe", "msedgedriver.exe")
    $latestTimestamps = @{}
    $events = Get-WinEvent -LogName $logPath -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 8004 }

    foreach ($event in $events) {
        $message = $event.Message
        $timestamp = $event.TimeCreated
        if ($message -match "\\([^\\]+\.exe)\s*was prevented from running\.$") {
            $fileName = $matches[1]
            if ($specificFiles -contains $fileName) {
                if ($timestamp -gt $latestTimestamps[$fileName]) {
                    $latestTimestamps[$fileName] = $timestamp
                }
            }
        }
    }
    foreach ($file in $specificFiles) {
        $timestamp = $latestTimestamps[$file]
        if ($timestamp -ne $null) {
            Write-Host "$file denied by the AppLocker at $($timestamp.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Red
            $isBlocked = $true

        }
    } 
    if ($isBlocked -eq $true) {
        Write-Host "Link to to an article with the required rules in Recommended Articles.txt file." -ForegroundColor Yellow
        "Applocker rules for Chrome or Edge and the related drivers - Step 4:`nhttps://cyberark.my.site.com/s/article/PSM-WebApp-Connection-Is-Not-Working`n" | Out-File $ARTICLES_TEXT_FILE -Append    
    }
    if ($isBlocked -eq $false) {
        Write-Host "AppLocker didn't block Chrome, Edge, or their drivers." -ForegroundColor Green
    }
    
}

#Checking if the PSM users exist.
function CheckIfUserExist {
    param (
        $user
    )
    if ($DOMAIN_ACCOUNTS -eq $true) {
        try {
            $ldapFilter = "(&(objectCategory=User)(sAMAccountName=$user))"
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = $ldapFilter
            $searchResult = $searcher.FindOne()
            $searchResult.GetDirectoryEntry()
            return $true
        }
        catch{
            Write-Host "User $user not found in AD." -ForegroundColor Red
            return $false
        }
    }
    elseif ($DOMAIN_ACCOUNTS -eq $false) {
        if ( ((Get-LocalUser).Name -Contains $user) -eq $true) {
            return $true
        }
        else {
            Write-Host "User $user not found in Local users." -ForegroundColor Red
            return $false
        }
    }
}

#The running process of users and Windows.
function UsersAndWindowsConfigs {
    $domainAccountsBool
    $IsAdmin = IsUserAdmin
    if ($DOMAIN_ACCOUNTS -eq $true) {
        $domainAccountsBool = $true
        Write-Host ""
        Write-Host "Connected with Local Administrator: $IsAdmin"  -ForegroundColor Yellow
    }
    elseif ($DOMAIN_ACCOUNTS -eq $false) {
        $domainAccountsBool = $true
        Write-Host ""
        Write-Host "Connected with Local Administrator: $IsAdmin"  -ForegroundColor Yellow
    }
    else {
        $domainAccountsBool = $false
    }
    if (($IsAdmin -eq $true) -and ($domainAccountsBool -eq $true)) {
        $stepsCounter = 0
        write-host ""
        if ($DOMAIN_ACCOUNTS -eq $true) {
            Write-Host "The configured PSM users are domain users." -ForegroundColor Black -BackgroundColor White
        }
        else {
            Write-Host "The configured PSM users are local users." -ForegroundColor Black -BackgroundColor White
        }
        Write-Host "PSMConnect user name: $PSM_CONNECT_USER." -ForegroundColor Black -BackgroundColor White
        Write-Host "SMAdminConnect user name: $PSM_ADMIN_CONNECT_USER." -ForegroundColor Black -BackgroundColor White
        Write-Host "PSM Components folder path: $global:PSM_COMPONENTS_FOLDER" -ForegroundColor Black -BackgroundColor White
        write-host ""
        $PSMConnExist = CheckIfUserExist -user $PSM_CONNECT_USER
        $PSMAdmConnExist = CheckIfUserExist -user $PSM_ADMIN_CONNECT_USER
        if (($PSMConnExist -eq $true) -and ($PSMAdmConnExist -eq $true)) {
        
            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if PSM users are not locked or disabled." -ForegroundColor Yellow
            RunDisabledOrLockedOut -user $PSM_CONNECT_USER
            RunDisabledOrLockedOut -user $PSM_ADMIN_CONNECT_USER
            Write-Host ""
    
            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if PSM users are not set to change password at next logon." -ForegroundColor Yellow
            ChangeOnNextLogon -user $PSM_CONNECT_USER
            ChangeOnNextLogon -user $PSM_ADMIN_CONNECT_USER
            Write-Host ""

            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if Environment tab is configured correctly." -ForegroundColor Yellow
            PSMinitSession -user $PSM_CONNECT_USER
            PSMinitSession -user $PSM_ADMIN_CONNECT_USER
            Write-Host ""
    
            if ($DOMAIN_ACCOUNTS -eq $true) {
                $stepsCounter++
                Write-Host "Step $stepsCounter) Checking if PSM users have ''Log On To'' permissions to the PSM." -ForegroundColor Yellow
                LogOnTo -user $PSM_CONNECT_USER
                LogOnTo -user $PSM_ADMIN_CONNECT_USER
                Write-Host ""
            }

            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if PSM service is set to run as Local System user." -ForegroundColor Yellow
            PSMServiceLocalSystem
            Write-Host ""
    
            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if PSM service is running." -ForegroundColor Yellow
            PSMService
            Write-Host ""
            
            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if PSM users are in the Remote Desktop Users local group." -ForegroundColor Yellow
            RDUGroup -user $PSM_CONNECT_USER
            RDUGroup -user $PSM_ADMIN_CONNECT_USER
            Write-Host ""
    
            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if PSM users have permissions on the Components folder." -ForegroundColor Yellow
            ComponentsFolderPermissions -user $PSM_CONNECT_USER
            ComponentsFolderPermissions -user $PSM_ADMIN_CONNECT_USER
            ComponentsFolderPermissions -user $PSM_SHADOW_USERS_GROUP
            Write-Host ""

            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if the PSMConnect and PSM Shadow Users group have permissions on the Recordings folder." -ForegroundColor Yellow
            RecordingsFolderPermissions -user $PSM_CONNECT_USER
            RecordingsFolderPermissions -user $PSM_SHADOW_USERS_GROUP
            Write-Host ""
    
            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if NLA is disabled on the PSM." -ForegroundColor Yellow
            NLA
            Write-Host ""
    
            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if PSMInitSession is published as a RemoteApp Program." -ForegroundColor Yellow
            $isPublished = CheckIfPublished
            Write-Host ""
    
            if ($isPublished -eq $true) {
                $stepsCounter++
                Write-Host "Step $stepsCounter) Checking if TSAppAllowList registry keys point to the correct location for PSMInitSession.exe." -ForegroundColor Yellow
                RegistryTSAppAllowList
                Write-Host ""
            }
    
            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if ''Start a program on connection'' GPO is not applied on the PSM." -ForegroundColor Yellow
            CheckGPO
            Write-Host ""
    
            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if PSM users are in ''Allow log on through Remote Desktop Services'' policy." -ForegroundColor Yellow
            AllowLogonPolicy -user $PSM_CONNECT_USER
            AllowLogonPolicy -user $PSM_ADMIN_CONNECT_USER
            Write-Host ""
    
            $stepsCounter++
            Write-Host "Step $stepsCounter) Checking if RDP-TCP registry keys are configured correctly." -ForegroundColor Yellow
            RDPTCPRegistry
            Write-Host ""
        
    
            if ($WINDOWS_UPDATES_CHECK -eq $true) {
                $stepsCounter++
                Write-Host "Step $stepsCounter) Checking if the PSM server has pending Windows updates." -ForegroundColor Yellow
                WindowsUpdates
                Write-Host ""
            }
        }
    }
    else {
        if ($IsAdmin -eq $false) {
            Write-Host "Must be connected with local Administrator." -ForegroundColor Red    
        }
        if ($domainAccountsBool -eq $false) {
            Write-Host "DOMAIN_ACCOUNTS in PSMCheckerConfig.ps1 must be set to $true or $false." -ForegroundColor Red    
        }

    }   
}

#The running process for Web Apps.
function WebAppsConfigs {
    $IsAdmin = IsUserAdmin
    Write-Host ""
    Write-Host "Connected with Local Administrator: $IsAdmin"  -ForegroundColor Yellow
    if ($IsAdmin -eq $true) {
        $stepsCounter = 0
        Write-Host ""
        Write-Host "Checking Web Apps issues:" -ForegroundColor Yellow
        Write-Host ""

        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking if Web Driver matches browser version." -ForegroundColor Yellow
        DriverAndBrowserVersion
        Write-Host ""

        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking if UAC is disabled on the PSM." -ForegroundColor Yellow
        UAC
        Write-Host ""

        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking if installed browser version is 32-bit." -ForegroundColor Yellow
        Browser64Bit
        Write-Host ""

        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking Web Dispatcher version." -ForegroundColor Yellow
        WebDispatcherVersion
        Write-Host ""

        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking if Hardening supports Web Apps." -ForegroundColor Yellow
        WebAppHardeningFalse
        Write-Host ""

        $stepsCounter++
        Write-Host "Step $stepsCounter) Checking if AppLocker blocked Chrome, Edge, or their drivers." -ForegroundColor Yellow
        WebAppAppLocker
        Write-Host ""
    }
    else {
        
        Write-Host "Must be connected with local Administrator." -ForegroundColor Red    
    }
}
#The menu of the tool
function Menu {
    Write-Host "1. Check and fix PSM users and Windows related issues." -BackgroundColor Black
    Write-Host "2. Check and fix Web Apps issues." -BackgroundColor Black
    Write-Host "Type ''exit'' to end the tool." -BackgroundColor Black
    $input = Read-Host "`nPlease choose one of the options" 
    switch ($input) {
        '1' { 
            UsersAndWindowsConfigs
            Write-Host ""
            Menu
        }
        '2' {
            WebAppsConfigs
            Write-Host ""
            Menu
        }
        'exit' {
        }
        Default {
            Write-Host "Answer with the number of one option." -BackgroundColor Black
            Write-Host ""
            Menu
        }
    }
    
}
#Strating the output to the log file.
Start-Transcript -Path $LOG_FILE  | Out-Null

#The running process - Main Function.

$componentsFolderCheck = ComponentsFolder
if ($componentsFolderCheck -eq $false) {
    Write-Host "The script must run on PSM server." -ForegroundColor Red
    exit
}

Write-Host "`nThank you for running PSMChecker Tool." -ForegroundColor Yellow -BackgroundColor Black
Menu

Write-Host ""
Write-Host "CyberArk PSMChecker Tool ended successfully." -ForegroundColor Yellow
Write-Host "The PSMChecker Tool identified  $issuescount issues and fix $fixcount issues." -ForegroundColor Yellow

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

If ($DOMAIN_ACCOUNTS -eq $true) {
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
