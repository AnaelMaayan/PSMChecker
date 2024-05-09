
# PSMChecker

## How To use

### What the script can do:
 
#### PSM common issues:
- Check if the PSM users are locked or disabled - notify and fix.
- Check if the PSM users are set to change password on next logon - notify and fix.
- Check if the PSM service is not set to run with Local System user - notify and fix.
- Check if the PSM service is down - notify and fix.
- Check if the PSM users doesn't have "Log On To" permissions on the AD (Domain users only) - notify and fix.
- Check if the PSM users are not part of the Remote Desktop Users local group - notify and fix.
- Check if the Environment tab isn't configured correctly - notify and fix.
- Check if the PSM users doesn't have permissions on the Components folder - notify and fix.
- Check if the NLA is enabled on the PSM - notify and fix.
- Check if the TSAppAllowList registry keys are not pointing to the correct location for the PSMInitSession.exe (Path and ShortPath) - notify and fix.
- Check if there is "Start a program on connection" GPO on the PSM - notify only.
- Check if the PSM users are not part of the "Allow log on through Remote Desktop Services" policy - notify only.
- Check if the RDP-TCP registry keys values configured as needed - notify and fix.
- Check if the PSM server has pending Windows updates - notify only, needs to be enabled.

#### Web Apps common issues:
- Check if the Web Driver is not updated to the browser version (Chrome & Edge) - notify only.
- Check if UAC is enabled on the PSM - notify and fix.
- Check if the installed browser version is 64-bit (Chrome & Edge) - notify only.
- Check the version of the Web Dispatcher - notify and suggests downloading a newer version if released.
- Check if the Hardening is set to not support Web Apps - notify only.



### What to edit - need to edit the PSMCheckerConfig.ps1 file only:

**$DOMAIN_ACCOUNTS** - $true using domain users, $false if using local users. 
\
**$PSM_CONNECT_USER** - PSMConnect username without Domain name.
\
**$PSM_ADMIN_CONNECT_USER** - PSMAdminConnect username without Domain name.
\
**$WINDOWS_UPDATES_CHECK** - $true to check for pending Windows updates - $false by default.
\
**$CHECK_WEB_APPS** - $true to check Web Apps common issues, $false to skip.

Note - No need to manually input the domain name, the script automatically identifies it.
\
No modifications are required within the script itself, adjustments are only needed in the PSMCheckerConfig.ps1 file.
 

## Developer

- [@Anael Maayan](https://www.linkedin.com/in/anael-maayan/)


[![Logo](https://www.cyberark.com/wp-content/uploads/2022/12/cyberark-logo-v2.svg)](https://www.cyberark.com/)

#
![version](https://img.shields.io/badge/version-2.0-blue.svg)