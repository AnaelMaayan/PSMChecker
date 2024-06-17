
########################################################################################################################
#                       PSMChecker POWERSHELL SCRIPT
#                    -------------------------------
# General : This script helps identifying and fixing PSM common issues.
#           Parameters that may be modified:
#           1) $DOMAIN_ACCOUNTS: 
#              Change to $true if using domain PSMConnect and PSMAdminConnect.
#              Change to $false if using local PSMConnect and PSMAdminConnect.
#
#	    	2) $PSM_CONNECT_USER:
#	           Insert the PSMConnect username without Domain name.
#
#           3) $PSM_ADMIN_CONNECT_USER: 
#	           Insert the PSMAdminConnect username without Domain name.
#
#           4) $WINDOWS_UPDATES_CHECK
#              Change to $true to check pending Windows updates.
#              Change to $false to skip the testing process for pending Windows updates.
#                 
#
# Version : 2.0
# Created : April 2024
# Cyber-Ark Software Ltd.
# Anael Maayan
########################################################################################################################

########################################################################################################################
# Constants Declaration
########################################################################################################################
$DOMAIN_ACCOUNTS = $true
$PSM_CONNECT_USER = "PSMConnect"
$PSM_ADMIN_CONNECT_USER = "PSMAdminConnect"
$WINDOWS_UPDATES_CHECK = $false
