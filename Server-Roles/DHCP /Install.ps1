
<#
.SYNOPSIS
    Automates the installation and configuration of the DHCP Server role on a Windows Server.

.DESCRIPTION
    This script performs the following actions:
    - Creates a log directory and log file (clears existing log on each run).
    - Checks if the DHCP Server feature is installed, and installs it if not.
    - Verifies and creates DHCP security groups (Administrators and Users) if missing.
    - Checks if the server is authorized in Active Directory; authorizes it if not.
    - Sets the ConfigurationState registry key for the DHCP role.
    - Restarts the DHCPServer service to apply changes.

.PARAMETER None
    This script requires no parameters.

.REQUIREMENTS
    - Must be run as an administrator.
    - Requires Active Directory and appropriate permissions to authorize a DHCP server.
    - Designed for use on Windows Server systems.

.OUTPUTS
    Creates or updates the log file at C:\Logs\DHCPSetup_log.txt with detailed output of each step.

.NOTES
    Author: [ConnectTek]
    Date: [06-06-2025]
    Version: 1.0

.EXAMPLE
    Run the script in PowerShell as an administrator:
    PS C:\> .\Configure-DHCP.ps1
#>

# Defining log variables
$LogPath = "C:\Logs" 
$LogFile = "$LogPath\DHCPSetup_log.txt" 
$TimeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture) 

# Checks if folder for logfile exists 
if (-Not (Test-Path -Path $LogPath))
    {
        New-Item -ItemType Directory -Path $LogPath 
        "" | Out-File -FilePath $LogFile # Clears log upon new run
        Write-Output "$TimeStamp - 📁 Creating directory for log: $LogPath" | Out-File $LogFile -Append
    } 
else 
    {
        "" | Out-File -FilePath $LogFile # Clears log upon new run
        Write-Output "$TimeStamp - ℹ️ Skipping creating directory: $LogPath" | Out-File $LogFile -Append
    }

# Checking if DHCPServer is installed
$Feature = "DHCP"
$DHCPCheck = Get-WindowsFeature $Feature

if (-not $DHCPCheck.Installed) 
    {
        Write-Output "$TimeStamp - ℹ️ $Feature role is not installed." | Out-File $LogFile -Append 
        Write-Output "$TimeStamp - 🛠️ Installing $Feature..." | Out-File $LogFile -Append

        Install-WindowsFeature -Name $Feature -IncludeManagementTools
        
        Write-Output "$TimeStamp - ℹ️ $Feature installed." | Out-File $LogFile -Append
    }

else 
    {
        Write-Output "$TimeStamp - ℹ️  $Feature already installed" | Out-File $LogFile -Append
    }

# Completes post deployment configuration 
$DHCPAdminGroup = "DHCP Administrators"
$DHCPUsersGroup  = "DHCP Users"

$AdminExists = Get-LocalGroup -Name $DHCPAdminGroup -ErrorAction SilentlyContinue
$UserExists  = Get-LocalGroup -Name $DHCPUsersGroup -ErrorAction SilentlyContinue

if (-not $AdminExists -or -not $UserExists)
     {
        Write-Output "$TimeStamp - ℹ️  DHCP groups doesn't exist." | Out-File $LogFile -Append
        netsh dhcp add securitygroups
        Write-Output "$TimeStamp - 🛠️  Creating DHCP groups..." | Out-File $LogFile -Append
    }
else
    {
        Write-Output "$TimeStamp - ℹ️  DHCP groups exists." | Out-File $LogFile -Append
    }

# Check athorization
$hostname = $env:COMPUTERNAME
$authorizedServers = Get-DhcpServerInDC -ErrorAction SilentlyContinue

if ($authorizedServers.DnsName -contains "$hostname.$env:USERDNSDOMAIN")
    {
        Write-Output "$TimeStamp - ℹ️ DHCP server is already authorized." | Out-File $LogFile -Append
    }
else 
    {
        Write-Output "$TimeStamp - 🛠️ This DHCP server is NOT authorized. Authorizing now..." | Out-File $LogFile -Append
        Add-DhcpServerInDC
    }


$regPath = "HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12"
$currentValue = Get-ItemProperty -Path $regPath -Name ConfigurationState -ErrorAction SilentlyContinue


if ($currentValue.ConfigurationState -ne 2)
    {
        Write-Output " $TimeStamp - 🛠️ Setting ConfigurationState registry key..." | Out-File $LogFile -Append
        Set-ItemProperty -Path $regPath -Name ConfigurationState -Value 2
    }
else
    {
        Write-Output "$TimeStamp - ℹ️ ConfigurationState is already set..." | Out-File $LogFile -Append
    }

Restart-Service DHCPServer



