<#
.SYNOPSIS
    Installs Active Directory Domain Services and promotes the server to a primary/new domain controller.

.DESCRIPTION
    This script installs Active Directory Domain Services (AD DS) along with the required management tools.
    It promotes the server by creating a new Active Directory forest, where the user must specify the Domain Name,
    NetBIOS name, and provide a Directory Services Restore Mode (DSRM) password.

    Installation logs saved at C:/Logs.

    Optional parameters allow customization of the NTDS database path,
    log file path, SYSVOL folder location, and the log output directory.

.PARAMETER DomainName
    The fully qualified domain name (FQDN) for the new forest (e.g., contoso.com).

.PARAMETER NetBIOSName
    The NetBIOS name for the domain (1–15 alphanumeric characters; e.g., CONTOSO).

.PARAMETER LogPath
    The directory where the AD DS promotion log file will be stored. Default: C:\Logs

.PARAMETER DatabasePath
    The file system path to store the Active Directory database (NTDS.DIT). Default: C:\NTDS

.PARAMETER ADLogPath
    The path to store the AD DS transaction log files. Default: C:\NTDS-Logs

.PARAMETER SysvolPath
    The file system path for the SYSVOL folder (used for replication). Default: C:\SYSVOL

.EXAMPLE
    .\ADSetup.ps1 -DomainName "contoso.com" -NetBIOSName "CONTOSO" -LogPath "D:\Logs"

    This command installs AD DS, creates a new forest named contoso.com with NetBIOS name CONTOSO,
    and stores logs at D:\Logs.
#>

# Setting parameters
[CmdletBinding()]
param(
    # Domain name parameter
    [Parameter(
        Mandatory = $true, # Is mandatory.
        HelpMessage = "Specify the fully qualified domain name (e.g., example.com)."
    )]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern(
        '^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$' # Accepted characters for domain name
        )]
    [string]$DomainName,

    # Net BIOS name parameter
    [Parameter(
        Mandatory = $true, 
        HelpMessage = "Specify the NetBIOS name (1-15 alphanumeric characters)."
    )]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern(
        '^[A-Za-z0-9\-]{1,15}$'
        )]
    [string]$NetBIOSName,

    # Sets default location for these folders, can be customized.
    [Parameter()]
    [string]$LogPath = "C:\Logs", 

    [Parameter()]
    [string]$DatabasePath = "C:\NTDS",

    [Parameter()]
    [string]$ADLogPath = "C:\NTDS-Logs",

    [Parameter()]
    [string]$SysvolPath = "C:\SYSVOL"
)  

# Defining log variables
$LogPath = "C:\Logs" 
$LogFile = "$LogPath\ADSetup_log.txt" 
$TimeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture) 


# Prompt for DSRM password
$SafeAdministratorPassword = Read-Host "Enter DSRM password" -AsSecureString
$ConfirmPassword = Read-Host "Confirm DSRM password" -AsSecureString

#Function for comparing password
function Compare-Password {
    param(
        [SecureString]$First, # First input
        [SecureString]$Second # second input
    )

    if ($null -in @($First, $Second)) {
        return $false
    }
    # Formats secure strings so there are readable in memory
    $Bstr1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($First)
    $Bstr2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Second)

    try {
        $Str1 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr1)
        $Str2 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr2)
        return $Str1 -eq $Str2
    }
    # Cleans after password
    finally {
        if ($Bstr1) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr1) }
        if ($Bstr2) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr2) }
    }
}

# Validate password match
if (-not (Compare-Password -First $SafeAdministratorPassword -Second $ConfirmPassword)) {
    Write-Error "DSRM passwords do not match. Exiting."
    exit 1
}

# Checks if folder for logfile exists 
if (-Not (Test-Path -Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath
    "" | Out-File -FilePath $LogFile # Clears log upon new run
    Write-Output "$TimeStamp - ℹ️ Following folder has been created: $LogPath" | Out-File $LogFile -Append
} 
else {
    "" | Out-File -FilePath $LogFile # Clears log upon new run
    Write-Output "$TimeStamp - ℹ️ The following folder already exists: $LogPath" | Out-File $LogFile -Append
}

# Checking if AD-DomainServices are installed
$Feature = "AD-Domain-Services"
$ADCheck = Get-WindowsFeature $Feature

 if (-not $ADCheck.Installed) 
    {
        Write-Output "$TimeStamp - ❌ $Feature role is not installed" | Out-File $LogFile -Append 
        Write-Output "$TimeStamp - Installing $Feature..." | Out-File $LogFile -Append
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    }
 
 else 
    {
        Write-Output "$TimeStamp - ✅ $Feature role is already installed" | Out-File $LogFile -Append
    }

try {
    # Log the start of the operation
    Write-Output "$TimeStamp - 🚀 Starting domain controller promotion..." | Out-File $LogFile -Append

    # Log all parameters and their values
    Write-Output "$TimeStamp - 📋 Parameters being used:" | Out-File $LogFile -Append
    $paramLog = @(
        "DomainName: $DomainName"
        "DomainNetbiosName: $NetBIOSName"
        "DatabasePath: $DatabasePath"
        "LogPath: $ADLogPath"
        "SysvolPath: $SysvolPath"
        "ForestMode: WinThreshold"
        "DomainMode: WinThreshold"
        "InstallDNS: Yes"
        "SafeModeAdministratorPassword: [REDACTED]"  # Avoid logging sensitive values
        "NoRebootOnCompletion: Yes"
        "Force: Yes"
    )
    $paramLog | ForEach-Object { Write-Output "$TimeStamp -   $_" } | Out-File $LogFile -Append

    # Run the Install-ADDSForest command and capture verbose output
    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetBIOSName `
        -SafeModeAdministratorPassword $SafeAdministratorPassword `
        -InstallDns `
        -DatabasePath $DatabasePath `
        -LogPath $ADLogPath `
        -SysvolPath $SysvolPath `
        -ForestMode "WinThreshold" `
        -DomainMode "WinThreshold" `
        -NoRebootOnCompletion `
        -Force `
        -ErrorAction Stop `
        -Verbose | Tee-Object -FilePath $LogFile -Append 

    # Log success
    Write-Output "$TimeStamp - ✅ Domain controller promotion completed successfully." | Out-File $LogFile -Append
}
catch {
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    # Log the error
    Write-Output "$TimeStamp - ❌ An error occurred during domain controller promotion: $_" | Out-File $LogFile -Append
    throw
}

Restart-Computer
