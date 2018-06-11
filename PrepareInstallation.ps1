<#
.SYNOPSIS
 Prepares a server for a custom Azure Stack Deployment. 

.DESCRIPTION
 The script will check if a customized installation will be required
 .NOTES
#>
[CmdletBinding()]
param (
    # For ASDK deployment - this switch may be expanded in future for Multinode deployments
    [Parameter(Mandatory = $true)]
    [String] $Password
)



function Write-LogMessage 
{
  [cmdletbinding()]
    param
    (
        [string]$SystemName = "PRE-ASDK",
        
        [parameter(Mandatory = $false)]
        [string]$Message = ''
    )

  BEGIN {}
  PROCESS {
    Write-Verbose "Writing log message"
    # Function for displaying formatted log messages.  Also displays time in minutes since the script was started
    write-host (Get-Date).ToShortTimeString() -ForegroundColor Cyan -NoNewline;
    write-host ' - [' -ForegroundColor White -NoNewline;
    write-host $systemName -ForegroundColor Yellow -NoNewline;
    write-Host "]::$($message)" -ForegroundColor White;
    Add-Content -Path "C:\ASDKDeployment.log" -Value $message
  }
  END {}
} 

Write-Host "      ************************************************" -foregroundColor Yellow
write-host "        Welcome back to the ASDK PREPARATION SCRIPT " -foregroundColor Yellow
Write-Host "      ************************************************" -foregroundColor Yellow
write-host ""

# This part is for the custom deployment where we want to change the internal network
#NOTE THAT THIS HERE BELOW IS COMPLETELY WITHOUT ANY SUPPORT - AND FULLY UNSUPPORTED - DID I MENTION like **NO** SUPPORT AT ALL?
$RegionName='local'
$ExternalDomainSuffix='AzureStack.external'
$DomainFQDN='AzureStack.local'

If (test-path 'D:\sources\customization.xml') {
    write-LogMessage -Message "Customization file found"
    write-LogMessage -Message "Extracting Azure Stack scripts"
    $DeploymentScriptPath = "$env:SystemDrive\CloudDeployment\Setup\DeploySingleNode.ps1"
    if (!(Test-Path $DeploymentScriptPath))
        {
            . C:\CloudDeployment\Setup\BootstrapAzureStackDeployment.ps1
        }
    
    [xml]$CustomXML=Get-Content 'D:\sources\customization.xml'
    If (($CustomXML.custom.ExternalNetwork) -and (test-path 'D:\Sources\ChangeNetworkGA.ps1')){
        $CustomExtNetwork=$CustomXML.custom.ExternalNetwork.value
        Write-LogMessage -message "Custom External Network $CustomExtNetwork"
        cd d:\sources
        .\ChangeNetworkGA.ps1 -ExternalNetwork $CustomXML.custom.ExternalNetwork.value
    }

    If ($CustomXML.custom.RegionName){
        $RegionName=$CustomXML.custom.RegionName.value
        Write-LogMessage -Message "Custom Region set to $RegionName"
    }
    If ($CustomXML.custom.ExternalDomainSuffix.value){
        $ExternalDomainSuffix=$CustomXML.custom.ExternalDomainSuffix.value
        Write-LogMessage -Message "Custom ExternalDomainSuffix set to: $ExternalDomainSuffix"
    }
    If ($CustomXML.custom.DomainFQDN.value){
        $DomainFQDN=$CustomXML.custom.DomainFQDN.value
        Write-LogMessage -Message "Custom DomainFQDN set to: $DomainFQDN"
    }
}


#Set screen power option to infinite to avoid lockscreen
If (test-path c:\Windows\System32\powercfg.exe) {
    write-LogMessage -Message "Disabling Screen Power shutdown (so screen stays on during install) "
    cd c:\Windows\System32
    .\powercfg -change -monitor-timeout-ac 0
    write-LogMessage -Message "Setting High-Performance PowerScheme"
    POWERCFG.EXE /S SCHEME_MIN
}

#Set Windows Updates to none
Write-LogMessage -Message "Disabling Windows Update"
If (!(test-path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate)){    
    New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name WindowsUpdate
}
If (!(test-path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU)){    
    New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name AU
}
$CurrentValues=Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
If (!($CurrentValues.NoAutoUpdate)){
    New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Value 1
}
$CurrentValues=Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
If ($CurrentValues.NoAutoUpdate -ne 1) {
    New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Value 1
}

   $Connection = test-connection -computername raw.githubusercontent.com -count 1 -quiet
    If (!$Connection) {
        Write-LogMessage -Message "No Internet connection available, please manually install the applications"
    return $false
    }elseIf ($Connection) {
        Write-LogMessage -message "Installing applications"
        Write-LogMessage -message " - Installing Choco"
        # Install useful ASDK Host Apps via Chocolatey
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

        # Enable Choco Global Confirmation
        Write-Verbose " - Enabling global confirmation to streamline installs"
        choco feature enable -n allowGlobalConfirmation
  
        # Visual Studio Code
        If (!(test-path 'C:\Program Files\Microsoft VS Code')){
          Write-Verbose " - Installing VS Code with Chocolatey"
          choco install visualstudiocode
        }

        # Putty
        If (!(test-path 'C:\Program Files\PuTTY')){
          Write-Verbose " - Installing Putty with Chocolatey"
          choco install putty.install
        }

        # WinSCP
        If (!(test-path 'C:\Program Files (x86)\WinSCP\WinSCP.exe')){
          Write-Verbose " - Installing WinSCP with Chocolatey"
          choco install winscp.install 
        }

        # Chrome
        If (!(test-path 'C:\Program Files (x86)\Google')){
          Write-Verbose " - Installing Chrome with Chocolatey"
          choco install googlechrome
        }

        # Azure CLI
        If (!(test-path 'C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2')){
          Write-Verbose " - Installing latest version of Azure CLI with Chocolatey"
          choco install azure-cli
        }
    }

#Dell OpenManage Installation
If ((test-path D:\sources\openmanage.exe) -and (!(test-path 'C:\OpenManage'))){
    write-LogMessage "Extracting Dell OpenManage"
    Start-Process "D:\sources\openmanage.exe" -ArgumentList "/auto" -wait
    #Exctracts the installer to C:\OpenManage
     If (test-path  C:\OpenManage\windows\SystemsManagementx64\SysMgmtx64.msi) {
         write-LogMessage "Installing Dell OpenManage"
         Start-Process "C:\Windows\System32\MsiExec.exe" -ArgumentList "/i C:\OpenManage\windows\SystemsManagementx64\SysMgmtx64.msi /qb" -wait
     }
}



#Disabling unconnected NIC's
Get-NetAdapter | where {$_.status -eq 'Disconnected'} | Disable-NetAdapter -Confirm:$false

#Getting Variables:
$NTP=(Resolve-DnsName time.windows.com | select IPAddress).IPAddress

$NTPIP=[IPAddress]$NTP[1]
$TimeServer=$NTPIP.IPAddressToString

[array]$NIC=get-netadapter | where {$_.Status -eq 'up'}
If ($NIC.count -gt 1){
    Write-LogMessage -message "Too Many Adapters still online"
    Foreach ($Adapter in $NIC){
        $NicName=$Adapter.InterfaceAlias
        Write-LogMessage -message "$NicName is still online"
    }
}
ElseIF ($NIC.count -eq 1){
    Write-LogMessage -message "retrieving DNS settings"
    [array]$DNSArray=Get-DnsClientServerAddress -InterfaceIndex $nic[0].ifindex
    $DNSForwarder = $DNSArray[0].ServerAddresses
}
Else {
    Write-LogMessage "NO Active NIC's Found!!"
    Exit
}
#Starting the deployment
If (test-path D:\sources\AzureStack_Installer\asdk-installer.ps1) {
    $adminpass = ConvertTo-SecureString $Password -AsPlainText -Force
    cd C:\CloudDeployment\Setup
    #cd D:\sources\AzureStack_Installer
    write-LogMessage -Message "using DNS $DNSForwarder and timeServer $TimeServer"
    write-LogMessage "Ready to run the installer"
    #.\asdk-installer.ps1
    .\InstallAzureStackPOC.ps1 -AdminPassword $adminpass -UseADFS -DNSForwarder $DNSForwarder -TimeServer $TimeServer 
    #.\InstallAzureStackPOC.ps1 -AdminPassword $adminpass -UseADFS -DNSForwarder $DNSForwarder -TimeServer $TimeServer -RegionName $RegionName -DomainFQDN $DomainFQDN -ExternalDomainSuffix $ExternalDomainSuffix
}

