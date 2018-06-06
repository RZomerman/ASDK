<#
.SYNOPSIS
 Prepares a server for a full Azure Stack Deployment. 

 !!!!! IT WILL DESTROY ALL DATA ON YOUR DRIVES !!!!!

.DESCRIPTION
 The script has two options: USB or Network sourced 
 - it autodetects if a USB with cloudbuilder.vhdx is present on a USB drive
 IF USB sources, it can be placed in a dual-partition USB {1st being the winPE}
 2nd partition containing CloudBuilder.vhdx and ASDKUnattend.xml

 The script will download the adsk_installer and master.zip scripts 
 - if internet is found

 If the network mentioned settings are added and $override is specified
  - it will auto connect to the network and copy the required files
 Make to sure have CloudBuilder.vhdx and ASDKUnattend.xml in the same network share

If ADSKUnattend.xml does not exist, this script will create one, with default P@ssw0rd!

 .NOTES
#>


## ADDED TO SKIP THE SSL CERT CHECK MUST BE REMOVED
Add-Type @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            ServicePointManager.ServerCertificateValidationCallback += 
                delegate
                (
                    Object obj, 
                    X509Certificate certificate, 
                    X509Chain chain, 
                    SslPolicyErrors errors
                )
                {
                    return true;
                };
        }
    }
"@
 
[ServerCertificateValidationCallback]::Ignore();

## START SCRIPT
$NETWORK_WAIT_TIMEOUT_SECONDS = 120

#If speficied as true, it will ask the user to override the network settings
$override=$false

#If DellHost it will download OpenManage
$DellHost = $true

#If specified, it will go to the network share to download this..
#Username and password for network
$DVM_USERNAME = 'AzureStack'
$DVM_PASSWORD = 'AzureStack'
$ShareRoot = "\\172.16.5.9\AzureStack"
$sourceVHD="\DeployAzureStack\MASImage"
$ADSKPassword="MySuperStrongPasswordAT@123"
$version="201806062"

try
{
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
$winPEStartTime = (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')

Import-Module "$PSScriptRoot\PrepareAzureStackPOC.psm1" -Force
cls
Write-Host "      *****************************************" -foregroundColor Yellow
write-host "        Welcome to the ASDK PREPARATION SCRIPT " -foregroundColor Yellow
Write-Host "      *****************************************" -foregroundColor Yellow
write-host ""

$ActiveLog = ActivateLog
Write-LogMessage -Message "Preparing Azure Stack POC Deployment at $winPEStartTime"
Write-LogMessage -Message "Script version: $version"
Write-LogMessage -Message "Initialize WinPE"
Write-LogMessage -Message "Configure boot and storage Disks."
Write-LogMessage -Message "Finding Boot USB Drive"
    $networkSource=$true
    
    $USBDrive=Get-physicalDisk | where {$_.BusType -eq "USB"}
    If ($USBDrive) {
        $USBPresent=$true
        $DriveLetterOnUSB = (Get-partition -DiskNumber $USBDrive.DeviceId | where {$_.size -gt 2GB}).Driveletter
        $USBFreeSpace=Get-PSDrive $DriveLetterOnUSB | Select-Object Free
        $SourceDrive = ($DriveLetterOnUSB + ":")
        Write-LogMessage -Message "USB Source is $SourceDrive"
        $testPathForFile=($SourceDrive + "\CloudBuilder.vhdx")
        If (test-path $testPathForFile) {
            Write-LogMessage -Message "Local file found"
            $networkSource = $false
            $USBSource=$true
        }
    }else{
        #No source file found, trying to connect to network
        $USBPresent=$false
        Write-LogMessage -Message "No USB drive or no file found, checking network"
        Set-WinPEDeploymentPrerequisites -Network $networkSource

    #first ping to see if network comes alive or it is a standalone install
        If ($override) {
            Write-AlertMessage -Message "please enter 'download' if you wish to download the ASDK software" 
            Write-AlertMessage -Message "please provide fileshare for CloudBuilder.vhdx (eg. \\172.16.5.10\Share)"
            $ShareRoot = read-host 
            if ($ShareRoot.tolower() -ne 'download') {         
                Write-AlertMessage -Message "Please provide username and password for share"
                $Credential=get-credential 
                Write-AlertMessage -Message "please provide the path to the CloudBuilder.vhdx (eg:\DeployAzureStack\MASImage)"
                $sourceVHD = read-host 
                }else{
                    write-LogMessage -Message "download was entered manually - switching to download mode"
                    $downloadSource=$true
                    $networkSource=$false
                }
            }else{
                $secureDVMPassword = ConvertTo-SecureString -String $DVM_PASSWORD -AsPlainText -Force
                $Credential = New-Object PSCredential -ArgumentList $DVM_USERNAME, $secureDVMPassword
            }

        If (!($downloadSource)) {
            $DriveLetter = "Z"
            Write-LogMessage -Message ("validating network access to " + $ShareRoot)
            If (test-connection $ShareRoot.split('\')[2]) {
            Write-LogMessage -Message "Creating network drive $DriveLetter to source share"
                If (test-path z:\) {
                    Write-LogMessage -Message "Network drive already mounted"
                }else{
                    New-PSDrive -Name $DriveLetter -PSProvider FileSystem -Root $ShareRoot -Credential $Credential -Persist -Scope Global
                    }
                If (test-path ($DriveLetter + ':' + $sourceVHD + '\CloudBuilder.vhdx')) {
                    write-LogMessage -Message ("File found: " + $DriveLetter + ':' + $sourceVHD + '\CloudBuilder.vhdx')
                    write-LogMessage -Message "switching to network mode"
                    $networkSource = $true   
                    }else{
                        write-LogMessage -Message ($DriveLetter + ':' + $sourceVHD + '\CloudBuilder.vhdx not found, switching to download mode')
                        $networkSource = $false
                        $downloadSource=$true 
                    }

                }else{
                    write-LogMessage "Network share or file not found, switching to download mode"
                    $networkSource = $false
                    $downloadSource=$true
                }
        }

$sourceVHDLocation = ($ShareRoot + $sourceVHD)


#ADD DISCLAIMER THAT DRIVES WILL BE WIPED
if ($override) {
    write-AlertMessage -Message "This script will delete all partitions from your drives, press C to continue" 
    $confirm = read-host 
    if ($confirm.tolower() -ne 'c') {
        write-host "Drive format not confirmed - exiting" -foregroundColor Red
        exit
    } 
}
CreateDiskPartClear -ClearDiskFilePath "X:\DiskPartClear.txt"
$TargetDrive = DiskConfiguration -ClearDiskFilePath "X:\DiskPartClear.txt"
If ($TargetDrive.StartsWith("[string]") -or $TargetDrive.count -gt 2){
    $TargetDrive=$TargetDrive[6]
}

#setting variable for later-on
$Target=$TargetDrive + "\CloudBuilder.vhdx"

Write-LogMessage -Message "Downloading support scripts and applications"
$DownloadResult = DownloadScripts -SystemDrive $TargetDrive -DellHost $DellHost
If ($DownloadResult) {
    #Write-LogMessage -Message "Download complete"
}
If (!$DownloadResult) {
    Write-LogMessage -Message "No Internet connection, please manually download scripts"
}

If ($networkSource -eq $false){
    $AStackVHD = ($SourceDrive + "\CloudBuilder.vhdx") 
    $ChangeNetworkGA=($SourceDrive + "\changeNetworkGA.ps1")
    $CustomDeployment=($SourceDrive + "\customization.xml")
}

If ($networkSource) {
    $AStackVHD = $sourceVHDLocation + "\CloudBuilder.vhdx"
    $ChangeNetworkGA=($sourceVHDLocation + "\changeNetworkGA.ps1")
    $CustomDeployment=($sourceVHDLocation + "\customization.xml")
}
If ($downloadSource) {
        GetStackRemotely -SystemDrive $TargetDrive         
    
    If ($USBPresent) {
        #COPY TO USB for future use (using 1Gb extra)
        $fileobject=Get-Item $Target
        $FileSizeRequired=$fileobject.Length + 1Gb
        If ($USBPresent -and $USBFreeSpace -gt $FileSizeRequired) {
            Copy-File -from $Target -to ($DriveLetterOnUSB + ":\CloudBuilder.vhdx")
        }
    }

    }else{
        Write-LogMessage -Message "Copying $AStackVHD to '$TargetDrive'"
        copy-file -from $AStackVHD -to $Target -force

        Write-LogMessage -Message "Copying support files"
        $TargetForChangeNetwork=($TargetDrive + "\sources\changeNetworkGA.ps1")
        $TargetForCustomDeployment = ($TargetDrive + "\sources\customization.xml")
        If (test-path $changeNetworkGA) {
            If (!(test-path ($TargetDrive + "\sources"))) {
                 New-Item ($TargetDrive + "\sources") -Type directory | Out-Null
            }
            copy-file -from $ChangeNetworkGA -to $TargetForChangeNetwork -force
        }
        If (test-path $CustomDeployment) {
                If (!(test-path ($TargetDrive + "\sources"))) {
                New-Item ($TargetDrive + "\sources") -Type directory | Out-Null
            }
            copy-file -from $CustomDeployment -to $TargetForCustomDeployment -force
        }
    }
}



Write-LogMessage -Message "Configure host for VHD Boot at $Target" 
$scriptRepository = ($TargetDrive + "\sources")
    If ($networkSource -eq $false){
        $UnattendFile = ($SourceDrive + "\ASDKUnattend.xml") 
        }
    If ($networkSource) {
        $UnattendFile = $sourceVHDLocation + "\ASDKUnattend.xml"
        }
    If (!(test-path $UnattendFile)){
        CreateUnattend -File ($TargetDrive + "\ASDKUnattend.xml") -Password $ADSKPassword
        $UnattendFile = ($TargetDrive + "\ASDKUnattend.xml")
    }
Set-HostVHDBoot -BootVHDFilePath $Target -Un $UnattendFile -SourcesRoot $scriptRepository -SystemDrive $TargetDrive

Write-LogMessage -Message "Copying Logfile to fixed drive"
    $date=(Get-Date).ToString("d-M-y-h.m.s")
	$logname = ("ASDKDeploy-" + $date + ".log")
    $LogTarget=$TargetDrive + $logname
    copy-file -from 'X:\ASDKDeployment.log' -to $LogTarget

Write-LogMessage -Message "Rebooting to full OS."
"Rebooting to full OS." 
(Get-Date).ToString('yyyy/MM/dd HH:mm:ss') 
Write-host "reboot halted, please type: wpeutil reboot"
wpeutil reboot
}
catch
{
    $_

}
finally
{
    # Sleep to let the remote logs catch up
    Start-Sleep -Seconds 10
}
