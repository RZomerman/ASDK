<#
.SYNOPSIS
 Prepares a server for a full Azure Stack Deployment. 

 !!!!! IT MAY DESTROY ALL DATA ON YOUR DRIVES !!!!!

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

<#
 #<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
 #This part was added to allow local copy from an IIS server
 # with an invalid certificate. remove for production use!
 #<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
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
#<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#>

[cmdletbinding()]
    param (
        [parameter(Mandatory = $false)]
        [string]$ASDKPassword,

        [parameter(Mandatory = $false)]
        [string]$ShareUsername,

        [parameter(Mandatory = $false)]
        [string]$SharePassword,

        [parameter(Mandatory = $false)]
        [string]$NetworkVHDLocation,

        [parameter(Mandatory = $false)]
        [string]$CustomGitLocation,

        [parameter(Mandatory = $false)]
        [string]$CustomGitBranch
    )

# Define Regex for Password Complexity - needs to be at least 12 characters, with at least 1 upper case, 1 lower case, 1 number and 1 special character
$regex = @"
(?=^.{12,123}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9])(?=.*[a-z])|(?=.*[^A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9]))^.*
"@


#If speficied as true, it will ask the user to override the network settings - set to true if parameters are given
#Setting the default variables if none are given
If (!($NetworkVHDLocation)){$override=$true}
If (!($ShareUsername)){$ShareUsername = 'AzureStack'}
If (!($SharePassword)){$SharePassword = 'AzureStack'}
If (!($NetworkVHDLocation)){$NetworkVHDLocation = '\\172.16.5.9\AzureStack\DeployAzureStack\MASImage'}
If (!($CustomGitBranch)){$CustomGitBranch='master'}
If (!($CustomGitLocation)){$CustomGitLocation='RZomerman/ASDK'}

#If DellHost it will download OpenManage
$DellHost = $false

#If specified, it will go to the network share to download the Cloudbuilder.vhdx..
#Username and password for network
$version="201809173"

## START SCRIPT
$NETWORK_WAIT_TIMEOUT_SECONDS = 120
$networkSource=$true
$DISMUpdate=$false
$global:logname = $null
try
{
 If (!(test-path x:\))    {
     $LogDriveLetter='.'
 }else{
     $LogDriveLetter='X:'
 }
 $global:logname = ($LogDriveLetter + "\ASDKDeployment.log") 

 #Check if PowerShell Version is up to date.. (for Win2012R2 installs)
 If (!($PSVersionTable.PSVersion.Major -ge 5))  {
     Write-Host "Powershell version is not to up date... please install update"
     write-host "https://www.microsoft.com/en-us/download/details.aspx?id=50395"
 exit
 }
 
 $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
 $winPEStartTime = (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
 $ScriptVersion=(Get-Item .\PrepareAzureStackPOC.ps1).LastWriteTime
 Import-Module "$PSScriptRoot\PrepareAzureStackPOC.psm1" -Force
 cls
 write-host ""
write-host ""
write-host "                               _____        __                                " -ForegroundColor Green
write-host "     /\                       |_   _|      / _|                               " -ForegroundColor Yellow
write-host "    /  \    _____   _ _ __ ___  | |  _ __ | |_ _ __ __ _   ___ ___  _ __ ___  " -ForegroundColor Red
write-host "   / /\ \  |_  / | | | '__/ _ \ | | | '_ \|  _| '__/ _' | / __/ _ \| '_ ' _ \ " -ForegroundColor Cyan
write-host "  / ____ \  / /| |_| | | |  __/_| |_| | | | | | | | (_| || (_| (_) | | | | | |" -ForegroundColor DarkCyan
write-host " /_/    \_\/___|\__,_|_|  \___|_____|_| |_|_| |_|  \__,_(_)___\___/|_| |_| |_|" -ForegroundColor Magenta
write-host "                                                                              "
 write-host "                    Welcome to the ASDK PREPARATION SCRIPT " -foregroundColor Yellow
 write-host ""

 $ActiveLog = ActivateLog
 $Info=ComputerInfo
 $HostManufacturer=$Info.Manufacturer
 $HostModel=$Info.Model
 $DecomposedShare=$NetworkVHDLocation.split("\")
 $ShareRoot = ("\\" + $DecomposedShare[2] + "\" + $DecomposedShare[3])
 $sourceVHDFolder=$NetworkVHDLocation.Replace($ShareRoot,"")

 If ($sourceVHDFolder.Substring($sourceVHDFolder.Length -1) -eq "\") {
    $sourceVHDFolder=$sourceVHDFolder.Substring(0,$sourceVHDFolder.Length-1)
 }

 Write-LogMessage -Message "Preparing Azure Stack POC Deployment: $winPEStartTime"
 Write-LogMessage -Message "Script version: $version"
 Write-LogMessage -Message "Running on a $HostManufacturer $HostModel"
#System Validation checks
    CheckCPU
    CheckHyperVSupport
    CheckRam
    CheckDisks

 #If password is still set to NULL 
    If (!($ASDKPassword)) {
        Write-AlertMessage -Message "Please specify a password to use"
        $secureVMpwd = Read-Host -AsSecureString "Enter a secure ASDK password"
        $secureVMpwd2 = Read-Host -AsSecureString "Confirm secure ASDK password"
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureVMpwd)    
        $ASDKPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureVMpwd2)            
        $ASDKPasswordValidate = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
        If ($ASDKPassword -ne $ASDKPasswordValidate)  {
            Write-LogMessage -Message "Passwords do not match"
            Write-LogMessage -Message "Please restart script"
            exit
        }

        #If a password was entered, validating the complexity (ASDK will halt install if not)
        if ($ASDKPassword -cmatch $regex -eq $true) {
            Write-LogMessage -Message "Password complexity Validated" 
            # Convert plain text password to a secure string
        }elseif ($ASDKPassword -cmatch $regex -eq $false) {
            Write-LogMessage -Message "The password doesn't meet complexity requirements,"
            Write-LogMessage -Message "it needs to be at least 12 characters in length."
            Write-LogMessage -Message "Your password should also have at least 3 of the following 4 options"
            Write-LogMessage -Message "1 upper case, 1 lower case, 1 number, 1 special character."
            # Obtain new password and store as a secure string
            $secureVMpwd = Read-Host -AsSecureString "Enter a secure ASDK password"
            $secureVMpwd2 = Read-Host -AsSecureString "Confirm secure ASDK password"
            # Convert to plain text to test regex complexity
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureVMpwd)            
            $ASDKPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)  

            $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureVMpwd2)            
            $ASDKPasswordValidate = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
            If ($ASDKPassword -ne $ASDKPasswordValidate)  {
                Write-LogMessage -Message "Passwords do not match"
                exit
            }
            if ($ASDKPassword -cmatch $regex -eq $true) {
                Write-LogMessage -Message "Password complexity Validated" 
            }else{
                Write-LogMessage -Message "No valid password was entered again. Exiting process..." -ErrorAction Stop 
                exit
            }
        }
    }

 Write-LogMessage -Message "Initializing ASDK Script"
 
 If ( $HostModel.Contains("T710")){
     $DellHost = $true
     Write-LogMessage -Message "Dell hardware detected - enabled OpenManage Download"
 }
 

Write-LogMessage -Message "Configure boot and storage Disks."
#This section is added for Full OS based install. It validates exiting files and required features
 $IsWinPe = HostIsWinPE
 If (!($IsWinPe)){       
     $OSDisk=GetOSDiskForDualBoot
     If (Test-Path ($OSDisk + "\Cloudbuilder.vhdx")){
         Write-LogMessage -Message "Found CloudBuilder.vhdx on $OSDisk"
         If ($override) {
             Write-AlertMessage -Message "Would you like to delete  this file? (Default is Yes)"
             $Readhost = Read-Host " ( y / n ) " 
             Switch ($ReadHost) 
             { 
                 Y {
                     Write-LogMessage -Message  "Yes, Deleting exiting file"
                     Remove-Item -path ($OSDisk + "\Cloudbuilder.vhdx")
                     } 
                 N {
                     Write-LogMessage -Message "No, exiting script"
                     #exit
                     } 
                 Default {
                     Write-LogMessage -Message "Default, deleting file"
                     Remove-Item -path ($OSDisk + "\Cloudbuilder.vhdx")
                     } 
             }  

         }else{
             Write-LogMessage -Message "Bypass enabled: Deleting exiting file"
             Remove-Item -path ($OSDisk + "\Cloudbuilder.vhdx")
         }
     } 
 #DISM for Windows 10/2016 will be required at a later stage.. checking and installing
     If (!(Test-Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\dism.exe')){
         Write-LogMessage -Message "DISM version 10 not found.. downloading"
        $DISMUpdate=$true
     }
 }

#For all systems runtime (including WinPE)
 Write-LogMessage -Message "Finding Boot USB Drive"
 #Validate if USB drive is present
 $USBDrive=findUSB  
 If ($USBDrive -eq $false){
     #Write-LogMessage -Message "Initiating network"
     If ($IsWinPe){
         Set-WinPEDeploymentPrerequisites -Network $networkSource
     }
         #Override for manual deployments instead of fully automated
         If ($override) {
         Write-AlertMessage -Message "please enter 'download' if you wish to download the ASDK software" 
         Write-AlertMessage -Message "or provide fileshare for CloudBuilder.vhdx (eg. \\172.16.5.10\Share)"
         $ShareRoot = read-host 
         if ($ShareRoot.tolower() -ne 'download') {         
             Write-AlertMessage -Message "Please provide username and password for share"
             $Credential=get-credential 
             Write-AlertMessage -Message "please provide the path to the CloudBuilder.vhdx (eg:\DeployAzureStack\MASImage)"
             $sourceVHDFolder = read-host 
             }else{
                 write-LogMessage -Message "download was entered manually - switching to download mode"
                 $downloadSource=$true
                 $networkSource=$false
             }
         }else{
             $secureDVMPassword = ConvertTo-SecureString -String $SharePassword -AsPlainText -Force
             $Credential = New-Object PSCredential -ArgumentList $ShareUsername, $secureDVMPassword
         }
         #End of override for automated deployments

         If (!($downloadSource)) {
             $DriveLetter = "Z"
             Write-LogMessage -Message ("Validating network access to " + $ShareRoot)
             If (test-connection $ShareRoot.split('\')[2]) {
             Write-LogMessage -Message "Creating network drive $DriveLetter to source share"
                 If (test-path z:\) {
                     Write-LogMessage -Message "Network drive already mounted"
                 }else{
                     New-PSDrive -Name $DriveLetter -PSProvider FileSystem -Root $ShareRoot -Credential $Credential -Persist -Scope Global
                     }
                 #validating if customization files are present
                 If (test-path ($DriveLetter + ':' + $sourceVHDFolder + '\ChangeNetworkGA.ps1')) {
                     write-LogMessage -Message "Custom network activated"
                     $ChangeNetworkGA=($DriveLetter + ':' + $sourceVHDFolder + '\ChangeNetworkGA.ps1')
                 }
                 If (test-path ($DriveLetter + ':' + $sourceVHDFolder + '\customization.xml')) {
                     write-LogMessage -Message "Customization activated"
                     $CustomDeployment=($DriveLetter + ':' + $sourceVHDFolder + '\customization.xml')
                 }

                 If (test-path ($DriveLetter + ':' + $sourceVHDFolder + '\CloudBuilder.vhdx')) {
                     $sourceVHDLocation = ($DriveLetter + ':' + $sourceVHDFolder + '\CloudBuilder.vhdx')
                     write-LogMessage -Message ("Using: " + $sourceVHDLocation)
                     write-LogMessage -Message "Switching to network mode"
                     $networkSource = $true   
                     }else{
                         write-LogMessage -Message ($DriveLetter + ':' + $sourceVHDFolder + '\CloudBuilder.vhdx not found, switching to download mode')
                         $networkSource = $false
                         $downloadSource=$true 
                     }
                 }else{
                     write-LogMessage  -Message "Network share or file not found, switching to download mode"
                     $networkSource = $false
                     $downloadSource=$true
                 }
         }
 }else{
     write-LogMessage  -Message "USB drive present"
     $USBdriveLetter=getUSBDriveLetter -USBDrive $USBDrive
     If (test-path($USBdriveLetter + ":\CloudBuilder.vhdx")){
         write-LogMessage -Message ("Cloudbuilder found on USB: " + $USBdriveLetter + ":\CloudBuilder.vhdx")
         $sourceVHDLocation=($USBdriveLetter + ":\CloudBuilder.vhdx")
         $USBDriveSource=$true
     }else{
         $USBDriveSource=$false
     }

 }


 If ($IsWinPe) {
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
 }
 If (!($IsWinPe)) {
     #If the Boot OS is not WinPE, we still need to have the TargetDrive for placing the vhdx
     $TargetDrive = GetOSDiskForDualBoot
 }
 #setting variable for later-on
 $Target=$TargetDrive + "\CloudBuilder.vhdx"

 Write-LogMessage -Message "Downloading support scripts and applications"
 $DownloadResult = DownloadScripts -SystemDrive $TargetDrive -DellHost $DellHost -DISMUpdate $DISMUpdate -CustomGitLocation $CustomGitLocation -CustomGitBranch $CustomGitBranch
 If ($DownloadResult) {
     #Write-LogMessage -Message "Download complete"
 }
 If (!$DownloadResult) {
     Write-LogMessage -Message "No Internet connection, please manually download scripts"
 }

 #Have to set the Source for the VHD this is either USB or Network or Download or local (not root)
 #If network its sourceVHDLocation if its USB its the USBDriveLetter+:\ if its download its call download

 If ($USBDriveSource){
     $AStackVHD = $AStackVHD
 }

 If ($networkSource) {
     $AStackVHD = $sourceVHDLocation + "\CloudBuilder.vhdx"
 }

 If ($downloadSource) {
         GetStackRemotely -SystemDrive $TargetDrive         
     If ($USBDrive) {
         #COPY TO USB for future use (using 1Gb extra)
         $fileobject=Get-Item $Target
         $FileSizeRequired=$fileobject.Length + 1Gb
         #will it fit on the USB
         $USBFreeSpace=getUSBFreeSpace -USBDrive $USBDrive
         If ($USBFreeSpace -gt $FileSizeRequired) {
             write-LogMessage "Copying CloudBuilder to USB for future use"
             Copy-File -from $Target -to ($USBdriveLetter + ":\CloudBuilder.vhdx")
         }
     }

 }else{
     Write-LogMessage -Message "Copying $sourceVHDLocation to '$Target'"
     copy-file -from $sourceVHDLocation -to $Target -force
     Write-LogMessage -Message "Copying support files"
     $TargetForChangeNetwork=($TargetDrive + "\sources\ChangeNetworkGA.ps1")
     $TargetForCustomDeployment = ($TargetDrive + "\sources\customization.xml")
     If ($changeNetworkGA) {
         If (!(test-path ($TargetDrive + "\sources"))) {
              New-Item ($TargetDrive + "\sources") -Type directory | Out-Null
         }
         copy-file -from $ChangeNetworkGA -to $TargetForChangeNetwork -force
     }
     If ($CustomDeployment) {
        If (!(test-path ($TargetDrive + "\sources"))) {
            New-Item ($TargetDrive + "\sources") -Type directory | Out-Null
        }
        copy-file -from $CustomDeployment -to $TargetForCustomDeployment -force
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
         CreateUnattend -File ($TargetDrive + "\ASDKUnattend.xml") -Password $ASDKPassword
         $UnattendFile = ($TargetDrive + "\ASDKUnattend.xml")
     }

 Set-HostVHDBoot -BootVHDFilePath $Target -Un $UnattendFile -SourcesRoot $scriptRepository -SystemDrive $TargetDrive -UseWinPE $IsWinPe



 If ($IsWinPE){
     Write-LogMessage -Message "Copying Logfile to fixed drive"
     $date=(Get-Date).ToString("d-M-y-h.m.s")
     $logname = ("ASDKDeploy-" + $date + ".log")
     $LogTarget=$TargetDrive + $logname
     
     Write-LogMessage -Message "Rebooting to full OS."
     (Get-Date).ToString('yyyy/MM/dd HH:mm:ss') 
     copy-file -from 'X:\ASDKDeployment.log' -to $LogTarget

         wpeutil reboot
     }
 If (!($IsWinPe)) {write-LogMessage "Please reboot the system to continue"}
}
catch
{
 $_

}
finally
{
 # Sleep to let the remote logs catch up
 Start-Sleep -Seconds 2
}
