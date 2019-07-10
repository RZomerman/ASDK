    <#
    .SYNOPSIS
        Creating a WinPE ISO image to be used for the automated deployment of ASDK

    .DESCRIPTION
        Creates an ISO image to be used for deploying ASDK

    .PARAMETER TargetDirectory
        $TargetDirectory where the image must be created 
    
        Note
            About 500Mb free space required (is not checked)

    .PARAMETER ASDKPassword
        The password to be used for the deployment

    .PARAMETER NetworkVHDLocation (optional)
        The network location where the scripts can find the cloudbuilder.vhdx
        \\192.168.0.1\share\image\   (without cloudbuilder.vhdx filename)

    .PARAMETER ShareUsername (optional)
        The username for a network share (if specified)

    .PARAMETER SharePassword (optional)
        The password for the username to access the share

    .PARAMETER CustomGitBranch
        If not using the master branch, can allocate another branch
        master, development, etc
    
    .PARAMETER CustomGitLocation
        To use your own GitHub Repository (Name/Repo)

    .PARAMETER USBMode
        Instead of creating an ISO, the script creates a bootable USB - drive will be overwritten!
    
    .PARAMETER USBDrive
        Used in combination with USBMode ; requires driveletter in the form of G: (not G:\)
        
    .PARAMETER USBDrive
        Used in combination with USBMode ; reuses an existing image to create multiple USB drives
    
    .EXAMPLE
        CreateASDKDeploymentIso.ps1 -TargetDirectory d:\winpe_asdk


    .FUNCTIONALITY
        PowerShell Language

    #>
[cmdletbinding()]
    param (
        [string]$TargetDirectory,

        [parameter(Mandatory = $true)]
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
        [string]$CustomGitBranch,

        [parameter(Mandatory = $false)]
        [boolean]$USBMode,

        [parameter(Mandatory = $false)]
        [string]$USBDrive,

        [parameter(Mandatory = $false)]
        [boolean]$Reuse
    )

#$TargetDirectory='d:\winpe_amd81'
$version="201907071"


# Define Regex for Password Complexity - needs to be at least 12 characters, with at least 1 upper case, 1 lower case, 1 number and 1 special character
$regex = @"
(?=^.{12,123}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9])(?=.*[a-z])|(?=.*[^A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9]))^.*
"@

$TargetBatchFile=($env:TEMP + '\PreparewinPE.bat')
$ClosingISOBatchFile=($env:TEMP + '\PrepareISO.bat')
$ClosingUSBBatchFile=($env:TEMP + '\PrepareUSB.bat')

If (($NetworkVHDLocation) -and ((!($SharePassword) -or (!($ShareUsername))))) {
    Write-host "Please provide all parameters"
    exit
}

If (($USBMode) -and (!($USBDrive))) {
    Write-host "Please provide USB Drive in the form of P:"
    exit
}

If ($USBDrive) {
    $USBMode=$true
}

If (!($CustomGitBranch)){$CustomGitBranch='master'}
If (!($CustomGitLocation)){$CustomGitLocation='RZomerman/ASDK'}



function Write-LogMessage {
    [cmdletbinding()]
      param
      (
          [string]$SystemName = "PRE-ASDK",
          
          [parameter(Mandatory = $false)]
          [string]$Message = '',

          [parameter(Mandatory = $false)]
          [boolean]$NoNewLine
    )
  
    BEGIN {}
    PROCESS {
      Write-Verbose "Writing log message"
      # Function for displaying formatted log messages.  Also displays time in minutes since the script was started
        write-host (Get-Date).ToShortTimeString() -ForegroundColor Cyan -NoNewline;
        write-host ' - [' -ForegroundColor White -NoNewline;
        write-host $systemName -ForegroundColor Yellow -NoNewline;
      If ($NoNewLine) {
        write-Host "]::$($message)" -ForegroundColor White -NoNewline;
      }Else{
        write-Host "]::$($message)" -ForegroundColor White;
      }
    }
    END {}
  } 


Function Get-FileContents {
    Param(
    [string]$file
    )
    Process
    {
        $read = New-Object System.IO.StreamReader($file)
        $serverarray = @()

        while (($line = $read.ReadLine()) -ne $null)
        {
            $serverarray += $line
        }

        $read.Dispose()
        return $serverarray
    }
}

Function IsUSBDone ($USBDrive){
        Write-Host  "Writing drive" -NoNewline 
        While (!(test-path ($USBDrive + "\sources\boot.wim"))) {
            write-host "." -NoNewline
            start-sleep -s 3
        } 
}
Function IsDISMStillRunning {
    #This function validates if the DISM process is still running... and halts the script until it is
    While (Get-Process | where-object {$_.ProcessName -Contains "Dism"}) {
        write-host "." -NoNewline
        start-sleep -s 3
    } 
}
Function IsMakeWinPEMediaRunning{
    #This function validates if the IsMakeWinPEMediaRunning process is still running... and halts the script until it is done
    While (Get-Process | where-object {$_.ProcessName -Contains "MakeWinPEMedia"}) { 
        write-host "." -NoNewline
        start-sleep -s 2
    }   
}
function DownloadWithRetry{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $url,

        [Parameter(Mandatory=$false)]
        [string]
        $downloadLocation,
        
        [Parameter(Mandatory=$false)]
        [int]
        $retries
    )
    while($true)
    {
        try
        {
            Invoke-WebRequest $url -OutFile $downloadLocation
            break
        }
        catch
        {
            $exceptionMessage = $_.Exception.Message
            Write-Host  "Error downloading '$url': $exceptionMessage"
            if ($retries -gt 0) {
                $retries--
                Write-Host ("Waiting 10 seconds before retrying. Retries left: " + $retries)
                Start-Sleep -Seconds 10
 
            }
            else
            {
                $exception = $_.Exception
                Write-Host "Failed to download '$url': $exceptionMessage"
                break
            }
        }
    }
}


Write-Host "      *******************************" -foregroundColor Yellow
write-host "        Welcome to the ASDK BUILDER " -foregroundColor Yellow
Write-Host "      *******************************" -foregroundColor Yellow
Write-LogMessage -Message "Validating if a newer version is available."

    $localversion=$version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Connection = test-connection -computername raw.githubusercontent.com -count 1 -quiet
    If (!$Connection) {
        Write-LogMessage -Message "No Internet connection available. Using local script"
        $NoInternet=$true
    }elseIf ($Connection) {
        $Uri = 'https://raw.githubusercontent.com/RZomerman/ASDK/master/CreateASDKDeploymentIso.ps1'
        $OutFile  = ($env:TEMP + '\' + 'CreateASDKDeploymentIso.ps1')
        DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        $DownloadedFile=Get-FileContents $outfile
        Foreach ($line in $DownloadedFile) {
            If ($line -like '$version=*') {
                $version=$line.replace('$version=','')
                $version=$version.replace('"',"")
                break
            }
        }
        Write-LogMessage -Message "Downloaded file" $version
        Write-LogMessage -Message "Local file" $Localversion
        If ($version -gt $Localversion) {
            Copy-item ($env:TEMP + '\' + 'CreateASDKDeploymentIso.ps1') 'CreateASDKDeploymentIso.ps1' -force
            
            Write-LogMessage -Message "A newer version of this script was downloaded -" 
            Write-LogMessage -Message "      ***Please restart this script***"
            exit
        }
        Elseif ($version -eq $Localversion){
                Write-LogMessage -Message "Using local script"
        }
        Else{
            Write-LogMessage -Message "Using local script"
        }
    }


    Write-LogMessage -Message "Validating if running under Admin Privileges"

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    If (!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))){
        Write-LogMessage -Message "User is not administrator - forced quit" 
        exit
    }
#If a password was entered, validating the complexity (ASDK will halt install if not)
If ($ASDKPassword){
    if ($ASDKPassword -cmatch $regex -eq $true) {
        Write-LogMessage -Message "Password complexity Validated" 
        # Convert plain text password to a secure string
    }

    elseif ($ASDKPassword -cmatch $regex -eq $false) {
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
        }
        else {
            Write-LogMessage -Message "No valid password was entered again. Exiting process..." -ErrorAction Stop 
            exit
        }
    }
}

#Validating USB if USB mode is enabled
If ($USBDrive) {
    $AllRemovableDrives=gwmi win32_diskdrive | ?{$_.interfacetype -eq "USB"} | %{gwmi -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=`"$($_.DeviceID.replace('\','\\'))`"} WHERE AssocClass = Win32_DiskDriveToDiskPartition"} |  %{gwmi -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=`"$($_.DeviceID)`"} WHERE AssocClass = Win32_LogicalDiskToPartition"} | %{$_.deviceid}
    If ($AllRemovableDrives -notcontains $USBDrive) {
        Write-LogMessage "--------" -Message "Removable Drive Not Found"
        Exit
    }
}


$CopyDir=$TargetDirectory
#Validating if Windows ADK is installed
If (!(test-path "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat")) {
    Write-LogMessage -Message "Windows Assessment and Deployment Kit (Windows ADK) was not found"
        #https://go.microsoft.com/fwlink/?linkid=873065
        $Uri = 'https://go.microsoft.com/fwlink/?linkid=873065'
        $OutFile  = ($env:TEMP + '\' + 'adksetup.exe')
        If (!(Test-Path $OutFile)){
            DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        }
    #If download was successfull: install ADK features we need
    Write-LogMessage -Message "Installing Windows ADK features - this might take up to 30 minutes"
    Write-LogMessage -Message "Windows ADK will download additional components for installation"
    Write-LogMessage -Message "Windows ADK Installation will only be required once"
    Write-LogMessage -Message "Windows ADK Installation will take-up ~5.88Gb of space on your System drive"

    #creating a log directory for the installation
    If (!(test-path ($env:TEMP + "\ADKLogs"))){
        New-Item ($env:TEMP + "\ADKLogs") -Type directory | Out-Null
    }

    $adklogfile = ("ADKLog-" + (Get-Date).tostring("dd-MM-yyyy-hh-mm-ss") + ".log")
    $logFilePath=($env:TEMP + "\ADKLogs\" + $adklogfile)
    $logDirectory=('"'+ $logFilePath+ '"')
    
    $InstallArguments = ("/log $logDirectory /quiet /norestart /features OptionId.DeploymentTools OptionId.WindowsPreinstallationEnvironment")
    Start-Process -FilePath ($env:TEMP + '\' + 'adksetup.exe') -ArgumentList $InstallArguments
    Write-LogMessage -Message "Installing" -NoNewline $true
    #Waiting for the process to initialize prior to grabbing the logfile
    start-sleep 10
    
    #Monitoring the logfile to check for Exit code
    While (1 -eq 1) {
        $LogFileContents=Get-Content $logFilePath -Tail 2   
        $InstallStatus = $LogfileContents | %{$_ -match "Exit code: "}
        If ($InstallStatus -contains $true) {
            #Exit code found
            $Installcompleted = $LogfileContents | %{$_ -match "Exit code: 0x0"}
            If ($Installcompleted -contains $true) {
                #Exit code is 0x0
                Write-host "" | Out-Null
                Write-LogMessage -Message "Installation completed"
                break
            } Else {
                Write-host "" | Out-Null
                Write-LogMessage -Message "Installation Failed, please install manually"
                Write-Host -ForegroundColor Red "Windows ADK required"
                exit
            }
        }
        #sleep for 2 seconds, then check again
        Write-host "." -NoNewline
        Start-Sleep -s 10
    }
    #to avoid the . to be in front of the Write-LogMessage
    Write-host "" | Out-Null

    
}else{
#windows ADK was found
    Write-LogMessage -Message "Windows ADK found"
}

#Validating input directory
If ($TargetDirectory.Contains(" ")) {
    Write-LogMessage -Message "Input contains spaces, trimming"
    $TargetDirectory=$TargetDirectory.Replace(" ","")
    Write-LogMessage -Message "Directory to be used: $TargetDirectory"
}

#Setting Github user location
$GitHubLocation=('https://raw.githubusercontent.com/' + $CustomGitLocation + '/' + $CustomGitBranch + '/')

If ($NoInternet) {
    If ((!(Test-Path ($env:TEMP + '\' + 'Start.ps1'))) -and (!(Test-Path ($env:TEMP + '\' + 'PrepareAzureStackPOC.psm1'))) -and (!(Test-Path ($env:TEMP + '\' + 'PrepareAzureStackPOC.ps1'))) -and (!(Test-Path ($env:TEMP + '\' + 'winpe.jpg')))) {
        Write-LogMessage -Message "Local files not available in $env:TEMP" 
        Write-LogMessage -Message "this script needs to have internet to download files from GitHub"
    }
}Else{
    #Need to copy all the required files from github to temp
    Write-LogMessage -Message "Downloading scripts from GitHub"  
    Write-LogMessage -Message " - reposi: $CustomGitLocation"
    Write-LogMessage -Message " - branch: $CustomGitBranch"
    $Uri = ($GitHubLocation + 'Start.ps1')
    #write-host $uri
    $OutFile  = ($env:TEMP + '\' + 'Start.ps1')
    DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3

    $Uri = ($GitHubLocation + 'PrepareAzureStackPOC.psm1')
    #write-host $uri
    $OutFile  = ($env:TEMP + '\' + 'PrepareAzureStackPOC.psm1')
    DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3


    $Uri = ($GitHubLocation + 'PrepareAzureStackPOC.ps1')
    #write-host $uri
    $OutFile  = ($env:TEMP + '\' + 'PrepareAzureStackPOC.ps1')
    DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3


    $Uri = ($GitHubLocation + 'winpe.jpg')
    #write-host $uri
    $OutFile  = ($env:TEMP + '\' + 'winpe.jpg')
    DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
}

#Customize the ps1 if optional attributes are found
$BaseCommand='    . x:\PrepareAzureStackPOC.ps1'
If ($ShareUsername) {               
    $NewCommand=($NewCommand + " -ShareUserName " + $ShareUsername)
}
If ($SharePassword) {               
    $NewCommand=($NewCommand + " -SharePassword " + $SharePassword)
}
If ($NetworkVHDLocation){
    $NewCommand=($NewCommand + " -NetworkVHDLocation " + $NetworkVHDLocation)
}
If ($ASDKPassword){
    $NewCommand=($NewCommand + " -ASDKPassword " + $ASDKPassword)
}
If ($CustomGitLocation){
    $NewCommand=($NewCommand + " -CustomGitLocation " + $CustomGitLocation)
    $NewStartCommand=($NewStartCommand + " -CustomGitLocation " + $CustomGitLocation)
}
If ($CustomGitBranch){
    $NewCommand=($NewCommand + " -CustomGitBranch " + $CustomGitBranch)
    $NewStartCommand=($NewStartCommand + " -CustomGitBranch " + $CustomGitBranch)
}
Write-Verbose ($BaseCommand + $NewCommand)
Add-Content ($env:TEMP + '\' + 'Start.ps1') ($BaseCommand + $NewCommand)

#Creating a copy of the Deployment Toolkit cmd start script so we can add the copype.cmd to it when starting
    copy-item "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat" $TargetBatchFile 
        $batchfile = Get-Content $TargetBatchFile
        $batchfile += "`r`nREM Creating WinPE repository"
        $batchfile += "`r`ncopype.cmd amd64 $TargetDirectory"
    Set-Content -Value $batchfile -Path $TargetBatchFile -Force


#Starting the Deployment Toolkit CMD from the created batchfile - this will automatically start the copype.cmd script
    Write-LogMessage -Message "Creating WinPE on $TargetDirectory"
    If (!(test-path $TargetDirectory)) {       
            Write-LogMessage -Message "Creating base WinPE image"
            Start-Process 'C:\WINDOWS\system32\cmd.exe' -argumentlist "/k $TargetBatchFile" -Verb runAs -WindowStyle Minimized
    }else{
        Write-LogMessage -Message "Target Directory already exists"
        If (!($Reuse)) {
            Write-LogMessage -Message "Please make sure to specify a non-existing directory"
            Write-LogMessage -Message "or specify -reuse"
            Exit
        }
        If (($Reuse) -and (Test-Path ($TargetDirectory + '\media\bootmgr.efi' )) -and (!(test-path ($TargetDirectory + '\mount\windows')))) {
            Write-LogMessage -Message "Reusing existing image"
        }
        Else {
            Write-LogMessage "--------" -Message "Existing image not valid or not unmounted"
            exit
        }
#exit
    }


#/IMAGE BUILD    
If (!($Reuse)) {
    #Need to wait for the copype.cmd to be completed - last file seems to be Media\zh-tw\bootmgt.efi.mui
    $MonitorredFile=($TargetDirectory + '\Media\zh-tw\bootmgr.efi.mui')
        Write-LogMessage -Message "waiting for copy to complete"
        start-sleep -Seconds 3
        While (1 -eq 1) {
            IF (Test-Path $MonitorredFile) {
                #file exists. break loop
                write-host "" | Out-Null
                break
            }
            #sleep for 2 seconds, then check again
            Write-host "." -NoNewline
            Start-Sleep -s 2
        }

    #Mounting the image and adding the required repositories to it
        $1=('/mount-image /imagefile:' + $TargetDirectory + '\media\sources\boot.wim /index:1 /mountdir:' + $TargetDirectory + '\mount')
        $2=('/Image:' + $TargetDirectory + '\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-WMI.cab"')
        $3=('/Image:' + $TargetDirectory + '\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-NetFX.cab"')
        $4=('/Image:' + $TargetDirectory + '\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-Scripting.cab"')
        $5=('/Image:' + $TargetDirectory + '\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-PowerShell.cab"')
        $6=('/Image:' + $TargetDirectory + '\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-DismCmdlets.cab"')
        $7=('/Image:' + $TargetDirectory + '\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-StorageWMI.cab"') 
        
    #Mounting the image
        Write-LogMessage -Message "Mounting the WinPE image" -NoNewline $true
        Start-Process 'DISM' -ArgumentList $1 -WindowStyle Minimized

    #Need to check if c:\windows\system32\dism.exe is still running
    IsDISMStillRunning
        write-host "" | Out-Null
        Write-LogMessage -Message "Adding WMI package" -NoNewline $true
        Start-Process 'DISM'  -ArgumentList $2 -WindowStyle Minimized
    IsDISMStillRunning
        write-host ""
        Write-LogMessage -Message "Adding Network package" -NoNewline $true
        Start-Process 'DISM'-ArgumentList $3 -WindowStyle Minimized
    IsDISMStillRunning
        write-host ""
        Write-LogMessage -Message "Adding Scriptig package" -NoNewline $true
        Start-Process 'DISM'-ArgumentList $4 -WindowStyle Minimized
    IsDISMStillRunning
        write-host ""
        Write-LogMessage -Message "Adding Powershell package" -NoNewline $true
        Start-Process 'DISM'-ArgumentList $5 -WindowStyle Minimized
    IsDISMStillRunning
        write-host ""
        Write-LogMessage -Message "Adding DISM package" -NoNewline $true
        Start-Process 'DISM'  -ArgumentList $6 -WindowStyle Minimized
    IsDISMStillRunning
        write-host ""
        Write-LogMessage -Message "Adding Storage WMI package" -NoNewline $true
        Start-Process 'DISM' -ArgumentList $7 -WindowStyle Minimized
    IsDISMStillRunning



    #Copy the files to the mounted image
    If (test-path ($TargetDirectory + "\mount\Windows")) {
        write-host ""
        Write-LogMessage -Message "Copying files to the mounted image" -NoNewLine $true
        If (test-path ($env:TEMP + '\' + 'Start.ps1')) {
            $target=($TargetDirectory + '\mount\Start.ps1')
            write-host "." -NoNewline
            Copy-Item ($env:TEMP + '\' + 'Start.ps1') $target -Force
        }

        If (test-path ($env:TEMP + '\' + 'PrepareAzureStackPOC.ps1')) {
            $target=($TargetDirectory + '\mount\PrepareAzureStackPOC.ps1')
                write-host "." -NoNewline
                Copy-Item ($env:TEMP + '\' + 'PrepareAzureStackPOC.ps1') $target -Force
            }
        If (test-path ($env:TEMP + '\' + 'PrepareAzureStackPOC.psm1')) {
            $target=($TargetDirectory + '\mount\PrepareAzureStackPOC.psm1')
            write-host "." -NoNewline
            Copy-Item ($env:TEMP + '\' + 'PrepareAzureStackPOC.psm1') $target -Force
        }
    #need to take ownership of WinPE and delete it (to change background later on)
    write-host "" | Out-Null
    Write-LogMessage -Message "Taking ownership of background image"
        $BackgroundImage=($TargetDirectory + '\mount\Windows\System32\winpe.jpg')
        $acl=Get-Acl $BackgroundImage
        $Group = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
        $ACL.SetOwner($Group)
        Set-Acl -Path $BackgroundImage -AclObject $acl

    #Delete the old WinPE.jpg and copy the new one
    Write-LogMessage -Message "Taking full control of background image for replacement"
        $permission = ".\Administrators","FullControl","Allow"
        $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $BackgroundImage -AclObject $acl
        remove-item $BackgroundImage
        If (test-path ($env:TEMP + '\' + 'winpe.jpg')) {
            Write-LogMessage -Message "Replacing background image"
            Copy-Item ($env:TEMP + '\' + 'winpe.jpg') ($BackgroundImage) -Force
        }

    #Setting the autostart to run powershell start.ps1 script
    Write-LogMessage -Message "Setting the autostart scripts"

        $StartCommand="powershell -NoExit -c X:\Start.ps1"
        $StartCommand=($StartCommand + $NewStartCommand)
        $startnet = Get-Content ($TargetDirectory + '\mount\windows\system32\startnet.cmd')
        $startnet += "`r`npowershell -c Set-ExecutionPolicy Unrestricted -Force"
        $startnet += "`r`ncd\"
        $startnet += "`r`n$StartCommand"
        #$startnet
        Set-Content -Value $startnet -Path ($TargetDirectory +  "\mount\windows\system32\startnet.cmd") -Force
    }

    #Closing the mount and making an ISO out of it.....
        $DISM=('/unmount-image /mountdir:' + $TargetDirectory + '\mount /commit')
        write-host "" | Out-Null
        Write-LogMessage -Message "Unmounting the image" -NoNewline $true
        Start-process 'Dism' -ArgumentList $DISM -WindowStyle Minimized
        write-host "" | Out-Null
        #Monitoring process in function
        IsDISMStillRunning
}#/IMAGE BUILD 
        
#BASE IMAGE CREATED: EXPORT     
        $ISO=('MakeWinPEMedia /ISO ' + $TargetDirectory + ' ' + $TargetDirectory + '\WinPE_ASDK_Stack.iso')
        $USB=('MakeWinPEMedia /UFD /F ' + $TargetDirectory + ' ' + $USBDrive)

        If (test-path "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat") {
            
            If ($USBMode -eq $false) {    
                copy-item "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat" $ClosingISOBatchFile
                $ISOfile = Get-Content $ClosingISOBatchFile
                $ISOfile += "`r`nREM Creating ISO"
                $ISOfile += "`r`n$ISO"            
                Set-Content -Value $ISOfile -Path $ClosingISOBatchFile -Force
                Write-LogMessage -Message "Creating the ISO image"
                $MonitorredFile=($TargetDirectory + '\WinPE_ASDK_Stack.iso')
                If (test-path $MonitorredFile) {
                    Write-LogMessage "ISO is already present.."
                } Else {        
                    Start-Process 'C:\WINDOWS\system32\cmd.exe' -argumentlist "/k $ClosingISOBatchFile" -Verb runAs -WindowStyle Minimized
                }
                $MonitorredFile=($TargetDirectory + '\WinPE_ASDK_Stack.iso')
                Write-LogMessage -Message "waiting for ISO to be created"
                While (1 -eq 1) {
                    IF (Test-Path $MonitorredFile) {
                        #file exists. break loop
                        break
                    }
                    #sleep for 2 seconds, then check again
                    Start-Sleep -s 4
                }
                If (test-path ($TargetDirectory + '\WinPE_ASDK_Stack.iso')) {
                    Write-LogMessage -Message "Iso successfully created"
                    $ISOOutput=($TargetDirectory + '\WinPE_ASDK_Stack.iso')
                    Write-Host "      ***********************************************" -foregroundColor Yellow
                    write-host "      please check $ISOOutput " -foregroundColor Yellow
                    Write-Host "      ***********************************************" -foregroundColor Yellow
                    write-host ""
                    
                }

        }ElseIf ($USBMode -eq $true) {
            #CREATING USB INSTEAD OF ISO
                copy-item "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat" $ClosingUSBBatchFile
                $USBfile = Get-Content $ClosingUSBBatchFile
                $USBfile += "`r`nREM Creating USB"
                $USBfile += "`r`n$USB"            
                Set-Content -Value $USBfile -Path $ClosingUSBBatchFile -Force
                Write-LogMessage -Message "Creating the USB drive"
                #need to validate drive is actually a USB drive: and confirmation
                
                $title = 'Warning:'
                $msg   = (' overwriting all contents in drive ' + $USBDrive + ' - Are you sure?')

                $yes = New-Object Management.Automation.Host.ChoiceDescription '&Yes'
                $no  = New-Object Management.Automation.Host.ChoiceDescription '&No'
                $options = [Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $default = 1  # $no
                
                $response = $Host.UI.PromptForChoice($title, $msg, $options, $default)
                if ($response -eq 0) {
                    Start-Process 'C:\WINDOWS\system32\cmd.exe' -argumentlist "/k $ClosingUSBBatchFile" -Verb runAs -WindowStyle Minimized 
                    start-sleep 10 #WAIT FOR FORMAT
                    IsUSBDone $USBDrive
                    Write-Host ""
                    Write-Host ""
                    Write-Host "      ***********************************************" -foregroundColor Yellow
                    write-host "       please wait a minute for $USBDrive to be completed" -foregroundColor Yellow
                    Write-Host "      ***********************************************" -foregroundColor Yellow
                    write-host ""         
                }
                else {
                    Write-LogMessage -Message "Cancelled the creation of USB drive"
                    Exit
                    }
        }

    }
    Write-LogMessage "--------" -Message "Check CMD windows and close if required"
    Write-LogMessage -Message "Script completed"



