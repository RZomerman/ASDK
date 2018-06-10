    <#
    .SYNOPSIS
        Creating a WinPE ISO image to be used for the automated deployment of ASDK

    .DESCRIPTION
        Creates an ISO image to be used for deploying ASDK

    .PARAMETER TargetDirectory
        $TargetDirectory where the image must be created 
    
        Note
            About 500Mb free space required (is not checked)

    .EXAMPLE
        CreateASDKDeploymentIso.ps1 -TargetDirectory d:\winpe_asdk


    .FUNCTIONALITY
        PowerShell Language

    #>
[cmdletbinding()]
    param (
        [string]$TargetDirectory,
        
        [parameter(Mandatory = $false)]
        [string]$CustomGitLocation
    )

#$TargetDirectory='d:\winpe_amd81'
$version="201806107"

$TargetBatchFile=($env:TEMP + '\PreparewinPE.bat')
$ClosingISOBatchFile=($env:TEMP + '\PrepareISO.bat')
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
write-host ""
Write-LogMessage -Message "Validating if a newer version is available."

    $localversion=$version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Connection = test-connection -computername raw.githubusercontent.com -count 1 -quiet
    If (!$Connection) {
        Write-LogMessage -Message "No Internet connection available. Using local script"
    return $false
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
                Write-LogMessage -Message "Installation completed"
                break
            } Else {
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
If ($CustomGitLocation){
    #custom location should be in the form of: RZomerman/ASDK
    $GitHubLocation=('https://raw.githubusercontent.com/' + $CustomGitLocation + '/master/')
    Write-LogMessage -Message "Using Custom GitHub source $CustomGitLocation"
}Else{
    $GitHubLocation=('https://raw.githubusercontent.com/RZomerman/ASDK/master/')
}

#Creating a copy of the Deployment Toolkit cmd start script so we can add the copype.cmd to it when starting
    copy-item "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat" $TargetBatchFile 
        $batchfile = Get-Content $TargetBatchFile
        $batchfile += "`r`nREM Creating WinPE repository"
        $batchfile += "`r`ncopype.cmd amd64 $TargetDirectory"
    Set-Content -Value $batchfile -Path $TargetBatchFile -Force

#Starting the Deployment Toolkit CMD from the created batchfile - this will automatically start the copype.cmd script
    Write-LogMessage -Message "creating WinPE on $TargetDirectory"
    If (!(test-path $TargetDirectory)) {       
            Write-LogMessage -Message "Creating base WinPE image"
            Start-Process 'C:\WINDOWS\system32\cmd.exe' -argumentlist "/k $TargetBatchFile" -Verb runAs -WindowStyle Minimized
    }else{
        Write-LogMessage -Message "Target Directory already exists"
#exit
    }

#Need to wait for the copype.cmd to be completed - last file seems to be Media\zh-tw\bootmgt.efi.mui
$MonitorredFile=($TargetDirectory + '\Media\zh-tw\bootmgr.efi.mui')
    Write-LogMessage -Message "waiting for copy to complete"
    start-sleep -Seconds 3
    While (1 -eq 1) {
        IF (Test-Path $MonitorredFile) {
            #file exists. break loop
            break
        }
        #sleep for 2 seconds, then check again
        write-host "sleeping"
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
    Write-LogMessage -Message "Mounting the WinPE image" -NoNewline $true
    Start-Process 'DISM' -ArgumentList $1 

#Need to check if c:\windows\system32\dism.exe is still running
    While (Get-Process | where-object {$_.ProcessName -Contains "Dism"}) {
        write-host "." -NoNewline
        start-sleep -s 2
    }    
    write-host ""
    Write-LogMessage -Message "Adding WMI package"
    Start-Process 'DISM' -wait -ArgumentList $2 
    Write-LogMessage -Message "Adding Network package"
    Start-Process 'DISM' -wait -ArgumentList $3 
    Write-LogMessage -Message "Adding Scriptig package"
    Start-Process 'DISM' -wait -ArgumentList $4 
    Write-LogMessage -Message "Adding Powershell package"
    Start-Process 'DISM' -wait -ArgumentList $5 
    Write-LogMessage -Message "Adding DISM package"
    Start-Process 'DISM' -wait -ArgumentList $6 
    Write-LogMessage -Message "Adding Storage WMI package"
    Start-Process 'DISM' -wait -ArgumentList $7

#Need to copy all the required files from github to temp
    Write-LogMessage -Message "Downloading scripts from GitHub"
        $Uri = ($GitHubLocation + 'Start.ps1')
        $OutFile  = ($env:TEMP + '\' + 'Start.ps1')
        DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        
        $Uri = ($GitHubLocation + 'PrepareAzureStackPOC.psm1')
        $OutFile  = ($env:TEMP + '\' + 'PrepareAzureStackPOC.psm1')
        DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        

        $Uri = ($GitHubLocation + 'PrepareAzureStackPOC.ps1')
        $OutFile  = ($env:TEMP + '\' + 'PrepareAzureStackPOC.ps1')
        DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        

        $Uri = ($GitHubLocation + 'winpe.jpg')
        $OutFile  = ($env:TEMP + '\' + 'winpe.jpg')
        DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        

#Copy the files to the mounted image
    If (test-path ($TargetDirectory + "\mount\Windows")) {
        Write-LogMessage -Message "Copying files to the mounted image" -NoNewLine $true
        If (test-path ($env:TEMP + '\' + 'Start.ps1')) {
            $target=($TargetDirectory + '\mount\Start.ps1')
            write-host "." -NoNewline
            Copy-Item ($env:TEMP + '\' + 'Statr.ps1') $target -Force
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
        $startnet = Get-Content ($TargetDirectory + '\mount\windows\system32\startnet.cmd')
        $startnet += "`r`npowershell -c Set-ExecutionPolicy Unrestricted -Force"
        $startnet += "`r`ncd\"
        $startnet += "`r`npowershell -NoExit -c X:\Start.ps1"
        #$startnet
        Set-Content -Value $startnet -Path ($TargetDirectory +  "\mount\windows\system32\startnet.cmd") -Force
    }

    #Closing the mount and making an ISO out of it.....
        $DISM=('/unmount-image /mountdir:' + $TargetDirectory + '\mount /commit')
        Write-LogMessage -Message "Unmounting the image"
        Start-process 'Dism' -ArgumentList $DISM -Wait -WindowStyle Minimized
        
        $ISO=('MakeWinPEMedia /ISO ' + $TargetDirectory + ' ' + $TargetDirectory + '\WinPE_ASDK_Stack.iso')
        If (test-path "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat") {
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
    #Dism /unmount-image /mountdir:D:\winpe_amd71\mount /commit
    #MakeWinPEMedia /ISO D:\winpe_amd71 D:\winpe_amd71\WinPE_ASDK_Stack.iso
    #MakeWinPEMedia /UFD D:\winpe_amd71 P:



