$HostFile = "$Env:SystemRoot\System32\Drivers\Etc\Hosts" 

#Findsout if the script is ran from WinPE or dual-boot config
Function HostIsWinPE{
    $wmi = $(gwmi Win32_OperatingSystem -computerName 'localhost')
    if ($wmi.OperatingSystemSKU -ge 7) {
        Write-LogMessage -Message "Windows Server system detected"
        Write-LogMessage -Message "CloudBuilder download option enabled"
        Write-LogMessage -Message "Drive erase disabled"
        return $false
    }elseif ($wmi.OperatingSystemSKU -eq 1) {
        Write-LogMessage -Message "WINPE OS detected"
        return $true
    }else{
        Write-LogMessage -Message "Could not detect SKU level $wmi.OperatingSystemSKU"
        Write-LogMessage -Message "Drive erase disabled"
        return $false
    }
}

function ComputerInfo {
    $ComputerInfo=Get-WmiObject -Class Win32_ComputerSystem Model,Manufacturer
    return $ComputerInfo
}
# Starts all the services needed to intialize deployment on win PE
function Set-WinPEDeploymentPrerequisites
{
    Param (
        [Parameter(Mandatory=$true)]
        [string]
        $Network
    )
    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    if (-not (Get-Command wpeutil*)) {
        Write-Warning "This script is intended to be execute in WinPE only."
        return
    }
    If ($network) {
    Write-LogMessage -Message "Initializing Network"
    $null = wpeutil InitializeNetwork
    $null = wpeutil EnableFirewall
    $null = wpeutil WaitForNetwork
    $null = Start-Service -Name LanmanWorkstation
    }
}

#NOT USED IN THIS VERSION
function New-NetworkDrive

{
    Param (
        [Parameter(Mandatory=$true)]
        [string]
        $IPv4Address,

        [Parameter(Mandatory=$true)]
        [string]
        $HostName,

        [Parameter(Mandatory=$true)]
        [string]
        $ShareRoot,

        [Parameter(Mandatory=$true)]
        [PSCredential]
        $Credential,

        [Parameter(Mandatory=$true)]
        [string]
        $DriveLetter
    )

    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    # Add Host Entry
    $hostEntry = "$IPv4Address     $HostName"

    if(-not (Get-Content $HostFile).Contains($hostEntry))
    {
        Write-LogMessage -Message "Add host entry: '$hostEntry'."
        $hostEntry | Out-File -FilePath $HostFile -Append -Encoding ascii
    }

    # Set PS Drive
    if(-not (Get-PSDrive | ? Name -EQ $DriveLetter))
    {
        Write-LogMessage -Message "Create PSDrive '$DriveLetter' to '$ShareRoot'."
        New-PSDrive -Name $DriveLetter -PSProvider FileSystem -Root $ShareRoot -Credential $Credential -Persist -Scope Global
    }
}

# Returns back the SystemDrive
function DiskConfiguration
{
    [CmdletBinding()]
    [OutputType([String])]
    param (

        [Parameter(Mandatory=$true)]
        [string]
		$ClearDiskFilePath
    )

    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    (Get-Date).ToString('yyyy/MM/dd HH:mm:ss') 
    Write-LogMessage -Message "Reset the disks and clean them of all data."
    #Must not remove partition from USB drive
    $ArrayOfDisks=Get-PhysicalDisk | where {$_.BusType -ne "USB" -and $_.OperationalStatus -eq "OK"}
    #$ArrayOfDisks | ft FriendlyName,MediaType,Size
    Foreach ($Disk in $ArrayOfDisks) {
        $DiskPhysicalLocation=$Disk.PhysicalLocation
        Write-LogMessage -Message "Cleaning disk $DiskPhysicalLocation"
        Get-Partition -DiskNumber $Disk.DeviceID -ErrorAction SilentlyContinue| Remove-Partition -Confirm:$false -ErrorAction SilentlyContinue
    }
    
    Get-Disk | ? PartitionStyle -ne RAW | % {
        $_ | Set-Disk -IsOffline:$false -ErrorAction SilentlyContinue
        $_ | Set-Disk -IsReadOnly:$false -ErrorAction SilentlyContinue
        $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -ErrorAction SilentlyContinue
    }
<# 
    #Was previously used, but cannot be used anymore in latest versions of Stack
    Get-Disk | % {
        $_ | Set-Disk -IsReadOnly:$true -ErrorAction SilentlyContinue
        $_ | Set-Disk -IsOffline:$true -ErrorAction SilentlyContinue
    }
#>
    Update-StorageProviderCache -DiscoveryLevel Full
    (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
    #Write-LogMessage -Message "Select the disk to boot from."

    #Get-PhysicalDisk | Sort DeviceId | Format-Table DeviceId, Model, BusType, MediaType, Size | Out-String 
    #Get-Disk | Out-String 

        
	$allbootCandidateDisks = $ArrayOfDisks
	if (-not $allbootCandidateDisks) {
    		throw 'No suitable boot candidate disks found.'
    	}
    
	# $allbootCandidateDisks | Out-String 
    $bootCandidateDisks = $allbootCandidateDisks | ? BusType -in 'SATA', 'SAS', 'RAID'

    $bootCandidateDisks = $bootCandidateDisks | ? DeviceId -in (Get-Disk).Number
    $bootCandidateDisks = $bootCandidateDisks | Sort-Object Size, DeviceId
    $bootCandidateDisk = $bootCandidateDisks | Select-Object -First 1
    $bootDiskNumber = $bootCandidateDisk.DeviceId
    

    
    Write-LogMessage -Message "Initializing drive $bootDiskNumber for boot partition."

   Get-Disk | ? Number -ne $bootCandidateDisk.DeviceId | % {
        $diskID= $_.Number
        Write-LogMessage -Message "Initializing drive $DiskID for storage pool"
        $_ | Initialize-Disk -PartitionStyle GPT 
    }

    wpeutil UpdateBootInfo 

    $peFirmwareType = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control).PEFirmwareType

    # Returns 0x1 if the PC is booted into BIOS mode, or 0x2 if the PC is booted in UEFI mode.
    $isLegacyBoot = $peFirmwareType -eq 1

    if ($isLegacyBoot) 
    {
        Write-LogMessage -Message "Create new partitions for Legacy Boot."
        $null = Initialize-Disk -Number $bootDiskNumber -PartitionStyle MBR -ErrorAction SilentlyContinue
        $partition = New-Partition -DiskNumber $bootDiskNumber -UseMaximumSize -AssignDriveLetter -IsActive
        $systemDrive = $partition.DriveLetter + ':'
        $osVolume = Format-Volume -Partition $partition -FileSystem NTFS -Confirm:$false
    }else{
        Write-LogMessage -Message "Create new partitions for EUFI."
    #Preparing DiskPartClear.txt for correct disk
        (Get-Content $ClearDiskFilePath).replace('REPLACEME', $bootDiskNumber) | Set-Content x:\DiskPartClear.txt
        Start-Process 'DiskPart' -ArgumentList "/s X:\DiskPartClear.txt" -WindowStyle Hidden -Wait
        start-sleep -s 5
        $null = Initialize-Disk -Number $bootDiskNumber -ErrorAction SilentlyContinue
        $espPartition = New-Partition -DiskNumber $bootDiskNumber -Size 200MB -GptType "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"  # ESP
        $msrPartition = New-Partition -DiskNumber $bootDiskNumber -Size 128MB -GptType "{e3c9e316-0b5c-4db8-817d-f92df00215ae}" # MSR
        $osPartition = New-Partition -DiskNumber $bootDiskNumber -UseMaximumSize -AssignDriveLetter -GptType "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}" # OS
        Start-Sleep 3 #Required for partioning to finish on older drives
        Write-LogMessage -Message "Formatting partition"
        
        $OSPartition = Get-Partition -DiskNumber $bootDiskNumber | Where-object {$_.Size -gt 50GB}
        $osVolume = Format-Volume -Partition $osPartition -FileSystem NTFS -Confirm:$false
        
        $espPartition | Add-PartitionAccessPath -AccessPath Q:
        $null = format Q: /fs:FAT32 /v:EFS /Y
        $OsDriveLetter = $osPartition.DriveLetter + ':'
        Write-LogMessage -Message "Using $OsDriveLetter as the target drive"
    }
    start-sleep 5
    return $($OsDriveLetter)
}
function findUSB{
    $USBDrive=Get-physicalDisk | where {$_.BusType -eq "USB"}
    If ($USBDrive) {
        $USBPresent=$true
        $DriveLetterOnUSB = (Get-partition -DiskNumber $USBDrive.DeviceId | where {$_.size -gt 2GB}).Driveletter
        $USBFreeSpace=Get-PSDrive $DriveLetterOnUSB | Select-Object Free
        $SourceDrive = ($DriveLetterOnUSB + ":")
        Write-LogMessage -Message "USB Source is $SourceDrive"
        $testPathForFile=($SourceDrive + "\CloudBuilder.vhdx")
        If (test-path $testPathForFile) {
            Write-LogMessage -Message "Local file found on USB"
            return $USBDrive
        }else{
           Write-LogMessage -Message "No Cloudbuilder.vhdx on USB" 
           return $false
        }
    }else{
        Write-LogMessage -Message "No USB found" 
        return $false
    }   
}
function getUSBDriveLetter{
    [CmdletBinding()]
    param (    
        [Parameter(Mandatory=$true)]
        $USBDrive
    )
    $DriveLetterOnUSB = (Get-partition -DiskNumber $USBDrive.DeviceId | where {$_.size -gt 2GB}).Driveletter
    return $($DriveLetterOnUSB)
}

function getUSBFreeSpace{
    [CmdletBinding()]
    param (    
        [Parameter(Mandatory=$true)]
        $DriveLetterOnUSB
    )
    #Input is raw file driveletter eg F
    $USBFreeSpace=Get-PSDrive $DriveLetterOnUSB | Select-Object Free
    return $($USBFreeSpace)
}

function GetOSDiskForDualBoot{
    #this function is used for dual boot installation (where Windows Server was used as the base OS rather than WinPE boot)
    $OSDrive=get-disk | where {$_.IsSystem}
    #Get all partitions on the OS Drive with a driveletter.. and then sort them from big to small and select the first partition (biggest)
    $OSPartition=Get-Partition -DiskNumber $OSDrive.Number| where {$_.DriveLetter} | Sort-Object "Size" -Descending | Select-object -First 1 
    $OsDriveLetter = $OSPartition.DriveLetter + ':'
    return $($OsDriveLetter)
    }

function DownloadWithRetry
{
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
            Write-LogMessage -Message "Error downloading '$url': $exceptionMessage"
            if ($retries -gt 0) {
                $retries--
                Write-LogMessage -Message ("Waiting 10 seconds before retrying. Retries left: " + $retries)
                Start-Sleep -Seconds 10
 
            }else{
                $exception = $_.Exception
                Write-LogMessage -Message "Failed to download '$url': $exceptionMessage"
                break
            }
        }
    }
}

function DownloadScripts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SystemDrive,

        [Parameter(Mandatory=$false)]
        [string]
        $DellHost,

        [Parameter(Mandatory=$false)]
        [string]
        $DISMUpdate,

        [parameter(Mandatory = $true)]
        [string]$CustomGitLocation,

        [parameter(Mandatory = $true)]
        [string]$CustomGitBranch

    )
    #updated for tls1.1 expiration
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    #Sources path = ROOTDRIVE \ Sources (the root of all scripts and things we download)
    $SourcesRoot=($systemDrive + "\sources")
    If (!(test-path $SourcesRoot)){
        New-Item ($systemDrive + "\sources") -Type directory | Out-Null
    }

    $Connection = test-connection -computername raw.githubusercontent.com -count 1 -quiet
    If (!$Connection) {
        Write-LogMessage -Message "No Internet connection available, please manually download scripts"
    return $false
    }elseIf ($Connection) {

        $LocalPath = ($SystemDrive + '\sources\AzureStack_Installer')
        If (!(test-path $LocalPath)){
            New-Item $LocalPath -Type directory | Out-Null
        }

        Write-LogMessage -Message "Downloading ADSK_installer.ps1"
        $Uri = 'https://raw.githubusercontent.com/Azure/AzureStack-Tools/master/Deployment/asdk-installer.ps1'
        $OutFile  = ($LocalPath + '\' + 'asdk-installer.ps1')
        DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        
        # Download the ConfigASDK Script. - Full Post Installer for installing all services
        # See: https://github.com/mattmcspirit/azurestack
        Write-LogMessage -Message "Downloading PostInstaller"
        $Uri = 'http://bit.ly/configasdk'
        $OutFile  = ($SourcesRoot + '\' + 'ConfigASDK.ps1')
        DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        
        Write-LogMessage -Message "Downloading CustomInstaller"
        $GitHubLocation=('https://raw.githubusercontent.com/' + $CustomGitLocation + '/' + $CustomGitBranch + '/')
        $Uri = ($GitHubLocation + 'PrepareInstallation.ps1')
        $OutFile  = ($SourcesRoot + '\' + 'PrepareInstallation.ps1')
        DownloadWithRetry -url $uri -downloadLocation $OutFile -retries 3

        #Downloading Azure Stack Tools - in case the full PostInstaller is not used 
        Write-LogMessage -Message "Downloading tools Master.zip"
        $Uri = 'https://github.com/Azure/AzureStack-Tools/archive/master.zip'
        $OutFile  = ($SourcesRoot + '\' + 'master.zip')
        DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        #Expanding archive
        Expand-archive $OutFile -DestinationPath $SourcesRoot -Force

        If ($DellHost -eq $true) {           
            $Uri = 'https://downloads.dell.com/FOLDER04242232M/1/OM-SrvAdmin-Dell-Web-WINX64-8.5.0-2372_A00.exe'
            $OutFile  = ($SourcesRoot + '\' + 'openmanage.exe')
            #Invoke-WebRequest $uri -OutFile $OutFile
            If (!(test-path $OutFile)) {
                Write-LogMessage -Message "Downloading OpenManage"
                DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
            }else{
                Write-LogMessage -Message "Found OpenManage executable"
            }
        }

            If ($DISMUpdate -eq $true) {           
            $uri='https://go.microsoft.com/fwlink/p/?linkid=859206'
            $OutFile  = ($SourcesRoot + '\' + 'adksetup.exe')
            #Invoke-WebRequest $uri -OutFile $OutFile
            If (!(test-path $OutFile)) {
                Write-LogMessage -Message "Downloading ADKSetup"
                DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
            }else{
                Write-LogMessage -Message "Found ADKSetup executable"
            }
            Write-LogMessage -Message "Instaling ADKSetup update"
            Start-Process $outfile -ArgumentList "/features Optionid.deploymenttools /quiet" -wait
        }
        
        return $true
    }else{
        Write-LogMessage -Message "No internet found.. something went wrong"
    }
}

function GetStackRemotely {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $SystemDrive
    )

    Write-LogMessage -Message "Initiating download of ASDK"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    #this function downloads the (latest) Azure Stack bits and is used when a vhdx location cannot be found (on network or USB)
    
    $SourcesRoot=($systemDrive + "\sources")
        If (!(test-path $SourcesRoot)){
            New-Item ($systemDrive + "\sources") -Type directory | Out-Null
        }
    $StackDownloadFolder=($systemDrive + "\sources\StackDownload")
        If (!(test-path $StackDownloadFolder)){
            New-Item ($systemDrive + "\sources\StackDownload") -Type directory | Out-Null
        }
    
    $uri='https://aka.ms/azurestack-latestrelease'
    $XMLfile=($SourcesRoot + '\' + 'DownloadManifest.xml')
    #invoke-WebRequest -uri $uri -OutFile $XMLfile
    DownloadWithRetry -url $uri -downloadLocation $XMLfile -retries 3
    
    If (test-path $XMLfile) {Write-LogMessage -Message "Downloaded ASDK Manifest"}
    
    #interpreting the XML doc and extracting download files
    [xml]$XmlDocument = Get-Content -Path $XMLfile
    $arrayOfFiles=$XmlDocument.DownloadFileList.Files
    $uriBase=$XmlDocument.DownloadFileList.DownloadSource
    Write-LogMessage -Message ('ASDK version: ' + $XmlDocument.DownloadFileList.version)
    Write-LogMessage -Message ("source: " + $uriBase)
    foreach ($entry in $arrayOfFiles) {
        $uri=($uriBase + $entry.FileName)
        $outfile=($StackDownloadFolder + '\' + $entry.FileName)
        If (!(test-path $outfile)){
            write-LogMessage -Message ("Downloading " + $entry.FileName)
            #invoke-WebRequest -uri $uri -outfile $outfile
            DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        }else{
            Write-AlertMessage -Message "Existing file found.. if wrong version, please delete"
        }
        $byteSize=(Get-Item $outfile).length
        If (!($byteSize -eq $entry.FileSizeInBytes)) {
            Write-AlertMessage -Message "Something went wrong in the download... please check file or download manually"
        
        }else{
            write-LogMessage -Message ("Validated: " + $entry.FileName + "`t`t downloaded:" + $entry.FileSizeInBytes + " bytes")
        }
    }
   
    #Validate drivespace!
    $drive=$SystemDrive -replace '[:]',''
    $size=Get-PSDrive $drive | Select-Object Free
        #200Gb is minimum required from https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-deploy
    If ($size.free /1Gb -lt 200) {
        write-AlertMessage "Not enough space on the drive to extract the VHDX. Aborting"
        #NEED TO ABORT HERE
    }
    #after download need to start executable to extract all files
     $executable=($StackDownloadFolder + '\AzureStackDevelopmentKit.exe')
        #& $executable "/Silent"

    If (!(test-path ($SystemDrive  + '\CloudBuilder.vhdx'))){
        Start-Process $executable -ArgumentList "/Silent" -wait 
        #File will be extracted to StackDownloadFolder\Azure Stack Development Kit
        $ExtractionFolder=($StackDownloadFolder + '\Azure Stack Development Kit')
        [array]$FilesInFolder=Get-Item ($ExtractionFolder + '\*.vhdx')
        If ($FilesInFolder.Count -ne 1) {
            write-AlertMessage "Too many files found in folder - assuming default naming: cloudbuilder.vhdx"
            $ExtractedFile=('\CloudBuilder.vhdx')
        }else{
            $ExtractedFile=('\' +  $FilesInFolder[0].Name)
        }
        #Move the file to $systemdrive
        Write-LogMessage -Message ("Moving VHDX to " + $SystemDrive)
        Move-Item -Path ($ExtractionFolder + '\*.vhdx') -Destination ($SystemDrive  + '\')
    }else{
        Write-LogMessage -Message "Existing CloudBuilder.vhdx found"
    }
}

function Copy-File {
    param( [string]$from, [string]$to)
    $ffile = [io.file]::OpenRead($from)
    $tofile = [io.file]::OpenWrite($to)
    Write-Progress -Activity "Copying file" -status "$from -> $to" -PercentComplete 0
    try {
        [byte[]]$buff = new-object byte[] 4096
        [long]$total = [long]$count = 0
        do {
            $count = $ffile.Read($buff, 0, $buff.Length)
            $tofile.Write($buff, 0, $count)
            $total += $count
            if ($total % 1mb -eq 0) {
                Write-Progress -Activity "Copying file" -status "$from -> $to" `
                   -PercentComplete ([long]($total/$ffile.Length* 100))
            }
        } while ($count -gt 0)
    }
    finally {
        $ffile.Dispose()
        $tofile.Dispose()
        Write-Progress -Activity "Copying file" -Status "Ready" -Completed
    }
}

function Set-HostVHDBoot
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $BootVHDFilePath,

        [Parameter(Mandatory=$true)]
        [string]
        $UnattendFile,

        [Parameter(Mandatory=$true)]
        [string]
        $SourcesRoot,

        [Parameter(Mandatory=$true)]
        [string]
        $SystemDrive,

        [Parameter(Mandatory=$true)]
        [string]
        $UseWinPE
    )

    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    try
    {
        Write-LogMessage -Message "winPE is '$UseWinPE'."
        Write-LogMessage -Message "Mounting VHD '$BootVHDFilePath'."
        $null = Mount-DiskImage -ImagePath $BootVHDFilePath
        $virtualDiskDriveLetter = Get-Disk | ? BusType -like 'File Backed Virtual' | Get-Partition | ? Size -gt 2Gb | % DriveLetter
        $bootDrive = $virtualDiskDriveLetter + ':\'
        #Write-Host $bootDrive

        # workaround for issue where script cannot find drive
        $null = New-PSDrive -Name $virtualDiskDriveLetter -Root $bootDrive -PSProvider FileSystem

        Write-LogMessage -Message "Use-WindowsUnattend file '$UnattendFile' for offline values."
        $null = Use-WindowsUnattend -Path $bootDrive -UnattendPath $UnattendFile

        $unattendDirectory = "$($bootDrive)Windows\Panther\Unattend"
        Write-LogMessage -Message "Inject Unattend file '$UnattendFile' to '$unattendDirectory'."
        $null = New-Item -Path $unattendDirectory -ItemType Directory -Force
        $null = Copy-Item -Path $UnattendFile -Destination "$unattendDirectory\unattend.xml"
        #Prepping asdk_installer & master.zip
        $null = Copy-Item -Path ($SourcesRoot + "\*") -Destination $bootDrive -Recurse -Container -Force


        If ($IsWinPE){
            Write-LogMessage -Message "Set WINPE based boot sequence."
            $peFirmwareType = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control).PEFirmwareType
            # Returns 0x1 if the PC is booted into BIOS mode, or 0x2 if the PC is booted in UEFI mode.
            $isLegacyBoot = $peFirmwareType -eq 1

            if ($isLegacyBoot) 
            {
                Write-LogMessage -Message "Set BCD Boot Legacy."
                bcdboot "$($bootDrive)Windows" /S $systemDrive 
            }else{

                Write-LogMessage -Message "Set BCD Boot UEFI."
                bcdboot "$($bootDrive)Windows" /s Q: /f UEFI /d /addlast /v 

                # Remove invalid Windows Boot Manager entries, left from the previous deployment.
                $bcdFirmware = bcdedit /enum firmware
                $bcdFirmware = $bcdFirmware -join "`n"
                if ($bcdFirmware -match 'identifier\s*({\w*-[0-9a-z-]*})[^-]*?description\s*Windows Boot Manager') 
                {
                    for($i = 0; $i -lt $matches.Count; $i++) 
                    {
                        if ($matches[$i] -like '{*') 
                        {
                            bcdedit /delete $matches[$i]
                        }
                    }
                }
                bcdedit /enum firmware 
            }
        }else{
                Write-LogMessage -Message "Set dual boot sequence."
                #Remove Existing entry
                $bootOptions = bcdedit /enum  | Select-String 'path' -Context 2,1
                $bootOptions | ForEach-Object {
                    if ((($_.Context.PreContext[1] -replace '^device +') -like '*CloudBuilder.vhdx*') -and (($_.Context.PostContext[0] -replace '^description +') -eq 'Azure Stack'))
                    {
                    $BootID = '"' + ($_.Context.PreContext[0] -replace '^identifier +') + '"'
                    bcdedit /delete $BootID
                    }
                }
                #Add new entry
            bcdboot "$($bootDrive)Windows" 
            #Rename new entry to Azure Stack
            Start-Sleep -Seconds 4
            $bootOptions = bcdedit /enum  | Select-String 'path' -Context 2,1
            $bootOptions | ForEach-Object {
                if (((($_.Context.PreContext[1] -replace '^device +') -eq ('partition='+$Prepare_Vhdx_DriveLetter+':') -or (($_.Context.PreContext[1] -replace '^device +') -like '*CloudBuilder.vhdx*')) -and (($_.Context.PostContext[0] -replace '^description +') -ne 'Azure Stack'))) {
                write-host $_.Context.PreContext[0]
                $BootID = '"' + ($_.Context.PreContext[0] -replace '^identifier +') + '"'
                bcdedit /set $BootID description "Azure Stack"
                }
            }
        }
    }
    finally
    {
        $mountedImages = Get-DiskImage -ImagePath $BootVHDFilePath 
        if ($mountedImages) 
        {
            Write-LogMessage -Message "Dismount image $BootVHDFilePath"
            $null = Dismount-DiskImage -ImagePath $BootVHDFilePath
        }
    }
}

function ActivateLog{
    $logname=$global:logname
    If (!(test-path -Path $logname)) {
        New-Item -Path $logname -ItemType File
    }
	Add-Content -Path $logname -Value "***************************************************************************************************"
    Add-Content -Path $logname -Value "Started processing at [$([DateTime]::Now)]."
    Add-Content -Path $logname -Value "***************************************************************************************************"
}

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
      $logname=$global:logname
    Write-Verbose "Writing log message"
    # Function for displaying formatted log messages.  Also displays time in minutes since the script was started
    write-host (Get-Date).ToShortTimeString() -ForegroundColor Cyan -NoNewline;
    write-host ' - [' -ForegroundColor White -NoNewline;
    write-host $systemName -ForegroundColor Yellow -NoNewline;
    write-Host "]::$($message)" -ForegroundColor White;
    Add-Content -Path $logname -Value $message
  }
  END {}
} 

function Write-AlertMessage 
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
    write-Host "]::$($message)" -ForegroundColor Yellow;
    Add-Content -Path "$logname" -Value $message
  }
  END {}
} 

Function CreateDiskPartClear {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $ClearDiskFilePath
    )    
    $DiskpartClear = "select disk REPLACEME"
    $DiskpartClear += "`r`nonline disk"
    $DiskpartClear += "`r`nclean"
    Set-Content -Value $DiskpartClear -Path $ClearDiskFilePath

}

function CheckDisks {
    $physicalDisks = Get-PhysicalDisk | Where-Object { ($_.BusType -eq 'RAID' -or $_.BusType -eq 'SAS' -or $_.BusType -eq 'SATA') -and $_.Size -gt 250Gb }
    $selectedDisks = $physicalDisks | Group-Object -Property BusType | Sort-Object -Property Count -Descending | Select-Object -First 1

    if ($selectedDisks.Count -ge 3) {
        $DiskCount=$selectedDisks.Count
        Write-LogMessage -Message "Found $DiskCount disks that are >250Gb"
    }
    if ($selectedDisks.Count -lt 3) {
        Write-AlertMessage -Message "Not enough disks found for ASDK"
        Exit-PSHostProcess
     }    
}

function CheckRam {
    $mem = Get-WmiObject -Class Win32_ComputerSystem
    $totalMemoryInGB = [Math]::Round($mem.TotalPhysicalMemory / 1Gb)
    $MemoryInGB=([string]$totalMemoryInGB + "GB")
    if ($totalMemoryInGB -lt 96) {
        Write-AlertMessage -Message "$MemoryInGB is not enough memory to run ASDK"
        Exit-PSHostProcess
    }
    else
    {
       Write-LogMessage -Message "Server has $MemoryInGB of memory installed"
    }
}

function CheckHyperVSupport {
          $cpu = Get-WmiObject -Class WIN32_PROCESSOR
          $os = Get-WmiObject -Class Win32_OperatingSystem
          if (($cpu.VirtualizationFirmwareEnabled -contains $false) -or ($cpu.SecondLevelAddressTranslationExtensions -contains $false) -or ($cpu.VMMonitorModeExtensions -contains $false) -or ($os.DataExecutionPrevention_Available -eq $false)) {
            Write-AlertMessage -Message "CPU does not meet Hyper-V requirements.. "
         }
         else
         {
            Write-LogMessage -Message "CPU Virtualization is supported and enabled"
         }

}

function CheckCPU {
    $CPUCount = (Get-WmiObject -class win32_processor –computername localhost).count
    If ($CPUCount) {
       $CoreCount =  (Get-WmiObject -class win32_processor –computername localhost -Property "numberOfCores")[0].numberOfCores
        $TotalCores=$CPUCount * $CoreCount
	If ($TotalCores -lt 12){
            Write-AlertMessage -Message "Not enough cores available in the system"
            Exit-PSHostProcess
        }
        else
        {
            Write-LogMessage -Message "Server has $CPUCount CPU's with $TotalCores cores total"
        }
    }
    else{
        $CoreCount =  (Get-WmiObject -class win32_processor –computername localhost -Property "numberOfCores")[0].numberOfCores
        Write-LogMessage -Message "Server has $CoreCount cores per processor"
	Write-LogMessage -Message "Continuing based on assumption of enough cores
    }
}


Function CreateUnattend {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $File,

        [Parameter(Mandatory=$true)]
        [string]
        $Password
    )
    $UnattendXML = '<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
    $UnattendXML+= ' <settings pass="windowsPE">'
    $UnattendXML+= '    <component name="Microsoft-Windows-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="AMD64">'
    $UnattendXML+= '      <UpgradeData>'
    $UnattendXML+= '        <Upgrade>false</Upgrade>'
    $UnattendXML+= '      </UpgradeData>'
    $UnattendXML+= '      <UserData>'
    $UnattendXML+= '        <AcceptEula>true</AcceptEula>'
    $UnattendXML+= '        <FullName>Microsoft</FullName>'
    $UnattendXML+= '        <Organization>Microsoft</Organization>'
    $UnattendXML+= '        <ProductKey>'
    $UnattendXML+= '          <WillShowUI>OnError</WillShowUI>'
    $UnattendXML+= '         <Key>CB7KF-BWN84-R7R2Y-793K2-8XDDG</Key>'
    $UnattendXML+= '        </ProductKey>'
    $UnattendXML+= '      </UserData>'
    $UnattendXML+= '      <Restart>Restart</Restart>'
    $UnattendXML+= '    </component>'
    $UnattendXML+= '    <component name="Microsoft-Windows-International-Core-WinPE" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="AMD64">'
    $UnattendXML+= '      <SetupUILanguage>'
    $UnattendXML+= '        <UILanguage>en-us</UILanguage>'
    $UnattendXML+= '        <WillShowUI>OnError</WillShowUI>'
    $UnattendXML+= '      </SetupUILanguage>'
    $UnattendXML+= '      <UILanguage>en-us</UILanguage>'
    $UnattendXML+= '      <SystemLocale>en-us</SystemLocale>'
    $UnattendXML+= '      <UserLocale>en-us</UserLocale>'
    $UnattendXML+= '      <InputLocale>0409:00000409</InputLocale>'
    $UnattendXML+= '    </component>'
    $UnattendXML+= '  </settings>'
    $UnattendXML+= '  <settings pass="specialize">'
    $UnattendXML+= '    <component xmlns="" name="Microsoft-Windows-TerminalServices-LocalSessionManager" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">'
    $UnattendXML+= '      <fDenyTSConnections>false</fDenyTSConnections>'
    $UnattendXML+= '    </component>'
    $UnattendXML+= '    <component xmlns="" name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">'
    $UnattendXML+= '      <UserAuthentication>0</UserAuthentication>'
    $UnattendXML+= '    </component>'
    $UnattendXML+= '    <component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="AMD64">'
    $UnattendXML+= '      <ComputerName></ComputerName>'
    $UnattendXML+= '    </component>'
    $UnattendXML+= '    <component name="Networking-MPSSVC-Svc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    $UnattendXML+= '      <FirewallGroups>'
    $UnattendXML+= '        <FirewallGroup wcm:action="add" wcm:keyValue="RemoteDesktop">'
    $UnattendXML+= '          <Active>true</Active>'
    $UnattendXML+= '          <Profile>all</Profile>'
    $UnattendXML+= '          <Group>@FirewallAPI.dll,-28752</Group>'
    $UnattendXML+= '        </FirewallGroup>'
    $UnattendXML+= '      </FirewallGroups>'
    $UnattendXML+= '    </component>'
    $UnattendXML+= '    <component name="Microsoft-Windows-IE-ESC" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    $UnattendXML+= '      <IEHardenAdmin>false</IEHardenAdmin>'
    $UnattendXML+= '      <IEHardenUser>false</IEHardenUser>'
    $UnattendXML+= '    </component>'
    $UnattendXML+= '  </settings>'
    $UnattendXML+= '  <settings pass="oobeSystem">'
    $UnattendXML+= '    <component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="AMD64">'
    $UnattendXML+= '      <UserAccounts>'
    $UnattendXML+= '        <AdministratorPassword>'
    $UnattendXML+= '          <Value>' + $Password + '</Value>'
    $UnattendXML+= '          <PlainText>true</PlainText>'
    $UnattendXML+= '        </AdministratorPassword>'
    $UnattendXML+= '      </UserAccounts>'
    $UnattendXML+= '      <OOBE>'
    $UnattendXML+= '        <SkipMachineOOBE>true</SkipMachineOOBE>'
    $UnattendXML+= '      </OOBE>'
    $UnattendXML+= '      <AutoLogon>'
    $UnattendXML+= '        <Password>'
    $UnattendXML+= '          <Value>' + $Password + '</Value>'
    $UnattendXML+= '          <PlainText>true</PlainText>'
    $UnattendXML+= '        </Password>'
    $UnattendXML+= '        <Domain>ASTACK</Domain>'
    $UnattendXML+= '        <Enabled>true</Enabled>'
    $UnattendXML+= '        <LogonCount>1</LogonCount>'
    $UnattendXML+= '        <Username>Administrator</Username>'
    $UnattendXML+= '      </AutoLogon>'
    $UnattendXML+= '      <FirstLogonCommands>'
    $UnattendXML+= '        <SynchronousCommand wcm:action="add">'
    $UnattendXML+= '          <CommandLine>%windir%\System32\WindowsPowerShell\v1.0\powershell.exe -c "Get-NetAdapterBinding -ComponentID ms_tcpip6 | Set-NetAdapterBinding -Enabled $false"</CommandLine>'
    $UnattendXML+= '          <Description>Disable IPv6.</Description>'
    $UnattendXML+= '          <Order>1</Order>'
    $UnattendXML+= '        </SynchronousCommand>'
    $UnattendXML+= '        <SynchronousCommand wcm:action="add">'
    $UnattendXML+= '          <CommandLine>%windir%\System32\WindowsPowerShell\v1.0\powershell.exe -c "Enable-PSRemoting -Force; New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -PropertyType DWord -Value 1 -Force"</CommandLine>'
    $UnattendXML+= '          <Description>Enable PowerShell Remoting for local administrator account.</Description>'
    $UnattendXML+= '          <Order>2</Order>'
    $UnattendXML+= '        </SynchronousCommand>'
    $UnattendXML+= '        <SynchronousCommand wcm:action="add">'
    $UnattendXML+= '          <CommandLine>%windir%\System32\WindowsPowerShell\v1.0\powershell.exe -c "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"</CommandLine>'
    $UnattendXML+= '          <Description>Enable firewall rule for Windows Remote Management (HTTP-In).</Description>'
    $UnattendXML+= '          <Order>3</Order>'
    $UnattendXML+= '        </SynchronousCommand>'
    $UnattendXML+= '        <SynchronousCommand wcm:action="add">'
    $UnattendXML+= '          <CommandLine>%windir%\System32\WindowsPowerShell\v1.0\powershell.exe -c "D:\sources\PrepareInstallation.ps1" -Password ' + $Password + '</CommandLine>'
    $UnattendXML+= '          <Description>Preparing the ASDK installation sources.</Description>'
    $UnattendXML+= '          <Order>4</Order>'
    $UnattendXML+= '        </SynchronousCommand>'
#    $UnattendXML+= '        <SynchronousCommand wcm:action="add">'
#    $UnattendXML+= '          <CommandLine>%windir%\System32\logoff.exe</CommandLine>'
#    $UnattendXML+= '          <Description>Log off user session.</Description>'
#    $UnattendXML+= '          <Order>4</Order>'
#    $UnattendXML+= '        </SynchronousCommand>'
    $UnattendXML+= '      </FirstLogonCommands>'
    $UnattendXML+= '    </component>'
    $UnattendXML+= '  </settings>'
    $UnattendXML+= '</unattend>'
    Set-Content -Value $UnattendXML -Path $file
}
