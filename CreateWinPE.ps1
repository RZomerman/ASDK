$IsoMountDirectory='d:\winpe_amd80'
$ScriptWorkingDirectory='c:\scripts'


$TargetBatchFile='c:\scripts\PreparewinPE.bat'
$CloseBatchFile='c:\scripts\PrepareISO.bat'
$version="201806101"

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

cls
Write-Host "      *******************************" -foregroundColor Yellow
write-host "        Welcome to the ASDK BUILDER " -foregroundColor Yellow
Write-Host "      *******************************" -foregroundColor Yellow
write-host ""
Write-Host "Validating if a newer version of this script is available"
    $localversion=$version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Connection = test-connection -computername raw.githubusercontent.com -count 1 -quiet
    If (!$Connection) {
        Write-Host "No Internet connection available. Using local script"
    return $false
    }elseIf ($Connection) {
        $Uri = 'https://raw.githubusercontent.com/RZomerman/ASDK/master/CreateWinPE.ps1'
        $OutFile  = ($env:TEMP + '\' + 'CreateWinPE.ps1')
        DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        $DownloadedFile=Get-FileContents $outfile
        Foreach ($line in $DownloadedFile) {
            If ($line -like '$version=*') {
                $version=$line.replace('$version=','')
                $version=$version.replace('"',"")
                break
            }
        }
        Write-host "downloaded file is version" $version
        Write-host "local file is version" $Localversion
        If ($version -gt $Localversion) {
            Copy-item ($env:TEMP + '\' + 'CreateWinPE.ps1') 'CreateWinPE.ps1' -force
            Write-host "Please restart this script"
            exit
        }
        Elseif ($version -eq $Localversion){
            Write-host "local verison to up date"
        }
        Else {
            Write-host "local version is newer"
        }
    }




If (test-path "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat") {
    copy-item "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat" $TargetBatchFile
    
    $batchfile = Get-Content $TargetBatchFile
    $batchfile += "`r`nREM Creating WinPE repository"
    $batchfile += "`r`ncopype.cmd amd64 $IsoMountDirectory"

    #$batchfile += "`r`n$1"
    #$batchfile += "`r`n$2"
    #$batchfile += "`r`n$3"
    #$batchfile += "`r`n$4"
    #$batchfile += "`r`n$5"
    #$batchfile += "`r`n$6"
    #$batchfile += "`r`n$7"

        Set-Content -Value $batchfile -Path $TargetBatchFile -Force

#run with the Deployment and Imaging Tools Environment (cmdlet) - https://docs.microsoft.com/en-us/windows/deployment/windows-adk-scenarios-for-it-pros
        Start-Process 'C:\WINDOWS\system32\cmd.exe' -argumentlist "/k $TargetBatchFile" -Verb runAs
    }
    Elsif {
        Write-host "Windows Deployment tools not found!" -ForegroundColor red
        exit
    }

#Need to wait for the full extraction to be completed
    $MonitorredFile=($IsoMountDirectory + '\Media\zh-tw\bootmgr.efi.mui')
    While (1 -eq 1) {
        IF (Test-Path $theFile) {
            #file exists. break loop
            break
        }
        #sleep for 2 seconds, then check again
        Start-Sleep -s 2
    }

    $1=('/mount-image /imagefile:' + $IsoMountDirectory + '\media\sources\boot.wim /index:1 /mountdir:' + $IsoMountDirectory + '\mount')
    $2=('/Image:' + $IsoMountDirectory + '\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-WMI.cab"')
    $3=('/Image:' + $IsoMountDirectory + '\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-NetFX.cab"')
    $4=('/Image:' + $IsoMountDirectory + '\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-Scripting.cab"')
    $5=('/Image:' + $IsoMountDirectory + '\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-PowerShell.cab"')
    $6=('/Image:' + $IsoMountDirectory + '\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-DismCmdlets.cab"')
    $7=('/Image:' + $IsoMountDirectory + '\mount /Add-Package /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs\WinPE-StorageWMI.cab"') 

    Start-Process 'DISM' -wait -ArgumentList $1 
    Start-Process 'DISM' -wait -ArgumentList $2
    Start-Process 'DISM' -wait -ArgumentList $3 
    Start-Process 'DISM' -wait -ArgumentList $4 
    Start-Process 'DISM' -wait -ArgumentList $5 
    Start-Process 'DISM' -wait -ArgumentList $6 
    Start-Process 'DISM' -wait -ArgumentList $7 

#Need to copy all the required files from github to the new destination
        $Uri = 'https://raw.githubusercontent.com/RZomerman/ASDK/master/PrepareAzureStackPOC.psm1'
        $OutFile  = ($env:TEMP + '\' + 'PrepareAzureStackPOC.psm1')
        DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        $DownloadedFile=Get-FileContents $outfile

        $Uri = 'https://raw.githubusercontent.com/RZomerman/ASDK/master/PrepareAzureStackPOC.ps1'
        $OutFile  = ($env:TEMP + '\' + 'PrepareAzureStackPOC.ps1')
        DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        $DownloadedFile=Get-FileContents $outfile

        $Uri = 'https://raw.githubusercontent.com/RZomerman/ASDK/master/winpe.jpg'
        $OutFile  = ($env:TEMP + '\' + 'winpe.jpg')
        DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3
        $DownloadedFile=Get-FileContents $outfile

#Copy the files to the mounted image
    If (test-path ($IsoMountDirectory + "\mount\Windows")) {
        If (test-path ($env:TEMP + '\' + 'PrepareAzureStackPOC.ps1')) {
            Copy-Item ($env:TEMP + '\' + 'PrepareAzureStackPOC.ps1') ($IsoMountDirectory + '\mount\PrepareAzureStackPOC.ps1') -Force
        }
        If (test-path ($env:TEMP + '\' + 'PrepareAzureStackPOC.psm1')) {
            Copy-Item ($env:TEMP + '\' + 'PrepareAzureStackPOC.psm1') ($IsoMountDirectory + '\mount\PrepareAzureStackPOC.psm1') -Force
        }
#need to take ownership of WinPE and delete it (to change background later on)
    $BackgroundImage=($IsoMountDirectory + '\mount\Windows\System32\winpe.jpg')
    $acl=Get-Acl $BackgroundImage
    $Group = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
    $ACL.SetOwner($Group)
    Set-Acl -Path $BackgroundImage -AclObject $acl

#Delete the old WinPE.jpg and copy the new one
    $permission = ".\Administrators","FullControl","Allow"
    $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $BackgroundImage -AclObject $acl
    remove-item $BackgroundImage
    If (test-path ($env:TEMP + '\' + 'winpe.jpg')) {
        Copy-Item ($env:TEMP + '\' + 'winpe.jpg') ($BackgroundImage) -Force
    }

#Setting the autostart to run powershell start.ps1 script
    $startnet = Get-Content ($IsoMountDirectory + '\mount\windows\system32\startnet.cmd')
    $startnet += "`r`npowershell -c Set-ExecutionPolicy Unrestricted -Force"
    $startnet += "`r`ncd\"
    $startnet += "`r`npowershell -NoExit -c X:\Start.ps1"
    $startnet
    Set-Content -Value $startnet -Path ($IsoMountDirectory +  "\mount\windows\system32\startnet.cmd") -Force

#Closing the mount and making an ISO out of it.....
    
    $DISM=('/unmount-image /mountdir:' + $IsoMountDirectory + '\mount /commit')
    $ISO=('/ISO ' + $IsoMountDirectory + ' ' + $IsoMountDirectory + '\WinPE_ASDK_Stack.iso')
    Start-process 'Dism' -ArgumentList $DISM -Wait
    Start-process 'MakeWinPEMedia' -ArgumentList $ISO -Wait
}
#Dism /unmount-image /mountdir:D:\winpe_amd71\mount /commit
#MakeWinPEMedia /ISO D:\winpe_amd71 D:\winpe_amd71\WinPE_ASDK_Stack.iso


#MakeWinPEMedia /UFD D:\winpe_amd71 P:



