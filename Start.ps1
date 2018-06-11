<#
.SYNOPSIS
This script will be automatically started by the WINPE installer. 
The function of this script is to validate if internet is present and if so, to download the latest deployment files
If no internet is found, it will continue to use the local version of the PrepareAzureStack.ps1 and psm1 scripts


.DESCRIPTION


 .NOTES
#>

<#
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
#>

[cmdletbinding()]
    param (
        [parameter(Mandatory = $false)]
        [boolean]$ForceRun,

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

If (!($CustomGitBranch)){$CustomGitBranch='master'}
If (!($CustomGitLocation)){$CustomGitLocation='RZomerman/ASDK'}

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
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
$winPEStartTime = (Get-Date).ToString('yyyy/MM/dd HH:mm:ss')
#$ScriptVersion=(Get-Item x:\PrepareAzureStackPOC.ps1).LastWriteTime



cls
Write-Host "      *********************************************" -foregroundColor Yellow
write-host "        Welcome to the PRE ASDK PREPARATION SCRIPT " -foregroundColor Yellow
Write-Host "      *********************************************" -foregroundColor Yellow
write-host ""
Write-Host "Validating if a newer version of this script is available"


$ScriptVersion=Get-FileContents 'x:\PrepareAzureStackPOC.ps1'
 Foreach ($line in $ScriptVersion) {
            If ($line -like '$version=*') {
                $Localversion=$line.replace('$version=','')
                $Localversion=$Localversion.replace('"',"")
                Write-host "Stored file is version" $Localversion
                break
            }
}

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Connection = test-connection -computername raw.githubusercontent.com -count 1 -quiet
    If (!$Connection) {
        Write-Host "No Internet connection available. Using local script"
    return $false
    }elseIf ($Connection) {
        $GitHubLocation=('https://raw.githubusercontent.com/' + $CustomGitLocation + '/' + $CustomGitBranch + '/')
        $Uri = ($GitHubLocation + 'PrepareAzureStackPOC.ps1')
        $OutFile  = ($env:TEMP + '\' + 'PrepareAzureStackPOC.ps1')
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
            Write-host "Newer version found online, downloading updated support scripts...."
            $Uri = ($GitHubLocation + 'PrepareAzureStackPOC.psm1')
            $OutFile  = ($env:TEMP + '\' + 'PrepareAzureStackPOC.psm1')
            DownloadWithRetry -url $uri -downloadLocation $outfile -retries 3

            Copy-item ($env:TEMP + '\' + 'PrepareAzureStackPOC.psm1') 'x:\PrepareAzureStackPOC.psm1' -force
            Copy-item ($env:TEMP + '\' + 'PrepareAzureStackPOC.ps1') 'x:\PrepareAzureStackPOC.ps1' -force

        }
        Elseif ($version -eq $Localversion){
            Write-host "local verison to up date"
        }
        Else {
            Write-host "local version is newer"
        }
    }
#Manual deployment straight from start
    If ($ForceRun){
        $BaseCommand='x:\PrepareAzureStackPOC.ps1'
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
        $Command=($BaseCommand + $NewCommand)
        Write-Verbose $Command
        Invoke-Expression "& `"$BaseCommand`" $NewCommand"
    
        Exit
    }
#Automated deployment will be added below


