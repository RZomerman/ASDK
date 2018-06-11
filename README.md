# Azure Stack Development Kit (ASDK) Installer script

CreateASDKDeploymentISO.ps1
    
    Run from an Administrative PowerShell: 
        CreateASDKDeploymentISO.ps1 -TargetDirectory <folder to create ISO> -ASDKPassword <Password>
    to create a new ISO deployment file. The <folder to create ISO> should not yet exist. For example c:\winpeISO
    The script will use the Windows ADK to create a new ISO file that contains WindowsPE. During the creation it will download the latest scripts
        from the GitHub repository and place these on the root of WinPE (PrepareAzureStackPOC.ps1 / psm1 and Start.ps1). It will also download
        the winpe.jpg file from GitHub and place it in the System32 folder of the WinPE.
    If Windows ADK is not yet installed, it will trigger and monitor the installation) quietly. This might take a whlie as the ADK will download 
        additional files. 
    Once the download is complete, boot your server from the ISO. 


    OPTIONAL PARAMETERS
        CustomGitLocation - to use a custom GITHUB repo : 
            CreateASDKDeploymentISO.ps1 -TargetDirectory <folder to create ISO> -CustomGitLocation <username>/Repository

        CustomGitBranch - use a custom GITHUB branch : 
            CreateASDKDeploymentISO.ps1 -TargetDirectory <folder to create ISO> -CustomGitBranch development

        ASDKPassword - password will be used for the deployment. If no password is specified, the PrepareAzureStackPOC.ps1 will ask for a password
            CreateASDKDeploymentISO.ps1 -ASDKPassword <Password>
        
        NetworkVHDLocation - specifies folder where to find the cloudbuilder.vhd 
            Must be specified together with
                ShareUserName - username to access the network share
                SharePassword - password to access the network drive
            
                    CreateASDKDeploymentISO.ps1 -NetworkVHDLocation <UNCPath> -ShareUsername <user> -SharePassword <password>

    

    example:
            CreateASDKDeploymentISO.ps1 -ASDKPassword MYPAssword -TargetDirectory c:\test2 -ShareUsername AzureStack -SharePassword
                AzureStack -NetworkVHDLocation \\172.16.5.9\azurestack\DeployAzureStack\MASImage -CustomGitBranch development -CustomGitLocation RZomerman/ASDK
        

        Important:
            Git repository and GitBranch are CaSeSensiTive 


Start.ps1
    This script is ran initially when booting from the created ISO. It will check for the latest script versions and if a newer PrepareAzureStackPOC.ps1 is found
        it will download it and run the newer version.

    OPTIONAL PARAMETERS
        CustomGitLocation - to use a custom GITHUB repo : 
            CreateASDKDeploymentISO.ps1 -TargetDirectory <folder to create ISO> -CustomGitLocation <username>/Repository

        CustomGitBranch - use a custom GITHUB branch : 
            CreateASDKDeploymentISO.ps1 -TargetDirectory <folder to create ISO> -CustomGitBranch development

PrepareAzureStackPOC.ps1 / psm1
    This script will prepare the server for ASDK. It can run in multiple modes, which are described later. The script will !DELETE ALL DATA ON ALL DRIVES! and          therefore NEVER run the script on anything else than your ASDK host. (there are some failsaves built-in, but the warning stands). After preparing the drives 
        it will download support scripts and services and if a Dell hardware host is found, it will also download Dell OpenManage. It will also try to find the 
        CloudBuilder.vhdx (the ASDK file) from multiple sources

        USB: If a local USB drive is found, the cloudbuilder.vhdx will be searched on the root of the USB drive
        Network: 
            If $override=$true is specified, the script will ask for network location, credentials and the path to the cloudbuilder.vhdx
            If $override=$false is specified, the script will use all variables defined in the script
        Download:
            If the script is running in Windows 2012/2016, the download option is available. It will download the latest version and unpack the download
                (this might take a while)
            - The version for winPE is in the works
            If download is selected and a local USB is present, the downloaded/unpacked cloudbuilder.vhdx will be copied onto the USB if there is enough room

PrepareInstallation.ps1
    After the WinPE part of the deployment is completed, the server will be rebooted in the ASDK vhdx. After the initial boot, the PrepareInstallation.ps1 is started
    This script will install the supporting bits (like OpenManage, Visual Studio Code... ) as well as prepare the host by disabling Windows Update, enabling high-power scheme and other items.
    If a custom installation document is found, the ASDK deployment will follow the customizations in the JSON file. 

This PowerShell script to automated the deployment of [Azure Stack Development Kit (ASDK)](https://docs.microsoft.com/en-us/azure/azure-stack/asdk/asdk-what-is)
