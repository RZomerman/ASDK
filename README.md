# Azure Stack Development Kit (ASDK) Installer script

This PowerShell script to automated the deployment of [Azure Stack Development Kit (ASDK)](https://docs.microsoft.com/en-us/azure/azure-stack/asdk/asdk-what-is)

The script has two options: USB or Network sourced
* **If USB sources**: it can be placed in a dual-partition USB {1st being the winPE} and 2nd partition containing CloudBuilder.vhdx and ASDKUnattend.xml. This script will download the adsk_installer and master.zip scripts 
> This script autodetects if a USB with cloudbuilder.vhdx is present on a USB drive
* **If internet is found**: If the network mentioned settings are added and $override is specified, it will auto connect to the network and copy the required files.

> Make to sure have CloudBuilder.vhdx and ASDKUnattend.xml in the same network share
> If ADSKUnattend.xml does not exist, this script will create one, with default P@ssw0rd!
