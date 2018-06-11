If ($CustomXML.custom.InternalNetwork){
        If (test-path C:\CloudDeployment\Configuration\OneNodeCustomerConfigTemplate.xml) {
            write-LogMessage -Message "Setting Additional Internal Network Addresses"
            (Get-Content C:\CloudDeployment\Configuration\OneNodeCustomerConfigTemplate.xml).replace('192.168.', $CustomXML.custom.InternalNetwork.value) | Set-Content C:\CloudDeployment\Configuration\OneNodeCustomerConfigTemplate.xml
            If (test-path C:\CloudDeployment\Setup\DeploySingleNode.ps1) {
                (Get-Content C:\CloudDeployment\Setup\DeploySingleNode.ps1).replace('192.168.', $CustomXML.custom.InternalNetwork.value) | Set-Content C:\CloudDeployment\Setup\DeploySingleNode.ps1
            }
        }
    }