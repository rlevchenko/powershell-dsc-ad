<#
.Description
       Active Directory Deployment (2 DCs, PowerShell DSC)
.NOTES
       Name: AD
       Author : Roman Levchenko
       WebSite: www.rlevchenko.com
       Prerequisites: DC02 must be online
       Post-installation steps: check replication and overall health
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
param ()

# Creates HA DC ,2 nodes (DC01 and DC02). DC02 must be online.

#Parameters
$domainname=$args[0]
$netbios=$DomainName.split(“.”)[0]
$pwd = ConvertTo-SecureString "Pass123" -AsPlainText -Force
$domainCred = New-Object System.Management.Automation.PSCredential ("$netbios\Administrator", $pwd)
$safemodeAdministratorCred = New-Object System.Management.Automation.PSCredential ("$netbios\Administrator", $pwd)
$localcred = New-Object System.Management.Automation.PSCredential ("Administrator", $pwd)

####For securing MOF####
#$CertPW=ConvertTo-SecureString “Pass123” -AsPlainText -Force
#Import-PfxCertificate -Password $certpw -CertStoreLocation Cert:\LocalMachine\My -FilePath C:\publickey.pfx
########################

#Update Hosts (optional, no module required)
#$Name="$env:computername"
#$hosts = "$env:windir\System32\drivers\etc\hosts"
#if ($Name -eq "DC01") {"ip DC02"| Add-Content -passthru $hosts; set-item wsman:\localhost\Client\TrustedHosts -value "DC02" -Force }
#Elseif ($Name -eq "DC02") { "ip DC01"|Add-Content -PassThru $hosts; set-item wsman:\localhost\Client\TrustedHosts -value "DC01" -force}
########################

configuration HADC
{
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xNetworking

    Node $AllNodes.Where{$_.Role -eq "Primary DC"}.Nodename
    {
        LocalConfigurationManager            #Set LCM on DC01
        {            
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true    
            #CertificateId      = $AllNodes.Thumbprint         
       
        }  

        xHostsFile HostsUpd #Adds hosts record for DC02 (need to be prepared before script execution)
        {
          HostName  = 'DC02'
          IPAddress = 'ip here'
          Ensure    = 'Present'
        }
        xDhcpClient DisabledDhcpClient #DHCP Off
        {
            State          = 'Disabled'
            InterfaceAlias = "Ethernet"
            AddressFamily  = "IPv4"
        }

        xIPAddress NewIPAddress #New IP for DC01
        {
            IPAddress      = "ip here"
            InterfaceAlias = "Ethernet"
            SubnetMask     = 24
            AddressFamily  = "IPV4"
        }
         
        WindowsFeature ADDSInstall #Installs Windows Server roles
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }
	    WindowsFeature ADDSTools  #Optional          
        {             
            Ensure = "Present"             
            Name = "RSAT-ADDS"             
        }           

        xADDomain FirstDS #Prepares first DC in the new forest/domain
        {
            DomainName = $domainname
            DomainAdministratorCredential = $domaincred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

    }

    Node $AllNodes.Where{$_.Role -eq "Replica DC"}.Nodename #DC02 configuration starts here
    {
        LocalConfigurationManager            
        {            
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true  
            #CertificateId      = $AllNodes.Thumbprint         
             
        } 
        WindowsFeature ADDSInstall 
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
        }

        xWaitForADDomain DscForestWait #Waits while domain becomes available
        {
            DomainName = $domainname
            DomainUserCredential = $domaincred
            RetryCount = $Node.RetryCount
            RetryIntervalSec = $Node.RetryIntervalSec
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        xADDomainController SecondDC #Starts DC configuration
        {
            DomainName = $domainname
            DomainAdministratorCredential = $domaincred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }
    }
}
#If config file separated from the script use these lines
#$temp=Get-Content .\configdata.psd1
#$temp.replace("domain.com","$domainname") | set-content .\configdata.psd1 -force|Out-Null
#$config = Invoke-Expression (Get-content .\configdata.psd1 -Raw)

#Configuration Data for DCs
$ConfigData= @{
    AllNodes = @(

        @{
            Nodename = "DC01"
            Role = "Primary DC"
            PSDscAllowPlainTextPassword = $true
            #Thumbprint="‎cert details" 
            RetryCount = 20 
            RetryIntervalSec = 30 
        },

        @{
            Nodename = "DC02"
            Role = "Replica DC"
            PSDscAllowPlainTextPassword = $true
            #Thumbprint="‎cert details" 
            RetryCount = 20 
            RetryIntervalSec = 30 
        }
    )
}

#Creats MOF files
HADC -configurationData $configdata

#Sets LCM on DC01 and DC02
Set-DSCLocalConfigurationManager -Path .\HADC –Verbose 
Set-DSCLocalConfigurationManager -Path .\HADC –Verbose   -ComputerName "DC02" 

#Starts DSC on DC01 and DC02 (check status by running Get-DSCLocalConfigurationManager or events)
Start-DscConfiguration -Wait -Force -Verbose -ComputerName DC01 -Path .\HADC -Credential $localcred
Start-DscConfiguration -Wait -Force -Verbose -ComputerName DC02 -Path .\HADC -Credential $localcred

