<#                       
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |w|w|w|.|r|l|e|v|c|h|e|n|k|o|.|c|o|m|
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                                                                    

:: Additional DC configuration (PowerShell/DSC)
                                                                                             
 #>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
param ()

#Parameters
$domainname="rlevchenko" + $args[0]+'.com'
$netbios="rl-"+$args[0]
$dcname="rl"+$args[0]+'-'+"DC02"
$pwd = ConvertTo-SecureString "Pass1234" -AsPlainText -Force
$domainCred = New-Object System.Management.Automation.PSCredential ("$netbios\Administrator", $pwd)
$safemodeAdministratorCred = New-Object System.Management.Automation.PSCredential ("$netbios\Administrator", $pwd)
$localcred = New-Object System.Management.Automation.PSCredential ("Administrator", $pwd)
$gw="gw ip here"
$ip="desired dc ip here"
$dns1="first dns server ip"

<#$ip=(Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).IPAddress
$hostpart=$ip.split(".")[3]
$address=$ip.TrimEnd("$hostpart")
$fullip=$address + '11'#>

####For securing MOF####
#$CertPW=ConvertTo-SecureString “Pass123” -AsPlainText -Force
#Import-PfxCertificate -Password $certpw -CertStoreLocation Cert:\LocalMachine\My -FilePath C:\publickey.pfx
########################

#Update Hosts (optional, no module required)
#$Name="$env:computername"
#$hosts = "$env:windir\System32\drivers\etc\hosts"
#if ($Name -eq "DC01") {"dc02ip DC02"| Add-Content -passthru $hosts; set-item wsman:\localhost\Client\TrustedHosts -value "DC02" -Force }
#Elseif ($Name -eq "DC02") { "dc01ip DC01"|Add-Content -PassThru $hosts; set-item wsman:\localhost\Client\TrustedHosts -value "DC01" -force}
########################

configuration DC02
{
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xNetworking
    Import-DscResource -ModuleName xComputerManagement
    Import-DscResource -ModuleName xPendingReboot

    Node $AllNodes.Nodename
    {
         LocalConfigurationManager            
        {            
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true 
           # CertificateId      = $AllNodes.Thumbprint         
                      
        }  

         xIPAddress NewIPAddress #Set Static IPv4
        {
            IPAddress      = $ip
            InterfaceAlias = "Ethernet"
            SubnetMask     = 24
            AddressFamily  = "IPV4"
        }
         xDefaultGatewayAddress GW #Set GW address 
        {
            Address = $gw
            InterfaceAlias = "Ethernet"
            AddressFamily = "IPv4" 

        }

        xDnsServerAddress DNSServers #Set DC01 as a primary DNS Server
        {
           
            Address        = $Node.DNSAddresses
            InterfaceAlias = "Ethernet"
            AddressFamily  = "IPV4"
            DependsOn      = "[xIPAddress]NewIPAddress"

        } 
          

         xComputer PCName #Set PC Name
     
        {
            Name = $dcname
            WorkgroupName = "Workgroup"
            DependsOn     = "[xDnsServerAddress]DNSServers"
        }
          xPendingReboot BeforeADDSInstall #If reboots are required?
        {
            Name      = "BeforeADDSInstall"

            DependsOn  = "[xComputer]PCName"
        }

         WindowsFeature ADDSInstall #Install server roles
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
            DependsOn = "[xPendingReboot]BeforeADDSInstall"

        }
        
        WindowsFeature ADDSTools #Optional            
        {             
            Ensure = "Present"             
            Name = "RSAT-ADDS" 
            DependsOn = "[WindowsFeature]ADDSInstall"             
            
        } 
               xPendingReboot BeforeAddDC #If reboots are required?
        {
            Name      = "BeforeAddDC"

            DependsOn  = "[WindowsFeature]ADDSTools"
        }
        xWaitForADDomain DscForestWait #Waits while domainname becomes online (10 minutes)
        {
            DomainName = $domainname
            DomainUserCredential = $domaincred
            RetryCount = $Node.RetryCount
            RetryIntervalSec = $Node.RetryIntervalSec
            DependsOn = "[xPendingReboot]BeforeAddDC"
        }

        xADDomainController SecondDC #COnfigures second DC on the existing domain
        {
            DomainName = $domainname
            DomainAdministratorCredential = $domaincred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }
        xPendingReboot AfterSecondDC #If reboots are required?
        {
            Name      = "AfterSecondDC"

            DependsOn  = "[xADDomainController]SecondDC"
        }

        WindowsFeature WinBackup
        {
            Ensure = 'Present'
            Name = 'Windows-Server-Backup'
            DependsOn  = '[xPendingReboot]AfterSecondDC'
        }

    #### Delete DNS Forwarders and create txt file @end #####     
   
        Script GetStatus 
        {
            GetScript  = {return $null}
            SetScript  = {
                            New-Item -ItemType File -Path C:\DSC\setupisfinished.txt
                            Remove-DnsServerForwarder -IPAddress $using:dns1 -Force

                         }
            TestScript = {Test-Path -Path C:\DSC\setupisfinished.txt}
            DependsOn  = '[WindowsFeature]WinBackup' 
            Credential = $creds
        }

    }

 }
 $ConfigData = @{
    AllNodes = @(

        @{
            Nodename ="localhost"
            PSDscAllowPlainTextPassword = $true
            RetryCount = 30
            RetryIntervalSec = 30 
            DNSAddresses = @(
            $dns1
            '127.0.0.1'
            )

            #Thumbprint="‎cert details" 
        }
    )
  }

#For external config (optional)
#$temp=Get-Content .\configdata.psd1
#$temp.replace("domain.com","$domainname") | set-content .\configdata.psd1 -force|Out-Null
#$config = Invoke-Expression (Get-content .\configdc02.psd1 -Raw)

#Creating mof files
DC02 -configurationData $configdata

#Sets LCM
Set-DSCLocalConfigurationManager -Path .\DC02 –Verbose 

#Starts DSC
Start-DscConfiguration -Wait -Force -Verbose -Path .\DC02 -Credential $localcred
