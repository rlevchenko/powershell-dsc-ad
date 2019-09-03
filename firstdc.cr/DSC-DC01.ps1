<#                       
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |w|w|w|.|r|l|e|v|c|h|e|n|k|o|.|c|o|m|
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                                                                    

::Root DC Configuration (PowerShell/DSC)
                                                                                             
 #>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
param ()

#Parameters
$domainname="rl-" + $args[0]+'.com'
$netbios="rl-"+$args[0]
$dcname="rl-"+$args[0]+'-'+"DC01"
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
$fullip=$address + "10"#>

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

configuration DC01
{   
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xNetworking
    Import-DscResource -ModuleName xComputerManagement
    Import-DscResource -ModuleName xPendingReboot

    Node $AllNodes.Nodename
    {
         LocalConfigurationManager #LCM Settings            
        {            
            ConfigurationMode = 'ApplyOnly'
            #RebootNodeIfNeeded = $false
            #CertificateId      = $AllNodes.Thumbprint         
        } 
        xIPAddress NewIPAddress #Set IPv4 on Ethernet adapter
        {
            IPAddress      = $ip
            InterfaceAlias = "Ethernet"
            SubnetMask     = 24
            AddressFamily  = "IPV4"
        } 
        xDnsServerAddress DNSServers #Set DC01 as a primary DNS Server
        {
           
            Address        = $Node.DNSAddresses
            InterfaceAlias = "Ethernet"
            AddressFamily  = "IPV4"
            DependsOn      = "[xIPAddress]NewIPAddress"

        } 

         xDefaultGatewayAddress GW #Set GW address 
        {
            Address = $gw
            InterfaceAlias = "Ethernet"
            AddressFamily = "IPv4" 

        }

         xComputer PCName #Set PC Name
     
        {
            Name          = $dcname
            DependsOn     = "[xIPAddress]NewIPAddress"
        }
         
         xPendingReboot BeforeADDSInstall #If reboots are required?
        {
            Name      = "BeforeADDSInstall"

            DependsOn  = "[xComputer]PCName"
        }

        WindowsFeature ADDSInstall #Add server roles and features
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
            DependsOn = "[xPendingReboot]BeforeADDSInstall"
        }
        WindowsFeature ADDSTools    #Optional        
        {             
            Ensure = "Present"             
            Name = "RSAT-ADDS"
            DependsOn = "[WindowsFeature]ADDSInstall"             
        }  
     
        xADDomain FirstDC #Starts New forest configuration
        {
            DomainName = $domainname
            DomainAdministratorCredential = $domaincred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        Script Sleep #dreaming..
        {
        GetScript  =  {return $null}
        TestScript =  {return $false}
        SetScript  =  {Start-Sleep -Seconds 120}
        DependsOn  =  "[xADDomain]FirstDC"
        }
     
        xPendingReboot AfterFirstDC #reboot
        {
            Name      = "AfterFirstDC"

            DependsOn  = "[Script]Sleep"
        } 
        LocalConfigurationManager
        {
         
          RebootNodeIfNeeded = $true

        }
        ## 10/17 Update
        WindowsFeature WinBackup
        {
            Ensure = 'Present'
            Name = 'Windows-Server-Backup'
            DependsOn  = '[xPendingReboot]AfterFirstDC'
        }
        ## End
        
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

#For external config (optional)
#$temp=Get-Content .\configdata.psd1
#$temp.replace("domain.com","$domainname") | set-content .\configdata.psd1 -force|Out-Null

#Configuration data for nodes
$ConfigData = @{
    AllNodes = @(

        @{
            Nodename = $dcname
            PSDscAllowPlainTextPassword = $true
            RetryCount = 20 
            RetryIntervalSec = 30 
            DNSAddresses = @(
            $dns1
            "127.0.0.1"
            )
            #Thumbprint="‎cert details here" 
        }
    )
  }

#For external config (optional)
#$config = Invoke-Expression (Get-content .\configdc01.psd1 -Raw)

#Creating mof files
DC01 -configurationData $configdata

#Set LCM
Set-DSCLocalConfigurationManager -Path .\DC01 –Verbose 

#Start DSC
Start-DscConfiguration -Wait -Force -Verbose -Path .\DC01 -Credential $localcred
