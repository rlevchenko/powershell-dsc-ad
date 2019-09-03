## PowerShell DSC | Active Directory (two controllers)
Automates deployment of a new Active Directory forest consisting of two domain controllers. Scripts are based on PowerShell DSC and originally were created for using along with Virtual Machine Manager templates. 

## Please note

- All-in-one : one file to configure a forest with two DCs
- first. cr : custom resource with PowerShell DSC script to configure root DC
- second.cr : custom resource with PowerShell DSC script to add the second DC
- Written, tested and verified in far 2016. Should work with later WS though.