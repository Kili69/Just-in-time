<#
Script Info

Author: Andreas Lucas/Andreas Luy [MSFT]
Download: 

Disclaimer:
This sample script is not supported under any Microsoft standard support program or service. 
The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
all implied warranties including, without limitation, any implied warranties of merchantability 
or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
damages whatsoever (including, without limitation, damages for loss of business profits, business 
interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
possibility of such damages
#
#
.Synopsis
    This script create and maintain the local administrator groups

.DESCRIPTION
    this script run in the context of a GroupManagedServiceAccount and create a domain local group for each 
    server in the Tier1 Management OU
.PARAMETER configurationFile
    The ful qualified path to the configuration file. If this parameter is not available the script 
    will use the JIT.config will use the jit.config in the current directory

.EXAMPLE
    .\Tier1LocalAdminGroup.ps1
    run the script with the configuration file in the current directory
    .\Tier1LocalAdminGroup.ps1 -configurationFile "\\contoso.com\SYSVOL\contoso.com\JIT\jit.config"
    run the script with a dedicated configuration fil

.INPUTS
    -configurationFile
        use a dedicated configuration file. use this parameter if the configuration file is not in the working directory

.OUTPUTS
   none
.NOTES
    Version Tracking
    2021-10-12 
    Version 0.1
        - First internal release
    Version 0.1.2021294
        - Default installation directory changed from c:\Program Files\windowsPowershell\script to %working directory%
        - Added Event logging
    Version 0.1.20231113
        -exit code on error
        -mulit domain-forest support 
        -Domain DNS name on groups replaced with Domain NetBiosName
    Version 0.1.20231204
        - New Event 1004 if a OU doesn't exists
        - Code documentation
    Version 0.1.20240124
        - Bug fix on searchbase
    Version 0.1.20240202
        - Avoid error messages while search for computers in a different OU
        - Addtional Debug messages
    Version 0.1.20240726
        - If the paramter configuration file is not provided, the global environment variable JustInTimeConfig will be used
        instead of the local directory
    Version 0.1.20241227
        by Andreas Luy
	    Fixing minor bugs
    Version 0.1.20250127
        by Andreas Luy
	    re-writing to support AD-based configuration and delegation

    Event ID
    1000 Information LocalAdmin Group created
    1001 Error Group not created
    1002 Information permanent user removed
    1003 Error removing permanent user
    1004 Warning The Organizational unit doesn't exists
    1005 Information Server delegation has been updated
    1006 Error Server delegation could not be updated
    1007 Error delegation does not exist
    1100 Error configuration file missing 
    1101 Error invalid configuration file version 
    1110 Error delegation file hash mismatch
    
    exit code 
    0x3E8 configuratin file missing
    0x3E9 invalid configuration file version
    0x3EA malformed JSON file
#>
[CmdletBinding ( SupportsShouldProcess)]
#Script Version
$_scriptVersion = "20250102"
[int]$_configBuildVersion = "20241003"
$MinConfigVersionBuild = 20240123
Write-Debug "Script Version $_scriptVersion"

#load module
Import-Module Just-In-Time
if (!(Get-Variable DefaultJiTADCnfgObjectDN -Scope Global -ErrorAction SilentlyContinue)) {
    Set-Variable -name DefaultJiTADCnfgObjectDN -value ("CN=Jit-Configuration,CN=Just-In-Time Administration,CN=Services,"+(Get-ADRootDSE).configurationNamingContext) -Scope Global -Option ReadOnly
}
if (!(Get-Variable JitCnfgObjClassName -Scope Global -ErrorAction SilentlyContinue)) {
    Set-Variable -name JitCnfgObjClassName -value "JiT-ConfigurationObject" -Scope Global -Option ReadOnly
}
if (!(Get-Variable JiTAdSearchbase -Scope Global -ErrorAction SilentlyContinue)) {
    Set-Variable -name JiTAdSearchbase -value ("CN=Delegations,CN=Just-In-Time Administration,CN=Services,"+(Get-ADRootDSE).configurationNamingContext) -Scope Global -Option ReadOnly
}
if (!(Get-Variable JitDelegationObjClassName -Scope Global -ErrorAction SilentlyContinue)) {
    Set-Variable -name JitDelegationObjClassName -value "jiT-DelegationObject" -Scope Global -Option ReadOnly
}
if (!(Get-Variable config -Scope Global -ErrorAction SilentlyContinue)) {
    Set-Variable -name config -value (Get-JITconfig) -Scope Global -Option AllScope
}

function Write-ScriptLogMessage {
    param (
        [Parameter (Mandatory, Position=0)]
        [string] $Message,
        [Parameter (Mandatory=$false, Position=1)]
        [ValidateSet('Information','Warning','Error')]
        [string] $Severity = 'Information'
    )
    switch ($Severity) {
        'Warning' { $ForegroundColor = 'Yellow'}
        'Error'   { $ForegroundColor = 'Red'}
        Default   { $ForegroundColor = 'Gray'}
    }
    Write-Host $Message -ForegroundColor $ForegroundColor
}

function Write-LogFile {
    param (
        # status message
        [Parameter(Mandatory=$true)]
        [string]
        $Message,
        #Severity of the message
        [Parameter (Mandatory = $true)]
        [Validateset('Error', 'Warning', 'Information', 'Debug') ]
        $Severity
    )
    #Format the log message and write it to the log file
    $LogLine = "$(Get-Date -Format o), [$Severity],[$eventRecordID], $Message"
    Add-Content -Path $LogFile -Value $LogLine -ErrorAction SilentlyContinue
    switch ($Severity) {
        'Error'   { 
            Write-Host $Message -ForegroundColor Red             
            Add-Content -Path $LogFile -Value $Error[0].ScriptStackTrace   -ErrorAction SilentlyContinue
        }
        'Warning' { Write-Host $Message -ForegroundColor Yellow}
        'Information' { Write-Host $Message }
        }

}

function Get-DomainDNSfromDN 
{
    param(
        [Parameter (Mandatory=$true)][string]$AdObjectDN
    )
    $DomainDNS = (($AdObjectDN.tolower()).substring($AdObjectDN.tolower().IndexOf('dc=')+3).replace(“,dc=”,“.”))
    return $DomainDNS
}



Write-LogFile -Severity Debug -Message "sucessfully read the JiT configuration"

#region Manage log file
[int]$MaxLogFileSize = 1048576 #Maximum size of the log file
if (!(Test-Path -Path "$($env:ProgramData)\Just-In-Time")) {
    New-Item -Path "$($env:ProgramData)\Just-In-Time" -ItemType Directory
}
$LogFile = "$($env:ProgramData)\Just-In-Time\$($MyInvocation.MyCommand).log" #Name and path of the log file
#rename existing log files to *.sav if the currentlog file exceed the size of $MaxLogFileSize
if (Test-Path $LogFile){
    if ((Get-Item $LogFile ).Length -gt $MaxLogFileSize){
        if (Test-Path "$LogFile.sav"){
            Remove-Item "$LogFile.sav"
        }
        Rename-Item -Path $LogFile -NewName "$logFile.sav"
    }
}
#endregion

Write-ScriptLogMessage -Message "Tier1LocalAdminGroup & Delegation management process started (RequestID $eventRecordID). Detailed logging available $LogFile" -Severity Information #-EventID 2106
Write-LogFile -Message "Script Version $_ScriptVersion. Minimum required config Version $MinConfigVersionBuild" -Severity Information 

#region check for enabled and configured delegation
$Delegation = @()
if ($global:config.EnableDelegation) {
    $Delegation = Get-JitDelegation
}
#endregion

#region Group creation
# In this region the AD groups will be created and users on existing groups will be 
# removed if they are permanent members
#
# if Multi-Domain Mode is enabled add all domains to the $aryDomainList otherwise add only 
# the current domain to the array
$aryDomainList = @()
if ($global:config.EnableMultiDomainSupport) {
    $aryDomainList += (Get-ADForest).Domains
}
else {
    $aryDomainList += (Get-ADdomain).DNSRoot
}

#defining T1 server array
$T1ServerList = @()

#Region show progress activit init
#This section is not mandatory. It is only required for the interactive execution of the script to show the progress
$Starttime = Get-Date #Start time of the script to evaluate the runtime of the script
$GroupCount = 0 #Initialize the over all counter of detected computer object 
$Statuscounter = 0 #Initialize the counter a executed groups activites. THis could be creating the group or remove permanent objects from the group
#endregion

Foreach ($Domain in $aryDomainList) {
    #Working on every domain in the Forest
    Write-Debug "Working on Domain $Domain"
    #The searchbase parameter defines the OU where the script is looking for computer objects. 
    #if the value is <DomainRoot> the script searches in the entire domain from computer objects
    Foreach ($SearchBase in $global:config.T1Searchbase) {
        if ($SearchBase -notlike "*DC=*"){
            if ($SearchBase -eq "<DomainRoot>") {
                $SearchBase = (Get-ADDomain -Server $Domain).DistinguishedName
            }
            else {
                $SearchBase += ",$((Get-ADDomain -Server $Domain).DistinguishedName)"
            }
        }
        #Validate the OU exists. It is not mandatory to have the same Tier 1 OU structure in all domains
        if ($SearchBase -like "*$((Get-ADDomain -Server $Domain).DistinguishedName)") {
            #Search for computer object in the OU and based on the LDAP filter. 
            #While the LDAP filter doesn't support DistinguishedNames, the query must work against the $searchbase
            #$serverList = Get-ADComputer -LDAPFilter $global:config.LDAPT1Computers -Properties memberof,groupPriority -SearchBase $Searchbase -Server $Domain | Where-Object { $_.DistinguishedName -notlike "*$($global:config.LDAPT0ComputerPath)*" }
            #$serverList = Get-ADComputer -LDAPFilter $global:config.LDAPT1Computers -Properties memberof -SearchBase $Searchbase -Server $Domain | Where-Object { $_.MemberOf -notlike "*$($global:config.Tier0ServerGroupName)*" }
            $TmpServerList = Get-ADComputer -LDAPFilter $global:config.LDAPT1Computers -Properties memberof -SearchBase $Searchbase -Server $Domain
            #now we need to filter out all computer objects which are member of any tier 0 group in that domain
            foreach ($T0Group in $global:config.Tier0ServerGroupName) {
                #looking only for tier 0 groups of current working domain
                if ((Get-DomainDNSfromDN -AdObjectDN $T0Group) -eq $Domain) {
                    foreach ($Server in $TmpServerList) {
                        #checking server is member of T0 group
                        if ($Server.MemberOf -notcontains $T0Group) {
                            $T1ServerList += $Server
                        }
                    }
                }
            }
            $GroupCount += $T1ServerList.count #Display parameter to show the amount of computer object currently working on.
#            $NBDomain = (Get-ADDomain -Server $Domain).NetbiosName
            $DnsDomain = (Get-ADDomain -Server $Domain).DnsRoot
            Foreach ($Server in $T1ServerList) {
                $Statuscounter ++
                #Show progress for interactive execution
                Write-Progress -Activity "Group Management" -Status "groups completed $Statuscounter" -PercentComplete (($Statuscounter / $GroupCount) * 100)
                #If MultiDomain Support is enabled the domain DNS name will be added 
                #between Admin-Prefix and the computer name
                if ($global:config.EnableMultiDomainSupport) {
                    $GroupName = "$($global:config.AdminPrefix)$($DnsDomain)$($global:config.DomainSeparator)$($server.Name)"
                }
                else {
                    $GroupName = "$($global:config.AdminPreFix)$($Server.Name)"
                }
                #Check the group already exists. If not create a new group otherwise check for the groupmembers
                if (!([bool](Get-ADGroup -Filter { Name -eq $GroupName }))) {   
                    #create the Tier 1 computer group objects if they don't exists
                    try {
                        New-ADGroup -GroupCategory Security -GroupScope DomainLocal -SamAccountName $GroupName -Name $GroupName -Description "Provide Administrators privilege on $($Server.Name)" -Path $global:config.OU 
                        Write-EventLog -LogName $global:config.EventLog -Source $global:config.EventSource -EventId 1000 -Message "New Local admin group $GroupName created" -EntryType Information
                        Write-Output "New Local admin group $GroupName created"
                    }
                    catch {
                        Write-EventLog -LogName $global:config.EventLog -Source $global:config.EventSource -EventId 1001 -Message "Error creating Local Admin group $groupname : $Error[0]"  -EntryType Error
                        Write-Output "Error creating Local Admin group $groupname : $Error[0]"
                    }
                }
                else {
                    #remove any not timebombed object
                    #If the member property doesn't contains a TTL remove them from the group 
                    Foreach ($Member in (Get-ADGroup $GroupName -Property members -ShowMemberTimeToLive).members) {
                        Write-Debug "Removeing permanent users from $GroupName"
                        $Regex = [RegEx]::new("<TTL=\d*>,CN=.")
                        $Match = $Regex.Match($Member)
                        if (!$Match.Success -eq $true) {
                            try {
                                #here is still a bug if member is from a child domain
                                Get-ADGroup $GroupName | Remove-ADGroupMember -Members (Get-ADObject -Identity $Member ) -Confirm:$false
                                Write-EventLog -LogName $global:config.EventLog -Source $global:config.EventSource -EventId 1002 -Message "Removing permanent user $Member from group $GroupName" -EntryType Warning
                                Write-Output "Removing permanent user $Member from group $GroupName"
                            }
                            catch {
                                Write-EventLog -LogName $global:config.EventLog -Source $global:config.EventSource -EventId 1003 -Message "Can not remove permanent user from $GroupName $Error" -EntryType Error
                            }
                        }
                    }
                }
            }

            Write-Progress -Activity "Group Management" -Completed
        } else {
            Write-EventLog -LogName $global:config.EventLog -Source $global:config.EventSource -EventId 1004 -Message "$Domain : The OU $searchbase could not be found" -EntryType Warning
            Write-Output "$Domain : The OU $searchbase cound not be found"
        }
    }
}
#endregion
Write-Output "working on $GroupCount in $((Get-Date)-$Starttime)"

Remove-Variable -Name config -Scope Global -Force

