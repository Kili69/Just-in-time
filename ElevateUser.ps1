<#
Script Info

Author: Andreas Lucas/Andreas Luy [MSFT]
Download: https://github.com/Kili69/T1JIT

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
#>
<#
.Synopsis
    This script add the user object into a local group 

.DESCRIPTION
    This script adds users to the JIT administrators groups. The script is triggerd by the schedule 
    task in the context of the Group Managed service accounts.

.EXAMPLE
    .\ElevateUser.ps1   1000, xxx, .\jit.config

.INPUTS
.PARAMETER eventRecordID
    is the Event record ID 
.PARAMETER ConfigurationFile
    full qualified path to the configuration file
.EXAMPLE
    ElevateUser.ps1 -EventRecordID 1000 -Configurationfile \\contoso.com\SysVol\contoso.com\JIT\config.JIT

.OUTPUTS
   none
.NOTES
    Version Tracking
    Version 0.1.20231031
        Support of delegation mode
    Version 01.20231109
        Delegation mode activation
    Version 0.1.20231204
        Updated documentation
    Version 0.1.20240202
        Error handling
    Version 0.1.20240205
        Code documentation
    Version 0.1.20240206
        Users from child domain can enmumerate SID of allowed groups if the group is universal
        The request ID added to the error message
    Version 0.1.20240722
        Log files will be created in the %programdata%\Just-in-Time folder. 
        Bug fixing if the program is running in singedomain mode
        New Error Event ID 2105 occurs if the Global Catalog is down
    Version 0.1.20240731
        If the paramter configuration file is not provided, the global environment variable JustInTimeConfig will be used
        instead of the local directory
        Improved Monitoring
    Version 0.1.20240925
        More detailed debug information
    Version 0.1.20240928
        The Attribute ManageyBy can used to request admin access
    Version 0.1.20241004
        The validation the user is allowed is replaced by the Just-In-Time module function GetUserElevationStatus
        Elevation Throttle implemented. New parameter in the JIT.config MaxConcurrentServer required
    Version 0.1.20241023
        Fix bug in config build version detection
    Version 0.1.20241227
	by Andreas Luy
        Fixing minor bugs
    Version 0.1.20250127
	by Andreas Luy
        re-written to support AD-based configuration and delegation

    Event ID's
    1    Error  Unhandled Error has occured
    
    2000 Error  Configuration file missing
                Validate the configuration file jit.config is available on the current directory or the parameter configurationFile is correct
    2001 Error  The required group in AD is missing
                 The AD group assinged to this server is missing. Validate the server is in the configured OU and the Tier1LocalAdminGroup.ps1 does not report any error
    2002 Warning The user cannot be found in the active directory
                The user in the Event-ID could not be found in the active directory forest 
    2003 Warning The requested time exceed the max elevation time. The value is set to maximum elevation time
                The requested time excced the maximum time configured in the jit.config file. The requested time will be update to the maximum allowed time
    2004 Information The user is already user of this group. 
                The requested user is already elevated to on this group. The time-to-live paramter will be updated
    2005 Error  Invalid configuration file version. 
                The configuration file is available but the build version is older the expected. run the jit-config.ps1
    2006 Warning The request ID is not available
                The event log entry with the requested ID is not available
    2007 Error  Insufficient access rights
                The current user cannot update the AD groups or has no access to the active directory
    2008 Warning The user elevation threshold exceeded. Wait till the user is remove from admin groups


    2100 Error  The requested server is not available in the Active Directory
                Validate the requested computer object exists in the active directory. Disconnected DNS namespaces are not supported 
    2101 Error  The delegation JSON file is not available
                The delegation.config file configured in the jit.config is not accessible. Validate the user can access the delegation.config file
    2102 Error  The Server OU path is not defined in the Delegation.config file
                The requested server object distinguishedname is not configured in the delegation.config
    2103 Warning No SId mataches to the delegated OU
                The requested user is not member of any configured delegation in the delegation.config
    2104 Information The user is added to the local administrators group
                The requested user is successfully added to the requested AD group
    2105 Error  Global catalog is down 
    2106 Information Script logging path
                This event provides information about the elevate user script and the debug logging path
    2007 Error  The aD object class in the Managedby attribute is not supported
    2108 Error  The Delegation.config path is invalid

#>
[CmdletBinding(DefaultParameterSetName = 'DelegationModel')]
param(
    [Parameter (Mandatory=$true, Position = 0)]
    #Record ID to identify the event
    [int]$eventRecordID
    )


#region import required modules and variables
[int]$_ScriptVersion = "20250107"
[int]$MinConfigVersionBuild = "20241201"

Import-Module Just-In-Time

if (!(Get-Variable DefaultJiTADCnfgObjectDN -Scope Global -ErrorAction SilentlyContinue)) {
    Set-Variable -name DefaultJiTADCnfgObjectDN -value "CN=Jit-Configuration,CN=Just-In-Time Administration,CN=Services,CN=Configuration,DC=Fabrikam,DC=com" -Scope Global -Option ReadOnly
}
if (!(Get-Variable JitCnfgObjClassName -Scope Global -ErrorAction SilentlyContinue)) {
    Set-Variable -name JitCnfgObjClassName -value "JiT-ConfigurationObject" -Scope Global -Option ReadOnly
}
if (!(Get-Variable JiTAdSearchbase -Scope Global -ErrorAction SilentlyContinue)) {
    Set-Variable -name JiTAdSearchbase -value "CN=Delegations,CN=Just-In-Time Administration,CN=Services,CN=Configuration,DC=Fabrikam,DC=com" -Scope Global -Option ReadOnly
}
if (!(Get-Variable JitDelegationObjClassName -Scope Global -ErrorAction SilentlyContinue)) {
    Set-Variable -name JitDelegationObjClassName -value "jiT-DelegationObject" -Scope Global -Option ReadOnly
}
if (!(Get-Variable config -Scope Global -ErrorAction SilentlyContinue)) {
    Set-Variable -name config -value (Get-JITconfig) -Scope Global -Option ReadOnly
}

#Discover the next available Global catalog for queries
if (!(Get-Variable GlobalCatalogServer -Scope Global -ErrorAction SilentlyContinue)) {
    Set-Variable -name GlobalCatalogServer -value ("$((Get-ADDomainController -Discover -Domain ((Get-ADForest).rootdomain) -Service GlobalCatalog).HostName):3268") -Scope Global -Option ReadOnly
}
#endregion


function IsStringNullOrEmpty
{
    param
    (
        [Parameter(Mandatory = $true)]$PsValue
    )
    #return ([string]::IsNullOrWhiteSpace($PsValue))
    return ($PsValue -notmatch "\S")
}

<#
.SYNOPSIS 
    Writes the script output to the console and the Windows eventlog
.PARAMETER EventID
    Is the JIT event ID
.PARAMETER Severity
    Is the severity level of the message. 
    Error will be displayed with red foreground color and wrnings as yellow
.PARAMETER Message
    Is the event message test
.EXAMPLE
    Write-ScriptMessage 1 Warning "Test"
    Write the Message "test" with a yellow foreground color to the terminal and a Windows event with ID 1 to the Tier 1 Management eventlog 
#>
function Write-ScriptMessage {
    param(
        [Parameter (Mandatory, Position=0)]
        [int] $EventID,
        [Parameter (Mandatory, Position=1)]
        [ValidateSet ('Information','Warning','Error','Debug')]
        $Severity,
        [Parameter (Mandatory, Position=2)]
        [string] $Message
    )
    $WindowsEventLog = 'Tier 1 Management'
    switch ($Severity) {
        'Warning'{
            Write-Log -Message $Message -Severity Warning
            Write-EventLog -LogName $WindowsEventLog -EventId $EventID -EntryType $Severity -Message $Message -Source 'T1Mgmt'
        }
        'Error'{
            Write-Log -Message $Message -Severity Error
            Write-EventLog -LogName $WindowsEventLog -EventId $EventID -EntryType $Severity -Message $Message -Source 'T1Mgmt'
        }
        'Debug'{
            Write-Log -Message $Message -Severity Debug
        }
        Default{
            Write-Log -Message $Message -Severity Information
            Write-EventLog -LogName $WindowsEventLog -EventId $EventID -EntryType $Severity -Message $Message -Source 'T1Mgmt'
        }
    }
}

function Write-Log {
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


##############################################################################################################################
# Main Programm starts here                                                                                                  #
##############################################################################################################################
Write-Log -Severity Debug -Message "sucessfully read the JiT configuration"

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

Write-ScriptMessage -Message "ElevateUser process started (RequestID $eventRecordID). Detailed logging available $LogFile" -EventID 2106 -Severity Information
Write-Log -Message "Script Version $_ScriptVersion. Minimum required config Version $MinConfigVersionBuild" -Severity Information 

$configFileBuildVersion = [int]([regex]::Matches($global:config.ConfigScriptVersion,"[^\.]*$")).Groups[0].Value 
Write-Log -Severity Debug -Message "$configurationFile has build version $configFileBuildVersion"
#Validate the build version of the jit.config file is equal or higher then the tested jit.config file version
<#if ($MinConfigVersionBuild -gt $configFileBuildVersion)
{
    #breaking error
    Write-ScriptMessage -EventID 2005 -Severity Error -Message "RequestID $eventRecordID : Invalid configuration file version $configFileBuildVersion expected $MinConfigVersionBuild or higher"
    return
}
#>
Write-Log -Severity Debug -Message "The configuration is valid. The configuration version is $configFileBuildVersion"
try{
    #Discover the next available Global catalog for queries
    #$GlobalCatalogServer = "$((Get-ADDomainController -Discover -Service GlobalCatalog).HostName):3268"
    Write-Log -Severity Debug -Message "using global catalog $GlobalCatalogServer"

    #region Search for the event record in the eventlog, read the event and convert the event message from JSON into a PSobject
    $RequestEvent = Get-WinEvent -FilterHashtable @{LogName = $global:config.EventLog; ID= $global:config.ElevateEventID} | Where-Object -Property RecordId -eq $eventRecordID
    if ($null -eq $RequestEvent){
        #breaking error
        Write-ScriptMessage -EventID 2006 -Severity Warning -Message "A event record with event ID $eventRecordID is not available in Eventlog $($global:config.EventLog)"
        return
    }
    Write-Log -Severity Debug -Message "Found eventID $eventRecordID"
    Write-Log -Severity Debug -Message "Raw Event from Record $eventRecordID $($RequestEvent.Message)"
    $Request = ConvertFrom-Json $RequestEvent.Message
    #endregion

    #check the elevation group is available. If not terminate the script
    $AdminGroup = Get-ADGroup -Filter "Name -eq '$($Request.ServerGroup)'"
    if ($null -eq $AdminGroup )
    {
        #breaking error
        Write-ScriptMessage -EventID 2001 -Severity Error -Message "RequestID: $eventRecordID Can not find $($Request.ServerGroup)" 
        return
    }

    #region Search for the user in the entire AD Forest
    $oUser = Get-ADUser -Filter "DistinguishedName -eq '$($Request.UserDN)'" -Server $GlobalCatalogServer -Properties canonicalName
    #check the user object is available, If not terminate the script
    if ($null -eq $oUser ) 
    {
        #breaking error
        Write-ScriptMessage -EventID 2002 -Severity Warning -Message "Can't find user $($Request.UserDN)"
        return
    }
    $admStatus = Get-Adminstatus -User $oUser
    if ($admStatus.BaseType -eq "System.Array") {
        if ($admStatus.count -gt $global:config.MaxConcurrentServer){
            #not a breaking error but no need to continue
            Write-ScriptMessage -EventID 2008 -Message "The user elevation threshold exceeded. Wait till the user has been removed from some admin groups: $($Request.UserDN)"
            return
        }
    }
    $userDomain = [regex]::Match($oUser.canonicalName,"[^/]+").value
    Write-Log -Severity Debug -Message "Found user $userDomain \ $($oUser.SamAccountName)"
    #endregion

    #region This section check the permission for this user if the elevation version is enabled
    #extract the server name from the group name
    if ($global:config.EnableMultiDomainSupport){
        #$oServerName = [regex]::Match($Request.ServerGroup,"$($global:config.AdminPreFix)(\w+)$($global:config.DomainSeparator)(.+)").Groups[2].Value
        #extract the netbios name from the group name and convert it into the Domain DNS name
        #$oServerDomainNetBiosName = [regex]::Match($Request.ServerGroup,"$($global:config.AdminPreFix)(\w+)$($global:config.DomainSeparator)(.+)").Groups[1].Value
        #$oServerDNSDomain = (Get-ADObject -Filter "NetBiosName -eq '$oServerDomainNetBiosName'" -SearchBase "$((Get-ADRootDSE).ConfigurationNamingContext)" -Properties DNSRoot).DNSRoot
        #$oServer = Get-ADComputer -Identity $oServerName -Server $oServerDNSDomain[0] -Properties ManagedBy -ErrorAction SilentlyContinue
        #$oServerDNSDomain = (($Request.ServerGroup).Substring(($global:config.AdminPreFix).Length)).Split($global:config.DomainSeparator)[0]
        $oServerName = (($Request.ServerGroup).Substring(($global:config.AdminPreFix).Length)).Split($global:config.DomainSeparator)[1]
        $oServerDNSDomain = $Request.ServerDomain
        Write-Log -Severity Debug -Message "oServerDNSDomain: $oServerDNSDomain" 
        Write-Log -Severity Debug -Message "oServerName: $oServerName" 
        $oServer = Get-ADComputer -Identity $oServerName -Server $oServerDNSDomain -ErrorAction SilentlyContinue
        #$oServer = Get-ADComputer -Identity $oServerName -Server $oServerDNSDomain -Properties ManagedBy,groupPriority -ErrorAction SilentlyContinue
        Write-Log -Severity Debug -Message "Multidomain support is enabled - ServerName: $oServerName" 
    } else {
        #$oServerName = [regex]::Match($Request.ServerGroup,"$($global:config.AdminPreFix)(.+)").Groups[1].Value
        $oServerName = (($Request.ServerGroup).Substring(($global:config.AdminPreFix).Length))
        Write-log -Message "Multidomain support is disabled ServerName: $oServerName " -Severity Debug
        $oserver = Get-ADComputer -Identity $oServerName -ErrorAction SilentlyContinue
        #$oserver = Get-ADComputer -Identity $oServerName -Properties ManagedBy,groupPriority -ErrorAction SilentlyContinue
    }    
#    Write-Log -Message "oServerName = $oserverName oServerDomainNameBiosName = $oServerDomainNetBiosName oServerDNSDomain = $oServerDNSDomain" -Severity Debug
    Write-Log -Message "oServerName = $oserverName oServerDNSDomain = $oServerDNSDomain" -Severity Debug
    #search for the member server object
    #if the server object cannot be found in the AD terminat the script
    if ($null -eq $oServer){
        #breaking error
        Write-ScriptMessage -EventID 2100 -Severity Error -Message "RequestID $eventRecordID : Can't find $oServer in AD" 
        return
    }
    if ($global:config.EnableDelegation){
        Write-Log -Severity Debug -Message "Delegation support is enabled - ServerName: $oServerName" 
        if (!(Get-UserElevationStatus -ServerName $oServer.DNSHostName -UserName $oUser.UserPrincipalName -AllowManagebyAttribute:$false)){
            #breaking error
            Write-ScriptMessage -EventID 2103 -Message "User $($oUser.DistinguishedName) is not allowed to request privileged access on $($oServer.DistinguishedName) " -Severity Warning
            return
        }
    }
    #endregion

    #Region Add user to the local group"
    #if the timetolive in the request is higher then the maximum value. replace the ttl with the max evaluation time
    if ($Request.ElevationTime -gt $global:config.MaxElevatedTime)
    {
        Write-ScriptMessage -EventID 2003 -Severity Warning -Message "The requested time ($($Request.ElevationTime)))for user $($oUser.DistinguishedName) is higher the maximum time to live ($($global:config.MaxElevatedTime)). The time to live is replaced with ($($global:config.MaxElevatedTime))"
        $Request.ElevationTime = $global:config.MaxElevatedTime
    }
    if ($oUser.MemberOf -contains $AdminGroup)
    {
        Write-ScriptMessage -EventID 2004 -Severity Information -Message  "$($oUser.SamAccountName) is already member of $AdminGroup the TTL will be updated"
        Remove-ADGroupMember $AdminGroup -Members $oUser.DistinguishedName -Confirm:$false
    }
    Add-ADGroupMember -Identity $AdminGroup.Name -Members $oUser -MemberTimeToLive (New-TimeSpan -Minutes $Request.ElevationTime)
    Write-ScriptMessage -EventID 2104 -Severity Information -Message "RequestID $eventRecordID User $($oUser.DistinguishedName) added to group $AdminGroup"
    #Endregion
}
catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
    #breaking error
    Write-ScriptMessage -Severity Error -EventID 2105 -Message "RequestID $eventRecordID : A Server down exception occured. Validate the $GlobalCatalogServer is available" 
    return
}
catch [Microsoft.ActiveDirectory.Management.ADException]{
    #breaking error
    Write-ScriptMessage -Severity Error -EventID 2007 -Message "RequestID $eventRecordID : A AD exception has occured. $($Error[0])"
}
catch{
    #breaking error
    Write-ScriptMessage -Severity Error -EventID 1    -Message "RequestID $eventRecordID : a unexpected Error has occured $($Error[0].Exception) in line $($Error[0].InvocationInfo.ScriptLineNumber) "  
    return
}
Remove-Variable -Name config -Scope Global
