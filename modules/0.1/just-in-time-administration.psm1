<#
Module Info

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
#>

$configurationModuleVersion = "20250123"
$DefaultSTGroupManagementTaskName = "Tier 1 Local Group Management" #Name of the Schedule tasl to enumerate servers
$DefaultStGroupManagementTaskPath = "\Just-In-Time-Privilege" #Is the schedule task folder
$DefaultSTElevateUser = "Elevate User" #Is the name of the Schedule task to elevate users
$RegExDistinguishedName = "((OU|CN)=[^,]+,)*DC="

#region classes & styles
## loading .net classes needed
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()

# define fonts, colors and app icon
    $SuccessFontColor = "Green"
    $WarningFontColor = "Yellow"
    $FailureFontColor = "Red"

    $SuccessBackColor = "Black"
    $WarningBackColor = "Black"
    $FailureBackColor = "Black"

    $FontStdt = New-Object System.Drawing.Font("Arial",11,[System.Drawing.FontStyle]::Regular)
    $FontBold = New-Object System.Drawing.Font("Arial",11,[System.Drawing.FontStyle]::Bold)
    $FontItalic = New-Object System.Drawing.Font("Arial",9,[System.Drawing.FontStyle]::Italic)
#endregion


#load configuration
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
#if (!(Get-Variable config -Scope Global -ErrorAction SilentlyContinue)) {
#    Set-Variable -name config -value (Get-JITconfig) -Scope Global -Option ReadOnly
#}
#if (!(Get-Variable objFullDelegationList -Scope Global -ErrorAction SilentlyContinue)) {
#    Set-Variable -name objFullDelegationList -value (Get-JitDelegation) -Scope Global
#}


#region general functions

function IsStringNullOrEmpty
{
    param
    (
        [Parameter(Mandatory = $true)]$PsValue
    )
    #return ([string]::IsNullOrWhiteSpace($PsValue))
    return ($PsValue -notmatch "\S")
}

# stolen from
# https://pscustomobject.github.io/powershell/howto/identity%20management/PowerShell-Check-If-String-Is-A-DN/
function IsDNFormat
{
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$DNString
    )

    # Define DN Regex
    [regex]$distinguishedNameRegex = '^(?:(?<cn>CN=(?<name>(?:[^,]|\,)*)),)?(?:(?<path>(?:(?:CN|OU)=(?:[^,]|\,)+,?)+),)?(?<domain>(?:DC=(?:[^,]|\,)+,?)+)$'

    return $DNString -match $distinguishedNameRegex
}
    
function Get-DomainDNSfromDN 
{
    param(
        [Parameter (Mandatory=$true)][string]$AdObjectDN
    )
    $DomainDNS = (($AdObjectDN.tolower()).substring($AdObjectDN.tolower().IndexOf('dc=')+3).replace(“,dc=”,“.”))
    return $DomainDNS
}

function Get-DNfromDNS 
{
    param(
        [Parameter (Mandatory=$true)][string]$FQDN
    )

    $result = ""
    #get AD domains
    [array]$arrAdDomain = (Get-ADForest).domains

    #check if provided FQDN is domain DNS
    if ($arrAdDomain.Count -gt 0) {
        foreach ($domain in $arrAdDomain) {
            #check if provided FQDN is domain DNS
            if ($FQDN.toLower() -ne $domain.toLower()) {
                #check if FQDN can be found in one of the domains
                $result = (Get-ADObject -Filter 'Dnshostname -like $FQDN' -Server $domain).DistinguishedName
            } else {
                $result = 'DC=' + $domain.Replace('.',',DC=')
            }
            if ($result) {break}
        }
    }
    return $result
}

function Validate-DelegationObject
{
    param(
        [Parameter (Mandatory = $true,HelpMessage="Enter object name:")]
        [ValidateNotNullOrEmpty()][String]$Name
    )  

    $DomainDN = ""
    $DomainDNS = ""
    $Result = ""
    $ret = "" | select ObjectClass,DistinguishedName

    $GC = (Get-ADDomainController -Discover -Service GlobalCatalog)

    #do we have a unique DN provided? let's check
    #check if name really entered as DN
    if (IsDNFormat -DNString $Name) {
        #locate DN's domain
        $DomainDN = $Name.Substring($Name.IndexOf("DC="))
        Foreach ($ForestDomain in (Get-ADForest).Domains){
            if ((Get-ADDomain -Server $ForestDomain).DistinguishedName -eq $domainDN){
                $DomainDNS = $ForestDomain
                break
            }
        }
        if (IsStringNullOrEmpty $DomainDNS){
            Write-Host "Invalid domain" -ForegroundColor Red
            $Result=""
        } else {
            $Result = Get-ADObject -Filter 'DistinguishedName -eq $Name' -Server $DomainDNS
            If (IsStringNullOrEmpty $Result){
                Write-Host "Invalid DN: $($Name)" -ForegroundColor Red
                $Result=""
            }
        }
    } else {
        #lets see what other name formats we can identify
        switch -Wildcard ($Name.ToLower()){
            "*\*" { #netbios style? must be a computer object ...
                $NetBiosName = $Name.Split("\")
                $ServerName = $NetBiosName[1]
                $DomainDNS = (Get-ADForest).Domains | Where-Object {(Get-ADDomain -Server $_).NetBiosName -eq $NetBiosName[0]}
                if (IsStringNullOrEmpty $DomainDNS){
                    Write-Host "Invalid NetBios domain" -ForegroundColor Red
                    $Result=""
                } else {
                    if ($ServerName -like "*$") { #sAMAccountName included
                        $Result = (Get-ADObject -Filter {(sAMAccountName -eq $ServerName) -and (objectclass -eq "computer")} -Server $DomainDNS)#.DistinguishedName
                    } else { #we look for Name
                        $result= (Get-ADObject -Filter {(Name -like $ServerName) -and (objectclass -eq "computer")} -Server $DomainDNS)#.DistinguishedName
                    }
                }
            }
            "*$" { #samaccountname in local domain?
                $Result = (Get-ADObject -Filter {(sAMAccountName -eq $Name) -and (objectclass -eq "computer")} -Server $GC)#.DistinguishedName
                If (IsStringNullOrEmpty $Result){
                    Write-Host "Cannot find sAMaccountName: $($Name)" -ForegroundColor Red
                    $Result=""
                }
            }
            Default { #common name? name?
                #must be something in local domain - let's check if we can be resolve it
                #trying OUs 1st
                $Result = (Get-ADOrganizationalUnit -filter 'Name -like $Name' -Server $GC)#.DistinguishedName
                $LineCounter = 1
                if ($Result.count -gt 0) {
                    $Result | ForEach-Object { Write-Host "[$($LineCounter++)]: $($_)"}
                    do {
                        try {
                            $InputOk = $true
                            [int]$OUSelectNo = Read-Host "Select OU (by number)"
                            }
                        catch {$InputOk = $false}
                    }
                    until (($OUSelectNo -ge 1 -and $OUSelectNo -le $Result.count) -and $InputOk)
                    $Result = ($Result[$OUSelectNo - 1])
                } else {
                    #ok, no OU name - so let's try computers next
                    #common name 1st
                    $Result = (Get-ADObject -Filter {(cn -eq $Name) -and (objectclass -eq "computer")} -Server $GC)#.DistinguishedName
                    If (IsStringNullOrEmpty $Result){
                        #common name not found, Name next
                        $Result = (Get-ADObject -Filter {(name -eq $Name) -and (objectclass -eq "computer")} -Server $GC)#.DistinguishedName
                        If (IsStringNullOrEmpty $Result){
                            Write-Host "Cannot find computer with name: $($Name)" -ForegroundColor Red
                            $Result=""
                        }
                    }
                }
            }
        }
    }
    if (IsStringNullOrEmpty $Result) {
        $ret.ObjectClass = "UNDEFINED"
        $ret.DistinguishedName = "UNDEFINED"
    } else {
        $ret.ObjectClass = $Result.ObjectClass
        $ret.DistinguishedName = $Result.DistinguishedName
    }
    return $ret
}

function Validate-ADPrincipal
{
    param (
        [Parameter (Mandatory=$true,HelpMessage="Enter user or group name:")]
        [ValidateNotNullOrEmpty()][string]$Name
    )
    $GC = (Get-ADDomainController -Discover -Service GlobalCatalog)
    $ret = "" | Select Class, Name, DomainDNS
    $ret.Name = "UNDEFINED"
    $ret.Class = "UNDEFINED"
    $ret.DomainDNS = "UNDEFINED"
    $result = ""

    switch -Wildcard ($Name.ToLower()){
        "*@*" { #UPN provided
            #extracting DomainDNS
            $DomainDNS = $Name.Split("@")[1]
            $UPN = (Get-ADObject -Filter{UserprincipalName -eq $Name} -Server $DomainDNS -Properties UserprincipalName).UserprincipalName
            If (!(IsStringNullOrEmpty $UPN)) {
                $ret.Class = "user"
                $ret.Name = $UPN
                $ret.DomainDNS = $DomainDNS
            }
            break
        }
        "*\*" { #netbios style
            $NetBiosName = $Name.Split("\")
            $UserOrGroupName = $NetBiosName[1]
            $DomainDNS = (Get-ADForest).Domains | Where-Object {(Get-ADDomain -Server $_).NetBiosName -eq $NetBiosName[0]}
            #try sAMaccountName 1st
            $result = (Get-ADObject -Filter {SamAccountName -like $UserOrGroupName} -Server $DomainDNS)
            if ($result) {
                # assuming supported object class
                $ret.Class = $result.ObjectClass
                $ret.DomainDNS = $DomainDNS
                if ($result.ObjectClass -eq "group") {
                    $ret.Name = $result.DistinguishedName
                } elseif ($result.ObjectClass -eq "user") {
                    # collect UPN
                    $ret.Name = $result.UserprincipalName
                } else { # object class unsupported
                    $ret.Class = "UNDEFINED"
                    $ret.DomainDNS = "UNDEFINED"
                } 
            } else {
                #try Name next
                $result = (Get-ADObject -Filter {name -like $UserOrGroupName} -Server $DomainDNS)
                if ($result) {
                    # assuming supported object class
                    $ret.Class = $result.ObjectClass
                    $ret.DomainDNS = $DomainDNS
                    if ($result.ObjectClass -eq "group") {
                        $ret.Name = $result.DistinguishedName
                    } elseif ($result.ObjectClass -eq "user") {
                        # collect UPN
                        $ret.Name = $result.UserprincipalName
                    } else { # object class unsupported
                        $ret.Class = "UNDEFINED"
                        $ret.DomainDNS = "UNDEFINED"
                    } 
                }
            }
            break
        }
        "*cn=*" { #dn? could be anything
            #check if name really entered as DN
            if (IsDNFormat -DNString $Name) {
                #locate DN's domain
                $DomainDN = $Name.Substring($Name.IndexOf("DC="))
                Foreach ($ForestDomain in (Get-ADForest).Domains){
                    if ((Get-ADDomain -Server $ForestDomain).DistinguishedName -eq $domainDN){
                        $DomainDNS = $ForestDomain
                        break
                    }
                }
                if (IsStringNullOrEmpty $DomainDNS){
                    Write-Host "Invalid domain" -ForegroundColor Red
                    $Result=""
                } else {
                    $Result = (Get-ADObject -Filter 'DistinguishedName -eq $Name' -Server $DomainDNS)#.DistinguishedName
                    If (IsStringNullOrEmpty $Result){
                        Write-Host "Invalid DN: $($Name)" -ForegroundColor Red
                        $Result=""
                    } else {
                        $ret.Class = $result.ObjectClass
                        $ret.Name = $result.DistinguishedName
                        $ret.DomainDNS = $DomainDNS
                    }
                }
            }
        }
        Default {
            #let's try with local names
            #common name 1st
            $DomainDNS = (Get-ADdomain).DNSRoot
            $result = Get-ADObject -Filter {cn -eq $Name} -Server $DomainDNS
            if ($result) {
                # assuming supported object class
                $ret.Class = $result.ObjectClass
                $ret.DomainDNS = $DomainDNS
                if ($result.ObjectClass -eq "group") {
                    $ret.Name = $result.DistinguishedName
                } elseif ($result.ObjectClass -eq "user") {
                    # collect UPN
                    $ret.Name = $result.UserprincipalName
                } else { # object class unsupported
                    $ret.Class = "UNDEFINED"
                    $ret.DomainDNS = "UNDEFINED"
                } 
            }else {
                #name next
                $result = Get-ADObject -Filter {name -eq $Name} -Server $DomainDNS
                if ($result) {
                    # assuming supported object class
                    $ret.Class = $result.ObjectClass
                    $ret.DomainDNS = $DomainDNS
                    if ($result.ObjectClass -eq "group") {
                        $ret.Name = $result.DistinguishedName
                    } elseif ($result.ObjectClass -eq "user") {
                        # collect UPN
                        $ret.Name = $result.UserprincipalName
                    } else { # object class unsupported
                        $ret.Class = "UNDEFINED"
                        $ret.DomainDNS = "UNDEFINED"
                    } 
                }
            }
        }
    }
    return $ret
}

function Get-Sid 
{
[CmdletBinding(DefaultParameterSetName="NameString")]
    param (
        [Parameter(Mandatory = $true,HelpMessage="Enter user or group name:",ParameterSetName="NameString")]
        [ValidateNotNullOrEmpty()]
        [Alias('User','Group')][string]$Name,

        [Parameter(Mandatory = $true,ParameterSetName="NameObject")]
        [PSCustomObject]$objName
    )

    $OSID = ""
    $DomainDNS = ""
    $GC = (Get-ADDomainController -Discover -Service GlobalCatalog)

    if ($PSCmdlet.ParameterSetName -eq "NameString") {
        $UserOrGroup = Validate-ADPrincipal -Name $Name
    } else {
        $UserOrGroup = $objName
    }

    $DomainDNS = $UserOrGroup.DomainDNS
    switch ($UserOrGroup.class) {
        "user" {
            if (IsDNFormat -DNString $UserOrGroup.Name) {
                $OSID = (Get-ADObject -Identity $UserOrGroup.name -Server $DomainDNS -Properties ObjectSID).ObjectSid.Value
            } else {
                $OSID = (Get-ADObject -Filter {UserprincipalName -eq $UserOrGroup.Name} -Server $DomainDNS -Properties ObjectSID).ObjectSid.Value
            }
        }
        "group" {
            #$OSID = (Get-ADObject -Identity $UserOrGroup.Name -Server $DomainDNS -Properties ObjectSId).ObjectSID.Value
            $OSID = (Get-ADObject -Identity $UserOrGroup.Name -Server $DomainDNS -Properties ObjectSId).ObjectSID.Value
        }
        Default {
            # unsupported
            $OSID = $Null
        }
    }
    
    if (IsStringNullOrEmpty $OSID){
        $Name = ""
    }
    return $OSID
}

function ConvertFrom-DN2Dns {
    param(
        [Parameter(Mandatory= $true, ValueFromPipeline)]
        [string]$DistinguishedName
    )

    $DistinguishedName = [regex]::Match($DistinguishedName,"(dc=[^,]+,)*dc=.+$",[System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Value
    return (Get-ADObject -Filter "nCname -eq '$DistinguishedName'" -Searchbase (Get-ADForest).PartitionsContainer -Properties dnsroot).DnsRoot
}

function Write-ScriptMessage {
    param (
        [Parameter (Mandatory, Position=0)]
        [string] $Message,
        [Parameter (Mandatory=$false, Position=1)]
        [ValidateSet('Information','Warning','Error')]
        [string] $Severity = 'Information',
        [Parameter (Mandatory=$false, Position=2)]
        [bool]$UIused = $false
    )
    If ($UIused){
        Write-Output $Message
    } else {
        switch ($Severity) {
            'Warning' { $ForegroundColor = 'Yellow'}
            'Error'   { $ForegroundColor = 'Red'}
            Default   { $ForegroundColor = 'Gray'}
        }
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
}


<#
.SYNOPSIS
    Searching the user object in the entire forest with the user PAC
.DESCRIPTION
    This function searches a user in the entire forest and add the all group membership
    SID as a hashtable to the object
.PARAMETER USER
    If the name of the user. The username can be in the UPN or Domain\Name format. if the
    domain name is not part of the parameter, the user will be searched in the current domain
.INPUTS
    The name of the user
.OUTPUTS
    ActiveDirectoy.ADUser object
.EXAMPLE
    Get-User
        return the current user object
.EXAMPLE 
    Get-User myuser@contoso.com
        searches for the user with the user principal name myuser@contoso.com in the forest
.EXAMPLE
    Get-User contos\myuser
        searches for the user myuser in the contos domain
.EXAMPLE
    Get-User myuser
        searches for the user myuser in the current domain
#>
function Get-User{
    param(
        # Username
        [Parameter(Mandatory=$true,Position=0)]
        $User
    )
    if ($User -is [string]){
        #determine the user parameter format. The function support the format UPN, Domain\UserName, UserName
        switch ($user){
            ""{
                #searching for the current user object in AD
                $oUser = get-ADuser $env:UserName -Properties ObjectSID,CanonicalName  
                #break
            }
            ({$_ -like "*@*"}){
                #searching for the user in the UPN format
                $oUser = get-ADUser -Filter "UserPrincipalName -eq '$User'" -Server $global:GlobalCatalogServer -Properties ObjectSID,CanonicalName
                #break
            }
            ({$_ -like "*\*"}){
                #searching for the user in a specified domain
                #enumerate all domains in the forest and compare the domain netbios name with the parameter domain
                foreach ($DomainDNS in (GEt-ADForest).Domains){
                    $Domain = Get-ADDomain -Server $DomainDNS
                    if ($Domain.NetBIOSName -eq $user.split("\")[0]){
                        $oUser = get-aduser -Filter "SamAccountName -eq $($user.split("\")[1])" -Server $DomainDNS -Properties ObjectSID,CanonicalName
                        break
                    }
                }
                #breaK
            }
            Default {
                $oUser = Get-aduser -Filter "SamAccountName -eq '$User'" -Properties ObjectSID,CanonicalName
            }
        }
    } else {
        #assuming user parameter is of type ad-user
        $oUser = $User
    }
    #To enumerate the recursive memberof SID of the user a 2nd LDAP query is needed. The recursive memberof SID stored in the TokenGroups 
    # attribute
    #extracting the domain component from the user distinguishedname
    if ($null -eq $oUser){
        #can't find user object in the global catalog
        return $null
    } else {   
            #enumerating the Domain DNS name from the user distinguished name
            $userDomainDNSName = $oUser.CanonicalName.split("/")[0]
            #searching the user with the TokenGroups attribute
            $oUser = Get-ADUser -LDAPFilter "(ObjectClass=user)" -SearchBase $ouser.DistinguishedName -SearchScope Base -Server $userDomainDNSName -Properties "TokenGroups"
            return $oUser    
     }
}

#endregion

#region configuration functions
function Read-JIT.Configuration 
{
    $ret = $true
    $global:config = $null
    $ADconfig = $null

    #region configuration object
    try {
        $ADDomainDNS = (Get-ADDomain).DNSRoot #$current domain DNSName. Testing the Powershell AD modules are working
    }
    catch {
        Write-Output "Cannot determine AD domain - aborting!"
        $ret = $false
    }

    if ($ret) {
        try {
            $ADconfig = Get-ADObject -Identity $DefaultJiTADCnfgObjectDN -Properties *
        } catch {
            #cannot read JiT AD configuration
            Write-Output "Cannot read JiT configuration object in Active Directory  - aborting!"
            $ret = $false
        }
    }

    if ($ret) {
        #create global config object from AD  
        $global:config =[PSCustomObject]@{
            'ConfigScriptVersion'= $ADconfig.'JitCnfg-ConfigScriptVersion'
            'OU' = $ADconfig.'JitCnfg-JitAdmGroupOU'
            'AdminPreFix' = $ADconfig.'JitCnfg-AdminPreFix'
            'Domain' = $ADconfig.'JitCnfg-Domain'
            'Tier0ServerGroupName' = $ADconfig.'JitCnfg-Tier0ServerGroupName'
            'LDAPT1Computers' = $ADconfig.'JitCnfg-LDAPT1Computers'
            'T1Searchbase' = $ADconfig.'JitCnfg-T1Searchbase'
            'MaxElevatedTime' = $ADconfig.'JitCnfg-MaxElevatedTime'
            'DefaultElevatedTime' = $ADconfig.'JitCnfg-DefaultElevatedTime'
            'MaxConcurrentServer' = $ADconfig.'JitCnfg-MaxConcurrentServer'
            'GroupManagedServiceAccountName' = $ADconfig.'JitCnfg-GroupManagedServiceAccountName'
            'TaskRunInterval' = $ADconfig.'JitCnfg-TaskRunInterval'
            'TaskScriptSource' = $ADconfig.'JitCnfg-TaskScriptSource'
            'EventLog' = $ADconfig.'JitCnfg-EventLog'
            'EventSource' = $ADconfig.'JitCnfg-EventSource'
            'ElevateEventID' = $ADconfig.'JitCnfg-ElevateEventID'
            'RequestOnBehalfOf' = if ($ADconfig.'JitCnfg-RequestOnBehalfOf') {$ADconfig.'JitCnfg-RequestOnBehalfOf'}else{@("<EMPTY>")}
            'EnableMultiDomainSupport' = $ADconfig.'JitCnfg-EnableMultiDomainSupport'
            'EnableDelegation' = $ADconfig.'JitCnfg-EnableDelegation'
            'DomainSeparator' = $ADconfig.'JitCnfg-DomainSeparator'
            'UseManagedByforDelegation' = $ADconfig.'JitCnfg-UseManagedByforDelegation'
            'DelegationConfigPath' = $ADconfig.'JitCnfg-DelegationConfigPath'
            'AuthorizedServer' = $ADconfig.'JitCnfg-AuthorizedServer'
        }
        $ADconfig = $null
    } 
<#
    #build the default configuration object
    $config = New-Object PSObject
    $config | Add-Member -MemberType NoteProperty -Name "ConfigScriptVersion"            -Value "20241201"
    $config | Add-Member -MemberType NoteProperty -Name "ConfigVersion"                  -Value "20241201"
    $config | Add-Member -MemberType NoteProperty -Name "AdminPreFix"                    -Value "Admin_"
    $config | Add-Member -MemberType NoteProperty -Name "OU"                             -Value "OU=JIT-Administrator Groups,OU=Tier 1,OU=Admin,$((Get-ADDomain).DistinguishedName)"
    $config | Add-Member -MemberType NoteProperty -Name "MaxElevatedTime"                -Value 1440
    $config | Add-Member -MemberType NoteProperty -Name "DefaultElevatedTime"            -Value 60
    $config | Add-Member -MemberType NoteProperty -Name "ElevateEventID"                 -Value 100
    $config | Add-Member -MemberType NoteProperty -Name "Tier0ServerGroupName"           -Value "Tier 0 Computers"
    $config | Add-Member -MemberType NoteProperty -Name "LDAPT0Computers"                -Value "(&(ObjectClass=Computer)(!(ObjectClass=msDS-GroupManagedServiceAccount))(!(PrimaryGroupID=516))(!(PrimaryGroupID=521)))" #Deprecated Tier 0 computer identified by Tier 0 group membership
    $config | Add-Member -MemberType NoteProperty -Name "LDAPT0ComputerPath"             -Value "OU=Tier 0,OU=Admin"
    $config | Add-Member -MemberType NoteProperty -Name "LDAPT1Computers"                -Value "(&(OperatingSystem=*Windows*)(ObjectClass=Computer)(!(ObjectClass=msDS-GroupManagedServiceAccount))(!(PrimaryGroupID=516))(!(PrimaryGroupID=521)))" #added 20231201 LDAP query to search for Tier 1 computers
    $config | Add-Member -MemberType NoteProperty -Name "EventSource"                    -Value "T1Mgmt"
    $config | Add-Member -MemberType NoteProperty -Name "EventLog"                       -Value "Tier 1 Management"
    $config | Add-Member -MemberType NoteProperty -Name "GroupManagementTaskRerun"       -Value 5
    $config | Add-Member -MemberType NoteProperty -Name "GroupManagedServiceAccountName" -Value "T1GroupMgmt"
    $config | Add-Member -MemberType NoteProperty -Name "Domain"                         -Value $ADDomainDNS
    $config | Add-Member -MemberType NoteProperty -Name "DelegationConfigPath"           -Value "$InstallationDirectory\Tier1delegation.config" #Parameter added is the path to the delegation config file
    $config | Add-Member -MemberType NoteProperty -Name "EnableDelegation"               -Value $true
    $config | Add-Member -MemberType NoteProperty -Name "EnableMultiDomainSupport"       -Value $true
    $config | Add-Member -MemberType NoteProperty -Name "T1Searchbase"                   -Value @("<DomainRoot>")
    $config | Add-Member -MemberType NoteProperty -Name "DomainSeparator"                -Value "#"
    $config | Add-Member -MemberType NoteProperty -Name "MaxConcurrentServer"            -Value 50
    $config | Add-Member -MemberType NoteProperty -Name "UseManagedByforDelegation"      -Value $true
#>    
    return $ret
}

function Add-JitServerOU {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$OU
    )
    #Search for dnsdomain
    $DomainDN = [regex]::Match($OU,"dc=.+").Value
    foreach ($ADDomainDNS in (Get-ADForest).Domains){
        IF ($DomainDN -eq $(Get-ADDomain -Server $ADDomainDNS).DistinguishedName){
            break;
        }
    }
    if ((Get-ADObject -Filter "DistinguishedName -eq '$OU'" -server $ADDomainDNS)){
        if ($global:config.T1Searchbase -contains $OU){
            Write-Host "$OU is already defined" -ForegroundColor Yellow
        } else {
            $global:config.T1Searchbase += $OU
            #ConvertTo-Json $config | Out-File $env:JustInTimeConfig -Confirm:$false
        }
    } else {
        throw [System.ArgumentException]::new("Invalid DistinguishedName", $OU)
    }
}

function Get-JitServerOU {
    return ($global:config.T1Searchbase)
}

function Remove-JITServerOU {
    param(
        [Parameter (Mandatory = $true, ValueFromPipeline = $true)]
        [string]$OU
    )
    if ($global:config.T1Searchbase -contains $OU){
        $tempSearchBase = @()
        foreach ($sb in $global:config.T1Searchbase){
            if ($sb -ne $OU){
                $tempSearchBase += $sb
            }
        }
        $global:config.T1Searchbase = $tempSearchBase
        Update-JiTConfig
    } else {
        Write-Host "$OU is not defined" -ForegroundColor Yellow
    }
}

function Get-JITconfig
{
    param(
        [Parameter (Mandatory=$false)][switch]$UseForms
    )
    
    Read-JIT.Configuration|Out-Null
    return $global:config
}

#endregion

#region delegation functions
function Update-JitDelegation {
    [CmdletBinding(DefaultParameterSetName = 'ShowDelegation')]

    param (
    [Parameter(Mandatory=$true,
        ParameterSetName="ShowDelegation")]
    [Parameter(Mandatory=$true,
        ParameterSetName="UpdateDelegation")]
    [ValidateSet('ShowCurrentDelegation', 'AddDelegation', 'RemoveDelegation', 'RemoveUserOrGroup', IgnoreCase = $True)]
    [ValidateNotNullOrEmpty()][string]$action = 'ShowCurrentDelegation',
    
    [Parameter(Mandatory=$false,
        ParameterSetName="UpdateDelegation")]
    [PSCustomObject]$objADPrincipal,

    [Parameter(Mandatory=$true,
        ParameterSetName="UpdateDelegation")]
    [PSCustomObject]$DelegationObject,

    [Parameter(Mandatory=$false,
        ParameterSetName="UpdateDelegation")]
    [string]$AdPrincipalSid,

    [Parameter(Mandatory=$false,
        ParameterSetName="UpdateDelegation")]
    [switch]$SimplyRemoveAdPrincipalFromDelegation,

    [Parameter (Mandatory=$false)][switch]$UseForms
)

    switch ($PSCmdlet.ParameterSetName) {
        'ShowDelegation' {
            $retVal = @()
            $CurrentDelegation = @()
            try {
                Get-ADObject -Filter 'ObjectClass -eq "JiT-DelegationObject"' -SearchBase $JiTAdSearchbase -Properties 'jiTDel-ObjectClass','jiTDel-DelegationDN','jiTDel-AllowedToDelegate' | ForEach-Object {
                    $DelegationEntry = "" | select ObjectClass, DN, ADPrincipal
                    $DelegationEntry.ObjectClass = [string]$_.'jiTDel-ObjectClass'
                    $DelegationEntry.DN = [string]$_.'jiTDel-DelegationDN'
                    $DelegationEntry.ADPrincipal = $_.'jiTDel-AllowedToDelegate'
                    $CurrentDelegation += $DelegationEntry
                }
                $DelegationEntry = $null
            } catch {
                #no delegation entry
            }
            #create structured output
            For($iEntry= 0; $iEntry -lt $CurrentDelegation.Count; $iEntry++){
                $arySID = @()
                $aryAccount = @()
                For($iSID = 0; $iSID -lt $CurrentDelegation[$iEntry].ADPrincipal.count;$iSID++){
                    try {
                        $SID = New-Object System.Security.Principal.SecurityIdentifier($CurrentDelegation[$iEntry].ADPrincipal[$iSID])
                    }
                    catch {
                        Write-Host "Invalidate SID found: $($CurrentDelegation[$iEntry].ADPrincipal[$iSID]) - Skipping ..." -ForegroundColor Yellow -BackgroundColor Red
                        #New-WarningMsgBox -Message "Invalidate SID found: $($CurrentDelegation[$iEntry].ADPrincipal[$iSID])!`r`nSkipping ..."
                        $SID = "*$($CurrentDelegation[$iEntry].ADPrincipal[$iSID])" 
                        Continue
                    }
                    $arySID +=$SID
                    try {
                        $Account = $SID.Translate([System.Security.Principal.NTAccount]).Value
                    }
                    catch {
                        Write-Host "Cannot convert SID to account: $($CurrentDelegation[$iEntry].ADPrincipal[$iSID]) - Skipping ..." -ForegroundColor Yellow -BackgroundColor Red
                        #New-WarningMsgBox -Message "Cannot convert SID to account:`r`n$($CurrentDelegation[$iEntry].ADPrincipal[$iSID])!`r`nSkipping ..."
                        $Account = "*Unresolved"
                        Continue
                    }
                    $aryAccount += $Account
                }
                if ($aryAccount.count -gt 0) {
                    $DelegationEntry = New-Object PSObject
                    $DelegationEntry | Add-Member -MemberType NoteProperty -Name ObjectClass -Value $CurrentDelegation[$iEntry].ObjectClass
                    $DelegationEntry | Add-Member -MemberType NoteProperty -Name DN -Value $CurrentDelegation[$iEntry].DN
                    $DelegationEntry | Add-Member -MemberType NoteProperty -Name Accounts -Value $aryAccount
                    $DelegationEntry | Add-Member -MemberType NoteProperty -Name SID -Value $arySID
                    $retVal +=$DelegationEntry
                }
                $DelegationEntry = $null
            }
            return $retVal
        }
        Default {
            switch ($action) {
                'AddDelegation' {
                    $ObjectSId = Get-Sid -objName $objADPrincipal
                    $NewEntry = $true
                    $searchDN = [string]$DelegationObject.DistinguishedName
                    $Continue = $true

                    #finding delegation object
                    try {
                        $CurrDelObj = Get-ADObject -Filter 'JitDel-DelegationDN -eq $searchDN' -SearchBase $JiTAdSearchbase -Properties 'JiTDel-AllowedToDelegate'
                    } catch {
                        #could not access AD delegation object
                        #teminating error
                        $Continue = $false
                    }
                    if ($Continue) {
                        if ($CurrDelObj) {
                            $NewEntry = $false 
                            if (!($CurrDelObj.'JiTDel-AllowedToDelegate' -contains $objectSId)){
                                #update AD delegation object with new sid
                                #Get-ADObject -Filter 'JitDel-DelegationDN -eq $searchDN' -SearchBase $JiTAdSearchbase -Properties 'jiTDEL-AllowedToDelegate' | Set-ADObject -Add @{'jiTDEL-AllowedToDelegate'=$objectSId}
                                Set-ADObject -Identity $CurrDelObj.DistinguishedName -Add @{'JiTDel-AllowedToDelegate'=$objectSId}
                            }
                        }
                        if ($NewEntry) {
                            #create new Delegation object in AD
                            $ADObjName = $([System.Guid]::NewGuid().ToString())
                            New-ADObject -Name $ADObjName -Type $JitDelegationObjClassName -Path $JiTAdSearchbase -OtherAttributes @{'JiTDel-ObjectClass'=$DelegationObject.ObjectClass; 'JiTDel-DelegationDN'=$DelegationObject.DistinguishedName; 'JiTDel-AllowedToDelegate'=$objectSId}
                        }
                    }
                    $searchDN = $null
                    return $Continue
                }
                'RemoveDelegation'{
                    $searchDN = [string]$DelegationObject.DistinguishedName
                    #remove AD Delegation object
                    Get-ADObject -Filter 'JitDel-DelegationDN -eq $searchDN' -SearchBase $JiTAdSearchbase | Remove-ADObject
                    $searchDN = $null
                    return $true
                }
                'RemoveUserOrGroup'{
                    $searchDN = [string]$DelegationObject.DistinguishedName
                    $Continue = $true
                    if ($SimplyRemoveAdPrincipalFromDelegation) {
                        if (!(IsStringNullOrEmpty -PsValue $AdPrincipalSid)) {
                            $ObjectSId = $AdPrincipalSid
                        } else {
                            #this won't work without sid
                            return $false
                        }
                    } else {
                        $ObjectSID = Get-Sid -objName $objADPrincipal
                    }

                    try {
                        $CurrDelObj = Get-ADObject -Filter 'JitDel-DelegationDN -eq $searchDN' -SearchBase $JiTAdSearchbase -Properties 'jiTDEL-AllowedToDelegate'
                    } catch {
                        #could not access AD delegation object
                        #teminating error
                        $Continue = $false
                    }
                    if ($Continue) {
                        if ($CurrDelObj) {
                            $tempSIDList = @()
                            Foreach ($SID in $CurrDelObj.'jiTDEL-AllowedToDelegate'){
                                if ($SID -ne $ObjectSId){
                                    $tempSIDList +=  $SID
                                }
                            }

                            #update AD delegation object with new sid list
                            #Get-ADObject -Filter 'JitDel-DelegationDN -eq $searchDN' -SearchBase $JiTAdSearchbase -Properties 'jiTDEL-AllowedToDelegate' | Set-ADObject -Replace @{'jiTDEL-AllowedToDelegate'=$tempSIDList}
                            Set-ADObject -Identity $CurrDelObj.DistinguishedName -Replace @{'jiTDEL-AllowedToDelegate'=$tempSIDList}
                        }
                    }
                    $searchDN = $null
                    return $Continue    
                }
            }
        }
    }
}

function Add-JitDelegation {
    param (
        [Parameter (Mandatory = $true,Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')][string]$DelegationObject,
        [Parameter (Mandatory = $true,Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('User','Group')][string]$ADPrincipal,
        [Parameter (Mandatory=$false)][switch]$UseForms
    )

    $ValidationResult = ""
    #check if ADPrincipal can be resolved
    $ADObject = Validate-ADPrincipal -Name $ADPrincipal
    if ($ADObject.Class -eq "UNDEFINED") {
        #throw [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::new("$ADObject doesn't exist")
        if ($UseForms){
            New-BreakMsgBox -Message "Cannot identify $($ADPrincipal)!`r`nExiting..."
        } else {
            Write-Host "Cannot identify $($ADPrincipal)!`r`nExiting..." -ForegroundColor Yellow -BackgroundColor Red
            exit 0x3EA
        }
    }
    $ValidationResult = Validate-DelegationObject -Name $DelegationObject
    if ($ValidationResult.ObjectClass -ne "UNDEFINED") {
        $Result = Update-JitDelegation -action AddDelegation -DelegationObject $ValidationResult -objADPrincipal $ADObject
    }

    return $Result
}

function  Remove-JitDelegation {
    param (
        [Parameter (Mandatory = $true,Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')][string]$DelegationObject,
        [Parameter (Mandatory = $false,Position = 1)]
        [Alias('User','Group')][string]$ADPrincipal,
        [Parameter (Mandatory = $false)][string]$Sid,
        [Parameter (Mandatory = $false)][switch]$Force,
        [Parameter (Mandatory = $false)][switch]$RemoveAdPrincipalWithoutValidation,
        [Parameter (Mandatory = $false)][switch]$RemoveDelegationWithoutValidation
    )

    $ValidationResult = ""
    $ret = $null

    if ($RemoveDelegationWithoutValidation) {
        $ValidationResult = "" | select ObjectClass,DistinguishedName
        $ValidationResult.ObjectClass = "DOESNOTMATTER"
        $ValidationResult.DistinguishedName = $DelegationObject
    } else {
        $ValidationResult = Validate-DelegationObject -Name $DelegationObject
    }
    if ($ValidationResult.ObjectClass -ne "UNDEFINED") {
        if (IsStringNullOrEmpty $ADPrincipal){
            if ($Force){
                $Result = Update-JitDelegation -action RemoveDelegation -DelegationObject $ValidationResult
                $ret = $true
            } else {
                $confirmation = New-ConfirmationMsgBox -Message "Do you want to remove JiT delegation from object:`r`n  $($ValidationResult.DistinguishedName)"
                if ($confirmation -eq "Yes") {
                    $Result = Update-JitDelegation -action RemoveDelegation -DelegationObject $ValidationResult
                    $ret = $true
                } else {
                    #answer was "No" --> end function
                    $ret = $false
                }
            }
        } else {
            if ($RemoveAdPrincipalWithoutValidation) {
                if (!(IsStringNullOrEmpty -PsValue $Sid)) {
                    #AdPrincipal might be stale so remove from delegation list
                    $ADObject = "" | Select Class, Name, DomainDNS
                    $ADObject.Class = "DOESNOTMATTER"
                    $ADObject.DomainDNS = "DOESNOTMATTER"
                    $ADObject.Name = $ADPrincipal
                    $Result = Update-JitDelegation -action RemoveUserOrGroup -DelegationObject $ValidationResult -objADPrincipal $ADObject -AdPrincipalSid $Sid -SimplyRemoveAdPrincipalFromDelegation
                    $ret = $true
                } else {
                    #no sid, no removal
                    $ret = $false
                }
            } else {
                #verify AdPrincipal before removing from delegation list
                $ADObject = Validate-ADPrincipal -Name $ADPrincipal
                if ($ADObject.Class -ne "UNDEFINED") {
                    if ($Force){
                        $Result = Update-JitDelegation -action RemoveUserOrGroup -DelegationObject $ValidationResult -objADPrincipal $ADObject 
                    } else {
                        $confirmation = New-ConfirmationMsgBox -Message "Do you want to remove $($ADPrincipal) from JiT delegation of object:`r`n  $($ValidationResult.DistinguishedName)"
                        if ($confirmation -eq "Yes") {
                            $Result = Update-JitDelegation -action RemoveUserOrGroup -DelegationObject $ValidationResult -objADPrincipal $ADObject
                            $ret = $true
                        } else {
                            #answer was "No" --> end function
                            $ret = $false
                        }
                    }
                }
            }
        }
    }
    return $ret
}

function Get-JitDelegation
{
    param(
        [Parameter (Mandatory=$false)][switch]$UseForms,
        [Parameter (Mandatory=$false)][switch]$UseFileBasedDelegation
    )
    if ($UseForms) {
        return Update-JitDelegation -action ShowCurrentDelegation #-UseForms
    } else {
        return Update-JitDelegation -action ShowCurrentDelegation
    }
}

#endregion

#region request functions
<#
.DESCRIPTION
    This command validate a user is allowed to get acces to a server. It compares the user SID and the groups the user is member of
    with the managedby attribute and the delegation config
.PARAMETER ServerName
    Is the name of the target computer. This parameter support the format
    - as DNS Hostname
    - as server name of the local domain
    - as NetBiosName in the format <domain>\<servername>
    - as canonical name in the format <DNS domain>/<ou>/<servername>
.PARAMETER UserName
    is the name ob the user. This paramter support the format
    -as User principal name
    -as user name of the local domain
    -as netbios name in the format <domain>\<servername>
    -as canonical name in the format <DNS>/<OU>/<serverName>
.PARAMETER Delegationconfig
    The full qualified path to the delegation.config JSON file
.PARAMETER AllowManagedbyAttribute
    if this parameter is $true, the computer attribute "ManagedBy" will be used to validate a server
.OUTPUTS
    Return $true if the user is allowed to be elevated on the given computer
.EXAMPLE
    Get-UserElevationStatus -ServerName "Server0" -UserName "AA" -DelegationConfig "\\contoso.com\SYSVOL\contoso.com\Just-In-Time\Delegation.config"
.EXAMPLE
    Get-UserElevationStatus -ServerName "Server0.contoso.com" -UserName "AA@contoso.com" -DelegationConfig "\\contoso.com\SYSVOL\contoso.com\Just-In-Time\Delegation.config"
.EXAMPLE
    Get-UserElevationStatus -ServerName "Server0" -UserName "AA" 

#>
function Get-UserElevationStatus{
    param(
        [Parameter (mandatory=$true, Position=0)]
        [string]$ServerName,
        [Parameter (Mandatory=$true, Position=1)]
        [string]$UserName,
        [Parameter (Mandatory=$false)]
        [bool]$AllowManagebyAttribute = $true
    )

    $ret = $false
    $result = $null

    try {
        #region user
        $user = $null
        $computer = $null
        $ServerDelegations = $null
        switch -Wildcard ($UserName) {
            #the parameter UserName is formated as user principal name
            "*@*" {  
                $user = Get-ADUser -Filter "UserPrincipalName -eq '$UserName'" -Server $global:GlobalCatalogServer -Properties CanonicalName
                $userdomain = [regex]::Match($User.CanonicalName,"[^/]+").Value
                #$user = Get-ADUser -LDAPFilter '(ObjectClass=User)' -SearchBase $user.DistinguishedName -SearchScope Base -Server $userdomain -Properties "TokenGroups"
                $user = Get-ADUser -Identity $user.DistinguishedName -Server $userdomain -Properties TokenGroups
                break
            }
            #the parameter UserName is formated as 
            "*/*"{
                $uhelper = [regex]::Match($userName,"^([^/]+).*?/([^/]+)$")
                $user = Get-ADUser -Identity $uhelper.Groups[2].Value -Server $uhelper.Groups[1].Value -Properties TokenGroups
                #$user = Get-ADUser -LDAPFilter '(ObjectClass=User)' -SearchBase $user.DistinguishedName -SearchScope Base -Server $uhelper.Groups[1].Value -Properties "TokenGroups"
                break
            }
            #the parameter UserName is formated as netbios domain name with username
            "*\*" {
                $uhelper = [regex]::Match($UserName,"([^\\]+)\\(.+)")
                $DomainNetBios = $uhelper.Groups[1].Value
                #getting domain FQDN from netbios name
                $DomainFQDN = (Get-ADObject -Filter 'netbiosname -eq $DomainNetBios' -SearchBase (Get-ADForest).PartitionsContainer -Properties DnsRoot).DnsRoot 
                $user = Get-ADuser -Identity $uhelper.Groups[2].Value -Server $DomainFQDN -Properties TokenGroups
                #Foreach ($domainRoot in (Get-ADForest).Domains){
                #    $ADDomain = Get-ADDomain -server $domainRoot
                #    if ($ADDomain.NetbiosName -eq $uhelper.Groups[1].Value){                    
                #        $user = Get-ADuser -Identity $uhelper.Groups[2].Value -Server $domainRoot
                #        $user = Get-ADUser -LDAPFilter '(ObjectClass=User)' -SearchBase $user.DistinguishedName -SearchScope Base -Server $uhelper.Groups[1].Value -Properties "TokenGroups"
                #        break
                #    }
                #}
                break
            }
            #the parameter UserName is formated as local domain user
            Default {
                $user = Get-ADUser -Identity $UserName -Properties TokenGroups     
                #$user = Get-ADUser -LDAPFilter '(ObjectClass=User)' -SearchBase $user.DistinguishedName -SearchScope Base -Properties "TokenGroups"
                break
            }   
        }
        #endregion

        #region searching computer
        switch -Wildcard ($ServerName) {
            "*.*" {
                $Computer = Get-ADComputer -Filter "DNSHostName -eq '$ServerName'" -Server $global:GlobalCatalogServer
                #The global catalog does not contains the ManagedBy attribute
                #$domainDNS = ConvertFrom-DN2Dns $Computer.DistinguishedName
                #$Computer = Get-ADComputer $Computer -Properties ManagedBy,groupPriority -Server $domainDNS
                break
            }
            "*.*/*"{
                $uhelper = [regex]::Match($userName,"^([^/]+).*?/([^/]+)$")
                $Computer = Get-ADcomputer -Filter "CN -eq '$($uhelper.Groups[2].Value)" -Server $uhelper.Groups[1].Value
                #$Computer = Get-ADcomputer -Filter "CN -eq '$($uhelper.Groups[2].Value)" -Properties ManagedBy,groupPriority -Server $uhelper.Groups[1].Value
                break
            }
            "*\*"{
                $uhelper = [regex]::Match($ServerName,"([^\\]+)\\(.+)")
                $DomainNetBios = $uhelper.Groups[1].Value
                $DomainFQDN = (Get-ADObject -Filter 'netbiosname -eq $DomainNetBios' -SearchBase (Get-ADForest).PartitionsContainer -Properties DnsRoot).DnsRoot 
                $Computer = Get-ADComputer -Filter "CN -eq '$($uhelper.Groups[2].Value)'" -Server $DomainFQDN
                #Foreach ($ADDomainName in (Get-ADForest).Domains){
                #    $ADDomain = Get-ADDomain -Server $ADDomainName
                #    if ($ADDomain.NetBiosName -eq $uhelper.Groups[1].Value){
                #        $Computer = Get-ADComputer -Filter "CN -eq '$($uhelper.Groups[2].Value)'" -Properties ManagedBy,groupPriority -Server $uhelper.Groups[1].Value
                #        break
                #    }
                #}
                break
            }
            Default{
                $Computer = Get-ADcomputer -Filter "CN -eq '$ServerName'" #-Properties Managedby,groupPriority
                break
            }
        }
        #endregion
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        if ($null -eq $user){
            Write-Host "Cannot find user $userName " -ForegroundColor Red
        } else {
            Write-Host "Cannot find computer $serverName" -ForegroundColor Red
        }
        #un-recoverable error - quit here
        return $false
    }

    #check the ManagedBy attribute is available 1st if not --> use delegation configuration
    if ($null -ne $Computer.ManagedBy -and $AllowManagebyAttribute){
        $oManagedBy = Get-ADObject -Filter "DistinguishedName -eq '$($Computer.ManagedBy)'" -Server $global:GlobalCatalogServer -Properties ObjectSID, CanonicalName
        Switch ($oManagedBy.ObjectClass){
            "User"{
                if ($user.SID -eq $oManagedBy.ObjectSID.Value){
                    $ret = $true
                    #return $true
                }
            }
            "Group"{
                $groupDomain = [regex]::Match($Group.CanonicalName,"[^/]+").Value
                $oManagedByMembers = Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -Server $groupDomain
                foreach ($member in $oManagedByMembers){
                    if ($member -eq $user.ObjectSID.Value){
                        $ret = $true
                        #return $true
                    }
                }

            }
        }
    } else {
        # no match with ManagedBy attribute, using delegation.config
        if ($global:config.EnableDelegation){
            #$oDelegation = Get-Content $DelegationConfig | ConvertFrom-Json 
            #$ServerDelegations = $oDelegation | Where-Object {$Computer.DistinguishedName -like "*$($_.ComputerOU)"} 
            #delegation is based on AD delegation configuration
            $Cmptsearchfilter = [string]$Computer.DistinguishedName
            $Pathsearchfilter = $Cmptsearchfilter.Substring($Cmptsearchfilter.Split(",")[0].length+1)
            #checking for direct coputer delegation
            $result = Get-ADObject -Filter 'JitDel-DelegationDN -eq $Cmptsearchfilter' -SearchBase $JiTAdSearchbase -Properties *
            if (!$result) {
                #checking for OU-based delegation
                $result = Get-ADObject -Filter 'JitDel-DelegationDN -eq $Pathsearchfilter' -SearchBase $JiTAdSearchbase -Properties *
            }
            if ($result) {
                #check direct delegation 1st
                $ServerDelegations = $result.'JiTDel-AllowedToDelegate'
                if ($result.'JiTDel-AllowedToDelegate' -contains $user.SID){
                    #direct match found - delegation granted
                    $ret = $true
                }
            }
            #check delegation via group membership next
            if (!$ret) {
                foreach ($usergroupSID in $user.TokenGroups){
                    if ($result.'JiTDel-AllowedToDelegate' -contains $usergroupSID){
                        #group match found - delegation granted
                        $ret = $true
                    }
                }
            }
        }
    }
    return $ret
}
#endregion

<#
New-AdminRequest
.SYNOPSIS
    requesting administrator privileges to a server
.DESCRIPTION
    The New-JITRequestAdminAccess creates a new Event to request administrator privileges on a server.
    This function validates the parameters and create the required event log entry
.PARAMETER Server
    Is the name of the server. The server can be in the format hostname or FQDN. This parameter is mandatory
.PARAMETER Minutes
    Is the requested a mount of administrator time in minutes. If the parameter is 0 or empty the configured
    default value time will be used. The parameter cannot exceed the maximum elevation time. If the parameter
    is greater the configured maximum elevation time, the time will be reduced to the maximum elevation time
.PARAMETER User
    This parameter is used if the request is for a different user then the calling user
.PARAMETER UIused
    This is a optional parameter to use the output for the PS GUID. If this parameter is $false (Default value)
    the output will formated
.INPUTS
    The name of the server on postion 0
    the amount of minutes on position 1
.OUTPUTS
    None
.EXAMPLE
    New-AdminAccess myhost.contoso.com
        Create a administrator request for the current user for server myhost.compunter.com
    New-AdminAccess myhost
        Create a administrator request for the current user for the server myhost. My host must exists
        in the forest necessarily in the current domain
    New-AdminAccess myhost.contoso.com 30
        Request administrator privileges for myhost.contoso.com for 30 minutes
    New-AdminAccess -Server myhost.contoso.com -Minutes 30 -user myuser@contoso.com
        Request administrator privileges for myhost.contoso.com for 30 minutes for user myuser@contoso.com
#>
function New-AdminRequest{
    param(
        # The name of the server requesting administrator privileges
        [Parameter(Mandatory = $true, Position=0 )]
        [string]$Server,
        # The amount of minutes to request administrator privileges
        #In Multi Forest environments you can provide the domain name instead of the FQDN
        [Parameter(Mandatory = $false)]
        [string]$ServerDomain,
        [Parameter(Mandatory = $false, Position=1)]
        [int]$Minutes = 0,
        #If the request is for a different user
        [Parameter(Mandatory = $false)]
        [string]$User,
        [Parameter (Mandatory = $false)]
        [bool]$UIused = $false
    )

    #The following part is only required if UI is NOT used
    if (!$UIused) {

        #region validation of minutes
        #if the value must be between 15 and the maximum configured value. If the value is lower then 15
        #then the minutes variable will be set to 15
        #if the parameter is 0 the parameter will be changed to the configured default value 
        switch ($Minutes) {
            0 {
                $Minutes = $global:config.DefaultElevatedTime
                break
              }
            ({$_ -lt 15}){
                $Minutes = 15
                break
            }
            ({$_ -gt $global:config.MaxElevatedTime}){
                $Minutes = $global:config.MaxElevatedTime
                break
            }
        }
        #endregion
    }

    #region user evaluation
    if (!$User) { # no user provided
        # get current logged on user
        $User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.split("\")[1]
    }

    #terminate the function if the user object is not available in the AD forest
    $oUser = Get-User $User
    if ((Get-AdminStatus $oUser).count -gt $global:config.MaxConcurrentServer){
        Write-ScriptMessage "Elevation limit reached. retry in a couple of minutes" -UIused $UIused
    }
    if ($Null -eq $oUser){
        Write-ScriptMessage "Can find the user object." -Severity Warning -UIused $UIused
        return
    }
    #endregion

    #if the server variable contains a . the hostname is FQDN. The function searches for the computer
    #object with this DNSHostName attribute. This function does not query the DNS it self. It is mandatory
    #the primary DNS name is registered.
    #if the server parameter is not as FQDN the function searches for the computername in the AD forest
    #If multiple computers with the same name exists in the forest the function return a $null object
    switch ($Server) {
        {$_ -like "*\*"}{
            #Hostname format is NetBIOS
            $oNetBiosServerName = $server.Split("\")
            if ($oNetBiosServerName[0] -like "*.*"){
                $oserver = Get-ADComputer -Filter "Name -eq '$($oNetBiosServerName[1])'" -Server $oNetBiosServerName[0] -Properties CanonicalName, ManagedBy
            } else {
                Foreach ($ForestDomainDNSName in (Get-ADForest).Domains){
                    if ((Get-ADDomain -Server $ForestDomainDNSName).NetBiosName -eq $oNetBiosServerName[0]){
                        $oServer = Get-ADcomputer  -Filter "Name -eq '$($oNetBiosServerName[1])'"  -Server $ForestDomainDNSName -Properties CanonicalName, ManagedBy    
                        break
                    }
                }
            }
            break
        }
        {$_ -like "*.*"}{
            #Hostname format is DNS ServerName
            $oServer = Get-ADcomputer -Filter "DNSHostName -eq '$Server'" -Server $global:GlobalCatalogServer -Properties CanonicalName, ManagedBy
            break
        }
        Default {
            if ($ServerDomain -eq ""){
                $oServer = Get-ADComputer -Filter "Name -eq '$Server'" -Server $global:GlobalCatalogServer -Properties CanonicalName, ManagedBy
            } else {
                $oServer = Get-ADcomputer -Filter "Name -eq '$Server'" -Server $ServerDomain -Properties CanonicalName, ManagedBy
            }
        }
    }
    #validate the server object exists. If the serverobject doesn't exists terminate the function
    if ($null -eq $oServer){
        Write-ScriptMessage -Message "Can't find a server $server in the forest" -Severity Warning -UIused $UIused
        return
    }
    #if multiple server object with the same name exists in the forest, terminate the function
    if ($oServer.GetType().Name -eq "Object[]"){
        Write-ScriptMessage -Message "Multiple computer found with this name $server in the current forest, Please use the DNS hostname instead " -Severity Warning -UIused $UIused 
        return
    }
    # the group name in multidomain mode is
    #   <AdminPreFix><Dns Domain Name><Seperator><server short name>
    # in single mode
    #   <AdminPreFix><Server name>
    if ($global:config.EnableMultiDomainSupport){
        #$ServerDomainDN = [regex]::Match($oserver.DistinguishedName,"DC=.*").value
        #$ServerDomainDNSName = (Get-ADForest).domains | Where-Object {(Get-ADDomain -Server $_ -ErrorAction SilentlyContinue).DistinguishedName -eq $ServerDomainDN}
        $ServerDomainDNSName = $oServer.CanonicalName.split("/")[0]
        #$ServerDomainNetBiosName = (GEt-ADdomain -Server $ServerDomainDNSName).NetBIOSName
        #$ServerGroupName = "$($global:config.AdminPreFix)$serverDomainNetBiosName$($global:config.DomainSeparator)$($oServer.Name)"
        # we will work with dns domain name
        $ServerGroupName = "$($global:config.AdminPreFix)$ServerDomainDNSName$($global:config.DomainSeparator)$($oServer.Name)"
    } else {
        $ServerGroupName = "$($global:config.AdminPreFix)$($oServer.Name)"
    }
    #endregion

    if (!$oServer.DNSHostName){
        Write-ScriptMessage -Message "Missing DNS Hostname entry on the computer object. Aborting elevation" -Severity Warning -UIused $UIused
        return
    }
    #if delegation mode is activated, the function validates if the user is allowed to request access to this server
    if ($global:config.EnableDelegation) {
        $result = Get-UserElevationStatus -ServerName $oServer.DNSHostName -UserName $oUser.UserPrincipalName -AllowManagebyAttribute:$false
        if (!$result){
            Write-ScriptMessage -Message "User is not allowed to request administrator privileges" -Severity Warning -UIused $UIused
            return
        }
    }
    #Prepare the eventlog entry and write the JIT request to the Jit eventlog
    $ElevateUser = New-Object PSObject
    $ElevateUser | Add-Member -MemberType NoteProperty -Name "UserDN" -Value $oUser.DistinguishedName
    $ElevateUser | Add-Member -MemberType NoteProperty -Name "ServerGroup" -Value $ServerGroupName
    $ElevateUser | Add-Member -MemberType NoteProperty -Name "ServerDomain" -Value $ServerDomainDNSName
    $ElevateUser | Add-Member -MemberType NoteProperty -Name "ElevationTime" -Value $Minutes
    #$ElevateUser | Add-Member -MemberType NoteProperty -Name "CallingUser" -Value "$($env:USERNAME)@$($env:USERDNSDOMAIN)"
    $ElevateUser | Add-Member -MemberType NoteProperty -Name "CallingUser" -Value (([ADSI]"LDAP://<SID=$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)>").UserPrincipalName).ToString()
    $EventMessage = ConvertTo-Json $ElevateUser
    Write-EventLog -LogName $global:config.EventLog -Source $global:config.EventSource -EventId $global:config.ElevateEventID -Message $EventMessage
    Write-ScriptMessage -Message "The $($oUser.DistinguishedName) will be elevated soon" -Severity Information -UIused $UIused
}

<#
This function shows the current request status for a user. 
.PARAMETER User
    Is the name of the user
.PARAMETER UIused
    Is a internal parameter for show messages in the UI mode
.INPUTS
    user object 
.OUTPUTS
    a list of server group name where the user is member of
#>
function Get-AdminStatus{
    param(
    # Name of the user
    [Parameter(Mandatory=$false, Position=0, ValueFromPipeline = $true)]
    $User,
    [Parameter(Mandatory=$False)]
    [bool]$UIused = $False
    )
    if ($null -eq $User){
        $user = $env:USERNAME
    }
    if ($user -is [string]){
        $User = Get-User $User
    }
    $retVal = @()
    if ($null -eq $User){
        Write-ScriptMessage -Message "cannot find user " -Severity Warning -UIused $UIused
        Return
    }
    $AllJiTGroups = Get-ADGroup -Filter * -SearchBase $global:config.OU -Properties Members -ShowMemberTimeToLive
    foreach ($Group in $AllJiTGroups){
        $UserisMember = $Group.Members | Where-Object {$_ -like "*$($User.DistinguishedName)*"}
        If ($null -ne $UserisMember){            
            if ($global:config.EnableMultiDomainSupport){
                $Domain = (($Group.Name).Substring(($global:config.AdminPreFix).Length)).Split($global:config.DomainSeparator)[0]
                $Server = (($Group.Name).Substring(($global:config.AdminPreFix).Length)).Split($global:config.DomainSeparator)[1]
                #$Domain = [regex]::Match($Group.Name,"$($global:config.AdminPreFix)([^#]+)").Groups[1].Value
                #$Server = [regex]::Match($Group.Name,"$($global:config.AdminPreFix)[^#]+#(.+)").Groups[1].Value
                $TTLsec = [regex]::Match($UserisMember, "\d+").Value
            } else {
                $Server = (($Group.Name).Substring(($global:config.AdminPreFix).Length))
                #$Server = [regex]::Match($Group.Name,"$($global:config.AdminPreFix)(.+)").Groups[1].Value
                $TTLsec = [regex]::Match($UserisMember, "\d+").Value
            }
            if ($TTLsec -eq ""){
                $TimeValue = "permanent"    
            } elseif ($TTLsec -eq 0) {
                $TimeValue = "permanent"    
            } else {
                $TimeValue = [math]::Floor($TTLsec / 60)
            }   
            $obj = new-Object PSObject
            $obj | Add-Member -MemberType NoteProperty -Name "Server" -Value "$domain\$server"
            $obj | Add-Member -MemberType NoteProperty -Name "TTL"    -Value "$TimeValue"
            $retVal += $obj
        }
    }
    if ($UIused){
        $retVal |ForEach-Object{Write-scriptMessage -Message "$User is elevated on $($_.Server) for $($_.TTL) minutes" -UIused}
    } else {
        return $retVal
    }
}

#enregion

#region UI functions

function New-BreakMsgBox
{
    param(
        [Parameter(mandatory=$true)]$Message,
        [Parameter(mandatory=$false)]$ExitCode = 0x1
    )
    [void][System.Windows.Forms.MessageBox]::Show($Message,"Critical Error!","OK",[System.Windows.Forms.MessageBoxIcon]::Stop)
    break script $ExitCode
    #exit $ExitCode
}

function New-WarningMsgBox 
{
    param(
        [Parameter(mandatory=$true)]$Message
    )
    [void][System.Windows.Forms.MessageBox]::Show($Message,"Error!","OK",[System.Windows.Forms.MessageBoxIcon]::Warning)
}

function New-ConfirmationMsgBox 
{
    param(
        [Parameter(mandatory=$true)]$Message,
        [Parameter(mandatory=$false)][switch]$information
    )
    if ($information) {
        $MsgIcon = "Asterisk"
    } else {
        $MsgIcon = "Warning"
    }
    $ret = [System.Windows.Forms.MessageBox]::Show($Message,"Confirm...","YesNo",$MsgIcon)
    return $ret
}

function New-informationMsgBox 
{
    param(
        [Parameter(mandatory=$true)]$Message
    )
    [void][System.Windows.Forms.MessageBox]::Show($Message,"Information...","OK",[System.Windows.Forms.MessageBoxIcon]::Information)
}
#endregion

