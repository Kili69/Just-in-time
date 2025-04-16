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

.SYNOPSIS
    Installation of just in time solution
.DESCRIPTION
    This script install the Just-IN-Time Solution. The purpose of this script is to copy scripts into
    program files folder,the modules into the modules and start the configuration script
Version 0.1.20240918
    Inital Version
Version 0.1.20241006
    Overwrites existing versions
    change the working folder to program folder
Version 0.1.20241227
    by Andreas Luy
    Fixing minor bugs
Version 0.1.20250123
    by Andreas Luy
    completely re-written to add
    schema extension, AD structure, delegated installation and uninstallation options
#>


[CmdletBinding(DefaultParameterSetName = "FullInstall",SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false,
        ParameterSetName = "FullInstall")]
    [string]$JitProgramFolder,

    [Parameter(Mandatory = $false,
        ParameterSetName = "Update")]
    [switch]$UpdateConfiguration,

    [Parameter(Mandatory = $false,
        ParameterSetName = "AddServer")]
    [switch]$AddServer,

    [Parameter(Mandatory = $false,
        ParameterSetName = "Uninstall")]
    [switch]$Uninstall,

    [Parameter(Mandatory = $false,
        ParameterSetName = "CreateADObjects")]
    [switch]$createAdStructure,

    [Parameter(Mandatory = $false,
        ParameterSetName = "ExtendSchema")]
    [switch]$ExtendSchema,

    [Parameter(Mandatory = $false,
        ParameterSetName = "ExtendSchema")]
    [string]$CustomOidPrefix
)

begin {

    #region check if ActiveDirectory Powershell module is available
    $AdPosModInstalled = (Get-Module -ListAvailable -Name ActiveDirectory)
    if (!$AdPosModInstalled) {
        #check if RSAT-AD-Powershell feature has been installed
        if (((Get-WindowsFeature -Name rsat-ad-powershell).installstate) -ne "Installed") {
            Write-Host "AD Powershell modules not installed. To continue installation, it will be installed now!" -ForegroundColor Yellow
            try {
                Install-WindowsFeature -Name RSAT-AD-Powershell
            } catch {
                Write-Host "Windows Feature 'RSAT-AD-Powershell' could not be installed - aborting!" -ForegroundColor Red
                $exit = $true
                Exit 0x1
            }
        }
    }
    #endregion

    #current domain DNSName. Testing the Powershell AD modules are working
    try {
        $ADDomainDNS = (Get-ADDomain).DNSRoot 
    }
    catch {
        Write-Host "Cannot determine AD domain... " -ForegroundColor Red
        Write-Host "Ensure AD Powershell modules are available and local system has access to Active Directory" -ForegroundColor Red
        Write-Host "before continuing with JIT" -ForegroundColor Yellow
        Write-Host "Aborting!" -ForegroundColor Red
        $exit = $true
        Exit 0x1
    }

    #region validate DFL & FFL
    if ((Get-ADforest).forestmode -lt "Windows2016forest") {
        Write-Host "Active Directory forest functional level is lower than 'Windows2016forest'" -ForegroundColor Yellow
        Write-Host 
        Write-Host "Raise forest and domain functional level to 'Windows 2016'" -ForegroundColor Magenta
        Write-Host "Before continuing with JIT" -ForegroundColor Yellow
        Write-Host "Aborting!" -ForegroundColor Red
        $exit = $true
        Exit 0x1
    }

    if ((Get-ADDomain).domainmode -lt "Windows2016Domain") {
        Write-Host "Active Directory domain functional level is lower than 'Windows2016Domain'" -ForegroundColor Yellow
        Write-Host 
        Write-Host "Raise domain functional level to 'Windows 2016'" -ForegroundColor Magenta
        Write-Host "Before continuing with JIT" -ForegroundColor Yellow
        Write-Host "Aborting!" -ForegroundColor Red
        $exit = $true
        Exit 0x1
    }
    #endregion

    #region Validate the Active Directory PAM feature is activated. If not the script will terminate
    if (!((Get-ADOptionalFeature -Filter "name -eq 'Privileged Access Management Feature'").EnabledScopes)){
        Write-Host "Active Directory PAM feature is not enables" -ForegroundColor Yellow
        Write-Host "Run:"
        Write-Host "Enable-ADOptionalFeature ""Privileged Access Management Feature"" -Scope ForestOrConfigurationSet -Target $((Get-ADForest).Name)" -ForegroundColor Magenta
        Write-Host "Before continuing with JIT" -ForegroundColor Yellow
        Write-Host "Aborting!" -ForegroundColor Red
        $exit = $true
        Exit 0x1
    }
    #endregion

    #prepare variables
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
    if (!(Get-Variable DefaultJitProgramFolder -Scope Global -ErrorAction SilentlyContinue)) {
        Set-Variable -name DefaultJitProgramFolder -value ($env:ProgramFiles +"\Just-In-Time") -Scope Global -Option ReadOnly
    }
    if (!(Get-Variable DefaultSetupRegPath -Scope Global -ErrorAction SilentlyContinue)) {
        Set-Variable -name DefaultSetupRegPath -value ("HKLM:\SOFTWARE\Just-In-Time-Administration") -Scope Global -Option ReadOnly
    }

    #registry values
    # SetupStatus
    # only set with 'FullInstall' and 'AddServer'
    # 1000 - no installation yet
    # 1001 - files copied
    # 1002 - AD schema extantions done
    # 1003 - AD structure done
    # 1004 - Server authorized - JiT installed


    Function Check-AdminPrivileges
    {

	    $HasSeBackupPriv = $false
        $WindowsIdentity = [system.security.principal.windowsidentity]::GetCurrent()
        $HasSeSecurityPriv = (whoami /priv |findstr SeSecurityPrivilege)

        return $HasSeSecurityPriv
    }

    Function Read-YesNoAnswer 
    {
	    Param (
            [Parameter(Mandatory=$true)][String]$Title,
		    [Parameter(Mandatory=$true)][String]$Message,
		    [Parameter(Mandatory=$false)][Int]$DefaultOption = 0
        )
	
	    $No = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
	    $Yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
	    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($No, $Yes)
        $result = $host.ui.PromptForChoice($Title, $Message, $Options, $DefaultOption)	

	    return $result
    }

    function Gen-OID
    {
        if ($CustomOidPrefix) {
            $Prefix = $CustomOidPrefix
        } else {
            $Prefix="1.2.840.999999.1.1.5" # Microsoft AD schema OIDs 1.2.840.113556.1.8000 --> Microsoft: 113556 ANSI number
        }
        $GUID=[System.Guid]::NewGuid().ToString() 
        $Parts=@() 
        $Parts+=[UInt64]::Parse($guid.SubString(0,4),"AllowHexSpecifier") 
        $Parts+=[UInt64]::Parse($guid.SubString(4,4),"AllowHexSpecifier") 
        $Parts+=[UInt64]::Parse($guid.SubString(9,4),"AllowHexSpecifier") 
        $Parts+=[UInt64]::Parse($guid.SubString(14,4),"AllowHexSpecifier") 
        $Parts+=[UInt64]::Parse($guid.SubString(19,4),"AllowHexSpecifier") 
        $Parts+=[UInt64]::Parse($guid.SubString(24,6),"AllowHexSpecifier") 
        $Parts+=[UInt64]::Parse($guid.SubString(30,6),"AllowHexSpecifier") 
        $OID=[String]::Format("{0}.{1}.{2}.{3}.{4}.{5}.{6}.{7}",$prefix,$Parts[0],$Parts[1],$Parts[2],$Parts[3],$Parts[4],$Parts[5],$Parts[6]) 
        Return $oid 
    }

    function Update-Schema
    {
        [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
        param (
            [Parameter(Mandatory=$false)] [switch]$AddDelegationSchema
        )

        $ret = $True
        $ExecutionDirectory = (Get-Location).Path
        $ConfigSchemaAttributesFileName = $ExecutionDirectory + "\JitConfigSchema.ads"
        $DelegationSchemaAttributesFileName = $ExecutionDirectory + "\JitDelegationSchema.ads"

        #schema Path
        $AdSchemaPath = (Get-ADRootDSE).schemaNamingContext
        #get acl template
        $DefaultAcl = (Get-Acl "AD:/$('cn=Class-Registration,'+$AdSchemaPath)")

        #the new classes are of type structural
        $ObjectCategory = 1 # --> 'Structural'

        #DN name of new class objects
        $JitCnfgClassSchemaName = 'JiT-Configuration Object'
        $JitDelegationClassSchemaName = 'JiT-Delegation Object'

        #class/ldap name of new class objects
        $JitCnfgObjClassName = 'JiT-ConfigurationObject'
        $JitDelegationObjClassName = 'JiT-DelegationObject'


        if ($AddDelegationSchema) {
            $SchemaAttributesFileName = $DelegationSchemaAttributesFileName

            #region create the new classes
            $JiTDelegationClassAttributes = @{
                governsId = Gen-OID
                adminDescription = $JitDelegationClassSchemaName
                objectClass =  'classSchema'
                ldapDisplayName = $JitDelegationObjClassName
                adminDisplayName =  $JitDelegationClassSchemaName
                objectClassCategory = $ObjectCategory
                systemOnly =  $FALSE
                # subclassOf: top
                subclassOf = "2.5.6.0"
                # rdnAttId: cn
                rdnAttId = "2.5.4.3"
            }

            $ConfirmationMessage = "$($JitDelegationClassSchemaName) in $AdSchemaPath. This cannot be undone"
            $Caption = 'Adding new classes to Active Directory Schema'

            if ($PSCmdlet.ShouldProcess($ConfirmationMessage, $Caption)) {
                if (!(Get-ADObject -Filter 'name -eq $JitDelegationClassSchemaName' -SearchBase $AdSchemaPath)) {
                    try {
                        Write-Host "Creating new schema class $($JitDelegationClassSchemaName) ..." -ForegroundColor Yellow
                        New-ADObject -Name $JitDelegationClassSchemaName -Type 'classSchema' -Path $AdSchemaPath -OtherAttributes $JiTDelegationClassAttributes  
                        Write-Host "--> Schema class $($JitDelegationClassSchemaName) created!" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "Schema extention for class $($JitDelegationClassSchemaName) failed!" -ForegroundColor Red
                        Write-Host "exiting ..." -ForegroundColor Red
                        Write-Host $_.Exception.Message -ForegroundColor Red
                        $ret = $false
                        return $ret
                    }
                    try {
                        Write-Host
                        Write-Host "Setting permissions for new schema class $($JitDelegationClassSchemaName) ..." -ForegroundColor Yellow
                        Set-Acl -Path "AD:/$('CN='+$JitDelegationClassSchemaName+','+$AdSchemaPath)" -AclObject $DefaultAcl -Passthru:$PassThru
                        Write-Host "--> Done!" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "Could not set permissions for new class $($JitDelegationClassSchemaName)!" -ForegroundColor Red
                        Write-Host "exiting ..." -ForegroundColor Red
                        Write-Host $_.Exception.Message -ForegroundColor Red
                        $ret = $false
                        return $ret
                    }
                } else {
                    Write-Host "--> Schema class $($JitDelegationClassSchemaName) already exists!" -ForegroundColor Green
                }
            }
            #endregion

        } else {
            $SchemaAttributesFileName = $ConfigSchemaAttributesFileName

            #region create the new classes
            $JiTConfigClassAttributes = @{
                governsId = Gen-OID
                adminDescription = $JitCnfgClassSchemaName
                objectClass =  'classSchema'
                ldapDisplayName = $JitCnfgObjClassName
                adminDisplayName =  $JitCnfgClassSchemaName
                objectClassCategory = $ObjectCategory
                systemOnly =  $FALSE
                # subclassOf: top
                subclassOf = "2.5.6.0"
                # rdnAttId: cn
                rdnAttId = "2.5.4.3"
            }

            $ConfirmationMessage = "$($JitCnfgClassSchemaName) in $AdSchemaPath. This cannot be undone"
            $Caption = 'Adding new classes to Active Directory Schema'

            if ($PSCmdlet.ShouldProcess($ConfirmationMessage, $Caption)) {
                if (!(Get-ADObject -Filter 'name -eq $JitCnfgClassSchemaName' -SearchBase $AdSchemaPath)) {
                    try {
                        Write-Host
                        Write-Host "Creating new schema class $($JitCnfgClassSchemaName) ..." -ForegroundColor Yellow
                        New-ADObject -Name $JitCnfgClassSchemaName -Type 'classSchema' -Path $AdSchemaPath -OtherAttributes $JiTConfigClassAttributes  
                        Write-Host "--> Schema class $($JitCnfgClassSchemaName) created!" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "Schema extention for class $($JitCnfgClassSchemaName) failed!" -ForegroundColor Red
                        Write-Host "exiting ..." -ForegroundColor Red
                        Write-Host $_.Exception.Message -ForegroundColor Red
                        $ret = $false
                        return $ret
                    }
                    try {
                        Write-Host
                        Write-Host "Setting permissions for new schema class $($JitCnfgClassSchemaName) ..." -ForegroundColor Yellow
                        Set-Acl -Path "AD:/$('CN='+$JitCnfgClassSchemaName+','+$AdSchemaPath)" -AclObject $DefaultAcl -Passthru:$PassThru
                        Write-Host "--> Done!" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "Could not set permissions for new class $($JitCnfgClassSchemaName)!" -ForegroundColor Red
                        Write-Host "exiting ..." -ForegroundColor Red
                        Write-Host $_.Exception.Message -ForegroundColor Red
                        $ret = $false
                        return $ret
                    }
                } else {
                    Write-Host "--> Schema class $($JitCnfgClassSchemaName) already exists!" -ForegroundColor Green
                }
            }
            #endregion
        }

        #Get the schema attributes from the csv file
        if (!(Test-Path $SchemaAttributesFileName)) {
            Write-Host
            Write-Host "Schema attribute file: $SchemaAttributesFileName missing - aborting!" -ForegroundColor Red
            $ret = $false
            return $ret
        }else {
            try {
                $NewSchemaAttributes = Import-CSV $SchemaAttributesFileName
            }
            catch {
                Write-Host "Could not read schema attribute files - aborting!" -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                $ret = $false
                return $ret
            }
        }

        if ($AddDelegationSchema) {
            $ConfirmationMessage = "$($JitDelegationClassSchemaName) in $AdSchemaPath. This cannot be undone"
        } else {
            $ConfirmationMessage = "$($JitCnfgClassSchemaName) in $AdSchemaPath. This cannot be undone"
        }
        $Caption = 'Adding new attributes to Active Directory Schema'

        if ($PSCmdlet.ShouldProcess($ConfirmationMessage, $Caption)) {
            #region create the attributes
            ForEach ($Attribute in $NewSchemaAttributes) {
                # Build OtherAttributes
                $Attributes = @{
                    lDAPDisplayName = $Attribute.Name;
                    attributeId = Gen-OID
                    oMSyntax = $Attribute.oMSyntax;
                    attributeSyntax =  $Attribute.AttributeSyntax;
                    isSingleValued = if ($Attribute.isSingleValued -like "*true*") {$True} else {$false};
                    adminDescription = $Attribute.Description;
                    searchflags = if ($Attribute.Indexed -like "yes") {1} else {0}
                }
 
                $temp = $Attribute.Name
                if (!(Get-ADObject -Filter 'name -eq $temp' -SearchBase $AdSchemaPath)) {
                    #create new JiT schema attribute in AD
                    try {
                        Write-Host
                        Write-Host "Creating new schema attribute '$($Attribute.Name)' ..." -ForegroundColor Yellow
                        New-ADObject -Name  $Attribute.Name -Type attributeSchema -Path $AdSchemaPath -OtherAttributes $Attributes
                        Write-Host "--> Schema attribute '$($Attribute.Name)' created!" -ForegroundColor Green
                     }
                    catch {
                        Write-Host "Schema extention for attribute '$($Attribute.Name)' failed!" -ForegroundColor Red
                        Write-Host "exiting ..." -ForegroundColor Red
                        Write-Host $_.Exception.Message -ForegroundColor Red
                        $ret = $false
                        return $ret
                    }
                } else {
                    Write-Host "--> Schema attribute $($Attribute.Name) already exists!" -ForegroundColor Green
                }

                #add attribute to proper JiT class
                if ($AddDelegationSchema) {
                    $JitSchemaClass = get-adobject -SearchBase $AdSchemaPath -Filter 'name -eq $JitDelegationClassSchemaName'
                } else {
                    $JitSchemaClass = get-adobject -SearchBase $AdSchemaPath -Filter 'name -eq $JitCnfgClassSchemaName'
                }
                try {
                    Write-Host
                    Write-Host "Adding attribute '$($Attribute.Name)' to class '$($JitSchemaClass.Name)'..." -ForegroundColor Yellow
                    $JitSchemaClass | Set-ADObject -Add @{mayContain = $Attribute.Name}
                    Write-Host "--> Done!" -ForegroundColor Green
                 }
                catch {
                    Write-Host "Could not add schema attribute '$($Attribute.Name)' to class '$($JitSchemaClass.Name)'!" -ForegroundColor Red
                    Write-Host "exiting ..." -ForegroundColor Red
                    Write-Host $_.Exception.Message -ForegroundColor Red
                    $ret = $false
                    return $ret
                }
            }
            #setting possible superiors
            if ($AddDelegationSchema) {
                $JitSchemaClass = get-adobject -SearchBase $AdSchemaPath -Filter 'name -eq $JitDelegationClassSchemaName'
            } else {
                $JitSchemaClass = get-adobject -SearchBase $AdSchemaPath -Filter 'name -eq $JitCnfgClassSchemaName'
            }
            try {
                Write-Host
                Write-Host "Adding possible superiors for class '$($JitSchemaClass.Name)'..." -ForegroundColor Yellow
                $JitSchemaClass | Set-ADObject -Add @{possSuperiors = 'container'}
                Write-Host "--> Done!" -ForegroundColor Green
            }
            catch {
                Write-Host "Could not add possible superiors for class '$($JitSchemaClass.Name)'!" -ForegroundColor Red
                Write-Host "exiting ..." -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                $ret = $false
                return $ret
            }
            #endregion
        }
        return $ret
    }

    Function Authorize-Computer
    {
        #we assume all works well
        $ret = $true

        #get local computername and sid
        $CmpName = (Get-WmiObject Win32_ComputerSystem).name
        $ID = new-object System.Security.Principal.NTAccount($CmpName+"$")
        $CmpSid = $ID.Translate( [System.Security.Principal.SecurityIdentifier] ).toString()

        try {
            Write-Host
            Write-Host "Registering computer for using JiT ..." -ForegroundColor Yellow
            Set-ADObject -Identity $DefaultJiTADCnfgObjectDN -Add @{'JitCnfg-AuthorizedServer'=$CmpSid}|Out-Null
            Write-Host "--> Local computer: $($CmpName) successfully registered!" -ForegroundColor Green
        } catch {
    
            Write-Host "Could not register local computer for using JiT!" -ForegroundColor Red
            Write-Host "Operation failed!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            $ret = $false
        }
        return $ret
    }

    Function Unauthorize-Computer
    {
        #we assume all works well
        $ret = $true

        #get local computername and sid
        $CmpName = (Get-WmiObject Win32_ComputerSystem).name
        $ID = new-object System.Security.Principal.NTAccount($CmpName+"$")
        $CmpSid = $ID.Translate( [System.Security.Principal.SecurityIdentifier] ).toString()

        #getting list of current authorized systems
        try {
            $CurrJitAuth = (Get-ADObject -Identity $DefaultJiTADCnfgObjectDN -Properties 'JitCnfg-AuthorizedServer').'JitCnfg-AuthorizedServer'
            #$CurrJitAuth = $config.'JitCnfg-AuthorizedServer'
        } catch {
            #could not read AD config object
            #teminating error
            Write-Host "Could not read JiT configuration!" -ForegroundColor Red
            Write-Host "Operation failed!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            $ret = $false
        }
        if ($ret) {
            #ensuring resultened list is not empty
            if ($CurrJitAuth) {
                if ($CurrJitAuth -contains $CmpSid) {
                    #update AD config object with new list of authorized computers
                    try {
                        Write-Host
                        Write-Host "removing computer from using JiT ..." -ForegroundColor Yellow
                        Set-ADObject -Identity $DefaultJiTADCnfgObjectDN -Remove @{'JitCnfg-AuthorizedServer'=$CmpSid}
                        Write-Host "--> Local computer: $($CmpName) successfully removed!" -ForegroundColor Green
                    } catch {
                        Write-Host "Could not remove local computer from using JiT!" -ForegroundColor Red
                        Write-Host "Operation failed!" -ForegroundColor Red
                        Write-Host $_.Exception.Message -ForegroundColor Red
                        $ret = $false
                    }
                }
            }
        }
        return $ret
    }

    function create-AdJiTStructure
    {
        #we assume all works well
        $ret = $true

        #defining AD location & container names
        $baseAdPath = "CN=Services,"+(Get-ADRootDSE).configurationNamingContext
        $defaultJiTContainerName = "Just-In-Time Administration"
        $defaultJiTDelegationContainerName = "Delegations"
        $defaultJiTCnfgName = "JiT-Configuration"


        try {
            Write-Host
            Write-Host "Checking container: '$($defaultJiTContainerName)' ..." -ForegroundColor Yellow
            Get-ADObject -Identity ("CN=$($defaultJiTContainerName),$($baseAdPath)")
            Write-Host "--> container exists ..." -ForegroundColor Green
        }
        catch {
            Write-Host "Just-In-Time structure does not exists - creating ..." -ForegroundColor Yellow
            try {
                Write-Host
                Write-Host "creating container: '$($defaultJiTContainerName)' ..." -ForegroundColor Yellow
                New-ADObject -Name $defaultJiTContainerName -Type "container" -Path  $baseAdPath
                Write-Host "--> done ..." -ForegroundColor Green
            }
            catch {
                Write-Host "Could not create Just-In-Time structure in AD!" -ForegroundColor Red
                Write-Host 
                Write-Host $_.Exception.Message -ForegroundColor Red
                $ret = $false
            }
        }

        if ($ret) {
            try {
                Write-Host
                Write-Host "Checking for container: '$($defaultJiTDelegationContainerName)' ..." -ForegroundColor Yellow
                Get-ADObject -Identity ("CN=$($defaultJiTDelegationContainerName),CN=$($defaultJiTContainerName),$($baseAdPath)")
                Write-Host "--> container exists ..." -ForegroundColor Green
            }
            catch {
                Write-Host
                Write-Host "creating container: '$($defaultJiTDelegationContainerName)' ..." -ForegroundColor Yellow
                try {
                    New-ADObject -Name $defaultJiTDelegationContainerName -Type "container" -Path  ("CN=$($defaultJiTContainerName),$($baseAdPath)")
                    Write-Host "--> JiT AD structure done ..." -ForegroundColor Green
                }
                catch {
                    Write-Host "Could not create container: '$($defaultJiTDelegationContainerName)'!" -ForegroundColor Red
                    Write-Host 
                    Write-Host $_.Exception.Message -ForegroundColor Red
                    $ret = $false
                }
            }
        }
    
        if ($ret) {
            #region create default JiT configuration
            try {
                Write-Host
                Write-Host "creating default JiT configuration ..." -ForegroundColor Yellow
                Write-Host "--> $($DefaultJiTADCnfgObjectDN)"
                #only required attributes now
                New-ADObject -Name $defaultJiTCnfgName -Type $JitCnfgObjClassName -Path ("CN=$($defaultJiTContainerName),$($baseAdPath)") -OtherAttributes @{
                    'JitCnfg-ConfigScriptVersion' = "20250131"
                    'JitCnfg-JitAdmGroupOU' = "OU=JIT-Administrator Groups,OU=Tier 1,OU=Admin,$((Get-ADDomain).DistinguishedName)"
                    'JitCnfg-AdminPreFix' = "Admin_"
                    'JitCnfg-Domain' = $((Get-ADDomain).DNSRoot)
                    'JitCnfg-Tier0ServerGroupName' = @("Tier 0 Computers")
                    'JitCnfg-LDAPT1Computers' = "(&(OperatingSystem=*Windows*)(OperatingSystem=*Server*)(ObjectClass=Computer)(!(ObjectClass=msDS-GroupManagedServiceAccount))(!(PrimaryGroupID=516))(!(PrimaryGroupID=521)))"
                    'JitCnfg-T1Searchbase' = @("<DomainRoot>")
                    'JitCnfg-MaxElevatedTime' = 600
                    'JitCnfg-DefaultElevatedTime' = 60
                    'JitCnfg-MaxConcurrentServer' = 10
                    'JitCnfg-GroupManagedServiceAccountName' = "Tier1JiTgMSA"
                    'JitCnfg-TaskRunInterval' = 10
                    'JitCnfg-TaskScriptSource' = $DefaultJitProgramFolder
                    'JitCnfg-EventLog' = "Tier1 Just-in-Time"
                    'JitCnfg-EventSource' = "T1Mgmt"
                    'JitCnfg-ElevateEventID' = 100
                    'JitCnfg-EnableMultiDomainSupport' = $false
                    'JitCnfg-EnableDelegation' = $true
                    'JitCnfg-DomainSeparator' = "#"
                    'JitCnfg-UseManagedByforDelegation' = $false
                    'JitCnfg-DelegationConfigPath' = "(NotUsed!)"
                }
                Write-Host "--> Default JiT configuration created ..." -ForegroundColor Green
            }
            catch {
                Write-Host "Could not create JiT configuration!" -ForegroundColor Red
                Write-Host 
                Write-Host $_.Exception.Message -ForegroundColor Red
                $ret = $false
            }
            #endregion
        }
        return $ret
    }

    function Install-JiTFiles
    {
        param (
            [Parameter(Mandatory = $false)][string]$JitProgramFolder
        )

        #list of JiT program files
        $JitFileList = @(
            "Config-JIT.ps1",
            "Install-JIT.ps1",
            "Request-AdminAccessUI.ps1",
            "Configure-DelegationUI.ps1",
            "ElevateUser.ps1",
            "Tier1LocalAdminGroup.ps1"
        )

        #we assume all works well
        $ret = $true

        if ($null -ne $JitProgramFolder){
            $JitProgramFolder = $env:ProgramFiles +"\Just-In-Time"
        } else {
            $JitProgramFolder = $DefaultJitProgramFolder
        }

        Write-Host "Select 'Just-In-Time' programm folder..." -ForegroundColor Yellow
        $TargetDir = Read-Host "Installation Directory ($JitProgramFolder)"
        if ($TargetDir -eq ""){
            $TargetDir = $JitProgramFolder
        }
        try {
            if (!(Test-Path -Path $TargetDir)) {
                New-Item -Path $TargetDir -ItemType Directory -ErrorAction Stop
            }

            Write-Host "Copying 'Just-In-Time' programm files..." -ForegroundColor Yellow
            #copy program files
            $JitFileList | ForEach-Object {
                Write-Host "---> File: $($_)" -ForegroundColor Yellow
                #get full file path
                $FileName = Get-Item $_ -ErrorAction SilentlyContinue
                if ($FileName) {
                    Copy-Item $FileName.FullName $TargetDir -ErrorAction Stop -Force -Verbose
                } else {
                    Write-Host "File: $($_) does not exists - skipping..." -ForegroundColor Red
                }
                Write-Host
            }

            # copying the module files
            if (!(Test-Path "$($env:ProgramFiles)\WindowsPowerShell\Modules\Just-In-Time") ){
                New-Item "$($env:ProgramFiles)\WindowsPowerShell\Modules\Just-In-Time" -ItemType Directory -ErrorAction Stop -Verbose
            }
            Copy-Item .\modules\* -Destination "$($env:ProgramFiles)\WindowsPowerShell\Modules\Just-In-time" -Recurse -ErrorAction Stop -Force 
            #Set-Location -Path $TargetDir
        } 
        catch [System.UnauthorizedAccessException] {
            Write-Host "A access denied error occured" -ForegroundColor Red
            Write-Host "Run the installation as administrator"
            $ret = $false
        }
        catch{
            Write-Host "A unexpected error is occured" -ForegroundColor Red
            $Error[0] 
            $ret = $false
        }
        return $ret
    }

    function Move-CentralTaskScripts
    {
        #assuming all goes well
        $ret = $true

        $targetDir = (Get-ADObject -Identity $DefaultJiTADCnfgObjectDN -Properties 'JitCnfg-TaskScriptSource').'JitCnfg-TaskScriptSource'
        #$TargetDir = $global:config.'JitCnfg-TaskScriptSource'
        $JitFiles2Move = @(
            "Request-AdminAccessUI.ps1",
            "ElevateUser.ps1"
        )

        if ($DefaultJitProgramFolder -ne $TargetDir) {
            #move task files
            Write-Host 
            Write-Host "Moving central task scripts to $($targetDir)" -ForegroundColor Yellow
            try {
                $JitFiles2Move | ForEach-Object {
                    Write-Host "---> File: $($_)" -ForegroundColor Yellow
                    #get full file path
                    $FileName = Get-Item $_ -ErrorAction SilentlyContinue
                    if ($FileName) {
                        Move-Item $FileName.FullName $TargetDir -ErrorAction Stop -Force -Verbose
                    } else {
                        Write-Host "File: $($_) does not exists - skipping..." -ForegroundColor Red
                    }
                    Write-Host
                }
            }
            catch [System.UnauthorizedAccessException] {
                Write-Host "A access denied error occured" -ForegroundColor Red
                Write-Host "check permission at $($TargetDir)" -ForegroundColor Magenta
                $ret = $false
            }
            catch{
                Write-Host "A unexpected error is occured" -ForegroundColor Red
                $Error[0] 
                $ret = $false
            }
        }
        return $ret
    }

    function Uninstall-JiT
    {
        param(
            [Parameter(Mandatory = $false)][string]$JitProgramFolder
        )

        #we assume all works well
        $ret = $true

        if ($null -ne $JitProgramFolder){
            $JitProgramFolder = $env:ProgramFiles +"\Just-In-Time"
        }
        if (Check-AdminPrivileges) {
            #remove JiT module
            if ((Get-Module -Name 'just-in-time')) {
                Write-Host "removing 'Just-in-Time' Powershell module..." -ForegroundColor Yellow
                try {
                    Uninstall-Module Just-In-Time
                } catch {
                    Write-Host "'Just-in-Time' Powershell module could not be removed!" -ForegroundColor Yellow -BackgroundColor DarkRed
                }
            }
            #Remove scheduled tasks
            Write-Host "removing 'Just-in-Time' scheduled tasks..." -ForegroundColor Yellow
            Get-ScheduledTask -TaskPath "\Just-In-Time-Privilege\*"|Unregister-ScheduledTask -Confirm:$false
            Remove-Item "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Just-In-Time-Privilege" -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
            if (Test-Path "C:\Program Files\WindowsPowerShell\Modules\Just-In-Time") {
                Write-Host "removing 'Just-in-Time' module files..." -ForegroundColor Yellow
                Remove-Item "C:\Program Files\WindowsPowerShell\Modules\Just-In-Time" -Recurse -Force -Confirm:$false
            }
            #remove JiT program files&folders
            if ((Get-Item .).FullName -match [regex]::Escape($JitProgramFolder)) {
                cd ..
            }
            if (Test-Path $JitProgramFolder) {
                Write-Host "removing 'Just-in-Time' program files..." -ForegroundColor Yellow
                Remove-Item $JitProgramFolder -Recurse -Force -Confirm:$false
            }
            #
            Write-Host "Unauthorizing computer from 'Just-in-Time' administration..." -ForegroundColor Yellow
            if (!(Unauthorize-Computer)) {
                Write-Host "removing computer from JiT authorization failed!" -BackgroundColor DarkRed -ForegroundColor Yellow
                Write-Host "please remove computer manually from JiT authorization!" -BackgroundColor Magenta
                $ret = $false
            }
        } else {
            Write-Host "Not enough permissions ..." -BackgroundColor DarkRed -ForegroundColor Yellow
            Write-Host "Uninstallation failed!`n`rExiting ..." -BackgroundColor DarkRed -ForegroundColor Yellow
            $ret = $false
        }
        return $ret
    }

    function Update-SchemaCache
    {

        #we assume all works well
        $ret = $true

        $SchemaMaster = (Get-ADForest).SchemaMaster.Split('.')[0]
        Write-Host
        Write-Host "Now updating AD schema cache using schema master: $($SchemaMaster) ..." -ForegroundColor Yellow

        Try {
            $RootDSE = [ADSI] "LDAP://$SchemaMaster/RootDSE"
            $RootDSE.put("SchemaUpdateNOW",1)
            $RootDSE.SetInfo()
            Write-Host "--> AD schema cache successfully updated!" -ForegroundColor Green
        } Catch {
            Write-Host "--> AD schema cache could not be updated!" -ForegroundColor Red
            Write-Host "--> Please update AD schema cache manually and after run:" -ForegroundColor Red
            Write-Host "--> $($JitProgramFolder)\install.ps1 -createADObjects" -ForegroundColor Magenta
            Write-Host "--> to complete installation!" -ForegroundColor Yellow
            $_.Exception.Message
            $ret= $false
        }
      return $ret
    }

    function Delegate-AdJiTStructure
    {
        param (
            [Parameter(Mandatory=$True)] [string]$AdPrincipal
        )


        #we assume all works well
        $ret = $true

        #defining JiT AD location
        $defaultJiTContainerDN = "CN=Just-In-Time Administration,CN=Services,"+(Get-ADRootDSE).configurationNamingContext

        Write-Host "Delegating ACL on OU '$DefaultOUName' for $($objgMSA.name) ..." -ForegroundColor Yellow
        $aclGroupOU = Get-ACL -Path "AD:\$($defaultJiTContainerDN)"

        if (!($aclGroupOU.Sddl.Contains($objgMSA.SID))){
            Write-Debug "Adding ACE to structure"
            #granting gMSA control on group objects in Tier 1 Jit admin group OU.
            $Identity = [System.Security.Principal.IdentityReference] $objgMSA.SID
            $Type = 'Allow' 

            $Rule1AdRights = 'GenericAll' 
            $Rule1ObjectType = '00000000-0000-0000-0000-000000000000' 
            $Rule1InheritanceType = 'Descendents' 
            $Rule1InheritedObjectType = '00000000-0000-0000-0000-000000000000'  
            $Rule1ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$Rule1AdRights,$Type,$Rule1ObjectType,$Rule1InheritanceType,$Rule1InheritedObjectType


            # Full control to any group object in this OU and createChild, deleteChild for group object in this OU
            #$adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
            #$type = [System.Security.AccessControl.AccessControlType] "Allow"
            #$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
            #$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
            #$aclGroupOU.AddAccessRule($ace)
                
            $aclGroupOU.AddAccessRule($Rule1ACE)
            Set-Acl -AclObject $aclGroupOU "AD:\$($DefaultOUName)"
        }
    }

    #collecting run requirements
    $IsAdmin = Check-AdminPrivileges
    #collecting running user, group memberships and forest sid
    $CurrUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name.split("\")[1]
    $groupTokens = ([string](Get-ADUser -Filter 'samaccountname -eq $curruser').distinguishedname|Get-ADUser -Properties tokengroups).tokengroups.value

    #checking if running user is Domain admin or Enterprise admin
    $forestSid = (Get-ADDomain -server (Get-ADForest).rootdomain|Select-Object domainsid).domainsid.Value
    $HasDaOrEA = (($groupTokens.Value -eq ($forestSid+"-512")) -or ($groupTokens.Value -eq ($forestSid+"-519")))
    $IsSA = ($groupTokens.Value -eq ($forestSid+"-518"))

}

###########
# Main program
###########
process {
    
    if ($exit) {
        Exit
    }

    if ($null -ne $JitProgramFolder){
        $JitProgramFolder = $env:ProgramFiles +"\Just-In-Time"
    }

    #defines hard exit
    $exit = $false

    #start common welcome mask
    Clear-Host
    Write-Host
    Write-Host "###################################################################" -ForegroundColor Yellow
    Write-Host "Welcome the the 'Just-In-Time' administration programm installation" -ForegroundColor Yellow


    if ((!$exit) -and ($PSCmdlet.ParameterSetName -eq "FullInstall")) {

        #JiT schema in AD
        $JitDelegationClassDN = 'JiT-Delegation Object'
        $CnfgObjSchemaExtDone = $false

        #continue welcome mask
        Write-Host "--> Full Installation" -ForegroundColor Yellow
        Write-Host "###################################################################" -ForegroundColor Yellow
        Write-Host

        #checking if running user is Domain admin or Enterprise admin
        if ($HasDaOrEA) {
            #check for elevation
            if ($IsAdmin) {
                #create reg hive
                if (!(Test-Path $DefaultSetupRegPath)) {
                    Write-Host "Creating registry ..." -ForegroundColor Yellow
                    try{
                        New-Item -Path $DefaultSetupRegPath | Out-Null
                        New-ItemProperty -Path $DefaultSetupRegPath -Name "SetupStatus" -PropertyType dword -Value 1000 | Out-Null
                    } catch {
                        Write-Host "Could not create 'Just-in-Time' registry!" -ForegroundColor Red
                        Write-Host $_.Exception.Message -ForegroundColor Red
                        Write-Host "'Just-in-Time' installation failed!" -ForegroundColor Red
                        $exit = $true
                    }
                }
                if (!$exit) {
                    if ((Read-YesNoAnswer -Title "Just-in-Time Installation" -Message "Do you want to install 'Just-In-Time' administration now?") -eq 1) {
                        #installing files 1st
                        if (!(Install-JiTFiles)) {
                            Write-Host 
                            Write-Host 
                            Write-Host "'Just-in-Time' installation failed!" -ForegroundColor Red
                            $exit = $true
                        } else {
                            Set-ItemProperty -Path $DefaultSetupRegPath -Name "SetupStatus" -Value 1001 | Out-Null
                        }

                        #checking for JiT schema in AD
                        if (!$exit) {
                            try {
                                Write-Host
                                Write-Host "Checking for 'Just-in-Time' schema extensions..." -ForegroundColor Yellow
                                Get-ADObject -Identity "CN=$($JitDelegationClassDN),$((Get-ADRootDSE).schemaNamingContext)"|Out-Null
                                $CnfgObjSchemaExtDone = $true
                                Write-Host "--> 'Just-in-Time' schema extensions already implemented..." -ForegroundColor Green
                                Set-ItemProperty -Path $DefaultSetupRegPath -Name "SetupStatus" -Value 1002 | Out-Null
                            } catch {
                                #JiT schema missing
                                Write-Host 
                                Write-Host "AD schema not updated for 'Just-in-Time' administration!" -ForegroundColor Yellow
                                #check for schema admin
                                #get real schema admin token
                                $SchemaAdm = whoami /groups | findstr "Schema"
                                #if (($groupTokens.Value -eq ($forestSid+"-518"))) {
                                if ($SchemaAdm) {
                                    if ((Read-YesNoAnswer -Message "Do you want to extend the AD schema now?" -Title "Add JiT schema objects") -eq 1) {
                                        $CnfgObjSchemaExtDone = Update-Schema
                                        $CnfgObjSchemaExtDone = $CnfgObjSchemaExtDone -and (Update-Schema -AddDelegationSchema)
                                    } else {
                                        Write-Host "Don't forget to update AD schema before configuring JiT by running:" -ForegroundColor Yellow
                                        Write-Host "install-JiT.ps1 -ExtendSchema" -ForegroundColor Magenta
                                        $exit = $true
                                    }
                                } else {
                                    Write-Host
                                    Write-Host "AD schema cannot be updated as current run account is not member of 'Schema Admins'!" -ForegroundColor Red
                                    Write-Host
                                    Write-Host "Don't forget to update AD schema before configuring JiT by running:" -ForegroundColor Yellow
                                    Write-Host "install-JiT.ps1 -ExtendSchema" -ForegroundColor Magenta
                                    $exit = $true
                                }
                            }
                            #update schema chache
                            if ($CnfgObjSchemaExtDone) {
                                $CnfgObjSchemaExtDone = $CnfgObjSchemaExtDone -and (Update-SchemaCache)
                            }
                        }
                        #checking for JiT AD structure
                        if ($CnfgObjSchemaExtDone) {
                            try {
                                Set-ItemProperty -Path $DefaultSetupRegPath -Name "SetupStatus" -Value 1002 | Out-Null
                                Write-Host "Checking for 'Just-in-Time' administration AD structure..." -ForegroundColor Yellow
                                Get-ADObject -Identity $DefaultJiTADCnfgObjectDN|Out-Null
                                Write-Host "--> 'Just-in-Time' administration AD structure already created..." -ForegroundColor Green
                                Set-ItemProperty -Path $DefaultSetupRegPath -Name "SetupStatus" -Value 1003 | Out-Null
                            }
                            catch {
                                #JiT AD structure missing
                                Write-Host "JiT structure in Active Directory missing ..."
                                if ((Read-YesNoAnswer -Message "Do you want to create the JiT AD structure now?" -Title "Create AD JiT structure") -eq 1) {
                                    $exit = (!(create-AdJiTStructure))
                                } else {
                                    Write-Host "Don't forget to create JiT AD structure before configuring JiT by running:" -ForegroundColor Yellow
                                    Write-Host "install-JiT.ps1 -createAdStructure" -ForegroundColor Magenta
                                    $exit = $true
                                }
                            }
                            if (!$exit) {
                                Set-ItemProperty -Path $DefaultSetupRegPath -Name "SetupStatus" -Value 1003 | Out-Null
                                $exit = (!(Authorize-Computer))
                            }
                        } else {
                            $exit = $true
                        }
                    } else {
                        Write-Host "'Just-in-Time' installation canceled!" -ForegroundColor Red
                        $exit = $true
                    }
                }
            } else {
                Write-Host "Current run session is not elevated - aborting!" -ForegroundColor Red
                $exit = $true
            }
        } else {
            Write-Host "Current run account is not member of 'Domain Admins' - aborting!" -ForegroundColor Red
            $exit = $true
        }
    }

    if ((!$exit) -and ($PSCmdlet.ParameterSetName -eq "Uninstall")) {
        #continue welcome mask
        Write-Host "--> Removing 'Just-In-Time' from this computer" -ForegroundColor Yellow
        Write-Host "###################################################################" -ForegroundColor Yellow
        Write-Host
        if ((Read-YesNoAnswer -Title "Just-in-Time Uninstallation" -Message "Do you want to uninstall 'Just-In-Time' administration now?") -eq 1) {
            if (!(Uninstall-JiT)) {
                Write-Host 
                Write-Host 
                Write-Host "Uninstallation of Just-in-Time solution failed!" -ForegroundColor Red
                $exit = $true
            } else {
                Remove-Item -Path $DefaultSetupRegPath -Recurse | Out-Null
            }
        } else {
            Write-Host "'Just-in-Time' deinstallation canceled!" -ForegroundColor Yellow
            $exit = $true
        }
    }

    if ((!$exit) -and ($PSCmdlet.ParameterSetName -eq "ExtendSchema")) {
        #continue welcome mask
        Write-Host "--> AD Schema Extension" -ForegroundColor Yellow
        Write-Host "###################################################################" -ForegroundColor Yellow
        Write-Host
        #checking if running user is schema admin
        $CurrUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($IsSA) {
            #check for elevation
            if ($IsAdmin) {
                $schemaResult = Update-Schema
                if (!$schemaResult) {
                    Write-Host 
                    Write-Host 
                    Write-Host "Schema update failed!" -ForegroundColor Red
                    $exit = $true
                    #return
                } else {
                    $schemaResult = Update-Schema -AddDelegationSchema
                    if (!$schemaResult) {
                        Write-Host 
                        Write-Host 
                        Write-Host "Schema update failed!" -ForegroundColor Red
                        $exit = $true
                    } else {
                        if (!(Update-SchemaCache)) {
                            Write-Host 
                            Write-Host 
                            Write-Host "Refresh of schema cache failed!" -ForegroundColor Red
                            Write-Host "Please refresh schema cache manually before continuing!" -ForegroundColor Magenta
                        }
                    }
                }
            } else {
                Write-Host "Current run session is not elevated - aborting!" -ForegroundColor Red
                $exit = $true
            }
        } else {
            Write-Host "Current run account is not member of 'Schema Admins' - aborting!" -ForegroundColor Red
            $exit = $true
        }
    }

    if ((!$exit) -and ($PSCmdlet.ParameterSetName -eq "CreateADObjects")) {
        #continue welcome mask
        Write-Host "--> Creating 'Just-In-Time' AD Structure" -ForegroundColor Yellow
        Write-Host "###################################################################" -ForegroundColor Yellow
        Write-Host

        #check for EA/DA
        if ($HasDaOrEA) {
            #check for elevation
            if ($IsAdmin) {
                if (!(create-AdJiTStructure)) {
                    $exit = $true
                    #return $false
                }
            } else {
                Write-Host "Current run session is not elevated - aborting!" -ForegroundColor Red
                $exit = $true
            }
        } else {
            Write-Host "Current run account is not member of 'Domain Admins' - aborting!" -ForegroundColor Red
            $exit = $true
        }
    }

    if ((!$exit) -and ($PSCmdlet.ParameterSetName -eq "AddServer")) {

        #continue welcome mask
        Write-Host "--> Authorizing new server for 'Just-In-Time' configuration" -ForegroundColor Yellow
        Write-Host "###################################################################" -ForegroundColor Yellow
        Write-Host

        #checking for JiT schema in AD
        try {
            Get-ADObject -Identity "CN=$($JitDelegationClassDN),$((Get-ADRootDSE).schemaNamingContext)"
            $CnfgObjSchemaExtDone = $true
        } catch {
            #JiT schema missing
            Write-Host 
            Write-Host "AD schema not updated for Just-in-Time administration!" -ForegroundColor Yellow
            Write-Host "Installation cannot proceed!" -ForegroundColor Red
            Write-Host "Either run full installation or run:" -ForegroundColor Red
            Write-Host "install-JiT.ps1 -ExtendSchema" -ForegroundColor Magenta
            $exit = $true
        }
        #checking for JiT AD structure
        if (!$exit) {
            try {
                Get-ADObject -Identity $DefaultJiTADCnfgObjectDN|Out-Null
            }
            catch {
                #JiT AD structure missing
                Write-Host "JiT structure in Active Directory missing ..." -ForegroundColor Yellow
                Write-Host "Installation cannot proceed!" -ForegroundColor Red
                Write-Host "Either run full installation or run:" -ForegroundColor Red
                Write-Host "install-JiT.ps1 -createAdStructure" -ForegroundColor Magenta
                $exit = $true
            }
        }

        if (!$exit) {
            #checking if running user is Domain admin or Enterprise admin
            if ($HasDaOrEA) {
                #check for elevation
                if ($IsAdmin) {
                    #installing files 1st
                    if (!(Install-JiTFiles)) {
                        Write-Host 
                        Write-Host 
                        Write-Host "Just-in-Time installation failed!" -ForegroundColor Red
                        $exit = $true
                    }
                    
                    if (!$exit) {
                        Set-ItemProperty -Path $DefaultSetupRegPath -Name "SetupStatus" -Value 1001 | Out-Null
                        $exit = (!(Authorize-Computer))
                    }
                } else {
                    Write-Host "Current run session is not elevated - aborting!" -ForegroundColor Red
                    $exit = $true
                }
            } else {
                Write-Host "Current run account is not member of 'Domain Admins' - aborting!" -ForegroundColor Red
                $exit = $true
            }
        }
    }
}

end {

    Write-Host
    Write-Host
    Write-Host "-----------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host

    if ($exit) {
        switch ($PSCmdlet.ParameterSetName) {
            'AddServer' {
                Write-Host "Adding new server to 'Just-in-Time' administration failed!" -ForegroundColor Red
                Write-Host "Please correct any error and re-run 'Install.ps1 -AddServer'" -ForegroundColor Magenta
            }
            'CreateADObjects' {
                Write-Host "Creation of AD 'Just-in-Time' structure failed!" -ForegroundColor Red
                Write-Host "Please correct any error and re-run 'Install.ps1 -createAdStructure'" -ForegroundColor Magenta
            }
            'ExtendSchema' {
                Write-Host "Schema update for 'Just-in-Time' Administration failed!" -ForegroundColor Red
                Write-Host "Please correct any error and re-run 'Install.ps1 -ExtendSchema'" -ForegroundColor Magenta
            }
            'Uninstall' {
                Write-Host "Uninstallation of 'Just-in-Time' Administration failed!" -ForegroundColor Red
                Write-Host "Please correct any error and re-run 'Install.ps1 -uninstall'" -ForegroundColor Magenta
            }
            'FullInstall' {
                Write-Host "Installation of 'Just-in-Time' Administration failed!" -ForegroundColor Red
                Write-Host "Please correct any error and re-run 'Install.ps1'" -ForegroundColor Magenta
            }
        }
    } else {
        switch ($PSCmdlet.ParameterSetName) {
            'AddServer' {
                Set-ItemProperty -Path $DefaultSetupRegPath -Name "SetupStatus" -Value 1004 | Out-Null
                Write-Host "Adding new server to 'Just-in-Time' administration was successfull!" -ForegroundColor Yellow -BackgroundColor DarkGreen
            }
            'CreateADObjects' {
                Write-Host "AD 'Just-in-Time' structure successfully created!" -ForegroundColor Yellow -BackgroundColor DarkGreen
            }
            'ExtendSchema' {
                Write-Host "Schema successfully update for 'Just-in-Time' Administration!" -ForegroundColor Yellow -BackgroundColor DarkGreen
            }
            'Uninstall' {
                Write-Host "'Just-in-Time' Administration successfully removed!" -ForegroundColor Yellow -BackgroundColor DarkGreen
            }
            'FullInstall' {
                Set-ItemProperty -Path $DefaultSetupRegPath -Name "SetupStatus" -Value 1004 | Out-Null
                Write-Host "Installation of 'Just-in-Time' Administration succeeded!" -ForegroundColor Yellow -BackgroundColor DarkGreen
                Write-Host "Please run '$($JitProgramFolder)\Config-jit.ps1' to start using JiT!" -ForegroundColor Magenta
                cd $JitProgramFolder
            }
        }
        
    }

}