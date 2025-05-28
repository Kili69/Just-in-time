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
    This script install and configure the Tier 1 JIT solution 

.DESCRIPTION
    The installation script copies the required scripts to the script directory, create the 
    group managed service account and register the required schedule tasks

.EXAMPLE
    .\config-T1jit.ps1

.OUTPUTS
   none
.NOTES
    Version Tracking
    2021-10-12 
    Version 0.1
        - First internal release
    Version 0.1.2021294
        - Default installation directory changed from c:\Program Files\windowsPowershell\script to %working directory%
        - New parameter ServerEnumerationTime added. Time for scheduled task to evaluate the existing servers
    Version 0.1.20230612
        - Source code documentation
    Version 0.1.20231029
        - Add a the new parameter DelegationConfigFilePath to the configuration file
        - Existing configuration files will be updated the latest version
    Version 0.1.20231109
        - New parameter to enable of disable the delegation model
    Version 0.1.20231130
        - better validation of input paramters
        - Support of spaces in Tier 0 computer OU
        - Terminate script if the current configuration file is created with a newe config-jit.ps1 script
        - Set full control to the Tier 1 computer Group OU
    Version 0.1.20231201
        - New parameter in config file LDAPT1computers
            This parameter contains the LDAP query to select Tier 1 computers
            This parameter is required in Tier1LocalAdminGroup.ps1
        - Support of WhatIf and Confirm parameters
    Version 0.1.20231204
        - Bug Fix in LDAP query to evaluate the T0 Computer OU
        - The domain separator can be configured in the JIT.config
    Version 0.1.20240116
        - Bug fix creating OU structure
        - Bug fix creating schedule task
    Version 0.1.20240202
        - Bug fix ACL for GMSA
    Version 0.1.20240205
        - Terminate the configuration script, if the AD PAM feature is not enabled
    Version 0.1.20240213
        - by Andreas Luy
        - corrected several inconsistency issues with existing config file
        - simplified/corrected OU creation function 
        - integrated updating delegationconfig location
        - group validation corrected
        - ToDo: use custom form for input
    Version 0.1.20240722
        - bug fixing
    Version 0.1.20240731
        - New Parameter advancedsetup
            The LDAP configuration string will only be visible if this switch is available
        - New Environment variable
            A global environment variable will created to determnine the configuration file. This environment variable will 
            be used in the request and elevate script to read a central configuration without using the config parameter
        - removed all parameters except InstallationDirectory and AdvancedSetup
        - new switch parameter -silent
            This parameter installs the GMSA on the local computer, create the Windows Eventlog and the schedule task
            This parameter can be used if the solution run on multiple servers. this parameter required the JIT.config file 
            JIT.CONFIG can be availabel through
                - Environment variable
                - configurationFile parameter
                - local jit.config
        - Schedule task to elevate users run in paralell 
            The userelevate schedule task run in paralell if multiple request events send to the event log
     Version 0.1.20240801
        - Updated dialog messages
    Version 0.1.20241004
        -New configuration option to use the ManagedBy attribute added to the config
        -New configuration option max concurrent servers
    Version 0.1.20241013
        -Terminate script if it is not running as local administrator
   Version 0.1.20241227
        - by Andreas Luy
	- corrected minor bugs
   Version 0.1.20250107
        - by Andreas Luy
    - added (OperatingSystem=*Server*) to T1ldapfilter
 

.PARAMETER InstallationDirectory
    Installation directory
.PARAMETER NewCnfgObjName
    Intended to create additional Jit configuration objects, so that different 
    JiT configurations can be used by different admin groups
    NOT YET IMPLEMENTED
.PARAMETER UpdateConfig
    To change initial JiT configuration
    THE FOLLOWING ITEMS CANNOT BE CHANGED 
    due to dependencies of sharing the configuration between multiple servers:
    - Multi-domain support
    - JiT-GROUP NAMING
    - JiT-Group OU
    - Default domain for JiT server
    - gMSA 
    - JiT Eventlog
    - JiT Elevation EventID
    - Scheduled Tasks settings
.PARAMETER AddServer
    To to add an additional server acting as JiT admin server
    Multiple servers will share one JiT configuration
    NOT YET IMPLEMENTED

#>

[CmdletBinding(DefaultParameterSetName = "FullConfig",SupportsShouldProcess)]
param (
    [Parameter (Mandatory=$false,
        ParameterSetName = "FullConfig")]
    [string]$CnfgObjName,

    [Parameter (Mandatory=$false,
        ParameterSetName = "NewConfig")]
    [string]$NewCnfgObjName,

    [Parameter (Mandatory=$false,
        ParameterSetName = "UpdateConfig")]
    [switch]$UpdateConfig,

    [Parameter (Mandatory=$false,
        ParameterSetName = "AddServer")]
    [switch]$AddServer
)

begin {

    $exit = $false
    $success = $true

    [string]$_scriptVersion = "20250130" #the current script version


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
        Write-Host "Aborting!" -ForegroundColor Yellow
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

    #region prepare variables
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
    if (!(Get-Variable STGroupManagementTaskName -Scope Global -ErrorAction SilentlyContinue)) {
        Set-Variable -name STGroupManagementTaskName -value "Tier 1 Local Group Management" -Scope Script -Option ReadOnly #Name of the Schedule tasl to enumerate servers
    }
    if (!(Get-Variable StGroupManagementTaskPath -Scope Global -ErrorAction SilentlyContinue)) {
        Set-Variable -name StGroupManagementTaskPath -value "\Just-In-Time-Privilege" -Scope Script -Option ReadOnly #Is the schedule task folder
    }
    if (!(Get-Variable STElevateUser -Scope Global -ErrorAction SilentlyContinue)) {
        Set-Variable -name STElevateUser -value "Elevate User" -Scope Script -Option ReadOnly #Is the name of the Schedule task to elevate users
    }
    if (!(Get-Variable config -Scope Global -ErrorAction SilentlyContinue)) {
        #Set-Variable -name config -value (Get-JITconfig) -Scope Global -Option AllScope
        Set-Variable -name config -Scope Global -Option AllScope
    }
    if (!(Get-Variable DefaultJitProgramFolder -Scope Global -ErrorAction SilentlyContinue)) {
        Set-Variable -name DefaultJitProgramFolder -value ($env:ProgramFiles +"\Just-In-Time") -Scope Global -Option ReadOnly
    }
    if (!(Get-Variable DefaultSetupRegPath -Scope Global -ErrorAction SilentlyContinue)) {
        Set-Variable -name DefaultSetupRegPath -value ("HKLM:\SOFTWARE\Just-In-Time-Administration") -Scope Global -Option ReadOnly
    }

    #define standart configuration items as unconfirmed
    #define advanced configuration items as confirmed
    #this way user only need to care about required configuration
    #but could modify advanced default values as well
    [bool]$CnfgObjSchemaExtDone = $false
    [bool]$CnfgObjADStructureDone = $false
    [bool]$CnfgObjJitAdmGroupOUDone = $false
    [bool]$CnfgObjAdminPreFixDone = $false
    
    #if single domain forest, there is nothing to configure in regards to domain naming & multidomain support
    [bool]$CnfgObjDomainDone = $false
    [bool]$CnfgObjEnableMultiDomainSupportDone = $false
    if (((Get-ADForest).Domains).count -eq 1) {
        [bool]$CnfgObjDomainDone = $true
        [bool]$CnfgObjEnableMultiDomainSupportDone = $true
    }
    [bool]$CnfgObjTier0ServerGroupNameDone = $false
    [bool]$CnfgObjLDAPT1ComputersDone = $true
    [bool]$CnfgObjT1SearchbaseDone = $false
    [bool]$CnfgObjMaxElevatedTimeDone = $false
    [bool]$CnfgObjDefaultElevatedTimeDone = $false
    [bool]$CnfgObjMaxConcurrentServerDone = $false
    [bool]$CnfgObjGroupManagedServiceAccountNameDone = $false
    [bool]$CnfgObjTaskRunIntervalDone = $false
    [bool]$CnfgObjTaskScriptSourceDone = $false
    [bool]$CnfgObjEventLogDone = $true
    [bool]$CnfgObjEventSourceDone = $true
    [bool]$CnfgObjElevateEventIDDone = $true
    [bool]$CnfgObjRequestOnBehalfOfDone = $false
    [bool]$CnfgObjEnableDelegation = $false
    [bool]$CnfgObjDoneDomainSeparatorDone = $true
    #[bool]$CnfgObjUseManagedByforDelegationDone = $false
    #[bool]$CnfgObjDelegationConfigPathDone = $false
    [bool]$JiTCnfgDone = $false
    #endregion

    #registry values defined
    # SetupStatus
    # only set with 'FullInstall' and 'AddServer'
    # 1000 - no installation yet
    # 1001 - files copied
    # 1002 - AD schema extantions done
    # 1003 - AD structure done
    # 1004 - Server authorized - JiT installed

    # ConfigStatus
    # 2000 - no configuration yet
    # 2001 - config written to AD
    # 2002 - configuring new Server
    # 2003 - updating JiT
    # 2004 - Jit Configured

    #region Functions

    function Set-JitCnfgArrayValue
    {
	    Param (
            [Parameter(Mandatory=$true)]$Value,
		    [Parameter(Mandatory=$false)][String]$title,
		    [Parameter(Mandatory=$true)][String]$Msg,
		    [Parameter(Mandatory=$false)][Int]$Threshold = 0,
		    [Parameter(Mandatory=$false)][switch]$ValueMustDN
        )
	
        $Ret = ""
        $tmpValue = $Value
        do{
            $Result = ""
            Write-Host $title -ForegroundColor Cyan
            Write-Host $Msg -ForegroundColor Cyan
            Write-Host "-------------------------------"
            Write-Host "Add new entry" -ForegroundColor Yellow
            Write-Host "('number' delete entry|'e' empty list|'x' finish)" -ForegroundColor Yellow
            Write-Host 

            for ($i=0; $i -lt $tmpValue.count; $i++) {
                Write-Host "$([string]($i+1)).", $tmpValue[$i]
            }
            $Result = Read-Host
            
            switch ($Result.ToLower()) {
                "" {
                    #return entered - do nothing - we don't have a default now...
                }
                "x" {
                    if ($tmpValue.count -gt 1) {
                        #removing possible space holders
                        $Value = $tmpValue | Where-Object {($_ -ne "<DomainRoot>") -or ($_ -ne "<EMPTY>")}
                    } elseif ($tmpValue.count -eq 1) {
                        $Value = $tmpValue
                    }
                }
                "e" {
                    # empty list
                    $tmpValue = @()
                }
                #is numeric? all digits?
                {$Result.ToLower() -match "^[\d\.]+$"} {
                    #is value in valid range?
                    if ([int]$Result -in 1..($tmpValue.count+1)) {
                        #ok, lets remove selected entry from list
                        $tmp = @()
                        for ($i=0; $i -lt $tmpValue.count; $i++) {
                            if (([int]$Result-1) -ne $i) {
                                $tmp += $tmpValue[$i]
                            }
                        }
                        $tmpValue = $tmp
                        $tmp = $null
                    }
                }
                default {
                    if ($ValueMustDN) {
                        if (IsDNFormat -DNString $Result) {
                            if ($tmpValue -contains $Result){
                                Write-Host "$($Result) is already in list..." -ForegroundColor Yellow
                            } else {
                                $tmpValue += $Result
                            }
                        } else {
                            Write-Host "Invalid entry ..." -ForegroundColor Red
                        }
                    } else {
                        $tmpValue += $Result
                    }
                }
            }

        } while ($Result.ToLower() -ne "x") 
            
        $Ret = $Value
        return $Ret
    }
    
    function Set-JitCnfgValue
    {
	    Param (
            [Parameter(Mandatory=$true)]$Value,
		    [Parameter(Mandatory=$false)][String]$title,
		    [Parameter(Mandatory=$true)][String]$Msg,
		    [Parameter(Mandatory=$false)][Int]$Threshold = 0,
		    [Parameter(Mandatory=$false)][switch]$ValueMustDN,
		    [Parameter(Mandatory=$false)][switch]$ValueIsInt
        )
	
        $Result = ""
        $tmpValue = $Value
        do{
            Write-Host $Msg -ForegroundColor Cyan
            $Result = Read-Host -Prompt ("('x' to cancel) [$([string]$Value)]")
            if ($Result.ToLower() -ne "x") {
                if ($Result -eq ""){ 
                    $Result = $Value
                }
                if ($Threshold -gt 0) {
                    if ($ValueIsInt) {
                        if ([int]$Result -gt $Threshold) {
                            Write-Host "Invalid entry"
                            Start-Sleep 2
                            $Result = "x"
                        }
                    } else {
                        if ($Result.Length -gt $Threshold) {
                            Write-Host "Input value must not exceed $([string]$Threshold) characters..."
                            Start-Sleep 2
                            $Result = "x"
                        }
                    }
                }
            }
        } until (($Result -eq "x") -or ($Result -ne ""))
        return $Result
    }


    function ConfigurationMenu 
    {
	    Param (
		    [Parameter(Mandatory=$false)][switch]$UpdateOnly
        )

        #region new window size
        if ($host.name -eq 'ConsoleHost') {
            try {
                $pshost = get-host
                $pswindow = $pshost.ui.rawui
                $newsize = $pswindow.buffersize
                $newsize.height = 32
                $newsize.width = 140
                $pswindow.buffersize = $newsize
                $newsize = $pswindow.windowsize
                $newsize.height = 32
                $newsize.width = 90
                $pswindow.windowsize = $newsize
            } catch {
                #issues with resizing...
                #anyway no need to do something
            }
            $pswindow.windowtitle = "Just-in-Time Configuration"
            $pswindow.foregroundcolor = "White"
            $pswindow.backgroundcolor = "Black"
        }
        #endregion

        $ret = "Success"
        $exit = $false

    # Start the menu loop
        while (!$exit) {
            Clear-Host  # Clear the console to keep it clean
            Write-Host "============ Just-in-Time Configuration Menu ============"
            Write-Host " 1." -NoNewline; Write-Host " JiT schema extention                       --> " -NoNewline -ForegroundColor Yellow; Write-Host ($(if($CnfgObjSchemaExtDone){"done"}else{"open"})) -ForegroundColor $(if($CnfgObjSchemaExtDone){"Green"}else{"Red"})
            Write-Host " 2." -NoNewline; Write-Host " JiT AD structure                           --> " -NoNewline -ForegroundColor Yellow; Write-Host ($(if($CnfgObjADStructureDone){"done"}else{"open"})) -ForegroundColor $(if($CnfgObjADStructureDone){"Green"}else{"Red"})
            Write-Host " 3." -NoNewline; Write-Host " Enable/disable multi-domain support        --> " -NoNewline -ForegroundColor $(if($UpdateOnly){"Gray"}else{"Yellow"}); Write-Host ($(if($CnfgObjEnableMultiDomainSupportDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjEnableMultiDomainSupportDone){"Green"}else{"Red"}); if($CnfgObjEnableMultiDomainSupportDone){Write-Host "--> $($global:config.EnableMultiDomainSupport)"}else{Write-Host ""}
            Write-Host " 4." -NoNewline; Write-Host " Define OU for JiT admin groups             --> " -NoNewline -ForegroundColor $(if($UpdateOnly){"Gray"}else{"Yellow"}); Write-Host ($(if($CnfgObjJitAdmGroupOUDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjJitAdmGroupOUDone){"Green"}else{"Red"}); if($CnfgObjJitAdmGroupOUDone){Write-Host "--> $($global:config.OU)"}else{Write-Host ""}
            Write-Host " 5." -NoNewline; Write-Host " Define prefix for JiT-groups               --> " -NoNewline -ForegroundColor $(if($UpdateOnly){"Gray"}else{"Yellow"}); Write-Host ($(if($CnfgObjAdminPreFixDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjAdminPreFixDone){"Green"}else{"Red"}); if($CnfgObjAdminPreFixDone){Write-Host "--> $($global:config.AdminPreFix)"}else{Write-Host ""}
            Write-Host " 6." -NoNewline; Write-Host " Set default domain for JiT mgmt servers    --> " -NoNewline -ForegroundColor $(if($UpdateOnly){"Gray"}else{"Yellow"}); Write-Host ($(if($CnfgObjDomainDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjDomainDone){"Green"}else{"Red"}); if($CnfgObjDomainDone){Write-Host "--> $($global:config.Domain)"}else{Write-Host ""}
            Write-Host " 7." -NoNewline; Write-Host " Set Name(s) of Tier0 computer group(s)`r`n    -> multiple Tier0 groups are allowed       --> " -NoNewline -ForegroundColor Yellow; Write-Host ($(if($CnfgObjTier0ServerGroupNameDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjTier0ServerGroupNameDone){"Green"}else{"Red"}); if($CnfgObjTier0ServerGroupNameDone){Write-Host "--> $($global:config.Tier0ServerGroupName)" -Separator ";"}else{Write-Host ""}
            Write-Host " 8." -NoNewline; Write-Host " Define LDAP filters to Tier1 systems       --> " -NoNewline -ForegroundColor Yellow; Write-Host ($(if($CnfgObjLDAPT1ComputersDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjLDAPT1ComputersDone){"Green"}else{"Red"}); if($CnfgObjLDAPT1ComputersDone){Write-Host "--> $($global:config.LDAPT1Computers)"}else{Write-Host ""}
            Write-Host " 9." -NoNewline; Write-Host " Set Tier1 computers OUs (optional)-if not`r`n    specified, whole domain will be searched   --> " -NoNewline -ForegroundColor Yellow; Write-Host ($(if($CnfgObjT1SearchbaseDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjT1SearchbaseDone){"Green"}else{"Red"}); if($CnfgObjT1SearchbaseDone){Write-Host "--> $($global:config.T1Searchbase)" -Separator ";"}else{Write-Host ""}
            Write-Host "10." -NoNewline; Write-Host " Set Max elevation time allowed for JiT     --> " -NoNewline -ForegroundColor Yellow; Write-Host ($(if($CnfgObjMaxElevatedTimeDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjMaxElevatedTimeDone){"Green"}else{"Red"}); if($CnfgObjMaxElevatedTimeDone){Write-Host "--> $($global:config.MaxElevatedTime.ToString())"}else{Write-Host ""}
            Write-Host "11." -NoNewline; Write-Host " Set default elevation time used by JiT     --> " -NoNewline -ForegroundColor Yellow; Write-Host ($(if($CnfgObjDefaultElevatedTimeDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjDefaultElevatedTimeDone){"Green"}else{"Red"}); if($CnfgObjDefaultElevatedTimeDone){Write-Host "--> $($global:config.DefaultElevatedTime.ToString())"}else{Write-Host ""}
            Write-Host "12." -NoNewline; Write-Host " Set max. number of systems where users`r`n    can be elevated in parallel                --> " -NoNewline -ForegroundColor Yellow; Write-Host ($(if($CnfgObjMaxConcurrentServerDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjMaxConcurrentServerDone){"Green"}else{"Red"}); if($CnfgObjMaxConcurrentServerDone){Write-Host "--> $($global:config.MaxConcurrentServer.ToString())"}else{Write-Host ""}
            Write-Host "13." -NoNewline; Write-Host " Define name of gMSA running JiT tasks      --> " -NoNewline -ForegroundColor $(if($UpdateOnly){"Gray"}else{"Yellow"}); Write-Host ($(if($CnfgObjGroupManagedServiceAccountNameDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjGroupManagedServiceAccountNameDone){"Green"}else{"Red"}); if($CnfgObjGroupManagedServiceAccountNameDone){Write-Host "--> $($global:config.GroupManagedServiceAccountName)"}else{Write-Host ""}
            Write-Host "14." -NoNewline; Write-Host " Define task run interval (minutes)         --> " -NoNewline -ForegroundColor $(if($UpdateOnly){"Gray"}else{"Yellow"}); Write-Host ($(if($CnfgObjTaskRunIntervalDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjTaskRunIntervalDone){"Green"}else{"Red"}); if($CnfgObjTaskRunIntervalDone){Write-Host "--> $($global:config.TaskRunInterval)"}else{Write-Host ""}
            Write-Host "15." -NoNewline; Write-Host " Define central task script directory       --> " -NoNewline -ForegroundColor Yellow; Write-Host ($(if($CnfgObjTaskScriptSourceDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjTaskScriptSourceDone){"Green"}else{"Red"}); if($CnfgObjTaskScriptSourceDone){Write-Host "--> $($global:config.TaskScriptSource)"}else{Write-Host ""}
            Write-Host "16." -NoNewline; Write-Host " Define Just-in Time event log              --> " -NoNewline -ForegroundColor $(if($UpdateOnly){"Gray"}else{"Yellow"}); Write-Host ($(if($CnfgObjEventLogDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjEventLogDone){"Green"}else{"Red"}); if($CnfgObjEventLogDone){Write-Host "--> $($global:config.EventLog)"}else{Write-Host ""}
            Write-Host "17." -NoNewline; Write-Host " Define Just-in Time event source           --> " -NoNewline -ForegroundColor Yellow; Write-Host ($(if($CnfgObjEventSourceDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjEventSourceDone){"Green"}else{"Red"}); if($CnfgObjEventSourceDone){Write-Host "--> $($global:config.EventSource)"}else{Write-Host ""}
            Write-Host "18." -NoNewline; Write-Host " Set JiT elevation event ID                 --> " -NoNewline -ForegroundColor $(if($UpdateOnly){"Gray"}else{"Yellow"}); Write-Host ($(if($CnfgObjElevateEventIDDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjElevateEventIDDone){"Green"}else{"Red"}); if($CnfgObjElevateEventIDDone){Write-Host "--> $($global:config.ElevateEventID.ToString())"}else{Write-Host ""}
            Write-Host "19." -NoNewline; Write-Host " Set AD Principals allowed to request on`r`n    behalf of other identities                 --> " -NoNewline -ForegroundColor Yellow; Write-Host ($(if($CnfgObjRequestOnBehalfOfDone){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjRequestOnBehalfOfDone){"Green"}else{"Red"}); if($CnfgObjRequestOnBehalfOfDone){Write-Host "--> $($global:config.RequestOnBehalfOf)" -Separator ";"}else{Write-Host ""}
            Write-Host "20." -NoNewline; Write-Host " Enable/disable delegation mode             --> " -NoNewline -ForegroundColor Yellow; Write-Host ($(if($CnfgObjEnableDelegation){"done"}else{"open"})) -NoNewline -ForegroundColor $(if($CnfgObjEnableDelegation){"Green"}else{"Red"}); if($CnfgObjEnableDelegation){Write-Host "--> $($global:config.EnableDelegation)"}else{Write-Host ""}
            Write-Host "21." -NoNewline; Write-Host " Start configuration                        --> " -NoNewline -ForegroundColor Magenta; Write-Host ($(if($JiTCnfgDone){"done"}else{"open"})) -ForegroundColor $(if($JiTCnfgDone){"Green"}else{"Red"})
            Write-Host " 0." -NoNewline; Write-Host " Exit configuration" -ForegroundColor Magenta
            Write-Host "---------------------------------------------------------------------"
            Write-Host

            $result = ""
            try{
                [int]$choice = Read-Host "Select an configuration item (0-21)"
            } catch {
                $choice = 30
            }

            #only proceed if schema extension and AD structure exists
            if (($CnfgObjSchemaExtDone -and $CnfgObjADStructureDone) -or (($choice -lt 3))) {
     
                # Validate input
                switch ($choice) {
                    0 {
                        $ret = "Exit"
                        $exit = $true
                        break
                    }
                    1 { # JiT schema extention
                        # needs to be done by installation script
                        if (!$CnfgObjSchemaExtDone) {
                            Write-Host "To extend the AD schema for JiT, please run: "
                            Write-Host "install-JiT.ps1 -ExtendSchema " -ForegroundColor Magenta
                        } else {
                            Write-Host "AD schema already extended for JiT!"
                        }
                        Start-Sleep 2
                    }
                    2 { # JiT AD structure
                        # needs to be done by installation script
                        if (!$CnfgObjADStructureDone) {
                            Write-Host "To create JiT AD structure, please run: "
                            Write-Host "install-JiT.ps1 -createAdStructure " -ForegroundColor Magenta
                        } else {
                            Write-Host "JiT AD structure already created!"
                        }
                        Start-Sleep 2
                    }
                    3 {
                        if (!$UpdateOnly) {
                            $global:config.EnableMultiDomainSupport = if ((Read-YesNoAnswer -Title "Enable/disable multi-domain support" -Message "Do you want to enable multi-domain support?") -eq 1) {$true}else{$false}
                            $CnfgObjEnableMultiDomainSupportDone = $true
                            if (!($global:config.EnableMultiDomainSupport)) {
                                $global:config.Domain = [string]$ComputerDomainFQDN
                                $CnfgObjDomainDone = $true
                            }
                        }
                    }
                    4 {
                        if (!$UpdateOnly) {
                            #default value should reflect JiT mgmt server domain location
                            $OUFQDN = Get-DomainDNSfromDN -AdObjectDN $global:config.OU
                            if (!($OUFQDN -eq $ComputerDomainFQDN)) {
                                #Get-DNfromDNS -FQDN $ComputerDomainFQDN
                                $global:config.OU = (($global:config.OU).substring(0,($global:config.OU).tolower().IndexOf('dc=')) + (Get-DNfromDNS -FQDN $ComputerDomainFQDN))
                            }
                            $result = Set-JitCnfgValue -Value $global:config.OU -Msg "Define OU for JiT admin groups" -ValueMustDN
                            if ($result.toLower() -ne "x") {
                                if (IsDNFormat -DNString $result) {
                                    $global:config.OU = $result
                                    $CnfgObjJitAdmGroupOUDone = $true
                                } else {
                                    Write-Host "Invalid DN for T1 Admin Group OU"
                                }
                            }
                        }
                    }
                    5 {
                        if (!$UpdateOnly) {
                            $result = Set-JitCnfgValue -Value $global:config.AdminPreFix -Msg "Define prefix for JiT-groups"
                            if ($result.toLower() -ne "x") {
                                $global:config.AdminPreFix = $result
                                $CnfgObjAdminPreFixDone = $true
                            }
                        }
                    }
                    6 {
                        if (!$UpdateOnly) {
                            $result = Set-JitCnfgValue -Value $global:config.Domain -Msg "Set default domain (FQDN) for JiT management servers"
                            if ($result.toLower() -ne "x") {
                                $global:config.Domain = $result
                                $CnfgObjDomainDone = $true
                            }
                        }
                    }
                    7 {
                        $result = Set-JitCnfgArrayValue -Value $global:config.Tier0ServerGroupName -Msg "Set Name of Tier0 computer group(s).`n`r(For group names from other domains, full DN must be used!)"
                        $tmp = @()
                        foreach ($group in $result) {
                            if (IsDNFormat -DNString $group) {
                                $tdom = Get-DomainDNSfromDN -AdObjectDN $group
                            } else {
                                $tdom = (Get-ADDomain).DNSRoot
                            }
                            Try {
                                $tGroup = Get-ADGroup -Identity $group -Server $tdom
                                $tmp += $tGroup.DistinguishedName
                            } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                                Write-Host "$($tGroup) is not a valid AD group" -ForegroundColor Red 
                                Write-Host "Please enter either group's SamAccountName or DistinguishedName" -ForegroundColor Red 
                                Write-Host "skipping ..." -ForegroundColor Yellow
                                Start-Sleep 2
                            } 
                            catch {
                                Write-Host "unexpected error!" -ForegroundColor Red
                                Write-Host $Error[0]
                                Write-Host "skipping ..." -ForegroundColor Yellow
                                Start-Sleep 2
                            }
                            $tGroup = ""
                            $tdom = ""
                        }
                        #do we have valid entries in the list?
                        if ($tmp.count -gt 0) {
                            $global:config.Tier0ServerGroupName = $tmp
                            $CnfgObjTier0ServerGroupNameDone = $true
                            $tmp = $null
                        }
                    }
                    8 {
                        $result = Set-JitCnfgValue -Value $global:config.LDAPT1Computers -Msg "Define LDAP filter for Tier 1 systems"
                        if ($result.toLower() -ne "x") {
                            $global:config.LDAPT1Computers = $result
                            $CnfgObjLDAPT1ComputersDone = $true
                        }
                    }
                    9 {
                        $result = Set-JitCnfgArrayValue -Value $global:config.T1Searchbase -Msg "Define searchbases (OUs) for Tier 1 systems" -ValueMustDN
                        if ($result.toLower() -ne "x") {
                            $global:config.T1Searchbase = $result
                            $CnfgObjT1SearchbaseDone = $true
                        }
                    }
                    10 {
                        $result = Set-JitCnfgValue -Value $global:config.MaxElevatedTime -Msg "Set Max elevation time allowed for JiT" -Threshold 1440 -ValueIsInt
                        #string-based result must be 'x'
                        if ($result.GetType() -ne "String") {
                            $global:config.MaxElevatedTime = [int]$result
                            $CnfgObjMaxElevatedTimeDone = $true
                        }
                    }
                    11 {
                        $result = Set-JitCnfgValue -Value $global:config.DefaultElevatedTime -Msg "Set default elevation time used by JiT" -Threshold $global:config.MaxElevatedTime -ValueIsInt
                        #string-based result must be 'x'
                        if ($result.GetType() -ne "String") {
                            $global:config.DefaultElevatedTime = [int]$result
                            $CnfgObjDefaultElevatedTimeDone  = $true
                        }
                    }
                    12 {
                        $result = Set-JitCnfgValue -Value $global:config.MaxConcurrentServer -Msg "Set max. number of systems where users`r`ncan be elevated in parallel" -ValueIsInt
                        #string-based result must be 'x'
                        if ($result.GetType() -ne "String") {
                            $global:config.MaxConcurrentServer = [int]$result
                            $CnfgObjMaxConcurrentServerDone = $true
                        }
                    }
                    13 {
                        if (!$UpdateOnly) {
                            $result = Set-JitCnfgValue -Value $global:config.GroupManagedServiceAccountName -Msg "Define name of gMSA running JiT tasks" -Threshold 14
                            if ($result.toLower() -ne "x") {
                                $global:config.GroupManagedServiceAccountName = $result
                                $CnfgObjGroupManagedServiceAccountNameDone = $true
                            }
                        }
                    }
                    14 {
                        if (!$UpdateOnly) {
                            $result = Set-JitCnfgValue -Value $global:config.TaskRunInterval -Msg "Define task run interval (minutes)" -Threshold 240 -ValueIsInt
                            #string-based result must be 'x'
                            if ($result.GetType() -ne "String") {
                                $global:config.TaskRunInterval = [int]$result
                                $CnfgObjTaskRunIntervalDone = $true
                            }
                        }
                    }
                    15 {
                        $result = Set-JitCnfgValue -Value $global:config.TaskScriptSource -Msg "Define a central script source for Just-in Time task scripts"
                        if ($result.toLower() -ne "x") {
                            $global:config.TaskScriptSource = $result
                            $CnfgObjTaskScriptSourceDone = $true
                        }
                    }
                    16 {
                        if (!$UpdateOnly) {
                            $result = Set-JitCnfgValue -Value $global:config.EventLog -Msg "Define Just-in Time event log"
                            if ($result.toLower() -ne "x") {
                                $global:config.EventLog = $result
                                $CnfgObjEventLogDone = $true
                            }
                        }
                    }
                    17 {
                        $result = Set-JitCnfgValue -Value $global:config.EventSource -Msg "Define Just-in Time event source"
                        if ($result.toLower() -ne "x") {
                            $global:config.EventSource = $result
                            $CnfgObjEventSourceDone = $true
                        }
                    }
                    18 {
                        if (!$UpdateOnly) {
                            $result = Set-JitCnfgValue -Value $global:config.ElevateEventID -Msg "Set JiT elevation event ID" -ValueIsInt
                            #string-based result must be 'x'
                            if ($result.GetType() -ne "String") {
                                $global:config.ElevateEventID = [int]$result
                                $CnfgObjElevateEventIDDone = $true
                            }
                        }
                    }
                    19 {
                        $result = Set-JitCnfgArrayValue -Value @("<EMPTY>") -Msg "Set principals allowed to request elevation on behalf of other identities.`n`r(For principals from other domains, full DN must be used!)"
                        #$result = Set-JitCnfgArrayValue -Value $global:config.RequestOnBehalfOf -Msg "Set principals allowed to request elevation on behalf of other identities.`n`r(For principals from other domains, full DN must be used!)"
                        $tmp = @()
                        foreach ($Principal in $result) {
                            Try {
                                if (IsDNFormat -DNString $Principal) {
                                    $tdom = Get-DomainDNSfromDN -AdObjectDN $Principal
                                    $tPrinc = Get-ADObject -Identity $result -Properties ObjectSid -Server $tdom
                                } else {
                                    $tdom = (Get-ADDomain).DNSRoot
                                    $tPrinc = Get-ADObject -filter {(samaccountname -eq $result) -or (name -eq $result)} -Properties objectsid -Server $tdom
                                }
                                if ($tPrinc){
                                    $tmp += $tPrinc.objectsid
                                }
                            } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                                Write-Host "$($tPrinc) is not a valid AD principal" -ForegroundColor Red 
                                Write-Host "Please enter either SamAccountName or DistinguishedName" -ForegroundColor Red 
                                Write-Host "skipping ..." -ForegroundColor Yellow
                                Start-Sleep 2
                            } 
                            catch {
                                Write-Host "unexpected error!" -ForegroundColor Red
                                Write-Host $Error[0]
                                Write-Host "skipping ..." -ForegroundColor Yellow
                                Start-Sleep 2
                            }
                            $tPrinc = ""
                            $tdom = ""
                        }
                        #do we have valid entries in the list?
                        if ($tmp.count -gt 0) {
                            $global:config.RequestOnBehalfOf = $tmp
                            $CnfgObjRequestOnBehalfOfDone = $true
                            $tmp = $null
                        }
                    }
                    20 {
                        $global:config.EnableDelegation = if ((Read-YesNoAnswer -Title "Enable/disable delegation mode" -Message "Do you want to enable delegation mode?") -eq 1) {$true}else{$false}
                        $CnfgObjEnableDelegation = $true
                    }
                    21 {
                        $exit = $true
                        break
                    }
                    default {
                        Write-Host "Invalid input - please try again..."
                        Start-Sleep -Seconds 2  # Pause for 2 seconds to display the message
                    }
                }
            } else {
                Write-Host "JIT pre-requisites missing!"
                Write-Host "Before continuing, please run: "
                if (!$CnfgObjSchemaExtDone){
                    Write-Host "install-JiT.ps1 -ExtendSchema" -ForegroundColor Magenta
                }
                if (!$CnfgObjADStructureDone) {
                    Write-Host "install-JiT.ps1 -createAdStructure" -ForegroundColor Magenta
                }
                Start-Sleep 2
            }
        }
        return $ret
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
        $DomainDNS = (($AdObjectDN.tolower()).substring($AdObjectDN.tolower().IndexOf('dc=')+3).replace(',dc=','.'))
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

    function Move-CentralTaskScripts
    {
        #assuming all goes well
        $ret = $true

        $TargetDir = $global:config.TaskScriptSource
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

    function Configure-JiT
    {
        $success = $true
        #JiT gMSA task account
        $success = (create-gMSA -Name $global:config.GroupManagedServiceAccountName -Domain $global:config.Domain)
        if(!$success) {
            Write-Host "Creating gMSA $($global:config.GroupManagedServiceAccountName) failed!" -ForegroundColor Red
        } else {
            $objGmsa = Get-ADServiceAccount -Identity $global:config.GroupManagedServiceAccountName -Server ([string]$global:config.Domain)
            $success = Add-LogonAsABatchJobPrivilege -Sid $objGmsa.sid
            if (!$success) {
                Write-Host "Granting gMSA $($global:config.GroupManagedServiceAccountName) LogonAsBatchJob privileges failed!" -ForegroundColor Red
            } else {
                #grant gMSA permissions on Tier 1 JiT Mgmt group OU
                $success = Configure-JiTGroupOU -DefaultOUName $global:config.OU -objgMSA $objGmsa
                if (!$success){
                    Write-Host "Could not create T1 JiT OU for admin groups: $($global:config.OU)!" -ForegroundColor Red
                }
            }
        }

        #Jit event log
        if (!(create-Eventlog)) {
            Write-Host "Creating eventlog or event source failed!" -ForegroundColor Red
            $success = $false
        }

        #Jit scheduled tasks
        if (!(create-ScheduledTasks)) {
            Write-Host "Tier 1 scheduled tasks could not be created!" -ForegroundColor Red
            $success = $false
        }

        if (!(Move-CentralTaskScripts)) {
            Write-Host "Task scripts could not be moved to central location!" -ForegroundColor Red
            $success = $false
        }

        if ($success) {
            Write-EventLog -LogName $global:config.EventLog -Source $global:config.EventSource -EventId 1 -Message "JiT configuration completed"
        } else {
            Write-EventLog -LogName $global:config.EventLog -Source $global:config.EventSource -EventId 1 -Message "JiT configuration completed with errors - review the configuration and correct any issue before using JiT"
        }
        return $success
    }

    function create-Eventlog
    {
        #region create eventlog and register EventSource id required
        Write-Host "Reading Windows eventlogs please wait" -ForegroundColor Yellow
        if (!([System.Diagnostics.EventLog]::SourceExists($global:config.EventSource))) {
            Write-Host "Creating new Event log $($global:config.EventLog)"
            New-EventLog -LogName $global:config.EventLog -Source $global:config.EventSource
        } else {
            Write-Host "Eventlog '$($global:config.EventLog)' already exists, Checking for event source..." -ForegroundColor Yellow
            if (!([System.Diagnostics.EventLog]::SourceExists($global:config.EventSource))) {
                Write-Host "Creating new Event log $($global:config.EventSource)"
                New-EventLog -LogName $global:config.EventLog -Source $global:config.EventSource
            } else {
                Write-Host "Event source '$($global:config.EventSource)' already exists," -ForegroundColor Yellow
            }
        }
        #endregion
        return $true
    }

    function Read-gMSA
    {
        param (
            [Parameter(Mandatory=$True)] [string]$DefaultName
        )

        do{
            $gmsaName = Read-Host -Prompt "Group managed service account name [$($DefaultName)]"
            if ($gmsaName -eq ""){ 
                $gmsaName = $DefaultName
            }
            #validation GMSA name
            if (($gmsaName -lt 5) -or ($gmsaName.Length -gt 14) ){
                Write-Host "Invalid length of the GMSA name. The name must between 5 and 14 characters" -ForegroundColor Yellow
                $gmsaName = ""
            }
        } while ($gmsaName -eq "")
        return $gmsaName
    }

    function create-gMSA
    {
        param (
            [Parameter(Mandatory=$True)] [string]$Name,
            [Parameter(Mandatory=$True)] [string]$Domain
        )

        $ret = $true
        try {
            #create the group managed service account if not already exists. 
            if ($null -eq (Get-ADServiceAccount -Filter "Name -eq '$($Name)'" -Server $($Domain))){
                Write-Host "Creating gMSA $($Name) ..." -ForegroundColor Yellow
                New-ADServiceAccount -Name $Name -DisplayName $Name -DNSHostName "$($Name).$($Domain.ToLower())" -KerberosEncryptionType AES128, AES256 -Server $Domain
            } else {
                Write-Host "gMSA $($Name) already exists..." -ForegroundColor Yellow
            }
            $principalsAllowToRetrivePassword = (Get-ADServiceAccount -Identity $Name -Properties PrincipalsAllowedToRetrieveManagedPassword).PrincipalsAllowedToRetrieveManagedPassword
            if (($principalsAllowToRetrivePassword.Count -eq 0) -or ($principalsAllowToRetrivePassword.Value -notcontains (Get-ADComputer -Identity $env:COMPUTERNAME).DistinguishedName)){
                Write-Host "Adding current computer to the list of computer who will retrive the password" -ForegroundColor Yellow
                $principalsAllowToretrivePassword.Add((Get-ADComputer -Identity $env:COMPUTERNAME).DistinguishedName)
                Set-ADServiceAccount -Identity $Name -PrincipalsAllowedToRetrieveManagedPassword $principalsAllowToRetrivePassword -Server $Domain
            }
        } catch {
            if ( $Error[0].CategoryInfo.Activity -eq "New-ADServiceAccount"){
                Write-Host "gMSA coult not be created. Validate you have the correct privileges and the KDS rootkey exists" -ForegroundColor Red
                $ret = $false
            }
            Write-Host "A error occured while creating the gMSA or apply the current computer to the gMSA. Configuration stopped" -ForegroundColor Red
            Write-Host "Validate the gMSA exists and the computer has the privilege to retrive the gMSA password" -ForegroundColor Red
            $ret = $false
        }
        #install the group managed service account locally 
        $oGmsa = Get-ADServiceAccount -Identity $Name -Server $Domain
        if (!(Test-ADServiceAccount -Identity $Name )){
            #Test gMSA ...
            try {
                Install-ADServiceAccount -Identity $oGmsa
            } catch {
                Write-Host "Installation of the Group managed service account ($($Name)) failed." -ForegroundColor Red
                $ret = $false
            }
        }
        if ($ret) {
            if (!(Test-ADServiceAccount -Identity $Name)){
                Write-Host "validation of the Group managed service account ($($Name)) failed." -ForegroundColor Red
                $ret = $false
            }
        }
        return $ret
    }

    function create-ScheduledTasks
    {
        $ret = $true
        #folder of the schedule tasks
        $StGroupManagementTaskPath = "\Just-In-Time-Privilege" 
        #Name of the Schedule task to enumerate servers
        $STGroupManagementTaskName = "Tier 1 Local Group Management" 
        #name of the Schedule task to elevate users
        $STElevateUser = "Elevate User" 

        #region creating Scheduled Task Section
        Write-Host "creating schedule task to evaluate required Administrator groups" -ForegroundColor Yellow
        $STprincipal = New-ScheduledTaskPrincipal -UserId "$((Get-ADDomain).NetbiosName)\$((Get-ADServiceAccount $global:config.GroupManagedServiceAccountName).SamAccountName)" -LogonType Password
        If (!((Get-ScheduledTask).URI -contains "$StGroupManagementTaskPath\$STGroupManagementTaskName"))
        {
            try {
                $STaction  = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -file "' + $InstallationDirectory + '\Tier1LocalAdminGroup.ps1"') 
                $STTrigger = New-ScheduledTaskTrigger -AtStartup 
                $STTrigger.Repetition = $(New-ScheduledTaskTrigger -Once -at 7am -RepetitionInterval (New-TimeSpan -Minutes $($global:config.TaskRunInterval))).Repetition                      
                Register-ScheduledTask -Principal $STprincipal -TaskName $STGroupManagementTaskName -TaskPath $StGroupManagementTaskPath -Action $STaction -Trigger $STTrigger
                Start-ScheduledTask -TaskPath "$StGroupManagementTaskPath\" -TaskName $STGroupManagementTaskName
                If (!((Get-ScheduledTask).URI -contains "$StGroupManagementTaskPath\$STElevateUser"))
                {
                    # create s schedule task who is triggered by eventlog entry in the event Log Tier 1 Management
                    $STaction = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -file "' + $InstallationDirectory + '\ElevateUser.ps1" -eventRecordID $(eventRecordID)') -WorkingDirectory $InstallationDirectory
                    $CIMTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskEventTrigger
                    $Trigger = New-CimInstance -CimClass $CIMTriggerClass -ClientOnly
                    $Trigger.Subscription = "<QueryList><Query Id=""0"" Path=""$($global:config.EventLog)""><Select Path=""$($global:config.EventLog)"">*[System[Provider[@Name='$($global:config.EventSource)'] and EventID=$($global:config.ElevateEventID)]]</Select></Query></QueryList>"
                    $Trigger.Enabled = $true
                    $Trigger.ValueQueries = [CimInstance[]]$(Get-CimClass -ClassName MSFT_TaskNamedValue -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskNamedValue)
                    $Trigger.ValueQueries[0].Name = "eventRecordID"
                    $Trigger.ValueQueries[0].Value = "Event/System/EventRecordID"
                    $ElevateUserSettings = New-ScheduledTaskSettingsSet -MultipleInstances Parallel 
                    Register-ScheduledTask -Principal $STprincipal -TaskName $STElevateUser -TaskPath $StGroupManagementTaskPath -Action $STaction -Trigger $Trigger -Settings $ElevateUserSettings
                }                        
            }
            catch [System.UnauthorizedAccessException] {
                Write-Host "Schedule task cannot registered." -ForegroundColor Red
                $ret = $false
            }
            catch {
                Write-Host $_.Exception.Message -ForegroundColor Red
                $ret = $false
            }
        }
        #endregion
        return $ret
    }

    Function Check-AdminPrivileges 
    {

        $HasSeBackupPriv = $false
        $WindowsIdentity = [system.security.principal.windowsidentity]::GetCurrent()
        $HasSeSecurityPriv = (whoami /priv |findstr SeSecurityPrivilege)

        return $HasSeSecurityPriv
    }

    Function Write-JitConfig2AD
    {
	    Param (
            [Parameter(Mandatory=$false)][String]$JiTCnfgName
        )
        $ret = $True
        $baseAdPath = "CN=Services,"+(Get-ADRootDSE).configurationNamingContext
        $defaultJiTContainerName = "Just-In-Time Administration"
        $defaultJiTDelegationContainerName = "Delegations"
        $defaultJiTCnfgName = "JiT-Configuration"
        if ($JiTCnfgName) {
            $JitCnfgADDN = ("CN=$($JiTCnfgName),CN=$($defaultJiTContainerName),$($baseAdPath)")
        } else {
            $JiTCnfgName = $defaultJiTCnfgName
            $JitCnfgADDN = $DefaultJiTADCnfgObjectDN
        }

        #remove old AD config object
        try {
            Write-Host "Checking existing JiT configuration ..." -ForegroundColor Yellow
            Get-ADObject -Identity $JitCnfgADDN | Remove-ADObject -Confirm:$false
        } catch {
            #object does not exists - no further action
        }

        try {
            Write-Host "updating JiT configuration to AD ..." -ForegroundColor Yellow
            Write-Host "--> $($JitCnfgADDN)"
            #create object with single field attributes
            New-ADObject -Name $JiTCnfgName -Type $JitCnfgObjClassName -Path ("CN=$($defaultJiTContainerName),$($baseAdPath)") -OtherAttributes @{
                'JitCnfg-ConfigScriptVersion' = "20250131"
                'JitCnfg-JitAdmGroupOU' = [string]$global:config.OU
                'JitCnfg-AdminPreFix' = [string]$global:config.AdminPreFix
                'JitCnfg-Domain' = [string]$global:config.Domain
                'JitCnfg-LDAPT1Computers' = [string]$global:config.LDAPT1Computers
                'JitCnfg-MaxElevatedTime' = [int]$global:config.MaxElevatedTime
                'JitCnfg-DefaultElevatedTime' = [int]$global:config.DefaultElevatedTime
                'JitCnfg-MaxConcurrentServer' = [int]$global:config.MaxConcurrentServer
                'JitCnfg-GroupManagedServiceAccountName' = [string]$global:config.GroupManagedServiceAccountName
                'JitCnfg-TaskRunInterval' = [int]$global:config.TaskRunInterval
                'JitCnfg-TaskScriptSource' = [string]$global:config.TaskScriptSource
                'JitCnfg-EventLog' = [string]$global:config.EventLog
                'JitCnfg-EventSource' = [string]$global:config.EventSource
                'JitCnfg-ElevateEventID' = [int]$global:config.ElevateEventID
                'JitCnfg-EnableMultiDomainSupport' = $global:config.EnableMultiDomainSupport
                'JitCnfg-EnableDelegation' = $global:config.EnableDelegation
                'JitCnfg-DomainSeparator' = "#"
                'JitCnfg-UseManagedByforDelegation' = $false
            }
            #now writing multi-string attributes if not empty
            if ($global:config.Tier0ServerGroupName) {
                $global:config.Tier0ServerGroupName| ForEach-Object {
                    Set-AdObject -Identity $JitCnfgADDN -Add @{'JitCnfg-Tier0ServerGroupName' = [String]$_}
                }
            }
            if ($global:config.T1Searchbase) {
                $global:config.T1Searchbase| ForEach-Object {
                    Set-AdObject -Identity $JitCnfgADDN -Add @{'JitCnfg-T1Searchbase' = [String]$_}
                }
            }
            if ($global:config.RequestOnBehalfOf) {
                $global:config.RequestOnBehalfOf| ForEach-Object {
                    Set-AdObject -Identity $JitCnfgADDN -Add @{'JitCnfg-RequestOnBehalfOf' = [String]$_}
                }
            }
            if ($global:config.AuthorizedServer) {
                $global:config.AuthorizedServer| ForEach-Object {
                    Set-AdObject -Identity $JitCnfgADDN -Add @{'JitCnfg-AuthorizedServer' = [String]$_}
                }
            }

        } catch {
            Write-Host "Could not update JiT configuration!" -ForegroundColor Red
            Write-Host 
            Write-Host $_.Exception.Message -ForegroundColor Red
            $ret = $false
        }
        return $ret
    }

    <#
        This function add a SID to the "Logon as a Batch Job" privilege
    #>
    function Add-LogonAsABatchJobPrivilege 
    {
    <#
    .SYNOPSIS
        Assign the Logon As A Batch Job privilege to a SID
    .DESCRIPTION
        Assign the Logon As A Batch Job privilege to a SID
    .EXAMPLE
        Add-LogonAsABatchJob -SID "S-1-5-0"
    .OUTPUTS
        none
    .NOTES
        Author: Andreas Lucas
        Date: 2021-10-10
    #>
        param ($Sid)
    
        $ret = $true
        #Temporary files for secedit
        $tempPath = [System.IO.Path]::GetTempPath()
        $import = Join-Path -Path $tempPath -ChildPath "import.inf"
        if(Test-Path $import) { Remove-Item -Path $import -Force }
        $export = Join-Path -Path $tempPath -ChildPath "export.inf"
        if(Test-Path $export) { Remove-Item -Path $export -Force }
        $secedt = Join-Path -Path $tempPath -ChildPath "secedt.sdb"
        if(Test-Path $secedt) { Remove-Item -Path $secedt -Force }
        #Export the current configuration
        secedit /export /cfg $export
        if ($false -eq  (Test-Path $export)){
            Write-Host 'Administrator privileges required to set "Logon AS Batch job permission" please add the privilege manually' -ForegroundColor Yellow
            $ret = $false
        } else {
            #search for the current SID assigned to the SeBatchJob privilege
            $SIDs = (Select-String $export -Pattern "SeBatchLogonRight").Line
            if (!($SIDs.Contains($Sid)))
            {
                #create a new temporary security configuration file
                foreach ($line in @("[Unicode]", "Unicode=yes", "[System Access]", "[Event Audit]", "[Registry Values]", "[Version]", "signature=`"`$CHICAGO$`"", "Revision=1", "[Profile Description]", "Description=GrantLogOnAsABatchJob security template", "[Privilege Rights]", "$SIDs,*$sid"))
                {
                    Add-Content $import $line
                }
                #configure privileges
                secedit /import /db $secedt /cfg $import
                secedit /configure /db $secedt
                gpupdate /force
                Remove-Item -Path $import -Force
                Remove-Item -Path $secedt -Force
            }
            #remove all temporary files   
            Remove-Item -Path $export -Force
        }
        return $ret
    }

    function CreateOU 
    {
        [CmdletBinding ( SupportsShouldProcess)]
        param (
            [Parameter(Mandatory)]
            [string]$OUPath,
            [Parameter (Mandatory)]
            [string]$DomainDNS
        )
        try{
            #load the OU path into array to create the entire path step by step
            $DomainDN = (Get-ADDomain -Server $DomainDNS).DistinguishedName
            $aryOU=$OUPath.Split(",").Trim()
            $OUBuildPath = ","+$DomainDN
        
            #walk through the entire domain
            [array]::Reverse($aryOU)
            $aryOU|ForEach-Object {
                #ignore 'DC=' values
                if ($_ -like "ou=*") {
                    $OUName = $_ -ireplace [regex]::Escape("ou="), ""
                    #check if OU already exists
                    if (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$($_+$OUBuildPath)'") {
                        Write-Debug "$($_+$OUBuildPath) already exists no actions needed"
                    } else {
                        Write-Host "'$($_+$OUBuildPath)' doesn't exist. Creating OU" -ForegroundColor Green
                        New-ADOrganizationalUnit -Name $OUName -Path $OUBuildPath.Substring(1) -Server $DomainDNS                        
                    
                    }
                    #adding current OU to 'BuildOUPath' for next iteration
                    $OUBuildPath = ","+$_+$OUBuildPath
                }
            }
        } 
        catch [System.UnauthorizedAccessException]{
            Write-Host "Access denied to create $OUPath in $domainDNS"
            Return $false
        } 
        catch{
            Write-Host "A error occured while create OU Structure"
            Write-Host $Error[0].CategoryInfo.GetType()
            Return $false
        }
        Return $true
    }

    function configure-JiTGroupOU
    {
        param (
            [Parameter(Mandatory=$True)] [string]$DefaultOUName,
            [Parameter(Mandatory=$True)] $objgMSA
        )

        $ret = $True
        #region Definition of the AD OU where the T1 JiT AD admin groups are stored
        try{
            if (!([ADSI]::Exists("LDAP://$DefaultOUName"))){
                Write-Host "The OU '$DefaultOUName' doesn't exist - creating ..." -ForegroundColor Yellow
                if (CreateOU -OUPath $DefaultOUName -DomainDNS (Get-ADDomain).DNSRoot) {
                    Write-Host "'$DefaultOUName' succesfully created" -ForegroundColor Green
                }
                # $OU = $null
            }
        } 
        catch {
            $ret = $false
        }
        #endregion

        if ($ret) {
            Write-Debug  "OU $($DefaultOUName) is accessible updating ACL"
            Write-Host "Updating ACL on OU '$DefaultOUName' for $($objgMSA.name) ..." -ForegroundColor Yellow
            $aclGroupOU = Get-ACL -Path "AD:\$($DefaultOUName)"

            if (!($aclGroupOU.Sddl.Contains($objgMSA.SID))){
                Write-Debug "Adding ACE to OU"
                #granting gMSA control on group objects in Tier 1 Jit admin group OU.
                $Identity = [System.Security.Principal.IdentityReference] $objgMSA.SID
                $Type = 'Allow' 

                $Rule1AdRights = 'GenericAll' 
                $Rule1ObjectType = '00000000-0000-0000-0000-000000000000' 
                $Rule1InheritanceType = 'Descendents' 
                $Rule1InheritedObjectType = 'bf967a9c-0de6-11d0-a285-00aa003049e2'  
                $Rule1ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$Rule1AdRights,$Type,$Rule1ObjectType,$Rule1InheritanceType,$Rule1InheritedObjectType

                $Rule2AdRights = 'CreateChild, DeleteChild' 
                $Rule2ObjectType = 'bf967a9c-0de6-11d0-a285-00aa003049e2' 
                $Rule2InheritanceType = 'All' 
                $Rule2InheritedObjectType = '00000000-0000-0000-0000-000000000000'  
                $Rule2ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$Rule2AdRights,$Type,$Rule2ObjectType,$Rule2InheritanceType,$Rule2InheritedObjectType

                # Full control to any group object in this OU and createChild, deleteChild for group object in this OU
                #$adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
                #$type = [System.Security.AccessControl.AccessControlType] "Allow"
                #$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                #$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
                #$aclGroupOU.AddAccessRule($ace)
                
                $aclGroupOU.AddAccessRule($Rule1ACE)
                $aclGroupOU.AddAccessRule($Rule2ACE)
                Set-Acl -AclObject $aclGroupOU "AD:\$($DefaultOUName)"
            }
        }
        return $ret
    }

    #endregion

    #collecting run requirements
    $IsAdmin = Check-AdminPrivileges
    #collecting running user, group memberships and forest sid
    $CurrUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name.split("\")[1]
    $groupTokens = ([string](Get-ADUser -Filter 'samaccountname -eq $curruser').distinguishedname|Get-ADUser -Properties tokengroups).tokengroups.value

    #checking if running user is Domain admin or Enterprise admin
    $forestSid = (Get-ADDomain -server (Get-ADForest).rootdomain|Select-Object domainsid).domainsid.Value
    $HasDaOrEA = (($groupTokens.Value -eq ($forestSid+"-512")) -or ($groupTokens.Value -eq ($forestSid+"-519")))
    #exit if requirements are not met
    if (!($IsAdmin -and $HasDaOrEA)) {
        Write-Host "Current run account is either not local administrator or not a member of Domain/Enterprise Admins... " -ForegroundColor Red
        Write-Host "Ensure proper permissions for run account" -ForegroundColor Red
        Write-Host "before continuing with JIT" -ForegroundColor Yellow
        Write-Host "Aborting!" -ForegroundColor Red
        $exit = $true
    }

    #checking if reg path exists - exit if not
    if (!(Test-Path $DefaultSetupRegPath)) {
        Write-Host "'Just-in-Time' registry not found!" -ForegroundColor Red
        Write-Host "'Just-in-Time' administration is not properly installed!" -ForegroundColor Red
        Write-Host
        Write-Host "Please run Install-JiT.ps1 before continuing!" -ForegroundColor Magenta
        $exit = $true
    } else {
        if ((Get-ItemProperty -Path $DefaultSetupRegPath -Name "SetupStatus").SetupStatus -ne 1004) { 
            Write-Host "'Just-in-Time' administration is not properly installed!" -ForegroundColor Red
            Write-Host
            Write-Host "Please run Install-JiT.ps1 before continuing!" -ForegroundColor Magenta
            $exit = $true
        }
    }
    $ComputerIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().name
    $ComputerNBDomain = $ComputerIdentity.split("\")[0]
    $ComputerDomainFQDN = (Get-ADObject -Filter 'netbiosname -eq $ComputerNBDomain' -searchbase (Get-ADForest).partitionscontainer -Properties dnsroot).dnsroot
}

#############################################################################################
# Main program starts here
#############################################################################################

process {

    #checking for hard exit condition
    if ($exit) {
        Exit 0xa
    }

    #checking for JiT schema in AD
    $JitCnfgClass = 'JiT-Configuration Object'
    $JitDelegationClass = 'JiT-Delegation Object'

    try {
        Get-ADObject -Identity "CN=$($JitDelegationClass),$((Get-ADRootDSE).schemaNamingContext)"|Out-Null
        $CnfgObjSchemaExtDone = $true
    } catch {
        #JiT schema missing
        Write-Output "JiT schema extensios are missing in Active Directory ..."
        $success = $false
    }

    #checking for existens of JiT config object in AD
    try {
        $ADconfig = Get-ADObject -Identity $DefaultJiTADCnfgObjectDN -Properties *
        $CnfgObjADStructureDone = $true
    }
    catch {
        #JiT AD structure missing
        Write-Output "Cannot read JiT configuration object in Active Directory ..."
        #Write-Output "Please run: 'install-Jit.ps1 -createAdStructure' to create the required objects - aborting!"
        $success = $false
    }

    #region check for an existing configuration
    if ($CnfgObjSchemaExtDone -and $CnfgObjADStructureDone) {

        #create config object from AD
        $global:config = [PSCustomObject]@{
            'ConfigScriptVersion'= $ADconfig.'JitCnfg-ConfigScriptVersion'
            'OU' = $ADconfig.'JitCnfg-JitAdmGroupOU'
            'AdminPreFix' = $ADconfig.'JitCnfg-AdminPreFix'
            'Domain' = $ADconfig.'JitCnfg-Domain'
            'Tier0ServerGroupName' = $ADconfig.'JitCnfg-Tier0ServerGroupName'
            'LDAPT0ComputerPath' = $ADconfig.'JitCnfg-LDAPT0ComputerPath'
            'LDAPT0Computers' = $ADconfig.'JitCnfg-LDAPT0Computers'
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
            'AuthorizedServer' = $ADconfig.'JitCnfg-AuthorizedServer'
        }
    }
    #endregion

    if ($PSCmdlet.ParameterSetName -eq "FullConfig") {
        #Checking the access to the installation directory and provide the system environment variable
        #Validate the installation directory and stop execution if installation directory doesn't exists
        if (!($InstallationDirectory)){
            $InstallationDirectory = (Get-Location).Path
            Write-Host "Installation folder is $installationDirectory"
        } elseif (!(Test-Path $InstallationDirectory)) {
            Write-Output "Cannot access installation folder ..."
            Write-Output "ensure the folder exists and running user has access - aborting!"
            $success = $false
            Exit 0x5
        }
        #setting initial reg value
        try{
            New-ItemProperty -Path $DefaultSetupRegPath -Name "ConfigStatus" -PropertyType dword -Value 2000 | Out-Null
        } catch {
            Write-Host "Could not create 'Just-in-Time' registry!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            Write-Host
            Write-Host "'Just-in-Time' configuration failed!" -ForegroundColor Red
            $success = $false
            Exit 0x5
        }

        if ((ConfigurationMenu) -eq "Success") {

            #writing configuration
            if (Write-JitConfig2AD) { #continue
                Set-ItemProperty -Path $DefaultSetupRegPath -Name "ConfigStatus" -Value 2001 | Out-Null
                if (Configure-JiT) {
                    Set-ItemProperty -Path $DefaultSetupRegPath -Name "ConfigStatus" -Value 2004 | Out-Null
                    Write-Host 
                    Write-Host "JiT configuration successfully finished !" -ForegroundColor Yellow
                    if ($global:config.EnableDelegation){
                        Write-Host 
                        Write-Host 
                        Write-Host "Do not forget to configure the delegations!" -ForegroundColor Magenta
                    }
                } else {
                    Write-Host "JiT configuration could not successfully finished - aborting ..." -ForegroundColor Red
                    $success = $false
                }
            } else {
                Write-Host "JiT configuration could not be written to AD - aborting ..." -ForegroundColor Red
                $success = $false
            }
        } else {
            Write-Host "JiT configuration canceled ..." -ForegroundColor Red
            $success = $false
        }
    }

    if ($PSCmdlet.ParameterSetName -eq "UpdateConfig") {
        # check for valid configuration before doing some updates
        try {
            if ((Get-ItemProperty -Path $DefaultSetupRegPath -Name "ConfigStatus" -ErrorAction Stop).ConfigStatus -eq 2004) { 
                #region re-define all configuration items as configured
                [bool]$CnfgObjSchemaExtDone = $true
                [bool]$CnfgObjADStructureDone = $true
                [bool]$CnfgObjJitAdmGroupOUDone = $true
                [bool]$CnfgObjAdminPreFixDone = $true
                [bool]$CnfgObjDomainDone = $true
                [bool]$CnfgObjTier0ServerGroupNameDone = $true
                [bool]$CnfgObjLDAPT1ComputersDone = $true
                [bool]$CnfgObjT1SearchbaseDone = $true
                [bool]$CnfgObjMaxElevatedTimeDone = $true
                [bool]$CnfgObjDefaultElevatedTimeDone = $true
                [bool]$CnfgObjMaxConcurrentServerDone = $true
                [bool]$CnfgObjGroupManagedServiceAccountNameDone = $true
                [bool]$CnfgObjTaskRunIntervalDone = $true
                [bool]$CnfgObjTaskScriptSourceDone = $true
                [bool]$CnfgObjEventLogDone = $true
                [bool]$CnfgObjEventSourceDone = $true
                [bool]$CnfgObjElevateEventIDDone = $true
                [bool]$CnfgObjRequestOnBehalfOfDone = $true
                [bool]$CnfgObjEnableMultiDomainSupportDone = $true
                [bool]$CnfgObjEnableDelegation = $true
                [bool]$CnfgObjDoneDomainSeparatorDone = $true
                #[bool]$CnfgObjUseManagedByforDelegationDone = $false
                #[bool]$CnfgObjDelegationConfigPathDone = $false
                [bool]$JiTCnfgDone = $false
                #endregion

                #open config menue to change some settings
                if ((ConfigurationMenu -UpdateOnly) -eq "Success") {

                    #writing configuration
                    if (Write-JitConfig2AD) {
                        Write-Host 
                        Write-Host "JiT configuration successfully updated !" -ForegroundColor Yellow
                    } else {
                        Write-Host "JiT configuration could not be written to AD - aborting ..." -ForegroundColor Red
                        $success = $false
                    }
                } else {
                    Write-Host "JiT configuration canceled ..." -ForegroundColor Red
                    $success = $false
                }
            } else {
                Write-Host "No valid JiT configuration found ..." -ForegroundColor Red
                Write-Host "JiT re-configuration canceled!" -ForegroundColor Red
                $success = $false
            }
        }
        catch {
            Write-Host "No valid JiT configuration found ..." -ForegroundColor Red
            Write-Host "JiT re-configuration canceled!" -ForegroundColor Red
            $success = $false
        }
    }

    if ($PSCmdlet.ParameterSetName -eq "NewConfig") {

        if ((ConfigurationMenu) -eq "Success") {

            #writing configuration
            if (Write-JitConfig2AD -JiTCnfgName $NewCnfgObjName) {
                Write-Host 
                Write-Host "New JiT configuration successfully written to AD !" -ForegroundColor Yellow
                Write-Host "This function is NOT fully implemented yet !!!" -ForegroundColor Yellow
            } else {
                Write-Host "New JiT configuration could not be written to AD - aborting ..." -ForegroundColor Red
                $success = $false
            }
        } else {
            Write-Host "New JiT configuration canceled ..." -ForegroundColor Red
            $success = $false
        }
    }

    if ($PSCmdlet.ParameterSetName -eq "AddServer") {
        Write-Host "This function is not yet implemented ..." -ForegroundColor Yellow
        $success = $false
    }
}

end {
    if (!$success) {
        Write-Host "----------------------------------------------------------"
        Write-Host
        Write-Host "Just-in-Time configuration failed ..." -ForegroundColor Red
        Write-Host "Please review and correct any possible error before" -ForegroundColor Yellow
        Write-Host "re-running Config-Jit.ps1" -ForegroundColor Magenta
    }

    #clean varables 
    if (Get-Variable DefaultJiTADCnfgObjectDN -Scope Global -ErrorAction SilentlyContinue) {
        Remove-Variable -Name DefaultJiTADCnfgObjectDN -Force
    }
    if (Get-Variable JitCnfgObjClassName -Scope Global -ErrorAction SilentlyContinue) {
        Remove-Variable -Name JitCnfgObjClassName -Force
    }
    if (Get-Variable JiTAdSearchbase -Scope Global -ErrorAction SilentlyContinue) {
        Remove-Variable -Name JiTAdSearchbase -Force
    }
    if (Get-Variable JitDelegationObjClassName -Scope Global -ErrorAction SilentlyContinue) {
        Remove-Variable -Name JitDelegationObjClassName -Force
    }
    if (Get-Variable STGroupManagementTaskName -Scope Global -ErrorAction SilentlyContinue) {
        Remove-Variable -Name STGroupManagementTaskName -Force
    }
    if (Get-Variable StGroupManagementTaskPath -Scope Global -ErrorAction SilentlyContinue) {
        Remove-Variable -Name StGroupManagementTaskPath -Force
    }
    if (Get-Variable STElevateUser -Scope Global -ErrorAction SilentlyContinue) {
        Remove-Variable -Name STElevateUser -Force
    }
    if (Get-Variable DefaultSetupRegPath -Scope Global -ErrorAction SilentlyContinue) {
        Remove-Variable -Name DefaultSetupRegPath -Force
    }
}



