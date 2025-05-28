<#
Script Info

Author: Andreas Luy[MSFT]
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
    This script provide a UI for Tier 1 JIT delegation configuration

.DESCRIPTION
    The UI let you easily select the server object, the OU which you want to delegate

.EXAMPLE
    .\DelegationUI.ps1

.OUTPUTS
   none
.NOTES
    Version Tracking
    2025-01-07 
    Version 0.1
        - initial version
    2025-03-27 
    Version 1.1
        - stable version


.PARAMETER title
    if specifying a different windows title 
#>
Param(
    [Parameter (Mandatory=$false)]
    $Title = "Tier1 Just in Time Delegation"
)


begin
{

#region classes & styles
## loading .net classes needed
    Add-Type -a (
        'System.DirectoryServices',
        'System.DirectoryServices.AccountManagement',
        'System.Drawing',
        'System.Windows.Forms'
    )


Add-Type -TypeDefinition @'
    using System.Runtime.InteropServices;
    public class ProcessDPI {
        [DllImport("user32.dll", SetLastError=true)]
        public static extern bool SetProcessDPIAware();      
    }
'@
    $null = [ProcessDPI]::SetProcessDPIAware()
    [System.Windows.Forms.Application]::EnableVisualStyles()
    [Windows.Forms.Application]::EnableVisualStyles()
    Import-Module Just-In-Time


# define fonts and colors 
    $SuccessFontColor = "Green"
    $WarningFontColor = "Yellow"
    $FailureFontColor = "Red"
    $SuccessFormFontColor = [System.Drawing.Color]::Green
    $WaringFormFontColor = [System.Drawing.Color]::Yellow
    $FailureFormFontColor = [System.Drawing.Color]::Red
    $HeadlineFormFontColor = [System.Drawing.Color]::White


    $SuccessBackColor = "Black"
    $WarningBackColor = "Black"
    $FailureBackColor = "Black"
    $FormBackColorDark = [System.Drawing.Color]::ControlDark
    $FormBackColorDarkGray = [System.Drawing.Color]::DarkGray

    $FontStdt = New-Object System.Drawing.Font("Arial",11,[System.Drawing.FontStyle]::Regular)
    $FontHeading = New-Object System.Drawing.Font("Arial",14,[System.Drawing.FontStyle]::Regular)
    $FontBold = New-Object System.Drawing.Font("Arial",11,[System.Drawing.FontStyle]::Bold)
    $FontItalic = New-Object System.Drawing.Font("Arial",11,[System.Drawing.FontStyle]::Italic)

    $Border3D = [System.Windows.Forms.BorderStyle]'Fixed3D'
    $BorderFixedSingle = [System.Windows.Forms.BorderStyle]'FixedSingle'
#endregion

#region Script Version and initialization
    [int]$_configBuildVersion = "20250103"
    $MinConfigVersionBuild = 20241023

    if (!(Get-Variable objFullDelegationList -Scope Global -ErrorAction SilentlyContinue)) {
        Set-Variable -name objFullDelegationList -value @() -Scope Global -Option AllScope
    }
    $global:objFullDelegationList = Get-JitDelegation
    $global:ADBrowserResult = "" | select Result, DelegationDNValue, AdPrincipalDNValue
#endregion

#region general functions

    function Load-DelegationList
    {
        param(
            [Parameter(mandatory=$false)][String]$Filter = "NoFilter",
            [Parameter(mandatory=$false)][int32]$SelectedItem=0,
            [Parameter(mandatory=$false)][Switch]$ReloadFullList
        )

        [void]$objDelegationComboBox.Items.Clear()

        if ($ReloadFullList) {
            #load full list
            $global:objFullDelegationList = Get-JitDelegation
        }

        #load filtered list if requested
        if ($Filter -eq "OUsOnly") {
            $Script:FilteredDelegationView = $global:objFullDelegationList|where {$_.ObjectClass -eq "organizationalUnit"}

        } elseif ($Filter -eq "ComputersOnly") {
            $Script:FilteredDelegationView = $global:objFullDelegationList|where {$_.ObjectClass -eq "Computer"}
        } else {
            $Script:FilteredDelegationView = $global:objFullDelegationList
        }
        Foreach ($DelegationItem in $Script:FilteredDelegationView) {
            [void]$objDelegationComboBox.Items.Add(($DelegationItem.DN))
        }
        if ($objDelegationComboBox.Items.Count -gt 0) {
            $objDelegationComboBox.SelectedIndex = $SelectedItem
        }
    }

    function Load-PrincipalList
    {
        param(
            [Parameter(mandatory=$True)][int32]$DelegationEntry
        )

        #$Msg = " "
        [void]$objDelegationPrincipalListBox.Rows.Clear()

        if ($DelegationEntry -ge 0) {
            $Script:CurrDelEntry = $Script:FilteredDelegationView[$DelegationEntry]
            if ($Script:CurrDelEntry.Accounts.Count -gt 0){
                for ($i = 0; $i -lt $Script:CurrDelEntry.Accounts.Count; $i++){
                    [void]$objDelegationPrincipalListBox.Rows.Add(($Script:CurrDelEntry.Accounts)[$i],($Script:CurrDelEntry.SID)[$i])
                }
            }
        }
    }

    function Out-Message
    {
        param(
            [Parameter(mandatory=$True)][String]$Msg
        )
        $objResultTextBox.Text = $Msg
    }

    function Add-Principal
    {
        param(
            [Parameter(mandatory=$True)][String]$DelegationDN
        )
        AD-Browser -DomainDNS (Get-DomainDNSfromDN -AdObjectDN $DelegationDN) -Mode SelectADPrincipals
        if ($global:ADBrowserResult.Result -eq "Success") {
            $result = Add-JitDelegation -DelegationObject $DelegationDN -ADPrincipal $global:ADBrowserResult.AdPrincipalDNValue
        }
        return $result
    }

    function Delete-Principal
    {
        param(
            [Parameter(mandatory=$True)][String]$DelegationDN,
            [Parameter(mandatory=$True)][String]$AdPrincipal,
            [Parameter(mandatory=$false)][String]$PrincipalSid,
            [Parameter(mandatory=$false)][switch]$IgnoreValidation
        )
        if ($IgnoreValidation) {
            $result = Remove-JitDelegation -DelegationObject $DelegationDN -ADPrincipal $AdPrincipal -RemoveAdPrincipalWithoutValidation -Sid $PrincipalSid
        } else {
            $result = Remove-JitDelegation -DelegationObject $DelegationDN -ADPrincipal $AdPrincipal 
        }
        return $result
    }

    function Verify-Principal
    {
        param(
            [Parameter(mandatory=$True)][String]$DelegationDN,
            [Parameter(mandatory=$True)][String]$AdPrincipal,
            [Parameter(mandatory=$false)][String]$PrincipalSid
        )
        $AdPrincipalSid = Get-Sid -Name $AdPrincipal
        if (IsStringNullOrEmpty $AdPrincipalSid){
            $result = New-ConfirmationMsgBox -Message "AD Principal defined in Delegation configuration cannot be resolved:`r`n    $($AdPrincipal)!`r`n`r`nShould that entry be removed?"
            if ($result = "Yes") {
                $ret = Remove-JitDelegation -DelegationObject $DelegationDN -ADPrincipal $AdPrincipal -RemoveWithoutValidation -Sid $PrincipalSid
                return $true
            }
        }
        return $false
    }

    function Add-NewDelegationObject
    {
        $ret = $null
        
        # if Multi-Domain Mode is enabled add all domains to the $aryDomainList otherwise add only 
        # the current domain to the array
        if ($global:config.EnableMultiDomainSupport) {
            $Domain = (Get-ADForest).RootDomain
        }
        else {
            $Domain = (Get-ADdomain).DNSRoot
        }
        AD-Browser -DomainDNS $Domain -Mode SelectDelegationObject
        #$global:ADBrowserResult
        if ($global:ADBrowserResult.Result -eq "Success") {
            if (!(Add-JitDelegation -DelegationObject $global:ADBrowserResult.DelegationDNValue -ADPrincipal $global:ADBrowserResult.AdPrincipalDNValue)) {
                #adding failed
                $global:ADBrowserResult.Result -eq "Failed"
            }
        } else {
            #ad brower has been interupted
            $global:ADBrowserResult.Result -eq "Exit"
        }
        $ret = $global:ADBrowserResult
        return $ret
    }

    function Remove-DelegationObject
    {
           param(
            [Parameter(mandatory=$True)][String]$DelegationDN
        )

        $result = Remove-JitDelegation -DelegationObject $DelegationDN -RemoveDelegationWithoutValidation -Force
        return $result
    }

    Function Set-AdDelegationObjectPermissions
    {
        param (
            [Parameter(Mandatory=$false)] [string]$ObjectDN,
            [Parameter(Mandatory=$True)] [string]$gMSA
        )


        #dsacls.exe "OU=PKI,OU=Tier 1 Servers,DC=Fabrikam,DC=com" /I:S /G "fabrikam\T1GroupMgmt$:WP;groupPriority;computer"

        $ret = ""
        $acl = Get-Acl "AD:$($ObjectDN)"

        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            (Get-ADServiceAccount -Identity $gMSA).SID,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,
            "eea65905-8ac6-11d0-afda-00c04fd930c9",
            [DirectoryServices.ActiveDirectorySecurityInheritance]::All
        )

        $acl.AddAccessRule($ace)
        try {
            $acl |Set-Acl
            $ret = "Success"
        }
        catch {
            $ret = $_.Exception.Message
        }
        return $ret
    }

    function Get-AdDelegationObjectAclView
    {
        param (
            [Parameter(Mandatory=$false)] [string]$DelegationDN,
            [Parameter(Mandatory=$True)] [string]$gMSA,
            [Parameter(Mandatory=$false)] [switch]$ViewOnly
        )

        #region form dimensions
        $AdAclFormHeight = 400
        $AdAclFormWidth = 800

        if ($ViewOnly) {
            $objAdAclFormBtnCloseX = 10
            $AceGridViewHeight = $AdAclFormHeight-100
        } else {
            $objAdAclFormBtnCloseX = $AdAclFormWidth-160
            $AceGridViewHeight = $AdAclFormHeight-180
        }
        #endregion
        
        $AdAclFormIcon = "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"
        $AdAclFormIconBytes = [Convert]::FromBase64String($AdAclFormIcon)
        $AdAclFormStream = [System.IO.MemoryStream]::new($AdAclFormIconBytes, 0, $AdAclFormIconBytes.Length)


        #region design form
        $objAdAclForm = New-Object System.Windows.Forms.Form
        $objAdAclForm.Size = New-Object System.Drawing.Size($AdAclFormWidth,$AdAclFormHeight)
        $objAdAclForm.Icon = [System.Drawing.Icon]::FromHandle(([System.Drawing.Bitmap]::new($AdAclFormStream).GetHIcon()))
        $objAdAclForm.FormBorderStyle = "FixedDialog"
        #$objAdAclForm.StartPosition = "CenterScreen"
        $objAdAclForm.MinimizeBox = $False
        $objAdAclForm.MaximizeBox = $False
        $objAdAclForm.WindowState = "Normal"
        $objAdAclForm.Text ="Configured Access Permission: $($DelegationDN)"
        
        #region data grid view
        $AceGridView = New-Object System.Windows.Forms.DataGridView
        $AceGridView.Location = New-Object System.Drawing.Size(10,10)
        $AceGridView.Size=New-Object System.Drawing.Size(($AdAclFormWidth-30),$AceGridViewHeight)
        $AceGridView.AutoSizeRowsMode = "AllCells"

        $AceGridView.DefaultCellStyle.Font = "Microsoft Sans Serif, 9"
        $AceGridView.DefaultCellStyle.WrapMode = "True"
        $AceGridView.ColumnHeadersDefaultCellStyle.Font = "Microsoft Sans Serif, 10"
        $AceGridView.ColumnHeadersVisible = $true
        $AceGridView.SelectionMode = "FullRowSelect"
        $AceGridView.ReadOnly = $true
        $AceGridView.AllowUserToAddRows = $false

        $AceGridView.ColumnCount = 4
        $AceGridView.Columns[0].Name = "AdPrincipal"
        $AceGridView.Columns[1].Name = "Access Type"
        $AceGridView.Columns[2].Name = "ActiveDirectoryRights"
        $AceGridView.Columns[3].Name = "ObjectGUID"
        $AceGridView.Columns[0].Width = "180"
        $AceGridView.Columns[1].Width = "100"
        $AceGridView.Columns[2].Width = "160"
        $AceGridView.Columns[3].AutoSizeMode = "Fill"
        #endregion

        #region result text box
        $objAdAclFormTextBox = New-Object System.Windows.Forms.TextBox
        $objAdAclFormTextBox.Location = New-Object System.Drawing.Point(10,($AdAclFormHeight-160))
        $objAdAclFormTextBox.Size = New-Object System.Drawing.Size(($AdAclFormWidth-30),80)
        $objAdAclFormTextBox.ReadOnly = $true 
        $objAdAclFormTextBox.Multiline = $true
        $objAdAclFormTextBox.AcceptsReturn = $true 
        $objAdAclFormTextBox.Text = ""
        $objAdAclFormTextBox.Font = "Microsoft Sans Serif, 11"
        $objAdAclFormTextBox.Visible = (!$ViewOnly)
        #endregion

        #region form buttons
        $objAdAclFormBtnOk = New-Object System.Windows.Forms.Button
        $objAdAclFormBtnOk.Cursor = [System.Windows.Forms.Cursors]::Hand
        $objAdAclFormBtnOk.Location = New-Object System.Drawing.Point((10),($AdAclFormHeight-70))
        $objAdAclFormBtnOk.Size = New-Object System.Drawing.Size(140,30)
        $objAdAclFormBtnOk.Text = "Apply Permissions"
        $objAdAclFormBtnOk.Font = "Microsoft Sans Serif, 11"
        $objAdAclFormBtnOk.Visible = (!$ViewOnly)

        $objAdAclFormBtnClose = New-Object System.Windows.Forms.Button
        $objAdAclFormBtnClose.Cursor = [System.Windows.Forms.Cursors]::Hand
        $objAdAclFormBtnClose.Location = New-Object System.Drawing.Point($objAdAclFormBtnCloseX,($AdAclFormHeight-70))
        $objAdAclFormBtnClose.Size = New-Object System.Drawing.Size(140,30)
        $objAdAclFormBtnClose.Text = "Close"
        $objAdAclFormBtnClose.TabIndex=0
        $objAdAclFormBtnClose.Font = "Microsoft Sans Serif, 11"
        #endregion

        #endregion design form

        #region initial grid load
        $ObjectAcl = (Get-Acl "AD:/$($DelegationDN)").access | select identityreference, accesscontroltype, ActiveDirectoryRights, ObjectType
        foreach ($ace in $ObjectAcl) {    
            [void]$AceGridView.Rows.Add($ace.IdentityReference,$ace.AccessControlType,$ace.ActiveDirectoryRights,$ace.ObjectType)
        }
        #endregion

        #region build form
        $objAdAclForm.Controls.Add($AceGridView)
        $objAdAclForm.Controls.Add($objAdAclFormTextBox)
        $objAdAclForm.Controls.Add($objAdAclFormBtnOk)
        $objAdAclForm.Controls.Add($objAdAclFormBtnClose)
        #endregion

        #region event handlers
        $AceGridView.Add_SelectionChanged({
             $AceGridView.ClearSelection() 
        })

        $AceGridView.add_MouseDown({
            $AceGridView.ClearSelection() 
        })

        $objAdAclFormBtnClose.Add_Click({
            $objAdAclForm.Close()
            $objAdAclForm.dispose()
        })

        $objAdAclFormBtnOK.Add_Click({
            if ((New-ConfirmationMsgBox -Message "Do you want to configure write permissions to $($gMSA) for 'groupPriority'?") -eq "Yes") {
                $objAdAclFormTextBox.Text = "Applying write permissions to 'groupPriority' for $($gMSA) ...`n`r`n`r"
                $result = Set-AdDelegationObjectPermissions -ObjectDN $DelegationDN -gMSA $gMSA
                $objAdAclFormTextBox.Text += $result
                if ($result -eq "Success") {
                    #region reload grid
                    $AceGridView.Rows.Clear()
                    $ObjectAcl = (Get-Acl "AD:/$($DelegationDN)").access | select identityreference, accesscontroltype, ActiveDirectoryRights, ObjectType
                    foreach ($ace in $ObjectAcl) {    
                        [void]$AceGridView.Rows.Add($ace.IdentityReference,$ace.AccessControlType,$ace.ActiveDirectoryRights,$ace.ObjectType)
                    }
                    #endregion
                }
            }
        })
        #endregion

        $objAdAclForm.ShowDialog()



    }

    function Get-AdDelegationObjectPermissions
    {
        param (
            [Parameter(Mandatory=$false)] [string]$ObjectDN,
            [Parameter(Mandatory=$True)] [string]$gMSA
        )

        $found = $false
        $RunAccount = "*" + $gMSA + "$"

        $ObjectAcl = (Get-Acl "AD:/$($ObjectDN)").access | select identityreference, accesscontroltype, ActiveDirectoryRights, ObjectType
        if ($ObjectAcl.identityreference -like $RunAccount) {
            if ((New-ConfirmationMsgBox -Message "Permissions verified!`n`r`n`r$($gMSA) has write permission for 'groupPriority' attribute at:`n`r`n`r$($ObjectDN)`n`r`n`rDo you want to view permissions?" -information) -eq "Yes") {
                Get-AdDelegationObjectAclView -DelegationDN $ObjectDN -gMSA $gMSA -ViewOnly
            }
            $found = $True
        } else {
            #account could not be identified
            #bring up a grid view 
            if ((New-ConfirmationMsgBox -Message "Could not verify write permissions to $($gMSA) for 'groupPriority' attribute!`n`r`n`rDo you want to adjust permissions?") -eq "Yes") {
                Get-AdDelegationObjectAclView -DelegationDN $ObjectDN -gMSA $gMSA
            }
        }
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

    function IsStringNullOrEmpty
    {
        param
        (
            [Parameter(Mandatory = $true)]$PsValue
        )
        #return ([string]::IsNullOrWhiteSpace($PsValue))
        return ($PsValue -notmatch "\S")
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

    function Fill-Details 
    {

        param(
            [Parameter (Mandatory=$true)]$AdObject
        )

        $AdNodeDN = $AdObject.Node.Tag.Substring($AdObject.Node.Tag.IndexOf("://")+3)
        #get domain dns from AdObject
        #checking for domainroot (domainroot only contains domain fqdn)
        if (!($AdNodeDN.tolower() -match ",dc=")) {
            $DomainDNS = $AdNodeDN
            $AdNode = Get-ADDomain -Identity $DomainDNS
            $AdNodeDN = $AdNode.DistinguishedName
        } else {
            #create domain dns from DN
            $DomainDNS = Get-DomainDNSfromDN -AdObjectDN $AdNodeDN
            $AdNode = Get-ADObject -Filter 'DistinguishedName -eq $AdNodeDN' -Server $DomainDNS
        }
        #if (!$AdNode) {Write-Output "AdNode: EMPTY`r`n"}else{Write-Output "AdNode: $($AdNode)`r`n"}
        $AdNodeName = if ($AdNode.Name) {$AdNode.Name}else{$AdNode.cn}
        $RetVal = "Object Class:`r`n$([string]$AdNode.objectClass)`r`n`r`nName:`r`n$($AdNodeName)`r`n`r`nDN:`r`n$($AdNodeDN)"
        return $RetVal
    }

    function NewNode($name, $dn) {
        $node = new-object Windows.Forms.TreeNode -a $name
        $node.Tag = "LDAP://$dn"
        [void] $node.Nodes.Add($(new-object Windows.Forms.TreeNode `
            -a 'Loading...' -pr @{ Name = 'LoadingNode' }))
        return $node
    }

#endregion

#region AD Browser

# heavily based on the idea of
# https://codeplexarchive.org/project/adexploder
# 
# Copyright (c) 2013 Greg Toombs
#

function AD-Browser {
param(
    [Parameter (Mandatory=$true)][String]$DomainDNS,
    [Parameter (Mandatory=$false)]
    [ValidateSet('SelectAll', 'SelectDelegationObject', 'SelectADPrincipals', IgnoreCase = $True)]
    [String]$Mode = 'SelectADPrincipals',
    [Parameter (Mandatory=$false)]
    $Title = "AD Delegation Selector"
)


$SelectedAdPrincipalDN = ""

Set-Variable -name objClassFilter -Scope Global -Option AllScope
 
if ($Mode -eq "SelectADPrincipals") {
    $global:objClassFilter = "ADPrincipals"
} elseif ($Mode -eq "SelectDelegationObject") {
    $global:objClassFilter = "OU+Computer"
} else {
    $global:objClassFilter = "All"
}

#region initializing form    
    $formWidth = 500
    $formHeight = 550
    $Panelwidth = $formWidth-200
    $Panelheight = $formHeight-160
    $iconBase64 = "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"
    $iconBytes = [Convert]::FromBase64String($iconBase64)
    $stream = [System.IO.MemoryStream]::new($iconBytes, 0, $iconBytes.Length)
    
    #functionable variables
    $NewNode = get-Item function:NewNode
    $FillDetails = get-Item Function:Fill-Details
    $IsDNFormat = get-Item Function:IsDNFormat
    $GetDomainDNSfromDN = get-Item Function:Get-DomainDNSfromDN
    
    #$objConnectionForm = ConnectionDialog
    $objADForm = new-object Windows.Forms.Form
    $objADForm.ClientSize = new-object Drawing.Size -a $formWidth, $formHeight
    $objADForm.Text = $Title
    $objADForm.FormBorderStyle = "FixedDialog"
    #$objADForm.StartPosition = "CenterScreen"
    $objADForm.MinimizeBox = $False
    $objADForm.MaximizeBox = $False
    $objADForm.WindowState = "Normal"
    $objADForm.Icon = [System.Drawing.Icon]::FromHandle(([System.Drawing.Bitmap]::new($stream).GetHIcon()))
    #$objADForm.BackColor = "White"
    $objADForm.Font = $FontStdt
    $objADForm.AutoScaleMode
#endregion

#region AdBrowserLabel (display browser mode)
    $objAdBrowserLabel = new-object System.Windows.Forms.Label
    $objAdBrowserLabel.Location = new-object System.Drawing.Point(10,10) 
    $objAdBrowserLabel.size = new-object System.Drawing.Size(($formWidth-30),30) 
    if ($Mode -eq "SelectADPrincipals") {
        $objAdBrowserLabel.Text = "Select AD principal to be delegated"
    } elseif ($Mode -eq "SelectDelegationObject") {
        $objAdBrowserLabel.Text = "Select new delegation object"
    } else {
        $objAdBrowserLabel.Text = "Select AD object"
    }
    $objAdBrowserLabel.TextAlign = 'MiddleCenter'
    $objAdBrowserLabel.Font = $FontHeading
    #$objAdBrowserLabel.ForeColor = $HeadlineFormFontColor
    $objAdBrowserLabel.BackColor = $FormBackColorDarkGray
    $objAdBrowserLabel.BorderStyle = $BorderFixedSingle
    $objADForm.Controls.Add($objAdBrowserLabel)
#endregion

#region InputLabel1 (domains)
    $objDomainSelectLabel = new-object System.Windows.Forms.Label
    $objDomainSelectLabel.Location = new-object System.Drawing.Point(10,60) 
    $objDomainSelectLabel.size = new-object System.Drawing.Size(170,30) 
    $objDomainSelectLabel.Font = $FontStdt
    $objDomainSelectLabel.Text = "Select Domain:"
    $objDomainSelectLabel.AutoSize = $true
    $objADForm.Controls.Add($objDomainSelectLabel)
#endregion

#region Domain SelectionList
    $objDomainComboBox = New-Object System.Windows.Forms.ComboBox
    $objDomainComboBox.Location  = New-Object System.Drawing.Point(10,90)
    $objDomainComboBox.size = new-object System.Drawing.Size(200,25) #(($formWidth-30),25)
    $objDomainComboBox.Font = $FontStdt
    $objDomainComboBox.AutoCompleteSource = 'ListItems'
    $objDomainComboBox.AutoCompleteMode = 'Suggest'
    $objDomainComboBox.DropDownStyle = 'DropDownList'
    $objADForm.Controls.Add($objDomainComboBox)

    #load domain list - initial list will not change until tools is restarted
    $Domains = (Get-ADForest).Domains
    $RootDomain = (Get-ADForest).RootDomain
    
    #do we have multi domain forest and EnableMultiDomainSupport=true ?
    if (($Domains.count -gt 1) -and $global:config.EnableMultiDomainSupport) {
        Foreach ($Domain in $Domains) {
            [void]$objDomainComboBox.Items.Add($Domain)
            if ($Domain -eq $RootDomain) {
                $DomainDefaultSelection = ($objDomainComboBox.Items.Count) - 1
            }
            $InitialDomain = $RootDomain 
        }
    } else {
        #do we have single domain forest? - here we don't care about EnableMultiDomainSupport
        if ($Domains.count -eq 1) {
            [void]$objDomainComboBox.Items.Add($RootDomain)
            $InitialDomain = $RootDomain 
        } else {
            #last - we have multi domain forest but EnableMultiDomainSupport=false
            #means we need to tackle only local domain
            $InitialDomain = (Get-ADDomain).DNSRoot
            [void]$objDomainComboBox.Items.Add($InitialDomain)
        }
        $DomainDefaultSelection = ($objDomainComboBox.Items.Count) - 1
    }
    $objDomainComboBox.SelectedIndex = $DomainDefaultSelection
#endregion

#region DelegationLabel1 (Delegation)
    $objDelegationLabel = new-object System.Windows.Forms.Label
    $objDelegationLabel.Location = new-object System.Drawing.Point(10,($formHeight-150)) 
    $objDelegationLabel.size = new-object System.Drawing.Size(170,30) 
    $objDelegationLabel.Font = $FontStdt
    $objDelegationLabel.Text = "Selected Delegation Object:"
    $objDelegationLabel.AutoSize = $true
    $objDelegationLabel.Visible = $false
    $objADForm.Controls.Add($objDelegationLabel)
#endregion

#region DelegationTextBox (Selected Delegation Object)
    $objDelegationSelectTextBox = New-Object System.Windows.Forms.TextBox
    $objDelegationSelectTextBox.Location = New-Object System.Drawing.Point(10,($formHeight-120))
    $objDelegationSelectTextBox.Size = New-Object System.Drawing.Size(($formWidth-30),40)
    $objDelegationSelectTextBox.ReadOnly = $true 
    $objDelegationSelectTextBox.Multiline = $true
    $objDelegationSelectTextBox.AcceptsReturn = $true 
    $objDelegationSelectTextBox.WordWrap = $false
    $objDelegationSelectTextBox.Scrollbars = "Horizontal"
    $objDelegationSelectTextBox.ForeColor = $FailureFontColor
    $objDelegationSelectTextBox.BackColor = $FormBackColorDarkGray
    $objDelegationSelectTextBox.Font = $FontItalic
    $objDelegationSelectTextBox.Text = ""
    #$objDelegationSelectTextBox.TextAlign = 'MiddleRight'
    $objDelegationSelectTextBox.Visible = $false
    $objADForm.Controls.Add($objDelegationSelectTextBox)
#endregion

#region AdPrincipalsSelectLabel
    $objAdPrincipalsSelectLabel = new-object System.Windows.Forms.Label
    $objAdPrincipalsSelectLabel.Location = new-object System.Drawing.Point(10,($formHeight-120)) 
    $objAdPrincipalsSelectLabel.size = new-object System.Drawing.Size(($formWidth-30),30) 
    $objAdPrincipalsSelectLabel.Text = ""
    $objAdPrincipalsSelectLabel.Font = $FontItalic
    $objAdPrincipalsSelectLabel.ForeColor = $FailureFontColor
    $objAdPrincipalsSelectLabel.BackColor = $FormBackColorDarkGray
    $objAdPrincipalsSelectLabel.Visible = $false
    $objADForm.Controls.Add($objAdPrincipalsSelectLabel)
#endregion

#region ADTree
    $objADTree = new-object Windows.Forms.TreeView
    $objADTree.Dock = [Windows.Forms.DockStyle]::Fill
#endregion

#region object details box
    $objDetailsTextBox = New-Object System.Windows.Forms.TextBox
    #$objDetailsTextBox.Location = New-Object System.Drawing.Point(10,($height-120))
    #$objDetailsTextBox.Size = New-Object System.Drawing.Size(($width-200),80)
    $objDetailsTextBox.Dock = [Windows.Forms.DockStyle]::Fill
    $objDetailsTextBox.ReadOnly = $true 
    $objDetailsTextBox.Multiline = $true
    $objDetailsTextBox.AcceptsReturn = $true 
    $objDetailsTextBox.WordWrap = $false
    $objDetailsTextBox.Scrollbars = "Horizontal"
    $objDetailsTextBox.Font = $FontStdt
    $objDetailsTextBox.Text = ""
#endregion

#region splitterContainer
    $objSplitContainer = new-object Windows.Forms.SplitContainer
    $objSplitContainer.Location  = New-Object System.Drawing.Point(10,130)
    $objSplitContainer.size = new-object System.Drawing.Size(($formWidth-30),($formHeight-310)) 
    #$objSplitContainer.Dock = [Windows.Forms.DockStyle]::Bottom
    $objSplitContainer.SplitterWidth = 6
    $objSplitContainer.SplitterDistance = 200
    $objSplitContainer.Panel1.Controls.Add($objADTree)
    $objSplitContainer.Panel2.Controls.Add($objDetailsTextBox)
    $objADForm.Controls.Add($objSplitContainer)
#endregion

#region SelectButton
    $objSelectButton = New-Object System.Windows.Forms.Button
    $objSelectButton.Location = New-Object System.Drawing.Point(10,($formHeight-50))
    $objSelectButton.Size = New-Object System.Drawing.Size(150,30)
    $objSelectButton.Font = $FontStdt
    $objSelectButton.Text = "Select"
    $objADForm.Controls.Add($objSelectButton)
#endregion

#region DelegateButton
    $objDelegateButton = New-Object System.Windows.Forms.Button
    $objDelegateButton.Location = New-Object System.Drawing.Point(10,($formHeight-50))
    $objDelegateButton.Size = New-Object System.Drawing.Size(150,30)
    $objDelegateButton.Font = $FontStdt
    $objDelegateButton.Text = "Delegate"
    $objDelegateButton.Visible = $false
    $objDelegateButton.Enabled = $false
    $objDelegateButton.IsAccessible = $false
    $objADForm.Controls.Add($objDelegateButton)
#endregion

#region ExitButton
    $objBtnExit = New-Object System.Windows.Forms.Button
    $objBtnExit.Cursor = [System.Windows.Forms.Cursors]::Hand
    $objBtnExit.Location = New-Object System.Drawing.Point(((($formWidth/4)*3)-40),($formHeight-50))
    $objBtnExit.Size = New-Object System.Drawing.Size(150,30)
    $objBtnExit.Font = $FontStdt
    $objBtnExit.Text = "Exit"
    $objBtnExit.TabIndex=0
    $objADForm.Controls.Add($objBtnExit)
#endregion

if ($Mode -eq "SelectDelegationObject") {
    $objDelegationLabel.Visible = $true
    #$objDelegationSelectLabel.Visible = $true
    $objDelegationSelectTextBox.Visible = $true
    $objDelegateButton.Visible = $false
    $objSelectButton.Visible = $true
} else {
    $objDelegationLabel.Visible = $false
    #$objDelegationSelectLabel.Visible = $false
    $objDelegationSelectTextBox.Visible = $false
    $objDelegateButton.Visible = $true
    $objSelectButton.Visible = $false
}

#region form event handlers

    $objADTree.Add_AfterSelect({
        param($sender, $e)
        #show details only if class filter matches
        $strDN = ""
        $DN = $e.Node.Tag.Substring($e.Node.Tag.IndexOf("://")+3)

        #if no classFilter --> apply "All"
        $classMatch = $false
        if ($global:objClassFilter -eq "All") {
            $classMatch = $true
        } else {
            #check if dn is NOT domain root
            if (&$IsDNFormat -DNString $dn) {
                [string]$strDN = $dn
                $objClass = (Get-ADObject -Filter 'DistinguishedName -eq $strDN' -Server (&$GetDomainDNSfromDN -AdObjectDN $strDN)).objectClass
                # view OUs even if class filter is set to something else
                if ((($global:objClassFilter -eq "OU") -or ($global:objClassFilter -eq "OU+Computer")) -and ($objClass.toLower() -eq "organizationalunit")) {
                    $classMatch = $true
                } elseif ((($global:objClassFilter -eq "Computer") -or ($global:objClassFilter -eq "OU+Computer")) -and ($objClass.toLower() -eq "computer")) {
                    $classMatch = $true
                } elseif (($global:objClassFilter -eq "ADPrincipals") -and (($objClass.toLower() -eq "user") -or ($objClass.toLower() -eq "group"))) {
                    $classMatch = $true
                } elseif ($objClass.toLower() -eq "domainDNS") {
                    $classMatch = $true
                }
            } else {
                #dn is domain root
                if (($global:objClassFilter -eq "OU")) {
                    $classMatch = $true
                }
            }
        }
        if ($classMatch) {
            $objDetailsTextBox.Text = &$FillDetails -AdObject $e
            $SelectedAdPrincipalDN = $e.Node.Tag.Substring($e.Node.Tag.IndexOf("://")+3)
            $objDelegateButton.Enabled = $true
            $objDelegateButton.IsAccessible = $true
        }
    }.GetNewClosure())

    $objADTree.Add_AfterExpand({
        param($sender, $e)
        if ($e.Node.Nodes.Count -eq 1 -and $e.Node.Nodes[0].Name -eq 'LoadingNode') {
            $AdRootNode = new-object DirectoryServices.DirectoryEntry -a $e.Node.Tag
            foreach ($childNode in $AdRootNode.Children) {
                $strDN = ""
                $dn = $childNode.distinguishedName

                #if no classFilter --> apply "All"
                $classMatch = $false
                if ($global:objClassFilter -eq "All") {
                    $classMatch = $true
                } else {
                    #check if dn is NOT domain root
                    if (IsDNFormat -DNString $dn) {
                        [string]$strDN = $dn
                        $objClass = (Get-ADObject -Filter 'DistinguishedName -eq $strDN' -Server (Get-DomainDNSfromDN -AdObjectDN $strDN)).objectClass
                        # view OUs even if class filter is set to something else
                        #if ((($global:objClassFilter -eq "OU") -or ($global:objClassFilter -eq "Computer") -or ($global:objClassFilter -eq "ADPrincipals") -or ($global:objClassFilter -eq "OU+Computer")) -and ($objClass.toLower() -eq "organizationalunit")) {
                        if (($objClass.toLower() -eq "organizationalunit")) {
                            $classMatch = $true
                        } elseif ((($global:objClassFilter -eq "Computer") -or ($global:objClassFilter -eq "OU+Computer")) -and ($objClass.toLower() -eq "computer")) {
                            $classMatch = $true
                        } elseif (($global:objClassFilter -eq "ADPrincipals") -and (($objClass.toLower() -eq "user") -or ($objClass.toLower() -eq "group"))) {
                            $classMatch = $true
                        } elseif ($objClass.toLower() -eq "domainDNS") {
                            $classMatch = $true
                        }
                    } else {
                        #dn is domain root
                        $classMatch = $true
                    }
                }
                if ($classMatch) {
                    [void] $e.Node.Nodes.Add($(NewNode $childNode.Name $childNode.distinguishedName))
                    [Windows.Forms.Application]::DoEvents()
                }
            }
            $e.Node.Nodes.RemoveByKey('LoadingNode')
        }
    })

    $Connect = {
        param($NameSpace)
        if (!($objADTree.Nodes[0] -notmatch "\S")) {
            if ($NameSpace -ne $objADTree.Nodes[0]) {
                $objADTree.Nodes.Clear()
                $node = &$NewNode $NameSpace $NameSpace
                $objADTree.Nodes.Add($node)
                $objADTree.SelectedNode = $node
            }
        } else {
            $node = &$NewNode $NameSpace $NameSpace
            if (!$node) {
                $node = "EMPTY"
            }
            $objADTree.Nodes.Add($node)
            $objADTree.SelectedNode = $node
        }
    }.GetNewClosure()

    $objADForm.Add_Shown({
        if ($DomainDNS) {
            if ($DomainDNS.StartsWith('\\')) {
                $DomainDNS = $DomainDNS.Substring(2)
            }
            &$Connect $DomainDNS
        }
        $objADForm.Activate()
    }.GetNewClosure())

    $objDomainComboBox.Add_SelectedValueChanged({
        $DomainDNS = $objDomainComboBox.Items[$objDomainComboBox.SelectedIndex]
        if ($DomainDNS -ne "") {
            &$Connect $DomainDNS
        }
    }.GetNewClosure())

    $objDelegateButton.Add_Click({
        $global:ADBrowserResult.Result = "Success"
        #if ($Mode -eq "SelectADPrincipals") {
        #    $global:ADBrowserResult.AdPrincipalDNValue = ($objADTree.SelectedNode.Tag.ToString()).substring(7)
        #} elseif ($Mode -eq "SelectDelegationObject") {
        #    $global:ADBrowserResult.DelegationDNValue = $objDelegationSelectTextBox.Text
        #}
        $global:ADBrowserResult.AdPrincipalDNValue = ($objADTree.SelectedNode.Tag.ToString()).substring(7)
        $global:ADBrowserResult.DelegationDNValue = $objDelegationSelectTextBox.Text
        $objADForm.Close()
        $objADForm.dispose()
        #return $objADTree.SelectedNode.Tag
    }.GetNewClosure())

    $objSelectButton.Add_Click({
        $global:objClassFilter = "ADPrincipals"
        #Set-Variable -Scope 1 -name "objClassFilter" -Value "ADPrincipals"
        #Set-Variable -Scope 1 -name "Mode" -Value "SelectADPrincipals"

        #$objDelegationLabel.Visible = $false
        #$objDelegationSelectLabel.Visible = $false
        $objDelegateButton.Visible = $true
        $objDelegateButton.Enabled = $false
        $objDelegateButton.IsAccessible = $false
        $objSelectButton.Visible = $false
        #$global:objClassFilter = "ADPrincipals"
        $objAdBrowserLabel.Text = "Select AD principal to be delegated"
        #$objDelegationSelectLabel.Text = ($objADTree.SelectedNode.Tag.ToString()).substring(7)
        $objDelegationSelectTextBox.Text = ($objADTree.SelectedNode.Tag.ToString()).substring(7)

        $objDetailsTextBox.Text = ""
        $DomainDNS = $objDomainComboBox.Items[$objDomainComboBox.SelectedIndex]
        if ($DomainDNS -ne "") {
            &$Connect $DomainDNS
        }
    })

    $objBtnExit.Add_Click({
        $global:ADBrowserResult.Result = "Exit"
        $objADForm.Close()
        $objADForm.dispose()
    }.GetNewClosure())
#endregion

    [void]$objADForm.ShowDialog()
}
#endregion
    
######
#### main UI starts here
######

#region define app icon
    $iconBase64 = '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'
    $iconBytes = [Convert]::FromBase64String($iconBase64)
    $stream = [System.IO.MemoryStream]::new($iconBytes, 0, $iconBytes.Length)
#endregion

#region initial content load
#endregion


#Validate the build version of the jit.config file is equal or higher then the tested jit.config file version
[int]$configBuildVersion = [regex]::Match($global:config.ConfigScriptVersion, "[^\.]+$").Value

#region build UI

    #region form and form panel dimensions
        $width = 850
        $height = 490
        $Panelwidth = $Width-200
        $Panelheight = $Height-200

        $objForm = New-Object System.Windows.Forms.Form
        $objForm.Text = $Title
        $objForm.Size = New-Object System.Drawing.Size($width,$height) 
        #$objForm.AutoSize = $true
        $objForm.FormBorderStyle = "FixedDialog"
        $objForm.StartPosition = "CenterScreen"
        $objForm.MinimizeBox = $False
        $objForm.MaximizeBox = $False
        $objForm.WindowState = "Normal"
        $ObjForm.Icon = [System.Drawing.Icon]::FromHandle(([System.Drawing.Bitmap]::new($stream).GetHIcon()))
        #$objForm.BackColor = "White"
        $objForm.Font = $FontStdt
        $objForm.Topmost = $False
    #endregion

    #region InputPanel
        $objInputPanel = New-Object System.Windows.Forms.Panel
        $objInputPanel.Location = new-object System.Drawing.Point(10,20)
        $objInputPanel.size = new-object System.Drawing.Size($Panelwidth,$Panelheight) 
        #$objInputPanel.BackColor = "255,0,255"
        #$objInputPanel.BackColor = "Blue"
        $objInputPanel.Font = $FontStdt
        $objInputPanel.BorderStyle = "FixedSingle"
        $objForm.Controls.Add($objInputPanel)
    #endregion

    #region InputLabel3
        $objInputLabel3 = new-object System.Windows.Forms.Label
        $objInputLabel3.Location = new-object System.Drawing.Point(10,10) 
        $objInputLabel3.size = new-object System.Drawing.Size(170,30) 
        $objInputLabel3.Font = $FontStdt
        $objInputLabel3.Text = "Currently configured delegations:"
        $objInputLabel3.AutoSize = $true
        $objInputPanel.Controls.Add($objInputLabel3)
    #endregion

    #region Delegation SelectionList
        $objDelegationComboBox = New-Object System.Windows.Forms.ComboBox
        $objDelegationComboBox.Location  = New-Object System.Drawing.Point(10,80)
        $objDelegationComboBox.size = new-object System.Drawing.Size(($Panelwidth-30),25) 
        $objDelegationComboBox.Font = $FontStdt
        $objDelegationComboBox.AutoCompleteSource = 'ListItems'
        $objDelegationComboBox.AutoCompleteMode = 'SuggestAppend'
        #$objDelegationComboBox.DropDownStyle = 'DropDown'
        $objDelegationComboBox.DropDownStyle = 'DropDownList'
        $objInputPanel.Controls.Add($objDelegationComboBox)
    #endregion

    #region function radio buttons
        $objShowAllRB = New-Object System.Windows.Forms.RadioButton
        $objShowAllRB.Location = new-object System.Drawing.Point(10,40)
        $objShowAllRB.Font = $FontStdt
        $objShowAllRB.Text = "All delegations"
        $objShowAllRB.AutoSize = $true
        $objShowAllRB.Checked = $true

        $objShowOURB = New-Object System.Windows.Forms.RadioButton
        $objShowOURB.Location = new-object System.Drawing.Point(200,40)
        $objShowOURB.Font = $FontStdt
        $objShowOURB.Text = "OU delegations"
        $objShowOURB.AutoSize = $true

        $objShowComputerRB = New-Object System.Windows.Forms.RadioButton
        $objShowComputerRB.Location = new-object System.Drawing.Point(400,40)
        $objShowComputerRB.Font = $FontStdt
        $objShowComputerRB.Text = "Computer delegations"
        $objShowComputerRB.AutoSize = $true
        $objShowComputerRB.Checked = $false

        $objInputPanel.Controls.Add($objShowAllRB)
        $objInputPanel.Controls.Add($objShowOURB)
        $objInputPanel.Controls.Add($objShowComputerRB)
    #endregion

    #region delegation entry list
        $objDelegationPrincipalListBox = New-Object System.Windows.Forms.DataGridView 
        $objDelegationPrincipalListBox.Location = New-Object System.Drawing.Size(10,120) 
        $objDelegationPrincipalListBox.Size = New-Object System.Drawing.Size(($Panelwidth-20),150)
        $objDelegationPrincipalListBox.DefaultCellStyle.Font = "Microsoft Sans Serif, 9"
        $objDelegationPrincipalListBox.ColumnHeadersDefaultCellStyle.Font = "Microsoft Sans Serif, 9"
        $objDelegationPrincipalListBox.ColumnCount = 2
        $objDelegationPrincipalListBox.ColumnHeadersVisible = $true
        $objDelegationPrincipalListBox.SelectionMode = "FullRowSelect"
        $objDelegationPrincipalListBox.ReadOnly = $true
        $objDelegationPrincipalListBox.AllowUserToAddRows = $false
        $objDelegationPrincipalListBox.Columns[0].Name = "Principal"
        $objDelegationPrincipalListBox.Columns[1].Name = "SID"

        $objDelegationPrincipalListBox.Columns[0].Width = 250
        $objDelegationPrincipalListBox.Columns[1].Width = 335
        $objDelegationPrincipalListBox.ContextMenuStrip = $contextMenuRetrieveStrip1
        $objInputPanel.Controls.Add($objDelegationPrincipalListBox)
    #endregion

    #region context menu
        $contextMenuRetrieveStrip1 = New-Object System.Windows.Forms.ContextMenuStrip
        [System.Windows.Forms.ToolStripItem]$CxtRetrieveMnuStrip1Item1 = New-Object System.Windows.Forms.ToolStripMenuItem
        [System.Windows.Forms.ToolStripItem]$CxtRetrieveMnuStrip1Item2 = New-Object System.Windows.Forms.ToolStripMenuItem
        [System.Windows.Forms.ToolStripItem]$CxtRetrieveMnuStrip1Item3 = New-Object System.Windows.Forms.ToolStripMenuItem
        $contextMenuRetrieveStrip1.Font = $FontStdt
        $CxtRetrieveMnuStrip1Item1.Text = "Add Principal";
        $CxtRetrieveMnuStrip1Item2.Text = "Delete Principal";
        $CxtRetrieveMnuStrip1Item3.Text = "Verify Principal";
        #$CxtRetrieveMnuStrip1Item2.Enabled = $False
        #$CxtRetrieveMnuStrip1Item3.Enabled = $False
        [void]$contextMenuRetrieveStrip1.Items.Add($CxtRetrieveMnuStrip1Item1);
        [void]$contextMenuRetrieveStrip1.Items.Add($CxtRetrieveMnuStrip1Item2);
        [void]$contextMenuRetrieveStrip1.Items.Add($CxtRetrieveMnuStrip1Item3);
    #endregion

    #region Operation result text box
        $objResultTextBoxLabel = new-object System.Windows.Forms.Label
        $objResultTextBoxLabel.Location = new-object System.Drawing.Point(10,($height-170)) 
        $objResultTextBoxLabel.size = new-object System.Drawing.Size(100,25) 
        $objResultTextBoxLabel.Font = $FontStdt
        $objResultTextBoxLabel.Text = "Output log:"
        $objForm.Controls.Add($objResultTextBoxLabel)

        $objResultTextBox = New-Object System.Windows.Forms.TextBox
        $objResultTextBox.Location = New-Object System.Drawing.Point(10,($height-140))
        $objResultTextBox.Size = New-Object System.Drawing.Size(($width-200),80)
        $objResultTextBox.ReadOnly = $true 
        $objResultTextBox.Multiline = $true
        $objResultTextBox.AcceptsReturn = $true 
        $objResultTextBox.Font = $FontStdt
        $objResultTextBox.Text = ""
        $objForm.Controls.Add($objResultTextBox)
    #endregion

    #region RequestButton
        $objNewDelegationBtn = New-Object System.Windows.Forms.Button
        $objNewDelegationBtn.Location = New-Object System.Drawing.Point(($width-170),20)
        $objNewDelegationBtn.Size = New-Object System.Drawing.Size(150,30)
        $objNewDelegationBtn.Font = $FontStdt
        $objNewDelegationBtn.Text = "New Delegation"
        $objForm.Controls.Add($objNewDelegationBtn)
    #endregion

    #region RemoveButton
        $objBtnRemove = New-Object System.Windows.Forms.Button
        $objBtnRemove.Cursor = [System.Windows.Forms.Cursors]::Hand
        $objBtnRemove.Location = New-Object System.Drawing.Point(($width-170),70)
        $objBtnRemove.Size = New-Object System.Drawing.Size(150,30)
        $objBtnRemove.Font = $FontStdt
        $objBtnRemove.Text = "Remove Delegation"
        $objBtnRemove.TabIndex=0
        $objForm.Controls.Add($objBtnRemove)
    #endregion

    #region VerifyButton
        $objBtnVerify = New-Object System.Windows.Forms.Button
        $objBtnVerify.Cursor = [System.Windows.Forms.Cursors]::Hand
        $objBtnVerify.Location = New-Object System.Drawing.Point(($width-170),120)
        $objBtnVerify.Size = New-Object System.Drawing.Size(150,30)
        $objBtnVerify.Font = $FontStdt
        $objBtnVerify.Text = "Verify Delegation"
        #$objBtnVerify.Visible = $false
        #$objForm.Controls.Add($objBtnVerify)
    #endregion

    #region ViewButton
        $objBtnView = New-Object System.Windows.Forms.Button
        $objBtnView.Cursor = [System.Windows.Forms.Cursors]::Hand
        $objBtnView.Location = New-Object System.Drawing.Point(($width-170),170)
        $objBtnView.Size = New-Object System.Drawing.Size(150,30)
        $objBtnView.Font = $FontStdt
        $objBtnView.Text = "View Permissions"
        #$objBtnView.Visible = $false
        #$objForm.Controls.Add($objBtnView)
    #endregion

    #region ExitButton
        $objBtnExit = New-Object System.Windows.Forms.Button
        $objBtnExit.Cursor = [System.Windows.Forms.Cursors]::Hand
        $objBtnExit.Location = New-Object System.Drawing.Point(($width-170),($height-90))
        $objBtnExit.Size = New-Object System.Drawing.Size(150,30)
        $objBtnExit.Font = $FontStdt
        $objBtnExit.Text = "Exit"
        $objBtnExit.TabIndex=0
        $objForm.Controls.Add($objBtnExit)
    #endregion

#endregion

}

process {
#region form event handlers
    $objDelegationComboBox.Add_SelectedValueChanged({
        Load-PrincipalList -DelegationEntry $objDelegationComboBox.SelectedIndex
    })

    $ClickElementMenu=
    {
        [System.Windows.Forms.ToolStripItem]$sender = $args[0]
        [System.EventArgs]$e = $args[1]

        $PrincipalId = $objDelegationPrincipalListBox.CurrentRow.Cells.value[0]
        $PrincipalSid = $objDelegationPrincipalListBox.CurrentRow.Cells.value[1]
        Switch ($sender.Text) {
            "Add Principal" {
                Write-output $objDelegationComboBox.SelectedItem
                if (Add-Principal -DelegationDN $objDelegationComboBox.SelectedItem) {
                    $objResultTextBox.Text = "Delegation principal: $($PrincipalId)`r`nSid: $($PrincipalSid)`r`n`r`nsuccessfully added!"
                    Load-DelegationList -ReloadFullList -SelectedItem $objDelegationComboBox.SelectedIndex -Filter $Script:DelegationFilter
                    Load-PrincipalList -DelegationEntry $objDelegationComboBox.SelectedIndex
                } else {
                    $objResultTextBox.Text = "ERROR - adding failed!`r`nAD principal: $($PrincipalId)`r`nSid: $($PrincipalSid)"
                }
                Start-Sleep 4
                $objResultTextBox.Text = ""
            }
            "Delete Principal" {
                if (Delete-Principal -DelegationDN $objDelegationComboBox.SelectedItem -ADPrincipal $PrincipalId) {
                    Load-DelegationList -ReloadFullList -Filter $Script:DelegationFilter
                    Load-PrincipalList -DelegationEntry $objDelegationComboBox.SelectedIndex
                    $objResultTextBox.Text = "Delegation principal: $($PrincipalId)`r`nSid: $($PrincipalSid)`r`nsuccessfully removed!"
                } else {
                    $objResultTextBox.Text = "ERROR- Removal failed!`r`nAD principal: $($PrincipalId)`r`nSid: $($PrincipalSid)"
                }
                Start-Sleep 4
                $objResultTextBox.Text = ""
            }
            "Verify Principal" {
                if (Verify-Principal -DelegationDN $objDelegationComboBox.SelectedItem -ADPrincipal $PrincipalId -PrincipalSid $PrincipalSid) {
                    $objResultTextBox.Text = "Delegation principal $($PrincipalSid) successfully removed!"
                    Load-DelegationList -ReloadFullList -Filter $Script:DelegationFilter
                    Load-PrincipalList -DelegationEntry $objDelegationComboBox.SelectedIndex
                } else {
                    $objResultTextBox.Text = "Delegation principal $($PrincipalId) successfully validated!"
                }
                Start-Sleep 4
                $objResultTextBox.Text = ""
            }
        }
    
    }
    
    $CxtRetrieveMnuStrip1Item1.add_Click($ClickElementMenu)
    $CxtRetrieveMnuStrip1Item2.add_Click($ClickElementMenu)
    $CxtRetrieveMnuStrip1Item3.add_Click($ClickElementMenu)

    $objShowAllRB.Add_Click({
        $Script:DelegationFilter = "NoFilter"
        
        #$objDelegationPrincipalListBox.Rows.Clear()
        Load-DelegationList
        Load-PrincipalList -DelegationEntry $objDelegationComboBox.SelectedIndex
    })

    $objShowOURB.Add_Click({
        $Script:DelegationFilter = "OUsOnly"

        #$objDelegationPrincipalListBox.Rows.Clear()
        Load-DelegationList -Filter $Script:DelegationFilter
        Load-PrincipalList -DelegationEntry $objDelegationComboBox.SelectedIndex
    })

    $objShowComputerRB.Add_Click({
        $Script:DelegationFilter = "ComputersOnly"

        #$objDelegationPrincipalListBox.Rows.Clear()
        Load-DelegationList -Filter $Script:DelegationFilter
        Load-PrincipalList -DelegationEntry $objDelegationComboBox.SelectedIndex
    })

    $objDelegationPrincipalListBox.add_MouseDown({
        $sender = $args[0]
        [System.Windows.Forms.MouseEventArgs]$e= $args[1]

        if ($e.Button -eq  [System.Windows.Forms.MouseButtons]::Right)
        {
            [System.Windows.Forms.DataGridView+HitTestInfo] $hit = $objDelegationPrincipalListBox.HitTest($e.X, $e.Y);
            if ($hit.Type -eq [System.Windows.Forms.DataGridViewHitTestType]::Cell)
            {
                $objDelegationPrincipalListBox.CurrentCell = $objDelegationPrincipalListBox[$hit.ColumnIndex, $hit.RowIndex];
                $contextMenuRetrieveStrip1.Show($objDelegationPrincipalListBox, $e.X, $e.Y);
            }

        }
    })

    $objNewDelegationBtn.Add_Click({
        $result = Add-NewDelegationObject
        if ($result.Result -eq "Success") {
            $objResultTextBox.Text = "Successfully added principal: $($result.AdPrincipalDNValue)`r`nto: $($result.DelegationDNValue)"
            Load-DelegationList -ReloadFullList -SelectedItem $objDelegationComboBox.SelectedIndex -Filter $Script:DelegationFilter
            Load-PrincipalList -DelegationEntry $objDelegationComboBox.SelectedIndex
        } elseif ($result.Result -eq "Failed") {
            $objResultTextBox.Text = "ERROR - adding failed!`r`nAD principal: $($result.AdPrincipalDNValue)`r`nDelegation object: $($result.DelegationDNValue)"
        } else {
            $objResultTextBox.Text = "Operation aborded..."
        } 
        Start-Sleep 4
        $objResultTextBox.Text = ""
    })

    $objBtnRemove.Add_Click({
        $DelegationEntryDN = $objDelegationComboBox.SelectedItem
        $DelegationEntry = $Script:FilteredDelegationView[$objDelegationComboBox.SelectedIndex]
        $ret = New-ConfirmationMsgBox  -Message "Do you really want to remove delegation from:`r`n    $($DelegationEntryDN)"
        if ($ret -eq "Yes"){
            for ($i = 0; $i -lt $DelegationEntry.Accounts.Count; $i++){
                #Delete-Principal -DelegationDN $objDelegationComboBox.SelectedItem -ADPrincipal (($DelegationEntry.Accounts)[$i]) -PrincipalSid (($DelegationEntry.SID)[$i]) -IgnoreValidation
                Remove-DelegationObject -DelegationDN $objDelegationComboBox.SelectedItem
            }
            $objResultTextBox.Text = "Delegation removed from:`r`n    $($DelegationEntryDN)"
            Load-DelegationList -ReloadFullList -Filter $Script:DelegationFilter
            Load-PrincipalList -DelegationEntry $objDelegationComboBox.SelectedIndex
        } else {
            $objResultTextBox.Text = "Delegation NOT removed from:`r`n    $($DelegationEntryDN)"
        }
        Start-Sleep 4
        $objResultTextBox.Text = ""
    })

    $objBtnVerify.Add_Click({
        $script:BtnResult="Verify"
        Get-AdDelegationObjectPermissions -ObjectDN $objDelegationComboBox.SelectedItem -gMSA $global:config.GroupManagedServiceAccountName
    })

    $objBtnView.Add_Click({
        $script:BtnResult="View"
        Get-AdDelegationObjectAclView -DelegationDN $objDelegationComboBox.SelectedItem -gMSA $global:config.GroupManagedServiceAccountName -ViewOnly
    })

    $objBtnExit.Add_Click({
        $script:BtnResult="Exit"
        #Remove-Variable -Name config -Scope Global -Force
        #Remove-Variable -Name objFullDelegationList -Scope Script -Force
        $objForm.Close()
        $objForm.dispose()
        Remove-Variable -Name objClassFilter -Force
        Remove-Variable -Name ADBrowserResult -Force
        Remove-Variable -Name objFullDelegationList -Force
        Remove-Variable -Name DefaultJiTADCnfgObjectDN -Force
        Remove-Variable -Name JitCnfgObjClassName -Force
        Remove-Variable -Name JiTAdSearchbase -Force
        Remove-Variable -Name JitDelegationObjClassName -Force
    })

#endregion

#inital list population
Load-DelegationList #-ReloadFullList
Load-PrincipalList -DelegationEntry $objDelegationComboBox.SelectedIndex


[void]$objForm.Add_Shown({$objForm.Activate()})
[void]$objForm.ShowDialog()
}

end {
}

    
