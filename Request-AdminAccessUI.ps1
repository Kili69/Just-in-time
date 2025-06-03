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
#>
<#
.Synopsis
    This script provide a UI for Tier 1 JIT elevation

.DESCRIPTION
    The UI let you easily select the server on which you want to elevate your privileges

.EXAMPLE
    .\Request-AdminAccessUI.ps1

.OUTPUTS
   none
.NOTES
    Version Tracking
    2024-12-27 
    Version 0.1
        - re-worked initial version
    2025-03-27 
    Version 1.1
        - stable version


.PARAMETER configurationFile
    if specifying a dedicated config file 
.PARAMETER title
    if specifying a different windows title 
#>
Param(
    [Parameter (Mandatory=$false)]
    $Title = "Request T1 Admin Access"
)

begin {

    #region classes & styles
    ## loading .net classes needed
        add-type -a (
            'System.DirectoryServices',
            'System.DirectoryServices.AccountManagement',
            'System.Drawing',
            'System.Windows.Forms'
        )
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

        # app icon
        $iconBase64 = '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'
        $iconBytes = [Convert]::FromBase64String($iconBase64)
        $stream = [System.IO.MemoryStream]::new($iconBytes, 0, $iconBytes.Length)
        [int]$_configBuildVersion = "20241003"
    #endregion


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
    #Discover the next available Global catalog for queries
    if (!(Get-Variable GlobalCatalogServer -Scope Global -ErrorAction SilentlyContinue)) {
        Set-Variable -name GlobalCatalogServer -value ("$((Get-ADDomainController -Discover -Domain ((Get-ADForest).rootdomain) -Service GlobalCatalog).HostName):3268") -Scope Global -Option ReadOnly
    }

    function Load-T1ServerList
    {
        param(
            [Parameter(mandatory=$true)][String]$T1ServerOU,
            [Parameter(mandatory=$true)][String]$ServerDomain
        )


        $GroupNamePrefix = $global:config.AdminPreFix
        if ($global:config.EnableMultiDomainSupport) {
            $GroupNamePrefix = $GroupNamePrefix + $ServerDomain + $global:config.DomainSeparator
        }

        $T1Groups = Get-ADGroup -Filter "Name -like '*$($GroupNamePrefix)*'" -SearchBase $T1ServerOU
        $objT1ComboBox.Items.Clear()
        Foreach ($T1Group in $T1Groups) {
            [void]$objT1ComboBox.Items.Add(($T1Group.Name).Substring($GroupNamePrefix.Length))
        }

    }

    function Load-DomainList
    {
        $Domains = (Get-ADForest).Domains
        $RootDomain = (Get-ADForest).RootDomain
    
        #do we have multi domain forest and EnableMultiDomainSupport=true ?
        if (($Domains.count -gt 1) -and $global:config.EnableMultiDomainSupport) {
            Foreach ($Domain in $Domains) {
                [void]$objDomainComboBox.Items.Add($Domain)
                if ($Domain -eq $RootDomain) {
                    $DomainDefaultSelection = ($objDomainComboBox.Items.Count) - 1
                    #$DomainNetBIOSName = (Get-ADDomain -Identity $Domain).NetBIOSName
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
            #$DomainDefaultSelection = ($objDomainComboBox.Items.Count) - 1
        }
        return ($objDomainComboBox.Items.Count) - 1
    }

}

process {
    #extracting and converting the build version of the script and the configuration file
    $configFileBuildVersion = [int]([regex]::Matches($global:config.ConfigScriptVersion,"[^\.]*$")).Groups[0].Value 

    <#Validate the build version of the jit.config file is equal or higher then the tested jit.config file version
    if ($_configBuildVersion -ge $configFileBuildVersion)
    {
        New-BreakMsgBox -Message "Invalid configuration file version!`r`n`r`nAborting ..."
        Exit
    }
    #>

    #region design UI
    #region form and form panel dimensions
        $width = 450
        $height = 460
        $Panelwidth = $Width-40
        $Panelheight = $Height-230

        $objForm = New-Object System.Windows.Forms.Form
        $objForm.Text ="Request T1 Admin Access"
        $objForm.Size = New-Object System.Drawing.Size($width,$height) 
        #$objForm.AutoSize = $true
        $objForm.FormBorderStyle = "FixedDialog"
        $objForm.StartPosition = "CenterScreen"
        $objForm.MinimizeBox = $False
        $objForm.MaximizeBox = $False
        $objForm.WindowState = "Normal"
        $ObjForm.Icon = [System.Drawing.Icon]::FromHandle(([System.Drawing.Bitmap]::new($stream).GetHIcon()))
        $objForm.BackColor = "White"
        $objForm.Font = $FontStdt
        $objForm.Topmost = $False
    #endregion

    #region InputPanel
        $objInputPanel = New-Object System.Windows.Forms.Panel
        $objInputPanel.Location = new-object System.Drawing.Point(10,20)
        $objInputPanel.size = new-object System.Drawing.Size($Panelwidth,$Panelheight) 
        #$objInputPanel.BackColor = "255,0,255"
        #$objInputPanel.BackColor = "Blue"
        $objInputPanel.BorderStyle = "FixedSingle"
        $objInputPanel.Font = $FontStdt
    #endregion

    #region InputLabel1 (domains)
        $objInputLabel1 = new-object System.Windows.Forms.Label
        $objInputLabel1.Location = new-object System.Drawing.Point(10,10) 
        $objInputLabel1.size = new-object System.Drawing.Size(170,30) 
        $objInputLabel1.Font = $FontStdt
        $objInputLabel1.Text = "Select Domain:"
        $objInputLabel1.AutoSize = $true
    #endregion

    #region Domain SelectionList
        $objDomainComboBox = New-Object System.Windows.Forms.ComboBox
        $objDomainComboBox.Location  = New-Object System.Drawing.Point(10,40)
        $objDomainComboBox.size = new-object System.Drawing.Size(($Panelwidth-30),25) 
        $objDomainComboBox.Font = $FontStdt
        $objDomainComboBox.AutoCompleteSource = 'ListItems'
        $objDomainComboBox.AutoCompleteMode = 'Suggest'
        $objDomainComboBox.DropDownStyle = 'DropDownList'
    #endregion

    #region InputLabel3
        $objInputLabel3 = new-object System.Windows.Forms.Label
        $objInputLabel3.Location = new-object System.Drawing.Point(10,110) 
        $objInputLabel3.size = new-object System.Drawing.Size(170,30) 
        $objInputLabel3.Font = $FontStdt
        $objInputLabel3.Text = "Currently known T1 servers in domain:"
        $objInputLabel3.AutoSize = $true
    #endregion

    #region T1Server SelectionList
        $objT1ComboBox = New-Object System.Windows.Forms.ComboBox
        $objT1ComboBox.Location = New-Object System.Drawing.Point(10,140)
        $objT1ComboBox.size = new-object System.Drawing.Size(($Panelwidth-30),25) 
        $objT1ComboBox.Font = $FontStdt
        $objT1ComboBox.AutoCompleteSource = 'ListItems'
        $objT1ComboBox.AutoCompleteMode = 'SuggestAppend'
        $objT1ComboBox.DropDownStyle = 'DropDown'
        #$objT1ComboBox.DropDownStyle = 'DropDownList'
    #endregion

    #region InputLabel4
        $objInputLabel4 = new-object System.Windows.Forms.Label
        $objInputLabel4.Location = new-object System.Drawing.Point(10,190) 
        $objInputLabel4.size = new-object System.Drawing.Size(150,30) 
        $objInputLabel4.Font = $FontStdt
        $objInputLabel4.Text = "Elevation time (min):"
        $objInputLabel4AutoSize = $true
    #endregion

    #region InputBox1
        $objElevationTimeInputBox = New-Object System.Windows.Forms.TextBox
        $objElevationTimeInputBox.Location = New-Object System.Drawing.Point(170,185)
        $objElevationTimeInputBox.Size = New-Object System.Drawing.Size(50,30)
        $objElevationTimeInputBox.Multiline = $false
        $objElevationTimeInputBox.AcceptsReturn = $true 
        $objElevationTimeInputBox.Font = $FontStdt
        $objElevationTimeInputBox.Text = [String]$global:config.DefaultElevatedTime
    #endregion

    #region Operation result text box
        $objResultTextBoxLabel = new-object System.Windows.Forms.Label
        $objResultTextBoxLabel.Location = new-object System.Drawing.Point(10,($height-195)) 
        $objResultTextBoxLabel.size = new-object System.Drawing.Size(100,25) 
        $objResultTextBoxLabel.Font = $FontStdt
        $objResultTextBoxLabel.Text = "Output log:"

        $objResultTextBox = New-Object System.Windows.Forms.TextBox
        $objResultTextBox.Location = New-Object System.Drawing.Point(10,($height-170))
        $objResultTextBox.Size = New-Object System.Drawing.Size(($width-40),80)
        $objResultTextBox.Font = $FontStdt
        $objResultTextBox.ReadOnly = $true 
        $objResultTextBox.Multiline = $true
        $objResultTextBox.AcceptsReturn = $true 
        $objResultTextBox.Text = ""
    #endregion

    #region RequestButton
        $objRequestAccessButton = New-Object System.Windows.Forms.Button
        $objRequestAccessButton.Location = New-Object System.Drawing.Point(10,($height-80))
        $objRequestAccessButton.Size = New-Object System.Drawing.Size(150,30)
        $objRequestAccessButton.Font = $FontStdt
        $objRequestAccessButton.Text = "Request Access"
    #endregion

    #region ExitButton
        $objBtnExit = New-Object System.Windows.Forms.Button
        $objBtnExit.Cursor = [System.Windows.Forms.Cursors]::Hand
        $objBtnExit.Location = New-Object System.Drawing.Point(((($width/4)*3)-40),($height-80))
        $objBtnExit.Size = New-Object System.Drawing.Size(80,30)
        $objBtnExit.Font = $FontStdt
        $objBtnExit.Text = "Exit"
        $objBtnExit.TabIndex=0
    #endregion

    #region form event handler
        $objDomainComboBox.Add_SelectedValueChanged({
            $DomainSelection = $objDomainComboBox.Items[$objDomainComboBox.SelectedIndex]
            Load-T1ServerList -T1ServerOU $global:config.OU -ServerDomain $DomainSelection
        })

        $objElevationTimeInputBox.Add_TextChanged({
            if ($this.Text -match '[^0-9]') {
                $cursorPos = $this.SelectionStart
                $this.Text = $this.Text -replace '[^0-9]',''
                # move the cursor to the end of the text:
                # $this.SelectionStart = $this.Text.Length

                # or leave the cursor where it was before the replace
                $this.SelectionStart = $cursorPos - 1
                $this.SelectionLength = 0
            }
        })

        $objRequestAccessButton.Add_Click({
            if ($objT1ComboBox.selectedItem) {
                $objResultTextBox.Text = $objT1ComboBox.selectedItem
                $ElevationTime = [Int]$objElevationTimeInputBox.Text
                if (($ElevationTime -lt 15) -or ($ElevationTime -gt $global:config.MaxElevatedTime)) {
                    New-WarningMsgBox -Message ("Elevation time must be between 15 and "+[String]$global:config.MaxElevatedTime+" minutes")
                } else {
                    #assuming access is allowed
                    $AccessAllowed = $true
                    $ServerName = $objT1ComboBox.SelectedItem
                    if (!$global:config.EnableMultiDomainSupport) {    #in single domain mode local domain name will be used
                        #$ServerNBDomain = [__ComObject].InvokeMember('DomainShortName', 'GetProperty', $null, (New-Object -ComObject ADSystemInfo), $null)
                        $ServerDomain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).name
                        $ServerName = $ServerDomain+"\"+$ServerName
                    } else {
                        $DomainSelection = $objDomainComboBox.Items[$objDomainComboBox.SelectedIndex]
                        $ServerName = $DomainSelection+"\"+$ServerName
                    }
                    $ElevationMinutes = ([int]$objElevationTimeInputBox.Text)
                    if ($AccessAllowed) {
    #                    $objResultTextBox.Text = ("Requesting elevation for:`r`n  Server   : "+$ServerName+`
    #                        "`r`n  Domain: "+[String](Get-ADDomain).DNSroot+"`r`n  Time     : "+$objElevationTimeInputBox.Text)
                        $objResultTextBox.Text = ("Requesting elevation for:`r`n  Server   : "+$ServerName+`
                            "`r`n  Domain: "+$DomainSelection+"`r`n  Time     : "+$objElevationTimeInputBox.Text)
                        Start-Sleep -Seconds 3
                        #$result = RequestElevation -ServerDomain $objDomainComboBox.SelectedItem -ServerName $objT1ComboBox.selectedItem -ElevatedMinutes ([Int]$objElevationTimeInputBox.Text)
                        $result = New-AdminRequest -Server $ServerName -Minutes $ElevationMinutes -UIused $true
                        $objResultTextBox.Text = $result
                    } else {
                        $objResultTextBox.Text = "Elevated access to $($objT1ComboBox.selectedItem) is denied!"
                    }
                    Start-Sleep -Seconds 8
                    $objElevationTimeInputBox.Text = [String]$global:config.DefaultElevatedTime
                    $objResultTextBox.Text = ""
                }
            } else {
                $objResultTextBox.ForeColor = $FailureFontColor
                New-WarningMsgBox -Message "No server selected..."
            }
        })

        $objBtnExit.Add_Click({
            $script:BtnResult="Exit"
            #Remove-Variable -Name config -Scope Global
            #Remove-Variable -Name objFullDelegationList -Scope Script
            $objForm.Close()
            $objForm.dispose()
        })
    #endregion

    #endregion

    #region build form
        #Input panel
        $objInputPanel.Controls.Add($objInputLabel1)
        $objInputPanel.Controls.Add($objDomainComboBox)
        $objInputPanel.Controls.Add($objInputLabel3)
        $objInputPanel.Controls.Add($objT1ComboBox)
        $objInputPanel.Controls.Add($objInputLabel4)
        $objInputPanel.Controls.Add($objElevationTimeInputBox)
        #main form
        $objForm.Controls.Add($objInputPanel)
        $objForm.Controls.Add($objResultTextBoxLabel)
        $objForm.Controls.Add($objResultTextBox)
        $objForm.Controls.Add($objRequestAccessButton)
        $objForm.Controls.Add($objBtnExit)
    #endregion

    #region initial form population

        #load domain list into DomainComboBox - initial list will not change until tools is restarted
        $objDomainComboBox.SelectedIndex = Load-DomainList

        #inital T1 server list population
        Load-T1ServerList -T1ServerOU $global:config.OU -ServerDomain $objDomainComboBox.SelectedItem

    #endregion

    $objForm.Add_Shown({$objForm.Activate()})
    [void]$objForm.ShowDialog()

}

end {
}
    
