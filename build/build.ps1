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

.Synopsis
This script copies PowerShell files from the source directory to the release directory and updates the git repository.
.Description
    This script is designed to automate the process of preparing PowerShell files for release. It copies the necessary files from the source directory to the release directory and ensures that the git repository is updated with the latest changes.
.Author
    Andreas Lucas [MSFT]
    <https://github.com/Just-in-time-Group/Just-in-time>

#>

# Copy all files and directories from /src/powershell to /release
$ReleaseVersion = "0.1"
$source = "$PSScriptRoot/../src/powershell"
$destination = "$PSScriptRoot/../release"
Remove-Item -Path $destination\* -Recurse -Force
New-Item -Path $destination -ItemType Directory -Force
Copy-Item -Path $source\* -Destination $destination -Recurse -Force

# Update git repository
Set-Location $PSScriptRoot/..
$version = "Version $ReleaseVersion.{0}{1:D2}{2:D2}" -f (Get-Date).Year, (Get-Date).Month, (Get-Date).Day
git commit -m $version
git push origin HEAD