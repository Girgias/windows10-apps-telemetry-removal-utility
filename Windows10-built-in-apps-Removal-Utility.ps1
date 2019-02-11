[System.Console]::Title = "Windows10 Built-In apps Removal Utility"

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
    Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
    Exit
}

$Applist = Get-AppXProvisionedPackage -online

$Applist | WHere-Object {$_.packagename -like “*3d*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*alarms*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*appinstaller*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*appconnector*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*bing*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*camera*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*comm*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*connectivitystore*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*contact support*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*feedback*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*GetHelp*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*getstarted*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*holographic*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*maps*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*mess*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*mspaint*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*officehub*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*oneconnect*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*onenote*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*people*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*phone*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*sketch*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*skypeapp*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*solitaire*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*soundrec*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*sticky*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*Sway*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*wallet*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*xbox*”} | Remove-AppxProvisionedPackage -online
$Applist | WHere-Object {$_.packagename -like “*zune*”} | Remove-AppxProvisionedPackage -online

Get-AppxPackage -AllUsers *3d* | Remove-AppxPackage
Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage
Get-AppxPackage -AllUsers *appinstaller* | Remove-AppxPackage
Get-AppxPackage -AllUsers *appconnector* | Remove-AppxPackage
Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage
Get-AppxPackage -AllUsers *camera* | Remove-AppxPackage
Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage
Get-AppxPackage -AllUsers *connectivitystore* | Remove-AppxPackage
Get-AppxPackage -AllUsers *contact support* | Remove-AppxPackage
Get-AppxPackage -AllUsers *feedback* | Remove-AppxPackage
Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage
Get-AppxPackage -AllUsers *getstarted* | Remove-AppxPackage
Get-AppxPackage -AllUsers *holographic* | Remove-AppxPackage
Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage
Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage
Get-AppxPackage -AllUsers *mspaint* | Remove-AppxPackage
Get-AppxPackage -AllUsers *officehub* | Remove-AppxPackage
Get-AppxPackage -AllUsers *oneconnect* | Remove-AppxPackage
Get-AppxPackage -AllUsers *onenote* | Remove-AppxPackage
Get-AppxPackage -AllUsers *people* | Remove-AppxPackage
Get-AppxPackage -AllUsers *phone* | Remove-AppxPackage
Get-AppxPackage -AllUsers *sketch* | Remove-AppxPackage
Get-AppxPackage -AllUsers *skypeapp* | Remove-AppxPackage
Get-AppxPackage -AllUsers *solitaire* | Remove-AppxPackage
Get-AppxPackage -AllUsers *soundrec* | Remove-AppxPackage
Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage
Get-AppxPackage -AllUsers *Sway* | Remove-AppxPackage
Get-AppxPackage -AllUsers *wallet* | Remove-AppxPackage
Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage

Get-WindowsPackage -Online | Where PackageName -like *MediaPlayer* | Remove-WindowsPackage -Online -NoRestart
Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart
Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart
Get-WindowsPackage -Online | Where PackageName -like *InternetExplorer* | Remove-WindowsPackage -Online -NoRestart

Get-AppxPackage *xbox* | Remove-AppxPackage
Get-AppxPackage *people* | Remove-AppxPackage

$Title = "Remove Photo app?"
$Info = "Do you wish to remove the built-in Photo app?"
$options = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
[int]$defaultchoice = 1
$opt = $host.UI.PromptForChoice($Title , $Info , $Options,$defaultchoice)

if ($opt -eq 0) {
    $Applist | WHere-Object {$_.packagename -like “*photo*”} | Remove-AppxProvisionedPackage -online
    Get-AppxPackage -AllUsers *photo* | Remove-AppxPackage
}


$Title = "Remove Calculator app?"
$Info = "Do you wish to remove the built-in Calculator app?"
$options = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
[int]$defaultchoice = 1
$opt = $host.UI.PromptForChoice($Title , $Info , $Options,$defaultchoice)

if ($opt -eq 0) {
    $Applist | WHere-Object {$_.packagename -like “*calc*”} | Remove-AppxProvisionedPackage -online
    Get-AppxPackage -AllUsers *calc* | Remove-AppxPackage
}

Write-Host "Press any key to exit";
Exit;