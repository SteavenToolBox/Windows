Set-ExecutionPolicy RemoteSigned -scope CurrentUser
scoop install git | Out-Null
scoop bucket add extras | Out-Null
Write-Output "Scoop is now installed"
scoop install sudo aria2 wget git grep | Out-Null
Write-Output "Sudo and Aria2 and Wget and Git is now installed"
Install-Module PSWindowsUpdate
Add-WUServiceManager -MicrosoftUpdate
Write-Output "Windows update CLI have been installed"