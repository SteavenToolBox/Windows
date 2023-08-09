Set-ExecutionPolicy RemoteSigned -scope CurrentUser
winget upgrade --all
choco upgrade all -y
scoop update
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll | Out-File "C:\($env.computername-Get-Date -f yyyy-MM-dd)-MSUpdates.log" -Force