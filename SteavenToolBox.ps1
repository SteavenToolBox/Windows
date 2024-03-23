Invoke-WebRequest https://raw.githubusercontent.com/SteavenToolBox/Windows/main/SteavenToolBox.cmd -OutFile C:\windows\temp\SteavenToolBox.cmd
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
powershell.exe "C:\windows\temp\SteavenToolBox.cmd"