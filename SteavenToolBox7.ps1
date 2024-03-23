Invoke-WebRequest https://raw.githubusercontent.com/SteavenToolBox/Windows/main/SteavenToolBox7.cmd -OutFile C:\windows\temp\SteavenToolBox7.cmd
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
powershell.exe "C:\windows\temp\SteavenToolBox7.cmd"