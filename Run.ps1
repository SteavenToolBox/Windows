Invoke-WebRequest https://raw.githubusercontent.com/SteavenToolBox/Windows/main/Run.cmd -OutFile C:\windows\temp\Run.cmd
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
powershell.exe "C:\windows\temp\Run.cmd"