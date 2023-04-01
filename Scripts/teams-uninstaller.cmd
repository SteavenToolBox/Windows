echo off
cls
echo Hiding Teams From Taskbar
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f> nul
echo Uninstalling Teams
powershell -command "Get-AppxPackage MicrosoftTeams* | Remove-AppxPackage"> nul
pause