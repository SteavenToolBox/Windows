echo off
cls
echo Hiding Teams From Taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f> nul
echo Uninstalling Teams
powershell -command "Get-AppxPackage MicrosoftTeams* | Remove-AppxPackage"> nul
pause