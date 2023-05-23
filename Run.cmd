echo off
cls
ver | findstr /i "10\.0\.19045\." > nul && (powershell -command 'irm github.com/SteavenToolBox/Windows/raw/main/SteavenToolBox.ps1 | iex')
ver | findstr /i "6\.1\." > nul  && (powershell -command 'irm github.com/SteavenToolBox/Windows/raw/main/SteavenToolBox7.ps1 | iex')
echo "Could not detect Windows version! exiting..."
color 4F & pause & exit /B 1