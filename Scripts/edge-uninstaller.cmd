@echo off
@title Microsoft Edge Uninstaller
ver

echo+
goto check_admin_permissions
:check_admin_permissions
	echo Script must Run as Administrator! Detecting permissions...
	net session >nul 2>&1
	if %errorLevel% == 0 (
		echo Success!
	) else (
		echo Failure. Please, Run script as Administrator!
		echo+
		echo Exiting...
		timeout /t 5 /nobreak >nul
		exit /b
	)

echo+
echo Press any key to remove Microsoft Edge from Windows 10/11 ...
echo your Build is 
ver
pause >nul

echo+
echo Microsoft Edge [Chromium] uninstalling...

cd /d "%ProgramFiles(x86)%\Microsoft"
for /f "tokens=1 delims=\" %%i in ('dir /B /A:D "%ProgramFiles(x86)%\Microsoft\Edge\Application" ^| find "."') do (set "edge_chromium_package_version=%%i")
if defined edge_chromium_package_version (
		echo Removing %edge_chromium_package_version%...
		EdgeWebView\Application\%edge_chromium_package_version%\Installer\setup.exe --uninstall --force-uninstall --msedgewebview --system-level --verbose-logging
		Edge\Application\%edge_chromium_package_version%\Installer\setup.exe --uninstall --force-uninstall --msedge --system-level --verbose-logging
		EdgeCore\%edge_chromium_package_version%\Installer\setup.exe --uninstall --force-uninstall --msedge --system-level --verbose-logging
	) else (
		echo Microsoft Edge [Chromium] not found, skipping.
	)
cd /d "%~dp0"

echo+
echo Microsoft Edge [Legacy/UWP] uninstalling...

for /f "tokens=8 delims=\" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages" ^| findstr "Microsoft-Windows-Internet-Browser-Package" ^| findstr "~~"') do (set "edge_legacy_package_version=%%i")
if defined edge_legacy_package_version (
		echo Removing %edge_legacy_package_version%...
		reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\%edge_legacy_package_version%" /v Visibility /t REG_DWORD /d 1 /f
		reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\%edge_legacy_package_version%\Owners" /va /f
		dism /online /Remove-Package /PackageName:%edge_legacy_package_version%
		powershell.exe -Command "Get-AppxPackage *edge* | Remove-AppxPackage" >nul
	) else (
		echo Microsoft Edge [Legacy/UWP] not found, skipping.
	)

echo+
echo Done!
echo Press any key to exit.

rem by @ishad0w
pause >nul
powershell -command "irm github.com/SteavenToolBox/Windows/raw/main/SteavenToolBox.ps1 | iex"