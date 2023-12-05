@echo off
cls
call :IsAdmin
echo off
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f
:prestart
cls
color c
echo ---------------------------------------------------------------------------------------------------------------------                                    
echo 1. Install Runtime
echo 2. Start Toolbox
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' powershell.exe "iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/SteavenToolBox/Windows/main/Scripts/runtime.ps1'))"
if '%choice%'=='2' goto start
echo "%choice%" is not valid, try again
echo.
goto prestart
:start
title SteavenToolbox
cls
color b
echo =======================================================================
echo "SteavenToolbox | We care about your pc!" "Windows 10 and Windows 11!"
echo =======================================================================
echo ---------------------------------------------------------------------------------------------------------------------                                    
echo 1. Optmize windows
echo 2. Update All Installed Apps To Thair Lastest Versions
echo 3. Install Features, Programs and Apps
echo 4. Windows Update Fix 
echo 5. Crack Windows and Office (Use it at your own Risk)
echo 6. Uninstall Apps
echo 7. Repair Windows
echo 0. Go Back
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' goto optmizewindows
if '%choice%'=='2' powershell.exe "iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/SteavenToolBox/Windows/main/Scripts/update.ps1'))"
if '%choice%'=='3' goto installapps
if '%choice%'=='4' goto updatefix
if '%choice%'=='5' goto crack
if '%choice%'=='6' goto uninstall
if '%choice%'=='7' sfc /scannow && DISM /Online /Cleanup-Image /RestoreHealth && sfc /scannow && goto start
if '%choice%'=='0' goto prestart
echo "%choice%" is not valid, try again
echo.
goto start

:uninstall
cls
echo ---------------------------------------------------------------------------------------------------------------------                                    
echo 1. Uninstall Edge
echo 2. Uninstall Edge FULLY (cant reinstall edge after that)
echo 3. Uninstall OneDrive
echo 4. Uninstall Microsoft Teams
echo 5. Uninstall Windows Media Player (Legacay)
echo 6. Uninstall Cortana
echo 0. Go back
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' powershell -command "Invoke-WebRequest https://github.com/SteavenToolBox/Windows/raw/main/Scripts/edge-uninstaller.cmd -OutFile C:\windows\temp\edge-uninstaller.cmd" && powershell.exe -command "C:\windows\temp\edge-uninstaller.cmd"
if '%choice%'=='2' powershell -command "Invoke-WebRequest https://github.com/SteavenToolBox/Windows/raw/main/Scripts/edge-uninstaller-cant.cmd -OutFile C:\windows\temp\edge-uninstaller-cant.cmd" && powershell.exe -command "C:\windows\temp\edge-uninstaller-cant.cmd"
if '%choice%'=='3' powershell -command "Invoke-WebRequest https://github.com/SteavenToolBox/Windows/raw/main/Scripts/onedrive-uninstaller.cmd -OutFile C:\windows\temp\onedrive-uninstaller.cmd" && powershell.exe -command "C:\windows\temp\onedrive-uninstaller.cmd"
if '%choice%'=='4' powershell -command "Invoke-WebRequest https://github.com/SteavenToolBox/Windows/raw/main/Scripts/teams-uninstaller.cmd -OutFile C:\windows\temp\teams-uninstaller.cmd" && powershell.exe -command "C:\windows\temp\teams-uninstaller.cmd"
if '%choice%'=='5' powershell -command "Invoke-WebRequest https://github.com/SteavenToolBox/Windows/raw/main/Scripts/windows-media-player-legacay-uninstaller.cmd -OutFile C:\windows\temp\windows-media-player-legacay-uninstaller.cmd" && powershell.exe -command "C:\windows\temp\windows-media-player-legacay-uninstaller.cmd"
if '%choice%'=='6' powershell -command "Invoke-WebRequest https://github.com/SteavenToolBox/Windows/raw/main/Scripts/cortana-uninstaller.cmd -OutFile C:\windows\temp\cortana-uninstaller.cmd" && powershell.exe -command "C:\windows\temp\cortana-uninstaller.cmd"
if '%choice%'=='0' goto start
echo "%choice%" is not valid, try again
echo.
goto start
:optmizewindows
cls
color b
echo ---------------------------------------------------------------------------------------------------------------------
echo Desktop Vs Laptop vs 3
echo Laptop have Power Thrttling enabled while Desktop have it disabled 
echo Laptop Have automatic Maps updates enabled
echo Laptop Have Maps while Desktop have it Uninstalled 
echo 3 Bascily dont have any of this
echo Optmize Windows
echo 1. Desktop
echo 2. Laptop
echo 3. Without Laptop OR Desktop spifice Tweaks
echo 4. Chris Titus Tech Optmize Windows (Recommaded)
echo 0. Go back
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' goto optmizedesktop && goto optmize
if '%choice%'=='2' goto optmizelaptop && goto optmize
if '%choice%'=='3' cls && goto optmize && goto optmizewindows
if '%choice%'=='4' powershell -command "irm christitus.com/win | iex"
if '%choice%'=='0' goto start
echo "%choice%" is not valid, try again
echo.
goto optmizewindows
:optmizedesktop
cls
echo Disabling Power Thrttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "0" /f> nul
echo Disabling automatic Maps updates...
reg add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d "0" /f> nul
echo Uninstalling Maps app
powershell -command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"> nul
:optmizelaptop
cls
echo Enabling Power Thrttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f> nul
echo Installing Maps app
winget install --id 9WZDNCRDTBVB
echo Enabling automatic Maps updates...
reg add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d "1" /f> nul
:optmize
echo Hiding Teams Icon From Taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f> nul
echo Disabling Telemetry...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f> nul
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable> nul
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable> nul
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable> nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable> nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable> nul
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable> nul
echo Disabling Wi-Fi Sense...
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Wifi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Wifi\AllowWiFiHotSpotReporting" /v "Value" /t REG_DWORD /d "0" /f> nul
echo Disabling Application suggestions...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f> nul
echo Disabling Activity History...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f> nul
echo Disabling Location Tracking...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f> nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d "0" /f> nul
echo Disabling Feedback...
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f> nul
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable> nul
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable> nul
echo Uninstalling Feedback Hub
powershell -command "Get-AppxPackage *WindowsFeedbackHub* | Remove-AppxPackage"> nul
echo Disabling Advertising ID...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f> nul
echo Disabling Error reporting...
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f> nul
echo Restricting Windows Update P2P only to local network...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "1" /f> nul
echo Stopping and disabling Diagnostics Tracking Service...
sc stop DiagTrack> nul
sc config "DiagTrack" start=disabled> nul
echo Stopping and disabling WAP Push Service...
sc stop dmwappushservice> nul
sc config "dmwappushservice" start=disabled> nul
echo Enabling F8 boot menu options...
bcdedit /set {current} bootmenupolicy Legacy> nul
echo Stopping and disabling Home Groups services...
sc stop HomeGroupListener> nul
sc config "HomeGroupListener" start=disabled> nul
sc stop HomeGroupProvider> nul
sc config "HomeGroupProvider" start=disabled> nul
echo Disabling Remote Assistance...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f> nul
echo Enabling Hibernation...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HibernteEnabled" /t REG_DWORD /d "1" /f> nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowHibernateOption" /t REG_DWORD /d "1" /f> nul
echo Showing file operations details...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d "1" /f> nul
echo Hiding Cortana Button...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f> nul
echo Hiding Task View button...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f> nul
echo Hiding People icon...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d "0" /f> nul
echo Hide tray icons...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "1" /f> nul
echo Enabling NumLock after startup...
reg add "HKU\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_DWORD /d "558319670" /f> nul
echo Changing default Explorer view to This PC...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f> nul
echo Using regedit to improve RAM 
echo Making System Responsiveness Better using regedit
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f> nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "20" /f> nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_DWORD /d "2000" /f> nul
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f> nul
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f> nul
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f> nul
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f> nul
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f> nul
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f> nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f> nul
pause
goto optmizewindows
:installapps
cls
color b
echo ---------------------------------------------------------------------------------------------------------------------
echo 1. Browsers
echo 2. 7zip
echo 3. Winrar
echo 4. VLC
echo 5. Full Runtime
echo 6. Install Windows Subsystem for Linux
echo 7. Resoure Hacker
echo 8. Process Hacker
echo 0. Go back
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' goto browsers
if '%choice%'=='2' winget install -e --id 7zip.7zip
if '%choice%'=='3' winget install -e --id RARLab.WinRAR
if '%choice%'=='4' winget install -e --id VideoLAN.VLC
if '%choice%'=='5' choco install vcredist2005 vcredist2008 vcredist2010  vcredist2012 msvisualcplusplus2012-redist vcredist2013 vcredist2017 vcredist140 vcredist-all adoptopenjdk8openj9jre adoptopenjdk11openj9jre directx netfx-4.8.1 -y & DISM /Online /Enable-Feature /FeatureName:NetFx3 & dism /Online /enable-feature /FeatureName:"LegacyComponents" /All & dism /Online /enable-feature /FeatureName:"DirectPlay" /All
if '%choice%'=='6' wsl --install
if '%choice%'=='7' winget install --id=AngusJohnson.ResourceHacker  -e
if '%choice%'=='8' choco install processhacker -y
if '%choice%'=='0' goto start
echo "%choice%" is not valid, try again
echo.
goto installapps
:browsers
cls
color b
echo ---------------------------------------------------------------------------------------------------------------------
echo 1. Firefox
echo 2. Chrome
echo 3. Brave
echo 4. Chromium
echo 5. Edge (If you removed it before it may faill to reinstall)
echo 0. Go back
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' winget install -e --id Mozilla.Firefox
if '%choice%'=='2' winget install -e --id Google.Chrome
if '%choice%'=='3' winget install -e --id BraveSoftware.BraveBrowser
if '%choice%'=='4' winget install -e --id eloston.ungoogled-chromium
if '%choice%'=='5' winget install -e --id Microsoft.Edge
if '%choice%'=='0' goto installapps
echo "%choice%" is not valid, try again
echo.
goto installapps
:updatefix
cls
color 9
echo ---------------------------------------------------------------------------------------------------------------------
echo 0. Go Back
echo ---------------------------------------------------------------------------------------------------------------------
echo 1. Get Windows 11 on unsupported devices!
echo ---------------------------------------------------------------------------------------------------------------------
echo Chose your build that you are in right now
echo That will make you never upgrade to newer build that mean stable pc stable performace!
echo 2. 22H2 (Works on Windows 11)
echo 3. 21h2 (Works on Windows 11)
echo 4. 21h1
echo 5. 20h2 (2009)
echo 6. 20h1 (2004)
echo 7. 19h2 (1909)
echo 8. 19h1 (1903)
echo 9. 1809
echo 10. 1607
echo 11. Undo
echo ---------------------------------------------------------------------------------------------------------------------
echo Chose If you want to not get non security and security updates or security updates only!
echo Note: this wont remove the frist setting
echo 12. Security Updates only
echo 13. Security and non
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' powershell -command "Invoke-WebRequest https://github.com/AveYo/MediaCreationTool.bat/raw/main/bypass11/Skip_TPM_Check_on_Dynamic_Update.cmd -OutFile C:\windows\temp\bypass11.cmd" && powershell.exe -command "C:\windows\temp\bypass11.cmd"
if '%choice%'=='2' reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersion /t REG_DWORD /d 1 & reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersionInfo /t REG_SZ /d 22h2
if '%choice%'=='3' reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersion /t REG_DWORD /d 1 & reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersionInfo /t REG_SZ /d 21h2
if '%choice%'=='4' reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersion /t REG_DWORD /d 1 & reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersionInfo /t REG_SZ /d 21h1
if '%choice%'=='5' reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersion /t REG_DWORD /d 1 & reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersionInfo /t REG_SZ /d 20h2
if '%choice%'=='6' reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersion /t REG_DWORD /d 1 & reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersionInfo /t REG_SZ /d 2004
if '%choice%'=='7' reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersion /t REG_DWORD /d 1 & reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersionInfo /t REG_SZ /d 1903
if '%choice%'=='8' reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersion /t REG_DWORD /d 1 & reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersionInfo /t REG_SZ /d 1903
if '%choice%'=='9' reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersion /t REG_DWORD /d 1 & reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersionInfo /t REG_SZ /d 1809
if '%choice%'=='10' reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersion /t REG_DWORD /d 1 & reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersionInfo /t REG_SZ /d 1607
if '%choice%'=='11' reg delete  HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v TargetReleaseVersion /f & reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v TargetReleaseVersionInfo /f
if '%choice%'=='12' reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" /t REG_DWORD /d "0" /f & reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d "869" /f & reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "DeferQualityUpdatesPeriodInDays" /t REG_DWORD /d "4" /f & reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "BranchReadinessLevel" /t REG_DWORD /d "32" /f
if '%choice%'=='13' reg delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" /f & reg delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "DeferFeatureUpdatesPeriodInDays" /f & reg delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "DeferQualityUpdatesPeriodInDays" /f & reg delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "BranchReadinessLevel" /f
if '%choice%'=='0' goto start
echo "%choice%" is not valid, try again
echo.
goto updatefix
:crack
cls
echo 1. Crack Windows and Office
echo 0. Go Back
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' powershell -command "irm https://massgrave.dev/get | iex"
if '%choice%'=='0' goto start
echo "%choice%" is not valid, try again
echo.
goto start

:IsAdmin
reg query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & echo You must have administrator rights to continue ... 
 Pause & Exit
)
Cls
goto:eof
pause
goto :start