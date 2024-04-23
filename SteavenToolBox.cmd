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
echo 4. Uninstall appx Blot
echo 5. Uninstall legecy Blot
echo 6. Tweak Optinal Features
echo 7. Chris Titus Tech Optmize Windows (Recommaded)
echo 0. Go back
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' goto optmizedesktop
if '%choice%'=='2' goto optmizelaptop
if '%choice%'=='3' cls && goto optmize && goto optmizewindows
if '%choice%'=='4' goto appxdebloat
if '%choice%'=='5' goto legecyblot
if '%choice%'=='6' goto optionalfaetures
if '%choice%'=='7' powershell -command "irm christitus.com/win | iex"
if '%choice%'=='0' goto start
echo "%choice%" is not valid, try again
echo.
goto optmizewindows
:legecyblot
cls
echo Uninstalling Snipping Tool
"C:\Windows\System32\SnippingTool.exe" /uninstall> nul
pause
goto optmizewindows
:optionalfaetures
cls
powershell -command "Disable-WindowsOptionalFeature -Online -FeatureName Printing-XPSServices-Features -NoRestart"
powershell -command "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart"
powershell -command "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"
powershell -command "Disable-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -NoRestart"
powershell -command "Enable-WindowsOptionalFeature -Online -FeatureName LegacyComponents -NoRestart"
powershell -command "Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -NoRestart"
powershell -command "Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -NoRestart"
pause
goto optmizewindows
:appxdebloat
cls
echo Uninstalling Pepole
powershell -command "Get-AppxPackage Microsoft.People* | Remove-AppxPackage"
echo Uninstalling Bing News
powershell -command "Get-AppxPackage Microsoft.BingNews*  | Remove-AppxPackage"
echo Uninstalling Bing Sports
powershell -command "Get-AppxPackage *bingsports* | Remove-AppxPackage"
echo Uninstalling Bing Search
powershell -command "Get-AppxPackage Microsoft.BingSearch* | Remove-AppxPackage"
echo Uninstalling Bing Weather
powershell -command "Get-AppxPackage Microsoft.BingWeather* | Remove-AppxPackage"
echo Uninstalling Movies and TV
powershell -command "Get-AppxPackage *zunevideo* | Remove-AppxPackage"
echo Uninstalling OneNote
powershell -command "Get-AppxPackage *onenote* | Remove-AppxPackage"
echo Uninstalling windowscommunicationsapps
powershell -command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
echo Uninstalling Cortana
powershell -command "Get-AppxPackage Microsoft.549981C3F5F10 | Remove-AppxPackage"
echo Uninstalling Bing Sports
powershell -command "Get-AppxPackage Microsoft.BingSports* | Remove-AppxPackage"
echo Uninstalling Movies and TV
powershell -command "Get-AppxPackage Microsoft.ZuneVideo* | Remove-AppxPackage"
echo Uninstalling OneNote
powershell -command "Get-AppxPackage Microsoft.Office.OneNote* | Remove-AppxPackage"
echo Uninstalling Music
powershell -command "Get-AppxPackage Microsoft.ZuneMusic* | Remove-AppxPackage"
echo Uninstalling Skype
powershell -command "Get-AppxPackage Microsoft.SkypeApp* | Remove-AppxPackage"
echo Uninstalling Microsoft Solitaire Collection
powershell -command "Get-AppxPackage Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage"
echo Uninstalling Sticky Notes
powershell -command "Get-AppxPackage Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"
echo Uninstalling Windows Alarms
powershell -command "Get-AppxPackage Microsoft.WindowsAlarms* | Remove-AppxPackage"
echo Uninstalling Windows Feedback Hub
powershell -command "Get-AppxPackage Microsoft.WindowsFeedbackHub* | Remove-AppxPackage"
echo Uninstalling Windows Sound Recorder
powershell -command "Get-AppxPackage Microsoft.WindowsSoundRecorder* | Remove-AppxPackage"
echo Uninstalling Windows Calender
powershell -command "Get-AppxPackage Microsoft.Windows.Calendar* | Remove-AppxPackage"
echo Uninstalling Todo
powershell -command "Get-AppxPackage Microsoft.ToDo* | Remove-AppxPackage"
echo Uninstalling Word
powershell -command "Get-AppxPackage Microsoft.Office.Word* | Remove-AppxPackage"
echo Uninstalling Excel
powershell -command "Get-AppxPackage Microsoft.Office.Excel* | Remove-AppxPackage"
echo Uninstalling PowerPoint
powershell -command "Get-AppxPackage Microsoft.Office.PowerPoint* | Remove-AppxPackage"
echo Uninstalling Outlook
powershell -command "Get-AppxPackage Microsoft.Office.Outlook* | Remove-AppxPackage"
echo Uninstalling Mixed Reality Portal
powershell -command "Get-AppxPackage Microsoft.MixedReality.Portal* | Remove-AppxPackage"
echo Uninstalling Microsoft News
powershell -command "Get-AppxPackage Microsoft.MicrosoftNews* | Remove-AppxPackage"
echo Uninstalling Get Help
powershell -command "Get-AppxPackage Microsoft.GetHelp* | Remove-AppxPackage"
echo Uninstalling MsPaint
powershell -command "Get-AppxPackage Microsoft.MSPaint* | Remove-AppxPackage"
echo Uninstalling Office
powershell -command "Get-AppxPackage Microsoft.Office.* | Remove-AppxPackage"
echo Uninstalling Your Phone
powershell -command "Get-AppxPackage Microsoft.YourPhone* | Remove-AppxPackage"
echo Uninstalling Print to pdf
powershell -command "Get-AppxPackage Microsoft.MicrosoftPrinttoPDF* | Remove-AppxPackage"
echo Uninstalling Skydrive
powershell -command "Get-AppxPackage Microsoft.SkyDrive* | Remove-AppxPackage"
echo Uninstalling Clipchamp
powershell -command "Get-AppxPackage Clipchamp.Clipchamp* | Remove-AppxPackage"
echo Uninstalling DevHome
powershell -command "Get-AppxPackage Microsoft.Windows.DevHome* | Remove-AppxPackage"
echo Uninstalling Maps
powershell -command "Get-AppxPackage Microsoft.WindowsMaps* | Remove-AppxPackage"
echo Uninstalling Office Hub
powershell -command "Get-AppxPackage Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage"
echo Uninstalling Microsoft Teams
powershell -command "Get-AppxPackage MSTeams* | Remove-AppxPackage"
echo Uninstalling Screen Sketch
powershell -command "Get-AppxPackage Microsoft.ScreenSketch* | Remove-AppxPackage"
echo Uninstalling Outlook
powershell -command "Get-AppxPackage Microsoft.OutlookForWindows* | Remove-AppxPackage"
echo Uninstalling Quick Assist
powershell -command "Get-AppxPackage MicrosoftCorporationII.QuickAssist* | Remove-AppxPackage"
echo Uninstalling Getstarted
powershell -command "Get-AppxPackage Microsoft.Getstarted* | Remove-AppxPackage"
echo Uninstalling PowerAutomate
powershell -command "Get-AppxPackage Microsoft.PowerAutomate* | Remove-AppxPackage"
echo Uninstalling Copilot
powershell -command "Get-AppxPackage *Windows.Ai.Copilot.Provider* | Remove-AppxPackage"
pause
goto optmizewindows
:optmizedesktop
cls
echo Disabling Power Thrttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "0" /f> nul
echo Disabling automatic Maps updates...
reg add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d "0" /f> nul
echo Uninstalling Maps app
powershell -command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"> nul
goto optmize
:optmizelaptop
cls
echo Enabling Power Thrttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f> nul
echo Installing Maps app
winget install --id 9WZDNCRDTBVB
echo Enabling automatic Maps updates...
reg add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d "1" /f> nul
goto optmize
:optmize
echo Disabling Web Search and Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f> nul
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f> nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f> nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f> nul
echo Hiding Cortana From Taskbar
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f> nul
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
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "1" /f> nul
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f> nul
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f> nul
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "400" /f> nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f> nul
echo Winaero Tweaker regedit 
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f> nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f> nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 0 /f> nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f> nul
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SoftLandingEnabled /t REG_DWORD /d 0 /f> nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f> nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f> nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f> nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo /v Enabled /t REG_DWORD /d 0 /f> nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f> nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f> nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f> nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v "SubscribedContent-314563Enabled" /t REG_DWORD /d 0 /f> nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v EnablePeriodicBackup /t REG_DWORD /d 1 /f> nul
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer /v link /t REG_BINARY /d 00000000 /f> nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input\Settings" /v EnableExpressiveInputShellHotkey /t REG_DWORD /d 1 /f> nul
echo More Tweaks
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d 1 /f> nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d 1 /f> nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 1 /f> nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f> nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f> nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 0 /f> nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Ndu" /v "Start" /t REG_DWORD /d 2 /f> nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d 30 /f> nul
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d 0 /f> nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d 2 /f> nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f> nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f> nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f> nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f> nul
echo Disabling sound for Sticky Keys, Toggle Keys, and Filter Keys
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "SOUND" /t REG_SZ /d "" /f> nul
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "SOUND" /t REG_SZ /d "" /f> nul
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "SOUND" /t REG_SZ /d "" /f> nul
echo Disabling warning messages for Sticky Keys, Toggle Keys, and Filter Keys
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Warning" /t REG_SZ /d "0" /f> nul
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Warning" /t REG_SZ /d "0" /f> nul
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Warning" /t REG_SZ /d "0" /f> nul
echo Disabling mouse acceleration
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f> nul
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f> nul
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f> nul
echo Enabling pointer shadow
reg add "HKCU\Control Panel\Mouse" /v "MouseShadow" /t REG_DWORD /d "1" /f> nul
echo Disabling showing frequently used folders in Quick Access
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f> nul
echo Showing hidden files in File Explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f> nul
echo Showing file extensions for unknown file types
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f> nul
echo Seting Windows Explorer to launch folders in a separate process
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d "1" /f> nul
echo Enabling check boxes for file and folder selection in File Explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "CheckFileExtensions" /t REG_DWORD /d "1" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoCheckSelect" /t REG_DWORD /d "1" /f> nul
echo Showing all folders and libraries in File Explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d "1" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowLibraries" /t REG_DWORD /d "1" /f> nul
echo Seting indexing options to index the entire C: drive
reg add "HKLM\SOFTWARE\Microsoft\Windows Search\CrawlScopeManager\Windows\SystemIndex\DefaultRules" /v "{0}" /t REG_SZ /d "{1}" /f> nul
reg add "HKLM\SOFTWARE\Microsoft\Windows Search\CrawlScopeManager\Windows\SystemIndex\DefaultRules" /v "{1}" /t REG_DWORD /d 1 /f> nul
echo more tweaks
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f> nul
reg add "HKCU\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 1 /f> nul
echo Tweaking Desktop Icons
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideIcons /t REG_DWORD /d 0 /f> nul
reg add "HKCU\Software\Microsoft\Windows\Shell\Bags\1\Desktop" /v "AutoArrange" /t REG_SZ /d "1" /f> nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /V FFLAGS /T REG_DWORD /D 1075839525 /F> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /t REG_DWORD /d 0 /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /t REG_DWORD /d 0 /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v {59031a47-3f72-44a7-89c5-5595fe6b30ee} /t REG_DWORD /d 0 /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v {59031a47-3f72-44a7-89c5-5595fe6b30ee} /t REG_DWORD /d 0 /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v {F02C1A0D-BE21-4350-88B0-7367FC96EF3C} /t REG_DWORD /d 0 /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v {F02C1A0D-BE21-4350-88B0-7367FC96EF3C} /t REG_DWORD /d 0 /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v {5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0} /t REG_DWORD /d 0 /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v {5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0} /t REG_DWORD /d 0 /f> nul
echo seting dark mode
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize /v AppsUseLightTheme /t REG_DWORD /d 0 /f> nul
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize /v SystemUsesLightTheme /t REG_DWORD /d 0 /f> nul
echo tweaks releated to windows 11
echo enabling end task in taskbar
reg add  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v "TaskbarEndTask" /t REG_DWORD /d 1 /f> nul
echo disabling news
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f> nul
echo disabling Windows Copilot
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f> nul
echo making taskbar at left as windows 10 as it should be
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f> nul
echo making old right click menus default as windows 10 as it should be
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /d "" /f> nul
pause
goto optmizewindows
:installapps
cls
color b
echo ---------------------------------------------------------------------------------------------------------------------
echo 1. Full Runtime
echo 2. Web Browsers
echo 3. Zip Programs
echo 4. Media Programs
echo 5. Chat Programs
echo 6. Games 
echo 7. Install Windows Subsystem for Linux
echo 8. Resoure Hacker
echo 9. Process Hacker
echo 10. Kde Connect
echo 11. Nilesoft Shell
echo 12. Windows Terminal
echo 13. Starship
echo 14. yt-dlp
echo 15. WingetUi
echo 16. Intel Support Assistant
echo 17. Hp Smart
echo 18. NextCloud Desktop
echo 19. OBS Studio
echo 20. Kdenlive
echo 21. GIMP (Stable)
echo 22. GIMP (Nightly)
echo 23. Krita
echo 24. Visual Studio 2022 Community
echo 25. Visual Studio Code
echo 26. Github Desktop
echo 27. Ubuntu 22.04 Wsl
echo 28. Martinrotter RSSGuard
echo 0. Go back
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' choco install vcredist2005 vcredist2008 vcredist2010  vcredist2012 msvisualcplusplus2012-redist vcredist2013 vcredist2017 vcredist140 vcredist-all adoptopenjdk8openj9jre adoptopenjdk11openj9jre directx netfx-4.8.1 -y & DISM /Online /Enable-Feature /FeatureName:NetFx3 & dism /Online /enable-feature /FeatureName:"LegacyComponents" /All & dism /Online /enable-feature /FeatureName:"DirectPlay" /All
if '%choice%'=='2' goto browsers
if '%choice%'=='3' goto zipprogrames
if '%choice%'=='4' goto mediaprogrames
if '%choice%'=='5' goto chatprograms
if '%choice%'=='6' goto gamesprograms
if '%choice%'=='7' wsl --install
if '%choice%'=='8' winget install --id=AngusJohnson.ResourceHacker  -e
if '%choice%'=='9' choco install processhacker -y
if '%choice%'=='10' winget install -e --id 9N93MRMSXBF0
if '%choice%'=='11' winget install -e --id Nilesoft.Shell
if '%choice%'=='12' winget install -e --id Microsoft.WindowsTerminal
if '%choice%'=='13' winget install -e --id Starship.Starship
if '%choice%'=='14' winget install -e --id yt-dlp.yt-dlp
if '%choice%'=='15' winget install -e --id SomePythonThings.WingetUIStore
if '%choice%'=='16' winget install -e --id Intel.IntelDriverAndSupportAssistant
if '%choice%'=='17' winget install -e --id 9WZDNCRFHWLH
if '%choice%'=='18' winget install -e --id Nextcloud.NextcloudDesktop
if '%choice%'=='19' winget install -e --id OBSProject.OBSStudio
if '%choice%'=='20' winget install -e --id KDE.Kdenlive
if '%choice%'=='21' winget install -e --id GIMP.GIMP
if '%choice%'=='22' winget install -e --id GIMP.GIMP.Nightly
if '%choice%'=='23' winget install -e --id KDE.Krita
if '%choice%'=='24' winget install -e --id Microsoft.VisualStudio.2022.Community
if '%choice%'=='25' winget install -e --id Microsoft.VisualStudioCode
if '%choice%'=='26' winget install -e --id GitHub.GitHubDesktop
if '%choice%'=='27' winget install -e --id Canonical.Ubuntu.2204
if '%choice%'=='28' winget install -e --id martinrotter.RSSGuard
if '%choice%'=='0' goto start
echo "%choice%" is not valid, try again
echo.
goto installapps
:gamesprograms
cls
color b
echo ---------------------------------------------------------------------------------------------------------------------
echo 1. Steam
echo 2. Epic Games Launcher
echo 3. Heroic Games Launcher
echo 4. Ubisoft Connect
echo 5. EA App
echo 6. Parsec
echo 7. Moonlight
echo 8. Sunshine
echo 9. Minecraft Launcher
echo 10. Prism Launcher
echo 11. Labymod
echo 12. DuckStation
echo 13. PCSX2
echo 14. RPCS3
echo 15. Dolphin
echo 16. Cemu
echo 17. Ryujinx
echo 18. Retroarch
echo 19. EmulationStation
echo 0. Go back
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' winget install -e --id Valve.Steam
if '%choice%'=='2' winget install -e --id EpicGames.EpicGamesLauncher
if '%choice%'=='3' winget install -e --id HeroicGamesLauncher.HeroicGamesLauncher
if '%choice%'=='4' winget install -e --id Ubisoft.Connect
if '%choice%'=='5' winget install -e --id ElectronicArts.EADesktop
if '%choice%'=='6' winget install -e --id Parsec.Parsec
if '%choice%'=='7' winget install -e --id MoonlightGameStreamingProject.Moonlight
if '%choice%'=='8' winget install -e --id LizardByte.Sunshine
if '%choice%'=='9' winget install -e --id Mojang.MinecraftLauncher
if '%choice%'=='10' winget install -e --id PrismLauncher.PrismLauncher
if '%choice%'=='11' winget install -e --id LabyMediaGmbH.LabyModLauncher
if '%choice%'=='12' winget install -e --id stenzek.DuckStation
if '%choice%'=='13' choco install pcsx2 -y
if '%choice%'=='14' choco install rpcs3 --pre -y
if '%choice%'=='15' choco install dolphin --pre -y
if '%choice%'=='16' choco install cemu -y
if '%choice%'=='17' choco install ryujinx -y
if '%choice%'=='18' choco install retroarch -y
if '%choice%'=='19' choco install emulationstation.install -y
if '%choice%'=='0' goto installapps
echo "%choice%" is not valid, try again
echo.
goto installapps
:chatprograms
cls
color b
echo ---------------------------------------------------------------------------------------------------------------------
echo 1. Discord
echo 2. Element
echo 3. Telegram Desktop
echo 4. Whatsapp
echo 0. Go back
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' winget install -e --id Discord.Discord
if '%choice%'=='2' winget install -e --id Element.Element
if '%choice%'=='3' winget install -e --id Telegram.TelegramDesktop
if '%choice%'=='4' winget install -e --id 9NKSQGP7F2NH
if '%choice%'=='0' goto installapps
echo "%choice%" is not valid, try again
echo.
goto installapps
:mediaprogrames
cls
color b
echo ---------------------------------------------------------------------------------------------------------------------
echo 1. VLC
echo 2. Mpv
echo 3. Audacious Music Player
echo 4. K-Lite Codec Pack Mega
echo 0. Go back
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' winget install -e --id VideoLAN.VLC
if '%choice%'=='2' choco install mpv.install -y
if '%choice%'=='3' winget install -e --id Audacious.MediaPlayer
if '%choice%'=='4' winget install -e --id CodecGuide.K-LiteCodecPack.Mega
if '%choice%'=='0' goto installapps
echo "%choice%" is not valid, try again
echo.
goto installapps
:zipprogrames
cls
color b
echo ---------------------------------------------------------------------------------------------------------------------
echo 1. NanaZip
echo 2. 7zip
echo 3. Winrar
echo 0. Go back
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' winget install -e --id M2Team.NanaZip
if '%choice%'=='2' winget install -e --id 7zip.7zip
if '%choice%'=='3' winget install -e --id RARLab.WinRAR
if '%choice%'=='0' goto installapps
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
echo 6. Thorium
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
if '%choice%'=='6' winget install -e --id EDRLab.Thorium
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