echo off
mode con: cols=160 lines=78
powershell.exe "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
:start
color b
title SteavenToolBox for Windows 7! v1.0
cls
echo =====================================================================
echo "SteavenToolBox for Windows 7! v1.0 | We care about your OLD pc!"
echo =====================================================================
echo Before anything we recommand you to upgrade powershell to 5.1 for most features to work type 0
echo ---------------------------------------------------------------------------------------------------------------------
echo 1. Enable / Disable Windows 7 Features                    3. Install Apps that you need
echo 2. Clear Temp Files                                       4. Deblot Windows 7
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' goto features
if '%choice%'=='2' goto temp
if '%choice%'=='3' goto apps
if '%choice%'=='4' goto deblot
if '%choice%'=='0' start https://www.microsoft.com/en-us/download/details.aspx?id=54616
echo "%choice%" is not valid, try again
echo.
goto start
:features
cls
echo ---------------------------------------------------------------------------------------------------------------------
echo 0. Main
echo ---------------------------------------------------------------------------------------------------------------------
echo 1. Disable Internet Exploerer
echo 2. Enable Interent Exploerer
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='0' goto start
if '%choice%'=='1' dism /online /NoRestart /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64
if '%choice%'=='2' dism /online /NoRestart /Enable-Feature /FeatureName:Internet-Explorer-Optional-amd64
echo "%choice%" is not valid, try again
goto start
:temp 
cls
color 4
SC stop DoSvc
del c:\WIN386.SWP
del /s /f /q c:\windows\temp\*.*
del /s /f /q C:\WINDOWS\Prefetch
del /s /f /q %temp%\*.*
del /s /f /q %userprofile%\Recent\*.*
del /s /f /q C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Recent Items*.*
del /s /f /q %windir%\temp\*.*  
del /s /f /q %windir%\Prefetch\*.*      
del /s /f /q "%SysteDrive%\Temp"\*.*  
del /s /f /q %temp%\*.*  
del /s /f /q "%USERPROFILE%\Local Settings\History"\*.*  
del /s /f /q "%USERPROFILE%\Local Settings\Temporary Internet Files"\*.* 
del /s /f /q "%USERPROFILE%\Local Settings\Temp"\*.*       
del /s /f /q "%USERPROFILE%\Recent"\*.*    
del /s /f /q "%USERPROFILE%\Cookies"\*.* 
goto start
:apps
cls
color d
echo ---------------------------------------------------------------------------------------------------------------------
echo Install Apps
echo 1. Firefox
echo 2. Brave
echo 3. Chrome
echo 4. Vlc
echo 5. Github
echo 6. Discord
echo 7. Notepad Plus Plus
echo 8. Vs Code
echo 9. Paint.net
echo 0. Back to menu
echo ---------------------------------------------------------------------------------------------------------------------
set choice=
set /p choice=Type the number.
if not '%choice%'=='' set choice=%choice:~0,100%
if '%choice%'=='1' powershell -command "choco install firefox -y"
if '%choice%'=='2' powershell -command "choco install brave -y"
if '%choice%'=='3' powershell -command "choco install chrome -y"
if '%choice%'=='4' powershell -command "choco install vlc -y"
if '%choice%'=='5' powershell -command "choco install github -y"
if '%choice%'=='6' powershell -command "choco install discord -y"
if '%choice%'=='7' powershell -command "choco install notepadplusplus.install -y"
if '%choice%'=='8' powershell -command "choco install vscode -y"
if '%choice%'=='9' powershell -command "choco install paint.net -y"
echo "%choice%" is not valid, try again
goto start
:deblot
cls
color d
echo Disabling Useless Windows 7 Features
dism /online /NoRestart /Disable-Feature /FeatureName:"Internet Games"
dism /online /NoRestart /Disable-Feature /FeatureName:"Internet Checkers"
dism /online /NoRestart /Disable-Feature /FeatureName:"Internet Backgammon"
dism /online /NoRestart /Disable-Feature /FeatureName:"Internet Spades"
dism /online /NoRestart /Disable-Feature /FeatureName:"More Games"
dism /online /NoRestart /Disable-Feature /FeatureName:MediaCenter
dism /online /NoRestart /Disable-Feature /FeatureName:FaxServicesClientPackage
dism /online /NoRestart /Disable-Feature /FeatureName:Xps-Foundation-Xps-Viewer
dism /online /NoRestart /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64
dism /online /NoRestart /Disable-Feature /FeatureName:TabletPCOC
echo Stopping and disabling Diagnostics Tracking Service...
sc stop DiagTrack
sc config "DiagTrack" start= disabled
echo Stopping and disabling Home Groups services...
sc stop HomeGroupListener
sc config "HomeGroupListener" start= disabled
sc stop HomeGroupProvider
sc config "HomeGroupProvider" start= disabled
echo Stopping and disabling Superfetch service...
sc stop SysMain
sc config "SysMain" start= disabled
echo Showing file operations details...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d "1" /f
echo Making System Responsiveness Better using regedit
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "20" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_DWORD /d "2000" /f
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
pause
goto start