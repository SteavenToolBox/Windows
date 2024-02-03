@echo off
cls

echo Restoring your personal files to their default original location
xcopy /e "%UserProfile%\OneDrive" "%UserProfile%" > nul

echo Shell Fixing
set "REG_CMD=reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v"

%REG_CMD% "AppData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming" /f > nul
%REG_CMD% "Cache" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local\Microsoft\Windows\INetCache" /f > nul
%REG_CMD% "Cookies" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local\Microsoft\Windows\INetCookies" /f > nul
%REG_CMD% "Favorites" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Favorites" /f > nul
%REG_CMD% "History" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local\Microsoft\Windows\History" /f > nul
%REG_CMD% "Local AppData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local" /f > nul
%REG_CMD% "My Music" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Music" /f > nul
%REG_CMD% "My Video" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Videos" /f > nul
%REG_CMD% "NetHood" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Network Shortcuts" /f > nul
%REG_CMD% "PrintHood" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Printer Shortcuts" /f > nul
%REG_CMD% "Programs" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" /f > nul
%REG_CMD% "Recent" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Recent" /f > nul
%REG_CMD% "SendTo" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\SendTo" /f > nul
%REG_CMD% "Start Menu" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu" /f > nul
%REG_CMD% "Startup" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" /f > nul
%REG_CMD% "Templates" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Templates" /f > nul
%REG_CMD% "{374DE290-123F-4565-9164-39C4925E467B}" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Downloads" /f > nul
%REG_CMD% "Desktop" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Desktop" /f > nul
%REG_CMD% "My Pictures" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Pictures" /f > nul
%REG_CMD% "Personal" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Documents" /f > nul
%REG_CMD% "{F42EE2D3-909F-4907-8871-4C22FC0BF756}" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Documents" /f > nul
%REG_CMD% "{0DDD015D-B06C-45D5-8C4C-F59713854639}" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Pictures" /f > nul

taskkill /f /im OneDrive.exe > nul

echo Using winget to uninstall OneDrive
winget uninstall Microsoft.OneDrive

echo Doing it the old way
"%SystemRoot%\System32\OneDriveSetup.exe" /uninstall > nul
"%SystemRoot%\SysWOW64\OneDriveSetup.exe" /uninstall > nul

echo Removing remaining OneDrive folders.
xcopy /e "%UserProfile%\OneDrive" "%UserProfile%" > nul
rd /s /q "%UserProfile%\OneDrive" > nul
rd /s /q "%LocalAppData%\Microsoft\OneDrive" > nul
rd /s /q "%ProgramData%\Microsoft OneDrive" > nul
rd /s /q "C:\OneDriveTemp" > nul
del /s /f /q "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" > nul

echo Removing OneDrive registry keys.
reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f > nul
reg delete "HKEY_USERS\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f > nul

echo Deleting OneDrive Setup Files
echo Deleting OneDriveSetup.exe from SysWOW64...
takeown /f "%SystemRoot%\SysWOW64\OneDriveSetup.exe" > nul
icacls "%SystemRoot%\SysWOW64\OneDriveSetup.exe" /grant administrators:F > nul
del "%SystemRoot%\SysWOW64\OneDriveSetup.exe" /f > nul

echo Deleting OneDriveSetup.exe from System32...
takeown /f "%SystemRoot%\System32\OneDriveSetup.exe" > nul
icacls "%SystemRoot%\System32\OneDriveSetup.exe" /grant administrators:F > nul
del "%SystemRoot%\System32\OneDriveSetup.exe" /f > nul

echo Deleting it as a package
wget https://github.com/SteavenToolBox/Windows/raw/main/Scripts/install_wim_tweak.exe -O c:\install_wim_tweak.exe --no-check-certificate > nul
c:\install_wim_tweak.exe /o /c Microsoft-Windows-OneDrive > nul

pause