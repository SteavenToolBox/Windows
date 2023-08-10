echo off
cls
echo Restoring your personal files to their default original location
xcopy /e "%UserProfile%\OneDrive" "%UserProfile%"> nul
echo Shell Fixing
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "AppData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Cache" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local\Microsoft\Windows\INetCache" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Cookies" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local\Microsoft\Windows\INetCookies" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Favorites" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Favorites" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "History" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local\Microsoft\Windows\History" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Local AppData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Music" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Videos" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "NetHood" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Network Shortcuts" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "PrintHood" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Printer Shortcuts" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Programs" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Recent" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Recent" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "SendTo" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\SendTo" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Start Menu" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Startup" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Templates" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Templates" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{374DE290-123F-4565-9164-39C4925E467B}" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Downloads" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Desktop" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Desktop" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Pictures" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Personal" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Documents" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{F42EE2D3-909F-4907-8871-4C22FC0BF756}" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Documents" /f> nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{0DDD015D-B06C-45D5-8C4C-F59713854639}" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Pictures" /f> nul
taskkill /f /im OneDrive.exe> nul
%SystemRoot%\System32\OneDriveSetup.exe /uninstall> nul
%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall> nul
   echo Removing remaining OneDrive folders.
   xcopy /e "%UserProfile%\OneDrive" "%UserProfile%"> nul
   rd "%UserProfile%\OneDrive" /s /q> nul
   rd "%LocalAppData%\Microsoft\OneDrive" /s /q> nul
   rd "%ProgramData%\Microsoft OneDrive" /s /q> nul
   rd "C:\OneDriveTemp" /s /q> nul
   del "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /s /f /q> nul
   echo Removing OneDrive registry keys.  
   reg Delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f> nul
   reg Delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f> nul
   reg ADD "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f> nul
pause