echo off
cls
echo Disabling Windows Media Player
DISM /online /disable-feature /featurename:WindowsMediaPlayer
pause