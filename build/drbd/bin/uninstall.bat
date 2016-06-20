@echo off

setlocal

set DRIVER_PATH=.

if not (%1)==() set DRIVER_PATH=%1
cd %DRIVER_PATH%
rundll32.exe setupapi.dll,InstallHinfSection DefaultunInstall 0 .\drbd.inf

echo unstall finished. please reboot now.