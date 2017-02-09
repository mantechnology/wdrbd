@echo off

setlocal

set DRIVER_PATH=.

if not (%1)==() set DRIVER_PATH=%1

cd %DRIVER_PATH%

rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 0 .\drbd.inf
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 0 .\drbdlock.inf

rem echo reboot...