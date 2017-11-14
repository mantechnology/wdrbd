@echo off

setlocal

set DRIVER_PATH=.

if not (%1)==() set DRIVER_PATH=%1

cd %DRIVER_PATH%

rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 .\drbdlock.inf
sc config drbdlock start= boot binPath= \SystemRoot\system32\Drivers\drbdlock.sys

rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 0 .\drbd.inf


rem echo reboot...