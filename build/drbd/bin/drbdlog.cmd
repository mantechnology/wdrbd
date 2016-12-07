@echo off

setlocal

set PWD=%cd%
set DIR=%DRBD_PATH%
set PROVIDERNAME=drbdService
set EXT=log
cd "%DIR%"

:CREATE_LOG
drbdcon.exe /get_log ../log/%PROVIDERNAME%.%EXT% %1
if %errorlevel% NEQ 0 (
	echo ERROR: Cannot create log file, error : %errorlevel%
	goto END
)

:READ_LOG
start notepad ../log/%PROVIDERNAME%.%EXT%


:END
cd "%PWD%"