@echo off

setlocal

set PWD=%cd%
set DIR=%WDRBD_PATH%
set PROVIDERNAME=drbdService
set EXT=log
cd "%DIR%"

:CREATE_LOG
drbdcon.exe /get_log %PROVIDERNAME%
if %errorlevel% NEQ 0 (
	echo ERROR: Cannot create log file, error : %errorlevel%
	goto END
)

:READ_LOG
start notepad %PROVIDERNAME%.%EXT%


:END
cd "%PWD%"