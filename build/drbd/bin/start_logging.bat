@echo off
setlocal EnableDelayedExpansion

set D=%date: =%
set D=%D:-=%
set T=%time: =0%
set H=%T:~0,2%
set M=%T:~3,2%
set S=%T:~6,2%

set /a COUNT=0
set MAXCOUNT=3
set DIR=%WDRBD_PATH%\..\log

for /f %%i in ('dir "%DIR%\*etl.*" /b /O:D') do (
	@(set /a COUNT+=1 >nul)
	if !COUNT! == 1 (
		@(set DELFILE=%%i)
	)
)


if %COUNT% GTR %MAXCOUNT% (
	del /Q "%DIR%\%DELFILE%"
)

ren "%DIR%\tracelog.etl" "tracelog.etl.%D%_%H%%M%%S%" >nul 2>&1
logman start trace "wdrbdtrace" -p drbd_LogGuid 0xffffffff 0xff -o "%DIR%\tracelog.etl" -mode 0x00001200 -ct system -ft 1 -max 1 -a -ets >nul 2>&1

	