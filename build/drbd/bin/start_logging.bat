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
set MAXSIZE=2
set drbd_LogGuid={998bdf51-0349-4fbc-870c-d6130a955a5f}
set DIR=%WDRBD_PATH%\..\log


set cmd="logman -ets|findstr wdrbdtrace"
for /f %%i in ('%cmd%') do set X=%%i

if not !%X%==! (
	:: aready started
	goto END
)

::file backup
for /f %%i in ('dir "%DIR%\*.etl" /b /O:D') do (
	@(set /a COUNT+=1 >nul)
	if !COUNT! == 1 (
		@(set DELFILE=%%i)
	)
)


if %COUNT% GTR %MAXCOUNT% (
	del /Q "%DIR%\%DELFILE%"
)

ren "%DIR%\tracelog.etl" "tracelog_%D%_%H%%M%%S%.etl" >nul 2>&1
logman start trace "wdrbdtrace" -p %drbd_LogGuid% 0xffffffff 0xff -o "%DIR%\tracelog.etl" -mode 0x00001200 -ct system -ft 1 -max %MAXSIZE% -a -ets >nul 2>&1
:END
	