@echo off
::
:: USAGE: drbdlog [EtlFile] [-f {txt|evtx}] [-h|-help]
::

setlocal

set MAXSIZE=2
set drbd_LogGuid={998bdf51-0349-4fbc-870c-d6130a955a5f}
set PWD=%cd%
set DIR=%WDRBD_PATH%\..\log
set FILENAME=tracelog.etl
set OUTPUTNAME=tracelog
set FORMAT=txt
cd "%DIR%"


if !%1==! (
	goto CONVERT
)


set var=%1
set var1=%var:"=%

if /i "%var1%"=="-h" (
	goto HELP
)
if /i "%var1%"=="-help" (
	goto HELP
)

if /i "%var1%" == "-F" (
	if not !%3==! (
		goto ERROR
	)
	if !%2==! (
		goto ERROR
	)
	set FORMAT=%2
	goto CHECK_FORMAT

) else (

	FOR %%i IN ("%var1%") DO (
		set OUTPUTNAME=%%~ni
	)
	set FILENAME=%var1%

)
if !%2==! (
	goto CONVERT
) else (
	if not !%4==! (
		goto ERROR
	)
	if !%3==! (
		goto ERROR
	) else (
		set FORMAT=%3
		goto CHECK_FORMAT
	)
)


:CHECK_FORMAT
if /i "%FORMAT%" == "txt" (
	goto CONVERT
) else if /i "%FORMAT%" == "evtx" (
	goto CONVERT
)else (	
	goto ERROR
)

:CONVERT	
logman stop wdrbdtrace -ets > nul 2>&1
if %errorlevel% gtr 0 (
	echo ERROR: Failed to start logger
	goto END
)

netsh trace convert "%FILENAME%" dump=%FORMAT% overwrite=yes > nul 2>&1
if %errorlevel% gtr 0 (
	echo ERROR: Cannot convert "%FILENAME%"
	goto LOG_START
)

start /B cmd /c "%DIR%\%OUTPUTNAME%.%FORMAT%" > nul 2>&1

if %errorlevel% gtr 0 (
	echo ERROR: Cannot open "%DIR%\%OUTPUTNAME%.%FORMAT%"
	goto LOG_START
)


goto LOG_START


:HELP
:ERROR
echo USAGE: drbdlog [EtlFile] [-f {txt^|evtx}] [-h^|-help]
echo EXAMPLES:
echo 	drbdlog
echo 	drbdlog -f txt
echo 	drbdlog tracelog.etl
echo 	drbdlog tracelog_20160125_180343.etl -f evtx

:LOG_START
logman start trace "wdrbdtrace" -p %drbd_LogGuid% 0xffffffff 0xff -o "%DIR%\tracelog.etl" -mode 0x00001200 -ct system -ft 1 -max %MAXSIZE% -a -ets >nul 2>&1
if %errorlevel% gtr 0 (
	echo ERROR: Failed to start logger
)

:END
cd "%PWD%"

