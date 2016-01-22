@echo off
:: %1 - /F, /A 
:: %2 - file name
:: %3 - /T
:: %4 - txt, evtx
setlocal
set PWD=%cd%
set DIR=%WDRBD_PATH%\..\log
cd "%DIR%"

REM if !%1==! (
REM	echo USAGE: drbdlog [convert] [all^|filename.etl] [/F] [TXT^|EVTX]
REM	goto DEFAULT
REM )


logman stop wdrbdtrace -ets > nul 2>&1



REM netsh trace convert %1 %2 %4 overwrite=yes > nul 2>&1
REM goto LOGMAN

:DEFAULT
netsh trace convert "%DIR%\tracelog.etl" overwrite=yes > nul 2>&1

:LOGMAN
logman start trace "wdrbdtrace" -p drbd_LogGuid 0xffffffff 0xff -o "%DIR%\tracelog.etl" -mode 0x00001200 -ct system -ft 1 -max 1 -a -ets >nul 2>&1

cd "%PWD%"

