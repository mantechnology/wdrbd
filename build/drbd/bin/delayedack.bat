@echo off

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: %1 - enable or disable
:: %2 - IP address or GUID
:: %3 - network interface restart flag. 1 or 0 (default = 1)
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::


SET IP=%2

rem get nic info
SET cmd="wmic nicconfig get ipaddress,settingid |findstr %IP%"
FOR /F "delims=\n" %%i IN (' %cmd% ') DO SET INFO=%%i
if "%INFO%" == "" (
	echo %IP% not found.
	goto error
)



rem parsing GUID
rem {"10.10.100.167"} {F63F7A21-6354-419F-9320-5EEEBA25C3C8}
FOR /F "tokens=3 delims={}" %%a in ('ECHO %INFO%') DO SET ID={%%a}

rem edit registry values
set regpath="HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%ID%"

reg.exe query %regpath% >nul
if %errorlevel% gtr 0 (
	goto error
)

if "%1" == "disable" (
	set regcmd=add %regpath% /t "REG_DWORD" /v "TcpAckFrequency" /d "1" /f
) else if "%1" == "enable" (
	set regcmd=delete %regpath% /v "TcpAckFrequency" /f
)

reg.exe %regcmd% >nul
if %errorlevel% gtr 0 (
	goto error
)

if "%3" == "1" (
	rem nic disable
	echo network interface '%IP%' disable...
	wmic path win32_networkadapter where GUID="%ID%" call disable |findstr /C:"ReturnValue = 0" >nul
	if %errorlevel% gtr 0 (
		goto error
	)

	rem nic enable
	echo network interface '%IP%' enable...
	wmic path win32_networkadapter where GUID="%ID%" call enable |findstr /C:"ReturnValue = 0" >nul
	if %errorlevel% gtr 0 (
		goto error
	)
)



:end
echo SUCCESS
exit 0
:error
echo FAILURE
exit 0
