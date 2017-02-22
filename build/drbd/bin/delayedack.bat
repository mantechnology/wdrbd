@echo off

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: %1 - enable or disable
:: %2 - IP address or GUID
:: %3 - network interface restart flag. 1 or 0
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

SetLocal enabledelayedexpansion

SET IP=%2

rem get nic info
if "%IP%" == "all" (
	goto query
)

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
goto add_value


:query
for /f "tokens=1" %%x in ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"') do (
	set regpath=%%x
	:add_value
	if "%1" == "disable" (
		reg.exe add !regpath! /t "REG_DWORD" /v "TcpAckFrequency" /d "1" /f
		if %errorlevel% gtr 0 (
			echo Failed to add TcpAckFrequency.
		)
		reg.exe add !regpath! /t "REG_DWORD" /v "TcpNoDelay" /d "1" /f
		if %errorlevel% gtr 0 (
			echo Failed to add TcpNoDelay.
		)
	) else if "%1" == "enable" (
		reg.exe delete !regpath! /v "TcpAckFrequency" /f
		if %errorlevel% gtr 0 (
			echo Failed to delete TcpAckFrequency.
		)
		reg.exe delete !regpath! /v "TcpNoDelay" /f
		if %errorlevel% gtr 0 (
			echo Failed to delete TcpNoDelay.
		)
	)
	if not "%IP%" == "all" (
		goto break
	)
)
:break

for /f "tokens=2*" %%a in ('REG QUERY "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v InstallationType') do set "OsType=%%~b"
for /f "tokens=2*" %%c in ('REG QUERY "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v CurrentVersion') do set "WinVer=%%~d"

if /i "%OsType%" == "Server" (

  for /f "delims=. tokens=1-2" %%e in ("%WinVer%") do (
    set /a WinVer.Major=%%~e+0
    set /a WinVer.Minor=%%~f+0
  )

  if !WinVer.Major! GTR 6 (    
    set PsDaf=true
  )
  if !WinVer.Major! EQU 6 (
    if !WinVer.Minor! GEQ 3 (
      set PsDaf=true
    )
  )

  if "!PsDaf!" == "true" (
	if "%1" == "disable" (
		Powershell Set-NetTcpSetting -SettingName *Custom* -DelayedAckFrequency 1
	) else if "%1" == "enable" (
		Powershell Set-NetTcpSetting -SettingName *Custom* -DelayedAckFrequency 2
	)
  )
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

EndLocal


:end
echo SUCCESS
exit 0
:error
echo FAILURE
exit 0
