@echo off

REM 
REM drbd rc batch file
REM 

IF "%1" == "start" GOTO start
IF "%1" == "stop"  GOTO stop

@echo on
echo "Usage: rc.bat [start|stop] {vhd path for meta}"
goto :eof

REM ------------------------------------------------------------------------
:start

set log="%DRBD_PATH%\..\log\rc_start.log"
echo [%date%_%time%] rc.bat start. > %log%

:wdrbd_attach_vhd


for /f "usebackq tokens=*" %%a in (`drbdadm sh-md-idx all ^| findstr /C:".vhd"`) do (
	if %errorlevel% == 0 (
		call :sub_attach_vhd "%%a"
	)
)

REM for /f "usebackq tokens=*" %%a in (`drbdadm sh-resources-list`) do (
REM	drbdadm sh-dev %%a > tmp_vol.txt
REM	for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do drbdcon /letter %%b /init_thread
REM	for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do drbdcon /letter %%b /start_volume
REM	del tmp_vol.txt
REM )

REM linux! 
REM drbdadm -c /etc/drbd.conf adjust-with-progress all
:wdrbd_start
::echo WDRBD Starting ...

setlocal EnableDelayedExpansion

set /a adj_retry=0
:adjust_retry
for /f "usebackq tokens=*" %%a in (`drbdadm sh-resource all`) do (
	set ADJUST=0

	for /f "usebackq tokens=*" %%c in (`drbdadm sh-resource-option -n svc_autostart %%a`) do (

		if /i "%%c" == "yes" (
			@(set ADJUST=1)
		) else if /i "%%c" == "no" (
			@(set ADJUST=0)
		) else (
			@(set ADJUST=1)
		)		
	)
	if !ADJUST! == 1 (
		echo [!date!_!time!] drbdadm adjust %%a >> %log%
		drbdadm -c /etc/drbd.conf adjust %%a
		if !errorlevel! gtr 0 (
			echo [!date!_!time!] Failed to drbdadm adjust %%a. >> %log%
			set /a adj_retry=adj_retry+1
			REM Retry 10 times. If it fails more than 10 times, it may adjust fail.
			if %adj_retry% gtr 10 (
				echo [!date!_!time!] drbdadm adjust %%a finally failed.>> %log%
			) else (
				timeout /t 3 /NOBREAK > nul
				goto adjust_retry
			)	
		) else (
			echo [!date!_!time!] drbdadm adjust %%a success.>> %log%	
		)
		
		timeout /t 3 /NOBREAK > nul
	)
)
endlocal


REM User interruptible version of wait-connect all
::drbdadm -c /etc/drbd.conf  wait-con-int 
::echo return code %errorlevel%

REM Become primary if configured
::drbdadm -c /etc/drbd.conf  sh-b-pri all 
::echo return code %errorlevel%

::for /f "usebackq tokens=*" %%a in (`drbdadm sh-resources-list`) do (
	REM MVL: check registered first!
	REM MVL: unlock volume 

	::drbdadm sh-dev %%a > tmp_vol.txt

	REM : Edit mvl script please!!!
	REM for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do ..\mvl\vollock /u %%b:	

	::del tmp_vol.txt
::)

goto :eof


REM ------------------------------------------------------------------------

:stop

@echo off

echo Stopping all DRBD resources
drbdadm down all
timeout /t 3 /NOBREAK > nul

REM linux
REM for res in $(drbdsetup all show | sed -ne 's/^resource \(.*\) {$/\1/p'); do
REM	  drbdsetup "$res" down
REM done

REM @echo on

REM for /f "usebackq tokens=*" %%a in (`drbdadm sh-resource all`) do (
REM	drbdadm sh-dev %%a > tmp_vol.txt
REM MVL
REM for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do ..\mvl\vollock /l %%b:
REM	for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do drbdcon /df %%b
REM	del tmp_vol.txt
REM	drbdadm down %%a
REM	timeout /t 3 /NOBREAK > nul
REM )

goto :eof

:sub_attach_vhd
	if exist %1 (echo select vdisk file="%~f1" & echo attach vdisk) > _temp_attach
	if exist _temp_attach (diskpart /s _temp_attach  > nul & del _temp_attach )
	set /a retry=0
:check_vhd_status
	(echo select vdisk file="%~f1" & echo detail disk) > _check_volume	
	diskpart /s _check_volume | findstr /C:" ### " > nul
	if %errorlevel% gtr 0 (
		del _check_volume
		set /a retry=retry+1

		REM Retry 10 times. If it fails more than 10 times, it may become diskless state.
		if %retry% gtr 10 (
			echo [%date%_%time%] Failed to attach the %1 >> %log%
			goto :eof
		)

		echo [%date%_%time%] Waiting for %1 to attach... retry = %retry% >> %log%

		timeout /t 3 /NOBREAK > nul
		goto check_vhd_status
	)

	del _check_volume
	echo [%date%_%time%] %1 is mounted. >> %log%

	goto :eof