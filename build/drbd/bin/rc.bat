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

:wdrbd_attach_vhd
for /f "usebackq tokens=*" %%a in (`drbdadm sh-md-idx all`) do (call :sub_attach_vhd %%a)

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
	drbdadm -c /etc/drbd.conf adjust %%a
		if %errorlevel% gtr 0 (
			echo Failed to drbdadm adjust %%a
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

REM linux
REM for res in $(drbdsetup all show | sed -ne 's/^resource \(.*\) {$/\1/p'); do
REM	  drbdsetup "$res" down
REM done

REM @echo on

for /f "usebackq tokens=*" %%a in (`drbdadm sh-resource all`) do (
REM	drbdadm sh-dev %%a > tmp_vol.txt
REM MVL
REM for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do ..\mvl\vollock /l %%b:
REM	for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do drbdcon /df %%b
REM	del tmp_vol.txt
	drbdadm down %%a
	timeout /t 3 /NOBREAK > nul
)

goto :eof

:sub_attach_vhd
	if exist %1 (echo select vdisk file="%~f1"& echo attach vdisk) > _temp_attach
	if exist _temp_attach (diskpart /s _temp_attach  > nul & del _temp_attach & echo %1 is mounted.)
	goto :eof