REM enable fo test
REM @echo off

REM 
REM drbd rc batch file
REM 

IF "%1" == "start" GOTO start
IF "%1" == "stop"  GOTO stop

echo "Usage: rc.bat [start|stop]"
goto done

REM ------------------------------------------------------------------------
:start

echo DRBD START
drbdadm -c /etc/drbd.conf sh-nop
if %errorlevel% gtr 0 (
	goto end
)

REM @echo off

REM drbdcon /start_netlink
REM if %errorlevel% gtr 0 (
REM	goto end
REM )

REM for /f "usebackq tokens=*" %%a in (`drbdadm sh-resources-list`) do (
REM	drbdadm sh-dev %%a > tmp_vol.txt
REM	for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do drbdcon /letter %%b /init_thread
REM	for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do drbdcon /letter %%b /start_volume
REM	del tmp_vol.txt
REM )

REM linux! 
REM drbdadm -c /etc/drbd.conf adjust-with-progress all

drbdadm -c /etc/drbd.conf adjust all

if %errorlevel% gtr 0 (
	goto end
)

REM User interruptible version of wait-connect all
drbdadm -c /etc/drbd.conf  wait-con-int 
echo return code %errorlevel%

REM Become primary if configured
drbdadm -c /etc/drbd.conf  sh-b-pri all 
echo return code %errorlevel%

for /f "usebackq tokens=*" %%a in (`drbdadm sh-resources-list`) do (
	REM MVL: check registered first!
	REM MVL: unlock volume 

	drbdadm sh-dev %%a > tmp_vol.txt

	REM : Edit mvl script please!!!
	REM for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do ..\mvl\vollock /u %%b:	

	del tmp_vol.txt
)

goto end


REM ------------------------------------------------------------------------

:stop

echo Stopping all DRBD resources

REM linux
REM for res in $(drbdsetup all show | sed -ne 's/^resource \(.*\) {$/\1/p'); do
REM	  drbdsetup "$res" down
REM done

REM @echo on

for /f "usebackq tokens=*" %%a in (`drbdadm sh-resources-list`) do (
	drbdadm sh-dev %%a > tmp_vol.txt
REM MVL
REM for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do ..\mvl\vollock /l %%b:
	del tmp_vol.txt

	drbdsetup %%a  down
)

:end
	echo done.
:done

