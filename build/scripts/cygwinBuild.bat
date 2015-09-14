if not defined CYGWIN_HOME%2 (
	echo "ERROR : CYGWIN_HOME%2 is not set, skipping cli build"
	exit 1
) else (
	if %2 == x64 (
		set CYGWIN_HOME=%CYGWIN_HOMEx64%
	) else (
		set CYGWIN_HOME=%CYGWIN_HOMEx86%
	)
)

if not defined CYGWIN_HOME (
	echo "ERROR : CYGWIN_HOME is not set, skipping cli build"
) else (
	set "path=%path%;%CYGWIN_HOME%\bin";
	%CYGWIN_HOME%\bin\vi "+set ff=unix" +wq %1
	%CYGWIN_HOME%\bin\bash.exe %*
)