/*
	Copyright(C) 2007-2016, ManTechnology Co., LTD.
	Copyright(C) 2007-2016, wdrbd@mantech.co.kr

	Windows DRBD is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2, or (at your option)
	any later version.

	Windows DRBD is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Windows DRBD; see the file COPYING. If not, write to
	the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/


#include "stdafx.h"
#include <Shlwapi.h>

#define BATCH_TIMEOUT 60000
#define BUFFER_SIZE 500

DWORD Install(const TCHAR * full_path, const TCHAR * pName);
DWORD UnInstall(const TCHAR * pName);
DWORD KillService(const TCHAR * pName);
DWORD RunService(const TCHAR * pName);
DWORD UpdateDescription(const TCHAR * pName, const TCHAR * lang);

VOID ExecuteSubProcess();
VOID WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv);
VOID WINAPI ServiceHandler(DWORD fdwControl);
VOID AddEventSource(TCHAR * caPath, TCHAR * csApp);
DWORD RemoveEventSource(TCHAR *caPath, TCHAR * csApp);
DWORD RcDrbdStart();
DWORD RcDrbdStop(bool force);


BOOL g_bProcessStarted = TRUE;

TCHAR * ServiceName = _T("drbdService");
TCHAR * ServiceDisplayName = _T("DRBD for Windows");
//DW-1741 ko
TCHAR * DescriptionKO = _T("DRBD의 Windows 버전으로 실시간 블럭레벨 복제를 제공합니다. 이 서비스를 중지하면 복제 서비스에 문제가 발생할 수 있습니다.");
//DW-1741 en
TCHAR * DescriptionEN = _T("Provides real-time block-level replication with a Windows version of the DRBD. Stopping this service can cause problems with the replication service.");

SERVICE_TABLE_ENTRY		g_lpServiceStartTable[] =
{
    {(LPTSTR)ServiceName, ServiceMain},
    {NULL, NULL}
};

SERVICE_STATUS_HANDLE   g_hServiceStatusHandle;
SERVICE_STATUS          g_tServiceStatus;
WCHAR					*g_pwdrbdRcBat = L"rc.bat";
TCHAR                   gServicePath[MAX_PATH];

VOID WriteLogFormat(WCHAR* msg, ...)
{
	size_t size = 4096;
	wchar_t * buffer = new wchar_t[size];
	ZeroMemory(buffer, size * sizeof(wchar_t));
	va_list params;

	va_start(params, msg);
	_vstprintf(buffer, size, msg, params);
	va_end(params);

	WriteLog(buffer);

	delete[] buffer;
}

VOID WriteLog(wchar_t* pMsg)
{
    HANDLE hEventLog = RegisterEventSource(NULL, ServiceName);
    PCTSTR aInsertions[] = {pMsg};
	DWORD dwDataSize = 0;

	dwDataSize = (wcslen(pMsg) + 1) * sizeof(WCHAR);

    ReportEvent(
        hEventLog,                  // Handle to the eventlog
        EVENTLOG_INFORMATION_TYPE,  // Type of event
        0,							// Category (could also be 0)
        ONELINE_INFO,				// Event id
        NULL,                       // User's sid (NULL for none)
        1,                          // Number of insertion strings
        dwDataSize,                 // Number of additional bytes, need to provide it to read event log data
        aInsertions,                // Array of insertion strings
        pMsg                        // Pointer to additional bytes, need to provide it to read event log data
        );

    DeregisterEventSource(hEventLog);
}

// DW-1505: Return the oldest filename if the number of files 
// with search names is NUMOFLOGS or greater  
#define NUMOFLOGS 10
TCHAR* GetOldestFileName(TCHAR* FileAllPath)
{
	HANDLE hFind;
	WIN32_FIND_DATA FindFileData;
	WIN32_FIND_DATA OldFindFileData;
	int FileCount = 0;
	TCHAR tmp[256] = { 0, };

	hFind = FindFirstFile(FileAllPath, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE){
		_stprintf_s(tmp, _T("GetOldestFileName : hFind == INVALID_HANDLE_VALUE\n"));
		WriteLog(tmp);
		return NULL;
	}
	memcpy(&OldFindFileData, &FindFileData, sizeof(WIN32_FIND_DATA));

	do{
		FileCount++;
		// Compared file creation date and save old file contents 
		if (CompareFileTime(&OldFindFileData.ftCreationTime, &FindFileData.ftCreationTime) > 0){
			memcpy(&OldFindFileData, &FindFileData, sizeof(WIN32_FIND_DATA));
		}
	} while (FindNextFile(hFind, &FindFileData));

	FindClose(hFind);

	//  Returns the oldest file name if the number of files NUMOFLOGS or greater
	if (FileCount >= NUMOFLOGS){
		return OldFindFileData.cFileName;
	}
	else{
		return NULL;
	}
}


int _tmain(int argc, _TCHAR* argv[])
{
    TCHAR szPath[MAX_PATH] = { 0, };
    DWORD dwSize = GetModuleFileName(NULL, szPath, MAX_PATH);
    TCHAR * pdest = _tcsrchr(szPath, '\\');
    _tcsncpy_s(gServicePath, sizeof(gServicePath) / sizeof(TCHAR), szPath, (size_t)(pdest - szPath));

    if (argc < 2)
    {
        ExecuteSubProcess();
        return 0;
    }
    
    if (_tcsicmp(L"/i", argv[1]) == 0)
        return Install(szPath, ServiceName);
    else if (_tcsicmp(L"/k", argv[1]) == 0)
        return KillService(ServiceName);
    else if (_tcsicmp(L"/u", argv[1]) == 0)
        return UnInstall(ServiceName);
    else if (_tcsicmp(L"/s", argv[1]) == 0)
		return RunService(ServiceName);
	else if (_tcsicmp(L"/d", argv[1]) == 0)
		return UpdateDescription(ServiceName, argv[2]);
    else if (_tcsicmp(L"/t", argv[1]) == 0)
    {
        DWORD dwPID;
        WCHAR *szServicePath;
        WCHAR *cmd = L"drbdadm.exe initial-split-brain minor-6";
        WCHAR fullName[MAX_PATH] = {0};

        size_t len;
        errno_t err = _wdupenv_s(&szServicePath, &len, L"DRBD_PATH");
        if (err)
        {
            // default
            szServicePath = L"C:\\Program Files\\drbd\\bin";
        }
        if ((wcslen(szServicePath) + wcslen(cmd) + 4) > MAX_PATH)
        {
            printf("szServicePath: too big!!\n");
        }
        wcsncpy_s(fullName, szServicePath, wcslen(szServicePath));
        wcscat_s(fullName, L"\\");
        wcsncat_s(fullName, cmd, wcslen(cmd)); //wnsprintf
        printf("fullName: %ws\n", fullName);

        // test!
        DWORD ret = RunProcess(EXEC_MODE_WIN, SW_NORMAL, NULL, cmd, szServicePath, dwPID, 0, NULL, NULL);
        free(szServicePath);
        return ERROR_SUCCESS;
    }
#if 1 // _WIN32_HANDLER_TIMEOUT: test by a separate application, not daemon. remove later
	else if (_tcsicmp(L"/n", argv[1]) == 0) 
	{
		// internal test only: no-daemon test

		unsigned short servPort = DRBD_DAEMON_TCP_PORT;
		DWORD threadID;

		if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) SockListener, &servPort, 0, (LPDWORD) &threadID) == NULL)
		{
			WriteLog(L"pthread_create() failed\n");
			return 0;
		}

		int i = 0;
		while (1)
		{
			printf("test main loop(%d)...\n", i++);
			Sleep(10000);
		}
	}
#endif
    else
    {
        TCHAR msg[256];
        _stprintf_s(msg, _T("Usage: drbdService.exe [/i|/k|/u|/s]\n"));
        WriteLog(msg);
        return ERROR_INVALID_PARAMETER;
    }

    return ERROR_SUCCESS;
}

DWORD Install(const TCHAR * full_path, const TCHAR * pName)
{
    TCHAR pTemp[1024];
    DWORD err = ERROR_SUCCESS;

    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (schSCManager == 0)
    {
        err = GetLastError();
        _stprintf_s(pTemp, _T("OpenSCManager failed, error code = %d\n"), err);
        WriteLog(pTemp);
        return err;
    }

    SC_HANDLE schService = CreateService(
        schSCManager,				/* SCManager database      */
        ServiceName,						/* name of service         */
		ServiceDisplayName,						/* service name to display */
        SERVICE_ALL_ACCESS,			/* desired access          */
        SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, /* service type            */
        SERVICE_AUTO_START,			/* start type              */
        SERVICE_ERROR_NORMAL,		/* error control type      */
        full_path,					/* service's binary        */
        NULL,						/* no load ordering group  */
        NULL,						/* no tag identifier       */
        NULL,						/* no dependencies         */
        NULL,						/* LocalSystem account     */
        NULL
        );

    if (schService == 0)
    {
        err = GetLastError();
        _stprintf_s(pTemp, _T("Failed to create service %s, error code = %d\n"), ServiceName, err);
        WriteLog(pTemp);
    }
    else
	{
		SERVICE_DESCRIPTION sd;

		sd.lpDescription = DescriptionEN;

		if (!ChangeServiceConfig2(schService,
									SERVICE_CONFIG_DESCRIPTION,
									&sd))
		{
			err = GetLastError();
			_stprintf_s(pTemp, _T("Failed to change service config %s, error code = %d\n"), ServiceName, err);
			WriteLog(pTemp);
		}
		else
			AddEventSource(L"Application", ServiceName);

        CloseServiceHandle(schService);
    }

    CloseServiceHandle(schSCManager);

    return err;
}

DWORD UnInstall(const TCHAR * pName)
{
    TCHAR pTemp[1024];
    DWORD err = ERROR_SUCCESS;

    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == 0)
    {
        err = GetLastError();
        _stprintf_s(pTemp, _T("OpenSCManager failed, error code = %d\n"), err);
        WriteLog(pTemp);
        return err;
    }

    SC_HANDLE schService = OpenService(schSCManager, pName, SERVICE_ALL_ACCESS);
    if (schService == 0)
    {
        err = GetLastError();
        _stprintf_s(pTemp, _T("OpenService failed, error code = %d\n"), err);
        WriteLog(pTemp);
    }
    else
    {
        if (!DeleteService(schService))
        {
            _stprintf_s(pTemp, _T("Failed to delete service %s\n"), pName);
            WriteLog(pTemp);
        }
        else
        {
            _stprintf_s(pTemp, _T("Service %s removed(Uninstalled)\n"), pName);
            WriteLog(pTemp);
        }
        CloseServiceHandle(schService);
    }
    CloseServiceHandle(schSCManager);

    return err;
}

DWORD KillService(const TCHAR * pName)
{
    TCHAR pTemp[1024];
    DWORD err = ERROR_SUCCESS;

    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == 0)
    {
        err = GetLastError();
        _stprintf_s(pTemp, _T("OpenSCManager failed, error code = %d\n"), err);
        WriteLog(pTemp);
        return err;
    }

    // open the service
    SC_HANDLE schService = OpenService(schSCManager, pName, SERVICE_ALL_ACCESS);
    if (schService == 0)
    {
        err = GetLastError();
        _stprintf_s(pTemp, _T("OpenService failed, error code = %d\n"), err);
        WriteLog(pTemp);
        CloseServiceHandle(schSCManager);
        return err;
    }

    // call ControlService to kill the given service
    SERVICE_STATUS status;
    if (!ControlService(schService, SERVICE_CONTROL_STOP, &status))
    {
        err = GetLastError();
        _stprintf_s(pTemp, _T("ControlService failed, error code = %d\n"), err);
        WriteLog(pTemp);
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);

    return err;
}

//DW-1741 add update service description
DWORD UpdateDescription(const TCHAR * pName, const TCHAR * lang)
{
	wchar_t pTemp[1024];
	DWORD err = ERROR_SUCCESS;

	// run service with given name
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == 0)
	{
		err = GetLastError();
		_stprintf_s(pTemp, _T("OpenSCManager failed, error code = %d\n"), err);
		WriteLog(pTemp);
	}
	else
	{
		// open the service
		SC_HANDLE schService = OpenService(schSCManager, pName, SERVICE_ALL_ACCESS);
		if (schService == 0)
		{
			err = GetLastError();
			_stprintf_s(pTemp, _T("OpenService failed, error code = %d\n"), err);
			WriteLog(pTemp);
		}
		else
		{
			SERVICE_DESCRIPTION sd;

			if (_tcsicmp(L"ko", lang) == 0)
				sd.lpDescription = DescriptionKO;
			else
				sd.lpDescription = DescriptionEN;

			if (!ChangeServiceConfig2(schService,
				SERVICE_CONFIG_DESCRIPTION,
				&sd))
			{
				err = GetLastError();
				_stprintf_s(pTemp, _T("Failed to change service config %s, error code = %d\n"), ServiceName, err);
				WriteLog(pTemp);
			}

			CloseServiceHandle(schService);
		}

		CloseServiceHandle(schSCManager);
	}

	return err;
}
DWORD RunService(const TCHAR * pName)
{
    wchar_t pTemp[1024];
    DWORD err = ERROR_SUCCESS;

    // run service with given name
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == 0)
    {
        err = GetLastError();
        _stprintf_s(pTemp, _T("OpenSCManager failed, error code = %d\n"), err);
        WriteLog(pTemp);
    }
    else
    {
        // open the service
        SC_HANDLE schService = OpenService(schSCManager, pName, SERVICE_ALL_ACCESS);
        if (schService == 0)
        {
            err= GetLastError();
            _stprintf_s(pTemp, _T("OpenService failed, error code = %d\n"), err);
            WriteLog(pTemp);
        }
        else
        {
            // call StartService to run the service
            if (StartService(schService, 0, (const WCHAR**)NULL))
            {
                CloseServiceHandle(schService);
                CloseServiceHandle(schSCManager);
                return TRUE;
            }
            else
            {
                err = GetLastError();
                _stprintf_s(pTemp, _T("StartService failed, error code = %d\n"), err);
                WriteLog(pTemp);
            }
            CloseServiceHandle(schService);
        }
        CloseServiceHandle(schSCManager);
    }

    return err;
}

VOID ExecuteSubProcess()
{
    HANDLE hEventLog = RegisterEventSource(NULL, ServiceName);
    BOOL bSuccess = ReportEvent(
        hEventLog,                  // Handle to the eventlog
        EVENTLOG_INFORMATION_TYPE,	// Type of event
        0,						    // Category (could also be 0)
        MSG_SERVICE_START,          // Event id
        NULL,                       // User's sid (NULL for none)
        0,                          // Number of insertion strings
        0,                          // Number of additional bytes
        NULL,                       // Array of insertion strings
        NULL                        // Pointer to additional bytes
        );

    DeregisterEventSource(hEventLog);

    if (!StartServiceCtrlDispatcher(g_lpServiceStartTable))
    {
        TCHAR msg[MAX_PATH] = {0, };
        _stprintf_s(msg, _T("StartServiceCtrlDispatcher failed, error code = %d\n"), GetLastError());
        WriteLog(msg);
    }
}

VOID WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
    wchar_t pTemp[1024];

    g_tServiceStatus.dwServiceType = SERVICE_WIN32;
    g_tServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	g_tServiceStatus.dwControlsAccepted =
		SERVICE_ACCEPT_STOP |
		SERVICE_ACCEPT_PAUSE_CONTINUE |
#ifdef SERVICE_HANDLER_EX
		SERVICE_ACCEPT_PRESHUTDOWN; // don't use SERVICE_ACCEPT_PRESHUTDOWN flag with SERVICE_ACCEPT_SHUTDOWN 2016.2.25
#else
		SERVICE_ACCEPT_SHUTDOWN;
#endif
    g_tServiceStatus.dwWin32ExitCode = 0;
    g_tServiceStatus.dwServiceSpecificExitCode = 0;
    g_tServiceStatus.dwCheckPoint = 0;
    g_tServiceStatus.dwWaitHint = 0;
#ifdef SERVICE_HANDLER_EX
	g_hServiceStatusHandle = RegisterServiceCtrlHandlerEx(ServiceName, ServiceHandlerEx, NULL);
#else
	g_hServiceStatusHandle = RegisterServiceCtrlHandler(ServiceName, ServiceHandler);
#endif
    
    if (g_hServiceStatusHandle == 0)
    {
        long nError = GetLastError();

        wsprintf(pTemp, L"RegisterServiceCtrlHandler failed, error code = %d\n", nError);
        WriteLog(pTemp);
        return;
    }

    // Initialization complete - report running status 
    g_tServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_tServiceStatus.dwCheckPoint = 0;
    g_tServiceStatus.dwWaitHint = 0;
    if (!SetServiceStatus(g_hServiceStatusHandle, &g_tServiceStatus))
    {
        long nError = GetLastError();
        wsprintf(pTemp, L"SetServiceStatus failed, error code = %d\n", nError);
        WriteLog(pTemp);
    }

    unsigned short servPort = DRBD_DAEMON_TCP_PORT;
    DWORD threadID;

    if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SockListener, &servPort, 0, (LPDWORD)&threadID) == NULL)
    {
        WriteLog(L"pthread_create() failed\n");
        return;
    }

#ifdef _WIN32_LOGLINK
	extern int LogLink_Daemon(unsigned short *port);
	extern HANDLE g_LogLinkThread;
	extern int g_loglink_usage;
	extern void get_linklog_reg();

	get_linklog_reg();

	if (g_loglink_usage != LOGLINK_NOT_USED)
	{
		if ((g_LogLinkThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) LogLink_Daemon, NULL, 0, (LPDWORD) &threadID)) == NULL)
		{
			WriteLog(L"LogLink_Daemon failed\n");
			return;
		}
		// wait ultil LogLink connected ?
	}
#endif

    RcDrbdStart();

	TCHAR szFullPath[MAX_PATH] = { 0 }; DWORD ret; TCHAR tmp[256] = { 0, }; DWORD dwPID;
	_stprintf_s(szFullPath, _T("\"%ws\\%ws\" %ws %ws"), gServicePath, _T("drbdcon"), _T("/get_log"), _T("..\\log\\ServiceStart.log"));
	ret = RunProcess(EXEC_MODE_CMD, SW_NORMAL, NULL, szFullPath, gServicePath, dwPID, BATCH_TIMEOUT, NULL, NULL);
	if (ret) {
		_stprintf_s(tmp, _T("service start drbdlog fail:%d\n"), ret);
		WriteLog(tmp);
	}

    while (g_bProcessStarted)
    {
        Sleep(3000);
    }

    WriteLog(L"Service is stopped.\n");

    //DrbdSetStatus(SERVICE_STOPPED);
}

VOID ExecPreShutDownLog(TCHAR *PreShutdownTime, TCHAR *OldPreShutdownTime)
{
	// DW-1505 : Keep only NUMOFLOGS(10) Preshutdown logs 
	size_t path_size; WCHAR DrbdPath[MAX_PATH] = { 0, }; WCHAR DrbdLogPath[MAX_PATH] = { 0, }; TCHAR tmp[256] = { 0, };
	TCHAR *OldestFileName;  WCHAR FindAllLogFileName[MAX_PATH] = { 0, };
	errno_t result = _wgetenv_s(&path_size, DrbdPath, MAX_PATH, L"DRBD_PATH");
	if (result)
	{
		wcscpy_s(DrbdPath, L"c:\\Program Files\\drbd\\bin");
	}
	wcsncpy_s(DrbdLogPath, DrbdPath, wcslen(DrbdPath) - strlen("bin"));
	wcscat_s(DrbdLogPath, L"log\\");
	wcscat_s(FindAllLogFileName, DrbdLogPath);
	wcscat_s(FindAllLogFileName, _T("Preshutdown*")); // Path to file name beginning with 'Preshutdown'

	while ((OldestFileName = GetOldestFileName(FindAllLogFileName)) != NULL){
		WCHAR DeleteFileName[MAX_PATH] = { 0, };
		wcsncpy_s(DeleteFileName, DrbdLogPath, wcslen(DrbdLogPath));
		wcscat_s(DeleteFileName, OldestFileName);
		// Delete oldest file by name  
		if (DeleteFile(DeleteFileName) == 0){
			_stprintf_s(tmp, _T("fail to delete oldest Preshutdown log error = %d\n"), GetLastError());
			WriteLog(tmp);
			break;
		}
	}

	TCHAR szFullPath[MAX_PATH] = { 0 }; DWORD ret; DWORD dwPID;

	_stprintf_s(szFullPath, _T("\"%ws\\%ws\" %ws %ws"), gServicePath, _T("drbdcon"), _T("/get_log"), _T("..\\log\\"));
	// Change Preshutdown log name to date(eg. Preshutdown-YEAR-MONTH-DAY-HOUR-MINUTE.log)
	_tcscat(szFullPath, PreShutdownTime);

	ret = RunProcess(EXEC_MODE_CMD, SW_NORMAL, NULL, szFullPath, gServicePath, dwPID, BATCH_TIMEOUT, NULL, NULL);
	if (ret) {
		_stprintf_s(tmp, _T("service preshutdown drbdlog fail:%d\n"), ret);
		WriteLog(tmp);
	}
	else {
		//DW-1821 delete old log
		if (OldPreShutdownTime != NULL) {
			WCHAR DeleteFileName[MAX_PATH] = { 0, };

			wcsncpy_s(DeleteFileName, DrbdLogPath, wcslen(DrbdLogPath));
			wcscat_s(DeleteFileName, OldPreShutdownTime);
			// Delete oldest file by name  
			if (DeleteFile(DeleteFileName) == 0){
				_stprintf_s(tmp, _T("fail to delete oldest Preshutdown log error = %d\n"), GetLastError());
				WriteLog(tmp);
			}
		}
	}
}


#ifdef SERVICE_HANDLER_EX
DWORD WINAPI ServiceHandlerEx(_In_ DWORD  fdwControl, _In_ DWORD  dwEventType, _In_ LPVOID lpEventData, _In_ LPVOID lpContext)
#else
VOID WINAPI ServiceHandler(DWORD fdwControl)
#endif

{
    wchar_t pTemp[1024];

    switch (fdwControl)
    {
        case SERVICE_CONTROL_STOP:
            wsprintf(pTemp, L"ServiceHandler SERVICE_CONTROL_STOP\n");
            WriteLog(pTemp);
            g_tServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            break;
        case SERVICE_CONTROL_SHUTDOWN:
            wsprintf(pTemp, L"ServiceHandler SERVICE_CONTROL_SHUTDOWN\n");
            WriteLog(pTemp);
            g_tServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            break;
        case SERVICE_CONTROL_PRESHUTDOWN:
            wsprintf(pTemp, L"ServiceHandler SERVICE_CONTROL_PRESHUTDOWN\n");
            WriteLog(pTemp);
            g_tServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            break;
        case SERVICE_CONTROL_PAUSE:
            g_tServiceStatus.dwCurrentState = SERVICE_PAUSED;
            break;
        case SERVICE_CONTROL_CONTINUE:
            g_tServiceStatus.dwCurrentState = SERVICE_RUNNING;
            break;
        case SERVICE_CONTROL_INTERROGATE:
            break;
        default:
            wsprintf(pTemp, L"ServiceHandler: unexpected Control 0x%x occured! ignored.\n", fdwControl);
            WriteLog(pTemp);
#ifdef SERVICE_HANDLER_EX
			return 0;
#else
            return;
#endif
    };

    if (!SetServiceStatus(g_hServiceStatusHandle, &g_tServiceStatus))
    {
        long nError = GetLastError();
        wsprintf(pTemp, L"SetServiceStatus failed, error code = %d\n", nError);
        WriteLog(pTemp);
#ifdef SERVICE_HANDLER_EX
		return 0;
#else
        return;
#endif
    }

    switch (fdwControl)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_PRESHUTDOWN:
			
			if (SERVICE_CONTROL_STOP == fdwControl) {

				RcDrbdStop(false);

				TCHAR szFullPath[MAX_PATH] = { 0 }; DWORD ret; TCHAR tmp[256] = { 0, }; DWORD dwPID;
				_stprintf_s(szFullPath, _T("\"%ws\\%ws\" %ws %ws"), gServicePath, _T("drbdcon"), _T("/get_log"), _T("..\\log\\ServiceStop.log"));
				ret = RunProcess(EXEC_MODE_CMD, SW_NORMAL, NULL, szFullPath, gServicePath, dwPID, BATCH_TIMEOUT, NULL, NULL);
				if (ret) {
					_stprintf_s(tmp, _T("service stop drbdlog fail:%d\n"), ret);
					WriteLog(tmp);
				}
			}
			else {
				//DW-1821 log before running RcDrbdStop() when the system shuts down.
				TCHAR sPreShutdownTime[MAX_PATH], ePreShutdownTime[MAX_PATH];
				SYSTEMTIME sTime;

				GetLocalTime(&sTime);
				_stprintf(sPreShutdownTime, _T("Preshutdown-s-%02d-%02d-%02d-%02d-%02d.log"), sTime.wYear, sTime.wMonth, sTime.wDay, sTime.wHour, sTime.wMinute);
				ExecPreShutDownLog(sPreShutdownTime, NULL);

				RcDrbdStop(true);

				GetLocalTime(&sTime);
				_stprintf(ePreShutdownTime, _T("Preshutdown-%02d-%02d-%02d-%02d-%02d.log"), sTime.wYear, sTime.wMonth, sTime.wDay, sTime.wHour, sTime.wMinute);
				ExecPreShutDownLog(ePreShutdownTime, sPreShutdownTime);
			}
			
#ifdef _WIN32_LOGLINK
			extern int g_loglink_usage;
			if (g_loglink_usage != LOGLINK_NOT_USED)
			{
				extern HANDLE g_LogLinkThread;
				if (g_LogLinkThread)
				{
					TerminateThread(g_LogLinkThread, 0);
					CloseHandle(g_LogLinkThread);
					g_LogLinkThread = NULL;
				}
				// clear test registry!

				Sleep(3000); // enough
			}
#endif
            g_bProcessStarted = FALSE;
            g_tServiceStatus.dwWin32ExitCode = 0;
            g_tServiceStatus.dwCurrentState = SERVICE_STOPPED;
            g_tServiceStatus.dwCheckPoint = 0;
            g_tServiceStatus.dwWaitHint = 0;

            if (!SetServiceStatus(g_hServiceStatusHandle, &g_tServiceStatus))
            {
                long nError = GetLastError();
                wsprintf(pTemp, L"SetServiceStatus failed, error code = %d\n", nError);
                WriteLog(pTemp);
            }
            wsprintf(pTemp, L"ServiceHandler SERVICE_STOPPED done.\n");
            WriteLog(pTemp);
    }
#ifdef SERVICE_HANDLER_EX
	return 0;
#endif
}

void AddEventSource(TCHAR * csPath, TCHAR * csApp)
{
    HKEY    hRegKey = NULL;
    DWORD   dwError = 0;
    TCHAR   szPath[MAX_PATH];

	if (csPath)
	{
		_stprintf_s(szPath, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s\\%s"), csPath, csApp);
	}
	else
	{
		_stprintf_s(szPath, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s"), csApp);
	}

    // Create the event source registry key
    dwError = RegCreateKey(HKEY_LOCAL_MACHINE, szPath, &hRegKey);
    GetModuleFileName(NULL, szPath, MAX_PATH);
    dwError = RegSetValueEx(hRegKey, _T("EventMessageFile"), 0, REG_EXPAND_SZ, (PBYTE)szPath, (_tcslen(szPath) + 1) * sizeof TCHAR);
    DWORD dwTypes = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    dwError = RegSetValueEx(hRegKey, _T("TypesSupported"), 0, REG_DWORD, (LPBYTE)&dwTypes, sizeof dwTypes);

    RegCloseKey(hRegKey);
}

DWORD RemoveEventSource(TCHAR *csPath, TCHAR *csApp)
{
    TCHAR szPath[MAX_PATH];

   // _stprintf_s(szPath, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s"), csApp);
	if (csPath)
	{
		_stprintf_s(szPath, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s\\%s"), csPath, csApp);

	}
	else
	{
		_stprintf_s(szPath, _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s"), csApp);
	}
    return RegDeleteKey(HKEY_LOCAL_MACHINE, szPath);
}

DWORD RcDrbdStart()
{    
    DWORD dwPID;
    TCHAR tmp[1024];
    TCHAR szFullPath[MAX_PATH] = {0};
    DWORD dwLength;
    DWORD ret;

	WriteLog(L"rc_drbd_start");

    if ((dwLength = wcslen(gServicePath) + wcslen(g_pwdrbdRcBat) + 4) > MAX_PATH)
    {
        _stprintf_s(tmp, _T("Error: cmd too long(%d)\n"), dwLength);
        WriteLog(tmp);
        return -1;
    }
    _stprintf_s(szFullPath, _T("\"%ws\\%ws\" %ws"), gServicePath, g_pwdrbdRcBat, _T("start"));
    ret = RunProcess(EXEC_MODE_CMD, SW_NORMAL, NULL, szFullPath, gServicePath, dwPID, BATCH_TIMEOUT, NULL, NULL);

    if (ret)
    {
        _stprintf_s(tmp, _T("Faild rc_drbd_start: return val %d\n"), ret);
        WriteLog(tmp);
    }

    return ret;
}

DWORD RcDrbdStop(bool force)
{
    DWORD dwPID;
    WCHAR szFullPath[MAX_PATH] = {0};
    WCHAR tmp[1024];
    DWORD dwLength;
    DWORD ret;
	
	if (force)
		WriteLog(L"rc_drbd_stop force");
	else
		WriteLog(L"rc_drbd_stop");

    if ((dwLength = wcslen(gServicePath) + wcslen(g_pwdrbdRcBat) + 4 + 6) > MAX_PATH)
    {
        wsprintf(tmp, L"Error: cmd too long(%d)\n", dwLength);
        WriteLog(tmp);
        return -1;
    }
    wsprintf(szFullPath, L"\"%ws\\%ws\" %ws", gServicePath, g_pwdrbdRcBat, L"stop");
	//DW-1874
	if (force)
		wsprintf(szFullPath, L"%ws %ws", szFullPath, L"force");

    ret = RunProcess(EXEC_MODE_CMD, SW_NORMAL, NULL, szFullPath, gServicePath, dwPID, BATCH_TIMEOUT, NULL, NULL);
	
    if (ret)
    {
        wsprintf(tmp, L"Faild rc_drbd_stop: return val %d\n", ret);
        WriteLog(tmp);
    }

    return ret;
}