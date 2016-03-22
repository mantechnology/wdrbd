#include "stdafx.h"
#include <Shlwapi.h>

#define BATCH_TIMEOUT 60000
#define BUFFER_SIZE 500

DWORD Install(const TCHAR * full_path, const TCHAR * pName);
DWORD UnInstall(const TCHAR * pName);
DWORD KillService(const TCHAR * pName);
DWORD RunService(const TCHAR * pName);

VOID ExecuteSubProcess();
VOID WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv);
VOID WINAPI ServiceHandler(DWORD fdwControl);
VOID AddEventSource(TCHAR * caPath, TCHAR * csApp);
DWORD RemoveEventSource(TCHAR *caPath, TCHAR * csApp);
DWORD RcDrbdStart();
DWORD RcDrbdStop();

BOOL g_bProcessStarted = TRUE;

TCHAR * ServiceName = _T("drbdService");

SERVICE_TABLE_ENTRY		g_lpServiceStartTable[] =
{
    {(LPTSTR)ServiceName, ServiceMain},
    {NULL, NULL}
};

SERVICE_STATUS_HANDLE   g_hServiceStatusHandle;
SERVICE_STATUS          g_tServiceStatus;
WCHAR					*g_pwdrbdRcBat = L"rc.bat";
TCHAR                   gServicePath[MAX_PATH];

VOID WriteLog(wchar_t* pMsg)
{
    HANDLE hEventLog = RegisterEventSource(NULL, ServiceName);
    PCTSTR aInsertions[] = {pMsg};
    ReportEvent(
        hEventLog,                  // Handle to the eventlog
        EVENTLOG_INFORMATION_TYPE,  // Type of event
        0,							// Category (could also be 0)
        ONELINE_INFO,				// Event id
        NULL,                       // User's sid (NULL for none)
        1,                          // Number of insertion strings
        0,                          // Number of additional bytes
        aInsertions,                // Array of insertion strings
        NULL                        // Pointer to additional bytes
        );

    DeregisterEventSource(hEventLog);

	Log(pMsg);
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
    else if (_tcsicmp(L"/t", argv[1]) == 0)
    {
        DWORD dwPID;
        WCHAR *szServicePath;
        WCHAR *cmd = L"drbdadm.exe initial-split-brain minor-6";
        WCHAR fullName[MAX_PATH] = {0};

        size_t len;
        errno_t err = _wdupenv_s(&szServicePath, &len, L"WDRBD_PATH");
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
        ServiceName,						/* service name to display */
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
        CloseServiceHandle(schService);
		AddEventSource(L"Application", ServiceName);
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
            // 1060 :  지정한 서비스가 설치되어 있지 않습니다
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
		SERVICE_ACCEPT_PRESHUTDOWN; // don't use SERVICE_ACCEPT_PRESHUTDOWN flag with SERVICE_ACCEPT_SHUTDOWN 2016.2.25 sekim
#else
		SERVICE_ACCEPT_SHUTDOWN;
#endif

    //SERVICE_ACCEPT_NETBINDCHANGE 
    //SERVICE_ACCEPT_SESSIONCHANGE 
    //SERVICE_ACCEPT_PARAMCHANGE 
    //SERVICE_ACCEPT_HARDWAREPROFILECHANGE 
    //SERVICE_ACCEPT_POWEREVENT 

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

    StartRegistryCleaner();

    while (g_bProcessStarted)
    {
        Sleep(3000);

        //if (WaitForSingleObject(g_hStopSvcEvent, dwMonitorInterval) == WAIT_OBJECT_0)
        //{
        //	_terminateService();
        //	break;
        //}
    }

    WriteLog(L"Service is stopped.\n");

    //DrbdSetStatus(SERVICE_STOPPED);
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

            RcDrbdStop();
            StopRegistryCleaner();

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
    HANDLE hEventLog = RegisterEventSource(NULL, ServiceName);
    BOOL bSuccess;
    PCTSTR aInsertions[] = {L"rc_drbd_start"}; // EVENTLOG sample
    bSuccess = ReportEvent(
        hEventLog,                  // Handle to the eventlog
        EVENTLOG_INFORMATION_TYPE,  // Type of event
        0,							// Category (could also be 0)
        ONELINE_INFO,				// Event id
        NULL,                       // User's sid (NULL for none)
        1,                          // Number of insertion strings
        0,                          // Number of additional bytes
        aInsertions,                // Array of insertion strings
        NULL                        // Pointer to additional bytes
        );

    DeregisterEventSource(hEventLog);

    DWORD dwPID;
    TCHAR tmp[1024];
    TCHAR szFullPath[MAX_PATH] = {0};
    DWORD dwLength;
    DWORD ret;

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

DWORD RcDrbdStop()
{
    HANDLE hEventLog = RegisterEventSource(NULL, ServiceName);
    BOOL bSuccess;
    PCTSTR aInsertions[] = {L"rc_drbd_stop"}; // EVENTLOG sample
    bSuccess = ReportEvent(
        hEventLog,                  // Handle to the eventlog
        EVENTLOG_INFORMATION_TYPE,  // Type of event
        0,							// Category (could also be 0)
        ONELINE_INFO,				// Event id
        NULL,                       // User's sid (NULL for none)
        1,                          // Number of insertion strings
        0,                          // Number of additional bytes
        aInsertions,                // Array of insertion strings
        NULL                        // Pointer to additional bytes
        );

    DeregisterEventSource(hEventLog);

    DWORD dwPID;
    WCHAR szFullPath[MAX_PATH] = {0};
    WCHAR tmp[1024];
    DWORD dwLength;
    DWORD ret;
	
    if ((dwLength = wcslen(gServicePath) + wcslen(g_pwdrbdRcBat) + 4) > MAX_PATH)
    {
        wsprintf(tmp, L"Error: cmd too long(%d)\n", dwLength);
        WriteLog(tmp);
        return -1;
    }
    wsprintf(szFullPath, L"\"%ws\\%ws\" %ws", gServicePath, g_pwdrbdRcBat, L"stop");
    ret = RunProcess(EXEC_MODE_CMD, SW_NORMAL, NULL, szFullPath, gServicePath, dwPID, BATCH_TIMEOUT, NULL, NULL);
	
    if (ret)
    {
        wsprintf(tmp, L"Faild rc_drbd_stop: return val %d\n", ret);
        WriteLog(tmp);
    }

    return ret;
}