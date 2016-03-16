#include "stdafx.h" 
#include <stdio.h> 
#include <winsock.h> 
#include <stdlib.h> 
#include <Shlwapi.h>

#define MAXPENDING		5
#define RCVBUFSIZE		1024  
#define TMPBUF			256  


void DieWithError(wchar_t *errorMessage);
int HandleTCPClient(int clntSocket); 
int CreateTCPServerSocket(unsigned short port); 
int AcceptTCPConnection(int servSock); 
void *ThreadMain(void *arg); 

struct ThreadArgs
{
	int clntSock; 
};

DWORD RunProcess(
	__in WORD wExecMode,
	__in WORD wExecStyle,
	__in const wchar_t * pwszArg0,
	__in const wchar_t * pwszParameter,
	__in const wchar_t * pwszWorkingDirectory,
	__out volatile DWORD & dwPID,
	__in DWORD dwWait,
	LPDWORD lpdwExitCode,
	BOOL * bIsExist)
{
	DWORD				ret = ERROR_SUCCESS;
	STARTUPINFO			si;
	PROCESS_INFORMATION pi;
	wchar_t				wszCmd[MAX_PATH] = { 0, };
	wchar_t				wszCommandLine[MAX_PATH] = { 0, };
	wchar_t				*pwszAppName;
	wchar_t				tmp[TMPBUF];

	PVOID oldValue;
	Wow64DisableWow64FsRedirection(&oldValue);

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = wExecStyle;

	if (wExecMode == EXEC_MODE_CMD)
	{
		TCHAR systemDirPath[MAX_PATH] = _T("");
		GetSystemDirectory(systemDirPath, sizeof(systemDirPath) / sizeof(_TCHAR));
		swprintf_s(wszCmd, MAX_PATH, L"%s", systemDirPath);
		wcscat_s(wszCmd, MAX_PATH, L"\\cmd.exe");
		pwszAppName = wszCmd;
	}
	else
	{
		pwszAppName = NULL;
	}

	if (pwszArg0)
	{
		swprintf_s(wszCommandLine, MAX_PATH, L"%s", pwszArg0);
	}

	if (pwszParameter)
	{
		if (wcslen(pwszParameter) > 0)
		{
			if (wcslen(wszCommandLine) > 0)
			{
				wcscat_s(wszCommandLine, MAX_PATH, L" ");
			}

			if (wExecMode == EXEC_MODE_CMD)
			{
				wcscat_s(wszCommandLine, MAX_PATH, L"/C ");
			}
			wcscat_s(wszCommandLine, MAX_PATH, pwszParameter);
		}
	}

	if (!CreateProcess(pwszAppName,
			wszCommandLine,			// Command line
			NULL,					// Process handle not inheritable. 
			NULL,					// Thread handle not inheritable. 
			FALSE,					// Set handle inheritance to FALSE. 
			0,						// No creation flags. 
			NULL,					// Use parent's environment block. 
			pwszWorkingDirectory,	// Use parent's starting directory. 
			&si,					// Pointer to STARTUPINFO structure.
			&pi)					// Pointer to PROCESS_INFORMATION structure.
		)
	{
		ret = GetLastError();
		dwPID = 0;

		wsprintf(tmp, L"CreateProcess faild: GetLastError %d\n", ret);
		WriteLog(tmp);
		Wow64RevertWow64FsRedirection(oldValue);

		return ret;
	}

	dwPID = pi.dwProcessId;
	if (dwWait > 0)
	{
		ret = WaitForSingleObject(pi.hProcess, dwWait);
		if (ret != WAIT_OBJECT_0)
		{
			if (ret == WAIT_FAILED)
			{
				ret = GetLastError();
			}

			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			wsprintf(tmp, L"CreateProcess WaitForSingleObject faild: Error %d\n", ret);
			WriteLog(tmp);

			Wow64RevertWow64FsRedirection(oldValue);
			return ret;
		}
	}

	if (lpdwExitCode)
	{
		if (!GetExitCodeProcess(pi.hProcess, lpdwExitCode))
		{
			ret = GetLastError();
			wsprintf(tmp, L"CreateProcess GetExitCodeProcess faild: GetLastError %d\n", ret);
			WriteLog(tmp);
		}
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	Wow64RevertWow64FsRedirection(oldValue);
	return ERROR_SUCCESS;
}


int SockListener(unsigned short *servPort)
{
	int servSock; /* Socket descriptor for server */
	int clntSock; /* Socket descriptor for client */
	DWORD threadID; /* Thread ID from CreateThread() */
	struct ThreadArgs *threadArgs; /* Pointer to argument structure for thread */
	WSADATA wsaData; /* Structure for WinSock setup communication */
	wchar_t tmp[TMPBUF];

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) /* Load Winsock 2.2 DLL */
	{
		wsprintf(tmp, L"SockListener WSAStartup() failed");
		WriteLog(tmp);
		return(-1);
	}

	servSock = CreateTCPServerSocket(*servPort);

	for (;;)
	{
		clntSock = AcceptTCPConnection(servSock);
		{
			// DRBD_DOC: EVENTLOG 보강/정리
			extern const TCHAR * ServiceName;
			HANDLE hEventLog = RegisterEventSource(NULL, ServiceName);
			BOOL bSuccess;
			PCTSTR aInsertions [] = { L"call_usermodehelper:", L"Accepted", L"TCP connection" };
			bSuccess = ReportEvent(
				hEventLog,                  // Handle to the eventlog
				EVENTLOG_INFORMATION_TYPE,  // Type of event
				0,                             // Category (could also be 0)
				MSG_ACCEPT_TCP,                // Event id
				NULL,                       // User's sid (NULL for none)
				3,                          // Number of insertion strings
				0,                          // Number of additional bytes
				aInsertions,                // Array of insertion strings
				NULL                        // Pointer to additional bytes
				);

			DeregisterEventSource(hEventLog);
		}

		/* Create separate memory for client argument */
		threadArgs = (struct ThreadArgs *) malloc(sizeof(struct ThreadArgs));
		threadArgs->clntSock = clntSock;
		if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) ThreadMain, threadArgs, 0, (LPDWORD) &threadID) == NULL)
		{
			wsprintf(tmp, L"call_usermodehelper: CreateThread failed. err(%d)", GetLastError());
			WriteLog(tmp);
			return -1;
		}
	}
	/* NOT REACHED */
}

void *ThreadMain(void *threadArgs)
{
	int clntSock; 

	clntSock = ((struct ThreadArgs *) threadArgs)->clntSock;
	free(threadArgs); /* Deallocate memory for argument */
	HandleTCPClient(clntSock);
	return (NULL);
}

void DieWithError(wchar_t *errorMessage)
{
	wchar_t tmp[TMPBUF];
	
	wsprintf(tmp, L"call_usermodehelper error: %s\n", errorMessage); 
	WriteLog(tmp);
}

int CreateTCPServerSocket(unsigned short port)
{
	int sock; /* socket to create */
	struct sockaddr_in svrAddr; /* Local address */
	
	/* Create socket for incoming connections */
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		DieWithError(L"socket() failed");
		return -1;
	}

	/* Construct local address structure */
	memset(&svrAddr, 0, sizeof(svrAddr)); /* Zero out structure */
	svrAddr.sin_family = AF_INET; /* Internet address family */
	svrAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
	svrAddr.sin_port = htons(port); /* Local port */
	
	/* Bind to the local address */
	if (bind(sock, (struct sockaddr *) &svrAddr, sizeof(svrAddr)) < 0)
	{
		DieWithError(L"bind() failed");
		return -1;
	}

	/* Mark the socket so it will listen for incoming connections */
	if (listen(sock, MAXPENDING) < 0)
	{
		DieWithError(L"listen() failed");
		return -1;
	}

	return sock;
}

int AcceptTCPConnection(int servSock)
{
	int clntSock; 
	struct sockaddr_in clientAddr;
	unsigned int clntLen; 
	
	clntLen = sizeof(clientAddr);
	
	/* Wait for a client to connect */
	if ((clntSock = accept(servSock, (struct sockaddr *) &clientAddr, (int*) &clntLen)) < 0)
	{
		WriteLog(L"accept() failed");
		return -1;
	}

	/* clntSock is connected to a client! */
	return clntSock;
}

int HandleTCPClient(int clntSocket)
{
	char rxcmdbuf[RCVBUFSIZE]; 
	int recvMsgSize; 
	wchar_t tmp[TMPBUF];

	memset(tmp, 0, 256);
	memset(rxcmdbuf, 0, RCVBUFSIZE);
	if ((recvMsgSize = recv(clntSocket, rxcmdbuf, RCVBUFSIZE, 0)) < 0)
	{
		wsprintf(tmp, L"HandleTCPClient: recv failed(%d)\n", recvMsgSize);
		WriteLog(tmp);
		return -1;
	}

	DWORD dwPID;
	WCHAR dest[RCVBUFSIZE];
	DWORD dwExitCode = 0;
	DWORD ret;
	extern TCHAR gServicePath[];
	char *usermode_helper = "drbdadm.exe";

	wsprintf(dest, L"\"%ws\\%S\" %S", gServicePath, usermode_helper, rxcmdbuf);

	ret = RunProcess(EXEC_MODE_WIN, SW_NORMAL, dest, NULL, gServicePath, dwPID, INFINITE, &dwExitCode, NULL); // wait!!!
	Log(L"RunProcess - %ws\n", dest);
	if (ret != ERROR_SUCCESS)
	{
        wsprintf(tmp, L"Failed to run [%ws] process. GetLastError(%d)", gServicePath, ret);
        WriteLog(tmp);
	}

	// send response
	rxcmdbuf[0] = (char)dwExitCode;

	if (send(clntSocket, rxcmdbuf, 1, 0) != 1)
	{
		WriteLog(L"HandleTCPClient: send() failed");
		return -1;
	}

	closesocket(clntSocket);
	return 0;
}

#ifdef _WIN32_LOGLINK	

#define MAX_LOG_STRING	512
HANDLE g_LogLinkThread = NULL;
extern VOID WriteLog(wchar_t* pMsg, WORD wType);

int LogLink_Daemon(unsigned short *port)
{
	wchar_t tmp[TMPBUF];
	WSADATA WsaDat;

	if (WSAStartup(MAKEWORD(2, 2), &WsaDat) != 0)
	{
		WriteLog(L"LogLink: Winsock initialization failed\r\n");
		WSACleanup();
		return 0;
	}

	int loop = 0;

	while (1) // forever: killed by TerminateThread
	{ 
		int ret;

		wsprintf(tmp, L"LogLink: daemon main loop(#%d)\r\n", loop++);
		WriteLog(tmp);

		SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock == INVALID_SOCKET)
		{
			wsprintf(tmp, L"LogLink: Socket creation Failed err=0x%x\r\n", WSAGetLastError());
			WriteLog(tmp);
			Sleep(10000);
			continue;
		}

		struct hostent *host;
		if ((host = gethostbyname("127.0.0.1")) == NULL)
		{
			wsprintf(tmp, L"LogLink: Failed to resolve hostname err=0x%x\r\n", WSAGetLastError());
			WriteLog(tmp);
			Sleep(10000);
			continue;
		}

		SOCKADDR_IN sock_addr;
		sock_addr.sin_port = htons(DRBD_EVENTLOG_LINK_PORT);
		sock_addr.sin_family = AF_INET;
		sock_addr.sin_addr.s_addr = *((unsigned long*) host->h_addr);

		// Attempt to connect to drbd-engine
		int conn_loop = 0;
		while(1)
		{
			if ((ret = connect(sock, (SOCKADDR*) (&sock_addr), sizeof(sock_addr))) == 0)
			{
				wsprintf(tmp, L"LogLink: connected to drbd engine ok. retry=%d\r\n", conn_loop);
				WriteLog(tmp);
				break;
			}
			else
			{
				if (!(conn_loop++ % 30))
				{
					// accumulated? don't care.
					wsprintf(tmp, L"LogLink: connect(#%d) failed ret=%d err=0x%x\r\n", conn_loop++, ret, WSAGetLastError());
					WriteLog(tmp);
				}

				Sleep(500);
			}
		}

		while (1)
		{
			int sz;
			char buffer[MAX_LOG_STRING];
			wchar_t buffer2[MAX_LOG_STRING];

			memset(buffer, 0, sizeof(buffer));

			// recv msg size
			if ((ret = recv(sock, (char*) &sz, sizeof(int), 0)) != sizeof(int))
			{
				wsprintf(tmp, L"LogLink: rx header ret=%d err=0x%x\r\n", ret, WSAGetLastError());
				WriteLog(tmp);
				break;
			}

			// checkmsg size
			if (sz > (MAX_LOG_STRING - 1))
			{
				wsprintf(tmp, L"%S", "LogLink: msg size too big(%d)\r\n", sz);
				WriteLog(tmp, EVENTLOG_WARNING_TYPE);

				sz = MAX_LOG_STRING - 1;
			}

			// recv message
			if ((ret = recv(sock, (char*) &buffer, sz, 0)) != sz)
			{
				wsprintf(tmp, L"LogLink: rx log ret=%d err=0x%x\r\n", ret, WSAGetLastError());
				WriteLog(tmp);
				break;
			}

			// mapping drbd-engine err-level to windows eventlog 

			WORD wType;
			switch (buffer[1] - '0')
			{
				case 0: // PRINTK_EMERG
				case 1: // PRINTK_ALERT
				case 2: // PRINTK_CRIT
				case 3: // PRINTK_ERR
					wType = EVENTLOG_ERROR_TYPE;
					break;
				case 4: // PRINTK_WARN
				case 5: // PRINTK_NOTICE
					wType = EVENTLOG_WARNING_TYPE;
					break;
				case 6: // PRINTK_INFO
				default: // PRINTK_DBG or unexpected cases
					wType = EVENTLOG_INFORMATION_TYPE;
			}

			wsprintf(buffer2, L"%S", buffer + 3);
			WriteLog(buffer2, wType);

			//WriteLog(buffer2, EVENTLOG_ERROR_TYPE); // test
			//WriteLog(buffer2, EVENTLOG_WARNING_TYPE); // test

			// send ok
			if ((ret = send(sock, (char*) &sz, sizeof(int), 0)) != sizeof(int))
			{
				wsprintf(tmp, L"LogLink: tx ret=%d err=0x%x\r\n", ret, WSAGetLastError());
				WriteLog(tmp);
				break;
			}
		}

		closesocket(sock);
	}

	return 0;
}
#endif