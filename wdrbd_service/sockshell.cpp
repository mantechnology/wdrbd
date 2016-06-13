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
			extern TCHAR *ServiceName;
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

		HANDLE h;
		if ((h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) ThreadMain, &clntSock, 0, (LPDWORD) &threadID)) == NULL)
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
	HandleTCPClient(*(int*)threadArgs);
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
	
	BOOL    bValid = 1;
	setsockopt(sock,                // SOCKET
		SOL_SOCKET,                // level
		SO_REUSEADDR,            // Option
		(const char *) &bValid,    // Option Value
		sizeof(bValid));             // Option length

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
	DWORD ret;

	memset(tmp, 0, 256);
	memset(rxcmdbuf, 0, RCVBUFSIZE);

	if ((ret = send(clntSocket, "HI", 2, 0)) != 2)
	{
		wsprintf(tmp, L"HandleTCPClient: send HI (0x%x) failed", WSAGetLastError());
		WriteLog(tmp);
		shutdown(clntSocket, 2);
		closesocket(clntSocket);
		return -1;
	}

	if ((recvMsgSize = recv(clntSocket, rxcmdbuf, RCVBUFSIZE, 0)) < 0)
	{
		wsprintf(tmp, L"HandleTCPClient: recv failed(%d)\n", recvMsgSize);
		WriteLog(tmp);
		return -1;
	}

	DWORD dwPID;
	WCHAR dest[RCVBUFSIZE];
	DWORD dwExitCode = 0;

	extern TCHAR gServicePath[];
	char *usermode_helper = "drbdadm.exe";

	wsprintf(dest, L"\"%ws\\%S\" %S", gServicePath, usermode_helper, rxcmdbuf);
	WriteLog(dest);
	
	ret = RunProcess(EXEC_MODE_WIN, SW_NORMAL, dest, NULL, gServicePath, dwPID, INFINITE, &dwExitCode, NULL); // wait!!!

	wsprintf(tmp, L"RunProcess(%ws) done\n", dest);
	WriteLog(tmp);

	if (ret != ERROR_SUCCESS)
	{
        wsprintf(tmp, L"Failed to run [%ws] process. GetLastError(%d)", gServicePath, ret);
        WriteLog(tmp);
	}

	// send response
	rxcmdbuf[0] = (char)dwExitCode;


	if ((ret = send(clntSocket, rxcmdbuf, 1, 0)) != 1)
	{
		wsprintf(tmp, L"HandleTCPClient: send(0x%x) failed !!!!", WSAGetLastError());
		WriteLog(tmp);
		shutdown(clntSocket, 2);
		closesocket(clntSocket);
		return -1;
	}
	wsprintf(tmp, L"wait for engine BYE message.\n"); // TEST
	WriteLog(tmp);// TEST

	if ((recvMsgSize = recv(clntSocket, rxcmdbuf, 3, 0)) != 3)
	{
		wsprintf(tmp, L"HandleTCPClient: recv failed(%d) 0x%x\n", recvMsgSize, WSAGetLastError());
		WriteLog(tmp);
	}
	else
	{
	}

	closesocket(clntSocket);

	return 0;
}