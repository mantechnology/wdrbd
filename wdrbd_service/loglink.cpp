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
	along with drbd; see the file COPYING. If not, write to
	the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/


#include "stdafx.h" 

#define TMPBUF			256  
#define MAX_LOG_STRING	512

HANDLE g_LogLinkThread = NULL;
int g_loglink_usage;
int g_loglink_port;
TCHAR *new_logname = L"NEW_DRBD_LOG"; // TEST!!!

extern VOID WriteLog(TCHAR* pLogName, TCHAR* pMsg, WORD wType);
extern VOID AddEventSource(TCHAR * caPath, TCHAR * csApp);
extern TCHAR *ServiceName;

VOID WriteLog(wchar_t* pLogName, wchar_t* pMsg, WORD wType)
{
	if (!pLogName)
	{
		pLogName = ServiceName;
	}

	HANDLE hEventLog = RegisterEventSource(NULL, pLogName);
	PCTSTR aInsertions [] = { pMsg };
	DWORD dwDataSize = 0;

	dwDataSize = (wcslen(pMsg) + 1) * sizeof(WCHAR);

	ReportEvent(
		hEventLog,                  // Handle to the eventlog
		wType,						// Type of event
		0,							// Category (could also be 0)
		ONELINE_INFO,				// Event id
		NULL,                       // User's sid (NULL for none)
		1,                          // Number of insertion strings
		dwDataSize,                 // Number of additional bytes, need to provide it to read event log data
		aInsertions,                // Array of insertion strings
		pMsg                        // Pointer to additional bytes need to provide it to read event log data
		);

	DeregisterEventSource(hEventLog);
}

void get_linklog_reg()
{
	extern int g_loglink_usage;
	extern int g_loglink_port;

	DWORD value;
	HKEY hKey;
	DWORD status;
	DWORD type = REG_DWORD;
	DWORD size = sizeof(DWORD);
	const WCHAR * registryPath = L"SYSTEM\\CurrentControlSet\\Services\\drbd";

	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, registryPath, NULL, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS == status)
	{
		status = RegQueryValueEx(hKey, TEXT("loglink_tcp_port"), NULL, &type, (LPBYTE) &value, &size);
		if (ERROR_SUCCESS == status)
		{
			g_loglink_port = value;
		}
		else
		{
			g_loglink_port = DRBD_EVENTLOG_LINK_PORT;
		}

		status = RegQueryValueEx(hKey, TEXT("loglink_usage"), NULL, &type, (LPBYTE) &value, &size);
		if (ERROR_SUCCESS == status)
		{
			g_loglink_usage = value;
		}
		else
		{
			g_loglink_usage = LOGLINK_NOT_USED;
		}
	}
	printf("g_loglink_port=%d g_loglink_usage=%d \n", g_loglink_port, g_loglink_usage);

	RegCloseKey(hKey);
}

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

	if (g_loglink_usage == LOGLINK_NEW_NAME || g_loglink_usage == LOGLINK_2OUT)
	{
		// TEST: create with new name
		AddEventSource(NULL, new_logname);
		WriteLog(L"LogLink: create new log event\r\n");
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
		if ((host = gethostbyname((const char*)"127.0.0.1")) == NULL)
		{
			wsprintf(tmp, L"LogLink: Failed to resolve hostname err=0x%x\r\n", WSAGetLastError());
			WriteLog(tmp);
			Sleep(10000);
			continue;
		}

		SOCKADDR_IN sock_addr;
		sock_addr.sin_port = htons(g_loglink_port);
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
				WriteLog(NULL, tmp, EVENTLOG_WARNING_TYPE);

				sz = MAX_LOG_STRING - 1;
			}

			// recv message
			if ((ret = recv(sock, (char*) &buffer, sz, 0)) != sz)
			{
				wsprintf(tmp, L"LogLink:rx ret=%d err=0x%x\r\n", ret, WSAGetLastError());
				WriteLog(NULL, tmp, EVENTLOG_ERROR_TYPE);
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
			WriteLog(NULL, buffer2, wType);

			if (g_loglink_usage == LOGLINK_2OUT)
			{
				// TEST:
				WriteLog(new_logname, buffer2, wType);
			}

#if LOGLONK_TEST
			//WriteLog(buffer2, EVENTLOG_ERROR_TYPE); // test
			//WriteLog(buffer2, EVENTLOG_WARNING_TYPE); // test
			
			wsprintf(buffer2, L"linklog load test !!!!!!!!!!");
			WriteLog(buffer2, EVENTLOG_WARNING_TYPE);

			for (int i = 0; i < 10; i++)
			{
				wsprintf(buffer2, L"linklog load test ..........%d", i);
				WriteLog(buffer2, EVENTLOG_ERROR_TYPE);
			}
#endif
			// send ok
			if ((ret = send(sock, (char*) &sz, sizeof(int), 0)) != sizeof(int))
			{
				wsprintf(tmp, L"LogLink: tx ret=%d err=0x%x\r\n", ret, WSAGetLastError());
				WriteLog(NULL, tmp, EVENTLOG_ERROR_TYPE);
				break;
			}
		}
		
		closesocket(sock);
	}

	return 0;
}