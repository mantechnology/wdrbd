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
#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <tchar.h>

#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <list>

using namespace std;
using std::list;

WCHAR g_szHostName[MAX_PATH] = {0, };
wstring g_strLogPath;
WCHAR g_szEnvPath[MAX_PATH] = { 0, };

HANDLE g_hWatchDirThread = NULL;
HANDLE g_hCleanEvent = NULL;
HANDLE g_hCleanThread = NULL;
HANDLE g_hChangeHandle = NULL;

inline void GetHostName()
{
    DWORD buf_size = sizeof(g_szHostName);
    GetComputerNameW(g_szHostName, &buf_size);
}

inline bool CaseInsCharCompareN(WCHAR a, WCHAR b)
{
    return(toupper(a) == toupper(b));
}

/**
* @brief
*/
bool CaseInsCompare(const wstring& s1, const wstring& s2)
{
    return((s1.size() == s2.size()) &&
        equal(s1.begin(), s1.end(), s2.begin(), CaseInsCharCompareN));
}

/**
* @brief
*   Logging with file
*/
void LogPrint(WCHAR * msg, ...)
{
	wofstream log_file;
	size_t size = 4096;
	wchar_t * buffer = new wchar_t[size];
	ZeroMemory(buffer, size * sizeof(wchar_t));
	va_list params;

	va_start(params, msg);
	_vstprintf(buffer, size, msg, params);
	va_end(params);

	WCHAR time[128] = { 0, }, date[128] = { 0, };
	GetTimeFormatW(LOCALE_USER_DEFAULT, 0, 0, L"HH.mm.ss", time, 128);
	GetDateFormatW(LOCALE_USER_DEFAULT, 0, 0, L"yyyy:MM:dd", date, 128);

	log_file.open(g_strLogPath.c_str(), std::ios_base::out | std::ios_base::app);
	log_file << date << L" " << time << L" " << buffer;
	log_file.flush();	
	log_file.close();

	delete [] buffer;
}

/**
* @brief
*/
void Tokenizer(__in const WCHAR * str, __inout list<wstring> & token_list)
{
    WCHAR delims[] = L"., ?;!";
    WCHAR * tok, *next_token1 = NULL;

    tok = wcstok_s((WCHAR *)str, delims, &next_token1);
    while (tok)
    {
        token_list.push_back(wstring(tok));
        //cout << tok << endl;
        tok = wcstok_s(NULL, delims, &next_token1);
    }
}

/**
* @brief
*   after we get volume leter list by drbdadm sh-dev all, Add letter_list.
*/
DWORD GetDiskLetterList(__inout list<WCHAR> & letter_list)
{
    DWORD result;
    FILE *pPipe = NULL;
    char   readBuffer[1024];

    WCHAR systemDirPath[MAX_PATH];
    char cmd[MAX_PATH];

    GetSystemDirectory(systemDirPath, sizeof(systemDirPath) / sizeof(WCHAR));

    sprintf_s(cmd,"%ws\\cmd.exe /c \"%ws\\drbdadm.exe\" sh-dev all",systemDirPath, g_szEnvPath);

    pPipe = _popen(cmd, "r");

    if (!pPipe)
    {
        result = GetLastError();
        Log(L"drbdadm sh-dev all failed.\n");
        return result;
    }

    size_t readSize = 0;
    readSize = fread((void*)readBuffer, sizeof(char), 1024 - 1, pPipe);

    if (readSize == 0)
    {
        result = GetLastError();
        _pclose(pPipe);
        Log(L"no resources defined!\n");
        return result;
    }

    _pclose(pPipe);

    WCHAR   szBuffer[1024];
    WCHAR   *tok, *next_token1 = NULL;

    wsprintf(szBuffer, L"%hs", readBuffer);
    tok = wcstok_s(szBuffer, L"\n", &next_token1);
    
    while (tok)
    {
        letter_list.push_back(*tok);
        tok = wcstok_s(NULL, L"\n", &next_token1);
    }

    return ERROR_SUCCESS;
}

/**
* @brief
*   argument : drive letter list that got by parsing resource files.
*	if it exist in letter_list by registry enumeration, we skip this. 
*   if not exist, we delete it.
* @return
*   ERROR_SUCCESS - if registry's clean up is success.
*   else - RegOpenKeyEx(), RegDeleteValue()'s return value 
*/
DWORD DeleteRegistryVolumes(__in list<WCHAR>& letter_list)
{
    HKEY hKey = NULL;
    DWORD status = ERROR_SUCCESS, dwIndex = 0;
    WCHAR szRegLetter[MAX_PATH] = {0, };
    UCHAR volGuid[MAX_PATH] = {0, };
    DWORD cbRegLetter = MAX_PATH, cbVolGuid = MAX_PATH;
    const WCHAR * szRegistryPath = L"System\\CurrentControlSet\\Services\\drbd\\volumes";

    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, szRegistryPath, 0, KEY_ALL_ACCESS, &hKey);
    if (ERROR_SUCCESS != status)
    {
        Log(L"RegOpenKeyExW failed. status(%d)\n", status);
        return status;
    }

    while (ERROR_SUCCESS == 
        (status = RegEnumValueW(hKey, dwIndex++, szRegLetter, &cbRegLetter, NULL, NULL, (LPBYTE)volGuid, &cbVolGuid)))
    {
        Log(L"(%c) in registry ---> ", szRegLetter[0]);

        list<WCHAR>::iterator iter;
        for (iter = letter_list.begin(); iter != letter_list.end(); ++iter)
        {
            if (toupper(*iter) == toupper(szRegLetter[0]))
            {
                // found
                Log(L"(%c) exist\n", szRegLetter[0]);
                break;
            }
        }

        if (letter_list.end() == iter)
        {
            status = RegDeleteValueW(hKey, szRegLetter);
            if (ERROR_SUCCESS != status)
            {
                Log(L"RegDeleteValueW(%s) failed. status(0x%x)\n", szRegLetter, status);
                RegCloseKey(hKey);
                return status;
            }
            else
            {
                Log(L"%c was removed\n", szRegLetter[0]);
                --dwIndex;
            }
        }

        memset(szRegLetter, 0, sizeof(szRegLetter));
        memset(volGuid, 0, sizeof(volGuid));
        cbRegLetter = MAX_PATH;
        cbVolGuid = MAX_PATH;
    }

    RegCloseKey(hKey);

    return ERROR_SUCCESS;
}

void OutputSquare(WCHAR letter)
{
    Log(L"%c  ", letter);
};

/**
* @brief
*   after we get resource file's path list, we make driver letter list. 
*   next, we delete a letter that doesn't exist in letter list
*/
DWORD WINAPI CleanVolumeRegisty()
{
    list<WCHAR> letter_list;

    
    GetDiskLetterList(letter_list);

    Log(L"Hostname : %s's res list\n", g_szHostName);


    for_each(letter_list.begin(), letter_list.end(), OutputSquare);
    Log(L"\n");


    DeleteRegistryVolumes(letter_list);

    return ERROR_SUCCESS;
}

/**
* @brief
*   thread waiting for signal that clean registry 
*/
DWORD WINAPI RefreshDirectory(LPVOID lpDir)
{
    DWORD dwWaitResult;
    Log(L"Thread %d waiting for clean event...\n", GetCurrentThreadId());

    while (TRUE)
    {
        dwWaitResult = WaitForSingleObject(g_hCleanEvent, INFINITE);

        switch (dwWaitResult)
        {
            // Event object was signaled
            case WAIT_OBJECT_0:
                Log(L"\nDirectory (%s) changed.\n", lpDir);
                CleanVolumeRegisty();
                ResetEvent(g_hCleanEvent);
                break;

                // An error occurred
            default:
                printf("Wait error (%d)\n", GetLastError());
                return 0;
        }
    }

    return ERROR_SUCCESS;
}

/**
* @brief
*   watch lpDir directory, if something changed in lpDir Directory, wake up the registry cleaner thread
*/
DWORD WINAPI WatchDirectory(LPVOID lpDir)
{
    DWORD dwWaitStatus, dwThreadID, result = ERROR_SUCCESS;
    
    TCHAR lpDrive[4];
    TCHAR lpFile[_MAX_FNAME];
    TCHAR lpExt[_MAX_EXT];

    _tsplitpath_s((LPTSTR)lpDir, lpDrive, 4, NULL, 0, lpFile, _MAX_FNAME, lpExt, _MAX_EXT);

    lpDrive[2] = (TCHAR)'\\';
    lpDrive[3] = (TCHAR)'\0';

    // Watch the directory for file creation and deletion. 
    g_hChangeHandle = FindFirstChangeNotification(
        (LPTSTR)lpDir,                          // directory to watch 
        FALSE,                                  // do not watch subtree 
        FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME); // watch file name changes 

    if (g_hChangeHandle == INVALID_HANDLE_VALUE)
    {
        result = GetLastError();
        Log(L"\n ERROR: FindFirstChangeNotification function failed.\n");
        return result;
    }

    // Make a final validation check on our handles.

    if (g_hChangeHandle == NULL)
    {
        result = GetLastError();
        Log(L"\n ERROR: Unexpected NULL from FindFirstChangeNotification.\n");
        return result;
    }

    g_hCleanEvent = CreateEvent(
        NULL,               // default security attributes
        TRUE,               // manual-reset event
        FALSE,              // initial state is nonsignaled
        TEXT("CleanEvent")  // object name
        );

    if (!g_hCleanEvent)
    {
        result = GetLastError();
        Log(L"CreateEvent failed. GetLastError(%d)\n", result);
        return result;
    }

    g_hCleanThread = CreateThread(
        NULL,              // default security
        0,                 // default stack size
        RefreshDirectory, // name of the thread function
        lpDir,             // no thread parameters
        0,                 // default startup flags
        &dwThreadID);

    // Change notification is set. Now wait on both notification
    // handles and refresh accordingly.

    while (TRUE)
    {
        // Wait for notification.
        dwWaitStatus = WaitForSingleObject(g_hChangeHandle, INFINITE);

        switch (dwWaitStatus)
        {
            case WAIT_OBJECT_0:

                // A file was created, renamed, or deleted in the directory.
                // Refresh this directory and restart the notification.

				// FindFirstChangeNotification have a problem that notify many event, although file change happen one time.
				// maybe NTFS meta I/O operation is followed by a pure file I/O.
                // and then, we make the watchdog thread temporarily. 
				SetEvent(g_hCleanEvent);

                if (FindNextChangeNotification(g_hChangeHandle) == FALSE)
                {
                    Log(L"\n ERROR: FindNextChangeNotification function failed.\n");
                }
                break;

            default:
                Log(L"\n ERROR: Unhandled dwWaitStatus\n");
                break;
        }
    }

    if (g_hCleanEvent)
    {
        CloseHandle(g_hCleanEvent);
        g_hCleanEvent = NULL;
    }

    return result;
}

/**
* @brief
*/
DWORD StartRegistryCleaner()
{
    // get wdrbd's path in environment variables
    size_t path_size;
    errno_t result = _wgetenv_s(&path_size, g_szEnvPath, MAX_PATH, L"DRBD_PATH");
    if (result)
    {
        wcscpy_s(g_szEnvPath, L"c:\\Program Files\\drbd\\bin");
    }

    g_strLogPath = g_szEnvPath;
    g_strLogPath.append(L"\\drbdService.log");

    // get host name 
    GetHostName();

    WCHAR conf_path[MAX_PATH] = {0, };
    wcsncpy_s(conf_path, g_szEnvPath, wcslen(g_szEnvPath) - strlen("bin"));
    wcscat_s(conf_path, L"etc\\drbd.d");
    
    // kick watchdog
    DWORD dwThreadID;
    if (!g_hWatchDirThread)
    {
        g_hWatchDirThread = CreateThread(
            NULL,              // default security
            0,                 // default stack size
            WatchDirectory,   // name of the thread function
            conf_path,         // no thread parameters
            0,                 // default startup flags
            &dwThreadID);
    }
    else
    {
        Log(L"Watching thread is already running\n");
    }

    return ERROR_SUCCESS;
}

/**
* @brief
*   release a thread , handle
*/
DWORD StopRegistryCleaner()
{
    Log(L"stop_registry_cleaner...\n");

    if (g_hCleanThread)
    {
        TerminateThread(g_hCleanThread, 0);
        CloseHandle(g_hCleanThread);
        g_hCleanThread = NULL;
    }

    if (g_hCleanEvent)
    {
        CloseHandle(g_hCleanEvent);
        g_hCleanEvent = NULL;
    }

    if (g_hWatchDirThread)
    {
        TerminateThread(g_hWatchDirThread, 0);
        CloseHandle(g_hWatchDirThread);
        g_hWatchDirThread = NULL;
    }

    if (g_hChangeHandle)
    {
        FindCloseChangeNotification(g_hChangeHandle);
        g_hChangeHandle = NULL;
    }

    return ERROR_SUCCESS;
}
