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

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include "mvol.h"
#ifdef _WIN32_DEBUG_OOS
#include "OosTrace.h"
#endif
#include "LogManager.h"
#include "../../wdrbd_service/drbdService.h"


HANDLE
OpenDevice( PCHAR devicename )
{
    HANDLE		handle = INVALID_HANDLE_VALUE;

    handle = CreateFileA( devicename, GENERIC_READ, FILE_SHARE_READ, 
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if( handle == INVALID_HANDLE_VALUE )
    {
        printf("LOG_ERROR: OpenDevice: cannot open %s\n", devicename);	
    }

    return handle;
}

DWORD
MVOL_GetVolumeInfo( CHAR DriveLetter, PMVOL_VOLUME_INFO pVolumeInfo )
{
    HANDLE		driveHandle = INVALID_HANDLE_VALUE;
    DWORD		res = ERROR_SUCCESS;
    ULONG		iolen;
    ULONG		len;
    CHAR		letter[] = "\\\\.\\ :";

    if( pVolumeInfo == NULL )
    {
        printf("LOG_ERROR: MVOL_GetVolumeInfo: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    letter[4] = DriveLetter;
    driveHandle = CreateFileA( letter, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, 
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if( driveHandle == INVALID_HANDLE_VALUE )
    {
        res = GetLastError();
        printf("LOG_ERROR: MVOL_GetVolumeInfo: cannot open Drive (%c:), err=%u\n",
            DriveLetter, res);
        return res;
    }

    len = sizeof(MVOL_VOLUME_INFO);
    if( !DeviceIoControl(driveHandle, IOCTL_MVOL_GET_VOLUME_INFO,
        pVolumeInfo, len, pVolumeInfo, len, &iolen, NULL) )
    {
        res = GetLastError();
        printf("LOG_ERROR: MVOL_GetVolumeInfo: ioctl err=%d\n", res);
        goto out;
    }

    res = ERROR_SUCCESS;
out:
    if( driveHandle != INVALID_HANDLE_VALUE )
        CloseHandle(driveHandle);

    return res;
}

DWORD
MVOL_GetVolumesInfo(BOOLEAN verbose)
{
    DWORD res = ERROR_SUCCESS;

	HANDLE handle = OpenDevice(MVOL_DEVICE);
	if (INVALID_HANDLE_VALUE == handle)
	{
		res = GetLastError();
		fprintf(stderr, "%s: cannot open root device, err=%u\n", __FUNCTION__, res);
		return res;
	}

	DWORD mem_size = 1 << 13;
	DWORD dwReturned;
	PVOID buffer = malloc(mem_size);
	memset(buffer, 0, mem_size);

	while (!DeviceIoControl(handle, IOCTL_MVOL_GET_VOLUMES_INFO,
		NULL, 0, buffer, mem_size, &dwReturned, NULL))
	{
		res = GetLastError();
		if (ERROR_INSUFFICIENT_BUFFER == res)
		{
			mem_size <<= 1;
			free(buffer);
			buffer = malloc(mem_size);
			memset(buffer, 0, mem_size);
		}
		else
		{
			fprintf(stderr, "%s: ioctl err. GetLastError(%d)\n", __FUNCTION__, res);
			goto out;
		}
	}

	res = ERROR_SUCCESS;
	int count = dwReturned / sizeof(WDRBD_VOLUME_ENTRY);
	//printf("size(%d) count(%d) sizeof(WDRBD_VOLUME_ENTRY)(%d)\n", dwReturned, count, sizeof(WDRBD_VOLUME_ENTRY));
	
	if (verbose)
	{
		printf("=====================================================================================\n");
		printf(" PhysicalDeviceName MountPoint VolumeGuid Minor Lock ThreadActive ThreadExit AgreedSize Size\n");
		printf("=====================================================================================\n");
	}
	else
	{
		printf("================================\n");
		printf(" PhysicalDeviceName Minor Replication Volume\n");
		printf("================================\n");
	}
	
	for (int i = 0; i < count; ++i)
	{
		PWDRBD_VOLUME_ENTRY pEntry = ((PWDRBD_VOLUME_ENTRY)buffer) + i;

		if (verbose)
		{
			printf("%ws, %3ws, %ws, %2d, %d, %d, %d, %llu, %llu\n",
				pEntry->PhysicalDeviceName,
				pEntry->MountPoint,
				pEntry->VolumeGuid,
				pEntry->VolIndex,
				pEntry->ExtensionActive,
				pEntry->ThreadActive,
				pEntry->ThreadExit,
				pEntry->AgreedSize,
				pEntry->Size
			);
		}
		else
		{
			printf("%ws, %2d, %d\n",
				pEntry->PhysicalDeviceName,
				pEntry->VolIndex,
				pEntry->ExtensionActive
			);
		}
	}
out:
	if (INVALID_HANDLE_VALUE != handle)
	{
		CloseHandle(handle);
	}

	if (buffer)
	{
		free(buffer);
	}

	return res;
}

DWORD
MVOL_StartVolume( PWCHAR PhysicalVolume )
{
    HANDLE			rootHandle = INVALID_HANDLE_VALUE;
    DWORD			res = ERROR_SUCCESS;
    ULONG			iolen;
    ULONG			len;
    MVOL_VOLUME_INFO	volumeInfo = {0,};

    if( PhysicalVolume == NULL )
    {
        printf("LOG_ERROR: MVOL_StartVolume: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    if( wcslen(PhysicalVolume) > MAXDEVICENAME )
    {
        printf("LOG_ERROR: MVOL_StartVolume: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    rootHandle = OpenDevice( MVOL_DEVICE );
    if( rootHandle == INVALID_HANDLE_VALUE )
    {
        res = GetLastError();
        printf("LOG_ERROR: MVOL_StartVolume: cannot open root device, err=%u\n", res);
        return res;
    }

    wcscpy_s( volumeInfo.PhysicalDeviceName, PhysicalVolume );
    len = sizeof(MVOL_VOLUME_INFO);
    if( !DeviceIoControl(rootHandle, IOCTL_MVOL_VOLUME_START,
        &volumeInfo, len, NULL, 0, &iolen, NULL) )
    {
        res = GetLastError();
        printf("LOG_ERROR: MVOL_StartVolume: ioctl err=%d\n", res);
        goto out;
    }

    res = ERROR_SUCCESS;
out:
    if( rootHandle != INVALID_HANDLE_VALUE )
        CloseHandle(rootHandle);

    return res;
}

DWORD
MVOL_StartVolume( CHAR DriveLetter )
{
    HANDLE			hDrive = INVALID_HANDLE_VALUE;
    CHAR            letter[] = "\\\\.\\ :";
    DWORD			retVal = ERROR_SUCCESS;
    DWORD           dwReturned = 0;
    BOOL            ret = FALSE;

    letter[4] = DriveLetter;
    hDrive = CreateFileA( letter, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, 0, NULL );
    if( hDrive == INVALID_HANDLE_VALUE )
    {
        retVal = GetLastError();
        fprintf( stderr, "LOG_ERROR: %s: Failed open %c: drive. Err=%u\n",
            __FUNCTION__, DriveLetter, retVal );
        return retVal;
    }

    ret = DeviceIoControl( hDrive, IOCTL_MVOL_VOLUME_START,
        NULL, 0, NULL, 0, &dwReturned, NULL );
    if( ret == FALSE )
    {
        retVal = GetLastError();
        fprintf( stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_VOLUME_START. Err=%u\n",
            __FUNCTION__, retVal );
        goto out;
    }

    retVal = ERROR_SUCCESS;
out:
    if( hDrive != INVALID_HANDLE_VALUE )    CloseHandle( hDrive );

    return retVal;
}

DWORD
MVOL_StopVolume( PWCHAR PhysicalVolume )
{
    HANDLE			rootHandle = INVALID_HANDLE_VALUE;
    DWORD			res = ERROR_SUCCESS;
    ULONG			iolen;
    ULONG			len;
    MVOL_VOLUME_INFO	volumeInfo = {0,};

    if( PhysicalVolume == NULL )
    {
        printf("LOG_ERROR: MVOL_StopVolume: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    if( wcslen(PhysicalVolume) > MAXDEVICENAME )
    {
        printf("LOG_ERROR: MVOL_StopVolume: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    rootHandle = OpenDevice( MVOL_DEVICE );
    if( rootHandle == INVALID_HANDLE_VALUE )
    {
        res = GetLastError();
        printf("LOG_ERROR: MVOL_StopVolume: cannot open root device, err=%u\n", res);
        return res;
    }

    wcscpy_s( volumeInfo.PhysicalDeviceName, PhysicalVolume );
    len = sizeof(MVOL_VOLUME_INFO);
    if( !DeviceIoControl(rootHandle, IOCTL_MVOL_VOLUME_STOP,
        &volumeInfo, len, NULL, 0, &iolen, NULL) )
    {
        res = GetLastError();
        printf("LOG_ERROR: MVOL_StopVolume: ioctl err=%d\n", res);
        goto out;
    }

    res = ERROR_SUCCESS;
out:
    if( rootHandle != INVALID_HANDLE_VALUE )
        CloseHandle(rootHandle);

    return res;
}

DWORD
MVOL_StopVolume( CHAR DriveLetter )
{
    HANDLE			hDrive = INVALID_HANDLE_VALUE;
    CHAR            letter[] = "\\\\.\\ :";
    DWORD			retVal = ERROR_SUCCESS;
    DWORD           dwReturned = 0;
    BOOL            ret = FALSE;

    letter[4] = DriveLetter;
    hDrive = CreateFileA( letter, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, 0, NULL );
    if( hDrive == INVALID_HANDLE_VALUE )
    {
        retVal = GetLastError();
        fprintf( stderr, "LOG_ERROR: %s: Failed open %c: drive. Err=%u\n",
            __FUNCTION__, DriveLetter, retVal );
        return retVal;
    }

    ret = DeviceIoControl( hDrive, IOCTL_MVOL_VOLUME_STOP,
        NULL, 0, NULL, 0, &dwReturned, NULL );
    if( ret == FALSE )
    {
        retVal = GetLastError();
        fprintf( stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_VOLUME_STOP. Err=%u\n",
            __FUNCTION__, retVal );
        goto out;
    }

    retVal = ERROR_SUCCESS;
out:
    if( hDrive != INVALID_HANDLE_VALUE )    CloseHandle( hDrive );

    return retVal;
}

DWORD
MVOL_GetVolumeSize( PWCHAR PhysicalVolume, PLARGE_INTEGER pVolumeSize )
{
    HANDLE			handle = INVALID_HANDLE_VALUE;
    DWORD			res = ERROR_SUCCESS;
    ULONG			iolen;
    ULONG			len;
    MVOL_VOLUME_INFO	volumeInfo = {0,};

    if( PhysicalVolume == NULL || pVolumeSize == NULL )
    {
        printf("LOG_ERROR: MVOL_GetVolumeSize: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    if( wcslen(PhysicalVolume) > MAXDEVICENAME )
    {
        printf("LOG_ERROR: MVOL_GetVolumeSize: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    handle = OpenDevice( MVOL_DEVICE );
    if( handle == INVALID_HANDLE_VALUE )
    {
        res = GetLastError();
        printf("MVOL_GetVolumeSize: cannot open root device, err=%u\n", res);
        return res;
    }

    wcscpy_s( volumeInfo.PhysicalDeviceName, PhysicalVolume );
    len = sizeof(MVOL_VOLUME_INFO);
    if( !DeviceIoControl(handle, IOCTL_MVOL_GET_VOLUME_SIZE,
        &volumeInfo, len, pVolumeSize, sizeof(LARGE_INTEGER), &iolen, NULL) )
    {
        res = GetLastError();
        printf("MVOL_GetVolumeSize: ioctl err=%d\n", res);
        goto out;
    }

    res = ERROR_SUCCESS;
out:
    if( handle != INVALID_HANDLE_VALUE )
        CloseHandle(handle);

    return res;
}

DWORD MVOL_GetStatus( PMVOL_VOLUME_INFO VolumeInfo )
{
    HANDLE      hDevice = INVALID_HANDLE_VALUE;
    DWORD       retVal = ERROR_SUCCESS;
    DWORD       dwReturned = 0;
    BOOL        ret = FALSE;

    if( VolumeInfo == NULL )
    {
        fprintf( stderr, "LOG_ERROR: %s: Invalid parameter\n", __FUNCTION__ );
        return ERROR_INVALID_PARAMETER;
    }

    hDevice = OpenDevice( MVOL_DEVICE );
    if( hDevice == INVALID_HANDLE_VALUE )
    {
        retVal = GetLastError();
        fprintf( stderr, "LOG_ERROR: %s: Failed open drbd. Err=%u\n",
            __FUNCTION__, retVal );
        return retVal;
    }

    ret = DeviceIoControl( hDevice, IOCTL_MVOL_GET_PROC_DRBD,
        NULL, 0, VolumeInfo, sizeof(MVOL_VOLUME_INFO), &dwReturned, NULL );
    if( ret == FALSE )
    {
        retVal = GetLastError();
        fprintf( stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_GET_PROC_DRBD. Err=%u\n",
            __FUNCTION__, retVal );
    }

    if( hDevice != INVALID_HANDLE_VALUE )   CloseHandle( hDevice );
    return retVal;
}

DWORD MVOL_SetNagle(CHAR *ResourceName, CHAR *arg)
{   
    DWORD       retVal = ERROR_SUCCESS;
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi;
    
    WCHAR systemDirPath[MAX_PATH];
    WCHAR appName[MAX_PATH];
    WCHAR cmd[MAX_PATH];

    GetSystemDirectory(systemDirPath, sizeof(systemDirPath) / sizeof(WCHAR));
    swprintf_s(appName, MAX_PATH, L"%s\\cmd.exe", systemDirPath);
    swprintf_s(cmd, MAX_PATH, L"/C nagle.bat %hs %hs", arg, ResourceName);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    if (!CreateProcess(appName, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        retVal = GetLastError();
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return retVal;
}

DWORD
MVOL_set_ioctl(PWCHAR PhysicalVolume, DWORD code, MVOL_VOLUME_INFO *pVolumeInfo)
{
    HANDLE			handle = INVALID_HANDLE_VALUE;
    DWORD			res = ERROR_SUCCESS;
    ULONG			iolen;
    ULONG			len;
    MVOL_VOLUME_INFO	volumeInfo = {0,};

    if (PhysicalVolume == NULL)
    {
        printf("LOG_ERROR: MVOL_set_ioctl: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    if (wcslen(PhysicalVolume) > MAXDEVICENAME)
    {
        printf("LOG_ERROR: MVOL_set_ioctl: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    handle = OpenDevice(MVOL_DEVICE);
    if (handle == INVALID_HANDLE_VALUE)
    {
        res = GetLastError();
        printf("MVOL_set_ioctl: cannot open root device, err=%u\n", res);
        return res;
    }

    volumeInfo = *pVolumeInfo;
    wcscpy_s(volumeInfo.PhysicalDeviceName, PhysicalVolume);
    len = sizeof(MVOL_VOLUME_INFO);
    if (!DeviceIoControl(handle, code,
        &volumeInfo, len, pVolumeInfo, sizeof(MVOL_VOLUME_INFO), &iolen, NULL))
    {
        res = GetLastError();
        printf("MVOL_set_ioctl: ioctl err=%d\n", res);
        goto out;
    }

    res = ERROR_SUCCESS;
out:
    if (handle != INVALID_HANDLE_VALUE)
        CloseHandle(handle);

    return res;
}


BOOL LockVolume(HANDLE handle)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(handle, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &dwBytesReturned, NULL);
}

BOOL UnlockVolume(HANDLE handle)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(handle, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &dwBytesReturned, NULL);
}

BOOL IsVolumeMounted(HANDLE handle)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(handle, FSCTL_IS_VOLUME_MOUNTED, NULL, 0, NULL, 0, &dwBytesReturned, NULL);
}

BOOL Dismount(HANDLE handle)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &dwBytesReturned, NULL);
}

DWORD MVOL_MountVolume(char drive_letter)
{
    HANDLE			hDrive = INVALID_HANDLE_VALUE;
    char            letter[] = "\\\\.\\ :";
    DWORD			retVal = ERROR_SUCCESS;
    DWORD           dwReturned = 0;
	char			MsgBuff[MAX_PATH] = { 0, };
    BOOL            ok = FALSE;

    letter[4] = drive_letter;
    hDrive = CreateFileA(letter, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, 0, NULL);

    if (INVALID_HANDLE_VALUE == hDrive)
    {
        retVal = GetLastError();
        fprintf(stderr, "%s: Failed open %c: drive. Error Code=%u\n",
            __FUNCTION__, drive_letter, retVal);
        return retVal;
    }

    ok = DeviceIoControl(hDrive, IOCTL_MVOL_MOUNT_VOLUME,
		NULL, 0, MsgBuff, MAX_PATH, &dwReturned, NULL);
    if (!ok)
    {
        retVal = GetLastError();
        fprintf(stderr, "%s: Failed IOCTL_MVOL_MOUNT_VOLUME. ErrorCode(%u)\n",
            __FUNCTION__, retVal);
        goto out;
    }

	if (dwReturned)
	{
		fprintf(stderr, MsgBuff);
		retVal = 1;
		goto out;
	}
	
    retVal = ERROR_SUCCESS;
out:
    if (INVALID_HANDLE_VALUE != hDrive)
    {
        CloseHandle(hDrive);
    }

    return retVal;
}

DWORD MVOL_DismountVolume(CHAR DriveLetter, int Force)
{
    HANDLE      handle = NULL;
    CHAR        letter[] = "\\\\.\\ :";

    letter[4] = DriveLetter;
    
    __try
    {
        handle = CreateFileA(letter, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        
        if (INVALID_HANDLE_VALUE == handle)
        {
            DWORD dwErr = GetLastError();
            if (ERROR_FILE_NOT_FOUND != dwErr)
            {
                printf("LOG_ERROR: Failed to create vol(%S)'s handle. GetLastError(0x%x)\n"
                    , letter, GetLastError());
            }

            return GetLastError();
        }

        if (!IsVolumeMounted(handle))
        {
            printf("LOG_ERROR: %c: is already dismounted\n", DriveLetter);
            return ERROR_SUCCESS;
        }
         
        if (!Force)
        {
            if (!LockVolume(handle))
            {
                printf("LOG_ERROR: %c: in use\n", DriveLetter);
                return GetLastError();
            }
        }
        
        
        if (!Dismount(handle))
        {
            printf("LOG_ERROR: FSCTL_DISMOUNT_VOLUME fail. GetLastError(%d)\n", GetLastError());
            return GetLastError();
        }

        if (!Force)
        {
            if (!UnlockVolume(handle))
            {
                printf("LOG_ERROR: FSCTL_UNLOCK_VOLUME fail. GetLastError(%d)\n", GetLastError());
                return GetLastError();
            }
        }


        if (IsVolumeMounted(handle))
        {
            int duration = 10000, delay = 500;
            int i, count = duration / delay;
            for (i = 0; i < count; ++i)
            {
                Sleep(delay);
                printf("LOG_ERROR: vol(%s) is not dismounted yet. %d count delay. GetLastError(0x%x)\n", letter, i, GetLastError());
                if (!IsVolumeMounted(handle))
                {
                    return ERROR_SUCCESS;
                }
            }

            return GetLastError();
        }
    }
    __finally
    {
        if (handle)
        {
            CloseHandle(handle);
        }
    }
	printf("%c: Volume Dismount Success\n", DriveLetter);
    return ERROR_SUCCESS;
}

DWORD CreateLogFromEventLog(LPCSTR pszProviderName)
{
	HANDLE hEventLog = NULL;
	DWORD dwStatus = ERROR_SUCCESS;
	DWORD dwBytesToRead = 0;
	DWORD dwBytesRead = 0;
	DWORD dwMinBytesToRead = 0;
	PBYTE pBuffer = NULL;
	PBYTE pTemp = NULL;
	TCHAR tszProviderName[MAX_PATH];
	TCHAR szLogFilePath[MAX_PATH] = _T("");
	HANDLE hLogFile = INVALID_HANDLE_VALUE;
		

#ifdef _UNICODE
	if (0 == MultiByteToWideChar(CP_ACP, 0, (LPSTR)pszProviderName, -1, tszProviderName, MAX_PATH))
	{
		dwStatus = GetLastError();
		_tprintf(_T("MultiByteToWideChar failed, err : %d\n"), dwStatus);
		goto cleanup;
	}
#else
	strcpy(tszProviderName, pszProviderName);
#endif

	_tcscat_s(tszProviderName, MAX_PATH, LOG_FILE_EXT);

	// Get log file full path( [current process path]\[provider name].log )
	dwStatus = GetCurrentFilePath(tszProviderName, szLogFilePath);
	if (ERROR_SUCCESS != dwStatus)
	{
		_tprintf(_T("could not get log file path, err : %d\n"), dwStatus);
		return dwStatus;
	}

	// Create log file and overwrite if exists.
	hLogFile = CreateFile(szLogFilePath, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hLogFile)
	{
		dwStatus = GetLastError();
		_tprintf(_T("could not create file, err : %d\n"), dwStatus);
		return dwStatus;
	}
	
	// Provider name must exist as a subkey of Application.
	hEventLog = OpenEventLog(NULL, tszProviderName);
	if (NULL == hEventLog)
	{
		dwStatus = GetLastError();
		_tprintf(_T("could not open event log, err : %d\n"), dwStatus);
		goto cleanup;
	}

	// Buffer size will be increased if not enough.
	dwBytesToRead = MAX_RECORD_BUFFER_SIZE;
	pBuffer = (PBYTE)malloc(dwBytesToRead);
	if (NULL == pBuffer)
	{
		_tprintf(_T("allocate memory for record buffer failed\n"));
		dwStatus = ERROR_NOT_ENOUGH_MEMORY;
		goto cleanup;
	}

	while (ERROR_SUCCESS == dwStatus)
	{
		// read event log in chronological(old -> new) order.
		if (!ReadEventLog(hEventLog, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ, 0, pBuffer, dwBytesToRead, &dwBytesRead, &dwMinBytesToRead))
		{
			dwStatus = GetLastError();

			if (ERROR_INSUFFICIENT_BUFFER == dwStatus)
			{
				dwStatus = ERROR_SUCCESS;

				// Increase buffer size and re-try it.
				pTemp = (PBYTE)realloc(pBuffer, dwMinBytesToRead);
				if (NULL == pTemp)
				{
					_tprintf(_T("reallocate memory(%d bytes) for record buffer failed\n"), dwMinBytesToRead);
					goto cleanup;
				}

				pBuffer = pTemp;
				dwBytesToRead = dwMinBytesToRead;
			}
			else
			{
				if (ERROR_HANDLE_EOF != dwStatus)
				{
					_tprintf(_T("ReadEventLog failed, err : %d\n"), dwStatus);
				}
				else
				{
					// done.
					dwStatus = ERROR_SUCCESS;					
				}
					goto cleanup;
			}
		}
		else
		{
			dwStatus = WriteLogWithRecordBuf(hLogFile, tszProviderName, pBuffer, dwBytesRead);

			if (ERROR_SUCCESS != dwStatus)
			{
				_tprintf(_T("Write Log Failed, err : %d\n"), dwStatus);
			}
		}
	}
	
cleanup:

	if (INVALID_HANDLE_VALUE != hLogFile)
	{
		CloseHandle(hLogFile);
		hLogFile = INVALID_HANDLE_VALUE;
	}

	if (NULL != hEventLog)
	{
		CloseEventLog(hEventLog);
		hEventLog = NULL;
	}

	if (NULL != pBuffer)
	{
		free(pBuffer);
		pBuffer = NULL;
	}

	return dwStatus;
}

DWORD WriteLogWithRecordBuf(HANDLE hLogFile, LPCTSTR pszProviderName, PBYTE pBuffer, DWORD dwBytesRead)
{
	DWORD dwStatus = ERROR_SUCCESS;
	PBYTE pRecord = pBuffer;
	PBYTE pEndOfRecords = pBuffer + dwBytesRead;	
	
	while (pRecord < pEndOfRecords)
	{
		// Write event log data only when provider name matches.
		if (0 == _tcsicmp(pszProviderName, (LPCTSTR)(pRecord + sizeof(EVENTLOGRECORD))))
		{
			// Some data doesn't have data length if writer didn't provide data size.
			if (((PEVENTLOGRECORD)pRecord)->DataLength > 0)
			{
				PBYTE pData = NULL;
				TCHAR szTimeStamp[MAX_TIMESTAMP_LEN] = _T("");

				// Get time string (format : mm/dd/yyyy hh:mm:ss )
				GetTimestamp(((PEVENTLOGRECORD)pRecord)->TimeGenerated, szTimeStamp);

				pData = (PBYTE)malloc(((PEVENTLOGRECORD)pRecord)->DataLength);
				if (NULL == pData)
				{
					_tprintf(_T("malloc failed\n"));
					dwStatus = ERROR_NOT_ENOUGH_MEMORY;
					break;
				}

				memcpy(pData, (PBYTE)(pRecord + ((PEVENTLOGRECORD)pRecord)->DataOffset), ((PEVENTLOGRECORD)pRecord)->DataLength);
				
				dwStatus = WriteLogToFile(hLogFile, szTimeStamp, pData);
				if (ERROR_SUCCESS != dwStatus)
				{
					_tprintf(_T("WriteLogToFile failed, err : %d\n"), dwStatus);
					// Do not finish. Write next data.
				}

				if (NULL != pData)
				{
					free(pData);
					pData = NULL;
				}
			}			
		}

		pRecord += ((PEVENTLOGRECORD)pRecord)->Length;
	}	

	return dwStatus;
}

DWORD GetCurrentFilePath(LPCTSTR pszCurrentFileName, PTSTR pszCurrentFileFullPath)
{
	DWORD dwStatus = ERROR_SUCCESS;
	TCHAR szLogFilePath[MAX_PATH] = _T("");
	PTCHAR pTemp = NULL;

	// Get current module path. (it includes [processname].[ext])
	if (0 == GetModuleFileName(NULL, szLogFilePath, MAX_PATH))
	{
		dwStatus = GetLastError();
		_tprintf(_T("could not get module path, err : %d\n"), dwStatus);
		return dwStatus;
	}

	// Find last back slash.
	pTemp = _tcsrchr(szLogFilePath, _T('\\'));
	if (NULL == pTemp)
	{
		dwStatus = ERROR_PATH_NOT_FOUND;
		_tprintf(_T("invalid path format : %s\n"), szLogFilePath);
		return dwStatus;
	}

	// Remove process name.
	pTemp++;
	*pTemp = _T('\0');

	// Concatenate [filename].[ext]
	StringCchCat(szLogFilePath, MAX_PATH, pszCurrentFileName);

	StringCchCopy(pszCurrentFileFullPath, MAX_PATH, szLogFilePath);

	return dwStatus;
}

void GetTimestamp(const DWORD Time, TCHAR DisplayString[])
{
	ULONGLONG ullTimeStamp = 0;
	ULONGLONG SecsTo1970 = 116444736000000000;
	SYSTEMTIME st;
	FILETIME ft, ftLocal;

	ullTimeStamp = Int32x32To64(Time, 10000000) + SecsTo1970;
	ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
	ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);

	FileTimeToLocalFileTime(&ft, &ftLocal);
	FileTimeToSystemTime(&ftLocal, &st);
	StringCchPrintf(DisplayString, MAX_TIMESTAMP_LEN, L"%d/%d/%d %.2d:%.2d:%.2d",
		st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);
}

DWORD WriteLogToFile(HANDLE hLogFile, LPCTSTR pszTimeStamp, PBYTE pszData)
{
	DWORD dwStatus = ERROR_SUCCESS;
	TCHAR szLogData[MAX_LOGDATA_LEN] = _T("");
	CHAR szAnsiLogData[MAX_LOGDATA_LEN] = "";
	DWORD dwBytesToWrite = 0;
	DWORD dwBytesWritten = 0;

	// delete \r and \n if log contains them.
	for (int i = 1; i <= 2; i++)
	{
		PTCHAR pTemp = (PTCHAR)pszData;
		pTemp += (_tcslen(pTemp) - i);
		if (*pTemp == _T('\n') ||
			*pTemp == _T('\r'))
		{
			*pTemp = _T('\0');
		}
	}	
	
	// Log data format : mm/dd/yyyy hh:mm:ss [log data]
	if (S_OK != StringCchPrintf(szLogData, MAX_LOGDATA_LEN, _T("%s %s\r\n"), pszTimeStamp, pszData))
	{
		_tprintf(_T("making log data failed\n"));
		dwStatus = ERROR_INVALID_DATA;
		goto exit;
	}

#ifdef _UNICODE
	if (0 == WideCharToMultiByte(CP_ACP, 0, szLogData, -1, (LPSTR)szAnsiLogData, MAX_LOGDATA_LEN, NULL, NULL))
	{
		dwStatus = GetLastError();
		_tprintf(_T("WideChartoMultiByte failed, err : %d\n"), dwStatus);
		goto exit;
	}
#else
	strcpy(szAnsiLogData, szLogData);
#endif

	dwBytesToWrite = (DWORD)strlen(szAnsiLogData);
	if (!WriteFile(hLogFile, szAnsiLogData, dwBytesToWrite, &dwBytesWritten, NULL))
	{
		dwStatus = GetLastError();
		_tprintf(_T("write log data failed, err : %d\n"), dwStatus);
		goto exit;
	}

exit:
	return dwStatus;
}

DWORD WriteEventLog(LPCSTR pszProviderName, LPCSTR pszData)
{
	HANDLE hEventLog = NULL;	
	PWSTR pwszLogData = NULL;
	DWORD dwStatus = ERROR_SUCCESS;
	DWORD dwDataSize = 0;
	
	hEventLog = RegisterEventSourceA(NULL, pszProviderName);

	if (NULL == hEventLog)
	{
		dwStatus = GetLastError();
		_tprintf(_T("RegisterEventSource failed, err : %d\n"), dwStatus);
		goto cleanup;
	}

	dwDataSize = (DWORD)((strlen(pszData) + 1) * sizeof(WCHAR));

	pwszLogData = (PWSTR)malloc(dwDataSize);

	if (0 == MultiByteToWideChar(CP_ACP, 0, pszData, -1, pwszLogData, dwDataSize))
	{
		dwStatus = GetLastError();
		_tprintf(_T("MultiByteToWideChar failed, err : %d\n"), dwStatus);
		goto cleanup;
	}

	PCWSTR aInsertions[] = { pwszLogData };

	if (!ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, ONELINE_INFO, NULL, 1, dwDataSize, aInsertions, (PVOID)pwszLogData))
	{
		dwStatus = GetLastError();
		_tprintf(_T("ReportEvent failed, err : %d\n"), dwStatus);
		goto cleanup;
	}

	printf("Log data has been written (%s : %s)\n", pszProviderName, pszData);

cleanup:

	if (NULL != pwszLogData)
	{
		free(pwszLogData);
		pwszLogData = NULL;
	}

	if (NULL != hEventLog)
	{
		CloseHandle(hEventLog);
		hEventLog = NULL;
	}

	return dwStatus;
}

// Simulate Disk I/O Error 
DWORD MVOL_SimulDiskIoError(SIMULATION_DISK_IO_ERROR* pSdie)
{
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       retVal = ERROR_SUCCESS;
	DWORD       dwReturned = 0;
	BOOL        ret = FALSE;

	if (pSdie == NULL) {
		fprintf(stderr, "LOG_ERROR: %s: Invalid parameter\n", __FUNCTION__);
		return ERROR_INVALID_PARAMETER;
	}

	// 1. Open MVOL_DEVICE
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed open drbd. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}

	// 2. DeviceIoControl with SIMULATION_DISK_IO_ERROR parameter (DW-841, mvol.h)
	ret = DeviceIoControl(hDevice, IOCTL_MVOL_SET_SIMUL_DISKIO_ERROR,
		pSdie, sizeof(SIMULATION_DISK_IO_ERROR), pSdie, sizeof(SIMULATION_DISK_IO_ERROR), &dwReturned, NULL);
	if (ret == FALSE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_GET_PROC_DRBD. Err=%u\n",
			__FUNCTION__, retVal);
	}

	// 3. CloseHandle MVOL_DEVICE
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
	return retVal;
}

DWORD MVOL_SetMinimumLogLevel(PLOGGING_MIN_LV pLml)
{	
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       retVal = ERROR_SUCCESS;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
	BOOL        ret = FALSE;

	if (pLml == NULL ||
#ifdef _WIN32_DEBUG_OOS
		(pLml->nType != LOGGING_TYPE_SYSLOG && pLml->nType != LOGGING_TYPE_DBGLOG && pLml->nType != LOGGING_TYPE_OOSLOG) ||
#else
		(pLml->nType != LOGGING_TYPE_SYSLOG && pLml->nType != LOGGING_TYPE_DBGLOG) ||
#endif
		(pLml->nErrLvMin < 0 || pLml->nErrLvMin > 7))
	{
		fprintf(stderr, "LOG_ERROR: %s: Invalid parameter\n", __FUNCTION__);
		return ERROR_INVALID_PARAMETER;
	}

	// 1. Open MVOL_DEVICE
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed open drbd. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
	

	// 2. DeviceIoControl with LOGGING_MIN_LV parameter (DW-858)
	ret = DeviceIoControl(hDevice, IOCTL_MVOL_SET_LOGLV_MIN, pLml, sizeof(LOGGING_MIN_LV), NULL, 0, &dwReturned, NULL);
	if (ret == FALSE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_SET_LOGLV_MIN. Err=%u\n",
			__FUNCTION__, retVal);
	}

	// 3. CloseHandle MVOL_DEVICE
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
	return retVal;
}

#ifdef _WIN32_DEBUG_OOS
// DW-1153
PVOID g_pDrbdBaseAddr;		// base address of loaded drbd.sys
ULONG g_ulDrbdImageSize;		// image size of loaded drbd.sys
DWORD64 g_ModuleBase;			// base address of loaded drbd.pdb

// get base address and image size of loaded drbd.sys
BOOLEAN queryDrbdBase(VOID)
{
	DWORD dwSize = 0;
	NTSTATUS status;
	PVOID pDrbdAddr = NULL;
	BOOLEAN bRet = FALSE;
	PRTL_PROCESS_MODULES ModuleInfo = NULL;

	do	
	{
		status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &dwSize);

		if (status != STATUS_INFO_LENGTH_MISMATCH)
		{
			break;
		}

		ModuleInfo = (PRTL_PROCESS_MODULES)malloc(dwSize);

		if (NULL == ModuleInfo)
		{
			break;
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, ModuleInfo, dwSize, &dwSize);

		if (status != STATUS_SUCCESS)
		{
			break;
		}

		// found all loaded system modules.

		for (ULONG i = 0; i<ModuleInfo->NumberOfModules; i++)
		{
			PCHAR pFileName = (PCHAR)(ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName);
			if (strcmp(pFileName, DRBD_DRIVER_NAME) == 0)
			{
				// found loaded drbd.sys
				g_pDrbdBaseAddr = ModuleInfo->Modules[i].ImageBase;
				g_ulDrbdImageSize = ModuleInfo->Modules[i].ImageSize;
				bRet = TRUE;

				break;
			}
		}

	} while (false);
			
	if (NULL != ModuleInfo)
	{
		free(ModuleInfo);
		ModuleInfo = NULL;
	}

	return bRet;
}

BOOLEAN GetSymbolFileSize(const TCHAR* pFileName, DWORD& FileSize)
{
	BOOLEAN bRet = FALSE;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	if (pFileName == NULL)
	{
		_tprintf(_T("filePath is NULL\n"));
		return FALSE;	
	}

	do
	{
		hFile = CreateFile(pFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (hFile == INVALID_HANDLE_VALUE)
		{
			_tprintf(_T("CreateFile failed, %d \n"), GetLastError());
			break;
		}

		FileSize = GetFileSize(hFile, NULL);
		if (FileSize == INVALID_FILE_SIZE)
		{
			_tprintf(_T("GetFileSize failed, %d \n"), GetLastError());
			break;
		}
		
		bRet = TRUE;

	} while (false);

	if (INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}

	return bRet;
}

// 
BOOLEAN GetFuncNameWithOffset(ULONG ulOffset, PCHAR pszFuncName)
{
	BOOLEAN bRet = FALSE;
	DWORD64 SymAddr = g_ModuleBase + ulOffset;
	CSymbolInfoPackage sip;
	DWORD64 Displacement = 0;

	do
	{
		bRet = SymFromAddr(GetCurrentProcess(), SymAddr, &Displacement, &sip.si);
		if (!bRet)
		{
			_tprintf(_T("SymFromAddr fail : %d, offset(%Ix)\n"), GetLastError(), ulOffset);
			break;
		}

		if (sip.si.Tag != SymTagFunction)
		{
			break;
		}

		sprintf_s(pszFuncName, 50, "%s+0x%x", sip.si.Name, SymAddr - sip.si.Address);

		bRet = TRUE;

	} while (false);

	return bRet;
}

BOOLEAN GetFuncNameWithAddr(PVOID pAddr, PCHAR pszFuncName)
{
	BOOLEAN bRet = FALSE;
	ULONG_PTR ulOffset = 0;

	ulOffset = (ULONG_PTR)((DWORD64)pAddr - (DWORD64)g_pDrbdBaseAddr);
	
	if (ulOffset > g_ulDrbdImageSize)
	{
		// address is not in drbd range.
		return FALSE;
	}

	bRet = GetFuncNameWithOffset((ULONG)ulOffset, pszFuncName);

	return bRet;
}

// Convert call stack frame into readable function name.
VOID ConvertCallStack(PCHAR LogLine)
{
	CHAR szDelimiter[2] = FRAME_DELIMITER;
	PCHAR pTemp = LogLine;
	CHAR szStackFramesName[MAX_FUNCS_STR_LEN] = "";

	if (LogLine == NULL ||
		strstr(LogLine, OOS_TRACE_STRING) == NULL ||
		NULL == strchr(LogLine, szDelimiter[0]))
	{
		return;
	}
	
	while ((pTemp = strchr(pTemp, szDelimiter[0])) != NULL)
	{
		CHAR szAddr[MAX_FUNC_ADDR_LEN] = "";
		PVOID dwAddr = 0;
		CHAR szFuncName[MAX_FUNC_NAME_LEN] = "";
		pTemp++;
		PCHAR pEnd = strchr(pTemp, szDelimiter[0]);
		if (NULL == pEnd)
		{
			pEnd = strchr(pTemp, '\0');
			if (NULL == pEnd)
			{
				_tprintf(_T("invalid string!!\n"));
				continue;
			}
		}

		ULONG ulAddrLen = (ULONG)(pEnd - pTemp);

		strncpy_s(szAddr, pTemp, ulAddrLen);
		sscanf_s(szAddr, "%Ix", &dwAddr);

		strcat_s(szStackFramesName, MAX_FUNCS_STR_LEN, FRAME_DELIMITER);
		
		if (TRUE == GetFuncNameWithAddr(dwAddr, szFuncName))
			strcat_s(szStackFramesName, MAX_FUNCS_STR_LEN, szFuncName);
		else
			strcat_s(szStackFramesName, MAX_FUNCS_STR_LEN, szAddr);
	}

	pTemp = strchr(LogLine, szDelimiter[0]);
	if (NULL == pTemp)
	{
		_tprintf(_T("could not find delimiter from %s\n"), LogLine);
		return;
	}
	
	*pTemp = '\0';
	strcat_s(LogLine, MAX_DRBDLOG_BUF, szStackFramesName);	
}

// initialize out-of-sync trace.
// 1. get loaded drbd driver address, image size.
// 2. initialize and load drbd symbol
BOOLEAN InitOosTrace()
{
	BOOLEAN bRet = FALSE;
	DWORD dwFileSize = 0;
	DWORD64 BaseAddr = 0x10000000;
	TCHAR tszDrbdSymbolPath[MAX_PATH] = _T("");
#ifdef _UNICODE
	CHAR szDrbdSymbolPath[MAX_PATH] = "";
#endif

	GetCurrentFilePath(DRBD_SYMBOL_NAME, tszDrbdSymbolPath);
	
	do
	{
		if (g_pDrbdBaseAddr == NULL &&
			FALSE == queryDrbdBase())
		{
			_tprintf(_T("Failed to initialize drbd base\n"));
			break;			
		}

		_tprintf(_T("drbd.sys(%p), imageSize(%x)\n"), g_pDrbdBaseAddr, g_ulDrbdImageSize);

		DWORD Options = 0;

		Options = SymGetOptions();
		Options |= SYMOPT_DEBUG;
		Options |= SYMOPT_LOAD_LINES;

		SymSetOptions(Options);
		
		if (FALSE == SymInitialize(GetCurrentProcess(), NULL, FALSE))
		{
			_tprintf(_T("SymInitialize failed : %d\n"), GetLastError());
			break;
		}

		GetSymbolFileSize(tszDrbdSymbolPath, dwFileSize);

		if (0 == dwFileSize)
		{
			_tprintf(_T("Symbol file size is zero\n"));
			break;
		}

#ifdef _UNICODE
		if (0 == WideCharToMultiByte(CP_ACP, 0, tszDrbdSymbolPath, -1, (LPSTR)szDrbdSymbolPath, MAX_PATH, NULL, NULL))
		{
			_tprintf(_T("Failed to convert wchar to char : %d\n"), GetLastError());
			break;
		}

		g_ModuleBase = SymLoadModule64(GetCurrentProcess(), NULL, szDrbdSymbolPath, NULL, BaseAddr, dwFileSize);
#else
		g_ModuleBase = SymLoadModule64(GetCurrentProcess(), NULL, tszDrbdSymbolPath, NULL, BaseAddr, dwFileSize);
#endif
		if (0 == g_ModuleBase)
		{
			_tprintf(_T("SymLoadModule64 failed : %d\n"), GetLastError());
			break;
		}

		bRet = TRUE;

	} while (false);

	return bRet;
}

// initialize out-of-sync trace.
// 1. unload and clean up drbd symbol
VOID CleanupOosTrace()
{
	::SymUnloadModule64(GetCurrentProcess, g_ModuleBase);
	::SymCleanup(GetCurrentProcess());
}
#endif	// _WIN32_DEBUG_OOS

DWORD MVOL_GetDrbdLog(char* pszProviderName, BOOLEAN oosTrace)
{
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       retVal = ERROR_SUCCESS;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
	BOOL        ret = FALSE;
	PDRBD_LOG	pDrbdLog = NULL;

#ifdef _WIN32_DEBUG_OOS
	if (oosTrace)
		oosTrace = InitOosTrace();	
#endif

	// 1. Open MVOL_DEVICE
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed open drbd. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
	pDrbdLog = (PDRBD_LOG)malloc(DRBD_LOG_SIZE);
	if (!pDrbdLog) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed malloc. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
	// 2. DeviceIoControl with DRBD_LOG_SIZE parameter (DW-1054)
	ret = DeviceIoControl(hDevice, IOCTL_MVOL_GET_DRBD_LOG, pDrbdLog, DRBD_LOG_SIZE, pDrbdLog, DRBD_LOG_SIZE, &dwReturned, NULL);
	if (ret == FALSE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_GET_DRBD_LOG. Err=%u\n",
			__FUNCTION__, retVal);
	}
	else {
		HANDLE hLogFile = INVALID_HANDLE_VALUE;
		hLogFile = CreateFileA(pszProviderName, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hLogFile != INVALID_HANDLE_VALUE) {
			
			unsigned int loopcnt = min(pDrbdLog->totalcnt, LOGBUF_MAXCNT);
			if (pDrbdLog->totalcnt <= LOGBUF_MAXCNT) {
				for (unsigned int i = 0; i <= (loopcnt*MAX_DRBDLOG_BUF); i += MAX_DRBDLOG_BUF) {					
					DWORD dwWritten;
#ifdef _WIN32_DEBUG_OOS
					if (oosTrace)
						ConvertCallStack(&pDrbdLog->LogBuf[i]);
					else if (NULL != strstr(&pDrbdLog->LogBuf[i], OOS_TRACE_STRING))
					{
						// DW-1153: don't write out-of-sync trace log since user doesn't want to see..
						continue;
					}
#endif
					DWORD len = (DWORD)strlen(&pDrbdLog->LogBuf[i]);
					WriteFile(hLogFile, &pDrbdLog->LogBuf[i], len - 1, &dwWritten, NULL);
					WriteFile(hLogFile, "\r\n", 2, &dwWritten, NULL);
				}
			}
			else { // pDrbdLog->totalcnt > LOGBUF_MAXCNT
				unsigned int loopcnt1 = 0, loopcnt2 = 0;
				pDrbdLog->totalcnt = pDrbdLog->totalcnt%LOGBUF_MAXCNT;
				
				for (unsigned int i = (pDrbdLog->totalcnt + 1)*MAX_DRBDLOG_BUF; i < (LOGBUF_MAXCNT*MAX_DRBDLOG_BUF); i += MAX_DRBDLOG_BUF) {
					DWORD dwWritten;
#ifdef _WIN32_DEBUG_OOS
					if (oosTrace)
						ConvertCallStack(&pDrbdLog->LogBuf[i]);
					else if (NULL != strstr(&pDrbdLog->LogBuf[i], OOS_TRACE_STRING))
					{
						// DW-1153: don't write out-of-sync trace log since user doesn't want to see..
						continue;
					}
#endif
					DWORD len = (DWORD)strlen(&pDrbdLog->LogBuf[i]);
					WriteFile(hLogFile, &pDrbdLog->LogBuf[i], len - 1, &dwWritten, NULL);
					WriteFile(hLogFile, "\r\n", 2, &dwWritten, NULL);
				}

				for (unsigned int i = 0; i < (pDrbdLog->totalcnt + 1)*MAX_DRBDLOG_BUF; i += MAX_DRBDLOG_BUF) {
					DWORD dwWritten;
#ifdef _WIN32_DEBUG_OOS
					if (oosTrace)
						ConvertCallStack(&pDrbdLog->LogBuf[i]);
					else if (NULL != strstr(&pDrbdLog->LogBuf[i], OOS_TRACE_STRING))
					{
						// DW-1153: don't write out-of-sync trace log since user doesn't want to see..
						continue;
					}
#endif
					DWORD len = (DWORD)strlen(&pDrbdLog->LogBuf[i]);
					WriteFile(hLogFile, &pDrbdLog->LogBuf[i], len - 1, &dwWritten, NULL);
					WriteFile(hLogFile, "\r\n", 2, &dwWritten, NULL);
				}
			}
			CloseHandle(hLogFile);
		}
		else {
			retVal = GetLastError();
			fprintf(stderr, "LOG_ERROR: %s: Failed CreateFile. Err=%u\n",
				__FUNCTION__, retVal);
		}
	}
	// 3. CloseHandle MVOL_DEVICE
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
	if (pDrbdLog) {
		free(pDrbdLog);
	}
#ifdef _WIN32_DEBUG_OOS
	if (oosTrace){
		CleanupOosTrace();
	}
#endif	

	return retVal;
}

#ifdef _WIN32_DEBUG_OOS
DWORD WriteSearchLogIfMatch(HANDLE hResFile, PCHAR pszLine, unsigned long long ullSearchSector)
{
	DWORD dwRet = ERROR_SUCCESS;
	DWORD dwRead = 0;

	unsigned long long startSector = -1, endSector = -1;
	CHAR szSector[1024] = "";
	char *pSector = NULL;
	
	do
	{
		pSector = strstr(pszLine, "sector(") + strlen("sector(");
		if (NULL == pSector)
		{
			dwRet = ERROR_INVALID_DATA;
			_tprintf(_T("could not find sector string\n"));
			break;
		}
		
		strcpy_s(szSector, pSector);
		
		char *pSectorEnd = strchr(szSector, ')');
		if (NULL == pSectorEnd)
		{
			dwRet = ERROR_INVALID_DATA;
			_tprintf(_T("could not find sector string2\n"));
			break;
		}
		
		*pSectorEnd = '\0';
		
#define SECTOR_DELIMITER " ~ "

		pSectorEnd = strstr(szSector, SECTOR_DELIMITER);
		if (NULL == pSectorEnd)
		{
			dwRet = ERROR_INVALID_DATA;
			_tprintf(_T("could not find sector delimiter\n"));
			break;
		}
		
		pSector = szSector;
		*pSectorEnd = '\0';

		startSector = atoll(pSector);
		pSector = pSectorEnd + strlen(SECTOR_DELIMITER);
		endSector = atoll(pSector);

		if (startSector < 0 || endSector < 0)
		{
			dwRet = ERROR_INVALID_DATA;
			_tprintf(_T("we got invalid sector(%llu ~ %llu)\n"), startSector, endSector);
			break;
		}
		
		// check if ullSearchSector is between startSector and endSector
		if (ullSearchSector < startSector ||
			ullSearchSector > endSector)
		{
			// we are not interested in this sector, just return success.
			dwRet = ERROR_SUCCESS;
			break;
		}
		
		// write res file.
		if (!WriteFile(hResFile, pszLine, strlen(pszLine), &dwRead, NULL))
		{
			dwRet = GetLastError();
			_tprintf(_T("WriteFile1 failed, err : %d\n"), dwRet);
			break;
		}

		if (!WriteFile(hResFile, "\r\n", 2, &dwRead, NULL))
		{
			dwRet = GetLastError();
			_tprintf(_T("WriteFile1 failed, err : %d\n"), dwRet);
			break;
		}

		dwRet = ERROR_SUCCESS;
	} while (false);

	

	return dwRet;
}

DWORD MVOL_SearchOosLog(LPCTSTR pSrcFilePath, LPCTSTR szSector)
{
	DWORD dwRet = ERROR_SUCCESS;
	DWORD dwRead = 0;
	HANDLE hSrcFile = INVALID_HANDLE_VALUE;
	HANDLE hSearchedResFile = INVALID_HANDLE_VALUE;
	TCHAR ptSrcFilePath[MAX_PATH] = _T("");
	TCHAR ptResFilePath[MAX_PATH] = _T("");
	TCHAR ptSector[128] = _T("");
	unsigned long long ullSector = atoll((const char*)szSector);

	char *buff = NULL;

#ifdef _UNICODE
	if (0 == MultiByteToWideChar(CP_ACP, 0, (LPSTR)pSrcFilePath, -1, ptSrcFilePath, MAX_PATH))
	{
		dwRet = GetLastError();
		_tprintf(_T("MultiByteToWideChar failed, err : %d\n"), dwRet);
		return dwRet;
	}
	if (0 == MultiByteToWideChar(CP_ACP, 0, (LPSTR)szSector, -1, ptSector, 128))
	{
		dwRet = GetLastError();
		_tprintf(_T("MultiByteToWideChar failed, err : %d\n"), dwRet);
		return dwRet;
}
#else
	strcpy(ptSrcFilePath, pSrcFilePath);
	strcpy(ptSector, szSector);
#endif

	do
	{
		hSrcFile = CreateFile(ptSrcFilePath, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hSrcFile == INVALID_HANDLE_VALUE)
		{
			dwRet = GetLastError();
			_tprintf(_T("CreateFile for %s failed, %d \n"), ptSrcFilePath, dwRet);
			break;
		}

		LARGE_INTEGER liFileSize = { 0, };

		if (!GetFileSizeEx(hSrcFile, &liFileSize) ||
			!liFileSize.QuadPart)
		{
			dwRet = GetLastError();
			_tprintf(_T("GetFileSizeEx failed, %d \n"), dwRet);
			break;
		}
		
		buff = new char[liFileSize.QuadPart];
		if (!buff)
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
			printf("failed to alloc buff\n");
			break;
		}

		if (!ReadFile(hSrcFile, buff, liFileSize.QuadPart, &dwRead, NULL))
		{
			dwRet = GetLastError();
			_tprintf(_T("ReadFile failed, %d \n"), dwRet);
			break;
		}
		
		_stprintf_s(ptResFilePath, _T("%s_sector%s"), ptSrcFilePath, ptSector);
		_tprintf(_T("resfile : %s\n"), ptResFilePath);
				
		hSearchedResFile = CreateFile(ptResFilePath, GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hSearchedResFile == INVALID_HANDLE_VALUE)
		{
			dwRet = GetLastError();
			_tprintf(_T("CreateFile for %s failed, %d \n"), ptResFilePath, dwRet);
			break;
		}
		
		char *pLine = buff, *pTemp = buff;
		pTemp = strstr(pLine, "\0");		
		while (pTemp = strstr(pLine, "\r\n"))
		{
			CHAR szLineBuf[1024] = "";
			*pTemp = '\0';
			strcpy_s(szLineBuf, pLine);	

			// skip unless it's oos log.
			if (strstr(szLineBuf, OOS_TRACE_STRING) == NULL)
			{
				pLine = pTemp + 2;
				continue;
			}
			
			// write log if given sector is accessed
			dwRet = WriteSearchLogIfMatch(hSearchedResFile, szLineBuf, ullSector);
			if (ERROR_SUCCESS != dwRet)
			{
				break;
			}
			
			// go next
			pLine = pTemp + 2;
		}

		if (ERROR_SUCCESS != dwRet)
		{
			break;
		}
				
		if (strchr(pLine, '\0') != NULL)
		{
			CHAR szLineBuf[1024] = "";			
			strcpy_s(szLineBuf, pLine);
			
			// skip unless it's oos log.
			if (strstr(szLineBuf, OOS_TRACE_STRING) != NULL)
			{
				// check if given sector is accessed
				WriteSearchLogIfMatch(hSearchedResFile, szLineBuf, ullSector);
			}
		}

	} while (false);

	if (buff)
	{
		delete(buff);
		buff = NULL;
	}

	if (INVALID_HANDLE_VALUE != hSearchedResFile)
	{
		CloseHandle(hSearchedResFile);
		hSearchedResFile = INVALID_HANDLE_VALUE;
	}

	if (INVALID_HANDLE_VALUE != hSrcFile)
	{
		CloseHandle(hSrcFile);
		hSrcFile = INVALID_HANDLE_VALUE;
	}

	return dwRet;
}

DWORD MVOL_ConvertOosLog(LPCTSTR pSrcFilePath)
{
	DWORD dwRet = ERROR_SUCCESS;
	BOOLEAN bRet = FALSE;
	DWORD dwRead = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hConverted = INVALID_HANDLE_VALUE;
	TCHAR ptSrcFilePath[MAX_PATH] = _T("");
	TCHAR ptOrgRenamedFilePath[MAX_PATH] = _T("");
	char *buff = NULL;
	
#ifdef _UNICODE
	if (0 == MultiByteToWideChar(CP_ACP, 0, (LPSTR)pSrcFilePath, -1, ptSrcFilePath, MAX_PATH))
	{
		dwRet = GetLastError();
		_tprintf(_T("MultiByteToWideChar failed, err : %d\n"), dwRet);
		return dwRet;
	}
#else
	strcpy(ptSrcFilePath, pSrcFilePath);
#endif

	do
	{
		bRet = InitOosTrace();
		if (!bRet)
		{
			_tprintf(_T("InitOosTrace failed, %d \n"), GetLastError());
			break;
		}

		_tcscpy_s(ptOrgRenamedFilePath, ptSrcFilePath);
		_tcscat_s(ptOrgRenamedFilePath, _T("_org"));

		if (!MoveFile(ptSrcFilePath, ptOrgRenamedFilePath))
		{
			dwRet = GetLastError();
			_tprintf(_T("MoveFile for (%s -> %s) failed, %d \n"), ptSrcFilePath, ptOrgRenamedFilePath, dwRet);
			break;
		}

		hFile = CreateFile(ptOrgRenamedFilePath, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			dwRet = GetLastError();
			_tprintf(_T("CreateFile for %s failed, %d \n"), ptSrcFilePath, dwRet);
			break;
		}

		LARGE_INTEGER liFileSize = { 0, };

		if (!GetFileSizeEx(hFile, &liFileSize) ||
			!liFileSize.QuadPart)
		{
			dwRet = GetLastError();
			_tprintf(_T("GetFileSizeEx failed, %d \n"), dwRet);
			break;
		}

		buff = new char[liFileSize.QuadPart];
		if (!buff)
		{
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
			printf("failed to alloc buff\n");
			break;
		}

		if (!ReadFile(hFile, buff, liFileSize.QuadPart, &dwRead, NULL))
		{
			dwRet = GetLastError();
			_tprintf(_T("ReadFile failed, %d \n"), dwRet);
			break;
		}

		hConverted = CreateFile(ptSrcFilePath, GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			dwRet = GetLastError();
			_tprintf(_T("CreateFile for %s failed, %d \n"), ptSrcFilePath, dwRet);
			break;
		}

		char *pLine = buff, *pTemp = buff;
		while (pTemp = strstr(pLine, "\r\n"))
		{
			CHAR szLineBuf[1024] = "";
			*pTemp = '\0';
			strcpy_s(szLineBuf, pLine);
			// convert callstack by line
			ConvertCallStack(szLineBuf);
			WriteFile(hConverted, szLineBuf, strlen(szLineBuf), &dwRead, NULL);
			WriteFile(hConverted, "\r\n", 2, &dwRead, NULL);

			// go next
			pLine = pTemp+2;
		}

		_tprintf(_T("Converted Log Path : %s\n"), ptSrcFilePath);

	} while (false);

	
	if (buff)
		delete(buff);

	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	if (hConverted != INVALID_HANDLE_VALUE)
		CloseHandle(hConverted);

	if (bRet)
		CleanupOosTrace();

	return dwRet;
}
#endif

DWORD MVOL_SetHandlerUse(PHANDLER_INFO pHandler)
{
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       retVal = ERROR_SUCCESS;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
	BOOL        ret = FALSE;

	if (pHandler == NULL || pHandler->use < 0 || pHandler->use > 1)
	{
		fprintf(stderr, "LOG_ERROR: %s: Invalid parameter\n", __FUNCTION__);
		return ERROR_INVALID_PARAMETER;
	}

	// 1. Open MVOL_DEVICE
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed open drbd. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}


	// 2. DeviceIoControl with HANDLER_USE parameter
	ret = DeviceIoControl(hDevice, IOCTL_MVOL_SET_HANDLER_USE, pHandler, sizeof(HANDLER_INFO), NULL, 0, &dwReturned, NULL);
	if (ret == FALSE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_SET_HANDLER_USE. Err=%u\n",
			__FUNCTION__, retVal);
	}

	// 3. CloseHandle MVOL_DEVICE
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
	return retVal;
}
