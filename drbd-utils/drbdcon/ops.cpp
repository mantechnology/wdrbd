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

	DWORD dwReturned;
	PVOID buffer = malloc(8192);
	memset(buffer, 0, 8192);
 	if (!DeviceIoControl(handle, IOCTL_MVOL_GET_VOLUMES_INFO,
			NULL, 0, buffer, 8192, &dwReturned, NULL))
	{
		res = GetLastError();
		fprintf(stderr, "%s: ioctl err. GetLastError(%d)\n", __FUNCTION__, res);
		goto out;
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
		printf(" PhysicalDeviceName Minor Lock\n");
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

	return res;
}

DWORD
MVOL_InitThread( PWCHAR PhysicalVolume )
{
    HANDLE			rootHandle = INVALID_HANDLE_VALUE;
    DWORD			res = ERROR_SUCCESS;
    ULONG			iolen;
    ULONG			len;
    MVOL_VOLUME_INFO	volumeInfo = {0,};

    if( PhysicalVolume == NULL )
    {
        printf("LOG_ERROR: MVOL_InitThread: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    if( wcslen(PhysicalVolume) > MAXDEVICENAME )
    {
        printf("LOG_ERROR: MVOL_InitThread: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    rootHandle = OpenDevice( MVOL_DEVICE );
    if( rootHandle == INVALID_HANDLE_VALUE )
    {
        res = GetLastError();
        printf("LOG_ERROR: MVOL_InitThread: cannot open root device, err=%u\n", res);
        return res;
    }

    wcscpy_s( volumeInfo.PhysicalDeviceName, PhysicalVolume );
    len = sizeof(MVOL_VOLUME_INFO);
    if( !DeviceIoControl(rootHandle, IOCTL_MVOL_INIT_VOLUME_THREAD,
        &volumeInfo, len, NULL, 0, &iolen, NULL) )
    {
        res = GetLastError();
        printf("LOG_ERROR: MVOL_InitThread: ioctl err=%d\n", res);
        goto out;
    }

    res = ERROR_SUCCESS;
out:
    if( rootHandle != INVALID_HANDLE_VALUE )
        CloseHandle(rootHandle);

    return res;
}

DWORD
MVOL_InitThread( CHAR DriveLetter )
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

    ret = DeviceIoControl( hDrive, IOCTL_MVOL_INIT_VOLUME_THREAD,
        NULL, 0, NULL, 0, &dwReturned, NULL );
    if( ret == FALSE )
    {
        retVal = GetLastError();
        fprintf( stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_INIT_VOLUME_THREAD. Err=%u\n",
            __FUNCTION__, retVal );
        goto out;
    }

    retVal = ERROR_SUCCESS;
out:
    if( hDrive != INVALID_HANDLE_VALUE )    CloseHandle( hDrive );

    return retVal;
}

DWORD
MVOL_CloseThread( PWCHAR PhysicalVolume )
{
    HANDLE			rootHandle=INVALID_HANDLE_VALUE;
    DWORD			res = ERROR_SUCCESS;
    ULONG			iolen;
    ULONG			len;
    MVOL_VOLUME_INFO	volumeInfo = {0,};

    if( PhysicalVolume == NULL )
    {
        printf("LOG_ERROR: MVOL_CloseThread: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    if( wcslen(PhysicalVolume) > MAXDEVICENAME )
    {
        printf("LOG_ERROR: MVOL_CloseThread: invalid paramter\n");
        return ERROR_INVALID_PARAMETER;
    }

    rootHandle = OpenDevice( MVOL_DEVICE );
    if( rootHandle == INVALID_HANDLE_VALUE )
    {
        res = GetLastError();
        printf("LOG_ERROR: MVOL_CloseThread: cannot open root device, err=%u\n", res);
        return res;
    }

    wcscpy_s( volumeInfo.PhysicalDeviceName, PhysicalVolume );
    len = sizeof(MVOL_VOLUME_INFO);
    if( !DeviceIoControl(rootHandle, IOCTL_MVOL_CLOSE_VOLUME_THREAD,
        &volumeInfo, len, NULL, 0, &iolen, NULL) )
    {
        res = GetLastError();
        printf("LOG_ERROR: MVOL_CloseThread: ioctl err=%d\n", res);
        goto out;
    }

    res = ERROR_SUCCESS;
out:
    if( rootHandle != INVALID_HANDLE_VALUE )
        CloseHandle(rootHandle);

    return res;
}

DWORD
MVOL_CloseThread( CHAR DriveLetter )
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

    ret = DeviceIoControl( hDrive, IOCTL_MVOL_CLOSE_VOLUME_THREAD,
        NULL, 0, NULL, 0, &dwReturned, NULL );
    if( ret == FALSE )
    {
        retVal = GetLastError();
        fprintf( stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_CLOSE_VOLUME_THREAD. Err=%u\n",
            __FUNCTION__, retVal );
        goto out;
    }

    retVal = ERROR_SUCCESS;
out:
    if( hDrive != INVALID_HANDLE_VALUE )    CloseHandle( hDrive );

    return retVal;
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

	// Get log file full path( [current process path]\[provider name].log )
	dwStatus = GetLogFilePath(tszProviderName, szLogFilePath);
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

DWORD GetLogFilePath(LPCTSTR pszLogFileName, PTSTR pszLogFileFullPath)
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

	// Concatenate [logfilename].[ext]
	StringCchCat(szLogFilePath, MAX_PATH, pszLogFileName);
	StringCchCat(szLogFilePath, MAX_PATH, LOG_FILE_EXT);

	StringCchCopy(pszLogFileFullPath, MAX_PATH, szLogFilePath);

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
		(pLml->nType != LOGGING_TYPE_SYSLOG && pLml->nType != LOGGING_TYPE_SVCLOG && pLml->nType != LOGGING_TYPE_DBGLOG) ||
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

DWORD MVOL_GetDrbdLog(LPCTSTR pszProviderName)
{
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       retVal = ERROR_SUCCESS;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
	BOOL        ret = FALSE;
	PDRBD_LOG	pDrbdLog = NULL;

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
		hLogFile = CreateFile(L"drbdService.log", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hLogFile != INVALID_HANDLE_VALUE) {
			unsigned int loopcnt = min(pDrbdLog->totalcnt, LOGBUF_MAXCNT);
			if (pDrbdLog->totalcnt <= LOGBUF_MAXCNT) {
				for (unsigned int i = 0; i < (loopcnt*MAX_DRBDLOG_BUF); i += MAX_DRBDLOG_BUF) {
					//printf("%s", &pDrbdLog->LogBuf[i]);
					DWORD dwWritten;
					DWORD len = (DWORD)strlen(&pDrbdLog->LogBuf[i]);
					WriteFile(hLogFile, &pDrbdLog->LogBuf[i], len - 1, &dwWritten, NULL);
					WriteFile(hLogFile, "\r\n", 2, &dwWritten, NULL);
				}
			}
			else { // pDrbdLog->totalcnt > LOGBUF_MAXCNT
				unsigned int loopcnt1 = 0, loopcnt2 = 0;
				pDrbdLog->totalcnt = pDrbdLog->totalcnt%LOGBUF_MAXCNT - 1;
				
				for (unsigned int i = pDrbdLog->totalcnt*MAX_DRBDLOG_BUF; i < (LOGBUF_MAXCNT*MAX_DRBDLOG_BUF); i += MAX_DRBDLOG_BUF) {
					DWORD dwWritten;
					DWORD len = (DWORD)strlen(&pDrbdLog->LogBuf[i]);
					WriteFile(hLogFile, &pDrbdLog->LogBuf[i], len - 1, &dwWritten, NULL);
					WriteFile(hLogFile, "\r\n", 2, &dwWritten, NULL);
				}

				for (unsigned int i = 0; i < (pDrbdLog->totalcnt*MAX_DRBDLOG_BUF); i += MAX_DRBDLOG_BUF) {
					DWORD dwWritten;
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
	return retVal;
}

