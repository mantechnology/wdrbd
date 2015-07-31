#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include "mvol.h"

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
        NULL, 0, NULL, 0, &dwReturned, NULL);
    if (!ok)
    {
        retVal = GetLastError();
        fprintf(stderr, "%s: Failed IOCTL_MVOL_MOUNT_VOLUME. ErrorCode(%u)\n",
            __FUNCTION__, retVal);
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
