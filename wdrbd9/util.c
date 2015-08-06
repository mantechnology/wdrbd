#include <Ntifs.h>
#include <ntddk.h>
#include <stdlib.h>
#include <Mountmgr.h> 
#include "drbd_windrv.h"	/// SEO:
#include "drbd_wingenl.h"	/// SEO:
#include "proto.h"
#include "drbd_int.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, RetrieveVolumeGuid)
#ifdef _WIN32_MVFL
#pragma alloc_text(PAGE, FsctlDismountVolume)
#pragma alloc_text(PAGE, FsctlLockVolume)
#pragma alloc_text(PAGE, FsctlUnlockVolume)
#pragma alloc_text(PAGE, FsctlCreateVolume)
#endif
#endif


NTSTATUS
GetDeviceName( PDEVICE_OBJECT DeviceObject, PWCHAR Buffer, ULONG BufferLength )
{
	NTSTATUS					status;
	POBJECT_NAME_INFORMATION	nameInfo=NULL;
	ULONG						size;

	nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag( NonPagedPool, MAXDEVICENAME*sizeof(WCHAR), '26DW' );
	if( !nameInfo )
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory( nameInfo, MAXDEVICENAME * sizeof(WCHAR) );
	status = ObQueryNameString( DeviceObject, nameInfo, MAXDEVICENAME, &size );
	if( !NT_SUCCESS(status) )
	{
		WDRBD_ERROR("cannot get device name, err=0x%x\n", status);
		ExFreePool( nameInfo );
		return status;
	}

	if( BufferLength > nameInfo->Name.Length )
	{
		memcpy( Buffer, nameInfo->Name.Buffer, nameInfo->Name.Length );
	}
	else
	{
		memcpy( Buffer, nameInfo->Name.Buffer, BufferLength-4 );
	}

	ExFreePool( nameInfo );
	return STATUS_SUCCESS;
}

#ifdef _WIN32_MVFL
/**
* @brief    커널단에서 FSCTL_DISMOUNT_VOLUME을 수행한다.
*           이 명령은 볼륨의 사용유무에 상관없이 강제적으로 수행이 가능하므로 
*           lock - dismount - unlock 과정으로 사용할 것을 권고한다.
*           http://msdn.microsoft.com/en-us/library/windows/desktop/aa364562(v=vs.85).aspx 참조
*           FsctlLockVolume() - FsctlDismountVolume() - FsctlUnlockVolume() 으로 사용하면 되는데
*           Open시킨 볼륨의 HANDLE 값은 VOLUME_EXTENSION에 있다.
*           하지만 필요시 이 명령만 단독으로 사용가능하다.
*/
NTSTATUS FsctlDismountVolume(unsigned int minor)
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
#if 0
	PFILE_OBJECT pVolumeFileObject = NULL;
#endif
    HANDLE hFile = NULL;
    UNICODE_STRING device_name;

    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor);
    if (!pvext)
    {
        WDRBD_WARN("get_targetdev_by_minor Failed.\n");
        return STATUS_UNSUCCESSFUL;
    }

    RtlUnicodeStringInit(&device_name, pvext->PhysicalDeviceName);

    __try
    {
        if (!pvext->LockHandle)
        {
            InitializeObjectAttributes(&ObjectAttributes,
                &device_name,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                NULL,
                NULL);

            status = ZwCreateFile(&hFile,
                SYNCHRONIZE | FILE_READ_DATA,
                &ObjectAttributes,
                &StatusBlock,
                NULL,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0);
            if (!NT_SUCCESS(status))
            {
                WDRBD_WARN("ZwCreateFile Failed. status(0x%x)\n", status);
                __leave;
            }
        }
        else
        {
            hFile = pvext->LockHandle;
        }

#if 0
        status = ObReferenceObjectByHandle(hFile,
            FILE_READ_DATA,
            *IoFileObjectType,
            KernelMode,
            &pVolumeFileObject,
            NULL);
        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("ObReferenceObjectByHandle Failed. status(0x%x)\n", status);
            __leave;
        }
#endif
        status = ZwFsControlFile(hFile, 0, 0, 0, &StatusBlock, FSCTL_DISMOUNT_VOLUME, 0, 0, 0, 0);
        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("ZwFsControlFile Failed. status(0x%x)\n", status);
            __leave;
        }

        WDRBD_INFO("volume(%wZ) dismounted\n", &device_name);
    }
    __finally
    {
        if (!pvext->LockHandle && hFile)    // dismount를 단독으로 수행했을 경우
        {
            ZwClose(hFile);
        }
#if 0
        if (pVolumeFileObject)
        {
            ObDereferenceObject(pVolumeFileObject);
        }
#endif
    }

    return status;
}

/**
* @brief    커널단에서 FSCTL_LOCK_VOLUME을 수행한다.
*           lock 성공시 볼륨의 HANDLE값은 VOLUME_EXTENSION 구조체내에 가지게 되며
*           이 값은 FsctlUnlockVolume()을 해서 반드시 ZwClose 시켜 주어야 한다.
*           lock 실패시 FsctlUnlockVolume()을 할 필요는 없다.
*           볼륨을 어디선가 참조하고 있을 경우는 lock이 실패한다.
*/
NTSTATUS FsctlLockVolume(unsigned int minor)
{
    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor);
    if (!pvext)
    {
        WDRBD_WARN("get_targetdev_by_minor Failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
    HANDLE hFile = NULL;
    UNICODE_STRING device_name;

    RtlUnicodeStringInit(&device_name, pvext->PhysicalDeviceName);

    __try
    {
        InitializeObjectAttributes(&ObjectAttributes,
            &device_name,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        status = ZwCreateFile(&hFile,
            FILE_READ_DATA | FILE_WRITE_DATA,
            &ObjectAttributes,
            &StatusBlock,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);
        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("ZwCreateFile Failed. status(0x%x)\n", status);
            __leave;
        }

        int i = 0;
        do
        {
            status = ZwFsControlFile(hFile, 0, 0, 0, &StatusBlock, FSCTL_LOCK_VOLUME, 0, 0, 0, 0);            
            ++i;
        } while ((STATUS_ACCESS_DENIED == status) && i < 3);

        if (!NT_SUCCESS(status))
        {
            //printk(KERN_ERR "ZwFsControlFile Failed. status(0x%x)\n", status);
            WDRBD_ERROR("ZwFsControlFile Failed. status(0x%x) &ObjectAttributes(0x%p) hFile(0x%p)\n", status, &ObjectAttributes, hFile);
            __leave;
        }
        
        pvext->LockHandle = hFile;
        hFile = NULL;

        WDRBD_INFO("volume(%wZ) locked. handle(0x%p)\n", &device_name, pvext->LockHandle);
    }
    __finally
    {
        if (hFile)
        {
            ZwClose(hFile);
        }
    }

    return status;
}

/**
* @brief    커널단에서 FSCTL_UNLOCK_VOLUME을 수행한다.
*           FsctlLockVolume()에서 lock을 성공했을 시 볼륨의 HANDLE 값을
*           Unlock후 ZwClose 시켜준다. 그리고 NULL로 다시 초기화 한다.
*           볼륨의 HANDLE 값은 VOLUME_EXTENSION 구조체내에서 가지고 온다.
*/
NTSTATUS FsctlUnlockVolume(unsigned int minor)
{
    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor);
    if (!pvext)
    {
        WDRBD_WARN("get_targetdev_by_minor Failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    if (!pvext->LockHandle)
    {
        WDRBD_WARN("volume(%ws) not locked\n", pvext->PhysicalDeviceName);
        return STATUS_NOT_LOCKED;
    }

    NTSTATUS status = STATUS_SUCCESS;
    IO_STATUS_BLOCK StatusBlock;

    __try
    {
        status = ZwFsControlFile(pvext->LockHandle, 0, 0, 0, &StatusBlock, FSCTL_UNLOCK_VOLUME, 0, 0, 0, 0);
        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("ZwFsControlFile Failed. status(0x%x)\n", status);
            __leave;
        }

        WDRBD_INFO("volume(%ws) unlocked\n", pvext->PhysicalDeviceName);
    }
    __finally
    {
        ZwClose(pvext->LockHandle);
        pvext->LockHandle = NULL;
    }

    return status;
}

/**
*/
NTSTATUS FsctlFlushVolume(unsigned int minor)
{
    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor);
    if (!pvext)
    {
        WDRBD_WARN("get_targetdev_by_minor Failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
    HANDLE hFile = NULL;
    UNICODE_STRING device_name;

    RtlUnicodeStringInit(&device_name, pvext->PhysicalDeviceName);

    __try
    {
        InitializeObjectAttributes(&ObjectAttributes,
            &device_name,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        status = ZwCreateFile(&hFile,
            FILE_READ_DATA | FILE_WRITE_DATA,
            &ObjectAttributes,
            &StatusBlock,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);

        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("ZwCreateFile Failed. status(0x%x)\n", status);
            __leave;
        }

        status = ZwFlushBuffersFile(hFile, &StatusBlock);
    }
    __finally
    {
        if (hFile)
        {
            ZwClose(hFile);
        }
    }

    return status;
}

/**
*/
NTSTATUS FsctlCreateVolume(unsigned int minor)
{
    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor);
    if (!pvext)
    {
        WDRBD_WARN("get_targetdev_by_minor Failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
    HANDLE hFile = NULL;
    UNICODE_STRING device_name;

    RtlUnicodeStringInit(&device_name, pvext->PhysicalDeviceName);

    __try
    {
        InitializeObjectAttributes(&ObjectAttributes,
            &device_name,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        status = ZwCreateFile(&hFile,
            FILE_READ_DATA | FILE_WRITE_DATA,
            &ObjectAttributes,
            &StatusBlock,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            NULL,
            0);

        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("ZwCreateFile Failed. status(0x%x)\n", status);
            __leave;
        }
    }
    __finally
    {
        if (hFile)
        {
            ZwClose(hFile);
        }
    }

    return status;
}

#endif

PVOLUME_EXTENSION
mvolSearchDevice( PWCHAR PhysicalDeviceName )
{
	PROOT_EXTENSION		RootExtension = NULL;
	PVOLUME_EXTENSION	VolumeExtension = NULL;

	RootExtension = mvolRootDeviceObject->DeviceExtension;
	VolumeExtension = RootExtension->Head;
	while( VolumeExtension != NULL )
	{
		/// SEO: 대소문자 구분 제거
		if( !_wcsicmp(VolumeExtension->PhysicalDeviceName, PhysicalDeviceName) )
		{
			return VolumeExtension;
		}

		VolumeExtension = VolumeExtension->Next;
	}
	
	return NULL;
}

VOID
mvolAddDeviceList( PVOLUME_EXTENSION pEntry )
{
	PROOT_EXTENSION		RootExtension = mvolRootDeviceObject->DeviceExtension;
	PVOLUME_EXTENSION	pList = RootExtension->Head;

	/// 리스트가 비었을 경우
	if( pList == NULL )
	{
		RootExtension->Head = pEntry;
		InterlockedIncrement16( &RootExtension->Count );
		return ;
	}

	while( pList->Next != NULL )
	{
		pList = pList->Next;
	}

	pList->Next = pEntry;
	InterlockedIncrement16( &RootExtension->Count );
	return ;
}

VOID
mvolDeleteDeviceList( PVOLUME_EXTENSION pEntry )
{
	PROOT_EXTENSION		RootExtension = mvolRootDeviceObject->DeviceExtension;
	PVOLUME_EXTENSION	pList = RootExtension->Head;
	PVOLUME_EXTENSION	pTemp = NULL;

	/// 리스트가 비었을 경우
	if( pList == NULL )	return ;
	/// 삭제할 Entry가 헤더일 경우
    if (pList == pEntry)
	{
		RootExtension->Head = pList->Next;
		InterlockedDecrement16( &RootExtension->Count );
		return ;
	}

    while (pList->Next && pList->Next != pEntry)
	{
		pList = pList->Next;
	}

	/// 찾지 못했을 경우
	if( pList->Next == NULL )	return ;

	pTemp = pList->Next;
	pList->Next = pTemp->Next;
	InterlockedDecrement16( &RootExtension->Count );
}

ULONG
mvolGetDeviceCount()
{
	PROOT_EXTENSION		RootExtension = NULL;
	PVOLUME_EXTENSION	VolumeExtension = NULL;
	ULONG			count = 0;
	
	RootExtension = mvolRootDeviceObject->DeviceExtension;
	VolumeExtension = RootExtension->Head;
	while( VolumeExtension != NULL )
	{
		count++;
		VolumeExtension = VolumeExtension->Next;
	}

	WDRBD_TRACE("DeviceCount=%d\n", count);

	return count;
}

VOID
MVOL_LOCK()
{
	NTSTATUS					status;
	
	status = KeWaitForMutexObject( &mvolMutex, Executive, KernelMode, FALSE, NULL );
	if( !NT_SUCCESS(status) )
	{
		WDRBD_ERROR("cannot wait\n");
	}
}

VOID
MVOL_UNLOCK()
{
	KeReleaseMutex( &mvolMutex, FALSE );
}

VOID
COUNT_LOCK( PVOLUME_EXTENSION VolumeExtension )
{
	NTSTATUS	status;

	status = KeWaitForMutexObject( &VolumeExtension->CountMutex, Executive, KernelMode, FALSE, NULL );
	if( !NT_SUCCESS(status) )
	{
		WDRBD_ERROR("cannot wait\n");
	}
}

VOID
COUNT_UNLOCK( PVOLUME_EXTENSION VolumeExtension )
{
	KeReleaseMutex( &VolumeExtension->CountMutex, FALSE );
}

VOID
ResolveDriveLetters(VOID)
{
	PROOT_EXTENSION		RootExtension = NULL;
	PVOLUME_EXTENSION	VolumeExtension = NULL;
	NTSTATUS		status;

	MVOL_LOCK(); 
	RootExtension = mvolRootDeviceObject->DeviceExtension;
	VolumeExtension = RootExtension->Head;

	while( VolumeExtension != NULL )
	{
		UNICODE_STRING DeviceName;
		UNICODE_STRING DriveLetter;

		RtlInitUnicodeString(&DeviceName, VolumeExtension->PhysicalDeviceName);
		status = GetDriverLetterByDeviceName(&DeviceName, &DriveLetter);
		if (NT_SUCCESS(status))
		{
			PCHAR p = (PCHAR) DriveLetter.Buffer;
			VolumeExtension->Letter = toupper(*p);
			VolumeExtension->VolIndex = VolumeExtension->Letter - 'C'; // VolIndex be changed!
			
			WDRBD_INFO("%ws idx=%d letter=%c\n",
                VolumeExtension->PhysicalDeviceName, VolumeExtension->VolIndex, VolumeExtension->Letter);
		}
		else
		{
			WDRBD_WARN("%ws org_idx:%d. it's maybe not disk type. Ignored.\n",
                VolumeExtension->PhysicalDeviceName,  VolumeExtension->VolIndex);
			// IoVolumeDeviceToDosName에서 오류! 0xC0000034 STATUS_OBJECT_NAME_NOT_FOUND
		}

		VolumeExtension = VolumeExtension->Next;
	}
	MVOL_UNLOCK();
}

/**
* @brief
*   볼륨의 unique id를 구해온다.
*   이 id는 MOUNTDEV_UNIQUE_ID 구조체에 담겨져 있으며 ExAllocatePool() 으로
*   동적 메모리 할당을 하여 return 한다. 따라서 이 함수를 사용하는 쪽에서 반드시
*   ExFreePool() 을 하여 메모리 해제를 해주어야 한다.
*   MOUNTDEV_UNIQUE_ID에 관해서는 <http://msdn.microsoft.com/en-us/library/windows/hardware/ff567603(v=vs.85).aspx> 참조
* @param
*   volmgr - 드라이버의 인스턴스 오브젝트 포인터
* @return
*   PMOUNTDEV_UNIQUE_ID 타입의 볼륨 unique id
*/
PMOUNTDEV_UNIQUE_ID RetrieveVolumeGuid(PDEVICE_OBJECT devObj)
{
    PMOUNTDEV_UNIQUE_ID guid = NULL;
    NTSTATUS result = STATUS_SUCCESS;
    SIZE_T cbBuf = sizeof(MOUNTDEV_UNIQUE_ID) + 256;

    PAGED_CODE();
    for (;;)
    {
        PIRP req = NULL;
        IO_STATUS_BLOCK ioStatus;
        KEVENT evnt;

        KeInitializeEvent(&evnt, NotificationEvent, FALSE);

        guid = (PMOUNTDEV_UNIQUE_ID)ExAllocatePool(PagedPool, cbBuf);
        if (NULL == guid)
        {
            WDRBD_TRACE("Out of memory.\n");
            return NULL;
        }

        req = IoBuildDeviceIoControlRequest(IOCTL_MOUNTDEV_QUERY_UNIQUE_ID
            , devObj, NULL, 0, guid, (ULONG)cbBuf, FALSE, &evnt, &ioStatus);
        if (NULL == req)
        {
            goto Finally;
        }

        result = IoCallDriver(devObj, req);
        if (STATUS_PENDING == result)
        {
            KeWaitForSingleObject(&evnt, Executive, KernelMode, FALSE, NULL);
        }

        if (!NT_SUCCESS(ioStatus.Status))
        {
            if (STATUS_BUFFER_OVERFLOW == ioStatus.Status)
            {
                // Buffer is too small to store unique id information. We re-allocate memory for
                // bigger size. If the desired buffer size is smaller than we created, something is
                // wrong. We don't retry.
                if (sizeof(guid->UniqueId) + guid->UniqueIdLength > cbBuf)
                {
                    cbBuf = sizeof(guid->UniqueIdLength) + guid->UniqueIdLength;
                    ExFreePool(guid);
                    guid = NULL;
                    continue;
                }
            }

            result = ioStatus.Status;
            goto Finally;
        }

        break;
    }

Finally:
    {
        if (!NT_SUCCESS(result))
        {
            WDRBD_TRACE("Failed to retrieve a GUID: 0x%lx", result);
            ExFreePool(guid);
            guid = NULL;
        }

        return guid;
    }
}

/**
* @brief
*/
void PrintVolumeGuid(PDEVICE_OBJECT devObj)
{
    PMOUNTDEV_UNIQUE_ID guid = RetrieveVolumeGuid(devObj);

    if (NULL == guid)
    {
        WDRBD_WARN("Volume GUID: NULL\n", 0);
        return;
    }

    int i;
    char pguid_text[128] = {0, };
    char temp[8] = {0, };

    for (i = 0; i < guid->UniqueIdLength; ++i)
    {
        _itoa_s(guid->UniqueId[i], temp, 8, 16);
        strcat(pguid_text, temp);
        strcat(pguid_text, " ");
    }

    WDRBD_TRACE("device object(0x%x), Volume GUID(%s)\n", devObj, pguid_text);

    ExFreePool(guid);
}

NTSTATUS
GetDriverLetterByDeviceName(IN PUNICODE_STRING pDeviceName, OUT PUNICODE_STRING pDriveLetter)
{
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK StatusBlock;
	PFILE_OBJECT pVolumeFileObject = NULL;
	HANDLE FileHandle;

	InitializeObjectAttributes(&ObjectAttributes,
		pDeviceName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	Status = ZwCreateFile(&FileHandle,
		SYNCHRONIZE | FILE_READ_DATA,
		&ObjectAttributes,
		&StatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (Status != STATUS_SUCCESS)
	{
		//WDRBD_ERROR("ZwCreateFile: %d\n", Status);
		//LOG_ERROR: GetDriverLetterByDeviceName: ZwCreateFile: -1073741810
		// 부팅시 오류: 0xC000000E STATUS_NO_SUCH_DEVICE
		return Status;
	}
	Status = ObReferenceObjectByHandle(FileHandle,
		FILE_READ_DATA,
		*IoFileObjectType,
		KernelMode,
		&pVolumeFileObject,
		NULL);
	if (Status != STATUS_SUCCESS)
	{
		ZwClose(FileHandle);
		WDRBD_ERROR("ObReferenceObjectByHandle: %d\n", Status);
		return Status;
	}
	// RtlVolumeDeviceToDosName(pVolumeFileObject->DeviceObject, pDriveLetter);
	Status = IoVolumeDeviceToDosName(pVolumeFileObject->DeviceObject, pDriveLetter);
	if (Status != STATUS_SUCCESS)
	{
		WDRBD_ERROR("IoVolumeDeviceToDosName: %d\n", Status);
		// return Status;
	}
	ObDereferenceObject(pVolumeFileObject);
	ZwClose(FileHandle);
	return Status;
}

#ifdef DRDB_CHECK_DW128
NTSTATUS
RtlVolumeDeviceToDosName(
IN PVOID           VolumeDeviceObject,
OUT PUNICODE_STRING DosName
)
{
	PDEVICE_OBJECT volumeDeviceObject = VolumeDeviceObject;
	PMOUNTDEV_NAME name;
	CHAR            output[512];
	KEVENT          event;
	PIRP            irp;
	IO_STATUS_BLOCK ioStatus;
	NTSTATUS        status;
	UNICODE_STRING deviceName;
	WCHAR           buffer[30];
	UNICODE_STRING driveLetterName;
	WCHAR           c;
	UNICODE_STRING linkTarget;
	LIST_ENTRY      devicesInPath;

	name = (PMOUNTDEV_NAME) output;
	KeInitializeEvent(&event, NotificationEvent, FALSE);
	irp = IoBuildDeviceIoControlRequest(IOCTL_MOUNTDEV_QUERY_DEVICE_NAME,
		volumeDeviceObject, NULL, 0, name, 512,
		FALSE, &event, &ioStatus);
	if (!irp) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	status = IoCallDriver(volumeDeviceObject, irp);
	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = ioStatus.Status;
	}
	if (!NT_SUCCESS(status)) {
		return status;
	}
	deviceName.MaximumLength = deviceName.Length = name->NameLength;
	deviceName.Buffer = name->Name;
	swprintf(buffer, L":");
	RtlInitUnicodeString(&driveLetterName, buffer);

	for (c = 'A'; c <= 'Z'; c++) {
		driveLetterName.Buffer[4] = c;
		status = QuerySymbolicLink(&driveLetterName, &linkTarget);
		if (!NT_SUCCESS(status)) {
			continue;
		}
		if (RtlEqualUnicodeString(&linkTarget, &deviceName, TRUE)) {
			ExFreePool(linkTarget.Buffer);
			break;
		}
		ExFreePool(linkTarget.Buffer);
	}

	if (c <= 'Z') {
		DosName->Buffer = ExAllocatePool(PagedPool, 3 * sizeof(WCHAR));
		if (!DosName->Buffer) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		DosName->MaximumLength = 6;
		DosName->Length = 4;
		DosName->Buffer[0] = c;
		DosName->Buffer[1] = ':';
		DosName->Buffer[2] = 0;
		return STATUS_SUCCESS;
	}
	/*ZwOpenSymbolicLinkObject
	* ZwOpenFile
	* IoGetDeviceObjectPointer
	* ZwQueryDirectoryFile
	* ZwQueryInformationFile
	*/
	for (c = 'A'; c <= 'Z'; c++) {
		driveLetterName.Buffer[4] = c;
		InitializeListHead(&devicesInPath);
		status = FindPathForDevice(&driveLetterName, &deviceName,
			&devicesInPath, DosName);
		if (NT_SUCCESS(status)) {
			DosName->Length -= 4 * sizeof(WCHAR);
			RtlMoveMemory(DosName->Buffer, &DosName->Buffer[4],
				DosName->Length);
			DosName->Buffer[DosName->Length / sizeof(WCHAR)] = 0;
			return status;
		}
	}
	return status;
}
#endif

/**
* @brief
*   레지스트리에서 값을 삭제할 때 사용
* @param
*   preg_path - UNICODE_STRING 타입의 레지스트리 경로. ex)"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\drbd\\volumes"
*   pvalue_name - UNICODE_STRING 타입의 value.
* @return
*   STATUS_SUCCESS - 삭제 성공 시
*   그 외 - 실패시 api의 return 값
*/
NTSTATUS DeleteRegistryValueKey(__in PUNICODE_STRING preg_path, __in PUNICODE_STRING pvalue_name)
{
    PAGED_CODE();

    OBJECT_ATTRIBUTES   attributes;
    NTSTATUS            status;
    HANDLE              hKey = NULL;

    InitializeObjectAttributes(&attributes,
        preg_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenKey(&hKey, DELETE, &attributes);
    if (!NT_SUCCESS(status))
    {
        WDRBD_WARN("Failed to ZwOpenKey(). status(0x%x)\n", status);
        goto cleanup;
    }

    status = ZwDeleteValueKey(hKey, pvalue_name);
    if (!NT_SUCCESS(status))
    {
        WDRBD_WARN("Failed to ZwDeleteValueKey(). status(0x%x)\n", status);
        goto cleanup;
    }

cleanup:
    if (hKey)
    {
        ZwClose(hKey);
    }

    return status;
}

NTSTATUS GetRegistryValue(PCWSTR pwcsValueName, ULONG *pReturnLength, UCHAR *pucReturnBuffer, PUNICODE_STRING pRegistryPath)
{
    HANDLE hKey;
    ULONG ulLength;
    NTSTATUS status;
    OBJECT_ATTRIBUTES stObjAttr;
    UNICODE_STRING valueName;
    KEY_VALUE_PARTIAL_INFORMATION stKeyInfo;
    PKEY_VALUE_PARTIAL_INFORMATION pstKeyInfo;

    RtlInitUnicodeString(&valueName, pwcsValueName);

    InitializeObjectAttributes(&stObjAttr, pRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &stObjAttr);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    ulLength = 0;
    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, &stKeyInfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION), &ulLength);
    if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW) && (status != STATUS_BUFFER_TOO_SMALL))
    {
        ZwClose(hKey);
        return status;
    }

    pstKeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulLength, '36DW');
    if (pstKeyInfo == NULL)
    {
        ZwClose(hKey);
        return status;
    }

    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, pstKeyInfo, ulLength, &ulLength);
    if (NT_SUCCESS(status))
    {
        *pReturnLength = pstKeyInfo->DataLength;
        RtlCopyMemory(pucReturnBuffer, pstKeyInfo->Data, pstKeyInfo->DataLength);
    }
    ExFreePool(pstKeyInfo);
    ZwClose(hKey);
    return status;
}

int initRegistry(__in PUNICODE_STRING RegPath_unicode)
{
	ULONG ulLength;
	UCHAR aucTemp[255] = { 0 };
	NTSTATUS status;

#ifndef _WIN32_V9
	// set proc_details
	status = GetRegistryValue(L"proc_details", &ulLength, &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		proc_details = *(int*) aucTemp;
	}
	else
	{
		proc_details = 1;
	}
#endif

	// set bypass_level
	status = GetRegistryValue(L"bypass_level", &ulLength, &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_bypass_level = *(int*) aucTemp;
	}
	else
	{
		g_bypass_level = 0;
	}

	// set read_filter
	status = GetRegistryValue(L"read_filter", &ulLength, &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_read_filter = *(int*) aucTemp;
	}
	else
	{
		g_read_filter = 0;
	}

	// set use_volume_lock
	status = GetRegistryValue(L"use_volume_lock", &ulLength, &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_use_volume_lock = *(int*) aucTemp;
	}
	else
	{
		g_use_volume_lock = 0;
	}

	// set g_netlink_tcp_port
	status = GetRegistryValue(L"netlink_tcp_port", &ulLength, &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_netlink_tcp_port = *(int*) aucTemp;;
	}
	else
	{
		g_netlink_tcp_port = NETLINK_PORT;
	}

	// set daemon_tcp_port
	status = GetRegistryValue(L"daemon_tcp_port", &ulLength, &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_daemon_tcp_port = *(int*) aucTemp;
	}
	else
	{
		g_daemon_tcp_port = 5679;
	}

	// set ver
    // DRBD_DOC: 용도 미정
	status = GetRegistryValue(L"ver", &ulLength, &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		RtlCopyMemory(g_ver, aucTemp, ulLength * 2);
	}
	else
	{
		RtlCopyMemory(g_ver, "test", 4 * 2); 
	}

	// _WIN32_V9: proc_details 제거함.
    WDRBD_INFO("registry_path[%wZ]\n"
        "bypass_level=%d, read_filter=%d, use_volume_lock=%d, netlink_tcp_port=%d, "
        "netlink_tcp_port=%d, daemon_tcp_port=%d, ver=%ws\n",
        RegPath_unicode,
        g_bypass_level,
        g_read_filter,
        g_use_volume_lock,
        g_netlink_tcp_port,
        g_netlink_tcp_port,
        g_daemon_tcp_port,
        g_ver
        );
	return 0;
}

/**
* @brief
*/
PUNICODE_STRING ucsdup(IN OUT PUNICODE_STRING dst, IN PUNICODE_STRING src)
{
    if (!dst)
    {
        return NULL;
    }

    USHORT size = src->Length + sizeof(WCHAR);

    dst->Buffer = (WCHAR *)ExAllocatePoolWithTag(NonPagedPool, size, '46DW');
    dst->MaximumLength = size;

    RtlCopyUnicodeString(dst, src);

    return dst;
}

/**
* @brief
*/
void ucsfree(IN PUNICODE_STRING str)
{
    if (str)
    {
        kfree(str->Buffer);
    }
}


// GetIrpName
// from:https://github.com/iocellnetworks/ndas4windows/blob/master/fremont/3.20-stable/src/drivers/ndasfat/ndasfat.c

#ifdef IRP_TEST
#define OPERATION_NAME_BUFFER_SIZE  256
CHAR UnknownIrpMinor [] = "Unknown Irp minor code (%u)";

VOID
GetIrpName(
IN UCHAR MajorCode,
IN UCHAR MinorCode,
IN ULONG FsctlCode,
OUT PCHAR MajorCodeName,
OUT PCHAR MinorCodeName
)
/*++

Routine Description:

This routine translates the given Irp codes into printable strings which
are returned.  This guarantees to routine valid strings in each buffer.
The MinorCode string may be a NULL string (not a null pointer).

Arguments:

MajorCode - the IRP Major code of the operation
MinorCode - the IRP Minor code of the operation
FsctlCode - if this is an IRP_MJ_FILE_SYSTEM_CONTROL/IRP_MN_USER_FS_REQUEST
operation then this is the FSCTL code whose name is also
translated.  This name is returned as part of the MinorCode
string.
MajorCodeName - a string buffer at least OPERATION_NAME_BUFFER_SIZE
characters long that receives the major code name.
MinorCodeName - a string buffer at least OPERATION_NAME_BUFFER_SIZE
characters long that receives the minor/fsctl code name.

Return Value:

None.

--*/
{
    PCHAR irpMajorString;
    PCHAR irpMinorString = "";
    CHAR nameBuf[OPERATION_NAME_BUFFER_SIZE];

    switch (MajorCode) {
    case IRP_MJ_CREATE:
        irpMajorString = "IRP_MJ_CREATE";
        break;
    case IRP_MJ_CREATE_NAMED_PIPE:
        irpMajorString = "IRP_MJ_CREATE_NAMED_PIPE";
        break;
    case IRP_MJ_CLOSE:
        irpMajorString = "IRP_MJ_CLOSE";
        break;
    case IRP_MJ_READ:
        irpMajorString = "IRP_MJ_READ";
        switch (MinorCode) {
        case IRP_MN_NORMAL:
            irpMinorString = "IRP_MN_NORMAL";
            break;
        case IRP_MN_DPC:
            irpMinorString = "IRP_MN_DPC";
            break;
        case IRP_MN_MDL:
            irpMinorString = "IRP_MN_MDL";
            break;
        case IRP_MN_COMPLETE:
            irpMinorString = "IRP_MN_COMPLETE";
            break;
        case IRP_MN_COMPRESSED:
            irpMinorString = "IRP_MN_COMPRESSED";
            break;
        case IRP_MN_MDL_DPC:
            irpMinorString = "IRP_MN_MDL_DPC";
            break;
        case IRP_MN_COMPLETE_MDL:
            irpMinorString = "IRP_MN_COMPLETE_MDL";
            break;
        case IRP_MN_COMPLETE_MDL_DPC:
            irpMinorString = "IRP_MN_COMPLETE_MDL_DPC";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_WRITE:
        irpMajorString = "IRP_MJ_WRITE";
        switch (MinorCode) {
        case IRP_MN_NORMAL:
            irpMinorString = "IRP_MN_NORMAL";
            break;
        case IRP_MN_DPC:
            irpMinorString = "IRP_MN_DPC";
            break;
        case IRP_MN_MDL:
            irpMinorString = "IRP_MN_MDL";
            break;
        case IRP_MN_COMPLETE:
            irpMinorString = "IRP_MN_COMPLETE";
            break;
        case IRP_MN_COMPRESSED:
            irpMinorString = "IRP_MN_COMPRESSED";
            break;
        case IRP_MN_MDL_DPC:
            irpMinorString = "IRP_MN_MDL_DPC";
            break;
        case IRP_MN_COMPLETE_MDL:
            irpMinorString = "IRP_MN_COMPLETE_MDL";
            break;
        case IRP_MN_COMPLETE_MDL_DPC:
            irpMinorString = "IRP_MN_COMPLETE_MDL_DPC";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_QUERY_INFORMATION:
        irpMajorString = "IRP_MJ_QUERY_INFORMATION";
        break;
    case IRP_MJ_SET_INFORMATION:
        irpMajorString = "IRP_MJ_SET_INFORMATION";
        break;
    case IRP_MJ_QUERY_EA:
        irpMajorString = "IRP_MJ_QUERY_EA";
        break;
    case IRP_MJ_SET_EA:
        irpMajorString = "IRP_MJ_SET_EA";
        break;
    case IRP_MJ_FLUSH_BUFFERS:
        irpMajorString = "IRP_MJ_FLUSH_BUFFERS";
        break;
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
        irpMajorString = "IRP_MJ_QUERY_VOLUME_INFORMATION";
        break;
    case IRP_MJ_SET_VOLUME_INFORMATION:
        irpMajorString = "IRP_MJ_SET_VOLUME_INFORMATION";
        break;
    case IRP_MJ_DIRECTORY_CONTROL:
        irpMajorString = "IRP_MJ_DIRECTORY_CONTROL";
        switch (MinorCode) {
        case IRP_MN_QUERY_DIRECTORY:
            irpMinorString = "IRP_MN_QUERY_DIRECTORY";
            break;
        case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
            irpMinorString = "IRP_MN_NOTIFY_CHANGE_DIRECTORY";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_FILE_SYSTEM_CONTROL:
        irpMajorString = "IRP_MJ_FILE_SYSTEM_CONTROL";
        switch (MinorCode) {
        case IRP_MN_USER_FS_REQUEST:
            switch (FsctlCode) {
            case FSCTL_REQUEST_OPLOCK_LEVEL_1:
                irpMinorString = "FSCTL_REQUEST_OPLOCK_LEVEL_1";
                break;
            case FSCTL_REQUEST_OPLOCK_LEVEL_2:
                irpMinorString = "FSCTL_REQUEST_OPLOCK_LEVEL_2";
                break;
            case FSCTL_REQUEST_BATCH_OPLOCK:
                irpMinorString = "FSCTL_REQUEST_BATCH_OPLOCK";
                break;
            case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE:
                irpMinorString = "FSCTL_OPLOCK_BREAK_ACKNOWLEDGE";
                break;
            case FSCTL_OPBATCH_ACK_CLOSE_PENDING:
                irpMinorString = "FSCTL_OPBATCH_ACK_CLOSE_PENDING";
                break;
            case FSCTL_OPLOCK_BREAK_NOTIFY:
                irpMinorString = "FSCTL_OPLOCK_BREAK_NOTIFY";
                break;
            case FSCTL_LOCK_VOLUME:
                irpMinorString = "FSCTL_LOCK_VOLUME";
                break;
            case FSCTL_UNLOCK_VOLUME:
                irpMinorString = "FSCTL_UNLOCK_VOLUME";
                break;
            case FSCTL_DISMOUNT_VOLUME:
                irpMinorString = "FSCTL_DISMOUNT_VOLUME";
                break;
            case FSCTL_IS_VOLUME_MOUNTED:
                irpMinorString = "FSCTL_IS_VOLUME_MOUNTED";
                break;
            case FSCTL_IS_PATHNAME_VALID:
                irpMinorString = "FSCTL_IS_PATHNAME_VALID";
                break;
            case FSCTL_MARK_VOLUME_DIRTY:
                irpMinorString = "FSCTL_MARK_VOLUME_DIRTY";
                break;
            case FSCTL_QUERY_RETRIEVAL_POINTERS:
                irpMinorString = "FSCTL_QUERY_RETRIEVAL_POINTERS";
                break;
            case FSCTL_GET_COMPRESSION:
                irpMinorString = "FSCTL_GET_COMPRESSION";
                break;
            case FSCTL_SET_COMPRESSION:
                irpMinorString = "FSCTL_SET_COMPRESSION";
                break;
            case FSCTL_MARK_AS_SYSTEM_HIVE:
                irpMinorString = "FSCTL_MARK_AS_SYSTEM_HIVE";
                break;
            case FSCTL_OPLOCK_BREAK_ACK_NO_2:
                irpMinorString = "FSCTL_OPLOCK_BREAK_ACK_NO_2";
                break;
            case FSCTL_INVALIDATE_VOLUMES:
                irpMinorString = "FSCTL_INVALIDATE_VOLUMES";
                break;
            case FSCTL_QUERY_FAT_BPB:
                irpMinorString = "FSCTL_QUERY_FAT_BPB";
                break;
            case FSCTL_REQUEST_FILTER_OPLOCK:
                irpMinorString = "FSCTL_REQUEST_FILTER_OPLOCK";
                break;
            case FSCTL_FILESYSTEM_GET_STATISTICS:
                irpMinorString = "FSCTL_FILESYSTEM_GET_STATISTICS";
                break;
            case FSCTL_GET_NTFS_VOLUME_DATA:
                irpMinorString = "FSCTL_GET_NTFS_VOLUME_DATA";
                break;
            case FSCTL_GET_NTFS_FILE_RECORD:
                irpMinorString = "FSCTL_GET_NTFS_FILE_RECORD";
                break;
            case FSCTL_GET_VOLUME_BITMAP:
                irpMinorString = "FSCTL_GET_VOLUME_BITMAP";
                break;
            case FSCTL_GET_RETRIEVAL_POINTERS:
                irpMinorString = "FSCTL_GET_RETRIEVAL_POINTERS";
                break;
            case FSCTL_MOVE_FILE:
                irpMinorString = "FSCTL_MOVE_FILE";
                break;
            case FSCTL_IS_VOLUME_DIRTY:
                irpMinorString = "FSCTL_IS_VOLUME_DIRTY";
                break;
            case FSCTL_ALLOW_EXTENDED_DASD_IO:
                irpMinorString = "FSCTL_ALLOW_EXTENDED_DASD_IO";
                break;
            case FSCTL_FIND_FILES_BY_SID:
                irpMinorString = "FSCTL_FIND_FILES_BY_SID";
                break;
            case FSCTL_SET_OBJECT_ID:
                irpMinorString = "FSCTL_SET_OBJECT_ID";
                break;
            case FSCTL_GET_OBJECT_ID:
                irpMinorString = "FSCTL_GET_OBJECT_ID";
                break;
            case FSCTL_DELETE_OBJECT_ID:
                irpMinorString = "FSCTL_DELETE_OBJECT_ID";
                break;
            case FSCTL_SET_REPARSE_POINT:
                irpMinorString = "FSCTL_SET_REPARSE_POINT";
                break;
            case FSCTL_GET_REPARSE_POINT:
                irpMinorString = "FSCTL_GET_REPARSE_POINT";
                break;
            case FSCTL_DELETE_REPARSE_POINT:
                irpMinorString = "FSCTL_DELETE_REPARSE_POINT";
                break;
            case FSCTL_ENUM_USN_DATA:
                irpMinorString = "FSCTL_ENUM_USN_DATA";
                break;
            case FSCTL_SECURITY_ID_CHECK:
                irpMinorString = "FSCTL_SECURITY_ID_CHECK";
                break;
            case FSCTL_READ_USN_JOURNAL:
                irpMinorString = "FSCTL_READ_USN_JOURNAL";
                break;
            case FSCTL_SET_OBJECT_ID_EXTENDED:
                irpMinorString = "FSCTL_SET_OBJECT_ID_EXTENDED";
                break;
            case FSCTL_CREATE_OR_GET_OBJECT_ID:
                irpMinorString = "FSCTL_CREATE_OR_GET_OBJECT_ID";
                break;
            case FSCTL_SET_SPARSE:
                irpMinorString = "FSCTL_SET_SPARSE";
                break;
            case FSCTL_SET_ZERO_DATA:
                irpMinorString = "FSCTL_SET_ZERO_DATA";
                break;
            case FSCTL_QUERY_ALLOCATED_RANGES:
                irpMinorString = "FSCTL_QUERY_ALLOCATED_RANGES";
                break;
            case FSCTL_SET_ENCRYPTION:
                irpMinorString = "FSCTL_SET_ENCRYPTION";
                break;
            case FSCTL_ENCRYPTION_FSCTL_IO:
                irpMinorString = "FSCTL_ENCRYPTION_FSCTL_IO";
                break;
            case FSCTL_WRITE_RAW_ENCRYPTED:
                irpMinorString = "FSCTL_WRITE_RAW_ENCRYPTED";
                break;
            case FSCTL_READ_RAW_ENCRYPTED:
                irpMinorString = "FSCTL_READ_RAW_ENCRYPTED";
                break;
            case FSCTL_CREATE_USN_JOURNAL:
                irpMinorString = "FSCTL_CREATE_USN_JOURNAL";
                break;
            case FSCTL_READ_FILE_USN_DATA:
                irpMinorString = "FSCTL_READ_FILE_USN_DATA";
                break;
            case FSCTL_WRITE_USN_CLOSE_RECORD:
                irpMinorString = "FSCTL_WRITE_USN_CLOSE_RECORD";
                break;
            case FSCTL_EXTEND_VOLUME:
                irpMinorString = "FSCTL_EXTEND_VOLUME";
                break;
            case FSCTL_QUERY_USN_JOURNAL:
                irpMinorString = "FSCTL_QUERY_USN_JOURNAL";
                break;
            case FSCTL_DELETE_USN_JOURNAL:
                irpMinorString = "FSCTL_DELETE_USN_JOURNAL";
                break;
            case FSCTL_MARK_HANDLE:
                irpMinorString = "FSCTL_MARK_HANDLE";
                break;
            case FSCTL_SIS_COPYFILE:
                irpMinorString = "FSCTL_SIS_COPYFILE";
                break;
            case FSCTL_SIS_LINK_FILES:
                irpMinorString = "FSCTL_SIS_LINK_FILES";
                break;
                //case FSCTL_HSM_MSG:
                //     irpMinorString = "FSCTL_HSM_MSG";
                //    break;
                //case FSCTL_HSM_DATA:
                //    irpMinorString = "FSCTL_HSM_DATA";
                //    break;
            case FSCTL_RECALL_FILE:
                irpMinorString = "FSCTL_RECALL_FILE";
                break;
#if WINVER >= 0x0501                            
            case FSCTL_READ_FROM_PLEX:
                irpMinorString = "FSCTL_READ_FROM_PLEX";
                break;
            case FSCTL_FILE_PREFETCH:
                irpMinorString = "FSCTL_FILE_PREFETCH";
                break;
#endif                            
            default:
                sprintf(nameBuf, "Unknown FSCTL (%u)", MinorCode);
                irpMinorString = nameBuf;
                break;
            }

            sprintf(nameBuf, "%s (USER)", irpMinorString);
            irpMinorString = nameBuf;
            break;

        case IRP_MN_MOUNT_VOLUME:
            irpMinorString = "IRP_MN_MOUNT_VOLUME";
            break;
        case IRP_MN_VERIFY_VOLUME:
            irpMinorString = "IRP_MN_VERIFY_VOLUME";
            break;
        case IRP_MN_LOAD_FILE_SYSTEM:
            irpMinorString = "IRP_MN_LOAD_FILE_SYSTEM";
            break;
        case IRP_MN_TRACK_LINK:
            irpMinorString = "IRP_MN_TRACK_LINK";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_DEVICE_CONTROL:
        irpMajorString = "IRP_MJ_DEVICE_CONTROL";
        switch (MinorCode) {
        case 0:
            irpMinorString = "User request";
            break;
        case IRP_MN_SCSI_CLASS:
            irpMinorString = "IRP_MN_SCSI_CLASS";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        irpMajorString = "IRP_MJ_INTERNAL_DEVICE_CONTROL";
        break;
    case IRP_MJ_SHUTDOWN:
        irpMajorString = "IRP_MJ_SHUTDOWN";
        break;
    case IRP_MJ_LOCK_CONTROL:
        irpMajorString = "IRP_MJ_LOCK_CONTROL";
        switch (MinorCode) {
        case IRP_MN_LOCK:
            irpMinorString = "IRP_MN_LOCK";
            break;
        case IRP_MN_UNLOCK_SINGLE:
            irpMinorString = "IRP_MN_UNLOCK_SINGLE";
            break;
        case IRP_MN_UNLOCK_ALL:
            irpMinorString = "IRP_MN_UNLOCK_ALL";
            break;
        case IRP_MN_UNLOCK_ALL_BY_KEY:
            irpMinorString = "IRP_MN_UNLOCK_ALL_BY_KEY";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_CLEANUP:
        irpMajorString = "IRP_MJ_CLEANUP";
        break;
    case IRP_MJ_CREATE_MAILSLOT:
        irpMajorString = "IRP_MJ_CREATE_MAILSLOT";
        break;
    case IRP_MJ_QUERY_SECURITY:
        irpMajorString = "IRP_MJ_QUERY_SECURITY";
        break;
    case IRP_MJ_SET_SECURITY:
        irpMajorString = "IRP_MJ_SET_SECURITY";
        break;
    case IRP_MJ_POWER:
        irpMajorString = "IRP_MJ_POWER";
        switch (MinorCode) {
        case IRP_MN_WAIT_WAKE:
            irpMinorString = "IRP_MN_WAIT_WAKE";
            break;
        case IRP_MN_POWER_SEQUENCE:
            irpMinorString = "IRP_MN_POWER_SEQUENCE";
            break;
        case IRP_MN_SET_POWER:
            irpMinorString = "IRP_MN_SET_POWER";
            break;
        case IRP_MN_QUERY_POWER:
            irpMinorString = "IRP_MN_QUERY_POWER";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_SYSTEM_CONTROL:
        irpMajorString = "IRP_MJ_SYSTEM_CONTROL";
        switch (MinorCode) {
        case IRP_MN_QUERY_ALL_DATA:
            irpMinorString = "IRP_MN_QUERY_ALL_DATA";
            break;
        case IRP_MN_QUERY_SINGLE_INSTANCE:
            irpMinorString = "IRP_MN_QUERY_SINGLE_INSTANCE";
            break;
        case IRP_MN_CHANGE_SINGLE_INSTANCE:
            irpMinorString = "IRP_MN_CHANGE_SINGLE_INSTANCE";
            break;
        case IRP_MN_CHANGE_SINGLE_ITEM:
            irpMinorString = "IRP_MN_CHANGE_SINGLE_ITEM";
            break;
        case IRP_MN_ENABLE_EVENTS:
            irpMinorString = "IRP_MN_ENABLE_EVENTS";
            break;
        case IRP_MN_DISABLE_EVENTS:
            irpMinorString = "IRP_MN_DISABLE_EVENTS";
            break;
        case IRP_MN_ENABLE_COLLECTION:
            irpMinorString = "IRP_MN_ENABLE_COLLECTION";
            break;
        case IRP_MN_DISABLE_COLLECTION:
            irpMinorString = "IRP_MN_DISABLE_COLLECTION";
            break;
        case IRP_MN_REGINFO:
            irpMinorString = "IRP_MN_REGINFO";
            break;
        case IRP_MN_EXECUTE_METHOD:
            irpMinorString = "IRP_MN_EXECUTE_METHOD";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_DEVICE_CHANGE:
        irpMajorString = "IRP_MJ_DEVICE_CHANGE";
        break;
    case IRP_MJ_QUERY_QUOTA:
        irpMajorString = "IRP_MJ_QUERY_QUOTA";
        break;
    case IRP_MJ_SET_QUOTA:
        irpMajorString = "IRP_MJ_SET_QUOTA";
        break;
    case IRP_MJ_PNP:
        irpMajorString = "IRP_MJ_PNP";
        switch (MinorCode) {
        case IRP_MN_START_DEVICE:
            irpMinorString = "IRP_MN_START_DEVICE";
            break;
        case IRP_MN_QUERY_REMOVE_DEVICE:
            irpMinorString = "IRP_MN_QUERY_REMOVE_DEVICE";
            break;
        case IRP_MN_REMOVE_DEVICE:
            irpMinorString = "IRP_MN_REMOVE_DEVICE";
            break;
        case IRP_MN_CANCEL_REMOVE_DEVICE:
            irpMinorString = "IRP_MN_CANCEL_REMOVE_DEVICE";
            break;
        case IRP_MN_STOP_DEVICE:
            irpMinorString = "IRP_MN_STOP_DEVICE";
            break;
        case IRP_MN_QUERY_STOP_DEVICE:
            irpMinorString = "IRP_MN_QUERY_STOP_DEVICE";
            break;
        case IRP_MN_CANCEL_STOP_DEVICE:
            irpMinorString = "IRP_MN_CANCEL_STOP_DEVICE";
            break;
        case IRP_MN_QUERY_DEVICE_RELATIONS:
            irpMinorString = "IRP_MN_QUERY_DEVICE_RELATIONS";
            break;
        case IRP_MN_QUERY_INTERFACE:
            irpMinorString = "IRP_MN_QUERY_INTERFACE";
            break;
        case IRP_MN_QUERY_CAPABILITIES:
            irpMinorString = "IRP_MN_QUERY_CAPABILITIES";
            break;
        case IRP_MN_QUERY_RESOURCES:
            irpMinorString = "IRP_MN_QUERY_RESOURCES";
            break;
        case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
            irpMinorString = "IRP_MN_QUERY_RESOURCE_REQUIREMENTS";
            break;
        case IRP_MN_QUERY_DEVICE_TEXT:
            irpMinorString = "IRP_MN_QUERY_DEVICE_TEXT";
            break;
        case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
            irpMinorString = "IRP_MN_FILTER_RESOURCE_REQUIREMENTS";
            break;
        case IRP_MN_READ_CONFIG:
            irpMinorString = "IRP_MN_READ_CONFIG";
            break;
        case IRP_MN_WRITE_CONFIG:
            irpMinorString = "IRP_MN_WRITE_CONFIG";
            break;
        case IRP_MN_EJECT:
            irpMinorString = "IRP_MN_EJECT";
            break;
        case IRP_MN_SET_LOCK:
            irpMinorString = "IRP_MN_SET_LOCK";
            break;
        case IRP_MN_QUERY_ID:
            irpMinorString = "IRP_MN_QUERY_ID";
            break;
        case IRP_MN_QUERY_PNP_DEVICE_STATE:
            irpMinorString = "IRP_MN_QUERY_PNP_DEVICE_STATE";
            break;
        case IRP_MN_QUERY_BUS_INFORMATION:
            irpMinorString = "IRP_MN_QUERY_BUS_INFORMATION";
            break;
        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
            irpMinorString = "IRP_MN_DEVICE_USAGE_NOTIFICATION";
            break;
        case IRP_MN_SURPRISE_REMOVAL:
            irpMinorString = "IRP_MN_SURPRISE_REMOVAL";
            break;
        case IRP_MN_QUERY_LEGACY_BUS_INFORMATION:
            irpMinorString = "IRP_MN_QUERY_LEGACY_BUS_INFORMATION";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    default:
        sprintf(nameBuf, "Unknown Irp major code (%u)", MajorCode);
        irpMajorString = nameBuf;
    }

    strcpy(MajorCodeName, irpMajorString);
    strcpy(MinorCodeName, irpMinorString);
}

VOID
PrintIrp(
PCHAR					Where,
PVOID					VolDo,
PIRP					Irp
)
{
#if 1 // DBG

    PIO_STACK_LOCATION  irpSp = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT		fileObject = irpSp->FileObject;
    UNICODE_STRING		nullName;
    UCHAR				minorFunction;
    CHAR				irpMajorString[OPERATION_NAME_BUFFER_SIZE];
    CHAR				irpMinorString[OPERATION_NAME_BUFFER_SIZE];

    GetIrpName(
        irpSp->MajorFunction,
        irpSp->MinorFunction,
        irpSp->Parameters.FileSystemControl.FsControlCode,
        irpMajorString,
        irpMinorString
        );

    RtlInitUnicodeString(&nullName, L"fileObject == NULL");

    if (irpSp->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL && irpSp->MinorFunction == IRP_MN_USER_FS_REQUEST)
        minorFunction = (UCHAR) ((irpSp->Parameters.FileSystemControl.FsControlCode & 0x00003FFC) >> 2);
    else if (irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL && irpSp->MinorFunction == 0)
        minorFunction = (UCHAR) ((irpSp->Parameters.DeviceIoControl.IoControlCode & 0x00003FFC) >> 2);
    else
        minorFunction = irpSp->MinorFunction;

    ASSERT(Irp->RequestorMode == KernelMode || Irp->RequestorMode == UserMode);

    if (KeGetCurrentIrql() < DISPATCH_LEVEL) {

        DbgPrint
            ("%s %p Irql:%d Irp:%p %s %s (%u:%u) %08x %02x ",
            (Where) ? Where : "", VolDo,
            KeGetCurrentIrql(),
            Irp, irpMajorString, irpMinorString, irpSp->MajorFunction, minorFunction,
            Irp->Flags, irpSp->Flags);

        /*"%s %c%c%c%c%c ", */
        /*(Irp->RequestorMode == KernelMode) ? "KernelMode" : "UserMode",
        (Irp->Flags & IRP_PAGING_IO) ? '*' : ' ',
        (Irp->Flags & IRP_SYNCHRONOUS_PAGING_IO) ? '+' : ' ',
        (Irp->Flags & IRP_SYNCHRONOUS_API) ? 'A' : ' ',
        BooleanFlagOn(Irp->Flags,IRP_NOCACHE) ? 'N' : ' ',
        (fileObject && fileObject->Flags & FO_SYNCHRONOUS_IO) ? '&':' ',*/

        DbgPrint
            ("file: %p  %08x %p %wZ %d\n",
            fileObject,
            fileObject ? fileObject->Flags : 0,
            fileObject ? fileObject->RelatedFileObject : NULL,
            fileObject ? &fileObject->FileName : &nullName,
            fileObject ? fileObject->FileName.Length : 0
            );
    }

#else

    UNREFERENCED_PARAMETER(DebugLevel);
    UNREFERENCED_PARAMETER(Where);
    UNREFERENCED_PARAMETER(VolDo);
    UNREFERENCED_PARAMETER(Irp);

#endif

    return;
}
#endif