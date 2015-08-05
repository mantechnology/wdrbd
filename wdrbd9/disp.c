#include <wdm.h>
#include <ntstrsafe.h>
#include "drbd_windrv.h"	/// SEO:
#include "drbd_wingenl.h"	/// SEO:
#include "disp.h"
#include "mvolmsg.h"
#include "proto.h"

#include "linux-compat/idr.h"
#include "drbd_int.h"
#include "drbd_wrappers.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD mvolUnload;
DRIVER_ADD_DEVICE mvolAddDevice;

_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH mvolCreate;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH mvolClose;
_Dispatch_type_(IRP_MJ_SHUTDOWN) DRIVER_DISPATCH mvolShutdown;
_Dispatch_type_(IRP_MJ_FLUSH_BUFFERS) DRIVER_DISPATCH mvolFlush;
_Dispatch_type_(IRP_MJ_POWER) DRIVER_DISPATCH mvolDispatchPower;
_Dispatch_type_(IRP_MJ_SYSTEM_CONTROL) DRIVER_DISPATCH mvolSystemControl;
_Dispatch_type_(IRP_MJ_READ) DRIVER_DISPATCH mvolRead;
_Dispatch_type_(IRP_MJ_WRITE) DRIVER_DISPATCH mvolWrite;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH mvolDeviceControl;
_Dispatch_type_(IRP_MJ_PNP) DRIVER_DISPATCH mvolDispatchPnp;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, _query_mounted_devices)
#endif

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS            		status;
    PDEVICE_OBJECT      		deviceObject;
    PROOT_EXTENSION			RootExtension = NULL;
    UNICODE_STRING      		nameUnicode, linkUnicode;
    ULONG				i;

    WDRBD_TRACE("MVF Driver Loading...\n");

    initRegistry(RegistryPath);

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = mvolSendToNextDriver;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = mvolCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = mvolClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = mvolRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = mvolWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = mvolDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = mvolShutdown;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = mvolFlush;
    DriverObject->MajorFunction[IRP_MJ_PNP] = mvolDispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = mvolSystemControl;
    DriverObject->MajorFunction[IRP_MJ_POWER] = mvolDispatchPower;

    DriverObject->DriverExtension->AddDevice = mvolAddDevice;
    DriverObject->DriverUnload = mvolUnload;

    // init lookaside
    ExInitializeNPagedLookasideList(&drbd_printk_msg, NULL, NULL, 0, MAX_ELOG_BUF, '65DW', 0);
    
    RtlInitUnicodeString(&nameUnicode, L"\\Device\\mvolCntl");
    status = IoCreateDevice(DriverObject, sizeof(ROOT_EXTENSION),
        &nameUnicode, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status))
    {
        WDRBD_ERROR("Can't create root, err=%x\n", status);
        return status;
    }

    RtlInitUnicodeString(&linkUnicode, L"\\DosDevices\\mvolCntl");
    status = IoCreateSymbolicLink(&linkUnicode, &nameUnicode);
    if (!NT_SUCCESS(status))
    {
        WDRBD_ERROR("cannot create symbolic link, err=%x\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    mvolDriverObject = DriverObject;
    mvolRootDeviceObject = deviceObject;

    RootExtension = deviceObject->DeviceExtension;
    RootExtension->Magic = MVOL_MAGIC;
    RootExtension->Head = NULL;
    RootExtension->Count = 0;
    ucsdup(&RootExtension->RegistryPath, RegistryPath);
    RootExtension->PhysicalDeviceNameLength = nameUnicode.Length;
    RtlCopyMemory(RootExtension->PhysicalDeviceName, nameUnicode.Buffer, nameUnicode.Length);

    KeInitializeSpinLock(&mvolVolumeLock);
    KeInitializeMutex(&mvolMutex, 0);
    KeInitializeMutex(&eventlogMutex, 0);

    WDRBD_INFO("MVF Driver loaded.\n");

    return STATUS_SUCCESS;
}

VOID
mvolUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS
mvolAddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT PhysicalDeviceObject)
{
    NTSTATUS            status;
    PDEVICE_OBJECT      AttachedDeviceObject = NULL;
    PDEVICE_OBJECT      ReferenceDeviceObject = NULL;
    PVOLUME_EXTENSION   VolumeExtension = NULL;
    ULONG               deviceType = 0;
    static BOOLEAN      IsEngineStart = FALSE;

    if (FALSE == InterlockedCompareExchange(&IsEngineStart, TRUE, FALSE))
    {
        extern VOID NTAPI drbd_init(void);
        HANDLE		hThread = NULL;
        NTSTATUS	Status = STATUS_UNSUCCESSFUL;

        // Init WSK and StartNetLinkServer
#ifdef WSK_EVENT_CALLBACK
        Status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, InitWskNetlink, NULL);
#else
        Status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, NetlinkServerThread, NULL);
#endif
        if (!NT_SUCCESS(Status))
        {
            WDRBD_ERROR("PsCreateSystemThread failed with status 0x%08X\n", Status);
            return Status;
        }

        Status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &g_NetlinkServerThread, NULL);
        ZwClose(hThread);

        if (!NT_SUCCESS(Status))
        {
            WDRBD_ERROR("ObReferenceObjectByHandle() failed with status 0x%08X\n", Status);
            return Status;
        }

        // Init DRBD engine
        drbd_init();
    }

    ReferenceDeviceObject = IoGetAttachedDeviceReference(PhysicalDeviceObject);
    deviceType = ReferenceDeviceObject->DeviceType; //deviceType = 0x7 = FILE_DEVICE_DISK 
    ObDereferenceObject(ReferenceDeviceObject);

    status = IoCreateDevice(mvolDriverObject, sizeof(VOLUME_EXTENSION), NULL,
        deviceType, FILE_DEVICE_SECURE_OPEN, FALSE, &AttachedDeviceObject);
    if (!NT_SUCCESS(status))
    {
        mvolLogError(mvolRootDeviceObject, 102, MSG_ADD_DEVICE_ERROR, status);
        WDRBD_ERROR("cannot create device, err=0x%x\n", status);
        return status;
    }

    AttachedDeviceObject->Flags |= (DO_DIRECT_IO | DO_POWER_PAGABLE);
    AttachedDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    VolumeExtension = AttachedDeviceObject->DeviceExtension;
    RtlZeroMemory(VolumeExtension, sizeof(VOLUME_EXTENSION));
    VolumeExtension->DeviceObject = AttachedDeviceObject;
    VolumeExtension->PhysicalDeviceObject = PhysicalDeviceObject;
    VolumeExtension->Magic = MVOL_MAGIC;
    VolumeExtension->Flag = 0;
    VolumeExtension->IrpCount = 0;
    VolumeExtension->TargetDeviceObject =
        IoAttachDeviceToDeviceStack(AttachedDeviceObject, PhysicalDeviceObject);
    if (VolumeExtension->TargetDeviceObject == NULL)
    {
        mvolLogError(mvolRootDeviceObject, 103, MSG_ADD_DEVICE_ERROR, STATUS_NO_SUCH_DEVICE);
        IoDeleteDevice(AttachedDeviceObject);
        return STATUS_NO_SUCH_DEVICE;
    }

    status = GetDeviceName(PhysicalDeviceObject,
        VolumeExtension->PhysicalDeviceName, MAXDEVICENAME * sizeof(WCHAR)); // -> \Device\HarddiskVolumeXX
    if (!NT_SUCCESS(status))
    {
        mvolLogError(mvolRootDeviceObject, 101, MSG_ADD_DEVICE_ERROR, status);
        return status;
    }

    VolumeExtension->PhysicalDeviceNameLength = wcslen(VolumeExtension->PhysicalDeviceName) * sizeof(WCHAR);
    KeInitializeMutex(&VolumeExtension->CountMutex, 0);

    query_targetdev(VolumeExtension);  // letter, VolIndex(minor), block_device assign

    MVOL_LOCK();
    mvolAddDeviceList(VolumeExtension);
    MVOL_UNLOCK();
    
#ifdef _WIN32_MVFL
    if (do_add_minor(VolumeExtension->VolIndex))
    {
        status = mvolInitializeThread(VolumeExtension, &VolumeExtension->WorkThreadInfo, mvolWorkThread);
        if (!NT_SUCCESS(status))
        {
            WDRBD_ERROR("Failed to initialize WorkThread. status(0x%x)\n", status);
            //return status;
        }

        VolumeExtension->Active = TRUE;
    }
#endif
    WDRBD_INFO("VolumeExtension(0x%p) minor(%d) Letter(%c) PhysicalDeviceName(%ws) Active(%d)\n",
        VolumeExtension,
        VolumeExtension->VolIndex,
        (VolumeExtension->Letter) ? (VolumeExtension->Letter) : '?',
        VolumeExtension->PhysicalDeviceName,
        VolumeExtension->Active);

    return STATUS_SUCCESS;
}

NTSTATUS
mvolSendToNextDriver(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;

    if (DeviceObject == mvolRootDeviceObject)
    {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
}

NTSTATUS
mvolCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    return mvolSendToNextDriver(DeviceObject, Irp);
}

NTSTATUS
mvolClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    return mvolSendToNextDriver(DeviceObject, Irp);
}

NTSTATUS
mvolShutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;

    void drbd_cleanup_by_win_shutdown(PVOLUME_EXTENSION VolumeExtension);
    drbd_cleanup_by_win_shutdown(VolumeExtension);

    return mvolSendToNextDriver(DeviceObject, Irp);
}

NTSTATUS
mvolFlush(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    return mvolSendToNextDriver(DeviceObject, Irp);
}

_Use_decl_annotations_
NTSTATUS
mvolSystemControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;

    if (DeviceObject == mvolRootDeviceObject)
    {
        WDRBD_TRACE("mvolRootDevice Request\n");

        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

#ifdef _WIN32_MVFL
    if (VolumeExtension->Active)
    {
#ifdef _WIN32_CHECK
        struct drbd_conf *mdev = minor_to_mdev(VolumeExtension->VolIndex);
        if (mdev && (R_PRIMARY != mdev->state.role))
        {
            //PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
            //WDRBD_TRACE("DeviceObject(0x%x), MinorFunction(0x%x) STATUS_INVALID_DEVICE_REQUEST\n", DeviceObject, irpSp->MinorFunction);

            Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return STATUS_INVALID_DEVICE_REQUEST;
        }
#endif
    }
#endif
    IoSkipCurrentIrpStackLocation(Irp);

    return IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
}

NTSTATUS
mvolDispatchPower(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    return mvolSendToNextDriver(DeviceObject, Irp);
}

_Use_decl_annotations_
NTSTATUS
mvolRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;

    if (DeviceObject == mvolRootDeviceObject)
    {
        /// SEO: DRBD DriverObject로 READ/WRITE가 들어올 수 없음
        goto invalid_device;
    }

    if (VolumeExtension->Active)
    {
#ifdef _WIN32_CHECK
        struct drbd_conf *mdev = minor_to_mdev(VolumeExtension->VolIndex);
        if (mdev && (mdev->state.role == R_PRIMARY))
        {
            if (g_read_filter)
            {
                goto async_read_filter;
            }
        }
        else
        {
            goto invalid_device;
        }
#endif
    }

    IoSkipCurrentIrpStackLocation(Irp);

    return IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);

async_read_filter:
    {
#ifdef DRBD_TRACE
        PIO_STACK_LOCATION readIrpSp = IoGetCurrentIrpStackLocation(Irp);
        WDRBD_TRACE("\n\nupper driver READ request start! vol:%c: sect:0x%llx sz:%d --------------------------------!\n",
            VolumeExtension->Letter, (readIrpSp->Parameters.Read.ByteOffset.QuadPart / 512), readIrpSp->Parameters.Read.Length);
#endif
        PMVOL_THREAD pThreadInfo = &VolumeExtension->WorkThreadInfo;

        IoMarkIrpPending(Irp);
        ExInterlockedInsertTailList(&pThreadInfo->ListHead, &Irp->Tail.Overlay.ListEntry, &pThreadInfo->ListLock);
        IO_THREAD_SIG(pThreadInfo);
    }
    return STATUS_PENDING;

invalid_device:
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS
mvolWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;

    if (DeviceObject == mvolRootDeviceObject)
    {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (VolumeExtension->Active)
    {
#ifdef _WIN32_CHECK
        struct drbd_conf *mdev = minor_to_mdev(VolumeExtension->VolIndex);

        if (mdev/* && (mdev->state.role == R_PRIMARY)*/)
        {
            NTSTATUS					status;
            PMVOL_THREAD				pThreadInfo;

            InterlockedIncrement(&VolumeExtension->IrpCount);
            InterlockedIncrement64(&VolumeExtension->WriteCount.QuadPart);

#ifdef DRBD_TRACE
            PIO_STACK_LOCATION writeIrpSp = IoGetCurrentIrpStackLocation(Irp);
            WDRBD_TRACE("\n(%s):Upper driver WRITE request start! vol:%c: sect:0x%llx sz:%d ................Queuing(%d)!\n",
                current->comm, VolumeExtension->Letter, (writeIrpSp->Parameters.Write.ByteOffset.QuadPart / 512), writeIrpSp->Parameters.Write.Length, VolumeExtension->IrpCount);
#endif

#ifdef MULTI_WRITE_HOOKER_THREADS
            pThreadInfo = &deviceExtension->WorkThreadInfo[deviceExtension->Rr];
            IoMarkIrpPending(Irp);
            ExInterlockedInsertTailList(&pThreadInfo->ListHead,
                &Irp->Tail.Overlay.ListEntry, &pThreadInfo->ListLock);

            IO_THREAD_SIG(pThreadInfo);
            if (++deviceExtension->Rr >= 5)
            {
                deviceExtension->Rr = 0;
            }
#else
            pThreadInfo = &VolumeExtension->WorkThreadInfo;
            IoMarkIrpPending(Irp);
            ExInterlockedInsertTailList(&pThreadInfo->ListHead,
                &Irp->Tail.Overlay.ListEntry, &pThreadInfo->ListLock);
            IO_THREAD_SIG(pThreadInfo);
#endif
            return STATUS_PENDING;
        }
        else
        {
            Irp->IoStatus.Information = 0;
            Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return STATUS_INVALID_DEVICE_REQUEST;
        }
#endif
    }
    else
    {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
    }
}

NTSTATUS
mvolDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS		status;
    PIO_STACK_LOCATION	irpSp = NULL;
    PVOLUME_EXTENSION	VolumeExtension = DeviceObject->DeviceExtension;

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_MVOL_GET_PROC_DRBD:
        {
            extern int seq_file_idx;
            extern int drbd_seq_show(struct seq_file *seq, void *v);
            PMVOL_VOLUME_INFO p = NULL;

            p = (PMVOL_VOLUME_INFO)Irp->AssociatedIrp.SystemBuffer;

            MVOL_LOCK();
            seq_file_idx = 0;
            drbd_seq_show((struct seq_file *)&p->Seq, 0); // DRBD_DOC:DW130: struct seq_file 는 바로 char buffer 임으로 강제 캐스팅 가능
            MVOL_UNLOCK();

            irpSp->Parameters.DeviceIoControl.OutputBufferLength = sizeof(MVOL_VOLUME_INFO);
            MVOL_IOCOMPLETE_REQ(Irp, STATUS_SUCCESS, sizeof(MVOL_VOLUME_INFO));
        }

        case IOCTL_MVOL_GET_VOLUME_COUNT:
        {
            PROOT_EXTENSION RootExtension = mvolRootDeviceObject->DeviceExtension;

            *(PULONG)(Irp->AssociatedIrp.SystemBuffer) = RootExtension->Count;
            MVOL_IOCOMPLETE_REQ(Irp, STATUS_SUCCESS, sizeof(ULONG));
        }

        case IOCTL_MVOL_GET_VOLUMES_INFO:
        {
            ULONG size = 0;

            status = IOCTL_GetAllVolumeInfo(Irp, &size);
            MVOL_IOCOMPLETE_REQ(Irp, status, size);
        }

        case IOCTL_MVOL_GET_VOLUME_INFO:
        {
            ULONG size = 0;

            status = IOCTL_GetVolumeInfo(DeviceObject, Irp, &size);
            MVOL_IOCOMPLETE_REQ(Irp, status, size);
        }

        case IOCTL_MVOL_INIT_VOLUME_THREAD:
        {
            status = IOCTL_InitVolumeThread(DeviceObject, Irp);
            MVOL_IOCOMPLETE_REQ(Irp, status, 0);
        }

        case IOCTL_MVOL_CLOSE_VOLUME_THREAD:
        {
            status = IOCTL_CloseVolumeThread(DeviceObject, Irp);
            MVOL_IOCOMPLETE_REQ(Irp, status, 0);
        }

        case IOCTL_MVOL_VOLUME_START:
        {
            status = IOCTL_VolumeStart(DeviceObject, Irp);
            MVOL_IOCOMPLETE_REQ(Irp, status, 0);
        }

        case IOCTL_MVOL_VOLUME_STOP:
        {
            status = IOCTL_VolumeStop(DeviceObject, Irp);
            MVOL_IOCOMPLETE_REQ(Irp, status, 0);
        }

        case IOCTL_MVOL_GET_VOLUME_SIZE:
        {
            status = IOCTL_GetVolumeSize(DeviceObject, Irp);
            MVOL_IOCOMPLETE_REQ(Irp, status, sizeof(LARGE_INTEGER));
        }

        case IOCTL_MVOL_GET_COUNT_INFO:
        {
            ULONG			size = 0;

            status = IOCTL_GetCountInfo(DeviceObject, Irp, &size);
            MVOL_IOCOMPLETE_REQ(Irp, status, size);
        }

        case IOCTL_MVOL_MOUNT_VOLUME:
        {
            WDRBD_INFO("IOCTL_MVOL_MOUNT_VOLUME. DeviceObject(0x%p) VolumeExtension(0x%p)\n", DeviceObject, VolumeExtension);

            status = IOCTL_MountVolume(DeviceObject, Irp);
            WDRBD_TRACE("IOCTL_MVOL_MOUNT_VOLUME. status(0x%x)\n", status);
            MVOL_IOCOMPLETE_REQ(Irp, status, 0);
        }
    }

    if (DeviceObject == mvolRootDeviceObject ||
        VolumeExtension->TargetDeviceObject == NULL)
    {
        status = STATUS_UNSUCCESSFUL;
        MVOL_IOCOMPLETE_REQ(Irp, status, 0);
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
}

NTSTATUS
mvolDispatchPnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS		status;
    PIO_STACK_LOCATION	irpSp;

    if (DeviceObject == mvolRootDeviceObject)
    {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    switch (irpSp->MinorFunction)
    {
        case IRP_MN_START_DEVICE:
        {
            status = mvolStartDevice(DeviceObject, Irp);
            break;
        }
        case IRP_MN_REMOVE_DEVICE:
        {
            status = mvolRemoveDevice(DeviceObject, Irp);
            break;
        }
        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        {
            status = mvolDeviceUsage(DeviceObject, Irp);
            break;
        }

        default:
            return mvolSendToNextDriver(DeviceObject, Irp);
    }

    return status;
}

/**
* @brief
*   MOUNTDEV_UNIQUE_ID 값이 레지스트리에 있는지를 query 한다.
*   있다면 "\DosDevices\" 로 시작되는 drive letter 가 존재하는지를 확인 한 후
*   그 letter값을 return한다.
*   참고 http://msdn.microsoft.com/en-us/library/windows/hardware/ff567603(v=vs.85).aspx
*/
char _query_mounted_devices(PMOUNTDEV_UNIQUE_ID pmuid)
{
    OBJECT_ATTRIBUTES           attributes;
    PKEY_FULL_INFORMATION       keyInfo = NULL;
    PKEY_VALUE_FULL_INFORMATION valueInfo = NULL;
    size_t                      valueInfoSize = sizeof(KEY_VALUE_FULL_INFORMATION) + 1024 + sizeof(ULONGLONG);

    UNICODE_STRING mm_reg_path;
    char letter_token = '\0';

    NTSTATUS status;
    HANDLE hKey = NULL;
    ULONG size;
    int Count;

    PAGED_CODE();

    RtlUnicodeStringInit(&mm_reg_path, L"\\Registry\\Machine\\System\\MountedDevices");

    InitializeObjectAttributes(&attributes,
        &mm_reg_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &attributes);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = ZwQueryKey(hKey, KeyFullInformation, NULL, 0, &size);
    if (status != STATUS_BUFFER_TOO_SMALL)
    {
        ASSERT(!NT_SUCCESS(status));
        goto cleanup;
    }

    keyInfo = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, size, '00DW');
    if (!keyInfo)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    status = ZwQueryKey(hKey, KeyFullInformation, keyInfo, size, &size);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    Count = keyInfo->Values;

    valueInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoSize, '10DW');
    if (!valueInfo)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    for (int i = 0; i < Count; ++i)
    {
        RtlZeroMemory(valueInfo, valueInfoSize);

        status = ZwEnumerateValueKey(hKey, i, KeyValueFullInformation, valueInfo, valueInfoSize, &size);

        if (!NT_SUCCESS(status))
        {
            if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL)
            {
                goto cleanup;
            }
        }

        if (REG_BINARY == valueInfo->Type)
        {
            PWCHAR dos_name = ExAllocatePoolWithTag(PagedPool, valueInfo->NameLength + sizeof(WCHAR), '20DW');
            RtlZeroMemory(dos_name, valueInfo->NameLength + sizeof(WCHAR));
            RtlCopyMemory(dos_name, valueInfo->Name, valueInfo->NameLength);

            if (wcsstr(dos_name, L"\\DosDevices\\"))
            {
                if (pmuid->UniqueIdLength == valueInfo->DataLength &&
                    ((SIZE_T)pmuid->UniqueIdLength == RtlCompareMemory(pmuid->UniqueId, (unsigned char *)valueInfo + valueInfo->DataOffset, pmuid->UniqueIdLength)))
                {
                    letter_token = (char)(*(dos_name + wcslen(L"\\DosDevices\\")));
                }
            }

            ExFreePool(dos_name);
        }
    }

cleanup:
    kfree(keyInfo);
    kfree(valueInfo);

    if (hKey)
    {
        ZwClose(hKey);
    }

    return letter_token & ~0x20;
}
