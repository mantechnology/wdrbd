#include <wdm.h>
#include "drbd_windrv.h"	/// SEO:
#include "drbd_wingenl.h"	/// SEO:
#include "proto.h"

#include "linux-compat/idr.h"
#include "drbd_int.h"
#include "drbd_wrappers.h"

#ifdef _WIN32_V9 //헤더파일이 지정해야할 이유 파악
#include <ntdddisk.h>
#endif

NTSTATUS
mvolIrpCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	PKEVENT Event = (PKEVENT) Context;

	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}


NTSTATUS
mvolRunIrpSynchronous(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS		status;
	KEVENT			event;
	PVOLUME_EXTENSION	VolumeExtension = DeviceObject->DeviceExtension;

	KeInitializeEvent(&event, NotificationEvent, FALSE);
	IoCopyCurrentIrpStackLocationToNext(Irp);
	IoSetCompletionRoutine(Irp, mvolIrpCompletion, &event, TRUE, TRUE, TRUE);
	status = IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, (PLARGE_INTEGER) NULL);
		status = Irp->IoStatus.Status;
	}

	return status;
}

VOID
mvolSyncFilterWithTarget(IN PDEVICE_OBJECT FilterDevice, IN PDEVICE_OBJECT TargetDevice)
{
	ULONG	propFlags;

	//
	// Propogate all useful flags from target to mvol. MountMgr will look
	// at the mvol object capabilities to figure out if the disk is
	// a removable and perhaps other things.
	//
	propFlags = TargetDevice->Flags & FILTER_DEVICE_PROPOGATE_FLAGS;
	FilterDevice->Flags |= propFlags;

	propFlags = TargetDevice->Characteristics & FILTER_DEVICE_PROPOGATE_CHARACTERISTICS;
	FilterDevice->Characteristics |= propFlags;
}

NTSTATUS
mvolStartDevice(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS		status;
	PVOLUME_EXTENSION	VolumeExtension = DeviceObject->DeviceExtension;

	status = mvolRunIrpSynchronous(DeviceObject, Irp);
	mvolSyncFilterWithTarget(DeviceObject, VolumeExtension->TargetDeviceObject);
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS
mvolRemoveDevice(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS		status;
	PVOLUME_EXTENSION	VolumeExtension = DeviceObject->DeviceExtension;

	status = mvolRunIrpSynchronous(DeviceObject, Irp);
	if (!NT_SUCCESS(status))
	{
		WDRBD_ERROR("cannot remove device, status=0x%x\n", status);
	}

#ifdef MULTI_WRITE_HOOKER_THREADS
	{
		int i = 0;
		for (i = 0; i < 5; i++) // TEST!!!
		{
			if (deviceExtension->WorkThreadInfo[i].Active)
			{
				mvolTerminateThread(&deviceExtension->WorkThreadInfo);
				WDRBD_TRACE("[%ws]: WorkThread Terminate Completely\n",
					deviceExtension->PhysicalDeviceName);
			}
		}
	}
#else
	if (VolumeExtension->WorkThreadInfo.Active)
	{
		mvolTerminateThread(&VolumeExtension->WorkThreadInfo);
		WDRBD_TRACE("[%ws]: WorkThread Terminate Completely\n",	VolumeExtension->PhysicalDeviceName);
	}
#endif

	extern int drbd_adm_down_from_engine(struct drbd_tconn *tconn);
    struct drbd_conf *mdev;
    if (VolumeExtension->Active)
    {
        mdev = minor_to_device(VolumeExtension->VolIndex);
    }
    else
    {
        mdev = get_targetdev_by_md(VolumeExtension->Letter);
    }

    if (mdev)
    {
        // DRBD-UPGRADE: if primary, check umount first? maybe umounted already?
#ifdef _WIN32_V9
		struct drbd_resource *resource = mdev->resource;
		struct drbd_connection *connection, *tmp;
		int ret; 

		for_each_connection_safe(connection, tmp, resource)
		{
			ret = drbd_adm_down_from_engine(connection);
			if (ret != NO_ERROR)
			{
				WDRBD_ERROR("drbd_adm_down_from_engine failed. ret=%d\n", ret); // EVENTLOG!
				// error ignored.
			}
		}
#else
        int ret = drbd_adm_down_from_engine(mdev->tconn);

        if (ret != NO_ERROR)
        {
            WDRBD_ERROR("drbd_adm_down_from_engine failed. ret=%d\n", ret); // EVENTLOG!
            // error ignored.
        }
#endif
        drbdFreeDev(VolumeExtension);
    }

	MVOL_LOCK();
	mvolDeleteDeviceList(VolumeExtension);
	MVOL_UNLOCK();

	IoDetachDevice(VolumeExtension->TargetDeviceObject);
	IoDeleteDevice(DeviceObject);
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS
mvolDeviceUsage(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS		status;
	PVOLUME_EXTENSION	VolumeExtension = DeviceObject->DeviceExtension;
	PDEVICE_OBJECT		attachedDeviceObject;

	attachedDeviceObject = IoGetAttachedDeviceReference(DeviceObject);
	if (attachedDeviceObject)
	{
		if (attachedDeviceObject == DeviceObject ||
			(attachedDeviceObject->Flags & DO_POWER_PAGABLE))
		{
			DeviceObject->Flags |= DO_POWER_PAGABLE;
		}
		ObDereferenceObject(attachedDeviceObject);
	}

	status = mvolRunIrpSynchronous(DeviceObject, Irp);

	if (!(VolumeExtension->TargetDeviceObject->Flags & DO_POWER_PAGABLE))
	{
		DeviceObject->Flags &= ~DO_POWER_PAGABLE;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

int DoSplitIo(PVOLUME_EXTENSION VolumeExtension, ULONG io, PIRP upper_pirp, struct splitInfo *splitInfo,
	long split_id, long split_total_id, long split_total_length, struct drbd_conf *mdev, PVOID buffer, LARGE_INTEGER offset, ULONG length)
{
	struct bio				*bio;
	unsigned int			nr_pages;
	struct request_queue	*q;

	nr_pages = (length + PAGE_SIZE - 1) >> PAGE_SHIFT;
	bio = bio_alloc(GFP_NOIO, nr_pages);
	if (!bio) 
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	bio->split_id = split_id;
	bio->split_total_id = split_total_id;
	bio->split_total_length = split_total_length;
	bio->splitInfo = splitInfo;
	bio->win32_page_buf = buffer;
	bio->pMasterIrp = upper_pirp; 

	bio->bi_sector = offset.QuadPart >> 9; 
	bio->bi_bdev = VolumeExtension->dev;
	bio->bi_rw |= (io == IRP_MJ_WRITE) ? WRITE : READ;
	bio->bi_size = length;

	q = kzalloc(sizeof(struct request_queue), 0, '85DW');
	if (!q)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	q->queuedata = mdev;

	drbd_make_request(q, bio); // drbd local I/O entry point 

	kfree(q);
	return STATUS_SUCCESS;
}

NTSTATUS
mvolReadWriteDevice(PVOLUME_EXTENSION VolumeExtension, PIRP Irp, ULONG Io)
{
	NTSTATUS					status = STATUS_INSUFFICIENT_RESOURCES;
	PIO_STACK_LOCATION			irpSp;
	PVOID						buffer;
	LARGE_INTEGER				offset;
	ULONG						length;
	struct drbd_conf			*mdev = NULL;

	irpSp = IoGetCurrentIrpStackLocation(Irp);
	if (Irp->MdlAddress)
	{
		buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		if (buffer == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	else
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (Io == IRP_MJ_WRITE)
	{
		offset.QuadPart = irpSp->Parameters.Write.ByteOffset.QuadPart;
		length = irpSp->Parameters.Write.Length;
	}
	else
	{
		offset.QuadPart = irpSp->Parameters.Read.ByteOffset.QuadPart;
		length = irpSp->Parameters.Read.Length;
	}

	mdev = minor_to_device(VolumeExtension->VolIndex);
	if (mdev/* && (mdev->state.role == R_PRIMARY)*/)
	{
		struct splitInfo *splitInfo = 0;
		ULONG io_id = 0;
		ULONG rest, slice, loop;
		ULONG splitted_io_count;

		slice = MAX_SPILT_BLOCK_SZ; // 1MB fixed
		loop = length / slice;
		rest = length % slice;

		if (loop == 0)
		{
			splitted_io_count = 1;
		}
		else
		{
			if (rest)
			{
				splitted_io_count = loop + 1;
			}
			else
			{
				splitted_io_count = loop;
			}

			splitInfo = kzalloc(sizeof(struct splitInfo), 0, '95DW');
			if (!splitInfo)
			{
				goto fail;
			}
			splitInfo->finished = 0;
		}

		for (io_id = 0; io_id < loop; io_id++)
		{
#ifdef _WIN32_TMP_Win8_BUG_0x1a_61946
			char *newbuf;
			if (Io == IRP_MJ_READ)
			{
				newbuf = kzalloc(slice, 0, 'A5DW');
				if (!newbuf)
				{
					WDRBD_ERROR("HOOKER malloc fail!!!\n");
					goto fail;
				}
				//memcpy(newbuf, buffer, slice); // for write
			}
			else
			{
				newbuf = buffer;
			}

			if ((status = DoSplitIo(VolumeExtension, Io, Irp, splitInfo, io_id, splitted_io_count, length, mdev, newbuf, offset, slice)) != 0)
#else
            if ((status = DoSplitIo(VolumeExtension, Io, Irp, splitInfo, io_id, splitted_io_count, length, mdev, buffer, offset, slice)))
#endif
			{
				goto fail;
			}

			offset.QuadPart = offset.QuadPart + slice;
			buffer = (char *) buffer + slice;
		}

		if (rest)
		{
#ifdef _WIN32_TMP_Win8_BUG_0x1a_61946
			char *newbuf;
			if (Io == IRP_MJ_READ)
			{
				newbuf = kzalloc(rest, 0, 'B5DW');
				if (!newbuf)
				{
					WDRBD_ERROR("HOOKER rest malloc fail!!\n");
					goto fail;
				}
				//memcpy(newbuf, buffer, rest); // for write
			}
			else
			{
				newbuf = buffer;
			}

			if ((status = DoSplitIo(VolumeExtension, Io, Irp, splitInfo, io_id, splitted_io_count, length, mdev, newbuf, offset, rest)) != 0)
#else
            if ((status = DoSplitIo(VolumeExtension, Io, Irp, splitInfo, io_id, splitted_io_count, length, mdev, buffer, offset, rest)))
#endif
			{
				goto fail;
			}
		}

		return STATUS_SUCCESS;
	}
	else
	{
		status = STATUS_INVALID_DEVICE_REQUEST;
	}

fail:
	WDRBD_ERROR("failed. status=0x%x\n", status);
	return status;
}

NTSTATUS
mvolGetVolumeSize(PDEVICE_OBJECT TargetDeviceObject, PLARGE_INTEGER pVolumeSize)
{
    NTSTATUS					status;
    KEVENT						event;
    IO_STATUS_BLOCK				ioStatus;
    PIRP						newIrp;
    GET_LENGTH_INFORMATION      li;

    memset(&li, 0, sizeof(li));

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    if (KeGetCurrentIrql() > APC_LEVEL)
    {
        WDRBD_ERROR("cannot run IoBuildDeviceIoControlRequest becauseof IRP(%d) #########\n", KeGetCurrentIrql());
    }

    newIrp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_LENGTH_INFO,
        TargetDeviceObject, NULL, 0,
        &li, sizeof(li),
        FALSE, &event, &ioStatus);
    if (!newIrp)
    {
        WDRBD_ERROR("cannot alloc new IRP\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(TargetDeviceObject, newIrp);
    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, (PLARGE_INTEGER)NULL);
        status = ioStatus.Status;
    }

    if (!NT_SUCCESS(status))
    {
        WDRBD_ERROR("cannot get volume information, err=0x%x\n", status);
        return status;
    }

    pVolumeSize->QuadPart = li.Length.QuadPart;

    return status;
}

#ifdef _WIN32_GetDiskPerf
NTSTATUS
mvolGetDiskPerf(PDEVICE_OBJECT TargetDeviceObject, PDISK_PERFORMANCE pDiskPerf)
{
	NTSTATUS					status;
	KEVENT						event;
	IO_STATUS_BLOCK				ioStatus;
	PIRP						newIrp;

	KeInitializeEvent(&event, NotificationEvent, FALSE);
	newIrp = IoBuildDeviceIoControlRequest(IOCTL_DISK_PERFORMANCE,
											TargetDeviceObject, NULL, 0,
											pDiskPerf, sizeof(DISK_PERFORMANCE),
											FALSE, &event, &ioStatus);
	if (!newIrp)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = IoCallDriver(TargetDeviceObject, newIrp);
	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, (PLARGE_INTEGER) NULL);
		status = ioStatus.Status;
	}
	return status;
}
#endif

VOID
mvolLogError(PDEVICE_OBJECT DeviceObject, ULONG UniqID, NTSTATUS ErrorCode, NTSTATUS Status)
{
	PIO_ERROR_LOG_PACKET		pLogEntry;
	PROOT_EXTENSION			RootExtension = NULL;
	PVOLUME_EXTENSION		VolumeExtension = NULL;
	PWCHAR				wp;
	USHORT				len, deviceNameLength;
	
	if( mvolRootDeviceObject == DeviceObject )
	{
		RootExtension = DeviceObject->DeviceExtension;
		deviceNameLength = RootExtension->PhysicalDeviceNameLength;
	}
	else
	{
		VolumeExtension = DeviceObject->DeviceExtension;
		deviceNameLength = VolumeExtension->PhysicalDeviceNameLength;
	}

	len = sizeof(IO_ERROR_LOG_PACKET) + deviceNameLength + 4;
	pLogEntry = (PIO_ERROR_LOG_PACKET) IoAllocateErrorLogEntry(mvolDriverObject, (UCHAR) len);
	if (pLogEntry == NULL)
	{
		WDRBD_ERROR("cannot alloc Log Entry\n");
		return;
	}
	RtlZeroMemory(pLogEntry, len);

	pLogEntry->ErrorCode = ErrorCode;
	pLogEntry->UniqueErrorValue = UniqID;
	pLogEntry->FinalStatus = Status;
	pLogEntry->DumpDataSize = 0;
	pLogEntry->NumberOfStrings = 1; // -> 1 for %2, 2 for %3...! %1 is driver obkect!
	pLogEntry->StringOffset = sizeof(IO_ERROR_LOG_PACKET) +pLogEntry->DumpDataSize;

	wp = (PWCHAR) ((PCHAR) pLogEntry + pLogEntry->StringOffset);

	if( RootExtension != NULL )
		wcscpy(wp, RootExtension->PhysicalDeviceName);
	else
		wcscpy(wp, VolumeExtension->PhysicalDeviceName);
	wp += deviceNameLength / sizeof(WCHAR);
	*wp = 0;

	IoWriteErrorLogEntry(pLogEntry);
}

NPAGED_LOOKASIDE_LIST drbd_printk_msg;

#ifdef _WIN32_EVENTLOG
char * printk_str(const char *fmt, ...)
{
	int ret = 0;
	va_list args;

    char * buf = (char *)ExAllocateFromNPagedLookasideList(&drbd_printk_msg);
    if (!buf)
    {
        return 0;
    }
    RtlZeroMemory(buf, MAX_ELOG_BUF);

	va_start(args, fmt);
	ret = vsprintf(buf, fmt, args); // DRBD_DOC: vsnprintf 개선
	va_end(args);

    // caller must ExFreePoolWithTag(buf, DRBD_GENERIC_POOL_TAG);

	return buf;
}

void _printk(const char * format, ...)
{
    int ret = 0;
	va_list args;

    char * buf = (char *)ExAllocateFromNPagedLookasideList(&drbd_printk_msg);
    if (!buf)
    {
        return;
    }
    RtlZeroMemory(buf, MAX_ELOG_BUF);

    va_start(args, format);
    ret = vsprintf(buf, format, args); // DRBD_DOC: vsnprintf 개선
	va_end(args);

    ULONG msgid = PRINTK_INFO;
    int level_index = format[1] - '0';
    static DWORD msgids[] = {
        PRINTK_EMERG,
        PRINTK_ALERT,
        PRINTK_CRIT,
        PRINTK_ERR,
        PRINTK_WARN,
        PRINTK_NOTICE,
        PRINTK_INFO,
        PRINTK_DBG
    };

    ASSERT((level_index >= 0) && (level_index < 8));

    WriteEventLogEntryData(msgids[level_index], 0, 0, 1, L"%S", buf + 3);

    ExFreeToNPagedLookasideList(&drbd_printk_msg, buf);
}
#endif

static int _char_to_wchar(wchar_t * dst, size_t buf_size, char * src)
{
    char * p = src;
    wchar_t * t = dst;
    int c = 0;

    for (; *p && c < buf_size; ++c)
    {
        *t++ = (wchar_t)*p++;
    }

    return c;
}

int
WriteEventLogEntryData(
	ULONG	pi_ErrorCode,
	ULONG	pi_UniqueErrorCode,
	ULONG	pi_FinalStatus,
	ULONG	pi_nDataItems,
	...
)
/*++

Routine Description:
Writes an event log entry to the event log.

Arguments:

pi_pIoObject......... The IO object ( driver object or device object ).
pi_ErrorCode......... The error code.
pi_UniqueErrorCode... A specific error code.
pi_FinalStatus....... The final status.
pi_nDataItems........ Number of data items (i.e. pairs of data parameters).
.
. data items values
.

Return Value:

None .

Reference : http://git.etherboot.org/scm/mirror/winof/hw/mlx4/kernel/bus/core/l2w_debug.c
--*/
{
	/* Variable argument list */
	va_list					l_Argptr;
	/* Pointer to an error log entry */
	PIO_ERROR_LOG_PACKET	l_pErrorLogEntry;
	/* sizeof insertion string */
	int 	l_Size = 0;
	/* temp buffer */
	UCHAR l_Buf[ERROR_LOG_MAXIMUM_SIZE - 2];
	/* position in buffer */
	UCHAR * l_Ptr = l_Buf;
	/* Data item index */
	USHORT l_nDataItem;
	/* total packet size */
	int l_TotalSize;
#if 0
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) // DRBD_DOC: DV: skip api RtlStringCchPrintfW(PASSIVE_LEVEL)
    {
        // DRBD_DOC: EVENTLOG 처리시 고려
        WDRBD_WARN("IRQL(%d) too high. Log canceled.\n", KeGetCurrentIrql());
        return 1;
    }
#endif
	if (mvolRootDeviceObject == NULL) {
		ASSERT(mvolRootDeviceObject != NULL);
		return 2;
	}

	/* Init the variable argument list */
	va_start(l_Argptr, pi_nDataItems);

	/* Create the insertion strings Insert the data items */
	memset(l_Buf, 0, sizeof(l_Buf));
	for (l_nDataItem = 0; l_nDataItem < pi_nDataItems; l_nDataItem++)
	{
		//NTSTATUS status;
		/* Current binary data item */
		int l_CurDataItem;
		/* Current pointer data item */
		void* l_CurPtrDataItem;
		/* format specifier */
		WCHAR* l_FormatStr;
		/* the rest of the buffer */
		int l_BufSize = (int) (l_Buf + sizeof(l_Buf) -l_Ptr);
		/* size of insertion string */
		size_t l_StrSize;

		/* print as much as we can */
		if (l_BufSize < 4)
			break;

		/* Get format specifier */
		l_FormatStr = va_arg(l_Argptr, PWCHAR);

        int ret = 0;
		/* Get next data item */
        if (!wcscmp(l_FormatStr, L"%S")) {
			l_CurPtrDataItem = va_arg(l_Argptr, PCHAR);
            ret = _char_to_wchar(l_Ptr, l_BufSize >> 1, l_CurPtrDataItem);
		}
		else if (!wcscmp(l_FormatStr, L"%s")) {
			l_CurPtrDataItem = va_arg(l_Argptr, PWCHAR);
			/* convert to string */
            swprintf_s(l_Ptr, l_BufSize >> 1, l_FormatStr, l_CurPtrDataItem);
            //status = RtlStringCchPrintfW((NTSTRSAFE_PWSTR)l_Ptr, l_BufSize >> 1, l_FormatStr, l_CurPtrDataItem);
		}
		else {
			l_CurDataItem = va_arg(l_Argptr, int);
			/* convert to string */
            swprintf_s(l_Ptr, l_BufSize >> 1, l_FormatStr, l_CurDataItem);
			//status = RtlStringCchPrintfW((NTSTRSAFE_PWSTR) l_Ptr, l_BufSize >> 1, l_FormatStr, l_CurDataItem);
		}

        if (!ret)
			return 3;

		/* prepare the next loop */
        l_StrSize = wcslen((PWCHAR)l_Ptr) * sizeof(WCHAR);
		//status = RtlStringCbLengthW((NTSTRSAFE_PWSTR) l_Ptr, l_BufSize, &l_StrSize);
		//if (!NT_SUCCESS(status))
		//	return 4;
		*(WCHAR*) &l_Ptr[l_StrSize] = (WCHAR) 0;
		l_StrSize += 2;
		l_Size = l_Size + (int) l_StrSize;
		l_Ptr = l_Buf + l_Size;
		l_BufSize = (int) (l_Buf + sizeof(l_Buf) -l_Ptr);

	} /* Inset a data item */

	/* Term the variable argument list */
	va_end(l_Argptr);

	/* Allocate an error log entry */
	l_TotalSize = sizeof(IO_ERROR_LOG_PACKET) +l_Size;
	if (l_TotalSize >= ERROR_LOG_MAXIMUM_SIZE - 2) {
		l_TotalSize = ERROR_LOG_MAXIMUM_SIZE - 2;
		l_Size = l_TotalSize - sizeof(IO_ERROR_LOG_PACKET);
	}
	l_pErrorLogEntry = (PIO_ERROR_LOG_PACKET) IoAllocateErrorLogEntry(
		mvolRootDeviceObject, (UCHAR) l_TotalSize);

	/* Check allocation */
	if (l_pErrorLogEntry != NULL)
	{ /* OK */

		/* Set the error log entry header */
		l_pErrorLogEntry->ErrorCode = pi_ErrorCode;
		l_pErrorLogEntry->DumpDataSize = 0;
		l_pErrorLogEntry->SequenceNumber = 0;
		l_pErrorLogEntry->MajorFunctionCode = 0;
		l_pErrorLogEntry->IoControlCode = 0;
		l_pErrorLogEntry->RetryCount = 0;
		l_pErrorLogEntry->UniqueErrorValue = pi_UniqueErrorCode;
		l_pErrorLogEntry->FinalStatus = pi_FinalStatus;
		l_pErrorLogEntry->NumberOfStrings = l_nDataItem;
		l_pErrorLogEntry->StringOffset = sizeof(IO_ERROR_LOG_PACKET) +l_pErrorLogEntry->DumpDataSize;
		l_Ptr = (UCHAR*) l_pErrorLogEntry + l_pErrorLogEntry->StringOffset;
		if (l_Size)
			memcpy(l_Ptr, l_Buf, l_Size);

		/* Write the packet */
		IoWriteErrorLogEntry(l_pErrorLogEntry);

	} /* OK */
    return 0;
} /* WriteEventLogEntry */

NTSTATUS DeleteDriveLetterInRegistry(char letter)
{
    UNICODE_STRING reg_path, valuekey;
    wchar_t wszletter[] = L"A";

    RtlUnicodeStringInit(&reg_path, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\drbd\\volumes");

    wszletter[0] = (WCHAR)letter;
    RtlUnicodeStringInit(&valuekey, wszletter);

    return DeleteRegistryValueKey(&reg_path, &valuekey);
}

/**
* @brief   VOLUME_EXTENSION 객체의 값을 참조하여 block_device 객체값을 생성한다.
*          여기서 생성된 block_device 값은 다른 곳에서 적절히 ExFreePool()해줘야 한다.
*/
struct block_device * create_drbd_block_device(IN OUT PVOLUME_EXTENSION pvext)
{
    struct block_device * dev;

    dev = kmalloc(sizeof(struct block_device), 0, 'C5DW');
    if (!dev)
    {
        WDRBD_ERROR("Failed to allocate block_device NonPagedMemory");
        goto block_device_failed;
    }

    dev->bd_disk = kmalloc(sizeof(struct gendisk), 0, 'D5DW');
    if (!dev->bd_disk)
    {
        WDRBD_ERROR("Failed to allocate gendisk NonPagedMemory");
        goto gendisk_failed;
    }
#if 0
    dev->d_size = get_targetdev_volsize(pvext);
    if (0 == dev->d_size)
    {
        WDRBD_WARN("Failed to get (%c): volume size\n", pvext->Letter);
        goto gendisk_failed;
    }
#endif
    dev->bd_disk->disk_name[0] = pvext->Letter;
    dev->bd_disk->disk_name[1] = ':';
    dev->bd_disk->disk_name[2] = '\n';

    dev->bd_disk->queue = kmalloc(sizeof(struct request_queue), 0, 'E5DW');
    if (!dev->bd_disk->queue)
    {
        WDRBD_ERROR("Failed to allocate request_queue NonPagedMemory");
        goto request_queue_failed;
    }

    dev->bd_disk->pDeviceExtension = pvext;

    dev->bd_disk->queue->backing_dev_info.pDeviceExtension = pvext;
    dev->bd_disk->queue->logical_block_size = 512;
    dev->bd_disk->queue->max_hw_sectors = DRBD_MAX_BIO_SIZE >> 9;

    return dev;

request_queue_failed:
    kfree(dev->bd_disk->queue);

gendisk_failed:
    kfree(dev->bd_disk);

block_device_failed:
    kfree(dev);

    return NULL;
}

// 장착된 disk 정보 일괄 구축. 추후 drbd 엔진에서 사용되는 mdev의 blkdev_XXX 정보로 사용.
// 구축된 disk 자료구조의 free 는 스레드 종료시 개별적으로 처리함. 
// MVF dev 와 DRBD mdev 자료구조 통합, drbdadm 명령 통합 고려

VOID drbdCreateDev()
{
	PROOT_EXTENSION		rootExtension = NULL;
	PVOLUME_EXTENSION	pDeviceExtension = NULL;

	MVOL_LOCK();
	rootExtension = mvolRootDeviceObject->DeviceExtension;
	pDeviceExtension = rootExtension->Head;

	while (pDeviceExtension != NULL)
	{
        if (0 == pDeviceExtension->VolIndex)
        {
            pDeviceExtension = pDeviceExtension->Next;
            continue;
        }

		if (pDeviceExtension->dev)
		{
			WDRBD_WARN("pDeviceExtension(%c)->dev Already exists\n", pDeviceExtension->Letter);
			pDeviceExtension = pDeviceExtension->Next;
			continue;
		}

		pDeviceExtension->dev = kmalloc(sizeof(struct block_device), 0, 'F5DW');
		if (!pDeviceExtension->dev)
		{
			WDRBD_ERROR("pDeviceExtension(%c)->dev:kzalloc failed\n", pDeviceExtension->Letter);
			pDeviceExtension = pDeviceExtension->Next;
			continue;
		}

		pDeviceExtension->dev->bd_disk = kmalloc(sizeof(struct gendisk), 0, '06DW');
		if (!pDeviceExtension->dev->bd_disk)
		{
			WDRBD_ERROR("pDeviceExtension(%c)->dev->bd_disk:kzalloc failed\n", pDeviceExtension->Letter);
			kfree(pDeviceExtension->dev);
			pDeviceExtension->dev = 0;
			pDeviceExtension = pDeviceExtension->Next;
			continue;
		}

        pDeviceExtension->dev->d_size = get_targetdev_volsize(pDeviceExtension);
        if (!pDeviceExtension->dev->d_size)
		{
			WDRBD_ERROR("volume(%c) size is zero\n", pDeviceExtension->Letter);
			kfree(pDeviceExtension->dev->bd_disk);
			kfree(pDeviceExtension->dev);
			pDeviceExtension->dev = 0;
			pDeviceExtension = pDeviceExtension->Next;
			continue;
		}

		sprintf(pDeviceExtension->dev->bd_disk->disk_name, "%c:", pDeviceExtension->Letter);
		pDeviceExtension->dev->bd_disk->queue = kmalloc(sizeof(struct request_queue), 0, '16DW'); // CHECK FREE!!!!
		if (!pDeviceExtension->dev->bd_disk->queue)
		{
			WDRBD_ERROR("pDeviceExtension->dev->bd_disk->queue:kzalloc failed\n");
			kfree(pDeviceExtension->dev->bd_disk);
			kfree(pDeviceExtension->dev);
			pDeviceExtension->dev = 0;
			pDeviceExtension = pDeviceExtension->Next;
			continue;
		}
		pDeviceExtension->dev->bd_disk->pDeviceExtension = pDeviceExtension;

		pDeviceExtension->dev->bd_disk->queue->backing_dev_info.pDeviceExtension = pDeviceExtension;
		pDeviceExtension->dev->bd_disk->queue->logical_block_size = 512;
		pDeviceExtension->dev->bd_disk->queue->max_hw_sectors = DRBD_MAX_BIO_SIZE >> 9;
		pDeviceExtension = pDeviceExtension->Next;
	}
	MVOL_UNLOCK();
}

/**
* @brief   VOLUME_EXTENSION 내의 dev객체를 memory free 해준다.
*          생성은 drbdCreateDev와 짝을 이룬다.
*/
VOID drbdFreeDev(PVOLUME_EXTENSION VolumeExtension)
{
	if (VolumeExtension->dev == NULL)
	{
		WDRBD_WARN("(%c:)'s PVOLUME_EXTENSION->dev already freed\n",
			VolumeExtension->Letter);
		return;
	}

    kfree(VolumeExtension->dev->bd_disk->queue);   // kmpak. memory leak
	kfree(VolumeExtension->dev->bd_disk);
	kfree(VolumeExtension->dev);
	VolumeExtension->dev = NULL;
}
