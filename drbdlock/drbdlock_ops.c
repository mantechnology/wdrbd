/*++

Module Name:

	drbdlock_ops.c

Abstract:

	This is the device operations module of the drbdlock miniFilter driver.

Environment:

	Kernel mode

--*/

#include "pch.h"

PDEVICE_OBJECT g_DeviceObject;
UNICODE_STRING g_usDeviceName;
UNICODE_STRING g_usSymlinkName;

PCALLBACK_OBJECT g_pCallbackObj;
PVOID g_pCallbackReg;

NTSTATUS
drbdlockCreateControlDeviceObject(
	IN PDRIVER_OBJECT pDrvObj
	)
/*++

Routine Description:

	Creates control device object to communicate.

Arguments:

	pDrvObj - drbdlock driver object.

Return Value:

	NtStatus value.

--*/
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG i;

	RtlInitUnicodeString(&g_usDeviceName, DRBDLOCK_DEVICE_OBJECT_NAME);
	status = IoCreateDevice(pDrvObj, 0, &g_usDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
	if (!NT_SUCCESS(status))
	{
		drbdlock_print_log("IoCreateDevice Failed, status : 0x%x\n", status);
		return status;
	}

	RtlInitUnicodeString(&g_usSymlinkName, DRBDLOCK_SYMLINK_NAME);
	status = IoCreateSymbolicLink(&g_usSymlinkName, &g_usDeviceName);
	if (!NT_SUCCESS(status))
	{
		drbdlock_print_log("IoCreateSymbolicLink Failed, status : 0x%x\n", status);
		return status;
	}

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		pDrvObj->MajorFunction[i] = DefaultIrpDispatch;		

	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlDispatch;

	return status;
}

VOID
drbdlockDeleteControlDeviceObject(
	VOID
	)
/*++

Routine Description:

	Deletes control device object.

Arguments:

	None.

Return Value:

	None.

--*/
{
	IoDeleteSymbolicLink(&g_usSymlinkName);

	if (g_DeviceObject != NULL)
		IoDeleteDevice(g_DeviceObject);
}

VOID
drbdlockCallbackFunc(
	IN PVOID Context,
	IN PVOID Argument1,
	IN PVOID Argument2
	)
/*++

Routine Description:

	This routine is called whenever other driver notifies drbdlock's callback object.

Arguments:

	Context - not used.
	Argument1 - Pointer to the DRBDLOCK_VOLUME_CONTROL data structure containing volume information to be (un)blocked.
	Argument2 - not used.

Return Value:

	None.

--*/
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Argument2);

	PDRBDLOCK_VOLUME_CONTROL pVolumeControl = (PDRBDLOCK_VOLUME_CONTROL)Argument1;
	PDEVICE_OBJECT pVolObj = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG ulSize = 0;
	POBJECT_NAME_INFORMATION pNameInfo = NULL;

	if (pVolumeControl == NULL)
	{
		// invalid parameter.
		drbdlock_print_log("pVolumeControl is NULL\n");
		return;
	}
	
	status = ConvertVolume(&pVolumeControl->volume, &pVolObj);
	if (!NT_SUCCESS(status))
	{
		drbdlock_print_log("ConvertVolume failed, status : 0x%x\n", status);
		return;
	}

	if (STATUS_INFO_LENGTH_MISMATCH == ObQueryNameString(pVolObj, NULL, 0, &ulSize))
	{
		pNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPool, ulSize);		
		if (pNameInfo)
		{
			status = ObQueryNameString(pVolObj, pNameInfo, ulSize, &ulSize);
			if (!NT_SUCCESS(status))
			{
				ulSize = 0;
			}
		}
	}	

	if (pVolumeControl->bBlock)
	{
		if (AddProtectedVolume(pVolObj))
		{			
			drbdlock_print_log("volume(%ws) has been added as protected\n", (ulSize && pNameInfo) ? pNameInfo->Name.Buffer : L"NULL");
		}
		else
		{
			drbdlock_print_log("volume(%ws) add failed\n", (ulSize && pNameInfo) ? pNameInfo->Name.Buffer : L"NULL");
		}
	}
	else
	{
		if (DeleteProtectedVolume(pVolObj))
		{
			drbdlock_print_log("volume(%ws) has been deleted from protected volume list\n", (ulSize && pNameInfo) ? pNameInfo->Name.Buffer : L"NULL");
		}
		else
		{
			drbdlock_print_log("volume(%ws) delete failed\n", (ulSize && pNameInfo) ? pNameInfo->Name.Buffer : L"NULL");
		}
	}

	if (pNameInfo)
		ExFreePool(pNameInfo);
}

NTSTATUS
drbdlockStartupCallback(
	VOID
	)
/*++

Routine Description:

	Initializes callback object to be notified.

Arguments:

	None.

Return Value:

	NtStatus values.

--*/
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES oa = { 0, };
	UNICODE_STRING usCallbackName;

	RtlInitUnicodeString(&usCallbackName, DRBDLOCK_CALLBACK_NAME);
	InitializeObjectAttributes(&oa, &usCallbackName, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, 0, 0);

	status = ExCreateCallback(&g_pCallbackObj, &oa, TRUE, TRUE);
	if (!NT_SUCCESS(status))
	{
		drbdlock_print_log("ExCreateCallback failed, status : 0x%x\n", status);
		return status;
	}

	g_pCallbackReg = ExRegisterCallback(g_pCallbackObj, drbdlockCallbackFunc, NULL);

	return status;
}

VOID
drbdlockCleanupCallback(
	VOID
	)
/*++

Routine Description:

	Cleans up callback object.

Arguments:

	None.

Return Value:

	None.

--*/
{
	if (g_pCallbackReg)
		ExUnregisterCallback(g_pCallbackReg);

	if (g_pCallbackObj)
		ObDereferenceObject(g_pCallbackObj);
}


NTSTATUS NotifyCallbackObject(PWSTR pszCallbackName, PVOID pParam)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES cboa = { 0, };
	UNICODE_STRING usCbName;
	PCALLBACK_OBJECT pCallbackObj;

	if (pszCallbackName == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlInitUnicodeString(&usCbName, pszCallbackName);
	InitializeObjectAttributes(&cboa, &usCbName, OBJ_CASE_INSENSITIVE, 0, 0);

	status = ExCreateCallback(&pCallbackObj, &cboa, FALSE, TRUE);

	if (NT_SUCCESS(status))
	{
		ExNotifyCallback(pCallbackObj, pParam, NULL);
		ObDereferenceObject(pCallbackObj);
	}
	else
		drbdlock_print_log("Failed to open callback object for %ws, status : 0x%x\n", pszCallbackName, status);

	return status;
}

NTSTATUS ResizeDrbdVolume(PDEVICE_OBJECT pDeviceObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;


	DRBD_VOLUME_CONTROL volume = { 0, };

	volume.pVolumeObject = pDeviceObject;
	
	
	status = NotifyCallbackObject(DRBD_CALLBACK_NAME, &volume);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return status;
}


NTSTATUS
DefaultIrpDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
	)
/*++

Routine Description:

	This dispatch routine only completes specified irp with success.

Arguments:

	pDeviceObject - Pointer to the device object that received specified irp.
	pIrp - Pointer to the irp.

Return Value:

	NtStatus value.

--*/
{
	UNREFERENCED_PARAMETER(pDeviceObject);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
IOCTL_GetStatus(
	PIRP pIrp, 
	PULONG pulSize
	)
/*++

Routine Description:

	This routine is called when received IOCTL_DRBDLOCK_GET_STATUS and returns status of drbdlock.

Arguments:

	pIrp - Pointer to the irp of device control.
	pulSize - The size to be retrieved to caller.

Return Value:

	NtStatus values.

--*/
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);	
	PDEVICE_OBJECT pDevice = NULL;
	DRBDLOCK_VOLUME Vol = { 0, };
	PVOID pBuf = pIrp->AssociatedIrp.SystemBuffer;

	if (pBuf == NULL ||
		pIrpStack->Parameters.DeviceIoControl.InputBufferLength < (2 * sizeof(WCHAR)) ||
		pIrpStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(BOOLEAN))
	{
		drbdlock_print_log("invalid buffer length, input(%u), output(%u)\n",
			pIrpStack->Parameters.DeviceIoControl.InputBufferLength,
			pIrpStack->Parameters.DeviceIoControl.OutputBufferLength);
		return STATUS_INVALID_PARAMETER;
	}

	Vol.volumeType = VOLUME_TYPE_DEVICE_NAME;
	status = RtlStringCchCopyW(Vol.volumeID.volumeName, DRBDLOCK_VOLUMENAME_MAX_LEN, pBuf);

	if (!NT_SUCCESS(status))
		return status;

	status = ConvertVolume(&Vol, &pDevice);

	if (NT_SUCCESS(status))
	{
		BOOLEAN r = isProtectedVolume(pDevice);

		RtlCopyMemory(pBuf, &r, sizeof(BOOLEAN));

		*pulSize = sizeof(BOOLEAN);
	}

	return status;
}

NTSTATUS
DeviceIoControlDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
	)
/*++

Routine Description:

	Device io control dispatch routine.

Arguments:

	pDeviceObject - Pointer to the device object that received specified irp.
	pIrp - Pointer to the irp.

Return Value:

	NtStatus values.

--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpStack = NULL;
	ULONG ulSize = 0;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	switch (pIrpStack->Parameters.DeviceIoControl.IoControlCode)
	{	
		case IOCTL_DRBDLOCK_GET_STATUS:
		{
			status = IOCTL_GetStatus(pIrp, &ulSize);

			break;
		}

		default:
		{
			break;
		}
	}

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = ulSize;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	UNREFERENCED_PARAMETER(pDeviceObject);

	return status;
}