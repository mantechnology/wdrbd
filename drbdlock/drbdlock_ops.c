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
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG i;

	RtlInitUnicodeString(&g_usDeviceName, DRBDLOCK_DEVICE_OBJECT_NAME);
	status = IoCreateDevice(pDrvObj, 0, &g_usDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	RtlInitUnicodeString(&g_usSymlinkName, DRBDLOCK_SYMLINK_NAME);
	status = IoCreateSymbolicLink(&g_usSymlinkName, &g_usDeviceName);
	if (!NT_SUCCESS(status))
	{
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
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Argument2);

	PDRBDLOCK_VOLUME_CONTROL pVolumeControl = (PDRBDLOCK_VOLUME_CONTROL)Argument1;
	PDEVICE_OBJECT pVolObj = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;


	if (pVolumeControl == NULL)
	{
		// invalid parameter.
		return;
	}


	status = ConvertVolume(&pVolumeControl->volume, &pVolObj);

	if (!NT_SUCCESS(status))
	{
		return;
	}	

	if (pVolumeControl->bBlock)
	{
		if (AddProtectedVolume(pVolObj))
		{
			DbgPrint("volume has been added as protected\n");
		}
		else
		{
			DbgPrint("volume add failed!!\n");
		}
	}
	else
	{
		if (DeleteProtectedVolume(pVolObj))
		{
			DbgPrint("volume has been deleted as protected\n");
		}
		else
		{
			DbgPrint("volume delete failed!!\n");
		}
	}


}

NTSTATUS
drbdlockStartupCallback(
	VOID
	)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES oa = { 0, };
	UNICODE_STRING usCallbackName;

	RtlInitUnicodeString(&usCallbackName, DRBDLOCK_CALLBACK_NAME);
	InitializeObjectAttributes(&oa, &usCallbackName, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, 0, 0);

	status = ExCreateCallback(&g_pCallbackObj, &oa, TRUE, TRUE);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	g_pCallbackReg = ExRegisterCallback(g_pCallbackObj, drbdlockCallbackFunc, NULL);

	return status;
}

VOID
drbdlockCleanupCallback(
	VOID
	)
{
	if (g_pCallbackReg)
		ExUnregisterCallback(g_pCallbackReg);

	if (g_pCallbackObj)
		ObDereferenceObject(g_pCallbackObj);
}

NTSTATUS
DefaultIrpDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
	)
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
		return STATUS_INVALID_PARAMETER;
	}

	Vol.volumeType = VOLUME_TYPE_DEVICE_NAME;
	wcscpy_s(Vol.volumeID.volumeName, DRBDLOCK_VOLUMENAME_MAX_LEN, pBuf);

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