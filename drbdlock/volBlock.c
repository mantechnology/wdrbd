/*++

Module Name:

	volBlock.c

Abstract:

	This is the volume block module of the drbdlock miniFilter driver.

Environment:

	Kernel mode

--*/

#include "pch.h"

RTL_GENERIC_TABLE g_GenericTable;
extern PFLT_FILTER gFilterHandle;

static RTL_GENERIC_COMPARE_RESULTS
TableCompareRoutine(
	__in struct _RTL_GENERIC_TABLE  *Table,
	__in PVOID  FirstStruct,
	__in PVOID  SecondStruct
	)
/*++

Routine Description:

	An entry point of a comparison callback routine.

Arguments:

	Table - Pointer to the generic table.
	FirstStruct - Pointer to the first item to be compared.
	SecondStruct - Pointer to the second item to be compared.

Return Value:

	GenericLessThan - first item is less than second one.
	GenericGreaterThan - first item is greater than second one.
	GenericEqual - first and second item are equal.

--*/
{
	UNREFERENCED_PARAMETER(Table);

	if (*(ULONG_PTR*)FirstStruct < *(ULONG_PTR*)SecondStruct)
		return GenericLessThan;
	else if (*(ULONG_PTR*)FirstStruct >*(ULONG_PTR*)SecondStruct)
		return GenericGreaterThan;
	else
		return GenericEqual;
}

static PVOID 
TableAllocateRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN CLONG ByteSize
	)
/*++

Routine Description:

	An entry point of an allocation callback routine.

Arguments:

	Table - Pointer to the generic table.
	ByteSize - The number of bytes to allcoate.

Return Value:

	None.

--*/
{
	PVOID Buffer = NULL;
	UNREFERENCED_PARAMETER(Table);

	Buffer = ExAllocatePool(NonPagedPool, ByteSize);

	return Buffer;
}

static VOID 
TableFreeRoutine(
	IN PRTL_GENERIC_TABLE Table, 
	IN PVOID Buffer
	)
/*++

Routine Description:

	An entry point of a deallocation callback routine.

Arguments:

	Table - Pointer to the generic table.
	Buffer - Pointer to the element that is being deleted.

Return Value:

	None.

--*/
{
	UNREFERENCED_PARAMETER(Table);

	if (Buffer)
		ExFreePool(Buffer);
}

VOID
InitVolBlock(
	VOID
	)
/*++

Routine Description:

	Initializes volume blocker, it does initialize generic table to be used to store volume information to be blocked.

Arguments:

	None.

Return Value:

	None.

--*/
{
	RtlInitializeGenericTable(&g_GenericTable, TableCompareRoutine, TableAllocateRoutine, TableFreeRoutine, NULL);
}

VOID
CleanupVolBlock(
	VOID
	)
/*++

Routine Description:

	Cleans up volume blocker, it does delete generic table.

Arguments:

	None.

Return Value:

	None.

--*/
{
	for (PVOID p = RtlEnumerateGenericTable(&g_GenericTable, TRUE); p != NULL; p = RtlEnumerateGenericTable(&g_GenericTable, TRUE))
		RtlDeleteElementGenericTable(&g_GenericTable, p);
}

BOOLEAN
AddProtectedVolume(
	PVOID pVolumeObject
	)
/*++

Routine Description:

	This routine adds specified volume device object into generic table to be blocked.

Arguments:

	pVolumeObject - Pointer to the volume device object which will be added as protected volume.

Return Value:

	True: the volume has been added.
	False: the volume has NOT been added because specified volume already exists in the generic table.

--*/
{
	BOOLEAN bRet = FALSE;
	
	RtlInsertElementGenericTable(&g_GenericTable, &pVolumeObject, sizeof(PFLT_VOLUME), &bRet);

	return bRet;
}

BOOLEAN
DeleteProtectedVolume(
	PVOID pVolumeObject
	)
/*++

Routine Description:

	This routine deletes specified volume device object into generic table to be blocked.

Arguments:

	pVolumeObject - Pointer to the volume device object which will be deleted from protected volume table.

Return Value:

	True: the volume has been deleted from generic table.
	False: the volume is NOT deleted from generic table because specified volume doesn't exist in the generic table.

--*/
{
	return RtlDeleteElementGenericTable(&g_GenericTable, &pVolumeObject);
}

BOOLEAN
isProtectedVolume(
	IN PDEVICE_OBJECT pVolume
	)
/*++

Routine Description:

	This routine checks if specified volume is protected.

Arguments:

	pVolume - volume device object to be chekced.

Return Value:

	True: specified volume is protected by drbdlock.
	False: specified volume is NOT protected.

--*/
{
	return RtlLookupElementGenericTable(&g_GenericTable, &pVolume) != NULL ? TRUE : FALSE;
}

NTSTATUS
GetDeviceObjectFlt(
	IN PUNICODE_STRING pusDevName,
	OUT PDEVICE_OBJECT *pDeviceObject
	)
/*++

Routine Description:

	This routine retrieves a pointer to the volume device object of specified device name.
	it gets volume device object through filter level api such as FltGetVolumeFromName, FltGetDiskDeviceObject, etc.
	it can be failed when try to get volume object that has no instance.

Arguments:

	pusDevName - Pointer to a buffer that contains a unicode string that is the name of the device object.
	pDeviceObject - Pointer to the volume device object.

Return Value:

	NtStatus values.

--*/
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PDEVICE_OBJECT pDiskDeviceObject = NULL;
	PFLT_VOLUME pVolume = NULL;

	do
	{
		status = FltGetVolumeFromName(gFilterHandle, pusDevName, &pVolume);

		if (!NT_SUCCESS(status))
		{
			drbdlock_print_log("FltGetVolumeFromName failed, status : 0x%x\n", status);
			break;
		}

		status = FltGetDiskDeviceObject(pVolume, &pDiskDeviceObject);

		if (!NT_SUCCESS(status))
		{
			drbdlock_print_log("FltGetDiskDeviceObject failed, status : 0x%x\n", status);
			break;
		}

	} while (FALSE);

	*pDeviceObject = pDiskDeviceObject;
	
	if (pVolume)
	{
		FltObjectDereference(pVolume);
		pVolume = NULL;
	}

	if (pDiskDeviceObject)
	{
		ObDereferenceObject(pDiskDeviceObject);
		pDiskDeviceObject = NULL;
	}

	return status;
}

NTSTATUS
GetDeviceObjectNonFlt(
	IN PUNICODE_STRING pusDevName,
	OUT PDEVICE_OBJECT *pDeviceObject
	)
/*++

Routine Description:

	This routine retrieves a pointer to the volume device object of specified device name.
	it gets volume device object through io manager api.
	it can be failed when try to get volume object that is being used, with status of sharing violation.

Arguments:

	pusDevName - Pointer to a buffer that contains a unicode string that is the name of the device object.
	pDeviceObject - Pointer to the volume device object.

Return Value:

	NtStatus values.

--*/
{
	PFILE_OBJECT pFileObject = NULL;
	PDEVICE_OBJECT pDev = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;	
	
	do
	{
		status = IoGetDeviceObjectPointer(pusDevName, FILE_READ_DATA, &pFileObject, &pDev);
		if (!NT_SUCCESS(status))
		{
			drbdlock_print_log("IoGetDeviceObjectPointer failed, status : 0x%x\n", status);
			break;
		}

	} while (FALSE);

	if (NT_SUCCESS(status) &&
		pFileObject)
	{
		*pDeviceObject = pFileObject->DeviceObject;
		ObDereferenceObject(pFileObject);
		pFileObject = NULL;
	}
	else
	{
		*pDeviceObject = NULL;
	}

	return status;
}

NTSTATUS
ConvertVolume(
	IN PDRBDLOCK_VOLUME pVolumeInfo,
	OUT PDEVICE_OBJECT *pConverted
	)
/*++

Routine Description:

	This routine gets volume device object from DRBDLOCK_VOLUME structure.

Arguments:

	pVolumeInfo - Pointer to the DRBDLOCK_VOLUME_CONTROL data structure containing volume information.
	pConverted - Pointer to the volume device object that is gotton from pVolumeInfo.

Return Value:

	NtStatus values.

--*/
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING usVolName = { 0, };

	if (pVolumeInfo == NULL ||
		pConverted == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (pVolumeInfo->volumeType == VOLUME_TYPE_DEVICE_OBJECT)
	{
		*pConverted = pVolumeInfo->volumeID.pVolumeObject;

		return STATUS_SUCCESS;
	}

	RtlInitUnicodeString(&usVolName, pVolumeInfo->volumeID.volumeName);

	status = GetDeviceObjectFlt(&usVolName, pConverted);

	if (status == STATUS_FLT_VOLUME_NOT_FOUND)
	{
		status = GetDeviceObjectNonFlt(&usVolName, pConverted);
	}

	if (!NT_SUCCESS(status))
	{
		drbdlock_print_log("could not get device object for volume(%ws)\n", pVolumeInfo->volumeID.volumeName);
	}

	return status;	
}