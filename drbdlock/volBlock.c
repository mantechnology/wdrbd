#include "pch.h"

RTL_GENERIC_TABLE g_GenericTable;
extern PFLT_FILTER gFilterHandle;

static RTL_GENERIC_COMPARE_RESULTS
TableCompareRoutine(
	__in struct _RTL_GENERIC_TABLE  *Table,
	__in PVOID  FirstStruct,
	__in PVOID  SecondStruct
	)
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
{
	UNREFERENCED_PARAMETER(Table);

	if (Buffer)
		ExFreePool(Buffer);
}

VOID
InitVolBlock(
	VOID
	)
{
	RtlInitializeGenericTable(&g_GenericTable, TableCompareRoutine, TableAllocateRoutine, TableFreeRoutine, NULL);
}

VOID
CleanupVolBlock(
	VOID
	)
{
	for (PVOID p = RtlEnumerateGenericTable(&g_GenericTable, TRUE); p != NULL; p = RtlEnumerateGenericTable(&g_GenericTable, TRUE))
		RtlDeleteElementGenericTable(&g_GenericTable, p);
}

BOOLEAN
AddProtectedVolume(
	PVOID pFltVolume
)
{
	BOOLEAN bRet = FALSE;
	
	RtlInsertElementGenericTable(&g_GenericTable, &pFltVolume, sizeof(PFLT_VOLUME), &bRet);

	return bRet;
}

BOOLEAN
DeleteProtectedVolume(
	PVOID pFltVolume
)
{
	return RtlDeleteElementGenericTable(&g_GenericTable, &pFltVolume);
}

BOOLEAN
isProtectedVolume(
	IN PDEVICE_OBJECT pVolume
	)
{
	return RtlLookupElementGenericTable(&g_GenericTable, &pVolume) != NULL ? TRUE : FALSE;
}

NTSTATUS
GetDeviceObjectFlt(
	IN PUNICODE_STRING pusDevName,
	OUT PDEVICE_OBJECT *pDeviceObject
	)
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

	*pDeviceObject = pDiskDeviceObject;

	return status;
}

NTSTATUS
GetDeviceObjectNonFlt(
	IN PUNICODE_STRING pusDevName,
	OUT PDEVICE_OBJECT *pDeviceObject
	)
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