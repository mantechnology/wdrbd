#include "pch.h"

RTL_GENERIC_TABLE g_GenericTable;

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
	PFLT_VOLUME pFltVolume
)
{
	BOOLEAN bRet = FALSE;
	
	RtlInsertElementGenericTable(&g_GenericTable, &pFltVolume, sizeof(PFLT_VOLUME), &bRet);

	return bRet;
}

BOOLEAN
DeleteProtectedVolume(
	PFLT_VOLUME pFltVolume
)
{
	return RtlDeleteElementGenericTable(&g_GenericTable, &pFltVolume);
}

BOOLEAN
isProtectedVolume(
	IN PFLT_VOLUME pVolume
	)
{
	return RtlLookupElementGenericTable(&g_GenericTable, &pVolume) != NULL ? TRUE : FALSE;
}