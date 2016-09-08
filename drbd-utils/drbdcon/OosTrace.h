#ifndef __OOS_TRACE__
#define __OOS_TRACE__

#ifdef _WIN32_DEBUG_OOS

#include <DbgHelp.h>
#include <Windows.h>
#include "ioctl.h"

#pragma comment( lib, "ntdll.lib" )
#pragma comment( lib, "dbghelp.lib" )

extern "C" NTSYSAPI NTSTATUS WINAPI ZwQuerySystemInformation(
	_In_      ULONG		SystemInformationClass,
	_Inout_   PVOID     SystemInformation,
	_In_      ULONG     SystemInformationLength,
	_Out_opt_ PULONG    ReturnLength);

#define DRBD_DRIVER_NAME	"drbd.sys"
#define DRBD_SYMBOL_NAME	_T("drbd.pdb")

#define SymTagFunction 5
#define SystemModuleInformation 11
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)   
#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004L)  

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

struct CSymbolInfoPackage : public SYMBOL_INFO_PACKAGE
{
	CSymbolInfoPackage()
	{
		si.SizeOfStruct = sizeof(SYMBOL_INFO);
		si.MaxNameLen = sizeof(name);
	}
};

#endif	// __WIN32_DEBUG_TRACE
#endif	// __OOS_TRACE__