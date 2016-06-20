// listprocess.cpp : Defines the entrypoint for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "winternl.h"
#include "strsafe.h"
#include "psapi.h"

#include <map>
#include <set>
#include <iostream>
#include <sstream>

using namespace std;

// winternal.h
// Undocumented SYSTEM_INFORMATION_CLASS: SystemHandleInformation
const SYSTEM_INFORMATION_CLASS SystemHandleInformation = (SYSTEM_INFORMATION_CLASS)16;

// Ntstatus.h
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

typedef NTSTATUS(NTAPI *PFN_NtQuerySystemInformation)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

typedef NTSTATUS(NTAPI *PFN_NtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);
typedef NTSTATUS(NTAPI *PFN_NtQueryObject)(
	_In_opt_   HANDLE Handle,
	_In_       OBJECT_INFORMATION_CLASS ObjectInformationClass,
	_Out_opt_  PVOID ObjectInformation,
	_In_       ULONG ObjectInformationLength,
	_Out_opt_  PULONG ReturnLength
	);

// The NtQueryInformationFile function and the structures that it returns 
// are internal to the operating system and subject to change from one 
// release of Windows to another. To maintain the compatibility of your 
// application, it is better not to use the function.
typedef NTSTATUS(NTAPI *PFN_NtQueryInformationFile)(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass
	);

#define HANDLE_TYPE_FILE_XP				25 // xp, 2003
#define HANDLE_TYPE_FILE_VISTA			28 // windows 7, 2008
#define HANDLE_TYPE_FILE				30 // windows 8, 2012

#define MAX_DRIVEMAPS					64
/*
* Custom defined process info
*/
typedef struct _DOS_DEVICE_DRIVE_LETTER_MAP{
	TCHAR devname[MAX_PATH];		/* The long device name,					*/
	/*   like \Device\HarddiskVolume2			*/
	TCHAR drive[32];				/* The drive name (like C:\).				*/
} DOS_DEVICE_DRIVE_LETTER_MAP;

// Undocumented structure: SYSTEM_HANDLE_INFORMATION
/*
* structure for NtQuerySystemInformation with SystemHandleInformation parameter.
*/
typedef struct _SYSTEM_HANDLE
{
	DWORD ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE;
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION;


/*
* Custom defined process info
*/
typedef struct _HANDLE_INFO
{
	HANDLE Handle;
	UCHAR ObjectTypeNumber;
	wstring *Path;
	wstring *TypeName;
} HANDLE_INFO;

typedef struct _PROCESS_HANDLE_INFO
{
	HANDLE Pid;
	TCHAR Path[MAX_PATH];
	map<HANDLE, HANDLE_INFO> *FileMap;
} PROCESS_HANDLE_INFO;

map<HANDLE, PROCESS_HANDLE_INFO *> procMap;
set<UCHAR> setFileTypes;

DOS_DEVICE_DRIVE_LETTER_MAP drivemaps[MAX_DRIVEMAPS];

TCHAR *getImageName(TCHAR *path);
bool parseOptions(int argc, _TCHAR* argv[]);
void printUsage(_TCHAR *cmd);
void printMap(void);

void printProcess(PROCESS_HANDLE_INFO *info, bool matched);
int listProcesses(void);
int listHandles(void);
void setDebugPrivilege(bool enable);
bool getProcessName(HANDLE pid, TCHAR *path);
void cacheDriveNames(void);
void dosDeviceToLetter(TCHAR *path);
void cacheFileObjectTypes(const SYSTEM_HANDLE_INFORMATION *);

HINSTANCE hNtDll;

bool _bNoPidKey = FALSE;
bool _bPrintFileHandle = FALSE;
bool _bSimpleFormat = FALSE;
bool _bDebug = FALSE;
TCHAR *_wszPath = NULL;
int _nMatchedProcs = 0;
int _nDrives = 0;

int _tmain(int argc, _TCHAR* argv[])
{
	TCHAR *cmd = getImageName(argv[0]);

	if (argc == 1)
	{
		printUsage(cmd);
		return FALSE;
	}

	for (int index = 1; index < argc; index++)
	{
		if (wcscmp(argv[index], L"/nk") == 0)
		{
			_bNoPidKey = TRUE;
		}
		else if (wcscmp(argv[index], L"/fh") == 0)
		{
			_bPrintFileHandle = TRUE;
		}
		else if (wcscmp(argv[index], L"/im") == 0)
		{
			_bSimpleFormat = TRUE;
		}
		else if (wcscmp(argv[index], L"/debug") == 0)
		{
			_bDebug = TRUE;
		}
		else if (wcscmp(argv[index], L"/?") == 0 || wcscmp(argv[index], L"-h") == 0)
		{
			printf_s("\nPrint all process and handle whose path is starting with the given path\n");
			printUsage(cmd);
			return TRUE;
		}
		else if (argv[index][0] == '/')
		{
			printf_s("invalid option: %ws\n\n", argv[index]);
			return FALSE;
		}
		else
		{
			_wszPath = argv[index];
		}
	}

	if (_wszPath == NULL)
	{
		printUsage(cmd);
		return 0;
	}

	hNtDll = LoadLibrary(_T("ntdll.dll"));
	if (!hNtDll)
	{
		printf_s("failed to load ntdll");
		return GetLastError();
	}

	cacheDriveNames();
	listProcesses();
	listHandles();
	printMap();

	return _nMatchedProcs;
}

TCHAR *getImageName(TCHAR *fullPath)
{
	TCHAR *ptr;
	if (fullPath[sizeof(fullPath) - 1] != '\\' &&
		(ptr = wcsrchr(fullPath, '\\')) != NULL)
	{
		return ptr + 1;
	}
	return fullPath;
}

void printUsage(_TCHAR *cmd)
{
	printf_s("\nUsage : %ws [/nk|/fh] [/im] start_path_string\n\n", cmd);
	printf_s("\t/nk\t with no key 'PID'\n");
	printf_s("\t/fh\t print open files\n");
	printf_s("\t/im\t print image name of the process\n\n");
	printf_s("It returns number of matched processes.\n\n");
	printf_s("Examples");
	printf_s("\tex)%ws C:\\Windows\n", cmd);
	printf_s("\t\tPID: 329 C:\\Windows\\System32\\notepad.exe\n");
	printf_s("\tex)%ws /nk C:\n", cmd);
	printf_s("\t\t329 C:\\Windows\\System32\\notepad.exe\n");
	printf_s("\tex)%ws /fh C:\\Windows\\System32\n", cmd);
	printf_s("\t\tPID:329 C:\\Windows\\System32\\notepad.exe\n");
	printf_s("\t\tHANDLE: 339 C:\\Windows\\System32\\test.txt\n");
	printf_s("\tex)%ws /im D\n", cmd);
	printf_s("\t\tPID:1329 notepad.exe\n\n");
}

void cacheFileObjectTypes(const SYSTEM_HANDLE_INFORMATION *pSysHandleInfo)
{
	PFN_NtQueryObject NtQueryObject = (PFN_NtQueryObject)GetProcAddress(hNtDll, "NtQueryObject");
	DWORD nSize = 4096, nRequired;
	if (_bDebug)
	{
		printf("caching object types....\n");
	}
	
	set<UCHAR>::iterator itrSet;

	for (size_t i = 0; i < pSysHandleInfo->NumberOfHandles; i++)
	{
		const SYSTEM_HANDLE *hSystem = &(pSysHandleInfo->Handles[i]);
		
		// if object type is already added to cache, continue to next item.
		itrSet = setFileTypes.find(hSystem->ObjectTypeNumber);
		if ( itrSet != setFileTypes.end() ) continue;

		nSize = 4096;
		PUBLIC_OBJECT_TYPE_INFORMATION *pObjTypeInfo = NULL;
		NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
		while (true)
		{
			pObjTypeInfo = (PUBLIC_OBJECT_TYPE_INFORMATION *)
				HeapAlloc(GetProcessHeap(), 0, nSize);
			status = NtQueryObject((HANDLE)hSystem->Handle, ObjectTypeInformation, pObjTypeInfo, nSize, &nRequired);
			if (status != STATUS_INFO_LENGTH_MISMATCH) break;

			HeapFree(GetProcessHeap(), 0, pObjTypeInfo);
			nSize = nRequired;
		};
		if (NT_SUCCESS(status) && _wcsicmp(pObjTypeInfo->TypeName.Buffer, L"File") == 0)
		{
			setFileTypes.insert(hSystem->ObjectTypeNumber);
			if (_bDebug)
			{
				printf("File[%d] object type added to cache\n",hSystem->ObjectTypeNumber);
			}
		}

		HeapFree(GetProcessHeap(), 0, pObjTypeInfo);
	}
}

int listHandles(void)
{
	if(_bDebug)
		printf("listing handles....\n");

	PFN_NtQuerySystemInformation NtQuerySystemInformation = (PFN_NtQuerySystemInformation)
		GetProcAddress(hNtDll, "NtQuerySystemInformation");
	PFN_NtQueryObject NtQueryObject = (PFN_NtQueryObject)GetProcAddress(hNtDll, "NtQueryObject");

	DWORD nSize = 4096, nRequired;
	SYSTEM_HANDLE_INFORMATION *pSysHandleInfo = (SYSTEM_HANDLE_INFORMATION *)
		HeapAlloc(GetProcessHeap(), 0, nSize);

	// NtQuerySystemInformation does not return the correct required buffer 
	// size if the buffer passed is too small. Instead you must call the 
	// function while increasing the buffer size until the function no longer 
	// returns STATUS_INFO_LENGTH_MISMATCH.
	while (NtQuerySystemInformation(SystemHandleInformation, pSysHandleInfo,
		nSize, &nRequired) == STATUS_INFO_LENGTH_MISMATCH)
	{
		HeapFree(GetProcessHeap(), 0, pSysHandleInfo);
		nSize = nRequired;
		pSysHandleInfo = (SYSTEM_HANDLE_INFORMATION*)HeapAlloc(
			GetProcessHeap(), 0, nSize);
	}

	setDebugPrivilege(TRUE);

	cacheFileObjectTypes(pSysHandleInfo);

	map<HANDLE, PROCESS_HANDLE_INFO *>::iterator iterPos;

	DWORD dwFiles = 0;
	DWORD dwKnownFiles = 0;
	DWORD dwProcs = 0;
	for (size_t i = 0; i < pSysHandleInfo->NumberOfHandles; i++)
	{
		SYSTEM_HANDLE *hSystem = &(pSysHandleInfo->Handles[i]);

		// skip non file handle
		bool bFileHandle;
		set<UCHAR>::iterator itrSet;
		for (itrSet = setFileTypes.begin(); itrSet != setFileTypes.end(); itrSet++)
		{
			if (bFileHandle = (hSystem->ObjectTypeNumber == *itrSet)) break;
		}
		if (!bFileHandle) continue;

		nSize = 4096;
		PUBLIC_OBJECT_TYPE_INFORMATION *pObjTypeInfo = NULL;
		NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
		while (true)
		{
			pObjTypeInfo = (PUBLIC_OBJECT_TYPE_INFORMATION *)
				HeapAlloc(GetProcessHeap(), 0, nSize);
			status = NtQueryObject((HANDLE*)hSystem->Handle, ObjectTypeInformation, pObjTypeInfo, nSize, &nRequired);
			if (status != STATUS_INFO_LENGTH_MISMATCH) break;

			HeapFree(GetProcessHeap(), 0, pObjTypeInfo);
			nSize = nRequired;
		}
		if (!NT_SUCCESS(status) || 
			hSystem->GrantedAccess == 0x12019f )
		{
			goto CLEAN_OBJ_TYPE_INFO;
		}

		ULONG pid = hSystem->ProcessId;

		// if process is not found in cache, continue to next
		iterPos = procMap.find((HANDLE)pid);
		if (iterPos == procMap.end()) 
			goto CLEAN_OBJ_TYPE_INFO;;

		HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProcess) 
			goto CLEAN_OBJ_TYPE_INFO;;

		// Duplicate the handle of process 
		HANDLE hCopy = NULL;
		HANDLE hFile = (HANDLE)hSystem->Handle;
		if (DuplicateHandle(hProcess, hFile, GetCurrentProcess(), &hCopy, 0, FALSE, DUPLICATE_SAME_ACCESS))
		{
			// if file type is not FILE_TYPE_DISK, GetFinalPathNameByHandle might be hung!
			DWORD dwFileType = GetFileType(hCopy);
			if (dwFileType != FILE_TYPE_DISK)
				goto CLEAN_OBJ_TYPE_INFO;;
			
			TCHAR szFilePath[MAX_PATH] = { '\0' };
			DWORD length = GetFinalPathNameByHandle(hCopy, szFilePath, sizeof(szFilePath), VOLUME_NAME_NT);
			dwKnownFiles++;
			if (length)
			{
				PROCESS_HANDLE_INFO *pInfo = iterPos->second;
				dosDeviceToLetter(szFilePath);
				wstringstream stream;
				stream << hSystem->ObjectTypeNumber << " ";
				if (pObjTypeInfo)
				{
					stream << pObjTypeInfo->TypeName.Buffer;
				}
				HANDLE_INFO hInfo = { hFile, hSystem->ObjectTypeNumber, new wstring(szFilePath), new wstring(stream.str()) };
				(*pInfo->FileMap)[hFile] = hInfo;
			}
			CloseHandle(hCopy);
		}
		
		CloseHandle(hProcess);

		CLEAN_OBJ_TYPE_INFO:
		if (pObjTypeInfo) HeapFree(GetProcessHeap(), 0, pObjTypeInfo);
	}
	setDebugPrivilege(FALSE);
	return dwFiles;
}

/*
* Construct map of PROCESS_HANDLE_INFO by NtQuerySystemInformation with SystemProcessInformation.
*/
int listProcesses(void)
{
	PFN_NtQuerySystemInformation NtQuerySystemInformation = (PFN_NtQuerySystemInformation)
		GetProcAddress(hNtDll, "NtQuerySystemInformation");

	TCHAR szPath[MAX_PATH] = { '\0', };

	DWORD dwSize = 4096, dwRequired = 1;
	NTSTATUS status;
	PSYSTEM_PROCESS_INFORMATION pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)
		HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
	while (true)
	{
		status = NtQuerySystemInformation(SystemProcessInformation, pSysProcInfo, dwSize, &dwRequired);
		if (NT_SUCCESS(status)) break;

		HeapFree(GetProcessHeap(), 0, pSysProcInfo);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			dwSize = dwRequired > dwSize ? dwRequired : dwSize + 4096;
			pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)
				HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
			continue;
		}
		return status;
	}

	setDebugPrivilege(TRUE);
	DWORD dwPidCount = 0;

	map<HANDLE, PROCESS_HANDLE_INFO *>::iterator itrProc;

	while (pSysProcInfo->NextEntryOffset)
	{
		HANDLE pid = pSysProcInfo->UniqueProcessId;
		if (pid)
		{
			itrProc = procMap.find(pid);
			PROCESS_HANDLE_INFO * pInfo = NULL;
			if (itrProc == procMap.end())
			{
				pInfo = (PROCESS_HANDLE_INFO *)
					HeapAlloc(GetProcessHeap(), 0, sizeof(PROCESS_HANDLE_INFO));
			}
			else
			{
				pInfo = itrProc->second;
			}
			pInfo->Pid = pid;
			ZeroMemory(pInfo->Path, sizeof(pInfo->Path));
			if (getProcessName(pid, pInfo->Path))
			{
				dosDeviceToLetter(pInfo->Path);
				procMap[pInfo->Pid] = pInfo;
				pInfo->FileMap = new map < HANDLE, HANDLE_INFO, less<HANDLE> >; // &fMap;
			}
			else
			{
				HeapFree(GetProcessHeap(), 0, pInfo);
			}
		}

		pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pSysProcInfo + pSysProcInfo->NextEntryOffset);
	}
	setDebugPrivilege(FALSE);
	return 0;
}

void printMap(void)
{
	setlocale(LC_ALL, ""); // to print korean path name
	map<HANDLE, PROCESS_HANDLE_INFO *>::iterator itrProc;
	for (itrProc = procMap.begin(); itrProc != procMap.end(); itrProc++)
	{
		PROCESS_HANDLE_INFO *info = itrProc->second;

		// skip explorer.exe process.
		TCHAR * wszImageName = getImageName(info->Path);
		if (_wcsicmp(wszImageName, L"explorer.exe") == 0) continue;

		map<HANDLE, HANDLE_INFO>::iterator itrFile;

		// if process file name start with the path, print it with asterisk.
		BOOL bProcPrinted = FALSE;
		if (_wcsnicmp(info->Path, _wszPath, wcslen(_wszPath)) == 0)
		{
			printProcess(info, true);
			bProcPrinted = TRUE;
		}
		// for each file handles of the process
		for (itrFile = (*info->FileMap).begin(); itrFile != (*info->FileMap).end(); itrFile++)
		{
			HANDLE handle = itrFile->first;
			HANDLE_INFO hInfo = itrFile->second;
			//const wchar_t *path = itrFile->second->c_str();
			const wchar_t *path = hInfo.Path->c_str();
			bool matched = _wcsnicmp(_wszPath, path, wcslen(_wszPath)) == 0;
			if (matched)
			{
				if (!bProcPrinted)
				{
					printProcess(info, false);
					bProcPrinted = TRUE;
				}
				if (!_bPrintFileHandle) continue;
				if (_bSimpleFormat)
				{
					printf_s("  HANDLE=%4ld:\t%ws\n", handle, path);
				}
				else
				{
					printf_s("  HANDLE=%4ld:\t%-30ws%ws\n", handle, hInfo.TypeName->c_str(), path);
				}
			}
		}
	}
}

void printProcess(PROCESS_HANDLE_INFO *info, bool matched)
{
	printf_s("----------------------------------------------------------------\n");
	_nMatchedProcs++;
	if (!_bNoPidKey)
	{
		printf_s("PID=%4ld: ", info->Pid);
	}
	else
	{
		printf_s("%-4ld: ", info->Pid);
	}
	if (matched) printf_s("%7s ", "*");
	if (_bSimpleFormat)
	{
		printf_s("%ws", getImageName(info->Path));
	}
	else
	{
		printf_s("%ws", info->Path);
	}
	printf_s("\n");
}

/*
* Enable Debug Privilege
*/
void setDebugPrivilege(bool enable)
{
	HANDLE hToken;
	LUID luid;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf_s("ERROR(%d) OpenProcessToken failure\n", GetLastError());
	}
	else
	{
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			printf_s("ERROR(%d) LookupPrivilegeValue failure\n", GetLastError());
			CloseHandle(hToken);
		}

		TOKEN_PRIVILEGES tokenPriv;
		tokenPriv.PrivilegeCount = 1;
		tokenPriv.Privileges[0].Luid = luid;
		tokenPriv.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		{
			printf_s("ERROR(%d) LookupPrivilegeValue failure\n", GetLastError());
		}
		CloseHandle(hToken);
	}
}



/*
* Get process image file path from PID
*/
bool getProcessName(HANDLE pid, TCHAR *path)
{
	HANDLE hProcess;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
	if (!hProcess) { return false; }

	if (GetProcessImageFileName(hProcess, path, MAX_PATH) > 0)
	{
		return true;
	}
	printf_s("Error getting process name: %ld\n", GetLastError());
	CloseHandle(hProcess);
	return false;
}


void cacheDriveNames(void)
{
	TCHAR buffer[2048];
	TCHAR *ptr;

	/* Get the logical drive strings, like C:\ - etc */
	memset(buffer, '\0', sizeof(buffer));
	GetLogicalDriveStrings(sizeof(buffer), buffer);

	/* Examine each one and add it to our list */
	for (int index = 0; index < sizeof(buffer); index++) {

		if (_nDrives >= MAX_DRIVEMAPS) break;

		wcscpy_s(drivemaps[_nDrives].drive, &buffer[index]);
		index += wcslen(drivemaps[_nDrives].drive);

		if (*drivemaps[_nDrives].drive == '\0')
		{
			break;
		}

		DWORD dwDriveType = GetDriveType(drivemaps[_nDrives].drive);
		if (dwDriveType != DRIVE_FIXED) continue;


		/* Strip off the trailing backslash -- QueryDosDevice needs it gone */
		if ((ptr = wcsrchr(drivemaps[_nDrives].drive, '\\')) != NULL) {
			*ptr = '\0';
		}

		QueryDosDevice(drivemaps[_nDrives].drive,
			drivemaps[_nDrives].devname,
			sizeof(drivemaps[_nDrives].devname));

		_nDrives++;
	}
}


/****************************************************************************
* dosDeviceToLetter():
*
* Translate from \Device\whatever to drive name.
****************************************************************************/

void dosDeviceToLetter(TCHAR *path)
{
	int index;
	int len;
	TCHAR newpath[MAX_PATH];

	for (index = 0; index < _nDrives; index++)
	{
		len = wcslen(drivemaps[index].devname);
		if (!_wcsnicmp(path, drivemaps[index].devname, len)
			&& path[len] == '\\') // HarddiskVolume1 != HarddiskVolume11
		{
			wsprintf(newpath, L"%s%s",
				drivemaps[index].drive,
				path + len);
			wcscpy_s(path, wcslen(newpath)+1, newpath);
		}
	}
}
