#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include "mvol.h"
#include "LogManager.h"


void
usage()
{
	printf("usage: drbdcon cmds options \n\n"
		"cmds:\n"
/*		"   /proc/drbd \n"*/
/*		"   /get_volume_size \n"*/
		"   /nodelayedack [ip|guid]\n"
        "   /delayedack_enable [ip|guid]\n"
        "   /m [letter] : mount\n"
        /*"   /d[f] : dismount[force] \n"*/
		"   /get_log [ProviderName] \n"
		"   /minlog_lv dbg [Level : 0~7] \n"
		"   /write_log [ProviderName] \"[LogData]\" \n"
		"   /handler_use [0,1]\n"
		"	/drbdlock_status\n"
		"   /info\n"
		"   /status : drbd version\n"

		"\n\n"

		"options:\n"
		"   /letter or /l : drive letter \n"
		"\n\n"

		"examples:\n"
/*		"drbdcon /proc/drbd\n"*/
/*		"drbdcon /status\n"*/
/*		"drbdcon /s\n"*/
        "drbdcon /nodelayedack 10.10.0.1 \n"
        /*"drbdcon /d F \n"*/
        "drbdcon /m F \n"
		"drbdcon /get_log drbdService \n"
		"drbdcon /minlog_lv dbg 6 \n"
		"drbdcon /write_log drbdService \"Logging start\" \n"
		"drbdcon /handler_use 1 \n"
	);

	exit(ERROR_INVALID_PARAMETER);
}

const TCHAR gDrbdRegistryPath[] = _T("System\\CurrentControlSet\\Services\\drbd\\volumes");

static
DWORD DeleteVolumeReg(TCHAR letter)
{
	HKEY hKey = NULL;
	DWORD dwIndex = 0;
	const int MAX_VALUE_NAME = 16;
	const int MAX_VOLUME_GUID = 256;

	TCHAR szSrcLetter[2] = { letter, 0 };
	TCHAR szRegLetter[MAX_VALUE_NAME] = { 0, };
	DWORD cbRegLetter = MAX_VALUE_NAME;
	UCHAR volGuid[MAX_VOLUME_GUID] = { 0, };
	DWORD cbVolGuid = MAX_VOLUME_GUID;

	LONG lResult = ERROR_SUCCESS;

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, gDrbdRegistryPath, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		if (lResult == ERROR_FILE_NOT_FOUND) {
			fprintf(stderr, "Key not found\n");
		}
		else {
			fprintf(stderr, "Error opening key\n");
		}
		return lResult;
	}

	while (ERROR_SUCCESS == RegEnumValue(hKey, dwIndex++, szRegLetter, &cbRegLetter,
		NULL, NULL, (LPBYTE)volGuid, &cbVolGuid)) {

		if (!_tcsicmp(szRegLetter, szSrcLetter)) {
			lResult = RegDeleteValue(hKey, szRegLetter);
			if (ERROR_SUCCESS != lResult) {
				fprintf(stderr, "Error deleting value. code(0x%x)\n", lResult);
			}
			RegCloseKey(hKey);
			return lResult;
		}

		memset(szRegLetter, 0, MAX_VALUE_NAME * sizeof(TCHAR));
		memset(volGuid, 0, MAX_VOLUME_GUID * sizeof(UCHAR));
		cbRegLetter = MAX_VALUE_NAME;
		cbVolGuid = MAX_VOLUME_GUID;
	}

	RegCloseKey(hKey);

	return lResult;
}

DWORD
main(int argc, char* argv [])
{
	DWORD	res = ERROR_SUCCESS;
	int  	argIndex = 0;
	UCHAR	Letter = 'C';
	char	GetVolumeSizeFlag = 0;
	char	ProcDrbdFlag = 0;
	char	ProcDrbdFlagWithLetter = 0;
    char    DelayedAckEnableFlag = 0;
    char    DelayedAckDisableFlag = 0;
	char	HandlerUseFlag = 0;
    char    MountFlag = 0, DismountFlag = 0;
	char	SimulDiskIoErrorFlag = 0;
    char    *addr = NULL;
	char	GetLog = 0;
	char	OosTrace = 0;
#ifdef _WIN32_DEBUG_OOS
	char	ConvertOosLog = 0;
	char	*pSrcFilePath = NULL;	
	char	SearchOosLog = 0;
	char	*sector = NULL;
#endif
	char	WriteLog = 0;
	char	SetMinLogLv = 0;
	char	*ProviderName = NULL;
	char	*LoggingData = NULL;
	char	VolumesInfoFlag = 0;
	char	Drbdlock_status = 0;
	char	Verbose = 0;

    int     Force = 0;

	LARGE_INTEGER Offset = {0,};
	ULONG	BlockSize = 0;
	ULONG	Count = 0;
	SIMULATION_DISK_IO_ERROR sdie = { 0, };
	LOGGING_MIN_LV lml = { 0, };
	HANDLER_INFO hInfo = { 0, };

	if (argc < 2)
		usage();

	for (argIndex = 1; argIndex < argc; argIndex++)
	{
		if (strcmp(argv[argIndex], "/get_volume_size") == 0)
		{
			GetVolumeSizeFlag++;
		}
        else if (strcmp(argv[argIndex], "/delayedack_enable") == 0)
        {
            DelayedAckEnableFlag++;
            argIndex++;

			if (argIndex < argc)
				addr = argv[argIndex];
            else
                usage();
        }
        else if (strcmp(argv[argIndex], "/nodelayedack") == 0)
        {
            DelayedAckDisableFlag++;
            argIndex++;

            if (argIndex < argc)
                addr = argv[argIndex];
            else
                usage();
        }
		else if (strcmp(argv[argIndex], "/get_log") == 0)
		{
			argIndex++;
			GetLog++;

			if (argIndex < argc)
				ProviderName = argv[argIndex];
			else
				usage();
#ifdef _WIN32_DEBUG_OOS
			argIndex++;
			if (argIndex < argc)
			{
				if (strcmp(argv[argIndex], "oos") == 0)
					OosTrace++;
			}
#endif
		}
#ifdef _WIN32_DEBUG_OOS
		else if (strcmp(argv[argIndex], "/convert_oos_log") == 0)
		{
			argIndex++;
			ConvertOosLog++;

			// Get oos log path
			if (argIndex < argc)
				pSrcFilePath = argv[argIndex];
			else
				usage();
		}
		else if (strcmp(argv[argIndex], "/search_oos_log") == 0)
		{
			argIndex++;
			SearchOosLog++;

			// Get oos log path
			if (argIndex < argc)
				pSrcFilePath = argv[argIndex];
			else
				usage();

			// Get oos search sector
			argIndex++;
			if (argIndex < argc)
				sector = argv[argIndex];
			else
				usage();
		}
#endif
		else if (strcmp(argv[argIndex], "/write_log") == 0)
		{
			argIndex++;
			WriteLog++;
			
			// Get eventlog provider name.
			if (argIndex < argc)
				ProviderName = argv[argIndex];
			else
				usage();

			// Get eventlog data to be written.
			argIndex++;
			if (argIndex < argc)
				LoggingData = argv[argIndex];
			else
				usage();
		}
		else if (strcmp(argv[argIndex], "/handler_use") == 0)
		{
			HandlerUseFlag++;
			argIndex++;

			if (argIndex < argc)
				hInfo.use = atoi(argv[argIndex]);
			else
				usage();
		}
		else if (!_stricmp(argv[argIndex], "/letter") || !_stricmp(argv[argIndex], "/l"))
		{
			argIndex++;

			if (argIndex < argc)
				Letter = (UCHAR) *argv[argIndex];
			else
				usage();
		}
		else if (!strcmp(argv[argIndex], "/proc/drbd"))
		{
			ProcDrbdFlag++;
		}
		else if (!strcmp(argv[argIndex], "/status") || !strcmp(argv[argIndex], "/s"))
		{
			ProcDrbdFlagWithLetter++;
		}
		else if (!_stricmp(argv[argIndex], "/d"))
        {
            DismountFlag++;
            argIndex++;

            if (argIndex < argc)
                Letter = (UCHAR)*argv[argIndex];
            else
                usage();
        }
		/*
		else if (!_stricmp(argv[argIndex], "/fd") || !_stricmp(argv[argIndex], "/df"))
        {
            Force = 1;
            DismountFlag++;
            argIndex++;

            if (argIndex < argc)
                Letter = (UCHAR)*argv[argIndex];
            else
                usage();
        }
		*/
        else if (!_stricmp(argv[argIndex], "/m"))
        {
            MountFlag++;
            argIndex++;

            if (argIndex < argc)
                Letter = (UCHAR)*argv[argIndex];
            else
                usage();
        }
		else if (!_stricmp(argv[argIndex], "/disk_error")) // Simulate Disk I/O Error
		{
			SimulDiskIoErrorFlag++;
			argIndex++;
			// get parameter 1 (DiskI/O error flag)
			if (argIndex < argc) {
				sdie.bDiskErrorOn = atoi(argv[argIndex]);
			} else {
				usage();
			}
			
			argIndex++;
			// get parameter 2 (DiskI/O error Type)
			if (argIndex < argc) {
				sdie.ErrorType = atoi(argv[argIndex]);
			} else {
				// if parameter 2 does not exist, parameter 2 is default value(0)
			}
		}
		else if (strcmp(argv[argIndex], "/minlog_lv") == 0)
		{
			argIndex++;
			SetMinLogLv++;

			// first argument indicates logging type.
			if (argIndex < argc)
			{
				if (strcmp(argv[argIndex], "sys") == 0)
				{
					lml.nType = LOGGING_TYPE_SYSLOG;
				}
				else if (strcmp(argv[argIndex], "dbg") == 0)
				{
					lml.nType = LOGGING_TYPE_DBGLOG;
				}
#ifdef _WIN32_DEBUG_OOS
				else if (strcmp(argv[argIndex], "oos") == 0)
				{
					lml.nType = LOGGING_TYPE_OOSLOG;
				}
#endif
				else
					usage();				
			}

			// second argument indicates minimum logging level.
			argIndex++;
			if (argIndex < argc)
			{
				lml.nErrLvMin = atoi(argv[argIndex]);
			}
			else
				usage();
		}
		else if (!strcmp(argv[argIndex], "/drbdlock_status"))
		{
			Drbdlock_status++;
		}
		else if (!strcmp(argv[argIndex], "/info"))
		{
			VolumesInfoFlag++;
		}
		else if (!strcmp(argv[argIndex], "--verbose"))
		{
			Verbose++;
		}
		else
		{
			printf("Please check undefined arg[%d]=(%s)\n", argIndex, argv[argIndex]);
		}
	}

	if (GetVolumeSizeFlag)
	{
		MVOL_VOLUME_INFO	srcVolumeInfo;
		LARGE_INTEGER		volumeSize;

		printf("GET VOLUME SIZE\n");

		memset(&srcVolumeInfo, 0, sizeof(MVOL_VOLUME_INFO));

		res = MVOL_GetVolumeInfo(Letter, &srcVolumeInfo);
		if (res)
		{
			printf("cannot get src volume info, Drive=%c:, err=%d\n",
				Letter, GetLastError());
			return res;
		}

		volumeSize.QuadPart = 0;
		res = MVOL_GetVolumeSize(srcVolumeInfo.PhysicalDeviceName, &volumeSize);
		if (res)
		{
			printf("cannot MVOL_GetVolumeSize, err=%d\n", res);
			return res;
		}
		else
			printf("VolumeSize = %I64d\n", volumeSize.QuadPart);

		return res;
	}

	if (ProcDrbdFlag)
	{
		MVOL_VOLUME_INFO VolumeInfo = {0,};

		res = MVOL_GetStatus( &VolumeInfo );
		if( res != ERROR_SUCCESS )
		{
			fprintf( stderr, "Failed MVOL_GetStatus. Err=%u\n", res );
		}
		else
		{
			fprintf( stdout, "%s\n", VolumeInfo.Seq );
		}

		return res;
	}

	if (ProcDrbdFlagWithLetter)
	{
		MVOL_VOLUME_INFO VolumeInfo = { 0, };
		CHAR tmpSeq[sizeof(VolumeInfo.Seq)] = { NULL };
		CHAR *line, *cline;
		CHAR *context = NULL;
		CHAR buffer[2] = { NULL };

		res = MVOL_GetStatus(&VolumeInfo);
		if (res != ERROR_SUCCESS)
		{
			fprintf(stderr, "Failed MVOL_GetStatus. Err=%u\n", res);
		}
		else
		{
			int lineCount = 1;
			line = strtok_s(VolumeInfo.Seq, "\n", &context);
			while (line)
			{
				if (strstr(line, ": cs:"))
				{
					cline = (char *)malloc(strlen(line) + 1);
					strcpy_s(cline, strlen(line) + 1, line);
					buffer[0] = atoi(strtok_s(NULL, ":", &cline)) + 67;
					buffer[1] = '\0';
					strcat_s(tmpSeq, buffer);
				}

				strcat_s(tmpSeq, line);
				strcat_s(tmpSeq, "\n");
				line = strtok_s(NULL, "\n", &context);
				if (lineCount == 2) strcat_s(tmpSeq, "\n");
				lineCount++;
			}
			fprintf(stdout, "%s\n", tmpSeq);
		}

		return res;
	}

    if (DelayedAckEnableFlag)
    {	
		res = MVOL_SetDelayedAck(addr, "enable");
        if (res != ERROR_SUCCESS)
        {
            fprintf(stderr, "Cannot enable DelayedAck. Err=%u\n", res);
        }

        return res;
    }

    if (DelayedAckDisableFlag)
    {
        res = MVOL_SetDelayedAck(addr, "disable");
        if (res != ERROR_SUCCESS)
        {
            fprintf(stderr, "Cannot disable DelayedAck. Err=%u\n", res);
        }

        return res;
    }

    if (DismountFlag)
    {
        res = MVOL_DismountVolume(Letter, Force);

        if (res != ERROR_SUCCESS)
        {
            fprintf(stderr, "Failed MVOL_DismountVolume. Err=%u\n", res);
        }
    }

	if (MountFlag) {
		res = MVOL_MountVolume(Letter);
		if (ERROR_SUCCESS == res) {
			if (ERROR_SUCCESS == DeleteVolumeReg(Letter)) {
				fprintf(stderr, "%c: is Mounted, not any more drbd volume.\nRequire to delete a resource file.\n", Letter);
			}
		}
	}

	if (SimulDiskIoErrorFlag) {
		res = MVOL_SimulDiskIoError(&sdie);
	}

	if (SetMinLogLv) {
		res = MVOL_SetMinimumLogLevel(&lml);
	}

	if (GetLog)
	{
		//res = CreateLogFromEventLog( (LPCSTR)ProviderName );
		res = MVOL_GetDrbdLog(ProviderName, OosTrace);
	}
#ifdef _WIN32_DEBUG_OOS
	if (ConvertOosLog)
	{
		res = MVOL_ConvertOosLog((LPCTSTR)pSrcFilePath);
	}

	if (SearchOosLog)
	{
		res = MVOL_SearchOosLog((LPCTSTR)pSrcFilePath, (LPCTSTR)sector);
	}
#endif

	if (WriteLog)
	{
		res = WriteEventLog((LPCSTR)ProviderName, (LPCSTR)LoggingData);
	}

	if (VolumesInfoFlag)
	{
		res = MVOL_GetVolumesInfo(Verbose);
		if( res != ERROR_SUCCESS )
		{
			fprintf( stderr, "Failed MVOL_InitThread. Err=%u\n", res );
		}

		return res;
	}

	if (Drbdlock_status)
	{
		res = GetDrbdlockStatus();
	}

	if (HandlerUseFlag)
	{
		res = MVOL_SetHandlerUse(&hInfo);
	}

	return res;
}

