#include <windows.h>
#include <stdio.h>
#include "mvol.h"


void
usage()
{
	printf("usage: drbdcon cmds options \n\n"
		"cmds:\n"
		"   /proc/drbd \n"
		"   /init_thread \n"
		"   /close_thread \n"
		"   /start_volume \n"
		"   /stop_volume\n"
		"   /get_volume_size \n"
        "   /nagle_disable \n"
        "   /nagle_enable \n"
        "   /m [letter] : mount\n"
        "   /d[f] : dismount[force] \n"
		"\n\n"

		"options:\n"
		"   /letter or /l : drive letter \n"
		"\n\n"

		"examples:\n"
		"drbdcon /proc/drbd\n"
		"drbdcon /status\n"
		"drbdcon /s\n"
		"drbdcon /letter F /start_volume \n"
		"drbdcon /letter F /init_thread \n"
        "drbdcon /nagle_disable r0 \n"
        "drbdcon /d F \n"
        "drbdcon /m F \n"
	);

	exit(ERROR_INVALID_PARAMETER);
}

DWORD
main(int argc, char* argv [])
{
	DWORD	res = ERROR_SUCCESS;
	int  	argIndex = 0;
	UCHAR	Letter = 'C';
	char	InitThreadFlag = 0, CloseThreadFlag = 0;
	char	StartFlag = 0, StopFlag = 0;
	char	GetVolumeSizeFlag = 0;
	char	ProcDrbdFlag = 0;
	char	ProcDrbdFlagWithLetter = 0;
    char    NagleEnableFlag = 0;
    char    NagleDisableFlag = 0;
    char    MountFlag = 0, DismountFlag = 0;
	char	SimulDiskIoErrorFlag = 0;
    char    *ResourceName = NULL;

    int     Force = 0;

	LARGE_INTEGER Offset = {0,};
	ULONG	BlockSize = 0;
	ULONG	Count = 0;
	SIMULATION_DISK_IO_ERROR sdie = { 0, };

	if (argc < 2)
		usage();

	for (argIndex = 1; argIndex < argc; argIndex++)
	{
		if (strcmp(argv[argIndex], "/start_volume") == 0)
		{
			StartFlag++;
		}
		else if (strcmp(argv[argIndex], "/stop_volume") == 0)
		{
			StopFlag++;
		}
		else if (strcmp(argv[argIndex], "/init_thread") == 0)
		{
			InitThreadFlag++;
		}
		else if (strcmp(argv[argIndex], "/close_thread") == 0)
		{
			CloseThreadFlag++;
		}
		else if (strcmp(argv[argIndex], "/get_volume_size") == 0)
		{
			GetVolumeSizeFlag++;
		}
        else if (strcmp(argv[argIndex], "/nagle_enable") == 0)
        {
            NagleEnableFlag++;
            argIndex++;

            if (argIndex < argc)
                ResourceName = argv[argIndex];
            else
                usage();
        }
        else if (strcmp(argv[argIndex], "/nagle_disable") == 0)
        {
            NagleDisableFlag++;
            argIndex++;

            if (argIndex < argc)
                ResourceName = argv[argIndex];
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
		else
		{
			printf("Please check undefined arg[%d]=(%s)\n", argIndex, argv[argIndex]);
		}
	}

	 if (InitThreadFlag)
	{
		res = MVOL_InitThread( Letter );
		if( res != ERROR_SUCCESS )
		{
			fprintf( stderr, "Failed MVOL_InitThread. Err=%u\n", res );
		}

		return res;
	}

	if (CloseThreadFlag)
	{
		res = MVOL_CloseThread( Letter );
		if( res != ERROR_SUCCESS )
		{
			fprintf( stderr, "Failed MVOL_CloseThread. Err=%u\n", res );
		}

		return res;
	}

	if (StartFlag)
	{
		res = MVOL_StartVolume( Letter );
		if( res != ERROR_SUCCESS )
		{
			fprintf( stderr, "Failed MVOL_StartVolume. Err=%u\n", res );
		}

		return res;
	}

	if (StopFlag)
	{
		res = MVOL_StopVolume( Letter );
		if( res != ERROR_SUCCESS )
		{
			fprintf( stderr, "Failed MVOL_StopVolume. Err=%u\n", res );
		}

		return res;
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

    if (NagleEnableFlag)
    {
        res = MVOL_SetNagle(ResourceName, "enable");
        if (res != ERROR_SUCCESS)
        {
            fprintf(stderr, "Cannot enable nagle. Err=%u\n", res);
        }

        return res;
    }

    if (NagleDisableFlag)
    {
        res = MVOL_SetNagle(ResourceName, "disable");
        if (res != ERROR_SUCCESS)
        {
            fprintf(stderr, "Cannot disable nagle. Err=%u\n", res);
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

    if (MountFlag)
    {
        res = MVOL_MountVolume(Letter);
    }

	if (SimulDiskIoErrorFlag) {
		res = MVOL_SimulDiskIoError(&sdie); 
	}

	return res;
}

