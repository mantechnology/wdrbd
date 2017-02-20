#include <wdm.h>
#include "drbdlock_struct.h"

#define DRBDLOCK_DEVICE_OBJECT_NAME	L"\\Device\\DrbdLock"
#define DRBDLOCK_SYMLINK_NAME		L"\\DosDevices\\DrbdLock"
#define DRBDLOCK_CALLBACK_NAME		L"\\Callback\\DrbdLock"

#define	DRBDLOCK_TYPE		0x9801

typedef struct _DRBDLOCK_VOLUME_CONTROL
{
	DRBDLOCK_VOLUME volume;
	BOOLEAN bBlock;
}DRBDLOCK_VOLUME_CONTROL, *PDRBDLOCK_VOLUME_CONTROL;