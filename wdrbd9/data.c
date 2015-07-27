#include <ntddk.h>
#include "disp.h"
#include "proto.h"

PDEVICE_OBJECT	mvolRootDeviceObject;
PDRIVER_OBJECT	mvolDriverObject;
KSPIN_LOCK		mvolVolumeLock;
KMUTEX			mvolMutex;
KMUTEX			eventlogMutex;
PETHREAD		g_NetlinkServerThread;

int				seq_file_idx		= 0;



