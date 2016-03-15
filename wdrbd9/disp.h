#ifndef MVF_DISP_H
#define MVF_DISP_H

#include <mountdev.h>
#include "mvolse.h"
#include "windows/ioctl.h"
#include "windows/drbd.h"


#define	MVOL_IOCOMPLETE_REQ(Irp, status, size)		\
{							\
	Irp->IoStatus.Status = status;			\
	Irp->IoStatus.Information = size;		\
	IoCompleteRequest( Irp, IO_NO_INCREMENT );	\
	return status;					\
}

#define	MVOL_IOTYPE_SYNC		0x01
#define	MVOL_IOTYPE_ASYNC		0x02

typedef struct _MVOL_THREAD
{
	PDEVICE_OBJECT				DeviceObject;		// mvol Volume DeviceObject
	BOOLEAN						Active;
	BOOLEAN						exit_thread;
	LIST_ENTRY					ListHead;
	KSPIN_LOCK					ListLock;
	MVOL_SECURITY_CLIENT_CONTEXT	se_client_context;
	KEVENT						RequestEvent;
	PVOID						pThread;
	ULONG						Id;                 // MULTI_WRITE_HOOKER_THREADS
	KEVENT						SplitIoDoneEvent;
} MVOL_THREAD, *PMVOL_THREAD;

#define	MVOL_MAGIC				0x853a2954

#define	MVOL_READ_OFF			0x01
#define	MVOL_WRITE_OFF			0x02

typedef struct _VOLUME_EXTENSION
{
	struct _VOLUME_EXTENSION	*Next;

	PDEVICE_OBJECT		DeviceObject;		// volume deviceobject
	PDEVICE_OBJECT		PhysicalDeviceObject;
	PDEVICE_OBJECT		TargetDeviceObject;
#ifdef _WIN32_MVFL
    HANDLE              LockHandle;
#endif
	ULONG				Flag;
	ULONG				Magic;
	BOOLEAN				Active;

	IO_REMOVE_LOCK		RemoveLock; // RemoveLock for Block Device 

	USHORT				PhysicalDeviceNameLength;
	WCHAR				PhysicalDeviceName[MAXDEVICENAME];
	KMUTEX				CountMutex;
	LARGE_INTEGER		WriteCount;
	ULONG				IrpCount;

	ULONG				VolIndex;
	CHAR				Letter;
#ifdef MULTI_WRITE_HOOKER_THREADS
	ULONG				Rr; // MULTI_WRITE_HOOKER_THREADS
	MVOL_THREAD			WorkThreadInfo[5]; 
#else
	MVOL_THREAD			WorkThreadInfo;
#endif
	struct block_device	*dev;
} VOLUME_EXTENSION, *PVOLUME_EXTENSION;

typedef struct _ROOT_EXTENSION
{
    PVOLUME_EXTENSION   Head;
    ULONG				Magic;
    USHORT				Count;	/// SEO: 볼륨 갯수
    USHORT				PhysicalDeviceNameLength;
    WCHAR				PhysicalDeviceName[MAXDEVICENAME];
    UNICODE_STRING      RegistryPath;
} ROOT_EXTENSION, *PROOT_EXTENSION;

extern PDEVICE_OBJECT		mvolRootDeviceObject;
extern PDRIVER_OBJECT		mvolDriverObject;

#define	IO_THREAD_WAIT(X)	KeWaitForSingleObject( &X->RequestEvent, Executive, KernelMode, FALSE, (PLARGE_INTEGER)NULL );
#define	IO_THREAD_SIG(X)	KeSetEvent( &X->RequestEvent, (KPRIORITY)0, FALSE ); 
#define	IO_THREAD_CLR(X)	KeClearEvent( &X->RequestEvent );

#define	FILTER_DEVICE_PROPOGATE_FLAGS			0
#define	FILTER_DEVICE_PROPOGATE_CHARACTERISTICS		(FILE_REMOVABLE_MEDIA | FILE_READ_ONLY_DEVICE | FILE_FLOPPY_DISKETTE)

extern KSPIN_LOCK			mvolVolumeLock;
extern KMUTEX				mvolMutex;
extern KMUTEX				eventlogMutex;

NTSTATUS GetDriverLetterByDeviceName(IN PUNICODE_STRING pDeviceName, OUT PUNICODE_STRING pDriveLetter);
extern char _query_mounted_devices(PMOUNTDEV_UNIQUE_ID pmuid);
extern int drbd_init(void);
#endif MVF_DISP_H
