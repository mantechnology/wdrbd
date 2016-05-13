#ifndef __PROTO_H__
#define __PROTO_H__
#include <mountdev.h>

//
// disp.c
//
NTSTATUS
mvolSendToNextDriver( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );


//
// sub.c
//
NTSTATUS
mvolStartDevice( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );
NTSTATUS
mvolRemoveDevice( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );
NTSTATUS
mvolDeviceUsage( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );
NTSTATUS
mvolReadWriteDevice( IN PVOLUME_EXTENSION VolumeExtension, IN PIRP Irp, IN ULONG Io );
NTSTATUS
mvolGetVolumeSize( PDEVICE_OBJECT TargetDeviceObject, PLARGE_INTEGER pVolumeSize );
VOID
mvolLogError( PDEVICE_OBJECT DeviceObject, ULONG UniqID,
	NTSTATUS ErrorCode, NTSTATUS Status );

NTSTATUS
IOCTL_SetIOFlag(PDEVICE_OBJECT DeviceObject, PIRP Irp, ULONG Val, BOOLEAN On);


//
// util.c
//
NTSTATUS
GetDeviceName( PDEVICE_OBJECT DeviceObject, PWCHAR Buffer, ULONG BufferLength );

PVOLUME_EXTENSION
mvolSearchDevice( PWCHAR PhysicalDeviceName );

VOID
mvolAddDeviceList( PVOLUME_EXTENSION VolumeExtension );
VOID
mvolDeleteDeviceList( PVOLUME_EXTENSION VolumeExtension );
ULONG
mvolGetDeviceCount();

VOID
MVOL_LOCK();
VOID
MVOL_UNLOCK();
VOID
COUNT_LOCK( PVOLUME_EXTENSION VolumeExtension );
VOID
COUNT_UNLOCK( PVOLUME_EXTENSION VolumeExtension );


//
// ops.c
//
NTSTATUS
IOCTL_GetAllVolumeInfo( PIRP Irp, PULONG ReturnLength );
NTSTATUS
IOCTL_GetVolumeInfo( PDEVICE_OBJECT DeviceObject, PIRP Irp, PULONG ReturnLength );
NTSTATUS
IOCTL_InitVolumeThread( PDEVICE_OBJECT DeviceObject, PIRP Irp );
NTSTATUS
IOCTL_CloseVolumeThread( PDEVICE_OBJECT DeviceObject, PIRP Irp );
NTSTATUS
IOCTL_VolumeStart( PDEVICE_OBJECT DeviceObject, PIRP Irp );
NTSTATUS
IOCTL_VolumeStop( PDEVICE_OBJECT DeviceObject, PIRP Irp );
NTSTATUS
IOCTL_GetVolumeSize( PDEVICE_OBJECT DeviceObject, PIRP Irp );
NTSTATUS
IOCTL_VolumeReadOff( PDEVICE_OBJECT DeviceObject, PIRP Irp, BOOLEAN ReadEnable );
NTSTATUS
IOCTL_VolumeWriteOff( PDEVICE_OBJECT DeviceObject, PIRP Irp, BOOLEAN WriteEnable );
NTSTATUS
IOCTL_GetCountInfo( PDEVICE_OBJECT DeviceObject, PIRP Irp, PULONG ReturnLength );
NTSTATUS
IOCTL_MountVolume(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS
IOCTL_SetSimulDiskIoError( PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS
IOCTL_SetMinimumLogLevel(PDEVICE_OBJECT DeviceObject, PIRP Irp);

//
// thread.c
//
NTSTATUS
mvolInitializeThread( PVOLUME_EXTENSION DeviceExtension,
	PMVOL_THREAD pThreadInfo, PKSTART_ROUTINE ThreadRoutine );
VOID
mvolTerminateThread( PMVOL_THREAD pThreadInfo );
VOID
mvolWorkThread( PVOID arg );

#endif __PROTO_H__
