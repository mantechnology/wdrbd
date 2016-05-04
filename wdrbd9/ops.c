#include <wdm.h>
#include "drbd_windows.h"
#include "disp.h"
#include "proto.h"


NTSTATUS
IOCTL_GetAllVolumeInfo( PIRP Irp, PULONG ReturnLength )
{
	PIO_STACK_LOCATION			irpSp=IoGetCurrentIrpStackLocation(Irp);
	PROOT_EXTENSION				RootExtension = mvolRootDeviceObject->DeviceExtension;
	PVOLUME_EXTENSION			VolumeExtension = NULL;
	PMVOL_VOLUME_INFO			pOutBuffer = NULL;
	ULONG					outlen, count = 0;

	count = RootExtension->Count;
	if( count == 0 )
		return STATUS_SUCCESS;

	outlen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if( outlen < (count * sizeof(MVOL_VOLUME_INFO)) )
	{
		mvolLogError( mvolRootDeviceObject, 201,
						MSG_BUFFER_SMALL, STATUS_BUFFER_TOO_SMALL );
		WDRBD_ERROR("buffer too small\n");
		*ReturnLength = count * sizeof(MVOL_VOLUME_INFO);
		return STATUS_BUFFER_TOO_SMALL;
	}

	pOutBuffer = (PMVOL_VOLUME_INFO) Irp->AssociatedIrp.SystemBuffer;

	MVOL_LOCK();
	VolumeExtension = RootExtension->Head;
	while (VolumeExtension != NULL)
	{
		RtlCopyMemory(pOutBuffer->PhysicalDeviceName, VolumeExtension->PhysicalDeviceName,
			MAXDEVICENAME * sizeof(WCHAR));
		pOutBuffer->Active = VolumeExtension->Active;
		pOutBuffer++;
		VolumeExtension = VolumeExtension->Next;
	}

	MVOL_UNLOCK();
	*ReturnLength = count * sizeof(MVOL_VOLUME_INFO);
	return STATUS_SUCCESS;
}

NTSTATUS
IOCTL_GetVolumeInfo( PDEVICE_OBJECT DeviceObject, PIRP Irp, PULONG ReturnLength )
{
	PIO_STACK_LOCATION	irpSp = IoGetCurrentIrpStackLocation(Irp);
	PVOLUME_EXTENSION	VolumeExtension = NULL;
	PMVOL_VOLUME_INFO	pOutBuffer = NULL;
	ULONG			outlen;

	if( DeviceObject == mvolRootDeviceObject )
	{
		mvolLogError( DeviceObject, 211,
			MSG_ROOT_DEVICE_REQUEST, STATUS_INVALID_DEVICE_REQUEST );
		WDRBD_ERROR("RootDevice\n");
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	VolumeExtension = DeviceObject->DeviceExtension;
	outlen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if( outlen < sizeof(MVOL_VOLUME_INFO) )
	{
		mvolLogError( DeviceObject, 212, MSG_BUFFER_SMALL, STATUS_BUFFER_TOO_SMALL );
		WDRBD_ERROR("buffer too small out %d sizeof(MVOL_VOLUME_INFO) %d\n", outlen, sizeof(MVOL_VOLUME_INFO));
		*ReturnLength = sizeof(MVOL_VOLUME_INFO);
		return STATUS_BUFFER_TOO_SMALL;
	}

	pOutBuffer = (PMVOL_VOLUME_INFO) Irp->AssociatedIrp.SystemBuffer;
	RtlCopyMemory( pOutBuffer->PhysicalDeviceName, VolumeExtension->PhysicalDeviceName,
		MAXDEVICENAME * sizeof(WCHAR) );
	pOutBuffer->Active = VolumeExtension->Active;
	*ReturnLength = sizeof(MVOL_VOLUME_INFO);
	return STATUS_SUCCESS;
}

NTSTATUS
IOCTL_InitVolumeThread(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS		status;
	ULONG			inlen;
	PIO_STACK_LOCATION	irpSp = IoGetCurrentIrpStackLocation(Irp);
	PVOLUME_EXTENSION	VolumeExtension = NULL;
	PMVOL_VOLUME_INFO	pVolumeInfo = NULL;

	if (DeviceObject == mvolRootDeviceObject)
	{
		inlen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
		if (inlen < sizeof(MVOL_VOLUME_INFO))
		{
			mvolLogError(DeviceObject, 221, MSG_BUFFER_SMALL, STATUS_BUFFER_TOO_SMALL);
			WDRBD_ERROR("buffer too small\n");
			return STATUS_BUFFER_TOO_SMALL;
		}

		pVolumeInfo = (PMVOL_VOLUME_INFO) Irp->AssociatedIrp.SystemBuffer;
		WDRBD_TRACE("Root Device IOCTL\n");

		MVOL_LOCK();
		VolumeExtension = mvolSearchDevice(pVolumeInfo->PhysicalDeviceName);
		MVOL_UNLOCK();

		if (VolumeExtension == NULL)
		{
			mvolLogError(DeviceObject, 222, MSG_NO_DEVICE, STATUS_NO_SUCH_DEVICE);
			WDRBD_ERROR("cannot find volume, PD=%ws\n",	pVolumeInfo->PhysicalDeviceName);
			return STATUS_NO_SUCH_DEVICE;
		}
	}
	else
	{
		VolumeExtension = DeviceObject->DeviceExtension;
	}

	if (VolumeExtension->Active == TRUE)
	{
		mvolLogError(VolumeExtension->DeviceObject, 223,
			MSG_INVALID_DEVICE_REQUEST, STATUS_INVALID_DEVICE_REQUEST);
		WDRBD_ERROR("already Volume Started\n");
		return STATUS_INVALID_DEVICE_REQUEST;
	}

#ifdef MULTI_WRITE_HOOKER_THREADS
	{
		int i = 0;
		deviceExtension->Rr = 0; 

		for (i = 0; i < 5; i++) 
		{
			deviceExtension->WorkThreadInfo[i].Id = i; //ID

			if (deviceExtension->WorkThreadInfo[i].Active == TRUE)
			{
				mvolLogError(deviceExtension->DeviceObject, 225,
					MSG_INVALID_DEVICE_REQUEST, STATUS_INVALID_DEVICE_REQUEST);

				WDRBD_ERROR("Thread already started..\n");
				return STATUS_INVALID_DEVICE_REQUEST;
			}

			status = mvolInitializeThread( deviceExtension,
				&deviceExtension->WorkThreadInfo[i], mvolWorkThread );
			if (!NT_SUCCESS(status))
			{
				mvolLogError(deviceExtension->DeviceObject, 226, MSG_THREAD_INIT_ERROR, status);

				WDRBD_ERROR("cannot initialize WorkThread, err=0x%x\n", status);
				return status;
			}
		}
	}
#else
	if (VolumeExtension->WorkThreadInfo.Active == TRUE)
	{
		mvolLogError(VolumeExtension->DeviceObject, 225,
			MSG_INVALID_DEVICE_REQUEST, STATUS_INVALID_DEVICE_REQUEST);
		WDRBD_ERROR("Thread already started..\n");
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	drbdCreateDev();

	status = mvolInitializeThread( VolumeExtension, &VolumeExtension->WorkThreadInfo, mvolWorkThread );
	if( !NT_SUCCESS(status) )
	{
		mvolLogError( VolumeExtension->DeviceObject, 226, MSG_THREAD_INIT_ERROR, status );
		WDRBD_ERROR("cannot initialize WorkThread, err=0x%x\n", status);
		return status;
	}
#endif
	return STATUS_SUCCESS;
}

NTSTATUS
IOCTL_CloseVolumeThread( PDEVICE_OBJECT DeviceObject, PIRP Irp )
{
	ULONG			inlen;
	ULONG			irpCount;
	PIO_STACK_LOCATION	irpSp=IoGetCurrentIrpStackLocation(Irp);
	PVOLUME_EXTENSION	VolumeExtension = NULL;
	PMVOL_VOLUME_INFO	pVolumeInfo = NULL;
	
	if( DeviceObject == mvolRootDeviceObject )
	{
		inlen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
		if( inlen < sizeof(MVOL_VOLUME_INFO) )
		{
			mvolLogError( DeviceObject, 231, MSG_BUFFER_SMALL, STATUS_BUFFER_TOO_SMALL );
			WDRBD_ERROR("buffer too small\n");
			return STATUS_BUFFER_TOO_SMALL;
		}

		pVolumeInfo = (PMVOL_VOLUME_INFO) Irp->AssociatedIrp.SystemBuffer;
		WDRBD_TRACE("Root Device IOCTL\n");

		MVOL_LOCK();
		VolumeExtension = mvolSearchDevice( pVolumeInfo->PhysicalDeviceName );
		MVOL_UNLOCK();

		if( VolumeExtension == NULL )
		{
			mvolLogError( DeviceObject, 232, MSG_NO_DEVICE, STATUS_NO_SUCH_DEVICE );
			WDRBD_ERROR("cannot find volume, PD=%ws\n",	pVolumeInfo->PhysicalDeviceName);
			return STATUS_NO_SUCH_DEVICE;
		}
	}
	else
	{
		VolumeExtension = DeviceObject->DeviceExtension;
	}

	if( VolumeExtension->Active == TRUE )
	{
		mvolLogError( VolumeExtension->DeviceObject, 233,
			MSG_INVALID_DEVICE_REQUEST, STATUS_INVALID_DEVICE_REQUEST );
		WDRBD_ERROR("already Volume Started\n");
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	COUNT_LOCK( VolumeExtension );
	irpCount = VolumeExtension->IrpCount;
	COUNT_UNLOCK( VolumeExtension );
	if( irpCount )
	{
		mvolLogError( VolumeExtension->DeviceObject, 235,
			MSG_DEVICE_BUSY, STATUS_DEVICE_BUSY );
		WDRBD_ERROR("Volume Busy, irpCount=%d\n", irpCount);
		return STATUS_DEVICE_BUSY;
	}
	
	drbdFreeDev(VolumeExtension);

#ifdef MULTI_WRITE_HOOKER_THREADS
	{
		int i = 0;
		for (i = 0; i < 5; i++) 
		{

			if (deviceExtension->WorkThreadInfo[i].Active)
				mvolTerminateThread(&deviceExtension->WorkThreadInfo);
		}
	}

#else
	if (VolumeExtension->WorkThreadInfo.Active)
		mvolTerminateThread(&VolumeExtension->WorkThreadInfo);
#endif

	return STATUS_SUCCESS;
}

NTSTATUS
IOCTL_VolumeStart( PDEVICE_OBJECT DeviceObject, PIRP Irp )
{
	ULONG			inlen;
	PIO_STACK_LOCATION	irpSp=IoGetCurrentIrpStackLocation(Irp);
	PVOLUME_EXTENSION	VolumeExtension = NULL;
	PMVOL_VOLUME_INFO	pVolumeInfo = NULL;
	
	if( DeviceObject == mvolRootDeviceObject )
	{
		inlen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
		if( inlen < sizeof(MVOL_VOLUME_INFO) )
		{
			mvolLogError( DeviceObject, 261, MSG_BUFFER_SMALL, STATUS_BUFFER_TOO_SMALL );
			WDRBD_ERROR("buffer too small\n");
			return STATUS_BUFFER_TOO_SMALL;
		}

		pVolumeInfo = (PMVOL_VOLUME_INFO) Irp->AssociatedIrp.SystemBuffer;
		WDRBD_TRACE("Root Device IOCTL\n");

		MVOL_LOCK();
		VolumeExtension = mvolSearchDevice( pVolumeInfo->PhysicalDeviceName );
		MVOL_UNLOCK();

		if( VolumeExtension == NULL )
		{
			mvolLogError( DeviceObject, 263, MSG_NO_DEVICE, STATUS_NO_SUCH_DEVICE );
			WDRBD_ERROR("cannot find volume, PD=%ws\n", pVolumeInfo->PhysicalDeviceName);
			return STATUS_NO_SUCH_DEVICE;
		}
	}
	else
	{
		VolumeExtension = DeviceObject->DeviceExtension;
	}
	
	if( VolumeExtension->Active == TRUE )
	{
		mvolLogError( VolumeExtension->DeviceObject, 264,
			MSG_INVALID_DEVICE_REQUEST, STATUS_INVALID_DEVICE_REQUEST );
		WDRBD_ERROR("already Volume Started\n");
		return STATUS_INVALID_DEVICE_REQUEST;
	}

#ifdef MULTI_WRITE_HOOKER_THREADS
	{
		int i = 0;
		for (i = 0; i < 5; i++) // TEST!!!
		{
			if (deviceExtension->WorkThreadInfo[i].Active == FALSE)
			{
				mvolLogError(deviceExtension->DeviceObject, 267,
					MSG_INVALID_DEVICE_REQUEST, STATUS_INVALID_DEVICE_REQUEST);
				return STATUS_INVALID_DEVICE_REQUEST;
			}
		}
	}
#else
	if( VolumeExtension->WorkThreadInfo.Active == FALSE )
	{
		mvolLogError( VolumeExtension->DeviceObject, 267,
			MSG_INVALID_DEVICE_REQUEST, STATUS_INVALID_DEVICE_REQUEST );
		WDRBD_ERROR("not initialized Volume Thread\n");
		return STATUS_INVALID_DEVICE_REQUEST;
	}
#endif
	VolumeExtension->Active = TRUE;
	return STATUS_SUCCESS;
}

NTSTATUS
IOCTL_VolumeStop( PDEVICE_OBJECT DeviceObject, PIRP Irp )
{
	ULONG			inlen;
	PIO_STACK_LOCATION	irpSp=IoGetCurrentIrpStackLocation(Irp);
	PVOLUME_EXTENSION	VolumeExtension = NULL;
	PMVOL_VOLUME_INFO	pVolumeInfo = NULL;

	if( DeviceObject == mvolRootDeviceObject )
	{
		inlen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
		if( inlen < sizeof(MVOL_VOLUME_INFO) )
		{
			mvolLogError( DeviceObject, 271, MSG_BUFFER_SMALL, STATUS_BUFFER_TOO_SMALL );
			WDRBD_ERROR("buffer too small\n");
			return STATUS_BUFFER_TOO_SMALL;
		}

		pVolumeInfo = (PMVOL_VOLUME_INFO) Irp->AssociatedIrp.SystemBuffer;
		WDRBD_TRACE("Root Device IOCTL\n");

		MVOL_LOCK();
		VolumeExtension = mvolSearchDevice( pVolumeInfo->PhysicalDeviceName );
		MVOL_UNLOCK();

		if( VolumeExtension == NULL )
		{
			mvolLogError( DeviceObject, 272, MSG_NO_DEVICE, STATUS_NO_SUCH_DEVICE );
			WDRBD_ERROR("cannot find volume, PD=%ws\n", pVolumeInfo->PhysicalDeviceName);
			return STATUS_NO_SUCH_DEVICE;
		}
	}
	else
	{
		VolumeExtension = DeviceObject->DeviceExtension;
	}

	if( VolumeExtension->Active == FALSE )
	{
		mvolLogError( VolumeExtension->DeviceObject, 273,
			MSG_INVALID_DEVICE_REQUEST, STATUS_INVALID_DEVICE_REQUEST );
		WDRBD_ERROR("Not Volume Started\n");
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	VolumeExtension->Active = FALSE;
	return STATUS_SUCCESS;
}

NTSTATUS
IOCTL_MountVolume(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    ULONG inlen;
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    if (DeviceObject == mvolRootDeviceObject)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    PVOLUME_EXTENSION pvext = DeviceObject->DeviceExtension;

    COUNT_LOCK(pvext);

    if (!pvext->Active)
    {
        WDRBD_ERROR("%c: volume is not dismounted\n", pvext->Letter);
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto out;
    }

    int irp_count = atomic_read((atomic_t *)&pvext->IrpCount);
    if (irp_count > 0)
    {
        status = STATUS_DEVICE_BUSY;
        mvolLogError(pvext->DeviceObject, 235, MSG_DEVICE_BUSY, status);
        WDRBD_ERROR("%c: volume is busy. irp_count(%d)\n", pvext->Letter, irp_count);
        goto out;
    }

    if (pvext->WorkThreadInfo.Active)
    {
        // 볼륨 io 스레드가 active = TRUE 상태에서는 access 허용하지 않는다.
        // 그래서 리소스가 up 되어 있는 경우에는 이 명령을 내리더라도 실패하게끔 한다.
        WDRBD_ERROR("%c: volume is attached by wdrbd, so it's impossible to access\n", pvext->Letter);
        status = STATUS_VOLUME_DISMOUNTED;
        goto out;
    }

    // drbdadm down 명령을 하면 볼륨 io 스레드도 종료시키도록 수정할 필요가 있고
    // 이후에 mount volume을 시도하면
    // access 접근이 가능하도록 VOLUME_EXTENSION의 Active를 FALSE 시키도록 한다.
    pvext->Active = FALSE;

out:
    COUNT_UNLOCK(pvext);
        
    return status;
}

NTSTATUS
IOCTL_GetVolumeSize( PDEVICE_OBJECT DeviceObject, PIRP Irp )
{
	NTSTATUS		status;
	ULONG			inlen, outlen;
	PIO_STACK_LOCATION	irpSp=IoGetCurrentIrpStackLocation(Irp);
	PVOLUME_EXTENSION	VolumeExtension = NULL;
	PMVOL_VOLUME_INFO	pVolumeInfo = NULL;
	PLARGE_INTEGER		pVolumeSize;

	inlen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outlen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if( inlen < sizeof(MVOL_VOLUME_INFO) || outlen < sizeof(LARGE_INTEGER) )
	{
		mvolLogError( DeviceObject, 321, MSG_BUFFER_SMALL, STATUS_BUFFER_TOO_SMALL );

		WDRBD_ERROR("buffer too small\n");
		return STATUS_BUFFER_TOO_SMALL;
	}

	pVolumeInfo = (PMVOL_VOLUME_INFO) Irp->AssociatedIrp.SystemBuffer;
	
	if( DeviceObject == mvolRootDeviceObject )
	{
		WDRBD_TRACE("Root Device IOCTL\n");

		MVOL_LOCK();
		VolumeExtension = mvolSearchDevice( pVolumeInfo->PhysicalDeviceName );
		MVOL_UNLOCK();

		if( VolumeExtension == NULL )
		{
			mvolLogError( DeviceObject, 322, MSG_NO_DEVICE, STATUS_NO_SUCH_DEVICE );
			WDRBD_ERROR("cannot find volume, PD=%ws\n", pVolumeInfo->PhysicalDeviceName);
			return STATUS_NO_SUCH_DEVICE;
		}
	}
	else
	{
		VolumeExtension = DeviceObject->DeviceExtension;
	}

	pVolumeSize = (PLARGE_INTEGER) Irp->AssociatedIrp.SystemBuffer;
	status = mvolGetVolumeSize( VolumeExtension->TargetDeviceObject, pVolumeSize );
	if( !NT_SUCCESS(status) )
	{
		mvolLogError( VolumeExtension->DeviceObject, 323, MSG_CALL_DRIVER_ERROR, status );
		WDRBD_ERROR("cannot get volume size, err=0x%x\n", status);
	}

	return status;
}

NTSTATUS
IOCTL_GetCountInfo( PDEVICE_OBJECT DeviceObject, PIRP Irp, PULONG ReturnLength )
{
	ULONG			inlen, outlen;
	PIO_STACK_LOCATION	irpSp=IoGetCurrentIrpStackLocation(Irp);
	PVOLUME_EXTENSION	VolumeExtension = NULL;
	PMVOL_VOLUME_INFO	pVolumeInfo = NULL;
	PMVOL_COUNT_INFO	pCountInfo = NULL;

	inlen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outlen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if( inlen < sizeof(MVOL_VOLUME_INFO) || outlen < sizeof(MVOL_COUNT_INFO) )
	{
		mvolLogError( DeviceObject, 351, MSG_BUFFER_SMALL, STATUS_BUFFER_TOO_SMALL );
		WDRBD_ERROR("buffer too small\n");
		return STATUS_BUFFER_TOO_SMALL;
	}

	pVolumeInfo = (PMVOL_VOLUME_INFO) Irp->AssociatedIrp.SystemBuffer;
	if( DeviceObject == mvolRootDeviceObject )
	{
		WDRBD_TRACE("Root Device IOCTL\n");

		MVOL_LOCK();
		VolumeExtension = mvolSearchDevice( pVolumeInfo->PhysicalDeviceName );
		MVOL_UNLOCK();

		if( VolumeExtension == NULL )
		{
			mvolLogError( DeviceObject, 352, MSG_NO_DEVICE, STATUS_NO_SUCH_DEVICE );
			WDRBD_ERROR("cannot find volume, PD=%ws\n", pVolumeInfo->PhysicalDeviceName);
			return STATUS_NO_SUCH_DEVICE;
		}
	}
	else
	{
		VolumeExtension = DeviceObject->DeviceExtension;
	}

	pCountInfo = (PMVOL_COUNT_INFO) Irp->AssociatedIrp.SystemBuffer;
	pCountInfo->IrpCount = VolumeExtension->IrpCount;

	*ReturnLength = sizeof(MVOL_COUNT_INFO);
	return STATUS_SUCCESS;
}
