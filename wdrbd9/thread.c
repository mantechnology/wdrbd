#include <Ntifs.h>
#include <wdm.h>
#include "drbd_windrv.h"	/// SEO:
#include "proto.h"


NTSTATUS
mvolInitializeThread( PVOLUME_EXTENSION VolumeExtension,
	PMVOL_THREAD pThreadInfo, PKSTART_ROUTINE ThreadRoutine )
{
	NTSTATUS					status;
	HANDLE						threadhandle;
	SECURITY_QUALITY_OF_SERVICE	se_quality_service;

    if (pThreadInfo->Active)
    {
        return STATUS_DEVICE_ALREADY_ATTACHED;
    }

	pThreadInfo->exit_thread = FALSE;
	pThreadInfo->DeviceObject = VolumeExtension->DeviceObject;

	RtlZeroMemory( &se_quality_service, sizeof(SECURITY_QUALITY_OF_SERVICE) );
	se_quality_service.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
	se_quality_service.ImpersonationLevel = SecurityImpersonation;
	se_quality_service.ContextTrackingMode = SECURITY_STATIC_TRACKING;
	se_quality_service.EffectiveOnly = FALSE;

	status = SeCreateClientSecurity( PsGetCurrentThread(), &se_quality_service,
		FALSE, &pThreadInfo->se_client_context );
	if( !NT_SUCCESS(status) )
	{
		WDRBD_ERROR("cannot create client security, err=0x%x\n", status);
		return status;
	}

	KeInitializeEvent(&pThreadInfo->RequestEvent, SynchronizationEvent, FALSE);
	KeInitializeEvent(&pThreadInfo->SplitIoDoneEvent, SynchronizationEvent, FALSE);
	InitializeListHead(&pThreadInfo->ListHead);
	KeInitializeSpinLock(&pThreadInfo->ListLock);

	status = PsCreateSystemThread( &threadhandle, 0L, NULL, 0L, NULL,
		(PKSTART_ROUTINE)ThreadRoutine, (PVOID)pThreadInfo );
	if( !NT_SUCCESS(status) )
	{
		WDRBD_ERROR("cannot create Thread, err=0x%x\n", status);
		SeDeleteClientSecurity( &pThreadInfo->se_client_context );
		return status;
	}

	status = ObReferenceObjectByHandle( threadhandle, THREAD_ALL_ACCESS, NULL, KernelMode,
		&pThreadInfo->pThread, NULL );
	ZwClose( threadhandle );
	if( !NT_SUCCESS(status) )
	{
		pThreadInfo->exit_thread = TRUE;
		IO_THREAD_SIG( pThreadInfo);
		SeDeleteClientSecurity( &pThreadInfo->se_client_context );
		return status;
	}

	pThreadInfo->Active = TRUE;
	return STATUS_SUCCESS;
}

VOID
mvolTerminateThread( PMVOL_THREAD pThreadInfo )
{
    if( NULL == pThreadInfo )   return ;
    if( TRUE == pThreadInfo->Active )
    {
        pThreadInfo->exit_thread = TRUE;
	    IO_THREAD_SIG( pThreadInfo );
        KeWaitForSingleObject( pThreadInfo->pThread, Executive, KernelMode, FALSE, NULL );
    }

    if( NULL != pThreadInfo->pThread )
    {
	    ObDereferenceObject( pThreadInfo->pThread );
	    SeDeleteClientSecurity( &pThreadInfo->se_client_context );
        pThreadInfo->pThread = NULL;
    }

	pThreadInfo->Active = FALSE;
}

VOID
mvolWorkThread(PVOID arg)
{
	NTSTATUS					status;
	PMVOL_THREAD				pThreadInfo;
	PDEVICE_OBJECT				DeviceObject;
	PVOLUME_EXTENSION			VolumeExtension = NULL;
	PLIST_ENTRY					request;
	PIRP						irp;
	PIO_STACK_LOCATION			irpSp;
	pThreadInfo = (PMVOL_THREAD) arg;
	ULONG						id;
	int							high = 0;
	
	DeviceObject = pThreadInfo->DeviceObject;
	VolumeExtension = DeviceObject->DeviceExtension;
	
	id = pThreadInfo->Id;
    WDRBD_TRACE("WorkThread [%ws]:id %d handle 0x%x start\n", VolumeExtension->PhysicalDeviceName, id, KeGetCurrentThread());

	pThreadInfo->read_req_count = 0;
	pThreadInfo->write_req_count = 0;

	for (;;)
	{
		int loop = 0;

		IO_THREAD_WAIT(pThreadInfo);
		if (pThreadInfo->exit_thread)
		{
			WDRBD_TRACE("WorkThread [%ws]: Terminate Thread\n", VolumeExtension->PhysicalDeviceName);
			PsTerminateSystemThread(STATUS_SUCCESS);
		}

		while ((request = ExInterlockedRemoveHeadList(&pThreadInfo->ListHead, &pThreadInfo->ListLock)) != 0)
		{
			irp = CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);
			irpSp = IoGetCurrentIrpStackLocation(irp);

#ifdef DRBD_TRACE	
			DbgPrint("\n");
			WDRBD_TRACE("I/O Thread:IRQL(%d) start I/O(%s) loop(%d) .......................!\n", 
				KeGetCurrentIrql(), (irpSp->MajorFunction == IRP_MJ_WRITE)? "Write" : "Read", loop);
#endif

			switch (irpSp->MajorFunction)
			{
			case IRP_MJ_WRITE:
				InterlockedDecrement( &VolumeExtension->IrpCount );/// deviceExtension->IrpCount--;
				InterlockedIncrement( &pThreadInfo->write_req_count );/// pThreadInfo->write_req_count++;
				status = mvolReadWriteDevice(VolumeExtension, irp, IRP_MJ_WRITE);
				if (status != STATUS_SUCCESS)
				{
				mvolLogError(VolumeExtension->DeviceObject, 111, MSG_WRITE_ERROR, status);

				irp->IoStatus.Information = 0;
				irp->IoStatus.Status = status;
				IoCompleteRequest(irp, (CCHAR)(NT_SUCCESS(irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
				}
				break;

			case IRP_MJ_READ:
				if (g_read_filter)
				{
				InterlockedIncrement( &pThreadInfo->read_req_count );/// pThreadInfo->read_req_count++;
				status = mvolReadWriteDevice(VolumeExtension, irp, IRP_MJ_READ);
				if (status != STATUS_SUCCESS)
				{
					mvolLogError(VolumeExtension->DeviceObject, 111, MSG_WRITE_ERROR, status);
					irp->IoStatus.Information = 0;
					irp->IoStatus.Status = status;
					IoCompleteRequest(irp, (CCHAR)(NT_SUCCESS(irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
				}
				}
				break;

			default:
				WDRBD_ERROR("WorkThread: invalid IRP MJ=0x%x\n", irpSp->MajorFunction);
				irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				IoCompleteRequest(irp, (CCHAR)(NT_SUCCESS(irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
				break;
			}
			loop++;
		}

		if (loop > 1)
		{
			if (high < loop)
			{
				high = loop;
				WDRBD_INFO("hooker[%ws:%c] thread id %d: irp processing peek(%d)\n",
					VolumeExtension->PhysicalDeviceName, VolumeExtension->Letter, id, high);
			}
		}		
		loop = 0;
	}
}
