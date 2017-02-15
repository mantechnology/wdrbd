/*++

Module Name:

    drbdlock.c

Abstract:

    This is the main module of the drbdlock miniFilter driver.

Environment:

    Kernel mode

--*/

#include "pch.h"

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
        KdPrint _string

/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
drbdlockInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
drbdlockInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
drbdlockInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
drbdlockUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
drbdlockInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
drbdlockPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
drbdlockPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
drbdlockPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

		{ IRP_MJ_CREATE,
		0,
		drbdlockPreOperation,
		drbdlockPostOperation },

		{ IRP_MJ_CLOSE,
		0,
		drbdlockPreOperation,
		drbdlockPostOperation },

		{ IRP_MJ_READ,
		0,
		drbdlockPreOperation,
		drbdlockPostOperation },

		{ IRP_MJ_WRITE,
		0,
		drbdlockPreOperation,
		drbdlockPostOperation },



#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_CLOSE,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_READ,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_WRITE,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_SET_EA,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      drbdlockPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_PNP,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      drbdlockPreOperation,
      drbdlockPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    drbdlockUnload,                           //  MiniFilterUnload

    drbdlockInstanceSetup,                    //  InstanceSetup
    drbdlockInstanceQueryTeardown,            //  InstanceQueryTeardown
    drbdlockInstanceTeardownStart,            //  InstanceTeardownStart
    drbdlockInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
drbdlockInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );
	
    return STATUS_SUCCESS;
}


NTSTATUS
drbdlockInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    return STATUS_SUCCESS;
}


VOID
drbdlockInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
}


VOID
drbdlockInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("drbdlock!DriverEntry: Entered\n") );
	
    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = drbdlockCreateControlDeviceObject(DriverObject);
	if (!NT_SUCCESS(status))
	{
		FltUnregisterFilter(gFilterHandle);
		return status;
	}			

    //
    //  Start filtering i/o
    //
    status = FltStartFiltering( gFilterHandle );

    if (!NT_SUCCESS( status )) {

        FltUnregisterFilter( gFilterHandle );
    }
   

    return status;
}

NTSTATUS
drbdlockUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );
	
    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("drbdlock!drbdlockUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

	drbdlockDeleteControlDeviceObject();

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
drbdlockPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
drbdlockPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );
	    
    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
drbdlockPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}