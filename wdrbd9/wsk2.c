
#include "drbd_windows.h"
#include "wsk2.h"

/* DW-1587 
 * Turns off the C6102 warning.
 * this warning warns to access uninitialized variable, 
 * but disables warnig because there is no problem in code
 *
 * Turns off the C6387 warning.
 * Even though pointer parameters need to contain NULLs,
 * they are treated as warnings.
 *
 * C6101, C28252, C28253 warnings is not a problem in wsk2.c.
 */
#pragma warning (disable: 6053 6101 6102 6387 28252 28253 28719)
extern bool drbd_stream_send_timed_out(struct drbd_transport *transport, enum drbd_stream stream);
IO_COMPLETION_ROUTINE CompletionRoutine;
IO_COMPLETION_ROUTINE SendCompletionRoutine;
#ifdef _WIN32_NOWAIT_COMPLETION
IO_COMPLETION_ROUTINE NoWaitCompletionRoutine;
#endif

WSK_REGISTRATION			g_WskRegistration;
static WSK_PROVIDER_NPI		g_WskProvider;
static WSK_CLIENT_DISPATCH	g_WskDispatch = { MAKE_WSK_VERSION(1, 0), 0, NULL };
LONG						g_WskState = DEINITIALIZED;

//#define WSK_ASYNCCOMPL	1
struct socket* gpNetlinkServerSocket = NULL;
//PWSK_SOCKET         netlink_server_socket = NULL;

WSK_REGISTRATION    gWskEventRegistration;
WSK_PROVIDER_NPI    gWskEventProviderNPI;


// Socket-level callback table for listening sockets
const WSK_CLIENT_LISTEN_DISPATCH ClientListenDispatch = {
    NetlinkAcceptEvent,
    NULL, // WskInspectEvent is required only if conditional-accept is used.
    NULL  // WskAbortEvent is required only if conditional-accept is used.
};

struct SendParameter {
	PKEVENT		Event;
	PCHAR		DataBuffer;
	PWSK_BUF	WskBuffer;
	PNTSTATUS	Status;
	PLONG		BytesSent;
};

char *GetSockErrorString(NTSTATUS status)
{
	char *ErrorString;
	switch (status)	{
		case STATUS_SUCCESS:
			ErrorString = "STATUS_SUCCESS";
			break;
		case STATUS_PENDING:
			ErrorString = "STATUS_PENDING";
			break;
		case STATUS_CONNECTION_RESET:
			ErrorString = "STATUS_CONNECTION_RESET";
			break;
		case STATUS_CONNECTION_DISCONNECTED:
			ErrorString = "STATUS_CONNECTION_DISCONNECTED";
			break;
		case STATUS_CONNECTION_REFUSED:
			ErrorString = "STATUS_CONNECTION_REFUSED";
			break;	
		case STATUS_GRACEFUL_DISCONNECT:
			ErrorString = "STATUS_GRACEFUL_DISCONNECT";
			break;
		case STATUS_ADDRESS_ALREADY_ASSOCIATED:
			ErrorString = "STATUS_ADDRESS_ALREADY_ASSOCIATED";
			break;
		case STATUS_ADDRESS_NOT_ASSOCIATED:
			ErrorString = "STATUS_ADDRESS_NOT_ASSOCIATED";
			break;
		case STATUS_CONNECTION_INVALID:
			ErrorString = "STATUS_CONNECTION_INVALID";
			break;
		case STATUS_CONNECTION_ACTIVE:
			ErrorString = "STATUS_CONNECTION_ACTIVE";
			break;
		case STATUS_NETWORK_UNREACHABLE:
			ErrorString = "STATUS_NETWORK_UNREACHABLE";
			break;
		case STATUS_HOST_UNREACHABLE:
			ErrorString = "STATUS_HOST_UNREACHABLE";
			break;
		case STATUS_PROTOCOL_UNREACHABLE:
			ErrorString = "STATUS_PROTOCOL_UNREACHABLE";
			break;
		case STATUS_PORT_UNREACHABLE:
			ErrorString = "STATUS_PORT_UNREACHABLE";
			break;
		case STATUS_REQUEST_ABORTED:
			ErrorString = "STATUS_REQUEST_ABORTED";
			break;
		case STATUS_CONNECTION_ABORTED:
			ErrorString = "STATUS_CONNECTION_ABORTED";
			break;
		case STATUS_CONNECTION_COUNT_LIMIT:
			ErrorString = "STATUS_CONNECTION_COUNT_LIMIT";
			break;
		case STATUS_INVALID_ADDRESS_COMPONENT:
			ErrorString = "STATUS_INVALID_ADDRESS_COMPONENT";
			break;
		case STATUS_IO_TIMEOUT:
			ErrorString = "STATUS_IO_TIMEOUT";
			break;
		case STATUS_INVALID_DEVICE_STATE:
			ErrorString = "STATUS_INVALID_DEVICE_STATE";
			break;
		case STATUS_FILE_FORCED_CLOSED:
			ErrorString = "STATUS_FILE_FORCED_CLOSED";
			break;
		default:
			ErrorString = "unknown error";
			WDRBD_INFO("unknown error NTSTATUS:%x\n",status);
			break;
	}
	return ErrorString;
}


NTSTATUS
NTAPI CompletionRoutine(
	__in PDEVICE_OBJECT	DeviceObject,
	__in PIRP			Irp,
	__in PVOID		Context
)
{
	PKEVENT			CompletionEvent = Context;
	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(DeviceObject);

	ASSERT(CompletionEvent);
	
	if (CompletionEvent)
		KeSetEvent(CompletionEvent, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

#ifdef _WIN32_NOWAIT_COMPLETION
NTSTATUS
NTAPI NoWaitCompletionRoutine(
	__in PDEVICE_OBJECT	DeviceObject,
	__in PIRP			Irp,
	__in PVOID		Context
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Context);

	IoFreeIrp(Irp);
	return STATUS_MORE_PROCESSING_REQUIRED;
}
#endif


NTSTATUS
InitWskData(
	__out PIRP*		pIrp,
	__out PKEVENT	CompletionEvent,
	__in  BOOLEAN	bRawIrp
)
{
	ASSERT(pIrp);
	ASSERT(CompletionEvent);

	// DW-1316 use raw irp.
	if (bRawIrp) {
		*pIrp = ExAllocatePoolWithTag(NonPagedPool, IoSizeOfIrp(1), 'FFDW');
		if (!*pIrp) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		IoInitializeIrp(*pIrp, IoSizeOfIrp(1), 1);
	}
	else {
		*pIrp = IoAllocateIrp(1, FALSE);
	}

	if (!*pIrp) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	KeInitializeEvent(CompletionEvent, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(*pIrp, CompletionRoutine, CompletionEvent, TRUE, TRUE, TRUE);

	return STATUS_SUCCESS;
}

#ifdef _WIN32_NOWAIT_COMPLETION
NTSTATUS
InitWskNoWaitData(
	__out PIRP*		pIrp,
	__in  BOOLEAN	bRawIrp
)
{
	ASSERT(pIrp);

	// DW-1316 use raw irp.
	if (bRawIrp) {
		*pIrp = ExAllocatePoolWithTag(NonPagedPool, IoSizeOfIrp(1), 'FFDW');
		if (!*pIrp) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		IoInitializeIrp(*pIrp, IoSizeOfIrp(1), 1);
	}
	else {
		*pIrp = IoAllocateIrp(1, FALSE);
	}

	if (!*pIrp) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	IoSetCompletionRoutine(*pIrp, NoWaitCompletionRoutine, NULL, TRUE, TRUE, TRUE);

	return STATUS_SUCCESS;
}
#endif


NTSTATUS
InitWskBuffer(
	__in  PVOID		Buffer,
	__in  ULONG		BufferSize,
	__out PWSK_BUF	WskBuffer,
	__in  BOOLEAN	bWriteAccess
)
{
	NTSTATUS Status = STATUS_SUCCESS;

	ASSERT(Buffer);
	ASSERT(BufferSize);
	ASSERT(WskBuffer);

	WskBuffer->Offset = 0;
	WskBuffer->Length = BufferSize;

	WskBuffer->Mdl = IoAllocateMdl(Buffer, BufferSize, FALSE, FALSE, NULL);
	if (!WskBuffer->Mdl) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

    try {
		// DW-1223: Locking with 'IoWriteAccess' affects buffer, which causes infinite I/O from ntfs when the buffer is from mdl of write IRP.
		// we need write access for receiver, since buffer will be filled.
		
		MmProbeAndLockPages(WskBuffer->Mdl, KernelMode, bWriteAccess?IoWriteAccess:IoReadAccess);
    } except(EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(WskBuffer->Mdl);
		WskBuffer->Mdl = NULL;

        WDRBD_ERROR("MmProbeAndLockPages failed. exception code=0x%x\n", GetExceptionCode());
        return STATUS_INSUFFICIENT_RESOURCES;
    }
	return Status;
}

VOID
FreeWskBuffer(
__in PWSK_BUF WskBuffer
)
{
	ASSERT(WskBuffer);
	//DW-1882 If MmProbeAndLockPages fails, do not call the Unlock function.
	if (WskBuffer->Mdl->MdlFlags & MDL_PAGES_LOCKED)
		MmUnlockPages(WskBuffer->Mdl);
	IoFreeMdl(WskBuffer->Mdl);
}

VOID
FreeWskData(
__in PIRP pIrp
)
{
	if (pIrp)
		IoFreeIrp(pIrp);
}

//
// Library initialization routine
//

NTSTATUS NTAPI WskGetNPI()
{
	WSK_CLIENT_NPI	WskClient = { 0 };
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	if (InterlockedCompareExchange(&g_WskState, INITIALIZING, DEINITIALIZED) != DEINITIALIZED)
		return STATUS_ALREADY_REGISTERED;

	WskClient.ClientContext = NULL;
	WskClient.Dispatch = &g_WskDispatch;

	Status = WskRegister(&WskClient, &g_WskRegistration);
	if (!NT_SUCCESS(Status)) {
		InterlockedExchange(&g_WskState, DEINITIALIZED);
		return Status;
	}

	WDRBD_INFO("WskCaptureProviderNPI start.\n");
	Status = WskCaptureProviderNPI(&g_WskRegistration, WSK_INFINITE_WAIT, &g_WskProvider);
	WDRBD_INFO("WskCaptureProviderNPI done.\n"); // takes long time! msg out after MVL loaded.

	if (!NT_SUCCESS(Status)) {
		WDRBD_ERROR("WskCaptureProviderNPI() failed with status 0x%08X\n", Status);
		WskDeregister(&g_WskRegistration);
		InterlockedExchange(&g_WskState, DEINITIALIZED);
		return Status;
	}

	InterlockedExchange(&g_WskState, INITIALIZED);
	return STATUS_SUCCESS;
}

//
// Library deinitialization routine
//

VOID NTAPI WskPutNPI()
{
	if (InterlockedCompareExchange(&g_WskState, INITIALIZED, DEINITIALIZING) != INITIALIZED)
		return;
	WskReleaseProviderNPI(&g_WskRegistration);
	WskDeregister(&g_WskRegistration);

	InterlockedExchange(&g_WskState, DEINITIALIZED);
}

PWSK_SOCKET
NTAPI
CreateSocket(
	__in ADDRESS_FAMILY	AddressFamily,
	__in USHORT			SocketType,
	__in ULONG			Protocol,
    __in PVOID          *SocketContext,
    __in PWSK_CLIENT_LISTEN_DISPATCH Dispatch,
	__in ULONG			Flags
)
{
	KEVENT			CompletionEvent = { 0 };
	PIRP			Irp = NULL;
	PWSK_SOCKET		WskSocket = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	if (g_WskState != INITIALIZED) {
		return NULL;
	}

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}

	Status = g_WskProvider.Dispatch->WskSocket(
				g_WskProvider.Client,
				AddressFamily,
				SocketType,
				Protocol,
				Flags,
				SocketContext,
				Dispatch,
				NULL,
				NULL,
				NULL,
				Irp);

	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	WskSocket = NT_SUCCESS(Status) ? (PWSK_SOCKET) Irp->IoStatus.Information : NULL;
	IoFreeIrp(Irp);

	return (PWSK_SOCKET) WskSocket;
}


#ifdef _WIN32_NOWAIT_COMPLETION
NTSTATUS
NTAPI
CloseSocket(
	__in struct socket* pSock
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_WskState != INITIALIZED || !WskSocket){
		return STATUS_INVALID_PARAMETER;
	}

	Status = InitWskNoWaitData(&Irp, TRUE);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	pSock->sk_state = WSK_CLOSING;
	
	Status = ((PWSK_PROVIDER_BASIC_DISPATCH) WskSocket->Dispatch)->WskCloseSocket(WskSocket, Irp);

	return STATUS_SUCCESS;
}
#else
NTSTATUS
NTAPI
CloseSocket(
	__in struct socket* pSock
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
	PIRP		Irp = NULL;
	KEVENT		CompletionEvent = { 0 };
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER	nWaitTime;
	nWaitTime.QuadPart = (-1 * 1000 * 10000);   // wait 1000ms relative 

	if (g_WskState != INITIALIZED || !WskSocket){
		return STATUS_INVALID_PARAMETER;
	}
	Status = InitWskData(&Irp, &CompletionEvent, TRUE);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	pSock->sk_state = WSK_CLOSING;
	
	Status = ((PWSK_PROVIDER_BASIC_DISPATCH) WskSocket->Dispatch)->WskCloseSocket(WskSocket, Irp);
	if (Status == STATUS_PENDING) {
		Status = KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, &nWaitTime);
		if (STATUS_TIMEOUT == Status) { // DW-1316 detour WskCloseSocket hang in Win7/x86.
			WDRBD_INFO("Timeout... Cancel WskCloseSocket:%p. maybe required to patch WSK Kernel. (irp:%p)\n", WskSocket, Irp);
			IoCancelIrp(Irp);
			// DW-1388: canceling must be completed before freeing the irp.
			KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		}
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	return Status;
}
#endif

NTSTATUS
NTAPI
Connect(
	__in struct socket* pSock,
	__in PSOCKADDR		RemoteAddress
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_WskState != INITIALIZED || !WskSocket || !RemoteAddress)
		return STATUS_INVALID_PARAMETER;

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskConnect(
		WskSocket,
		RemoteAddress,
		0,
		Irp);

	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);

	if (NT_SUCCESS(Status)) {
		//DW-1844 set connection status to WSK_ESTABLISHED
		pSock->sk_state = WSK_ESTABLISHED;
	}

	return Status;
}

NTSTATUS NTAPI
Disconnect(
	__in struct socket* pSock
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
	PIRP			Irp = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER	nWaitTime;
	nWaitTime.QuadPart = (-1 * 1000 * 10000);   // wait 1000ms relative 
	
	if (g_WskState != INITIALIZED || !WskSocket)
		return STATUS_INVALID_PARAMETER;

	Status = InitWskNoWaitData(&Irp, FALSE);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	pSock->sk_state = WSK_DISCONNECTING;
	
	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskDisconnect(
		WskSocket,
		NULL,
		WSK_FLAG_ABORTIVE,//=> when disconnecting, ABORTIVE was going to standalone, and then we removed ABORTIVE
		Irp);

	return STATUS_SUCCESS;
}

#ifdef _WSK_SOCKET_STATE
PWSK_SOCKET
NTAPI
CreateSocketConnect(
	__in struct socket* pSock,
	__in USHORT		SocketType,
	__in ULONG		Protocol,
	__in PSOCKADDR	LocalAddress, // address family desc. required
	__in PSOCKADDR	RemoteAddress, // address family desc. required
	__inout  NTSTATUS* pStatus,
	__in PWSK_CLIENT_CONNECTION_DISPATCH dispatch,
	__in PVOID socketContext
	)
#else 
PWSK_SOCKET
NTAPI
CreateSocketConnect(
	__in struct socket* pSock,
	__in USHORT		SocketType,
	__in ULONG		Protocol,
	__in PSOCKADDR	LocalAddress, // address family desc. required
	__in PSOCKADDR	RemoteAddress, // address family desc. required
	__inout  NTSTATUS* pStatus
)
#endif
{
	KEVENT			CompletionEvent = { 0 };
	PIRP			Irp = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	PWSK_SOCKET		WskSocket = NULL;

	if (g_WskState != INITIALIZED || !RemoteAddress || !LocalAddress || !pStatus)
		return NULL;

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}

#ifdef _WSK_SOCKET_STATE
	Status = g_WskProvider.Dispatch->WskSocketConnect(
				g_WskProvider.Client,
				SocketType,
				Protocol,
				LocalAddress,
				RemoteAddress,
				0,
				socketContext,
				dispatch,
				NULL,
				NULL,
				NULL,
				Irp);
#else 
	Status = g_WskProvider.Dispatch->WskSocketConnect(
		g_WskProvider.Client,
		SocketType,
		Protocol,
		LocalAddress,
		RemoteAddress,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		Irp);
#endif 
	if (Status == STATUS_PENDING) {
		// DW-1689 Timeout(Adjusted from 3 sec to 2 sec) handling for WskSocketConnect.
		LARGE_INTEGER nWaitTime = { 0, };
		nWaitTime = RtlConvertLongToLargeInteger(-2 * 1000 * 1000 * 10);	// 2s
		if ((Status = KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, &nWaitTime)) == STATUS_TIMEOUT) {
			IoCancelIrp(Irp);
			KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);			
			*pStatus = STATUS_TIMEOUT;
		} else {
			*pStatus = Status = Irp->IoStatus.Status;
		}
	} 
	
	if(Status == STATUS_SUCCESS) {
		// note: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wsk/nc-wsk-pfn_wsk_socket_connect
		// If the IRP is completed with success status, the IoStatus.Information field of the IRP contains a pointer to a socket object structure ( WSK_SOCKET) for the new socket.
		WskSocket = (PWSK_SOCKET) Irp->IoStatus.Information;
	} else {
		WskSocket = NULL;
	}
	pSock->sk_state = WSK_INITIALIZING;

	IoFreeIrp(Irp);
	
	return WskSocket;
}



NTSTATUS
NTAPI SendCompletionRoutine(
__in PDEVICE_OBJECT	DeviceObject,
__in PIRP			Irp,
__in PVOID			Context
)
{
	struct SendParameter* SendParam = Context;
	UNREFERENCED_PARAMETER(DeviceObject);

	if (SendParam == NULL)
		return STATUS_MORE_PROCESSING_REQUIRED;

	FreeWskBuffer(SendParam->WskBuffer);
	ExFreePool(SendParam->WskBuffer);
	ExFreePool(SendParam->DataBuffer);

	if (!Irp->Cancel)
	{
		*(SendParam->Status) = Irp->IoStatus.Status;

		if (*(SendParam->Status) == STATUS_SUCCESS) {
			*(SendParam->BytesSent) = (LONG)Irp->IoStatus.Information;
		}

		KeSetEvent(SendParam->Event, IO_NO_INCREMENT, FALSE);
	}
	else
	{
		ExFreePool(SendParam->Event);
		IoFreeIrp(Irp);
	}

	ExFreePool(SendParam);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
InitWskSendBuffer(
__out PCHAR*	DataBuffer,
__in  PVOID		Buffer,
__in  ULONG		BufferSize,
__out PWSK_BUF	*WskBuffer,
__in  BOOLEAN	bWriteAccess
)
{
	NTSTATUS Status = STATUS_SUCCESS;

	ASSERT(Buffer);
	ASSERT(BufferSize);

	(*DataBuffer) = ExAllocatePoolWithTag(NonPagedPool, BufferSize, 'DFDW');
	if (!(*DataBuffer)) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}


	(*WskBuffer) = ExAllocatePoolWithTag(NonPagedPool, sizeof(WSK_BUF), 'DFDW');
	if (!(*WskBuffer)) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	(*WskBuffer)->Offset = 0;
	(*WskBuffer)->Length = BufferSize;

	memcpy((*DataBuffer), Buffer, BufferSize);

	(*WskBuffer)->Mdl = IoAllocateMdl((*DataBuffer), BufferSize, FALSE, FALSE, NULL);
	if (!(*WskBuffer)->Mdl) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	try {
		// DW-1223: Locking with 'IoWriteAccess' affects buffer, which causes infinite I/O from ntfs when the buffer is from mdl of write IRP.
		// we need write access for receiver, since buffer will be filled.

		MmProbeAndLockPages((*WskBuffer)->Mdl, KernelMode, bWriteAccess ? IoWriteAccess : IoReadAccess);
	} except(EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl((*WskBuffer)->Mdl);
		(*WskBuffer)->Mdl = NULL;

		WDRBD_ERROR("MmProbeAndLockPages failed. exception code=0x%x\n", GetExceptionCode());
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	return Status;
}

NTSTATUS
InitWskSendData(
__out PIRP*		pIrp,
__out PKEVENT*	CompletionEvent,
__in  PCHAR		DataBuffer,
__in  WSK_BUF*	WskBuffer,
__in  LONG*		BytesSent,
__in  NTSTATUS*	SendStatus,
__in  BOOLEAN	bRawIrp)
{
	ASSERT(pIrp);

	struct SendParameter *param = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct SendParameter), 'CFDW');

	if (!param) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (bRawIrp) {
		*pIrp = ExAllocatePoolWithTag(NonPagedPool, IoSizeOfIrp(1), 'FFDW');
		if (!*pIrp) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		IoInitializeIrp(*pIrp, IoSizeOfIrp(1), 1);
	}
	else {
		*pIrp = IoAllocateIrp(1, FALSE);
	}

	if (!*pIrp) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//DW-1758 : Dynamic allocation of 'CompletionEvet', for resource management in completion routine
	*CompletionEvent = ExAllocatePoolWithTag(NonPagedPool, sizeof(KEVENT), 'CFDW');
	if (!*CompletionEvent) {
		return SOCKET_ERROR;
	}

	param->DataBuffer = DataBuffer;
	param->BytesSent = BytesSent;
	param->Event = *CompletionEvent;
	param->Status = SendStatus;
	param->WskBuffer = WskBuffer;

	KeInitializeEvent(*CompletionEvent, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(*pIrp, SendCompletionRoutine, param, TRUE, TRUE, TRUE);

	return STATUS_SUCCESS;
}


LONG
NTAPI
Send(
	__in struct socket* pSock,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout, // ms
	__in KEVENT			*send_buf_kill_event,
	__in struct			drbd_transport *transport,
	__in enum			drbd_stream stream
)
{
	UNREFERENCED_PARAMETER(send_buf_kill_event);
	UNREFERENCED_PARAMETER(transport);
	UNREFERENCED_PARAMETER(stream);

	PWSK_SOCKET		WskSocket = pSock->sk;
	PKEVENT			CompletionEvent = NULL;
	PIRP			Irp = NULL;
	PWSK_BUF		WskBuffer = NULL;
	LONG			BytesSent = SOCKET_ERROR; // DRBC_CHECK_WSK: SOCKET_ERROR be mixed EINVAL?
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER	nWaitTime; LARGE_INTEGER	*pTime;
	NTSTATUS		SendStatus = STATUS_UNSUCCESSFUL;
	PCHAR			DataBuffer = NULL;
	LONGLONG		send_ts = 0;
	if (g_WskState != INITIALIZED || !WskSocket || !Buffer || ((int)BufferSize <= 0) || (pSock->sk_state == WSK_INVALID_DEVICE)) {
		return SOCKET_ERROR;
	}

	//DW-1758 : Dynamic allocation of 'WskBuffer', for resource management in completion routine
	//Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer, FALSE);
	Status = InitWskSendBuffer(&DataBuffer, Buffer, BufferSize, &WskBuffer, FALSE); 
	if (!NT_SUCCESS(Status)) {
		BytesSent = SOCKET_ERROR;
		goto $Send_fail;
	}

	//Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	Status = InitWskSendData(&Irp,
								&CompletionEvent,
								DataBuffer,
								WskBuffer,
								&BytesSent, //DW-1758 : Get BytesSent (Irp->IoStatus.Information)
								&SendStatus, //DW-1758 : Get SendStatus (Irp->IoStatus.Status)
								FALSE);
	if (!NT_SUCCESS(Status)) {
		BytesSent = SOCKET_ERROR;
		goto $Send_fail;
	}

	Flags |= WSK_FLAG_NODELAY;

	nWaitTime = RtlConvertLongToLargeInteger(-1 * Timeout * 1000 * 10);
	pTime = &nWaitTime;

	if(pSock->sk_state <= WSK_DISCONNECTING) {
		// DW-1749 Do not call WskSend if socket is being disconnected or closed. The operation context will not be used any more.
		// Otherwise, a hang occurs.
		WDRBD_INFO("%s, No Connect, Current state : %d(0x%p)\n", __FUNCTION__, pSock->sk_state, WskSocket);
		BytesSent = -ECONNRESET;
		goto $Send_fail;
	}

	if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY)
		send_ts = timestamp();

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskSend(
																			WskSocket,
																			WskBuffer,
																			Flags,
																			Irp);

	if (Status == STATUS_PENDING) {
		//Status = KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = KeWaitForSingleObject(CompletionEvent, Executive, KernelMode, FALSE, pTime);
		if(Status == STATUS_TIMEOUT) {
			// DW-1679 if WSK_INVALID_DEVICE, we goto fail.
			if(pSock->sk_state == WSK_INVALID_DEVICE) {
				BytesSent = -ECONNRESET;
			} else {
				// DW-1749 Modified to remove WSK I/O cancel logic for occasional WSK I/O hang issues
				// The transmission timeout depends on the WSK kernel, Remove the I/O cancel logic at the existing timeout.
				//IoCancelIrp(Irp);
				//KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);

				// DW-1758 : release resource from the completion routine if IRP is cancelled 
				WDRBD_INFO("%s, Timeout(%dms), Current state : %d(0x%p) size(%lu)\n", __FUNCTION__, Timeout, pSock->sk_state, WskSocket, BufferSize);
				IoCancelIrp(Irp);

				return -EAGAIN;
			}
			goto $Send_fail;
		}
		else if (Status == STATUS_SUCCESS) {
			if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY) {
				WDRBD_LATENCY("%s, SUCCESS, Current state : %d(0x%p) size(%lu) elapse(%lldus)\n", __FUNCTION__, pSock->sk_state, WskSocket, BufferSize, timestamp_elapse(send_ts, timestamp()));
			}
		}
	}

	if (SendStatus != STATUS_SUCCESS) {
		switch (SendStatus) {
		case STATUS_IO_TIMEOUT:
			WDRBD_INFO("Send timeout... wsk(0x%p) size(%lu)\n", WskSocket, BufferSize);
			BytesSent = -EAGAIN;
			break;
		case STATUS_INVALID_DEVICE_STATE:
		case STATUS_FILE_FORCED_CLOSED:
			WDRBD_INFO("Send invalid WSK Socket state (%s) wsk(0x%p) size(%lu)\n", GetSockErrorString(SendStatus), WskSocket, BufferSize);
			pSock->sk_state = WSK_INVALID_DEVICE;
			BytesSent = -ECONNRESET;
			break;
		default:
			WDRBD_INFO("Send error, default state(%s) wsk(0x%p) size(%lu)\n", GetSockErrorString(SendStatus), WskSocket, BufferSize);
			BytesSent = -ECONNRESET;
			break;
		}
	}

	ExFreePool(CompletionEvent);
	IoFreeIrp(Irp);

	return BytesSent;

$Send_fail:		
	if (WskBuffer) {
		if (WskBuffer->Mdl)
			FreeWskBuffer(WskBuffer);
		ExFreePool(WskBuffer);
	}

	if (DataBuffer)
		ExFreePool(DataBuffer);

	if (CompletionEvent)
		ExFreePool(CompletionEvent);

	if (Irp)
		IoFreeIrp(Irp);
	
	return BytesSent;
}


LONG
NTAPI
SendLocal(
	__in struct socket* pSock,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout // ms
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
	PKEVENT			CompletionEvent = NULL;
	PIRP			Irp = NULL;
	PWSK_BUF		WskBuffer = NULL;
	LONG		BytesSent = SOCKET_ERROR;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER	nWaitTime; LARGE_INTEGER	*pTime;
	NTSTATUS		SendStatus = STATUS_UNSUCCESSFUL;
	PCHAR			DataBuffer = NULL;

	if (g_WskState != INITIALIZED || !WskSocket || !Buffer || ((int) BufferSize <= 0) || (pSock->sk_state == WSK_INVALID_DEVICE)) {
		WDRBD_INFO("pSock->sk_state == WSK_INVALID_DEVICE WskSocket:%p\n",WskSocket);
		return SOCKET_ERROR;
	}

	//DW-1758 : Dynamic allocation of 'WskBuffer', for resource management in completion routine
	//Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer, FALSE);
	Status = InitWskSendBuffer(&DataBuffer, Buffer, BufferSize, &WskBuffer, FALSE);
	if (!NT_SUCCESS(Status)) {
		BytesSent = SOCKET_ERROR;
		goto $SendLoacl_fail;
	}

	//Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	Status = InitWskSendData(&Irp,
								&CompletionEvent,
								DataBuffer,
								WskBuffer,
								&BytesSent, //DW-1758 : Get BytesSent (Irp->IoStatus.Information)
								&SendStatus, //DW-1758 : Get SendStatus (Irp->IoStatus.Status)
		FALSE);
	if (!NT_SUCCESS(Status)) {
		BytesSent = SOCKET_ERROR;
		goto $SendLoacl_fail;
	}

	// DW-1015 fix crash. WskSocket->Dispatch)->WskSend is NULL while machine is shutdowning
	// DW-1029 to prevent possible contingency, check if dispatch table is valid.
	if(gbShutdown || !WskSocket->Dispatch) { 
		BytesSent = SOCKET_ERROR;
		goto $SendLoacl_fail;
	}

	Flags |= WSK_FLAG_NODELAY;

	nWaitTime = RtlConvertLongToLargeInteger(-1 * Timeout * 1000 * 10);
	pTime = &nWaitTime;

	if(pSock->sk_state <= WSK_DISCONNECTING) {
		// DW-1749 
		WDRBD_INFO("%s, No Connect, Current state : %d(0x%p)\n", __FUNCTION__, pSock->sk_state, WskSocket);
		BytesSent = -ECONNRESET;
		goto $SendLoacl_fail;
	}
	
	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskSend(
																			WskSocket,
																			WskBuffer,
																			Flags,
																			Irp);
	if (Status == STATUS_PENDING) {
		Status = KeWaitForSingleObject(CompletionEvent, Executive, KernelMode, FALSE, pTime);

		if(Status == STATUS_TIMEOUT) {
			// DW-1679 if WSK_INVALID_DEVICE, we goto fail.
			if(pSock->sk_state == WSK_INVALID_DEVICE) {
				WDRBD_INFO("SendLocal WSK_INVALID_DEVICE(0x%p)\n", WskSocket);
				BytesSent = -ECONNRESET;
			} else {
				// FIXME: cancel & completion's race condition may be occurred.
				// Status or Irp->IoStatus.Status  

				//DW-1758 : release resource from the completion routine if IRP is cancelled 
				WDRBD_INFO("%s, Timeout(%dms), Current state : %d(0x%p)\n", __FUNCTION__, Timeout, pSock->sk_state, WskSocket);
				IoCancelIrp(Irp);
				//KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
				return -EAGAIN;
			}
			goto $SendLoacl_fail;
		}
	}

	if (SendStatus != STATUS_SUCCESS) {
		switch (SendStatus) {
		case STATUS_IO_TIMEOUT:
			WDRBD_INFO("Send timeout... wsk(0x%p)\n", WskSocket);
			BytesSent = -EAGAIN;
			break;
		case STATUS_INVALID_DEVICE_STATE:
		case STATUS_FILE_FORCED_CLOSED:
			WDRBD_INFO("Send invalid WSK Socket state (%s) wsk(0x%p)\n", GetSockErrorString(SendStatus), WskSocket);
			pSock->sk_state = WSK_INVALID_DEVICE;
			BytesSent = -ECONNRESET;
			break;
		default:
			WDRBD_INFO("Send error, default state(%s) wsk(0x%p)\n", GetSockErrorString(SendStatus), WskSocket);
			BytesSent = -ECONNRESET;
			break;
		}
	}

	ExFreePool(CompletionEvent);
	IoFreeIrp(Irp);

	return BytesSent;
	
$SendLoacl_fail:	
	if (WskBuffer) {
		if (WskBuffer->Mdl)
			FreeWskBuffer(WskBuffer);
		ExFreePool(WskBuffer);
	}

	if (DataBuffer)
		ExFreePool(DataBuffer);

	if (CompletionEvent)
		ExFreePool(CompletionEvent);

	if (Irp)
		IoFreeIrp(Irp);

	return BytesSent;
}


LONG
NTAPI
SendAsync(
	__in struct socket* pSock,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout, // ms
	__in struct			drbd_transport *transport,
	__in enum			drbd_stream stream
)
{
	UNREFERENCED_PARAMETER(transport);
	UNREFERENCED_PARAMETER(stream);

	PWSK_SOCKET		WskSocket = pSock->sk;
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesSent = SOCKET_ERROR; // DRBC_CHECK_WSK: SOCKET_ERROR be mixed EINVAL?
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_WskState != INITIALIZED || !WskSocket || !Buffer || ((int) BufferSize <= 0))
		return SOCKET_ERROR;

	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer, FALSE);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		FreeWskBuffer(&WskBuffer);
		return SOCKET_ERROR;
	}

	Flags |= WSK_FLAG_NODELAY;

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskSend(
		WskSocket,
		&WskBuffer,
		Flags,
		Irp);

	if (Status == STATUS_PENDING) {
		LARGE_INTEGER	nWaitTime;
		LARGE_INTEGER	*pTime;

		if (Timeout <= 0 || Timeout == MAX_SCHEDULE_TIMEOUT) {
			pTime = NULL;
		} else {
			nWaitTime = RtlConvertLongToLargeInteger(-1 * Timeout * 1000 * 10);
			pTime = &nWaitTime;
		}
		
		{
			//struct      task_struct *thread = current;
			int 		retry_count = 0;
$SendAsync_retry:			
			// DW-1173: do not wait for send_buf_kill_event, we need to send all items queued before cleaning up.
			Status = KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, pTime);
			switch (Status) {
			case STATUS_TIMEOUT:
				// DW-1095 adjust retry_count logic 
				//if (!(++retry_count % 5)) {
				if (!(++retry_count % 2)) {
					WDRBD_INFO("SendAsync buffering: tx timeout(%d ms). retry.\n", Timeout);// for trace
					// DW-1524 fix infinite send retry on low-bandwith
					IoCancelIrp(Irp);
					KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
					WDRBD_INFO("SendAsync cancel done\n", Timeout);// for trace
					BytesSent = -EAGAIN;
					break;
				} 

				goto $SendAsync_retry;
				
				//IoCancelIrp(Irp);
				//KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
				//BytesSent = -EAGAIN;
				break;

			case STATUS_SUCCESS:
				if (NT_SUCCESS(Irp->IoStatus.Status)) {
					BytesSent = (LONG)Irp->IoStatus.Information;
				} else {
					WDRBD_INFO("tx error(%s) wsk(0x%p)\n", GetSockErrorString(Irp->IoStatus.Status), WskSocket);
					switch (Irp->IoStatus.Status) {
						case STATUS_IO_TIMEOUT:
							BytesSent = -EAGAIN;
							break;
						case STATUS_INVALID_DEVICE_STATE:
							BytesSent = -ECONNRESET;
							WDRBD_INFO("STATUS_INVALID_DEVICE_STATE(%s) wsk(0x%p)\n", GetSockErrorString(Irp->IoStatus.Status), WskSocket);
							break;	
						case STATUS_FILE_FORCED_CLOSED:
							BytesSent = -ECONNRESET;
							WDRBD_INFO("STATUS_FILE_FORCED_CLOSED(%s) wsk(0x%p)\n", GetSockErrorString(Irp->IoStatus.Status), WskSocket);
							break;	
						default:
							BytesSent = -ECONNRESET;
							break;
					}
				}
				break;

			default:
				WDRBD_INFO("Wait failed. status 0x%x\n", Status);
				BytesSent = SOCKET_ERROR;
			}
		}
	} else {
		if (Status == STATUS_SUCCESS) {
			BytesSent = (LONG) Irp->IoStatus.Information;
			WDRBD_INFO("(%s) WskSend No pending: but sent(%d)!\n", current->comm, BytesSent);
		} else {
			WDRBD_INFO("(%s) WskSend error(0x%x)\n", current->comm, Status);
			BytesSent = SOCKET_ERROR;
		}
	}

	IoFreeIrp(Irp);
	FreeWskBuffer(&WskBuffer);

	return BytesSent;
}


LONG
NTAPI
SendTo(
	__in struct socket* pSock,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in_opt PSOCKADDR	RemoteAddress
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesSent = SOCKET_ERROR;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_WskState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
		return SOCKET_ERROR;

	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer, FALSE);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		FreeWskBuffer(&WskBuffer);
		return SOCKET_ERROR;
	}

	Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH) WskSocket->Dispatch)->WskSendTo(
		WskSocket,
		&WskBuffer,
		0,
		RemoteAddress,
		0,
		NULL,
		Irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	BytesSent = NT_SUCCESS(Status) ? (LONG) Irp->IoStatus.Information : SOCKET_ERROR;

	IoFreeIrp(Irp);
	FreeWskBuffer(&WskBuffer);
	return BytesSent;
}

LONG NTAPI Receive(
	__in struct socket* pSock,
	__out PVOID			Buffer,
	__in  ULONG			BufferSize,
	__in  ULONG			Flags,
	__in ULONG			Timeout
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesReceived = SOCKET_ERROR;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;
	LONGLONG	recv_ts = 0;
    struct      task_struct *thread = current;
    PVOID       waitObjects[2];
    int         wObjCount = 1;

	if (g_WskState != INITIALIZED || !WskSocket || !Buffer || (pSock->sk_state == WSK_INVALID_DEVICE) )
		return SOCKET_ERROR;

	if ((int) BufferSize <= 0) {
		return SOCKET_ERROR;
	}

	RtlZeroMemory(Buffer, BufferSize);
	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer, TRUE);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);

	if (!NT_SUCCESS(Status)) {
		FreeWskBuffer(&WskBuffer);
		return SOCKET_ERROR;
	}

	if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY)
		recv_ts = timestamp();

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskReceive(
				WskSocket,
				&WskBuffer,
				Flags,
				Irp);

    if (Status == STATUS_PENDING) {
        LARGE_INTEGER	nWaitTime;
        LARGE_INTEGER	*pTime;

        if (Timeout <= 0 || Timeout == MAX_SCHEDULE_TIMEOUT) {
            pTime = 0;
        } else {
            nWaitTime = RtlConvertLongToLargeInteger(-1 * Timeout * 1000 * 10);
            pTime = &nWaitTime;
        }

        waitObjects[0] = (PVOID) &CompletionEvent;
        if (thread->has_sig_event) {
            waitObjects[1] = (PVOID) &thread->sig_event;
            wObjCount = 2;
        }
		
        Status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);
        switch (Status) {
        case STATUS_WAIT_0: // waitObjects[0] CompletionEvent
            if (Irp->IoStatus.Status == STATUS_SUCCESS) {
                BytesReceived = (LONG) Irp->IoStatus.Information;

				if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY) {
					WDRBD_LATENCY("RECV(%s) wsk(0x%p) SUCCESS err(0x%x:%s) size(%lu) elapse(%lldus)\n", thread->comm, WskSocket, Irp->IoStatus.Status, GetSockErrorString(Irp->IoStatus.Status), BufferSize, timestamp_elapse(recv_ts, timestamp()));
				}
            } else {
				WDRBD_INFO("RECV(%s) wsk(0x%p) multiWait err(0x%x:%s) size(%lu)\n", thread->comm, WskSocket, Irp->IoStatus.Status, GetSockErrorString(Irp->IoStatus.Status), BufferSize);
				if(Irp->IoStatus.Status) {
                    BytesReceived = -ECONNRESET;
                }
            }
            break;

        case STATUS_WAIT_1:
            BytesReceived = -EINTR;
            break;

        case STATUS_TIMEOUT:
            BytesReceived = -EAGAIN;
            break;

        default:
            BytesReceived = SOCKET_ERROR;
            break;
        }
    } else {
    	Status = Irp->IoStatus.Status;
		if(NT_SUCCESS (Status)) {
			BytesReceived = (LONG) Irp->IoStatus.Information;
		} else {
			switch (Irp->IoStatus.Status) {
			case STATUS_IO_TIMEOUT:
				BytesReceived = -EAGAIN;
				WDRBD_INFO("WskReceive timeout... wsk(0x%p) size(%lu)\n", BufferSize, WskSocket);
				break;
			case STATUS_INVALID_DEVICE_STATE:
			case STATUS_FILE_FORCED_CLOSED:
				BytesReceived = -ECONNRESET;
				WDRBD_INFO("WskReceive invalid WSK Socket state (%s) wsk(0x%p) size(%lu)\n", GetSockErrorString(Irp->IoStatus.Status), WskSocket, BufferSize);
				pSock->sk_state = WSK_INVALID_DEVICE;
				break;	
			default:
				BytesReceived = -ECONNRESET;
				break;
			}
		}
	}

	if (BytesReceived == -EINTR || BytesReceived == -EAGAIN) {
		// cancel irp in wsk subsystem
		IoCancelIrp(Irp);
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		if (Irp->IoStatus.Information > 0) {
			//WDRBD_INFO("rx canceled but rx data(%d) avaliable.\n", Irp->IoStatus.Information);
			BytesReceived = (LONG)Irp->IoStatus.Information;
		}
	}

	IoFreeIrp(Irp);
	FreeWskBuffer(&WskBuffer);

	return BytesReceived;
}


LONG
NTAPI
ReceiveFrom(
	__in struct socket* pSock,
	__out PVOID			Buffer,
	__in  ULONG			BufferSize,
	__out_opt PSOCKADDR	RemoteAddress,
	__out_opt PULONG	ControlFlags
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesReceived = SOCKET_ERROR;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_WskState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
		return SOCKET_ERROR;

	RtlZeroMemory(Buffer, BufferSize);
	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer, TRUE);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		FreeWskBuffer(&WskBuffer);
		return SOCKET_ERROR;
	}

	Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH) WskSocket->Dispatch)->WskReceiveFrom(
		WskSocket,
		&WskBuffer,
		0,
		RemoteAddress,
		0,
		NULL,
		ControlFlags,
		Irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	BytesReceived = NT_SUCCESS(Status) ? (LONG) Irp->IoStatus.Information : SOCKET_ERROR;

	IoFreeIrp(Irp);
	FreeWskBuffer(&WskBuffer);
	return BytesReceived;
}

NTSTATUS
NTAPI
Bind(
	__in struct socket* pSock,
	__in PSOCKADDR		LocalAddress
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_WskState != INITIALIZED || !WskSocket || !LocalAddress)
		return STATUS_INVALID_PARAMETER;

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskBind(
		WskSocket,
		LocalAddress,
		0,
		Irp);

	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}
	IoFreeIrp(Irp);
	return Status;
}

PWSK_SOCKET
NTAPI
Accept(
	__in struct socket* pSock,
	__out_opt PSOCKADDR	LocalAddress,
	__out_opt PSOCKADDR	RemoteAddress,
	__out_opt NTSTATUS* RetStatus,
	__in int			timeout
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
	KEVENT			CompletionEvent = { 0 };
	PIRP			Irp = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	PWSK_SOCKET		AcceptedSocket = NULL;
    struct task_struct *thread = current;
    PVOID waitObjects[2];
    int wObjCount = 1;

	if (g_WskState != INITIALIZED || !WskSocket) {
		*RetStatus = SOCKET_ERROR;
		return NULL;
	}

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		*RetStatus = Status;
		return NULL;
	}

	Status = ((PWSK_PROVIDER_LISTEN_DISPATCH) WskSocket->Dispatch)->WskAccept(
		WskSocket,
		0,
		NULL,
		NULL,
		LocalAddress,
		RemoteAddress,
		Irp);

	if (Status == STATUS_PENDING) {
		LARGE_INTEGER	nWaitTime;
		LARGE_INTEGER	*pTime;

		if (timeout <= 0 || timeout == MAX_SCHEDULE_TIMEOUT) {
			pTime = 0;
		} else {
			nWaitTime = RtlConvertLongToLargeInteger(-1 * timeout * 10000000);
			pTime = &nWaitTime;
		}

        waitObjects[0] = (PVOID) &CompletionEvent;
        if (thread->has_sig_event) {
            waitObjects[1] = (PVOID) &thread->sig_event;
            wObjCount = 2;
        }

        Status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);

		switch (Status) {
			case STATUS_WAIT_0:
				break;

			case STATUS_WAIT_0 + 1:
				IoCancelIrp(Irp);
				KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
				*RetStatus = -EINTR;
				break;

			case STATUS_TIMEOUT:
				IoCancelIrp(Irp);
				KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
				*RetStatus = STATUS_TIMEOUT;
				break;

			default:
				WDRBD_ERROR("Unexpected Error Status=0x%x\n", Status);
				break;
		}
	} else {
		if (Status != STATUS_SUCCESS) {
			WDRBD_TRACE("Accept Error Status=0x%x\n", Status);
		}
	}

	AcceptedSocket = (Status == STATUS_SUCCESS) ? (PWSK_SOCKET) Irp->IoStatus.Information : NULL;
	IoFreeIrp(Irp);
	return AcceptedSocket;
}

NTSTATUS
NTAPI
ControlSocket(
	__in struct socket* pSock,
	__in ULONG			RequestType,
	__in ULONG		    ControlCode,
	__in ULONG			Level,
	__in SIZE_T			InputSize,
	__in_opt PVOID		InputBuffer,
	__in SIZE_T			OutputSize,
	__out_opt PVOID		OutputBuffer,
	__out_opt SIZE_T	*OutputSizeReturned
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_WskState != INITIALIZED || !WskSocket)
		return SOCKET_ERROR;

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		WDRBD_ERROR("InitWskData() failed with status 0x%08X\n", Status);
		return SOCKET_ERROR;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskControlSocket(
				WskSocket,
				RequestType,		// WskSetOption, 
				ControlCode,		// SIO_WSK_QUERY_RECEIVE_BACKLOG, 
				Level,				// IPPROTO_IPV6,
				InputSize,			// sizeof(optionValue),
				InputBuffer,		// NULL, 
				OutputSize,			// sizeof(int), 
				OutputBuffer,		// &backlog, 
				OutputSizeReturned, // NULL,
				Irp);


	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	return Status;
}

NTSTATUS
NTAPI
GetRemoteAddress(
	__in struct socket* pSock,
	__out PSOCKADDR		pRemoteAddress
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	Status = InitWskData(&Irp, &CompletionEvent, FALSE);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskGetRemoteAddress(WskSocket, pRemoteAddress, Irp);
	if (Status != STATUS_SUCCESS) {
		if (Status == STATUS_PENDING) {
			KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
			Status = Irp->IoStatus.Status;
		}

		if (Status != STATUS_SUCCESS) {
			if (Status != STATUS_INVALID_DEVICE_STATE) {
				WDRBD_TRACE("STATUS_INVALID_DEVICE_STATE....\n");
			} else if (Status != STATUS_FILE_FORCED_CLOSED) {
				WDRBD_TRACE("STATUS_FILE_FORCED_CLOSED....\n");
			} else {
				WDRBD_TRACE("Status 0x%x\n", Status);
			}
		}
	}
	
	IoFreeIrp(Irp);
	return Status;
}


NTSTATUS
InitWskEvent()
{
    NTSTATUS status;
    WSK_CLIENT_NPI  wskClientNpi;

    wskClientNpi.ClientContext = NULL;
    wskClientNpi.Dispatch = &g_WskDispatch;
    
    status = WskRegister(&wskClientNpi, &gWskEventRegistration);
    if (!NT_SUCCESS(status)) {
        WDRBD_ERROR("Failed to WskRegister(). status(0x%x)\n", status);
        return status;
    }

    status = WskCaptureProviderNPI(&gWskEventRegistration,
        WSK_INFINITE_WAIT, &gWskEventProviderNPI);
	
	if (!NT_SUCCESS(status)) {
        WDRBD_ERROR("Failed to WskCaptureProviderNPI(). status(0x%x)\n", status);
        WskDeregister(&gWskEventRegistration);
        return status;
    }
	//WDRBD_INFO("WskProvider Version Major:%d Minor:%d\n",WSK_MAJOR_VERSION(gWskEventProviderNPI.Dispatch->Version),WSK_MINOR_VERSION(gWskEventProviderNPI.Dispatch->Version));
    return status;
}

PWSK_SOCKET
CreateEventSocket(
__in ADDRESS_FAMILY	AddressFamily,
__in USHORT			SocketType,
__in ULONG			Protocol,
__in ULONG			Flags
)
{
    KEVENT			CompletionEvent = {0};
    PIRP			irp = NULL;
    PWSK_SOCKET		socket = NULL;
    NTSTATUS		status;

    status = InitWskData(&irp, &CompletionEvent, FALSE);
    if (!NT_SUCCESS(status)) {
        return NULL;
    }

    WSK_EVENT_CALLBACK_CONTROL callbackControl;

    callbackControl.NpiId = (PNPIID)&NPI_WSK_INTERFACE_ID;
    callbackControl.EventMask = WSK_EVENT_ACCEPT;

    status = gWskEventProviderNPI.Dispatch->WskControlClient(
        gWskEventProviderNPI.Client,
        WSK_SET_STATIC_EVENT_CALLBACKS,
        sizeof(callbackControl),
        &callbackControl,
        0,
        NULL,
        NULL,
        NULL);
    if (!NT_SUCCESS(status)) {
        IoFreeIrp(irp);
        WDRBD_ERROR("Failed to WskControlClient(). status(0x%x)\n", status);
        return NULL;
    }

    status = gWskEventProviderNPI.Dispatch->WskSocket(
        gWskEventProviderNPI.Client,
        AddressFamily,
        SocketType,
        Protocol,
        Flags,
        NULL,
        &ClientListenDispatch,
        NULL,
        NULL,
        NULL,
        irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }

    if (NT_SUCCESS(status)) {
        socket = (PWSK_SOCKET)irp->IoStatus.Information;
    } else {
        WDRBD_ERROR("Failed to WskSocket(). status(0x%x)\n", status);
    }

    IoFreeIrp(irp);

    return (PWSK_SOCKET)socket;
}

NTSTATUS
CloseEventSocket()
{
    KEVENT		CompletionEvent = {0};
    PIRP		irp = NULL;
	NTSTATUS 	status = STATUS_UNSUCCESSFUL;
	
	if (!gpNetlinkServerSocket->sk) {
        return status;
    }
		
    status = InitWskData(&irp, &CompletionEvent, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ((PWSK_PROVIDER_BASIC_DISPATCH)gpNetlinkServerSocket->sk->Dispatch)->WskCloseSocket(gpNetlinkServerSocket->sk, irp);
    if (STATUS_PENDING == status) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }

    IoFreeIrp(irp);

    WskDeregister(&gWskEventRegistration);

    return status;
}


void
ReleaseProviderNPI()
{
    WskReleaseProviderNPI(&gWskEventRegistration);
}


NTSTATUS
NTAPI
SetEventCallbacks(
	__in struct socket* pSock,
	__in LONG			mask
)
{
	PWSK_SOCKET		WskSocket = pSock->sk;
    KEVENT			CompletionEvent = { 0 };
    PIRP			Irp = NULL;
    NTSTATUS		Status = STATUS_UNSUCCESSFUL;

    if (g_WskState != INITIALIZED || !WskSocket) {
        return Status;
    }

    Status = InitWskData(&Irp, &CompletionEvent,FALSE);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    WSK_EVENT_CALLBACK_CONTROL callbackControl;
    callbackControl.NpiId = &NPI_WSK_INTERFACE_ID;

    // Set the event flags for the event callback functions that
    // are to be enabled on the socket
    callbackControl.EventMask = mask;

    // Initiate the control operation on the socket
    Status =
        ((PWSK_PROVIDER_BASIC_DISPATCH)WskSocket->Dispatch)->WskControlSocket(
        WskSocket,
        WskSetOption,
        SO_WSK_EVENT_CALLBACK,
        SOL_SOCKET,
        sizeof(WSK_EVENT_CALLBACK_CONTROL),
        &callbackControl,
        0,
        NULL,
        NULL,
        Irp
        );

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        Status = Irp->IoStatus.Status;
    }

    IoFreeIrp(Irp);
    return Status;
}

NTSTATUS WSKAPI
AcceptEvent(
_In_  PVOID         SocketContext,
_In_  ULONG         Flags,
_In_  PSOCKADDR     LocalAddress,
_In_  PSOCKADDR     RemoteAddress,
_In_opt_  PWSK_SOCKET AcceptSocket,
_Outptr_result_maybenull_ PVOID *AcceptSocketContext,
_Outptr_result_maybenull_ CONST WSK_CLIENT_CONNECTION_DISPATCH **AcceptSocketDispatch
)
{
	UNREFERENCED_PARAMETER(AcceptSocketContext);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(RemoteAddress);
	UNREFERENCED_PARAMETER(AcceptSocketDispatch);
	UNREFERENCED_PARAMETER(LocalAddress);

    // Check for a valid new socket
    if (AcceptSocket != NULL) {
        WDRBD_INFO("incoming connection on a listening socket.\n");
        struct accept_wait_data *ad = (struct accept_wait_data*)SocketContext;        
        ad->s_accept = kzalloc(sizeof(struct socket), 0, '89DW');
        if(!ad->s_accept) {
        	return STATUS_REQUEST_NOT_ACCEPTED;
        }
        ad->s_accept->sk = AcceptSocket;
		_snprintf(ad->s_accept->name, sizeof(ad->s_accept->name) - 1, "estab_sock");
        ad->s_accept->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '92DW');
        if (!ad->s_accept->sk_linux_attr) {
            ExFreePool(ad->s_accept);
            return STATUS_REQUEST_NOT_ACCEPTED;
        }

        complete(&ad->door_bell);
        return STATUS_SUCCESS;
    } else {
    	// Error with listening socket
        return STATUS_REQUEST_NOT_ACCEPTED;
    }
}


#ifdef _WSK_SOCKET_STATE 
NTSTATUS WskDisconnectEvent(
	_In_opt_ PVOID SocketContext,
	_In_     ULONG Flags
	)
{
	if (SocketContext == NULL)
		return STATUS_UNSUCCESSFUL;

	UNREFERENCED_PARAMETER(Flags);
	
	WDRBD_CONN_TRACE("WskDisconnectEvent\n");
	struct socket *sock = (struct socket *)SocketContext; 
	WDRBD_CONN_TRACE("socket->sk = %p\n", sock->sk);
	sock->sk_state = WSK_DISCONNECTED;
	return STATUS_SUCCESS;
}
#endif

