
#include "drbd_windows.h"
#include "wsk2.h"
enum
{
	DEINITIALIZED,
	DEINITIALIZING,
	INITIALIZING,
	INITIALIZED
};

WSK_REGISTRATION			g_WskRegistration;
static WSK_PROVIDER_NPI		g_WskProvider;
static WSK_CLIENT_DISPATCH	g_WskDispatch = { MAKE_WSK_VERSION(1, 0), 0, NULL };
static LONG					g_SocketsState = DEINITIALIZED;

NTSTATUS
NTAPI CompletionRoutine(
	__in PDEVICE_OBJECT	DeviceObject,
	__in PIRP			Irp,
	__in PKEVENT		CompletionEvent
)
{
	ASSERT(CompletionEvent);
	KeSetEvent(CompletionEvent, IO_NO_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
InitWskData(
	__out PIRP*		pIrp,
	__out PKEVENT	CompletionEvent
)
{
	ASSERT(pIrp);
	ASSERT(CompletionEvent);

	*pIrp = IoAllocateIrp(1, FALSE);
	if (!*pIrp)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(CompletionEvent, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(*pIrp, CompletionRoutine, CompletionEvent, TRUE, TRUE, TRUE);

	return STATUS_SUCCESS;
}

VOID
ReInitWskData(
__out PIRP*		pIrp,
__out PKEVENT	CompletionEvent
)
{
	ASSERT(pIrp);
	ASSERT(CompletionEvent);

	KeResetEvent(CompletionEvent);
	IoReuseIrp(*pIrp, STATUS_UNSUCCESSFUL);
	IoSetCompletionRoutine(*pIrp, CompletionRoutine, CompletionEvent, TRUE, TRUE, TRUE);

	return;
}
NTSTATUS
InitWskBuffer(
	__in  PVOID		Buffer,
	__in  ULONG		BufferSize,
	__out PWSK_BUF	WskBuffer
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
	    MmProbeAndLockPages(WskBuffer->Mdl, KernelMode, IoWriteAccess);
    } except(EXCEPTION_EXECUTE_HANDLER) {
        if (WskBuffer->Mdl != NULL) {
            IoFreeMdl(WskBuffer->Mdl);
        }
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

NTSTATUS NTAPI SocketsInit()
{
	WSK_CLIENT_NPI	WskClient = { 0 };
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	if (InterlockedCompareExchange(&g_SocketsState, INITIALIZING, DEINITIALIZED) != DEINITIALIZED)
		return STATUS_ALREADY_REGISTERED;

	WskClient.ClientContext = NULL;
	WskClient.Dispatch = &g_WskDispatch;

	Status = WskRegister(&WskClient, &g_WskRegistration);
	if (!NT_SUCCESS(Status)) {
		InterlockedExchange(&g_SocketsState, DEINITIALIZED);
		return Status;
	}

	WDRBD_INFO("WskCaptureProviderNPI start.\n");
	Status = WskCaptureProviderNPI(&g_WskRegistration, WSK_INFINITE_WAIT, &g_WskProvider);
	WDRBD_INFO("WskCaptureProviderNPI done.\n"); // takes long time! msg out after MVL loaded.

	if (!NT_SUCCESS(Status)) {
		WDRBD_ERROR("WskCaptureProviderNPI() failed with status 0x%08X\n", Status);
		WskDeregister(&g_WskRegistration);
		InterlockedExchange(&g_SocketsState, DEINITIALIZED);
		return Status;
	}

	InterlockedExchange(&g_SocketsState, INITIALIZED);
	return STATUS_SUCCESS;
}

//
// Library deinitialization routine
//

VOID NTAPI SocketsDeinit()
{
	if (InterlockedCompareExchange(&g_SocketsState, INITIALIZED, DEINITIALIZING) != INITIALIZED)
		return;
	WskReleaseProviderNPI(&g_WskRegistration);
	WskDeregister(&g_WskRegistration);

	InterlockedExchange(&g_SocketsState, DEINITIALIZED);
}

PWSK_SOCKET
NTAPI
CreateSocket(
	__in ADDRESS_FAMILY	AddressFamily,
	__in USHORT			SocketType,
	__in ULONG			Protocol,
#ifdef WSK_ACCEPT_EVENT_CALLBACK
    __in PVOID          *SocketContext,
    __in PWSK_CLIENT_LISTEN_DISPATCH Dispatch,
#endif
	__in ULONG			Flags
)
{
	KEVENT			CompletionEvent = { 0 };
	PIRP			Irp = NULL;
	PWSK_SOCKET		WskSocket = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED)
	{
		return NULL;
	}

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}

	Status = g_WskProvider.Dispatch->WskSocket(
				g_WskProvider.Client,
				AddressFamily,
				SocketType,
				Protocol,
				Flags,
#ifdef WSK_ACCEPT_EVENT_CALLBACK
                SocketContext,
                Dispatch,
#else
				NULL,
				NULL,
#endif
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

NTSTATUS
NTAPI
CloseSocket(
	__in PWSK_SOCKET WskSocket
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED || !WskSocket)
		return STATUS_INVALID_PARAMETER;

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Status = ((PWSK_PROVIDER_BASIC_DISPATCH) WskSocket->Dispatch)->WskCloseSocket(WskSocket, Irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}
	IoFreeIrp(Irp);
	return Status;
}

NTSTATUS
NTAPI
Connect(
	__in PWSK_SOCKET	WskSocket,
	__in PSOCKADDR		RemoteAddress
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !RemoteAddress)
		return STATUS_INVALID_PARAMETER;

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskConnect(
		WskSocket,
		RemoteAddress,
		0,
		Irp);

	if (Status == STATUS_PENDING) {
		LARGE_INTEGER	nWaitTime;
		nWaitTime = RtlConvertLongToLargeInteger(-1 * 1000 * 1000 * 10);
		if ((Status = KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, &nWaitTime)) == STATUS_TIMEOUT)
		{
			IoCancelIrp(Irp);
			KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		}
	}

	if (Status == STATUS_SUCCESS)
	{
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	return Status;
}

NTSTATUS NTAPI
Disconnect(
	__in PWSK_SOCKET	WskSocket
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED || !WskSocket)
		return STATUS_INVALID_PARAMETER;

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskDisconnect(
		WskSocket,
		NULL,
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
SocketConnect(
	__in USHORT		SocketType,
	__in ULONG		Protocol,
	__in PSOCKADDR	RemoteAddress,
	__in PSOCKADDR	LocalAddress
)
{
	KEVENT			CompletionEvent = { 0 };
	PIRP			Irp = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	PWSK_SOCKET		WskSocket = NULL;

	if (g_SocketsState != INITIALIZED || !RemoteAddress || !LocalAddress)
		return NULL;

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}

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

	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	WskSocket = NT_SUCCESS(Status) ? (PWSK_SOCKET) Irp->IoStatus.Information : NULL;
	IoFreeIrp(Irp);
	return WskSocket;
}

char *GetSockErrorString(NTSTATUS status)
{
	char *ErrorString;
	//DRBC_CHECK_WSK; 정리!
	switch (status)
	{
		case STATUS_CONNECTION_RESET:
			ErrorString = "CONNECTION_RESET";
			break;
		case STATUS_CONNECTION_DISCONNECTED:
			ErrorString = "CONNECTION_DISCONNECTED";
			break;
		case STATUS_CONNECTION_ABORTED:
			ErrorString = "CONNECTION_ABORTED";
			break;
		case STATUS_IO_TIMEOUT:
			ErrorString = "IO_TIMEOUT";
			break;
		case STATUS_INVALID_DEVICE_STATE:
			ErrorString = "INVALID_DEVICE_STATE";
			break;
		default:
			ErrorString = "SOCKET_IO_ERROR";
			break;
	}
	return ErrorString;
}

#ifdef _WIN32_SEND_BUFFING
LONG
NTAPI
Send(
	__in PWSK_SOCKET	WskSocket,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout,
	__in KEVENT			*send_buf_kill_event
)
#else
LONG
NTAPI
Send(
	__in PWSK_SOCKET	WskSocket,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout,
	__in KEVENT			*send_buf_kill_event,
	__in struct			drbd_transport *transport,
	__in enum			drbd_stream stream
)
#endif
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesSent = SOCKET_ERROR; // DRBC_CHECK_WSK: SOCKET_ERROR be mixed EINVAL?
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	//DbgPrint("DRBD_TEST:(%s)Tx: sz=%d to=%d\n", current->comm, BufferSize, Timeout); // _WIN32_V9_TEST

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || ((int) BufferSize <= 0))
		return SOCKET_ERROR;

	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent);
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

	if (Status == STATUS_PENDING)
	{
		LARGE_INTEGER	nWaitTime;
		LARGE_INTEGER	*pTime;

		int retry_count = 0;
	retry:
		if (Timeout <= 0 || Timeout == MAX_SCHEDULE_TIMEOUT)
		{
			pTime = NULL;
		}
		else
		{
			nWaitTime = RtlConvertLongToLargeInteger(-1 * Timeout * 1000 * 10);
			pTime = &nWaitTime;
		}
		{
			struct      task_struct *thread = current;
			PVOID       waitObjects[2];
			int         wObjCount = 1;

			waitObjects[0] = (PVOID) &CompletionEvent;
#ifndef _WIN32_SEND_BUFFING // WIN32_V9_REFACTO_: JHKIM: 입력인자 축소와 로그메세지 축소관련하여 추가 리팩토링 필요.
			if (thread->has_sig_event)
			{
				waitObjects[1] = (PVOID) &thread->sig_event;
				wObjCount = 2; // DRBD_DOC_V9:JHKIM: down 같은 CLI에서 요청될 때는 has_sig_event 가 없다. 이때는 wObjCount가 1 임.
			}
#else
			if (send_buf_kill_event)
			{
				waitObjects[1] = (PVOID) send_buf_kill_event; // DRBD_DOC_V9:JHKIM: 송신버퍼링에서 송출 도중에 kill 요청을 인지하는 방법임. thread->has_sig_event를 이용한 일관성있는 중지신호 수신방안이 필요(리팩토링 필요)
				wObjCount = 2;
			}
#endif
			Status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);
			switch (Status)
			{
			case STATUS_TIMEOUT:
#ifdef _WIN32_SEND_BUFFING
				if (wObjCount == 2)
				{
					retry_count++;
					WDRBD_WARN("(%s) sent timeout=%d sz=%d retry_count=%d WskSocket=%p IRP=%p\n",
						current->comm, Timeout, BufferSize, retry_count,WskSocket, Irp);

					// WIN32_DOC: IRP free 관계로 함수를 벗어나지 못하고 이곳에서 재시도.
					// 무한대기. 중단 여부는 상위레벨 BAB overflow 에서 처리. 
					// _WIN32_V9 포팅 후 안정화뒤 제거

					goto retry;
				}
				else
				{
					WDRBD_WARN("(%s) send buffering! Not reached!?\n");
					BUG(); // _WIN32_V9 포팅 후 안정화뒤 제거
				}
#else
				// WIN32_DOC: IRP free 관계로 함수를 벗어나지 못하고 이곳에서 재시도.
				// WIN32_V9 포팅 시 송신버퍼링이 기본이되고 이 부분은 단지 시험용.(internal used only)
				if (transport != NULL)
				{
					extern bool drbd_stream_send_timed_out(struct drbd_transport *transport, enum drbd_stream stream);
					if (!drbd_stream_send_timed_out(transport, stream))
					{
						goto retry;
					}
				}
#endif
				BytesSent = -EAGAIN;
				break;

			case STATUS_WAIT_0:
				if (NT_SUCCESS(Irp->IoStatus.Status))
				{
					BytesSent = (LONG)Irp->IoStatus.Information;
				}
				else
				{
					WDRBD_WARN("tx error(%s)\n", GetSockErrorString(Irp->IoStatus.Status));
					switch (Irp->IoStatus.Status)
					{
						case STATUS_IO_TIMEOUT:
							BytesSent = -EAGAIN;
							break;
						case STATUS_INVALID_DEVICE_STATE:
							BytesSent = -EAGAIN;
							break;
						default:
							BytesSent = -ECONNRESET;
							break;
					}
				}
				break;

			case STATUS_WAIT_0 + 1:// common: sender or send_bufferinf thread's kill signal
				BytesSent = -EINTR;
				WDRBD_WARN("signal occured.\n");
				break;

			default:
				WDRBD_ERROR("Wait failed. status 0x%x\n", Status);
				BytesSent = SOCKET_ERROR;
			}
		}
	}
	else
	{
		if (Status == STATUS_SUCCESS)
		{
			BytesSent = (LONG) Irp->IoStatus.Information;
			WDRBD_WARN("(%s) WskSend No pending: but sent(%d)!\n", current->comm, BytesSent);
		}
		else
		{
			WDRBD_WARN("(%s) WskSend error(0x%x)\n", current->comm, Status);
			BytesSent = SOCKET_ERROR;
		}
	}

	if (BytesSent == -EINTR || BytesSent == -EAGAIN)
	{
		IoCancelIrp(Irp);
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
	}

	IoFreeIrp(Irp);
	FreeWskBuffer(&WskBuffer);

	//DbgPrint("DRBD_TEST:(%s)Tx: done. ret=%d\n", current->comm, BytesSent); // _WIN32_V9_TEST
	return BytesSent;
}

// _WIN32_V9: _WIN32_SEND_BUFFING NEW!
LONG
NTAPI
SendLocal(
	__in PWSK_SOCKET	WskSocket,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesSent = SOCKET_ERROR;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	//DbgPrint("DRBD_TEST: SendLocal!! (%s)Tx: sz=%d to=%d\n", current->comm, BufferSize, Timeout); // _WIN32_V9_TEST

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || ((int) BufferSize <= 0))
		return SOCKET_ERROR;

	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent);
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

	if (Status == STATUS_PENDING)
	{
		LARGE_INTEGER	nWaitTime;
		LARGE_INTEGER	*pTime;

		if (Timeout <= 0 || Timeout == MAX_SCHEDULE_TIMEOUT)
		{
			pTime = NULL;
		}
		else
		{
			nWaitTime = RtlConvertLongToLargeInteger(-1 * Timeout * 1000 * 10);
			pTime = &nWaitTime;
		}
		Status = KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, pTime);

		switch (Status)
		{
		case STATUS_TIMEOUT:
			//IoCancelIrp(Irp);
			//KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
			BytesSent = -EAGAIN;
			break;

		case STATUS_WAIT_0:
			if (NT_SUCCESS(Irp->IoStatus.Status))
			{
				BytesSent = (LONG) Irp->IoStatus.Information;
			}
			else
			{
				WDRBD_WARN("(%s) sent error(%s)\n", current->comm, GetSockErrorString(Irp->IoStatus.Status));
				switch (Irp->IoStatus.Status)
				{
				case STATUS_IO_TIMEOUT:
					BytesSent = -EAGAIN;
					break;
				case STATUS_INVALID_DEVICE_STATE:
					BytesSent = -EAGAIN;
					break;
				default:
					BytesSent = -ECONNRESET;
					break;
				}
			}
			break;

		default:
			WDRBD_ERROR("KeWaitForSingleObject failed. status 0x%x\n", Status);
			BytesSent = SOCKET_ERROR;
		}
	}
	else
	{
		if (Status == STATUS_SUCCESS)
		{
			BytesSent = (LONG) Irp->IoStatus.Information;
			WDRBD_WARN("(%s) WskSend No pending: but sent(%d)!\n", current->comm, BytesSent);
		}
		else
		{
			WDRBD_WARN("(%s) WskSend error(0x%x)\n", current->comm, Status);
			BytesSent = SOCKET_ERROR;
		}
	}

	IoFreeIrp(Irp);
	FreeWskBuffer(&WskBuffer);
	//DbgPrint("DRBD_TEST:(%s)Tx: done. ret=%d\n", current->comm, BytesSent); // _WIN32_V9_TEST
	return BytesSent;
}

LONG
NTAPI
SendTo(
	__in PWSK_SOCKET	WskSocket,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in_opt PSOCKADDR	RemoteAddress
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesSent = SOCKET_ERROR;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
		return SOCKET_ERROR;

	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent);
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
	__in  PWSK_SOCKET	WskSocket,
	__out PVOID			Buffer,
	__in  ULONG			BufferSize,
	__in  ULONG			Flags,
	__in ULONG			Timeout
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesReceived = SOCKET_ERROR;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

    struct      task_struct *thread = current;
    PVOID       waitObjects[2];
    int         wObjCount = 1;

	//DbgPrint("DRBD_TEST:(%s)Rx: sz=%d to=%d\n", current->comm, BufferSize, Timeout);

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
		return SOCKET_ERROR;

	if ((int) BufferSize <= 0)
	{
		return SOCKET_ERROR;
	}

	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent);

	if (!NT_SUCCESS(Status)) {
		FreeWskBuffer(&WskBuffer);
		return SOCKET_ERROR;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskReceive(
				WskSocket,
				&WskBuffer,
				Flags,
				Irp);

    if (Status == STATUS_PENDING)
    {
        LARGE_INTEGER	nWaitTime;
        LARGE_INTEGER	*pTime;

        if (Timeout <= 0 || Timeout == MAX_SCHEDULE_TIMEOUT)
        {
            pTime = 0;
        }
        else
        {
            nWaitTime = RtlConvertLongToLargeInteger(-1 * Timeout * 1000 * 10);
            pTime = &nWaitTime;
        }

        waitObjects[0] = (PVOID) &CompletionEvent;
        if (thread->has_sig_event)
        {
            waitObjects[1] = (PVOID) &thread->sig_event;
            wObjCount = 2;
        }
        Status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);
        switch (Status)
        {
        case STATUS_WAIT_0: // waitObjects[0] CompletionEvent
            if (Irp->IoStatus.Status == STATUS_SUCCESS)
            {
                BytesReceived = (LONG) Irp->IoStatus.Information;
            }
            else
            {
                WDRBD_INFO("RECV(%s) multiWait err(0x%x:%s)\n", thread->comm, Irp->IoStatus.Status, GetSockErrorString(Irp->IoStatus.Status));
                switch (Irp->IoStatus.Status)
                {
                case STATUS_IO_TIMEOUT:
                    BytesReceived = -EAGAIN; // possiable???
                    break;
                default:
                    BytesReceived = -ECONNRESET;
                    break;
                }
            }
            break;

        case STATUS_WAIT_0 + 1:
            BytesReceived = -EINTR;
            break;

        case STATUS_TIMEOUT:
            BytesReceived = -EAGAIN;
            break;

        default:
            BytesReceived = SOCKET_ERROR;
            break;
        }
    }
	else
	{
		if (Status == STATUS_SUCCESS)
		{
			BytesReceived = (LONG) Irp->IoStatus.Information;
			WDRBD_INFO("(%s) Rx No pending and data(%d) is avail\n", current->comm, BytesReceived);
		}
		else
		{
			WDRBD_TRACE("WskReceive Error Status=0x%x\n", Status); // EVENT_LOG!
		}
	}

	if (BytesReceived == -EINTR || BytesReceived == -EAGAIN)
	{
		// cancel irp in wsk subsystem
		IoCancelIrp(Irp);
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		if (Irp->IoStatus.Information > 0)
		{
			WDRBD_INFO("rx canceled but rx data(%d) avaliable.\n", Irp->IoStatus.Information);
			BytesReceived = Irp->IoStatus.Information;
		}
	}

	IoFreeIrp(Irp);
	FreeWskBuffer(&WskBuffer);
	//DbgPrint("DRBD_TEST:(%s)Rx: done. ret=%d\n", current->comm, BytesReceived); // _WIN32_V9_TEST
	return BytesReceived;
}

LONG
NTAPI
ReceiveFrom(
	__in  PWSK_SOCKET	WskSocket,
	__out PVOID			Buffer,
	__in  ULONG			BufferSize,
	__out_opt PSOCKADDR	RemoteAddress,
	__out_opt PULONG	ControlFlags
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	WSK_BUF		WskBuffer = { 0 };
	LONG		BytesReceived = SOCKET_ERROR;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
		return SOCKET_ERROR;

	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent);
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
	__in PWSK_SOCKET	WskSocket,
	__in PSOCKADDR		LocalAddress
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED || !WskSocket || !LocalAddress)
		return STATUS_INVALID_PARAMETER;

	Status = InitWskData(&Irp, &CompletionEvent);
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
	__in PWSK_SOCKET	WskSocket,
	__out_opt PSOCKADDR	LocalAddress,
	__out_opt PSOCKADDR	RemoteAddress,
	__out_opt NTSTATUS	*RetStaus,
	__in int			timeout
)
{
	KEVENT			CompletionEvent = { 0 };
	PIRP			Irp = NULL;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	PWSK_SOCKET		AcceptedSocket = NULL;
    struct task_struct *thread = current;
    PVOID waitObjects[2];
    int wObjCount = 1;

	if (g_SocketsState != INITIALIZED || !WskSocket)
	{
		*RetStaus = SOCKET_ERROR;
		return NULL;
	}

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status)) {
		*RetStaus = Status;
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

	if (Status == STATUS_PENDING)
	{
		LARGE_INTEGER	nWaitTime;
		LARGE_INTEGER	*pTime;

		if (timeout <= 0 || timeout == MAX_SCHEDULE_TIMEOUT)
		{
			pTime = 0;
		}
		else
		{
			nWaitTime = RtlConvertLongToLargeInteger(-1 * timeout * 10000000);
			pTime = &nWaitTime;
		}

        waitObjects[0] = (PVOID) &CompletionEvent;
        if (thread->has_sig_event)
        {
            waitObjects[1] = (PVOID) &thread->sig_event;
            wObjCount = 2;
        }

        Status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);

		switch (Status)
		{
			case STATUS_WAIT_0:
				break;

			case STATUS_WAIT_0 + 1:
				IoCancelIrp(Irp);
				KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
				*RetStaus = -EINTR;	
				break;

			case STATUS_TIMEOUT:
				IoCancelIrp(Irp);
				KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
				*RetStaus = STATUS_TIMEOUT;
				break;

			default:
				WDRBD_ERROR("Unexpected Error Status=0x%x\n", Status); // EVENT_LOG!
				break;
		}
	}
	else
	{
		if (Status != STATUS_SUCCESS)
		{
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
	__in PWSK_SOCKET	WskSocket,
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
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	if (g_SocketsState != INITIALIZED || !WskSocket)
		return SOCKET_ERROR;

	Status = InitWskData(&Irp, &CompletionEvent);
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
	__in PWSK_SOCKET	WskSocket,
	__out PSOCKADDR	pRemoteAddress
)
{
	KEVENT		CompletionEvent = { 0 };
	PIRP		Irp = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status)) {
		return SOCKET_ERROR;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH) WskSocket->Dispatch)->WskGetRemoteAddress(WskSocket, pRemoteAddress, Irp);
	if (Status != STATUS_SUCCESS)
	{
		if (Status == STATUS_PENDING) {
			KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
			Status = Irp->IoStatus.Status;
		}

		if (Status != STATUS_SUCCESS)
		{
			if (Status != STATUS_INVALID_DEVICE_STATE)
			{
				WDRBD_TRACE("STATUS_INVALID_DEVICE_STATE....\n");
			}
			else if (Status != STATUS_FILE_FORCED_CLOSED)
			{
				WDRBD_TRACE("STATUS_FILE_FORCED_CLOSED....\n");
			}
			else
			{
				WDRBD_TRACE("0x%x....\n", Status);
			}
		}
	}
	IoFreeIrp(Irp);
	return Status;
}

WSK_REGISTRATION    gWskEventRegistration;
WSK_PROVIDER_NPI    gWskEventProviderNPI;
PWSK_SOCKET         netlink_server_socket = NULL;

// Socket-level callback table for listening sockets
const WSK_CLIENT_LISTEN_DISPATCH ClientListenDispatch = {
    NetlinkAcceptEvent,
    NULL, // WskInspectEvent is required only if conditional-accept is used.
    NULL  // WskAbortEvent is required only if conditional-accept is used.
};

NTSTATUS
InitWskEvent()
{
    NTSTATUS status;
    WSK_CLIENT_NPI  wskClientNpi;

    wskClientNpi.ClientContext = NULL;
    wskClientNpi.Dispatch = &g_WskDispatch;
    
    status = WskRegister(&wskClientNpi, &gWskEventRegistration);
    if (!NT_SUCCESS(status))
    {
        WDRBD_ERROR("Failed to WskRegister(). status(0x%x)\n", status);
        return status;
    }

    status = WskCaptureProviderNPI(&gWskEventRegistration,
        WSK_INFINITE_WAIT, &gWskEventProviderNPI);
    if (!NT_SUCCESS(status))
    {
        WDRBD_ERROR("Failed to WskCaptureProviderNPI(). status(0x%x)\n", status);
        WskDeregister(&gWskEventRegistration);
        return status;
    }

    return status;
}

PWSK_SOCKET
CreateSocketEvent(
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

    status = InitWskData(&irp, &CompletionEvent);
    if (!NT_SUCCESS(status))
    {
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
    if (!NT_SUCCESS(status))
    {
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
    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }

    if (NT_SUCCESS(status))
    {
        socket = (PWSK_SOCKET)irp->IoStatus.Information;
    }
    else
    {
        WDRBD_ERROR("Failed to WskSocket(). status(0x%x)\n", status);
    }

    IoFreeIrp(irp);

    return (PWSK_SOCKET)socket;
}

NTSTATUS
CloseWskEventSocket()
{
    if (!netlink_server_socket)
    {
        return STATUS_SUCCESS;
    }

    KEVENT		CompletionEvent = {0};
    PIRP		irp = NULL;

    NTSTATUS status = InitWskData(&irp, &CompletionEvent);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ((PWSK_PROVIDER_BASIC_DISPATCH)netlink_server_socket->Dispatch)->WskCloseSocket(netlink_server_socket, irp);
    if (STATUS_PENDING == status)
    {
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

#ifdef WSK_ACCEPT_EVENT_CALLBACK
NTSTATUS
NTAPI
SetEventCallbacks(
__in PWSK_SOCKET Socket,
__in LONG			mask
)
{
    KEVENT			CompletionEvent = { 0 };
    PIRP			Irp = NULL;
    PWSK_SOCKET		WskSocket = NULL;
    NTSTATUS		Status = STATUS_UNSUCCESSFUL;

    if (g_SocketsState != INITIALIZED)
    {
        return Status;
    }

    Status = InitWskData(&Irp, &CompletionEvent);
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
        ((PWSK_PROVIDER_BASIC_DISPATCH)Socket->Dispatch)->WskControlSocket(
        Socket,
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
    UNREFERENCED_PARAMETER(Flags);
    // Check for a valid new socket
    if (AcceptSocket != NULL)
    {
        WDRBD_INFO("incoming connection on a listening socket.\n");
        struct accept_wait_data *ad = (struct accept_wait_data*)SocketContext;        
        ad->s_accept = kzalloc(sizeof(struct socket), 0, '89DW');
        ad->s_accept->sk = AcceptSocket;
        sprintf(ad->s_accept->name, "estab_sock");
        ad->s_accept->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '92DW');
        if (!ad->s_accept->sk_linux_attr)
        {
            ExFreePool(ad->s_accept);
            return STATUS_REQUEST_NOT_ACCEPTED;
        }

        complete(&ad->door_bell);
        return STATUS_SUCCESS;
    }
    // Error with listening socket
    else
    {
        return STATUS_REQUEST_NOT_ACCEPTED;
    }
}
#endif
