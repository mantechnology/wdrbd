#pragma once
#include <ntddk.h>
#include <wsk.h>

#define SOCKET_ERROR -1

enum
{
	DEINITIALIZED,
	DEINITIALIZING,
	INITIALIZING,
	INITIALIZED
};

NTSTATUS NTAPI WskGetNPI();
VOID NTAPI WskPutNPI();

NTSTATUS
InitWskBuffer(
	__in  PVOID		Buffer,
	__in  ULONG		BufferSize,
	__out PWSK_BUF	WskBuffer,
	__in  BOOLEAN	bWriteAccess
	);

NTSTATUS
InitWskData(
	__out PIRP*		pIrp,
	__out PKEVENT	CompletionEvent,
	__in  BOOLEAN	bRawIrp
	);

NTSTATUS 
InitWskDataAsync(
	__out PIRP*		pIrp,
	__in  BOOLEAN	bRawIrp
	);

VOID
FreeWskBuffer(
	__in PWSK_BUF WskBuffer
	);

VOID
FreeWskData(
	__in PIRP pIrp
	);

PWSK_SOCKET
NTAPI
CreateSocket(
    __in ADDRESS_FAMILY	AddressFamily,
    __in USHORT			SocketType,
    __in ULONG			Protocol,
    __in PVOID          *SocketContext,
    __in PWSK_CLIENT_LISTEN_DISPATCH Dispatch,
    __in ULONG			Flags
    );

NTSTATUS
NTAPI
CloseSocket(
	__in struct socket* pSock
	);

NTSTATUS
NTAPI
Connect(
	__in struct socket* pSock,
	__in PSOCKADDR		RemoteAddress
	);

extern
NTSTATUS NTAPI
Disconnect(
	__in struct socket* pSock
	);

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
);
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
);
#endif 


LONG 
NTAPI
Send(
	__in struct socket* pSock,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout,
	__in KEVENT			*send_buf_kill_event,
	__in struct			drbd_transport *transport,
	__in enum			drbd_stream stream
	);

LONG
NTAPI
SendAsync(
	__in struct socket* pSock,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout,
	__in struct			drbd_transport *transport,
	__in enum			drbd_stream stream
);

LONG
NTAPI
SendLocal(
	__in struct socket* pSock,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout
);

LONG
NTAPI
SendTo(
	__in struct socket* pSock,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in_opt PSOCKADDR	RemoteAddress
	);

LONG
NTAPI
Receive(
	__in struct socket* pSock,
	__out PVOID			Buffer,
	__in  ULONG			BufferSize,
	__in  ULONG			Flags,
	__in ULONG			Timeout
	);

LONG
NTAPI
ReceiveFrom(
	__in struct socket* pSock,
	__out PVOID			Buffer,
	__in  ULONG			BufferSize,
	__out_opt PSOCKADDR	RemoteAddress,
	__out_opt PULONG	ControlFlags
	);

NTSTATUS
NTAPI
Bind(
	__in struct socket* pSock,
	__in PSOCKADDR		LocalAddress
	);

PWSK_SOCKET
NTAPI
Accept(
	__in struct socket* pSock,
	__out_opt PSOCKADDR	LocalAddress,
	__out_opt PSOCKADDR	RemoteAddress,
	__out_opt PNTSTATUS		Error,
	__in int					timeout
   );

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
	);

NTSTATUS
NTAPI
GetRemoteAddress(
	__in struct socket* pSock,
	__out PSOCKADDR	pRemoteAddress
	);

#define HTONS(n)		(((((unsigned short)(n) & 0xFFu  )) << 8) | \
				(((unsigned short) (n) & 0xFF00u) >> 8))

#define TC_PRIO_INTERACTIVE_BULK	1
#define TC_PRIO_INTERACTIVE		1

extern void sock_release(void  *sock);

#define HTON_SHORT(n) (((((unsigned short)(n) & 0xFFu  )) << 8) | \
    (((unsigned short)(n)& 0xFF00u) >> 8))

extern struct socket* gpNetlinkServerSocket;

extern
NTSTATUS InitWskEvent();

extern
PWSK_SOCKET CreateEventSocket(
__in ADDRESS_FAMILY	AddressFamily,
__in USHORT			SocketType,
__in ULONG			Protocol,
__in ULONG			Flags
);

extern
NTSTATUS CloseEventSocket();

extern
void ReleaseProviderNPI();

extern
NTSTATUS
NTAPI
SetEventCallbacks(
	__in struct socket* pSock,
	__in LONG			mask
	);

extern
NTSTATUS WSKAPI
AcceptEvent(
_In_  PVOID         SocketContext,
_In_  ULONG         Flags,
_In_  PSOCKADDR     LocalAddress,
_In_  PSOCKADDR     RemoteAddress,
_In_opt_  PWSK_SOCKET AcceptSocket,
_Outptr_result_maybenull_ PVOID *AcceptSocketContext,
_Outptr_result_maybenull_ CONST WSK_CLIENT_CONNECTION_DISPATCH **AcceptSocketDispatch
);

char *GetSockErrorString(NTSTATUS status);


#ifdef _WSK_SOCKET_STATE 

NTSTATUS WskDisconnectEvent(
	_In_opt_ PVOID SocketContext,
	_In_     ULONG Flags
	);
#endif

