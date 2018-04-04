

NTSTATUS
drbdlockCreateControlDeviceObject(
	IN PDRIVER_OBJECT pDrvObj
	);

VOID
drbdlockDeleteControlDeviceObject(
	VOID
	);

VOID
drbdlockCallbackFunc(
	IN PVOID Context,
	IN PVOID Argument1,
	IN PVOID Argument2
	);

NTSTATUS
drbdlockStartupCallback(
	VOID
	);

VOID
drbdlockCleanupCallback(
	VOID
	);

NTSTATUS
DefaultIrpDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
	);

NTSTATUS
DeviceIoControlDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
	);

NTSTATUS 
ResizeDrbdVolume(
	PDEVICE_OBJECT pDeviceObject
	);


