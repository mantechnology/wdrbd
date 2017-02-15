

NTSTATUS
drbdlockCreateControlDeviceObject(
	IN PDRIVER_OBJECT pDrvObj
	);

VOID
drbdlockDeleteControlDeviceObject(
	VOID
	);

NTSTATUS
DefaultIrpDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
	);