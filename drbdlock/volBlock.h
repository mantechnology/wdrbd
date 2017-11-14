

VOID
InitVolBlock(
	VOID
	);

VOID
CleanupVolBlock(
	VOID
	);

BOOLEAN
AddProtectedVolume(
	PVOID pVolumeObject
	);

BOOLEAN
DeleteProtectedVolume(
	PVOID pVolumeObject
	);

BOOLEAN
isProtectedVolume(
	IN PVOID pVolume
	);

NTSTATUS
ConvertVolume(
	IN PDRBDLOCK_VOLUME pVolumeInfo,
	OUT PDEVICE_OBJECT *pConverted
	);
