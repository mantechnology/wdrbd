

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
	PVOID pFltVolume
	);

BOOLEAN
DeleteProtectedVolume(
	PVOID pFltVolume
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
