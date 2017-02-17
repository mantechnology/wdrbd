

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
	PFLT_VOLUME pFltVolume
	);

BOOLEAN
DeleteProtectedVolume(
	PFLT_VOLUME pFltVolume
	);

BOOLEAN
isProtectedVolume(
	IN PFLT_VOLUME pVolume
	);

NTSTATUS
ConvertVolume(
	IN PDRBDLOCK_VOLUME pVolumeInfo,
	OUT PFLT_VOLUME *pConverted
	);
