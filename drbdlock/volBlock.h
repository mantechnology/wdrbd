

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