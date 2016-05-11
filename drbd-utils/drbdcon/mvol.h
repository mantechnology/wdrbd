#ifndef __MVOL_H__
#define __MVOL_H__

#include "ioctl.h"


DWORD MVOL_GetVolumeInfo( CHAR DriveLetter, PMVOL_VOLUME_INFO pVolumeInfo );
DWORD MVOL_InitThread( PWCHAR PhysicalVolume );
/**
 *      @brief  Create a thread processing a volume I/O
 *      @param  DriveLetter [in]    Local drive letter(ex C, D, E, ...)
 *      @return if it success, return ERROR_SUCCESS, if failed, return value is GetLastError()'s return
 */
DWORD MVOL_InitThread( CHAR DriveLetter );
DWORD MVOL_CloseThread( PWCHAR PhysicalVolume );
/**
 *      @brief  close a thread processing a volume I/O
 *      @param  DriveLetter [in]    Local drive letter(ex C, D, E, ...)
 *      @return if it success, return ERROR_SUCCESS, if failed, return value is GetLastError()'s return
 */
DWORD MVOL_CloseThread( CHAR DriveLetter );
DWORD MVOL_StartVolume( PWCHAR PhysicalVolume );
/**
 *      @brief  enable a volume
 *      @param  DriveLetter [in]    Local drive letter(ex C, D, E, ...)
 *      @return if it success, return ERROR_SUCCESS, if failed, return value is GetLastError()'s return
 */
DWORD MVOL_StartVolume( CHAR DriveLetter );
DWORD MVOL_StopVolume( PWCHAR PhysicalVolume );
/**
 *      @brief  disable a volume
 *      @param  DriveLetter [in]    Local drive letter(ex C, D, E, ...)
 *      @return if it success, return ERROR_SUCCESS, if failed, return value is GetLastError()'s return
 */
DWORD MVOL_StopVolume( CHAR DriveLetter );
DWORD MVOL_GetVolumeSize( PWCHAR PhysicalVolume, PLARGE_INTEGER pVolumeSize );
/**
 *      @brief  get drbd's status inforamtion 
 *      @param  VolumeInfo [out]    status Info buffer 
 *      @return if it success, return ERROR_SUCCESS, if failed, return value is GetLastError()'s return
 */
DWORD MVOL_GetStatus( PMVOL_VOLUME_INFO VolumeInfo );
DWORD MVOL_set_ioctl(PWCHAR PhysicalVolume, DWORD code, MVOL_VOLUME_INFO *volumeInfo);
/**
 *      @brief  change regisrty settings about nagle 
 *      @param  ResourceName [in]   resource name 
 *      @param  arg [in]            disable or enable
 *      @return if it success, return ERROR_SUCCESS, if failed, return value is GetLastError()'s return
 */
DWORD MVOL_SetNagle(CHAR *ResourceName, CHAR *arg);


/**
*      @brief  mount a volume
*      @param  driveletter [in] Local drive letter(ex C, D, E, ...)
*      @return if it success, return ERROR_SUCCESS, if failed, return value is GetLastError()'s return
*/
DWORD MVOL_MountVolume(char drive_letter);

/**
 *      @brief  dismount a volume
 *      @param  driveletter [in] Local drive letter(ex C, D, E, ...)
 *      @param  Force [in] true or false
 *              true -  FSCTL_DISMOUNT_VOLUME
 *              false - FSCTL_LOCK_VOLUME -> FSCTL_DISMOUNT_VOLUME -> FSCTL_UNLOCK_VOLUME
 *      @return if it success, return ERROR_SUCCESS, if failed, return value is GetLastError()'s return
 */
DWORD MVOL_DismountVolume(CHAR DriveLetter, int Force);

#endif __MVOL_H__
