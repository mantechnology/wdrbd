#ifndef __MVOL_H__
#define __MVOL_H__

#include "ioctl.h"


DWORD MVOL_GetVolumeInfo( CHAR DriveLetter, PMVOL_VOLUME_INFO pVolumeInfo );
DWORD MVOL_InitThread( PWCHAR PhysicalVolume );
/**
 *      @brief  볼륨 I/O를 처리하는 쓰레드를 생성한다.
 *      @param  DriveLetter [in]    Local drive letter(ex C, D, E, ...)
 *      @return 함수가 성공하면 ERROR_SUCCESS를 반환하고 실패하면 GetLastError()의
 *              값을 반환한다.
 */
DWORD MVOL_InitThread( CHAR DriveLetter );
DWORD MVOL_CloseThread( PWCHAR PhysicalVolume );
/**
 *      @brief  볼륨 I/O를 처리하는 쓰레드를 종료한다.
 *      @param  DriveLetter [in]    Local drive letter(ex C, D, E, ...)
 *      @return 함수가 성공하면 ERROR_SUCCESS를 반환하고 실패하면 GetLastError()의
 *              값을 반환한다.
 */
DWORD MVOL_CloseThread( CHAR DriveLetter );
DWORD MVOL_StartVolume( PWCHAR PhysicalVolume );
/**
 *      @brief  볼륨을 활성화한다.
 *      @param  DriveLetter [in]    Local drive letter(ex C, D, E, ...)
 *      @return 함수가 성공하면 ERROR_SUCCESS를 반환하고 실패하면 GetLastError()의
 *              값을 반환한다.
 */
DWORD MVOL_StartVolume( CHAR DriveLetter );
DWORD MVOL_StopVolume( PWCHAR PhysicalVolume );
/**
 *      @brief  볼륨을 비활성화한다.
 *      @param  DriveLetter [in]    Local drive letter(ex C, D, E, ...)
 *      @return 함수가 성공하면 ERROR_SUCCESS를 반환하고 실패하면 GetLastError()의
 *              값을 반환한다.
 */
DWORD MVOL_StopVolume( CHAR DriveLetter );
DWORD MVOL_GetVolumeSize( PWCHAR PhysicalVolume, PLARGE_INTEGER pVolumeSize );
/**
 *      @brief  DRBD의 상태 정보를 가져온다. 리눅스의 cat /proc/drbd와 동일한 내용을
 *              표시한다.
 *      @param  VolumeInfo [out]    DRBD의 상태 정보를 받는 버퍼
 *      @return 함수가 성공하면 ERROR_SUCCESS를 반환하고 실패하면 GetLastError()의
 *              값을 반환한다.
 */
DWORD MVOL_GetStatus( PMVOL_VOLUME_INFO VolumeInfo );
DWORD MVOL_set_ioctl(PWCHAR PhysicalVolume, DWORD code, MVOL_VOLUME_INFO *volumeInfo);
/**
 *      @brief  nagle 설정을 위해 레지스트리 값을 변경한다.
 *      @param  ResourceName [in]   nagle 속성을 설정할 리소스 이름
 *      @param  arg [in]            nagle 설정 값 (disable or enable)
 *      @return 함수가 성공하면 ERROR_SUCCESS를 반환하고 실패하면 GetLastError()의
 *              값을 반환한다.
*/
DWORD MVOL_SetNagle(CHAR *ResourceName, CHAR *arg);


/**
*      @brief  볼륨을 mount 한다.
*      @param  driveletter [in] Local drive letter(ex C, D, E, ...)
*      @return 함수가 성공하면 ERROR_SUCCESS를 반환하고 실패하면 GetLastError()의
*              값을 반환한다.
*/
DWORD MVOL_MountVolume(char drive_letter);

/**
 *      @brief  볼륨을 dismount 한다.
 *      @param  driveletter [in] Local drive letter(ex C, D, E, ...)
 *      @param  Force [in] true or false
 *              true -  FSCTL_DISMOUNT_VOLUME
 *              false - FSCTL_LOCK_VOLUME -> FSCTL_DISMOUNT_VOLUME -> FSCTL_UNLOCK_VOLUME
 *      @return 함수가 성공하면 ERROR_SUCCESS를 반환하고 실패하면 GetLastError()의
 *              값을 반환한다.
 */
DWORD MVOL_DismountVolume(CHAR DriveLetter, int Force);

#endif __MVOL_H__
