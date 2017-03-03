
#ifndef __DRBDLOCK_PCH_H_
#define __DRBDLOCK_PCH_H_

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")
#pragma warning(disable: 4127)

#include <FltKernel.h>
#include <ntstrsafe.h>
#include <dontuse.h>
#include <suppress.h>
#include "drbdlock.h"
#include "drbdlock_struct.h"
#include "drbdlock_comm.h"
#include "drbdlock_proc.h"
#include "volBlock.h"

#endif