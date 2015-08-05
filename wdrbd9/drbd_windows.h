#ifndef DRBD_WINDOWS_H
#define DRBD_WINDOWS_H


#include <windows.h>
#include <stdio.h>
//#include <stdbool.h>
//#include "windows/types.h"

//#define _WIN32_SEND_BUFFING	// V9 포팅을 위해 임시 제거. // BAB 송신버퍼링 사용. cygwin 빌드시 사용. 최종 안정화 후 제거
#define _WIN32_MVFL

#define pid_t				int
#define false				FALSE
#define true				TRUE

#define DRBD_EVENT_SOCKET_STRING	"DRBD_EVENTS"

#ifdef x64                  // for x64 app build(make x64=1)
#define BITS_PER_LONG		64
#else
#define BITS_PER_LONG		32
#endif



#define strdupa				strdup

#define BUG_ON(cond)				\
	do {							\
		int __cond = (cond);		\
		if (!__cond)				\
			break;					\
		fprintf(stderr, "BUG: %s:%d: %s == %u\n",	\
			__FILE__, __LINE__,	\
			#cond, __cond);		\
		abort();					\
	} while (0)


#endif // DRBD_WINDOWS_H
