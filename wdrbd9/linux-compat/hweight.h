#ifndef __HWEIGHT_H__
#define __HWEIGHT_H__
#include "windows/types.h"

extern unsigned int hweight32(unsigned int w);
extern unsigned int hweight16(unsigned int w);
extern unsigned int hweight8(unsigned int w);
extern unsigned long hweight64(__u64 w);

#endif
