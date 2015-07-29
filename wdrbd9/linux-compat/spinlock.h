#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__
#include <wdm.h>

typedef struct _tagSPINLOCK
{
    KSPIN_LOCK spinLock;
    KIRQL saved_oldIrql;
} spinlock_t, rwlock_t;

#endif