#ifndef __JIFFIES_H__
#define __JIFFIES_H__

__inline unsigned int jiffies_to_msecs(const unsigned long j)
{
#ifdef _WIN32_CHECK 
	// JHKIM: jiffies_to_msecs 포팅 및 ULONG_PTR 적용확인
#else
    return 0;
#endif
}

#endif