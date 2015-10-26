#ifndef __JIFFIES_H__
#define __JIFFIES_H__

__inline unsigned int jiffies_to_msecs(const ULONG_PTR j)
{
#ifdef _WIN32_XXX
	// JHKIM: jiffies_to_msecs 포팅 및 ULONG_PTR 적용확인 // 입력이 이미 milisec 임으로 그대로 리턴하면 됨. 정상.
#else
    return j;
#endif
}

#endif