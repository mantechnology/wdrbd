#include <stdint.h>
#include <stdarg.h>
#include <intrin.h>
#include <ntifs.h>
#include "drbd_windows.h"
#include "wsk2.h"
#include "drbd_wingenl.h"
#include "linux-compat/idr.h"
#include "drbd_wrappers.h"
#include "disp.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, do_add_minor)
#endif

int g_bypass_level;
int g_read_filter;
int g_use_volume_lock;
int g_netlink_tcp_port;
int g_daemon_tcp_port;
WCHAR g_ver[64];

/// SEO: from idr.c of LINUX 3.15
#define MAX_IDR_SHIFT		(sizeof(int) * 8 - 1)
#define MAX_IDR_BIT		(1U << MAX_IDR_SHIFT)

/* Leave the possibility of an incomplete final layer */
#define MAX_IDR_LEVEL ((MAX_IDR_SHIFT + IDR_BITS - 1) / IDR_BITS)

/* Number of id_layer structs to leave in free list */
#define MAX_IDR_FREE (MAX_IDR_LEVEL * 2)


//__ffs - find first bit in word.
ULONG_PTR __ffs(ULONG_PTR word) 
{
	int num = 0;

#if BITS_PER_LONG == 64
	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
#endif
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

#define ffz(x)  __ffs(~(x))

int fls(int x)
{
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

#define BITOP_WORD(nr)          ((nr) / BITS_PER_LONG)

#ifdef _WIN32_V9
ULONG_PTR find_first_bit(const ULONG_PTR* addr, ULONG_PTR size)
{
	const ULONG_PTR* p = addr;
	ULONG_PTR result = 0;
	ULONG_PTR tmp;

	while (size & ~(BITS_PER_LONG - 1)) {
		if ((tmp = *(p++)))
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
#ifdef _WIN64
	tmp = (*p) & (~0ULL >> (BITS_PER_LONG - size));
	if (tmp == 0ULL)	{	/* Are any bits set? */
#else
	tmp = (*p) & (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)	{	/* Are any bits set? */
#endif
		return result + size;	/* Nope. */
	}
found:
	return result + __ffs(tmp);
}
#endif

#pragma warning ( disable : 4706 )
ULONG_PTR find_next_bit(const ULONG_PTR *addr, ULONG_PTR size, ULONG_PTR offset)
{
	const ULONG_PTR *p = addr + BITOP_WORD(offset);
	ULONG_PTR result = offset & ~(BITS_PER_LONG - 1);
	ULONG_PTR tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
#ifdef _WIN64
		tmp &= (~0ULL << offset);
#else
		tmp &= (~0UL << offset);
#endif
		if (size < BITS_PER_LONG)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG - 1)) {
		if ((tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
#ifdef _WIN64
	tmp &= (~0ULL >> (BITS_PER_LONG - size));
	if (tmp == 0ULL)	/* Are any bits set? */
#else
	tmp &= (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)		/* Are any bits set? */
#endif
		return result + size;	/* Nope. */
found_middle:
	return result + __ffs(tmp);
}



const char _zb_findmap [] = {
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,6,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,5,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,7,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 8 };

static inline ULONG_PTR __ffz_word(ULONG_PTR nr, ULONG_PTR word)
 {
 #ifdef _WIN64
    if ((word & 0xffffffff) == 0xffffffff) {
            word >>= 32;
            nr += 32;
    }
 #endif
    if ((word & 0xffff) == 0xffff) {
            word >>= 16;
            nr += 16;
    }
    if ((word & 0xff) == 0xff) {
            word >>= 8;
            nr += 8;
    }
	return nr + _zb_findmap[(unsigned char) word];
 }
 /*
 * Find the first cleared bit in a memory region.
 */
ULONG_PTR find_first_zero_bit(const ULONG_PTR *addr, ULONG_PTR size)
 {
	const ULONG_PTR *p = addr;
	ULONG_PTR result = 0;
	ULONG_PTR tmp;

	 while (size & ~(BITS_PER_LONG - 1)) {
		 if (~(tmp = *(p++)))
			 goto found;
		 result += BITS_PER_LONG;
		 size -= BITS_PER_LONG;
	 }
	 if (!size)
		 return result;

#ifdef _WIN64
	 tmp = (*p) | (~0ULL << size);
	 if (tmp == ~0ULL)        /* Are any bits zero? */
#else
	 tmp = (*p) | (~0UL << size);
	 if (tmp == ~0UL)        /* Are any bits zero? */
#endif
		 return result + size;        /* Nope. */
 found:
	 return result + ffz(tmp);
 }

int find_next_zero_bit(const ULONG_PTR * addr, ULONG_PTR size, ULONG_PTR offset)
{
	const ULONG_PTR *p;
	ULONG_PTR bit, set;
 
    if (offset >= size)
            return size;
    bit = offset & (BITS_PER_LONG - 1);
    offset -= bit;
    size -= offset;
    p = addr + offset / BITS_PER_LONG;
    if (bit) {
        /*
        * __ffz_word returns BITS_PER_LONG
        * if no zero bit is present in the word.
        */
        set = __ffz_word(bit, *p >> bit);
        if (set >= size)
                return size + offset;
        if (set < BITS_PER_LONG)
                return set + offset;
        offset += BITS_PER_LONG;
        size -= BITS_PER_LONG;
        p++;
    }

    return offset + find_first_zero_bit(p, size);
 }

static int g_test_and_change_bit_flag = 0;
static spinlock_t g_test_and_change_bit_lock;

int test_and_change_bit(int nr, const ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr);
	ULONG_PTR old;
	ULONG_PTR flags;

	if (!g_test_and_change_bit_flag)
	{
		spin_lock_init(&g_test_and_change_bit_lock);
		g_test_and_change_bit_flag = 1;
	}

	spin_lock_irq(&g_test_and_change_bit_lock);
	old = *p;
	*p = old ^ mask;
	spin_unlock_irq(&g_test_and_change_bit_lock);

    return (old & mask) != 0;
}

void atomic_set(const atomic_t *v, int i)
{
	InterlockedExchange(v, i);
}

void atomic_add(int i, atomic_t *v)
{
	InterlockedExchangeAdd(v, i);
}

void atomic_sub(int i, atomic_t *v)
{
	atomic_sub_return(i, v);
}

int atomic_sub_return(int i, atomic_t *v)
{
	int retval;
	retval = InterlockedExchangeAdd(v, -i);
	retval -= i;
	return retval;
}

int atomic_dec_and_test(atomic_t *v)
{
	return (0 == InterlockedDecrement(v));
}

int atomic_sub_and_test(int i, atomic_t *v)
{
	int retval;
	retval = InterlockedExchangeAdd(v, -i);
	retval -= i;
	return (retval == 0);
}

long atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return InterlockedCompareExchange(v, new, old);
}

int atomic_xchg(atomic_t *v, int n)
{
	return InterlockedExchange(v, n);
}

int atomic_read(const atomic_t *v)
{
	return InterlockedAnd((atomic_t *)v, 0xffffffff);
}

void * kmalloc(int size, int flag, ULONG Tag)
{
	return kcalloc(1, size, flag, Tag);
}

void * kcalloc(int size, int count, int flag, ULONG Tag)
{
	return kzalloc(size * count, 0, Tag);
}

void * kzalloc(int size, int flag, ULONG Tag)
{
	void *mem;
    static int fail_count = 0; // DV

retry: // DV
	mem = ExAllocatePoolWithTag(NonPagedPool, size, Tag);
	if (!mem)
	{
        WDRBD_WARN("kzalloc: no memory! fail_count=%d\n", fail_count); 
        // DV TEST시 빈도가 높으면 제거! 
        // 현재 Win7 64에서 시험중 간헐적으로 출력되며 
        // 출력이 되는 경우에는 3회 정도 연속 출력이 됨(한 번에 3회 실패를 연속적으로 발생시키는 듯) 
        // 따라서 출력이 문제가 안됨으로 본격 DV 시험 전까지 유지

        if (!(fail_count++ % 100)) // For DV TEST
        {
            WDRBD_ERROR("kzalloc: no memory! Retry! fail_count=%d\n", fail_count);
            //EVENTLOG!!!
            // DV: 09.24 현재 DV로 검출된 메모리 부족시 부적절한 대응로직은 
            // DRBD_DV1으로 마킹된 2곳 이며 이 곳에서 반드시 메모리의 성공적인 할당을 원한다.
            // 해당 2곳에서 실패를 대비한 로직을 보강하면 되지만 로직 구조상 오류 처리가 어려워 이 곳에서 단순 처리함.
            // 이 방식이 부적절해 보이나 일단 이 방법으로 DV 시험을 회피하고 
            // DV 를 통해 더 많은 메모리 부족 오류를 검출한 후에
            // 문제되는 소스들을 변경하여 이 무한 룹 로직을 제거하는 것이 적절함.
        }
        // 고려사항: sleep 필요? 단일 cpu 인 경우 정상 동작확인
        goto retry;
	}

	RtlZeroMemory(mem, size);
	return mem;
}

char *kstrdup(const char *s, int gfp)
{
	size_t len;
	char *buf;

	if (!s)
		return NULL;

	len = strlen(s) + 1;
	buf = kzalloc(len, gfp, 'C3DW');
	if (buf)
		memcpy(buf, s, len);
	return buf;
}

void *page_address(const struct page *page)
{
	return page->addr;
}

struct page  *alloc_page(int flag)
{
	struct page *p = kmalloc(sizeof(struct page),0, 'D3DW'); 
	if (!p)
	{
		WDRBD_ERROR("malloc failed\n");
		return 0;
	}	

	p->addr = kzalloc(PAGE_SIZE, 0, 'E3DW');
	return p;
}

void __free_page(const struct page *page)
{
	kfree(page->addr);
	kfree(page); 
}

void * kmem_cache_alloc(struct kmem_cache *cache, int flag, ULONG Tag)
{
	return kzalloc(cache->size, flag, Tag); 
}

void kmem_cache_free(struct kmem_cache *cache, void * x)
{
	kfree(x);
}

void drbd_bp(char *msg)
{
    WDRBD_ERROR("breakpoint: msg(%s)\n", msg);
}

__inline void kfree(void * x)
{
	if (x)
	{
		ExFreePool(x);
	}
}

mempool_t *mempool_create(int min_nr, void *alloc_fn, void *free_fn, void *pool_data)
{
	mempool_t *p_pool;
	if (!pool_data)
	{
		return 0;
	}
	p_pool = kmalloc(sizeof(mempool_t), 0, 'F3DW');
	if (!p_pool)
	{
		return 0;
	}
	p_pool->p_cache = pool_data; // 사용 측에서 캐시 크기를 참고하기 위함
	p_pool->page_alloc = 0; // 페이지 단위로 할당여부 플래그
	return p_pool;
}

mempool_t *mempool_create_page_pool(int min_nr, int order)
{
	mempool_t *p_pool = kmalloc(sizeof(mempool_t), 0, '04DW');
	if (!p_pool)
	{
		return 0;
	}
	p_pool->page_alloc = 1; 
	return p_pool; 
}
#ifndef _WIN32_CHECK
mempool_t *mempool_create_slab_pool(int min_nr, int order)
{
	mempool_t *p_pool = kmalloc(sizeof(mempool_t), 0, '04DW');
	if (!p_pool)
	{
		return 0;
	}
	p_pool->page_alloc = 1; 
	return p_pool; 
}
#endif
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data)
{
	return 1; // skip error!
}

void *mempool_free_slab(gfp_t gfp_mask, void *pool_data)
{
	return 1; // skip error!
}

void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
{
	void *p;

	if (pool->page_alloc)
	{
		p = alloc_page(0);
	}
	else
	{
		p = kzalloc(pool->p_cache->size, gfp_mask, '14DW');
	}
	if (!p)
	{
		WDRBD_ERROR("kmalloc failed");
	}

	return p;
}

void mempool_free(void *p, mempool_t *mempool)
{
	if (mempool->page_alloc)
	{
		kfree(p);
	}
	else
	{
		kfree(p);
	}
}

void mempool_destroy(void *p)
{

}

void kmem_cache_destroy(struct kmem_cache *s)
{
	kfree(s);
	s = 0;
}

struct kmem_cache *kmem_cache_create(char *name, size_t size, size_t align,
                  unsigned long flags, void (*ctor)(void *), ULONG Tag)
{
	struct kmem_cache *p = kmalloc(sizeof(struct kmem_cache), 0, Tag);	
	if (!p)
	{
		WDRBD_ERROR("kzalloc failed\n");
		return 0;
	}
	p->size = size;
	p->name = name;
	return p;
}

// _WIN32_V9
// kmpak 이 부분은 linux 2.6.32 에서 가져왔다.
// linux 3.x 이후에는 이부분 내용이 kref_sub로 옮겨가서 kref_sub에서 처리해주는데
// drbd 9 오리지널에서는 linux 커널 버전별 차이를 맞춰주기 위해 kref_sub를 새로 정의해준다.
// 하지만 wdrbd에서는 그럴 필요없이 kref_put 에서 처리해준다.
int kref_put(struct kref *kref, void (*release)(struct kref *kref))
{
#ifdef _WIN32_V9
    WARN_ON(release == NULL);
    WARN_ON(release == (void (*)(struct kref *))kfree);

    if (atomic_dec_and_test(&kref->refcount))
    {
        release(kref);
        return 1;
    }
    return 0;// V9에서는 리턴을 사용함. 적절한 리턴값 확보 필요!
#else
	kref_sub(kref, 1, release); //_WIN32_CHECK
#endif
}

int kref_get(struct kref *kref)
{
	return atomic_inc_return(&kref->refcount) < 2;
}

void kref_init(struct kref *kref)
{
	atomic_set(&kref->refcount, 1);
}

struct request_queue *bdev_get_queue(struct block_device *bdev)
{
      return bdev->bd_disk->queue;
 }

// bio_alloc_bioset 는 리눅스 커널 API. 이 구조체는 코드 유지를 위해서 존재함
#pragma warning ( disable : 4716 )
struct bio *bio_alloc_bioset(gfp_t gfp_mask, int nr_iovecs, struct bio_set *bs)
{
}

struct bio *bio_alloc(gfp_t gfp_mask, int nr_iovecs, ULONG Tag)
{
	struct bio *bio;
	bio = kzalloc(sizeof(struct bio) + nr_iovecs * sizeof(struct bio_vec), gfp_mask, Tag);
	if (!bio)
	{
		return 0;
	}
	bio->bi_max_vecs = nr_iovecs;
	bio->bi_vcnt = 0;

	if (nr_iovecs > 256)
	{
		WDRBD_ERROR("DRBD_PANIC: bio_alloc: nr_iovecs too big = %d. check over 1MB.\n", nr_iovecs);
		BUG();
	}
	return bio;
}

void bio_put(struct bio *bio) 
{
	bio_free(bio);
}

void bio_free(struct bio *bio) 
{
	kfree(bio);
}

void submit_bio(int rw, struct bio *bio)
{
	bio->bi_rw |= rw; 
	generic_make_request(bio);
}

void bio_endio(struct bio *bio, int error)
{
	if (bio->bi_end_io)
	{
        WDRBD_INFO("thread(%s) bio_endio fault test with err=%d.\n", current->comm, error);
        bio->bi_end_io((void*)FAULT_TEST_FLAG, (void*) bio, (void*) error);
	}
}

struct bio *bio_clone(struct bio * bio_src, int flag)
{
    struct bio *bio = bio_alloc(flag, bio_src->bi_max_vecs, '24DW');

    if (!bio)
    {
        return NULL;
    }

	memcpy(bio->bi_io_vec, bio_src->bi_io_vec, bio_src->bi_max_vecs * sizeof(struct bio_vec));
	bio->bi_sector = bio_src->bi_sector;
	bio->bi_bdev = bio_src->bi_bdev;
	//bio->bi_flags |= 1 << BIO_CLONED;
	bio->bi_rw = bio_src->bi_rw;
	bio->bi_vcnt = bio_src->bi_vcnt;
	bio->bi_size = bio_src->bi_size;
	bio->bi_idx = bio_src->bi_idx;

	return bio;
}


int bio_add_page(struct bio *bio, struct page *page, unsigned int len,unsigned int offset)
{
	struct bio_vec *bvec = &bio->bi_io_vec[bio->bi_vcnt++]; //DRBD_DOC: 순차적 증가
		
	if (bio->bi_vcnt > 1)
	{
		WDRBD_ERROR("DRBD_PANIC: bio->bi_vcn=%d. multi page occured!\n", bio->bi_vcnt);
        BUG();
	}

	bvec->bv_page = page;
	bvec->bv_len = len;
	bvec->bv_offset = offset;
	bio->bi_size += len;

	return len;
}

#include "drbd_int.h"

union drbd_state g_mask_null; 
union drbd_state g_val_null;

union drbd_state ns_mask(union drbd_state prev, int bitpos, int mask, int val)
{
	prev.i |= (mask << bitpos);
	return prev;
}

union drbd_state ns_val(union drbd_state prev, int bitpos, int mask, int val)
{
	prev.i |= (val << bitpos);
	return prev;
}

union drbd_state ns2_val1(struct drbd_conf *mdev, int bitpos, int mask, int s)
{
	union drbd_state __ns;
	//__ns = drbd_read_state(mdev); //_WIN32_CHECK drbd_read_state 메소드 없어짐
	__ns.i &= ~(mask << bitpos);
	__ns.i |= (s << bitpos);
	return __ns;
}

union drbd_state ns2_val2(struct drbd_conf *mdev, int bitpos1, int mask1, int s1, int bitpos2, int mask2, int s2)
{
	union drbd_state __ns;
	//__ns = drbd_read_state(mdev); //_WIN32_CHECK drbd_read_state 메소드 없어짐
	__ns.i &= ~(mask1 << bitpos1);
	__ns.i |= (s1 << bitpos1);
	__ns.i &= ~(mask2 << bitpos2);
	__ns.i |= (s2 << bitpos2);
	return __ns;
}

long IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long) ptr); 
}

void *ERR_PTR(long error)
{
	return (void *) error;
}

long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

int IS_ERR(void *ptr)
{
	return IS_ERR_VALUE((unsigned long) ptr);
}

#ifdef _WIN32_CT
void wake_up_process(struct drbd_thread *thi)
{
    KeSetEvent(&thi->wait_event, 0, FALSE);
}
#else
int wake_up_process(struct task_struct *nt)
{
	KeWaitForSingleObject(&nt->start_event, Executive, KernelMode, FALSE, NULL);
	KeSetEvent(&nt->wait_event, 0, FALSE); 
}
#endif

void _wake_up(wait_queue_head_t *q, char *__func, int __line)
{		
    KeSetEvent(&q->wqh_event, 0, FALSE);
}

void init_completion(struct completion *completion)
{
	memset(completion->wait.eventName, 0, Q_NAME_SZ);
	strcpy(completion->wait.eventName, "completion");
	init_waitqueue_head(&completion->wait);
}

long wait_for_completion(struct completion *completion)
{
	return schedule(&completion->wait, MAX_SCHEDULE_TIMEOUT, __FUNCTION__, __LINE__);
}
#ifdef WSK_ACCEPT_EVENT_CALLBACK
long wait_for_completion_timeout(struct completion *completion, long timeout)
{
    return schedule(&completion->wait, timeout, __FUNCTION__, __LINE__);
}
#endif

void complete(struct completion *c)
{
    KeSetEvent(&c->wait.wqh_event, 0, FALSE);
}

void complete_all(struct completion *c)
{
    KeSetEvent(&c->wait.wqh_event, 0, FALSE);
}

static  void __add_wait_queue(wait_queue_head_t *head, wait_queue_t *new)
{
	list_add(&new->task_list, &head->task_list);
}

long schedule(wait_queue_head_t *q, long timeout, char *func, int line) 
{
	LARGE_INTEGER nWaitTime;
	LARGE_INTEGER *pTime;
	unsigned long expire;

	expire = timeout + jiffies;
	nWaitTime.QuadPart = 0;

	if(timeout != MAX_SCHEDULE_TIMEOUT)
	{
		nWaitTime = RtlConvertLongToLargeInteger((timeout) * (-1 * 1000 * 10));
	}
	else
	{
		// DRBD_DOC: wait cycle
		nWaitTime = RtlConvertLongToLargeInteger((60) * (-1 * 10000000));
	}
	pTime = &nWaitTime;

	//WDRBD_INFO("thread(%s) from(%s:%d): start. req timeout=%d(0x%x) nWaitTime=0x%llx(0x%x %d : 0x%x %d) with q=%s -------!!!!!!!\n",
	//	current->comm, func, line, timeout, timeout, nWaitTime.QuadPart,  nWaitTime.HighPart, nWaitTime.HighPart, nWaitTime.LowPart, nWaitTime.LowPart, q ? q->eventName : "no-queue");

	if ((q == NULL) || (q == SCHED_Q_INTERRUPTIBLE))
	{
		KTIMER ktimer;
		KeInitializeTimer(&ktimer);
		KeSetTimerEx(&ktimer, nWaitTime, 0, NULL);
		KeWaitForSingleObject(&ktimer, Executive, KernelMode, FALSE, NULL);
	}
	else
	{
		NTSTATUS status;
		PVOID waitObjects[2];
		struct task_struct *thread = current;

        int wObjCount = 1;

        waitObjects[0] = (PVOID) &q->wqh_event;
        if (thread->has_sig_event)
        {
            waitObjects[1] = (PVOID) &thread->sig_event;
            wObjCount = 2;
        }

        while (1)
        {
            status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);

            switch (status) {
            case STATUS_WAIT_0:
                KeResetEvent(&q->wqh_event); // DW-105: 이벤트/폴링 혼용. 리셋으로 시그널 분실시 1ms 타임아웃으로 보상
                break;

            case STATUS_WAIT_1:
                if (thread->sig == DRBD_SIGKILL)
                {
                    return -DRBD_SIGKILL;
                }
                break;

            case STATUS_TIMEOUT:
                if (timeout == MAX_SCHEDULE_TIMEOUT)
                {
                     continue;
                }
                break;

            default:
                WDRBD_ERROR("DRBD_PANIC: KeWaitForMultipleObjects done! default status=0x%x\n", status);
                BUG();
                break;
            }
            break;
        }
	}

	timeout = expire - jiffies;
	return timeout < 0 ? 0 : timeout;
}
#ifdef _WIN32_V9
bool queue_work(struct workqueue_struct* queue, struct work_struct* work)
#else
void queue_work(struct workqueue_struct* queue, struct work_struct* work)
#endif
{
	KeSetEvent(&queue->wakeupEvent, 0, FALSE); // send to run_singlethread_workqueue
#ifdef _WIN32_V9
	return TRUE; // queue work 방식이 Event 방식으로 구현되었기 때문에... 단순히 return TRUE 한다.
#else
	return;
#endif
}

void run_singlethread_workqueue(struct submit_worker *workq)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID waitObjects[2];
	int maxObj = 2;
	int loop = 0; 

#ifdef _WIN32_CT
    workq->thi.task = ct_add_thread(KeGetCurrentThread(), workq->wq->name, FALSE, '34DW');
    if (!workq->thi.task)
    {
        WDRBD_ERROR("DRBD_PANIC: ct_add_thread failed.\n");
        return;
    }

    KeSetEvent(&workq->thi.start_event, 0, FALSE);
    KeWaitForSingleObject(&workq->thi.wait_event, Executive, KernelMode, FALSE, NULL);

#else
	workq->task.current_thr = KeGetCurrentThread(); 
	workq->task.pid = workq->task.current_thr;
	sprintf(workq->task.comm, "%s\0", workq->wq->name); 
#endif
    
	waitObjects[0] = &workq->wq->wakeupEvent;
	waitObjects[1] = &workq->wq->killEvent;

	while (workq->wq->run == TRUE)
	{
		loop++;

		status = KeWaitForMultipleObjects(maxObj, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, NULL, NULL); 
		switch (status) 
		{
		case STATUS_TIMEOUT:
			continue;

		case STATUS_WAIT_0:
			if (!workq->wq->func)
			{
				WDRBD_ERROR("func is null! skip\n");
                BUG();
			}
			else
			{
				workq->wq->func(&workq->worker); 
			}
			break;

		case (STATUS_WAIT_1):
			workq->wq->run = FALSE;
			break;
		}
	}

#ifdef _WIN32_CT
    ct_delete_thread(KeGetCurrentThread());
#endif

	WDRBD_INFO("done.\n");
	PsTerminateSystemThread(STATUS_SUCCESS); 
}

struct workqueue_struct *create_singlethread_workqueue(void *name, void  *wq_s, void *func, ULONG Tag)
{
	HANDLE		hThread = NULL;
	NTSTATUS	status = STATUS_UNSUCCESSFUL;
	struct submit_worker *workq = (struct submit_worker *)wq_s; // DRBD_DOC: submit_worker, retry_worker 를 submit_worker 구조로 단일화

	workq->wq = kzalloc(sizeof(struct workqueue_struct), 0, Tag); 
	if (!workq->wq)
	{
		return 0;
	}

	KeInitializeEvent(&workq->wq->wakeupEvent, SynchronizationEvent, FALSE); 
	KeInitializeEvent(&workq->wq->killEvent, SynchronizationEvent, FALSE);

#ifdef _WIN32_CT
    KeInitializeEvent(&workq->thi.start_event, SynchronizationEvent, FALSE);
    KeInitializeEvent(&workq->thi.wait_event, SynchronizationEvent, FALSE);

#else
    workq->task.has_sig_event = FALSE;
#endif

	workq->wq->func = func;
	sprintf(workq->wq->name, "%s\0", name); 
	workq->wq->run = TRUE;
#ifdef _WIN32_CT
    workq->thi.task = NULL;
#endif

	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, run_singlethread_workqueue, (void *)workq);

	if (!NT_SUCCESS(status)) {
		WDRBD_ERROR("PsCreateSystemThread failed with status 0x%08X\n", status);
		kfree(workq->wq);
		return 0;
	}

#ifdef _WIN32_CT
    KeWaitForSingleObject(&workq->thi.start_event, Executive, KernelMode, FALSE, NULL);

    if (!workq->thi.task) {
        WDRBD_ERROR("PsCreateSystemThread failed with workq->thi.task\n");
        kfree(workq->wq);
        return 0;
    }

    KeSetEvent(&workq->thi.wait_event, 0, FALSE);
#endif

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &workq->wq->pThread, NULL);
	ZwClose(hThread);
	if (!NT_SUCCESS(status)) {
#ifdef _WIN32_CT
        WDRBD_ERROR("DRBD_PANIC: ObReferenceObjectByHandle failed with status 0x%08X\n", status);
        KeSetEvent(&workq->thi.wait_event, 0, FALSE);
        destroy_workqueue(workq->wq);
#else
		WDRBD_ERROR("ObReferenceObjectByHandle failed with status 0x%08X\n", status);
		kfree(workq->wq);
#endif
		return 0;
	}

	return workq->wq; 
}

#ifdef _WIN32_TMP_DEBUG_MUTEX
void mutex_init(struct mutex *m, char *name)
#else
void mutex_init(struct mutex *m)
#endif
{
	KeInitializeMutex(&m->mtx, 0);
#ifdef _WIN32_TMP_DEBUG_MUTEX
	memset(m->name, 0, 32);
	strcpy(m->name, name); 
#endif
}

__inline
NTSTATUS mutex_lock(struct mutex *m)
{
    return KeWaitForMutexObject(&m->mtx, Executive, KernelMode, FALSE, NULL);
}

#ifdef _WIN32_V9
__inline
NTSTATUS mutex_lock_interruptible(struct mutex *m)
{
	return KeWaitForMutexObject(&m->mtx, Executive, KernelMode, TRUE, NULL); //Alertable 인자가 TRUE
}
#endif

// Returns 1 if the mutex is locked, 0 if unlocked.
int mutex_is_locked(struct mutex *m)
{
	return (KeReadStateMutex(&m->mtx) == 0) ? 1 : 0;
}

// Try to acquire the mutex atomically. 
// Returns 1 if the mutex has been acquired successfully, and 0 on contention.
int mutex_trylock(struct mutex *m)
{
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = 0; 

	if (KeWaitForMutexObject(&m->mtx, Executive, KernelMode, FALSE, &Timeout) == STATUS_SUCCESS)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

void mutex_unlock(struct mutex *m)
{
    KeReleaseMutex(&m->mtx, FALSE);
}

#ifdef _WIN32_V9 // __WIN32_CHECK

void down(struct mutex *m)
{
	// mutex/spin lock 으로 대체 가능할 듯.
    mutex_lock(m);
    //WDRBD_TRACE("mutex_lock name(%s) ownerthread(%x)!\n", m->name, m->mtx.OwnerThread);
}

void up(struct mutex *m)
{
    // mutex/spin lock 으로 대체 가능할 듯.
    //WDRBD_TRACE("mutex_unlock name(%s) ownerthread(%x)!\n", m->name, m->mtx.OwnerThread);
    mutex_unlock(m);
}

/*
46 void __sched down_write(struct rw_semaphore *sem)
47 {
48         might_sleep();
49         rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_);
50
51         LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
52         rwsem_set_owner(sem);
53 }
*/
KIRQL du_OldIrql;

void downup_rwlock_init(KSPIN_LOCK* lock)
{
	KeInitializeSpinLock(lock);
}

//void down_write(struct semaphore *sem) // rw_semaphore *sem)
void down_write(KSPIN_LOCK* lock)
{
	// mutex/spin lock 으로 대체 가능할 듯.
	return KeAcquireSpinLock(lock, &du_OldIrql);
}

//void up_write(struct semaphore *sem) // rw_semaphore *sem)
void up_write(KSPIN_LOCK* lock)
{
	// mutex/spin lock 으로 대체 가능할 듯.
	return KeReleaseSpinLock(lock, du_OldIrql);
}

//void down_read(struct semaphore *sem) // rw_semaphore *sem)
void down_read(KSPIN_LOCK* lock)
{
	// mutex/spin lock 으로 대체 가능할 듯.
	return KeAcquireSpinLock(lock, &du_OldIrql);
}

//void up_read(struct semaphore *sem) // rw_semaphore *sem)
void up_read(KSPIN_LOCK* lock)
{
	// mutex/spin lock 으로 대체 가능할 듯.
	return KeReleaseSpinLock(lock, du_OldIrql);
}

#endif


void spin_lock_init(spinlock_t *lock)
{
	KeInitializeSpinLock(&lock->spinLock);
}

void acquireSpinLock(KSPIN_LOCK *lock, KIRQL *flags)
{
	KeAcquireSpinLock(lock, flags);
}

void releaseSpinLock(KSPIN_LOCK *lock, KIRQL flags)
{
	KeReleaseSpinLock(lock, flags);
}

long _spin_lock_irqsave(spinlock_t *lock)
{
	KIRQL	oldIrql;
	acquireSpinLock(&lock->spinLock, &oldIrql);
	return (long)oldIrql;
}

void spin_lock(spinlock_t *lock)
{
	spin_lock_irq(lock);
}

void spin_unlock(spinlock_t *lock)
{
	spin_unlock_irq(lock);
}

void spin_lock_irq(spinlock_t *lock)
{
	acquireSpinLock(&lock->spinLock, &lock->saved_oldIrql);
}


void spin_unlock_irq(spinlock_t *lock)
{
	releaseSpinLock(&lock->spinLock, lock->saved_oldIrql);
}

void spin_unlock_irqrestore(spinlock_t *lock, long flags)
{
	releaseSpinLock(&lock->spinLock, (KIRQL) flags);
}

#ifdef _WIN32_V9
void spin_lock_bh(spinlock_t *lock)
{
	//_WIN32_CHECK: dummy!!! spin lock  적용해도 문제 없을 듯.
	KeAcquireSpinLock(&lock->spinLock, &lock->saved_oldIrql);
}

void spin_unlock_bh(spinlock_t *lock)
{
	//_WIN32_CHECK: dummy!!! spin unlock  적용해도 문제 없을 듯.
	KeReleaseSpinLock(&lock->spinLock, lock->saved_oldIrql);
}
#endif


int blkdev_issue_flush(struct block_device *bdev, gfp_t gfp_mask,  sector_t *error_sector)
{
	// DRBD_UPGRADE: IRP_MJ_FLUSH_BUFFERS
    // IOCTL_VOLSNAP_FLUSH_AND_HOLD_WRITES?
	// bdev q에 있는 bio 를 플러시 함! submit_bio(WRITE_FLUSH, bio);
    // Windows 적용 가능성 확인
	return 0;
}

void get_random_bytes(void *buf, int nbytes)
{
    ULONG rn = nbytes;
    UCHAR * target = buf;
    int length = 0;

    do
    {
        rn = RtlRandomEx(&rn);
        length = (4 > nbytes) ? nbytes : 4;
        memcpy(target, (UCHAR *)&rn, length);
        nbytes -= length;
        target += length;
        
    } while (nbytes);

#if 0
    LARGE_INTEGER p = KeQueryPerformanceCounter(NULL);
	LARGE_INTEGER random;

	random.LowPart = p.LowPart ^ (ULONG) p.HighPart;
	p = KeQueryPerformanceCounter(NULL);
	random.HighPart = p.LowPart ^ (ULONG) p.HighPart;
	if (nbytes > 8)
		nbytes = 8; 

	memcpy(buf, (char*) &random.HighPart, nbytes);

	//DRBD_DOC: http://www.osronline.com/showThread.cfm?link=51429
#endif
}

unsigned int crypto_tfm_alg_digestsize(struct crypto_tfm *tfm)
{
	return 4; // DRBD_DOC: 4byte fixed
}

int page_count(struct page *page)
{
	return 1;
}

void init_timer(struct timer_list *t)
{
	DbgPrint("DRBD_TEST:(%s)init_timer t=%d\n", current->comm, t->expires); // _WIN32_V9_TEST
	KeInitializeTimer(&t->ktimer);
	KeInitializeDpc(&t->dpc, (PKDEFERRED_ROUTINE) t->function, t->data);
#ifdef DBG
    strcpy(t->name, "undefined");
#endif
}
#ifdef _WIN32_V9
// kmpak 20150824
// lock dependency에 따른 작업을 위해 key 값이 존재하나 아직 이것을
// 활용하진 못하겠다. key 외에 나머지는 timer init 시켜준다.
void init_timer_key(struct timer_list *timer, const char *name,
    struct lock_class_key *key)
{
    UNREFERENCED_PARAMETER(key);
	DbgPrint("DRBD_TEST:(%s)init_timer_key\n", current->comm); // _WIN32_V9_TEST
    init_timer(timer);
#ifdef DBG
    strcpy(timer->name, name);
#endif
}
#endif
void add_timer(struct timer_list *t)
{
	DbgPrint("DRBD_TEST:(%s)add_timer t=%d\n", current->comm, t->expires); // _WIN32_V9_TEST
	mod_timer(t, t->expires);
}

void del_timer(struct timer_list *t)
{
	DbgPrint("DRBD_TEST:(%s)del_timer t=%d\n", current->comm, t->expires); // _WIN32_V9_TEST
	KeCancelTimer(&t->ktimer);
    t->expires = 0;
}

int del_timer_sync(struct timer_list *t)
{
	DbgPrint("DRBD_TEST:(%s)del_timer_sync t=%d\n", current->comm, t->expires); // _WIN32_V9_TEST

    del_timer(t);
    return 0;
#ifdef _WIN32_CHECK // linux kernel 2.6.24에서 가져왔지만 이후 버전에서 조금 다르다. return 값이 어떤 것인지 파악 필요
  	for (;;) {
		int ret = try_to_del_timer_sync(timer);
		if (ret >= 0)
			return ret;
		cpu_relax();
	}
#endif
}
#ifdef _WIN32_V9
/**
 * timer_pending - is a timer pending?
 * @timer: the timer in question
 *
 * timer_pending will tell whether a given timer is currently pending,
 * or not. Callers must ensure serialization wrt. other operations done
 * to this timer, eg. interrupt contexts, or other CPUs on SMP.
 *
 * return value: 1 if the timer is pending, 0 if not.
 */
static __inline int timer_pending(const struct timer_list * timer)
{
    return timer->ktimer.TimerListEntry.Flink
        && !IsListEmpty(&timer->ktimer.TimerListEntry.Flink)
        && !KeReadStateTimer(&timer->ktimer);
}

static int
__mod_timer(struct timer_list *timer, ULONG_PTR expires, bool pending_only)
{
    if (!timer_pending(timer) && pending_only)
    {
        return 0;
    }

    LARGE_INTEGER nWaitTime = { .QuadPart = 0 };
    ULONG_PTR current_milisec = jiffies;

    timer->expires = expires;

    if (current_milisec >= expires)
    {
        nWaitTime.LowPart = 1;
    }
    else
    {
        expires -= current_milisec;
        nWaitTime = RtlConvertLongToLargeInteger(RELATIVE(MILLISECONDS(expires)));
    }

#ifdef DBG
//    WDRBD_TRACE("%s timer(0x%p) current(%d) expires(%d) gap(%d)\n",
//        timer->name, timer, current_milisec, timer->expires, timer->expires - current_milisec);
#endif
    KeSetTimer(&timer->ktimer, nWaitTime, &timer->dpc);
    return 1;
}

/**
 * mod_timer_pending - modify a pending timer's timeout
 * @timer: the pending timer to be modified
 * @expires: new timeout in jiffies
 *
 * mod_timer_pending() is the same for pending timers as mod_timer(),
 * but will not re-activate and modify already deleted timers.
 *
 * It is useful for unserialized use of timers.
 */
int mod_timer_pending(struct timer_list *timer, ULONG_PTR expires)
{
    return __mod_timer(timer, expires, true);
}

int mod_timer(struct timer_list *timer, ULONG_PTR expires)
{
    if (timer_pending(timer) && timer->expires == expires)
    	return 1;

    return __mod_timer(timer, expires, false);
}
#endif
void kobject_put(struct kobject *kobj)
{
    if (kobj) 
    {
        if (kobj->name == NULL)
        {
            //WDRBD_WARN("%p name is null.\n", kobj);
            return;
        }

        if (atomic_sub_and_test(1, &kobj->kref.refcount)) 
        { 
            void(*release)(struct kobject *kobj);
            release = kobj->ktype->release; 
            if (release == 0)
            {
                return;
            }
            release(kobj); 
        }
    }
    else
    {
        //WDRBD_WARN("kobj is null.\n");
        return;
    }
}

void kobject_del(struct kobject *kobj)
{
    if (!kobj)
    {
        WDRBD_WARN("kobj is null.\n");
        return;
    }
    kobject_put(kobj->parent); 
}

void kobject_get(struct kobject *kobj)
{
    if (kobj)
    {
        kref_get(&kobj->kref);
    }
    else
    {
        WDRBD_INFO("kobj is null.\n");
        return;
    }
}

void drbd_unregister_blkdev(unsigned int major, const char *name)
{

}

void del_gendisk(struct gendisk *disk)
{
	// free disk
}

 void destroy_workqueue(struct workqueue_struct *wq)
{
	 KeSetEvent(&wq->killEvent, 0, FALSE);
	 KeWaitForSingleObject(wq->pThread, Executive, KernelMode, FALSE, NULL);
	 ObDereferenceObject(wq->pThread);
     kfree(wq);
}

 void sock_release(struct socket *sock)
{
	NTSTATUS status;
	
	if (!sock)
	{
		WDRBD_WARN("socket is null.\n");
		return;
	}

	status = CloseSocket(sock->sk); 
	if (!NT_SUCCESS(status)) 
	{
		WDRBD_ERROR("error=0x%x\n", status);
		return;
	}

	if (sock->sk_linux_attr)
	{
		kfree(sock->sk_linux_attr);
		sock->sk_linux_attr = 0;
	}
#ifdef _WIN32_SEND_BUFFING
	if (sock->bab)
	{
		if (sock->bab->static_big_buf)
		{
			kfree(sock->bab->static_big_buf);
		}
		kfree(sock->bab);

	}
#endif
	kfree(sock);
}

//Linux/block/genhd.c
void set_disk_ro(struct gendisk *disk, int flag)
{

}

#ifdef _WIN32_CT
#define CT_MAX_THREAD_LIST          40
static LIST_HEAD(ct_thread_list);
static int ct_thread_num = 0;
static KSPIN_LOCK ct_thread_list_lock;
static KIRQL ct_oldIrql;

void ct_init_thread_list()
{
    KeInitializeSpinLock(&ct_thread_list_lock);
}

static struct task_struct *__find_thread(PKTHREAD id)
{
    struct task_struct *t;

    list_for_each_entry(struct task_struct, t, &ct_thread_list, list)
    {
        if (t->pid == id) {
            return t;
        }
    }
    return NULL;
}

static void __delete_thread(struct task_struct *t)
{
    list_del(&t->list);
    kfree(t);
    ct_thread_num--;

    // logic check
    if (ct_thread_num < 0)
    {
        WDRBD_ERROR("DRBD_PANIC:unexpected ct_thread_num(%d)\n", ct_thread_num);
        BUG();
    }
}

struct task_struct * ct_add_thread(PKTHREAD id, char *name, BOOLEAN event, ULONG Tag)
{
    struct task_struct *t;

    if (++ct_thread_num > CT_MAX_THREAD_LIST)
    {
        WDRBD_WARN("ct_thread too big(%d)\n", ct_thread_num);
    }

    if ((t = kzalloc(sizeof(*t), GFP_KERNEL, Tag)) == NULL)
    {
        return NULL;
    }

    t->pid = id;
    if (event)
    {
        KeInitializeEvent(&t->sig_event, SynchronizationEvent, FALSE);
        t->has_sig_event = TRUE;
    }
    strcpy(t->comm, name);
    KeAcquireSpinLock(&ct_thread_list_lock, &ct_oldIrql);
    list_add(&t->list, &ct_thread_list);
    KeReleaseSpinLock(&ct_thread_list_lock, ct_oldIrql);
    return t;
}

void ct_delete_thread(PKTHREAD id)
{
    KeAcquireSpinLock(&ct_thread_list_lock, &ct_oldIrql);
    __delete_thread(__find_thread(id));
    KeReleaseSpinLock(&ct_thread_list_lock, ct_oldIrql);
}

struct task_struct* ct_find_thread(PKTHREAD id)
{
    struct task_struct *t;
    KeAcquireSpinLock(&ct_thread_list_lock, &ct_oldIrql);
    t = __find_thread(id);
    if (!t)
    {
        static struct task_struct g_dummy_current;
        t = &g_dummy_current;
        t->pid = 0;
        t->has_sig_event = FALSE;
        strcpy(t->comm, "not_drbd_thread");
    }
    KeReleaseSpinLock(&ct_thread_list_lock, ct_oldIrql);
    return t;
}

#else

struct task_struct *find_current_thread() 
{
	extern struct task_struct g_nlThread;
#ifdef _WIN32_CHECK
	extern struct retry_worker retry;
#endif

	struct task_struct *curr = 0;
	struct drbd_conf *mdev;
	PKTHREAD threadHandle;
	int i;

	threadHandle = KeGetCurrentThread();
	if (g_nlThread.current_thr == threadHandle)
	{
		return &g_nlThread;
	}
#ifdef _WIN32_CHECK
	if (retry.task.current_thr == threadHandle)
	{
		return &retry.task.current_thr;
	}
#endif
	rcu_read_lock();
	idr_for_each_entry(&minors, mdev, i)  // i means minor number
	{
		if (mdev->submit.task.current_thr == threadHandle)
		{
			curr = &mdev->submit.task;
			break;
		}

		if (mdev->tconn->worker.task)
		{		
			if (mdev->tconn->worker.task->current_thr == threadHandle)
			{
				curr = mdev->tconn->worker.task;
				break;
			}
		}

		if (mdev->tconn->receiver.task)
		{		
			if (mdev->tconn->receiver.task->current_thr == threadHandle)
			{
				curr = mdev->tconn->receiver.task;
				break;
			}
		}

		if (mdev->tconn->asender.task)
		{
			if (mdev->tconn->asender.task->current_thr == threadHandle)
			{
				curr = mdev->tconn->asender.task;
				break;
			}
		}
	}
	rcu_read_unlock();

	if (!curr)
	{
		static struct task_struct g_dummy_current; // 공유?
		curr = &g_dummy_current;
		curr->current_thr = threadHandle;
		curr->pid = 0; // pid 의 값 존재 여부로 스레드 확인
        curr->has_sig_event = FALSE;
		strcpy(curr->comm, "notFound"); // io request from upper layer driver 
	}

	return curr;
}
#endif

int signal_pending(struct task_struct *task)
{
    if (task->has_sig_event)
	{
		if (task->sig || KeReadStateEvent(&task->sig_event))
		{
			return 1;
		}
	}
	return 0;
}

void force_sig(int sig, struct task_struct  *task)
{
    if (task->has_sig_event)
	{
		task->sig = sig;
		KeSetEvent(&task->sig_event, 0, FALSE);
	}
}

void flush_signals(struct task_struct *task)
{
    if (task->has_sig_event)
	{
		KeClearEvent(&task->sig_event); 
		task->sig = 0;
	}
}

void *crypto_alloc_tfm(char *name, u32 mask)
{
    // DRBD_DOC: CRYPTO 개선. sha1, md5
	WDRBD_INFO("request crypto name(%s) --> supported crc32c only.\n", name);
	return 1; 
}

void generic_make_request(struct bio *bio)
{
	PIRP newIrp;
	PVOID buffer;
	LARGE_INTEGER offset;
	ULONG io;
	struct request_queue *q = bdev_get_queue(bio->bi_bdev);

	offset.QuadPart = bio->bi_sector << 9;
	if (bio->win32_page_buf)
	{
		buffer = bio->win32_page_buf;
	}
	else
	{
		if (bio->bi_max_vecs > 1)
		{
			BUG(); // DRBD_PANIC
		}
		buffer = (PVOID) bio->bi_io_vec[0].bv_page->addr; 
	}

	if (bio->bi_rw & WRITE)
	{
		io = IRP_MJ_WRITE;
	}
	else
	{
		io = IRP_MJ_READ;
	}

#ifdef DRBD_TRACE
    WDRBD_TRACE("(%s)Local I/O(%s): sect=0x%llx sz=%d IRQL=%d buf=0x%p, off&=0x%llx target=%c:\n", 
		current->comm, (io == IRP_MJ_READ) ? "READ" : "WRITE", 
		offset.QuadPart / 512, bio->bi_size, KeGetCurrentIrql(), &offset, buffer, q->backing_dev_info.pDeviceExtension->Letter);
#endif

#ifdef _WIN32_TMP_IoAllocateIrp //DISPATCH_LEVEL 회피용
	newIrp = IoAllocateIrp(q->backing_dev_info.pDeviceExtension->TargetDeviceObject->StackSize, FALSE);
	if (NULL == newIrp) {
		WDRBD_ERROR("IoAllocateIrp: cannot alloc new IRP\n");
		return STATUS_INSUFFICIENT_RESOURCES; // vold!
	}
	// 
	// Obtain a pointer to the stack location of the first driver that will be
	// invoked.  This is where the function codes and the parameters are set.
	// 
	PIO_STACK_LOCATION  nextStack;
	nextStack = IoGetNextIrpStackLocation(newIrp);
	nextStack->MajorFunction = io;
	nextStack->Parameters.Write.Length = bio->bi_size;
	nextStack->Parameters.Write.ByteOffset = offset;


	if (q->backing_dev_info.pDeviceExtension->TargetDeviceObject->Flags & DO_BUFFERED_IO) {
		newIrp->AssociatedIrp.SystemBuffer = buffer;
		newIrp->MdlAddress = NULL;
	}
	else if (q->backing_dev_info.pDeviceExtension->TargetDeviceObject->Flags & DO_DIRECT_IO) {
		// 
		// The target device supports direct I/O operations.  Allocate
		// an MDL large enough to map the buffer and lock the pages into
		// memory.
		// 
		// The target device supports direct I/O operations.  Allocate
		// an MDL large enough to map the buffer and lock the pages into
		// memory.
		// 
		newIrp->MdlAddress = IoAllocateMdl(buffer,
			bio->bi_size,
			FALSE,
			FALSE,
			(PIRP) NULL);

		if (newIrp->MdlAddress == NULL) {
			IoFreeIrp(newIrp);
			return STATUS_INSUFFICIENT_RESOURCES;// vold!
		}

		try {
			static int x = 0;
			MmProbeAndLockPages(newIrp->MdlAddress,
				KernelMode,
				(LOCK_OPERATION) (nextStack->MajorFunction == IRP_MJ_WRITE ? IoReadAccess : IoWriteAccess));

		} except(EXCEPTION_EXECUTE_HANDLER) {
			if (newIrp->MdlAddress != NULL) {
				IoFreeMdl(newIrp->MdlAddress);
			}
			IoFreeIrp(newIrp);
			WDRBD_ERROR("DO_DIRECT_IO: cannot MmProbeAndLockPages\n");
			return  GetExceptionCode();
		}
	}
#else

	newIrp = IoBuildAsynchronousFsdRequest(
				io,
				q->backing_dev_info.pDeviceExtension->TargetDeviceObject,
				buffer,
				bio->bi_size,
				&offset,
				NULL
				);

	if (!newIrp)
	{
		WDRBD_ERROR("IoBuildAsynchronousFsdRequest: cannot alloc new IRP\n");
		return; 
	}
#endif

	IoSetCompletionRoutine(newIrp, bio->bi_end_io, bio, TRUE, TRUE, TRUE);
	IoCallDriver(q->backing_dev_info.pDeviceExtension->TargetDeviceObject, newIrp);
}

void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

void list_del_init(struct list_head *entry)
{
	__list_del_entry(entry);
	INIT_LIST_HEAD(entry);
}

int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

void INIT_HLIST_NODE(struct hlist_node *h)
{
    h->next = NULL;
    h->pprev = NULL;
}

void hlist_del_init(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}

void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

static const u32 crc32c_table[256] = { 
	0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
	0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
	0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
	0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
	0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
	0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
	0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
	0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
	0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
	0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
	0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
	0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
	0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
	0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
	0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
	0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
	0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
	0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
	0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
	0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
	0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
	0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
	0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
	0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
	0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
	0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
	0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
	0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
	0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
	0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
	0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
	0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
	0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
	0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
	0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
	0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
	0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
	0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
	0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
	0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
	0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
	0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
	0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
	0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
	0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
	0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
	0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
	0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
	0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
	0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
	0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
	0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
	0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
	0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
	0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
	0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
	0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
	0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
	0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
	0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
	0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
	0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
	0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
	0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};

uint32_t crc32c(uint32_t crc, const uint8_t *data, unsigned int length)
{
	while (length--)
		crc = crc32c_table[(crc ^ *data++) & 0xFFL] ^ (crc >> 8);

	return crc;
}

inline void __list_add_rcu(struct list_head *new, struct list_head *prev, struct list_head *next)
{
	new->next = next;
	new->prev = prev;
	rcu_assign_pointer(list_next_rcu(prev), new);
	next->prev = new;
}

void list_del_rcu(struct list_head *entry)
{
     __list_del(entry->prev, entry->next);
     entry->prev = LIST_POISON2;
}

void list_add_rcu(struct list_head *new, struct list_head *head)
{
    __list_add_rcu(new, head, head->next);
}

void list_add_tail_rcu(struct list_head *new, struct list_head *head)
{
     __list_add_rcu(new, head->prev, head);
}

 struct request_queue *blk_alloc_queue(gfp_t gfp_mask, ULONG Tag)
 {
     return kzalloc(sizeof(struct request_queue), 0, Tag);
 }

/**
    blk_alloc_queue와 blk_cleanup_queue는 리눅스 커널 코드로
    DRBD에 body가 있지 않음.
    blk_alloc_queue가 ExAllocatePool로 대체했기 때문에
    blk_cleanup_queue도 ExFreePool로 대체함.
*/
void blk_cleanup_queue(struct request_queue *q)
{
    if( q != NULL )
        ExFreePool( q );
}

struct gendisk *alloc_disk(int minors)
{	
	struct gendisk *p = kzalloc(sizeof(struct gendisk), 0, '44DW');
	return p;
}

void put_disk(struct gendisk *disk)
{
	kfree(disk);
}

void blk_queue_make_request(struct request_queue *q, make_request_fn *mfn)
{
	// 방식이 다름
}

void blk_queue_flush(struct request_queue *q, unsigned int flush)
{
}

// bio_alloc_bioset 는 리눅스 커널 API. 이 구조체는 코드 유지를 위해서 존재함
#pragma warning ( disable : 4716 )
struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad)
{
	// 방식이 다름
}

//
// porting netlink interface 
//
unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp = skb_tail_pointer(skb);
	// SKB_LINEAR_ASSERT(skb);
	skb->tail += len;
	skb->len  += len;

	if (skb->tail > skb->end)
	{
#ifndef _WIN32
		// skb_over_panic(skb, len, __builtin_return_address(0));
#else
		WDRBD_ERROR("drbd:skb_put: skb_over_panic\n");
#endif
	}

	return tmp;
}
void *compat_genlmsg_put(struct msg_buff *skb, u32 pid, u32 seq,
				       struct genl_family *family, int flags, u8 cmd)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *hdr;

	nlh = nlmsg_put(skb, pid, seq, family->id, GENL_HDRLEN + family->hdrsize, flags);
	if (nlh == NULL)
		return NULL;

	hdr = nlmsg_data(nlh);
	hdr->cmd = cmd;
	hdr->version = family->version;
	hdr->reserved = 0;

	return (char *) hdr + GENL_HDRLEN;
}

void *genlmsg_put_reply(struct msg_buff *skb,
                         struct genl_info *info,
                         struct genl_family *family,
                         int flags, u8 cmd)
{
#ifndef _WIN32
	return genlmsg_put(skb, info->snd_pid, info->snd_seq, family, flags, cmd);
#else
	return genlmsg_put(skb, info->snd_portid, info->snd_seq, family, flags, cmd);
#endif
}

void genlmsg_cancel(struct sk_buff *skb, void *hdr)
{

}

#ifdef _WIN32 // _WIN32_V9
int _DRBD_ratelimit(char * __FILE, int __LINE)
{ 
	int __ret;						
	static size_t toks = 0x80000000UL;
	static size_t last_msg; 
	static int missed;			
	size_t now = jiffies;
	toks += now - last_msg;					
	last_msg = now;

	__ret = 0;  // _WIN32_CHECK
#ifdef _WIN32_CHECK : 입력인자 대체 필요, 디버깅용 FILE, LINE 매크로 인자는 유지요망

	if (toks > (ratelimit_burst * ratelimit_jiffies))	
		toks = ratelimit_burst * ratelimit_jiffies;	
	if (toks >= ratelimit_jiffies) {

		int lost = missed;				
		missed = 0;					
		toks -= ratelimit_jiffies;			
		if (lost)					
			dev_warn(mdev, "%d messages suppressed in %s:%d.\n", lost, __FILE, __LINE);	
		__ret = 1;					
	}
	else {
		missed++;					
		__ret = 0;					
	}	
#endif
	return __ret;							
}
#else
int _DRBD_ratelimit(size_t ratelimit_jiffies, size_t ratelimit_burst, struct drbd_conf *mdev, char * __FILE, int __LINE)
{ 
	int __ret;						
	static size_t toks = 0x80000000UL;
	static size_t last_msg; 
	static int missed;			
	size_t now = jiffies;
	toks += now - last_msg;					
	last_msg = now;						
	if (toks > (ratelimit_burst * ratelimit_jiffies))	
		toks = ratelimit_burst * ratelimit_jiffies;	
	if (toks >= ratelimit_jiffies) {

		int lost = missed;				
		missed = 0;					
		toks -= ratelimit_jiffies;			
		if (lost)					
			dev_warn(mdev, "%d messages suppressed in %s:%d.\n", lost, __FILE, __LINE);	
		__ret = 1;					
	}
	else {
		missed++;					
		__ret = 0;					
	}							
	return __ret;							
}
#endif

#ifdef _WIN32_V9
 // _WIN32_CHECK: JHKIM: disable!
#else
bool _expect(long exp, struct drbd_conf *mdev, char *file, int line)
{
	if (!exp)
	{
		WDRBD_ERROR("minor(%d) ASSERTION FAILED in file:%s line:%d\n", mdev->minor, file, line);
        BUG();
	}
	return exp;
}
#endif
static int idr_max(int layers)
{
	int bits = min_t(int, layers * IDR_BITS, MAX_IDR_SHIFT);
	return (1 << bits) - 1;
}

#ifndef _WIN32
#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#else
#define __round_mask(x, y) ((y) - 1)
#endif
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)

void *idr_get_next(struct idr *idp, int *nextidp)
{
	struct idr_layer *p, *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];
	int id = *nextidp;
	int n, max;

	/* find first ent */
#ifdef _WIN32
	if (!idp)
	{
		return NULL;
	}
#endif

	p = rcu_dereference_raw(idp->top);
	if (!p)
		return NULL;
	n = (p->layer + 1) * IDR_BITS;
	max = idr_max(p->layer + 1);

	while (id >= 0 && id <= max) {
		while (n > 0 && p) {
			n -= IDR_BITS;
			*paa++ = p;
			p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
		}

		if (p) {
			*nextidp = id;
			return p;

		}

		id = round_up(id + 1, 1 << n);
		while (n < fls(id)) {
			n += IDR_BITS;
			p = *--paa;
		}
	}
	return NULL;
}

/**
* @brief   VOLUME_EXTENSION의 PhysicalDeviceObject를 기준으로
*   letter, VolIndex, block_device 값을 구한다.
*/
void query_targetdev(PVOLUME_EXTENSION pvext)
{
    PMOUNTDEV_UNIQUE_ID pmuid = RetrieveVolumeGuid(pvext->PhysicalDeviceObject);

    if (pmuid)
    {
        pvext->Letter = _query_mounted_devices(pmuid);

        if (pvext->Letter)
        {
            pvext->VolIndex = pvext->Letter - 'C';
            pvext->dev = create_drbd_block_device(pvext);
        }

        ExFreePool(pmuid);
    }
}

/**
* @brief   모든 VOLUME_EXTENSION 값의 정보를 새로 구한다.
*/
void refresh_targetdev_list()
{
    PROOT_EXTENSION prext = mvolRootDeviceObject->DeviceExtension;

    MVOL_LOCK();
    for (PVOLUME_EXTENSION pvext = prext->Head; pvext; pvext = pvext->Next)
    {
        query_targetdev(pvext);
    }
    MVOL_UNLOCK();
}

/**
* @brief   minor값으로 조회하여 PVOLUME_EXTENSION 값을 돌려준다.
*/
PVOLUME_EXTENSION get_targetdev_by_minor(unsigned int minor)
{
    PROOT_EXTENSION     prext = mvolRootDeviceObject->DeviceExtension;
    PVOLUME_EXTENSION   pvext = prext->Head;

    MVOL_LOCK();
    while (pvext)
    {
        if (!pvext->VolIndex && !pvext->Letter)
        {
            query_targetdev(pvext);
        }

        if (pvext->VolIndex == minor)
        {
            MVOL_UNLOCK();
//            WDRBD_TRACE("minor(%d) letter(%c:) name(%ws)\n", minor, pvext->Letter, pvext->PhysicalDeviceName);
            return pvext;
        }

        pvext = pvext->Next;
    }
    MVOL_UNLOCK();

    WDRBD_ERROR("Failed to find volume for minor(%d)\n", minor);

    return NULL;
}

/**
* @brief    PVOLUME_EXTENSION의 meta data block device letter가 인자로 전달받은 letter와 같다면 PVOLUME_EXTENSION 값을 돌려준다.
*           pvext->Active인 볼륨만 meta data block device를 조회한다.
* @letter:  Meta data block device letter.
*/
struct drbd_conf *get_targetdev_by_md(char letter)
{
    PROOT_EXTENSION     prext = mvolRootDeviceObject->DeviceExtension;
    PVOLUME_EXTENSION   pvext = prext->Head;

    MVOL_LOCK();
    while (pvext)
    {
        if (pvext->Active)
        {
            if (!pvext->VolIndex && !pvext->Letter)
            {
                query_targetdev(pvext);
            }

            struct drbd_conf *mdev = minor_to_device(pvext->VolIndex);
            if (mdev && mdev->ldev)
            {
                if (mdev->ldev->md_bdev->bd_disk->pDeviceExtension->Letter == letter)
                {
                    MVOL_UNLOCK();
                    WDRBD_TRACE("letter(%c:) name(%ws)\n", pvext->Letter, pvext->PhysicalDeviceName);
                    return mdev;
                }
            }
        }

        pvext = pvext->Next;
    }
    MVOL_UNLOCK();

    return NULL;
}

LONGLONG get_targetdev_volsize(PVOLUME_EXTENSION VolumeExtension)
{
	LARGE_INTEGER	volumeSize;
	NTSTATUS	status;

	if (VolumeExtension->TargetDeviceObject == NULL)
	{
		WDRBD_ERROR("TargetDeviceObject is null!\n");
		return (LONGLONG)0;
	}
	status = mvolGetVolumeSize(VolumeExtension->TargetDeviceObject, &volumeSize);
	if (!NT_SUCCESS(status))
	{
		WDRBD_WARN("get volume size error = 0x%x\n", status);
		volumeSize.QuadPart = 0;
	}
	return volumeSize.QuadPart;
}

#define DRBD_REGISTRY_VOLUMES       L"\\volumes"

/**
* @brief    argument로 들어온 minor 값으로 letter를 구한 후 
*   registry 등록이 되어 있는지 유무를 return 한다.
*/
BOOLEAN do_add_minor(unsigned int minor)
{
    OBJECT_ATTRIBUTES           attributes;
    PKEY_FULL_INFORMATION       keyInfo = NULL;
    PKEY_VALUE_FULL_INFORMATION valueInfo = NULL;
    size_t                      valueInfoSize = sizeof(KEY_VALUE_FULL_INFORMATION) + 1024 + sizeof(ULONGLONG);
    NTSTATUS                    status;
    HANDLE                      hKey = NULL;
    ULONG                       size;
    int                         count;
    bool                        ret = FALSE;

    PROOT_EXTENSION             prext = mvolRootDeviceObject->DeviceExtension;

    PAGED_CODE();

    PWCHAR new_reg_buf = (PWCHAR)ExAllocatePoolWithTag(PagedPool, MAX_TEXT_BUF, '93DW');
    if (!new_reg_buf)
    {
        WDRBD_ERROR("Failed to ExAllocatePoolWithTag new_reg_buf\n", 0);
        return FALSE;
    }

    UNICODE_STRING new_reg = {0, MAX_TEXT_BUF, new_reg_buf};
    RtlCopyUnicodeString(&new_reg, &prext->RegistryPath);
    RtlAppendUnicodeToString(&new_reg, DRBD_REGISTRY_VOLUMES);

    InitializeObjectAttributes(&attributes,
        &new_reg,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &attributes);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = ZwQueryKey(hKey, KeyFullInformation, NULL, 0, &size);
    if (status != STATUS_BUFFER_TOO_SMALL)
    {
        ASSERT(!NT_SUCCESS(status));
        goto cleanup;
    }

    keyInfo = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, size, 'A3DW');
    if (!keyInfo)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        WDRBD_ERROR("Failed to ExAllocatePoolWithTag() size(%d)\n", size);
        goto cleanup;
    }

    status = ZwQueryKey(hKey, KeyFullInformation, keyInfo, size, &size);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    count = keyInfo->Values;

    valueInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoSize, 'B3DW');
    if (!valueInfo)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        WDRBD_ERROR("Failed to ExAllocatePoolWithTag() valueInfoSize(%d)\n", valueInfoSize);
        goto cleanup;
    }

    for (int i = 0; i < count; ++i)
    {
        RtlZeroMemory(valueInfo, valueInfoSize);

        status = ZwEnumerateValueKey(hKey, i, KeyValueFullInformation, valueInfo, valueInfoSize, &size);

        if (!NT_SUCCESS(status))
        {
            if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL)
            {
                goto cleanup;
            }
        }

        if (REG_BINARY == valueInfo->Type)
        {
            valueInfo->Name[0] &= ~0x20;

            if (minor == valueInfo->Name[0] - L'C')
            {
                ret = true;
                goto cleanup;
            }
        }
    }

cleanup:
    kfree(new_reg_buf);
    kfree(keyInfo);
    kfree(valueInfo);

    if (hKey)
    {
        ZwClose(hKey);
    }

    return ret;
}
struct block_device *blkdev_get_by_path(const char *path, fmode_t dummy1, void *dummy2)
{
#ifndef _WIN32
	return open_bdev_exclusive(path, mode, holder);
#else
	PVOLUME_EXTENSION VolumeExtension = get_targetdev_by_minor(toupper(*path) - 'C'); // only one byte used.
	return (VolumeExtension == NULL) ? NULL : VolumeExtension->dev;
#endif
}

#ifndef _WIN32
struct block_device *blkdev_get_by_minor(int minor)
{

}
#endif

void dumpHex(const void *aBuffer, const size_t aBufferSize, size_t aWidth)
{
	char           sHexBuffer[6] = {0};  
	size_t         sLineSize;  
	size_t         sLineLength;    /* the number of bytes printed in a line */  
	char          *sLine = NULL;  
	size_t         sPos = 0;  
	size_t         i;  

	const uint8_t *sBuffer = (const uint8_t *)aBuffer;  
	const size_t   sAddrAreaSize = 6; /* address column (e.g. FFFF  ) */  
	const size_t   sColWidth     = 4; /* the number of bytes that consists a column (FF FF FF FF  FF FF FF FF  ) */  

	aWidth = ((aWidth + (sColWidth - 1)) / sColWidth) * sColWidth;  

	const size_t  sHexAreaSize = (aWidth * 3) + /* 3 chars required to display a byte (FF ) - including trailing space */
		(aWidth / sColWidth);  /* to distinguish a column by inserting additional space */

	const size_t  sCharAreaStartPos = sAddrAreaSize + sHexAreaSize;
	sLineSize = sAddrAreaSize + sHexAreaSize + aWidth + 1; /* Null terminator */
	sLine = (char *) kmalloc(sLineSize, 0, '54DW');
	if (!sLine)
	{
		WDRBD_ERROR("sLine:kzalloc failed\n");
		return;
	}

	*(sLine + sLineSize - 1) = '\0';

	WDRBD_INFO("DUMP: addr=0x%p, sz=%d. width=%d\n", aBuffer, aBufferSize, aWidth);

	while (sPos < aBufferSize)
	{
		memset(sLine, ' ', sLineSize - 1);
		sLineLength = ((aBufferSize - sPos) > aWidth) ? aWidth : (aBufferSize - sPos);

		/* Address */
		//snprintf(sHexBuffer, sizeof(sHexBuffer), "%04X:", (uint16_t) (sPos & 0xFFFF));
		memset(sHexBuffer, 0, 6);
		sprintf(sHexBuffer, "%04X:", (uint16_t) (sPos & 0xFFFF));
		memcpy(sLine, sHexBuffer, 5);

		/* Hex part */
		for (i = 0; i < sLineLength; i++)
		{
			//snprintf(sHexBuffer, sizeof(sHexBuffer), "%02X", *(sBuffer + sPos + i));
			memset(sHexBuffer, 0, 6);
			sprintf(sHexBuffer, "%02X", *(sBuffer + sPos + i));
			memcpy(sLine + sAddrAreaSize + (i * 3) + (i / sColWidth), sHexBuffer, 2);
		}

		/* Character part */
		for (i = 0; i < sLineLength; i++)
		{
			uint8_t sByte = *(sBuffer + sPos + i);
			*(sLine + sCharAreaStartPos + i) = (sByte < 127 && sByte >= 0x20) ? (char) sByte : '.';
		}
		sPos += aWidth;
		WDRBD_INFO("%s\n", sLine);
	}
	kfree(sLine);
}

int call_usermodehelper(char *path, char **argv, char **envp, enum umh_wait wait)
{
	SOCKADDR_IN		LocalAddress = { 0 }, RemoteAddress = { 0 };
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	PWSK_SOCKET		Socket = NULL;
	char *cmd_line;
	int leng;

	leng = strlen(path) + 1 + strlen(argv[0]) + 1 + strlen(argv[1]) + 1 + strlen(argv[2]) + 1;
	cmd_line = kcalloc(leng, 1, 0, '64DW');
	if (!cmd_line)
	{
		WDRBD_ERROR("malloc(%d) failed", leng);
		return -1;
	}

	sprintf(cmd_line, "%s %s\0", argv[1], argv[2]); // except "drbdadm.exe" string
	WDRBD_INFO("malloc len(%d) cmd_line(%s)\n", leng, cmd_line);
#ifdef WSK_ACCEPT_EVENT_CALLBACK
    Socket = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSK_FLAG_CONNECTION_SOCKET);
#else
	Socket = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET);
#endif
	if (Socket == NULL) {
		WDRBD_ERROR("CreateSocket() returned NULL\n");
		kfree(cmd_line);
		return -1; 
	}

	LocalAddress.sin_family = AF_INET;
	LocalAddress.sin_addr.s_addr = INADDR_ANY;
	LocalAddress.sin_port = 0; 

	Status = Bind(Socket, (PSOCKADDR) &LocalAddress);
	if (!NT_SUCCESS(Status)) {
		goto error;
	}

	RemoteAddress.sin_family = AF_INET;
	RemoteAddress.sin_addr.S_un.S_un_b.s_b1 = 127;
	RemoteAddress.sin_addr.S_un.S_un_b.s_b2 = 0;
	RemoteAddress.sin_addr.S_un.S_un_b.s_b3 = 0;
	RemoteAddress.sin_addr.S_un.S_un_b.s_b4 = 1;
	RemoteAddress.sin_port = HTONS(g_daemon_tcp_port); 

	Status = Connect(Socket, (PSOCKADDR) &RemoteAddress);
	if (!NT_SUCCESS(Status)) {
		goto error;;
	}
	else if (Status == STATUS_TIMEOUT)
	{
		WDRBD_INFO("Connect() timeout. IRQL(%d)\n", KeGetCurrentIrql());
		goto error;
	}

	WDRBD_INFO("Connected to the %u.%u.%u.%u:%u  status:0x%08X IRQL(%d)\n", 
			RemoteAddress.sin_addr.S_un.S_un_b.s_b1,
			RemoteAddress.sin_addr.S_un.S_un_b.s_b2,
			RemoteAddress.sin_addr.S_un.S_un_b.s_b3,
			RemoteAddress.sin_addr.S_un.S_un_b.s_b4,
			HTONS(RemoteAddress.sin_port),
			Status, KeGetCurrentIrql());

	{
		LONG readcount;
		char ret; 

		if ((Status = Send(Socket, cmd_line, strlen(cmd_line), 0, 0)) != (long)strlen(cmd_line))
		{
			WDRBD_ERROR("send fail stat=0x%x\n", Status);
			goto error;
		}

		if ((readcount = Receive(Socket, &ret, 1, 0, 0)) > 0)
		{
			WDRBD_INFO("recv val=0x%x\n", ret);
			CloseSocket(Socket);
			kfree(cmd_line);
			return ret; 
		}
		else
		{
			WDRBD_INFO("error recv status=0x%x\n", readcount);
			goto error;
		}
	}

error:
	CloseSocket(Socket);
	kfree(cmd_line);
	return -1;
}

void panic(char *msg)
{
    WDRBD_ERROR("%s\n", msg);
#ifdef _WIN32_EVENTLOG
	WriteEventLogEntryData((ULONG) DEV_ERR_3003, 0, 0, 1, L"%S", msg);
#endif
	KeBugCheckEx(0xddbd, __FILE__, __func__, 0x12345678, 0xd8bdd8bd);
}

// [choi] 사용되는 곳 없음.
int kobject_init_and_add(struct kobject *kobj, struct kobj_type *ktype, struct kobject *parent, const char *name)
{
    kobj->name = name;
    kobj->ktype = ktype;
    kobj->parent = 0;
    kref_init(&kobj->kref);
    return 0;
}



#ifdef _WIN32_V9
int scnprintf(char * buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i = 0;

	va_start(args, fmt);
    i = _vsnprintf_s(buf, size, _TRUNCATE, fmt, args);
	va_end(args);
	return (-1 == i) ? (size - 1) : i;
}

int list_is_singular(const struct list_head *head)
{
	return !list_empty(head) && (head->next == head->prev);
}

void __list_cut_position(struct list_head *list, struct list_head *head, struct list_head *entry)
{
	struct list_head *new_first = entry->next;
	list->next = head->next;
	list->next->prev = list;
	list->prev = entry;
	entry->next = list;
	head->next = new_first;
	new_first->prev = head;
}
// linux kernel 3.14 의 구현을 가져옴. (부가 함수:__list_cut_position, list_is_singular )
void list_cut_position(struct list_head *list, struct list_head *head, struct list_head *entry)
{
	if (list_empty(head))
		return;
	if (list_is_singular(head) &&
		(head->next != entry && head != entry))
		return;
	if (entry == head)
		INIT_LIST_HEAD(list);
	else
		__list_cut_position(list, head, entry);
}


#endif
