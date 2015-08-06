#ifndef __DRBD_WINDRV_H__
#define __DRBD_WINDRV_H__

#include <wdm.h>
#include <stdint.h>
#include <ntstrsafe.h>
#include <stdbool.h>
#include "linux-compat/list.h"
#include "linux-compat/Wait.h"
#include "windows/types.h"
#include "mvolmsg.h"
#include "disp.h"

#pragma warning(disable : 4100 4146 )

//#define DRBD_TRACE				    // 복제흐름보기(기본), 성능 개선후 제거
//#define DRBD_TRACE1				    // 복제흐름보기(상세), 성능 개선후 제거

//#define _WIN32_SEND_BUFFING				// V9 포팅을 위해 임시 제거. // 송신버퍼링 사용. 최종 안정화 후 제거
#define _WIN32_CT
 
#define _WIN32_EVENTLOG			        // Windows Eventlog 포팅지점

//#define _WIN32_TMP_DEBUG_MUTEX        // mutex에 이름을 부여 디버깅시 활용. 안정화 시점에 제거 및 소스 원복
#define _WIN32_TMP_Win8_BUG_0x1a_61946
#define _WIN32_V9	//_WIN32_V9 정의 

#ifdef _WIN32_V9
// JHKIM:너무 많아서 매트로 처리 
#define minor_to_mdev minor_to_device
#define drbd_conf drbd_device
#endif

#define WSK_EVENT_CALLBACK
#define WSK_ACCEPT_EVENT_CALLBACK     

#define DRBD_GENERIC_POOL_TAG       ((ULONG)'dbrd')

#ifdef _WIN64
#define BITS_PER_LONG				64 
#else
#define BITS_PER_LONG				32
#endif

#define DRBD_EVENT_SOCKET_STRING	"DRBD_EVENTS"		/// SEO: NETLINK에서 사용


/// SEO: 리눅스 코드 유지용
#define inline					__inline
#define __func__				__FUNCTION__
#define __bitwise__

#define __GFP_HIGHMEM           (0x02u)
#define __GFP_ZERO              (0x8000u) 
#define __GFP_WAIT              (0x10u) 
#define __GFP_NOWARN            (0x200u) 
#define GFP_HIGHUSER            (7)

#define	KERN_EMERG				"<0>"	/* system is unusable			*/
#define	KERN_ALERT				"<1>"	/* action must be taken immediately	*/
#define	KERN_CRIT				"<2>"	/* critical conditions			*/
#define	KERN_ERR				"<3>"	/* error conditions			*/
#define	KERN_WARNING			"<4>"	/* warning conditions			*/
#define	KERN_NOTICE				"<5>"	/* normal but significant condition	*/
#define	KERN_INFO				"<6>"	/* informational			*/
#define	KERN_DEBUG				"<7>"	/* debug-level messages			*/

#define smp_mb()				KeMemoryBarrier() 
#define smp_rmb()				KeMemoryBarrier()


#define false					FALSE
#define true					TRUE

#define GFP_KERNEL              1
#define GFP_ATOMIC              2
#define GFP_NOIO				(__GFP_WAIT)
#define GFP_NOWAIT	            0
#define gfp_t					int
#define atomic_t				volatile long

#define WARN_ON(x)				__noop
#define ATOMIC_INIT(i)			(i)

#define RELATIVE(wait) (-(wait))

#define __init                  NTAPI

#ifdef _WIN32_V9
#define __exit                  NTAPI
#endif

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

// from bio.h
#define BIO_RW					    0       /* Must match RW in req flags (blkdev.h) */
#define BIO_RW_AHEAD				1       /* Must match FAILFAST in req flags */
#define BIO_RW_BARRIER				2
#define BIO_RW_SYNCIO				3
#define BIO_RW_UNPLUG				4
#define BIO_RW_META				    5
#define BIO_RW_DISCARD				6
#define BIO_RW_FAILFAST_DEV			7
#define BIO_RW_FAILFAST_TRANSPORT	8
#define BIO_RW_FAILFAST_DRIVER		9
#define BIO_RW_NOIDLE				10

#define KBUILD_MODNAME      __FILE__

/*
 * Request flags.  For use in the cmd_flags field of struct request, and in
 * bi_rw of struct bio.  Note that some flags are only valid in either one.
 */
enum rq_flag_bits {
	/* common flags */
	__REQ_WRITE,		/* not set, read. set, write */
	__REQ_FAILFAST_DEV,	/* no driver retries of device errors */
	__REQ_FAILFAST_TRANSPORT, /* no driver retries of transport errors */
	__REQ_FAILFAST_DRIVER,	/* no driver retries of driver errors */

	__REQ_SYNC,		/* request is sync (sync write or read) */
	__REQ_META,		/* metadata io request */
	__REQ_PRIO,		/* boost priority in cfq */
	__REQ_DISCARD,		/* request to discard sectors */
	__REQ_SECURE,		/* secure discard (used with __REQ_DISCARD) */
	__REQ_WRITE_SAME,	/* write same block many times */

	__REQ_NOIDLE,		/* don't anticipate more IO after this one */
	__REQ_FUA,		/* forced unit access */
	__REQ_FLUSH,		/* request for cache flush */

	/* bio only flags */
	__REQ_RAHEAD,		/* read ahead, can fail anytime */
	__REQ_THROTTLED,	/* This bio has already been subjected to
				 * throttling rules. Don't do it again. */

	/* request only flags */
	__REQ_SORTED,		/* elevator knows about this request */
	__REQ_SOFTBARRIER,	/* may not be passed by ioscheduler */
	__REQ_NOMERGE,		/* don't touch this for merging */
	__REQ_STARTED,		/* drive already may have started this one */
	__REQ_DONTPREP,		/* don't call prep for this one */
	__REQ_QUEUED,		/* uses queueing */
	__REQ_ELVPRIV,		/* elevator private data attached */
	__REQ_FAILED,		/* set if the request failed */
	__REQ_QUIET,		/* don't worry about errors */
	__REQ_PREEMPT,		/* set for "ide_preempt" requests */
	__REQ_ALLOCED,		/* request came from our alloc pool */
	__REQ_COPY_USER,	/* contains copies of user pages */
	__REQ_FLUSH_SEQ,	/* request for flush sequence */
	__REQ_IO_STAT,		/* account I/O stat */
	__REQ_MIXED_MERGE,	/* merge of different types, fail separately */
	__REQ_KERNEL, 		/* direct IO to kernel pages */
	__REQ_PM,		/* runtime pm request */
	__REQ_END,		/* last of chain of requests */
	__REQ_NR_BITS,		/* stops here */
};

// from fs.h
/* file is open for reading */
#define FMODE_READ				    0x1
/* file is open for writing */
#define FMODE_WRITE				    0x2

// from notify.h
#define NOTIFY_DONE				    0x0000          /* Don't care */
#define NOTIFY_OK				    0x0001          /* Suits me */
#define NOTIFY_STOP_MASK			0x8000          /* Don't call further */
#define NOTIFY_BAD				    (NOTIFY_STOP_MASK|0x0002)

#define KERNEL_VERSION(_x, _y, _z)	0

#define EINVAL					1
#define EOPNOTSUPP				2
#define ENOMEM					3
#define ENOENT					4
#define EMEDIUMTYPE				5
#define EROFS					6
#define EAGAIN					7
#define MSG_NOSIGNAL			8
#define ETIMEDOUT				9
#define EBUSY					10
#define EOVERFLOW				11
#define ENOBUFS					12
#define ENODEV					13
#define EWOULDBLOCK				14
#define EINTR					15
#define ENOSPC					16
#define ECONNRESET				17
#define ERESTARTSYS				18
#define EIO					    5 //19
#define ENOMSG					20
#define EEXIST					21
#define EPERM					22
#define EMSGSIZE				23
#define ESRCH					24
#define ERANGE					25	
#define EINPROGRESS				26	
#define ECONNREFUSED			27	
#define ENETUNREACH				28
#define EHOSTDOWN				29
#define EHOSTUNREACH			30
#define EBADR					31

#define	ESTALE		116	/* Stale NFS file handle */

#define SIGXCPU					100
#define SIGHUP					101
#define MSG_MORE				102

#define MAX_ERRNO				4095
#define IS_ERR_VALUE(_x)		((_x) >= (unsigned long) -MAX_ERRNO)


#define READ					0
#define WRITE					1
#define WRITE_SYNC				WRITE	// REQ_SYNC | REQ_NOIDLE not used.

// for drbd_actlog.c
#define __attribute__(packed)
#define __attribute(packed)
#ifdef LONG_MAX
#undef LONG_MAX
#endif
#define LONG_MAX				((long)(~0UL>>1)) 
#define MAX_SCHEDULE_TIMEOUT	LONG_MAX	
#define _RET_IP_				(unsigned long)(0)
#define HZ					    1000

#ifdef stderr
#undef stderr
#endif
#define stderr					2

#define likely(_X)				(_X)
#define unlikely(_X)			(_X)

#define pid_t					int
#define BLKSSZGET				1

#define PAGE_KERNEL				1
#define TASK_INTERRUPTIBLE		1
#define TASK_UNINTERRUPTIBLE	2
#define	BIO_UPTODATE			1

#define cond_resched()		    __noop

enum km_type {
	KM_BOUNCE_READ,
	KM_SKB_SUNRPC_DATA,
	KM_SKB_DATA_SOFTIRQ,
	KM_USER0,
	KM_USER1,
	KM_BIO_SRC_IRQ,
	KM_BIO_DST_IRQ,
	KM_PTE0,
	KM_PTE1,
	KM_IRQ0,
	KM_IRQ1,
	KM_SOFTIRQ0,
	KM_SOFTIRQ1,
	KM_L1_CACHE,
	KM_L2_CACHE,
	KM_KDB,
	KM_TYPE_NR
};

typedef unsigned int                fmode_t;

#define MAX_ELOG_BUF				512
#define MAX_TEXT_BUF                256

#define MAX_SPILT_BLOCK_SZ			(1 << 20)

//#define WDRBD_THREAD_POINTER
#define WDRBD_FUNC_NAME

#define FLTR_COMPONENT              DPFLTR_DEFAULT_ID
//#define FLTR_COMPONENT              DPFLTR_IHVDRIVER_ID
#define FEATURE_WDRBD_PRINT

extern void _printk(const char * format, ...);
extern NPAGED_LOOKASIDE_LIST drbd_printk_msg;

#ifdef _WIN32_EVENTLOG
#define printk(format, ...)   \
    _printk(format, __VA_ARGS__)
#else
#define printk(format, ...)
#endif

#if defined (WDRBD_THREAD_POINTER) && defined (WDRBD_FUNC_NAME)
#define WDRBD_FATAL(_m_, ...)   \
do { \
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_ERROR_LEVEL, "WDRBD_FATA: [%s|0x%p] "##_m_, __FUNCTION__, KeGetCurrentThread(), __VA_ARGS__); \
    printk(KERN_CRIT "[%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
} while( 0 )
#elif defined(WDRBD_FUNC_NAME)
#define WDRBD_FATAL(_m_, ...)   \
do { \
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_ERROR_LEVEL, "WDRBD_FATA: [%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
    printk(KERN_CRIT "[%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
} while( 0 )
#elif defined(WDRBD_THREAD_POINTER)
#define WDRBD_FATAL(_m_, ...)   \
do { \
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_ERROR_LEVEL, "WDRBD_FATA: [0x%p] "##_m_, KeGetCurrentThread(), __VA_ARGS__); \
    printk(KERN_CRIT "[%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
} while( 0 )
#else
#define WDRBD_FATAL(_m_, ...)   \
do { \
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_ERROR_LEVEL, "WDRBD_FATA: "##_m_, __VA_ARGS__); \
    printk(KERN_CRIT "[%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
} while( 0 )
#endif

#if defined (WDRBD_THREAD_POINTER) && defined (WDRBD_FUNC_NAME)
#define WDRBD_ERROR(_m_, ...)   \
do { \
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_ERROR_LEVEL, "WDRBD_ERRO: [%s|0x%p] "##_m_, __FUNCTION__, KeGetCurrentThread(), __VA_ARGS__); \
    printk(KERN_ERR "[%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
} while( 0 )
#elif defined(WDRBD_FUNC_NAME)
#define WDRBD_ERROR(_m_, ...)   \
do { \
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_ERROR_LEVEL, "WDRBD_ERRO: [%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
    printk(KERN_ERR "[%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
} while( 0 )
#elif defined(WDRBD_THREAD_POINTER)
#define WDRBD_ERROR(_m_, ...)   \
do { \
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_ERROR_LEVEL, "WDRBD_ERRO: [0x%p] "##_m_, KeGetCurrentThread(), __VA_ARGS__); \
    printk(KERN_ERR "[%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
} while( 0 )
#else
#define WDRBD_ERROR(_m_, ...)   \
do { \
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_ERROR_LEVEL, "WDRBD_ERRO: "##_m_, __VA_ARGS__); \
    printk(KERN_ERR "[%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
} while( 0 )
#endif

#if defined (WDRBD_THREAD_POINTER) && defined (WDRBD_FUNC_NAME)
#define WDRBD_WARN(_m_, ...)    \
do { \
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_WARNING_LEVEL, "WDRBD_WARN: [%s|0x%p] "##_m_, __FUNCTION__, KeGetCurrentThread(), __VA_ARGS__); \
    printk(KERN_WARNING "[%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
} while( 0 )
#elif defined(WDRBD_FUNC_NAME)
#define WDRBD_WARN(_m_, ...)    \
do { \
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_WARNING_LEVEL, "WDRBD_WARN: [%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
    printk(KERN_WARNING "[%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
} while( 0 )
#elif defined(WDRBD_THREAD_POINTER)
#define WDRBD_WARN(_m_, ...)    \
do { \
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_WARNING_LEVEL, "WDRBD_WARN: [0x%p] "##_m_, KeGetCurrentThread(), __VA_ARGS__); \
    printk(KERN_WARNING "[%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
} while( 0 )
#else
#define WDRBD_WARN(_m_, ...)    \
do { \
    DbgPrintEx(FLTR_COMPONENT, DPFLTR_WARNING_LEVEL, "WDRBD_WARN: "##_m_, __VA_ARGS__); \
    printk(KERN_WARNING "[%s] "##_m_, __FUNCTION__, __VA_ARGS__); \
} while( 0 )
#endif

#if defined (WDRBD_THREAD_POINTER) && defined (WDRBD_FUNC_NAME)
#define WDRBD_TRACE(_m_, ...)   DbgPrintEx(FLTR_COMPONENT, DPFLTR_TRACE_LEVEL, "WDRBD_TRAC: [%s|0x%p] "##_m_, __FUNCTION__, KeGetCurrentThread(), __VA_ARGS__)
#elif defined(WDRBD_FUNC_NAME)
#define WDRBD_TRACE(_m_, ...)   DbgPrintEx(FLTR_COMPONENT, DPFLTR_TRACE_LEVEL, "WDRBD_TRAC: [%s] "##_m_, __FUNCTION__, __VA_ARGS__)
#elif defined(WDRBD_THREAD_POINTER)
#define WDRBD_TRACE(_m_, ...)   DbgPrintEx(FLTR_COMPONENT, DPFLTR_TRACE_LEVEL, "WDRBD_TRAC: [0x%p] "##_m_, KeGetCurrentThread(), __VA_ARGS__)
#else
#define WDRBD_TRACE(_m_, ...)   DbgPrintEx(FLTR_COMPONENT, DPFLTR_TRACE_LEVEL, "WDRBD_TRAC: "##_m_, __VA_ARGS__)
#endif

#if defined (WDRBD_THREAD_POINTER) && defined (WDRBD_FUNC_NAME)
#define WDRBD_INFO(_m_, ...)    DbgPrintEx(FLTR_COMPONENT, DPFLTR_INFO_LEVEL, "WDRBD_INFO: [%s|0x%p] "##_m_, __FUNCTION__, KeGetCurrentThread(), __VA_ARGS__)
#elif defined(WDRBD_FUNC_NAME)
#define WDRBD_INFO(_m_, ...)    DbgPrintEx(FLTR_COMPONENT, DPFLTR_INFO_LEVEL, "WDRBD_INFO: [%s] "##_m_, __FUNCTION__, __VA_ARGS__)
#elif defined(WDRBD_THREAD_POINTER)
#define WDRBD_INFO(_m_, ...)    DbgPrintEx(FLTR_COMPONENT, DPFLTR_INFO_LEVEL, "WDRBD_INFO: [0x%p] "##_m_, KeGetCurrentThread(), __VA_ARGS__)
#else
#define WDRBD_INFO(_m_, ...)    DbgPrintEx(FLTR_COMPONENT, DPFLTR_INFO_LEVEL, "WDRBD_INFO: "##_m_, __VA_ARGS__)
#endif
#define WDRBD_TRACE_NETLINK

#ifndef FEATURE_WDRBD_PRINT
#define WDRBD_ERROR     __noop
#define WDRBD_WARN      __noop
#define WDRBD_TRACE     __noop
#define WDRBD_INFO      __noop
#endif

#define ARRAY_SIZE(_x)				(sizeof(_x) / sizeof((_x)[0]))

#define BIT_MASK(_nr)				(1ULL << ((_nr) % BITS_PER_LONG))
#define BIT_WORD(_nr)				((_nr) / BITS_PER_LONG)

#define min_t(_type, _x, _y)		((_type)_x < (_type)_y ? (_type)_x : (_type)_y)
#define max_t(_type, _x, _y)		((_type)_x < (_type)_y ? (_type)_y : (_type)_x)

#define ALIGN(_x,_a)				(((_x) + (_a)-1) & ~((_a)-1))

#define container_of(ptr, type, member) \
	((type *)( \
	(PCHAR)(ptr) - \
	(ULONG_PTR)(&((type *)0)->member)))

#define offsetof(_type, _field)			(&((_type *)0)->_field)

struct mutex {
	KMUTEX mtx;
#ifdef _WIN32_TMP_DEBUG_MUTEX
	char name[32]; 
#endif
};

struct kref {
	int refcount;
};

struct hlist_head {
	struct hlist_node *first;
};
 
struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct kobject { 
    const char          *name;
    struct kobject      *parent;
    struct kobj_type    *ktype;
    struct kref         kref;
};

#define _K_SS_MAXSIZE	128 
struct sockaddr_storage_win {
	unsigned short	ss_family;		/* address family */
	char	__data[_K_SS_MAXSIZE - sizeof(unsigned short)];
}; 

struct sock {
	int sk_state_change;
	int sk_user_data;
	int sk_reuse;
	int sk_allocation;
	int sk_priority;
	int sk_sndtimeo; //intptr_t 
	int sk_rcvtimeo; //intptr_t
#ifdef _WIN32_SEND_BUFFING
	// unused!
#else
	int sk_wmem_queued;
#endif
	int sk_sndbuf;
	KSPIN_LOCK sk_callback_lock; 
};

#include <wsk.h>
struct socket {
	struct sock *sk_linux_attr;
	PWSK_SOCKET sk;
	char name[32];
#ifdef _WIN32_SEND_BUFFING
	struct ring_buffer *bab;
#endif
};


#define WQNAME_LEN	16	
struct workqueue_struct {
	int run;
	KEVENT	wakeupEvent;
	KEVENT	killEvent;
	PVOID	pThread;
	void (*func)();
	char name[WQNAME_LEN];
};

struct timer_list {
	void (*function)(PKDPC dpc, PVOID data, PVOID arg1, PVOID arg2);
	PVOID data;             
	struct list_head entry;  
	unsigned long expires; 
	KTIMER ktimer;
	KDPC dpc;
};

extern void init_timer(struct timer_list *t);
extern void add_timer(struct timer_list *t);
extern int del_timer_sync(struct timer_list *t);
extern void del_timer(struct timer_list *t);
extern int mod_timer(struct timer_list *t, unsigned long expires);

#ifdef _WIN32_V9
extern int mod_timer_pending(struct timer_list *timer, unsigned long expires); 
#endif

struct work_struct {
	struct list_head entry;
	void (*func)(struct work_struct *work);
};

struct block_device_operations {
	int (*open) ();
	void (*release) ();
};

struct kobj_type {
	void (*release)();
};

#define DISK_NAME_LEN		16
struct gendisk 
{
	char disk_name[DISK_NAME_LEN];  /* name of major driver */
	struct request_queue *queue;
	PVOLUME_EXTENSION pDeviceExtension;
};

struct block_device {
	struct gendisk * bd_disk;
	unsigned long long d_size;
};

typedef struct kmem_cache {
	int size;
	char *name;
} kmem_cache_t;

typedef struct mempool_s {
	struct kmem_cache *p_cache;
	int page_alloc;
} mempool_t;

struct bio_vec {
	struct page *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct bio;
typedef void(bio_end_io_t) (struct bio *, int);

struct splitInfo {	
	unsigned long finished;
};

struct bio {
	PIRP pMasterIrp;  /* _WIN32: for upper layer's  IRP */

	unsigned int split_id;
	unsigned int split_total_id;
	unsigned int split_total_length;

	char *win32_page_buf; 
	struct splitInfo *splitInfo;

	sector_t			bi_sector;	/* device address in 512 byte sectors */
	struct bio			*bi_next;	/* request queue link */
	struct block_device	*bi_bdev;
	unsigned long		bi_flags;	/* status, command, etc */
	unsigned long		bi_rw;		
	unsigned short		bi_vcnt;	/* how many bio_vec's */
	unsigned short		bi_idx;		/* current index into bvl_vec */
	unsigned int		bi_size;	/* residual I/O count */
	atomic_t			bi_cnt;		/* pin count */
	bio_end_io_t		*bi_end_io;
	void				*bi_private; 
	unsigned int		bi_max_vecs;    /* max bvl_vecs we can hold */
	struct bio_vec		bi_io_vec[1]; // only one!!!
};

struct bio_set {
	mempool_t *bio_pool;
};

struct completion {
	//unsigned int done;
	wait_queue_head_t wait;
};
#ifdef WSK_ACCEPT_EVENT_CALLBACK
struct accept_wait_data {
    struct drbd_tconn *tconn;
    struct socket *s_listen;
    struct socket *s_accept;
    struct completion door_bell;
};
#endif

extern struct bio *bio_clone(struct bio *, int x);
extern struct bio *bio_alloc_bioset(gfp_t gfp_mask, int nr_iovecs, struct bio_set *bs);
extern struct bio_pair *bio_split(struct bio *bi, int first_sectors);
extern void bio_pair_release(struct bio_pair *dbio);
extern struct bio_set *bioset_create(unsigned int, unsigned int);
extern void bioset_free(struct bio_set *);
extern struct bio *bio_alloc(gfp_t, int);
extern struct bio *bio_kmalloc(gfp_t, int);
extern struct bio *bio_alloc_bioset(gfp_t, int, struct bio_set *);
extern void bio_put(struct bio *);
extern void bio_free(struct bio *bio); 
extern void bio_endio(struct bio *, int);
extern int bio_add_page(struct bio *bio, struct page *page, unsigned int len,unsigned int offset);
extern void submit_bio(int rw, struct bio *bio);
extern void bio_endio(struct bio *bio, int error);

#define bio_get(bio)			atomic_inc(&(bio)->bi_cnt) 

#define bio_iovec_idx(bio, idx)		(&((bio)->bi_io_vec[(idx)]))
#define __bio_for_each_segment(bvl, bio, i, start_idx)			\
	for (bvl = bio_iovec_idx((bio), (start_idx)), i = (start_idx);	\
		i < (bio)->bi_vcnt;					\
		bvl++, i++)

#define bio_for_each_segment(bvl, bio, i)				\
	__bio_for_each_segment(bvl, bio, i, (bio)->bi_idx)

#define RW_MASK                 1 //  REQ_WRITE
#define bio_data_dir(bio)       ((bio)->bi_rw & 1)
#define bio_rw(bio)             ((bio)->bi_rw & (RW_MASK))

#ifdef _WIN32
// DRBD_DOC: 지원 불가
// BIO_UPTODATE로 최신 갱신된 블럭인지 확인, windows는 항상 최신 블럭임. 
//  - 수신된 블럭이 리눅스 스타일 같이 코아 메모리 페이지로 존재하는 것이 아니기 떄문에 최신인지 판단 방안이 없음

#define bio_flagged(bio, flag)  (1) 
#else
#define bio_flagged(bio, flag)  ((bio)->bi_flags & (1 << (flag))) 
#endif

extern void rwlock_init(void *lock);
extern void spin_lock_init(spinlock_t *lock);
///extern void spin_lock_irqsave(spinlock_t *lock, long flags);
extern void spin_lock_irq(spinlock_t *lock);
extern void spin_lock_bh(spinlock_t *lock);
extern void spin_unlock_bh(spinlock_t *lock); // _WIN32_V9
extern void spin_lock(spinlock_t *lock);
extern void spin_unlock(spinlock_t *lock);
extern void spin_unlock_irq(spinlock_t *lock);
extern void spin_unlock_irqrestore(spinlock_t *lock, long flags);
extern long _spin_lock_irqsave(spinlock_t* lock);

#define spin_lock_irqsave(lock, flags) flags = _spin_lock_irqsave(lock); 

extern void read_lock(spinlock_t *lock);
extern void read_unlock(spinlock_t *lock);	
extern void write_unlock_bh(spinlock_t *lock);
extern void write_unlock(spinlock_t *lock);
extern void write_lock_irq(spinlock_t *lock);
extern void write_lock_bh(spinlock_t *lock);
extern void write_unlock_irq(spinlock_t *lock);

#ifdef _WIN32_TMP_DEBUG_MUTEX
extern void mutex_init(struct mutex *m, char *name);
#else
extern void mutex_init(struct mutex *m);
#endif

extern NTSTATUS mutex_lock(struct mutex *m);
extern int mutex_is_locked(struct mutex *m);
extern void mutex_unlock(struct mutex *m);
extern int mutex_trylock(struct mutex *m);

#ifdef _WIN32_V9 
extern int kref_put(struct kref *kref, void (*release)(struct kref *kref));
#else
extern void kref_put(struct kref *kref, void(*release)(struct kref *kref));
#endif
extern int kref_get(struct kref *kref);
extern void kref_init(struct kref *kref);

extern struct request_queue *bdev_get_queue(struct block_device *bdev);
extern void blk_cleanup_queue(struct request_queue *q);
extern struct request_queue *blk_alloc_queue(gfp_t gfp_mask);
typedef void (make_request_fn) (struct request_queue *q, struct bio *bio);
extern void blk_queue_make_request(struct request_queue *q, make_request_fn *mfn);
extern void blk_queue_flush(struct request_queue *q, unsigned int flush);

extern struct gendisk *alloc_disk(int minors);
extern void put_disk(struct gendisk *disk);
extern void del_gendisk(struct gendisk *disk);
extern void set_disk_ro(struct gendisk *disk, int flag);


#define PREPARE_WORK(_work, _func)                                      \
	do {                                                            \
		(_work)->func = (_func);                                \
	} while (0)

#define __INIT_WORK(_work, _func, _onstack)                             \
	 do {                                                           \
	       /* __init_work((_work), _onstack);        */  \
	       /*  (_work)->data = (atomic_long_t) WORK_DATA_INIT(); */ \
		INIT_LIST_HEAD(&(_work)->entry);                        \
		PREPARE_WORK((_work), (_func));                         \
	} while (0)

#define INIT_WORK(_work, _func)                                         \
	 __INIT_WORK((_work), (_func), 0);  

#define TASK_COMM_LEN		32
struct task_struct {
#ifdef _WIN32_CT
    struct list_head list; 
#else
    KEVENT start_event; 
    KEVENT wait_event;
    PKTHREAD current_thr;
#endif
	PKTHREAD pid; // for linux style
    KEVENT sig_event;
    BOOLEAN has_sig_event;
	int sig; 
    char comm[TASK_COMM_LEN];
};

/// SEO: mempool
extern mempool_t *mempool_create(int min_nr, void *alloc_fn, void *free_fn, void *pool_data);
extern mempool_t *mempool_create_page_pool(int min_nr, int order);
extern mempool_t *mempool_create_slab_pool(int min_nr, int order);
extern void * mempool_alloc(mempool_t *pool, gfp_t gfp_mask);
extern void mempool_free(void *req, void *mempool);
extern void mempool_destroy(void *p);
extern void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data);
extern void *mempool_free_slab(gfp_t gfp_mask, void *pool_data);

#define	atomic_inc_return(_p)		InterlockedIncrement((_p))
#define	atomic_dec_return(_p)		InterlockedDecrement((_p))
#define atomic_inc(_v)			atomic_inc_return(_v)
#define atomic_dec(_v)			atomic_dec_return(_v)

extern void atomic_set(const atomic_t *v, int i);
extern void atomic_add(int i, atomic_t *v);
extern void atomic_sub(int i, atomic_t *v);
extern int atomic_sub_return(int i, atomic_t *v); 
extern int atomic_dec_and_test(atomic_t *v);
extern int atomic_sub_and_test(int i, atomic_t *v);
extern long atomic_cmpxchg(atomic_t *v, int old, int new);
extern int atomic_read(const atomic_t *v);
extern int atomic_xchg(atomic_t *v, int n);

// from rcu_list.h


static __inline void init_waitqueue_head(wait_queue_head_t *q)
{	
	spin_lock_init(&(q)->lock);	
	INIT_LIST_HEAD(&(q)->task_list);
	KeInitializeEvent(&q->wqh_event, NotificationEvent, FALSE);
};

typedef int (congested_fn)(void *, int);

struct backing_dev_info {
	unsigned long ra_pages; /* max readahead in PAGE_CACHE_SIZE units */ 
	congested_fn *congested_fn; /* Function pointer if device is md/dm */
	void *congested_data;   /* Pointer to aux data for congested func */
	PVOLUME_EXTENSION pDeviceExtension;
};

struct request_queue {
	void * queuedata;
	struct backing_dev_info backing_dev_info;
	spinlock_t *queue_lock; // _WIN32: unused.
	unsigned short logical_block_size;
	long max_hw_sectors;
};

static __inline ULONG_PTR JIFFIES()
{
	LARGE_INTEGER Tick;
	LARGE_INTEGER Elapse;
	KeQueryTickCount(&Tick);
	Elapse.QuadPart = Tick.QuadPart * KeQueryTimeIncrement();
	Elapse.QuadPart /= (10000);
	return Elapse.QuadPart;
}

#define jiffies				JIFFIES()

#define time_after(_a,_b)		((LONG_PTR)((LONG_PTR)(_b) - (LONG_PTR)(_a)) < 0)
#define time_after_eq(_a,_b)		((LONG_PTR)((LONG_PTR)(_a) - (LONG_PTR)(_b)) >= 0)

#define time_before(_a,_b)		time_after(_b, _a)
#define time_before_eq(_a,_b)		time_after_eq(_b, _a)

struct lru_cache;
extern struct lc_element *lc_element_by_index(struct lru_cache *lc, unsigned i);
extern unsigned int lc_index_of(struct lru_cache *lc, struct lc_element *e);

struct page {
	ULONG_PTR *private;
	void *addr;
};

#define page_private(_page)		((_page)->private)
#define set_page_private(_page, _v)	((_page)->private = (_v))

extern void *page_address(const struct page *page);
extern int page_count(struct page *page);
extern void __free_page(const struct page *page);
extern struct page * alloc_page(int flag);

struct scatterlist {
	struct page *page;
	unsigned int offset;
	unsigned int length;
};

#define MINORMASK				26
#define LC_STARVING				10

#define BUG()   WDRBD_FATAL("BUG: failure\n")

#define BUG_ON(_condition)	\
    do {	\
        if(_condition) { \
            WDRBD_FATAL("BUG: failure\n"); \
        }\
    } while (0)


extern struct workqueue_struct *create_singlethread_workqueue(void *name, void  *wq_s, void *func, ULONG Tag);
extern void queue_work(struct workqueue_struct* queue, struct work_struct* work);
extern void destroy_workqueue(struct workqueue_struct *wq);

extern void kobject_put(struct kobject *kobj);
extern void kobject_get(struct kobject *kobj);
extern void kobject_del(struct kobject *kobj);

extern void * kcalloc(int e_count, int x, int flag, ULONG Tag);
extern void * kzalloc(int x, int flag);
extern void * kmalloc(int size, int flag);
extern void kfree(void * x);
extern void * kmem_cache_alloc(void * cache, int flag, ULONG Tag);
extern void kmem_cache_destroy(struct kmem_cache *s);
extern struct kmem_cache *kmem_cache_create(char *name, size_t size, size_t align, unsigned long flags, void (*ctor)(void *));
extern void kmem_cache_free(void * cache, void * x);


static __inline wait_queue_t initqueue(wait_queue_t *wq)
{
	INIT_LIST_HEAD(&wq->task_list);
	return *wq; 
}

#define DEFINE_WAIT(name)
#define DEFINE_WAIT_FUNC(name)

extern void init_completion(struct completion *x);
extern long wait_for_completion(struct completion *x);
#ifdef WSK_ACCEPT_EVENT_CALLBACK
extern long wait_for_completion_timeout(struct completion *x, long timeout);
#endif
extern void complete(struct completion *c);
extern void complete_all(struct completion *c);

extern int signal_pending(struct task_struct *p);
extern void force_sig(int sig, struct task_struct *p);
extern void flush_signals(struct task_struct *p);
extern long schedule(wait_queue_head_t *q, long timeout, char *func, int line);

#define SCHED_Q_INTERRUPTIBLE	1
#define schedule_timeout_interruptible(timeout)  schedule((wait_queue_head_t *)SCHED_Q_INTERRUPTIBLE, (timeout), __FUNCTION__, __LINE__)
#define schedule_timeout_uninterruptible(timeout) schedule_timeout(timeout) 
#define schedule_timeout(timeout) schedule((wait_queue_head_t *)NULL, (timeout), __FUNCTION__, __LINE__)

#define __wait_event(wq, condition, __func, __line) \
	do {\
		for (;;) {\
			if (condition) \
						{ \
				break; \
						} \
			schedule(&wq, 1, __func, __line); /*  DW105: workaround: 1 ms polling  */ \
				} \
		} while (0)

#define wait_event(wq, condition) \
	do {\
		if (condition) \
			break; \
		__wait_event(wq, condition, __FUNCTION__, __LINE__); \
		} while (0)


#define __wait_event_timeout(wq, condition, ret)  \
	do {\
		int i = 0;\
		int t = 0;\
		for (;;) {\
			i++; \
			if (condition)   \
						{\
				break;     \
						}\
			/*ret = schedule(&wq, ret, __FUNC__, __LINE__);*/\
			if (++t > ret) \
						{\
				ret = 0;\
				break;\
						}\
			schedule(&wq, 1, __FUNCTION__, __LINE__); /*  DW105: workaround: 1 ms polling  */ \
				}  \
		} while (0)

#define wait_event_timeout(t, wq, condition, timeout) \
	do { \
		long __ret = timeout; \
		if (!(condition)) \
			__wait_event_timeout(wq, condition, __ret);  \
		t = __ret; \
		} while (0)

#define __wait_event_interruptible(wq, condition, ret)   \
	do { \
		for (;;) { \
			if (condition)     \
						{ \
				break;      \
						} \
			/* if (!signal_pending(current)) */ \
			{ \
				/*schedule(&wq, MAX_SCHEDULE_TIMEOUT, __FUNC__, __LINE__); */\
				schedule(&wq, 1, __FUNCTION__, __LINE__); /* DW105: workaround: 1 ms polling */ \
			}  \
				} \
		} while (0)

#define wait_event_interruptible(sig, wq, condition) \
	do {\
			int __ret = 0;  \
			if (!(condition))  \
				__wait_event_interruptible(wq, condition, __ret); \
			sig = __ret; \
		} while (0)

// _WIN32_V9 : CHECK
#define wait_event_interruptible_timeout(t, wq, cond, to) \
	do {\
			DbgPrint("_WIN32_CHECK: make wait_event_interruptible_timeout body!!\n"); \
		} while (0)

#define wake_up(q) _wake_up(q, __FUNCTION__, __LINE__)

#ifdef _WIN32_CT
struct drbd_thread;
extern void wake_up_process(struct drbd_thread *thi);
#else
extern int wake_up_process(struct task_struct *nt);
#endif

extern void _wake_up(wait_queue_head_t *q, char *__func, int __line);

extern int test_and_change_bit(int nr, const ULONG_PTR *vaddr);
extern size_t find_next_bit(const ULONG_PTR *addr, ULONG_PTR size, ULONG_PTR offset);
extern int find_next_zero_bit(const ULONG_PTR * addr, ULONG_PTR size, ULONG_PTR offset);

__inline
int test_and_set_bit(int bit, ULONG_PTR * base)
{
#ifdef _WIN64
    return (InterlockedBitTestAndSet64((volatile __int64 *)base, bit));
#else
    return (InterlockedBitTestAndSet((volatile long *)base, bit));
#endif
}

__inline
int test_and_clear_bit(int bit, ULONG_PTR * base)
{
#ifdef _WIN64
    return (InterlockedBitTestAndReset64((volatile __int64 *)base, bit));
#else
    return (InterlockedBitTestAndReset((volatile long *)base, bit));
#endif
}

__inline
void set_bit(int bit, ULONG_PTR * base)
{
    test_and_set_bit(bit, base);
}

__inline
void clear_bit(int bit, ULONG_PTR * base)
{
    test_and_clear_bit(bit, base);
}

static __inline void __set_bit(int nr, volatile ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);

	*p |= mask;
}

static __inline int __test_and_set_bit(int nr, volatile ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);
	ULONG_PTR old = *p;

	*p = old | mask;
	return (old & mask) != 0;
}

static __inline int __test_and_clear_bit(int nr, volatile ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);
	ULONG_PTR old = *p;

	*p = old & ~mask;
	return (old & mask) != 0;
}

static __inline int test_bit(int nr, const volatile ULONG_PTR *addr)
{
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG - 1)));
}

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define generic_test_le_bit(nr, addr)			test_bit(nr, addr)
#define generic___test_and_set_le_bit(nr, addr)		__test_and_set_bit(nr, addr)
#define generic___test_and_clear_le_bit(nr, addr)	__test_and_clear_bit(nr, addr)
#define generic_find_next_zero_le_bit(addr, size, offset) find_next_zero_bit(addr, size, offset)
#define generic_find_next_le_bit(addr, size, offset)	find_next_bit(addr, size, offset)
#endif

// _WIN32_CHECK: 헤더가 windrv.h 로 이동시킨 이유는 기억이 안남. 일단 V8과 동일하게 유지히고 추후 정리!!
struct retry_worker {
	struct workqueue_struct *wq;
	struct work_struct worker;
	spinlock_t lock;
	struct list_head writes;
	struct task_struct task;
};


#ifdef _WIN32_CT
#define current		    ct_find_thread(KeGetCurrentThread())
#else
/// SEO: 리눅스 코드 유지용 함수
extern struct task_struct * find_current_thread(); 
#define current		find_current_thread()
#endif

#define MAX_PROC_BUF	2048

extern void *crypto_alloc_tfm(char *name, u32 mask);
extern unsigned int crypto_tfm_alg_digestsize(struct crypto_tfm *tfm);

extern void generic_make_request(struct bio *bio);

extern int call_usermodehelper(char *path, char **argv, char **envp, enum umh_wait wait);

extern void * ERR_PTR(long error);
extern long PTR_ERR(const void *ptr);
extern long IS_ERR_OR_NULL(const void *ptr);
extern int IS_ERR(void *err);

extern int blkdev_issue_flush(struct block_device *bdev, gfp_t gfp_mask, sector_t *error_sector);
extern struct block_device *blkdev_get_by_path(const char *path, fmode_t mode, void *holder);

extern void hlist_add_head(struct hlist_node *n, struct hlist_head *h);
extern void hlist_del_init(struct hlist_node *entry);
extern int hlist_unhashed(const struct hlist_node *h);
extern void __hlist_del(struct hlist_node *n);

extern uint32_t crc32c(uint32_t crc, const uint8_t *data, unsigned int length);
extern bool lc_is_used(struct lru_cache *lc, unsigned int enr);
extern void get_random_bytes(void *buf, int nbytes);
extern int fls(int x);
extern unsigned char *skb_put(struct sk_buff *skb, unsigned int len);
extern char *kstrdup(const char *s, int gfp);
extern void panic(char *msg);
///

/// SEO: 전역 변수
extern int proc_details;
extern int g_bypass_level;
extern int g_read_filter;
extern int g_use_volume_lock;
extern int g_netlink_tcp_port;
extern int g_daemon_tcp_port;
extern WCHAR g_ver[];

extern PETHREAD	g_NetlinkServerThread;
extern union drbd_state g_mask; 
extern union drbd_state g_val;
///

extern void dumpHex(const void *b, const size_t s, size_t w);	/// SEO: 참조 없음
extern void ResolveDriveLetters(void);

extern VOID MVOL_LOCK();
extern VOID MVOL_UNLOCK();
#ifdef _WIN32_MVFL
extern NTSTATUS FsctlDismountVolume(unsigned int minor);
extern NTSTATUS FsctlLockVolume(unsigned int minor);
extern NTSTATUS FsctlUnlockVolume(unsigned int minor);
extern NTSTATUS FsctlFlushVolume(unsigned int minor);
extern NTSTATUS FsctlCreateVolume(unsigned int minor);
#endif

#ifdef WSK_EVENT_CALLBACK
extern
void InitWskNetlink(void * pctx);

extern
NTSTATUS ReleaseWskNetlink();

// Forward declaration for WskAcceptEvent in WSK_CLIENT_LISTEN_DISPATCH
extern
NTSTATUS WSKAPI
NetlinkAcceptEvent(
_In_  PVOID         SocketContext,
_In_  ULONG         Flags,
_In_  PSOCKADDR     LocalAddress,
_In_  PSOCKADDR     RemoteAddress,
_In_opt_  PWSK_SOCKET AcceptSocket,
_Outptr_result_maybenull_ PVOID *AcceptSocketContext,
_Outptr_result_maybenull_ CONST WSK_CLIENT_CONNECTION_DISPATCH **AcceptSocketDispatch
);
#endif

extern PMOUNTDEV_UNIQUE_ID RetrieveVolumeGuid(PDEVICE_OBJECT devObj);
extern PVOLUME_EXTENSION mvolSearchDevice(PWCHAR PhysicalDeviceName);
extern NTSTATUS mvolGetVolumeSize(PDEVICE_OBJECT TargetDeviceObject, PLARGE_INTEGER pVolumeSize);
extern int initRegistry(__in PUNICODE_STRING RegistryPath);
extern NTSTATUS DeleteRegistryValueKey(__in PUNICODE_STRING preg_path, __in PUNICODE_STRING pvalue_name);
extern NTSTATUS DeleteDriveLetterInRegistry(char letter);
extern void NTAPI NetlinkServerThread(PVOID p);
extern struct block_device * create_drbd_block_device(IN OUT PVOLUME_EXTENSION pvext);
extern BOOLEAN do_add_minor(unsigned int minor);
extern void drbdCreateDev();
extern void drbdFreeDev(PVOLUME_EXTENSION pDeviceExtension);
extern void query_targetdev(PVOLUME_EXTENSION pvext);
extern void refresh_targetdev_list();
extern PVOLUME_EXTENSION get_targetdev_by_minor(unsigned int minor);
extern struct drbd_conf *get_targetdev_by_md(char letter);
extern LONGLONG get_targetdev_volsize(PVOLUME_EXTENSION deviceExtension);

extern int WriteEventLogEntryData(
	ULONG	pi_ErrorCode,
	ULONG	pi_UniqueErrorCode,
	ULONG	pi_FinalStatus,
	ULONG	pi_nDataItems,
	...
);

extern PUNICODE_STRING ucsdup(IN OUT PUNICODE_STRING dst, IN PUNICODE_STRING src);
extern void ucsfree(IN PUNICODE_STRING str);

/// SEO: RCU 관련 함수 묶음, 제거 대상
extern void list_add_rcu(struct list_head *new, struct list_head *head);
extern void list_add_tail_rcu(struct list_head *new,   struct list_head *head);
extern void list_del_rcu(struct list_head *entry);

#define rcu_dereference(_PTR)		(_PTR)
#define __rcu_assign_pointer(_p, _v) \
	do { \
		smp_mb(); \
		(_p) = (_v); \
	} while (0)

#define rcu_assign_pointer(p, v) 	__rcu_assign_pointer((p), (v))
#define list_next_rcu(list)		(*((struct list_head **)(&(list)->next)))

extern EX_SPIN_LOCK g_rcuLock;

#define rcu_read_lock() \
    unsigned char oldIrql_rLock = ExAcquireSpinLockShared(&g_rcuLock);

#define rcu_read_unlock() \
    ExReleaseSpinLockShared(&g_rcuLock, oldIrql_rLock);

#define rcu_read_lock_w32_inner() \
	oldIrql_rLock = ExAcquireSpinLockShared(&g_rcuLock);

#define synchronize_rcu_w32_wlock() \
	unsigned char  oldIrql_wLock; \
	oldIrql_wLock = ExAcquireSpinLockExclusive(&g_rcuLock);

#define synchronize_rcu() \
	ExReleaseSpinLockExclusive(&g_rcuLock, oldIrql_wLock);

#ifdef _WIN32_CT
extern void ct_init_thread_list();
extern struct task_struct * ct_add_thread(PKTHREAD id, char *name, BOOLEAN event, ULONG Tag);
extern void ct_delete_thread(PKTHREAD id);
extern struct task_struct* ct_find_thread(PKTHREAD id);
#endif

//
//  Lock primitives
//

_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
FORCEINLINE
VOID
MvfAcquireResourceExclusive(
_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_exclusive_lock_(*_Curr_)
PERESOURCE Resource
)
{
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    NT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
        !ExIsResourceAcquiredSharedLite(Resource));

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceExclusiveLite(Resource, TRUE);
}

_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
FORCEINLINE
VOID
MvfAcquireResourceShared(
_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_shared_lock_(*_Curr_)
PERESOURCE Resource
)
{
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceSharedLite(Resource, TRUE);
}

_Releases_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
FORCEINLINE
VOID
MvfReleaseResource(
_Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_)
PERESOURCE Resource
)
{
    NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
    NT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
        ExIsResourceAcquiredSharedLite(Resource));

    ExReleaseResourceLite(Resource);
    KeLeaveCriticalRegion();
}

typedef struct _PTR_ENTRY
{
    SINGLE_LIST_ENTRY   slink;
    void *              ptr;
} PTR_ENTRY, * PPTR_ENTRY;


#ifdef _WIN32_V9
/////////////////////////////////////////////////////////////////////
// linux-2.6.24 define 
////////////////////////////////////////////////////////////////////

// kernel.h 
#define UINT_MAX	(~0U)

// socket.h 
#define MSG_DONTROUTE	4
#define MSG_PROBE		0x10	/* Do not send. Only probe path f.e. for MTU */

// asm-x86
#define PAGE_SHIFT	12		//_WIN32_CHECK Windows환경으로 포팅필요

//pagemap.h
#define PAGE_CACHE_SHIFT	PAGE_SHIFT //_WIN32_CHECK Windows환경으로 포팅필요

// Bio.h
#define BIO_MAX_PAGES		256		//_WIN32_CHECK Windows환경으로 포팅필요
#define BIO_MAX_SIZE		(BIO_MAX_PAGES << PAGE_CACHE_SHIFT) //_WIN32_CHECK Windows환경으로 포팅필요

//asm-x86 , asm-generic 
#define	EDESTADDRREQ	89	/* Destination address required */

/////////////////////////////////////////////////////////////////////
// linux-2.6.24 define end
////////////////////////////////////////////////////////////////////

#endif

#ifdef _WIN32_V9 // CHECK!!
#if 0
60 /* Common initializer macros and functions */
61
62 #ifdef CONFIG_DEBUG_LOCK_ALLOC
63 # define __RWSEM_DEP_MAP_INIT(lockname), .dep_map = { .name = #lockname }
64 #else
65 # define __RWSEM_DEP_MAP_INIT(lockname)
66 #endif
67
68 #ifdef CONFIG_RWSEM_SPIN_ON_OWNER
69 #define __RWSEM_OPT_INIT(lockname), .osq = OSQ_LOCK_UNLOCKED, .owner = NULL
70 #else
71 #define __RWSEM_OPT_INIT(lockname)
72 #endif
73
74 #define __RWSEM_INITIALIZER(name)                               \
 75         { .count = RWSEM_UNLOCKED_VALUE,                        \
 76           .wait_list = LIST_HEAD_INIT((name).wait_list),        \
 77           .wait_lock = __RAW_SPIN_LOCK_UNLOCKED(name.wait_lock) \
 78           __RWSEM_OPT_INIT(name)                                \
 79           __RWSEM_DEP_MAP_INIT(name) }
80
81 #define DECLARE_RWSEM(name) \
 82         struct rw_semaphore name = __RWSEM_INITIALIZER(name)
#endif

//semaphore 임시 포팅. 
// mutex.h 가 사용안되는 듯. 일단 복잡하여 이곳에서 처리함. 
struct semaphore {
	//17         raw_spinlock_t          lock;
	//18         unsigned int            count;
	//19         struct list_head        wait_list;
	//20 

	int dummy;
};

extern void down(struct semaphore *sem);
extern void up(struct semaphore *sem);
extern void down_write(struct semaphore *sem);
extern void down_read(struct semaphore *sem);
extern void up_write(struct semaphore *sem);
extern void up_read(struct semaphore *sem);

//uninitialized_va 매트로 처리!

//extern struct mutex notification_mutex; // kmpak 불필요

static int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
	sector_t nr_sects, gfp_t gfp_mask, bool discard)
{
	// _WIN32_CHECK: zero fill bio 관련 linux 의존 기능인 듯. 구현이 불필요 할 수도 있을 듯.
	DbgPrint("WIN32_CHECK: blkdev_issue_zeroout!\n");
}


#endif

#define snprintf(a, b, c,...) memset(a, 0, b); sprintf(a, c, ##__VA_ARGS__)

int drbd_genl_multicast_events(void *mdev, const struct sib_info *sib);

// _WIN32_V9: check later! scnprintf
static int scnprintf(char *buffer, int size, char *str)
{
	//DbgPrintf("DRBD_CHECK:descnprintf!!!!");
	return 0;
}

#endif __DRBD_WINDRV_H__
