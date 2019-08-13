﻿/*
  drbd_int.h

  This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

  Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
  Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
  Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

  drbd is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.

  drbd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with drbd; see the file COPYING.  If not, write to
  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#ifndef _DRBD_INT_H
#define _DRBD_INT_H

#ifdef _WIN32
//#pragma warning (disable : 4221 4706)
#include "stddef.h"
#include "windows/types.h"
#include "linux-compat/list.h"
#include "linux-compat/sched.h"
#include "linux-compat/bitops.h"
#include "linux/lru_cache.h"
#include "linux/drbd_genl_api.h"
#include "windows/drbd.h"
#include "linux/drbd_config.h"
#include "linux/drbd_limits.h"
#else
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/ratelimit.h>
#include <linux/mutex.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/genhd.h>
#include <linux/idr.h>
#include <linux/lru_cache.h>
#include <linux/prefetch.h>
#include <linux/drbd_genl_api.h>
#include <linux/drbd.h>
#include <linux/drbd_config.h>
#endif
#include "./drbd-kernel-compat/drbd_wrappers.h"
#include "drbd_strings.h"
#ifdef _WIN32_SEND_BUFFING
#include "send_buf.h"
#endif
#ifndef _WIN32
#include "compat.h"
#endif
#include "drbd_state.h"
#include "drbd_protocol.h"
#include "drbd_kref_debug.h"
#include "drbd_transport.h"

#ifdef __CHECKER__
# define __protected_by(x)       __attribute__((require_context(x,1,999,"rdwr")))
# define __protected_read_by(x)  __attribute__((require_context(x,1,999,"read")))
# define __protected_write_by(x) __attribute__((require_context(x,1,999,"write")))
# define __must_hold(x)       __attribute__((context(x,1,1), require_context(x,1,999,"call")))
#else
# define __protected_by(x)
# define __protected_read_by(x)
# define __protected_write_by(x)
# define __must_hold(x)
#endif

/* Compatibility for older kernels */
#ifndef __acquires
# ifdef __CHECKER__
#  define __acquires(x)	__attribute__((context(x,0,1)))
#  define __releases(x)	__attribute__((context(x,1,0)))
#  define __acquire(x)	__context__(x,1)
#  define __release(x)	__context__(x,-1)
# else
#  define __acquires(x)
#  define __releases(x)
#  define __acquire(x)	(void)0
#  define __release(x)	(void)0
# endif
#endif

/* module parameter, defined in drbd_main.c */
extern unsigned int minor_count;
extern bool disable_sendpage;
extern bool allow_oos;

#ifdef CONFIG_DRBD_FAULT_INJECTION
extern int enable_faults;
extern int fault_rate;
extern int fault_devs;
extern int two_phase_commit_fail;
#endif

#ifdef _WIN32
// MODIFIED_BY_MANTECH DW-1200: currently allocated request buffer size in byte.
extern atomic_t64 g_total_req_buf_bytes;
#endif

extern char usermode_helper[];

#ifndef DRBD_MAJOR
# define DRBD_MAJOR 147
#endif

/* This is used to stop/restart our threads.
 * Cannot use SIGTERM nor SIGKILL, since these
 * are sent out by init on runlevel changes
 * I choose SIGHUP for now.
 *
 * FIXME btw, we should register some reboot notifier.
 */
#define DRBD_SIGKILL SIGHUP

#define ID_IN_SYNC      (4711ULL)
#define ID_OUT_OF_SYNC  (4712ULL)
#define ID_SYNCER (UINT64_MAX)
//DW-1601 Add define values for split peer request processing and already sync processing
#define ID_SYNCER_SPLIT_DONE ID_SYNCER
#define ID_SYNCER_SPLIT (ID_SYNCER - 1)

#define UUID_NEW_BM_OFFSET ((u64)0x0001000000000000ULL)

struct drbd_device;
struct drbd_connection;

/* I want to be able to grep for "drbd $resource_name"
 * and get all relevant log lines. */
#ifdef _WIN32
#define __drbd_printk_device(level, device, fmt, ...)		\
    do {								\
        const struct drbd_device *__d = (device);		\
        const struct drbd_resource *__r = __d->resource;	\
        printk(level "drbd %s/%u minor %u, ds(%s), dvflag(0x%x): " fmt,			\
            __r->name, __d->vnr, __d->minor, drbd_disk_str(__d->disk_state[NOW]), __d->flags, __VA_ARGS__);	\
    } while (0,0)

// DW-1494 : (peer_device)->uuid_flags has caused a problem with the 32-bit operating system and therefore removed
#define __drbd_printk_peer_device(level, peer_device, fmt, ...)	\
    do {								\
        const struct drbd_device *__d;				\
        const struct drbd_connection *__c;			\
        const struct drbd_resource *__r;			\
        int __cn;					\
        /*rcu_read_lock();		_WIN32 // DW-	*/		\
        __d = (peer_device)->device;				\
        __c = (peer_device)->connection;			\
        __r = __d->resource;					\
        __cn = __c->peer_node_id;	\
        printk(level "drbd %s/%u minor %u pnode-id:%d, pdsk(%s), prpl(%s), pdvflag(0x%x): " fmt,		\
            __r->name, __d->vnr, __d->minor, __cn, drbd_disk_str((peer_device)->disk_state[NOW]), drbd_repl_str((peer_device)->repl_state[NOW]), (peer_device)->flags, __VA_ARGS__);\
        /*rcu_read_unlock();	_WIN32 // DW-	*/		\
	    } while (0,0)

#define __drbd_printk_resource(level, resource, fmt, ...) \
	printk(level "drbd %s, r(%s), f(0x%x), scf(0x%x): " fmt, (resource)->name, drbd_role_str((resource)->role[NOW]), (resource)->flags,(resource)->state_change_flags, __VA_ARGS__)

#define __drbd_printk_connection(level, connection, fmt, ...) \
    do {	                    \
        /*rcu_read_lock();	_WIN32 // DW- */ \
        printk(level "drbd %s pnode-id:%d, cs(%s), prole(%s), cflag(0x%x), scf(0x%x): " fmt, (connection)->resource->name,  \
        (connection)->peer_node_id, drbd_conn_str((connection)->cstate[NOW]), drbd_role_str((connection)->peer_role[NOW]), (connection)->flags,(connection)->resource->state_change_flags, __VA_ARGS__); \
        /*rcu_read_unlock(); _WIN32 // DW- */ \
	    } while (0,0)

void drbd_printk_with_wrong_object_type(void);
 
#define __drbd_printk_if_same_type(obj, type, func, level, fmt, ...) 

#define drbd_printk(level, obj, fmt, ...)   \
    do {    \
        __drbd_printk_##obj(level, obj, fmt, __VA_ARGS__);  \
    } while(0,0)

#if defined(disk_to_dev)
#define drbd_dbg(device, fmt, args...) \
	dev_dbg(disk_to_dev(device->vdisk), fmt, ## args)
#elif defined(DBG)
#define drbd_dbg(device, fmt, ...) \
	drbd_printk(KERN_DEBUG, device, fmt, __VA_ARGS__)
#else
#define drbd_dbg(device, fmt, ...) \
	do { if (false,false) drbd_printk(KERN_DEBUG, device, fmt, __VA_ARGS__); } while(false,false)
#endif

#if defined(dynamic_dev_dbg) && defined(disk_to_dev)
#define dynamic_drbd_dbg(device, fmt, args...) \
	dynamic_dev_dbg(disk_to_dev(device->vdisk), fmt, ## args)
#elif defined(_WIN32) && defined(DBG)
#define dynamic_drbd_dbg(device, fmt, ...) \
	drbd_dbg(device, fmt, __VA_ARGS__)
#else
#define dynamic_drbd_dbg(device, fmt, ...)
#endif

#define drbd_emerg(device, fmt, ...) \
	drbd_printk(KERN_EMERG, device, fmt, __VA_ARGS__)
#define drbd_alert(device, fmt, ...) \
	drbd_printk(KERN_ALERT, device, fmt, __VA_ARGS__)
#define drbd_err(device, fmt, ...) \
	drbd_printk(KERN_ERR, device, fmt, __VA_ARGS__)
#define drbd_warn(device, fmt, ...) \
	drbd_printk(KERN_WARNING, device, fmt, __VA_ARGS__)
#define drbd_info(device, fmt, ...) \
	drbd_printk(KERN_INFO, device, fmt, __VA_ARGS__)

#if defined(DBG)
#define drbd_debug(obj, fmt, ...) \
	drbd_printk(KERN_DEBUG, obj, fmt, __VA_ARGS__)
#else
#define drbd_debug(obj, fmt, ...) drbd_printk(KERN_DEBUG, obj, fmt, __VA_ARGS__)
#endif
#else
#define __drbd_printk_device(level, device, fmt, args...)		\
	({								\
		const struct drbd_device *__d = (device);		\
		const struct drbd_resource *__r = __d->resource;	\
		printk(level "drbd %s/%u drbd%u: " fmt,			\
			__r->name, __d->vnr, __d->minor, ## args);	\
	})

#define __drbd_printk_peer_device(level, peer_device, fmt, args...)	\
	({								\
		const struct drbd_device *__d;				\
		const struct drbd_connection *__c;			\
		const struct drbd_resource *__r;			\
		const char *__cn;					\
		rcu_read_lock();					\
		__d = (peer_device)->device;				\
		__c = (peer_device)->connection;			\
		__r = __d->resource;					\
		__cn = rcu_dereference(__c->transport.net_conf)->name;	\
		printk(level "drbd %s/%u drbd%u %s: " fmt,		\
			__r->name, __d->vnr, __d->minor, __cn, ## args);\
		rcu_read_unlock();					\
	})

#define __drbd_printk_resource(level, resource, fmt, args...) \
	printk(level "drbd %s: " fmt, (resource)->name, ## args)

#define __drbd_printk_connection(level, connection, fmt, args...) \
	({	rcu_read_lock(); \
		printk(level "drbd %s %s: " fmt, (connection)->resource->name,  \
		       rcu_dereference((connection)->transport.net_conf)->name, ## args); \
		rcu_read_unlock(); \
	})

void drbd_printk_with_wrong_object_type(void);

#define __drbd_printk_if_same_type(obj, type, func, level, fmt, args...) \
	(__builtin_types_compatible_p(typeof(obj), type) || \
	 __builtin_types_compatible_p(typeof(obj), const type)), \
	func(level, (const type)(obj), fmt, ## args)

#define drbd_printk(level, obj, fmt, args...) \
	__builtin_choose_expr( \
	  __drbd_printk_if_same_type(obj, struct drbd_device *, \
			     __drbd_printk_device, level, fmt, ## args), \
	  __builtin_choose_expr( \
	    __drbd_printk_if_same_type(obj, struct drbd_resource *, \
			       __drbd_printk_resource, level, fmt, ## args), \
	    __builtin_choose_expr( \
	      __drbd_printk_if_same_type(obj, struct drbd_connection *, \
				 __drbd_printk_connection, level, fmt, ## args), \
	      __builtin_choose_expr( \
		__drbd_printk_if_same_type(obj, struct drbd_peer_device *, \
				 __drbd_printk_peer_device, level, fmt, ## args), \
	        drbd_printk_with_wrong_object_type()))))

#if defined(disk_to_dev)
#define drbd_dbg(device, fmt, args...) \
	dev_dbg(disk_to_dev(device->vdisk), fmt, ## args)
#elif defined(DEBUG)
#define drbd_dbg(device, fmt, args...) \
	drbd_printk(KERN_DEBUG, device, fmt, ## args)
#else
#define drbd_dbg(device, fmt, args...) \
	do { if (0) drbd_printk(KERN_DEBUG, device, fmt, ## args); } while (0)
#endif

#if defined(dynamic_dev_dbg) && defined(disk_to_dev)
#define dynamic_drbd_dbg(device, fmt, args...) \
	dynamic_dev_dbg(disk_to_dev(device->vdisk), fmt, ## args)
#else
#define dynamic_drbd_dbg(device, fmt, args...) \
	drbd_dbg(device, fmt, ## args)
#endif

#define drbd_emerg(device, fmt, args...) \
	drbd_printk(KERN_EMERG, device, fmt, ## args)
#define drbd_alert(device, fmt, args...) \
	drbd_printk(KERN_ALERT, device, fmt, ## args)
#define drbd_err(device, fmt, args...) \
	drbd_printk(KERN_ERR, device, fmt, ## args)
#define drbd_warn(device, fmt, args...) \
	drbd_printk(KERN_WARNING, device, fmt, ## args)
#define drbd_info(device, fmt, args...) \
	drbd_printk(KERN_INFO, device, fmt, ## args)

#if defined(DEBUG)
#define drbd_debug(obj, fmt, args...) \
	drbd_printk(KERN_DEBUG, obj, fmt, ## args)
#else
#define drbd_debug(obj, fmt, args...)
#endif
#endif

#ifdef _WIN32
#define DEFAULT_RATELIMIT_INTERVAL      (5 * HZ)
#define DEFAULT_RATELIMIT_BURST         10

struct ratelimit_state {
	spinlock_t		lock;           /* protect the state */
	int             interval;
	int             burst;
	int             printed;
	int             missed;
	ULONG_PTR	    begin;
};
#endif

extern struct ratelimit_state drbd_ratelimit_state;

#ifdef _WIN32
extern int _DRBD_ratelimit(struct ratelimit_state *rs, const char * func, const char * __FILE, const int __LINE);
#define drbd_ratelimit() _DRBD_ratelimit(&drbd_ratelimit_state, __FUNCTION__, __FILE__, __LINE__)
#else
static inline int drbd_ratelimit(void)
{
	return __ratelimit(&drbd_ratelimit_state);
}
#endif

#ifdef _WIN32
#define D_ASSERT(x, exp) \
		if (!(exp))	{ \
			DbgPrint("\n\nASSERTION %s FAILED in %s #########\n\n",	\
				 #exp, __func__); \
		} 
#else
#define D_ASSERT(x, exp)							\
	do {									\
		if (!(exp))							\
			drbd_err(x, "ASSERTION %s FAILED in %s\n",		\
				 #exp, __func__);				\
	} while (0)
#endif
/**
 * expect  -  Make an assertion
 *
 * Unlike the assert macro, this macro returns a boolean result.
 */
#ifdef _WIN32
#define expect(x, exp) (exp)
#else
#define expect(x, exp) ({							\
		bool _bool = (exp);						\
		if (!_bool)							\
			drbd_err(x, "ASSERTION %s FAILED in %s\n",		\
			        #exp, __func__);				\
		_bool;								\
		})
#endif

/* Defines to control fault insertion */
#ifndef _WIN32
enum {
#else
enum _fault {
#endif
	DRBD_FAULT_MD_WR = 0,	/* meta data write */
	DRBD_FAULT_MD_RD = 1,	/*           read  */
	DRBD_FAULT_RS_WR = 2,	/* resync          */
	DRBD_FAULT_RS_RD = 3,
	DRBD_FAULT_DT_WR = 4,	/* data            */
	DRBD_FAULT_DT_RD = 5,
	DRBD_FAULT_DT_RA = 6,	/* data read ahead */
	DRBD_FAULT_BM_ALLOC = 7,	/* bitmap allocation */
	DRBD_FAULT_AL_EE = 8,	/* alloc ee */
	DRBD_FAULT_RECEIVE = 9, /* Changes some bytes upon receiving a [rs]data block */

	DRBD_FAULT_MAX,
};

extern unsigned int
_drbd_insert_fault(struct drbd_device *device, unsigned int type);

static inline int
drbd_insert_fault(struct drbd_device *device, unsigned int type) {
#ifdef CONFIG_DRBD_FAULT_INJECTION
#ifdef _WIN32
	int ret = fault_rate &&
		(enable_faults & (1<<type)) &&
		_drbd_insert_fault(device, type);

    if (ret)
    {
        WDRBD_INFO("FALUT_TEST: type=0x%x fault=%d\n", type, ret);
    }
    return ret;
#else
	return fault_rate &&
		(enable_faults & (1<<type)) &&
		_drbd_insert_fault(device, type);
#endif
#else
	return 0;
#endif
}

/*
 * our structs
 *************************/

#define SET_MDEV_MAGIC(x) \
	({ typecheck(struct drbd_device*, x); \
	  (x)->magic = (long)(x) ^ DRBD_MAGIC; })
#define IS_VALID_MDEV(x)  \
	(typecheck(struct drbd_device*, x) && \
	  ((x) ? (((x)->magic ^ DRBD_MAGIC) == (long)(x)) : 0))

extern struct idr drbd_devices; /* RCU, updates: genl_lock() */
extern struct list_head drbd_resources; /* RCU, updates: resources_mutex */
extern struct mutex resources_mutex;

/* for sending/receiving the bitmap,
 * possibly in some encoding scheme */
struct bm_xfer_ctx {
	/* "const"
	 * stores total bits and long words
	 * of the bitmap, so we don't need to
	 * call the accessor functions over and again. */
#ifdef _WIN32
	ULONG_PTR bm_bits;
	ULONG_PTR bm_words;
	/* during xfer, current position within the bitmap */
	ULONG_PTR bit_offset;
	ULONG_PTR word_offset;
#else
	unsigned long bm_bits;
	unsigned long bm_words;
	/* during xfer, current position within the bitmap */
	unsigned long bit_offset;
	unsigned long word_offset;
#endif

	/* statistics; index: (h->command == P_BITMAP) */
	unsigned packets[2];
	unsigned bytes[2];
};

extern void INFO_bm_xfer_stats(struct drbd_peer_device *, const char *, struct bm_xfer_ctx *);

static inline void bm_xfer_ctx_bit_to_word_offset(struct bm_xfer_ctx *c)
{
	/* word_offset counts "native long words" (32 or 64 bit),
	 * aligned at 64 bit.
	 * Encoded packet may end at an unaligned bit offset.
	 * In case a fallback clear text packet is transmitted in
	 * between, we adjust this offset back to the last 64bit
	 * aligned "native long word", which makes coding and decoding
	 * the plain text bitmap much more convenient.  */
#if BITS_PER_LONG == 64
	c->word_offset = c->bit_offset >> 6;
#elif BITS_PER_LONG == 32
	c->word_offset = c->bit_offset >> 5;
	c->word_offset &= ~(1UL);
#else
# error "unsupported BITS_PER_LONG"
#endif
}

extern unsigned int drbd_header_size(struct drbd_connection *connection);

/**********************************************************************/
enum drbd_thread_state {
	NONE,
	RUNNING,
	EXITING,
	RESTARTING
};

struct drbd_thread {
#ifdef _WIN32
    struct task_struct *nt;
    KEVENT start_event;
    KEVENT wait_event;
#endif
	spinlock_t t_lock;
	struct task_struct *task;
	struct completion stop;
	enum drbd_thread_state t_state;
	int (*function) (struct drbd_thread *);
	struct drbd_resource *resource;
	struct drbd_connection *connection;
	int reset_cpu_mask;
	const char *name;
};

static inline enum drbd_thread_state get_t_state(struct drbd_thread *thi)
{
	/* THINK testing the t_state seems to be uncritical in all cases
	 * (but thread_{start,stop}), so we can read it *without* the lock.
	 *	--lge */

	smp_rmb();
	return thi->t_state;
}

struct drbd_work {
	struct list_head list;
	int (*cb)(struct drbd_work *, int cancel);
};

struct drbd_io_error_work {
	struct drbd_work w;
	struct drbd_device *device;
	struct drbd_io_error *io_error;
};

struct drbd_peer_device_work {
	struct drbd_work w;
	struct drbd_peer_device *peer_device;
};

enum drbd_stream;

#include "drbd_interval.h"

extern int drbd_wait_misc(struct drbd_device *, struct drbd_peer_device *, struct drbd_interval *);

extern void lock_all_resources(void);
extern void unlock_all_resources(void);

extern enum drbd_disk_state disk_state_from_md(struct drbd_device *);
extern bool want_bitmap(struct drbd_peer_device *peer_device);
extern void device_to_info(struct device_info *, struct drbd_device *);
extern long twopc_timeout(struct drbd_resource *);
extern long twopc_retry_timeout(struct drbd_resource *, int);
extern void twopc_connection_down(struct drbd_connection *);
extern u64 directly_connected_nodes(struct drbd_resource *, enum which_state);
extern int w_notify_io_error(struct drbd_work *w, int cancel);
/* sequence arithmetic for dagtag (data generation tag) sector numbers.
 * dagtag_newer_eq: true, if a is newer than b */
#ifdef _WIN32
#define dagtag_newer_eq(a,b)      \
	((s64)(a) - (s64)(b) >= 0)

#define dagtag_newer(a,b)      \
	((s64)(a) - (s64)(b) > 0)
#else
#define dagtag_newer_eq(a,b)      \
	(typecheck(u64, a) && \
	 typecheck(u64, b) && \
	((s64)(a) - (s64)(b) >= 0))

#define dagtag_newer(a,b)      \
	(typecheck(u64, a) && \
	 typecheck(u64, b) && \
	((s64)(a) - (s64)(b) > 0))
#endif

struct drbd_request {
	struct drbd_device *device;

	/* if local IO is not allowed, will be NULL.
	 * if local IO _is_ allowed, holds the locally submitted bio clone,
	 * or, after local IO completion, the ERR_PTR(error).
	 * see drbd_request_endio(). */
	struct bio *private_bio;
#ifdef _WIN32
	char*	req_databuf;
	// DW-1237: add request buffer reference count to free earlier when no longer need buf.
	atomic_t req_databuf_ref;
#endif
	struct drbd_interval i;

	/* epoch: used to check on "completion" whether this req was in
	 * the current epoch, and we therefore have to close it,
	 * causing a p_barrier packet to be send, starting a new epoch.
	 *
	 * This corresponds to "barrier" in struct p_barrier[_ack],
	 * and to "barrier_nr" in struct drbd_epoch (and various
	 * comments/function parameters/local variable names).
	 */
	unsigned int epoch;

	/* Position of this request in the serialized per-resource change
	 * stream. Can be used to serialize with other events when
	 * communicating the change stream via multiple connections.
	 * Assigned from device->resource->dagtag_sector.
	 *
	 * Given that some IO backends write several GB per second meanwhile,
	 * lets just use a 64bit sequence space. */
	u64 dagtag_sector;

	struct list_head tl_requests; /* ring list in the transfer log */

#ifdef _WIN32_NETQUEUED_LOG
	struct list_head nq_requests; /* ring list in the net queued log */
	atomic_t nq_ref;
#endif
	
	struct bio *master_bio;       /* master bio pointer */

	/* see struct drbd_device */
	struct list_head req_pending_master_completion;
	struct list_head req_pending_local;

	/* for generic IO accounting */
#ifdef _WIN32
    ULONG_PTR start_jif;
#else
	unsigned long start_jif;
#endif

	/* for DRBD internal statistics */

	/* Minimal set of time stamps to determine if we wait for activity log
	 * transactions, local disk or peer.  32 bit "jiffies" are good enough,
	 * we don't expect a DRBD request to be stalled for several month.
	 */

	/* before actual request processing */
#ifdef _WIN32
	ULONG_PTR in_actlog_jif;
#else
	unsigned long in_actlog_jif;
#endif
	/* local disk */
#ifdef _WIN32
	ULONG_PTR pre_submit_jif;
#else
	unsigned long pre_submit_jif;
#endif
	/* per connection */
#ifdef _WIN32
	ULONG_PTR pre_send_jif[DRBD_PEERS_MAX];
	ULONG_PTR acked_jif[DRBD_PEERS_MAX];
	ULONG_PTR net_done_jif[DRBD_PEERS_MAX];
#else
	unsigned long pre_send_jif[DRBD_PEERS_MAX];
	unsigned long acked_jif[DRBD_PEERS_MAX];
	unsigned long net_done_jif[DRBD_PEERS_MAX];
#endif

	/* Possibly even more detail to track each phase:
	 *  master_completion_jif
	 *      how long did it take to complete the master bio
	 *      (application visible latency)
	 *  allocated_jif
	 *      how long the master bio was blocked until we finally allocated
	 *      a tracking struct
	 *  in_actlog_jif
	 *      how long did we wait for activity log transactions
	 *
	 *  net_queued_jif
	 *      when did we finally queue it for sending
	 *  pre_send_jif
	 *      when did we start sending it
	 *  post_send_jif
	 *      how long did we block in the network stack trying to send it
	 *  acked_jif
	 *      when did we receive (or fake, in protocol A) a remote ACK
	 *  net_done_jif
	 *      when did we receive final acknowledgement (P_BARRIER_ACK),
	 *      or decide, e.g. on connection loss, that we do no longer expect
	 *      anything from this peer for this request.
	 *
	 *  pre_submit_jif
	 *  post_sub_jif
	 *      when did we start submiting to the lower level device,
	 *      and how long did we block in that submit function
	 *  local_completion_jif
	 *      how long did it take the lower level device to complete this request
	 */


	/* once it hits 0, we may complete the master_bio */
	atomic_t completion_ref;
	/* once it hits 0, we may destroy this drbd_request object */
	struct kref kref;

	/* If not NULL, destruction of this drbd_request will
	 * cause kref_put() on ->destroy_next. */
	struct drbd_request *destroy_next;

	/* rq_state[0] is for local disk,
	 * rest is indexed by peer_device->bitmap_index + 1 */
	unsigned rq_state[1 + DRBD_NODE_ID_MAX];
};

#ifdef _WIN32
// MODIFIED_BY_MANTECH DW-1191: out-of-sync information that doesn't rely on drbd request.
struct drbd_oos_no_req{
	struct list_head oos_list_head;
	sector_t sector;
	unsigned int size;
};
#endif

struct drbd_epoch {
	struct drbd_connection *connection;
	struct list_head list;
	unsigned int barrier_nr;
	atomic_t epoch_size; /* increased on every request added. */
	atomic_t active;     /* increased on every req. added, and dec on every finished. */
#ifdef _WIN32	
	ULONG_PTR flags;
#else
	unsigned long flags;
#endif
};

/* drbd_epoch flag bits */
enum {
	DE_BARRIER_IN_NEXT_EPOCH_ISSUED,
	DE_BARRIER_IN_NEXT_EPOCH_DONE,
	DE_CONTAINS_A_BARRIER,
	DE_HAVE_BARRIER_NUMBER,
	DE_IS_FINISHING,
};

enum epoch_event {
	EV_PUT,
	EV_GOT_BARRIER_NR,
	EV_BARRIER_DONE,
	EV_BECAME_LAST,
	EV_CLEANUP = 32, /* used as flag */
};

struct digest_info {
	int digest_size;
	void *digest;
};

struct drbd_peer_request {
	struct drbd_work w;
	struct drbd_peer_device *peer_device;
	struct list_head recv_order; /* writes only */
	/* writes only, blocked on activity log;
	* FIXME merge with rcv_order or w.list? */
	struct list_head wait_for_actlog;

	struct drbd_page_chain_head page_chain;
	unsigned int op_flags; /* to be used as bi_op_flags */
	atomic_t pending_bios;
	struct drbd_interval i;
#ifdef _WIN32
    ULONG_PTR flags; /* see comments on ee flag bits below */
#else
	unsigned long flags; /* see comments on ee flag bits below */
#endif
	union {
		struct { /* regular peer_request */
			struct drbd_epoch *epoch; /* for writes */
#ifdef _WIN32
			ULONG_PTR submit_jif;
#else
			unsigned long submit_jif;
#endif 
			union {
				u64 block_id;
				struct digest_info *digest;
			};
			u64 dagtag_sector;
		}; 
		struct { /* reused object to queue send OOS to other nodes */
			u64 sent_oos_nodes; /* Used to notify L_SYNC_TARGETs about new out_of_sync bits */
			struct drbd_peer_device *send_oos_peer_device;
			u64 send_oos_in_sync;
		};
	};
#ifdef _WIN32
	void* peer_req_databuf;

	struct {
		ULONG_PTR s_bb;		/* DW-1601 start bitmap bit of split data */
		ULONG_PTR e_next_bb;/* DW-1601 end next bitmap bit of split data  */
		atomic_t *count;	/* DW-1601 total split request (bitmap bit) */		
		atomic_t *unmarked_count;	/* DW-1911 this is the count for the sector not written in the maked replication bit */
		atomic_t *failed_unmarked; /* DW-1911 true, if undamaged writing fails */
	};
#endif
};

// DW-1755 passthrough policy
// disk error structure to pass to events2
struct drbd_io_error {
	unsigned char	disk_type;
	unsigned char	io_type;
	NTSTATUS		error_code;
	sector_t		sector;
	unsigned int	size;
	bool			is_cleared;
};

/* ee flag bits.
 * While corresponding bios are in flight, the only modification will be
 * set_bit WAS_ERROR, which has to be atomic.
 * If no bios are in flight yet, or all have been completed,
 * non-atomic modification to ee->flags is ok.
 */
enum {
	__EE_MAY_SET_IN_SYNC,

	/* This peer request closes an epoch using a barrier.
	 * On successful completion, the epoch is released,
	 * and the P_BARRIER_ACK send. */
	__EE_IS_BARRIER,

	/* is this a TRIM aka REQ_DISCARD? */
	__EE_IS_TRIM,
	/* our lower level cannot handle trim,
	 * and we want to fall back to zeroout instead */
	__EE_IS_TRIM_USE_ZEROOUT,

	/* In case a barrier failed,
	 * we need to resubmit without the barrier flag. */
	__EE_RESUBMITTED,

	/* we may have several bios per peer request.
	 * if any of those fail, we set this flag atomically
	 * from the endio callback */
	__EE_WAS_ERROR,

	/* This ee has a pointer to a digest instead of a block id */
	__EE_HAS_DIGEST,

	/* Conflicting local requests need to be restarted after this request */
	__EE_RESTART_REQUESTS,

	/* The peer wants a write ACK for this (wire proto C) */
	__EE_SEND_WRITE_ACK,

	/* Is set when net_conf had two_primaries set while creating this peer_req */
	__EE_IN_INTERVAL_TREE,

	/* for debugfs: */
	/* has this been submitted, or does it still wait for something else? */
	__EE_SUBMITTED,

	/* this is/was a write request */
	__EE_WRITE,

	/* this is/was a write same request */
	__EE_WRITE_SAME,

	/* this originates from application on peer
	 * (not some resync or verify or other DRBD internal request) */
	__EE_APPLICATION,

	/* If it contains only 0 bytes, send back P_RS_DEALLOCATED */
	__EE_RS_THIN_REQ,

	/* Hold reference in activity log */
	__EE_IN_ACTLOG,

	//DW-1601
	/* split request */
	__EE_SPLIT_REQUEST,

	//DW-1601
	/* last split request */
	__EE_SPLIT_LAST_REQUEST,
};
#define EE_MAY_SET_IN_SYNC     		(1<<__EE_MAY_SET_IN_SYNC)			//LSB bit field:0
#define EE_IS_BARRIER          		(1<<__EE_IS_BARRIER)				//LSB bit field:1
#define EE_IS_TRIM             		(1<<__EE_IS_TRIM)					//LSB bit field:2
#define EE_IS_TRIM_USE_ZEROOUT 		(1<<__EE_IS_TRIM_USE_ZEROOUT)		//LSB bit field:3
#define EE_RESUBMITTED         		(1<<__EE_RESUBMITTED)				//LSB bit field:4
#define EE_WAS_ERROR           		(1<<__EE_WAS_ERROR)					//LSB bit field:5
#define EE_HAS_DIGEST          		(1<<__EE_HAS_DIGEST)				//LSB bit field:6
#define EE_RESTART_REQUESTS			(1<<__EE_RESTART_REQUESTS)			//LSB bit field:7
#define EE_SEND_WRITE_ACK			(1<<__EE_SEND_WRITE_ACK)			//LSB bit field:8
#define EE_IN_INTERVAL_TREE			(1<<__EE_IN_INTERVAL_TREE)			//LSB bit field:9
#define EE_SUBMITTED				(1<<__EE_SUBMITTED)					//LSB bit field:10
#define EE_WRITE					(1<<__EE_WRITE)						//LSB bit field:11
#define EE_WRITE_SAME				(1<<__EE_WRITE_SAME)				//LSB bit field:12
#define EE_APPLICATION				(1<<__EE_APPLICATION)				//LSB bit field:13
#define EE_RS_THIN_REQ				(1<<__EE_RS_THIN_REQ)				//LSB bit field:14
#define EE_IN_ACTLOG				(1<<__EE_IN_ACTLOG)					//LSB bit field:15
//DW-1601
#define EE_SPLIT_REQUEST			(1<<__EE_SPLIT_REQUEST)				//LSB bit field:16 
#define EE_SPLIT_LAST_REQUEST		(1<<__EE_SPLIT_LAST_REQUEST)				//LSB bit field:17

/* flag bits per device */
enum {
	UNPLUG_QUEUED,		/* only relevant with kernel 2.4 */
	UNPLUG_REMOTE,		/* sending a "UnplugRemote" could help */
	MD_DIRTY,		/* current uuids and flags not yet on disk */
	CRASHED_PRIMARY,	/* This node was a crashed primary.
				 * Gets cleared when the state.conn
				 * goes into L_ESTABLISHED state. */
	MD_NO_FUA,		/* meta data device does not support barriers,
				   so don't even try */
	WAS_READ_ERROR,		/* Local disk READ failed, returned IO error */
	FORCE_DETACH,		/* Force-detach from local disk, aborting any pending local IO */
	NEW_CUR_UUID,		/* Create new current UUID when thawing IO or issuing local IO */
	__NEW_CUR_UUID,        /* Set NEW_CUR_UUID as soon as state change visible */
	AL_SUSPENDED,		/* Activity logging is currently suspended. */
#ifndef	_WIN32
	// DW-874: Since resync works per peer device and device flag is shared for all peers, it may get racy with more than one peer.
	// To support resync for more than one peer, this flag must be set as a peer device flag.
	AHEAD_TO_SYNC_SOURCE,   /* Ahead -> SyncSource queued */
#endif
	UNREGISTERED,
	FLUSH_PENDING,		/* if set, device->flush_jif is when we submitted that flush
				 * from drbd_flush_after_epoch() */

        /* cleared only after backing device related structures have been destroyed. */
        GOING_DISKLESS,         /* Disk is being detached, because of io-error, or admin request. */

        /* to be used in drbd_device_post_work() */
        GO_DISKLESS,            /* tell worker to schedule cleanup before detach */
        DESTROY_DISK,           /* tell worker to close backing devices and destroy related structures. */
	MD_SYNC,		/* tell worker to call drbd_md_sync() */

	HAVE_LDEV,
	STABLE_RESYNC,		/* One peer_device finished the resync stable! */
	READ_BALANCE_RR,
};

/* flag bits per peer device */
enum {
	CONSIDER_RESYNC,
	RESYNC_AFTER_NEG,       /* Resync after online grow after the attach&negotiate finished. */
	RESIZE_PENDING,		/* Size change detected locally, waiting for the response from
				 * the peer, if it changed there as well. */
	RS_START,		/* tell worker to start resync/OV */
	RS_PROGRESS,		/* tell worker that resync made significant progress */
	RS_DONE,		/* tell worker that resync is done */
	B_RS_H_DONE,		/* Before resync handler done (already executed) */
	DISCARD_MY_DATA,	/* discard_my_data flag per volume */
	USE_DEGR_WFC_T,		/* degr-wfc-timeout instead of wfc-timeout. */
	INITIAL_STATE_SENT,
	INITIAL_STATE_RECEIVED,
	RECONCILIATION_RESYNC,
	UNSTABLE_RESYNC,	/* Sync source went unstable during resync. */
	SEND_STATE_AFTER_AHEAD,
	GOT_NEG_ACK,        /* got a neg_ack while primary, wait until peer_disk is lower than
                    D_UP_TO_DATE before becoming secondary! */
#ifdef _WIN32
	// DW-874: Moved from device flag. See device flag comment for detail.
	AHEAD_TO_SYNC_SOURCE,   /* Ahead -> SyncSource queued */
	// MODIFIED_BY_MANTECH DW-955: add resync aborted flag to resume it later.
	RESYNC_ABORTED,			/* Resync has been aborted due to unsyncable (peer)disk state, need to resume it when it goes syncable. */
#ifdef _WIN32_DISABLE_RESYNC_FROM_SECONDARY
	PROMOTED_RESYNC,		/* MODIFIED_BY_MANTECH DW-1225: I'm promoted, and there will be no initial sync. Do trigger resync after promotion */
#endif
#ifdef _WIN32_STABLE_SYNCSOURCE
	UNSTABLE_TRIGGER_CP,	/* MODIFIED_BY_MANTECH DW-1341: Do Trigger when my stability is unstable for Crashed Primay wiered case*/
#endif
	SEND_BITMAP_WORK_PENDING, /* DW-1447 : Do not queue send_bitmap() until the peer's repl_state changes to WFBitmapT.
										Used when invalidate-remote/invalidate.*/
#endif
#ifdef _WIN32 //DW-1598 
	CONNECTION_ALREADY_FREED,
	//DW-1799 use for disk size comparison and setup.
	INITIAL_SIZE_RECEIVED,
#endif 
};

/* We could make these currently hardcoded constants configurable
 * variables at create-md time (or even re-configurable at runtime?).
 * Which will require some more changes to the DRBD "super block"
 * and attach code.
 *
 * updates per transaction:
 *   This many changes to the active set can be logged with one transaction.
 *   This number is arbitrary.
 * context per transaction:
 *   This many context extent numbers are logged with each transaction.
 *   This number is resulting from the transaction block size (4k), the layout
 *   of the transaction header, and the number of updates per transaction.
 *   See drbd_actlog.c:struct al_transaction_on_disk
 * */
#define AL_UPDATES_PER_TRANSACTION	 64	// arbitrary
#define AL_CONTEXT_PER_TRANSACTION	919	// (4096 - 36 - 6*64)/4

/* definition of bits in bm_flags to be used in drbd_bm_lock
 * and drbd_bitmap_io and friends. */
enum bm_flag {
	/*
	 * The bitmap can be locked to prevent others from clearing, setting,
	 * and/or testing bits.  The following combinations of lock flags make
	 * sense:
	 *
	 *   BM_LOCK_CLEAR,
	 *   BM_LOCK_SET, | BM_LOCK_CLEAR,
	 *   BM_LOCK_TEST | BM_LOCK_SET | BM_LOCK_CLEAR.
	 */

	BM_LOCK_TEST = 0x1,
	BM_LOCK_SET = 0x2,
	BM_LOCK_CLEAR = 0x4,
	BM_LOCK_BULK = 0x8, /* locked for bulk operation, allow all non-bulk operations */

	BM_LOCK_ALL = BM_LOCK_TEST | BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK,

	BM_LOCK_SINGLE_SLOT = 0x10,
};

struct drbd_bitmap {
	struct page **bm_pages;
	spinlock_t bm_lock;

#ifdef _WIN32
    ULONG_PTR bm_set[DRBD_PEERS_MAX]; /* number of bits set */
    ULONG_PTR bm_bits;  /* bits per peer */
#else
	unsigned long bm_set[DRBD_PEERS_MAX]; /* number of bits set */
	unsigned long bm_bits;  /* bits per peer */
#endif
	size_t   bm_words;
	size_t   bm_number_of_pages;
	sector_t bm_dev_capacity;
	struct mutex bm_change; /* serializes resize operations */

	wait_queue_head_t bm_io_wait; /* used to serialize IO of single pages */

	enum bm_flag bm_flags;
	unsigned int bm_max_peers;

	/* exclusively to be used by __al_write_transaction(),
	 * and drbd_bm_write_hinted() -> bm_rw() called from there.
	 * One activity log extent represents 4MB of storage, which are 1024
	 * bits (at 4k per bit), times at most DRBD_PEERS_MAX (currently 32).
	 * The bitmap is created interleaved, with a potentially odd number
	 * of peer slots determined at create-md time.  Which means that one
	 * AL-extent may be associated with one or two bitmap pages.
	 */
	unsigned int n_bitmap_hints;
	unsigned int al_bitmap_hints[2*AL_UPDATES_PER_TRANSACTION];

	/* debugging aid, in case we are still racy somewhere */
	char          *bm_why;
	struct task_struct *bm_task;
	struct drbd_peer_device *bm_locked_peer;
};

struct drbd_work_queue {
	struct list_head q;
	spinlock_t q_lock;  /* to protect the list. */
	wait_queue_head_t q_wait;
};

struct drbd_peer_md {
	u64 bitmap_uuid;
	u64 bitmap_dagtag;
	u32 flags;
	s32 bitmap_index;
};

struct drbd_md {
	u64 md_offset;		/* sector offset to 'super' block */

	u64 effective_size;	/* last agreed size (sectors) */
	spinlock_t uuid_lock;
	u64 current_uuid;
	u64 device_uuid;
	u32 flags;
	s32 node_id;
	u32 md_size_sect;

	s32 al_offset;	/* signed relative sector offset to activity log */
	s32 bm_offset;	/* signed relative sector offset to bitmap */

	struct drbd_peer_md peers[DRBD_NODE_ID_MAX];
	u64 history_uuids[HISTORY_UUIDS];

	/* cached value of bdev->disk_conf->meta_dev_idx */
	s32 meta_dev_idx;

	/* see al_tr_number_to_on_disk_sector() */
	u32 al_stripes;
	u32 al_stripe_size_4k;
	u32 al_size_4k; /* cached product of the above */
};

struct drbd_backing_dev {
	struct block_device *backing_bdev;
	struct block_device *md_bdev;
	struct drbd_md md;
	struct disk_conf *disk_conf; /* RCU, for updates: resource->conf_update */
	sector_t known_size; /* last known size of that backing device */
};

struct drbd_md_io {
	struct page *page;
#ifdef _WIN32
    ULONG_PTR start_jif;	/* last call to drbd_md_get_buffer */
    ULONG_PTR submit_jif;	/* last _drbd_md_sync_page_io() submit */
#else
	unsigned long start_jif;	/* last call to drbd_md_get_buffer */
	unsigned long submit_jif;	/* last _drbd_md_sync_page_io() submit */
#endif
	const char *current_use;
	atomic_t in_use;
	unsigned int done;
	int error;
};

struct bm_io_work {
	struct drbd_work w;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	char *why;
	enum bm_flag flags;
	int (*io_fn)(struct drbd_device *, struct drbd_peer_device *);
	void (*done)(struct drbd_device *device, struct drbd_peer_device *, int rv);
};

struct fifo_buffer {
	/* singly linked list to accumulate multiple such struct fifo_buffers,
	 * to be freed after a single syncronize_rcu(),
	 * outside a critical section. */
	struct fifo_buffer *next;
	unsigned int head_index;
	unsigned int size;
	int total; /* sum of all values */
	int values[0];
};
#ifdef _WIN32
extern struct fifo_buffer *fifo_alloc(int fifo_size, ULONG Tag);
#else
extern struct fifo_buffer *fifo_alloc(int fifo_size);
#endif

/* flag bits per connection */
enum {
	SEND_PING,
	GOT_PING_ACK,		/* set when we receive a ping_ack packet, ping_wait gets woken */
	TWOPC_PREPARED,
	TWOPC_YES,
	TWOPC_NO,
	TWOPC_RETRY,
	CONN_DRY_RUN,		/* Expect disconnect after resync handshake. */
	CREATE_BARRIER,		/* next P_DATA is preceded by a P_BARRIER */
	DISCONNECT_EXPECTED,
	BARRIER_ACK_PENDING,
	CORKED,
	DATA_CORKED = CORKED,
	CONTROL_CORKED,
	C_UNREGISTERED,
	RECONNECT,
	CONN_DISCARD_MY_DATA,
	SEND_STATE_AFTER_AHEAD_C,
	//DW-1874
	FORCE_DISCONNECT,
};

/* flag bits per resource */
enum {
	EXPLICIT_PRIMARY,
	CALLBACK_PENDING,	/* Whether we have a call_usermodehelper(, UMH_WAIT_PROC)
				 * pending, from drbd worker context.
				 * If set, bdi_write_congested() returns true,
				 * so shrink_page_list() would not recurse into,
				 * and potentially deadlock on, this drbd worker.
				 */
	NEGOTIATION_RESULT_TOUCHED,
	TWOPC_ABORT_LOCAL,
	TWOPC_EXECUTED,         /* Commited or aborted */
	DEVICE_WORK_PENDING,	/* tell worker that some device has pending work */
	PEER_DEVICE_WORK_PENDING,/* tell worker that some peer_device has pending work */
	RESOURCE_WORK_PENDING,  /* tell worker that some peer_device has pending work */

        /* to be used in drbd_post_work() */
	TRY_BECOME_UP_TO_DATE,  /* try to become D_UP_TO_DATE */
};

enum which_state { NOW, OLD = NOW, NEW };

enum twopc_type {
	TWOPC_STATE_CHANGE,
	TWOPC_RESIZE,
};

struct twopc_reply {
	int vnr;
	unsigned int tid;  /* transaction identifier */
	int initiator_node_id;  /* initiator of the transaction */
	int target_node_id;  /* target of the transaction (or -1) */
	u64 target_reachable_nodes;  /* behind the target node */
	u64 reachable_nodes;  /* behind other nodes */
	union {
		struct { /* type == TWOPC_STATE_CHANGE */
			u64 primary_nodes;
			u64 weak_nodes;
		};
		struct { /* type == TWOPC_RESIZE */
			u64 diskful_primary_nodes;
			u64 max_possible_size;
		};
	};
	int is_disconnect:1;
	int is_aborted:1;
};

struct drbd_thread_timing_details
{
#ifdef _WIN32
	ULONG_PTR start_jif;
#else
	unsigned long start_jif;
#endif
	void *cb_addr;
	const char *caller_fn;
	unsigned int line;
	unsigned int cb_nr;
};
#define DRBD_THREAD_DETAILS_HIST	16

struct drbd_send_buffer {
	struct page *page;  /* current buffer page for sending data */
	char *unsent;  /* start of unsent area != pos if corked... */
	char *pos; /* position within that page */
	int allocated_size; /* currently allocated space */
	int additional_size;  /* additional space to be added to next packet's size */
};
#ifdef _WIN32
struct connect_work {
	struct drbd_work w;
	struct drbd_resource* resource;
	int(*func)(struct drbd_thread *thi);
	struct drbd_thread* receiver;
};

struct disconnect_work {
	struct drbd_work w;
	struct drbd_resource* resource;
};
#endif

struct flush_context_sync {
	atomic_t primary_node_id;
	atomic_t64 barrier_nr;
};

struct issue_flush_context {
	atomic_t pending;
	int error;
	struct completion done;
	struct flush_context_sync ctx_sync;
};
struct one_flush_context {
	struct drbd_device *device;
	struct issue_flush_context *ctx;
	struct flush_context_sync ctx_sync;
};

struct drbd_resource {
	char *name;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_res;
	struct dentry *debugfs_res_volumes;
	struct dentry *debugfs_res_connections;
	struct dentry *debugfs_res_in_flight_summary;
	struct dentry *debugfs_res_state_twopc;
#endif
	struct kref kref;
	struct kref_debug_info kref_debug;
	struct idr devices;		/* volume number to device mapping */
	struct list_head connections;
	struct list_head resources;
	struct res_opts res_opts;
	unsigned int max_node_id;
	struct mutex conf_update;	/* for ready-copy-update of net_conf and disk_conf
					   and devices, connection and peer_devices lists */
	struct mutex adm_mutex;		/* mutex to serialize administrative requests */
#ifdef _WIN32
	struct mutex vol_ctl_mutex;	/* DW-1317: chaning role involves the volume for device is (dis)mounted, use this when the role change needs to be waited. */
#endif
	spinlock_t req_lock;
	u64 dagtag_sector;		/* Protected by req_lock.
					 * See also dagtag_sector in
					 * &drbd_request */
#ifdef _WIN32	
	ULONG_PTR flags;
#else
	unsigned long flags;
#endif
	struct list_head transfer_log;	/* all requests not yet fully processed */

#ifdef _WIN32_NETQUEUED_LOG
	struct list_head net_queued_log;	/* RQ_NET_QUEUED requests */
#endif

	struct list_head peer_ack_list;  /* requests to send peer acks for */
	u64 last_peer_acked_dagtag;  /* dagtag of last PEER_ACK'ed request */
	struct drbd_request *peer_ack_req;  /* last request not yet PEER_ACK'ed */

	struct semaphore state_sem;
	wait_queue_head_t state_wait;  /* upon each state change. */
	enum chg_state_flags state_change_flags;
	const char **state_change_err_str;
	bool remote_state_change;  /* remote state change in progress */
	enum twopc_type twopc_type; /* from prepare phase */
	enum drbd_packet twopc_prepare_reply_cmd; /* this node's answer to the prepare phase or 0 */
	struct list_head twopc_parents;  /* prepared on behalf of peer */
	u64 twopc_parent_nodes;
	struct twopc_reply twopc_reply;
	struct timer_list twopc_timer;
	struct drbd_work twopc_work;
	wait_queue_head_t twopc_wait;
	struct twopc_resize {
		int dds_flags;            /* from prepare phase */
		sector_t user_size;       /* from prepare phase */
		u64 diskful_primary_nodes;/* added in commit phase */
		u64 new_size;             /* added in commit phase */
	} twopc_resize;
	struct list_head queued_twopc;
	spinlock_t queued_twopc_lock;
	struct timer_list queued_twopc_timer;
	struct queued_twopc *starting_queued_twopc;

	enum drbd_role role[2];
	bool susp[2];			/* IO suspended by user */
	bool susp_nod[2];		/* IO suspended because no data */

	enum write_ordering_e write_ordering;
	atomic_t current_tle_nr;	/* transfer log epoch number */
	unsigned current_tle_writes;	/* writes seen within this tl epoch */

#ifndef _WIN32
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30) && !defined(cpumask_bits)
	cpumask_t cpu_mask[1];
#else
	cpumask_var_t cpu_mask;
#endif
#endif

	struct drbd_work_queue work;
	struct drbd_thread worker;

	struct list_head listeners;
	spinlock_t listeners_lock;

	struct timer_list peer_ack_timer; /* send a P_PEER_ACK after last completion */
	struct timer_list repost_up_to_date_timer;

	unsigned int w_cb_nr; /* keeps counting up */
	struct drbd_thread_timing_details w_timing_details[DRBD_THREAD_DETAILS_HIST];
	wait_queue_head_t barrier_wait;  /* upon each state change. */
#ifdef _WIN32
	bool bPreSecondaryLock;
	bool bPreDismountLock; // DW-1286
	bool bTempAllowMount;  // DW-1317
	atomic_t bGetVolBitmapDone;  // DW-1391	
#endif
	bool breqbuf_overflow_alarm; // DW-1539
#ifdef _WIN32_MULTIVOL_THREAD
	MVOL_THREAD			WorkThreadInfo;
#endif
	struct issue_flush_context ctx_flush; // DW-1895
};

struct drbd_connection {
	struct list_head connections;
	struct drbd_resource *resource;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_conn;
	struct dentry *debugfs_conn_callback_history;
	struct dentry *debugfs_conn_oldest_requests;
	struct dentry *debugfs_conn_transport;
	struct dentry *debugfs_conn_debug;
#endif
	struct kref kref;
	struct kref_debug_info kref_debug;
	struct idr peer_devices;	/* volume number to peer device mapping */
	enum drbd_conn_state cstate[2];
	enum drbd_role peer_role[2];
	bool susp_fen[2];		/* IO suspended because fence peer handler runs */
#ifdef _WIN32
	ULONG_PTR flags;
#else
	unsigned long flags;
#endif
	
	enum drbd_fencing_policy fencing_policy;
	wait_queue_head_t ping_wait;	/* Woken upon reception of a ping, and a state change */

	struct drbd_send_buffer send_buffer[2];
	struct mutex mutex[2]; /* Protect assembling of new packet until sending it (in send_buffer) */
	int agreed_pro_version;		/* actually used protocol version */
	u32 agreed_features;

#ifdef _WIN32
	ULONG_PTR last_received;	/* in jiffies, either socket */
#else
	unsigned long last_received;	/* in jiffies, either socket */
#endif
	atomic_t64 ap_in_flight; /* App bytes in flight (waiting for ack) */
	atomic_t64 rs_in_flight; /* resync-data bytes in flight*/
	struct drbd_work connect_timer_work;
	struct timer_list connect_timer;

	struct crypto_hash *cram_hmac_tfm;
	struct crypto_hash *integrity_tfm;  /* checksums we compute, updates protected by connection->mutex[DATA_STREAM] */
	struct crypto_hash *peer_integrity_tfm;  /* checksums we verify, only accessed from receiver thread  */
	struct crypto_hash *csums_tfm;
	struct crypto_hash *verify_tfm;
	void *int_dig_in;
	void *int_dig_vv;

	/* receiver side */
	struct drbd_epoch *current_epoch;
	spinlock_t epoch_lock;
	unsigned int epochs;

#ifdef _WIN32
	ULONG_PTR last_reconnect_jif;
#else
	unsigned long last_reconnect_jif;
#endif

#ifndef _WIN32
	/* empty member on older kernels without blk_start_plug() */
	struct blk_plug receiver_plug;
#endif
	struct drbd_thread receiver;
	struct drbd_thread sender;
	struct drbd_thread ack_receiver;
	struct workqueue_struct *ack_sender;
	struct work_struct peer_ack_work;

	struct list_head peer_requests; /* All peer requests in the order we received them.. */
	u64 last_dagtag_sector;

	struct list_head active_ee; /* IO in progress (P_DATA gets written to disk) */
	struct list_head sync_ee;   /* IO in progress (P_RS_DATA_REPLY gets written to disk) */
	struct list_head read_ee;   /* [RS]P_DATA_REQUEST being read */
	struct list_head net_ee;    /* zero-copy network send in progress */
	struct list_head done_ee;   /* need to send P_WRITE_ACK */

	struct list_head inactive_ee;	//DW-1696 : List of active_ee, sync_ee not processed at the end of the connection

	atomic_t done_ee_cnt;
	struct work_struct send_acks_work;
	wait_queue_head_t ee_wait;

	atomic_t pp_in_use;		/* allocated from page pool */
	atomic_t pp_in_use_by_net;	/* sendpage()d, still referenced by transport */
	/* sender side */
	struct drbd_work_queue sender_work;

	struct sender_todo {
		struct list_head work_list;
#ifndef _WIN32
		/* If upper layers trigger an unplug on this side, we want to
		 * send and unplug hint over to the peer.  Sending it too
		 * early, or missing it completely, causes a potential latency
		 * penalty (requests idling too long in the remote queue).
		 * There is no harm done if we occasionally send one too many
		 * such unplug hints.
		 *
		 * We have two slots, which are used in an alternating fashion:
		 * If a new unplug event happens while the current pending one
		 * has not even been processed yet, we overwrite the next
		 * pending slot: there is not much point in unplugging on the
		 * remote side, if we have a full request queue to be send on
		 * this side still, and not even reached the position in the
		 * change stream when the previous local unplug happened.
		 */
		u64 unplug_dagtag_sector[2];
		unsigned int unplug_slot; /* 0 or 1 */
#endif
		/* the currently (or last) processed request,
		 * see process_sender_todo() */
		struct drbd_request *req;

		/* Points to the next request on the resource->transfer_log,
		 * which is RQ_NET_QUEUED for this connection, and so can
		 * safely be used as next starting point for the list walk
		 * in tl_next_request_for_connection().
		 *
		 * If it is NULL (we walked off the tail last time), it will be
		 * set by __req_mod( QUEUE_FOR.* ), so fast connections don't
		 * need to walk the full transfer_log list every time, even if
		 * the list is kept long by some slow connections.
		 *
		 * There is also a special value to reliably re-start
		 * the transfer log walk after having scheduled the requests
		 * for RESEND. */
#define TL_NEXT_REQUEST_RESEND	((void*)1)
		struct drbd_request *req_next;
	} todo;

	/* cached pointers,
	 * so we can look up the oldest pending requests more quickly.
	 * protected by resource->req_lock */
	struct drbd_request *req_ack_pending;
	struct drbd_request *req_not_net_done;

	unsigned int s_cb_nr; /* keeps counting up */
	unsigned int r_cb_nr; /* keeps counting up */
	struct drbd_thread_timing_details s_timing_details[DRBD_THREAD_DETAILS_HIST];
	struct drbd_thread_timing_details r_timing_details[DRBD_THREAD_DETAILS_HIST];

	struct {
#ifdef _WIN32
        ULONG_PTR last_sent_barrier_jif;
#else
		unsigned long last_sent_barrier_jif;
#endif
		int last_sent_epoch_nr;

		/* whether this sender thread
		 * has processed a single write yet. */
		bool seen_any_write_yet;

		/* Which barrier number to send with the next P_BARRIER */
		int current_epoch_nr;

		/* how many write requests have been sent
		 * with req->epoch == current_epoch_nr.
		 * If none, no P_BARRIER will be sent. */
		unsigned current_epoch_writes;

		/* position in change stream */
		u64 current_dagtag_sector;
	} send;

	ring_buffer* ptxbab[2];
	
	unsigned int peer_node_id;
	struct list_head twopc_parent_list;
	struct drbd_transport transport; /* The transport needs to be the last member. The acutal
					    implementation might have more members than the
					    abstract one. */
};

/* used to get the next lower or next higher peer_device depending on device node-id */
enum drbd_neighbor {
	NEXT_LOWER,
	NEXT_HIGHER
};

struct drbd_peer_device {
	struct list_head peer_devices;
	struct drbd_device *device;
	struct drbd_connection *connection;
#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1191: out-of-sync list and work that will be queued to send.
	struct list_head send_oos_list;
	struct work_struct send_oos_work;
	spinlock_t send_oos_lock;
#endif
	struct peer_device_conf *conf; /* RCU, for updates: resource->conf_update */
	enum drbd_disk_state disk_state[2];
	enum drbd_repl_state repl_state[2];
	bool resync_susp_user[2];
	bool resync_susp_peer[2];
	bool resync_susp_dependency[2];
	bool resync_susp_other_c[2];
	enum drbd_repl_state negotiation_result; /* To find disk state after attach */
	unsigned int send_cnt;
	unsigned int recv_cnt;
	atomic_t packet_seq;
	unsigned int peer_seq;
	spinlock_t peer_seq_lock;
	unsigned int max_bio_size;
	uint64_t d_size;  /* size of disk */
	uint64_t u_size;  /* user requested size */
	uint64_t c_size;  /* current exported size */
	uint64_t max_size;
	int bitmap_index;
	int node_id;
#ifdef _WIN32
	ULONG_PTR flags;
#else
	unsigned long flags;
#endif
	//DW-1806 set after initial send.
	KEVENT state_initial_send_event;
	

	enum drbd_repl_state start_resync_side;
	enum drbd_repl_state last_repl_state; /* What we received from the peer */
	struct timer_list start_resync_timer;
	struct drbd_work resync_work;
	struct timer_list resync_timer;
	struct drbd_work propagate_uuids_work;

	/* Used to track operations of resync... */
	struct lru_cache *resync_lru;
	/* Number of locked elements in resync LRU */
	unsigned int resync_locked;
	/* resync extent number waiting for application requests */
	unsigned int resync_wenr;
	enum drbd_disk_state resync_finished_pdsk; /* Finished while starting resync */
	int resync_again; /* decided to resync again while resync running */

	atomic_t ap_pending_cnt; /* AP data packets on the wire, ack expected */
	atomic_t unacked_cnt;	 /* Need to send replies for */
	atomic_t rs_pending_cnt; /* RS request/data packets on the wire */
	atomic_t wait_for_actlog;

	/* use checksums for *this* resync */
	bool use_csums;
#ifdef _WIN32
    /* blocks to resync in this run [unit BM_BLOCK_SIZE] */
    ULONG_PTR rs_total;
    /* number of resync blocks that failed in this run */
    ULONG_PTR rs_failed;
    /* Syncer's start time [unit jiffies] */
    ULONG_PTR rs_start;
    /* cumulated time in PausedSyncX state [unit jiffies] */
    ULONG_PTR rs_paused;
    /* skipped because csum was equal [unit BM_BLOCK_SIZE] */
    ULONG_PTR rs_same_csum;
#else
	/* blocks to resync in this run [unit BM_BLOCK_SIZE] */
	unsigned long rs_total;
	/* number of resync blocks that failed in this run */
	unsigned long rs_failed;
	/* Syncer's start time [unit jiffies] */
	unsigned long rs_start;
	/* cumulated time in PausedSyncX state [unit jiffies] */
	unsigned long rs_paused;
	/* skipped because csum was equal [unit BM_BLOCK_SIZE] */
	unsigned long rs_same_csum;
#endif
#define DRBD_SYNC_MARKS 8
#define DRBD_SYNC_MARK_STEP (3*HZ)
#ifdef _WIN32
    /* block not up-to-date at mark [unit BM_BLOCK_SIZE] */
    ULONG_PTR rs_mark_left[DRBD_SYNC_MARKS];
    /* marks's time [unit jiffies] */
    ULONG_PTR rs_mark_time[DRBD_SYNC_MARKS];
#else
	/* block not up-to-date at mark [unit BM_BLOCK_SIZE] */
	unsigned long rs_mark_left[DRBD_SYNC_MARKS];
	/* marks's time [unit jiffies] */
	unsigned long rs_mark_time[DRBD_SYNC_MARKS];
#endif
	/* current index into rs_mark_{left,time} */
	int rs_last_mark;
#ifdef _WIN32
    ULONG_PTR rs_last_writeout;
#else
	unsigned long rs_last_writeout;
#endif

	/* where does the admin want us to start? (sector) */
	sector_t ov_start_sector;
	sector_t ov_stop_sector;
	/* where are we now? (sector) */
	sector_t ov_position;
	/* Start sector of out of sync range (to merge printk reporting). */
	sector_t ov_last_oos_start;
	/* size of out-of-sync range in sectors. */
	sector_t ov_last_oos_size;
	int c_sync_rate; /* current resync rate after syncer throttle magic */
	struct fifo_buffer *rs_plan_s; /* correction values of resync planer (RCU, connection->conn_update) */
	atomic_t rs_sect_in; /* for incoming resync data rate, SyncTarget */
	int rs_last_sect_ev; /* counter to compare with */
	int rs_last_events;  /* counter of read or write "events" (unit sectors)
			      * on the lower level device when we last looked. */
	int rs_in_flight; /* resync sectors in flight (to proxy, in proxy and from proxy) */
#ifdef _WIN32
    ULONG_PTR ov_left; /* in bits */
#else
	unsigned long ov_left; /* in bits */
#endif

	u64 current_uuid;
	u64 bitmap_uuids[DRBD_PEERS_MAX];
	u64 history_uuids[HISTORY_UUIDS];
	u64 dirty_bits;
	u64 uuid_flags;
	u64 uuid_authoritative_nodes; /* when then UUID_FLAG_STABLE is cleared the peer thinks it is
					 not stable. It does that because it thinks these nodes
					 are authoritative */
	bool uuids_received;

#ifdef _WIN32
    ULONG_PTR comm_bm_set; /* communicated number of set bits. */
#else
	unsigned long comm_bm_set; /* communicated number of set bits. */
#endif

#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_peer_dev;
	struct dentry *debugfs_peer_dev_resync_extents;
	struct dentry *debugfs_peer_dev_proc_drbd;
#endif
	struct {/* sender todo per peer_device */
		bool was_ahead;
	} todo;
};

//DW-1911
struct drbd_marked_replicate {
	u64 bb;
	u8 marked_rl;	/* marks the sector as bit. (4k = 8sector = u8(8bit)) */
	struct list_head marked_rl_list;
	u16 end_unmarked_rl;
};


struct submit_worker {
	struct workqueue_struct *wq;
	struct work_struct worker;

	/* protected by ..->resource->req_lock */
	struct list_head writes;
	struct list_head peer_writes;
};

struct drbd_device {
#ifdef PARANOIA
	long magic;
#endif
	struct drbd_resource *resource;
	struct list_head peer_devices;
	struct list_head pending_bitmap_io;
#ifdef _WIN32
    ULONG_PTR flush_jif;
#else
	unsigned long flush_jif;
#endif
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_minor;
	struct dentry *debugfs_vol;
	struct dentry *debugfs_vol_oldest_requests;
	struct dentry *debugfs_vol_act_log_extents;
	struct dentry *debugfs_vol_data_gen_id;
	struct dentry *debugfs_vol_io_frozen;
	struct dentry *debugfs_vol_ed_gen_id;
#endif

	unsigned int vnr;	/* volume number within the connection */
	unsigned int minor;	/* device minor number */

	struct kref kref;
	struct kref_debug_info kref_debug;

	/* things that are stored as / read from meta data on disk */
#ifdef _WIN32
	ULONG_PTR flags;
#else
	unsigned long flags;
#endif

	/* configured by drbdsetup */
	struct drbd_backing_dev *ldev __protected_by(local);

	struct request_queue *rq_queue;
	struct block_device *this_bdev;
	struct gendisk	    *vdisk;

#ifdef _WIN32
    ULONG_PTR last_reattach_jif;
#else
	unsigned long last_reattach_jif;
#endif
	struct timer_list md_sync_timer;
	struct timer_list request_timer;
#ifdef DRBD_DEBUG_MD_SYNC
	struct {
		unsigned int line;
		const char* func;
	} last_md_mark_dirty;
#endif

	enum drbd_disk_state disk_state[2];
	wait_queue_head_t misc_wait;
	unsigned int read_cnt;
	unsigned int writ_cnt;
	unsigned int al_writ_cnt;
	unsigned int bm_writ_cnt;
	atomic_t ap_bio_cnt[2];	 /* Requests we need to complete. [READ] and [WRITE] */
	atomic_t ap_actlog_cnt;  /* Requests waiting for activity log */
	atomic_t local_cnt;	 /* Waiting for local completion */
	atomic_t suspend_cnt;

	/* Interval trees of pending local requests */
	struct rb_root read_requests;
	struct rb_root write_requests;

	/* for statistics and timeouts */
	/* [0] read, [1] write */
	struct list_head pending_master_completion[2];
	struct list_head pending_completion[2];

	struct drbd_bitmap *bitmap;
#ifdef _WIN32
    ULONG_PTR bm_resync_fo; /* bit offset for drbd_bm_find_next */
#else
	unsigned long bm_resync_fo; /* bit offset for drbd_bm_find_next */
#endif
	struct mutex bm_resync_fo_mutex;
#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
 
	//DW-1911 marked replication list, used for resync
	//does not use lock because it guarantees synchronization for the use of marked_rl_list.
	//Use lock if you cannot guarantee future marked_rl_list synchronization
	struct list_head marked_rl_list;

	//DW-1904 range set from out of sync to in sync as replication data.
	//used to determine whether to replicate during resync.
	ULONG_PTR s_rl_bb;
	ULONG_PTR e_rl_bb;

	//DW-1904 last recv resync data bitmap bit
	ULONG_PTR e_resync_bb;

	//DW-1911 hit resync in progress hit marked replicate,in sync count
	ULONG_PTR h_marked_bb;	
	ULONG_PTR h_insync_bb;
#endif

	int open_rw_cnt, open_ro_cnt;
	/* FIXME clean comments, restructure so it is more obvious which
	 * members are protected by what */

	int next_barrier_nr;
	struct drbd_md_io md_io;
	spinlock_t al_lock;
	wait_queue_head_t al_wait;
	struct lru_cache *act_log;	/* activity log */
	unsigned int al_tr_number;
	unsigned int al_tr_cycle;
	wait_queue_head_t seq_wait;
	u64 exposed_data_uuid; /* UUID of the exposed data */
	u64 next_exposed_data_uuid;
	atomic_t rs_sect_ev; /* for submitted resync data rate, both */
	struct pending_bitmap_work_s {
		atomic_t n;		/* inc when queued here, */
		spinlock_t q_lock;	/* dec only once finished. */
		struct list_head q;	/* n > 0 even if q already empty */
	} pending_bitmap_work;
	struct device_conf device_conf;

	/* any requests that would block in drbd_make_request()
	 * are deferred to this single-threaded work queue */
	struct submit_worker submit;
	bool susp_quorum[2];		/* IO suspended quorum lost */

	/* DW-1755 disk error information structure is managed as a list, 
	* and the error count is stored separately for the status command.
	Disk errors rarely occur, and even if they occur, 
	the list counts will not increase in a large amount 
	because they will occur only in a specific sector. */
	atomic_t io_error_count;
};

struct drbd_bm_aio_ctx {
	struct drbd_device *device;
	struct list_head list; /* on device->pending_bitmap_io */
#ifdef _WIN32
	ULONG_PTR start_jif;
#else
	unsigned long start_jif;
#endif
	atomic_t in_flight;
	unsigned int done;
	unsigned flags;
#define BM_AIO_COPY_PAGES	1
#define BM_AIO_WRITE_HINTED	2
#define BM_AIO_WRITE_ALL_PAGES	4
#define BM_AIO_READ	        8
#define BM_AIO_WRITE_LAZY      16
	int error;
	struct kref kref;
};

struct drbd_config_context {
	/* assigned from drbd_genlmsghdr */
	unsigned int minor;
	/* assigned from request attributes, if present */
	unsigned int volume;
#define VOLUME_UNSPECIFIED			UINT32_MAX	//volume type unsigned int
	unsigned int peer_node_id;
#define PEER_NODE_ID_UNSPECIFIED	UINT32_MAX	//peer_node_id type unsigned int
	/* pointer into the request skb,
	 * limited lifetime! */
	char *resource_name;
	struct nlattr *my_addr;
	struct nlattr *peer_addr;

	/* reply buffer */
	struct sk_buff *reply_skb;
	/* pointer into reply buffer */
	struct drbd_genlmsghdr *reply_dh;
	/* resolved from attributes, if possible */
	struct drbd_device *device;
	struct drbd_resource *resource;
	struct drbd_connection *connection;
	struct drbd_peer_device *peer_device;
};

static inline struct drbd_device *minor_to_device(unsigned int minor)
{
	return (struct drbd_device *)idr_find(&drbd_devices, minor);
}


static inline struct drbd_peer_device *
conn_peer_device(struct drbd_connection *connection, int volume_number)
{
#ifdef _WIN32
	return (struct drbd_peer_device *)idr_find(&connection->peer_devices, volume_number);
#else
	return idr_find(&connection->peer_devices, volume_number);
#endif
}

static inline unsigned drbd_req_state_by_peer_device(struct drbd_request *req,
		struct drbd_peer_device *peer_device)
{
	int idx = peer_device->node_id;
	if (idx < 0 || idx >= DRBD_NODE_ID_MAX) {
		drbd_warn(peer_device, "FIXME: node_id: %d\n", idx);
		/* WARN(1, "bitmap_index: %d", idx); */
		return 0;
	}
	return req->rq_state[1 + idx];
}

#ifdef _WIN32
#define for_each_resource(resource, _resources) \
	list_for_each_entry(struct drbd_resource, resource, _resources, resources)

#define for_each_resource_rcu(resource, _resources) \
	list_for_each_entry_rcu(struct drbd_resource, resource, _resources, resources)

#define for_each_resource_safe(resource, tmp, _resources) \
	list_for_each_entry_safe(struct drbd_resource, resource, tmp, _resources, resources)

/* Each caller of for_each_connect() must hold req_lock or adm_mutex or conf_update.
   The update locations hold all three! */
#define for_each_connection(connection, resource) \
    list_for_each_entry(struct drbd_connection, connection, &resource->connections, connections)

#define for_each_connection_rcu(connection, resource) \
	list_for_each_entry_rcu(struct drbd_connection, connection, &resource->connections, connections)

#define for_each_connection_safe(connection, tmp, resource) \
	list_for_each_entry_safe(struct drbd_connection, connection, tmp, &resource->connections, connections)
#else
#define for_each_resource(resource, _resources) \
	list_for_each_entry(resource, _resources, resources)

#define for_each_resource_rcu(resource, _resources) \
	list_for_each_entry_rcu(resource, _resources, resources)

#define for_each_resource_safe(resource, tmp, _resources) \
	list_for_each_entry_safe(resource, tmp, _resources, resources)

/* Each caller of for_each_connect() must hold req_lock or adm_mutex or conf_update.
   The update locations hold all three! */
#define for_each_connection(connection, resource) \
	list_for_each_entry(connection, &resource->connections, connections)

#define for_each_connection_rcu(connection, resource) \
	list_for_each_entry_rcu(connection, &resource->connections, connections)

#define for_each_connection_safe(connection, tmp, resource) \
	list_for_each_entry_safe(connection, tmp, &resource->connections, connections)
#endif
#define for_each_connection_ref(connection, m, resource)		\
	for (connection = __drbd_next_connection_ref(&m, NULL, resource); \
	     connection;						\
	     connection = __drbd_next_connection_ref(&m, connection, resource))

/* Each caller of for_each_peer_device() must hold req_lock or adm_mutex or conf_update.
   The update locations hold all three! */
#ifdef _WIN32
#define for_each_peer_device(peer_device, device) \
    list_for_each_entry(struct drbd_peer_device, peer_device, &device->peer_devices, peer_devices)

#define for_each_peer_device_rcu(peer_device, device) \
 	list_for_each_entry_rcu(struct drbd_peer_device, peer_device, &device->peer_devices, peer_devices)

#define for_each_peer_device_safe(peer_device, tmp, device) \
	list_for_each_entry_safe(struct drbd_peer_device, peer_device, tmp, &device->peer_devices, peer_devices)
#else
#define for_each_peer_device(peer_device, device) \
	list_for_each_entry(peer_device, &device->peer_devices, peer_devices)

#define for_each_peer_device_rcu(peer_device, device) \
	list_for_each_entry_rcu(peer_device, &device->peer_devices, peer_devices)

#define for_each_peer_device_safe(peer_device, tmp, device) \
	list_for_each_entry_safe(peer_device, tmp, &device->peer_devices, peer_devices)
#endif

#define for_each_peer_device_ref(peer_device, m, device)		\
	for (peer_device = __drbd_next_peer_device_ref(&m, NULL, device); \
	     peer_device;						\
	     peer_device = __drbd_next_peer_device_ref(&m, peer_device, device))

static inline unsigned int device_to_minor(struct drbd_device *device)
{
	return device->minor;
}

/*
 * function declarations
 *************************/

/* drbd_main.c */

enum dds_flags {
	/* This enum is part of the wire protocol!
	* See P_SIZES, struct p_sizes; */
	DDSF_ASSUME_UNCONNECTED_PEER_HAS_SPACE = 1,
	DDSF_NO_RESYNC = 2, /* Do not run a resync for the new space */
	DDSF_IGNORE_PEER_CONSTRAINTS = 4,
	DDSF_2PC = 8, /* local only, not on the wire */
};

extern int  drbd_thread_start(struct drbd_thread *thi);
extern void _drbd_thread_stop(struct drbd_thread *thi, int restart, int wait);

#ifdef _WIN32
#define drbd_thread_current_set_cpu(A) 
#define drbd_calc_cpu_mask(A)
#else
#ifdef CONFIG_SMP
extern void drbd_thread_current_set_cpu(struct drbd_thread *thi);
#else
#define drbd_thread_current_set_cpu(A) ({})
#endif
#endif

extern void tl_release(struct drbd_connection *, unsigned int barrier_nr,
		       unsigned int set_size);
extern void tl_clear(struct drbd_connection *);
extern void drbd_free_sock(struct drbd_connection *connection);

extern int __drbd_send_protocol(struct drbd_connection *connection, enum drbd_packet cmd);
extern int drbd_send_protocol(struct drbd_connection *connection);
extern int drbd_send_uuids(struct drbd_peer_device *, u64 uuid_flags, u64 weak_nodes);
extern void drbd_gen_and_send_sync_uuid(struct drbd_peer_device *);
extern int drbd_attach_peer_device(struct drbd_peer_device *);
extern int drbd_send_sizes(struct drbd_peer_device *, uint64_t u_size_diskless, enum dds_flags flags);
extern int conn_send_state(struct drbd_connection *, union drbd_state);
extern int drbd_send_state(struct drbd_peer_device *, union drbd_state);
extern int drbd_send_current_state(struct drbd_peer_device *);
extern int drbd_send_sync_param(struct drbd_peer_device *);
extern void drbd_send_b_ack(struct drbd_connection *connection, u32 barrier_nr, u32 set_size);
extern int drbd_send_out_of_sync(struct drbd_peer_device *, struct drbd_interval *);
extern int drbd_send_block(struct drbd_peer_device *, enum drbd_packet,
			   struct drbd_peer_request *);
extern int drbd_send_dblock(struct drbd_peer_device *, struct drbd_request *req);
extern int drbd_send_drequest(struct drbd_peer_device *, int cmd,
			      sector_t sector, int size, u64 block_id);
extern void *drbd_prepare_drequest_csum(struct drbd_peer_request *peer_req, int digest_size);
extern int drbd_send_ov_request(struct drbd_peer_device *, sector_t sector, int size);

extern int drbd_send_bitmap(struct drbd_device *, struct drbd_peer_device *);
extern int drbd_send_dagtag(struct drbd_connection *connection, u64 dagtag);
extern void drbd_send_sr_reply(struct drbd_connection *connection, int vnr,
			       enum drbd_state_rv retcode);
extern int drbd_send_rs_deallocated(struct drbd_peer_device *, struct drbd_peer_request *);
extern void drbd_send_twopc_reply(struct drbd_connection *connection,
				  enum drbd_packet, struct twopc_reply *);
extern void drbd_send_peers_in_sync(struct drbd_peer_device *, u64, sector_t, int);
extern int drbd_send_peer_dagtag(struct drbd_connection *connection, struct drbd_connection *lost_peer);
extern int drbd_send_current_uuid(struct drbd_peer_device *peer_device, u64 current_uuid, u64 weak_nodes);
extern void drbd_backing_dev_free(struct drbd_device *device, struct drbd_backing_dev *ldev);
extern void drbd_cleanup_device(struct drbd_device *device);
extern void drbd_print_uuids(struct drbd_peer_device *peer_device, const char *text, const char *caller);
extern void drbd_queue_unplug(struct drbd_device *device);

extern u64 drbd_capacity_to_on_disk_bm_sect(u64 capacity_sect, unsigned int max_peers);
extern void drbd_md_set_sector_offsets(struct drbd_device *device,
				       struct drbd_backing_dev *bdev);
extern void drbd_md_write(struct drbd_device *device, void *buffer);
extern void drbd_md_sync(struct drbd_device *device);
extern void drbd_md_sync_if_dirty(struct drbd_device *device);
extern int  drbd_md_read(struct drbd_device *device, struct drbd_backing_dev *bdev);
#ifdef _WIN32
// MODIFIED_BY_MANTECH DW-1145
extern void drbd_propagate_uuids(struct drbd_device *device, u64 nodes) __must_hold(local);
#endif
extern void drbd_uuid_received_new_current(struct drbd_peer_device *, u64 , u64) __must_hold(local);
extern void drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 val) __must_hold(local);
extern void _drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 val) __must_hold(local);
extern void _drbd_uuid_set_current(struct drbd_device *device, u64 val) __must_hold(local);
extern void drbd_uuid_new_current(struct drbd_device *device, bool forced);
extern void drbd_uuid_new_current_by_user(struct drbd_device *device);
extern void _drbd_uuid_push_history(struct drbd_device *device, u64 val) __must_hold(local);
extern u64 _drbd_uuid_pull_history(struct drbd_peer_device *peer_device) __must_hold(local);
extern void __drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 val) __must_hold(local);
extern u64 drbd_uuid_resync_finished(struct drbd_peer_device *peer_device) __must_hold(local);
#ifdef _WIN32
// MODIFIED_BY_MANTECH DW-955
extern void forget_bitmap(struct drbd_device *device, int node_id) __must_hold(local);
#endif
extern void drbd_uuid_detect_finished_resyncs(struct drbd_peer_device *peer_device) __must_hold(local);
extern u64 drbd_weak_nodes_device(struct drbd_device *device);
extern void drbd_md_set_flag(struct drbd_device *device, enum mdf_flag) __must_hold(local);
extern void drbd_md_clear_flag(struct drbd_device *device, enum mdf_flag)__must_hold(local);
extern int drbd_md_test_flag(struct drbd_device *device, enum mdf_flag);
extern void drbd_md_set_peer_flag(struct drbd_peer_device *, enum mdf_peer_flag);
extern void drbd_md_clear_peer_flag(struct drbd_peer_device *, enum mdf_peer_flag);
extern bool drbd_md_test_peer_flag(struct drbd_peer_device *, enum mdf_peer_flag);
#ifndef DRBD_DEBUG_MD_SYNC
extern void drbd_md_mark_dirty(struct drbd_device *device);
#else
#define drbd_md_mark_dirty(m)	drbd_md_mark_dirty_(m, __LINE__ , __func__ )
extern void drbd_md_mark_dirty_(struct drbd_device *device,
		unsigned int line, const char *func);
#endif
extern void drbd_queue_bitmap_io(struct drbd_device *,
				 int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
				 void (*done)(struct drbd_device *, struct drbd_peer_device *, int),
				 char *why, enum bm_flag flags,
				 struct drbd_peer_device *);
extern int drbd_bitmap_io(struct drbd_device *,
		int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
		char *why, enum bm_flag flags,
		struct drbd_peer_device *);
extern int drbd_bitmap_io_from_worker(struct drbd_device *,
		int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
		char *why, enum bm_flag flags,
		struct drbd_peer_device *);
extern int drbd_bmio_set_n_write(struct drbd_device *device, struct drbd_peer_device *) __must_hold(local);
#ifdef _WIN32
// DW-844
extern bool SetOOSAllocatedCluster(struct drbd_device *device, struct drbd_peer_device *, enum drbd_repl_state side, bool bitmap_lock) __must_hold(local);
#endif
extern int drbd_bmio_clear_all_n_write(struct drbd_device *device, struct drbd_peer_device *) __must_hold(local);
extern int drbd_bmio_set_all_n_write(struct drbd_device *device, struct drbd_peer_device *) __must_hold(local);
#ifdef _WIN32
// DW-1293
extern int drbd_bmio_set_all_or_fast(struct drbd_device *device, struct drbd_peer_device *peer_device) __must_hold(local);
#endif
extern bool drbd_device_stable(struct drbd_device *device, u64 *authoritative);
#ifdef _WIN32_STABLE_SYNCSOURCE
// DW-1315
#ifdef _WIN32_RCU_LOCKED
extern bool drbd_device_stable_ex(struct drbd_device *device, u64 *authoritative, enum which_state which, bool locked);
#else
extern bool drbd_device_stable_ex(struct drbd_device *device, u64 *authoritative, enum which_state which);
#endif
#endif
extern void drbd_flush_peer_acks(struct drbd_resource *resource);
extern void drbd_drop_unsent(struct drbd_connection* connection);
extern void drbd_cork(struct drbd_connection *connection, enum drbd_stream stream);
extern void drbd_uncork(struct drbd_connection *connection, enum drbd_stream stream);

extern struct drbd_connection *
__drbd_next_connection_ref(u64 *, struct drbd_connection *, struct drbd_resource *);

extern struct drbd_peer_device *
__drbd_next_peer_device_ref(u64 *, struct drbd_peer_device *, struct drbd_device *);


/* Meta data layout
 *
 * We currently have two possible layouts.
 * Offsets in (512 byte) sectors.
 * external:
 *   |----------- md_size_sect ------------------|
 *   [ 4k superblock ][ activity log ][  Bitmap  ]
 *   | al_offset == 8 |
 *   | bm_offset = al_offset + X      |
 *  ==> bitmap sectors = md_size_sect - bm_offset
 *
 *  Variants:
 *     old, indexed fixed size meta data:
 *
 * internal:
 *            |----------- md_size_sect ------------------|
 * [data.....][  Bitmap  ][ activity log ][ 4k superblock ][padding*]
 *                        | al_offset < 0 |
 *            | bm_offset = al_offset - Y |
 *  ==> bitmap sectors = Y = al_offset - bm_offset
 *
 *  [padding*] are zero or up to 7 unused 512 Byte sectors to the
 *  end of the device, so that the [4k superblock] will be 4k aligned.
 *
 *  The activity log consists of 4k transaction blocks,
 *  which are written in a ring-buffer, or striped ring-buffer like fashion,
 *  which are writtensize used to be fixed 32kB,
 *  but is about to become configurable.
 */

/* One activity log extent represents 4M of storage */
#define AL_EXTENT_SHIFT 22
#define AL_EXTENT_SIZE (1<<AL_EXTENT_SHIFT)

/* drbd_bitmap.c */
/*
 * We need to store one bit for a block.
 * Example: 1GB disk @ 4096 byte blocks ==> we need 32 KB bitmap.
 * Bit 0 ==> local node thinks this block is binary identical on both nodes
 * Bit 1 ==> local node thinks this block needs to be synced.
 */

#define SLEEP_TIME (HZ/10)

/* We do bitmap IO in units of 4k blocks.
 * We also still have a hardcoded 4k per bit relation. */
#define BM_BLOCK_SHIFT	12			 /* 4k per bit */
#define BM_BLOCK_SIZE	 (1<<BM_BLOCK_SHIFT)
/* mostly arbitrarily set the represented size of one bitmap extent,
 * aka resync extent, to 128 MiB (which is also 4096 Byte worth of bitmap
 * at 4k per bit resolution) */
#define BM_EXT_SHIFT	 27	/* 128 MiB per resync extent */
#define BM_EXT_SIZE	 (1<<BM_EXT_SHIFT)

#if (BM_BLOCK_SHIFT != 12)
#error "HAVE YOU FIXED drbdmeta AS WELL??"
#endif

/* thus many _storage_ sectors are described by one bit */
#define BM_SECT_TO_BIT(x)   ((x)>>(BM_BLOCK_SHIFT-9))
#define BM_BIT_TO_SECT(x)   ((sector_t)(x)<<(BM_BLOCK_SHIFT-9))
#define BM_SECT_PER_BIT     BM_BIT_TO_SECT(1)

/* bit to represented kilo byte conversion */
#define Bit2KB(bits) ((bits)<<(BM_BLOCK_SHIFT-10))

/* in which _bitmap_ extent (resp. sector) the bit for a certain
 * _storage_ sector is located in */
#define BM_SECT_TO_EXT(x)   ((x)>>(BM_EXT_SHIFT-9))
#define BM_BIT_TO_EXT(x)    ((x) >> (BM_EXT_SHIFT - BM_BLOCK_SHIFT))

/* first storage sector a bitmap extent corresponds to */
#define BM_EXT_TO_SECT(x)   ((sector_t)(x) << (BM_EXT_SHIFT-9))
/* how much _storage_ sectors we have per bitmap extent */
#define BM_SECT_PER_EXT     BM_EXT_TO_SECT(1)
/* how many bits are covered by one bitmap extent (resync extent) */
#define BM_BITS_PER_EXT     (1UL << (BM_EXT_SHIFT - BM_BLOCK_SHIFT))

#define BM_BLOCKS_PER_BM_EXT_MASK  (BM_BITS_PER_EXT - 1)


/* in one sector of the bitmap, we have this many activity_log extents. */
#define AL_EXT_PER_BM_SECT  (1 << (BM_EXT_SHIFT - AL_EXTENT_SHIFT))

/* the extent in "PER_EXTENT" below is an activity log extent
 * we need that many (long words/bytes) to store the bitmap
 *		     of one AL_EXTENT_SIZE chunk of storage.
 * we can store the bitmap for that many AL_EXTENTS within
 * one sector of the _on_disk_ bitmap:
 * bit	 0	  bit 37   bit 38	     bit (512*8)-1
 *	     ...|........|........|.. // ..|........|
 * sect. 0	 `296	  `304			   ^(512*8*8)-1
 *
#define BM_WORDS_PER_EXT    ( (AL_EXT_SIZE/BM_BLOCK_SIZE) / BITS_PER_LONG )
#define BM_BYTES_PER_EXT    ( (AL_EXT_SIZE/BM_BLOCK_SIZE) / 8 )  // 128
#define BM_EXT_PER_SECT	    ( 512 / BM_BYTES_PER_EXTENT )	 //   4
 */

#define DRBD_MAX_SECTORS_32 (0xffffffffLU)
/* we have a certain meta data variant that has a fixed on-disk size of 128
 * MiB, of which 4k are our "superblock", and 32k are the fixed size activity
 * log, leaving this many sectors for the bitmap.
 */

#ifdef _WIN32 // DW-1335 
#define DRBD_MAX_SECTORS_FIXED_BM \
	  (((256 << 20 >> 9) - (32768 >> 9) - (4096 >> 9)) * (1LL<<(BM_EXT_SHIFT-9))) 
#else \
#define DRBD_MAX_SECTORS_FIXED_BM \
	  (((128 << 20 >> 9) - (32768 >> 9) - (4096 >> 9)) * (1LL<<(BM_EXT_SHIFT-9)))
#endif \
	  
#if !defined(CONFIG_LBDAF) && !defined(CONFIG_LBD) && BITS_PER_LONG == 32
#define DRBD_MAX_SECTORS      DRBD_MAX_SECTORS_32
#define DRBD_MAX_SECTORS_FLEX DRBD_MAX_SECTORS_32
#else
#define DRBD_MAX_SECTORS      DRBD_MAX_SECTORS_FIXED_BM
/* 16 TB in units of sectors */
#if BITS_PER_LONG == 32
/* adjust by one page worth of bitmap,
 * so we won't wrap around in drbd_bm_find_next_bit.
 * you should use 64bit OS for that much storage, anyways. */
#define DRBD_MAX_SECTORS_FLEX BM_BIT_TO_SECT(0xffff7fff)
#else
/* we allow up to 1 PiB now on 64bit architecture with "flexible" meta data */
#ifdef _WIN32
#define DRBD_MAX_SECTORS_FLEX (1ULL << 51)
#else
#define DRBD_MAX_SECTORS_FLEX (1UL << 51)
#endif
/* corresponds to (1UL << 38) bits right now. */
#endif
#endif

/* Estimate max bio size as 256 * PAGE_CACHE_SIZE,
 * so for typical PAGE_CACHE_SIZE of 4k, that is (1<<20) Byte.
 * Since we may live in a mixed-platform cluster,
 * we limit us to a platform agnostic constant here for now.
 * A followup commit may allow even bigger BIO sizes,
 * once we thought that through. */
#ifndef _WIN32
#if DRBD_MAX_BIO_SIZE > (BIO_MAX_PAGES << PAGE_SHIFT)
#error Architecture not supported: DRBD_MAX_BIO_SIZE > (BIO_MAX_PAGES << PAGE_SHIFT)
#endif
#endif
#define DRBD_MAX_SIZE_H80_PACKET (1U << 15) /* Header 80 only allows packets up to 32KiB data */
#define DRBD_MAX_BIO_SIZE_P95    (1U << 17) /* Protocol 95 to 99 allows bios up to 128KiB */

/* For now, don't allow more than half of what we can "activate" in one
 * activity log transaction to be discarded in one go. We may need to rework
 * drbd_al_begin_io() to allow for even larger discard ranges */
#define DRBD_MAX_BATCH_BIO_SIZE	 (AL_UPDATES_PER_TRANSACTION/2*AL_EXTENT_SIZE)
#define DRBD_MAX_BBIO_SECTORS    (DRBD_MAX_BATCH_BIO_SIZE >> 9)

extern struct drbd_bitmap *drbd_bm_alloc(void);
extern int  drbd_bm_resize(struct drbd_device *device, sector_t sectors, int set_new_bits);
void drbd_bm_free(struct drbd_bitmap *bitmap);
extern void drbd_bm_set_all(struct drbd_device *device);
extern void drbd_bm_clear_all(struct drbd_device *device);
#ifdef _WIN32
/* set/clear/test only a few bits at a time */
extern unsigned int drbd_bm_set_bits(struct drbd_device *, unsigned int, ULONG_PTR, ULONG_PTR);
extern unsigned int drbd_bm_clear_bits(struct drbd_device *, unsigned int, ULONG_PTR, ULONG_PTR);
extern int drbd_bm_count_bits(struct drbd_device *, unsigned int, ULONG_PTR, ULONG_PTR);
/* bm_set_bits variant for use while holding drbd_bm_lock,
* may process the whole bitmap in one go */
extern void drbd_bm_set_many_bits(struct drbd_peer_device *, ULONG_PTR, ULONG_PTR);
extern void drbd_bm_clear_many_bits(struct drbd_peer_device *, ULONG_PTR, ULONG_PTR);
extern void _drbd_bm_clear_many_bits(struct drbd_device *, int, ULONG_PTR, ULONG_PTR);
extern ULONG_PTR drbd_bm_test_bit(struct drbd_peer_device *, const ULONG_PTR);
#else
/* set/clear/test only a few bits at a time */
extern unsigned int drbd_bm_set_bits(struct drbd_device *, unsigned int, unsigned long, unsigned long);
extern unsigned int drbd_bm_clear_bits(struct drbd_device *, unsigned int, unsigned long, unsigned long);
extern int drbd_bm_count_bits(struct drbd_device *, unsigned int, unsigned long, unsigned long);
/* bm_set_bits variant for use while holding drbd_bm_lock,
 * may process the whole bitmap in one go */
extern void drbd_bm_set_many_bits(struct drbd_peer_device *, unsigned long, unsigned long);
extern void drbd_bm_clear_many_bits(struct drbd_peer_device *, unsigned long, unsigned long);
extern void _drbd_bm_clear_many_bits(struct drbd_device *, int, unsigned long, unsigned long);
extern int drbd_bm_test_bit(struct drbd_peer_device *, unsigned long);
#endif

extern int  drbd_bm_read(struct drbd_device *, struct drbd_peer_device *) __must_hold(local);
extern void drbd_bm_reset_al_hints(struct drbd_device *device) __must_hold(local);
#ifdef _WIN32
extern void drbd_bm_mark_range_for_writeout(struct drbd_device *, ULONG_PTR, ULONG_PTR);
#else
extern void drbd_bm_mark_range_for_writeout(struct drbd_device *, unsigned long, unsigned long);
#endif
extern int  drbd_bm_write(struct drbd_device *, struct drbd_peer_device *) __must_hold(local);
extern int  drbd_bm_write_hinted(struct drbd_device *device) __must_hold(local);
extern int  drbd_bm_write_lazy(struct drbd_device *device, unsigned upper_idx) __must_hold(local);
extern int drbd_bm_write_all(struct drbd_device *, struct drbd_peer_device *) __must_hold(local);
extern int drbd_bm_write_copy_pages(struct drbd_device *, struct drbd_peer_device *) __must_hold(local);
extern size_t	     drbd_bm_words(struct drbd_device *device);
#ifdef _WIN32
extern ULONG_PTR drbd_bm_bits(struct drbd_device *device);
#else
extern unsigned long drbd_bm_bits(struct drbd_device *device);
#endif
extern sector_t      drbd_bm_capacity(struct drbd_device *device);
#ifdef _WIN32
#define DRBD_END_OF_BITMAP	UINTPTR_MAX
extern ULONG_PTR drbd_bm_find_next(struct drbd_peer_device *, ULONG_PTR);
/* bm_find_next variants for use while you hold drbd_bm_lock() */
extern ULONG_PTR _drbd_bm_find_next(struct drbd_peer_device *, ULONG_PTR);
extern ULONG_PTR _drbd_bm_find_next_zero(struct drbd_peer_device *, ULONG_PTR);
extern ULONG_PTR _drbd_bm_total_weight(struct drbd_device *, int);
extern ULONG_PTR drbd_bm_total_weight(struct drbd_peer_device *);
extern void check_and_clear_io_error_in_primary(struct drbd_device *);
extern void check_and_clear_io_error_in_secondary(struct drbd_peer_device *);

/* for receive_bitmap */
extern void drbd_bm_merge_lel(struct drbd_peer_device *peer_device, size_t offset,
    size_t number, ULONG_PTR *buffer);
/* for _drbd_send_bitmap */
extern void drbd_bm_get_lel(struct drbd_peer_device *peer_device, size_t offset,
    size_t number, ULONG_PTR *buffer);
#else
#define DRBD_END_OF_BITMAP	(~(unsigned long)0)
extern unsigned long drbd_bm_find_next(struct drbd_peer_device *, unsigned long);
/* bm_find_next variants for use while you hold drbd_bm_lock() */
extern unsigned long _drbd_bm_find_next(struct drbd_peer_device *, unsigned long);
extern unsigned long _drbd_bm_find_next_zero(struct drbd_peer_device *, unsigned long);
extern unsigned long _drbd_bm_total_weight(struct drbd_device *, int);
extern unsigned long drbd_bm_total_weight(struct drbd_peer_device *);
/* for receive_bitmap */
extern void drbd_bm_merge_lel(struct drbd_peer_device *peer_device, size_t offset,
		size_t number, unsigned long *buffer);
/* for _drbd_send_bitmap */
extern void drbd_bm_get_lel(struct drbd_peer_device *peer_device, size_t offset,
		size_t number, unsigned long *buffer);
#endif
extern void drbd_bm_lock(struct drbd_device *device, char *why, enum bm_flag flags);
extern void drbd_bm_unlock(struct drbd_device *device);
extern void drbd_bm_slot_lock(struct drbd_peer_device *peer_device, char *why, enum bm_flag flags);
extern void drbd_bm_slot_unlock(struct drbd_peer_device *peer_device);
extern void drbd_bm_copy_slot(struct drbd_device *device, unsigned int from_index, unsigned int to_index);
/* drbd_main.c */

#ifdef _WIN32
extern NPAGED_LOOKASIDE_LIST drbd_request_mempool;
extern NPAGED_LOOKASIDE_LIST drbd_ee_mempool;		/* peer requests */
extern NPAGED_LOOKASIDE_LIST drbd_bm_ext_cache;		/* bitmap extents */
extern NPAGED_LOOKASIDE_LIST drbd_al_ext_cache;		/* activity log extents */
#else
extern struct kmem_cache *drbd_request_cache;
extern struct kmem_cache *drbd_ee_cache;	/* peer requests */
extern struct kmem_cache *drbd_bm_ext_cache;	/* bitmap extents */
extern struct kmem_cache *drbd_al_ext_cache;	/* activity log extents */
extern mempool_t *drbd_request_mempool;
extern mempool_t *drbd_ee_mempool;
#endif

/* drbd's page pool, used to buffer data received from the peer,
 * or data requested by the peer.
 *
 * This does not have an emergency reserve.
 *
 * When allocating from this pool, it first takes pages from the pool.
 * Only if the pool is depleted will try to allocate from the system.
 *
 * The assumption is that pages taken from this pool will be processed,
 * and given back, "quickly", and then can be recycled, so we can avoid
 * frequent calls to alloc_page(), and still will be able to make progress even
 * under memory pressure.
 */
#ifndef _WIN32
extern struct page *drbd_pp_pool;
#endif
extern spinlock_t   drbd_pp_lock;
extern int	    drbd_pp_vacant;
extern wait_queue_head_t drbd_pp_wait;

/* We also need a standard (emergency-reserve backed) page pool
 * for meta data IO (activity log, bitmap).
 * We can keep it global, as long as it is used as "N pages at a time".
 * 128 should be plenty, currently we probably can get away with as few as 1.
 */
#define DRBD_MIN_POOL_PAGES	128
extern mempool_t *drbd_md_io_page_pool;

/* We also need to make sure we get a bio
 * when we need it for housekeeping purposes */
extern struct bio_set *drbd_md_io_bio_set;
/* to allocate from that set */
#ifdef _WIN32
extern struct bio *bio_alloc_drbd(gfp_t gfp_mask, ULONG Tag);
#else
extern struct bio *bio_alloc_drbd(gfp_t gfp_mask);
#endif

extern int conn_lowest_minor(struct drbd_connection *connection);
extern struct drbd_peer_device *create_peer_device(struct drbd_device *, struct drbd_connection *);
extern enum drbd_ret_code drbd_create_device(struct drbd_config_context *adm_ctx, unsigned int minor,
					     struct device_conf *device_conf, struct drbd_device **p_device);
extern void drbd_unregister_device(struct drbd_device *);
extern void drbd_put_device(struct drbd_device *);
extern void drbd_unregister_connection(struct drbd_connection *);
extern void drbd_put_connection(struct drbd_connection *);
void del_connect_timer(struct drbd_connection *connection);

extern struct drbd_resource *drbd_create_resource(const char *, struct res_opts *);
extern void drbd_free_resource(struct drbd_resource *resource);

extern void drbd_destroy_device(struct kref *kref);

extern int set_resource_options(struct drbd_resource *resource, struct res_opts *res_opts);
extern struct drbd_connection *drbd_create_connection(struct drbd_resource *resource,
						      struct drbd_transport_class *tc);
extern void drbd_transport_shutdown(struct drbd_connection *connection, enum drbd_tr_free_op op);
extern void drbd_destroy_connection(struct kref *kref);
extern struct drbd_resource *drbd_find_resource(const char *name);
extern void drbd_destroy_resource(struct kref *kref);
extern void conn_free_crypto(struct drbd_connection *connection);

#ifdef _WIN32
// DW-1398
extern void dtt_put_listeners(struct drbd_transport *);
#endif

/* drbd_req */
extern void do_submit(struct work_struct *ws);
#ifdef _WIN32
extern NTSTATUS __drbd_make_request(struct drbd_device *, struct bio *, ULONG_PTR);
#else
extern void __drbd_make_request(struct drbd_device *, struct bio *, unsigned long);
#endif

extern MAKE_REQUEST_TYPE drbd_make_request(struct request_queue *q, struct bio *bio);
#ifdef COMPAT_HAVE_BLK_QUEUE_MERGE_BVEC
extern int drbd_merge_bvec(struct request_queue *, struct bvec_merge_data *, struct bio_vec *);
#endif
extern int is_valid_ar_handle(struct drbd_request *, sector_t);


/* drbd_nl.c */
enum suspend_scope {
	READ_AND_WRITE,
	WRITE_ONLY
};
extern void drbd_suspend_io(struct drbd_device *device, enum suspend_scope);
extern void drbd_resume_io(struct drbd_device *device);
extern char *ppsize(char *buf, size_t len, unsigned long long size);
extern sector_t drbd_new_dev_size(struct drbd_device *,
	sector_t current_size, /* need at least this much */
	sector_t user_capped_size, /* want (at most) this much */
	enum dds_flags flags) __must_hold(local);
enum determine_dev_size {
	DS_2PC_ERR = -5,
	DS_2PC_NOT_SUPPORTED = -4,
	DS_ERROR_SHRINK = -3,
	DS_ERROR_SPACE_MD = -2,
	DS_ERROR = -1,
	DS_UNCHANGED = 0,
	DS_SHRUNK = 1,
	DS_GREW = 2,
	DS_GREW_FROM_ZERO = 3,
};
extern enum determine_dev_size
drbd_determine_dev_size(struct drbd_device *, sector_t peer_current_size,
		enum dds_flags, struct resize_parms *) __must_hold(local);
extern void resync_after_online_grow(struct drbd_peer_device *);
extern void drbd_reconsider_queue_parameters(struct drbd_device *device,
			struct drbd_backing_dev *bdev, struct o_qlim *o);
extern enum drbd_state_rv drbd_set_role(struct drbd_resource *, enum drbd_role, bool, struct sk_buff *);
#ifdef _WIN32
extern enum drbd_state_rv drbd_set_secondary_from_shutdown(struct drbd_resource *);
#endif
extern bool conn_try_outdate_peer(struct drbd_connection *connection);
extern void conn_try_outdate_peer_async(struct drbd_connection *connection);
extern int drbd_khelper(struct drbd_device *, struct drbd_connection *, char *);
extern int drbd_create_peer_device_default_config(struct drbd_peer_device *peer_device);

/* drbd_sender.c */
extern int drbd_sender(struct drbd_thread *thi);
extern int drbd_worker(struct drbd_thread *thi);
enum drbd_ret_code drbd_resync_after_valid(struct drbd_device *device, int o_minor);
void drbd_resync_after_changed(struct drbd_device *device);
extern bool drbd_stable_sync_source_present(struct drbd_peer_device *, enum which_state);
extern void drbd_start_resync(struct drbd_peer_device *, enum drbd_repl_state);
#ifdef _WIN32_STABLE_SYNCSOURCE
// DW-1314, DW-1315
#ifdef _WIN32_RCU_LOCKED
extern bool drbd_inspect_resync_side(struct drbd_peer_device *peer_device, enum drbd_repl_state side, enum which_state which, bool locked);
#else
extern bool drbd_inspect_resync_side(struct drbd_peer_device *peer_device, enum drbd_repl_state side, enum which_state which);
#endif
#endif
extern void resume_next_sg(struct drbd_device *device);
extern void suspend_other_sg(struct drbd_device *device);
extern int drbd_resync_finished(struct drbd_peer_device *, enum drbd_disk_state);
/* maybe rather drbd_main.c ? */
extern void *drbd_md_get_buffer(struct drbd_device *device, const char *intent);
extern void drbd_md_put_buffer(struct drbd_device *device);
extern int drbd_md_sync_page_io(struct drbd_device *device,
		struct drbd_backing_dev *bdev, sector_t sector, int op);
extern void drbd_ov_out_of_sync_found(struct drbd_peer_device *, sector_t, int);
extern void wait_until_done_or_force_detached(struct drbd_device *device,
		struct drbd_backing_dev *bdev, unsigned int *done);
extern void drbd_rs_controller_reset(struct drbd_peer_device *);
extern void drbd_ping_peer(struct drbd_connection *connection);
extern struct drbd_peer_device *peer_device_by_node_id(struct drbd_device *, int);
#ifdef _WIN32
extern KDEFERRED_ROUTINE repost_up_to_date_fn;
#else
extern void repost_up_to_date_fn(unsigned long data);
#endif 

static inline void ov_out_of_sync_print(struct drbd_peer_device *peer_device)
{
	if (peer_device->ov_last_oos_size) {
		drbd_err(peer_device, "Out of sync: start=%llu, size=%lu (sectors)\n",
		     (unsigned long long)peer_device->ov_last_oos_start,
		     (unsigned long)peer_device->ov_last_oos_size);
	}
	peer_device->ov_last_oos_size = 0;
}


#ifdef _WIN32
extern void drbd_csum_bio(struct crypto_hash *, struct drbd_request *, void *);
#else
extern void drbd_csum_bio(struct crypto_hash *, struct bio *, void *);
#endif

#ifdef _WIN32
extern void drbd_csum_pages(struct crypto_hash *, struct drbd_peer_request *, void *);
#else
extern void drbd_csum_pages(struct crypto_hash *, struct page *, void *);
#endif
/* worker callbacks */
extern int w_e_end_data_req(struct drbd_work *, int);
extern int w_e_end_rsdata_req(struct drbd_work *, int);
extern int w_e_end_csum_rs_req(struct drbd_work *, int);
extern int w_e_end_ov_reply(struct drbd_work *, int);
extern int w_e_end_ov_req(struct drbd_work *, int);
extern int w_ov_finished(struct drbd_work *, int);
extern int w_resync_timer(struct drbd_work *, int);
extern int w_send_dblock(struct drbd_work *, int);
extern int w_send_read_req(struct drbd_work *, int);
extern int w_e_reissue(struct drbd_work *, int);
extern int w_restart_disk_io(struct drbd_work *, int);
extern int w_start_resync(struct drbd_work *, int);
extern int w_send_uuids(struct drbd_work *, int);

#ifdef _WIN32
extern KDEFERRED_ROUTINE resync_timer_fn;
extern KDEFERRED_ROUTINE start_resync_timer_fn;
#else
extern void resync_timer_fn(unsigned long data);
extern void start_resync_timer_fn(unsigned long data);
#endif

extern void drbd_endio_write_sec_final(struct drbd_peer_request *peer_req);

void __update_timing_details(
		struct drbd_thread_timing_details *tdp,
		unsigned int *cb_nr,
		void *cb,
		const char *fn, const unsigned int line);

#define update_sender_timing_details(c, cb) \
	__update_timing_details(c->s_timing_details, &c->s_cb_nr, cb, __func__ , __LINE__ )
#define update_receiver_timing_details(c, cb) \
	__update_timing_details(c->r_timing_details, &c->r_cb_nr, cb, __func__ , __LINE__ )
#define update_worker_timing_details(r, cb) \
	__update_timing_details(r->w_timing_details, &r->w_cb_nr, cb, __func__ , __LINE__ )

/* drbd_receiver.c */
struct packet_info {
	enum drbd_packet cmd;
	unsigned int size;
	int vnr;
	void *data;
};

/* packet_info->data is just a pointer into some temporary buffer
 * owned by the transport. As soon as we call into the transport for
 * any further receive operation, the data it points to is undefined.
 * The buffer may be freed/recycled/re-used already.
 * Convert and store the relevant information for any incoming data
 * in drbd_peer_request_detail.
 */

struct drbd_peer_request_details {
	uint64_t sector;	/* be64_to_cpu(p_data.sector) */
	uint64_t block_id;	/* unmodified p_data.block_id */
	uint32_t peer_seq;	/* be32_to_cpu(p_data.seq_num) */
	uint32_t dp_flags;	/* be32_to_cpu(p_data.dp_flags) */
	uint32_t length;	/* endian converted p_head*.length */
	uint32_t bi_size;	/* resulting bio size */
	/* for non-discards: bi_size = length - digest_size */
	uint32_t digest_size;
};

struct queued_twopc {
	struct drbd_work w;
#ifdef _WIN32
    ULONG_PTR start_jif;
#else
	unsigned long start_jif;
#endif
	struct drbd_connection *connection;
	struct twopc_reply reply;
	struct packet_info packet_info;
	struct p_twopc_request packet_data;
};

extern int drbd_issue_discard_or_zero_out(struct drbd_device *device,
		sector_t start, unsigned int nr_sectors, bool discard);
extern int drbd_send_ack(struct drbd_peer_device *, enum drbd_packet,
			 struct drbd_peer_request *);
extern int drbd_send_ack_ex(struct drbd_peer_device *, enum drbd_packet,
			    sector_t sector, int blksize, u64 block_id);
extern int drbd_receiver(struct drbd_thread *thi);
extern int drbd_ack_receiver(struct drbd_thread *thi);
extern void drbd_send_ping_wf(struct work_struct *ws);
extern void drbd_send_acks_wf(struct work_struct *ws);
extern void drbd_send_peer_ack_wf(struct work_struct *ws);
#ifdef _WIN32
extern void drbd_send_out_of_sync_wf(struct work_struct *ws);
#endif
extern bool drbd_rs_c_min_rate_throttle(struct drbd_peer_device *);
extern bool drbd_rs_should_slow_down(struct drbd_peer_device *, sector_t,
				     bool throttle_if_app_is_waiting);
extern int drbd_submit_peer_request(struct drbd_device *,
				    struct drbd_peer_request *, const int,
				    const unsigned, const int);
extern void drbd_cleanup_after_failed_submit_peer_request(struct drbd_peer_request *peer_req);
extern int drbd_free_peer_reqs(struct drbd_resource *, struct list_head *, bool is_net_ee);
extern struct drbd_peer_request *drbd_alloc_peer_req(struct drbd_peer_device *, gfp_t) __must_hold(local);
extern void __drbd_free_peer_req(struct drbd_peer_request *, int);
#define drbd_free_peer_req(pr) __drbd_free_peer_req(pr, 0)
#define drbd_free_net_peer_req(pr) __drbd_free_peer_req(pr, 1)
extern void drbd_set_recv_tcq(struct drbd_device *device, int tcq_enabled);
extern void _drbd_clear_done_ee(struct drbd_device *device, struct list_head *to_be_freed);
extern int drbd_connected(struct drbd_peer_device *);
extern void apply_unacked_peer_requests(struct drbd_connection *connection);
extern struct drbd_connection *drbd_connection_by_node_id(struct drbd_resource *, int);
extern struct drbd_connection *drbd_get_connection_by_node_id(struct drbd_resource *, int);
#ifdef _WIN32
extern void drbd_resync_after_unstable(struct drbd_peer_device *peer_device) __must_hold(local);
#endif
extern void queue_queued_twopc(struct drbd_resource *resource);
#ifdef _WIN32
extern KDEFERRED_ROUTINE queued_twopc_timer_fn;
#else
extern void queued_twopc_timer_fn(unsigned long data);
#endif
extern bool drbd_have_local_disk(struct drbd_resource *resource);
extern enum drbd_state_rv drbd_support_2pc_resize(struct drbd_resource *resource);
extern enum determine_dev_size
drbd_commit_size_change(struct drbd_device *device, struct resize_parms *rs, u64 nodes_to_reach);

#ifdef _WIN32 // DW-1607 : get the real size of the meta disk.
static __inline sector_t drbd_get_md_capacity(struct block_device *bdev)
{
	if (!bdev) {
		WDRBD_ERROR("md block_device is null.\n");
		return 0;
	}

	PVOLUME_EXTENSION pvext = (bdev->bd_disk) ? bdev->bd_disk->pDeviceExtension : NULL;
	if (pvext && (KeGetCurrentIrql() < 2)) {
		bdev->d_size = get_targetdev_volsize(pvext);	// real size
		return bdev->d_size >> 9;
	}
	else
	{
		WDRBD_ERROR("bd_disk is null.\n");
		return 0;
	}
}
#endif

static __inline sector_t drbd_get_capacity(struct block_device *bdev)
{
#ifdef _WIN32
	if (!bdev) {
		WDRBD_WARN("Null argument\n");
		return 0;
	}
	
	if (bdev->d_size) {
		return bdev->d_size >> 9;
	}

	// Maybe... need to recalculate volume size
	PVOLUME_EXTENSION pvext = (bdev->bd_disk) ? bdev->bd_disk->pDeviceExtension : NULL;
	if (pvext && (KeGetCurrentIrql() < 2)) {
		bdev->d_size = get_targetdev_volsize(pvext);	// real size
		return bdev->d_size >> 9;
	} 
	
	if (bdev->bd_contains) {	// not real device
		bdev = bdev->bd_contains;
		if (bdev->d_size) {
			return bdev->d_size >> 9;
		}
	}
	
	return bdev->d_size >> 9;
#else
	/* return bdev ? get_capacity(bdev->bd_disk) : 0; */
	return bdev ? i_size_read(bdev->bd_inode) >> 9 : 0;
#endif
}

/* sets the number of 512 byte sectors of our virtual device */
static inline void drbd_set_my_capacity(struct drbd_device *device,
					sector_t size)
{
#ifdef _WIN32
	if (!device->this_bdev)
	{
		return;
}

	device->this_bdev->d_size = size << 9;
#else
	/* set_capacity(device->this_bdev->bd_disk, size); */
	set_capacity(device->vdisk, size);
	device->this_bdev->bd_inode->i_size = (loff_t)size << 9;
#endif
}

static inline void drbd_kobject_uevent(struct drbd_device *device)
{
	UNREFERENCED_PARAMETER(device);

#ifdef _WIN32
	// required refactring for debugfs
#else
	kobject_uevent(disk_to_kobj(device->vdisk), KOBJ_CHANGE);
#endif
	/* rhel4 / sles9 and older don't have this at all,
	 * which means user space (udev) won't get events about possible changes of
	 * corresponding resource + disk names after the initial drbd minor creation.
	 */
}

/*
 * used to submit our private bio
 */
static inline void drbd_generic_make_request(struct drbd_device *device,
					     int fault_type, struct bio *bio)
{
	__release(local);
	if (!bio->bi_bdev) {
		drbd_err(device, "drbd_generic_make_request: bio->bi_bdev == NULL\n");
		bio_endio(bio, -ENODEV);
		return;
	}

	if (drbd_insert_fault(device, fault_type))
		bio_endio(bio, -EIO);
#ifndef _WIN32
	else
		generic_make_request(bio);
#else
	else {
		if (generic_make_request(bio)) {
			bio_endio(bio, -EIO);
		}
	}
#endif
}

void drbd_bump_write_ordering(struct drbd_resource *resource, struct drbd_backing_dev *bdev,
			      enum write_ordering_e wo);
#ifdef _WIN32
extern KDEFERRED_ROUTINE twopc_timer_fn;
extern KDEFERRED_ROUTINE connect_timer_fn;
#else
extern void twopc_timer_fn(unsigned long);
extern void connect_timer_fn(unsigned long);
#endif
#ifdef _WIN32
// not support
#else
/* drbd_proc.c */
extern struct proc_dir_entry *drbd_proc;
extern const struct file_operations drbd_proc_fops;
#endif


typedef enum { RECORD_RS_FAILED, SET_OUT_OF_SYNC, SET_IN_SYNC } update_sync_bits_mode;

/* drbd_actlog.c */
extern bool drbd_al_try_lock(struct drbd_device *device);
extern bool drbd_al_try_lock_for_transaction(struct drbd_device *device);
extern int drbd_al_begin_io_nonblock(struct drbd_device *device, struct drbd_interval *i);
extern void drbd_al_begin_io_commit(struct drbd_device *device);
extern bool drbd_al_begin_io_fastpath(struct drbd_device *device, struct drbd_interval *i);
extern int drbd_al_begin_io_for_peer(struct drbd_peer_device *peer_device, struct drbd_interval *i);
extern bool drbd_al_complete_io(struct drbd_device *device, struct drbd_interval *i);
extern void drbd_rs_complete_io(struct drbd_peer_device *, sector_t, char *);
extern int drbd_rs_begin_io(struct drbd_peer_device *, sector_t);
extern int drbd_try_rs_begin_io(struct drbd_peer_device *, sector_t, bool);
extern void drbd_rs_cancel_all(struct drbd_peer_device *);
extern int drbd_rs_del_all(struct drbd_peer_device *);
extern void drbd_rs_failed_io(struct drbd_peer_device *, sector_t, int);
#ifdef _WIN32
extern void drbd_advance_rs_marks(struct drbd_peer_device *, ULONG_PTR);
#else
extern void drbd_advance_rs_marks(struct drbd_peer_device *, unsigned long);
#endif
extern bool drbd_set_all_out_of_sync(struct drbd_device *, sector_t, int);
#ifdef _WIN32
extern unsigned long drbd_set_sync(struct drbd_device *, sector_t, int, ULONG_PTR, ULONG_PTR);
extern int update_sync_bits(struct drbd_peer_device *peer_device,
	unsigned long sbnr, unsigned long ebnr, update_sync_bits_mode mode);
#else
extern bool drbd_set_sync(struct drbd_device *, sector_t, int, unsigned long, unsigned long);
#endif
extern int __drbd_change_sync(struct drbd_peer_device *peer_device, sector_t sector, int size,
		update_sync_bits_mode mode);
#define drbd_set_in_sync(peer_device, sector, size) \
	__drbd_change_sync(peer_device, sector, size, SET_IN_SYNC)
#define drbd_set_out_of_sync(peer_device, sector, size) \
	__drbd_change_sync(peer_device, sector, size, SET_OUT_OF_SYNC)
#define drbd_rs_failed_io(peer_device, sector, size) \
	__drbd_change_sync(peer_device, sector, size, RECORD_RS_FAILED)

extern void drbd_al_shrink(struct drbd_device *device);
extern bool drbd_sector_has_priority(struct drbd_peer_device *, sector_t);
extern int drbd_al_initialize(struct drbd_device *, void *);

/* drbd_nl.c */

extern struct mutex notification_mutex;
extern atomic_t drbd_genl_seq;

extern void notify_resource_state(struct sk_buff *,
				  unsigned int,
				  struct drbd_resource *,
				  struct resource_info *,
				  enum drbd_notification_type);
extern void notify_device_state(struct sk_buff *,
				unsigned int,
				struct drbd_device *,
				struct device_info *,
				enum drbd_notification_type);
extern void notify_connection_state(struct sk_buff *,
				    unsigned int,
				    struct drbd_connection *,
				    struct connection_info *,
				    enum drbd_notification_type);
extern void notify_peer_device_state(struct sk_buff *,
				     unsigned int,
				     struct drbd_peer_device *,
				     struct peer_device_info *,
				     enum drbd_notification_type);
extern void notify_helper(enum drbd_notification_type, struct drbd_device *,
			  struct drbd_connection *, const char *, int);
extern void notify_path(struct drbd_connection *, struct drbd_path *,
			enum drbd_notification_type);

extern sector_t drbd_local_max_size(struct drbd_device *device) __must_hold(local);
extern int drbd_open_ro_count(struct drbd_resource *resource);

/*
 * inline helper functions
 *************************/

static inline int drbd_peer_req_has_active_page(struct drbd_peer_request *peer_req)
{
	UNREFERENCED_PARAMETER(peer_req);
#ifdef _WIN32
	// not support.
#else	
	struct page *page = peer_req->page_chain.head;
	page_chain_for_each(page) {
		if (page_count(page) > 1)
			return 1;
	}
#endif
	return 0;
}

/*
 * When a device has a replication state above L_OFF, it must be
 * connected.  Otherwise, we report the connection state, which has values up
 * to C_CONNECTED == L_OFF.
 */
static inline int combined_conn_state(struct drbd_peer_device *peer_device, enum which_state which)
{
	enum drbd_repl_state repl_state = peer_device->repl_state[which];

	if (repl_state > L_OFF)
		return repl_state;
	else
		return peer_device->connection->cstate[which];
}

enum drbd_force_detach_flags {
	DRBD_READ_ERROR,
	DRBD_WRITE_ERROR,
	DRBD_META_IO_ERROR,
	DRBD_FORCE_DETACH,
};

#define __drbd_chk_io_error(m,f) __drbd_chk_io_error_(m,f, __func__)
static inline void __drbd_chk_io_error_(struct drbd_device *device,
					enum drbd_force_detach_flags df,
					const char *where)
{
	enum drbd_io_error_p ep;

	rcu_read_lock();
	ep = rcu_dereference(device->ldev->disk_conf)->on_io_error;
	rcu_read_unlock();
	switch (ep) {
	case EP_PASS_ON: /* FIXME would this be better named "Ignore"? */
		if (df == DRBD_READ_ERROR ||  df == DRBD_WRITE_ERROR) {
			if (drbd_ratelimit())
				WDRBD_ERROR("Local IO failed in %s.\n", where);
			if (device->disk_state[NOW] > D_INCONSISTENT) {
				begin_state_change_locked(device->resource, CS_HARD);
				__change_disk_state(device, D_INCONSISTENT, __FUNCTION__);
#ifdef _WIN32_RCU_LOCKED
				end_state_change_locked(device->resource, false, __FUNCTION__);
#else
				end_state_change_locked(device->resource);
#endif
			}
			break;
		}
		/* NOTE fall through for DRBD_META_IO_ERROR or DRBD_FORCE_DETACH */
	case EP_DETACH:
	case EP_CALL_HELPER:
		/* Remember whether we saw a READ or WRITE error.
		 *
		 * Recovery of the affected area for WRITE failure is covered
		 * by the activity log.
		 * READ errors may fall outside that area though. Certain READ
		 * errors can be "healed" by writing good data to the affected
		 * blocks, which triggers block re-allocation in lower layers.
		 *
		 * If we can not write the bitmap after a READ error,
		 * we may need to trigger a full sync (see w_go_diskless()).
		 *
		 * Force-detach is not really an IO error, but rather a
		 * desperate measure to try to deal with a completely
		 * unresponsive lower level IO stack.
		 * Still it should be treated as a WRITE error.
		 *
		 * Meta IO error is always WRITE error:
		 * we read meta data only once during attach,
		 * which will fail in case of errors.
		 */
		if (df == DRBD_FORCE_DETACH)
			set_bit(FORCE_DETACH, &device->flags);
		if (device->disk_state[NOW] > D_FAILED) {
			begin_state_change_locked(device->resource, CS_HARD);
			__change_disk_state(device, D_FAILED, __FUNCTION__);
#ifdef _WIN32_RCU_LOCKED
			end_state_change_locked(device->resource, false, __FUNCTION__);
#else
			end_state_change_locked(device->resource);
#endif
			drbd_err(device, "Local IO failed in %s. Detaching...\n", where);
		}
		break;
	// DW-1755
	case EP_PASSTHROUGH:
		// DW-1814 
		// If an error occurs in the meta volume, disk consistency can not be guaranteed and replication must be stopped in any case. 
		if (df == DRBD_FORCE_DETACH)
			set_bit(FORCE_DETACH, &device->flags);
		if (df == DRBD_META_IO_ERROR || df == DRBD_FORCE_DETACH) {
			if (device->disk_state[NOW] > D_FAILED) {
				begin_state_change_locked(device->resource, CS_HARD);
				__change_disk_state(device, D_FAILED, __FUNCTION__);
#ifdef _WIN32_RCU_LOCKED
				end_state_change_locked(device->resource, false, __FUNCTION__);
#else
				end_state_change_locked(device->resource);
#endif
			}

			if (df == DRBD_META_IO_ERROR)
				drbd_err(device, "IO error occurred on meta-disk in %s. Detaching...\n", where);
			else
				drbd_err(device, "Force-detaching in %s\n", where);
		}
		else {
		// DW-1814 
		// In the event of a write or read error on a clone volume, there is no action here to commit it to the failure handling mechanism.
		// When a write error occurs in the duplicate volume, P_NEG_ACK is transmitted and the OOS is recorded and synchronized.
		// When a read error occurs, P_NEG_RS_DREPLY is transmitted, and synchronization can be restarted for failed bits.
			if (atomic_read(&device->io_error_count) == 1)
				drbd_err(device, "%s IO error occurred on repl-disk. Passthrough...\n", (df == DRBD_READ_ERROR) ? "Read" : "Write");
		}

		break;
	}
}

/**
 * drbd_chk_io_error: Handle the on_io_error setting, should be called from all io completion handlers
 * @device:	 DRBD device.
 * @error:	 Error code passed to the IO completion callback
 * @forcedetach: Force detach. I.e. the error happened while accessing the meta data
 *
 * See also drbd_main.c:after_state_ch() if (os.disk > D_FAILED && ns.disk == D_FAILED)
 */
#define drbd_chk_io_error(m,e,f) drbd_chk_io_error_(m,e,f, __func__)
static inline void drbd_chk_io_error_(struct drbd_device *device,
	int error, enum drbd_force_detach_flags forcedetach, const char *where)
{
	if (error) {
		unsigned long flags;
		spin_lock_irqsave(&device->resource->req_lock, flags);
		__drbd_chk_io_error_(device, forcedetach, where);
		spin_unlock_irqrestore(&device->resource->req_lock, flags);
	}
}


/**
 * drbd_md_first_sector() - Returns the first sector number of the meta data area
 * @bdev:	Meta data block device.
 *
 * BTW, for internal meta data, this happens to be the maximum capacity
 * we could agree upon with our peer node.
 */
static inline sector_t drbd_md_first_sector(struct drbd_backing_dev *bdev)
{
	switch (bdev->md.meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		return bdev->md.md_offset + bdev->md.bm_offset;
	case DRBD_MD_INDEX_FLEX_EXT:
	default:
		return bdev->md.md_offset;
	}
}

/**
 * drbd_md_last_sector() - Return the last sector number of the meta data area
 * @bdev:	Meta data block device.
 */
static inline sector_t drbd_md_last_sector(struct drbd_backing_dev *bdev)
{
	switch (bdev->md.meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		return bdev->md.md_offset + (4096 >> 9) -1;
	case DRBD_MD_INDEX_FLEX_EXT:
	default:
		return bdev->md.md_offset + bdev->md.md_size_sect -1;
	}
}

/**
 * drbd_get_max_capacity() - Returns the capacity we announce to out peer
 * @bdev:	Meta data block device.
 *
 * returns the capacity we announce to out peer.  we clip ourselves at the
 * various MAX_SECTORS, because if we don't, current implementation will
 * oops sooner or later
 */
static inline sector_t drbd_get_max_capacity(struct drbd_backing_dev *bdev)
{
	sector_t s;

	switch (bdev->md.meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
#ifdef _WIN32 // DW-1469 : get real size
		s = drbd_get_capacity(bdev->backing_bdev->bd_contains)
#else
		s = drbd_get_capacity(bdev->backing_bdev)
#endif
			? min_t(sector_t, DRBD_MAX_SECTORS_FLEX,
				drbd_md_first_sector(bdev))
			: 0;
		break;
	case DRBD_MD_INDEX_FLEX_EXT:		
#ifdef _WIN32 // DW-1469
		s = min_t(sector_t, DRBD_MAX_SECTORS_FLEX,
				drbd_get_capacity(bdev->backing_bdev->bd_contains));
#else
		s = min_t(sector_t, DRBD_MAX_SECTORS_FLEX,
				//drbd_get_capacity(bdev->backing_bdev));
#endif
		/* clip at maximum size the meta device can support */
		s = min_t(sector_t, s,
			BM_EXT_TO_SECT(bdev->md.md_size_sect
				     - bdev->md.bm_offset));
		break;
	default:		
#ifdef _WIN32 // DW-1469
		s = min_t(sector_t, DRBD_MAX_SECTORS,
				drbd_get_capacity(bdev->backing_bdev->bd_contains));
#else
		s = min_t(sector_t, DRBD_MAX_SECTORS,
				drbd_get_capacity(bdev->backing_bdev));
#endif
	}
	return s;
}

/**
 * drbd_md_ss() - Return the sector number of our meta data super block
 * @bdev:	Meta data block device.
 */
static inline sector_t drbd_md_ss(struct drbd_backing_dev *bdev)
{
	const int meta_dev_idx = bdev->md.meta_dev_idx;

	if (meta_dev_idx == DRBD_MD_INDEX_FLEX_EXT)
		return 0;

	/* Since drbd08, internal meta data is always "flexible".
	 * position: last 4k aligned block of 4k size */
	if (meta_dev_idx == DRBD_MD_INDEX_INTERNAL ||
	    meta_dev_idx == DRBD_MD_INDEX_FLEX_INT)
		return (drbd_get_capacity(bdev->backing_bdev) & ~7ULL) - 8;

	/* external, some index; this is the old fixed size layout */
#ifdef _WIN32 // DW-1335
	return (256 << 20 >> 9) * bdev->md.meta_dev_idx;
#else
	return (128 << 20 >> 9) * bdev->md.meta_dev_idx;
#endif
}

void drbd_queue_work(struct drbd_work_queue *, struct drbd_work *);

static inline void
drbd_queue_work_if_unqueued(struct drbd_work_queue *q, struct drbd_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&q->q_lock, flags);
	if (list_empty_careful(&w->list))
		list_add_tail(&w->list, &q->q);
	spin_unlock_irqrestore(&q->q_lock, flags);
	wake_up(&q->q_wait);
}

static inline void
drbd_device_post_work(struct drbd_device *device, int work_bit)
{
	if (!test_and_set_bit(work_bit, &device->flags)) {
		struct drbd_resource *resource = device->resource;
		struct drbd_work_queue *q = &resource->work;
		if (!test_and_set_bit(DEVICE_WORK_PENDING, &resource->flags))
			wake_up(&q->q_wait);
	}
}

static inline void
drbd_peer_device_post_work(struct drbd_peer_device *peer_device, int work_bit)
{
	if (!test_and_set_bit(work_bit, &peer_device->flags)) {
		struct drbd_resource *resource = peer_device->device->resource;
		struct drbd_work_queue *q = &resource->work;
		if (!test_and_set_bit(PEER_DEVICE_WORK_PENDING, &resource->flags))
			wake_up(&q->q_wait);
	}
}

static inline void
drbd_post_work(struct drbd_resource *resource, int work_bit)
{
	if (!test_and_set_bit(work_bit, &resource->flags)) {
		struct drbd_work_queue *q = &resource->work;
		if (!test_and_set_bit(RESOURCE_WORK_PENDING, &resource->flags))
			wake_up(&q->q_wait);
	}
}


/* DW-1755 passthrough policy
 * Synchronization objects used in the process of forwarding events to events2 
 * only work when irql is less than APC_LEVEL. 
 * However, because the completion routine can operate in DISPATCH_LEVEL, 
 * it must be handled through the work thread.*/

#define drbd_queue_notify_io_error_cleared(device) \
	drbd_queue_notify_io_error(device, 0, 0, 0, 0, 0, true)

#define drbd_queue_notify_io_error_occurred(device, disk_type, io_type, error_code, sector, size) \
	drbd_queue_notify_io_error(device, disk_type, io_type, error_code, sector, size, false)

static inline void
drbd_queue_notify_io_error(struct drbd_device *device, unsigned char disk_type, unsigned char io_type, NTSTATUS error_code, sector_t sector, unsigned int size, bool is_cleared)
{
	struct drbd_io_error_work *w;
#ifdef _WIN32 
	w = kmalloc(sizeof(*w), GFP_ATOMIC, 'W1DW');
#else
	w = kmalloc(sizeof(*w), GFP_ATOMIC);
#endif
	if (w) {
#ifdef _WIN32
		w->io_error = kmalloc(sizeof(*(w->io_error)), GFP_ATOMIC, 'W2DW');
#else
		w = kmalloc(sizeof(*w), GFP_ATOMIC);
#endif
		if (w->io_error) {
			w->device = device;
			w->w.cb = w_notify_io_error;
			w->io_error->error_code = error_code;
			w->io_error->sector = sector;
			w->io_error->size = size;
			w->io_error->io_type = io_type;
			w->io_error->disk_type = disk_type;
			w->io_error->is_cleared = is_cleared;
			drbd_queue_work(&device->resource->work, &w->w);
		}
		else {
			drbd_err(device, "kmalloc failed.\n");
		}
	}
}



#ifdef _WIN32
extern void drbd_flush_workqueue(struct drbd_resource* resource, struct drbd_work_queue *work_queue);
extern void drbd_flush_workqueue_timeout(struct drbd_resource* resource, struct drbd_work_queue *work_queue);
#else
extern void drbd_flush_workqueue(struct drbd_work_queue *work_queue);
#endif

/* To get the ack_receiver out of the blocking network stack,
 * so it can change its sk_rcvtimeo from idle- to ping-timeout,
 * and send a ping, we need to send a signal.
 * Which signal we send is irrelevant. */
static inline void wake_ack_receiver(struct drbd_connection *connection)
{
	struct task_struct *task = connection->ack_receiver.task;
	if (task && get_t_state(&connection->ack_receiver) == RUNNING)
		force_sig(SIGXCPU, task);
}

static inline void request_ping(struct drbd_connection *connection)
{
	set_bit(SEND_PING, &connection->flags);
	wake_ack_receiver(connection);
}

extern void *__conn_prepare_command(struct drbd_connection *, int, enum drbd_stream);
extern void *conn_prepare_command(struct drbd_connection *, int, enum drbd_stream);
extern void *drbd_prepare_command(struct drbd_peer_device *, int, enum drbd_stream);
extern int __send_command(struct drbd_connection *, int, enum drbd_packet, enum drbd_stream);
extern int send_command(struct drbd_connection *, int, enum drbd_packet, enum drbd_stream);
extern int drbd_send_command(struct drbd_peer_device *, enum drbd_packet, enum drbd_stream);

extern int drbd_send_ping(struct drbd_connection *connection);
extern int drbd_send_ping_ack(struct drbd_connection *connection);
extern int conn_send_state_req(struct drbd_connection *, int vnr, enum drbd_packet, union drbd_state, union drbd_state);
extern int conn_send_twopc_request(struct drbd_connection *, int vnr, enum drbd_packet, struct p_twopc_request *);
extern int drbd_send_peer_ack(struct drbd_connection *, struct drbd_request *);

static inline void drbd_thread_stop(struct drbd_thread *thi)
{
	_drbd_thread_stop(thi, false, true);
}

static inline void drbd_thread_stop_nowait(struct drbd_thread *thi)
{
	_drbd_thread_stop(thi, false, false);
}

static inline void drbd_thread_restart_nowait(struct drbd_thread *thi)
{
	_drbd_thread_stop(thi, true, false);
}

/* counts how many answer packets packets we expect from our peer,
 * for either explicit application requests,
 * or implicit barrier packets as necessary.
 * increased:
 *  w_send_barrier
 *  _req_mod(req, QUEUE_FOR_NET_WRITE or QUEUE_FOR_NET_READ);
 *    it is much easier and equally valid to count what we queue for the
 *    sender, even before it actually was queued or sent.
 *    (drbd_make_request_common; recovery path on read io-error)
 * decreased:
 *  got_BarrierAck (respective tl_clear, tl_clear_barrier)
 *  _req_mod(req, DATA_RECEIVED)
 *     [from receive_DataReply]
 *  _req_mod(req, WRITE_ACKED_BY_PEER or RECV_ACKED_BY_PEER or NEG_ACKED)
 *     [from got_BlockAck (P_WRITE_ACK, P_RECV_ACK)]
 *     FIXME
 *     for some reason it is NOT decreased in got_NegAck,
 *     but in the resulting cleanup code from report_params.
 *     we should try to remember the reason for that...
 *  _req_mod(req, SEND_FAILED or SEND_CANCELED)
 *  _req_mod(req, CONNECTION_LOST_WHILE_PENDING)
 *     [from tl_clear_barrier]
 */
static inline void inc_ap_pending(struct drbd_peer_device *peer_device)
{
	atomic_inc(&peer_device->ap_pending_cnt);
}

#define dec_ap_pending(peer_device) \
	((void)expect((peer_device), __dec_ap_pending(peer_device) >= 0))
static inline int __dec_ap_pending(struct drbd_peer_device *peer_device)
{
	int ap_pending_cnt = atomic_dec_return(&peer_device->ap_pending_cnt);
	if (ap_pending_cnt == 0)
		wake_up(&peer_device->device->misc_wait);
	return ap_pending_cnt;
}

/* counts how many resync-related answers we still expect from the peer
 *		     increase			decrease
 * L_SYNC_TARGET sends P_RS_DATA_REQUEST (and expects P_RS_DATA_REPLY)
 * L_SYNC_SOURCE sends P_RS_DATA_REPLY   (and expects P_WRITE_ACK with ID_SYNCER)
 *					   (or P_NEG_ACK with ID_SYNCER)
 */
static inline void inc_rs_pending(struct drbd_peer_device *peer_device)
{
	atomic_inc(&peer_device->rs_pending_cnt);
}

#define dec_rs_pending(peer_device) \
	((void)expect((peer_device), __dec_rs_pending(peer_device) >= 0))
static inline int __dec_rs_pending(struct drbd_peer_device *peer_device)
{
	return atomic_dec_return(&peer_device->rs_pending_cnt);
}

/* counts how many answers we still need to send to the peer.
 * increased on
 *  receive_Data	unless protocol A;
 *			we need to send a P_RECV_ACK (proto B)
 *			or P_WRITE_ACK (proto C)
 *  receive_RSDataReply (recv_resync_read) we need to send a P_WRITE_ACK
 *  receive_DataRequest (receive_RSDataRequest) we need to send back P_DATA
 *  receive_Barrier_*	we need to send a P_BARRIER_ACK
 */
static inline void inc_unacked(struct drbd_peer_device *peer_device)
{
	atomic_inc(&peer_device->unacked_cnt);
}

#define dec_unacked(peer_device) \
	((void)expect(peer_device, __dec_unacked(peer_device) >= 0))
static inline int __dec_unacked(struct drbd_peer_device *peer_device)
{
	return atomic_dec_return(&peer_device->unacked_cnt);
}

#define sub_unacked(peer_device, n) \
	((void)expect(peer_device, __sub_unacked(peer_device) >= 0))
static inline int __sub_unacked(struct drbd_peer_device *peer_device, int n)
{
	return atomic_sub_return(n, &peer_device->unacked_cnt);
}

static inline bool is_sync_target_state(struct drbd_peer_device *peer_device,
					enum which_state which)
{
	enum drbd_repl_state repl_state = peer_device->repl_state[which];

	return repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T;
}

static inline bool is_sync_target(struct drbd_peer_device *peer_device)
{
	return is_sync_target_state(peer_device, NOW) ||
				peer_device->repl_state[NOW] == L_WF_BITMAP_T;
}

static inline bool is_sync_source_state(struct drbd_peer_device *peer_device,
					enum which_state which)
{
	enum drbd_repl_state repl_state = peer_device->repl_state[which];

	return repl_state == L_SYNC_SOURCE || repl_state == L_PAUSED_SYNC_S;
}

static inline bool is_sync_state(struct drbd_peer_device *peer_device,
				 enum which_state which)
{
	return is_sync_source_state(peer_device, which) ||
		is_sync_target_state(peer_device, which);
}

static inline bool is_sync_source(struct drbd_peer_device *peer_device)
{
	return is_sync_source_state(peer_device, NOW) ||
		peer_device->repl_state[NOW] == L_WF_BITMAP_S;
}
/**
 * get_ldev() - Increase the ref count on device->ldev. Returns 0 if there is no ldev
 * @_device:		DRBD device.
 * @_min_state:		Minimum device state required for success.
 *
 * You have to call put_ldev() when finished working with device->ldev.
 */
#ifdef _WIN32
#define get_ldev_if_state(_device, _min_state)				\
	(_get_ldev_if_state((_device), (_min_state)) ?			\
	true : false)
#else
#define get_ldev_if_state(_device, _min_state)				\
	(_get_ldev_if_state((_device), (_min_state)) ?			\
	 ({ __acquire(x); true; }) : false)
#endif
#define get_ldev(_device) get_ldev_if_state(_device, D_INCONSISTENT)

static inline void put_ldev(struct drbd_device *device)
{
	enum drbd_disk_state disk_state = device->disk_state[NOW];
	/* We must check the state *before* the atomic_dec becomes visible,
	 * or we have a theoretical race where someone hitting zero,
	 * while state still D_FAILED, will then see D_DISKLESS in the
	 * condition below and calling into destroy, where he must not, yet. */
	int i = atomic_dec_return(&device->local_cnt);

	/* This may be called from some endio handler,
	 * so we must not sleep here. */

	__release(local);
	D_ASSERT(device, i >= 0);
	if (i == 0) {
		if (disk_state == D_DISKLESS)
			/* even internal references gone, safe to destroy */
			drbd_device_post_work(device, DESTROY_DISK);
		if (disk_state == D_FAILED || disk_state == D_DETACHING)
			/* all application IO references gone. */
			if (!test_and_set_bit(GOING_DISKLESS, &device->flags))
				drbd_device_post_work(device, GO_DISKLESS);
		wake_up(&device->misc_wait);
	}
}

#ifndef __CHECKER__
static inline int _get_ldev_if_state(struct drbd_device *device, enum drbd_disk_state mins)
{
	int io_allowed;

	/* never get a reference while D_DISKLESS */
	if (device->disk_state[NOW] == D_DISKLESS)
		return 0;

	atomic_inc(&device->local_cnt);
	io_allowed = (device->disk_state[NOW] >= mins);
	if (!io_allowed)
		put_ldev(device);
	return io_allowed;
}
#else
extern int _get_ldev_if_state(struct drbd_device *device, enum drbd_disk_state mins);
#endif

static inline bool drbd_state_is_stable(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	bool stable = true;

	/* DO NOT add a default clause, we want the compiler to warn us
	 * for any newly introduced state we may have forgotten to add here */

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		switch (peer_device->repl_state[NOW]) {
		/* New io is only accepted when the peer device is unknown or there is
		 * a well-established connection. */
		case L_OFF:
		case L_ESTABLISHED:
		case L_SYNC_SOURCE:
		case L_SYNC_TARGET:
		case L_VERIFY_S:
		case L_VERIFY_T:
		case L_PAUSED_SYNC_S:
		case L_PAUSED_SYNC_T:
		case L_AHEAD:
		case L_BEHIND:
		case L_STARTING_SYNC_S:
		case L_STARTING_SYNC_T:
			break;

			/* Allow IO in BM exchange states with new protocols */
		case L_WF_BITMAP_S:
#ifndef _WIN32
			// MODIFIED_BY_MANTECH DW-1121: sending out-of-sync when repl state is WFBitmapS possibly causes stopping resync, by setting new out-of-sync sector which bm_resync_fo has been already swept.
			if (peer_device->connection->agreed_pro_version < 96)
#else
			// DW-1391 : Allow IO while getting the volume bitmap.
			if (atomic_read(&device->resource->bGetVolBitmapDone))
#endif
				stable = false;
			break;

			/* no new io accepted in these states */
		case L_WF_BITMAP_T:
		case L_WF_SYNC_UUID:
			stable = false;
			break;
		}
		if (!stable)
			break;
	}
	rcu_read_unlock();

	switch (device->disk_state[NOW]) {
	case D_DISKLESS:
	case D_INCONSISTENT:
	case D_OUTDATED:
	case D_CONSISTENT:
	case D_UP_TO_DATE:
	case D_FAILED:
	case D_DETACHING:
		/* disk state is stable as well. */
		break;

	/* no new io accepted during transitional states */
	case D_ATTACHING:
	case D_NEGOTIATING:
	case D_UNKNOWN:
	case D_MASK:
		stable = false;
	}

	return stable;
}

extern void drbd_queue_pending_bitmap_work(struct drbd_device *);

/* rw = READ or WRITE (0 or 1); nothing else. */
static inline void dec_ap_bio(struct drbd_device *device, int rw)
{
	unsigned int nr_requests = device->resource->res_opts.nr_requests;
	int ap_bio = atomic_dec_return(&device->ap_bio_cnt[rw]);

	D_ASSERT(device, ap_bio >= 0);

	/* Check for list_empty outside the lock is ok.  Worst case it queues
	 * nothing because someone else just now did.  During list_add, both
	 * resource->req_lock *and* a refcount on ap_bio_cnt[WRITE] are held,
	 * a list_add cannot race with this code path.
	 * Checking pending_bitmap_work.n is not correct,
	 * it has a different lifetime. */
	if (ap_bio == 0 && rw == WRITE && !list_empty(&device->pending_bitmap_work.q))
		drbd_queue_pending_bitmap_work(device);

	if (ap_bio == 0 || ap_bio == (int)nr_requests-1)
		wake_up(&device->misc_wait);
}


static inline bool drbd_suspended(struct drbd_device *device)
{
	return resource_is_suspended(device->resource, NOW);
}

static inline bool may_inc_ap_bio(struct drbd_device *device)
{
	if (drbd_suspended(device))
		return false;
	if (atomic_read(&device->suspend_cnt))
		return false;

	/* to avoid potential deadlock or bitmap corruption,
	 * in various places, we only allow new application io
	 * to start during "stable" states. */

	/* no new io accepted when attaching or detaching the disk */
	if (!drbd_state_is_stable(device))
		return false;

	if (atomic_read(&device->pending_bitmap_work.n))
		return false;
	return true;
}

static inline bool inc_ap_bio_cond(struct drbd_device *device, int rw)
{
	bool rv = false;
	unsigned int nr_requests;
#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1200: request buffer maximum size.
	LONGLONG req_buf_size_max;
#endif

	spin_lock_irq(&device->resource->req_lock);
	nr_requests = device->resource->res_opts.nr_requests;
	rv = may_inc_ap_bio(device) && (unsigned int)atomic_read(&device->ap_bio_cnt[rw]) < nr_requests;

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1200: postpone I/O if current request buffer size is too big.
	req_buf_size_max = ((LONGLONG)device->resource->res_opts.req_buf_size << 10);    // convert to byte
	if (req_buf_size_max < ((LONGLONG)DRBD_REQ_BUF_SIZE_MIN << 10) ||
		req_buf_size_max >((LONGLONG)DRBD_REQ_BUF_SIZE_MAX << 10))
	{
		drbd_err(device, "got invalid req_buf_size(%llu), use default value(%llu)\n", req_buf_size_max, ((LONGLONG)DRBD_REQ_BUF_SIZE_DEF << 10));
		req_buf_size_max = ((LONGLONG)DRBD_REQ_BUF_SIZE_DEF << 10);    // use default if value is invalid.    
	}
	if (atomic_read64(&g_total_req_buf_bytes) > req_buf_size_max) {
		device->resource->breqbuf_overflow_alarm = TRUE;
	
		if (drbd_ratelimit())
			drbd_warn(device, "request buffer is full, postponing I/O until we get enough memory. cur req_buf_size(%llu), max(%llu)\n", atomic_read64(&g_total_req_buf_bytes), req_buf_size_max);
		rv = false;
	} else {
		device->resource->breqbuf_overflow_alarm = FALSE;
	}
#endif

	if (rv)
		atomic_inc(&device->ap_bio_cnt[rw]);
	spin_unlock_irq(&device->resource->req_lock);

	return rv;
}

static inline void inc_ap_bio(struct drbd_device *device, int rw)
{
	/* we wait here
	 *    as long as the device is suspended
	 *    until the bitmap is no longer on the fly during connection
	 *    handshake as long as we would exceed the max_buffer limit.
	 *
	 * to avoid races with the reconnect code,
	 * we need to atomic_inc within the spinlock. */

	wait_event(device->misc_wait, inc_ap_bio_cond(device, rw));
}

static inline int drbd_set_exposed_data_uuid(struct drbd_device *device, u64 val)
{
	int changed = device->exposed_data_uuid != val;
	device->exposed_data_uuid = val;
	return changed;
}

static inline u64 drbd_current_uuid(struct drbd_device *device)
{
	if (!device->ldev)
		return 0;
	return device->ldev->md.current_uuid;
}

static inline bool verify_can_do_stop_sector(struct drbd_peer_device *peer_device)
{
	return peer_device->connection->agreed_pro_version >= 97 &&
		peer_device->connection->agreed_pro_version != 100;
}

static inline u64 drbd_bitmap_uuid(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_md *peer_md;

	if (!device->ldev)
		return 0;

	peer_md = &device->ldev->md.peers[peer_device->node_id];
	return peer_md->bitmap_uuid;
}

static inline u64 drbd_history_uuid(struct drbd_device *device, int i)
{
	if (!device->ldev || i >= ARRAY_SIZE(device->ldev->md.history_uuids))
		return 0;

	return device->ldev->md.history_uuids[i];
}

static inline int drbd_queue_order_type(struct drbd_device *device)
{
	UNREFERENCED_PARAMETER(device);

	/* sorry, we currently have no working implementation
	 * of distributed TCQ stuff */
#ifndef QUEUE_ORDERED_NONE
#define QUEUE_ORDERED_NONE 0
#endif
	return QUEUE_ORDERED_NONE;
}

#ifdef _WIN32
extern struct genl_ops * get_drbd_genl_ops(u8 cmd);
#endif

#ifdef blk_queue_plugged
static inline void drbd_blk_run_queue(struct request_queue *q)
{
	if (q && q->unplug_fn)
		q->unplug_fn(q);
}

static inline void drbd_kick_lo(struct drbd_device *device)
{
	if (get_ldev(device)) {
		drbd_blk_run_queue(bdev_get_queue(device->ldev->backing_bdev));
		put_ldev(device);
	}
}
#else
static inline void drbd_blk_run_queue(struct request_queue *q)
{
	UNREFERENCED_PARAMETER(q);
}
static inline void drbd_kick_lo(struct drbd_device *device)
{
	UNREFERENCED_PARAMETER(device);
}
#endif

/* resync bitmap */
/* 128MB sized 'bitmap extent' to track syncer usage */
struct bm_extent {
	int rs_left; /* number of bits set (out of sync) in this extent. */
	int rs_failed; /* number of failed resync requests in this extent. */
#ifdef _WIN32
	ULONG_PTR flags;
#else
	unsigned long flags;
#endif
	struct lc_element lce;
};

#define BME_NO_WRITES  0  /* bm_extent.flags: no more requests on this one! */
#define BME_LOCKED     1  /* bm_extent.flags: syncer active on this one. */
#define BME_PRIORITY   2  /* finish resync IO on this extent ASAP! App IO waiting! */

/* should be moved to idr.h */
/**
 * idr_for_each_entry - iterate over an idr's elements of a given type
 * @idp:     idr handle
 * @entry:   the type * to use as cursor
 * @id:      id entry's key
 */
#ifndef idr_for_each_entry
#ifdef _WIN32
#define idr_for_each_entry(type, idp, entry, id)				\
	for (id = 0, entry = (type)idr_get_next((idp), &(id)); \
	     entry != NULL;						\
	     ++id, entry = (type)idr_get_next((idp), &(id))) 
#else
#define idr_for_each_entry(idp, entry, id)				\
	for (id = 0, entry = (typeof(entry))idr_get_next((idp), &(id)); \
	     entry != NULL;						\
	     ++id, entry = (typeof(entry))idr_get_next((idp), &(id)))
#endif
#endif

#ifndef idr_for_each_entry_continue
#ifdef _WIN32
#define idr_for_each_entry_continue(type, idp, entry, id)			\
	for (entry = (type)idr_get_next((idp), &(id));		\
	     entry;							\
	     ++id, entry = (type)idr_get_next((idp), &(id)))
#else
#define idr_for_each_entry_continue(idp, entry, id)			\
	for (entry = (typeof(entry))idr_get_next((idp), &(id));		\
	     entry;							\
	     ++id, entry = (typeof(entry))idr_get_next((idp), &(id)))
#endif
#endif

static inline struct drbd_connection *first_connection(struct drbd_resource *resource)
{
	return list_first_entry_or_null(&resource->connections,
				struct drbd_connection, connections);
}

#define NODE_MASK(id) ((u64)1 << (id))

#endif
