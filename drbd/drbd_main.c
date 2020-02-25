﻿/*
   drbd_main.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

   Thanks to Carter Burden, Bart Grantham and Gennadiy Nerubayev
   from Logicworks, Inc. for making SDP replication support possible.

   drbd is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   drbd is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt
#ifdef _WIN32
/* DW-1587 
 * Turns off the C6319 warning caused by code analysis.
 * The use of comma does not cause any performance problems or bugs, 
 * but keep the code as it is written.
 */
#pragma warning (disable: 6053 6319 28719)
#include <ntifs.h>
#include "windows/drbd.h"
#include "linux-compat/drbd_endian.h"
#include <linux-compat/Kernel.h>
#else
#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/drbd.h>
#include <linux/uaccess.h>
#include <asm/types.h>
#include <net/sock.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/reboot.h>
#include <linux/notifier.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/dynamic_debug.h>
#endif
#include <linux/drbd_limits.h>
#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h" /* only for _req_mod in tl_release and tl_clear */
#include "drbd_vli.h"
#ifdef _WIN32_SEND_BUFFING
#include "send_buf.h"		
#endif
#include "drbd_debugfs.h"
#include "drbd_meta_data.h"
#ifndef _WIN32 
#ifdef COMPAT_HAVE_LINUX_BYTEORDER_SWABB_H
#include <linux/byteorder/swabb.h>
#else
#include <linux/swab.h>
#endif
#endif
#ifdef _WIN32_MULTIVOL_THREAD
#include "Proto.h"
#endif


#ifdef COMPAT_DRBD_RELEASE_RETURNS_VOID
#define DRBD_RELEASE_RETURN void
#else
#define DRBD_RELEASE_RETURN int
#endif

static int drbd_open(struct block_device *bdev, fmode_t mode);
static DRBD_RELEASE_RETURN drbd_release(struct gendisk *gd, fmode_t mode);
#ifdef _WIN32
static KDEFERRED_ROUTINE md_sync_timer_fn;
static KDEFERRED_ROUTINE peer_ack_timer_fn;
KSTART_ROUTINE drbd_thread_setup;
extern void nl_policy_init_by_manual(void);
#else
static void md_sync_timer_fn(unsigned long data);
#endif
static int w_bitmap_io(struct drbd_work *w, int unused);
static int flush_send_buffer(struct drbd_connection *connection, enum drbd_stream drbd_stream);
#ifndef _WIN32
MODULE_AUTHOR("Philipp Reisner <phil@linbit.com>, "
	      "Lars Ellenberg <lars@linbit.com>");
MODULE_DESCRIPTION("drbd - Distributed Replicated Block Device v" REL_VERSION);
MODULE_VERSION(REL_VERSION);
MODULE_LICENSE("GPL");
MODULE_PARM_DESC(minor_count, "Approximate number of drbd devices ("
		 __stringify(DRBD_MINOR_COUNT_MIN) "-" __stringify(DRBD_MINOR_COUNT_MAX) ")");
MODULE_ALIAS_BLOCKDEV_MAJOR(DRBD_MAJOR);

#include <linux/moduleparam.h>
/* allow_open_on_secondary */
MODULE_PARM_DESC(allow_oos, "DONT USE!");
/* thanks to these macros, if compiled into the kernel (not-module),
 * this becomes the boot parameter drbd.minor_count */
module_param(minor_count, uint, 0444);
module_param(disable_sendpage, bool, 0644);
module_param(allow_oos, bool, 0);
#endif
#ifdef CONFIG_DRBD_FAULT_INJECTION
#ifdef _WIN32

//Example: Simulate data write errors on / dev / drbd0 with a probability of 5 % .
//		echo 16 > /sys/module/drbd/parameters/enable_faults
//		echo 1 > /sys/module/drbd/parameters/fault_devs
//		echo 5 > /sys/module/drbd/parameters/fault_rate

int enable_faults = 0;  // 0xFFFF;
int fault_rate = 0;     // test on lower than 5%
int fault_devs = 0;     // minor number for test target
static int fault_count = 0;
#else
int enable_faults;
int fault_rate;
static int fault_count;
int fault_devs;
#endif
int two_phase_commit_fail;
extern spinlock_t g_inactive_lock;

#ifndef _WIN32
/* bitmap of enabled faults */
module_param(enable_faults, int, 0664);
/* fault rate % value - applies to all enabled faults */
module_param(fault_rate, int, 0664);
/* count of faults inserted */
module_param(fault_count, int, 0664);
/* bitmap of devices to insert faults on */
module_param(fault_devs, int, 0644);
module_param(two_phase_commit_fail, int, 0644);
#endif
#endif

/* module parameter, defined */
unsigned int minor_count = DRBD_MINOR_COUNT_DEF;
#ifdef _WIN32 
// if not initialized, it means error.
bool disable_sendpage = 1;      // not support page I/O
bool allow_oos = 0;
#else
bool disable_sendpage;
bool allow_oos;
#endif

/* Module parameter for setting the user mode helper program
 * to run. Default is /sbin/drbdadm */
#ifdef _WIN32
char usermode_helper[80] = "drbdadm.exe";
#else
char usermode_helper[80] = "/sbin/drbdadm";
#endif
#ifndef _WIN32
module_param_string(usermode_helper, usermode_helper, sizeof(usermode_helper), 0644);
#endif
/* in 2.6.x, our device mapping and config info contains our virtual gendisks
 * as member "struct gendisk *vdisk;"
 */
struct idr drbd_devices;
struct list_head drbd_resources;

#ifdef _WIN32
NPAGED_LOOKASIDE_LIST drbd_request_mempool;
NPAGED_LOOKASIDE_LIST drbd_ee_mempool;		/* peer requests */
NPAGED_LOOKASIDE_LIST drbd_al_ext_cache;	/* bitmap extents */
NPAGED_LOOKASIDE_LIST drbd_bm_ext_cache;	/* activity log extents */
#else
struct kmem_cache *drbd_request_cache;
struct kmem_cache *drbd_ee_cache;	/* peer requests */
struct kmem_cache *drbd_bm_ext_cache;	/* bitmap extents */
struct kmem_cache *drbd_al_ext_cache;	/* activity log extents */
mempool_t *drbd_request_mempool;
mempool_t *drbd_ee_mempool;
#endif
mempool_t *drbd_md_io_page_pool;
struct bio_set *drbd_md_io_bio_set;

/* I do not use a standard mempool, because:
   1) I want to hand out the pre-allocated objects first.
   2) I want to be able to interrupt sleeping allocation with a signal.
   Note: This is a single linked list, the next pointer is the private
	 member of struct page.
 */
#ifndef _WIN32
struct page *drbd_pp_pool;
#endif
spinlock_t   drbd_pp_lock;
int          drbd_pp_vacant;
wait_queue_head_t drbd_pp_wait;

#ifdef _WIN32

struct ratelimit_state drbd_ratelimit_state;	// need to initialize before use.

static inline void ratelimit_state_init(struct ratelimit_state *state, int interval_init, int burst_init)
{
	if (NULL != state)
	{
		state->interval = interval_init;
		state->burst = burst_init;
		spin_lock_init(&state->lock);
	}
}

#else
DEFINE_RATELIMIT_STATE(drbd_ratelimit_state, DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);
#endif

#ifdef _WIN32
// MODIFIED_BY_MANTECH DW-1130: check if peer's replication state is ok to forget it's bitmap.
static inline bool isForgettableReplState(enum drbd_repl_state repl_state)
{
	if (repl_state < L_ESTABLISHED ||
		repl_state == L_SYNC_SOURCE ||
		repl_state == L_AHEAD ||
		repl_state == L_WF_BITMAP_S ||
		// DW-1369 do not clear bitmap when STARTING_SYNC_X state.
		repl_state == L_STARTING_SYNC_S ||
		repl_state == L_STARTING_SYNC_T
		)
		return false;

	return true;
}
#endif

#ifdef _WIN32
EX_SPIN_LOCK g_rcuLock; //rcu lock is ported with spinlock
struct mutex g_genl_mutex;
// DW-1495: change att_mod_mutex(DW-1293) to global mutex because it can be a problem if IO also occurs on othere resouces on the same disk. 
struct mutex att_mod_mutex; 
// DW-1998
u8 g_genl_run_cmd;
struct mutex g_genl_run_cmd_mutex;
#endif
static const struct block_device_operations drbd_ops = {
#ifndef _WIN32
	.owner =   THIS_MODULE,
#endif
	.open =    drbd_open,
	.release = drbd_release,
};

#ifdef COMPAT_HAVE_BIO_FREE
static void bio_destructor_drbd(struct bio *bio)
{
	bio_free(bio, drbd_md_io_bio_set);
}
#endif

#ifdef _WIN32
struct bio *bio_alloc_drbd(gfp_t gfp_mask, ULONG Tag)
#else
struct bio *bio_alloc_drbd(gfp_t gfp_mask)
#endif
{
#ifdef _WIN32
	return bio_alloc(gfp_mask, 1, Tag);
#else
	struct bio *bio;

	if (!drbd_md_io_bio_set)
		return bio_alloc(gfp_mask, 1);

	bio = bio_alloc_bioset(gfp_mask, 1, drbd_md_io_bio_set);
	if (!bio)
		return NULL;
#ifdef COMPAT_HAVE_BIO_FREE
	bio->bi_destructor = bio_destructor_drbd;
#endif
	return bio;
#endif
}

#ifdef __CHECKER__
/* When checking with sparse, and this is an inline function, sparse will
   give tons of false positives. When this is a real functions sparse works.
 */
int _get_ldev_if_state(struct drbd_device *device, enum drbd_disk_state mins)
{
	int io_allowed;

	atomic_inc(&device->local_cnt);
	io_allowed = (device->disk_state[NOW] >= mins);
	if (!io_allowed) {
		if (atomic_dec_and_test(&device->local_cnt))
			wake_up(&device->misc_wait);
	}
	return io_allowed;
}

#endif

struct drbd_connection *__drbd_next_connection_ref(u64 *visited,
						   struct drbd_connection *connection,
						   struct drbd_resource *resource)
{
	int node_id;

	rcu_read_lock();
	if (!connection) {
#ifdef _WIN32
        list_first_or_null_rcu(connection, &resource->connections, struct drbd_connection, connections);
#else
		connection = list_first_or_null_rcu(&resource->connections,
						    struct drbd_connection,
						    connections);
#endif
		*visited = 0;
	} else {
		struct list_head *pos;
		bool previous_visible; /* on the resources connections list */

		pos = list_next_rcu(&connection->connections);
		/* follow the pointer first, then check if the previous element was
		   still an element on the list of visible connections. */
		smp_rmb();
		previous_visible = !test_bit(C_UNREGISTERED, &connection->flags);

		kref_debug_put(&connection->kref_debug, 13);
		kref_put(&connection->kref, drbd_destroy_connection);

		if (pos == &resource->connections) {
			connection = NULL;
		} else if (previous_visible) {	/* visible -> we are now on a vital element */
			connection = list_entry_rcu(pos, struct drbd_connection, connections);
		} else { /* not visible -> pos might point to a dead element now */
			for_each_connection_rcu(connection, resource) {
				node_id = connection->peer_node_id;
				if (!(*visited & NODE_MASK(node_id)))
					goto found;
			}
			connection = NULL;
		}
	}

	if (connection) {
	found:
		node_id = connection->peer_node_id;
		*visited |= NODE_MASK(node_id);

		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 13);
	}

	rcu_read_unlock();
	return connection;
}


struct drbd_peer_device *__drbd_next_peer_device_ref(u64 *visited,
						     struct drbd_peer_device *peer_device,
						     struct drbd_device *device)
{
	rcu_read_lock();
	if (!peer_device) {
#ifdef _WIN32
        list_first_or_null_rcu(peer_device, &device->peer_devices, struct drbd_peer_device, peer_devices);
#else
		peer_device = list_first_or_null_rcu(&device->peer_devices,
						    struct drbd_peer_device,
						    peer_devices);
#endif
		*visited = 0;
	} else {
		struct list_head *pos;
		bool previous_visible;

		pos = list_next_rcu(&peer_device->peer_devices);
		smp_rmb();
		previous_visible = !test_bit(C_UNREGISTERED, &peer_device->connection->flags);

		kref_debug_put(&peer_device->connection->kref_debug, 15);
		kref_put(&peer_device->connection->kref, drbd_destroy_connection);

		if (pos == &device->peer_devices) {
			peer_device = NULL;
		} else if (previous_visible) {
			peer_device = list_entry_rcu(pos, struct drbd_peer_device, peer_devices);
		} else {
			for_each_peer_device_rcu(peer_device, device) {
				if (!(*visited & NODE_MASK(peer_device->node_id)))
					goto found;
			}
			peer_device = NULL;
		}
	}

	if (peer_device) {
	found:
		*visited |= NODE_MASK(peer_device->node_id);

		kref_get(&peer_device->connection->kref);
		kref_debug_get(&peer_device->connection->kref_debug, 15);
	}

	rcu_read_unlock();
	return peer_device;
}

/* This is a list walk that holds a reference on the next element! The
   reason for that is that one of the requests might hold a reference to a
   following request. A _req_mod() that destroys the current req might drop
   the references on the next request as well! I.e. the "save" of a
   list_for_each_entry_safe() element gets destroyed! -- With holding a
   reference that destroy gets delayed as necessary */

#define tl_for_each_req_ref_from(req, next, tl)		\
	for (req = __tl_first_req_ref(&next, req, tl);	\
	     req;					\
	     req = __tl_next_req_ref(&next, req, tl))

#define tl_for_each_req_ref(req, next, tl)				\
	for (req = __tl_first_req_ref(&next,				\
	list_first_entry_or_null(tl, struct drbd_request, tl_requests), \
				      tl);				\
	     req;							\
	     req = __tl_next_req_ref(&next, req, tl))

static struct drbd_request *__tl_first_req_ref(struct drbd_request **pnext,
					       struct drbd_request *req,
					       struct list_head *transfer_log)
{
	if (req) {
#ifdef _WIN32
		struct drbd_request *next = list_next_entry(struct drbd_request, req, tl_requests);
#else
		struct drbd_request *next = list_next_entry(req, tl_requests);
#endif
		
		if (&next->tl_requests != transfer_log)
			kref_get(&next->kref);
		*pnext = next;
	}
	return req;
}

static struct drbd_request *__tl_next_req_ref(struct drbd_request **pnext,
					      struct drbd_request *req,
					      struct list_head *transfer_log)
{
	struct drbd_request *next = *pnext;
	bool next_is_head = (&next->tl_requests == transfer_log);

	do {
		if (next_is_head)
			return NULL;
		req = next;
#ifdef _WIN32
		next = list_next_entry(struct drbd_request, req, tl_requests);
#else
		next = list_next_entry(req, tl_requests);
#endif
		
		next_is_head = (&next->tl_requests == transfer_log);
		if (!next_is_head)
			kref_get(&next->kref);
	} while (kref_put(&req->kref, drbd_req_destroy));
	*pnext = next;
	return req;
}

static void tl_abort_for_each_req_ref(struct drbd_request *next, struct list_head *transfer_log)
{
	if (&next->tl_requests != transfer_log)
		kref_put(&next->kref, drbd_req_destroy);
}

/**
 * tl_release() - mark as BARRIER_ACKED all requests in the corresponding transfer log epoch
 * @device:	DRBD device.
 * @barrier_nr:	Expected identifier of the DRBD write barrier packet.
 * @set_size:	Expected number of requests before that barrier.
 *
 * In case the passed barrier_nr or set_size does not match the oldest
 * epoch of not yet barrier-acked requests, this function will cause a
 * termination of the connection.
 */
void tl_release(struct drbd_connection *connection, unsigned int barrier_nr,
		unsigned int set_size)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_request *r;
	struct drbd_request *req = NULL;
	unsigned int expect_epoch = 0;
	unsigned int expect_size = 0;

	spin_lock_irq(&connection->resource->req_lock);

	/* find oldest not yet barrier-acked write request,
	 * count writes in its epoch. */
#ifdef _WIN32
    list_for_each_entry(struct drbd_request, r, &resource->transfer_log, tl_requests) {
#else
	list_for_each_entry(r, &resource->transfer_log, tl_requests) {
#endif
		struct drbd_peer_device *peer_device;
		int idx;
		peer_device = conn_peer_device(connection, r->device->vnr);
		idx = 1 + peer_device->node_id;

		if (!req) {
			if (!(r->rq_state[0] & RQ_WRITE))
				continue;
			if (!(r->rq_state[idx] & RQ_NET_MASK))
				continue;
			if (r->rq_state[idx] & RQ_NET_DONE)
				continue;
			req = r;
			expect_epoch = req->epoch;
			expect_size ++;
		} else {
			if (r->epoch != expect_epoch)
				break;
			if (!(r->rq_state[0] & RQ_WRITE))
				continue;
#ifdef _WIN32_MULTI_VOLUME
			if (!(r->rq_state[idx] & RQ_NET_MASK))
				continue;
			// MODIFIED_BY_MANTECH DW-1166 : Check RQ_NET_DONE for multi-volume
			if (r->rq_state[idx] & RQ_NET_DONE)
				continue;
#else
			/* if (s & RQ_DONE): not expected */
			/* if (!(s & RQ_NET_MASK)): not expected */
#endif
			expect_size++;
		}
	}

	/* first some paranoia code */
	if (req == NULL) {
		drbd_err(connection, "BAD! BarrierAck #%u received, but no epoch in tl!?\n",
			 barrier_nr);
		goto bail;
	}
	if (expect_epoch != barrier_nr) {
		drbd_err(connection, "BAD! BarrierAck #%u received, expected #%u!\n",
			 barrier_nr, expect_epoch);
		goto bail;
	}

	if (expect_size != set_size) {
		drbd_err(connection, "BAD! BarrierAck #%u received with n_writes=%u, expected n_writes=%u!\n",
			 barrier_nr, set_size, expect_size);
		goto bail;
	}

	/* Clean up list of requests processed during current epoch. */
	/* this extra list walk restart is paranoia,
	 * to catch requests being barrier-acked "unexpectedly".
	 * It usually should find the same req again, or some READ preceding it. */
#ifdef _WIN32
    list_for_each_entry(struct drbd_request, req, &resource->transfer_log, tl_requests)
#else
	list_for_each_entry(req, &resource->transfer_log, tl_requests)
#endif
	if (req->epoch == expect_epoch)
			break;
	tl_for_each_req_ref_from(req, r, &resource->transfer_log) {
		struct drbd_peer_device *peer_device;
		if (req->epoch != expect_epoch) {
			tl_abort_for_each_req_ref(r, &resource->transfer_log);
			break;
		}
		peer_device = conn_peer_device(connection, req->device->vnr);
		_req_mod(req, BARRIER_ACKED, peer_device);
	}
	spin_unlock_irq(&connection->resource->req_lock);

	if ((int)(barrier_nr) == connection->send.last_sent_epoch_nr) {
		clear_bit(BARRIER_ACK_PENDING, &connection->flags);
		wake_up(&resource->barrier_wait);
	}

	return;

bail:
	spin_unlock_irq(&connection->resource->req_lock);
	change_cstate_ex(connection, C_PROTOCOL_ERROR, CS_HARD);
}


/**
 * _tl_restart() - Walks the transfer log, and applies an action to all requests
 * @connection:	DRBD connection to operate on.
 * @what:       The action/event to perform with all request objects
 *
 * @what might be one of CONNECTION_LOST_WHILE_PENDING, RESEND, FAIL_FROZEN_DISK_IO,
 * RESTART_FROZEN_DISK_IO.
 */
/* must hold resource->req_lock */
void _tl_restart(struct drbd_connection *connection, enum drbd_req_event what)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	struct drbd_request *req, *r;

	tl_for_each_req_ref(req, r, &resource->transfer_log) {
#ifdef _WIN32 // DW-689 temporary patch
		if (NULL == req->device) { DbgPrintEx(FLTR_COMPONENT, DPFLTR_TRACE_LEVEL,"req->device is null! ignore!"); break; }
#endif
		peer_device = conn_peer_device(connection, req->device->vnr);

#ifdef _WIN32 // DW-689 temporary patch
		if (NULL == peer_device) { DbgPrintEx(FLTR_COMPONENT, DPFLTR_TRACE_LEVEL,"peer_device is null! ignore!"); break; }
#endif
		_req_mod(req, what, peer_device);
	}
}

void tl_restart(struct drbd_connection *connection, enum drbd_req_event what)
{
	struct drbd_resource *resource = connection->resource;

	del_timer_sync(&resource->peer_ack_timer);
	spin_lock_irq(&resource->req_lock);
	_tl_restart(connection, what);
	spin_unlock_irq(&resource->req_lock);
}


/**
 * tl_clear() - Clears all requests and &struct drbd_tl_epoch objects out of the TL
 * @device:	DRBD device.
 *
 * This is called after the connection to the peer was lost. The storage covered
 * by the requests on the transfer gets marked as our of sync. Called from the
 * receiver thread and the sender thread.
 */
void tl_clear(struct drbd_connection *connection)
{
	tl_restart(connection, CONNECTION_LOST_WHILE_PENDING);
}

/**
 * tl_abort_disk_io() - Abort disk I/O for all requests for a certain device in the TL
 * @device:     DRBD device.
 */
void tl_abort_disk_io(struct drbd_device *device)
{
        struct drbd_resource *resource = device->resource;
        struct drbd_request *req, *r;

        spin_lock_irq(&resource->req_lock);
		tl_for_each_req_ref(req, r, &resource->transfer_log) {
                if (!(req->rq_state[0] & RQ_LOCAL_PENDING))
                        continue;
                if (req->device != device)
                        continue;
                _req_mod(req, ABORT_DISK_IO, NULL);
        }
        spin_unlock_irq(&resource->req_lock);
}

#ifdef _WIN32
VOID NTAPI drbd_thread_setup(void *arg)
#else
static int drbd_thread_setup(void *arg)
#endif
{
	struct drbd_thread *thi = (struct drbd_thread *) arg;
	struct drbd_resource *resource = thi->resource;
	struct drbd_connection *connection = thi->connection;
	unsigned long flags;
	int retval;
#ifdef _WIN32
    thi->nt = ct_add_thread(KeGetCurrentThread(), thi->name, TRUE, 'B0DW');
    if (!thi->nt)
    {
        WDRBD_ERROR("DRBD_PANIC: ct_add_thread faild.\n");
        PsTerminateSystemThread(STATUS_SUCCESS);
    }

    KeSetEvent(&thi->start_event, 0, FALSE);
    KeWaitForSingleObject(&thi->wait_event, Executive, KernelMode, FALSE, NULL);
#endif

restart:
	retval = thi->function(thi);

	spin_lock_irqsave(&thi->t_lock, flags);

	/* if the receiver has been "EXITING", the last thing it did
	 * was set the conn state to "StandAlone",
	 * if now a re-connect request comes in, conn state goes C_UNCONNECTED,
	 * and receiver thread will be "started".
	 * drbd_thread_start needs to set "RESTARTING" in that case.
	 * t_state check and assignment needs to be within the same spinlock,
	 * so either thread_start sees EXITING, and can remap to RESTARTING,
	 * or thread_start see NONE, and can proceed as normal.
	 */

	if (thi->t_state == RESTARTING) {
		if (connection)
			drbd_info(connection, "Restarting %s thread\n", thi->name);
		else
			drbd_info(resource, "Restarting %s thread\n", thi->name);
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
		goto restart;
	}
#ifdef _WIN32
    ct_delete_thread(thi->task->pid);
#endif
	thi->task = NULL;
	thi->t_state = NONE;
	smp_mb();

	if (connection)
		drbd_info(connection, "Terminating %s thread\n", thi->name);
	else
		drbd_info(resource, "Terminating %s thread\n", thi->name);

	complete(&thi->stop);
	spin_unlock_irqrestore(&thi->t_lock, flags);

#ifdef _WIN32	
    PsTerminateSystemThread(STATUS_SUCCESS); 
	// not reached here
#else
	return retval;
#endif
}

static void drbd_thread_init(struct drbd_resource *resource, struct drbd_thread *thi,
			     int (*func) (struct drbd_thread *), const char *name)
{
	spin_lock_init(&thi->t_lock);
	thi->task    = NULL;
	thi->t_state = NONE;
	thi->function = func;
	thi->resource = resource;
	thi->connection = NULL;
	thi->name = name;
}

int drbd_thread_start(struct drbd_thread *thi)
{
	struct drbd_resource *resource = thi->resource;
	struct drbd_connection *connection = thi->connection;
#ifndef _WIN32
	struct task_struct *nt;
#endif
	unsigned long flags;

	/* is used from state engine doing drbd_thread_stop_nowait,
	 * while holding the req lock irqsave */
	spin_lock_irqsave(&thi->t_lock, flags);

	switch (thi->t_state) {
	case NONE:
#ifdef _WIN32
		if (connection)
			drbd_info(connection, "Starting %s thread (from %s [0x%p])\n",
				 thi->name, current->comm, current->pid);
		else
			drbd_info(resource, "Starting %s thread (from %s [0x%p])\n",
				 thi->name, current->comm, current->pid);
#else
		if (connection)
			drbd_info(connection, "Starting %s thread (from %s [%d])\n",
				 thi->name, current->comm, current->pid);
		else
			drbd_info(resource, "Starting %s thread (from %s [%d])\n",
				 thi->name, current->comm, current->pid);
#endif
		init_completion(&thi->stop);
		D_ASSERT(resource, thi->task == NULL);
		thi->reset_cpu_mask = 1;
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
		flush_signals(current); /* otherw. may get -ERESTARTNOINTR */
#ifdef _WIN32
        thi->nt = NULL;
        {
            HANDLE		hThread = NULL;
            NTSTATUS	Status = STATUS_UNSUCCESSFUL;

            KeInitializeEvent(&thi->start_event, SynchronizationEvent, FALSE);
            KeInitializeEvent(&thi->wait_event, SynchronizationEvent, FALSE);
            Status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, drbd_thread_setup, (void *) thi);
            if (!NT_SUCCESS(Status)) {
                return false;
            }
            ZwClose(hThread);
        }

        KeWaitForSingleObject(&thi->start_event, Executive, KernelMode, FALSE, NULL);
        if (!thi->nt)
        {
            return false;
        }
#else

		nt = kthread_create(drbd_thread_setup, (void *) thi,
				    "drbd_%c_%s", thi->name[0], resource->name);

		if (IS_ERR(nt)) {
			if (connection)
				drbd_err(connection, "Couldn't start thread\n");
			else
				drbd_err(resource, "Couldn't start thread\n");

			return false;
		}
#endif
		spin_lock_irqsave(&thi->t_lock, flags);
#ifdef _WIN32
        thi->task = thi->nt;
#else
		thi->task = nt;
#endif
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
#ifdef _WIN32
        wake_up_process(thi);
#else
		wake_up_process(nt);
#endif
		break;
	case EXITING:
		thi->t_state = RESTARTING;
		if (connection)
			drbd_info(connection, "Restarting %s thread (from %s [%d])\n",
					thi->name, current->comm, current->pid);
		else
			drbd_info(resource, "Restarting %s thread (from %s [%d])\n",
					thi->name, current->comm, current->pid);
		/* fall through */
	case RUNNING:
	case RESTARTING:
	default:
		spin_unlock_irqrestore(&thi->t_lock, flags);
		break;
	}

	return true;
}


void _drbd_thread_stop(struct drbd_thread *thi, int restart, int wait)
{
	unsigned long flags;

	enum drbd_thread_state ns = restart ? RESTARTING : EXITING;

	/* may be called from state engine, holding the req lock irqsave */
	spin_lock_irqsave(&thi->t_lock, flags);

#ifdef _WIN32
	//WDRBD_INFO("thi(%s) ns(%s) state(%d) waitflag(%d) event(%d)-------------------!\n", 
	//	thi->name, (ns == RESTARTING) ? "RESTARTING" : "EXITING", thi->t_state, wait, KeReadStateEvent(&thi->stop.wait.wqh_event)); // _WIN32
#endif
	if (thi->t_state == NONE) {
		spin_unlock_irqrestore(&thi->t_lock, flags);
		if (restart)
			drbd_thread_start(thi);
		return;
	}

	if (thi->t_state == EXITING && ns == RESTARTING) {
		/* Do not abort a stop request, otherwise a waiter might never wake up */
		spin_unlock_irqrestore(&thi->t_lock, flags);
		return;
	}

	if (thi->t_state != ns) {
		if (thi->task == NULL) {
			spin_unlock_irqrestore(&thi->t_lock, flags);
			return;
		}

		thi->t_state = ns;
		smp_mb();
		init_completion(&thi->stop);
		if (thi->task != current)
#ifdef _WIN32
		{
			force_sig(DRBD_SIGKILL, thi->task);
		}
		else
		{
		//	WDRBD_INFO("cur=(%s) thi=(%s) stop myself\n", current->comm, thi->name ); 
		}
#else
			force_sig(DRBD_SIGKILL, thi->task);
#endif
	}
	spin_unlock_irqrestore(&thi->t_lock, flags);

	if (wait)
#ifdef _WIN32
	{ 
		//WDRBD_INFO("(%s) wait_for_completion. signaled(%d)\n", current->comm, KeReadStateEvent(&thi->stop.wait.wqh_event));

		while (wait_for_completion(&thi->stop) == -DRBD_SIGKILL)
		{
		//	WDRBD_INFO("DRBD_SIGKILL occurs. Ignore and wait for real event\n"); // not happened.
		}
    }
#else
		wait_for_completion(&thi->stop);
#endif
	//WDRBD_INFO("waitflag(%d) signaled(%d). sent stop sig done.\n", wait, KeReadStateEvent(&thi->stop.wait.wqh_event)); // _WIN32
}

int conn_lowest_minor(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr = 0, minor = -1;

	rcu_read_lock();
	peer_device = idr_get_next(&connection->peer_devices, &vnr);
	if (peer_device)
		minor = device_to_minor(peer_device->device);
	rcu_read_unlock();

	return minor;
}

#ifdef CONFIG_SMP
/**
 * drbd_calc_cpu_mask() - Generate CPU masks, spread over all CPUs
 *
 * Forces all threads of a resource onto the same CPU. This is beneficial for
 * DRBD's performance. May be overwritten by user's configuration.
 */
static void drbd_calc_cpu_mask(cpumask_var_t *cpu_mask)
{
	unsigned int *resources_per_cpu, min_index = ~0;

	resources_per_cpu = kzalloc(nr_cpu_ids * sizeof(*resources_per_cpu), GFP_KERNEL);
	if (resources_per_cpu) {
		struct drbd_resource *resource;
		unsigned int cpu, min = ~0;

		rcu_read_lock();
		for_each_resource_rcu(resource, &drbd_resources) {
			for_each_cpu(cpu, resource->cpu_mask)
				resources_per_cpu[cpu]++;
		}
		rcu_read_unlock();
		for_each_online_cpu(cpu) {
			if (resources_per_cpu[cpu] < min) {
				min = resources_per_cpu[cpu];
				min_index = cpu;
			}
		}
		kfree(resources_per_cpu);
	}
	if (min_index == ~0) {
		cpumask_setall(*cpu_mask);
		return;
	}
	cpumask_set_cpu(min_index, *cpu_mask);
}

/**
 * drbd_thread_current_set_cpu() - modifies the cpu mask of the _current_ thread
 * @device:	DRBD device.
 * @thi:	drbd_thread object
 *
 * call in the "main loop" of _all_ threads, no need for any mutex, current won't die
 * prematurely.
 */
void drbd_thread_current_set_cpu(struct drbd_thread *thi)
{
	struct drbd_resource *resource = thi->resource;
	struct task_struct *p = current;

	if (!thi->reset_cpu_mask)
		return;
	thi->reset_cpu_mask = 0;
	set_cpus_allowed_ptr(p, resource->cpu_mask);
}
#endif

static bool drbd_all_neighbor_secondary(struct drbd_resource *resource, u64 *authoritative_ptr)
{
	struct drbd_connection *connection;
	bool all_secondary = true;
	u64 authoritative = 0;
	int id;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[NOW] >= C_CONNECTED &&
		    connection->peer_role[NOW] == R_PRIMARY) {
			all_secondary = false;
			id = connection->peer_node_id;
			authoritative |= NODE_MASK(id);
		}
	}
	rcu_read_unlock();

	if (authoritative_ptr)
		*authoritative_ptr = authoritative;

	return all_secondary;
}

/* This function is supposed to have the same semantics as calc_device_stable() in drbd_state.c
   A primary is stable since it is authoritative.
   Unstable are neighbors of a primary and resync target nodes.
   Nodes further away from a primary are stable! */
bool drbd_device_stable(struct drbd_device *device, u64 *authoritative_ptr)
{
	struct drbd_resource *resource = device->resource;
	struct drbd_connection *connection;
	struct drbd_peer_device *peer_device;
	u64 authoritative = 0;
	bool device_stable = true;

	if (resource->role[NOW] == R_PRIMARY)
		return true;

	if (!drbd_all_neighbor_secondary(resource, authoritative_ptr))
		return false;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		peer_device = conn_peer_device(connection, device->vnr);
		switch (peer_device->repl_state[NOW]) {
		case L_WF_BITMAP_T:
		case L_SYNC_TARGET:
		case L_PAUSED_SYNC_T:
			device_stable = false;
			authoritative |= NODE_MASK(peer_device->node_id);
			goto out;
		default:
			continue;
		}
	}

out:
	rcu_read_unlock();
	if (authoritative_ptr)
		*authoritative_ptr = authoritative;
	return device_stable;
}

#ifdef _WIN32_STABLE_SYNCSOURCE
// DW-1315: check if I have primary neighbor, it has same semantics as drbd_all_neighbor_secondary and is also able to check the role to be changed.
#ifdef _WIN32_RCU_LOCKED
static bool drbd_all_neighbor_secondary_ex(struct drbd_resource *resource, u64 *authoritative, enum which_state which, bool locked)
#else
static bool drbd_all_neighbor_secondary_ex(struct drbd_resource *resource, u64 *authoritative, enum which_state which)
#endif
{
	struct drbd_connection *connection;
	bool all_secondary = true;
	int id;

#ifdef _WIN32_RCU_LOCKED
	rcu_read_lock_check(locked);
#else
	rcu_read_lock();
#endif
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[which] >= C_CONNECTED &&
			connection->peer_role[which] == R_PRIMARY) {
			all_secondary = false;
			if (authoritative) {
				id = connection->peer_node_id;
				*authoritative |= NODE_MASK(id);
			}
			else {
				break;
			}
		}
	}
#ifdef _WIN32_RCU_LOCKED
	rcu_read_unlock_check(locked);
#else
	rcu_read_unlock();
#endif

	return all_secondary;
}

// DW-1315: check the stability and authoritative node(if unstable), it has same semantics as drbd_device_stable and is also able to check the state to be changed.
#ifdef _WIN32_RCU_LOCKED
bool drbd_device_stable_ex(struct drbd_device *device, u64 *authoritative, enum which_state which, bool locked)
#else
bool drbd_device_stable_ex(struct drbd_device *device, u64 *authoritative, enum which_state which)
#endif
{
	struct drbd_resource *resource = device->resource;
	struct drbd_connection *connection;
	struct drbd_peer_device *peer_device;
	bool device_stable = true;

	if (resource->role[which] == R_PRIMARY)
		return true;

#ifdef _WIN32_RCU_LOCKED
	if (!drbd_all_neighbor_secondary_ex(resource, authoritative, which, locked))
#else
	if (!drbd_all_neighbor_secondary_ex(resource, authoritative, which))
#endif
		return false;

#ifdef _WIN32_RCU_LOCKED
	rcu_read_lock_check(locked);
#else
	rcu_read_lock();
#endif

	for_each_connection_rcu(connection, resource) {
		peer_device = conn_peer_device(connection, device->vnr);
		switch (peer_device->repl_state[which]) {
		case L_WF_BITMAP_T:
		case L_SYNC_TARGET:
		case L_PAUSED_SYNC_T:
			device_stable = false;
			if (authoritative)
				*authoritative |= NODE_MASK(peer_device->node_id);
			goto out;
		default:
			continue;
		}
	}

out:
#ifdef _WIN32_RCU_LOCKED
	rcu_read_unlock_check(locked);
#else
	rcu_read_unlock();
#endif
	return device_stable;
}
#endif

#ifdef _WIN32
// MODIFIED_BY_MANTECH DW-1145: it returns true if my disk is consistent with primary's
bool is_consistent_with_primary(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device = NULL;
	int node_id = -1;

	if (device->disk_state[NOW] != D_UP_TO_DATE)
		return false;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++){
		peer_device = peer_device_by_node_id(device, node_id);
		if (!peer_device)
			continue;
		if (peer_device->connection->peer_role[NOW] == R_PRIMARY &&
			peer_device->repl_state[NOW] >= L_ESTABLISHED &&
			peer_device->uuids_received &&
			drbd_bm_total_weight(peer_device) == 0)
			return true;
	}
	return false;
}
#endif

/**
 * drbd_header_size  -  size of a packet header
 *
 * The header size is a multiple of 8, so any payload following the header is
 * word aligned on 64-bit architectures.  (The bitmap send and receive code
 * relies on this.)
 */
unsigned int drbd_header_size(struct drbd_connection *connection)
{
	if (connection->agreed_pro_version >= 100) {
		BUILD_BUG_ON(!IS_ALIGNED(sizeof(struct p_header100), 8));
		return sizeof(struct p_header100);
	} else {
		BUILD_BUG_ON(sizeof(struct p_header80) !=
			     sizeof(struct p_header95));
		BUILD_BUG_ON(!IS_ALIGNED(sizeof(struct p_header80), 8));
		return sizeof(struct p_header80);
	}
}

static void prepare_header80(struct p_header80 *h, enum drbd_packet cmd, int size)
{
	h->magic   = cpu_to_be32(DRBD_MAGIC);
	h->command = cpu_to_be16(cmd);

	BUG_ON_UINT16_OVER((__be16)size - sizeof(struct p_header80));

	h->length  = cpu_to_be16((__be16)size - sizeof(struct p_header80));
}

static void prepare_header95(struct p_header95 *h, enum drbd_packet cmd, int size)
{
	h->magic   = cpu_to_be16(DRBD_MAGIC_BIG);
	h->command = cpu_to_be16(cmd);
	h->length = cpu_to_be32(size - sizeof(struct p_header95));
}

static void prepare_header100(struct p_header100 *h, enum drbd_packet cmd,
				      int size, int vnr)
{
	h->magic = cpu_to_be32(DRBD_MAGIC_100);
	BUG_ON_UINT16_OVER(vnr);
	h->volume = cpu_to_be16((uint16_t)vnr);
	h->command = cpu_to_be16(cmd);
	h->length = cpu_to_be32(size - sizeof(struct p_header100));
	h->pad = 0;
}

static void prepare_header(struct drbd_connection *connection, int vnr,
			   void *buffer, enum drbd_packet cmd, int size)
{
	if (connection->agreed_pro_version >= 100)
		prepare_header100(buffer, cmd, size, vnr);
	else if (connection->agreed_pro_version >= 95 &&
		 size > DRBD_MAX_SIZE_H80_PACKET)
		prepare_header95(buffer, cmd, size);
	else
		prepare_header80(buffer, cmd, size);
}

static void new_or_recycle_send_buffer_page(struct drbd_send_buffer *sbuf)
{
	while (true, true) {
		struct page *page;
		int count = page_count(sbuf->page);

		BUG_ON(count == 0);
		if (count == 1)
			goto have_page;

		page = alloc_page(GFP_KERNEL);
		if (page) {
#ifndef _WIN32
			put_page(sbuf->page);
#endif
			sbuf->page = page;
			goto have_page;
		}

		schedule_timeout(HZ / 10);
	}
have_page:
	sbuf->unsent =
	sbuf->pos = page_address(sbuf->page);
}

static char *alloc_send_buffer(struct drbd_connection *connection, int size,
			      enum drbd_stream drbd_stream)
{
	struct drbd_send_buffer *sbuf = &connection->send_buffer[drbd_stream];
	char *page_start = page_address(sbuf->page);
	
	if (sbuf->pos - page_start + size > PAGE_SIZE) {
#ifdef _WIN32
		WDRBD_TRACE_RS("(%s) stream(%d)! unsent(%d) pos(%d) size(%d)\n", current->comm, drbd_stream, sbuf->unsent, sbuf->pos, size);
#endif
		flush_send_buffer(connection, drbd_stream);
		new_or_recycle_send_buffer_page(sbuf);
	}

	sbuf->allocated_size = size;
	sbuf->additional_size = 0;

	return sbuf->pos;
}

/* Only used the shrink the previously allocated size. */
static void resize_prepared_command(struct drbd_connection *connection,
				    enum drbd_stream drbd_stream,
				    int size)
{
	connection->send_buffer[drbd_stream].allocated_size =
		size + drbd_header_size(connection);
}

static void additional_size_command(struct drbd_connection *connection,
				    enum drbd_stream drbd_stream,
				    int additional_size)
{
	connection->send_buffer[drbd_stream].additional_size = additional_size;
}

void *__conn_prepare_command(struct drbd_connection *connection, int size,
				    enum drbd_stream drbd_stream)
{
	struct drbd_transport *transport = &connection->transport;
	int header_size;

	if (!transport->ops->stream_ok(transport, drbd_stream)) {
		drbd_err(connection, "socket not allocate\n");
		return NULL;
	}

	header_size = drbd_header_size(connection);
#ifdef _WIN32
	void *p = (char *)alloc_send_buffer(connection, header_size + size, drbd_stream) + header_size;
	if(!p) {
		drbd_err(connection, "failed allocate send buffer\n");
	}
	return p;
#else
	return alloc_send_buffer(connection, header_size + size, drbd_stream) + header_size;
#endif
}

/**
 * conn_prepare_command() - Allocate a send buffer for a packet/command
 * @conneciton:	the connections the packet will be sent through
 * @size:	number of bytes to allocate
 * @stream:	DATA_STREAM or CONTROL_STREAM
 *
 * This allocates a buffer with capacity to hold the header, and
 * the requested size. Upon success is return a pointer that points
 * to the first byte behind the header. The caller is expected to
 * call xxx_send_command() soon.
 */
void *conn_prepare_command(struct drbd_connection *connection, int size,
			   enum drbd_stream drbd_stream)
{
	void *p;

	mutex_lock(&connection->mutex[drbd_stream]);
	p = __conn_prepare_command(connection, size, drbd_stream);
	if (!p)
		mutex_unlock(&connection->mutex[drbd_stream]);

	return p;
}

/**
 * drbd_prepare_command() - Allocate a send buffer for a packet/command
 * @conneciton:	the connections the packet will be sent through
 * @size:	number of bytes to allocate
 * @stream:	DATA_STREAM or CONTROL_STREAM
 *
 * This allocates a buffer with capacity to hold the header, and
 * the requested size. Upon success is return a pointer that points
 * to the first byte behind the header. The caller is expected to
 * call xxx_send_command() soon.
 */
void *drbd_prepare_command(struct drbd_peer_device *peer_device, int size, enum drbd_stream drbd_stream)
{
	return conn_prepare_command(peer_device->connection, size, drbd_stream);
}

static int flush_send_buffer(struct drbd_connection *connection, enum drbd_stream drbd_stream)
{
	struct drbd_send_buffer *sbuf = &connection->send_buffer[drbd_stream];
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;
	int msg_flags, err;
	ULONG_PTR size;
	ULONG_PTR offset;

	size = sbuf->pos - sbuf->unsent + sbuf->allocated_size;
	if (size == 0)
		return 0;

	if (drbd_stream == DATA_STREAM) {
    	rcu_read_lock();
		connection->transport.ko_count = rcu_dereference(connection->transport.net_conf)->ko_count;
		rcu_read_unlock();
	}

	msg_flags = sbuf->additional_size ? MSG_MORE : 0;
	offset = sbuf->unsent - (char *)page_address(sbuf->page);
#ifdef _WIN64
	BUG_ON_UINT32_OVER(offset);
#endif
#ifdef _WIN32
    err = tr_ops->send_page(transport, drbd_stream, sbuf->page->addr, (int)offset, (size_t)size, msg_flags);
#else
	err = tr_ops->send_page(transport, drbd_stream, sbuf->page, offset, size, msg_flags);
#endif
	if (!err) {
		sbuf->unsent =
		sbuf->pos += sbuf->allocated_size;      /* send buffer submitted! */
	}

	sbuf->allocated_size = 0;

	return err;
}

int __send_command(struct drbd_connection *connection, int vnr,
			  enum drbd_packet cmd, enum drbd_stream drbd_stream)
{
	struct drbd_send_buffer *sbuf = &connection->send_buffer[drbd_stream];
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;
	bool corked = test_bit(CORKED + drbd_stream, &connection->flags);
	bool flush = (cmd == P_PING || cmd == P_PING_ACK || cmd == P_TWOPC_PREPARE);
	int err;

	/* send P_PING and P_PING_ACK immediately, they need to be delivered as
	   fast as possible.
	   P_TWOPC_PREPARE might be used from the worker context while corked.
	   The work item (connect_work) calls change_cluster_wide_state() which
	   in turn waits for reply packets. -> Need to send it regardless of
	   corking.  */

	if (connection->cstate[NOW] < C_CONNECTING)
		return -EIO;
	prepare_header(connection, vnr, sbuf->pos, cmd,
		       sbuf->allocated_size + sbuf->additional_size);

	if (corked && !flush) {
		drbd_debug(connection, "send buff %s, size: %d vnr: %d, stream : %s\n", drbd_packet_name(cmd), (sbuf->allocated_size + sbuf->additional_size), vnr, drbd_stream == DATA_STREAM ? "DATA" : "CONTROL");
		sbuf->pos += sbuf->allocated_size;
		sbuf->allocated_size = 0;
		err = 0;
	} else {
		drbd_debug(connection, "sending %s, size: %d vnr: %d, stream : %s\n", drbd_packet_name(cmd), (sbuf->pos - sbuf->unsent + sbuf->allocated_size), vnr, drbd_stream == DATA_STREAM ? "DATA" : "CONTROL");
		err = flush_send_buffer(connection, drbd_stream);

		/* DRBD protocol "pings" are latency critical.
		 * This is supposed to trigger tcp_push_pending_frames() */
		if (!err && flush)
			tr_ops->hint(transport, drbd_stream, NODELAY);

		if (drbd_stream == DATA_STREAM) {
			if (!err)
				connection->last_send_packet = cmd;
			// DW-1977 last successful protocol may not be correct because it is a transfer to the buffer
			else
				drbd_info(connection, "last successful protocol %s\n", drbd_packet_name(cmd));
		}
	}

	return err;
}

void drbd_drop_unsent(struct drbd_connection* connection)
{
	int i;

	clear_bit(DATA_CORKED, &connection->flags);
	clear_bit(CONTROL_CORKED, &connection->flags);

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		struct drbd_send_buffer *sbuf = &connection->send_buffer[i];
		sbuf->unsent =
		sbuf->pos = page_address(sbuf->page);
		sbuf->allocated_size = 0;
		sbuf->additional_size = 0;
	}
}

void drbd_cork(struct drbd_connection *connection, enum drbd_stream stream)
{
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;

	mutex_lock(&connection->mutex[stream]);
	set_bit(CORKED + stream, &connection->flags);
	tr_ops->hint(transport, stream, CORK);
	mutex_unlock(&connection->mutex[stream]);
}

void drbd_uncork(struct drbd_connection *connection, enum drbd_stream stream)
{
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;


	mutex_lock(&connection->mutex[stream]);
	flush_send_buffer(connection, stream);

	clear_bit(CORKED + stream, &connection->flags);
	tr_ops->hint(transport, stream, UNCORK);
	mutex_unlock(&connection->mutex[stream]);
}

int send_command(struct drbd_connection *connection, int vnr,
		 enum drbd_packet cmd, enum drbd_stream drbd_stream)
{
	int err;

	err = __send_command(connection, vnr, cmd, drbd_stream);
	mutex_unlock(&connection->mutex[drbd_stream]);
	return err;
}

int drbd_send_command(struct drbd_peer_device *peer_device,
		      enum drbd_packet cmd, enum drbd_stream drbd_stream)
{
	return send_command(peer_device->connection, peer_device->device->vnr,
			    cmd, drbd_stream);
}

int drbd_send_ping(struct drbd_connection *connection)
{
	if (!conn_prepare_command(connection, 0, CONTROL_STREAM))
		return -EIO;
	return send_command(connection, -1, P_PING, CONTROL_STREAM);
}

int drbd_send_ping_ack(struct drbd_connection *connection)
{
	if (!conn_prepare_command(connection, 0, CONTROL_STREAM))
		return -EIO;
	return send_command(connection, -1, P_PING_ACK, CONTROL_STREAM);
}

int drbd_send_peer_ack(struct drbd_connection *connection,
			      struct drbd_request *req)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_connection *c;
	struct p_peer_ack *p;
	u64 mask = 0;

#ifndef _WIN32
	// MODIFIED_BY_MANTECH DW-1099: masking my node id causes peers to improper in-sync.
	if (req->rq_state[0] & RQ_LOCAL_OK)
		mask |= NODE_MASK(resource->res_opts.node_id);
#endif

	rcu_read_lock();
	for_each_connection_rcu(c, resource) {
		int node_id = c->peer_node_id;
		int idx = 1 + node_id;

		if (req->rq_state[idx] & RQ_NET_OK)
			mask |= NODE_MASK(node_id);
	}
	rcu_read_unlock();

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (!p)
		return -EIO;
	p->mask = cpu_to_be64(mask);
	p->dagtag = cpu_to_be64(req->dagtag_sector);

	return send_command(connection, -1, P_PEER_ACK, CONTROL_STREAM);
}

int drbd_send_sync_param(struct drbd_peer_device *peer_device)
{
	struct p_rs_param_95 *p;
	int size;
	const int apv = peer_device->connection->agreed_pro_version;
	enum drbd_packet cmd;
	struct net_conf *nc;
	struct peer_device_conf *pdc;

	rcu_read_lock();
	nc = rcu_dereference(peer_device->connection->transport.net_conf);

	size = apv <= 87 ? (int)sizeof(struct p_rs_param)
		: apv == 88 ? (int)sizeof(struct p_rs_param)
		+ (int)(strlen(nc->verify_alg) + 1)
			: apv <= 94 ? (int)sizeof(struct p_rs_param_89)
		: /* apv >= 95 */ (int)sizeof(struct p_rs_param_95);

	cmd = apv >= 89 ? P_SYNC_PARAM89 : P_SYNC_PARAM;
	rcu_read_unlock();

	p = drbd_prepare_command(peer_device, size, DATA_STREAM);
	if (!p)
		return -EIO;

	/* initialize verify_alg and csums_alg */
	memset(p->verify_alg, 0, SHARED_SECRET_MAX);
	memset(p->csums_alg, 0, SHARED_SECRET_MAX);
#ifdef _WIN32
    rcu_read_lock_w32_inner();
#else
	rcu_read_lock();
#endif
	nc = rcu_dereference(peer_device->connection->transport.net_conf);

	// DW-2023 fix incorrect resync-rate setting
	pdc = rcu_dereference(peer_device->conf);
	p->resync_rate = cpu_to_be32(pdc->resync_rate);
	p->c_plan_ahead = cpu_to_be32(pdc->c_plan_ahead);
	p->c_delay_target = cpu_to_be32(pdc->c_delay_target);
	p->c_fill_target = cpu_to_be32(pdc->c_fill_target);
	p->c_max_rate = cpu_to_be32(pdc->c_max_rate);	

	if (apv >= 88)
		strncpy(p->verify_alg, nc->verify_alg, sizeof(p->verify_alg) - 1);
	if (apv >= 89)
		strncpy(p->csums_alg, nc->csums_alg, sizeof(p->csums_alg) - 1);
	rcu_read_unlock();

	return drbd_send_command(peer_device, cmd, DATA_STREAM);
}

int __drbd_send_protocol(struct drbd_connection *connection, enum drbd_packet cmd)
{
	struct p_protocol *p;
	struct net_conf *nc;
	int size, cf;

	if (test_bit(CONN_DRY_RUN, &connection->flags) && connection->agreed_pro_version < 92) {
		clear_bit(CONN_DRY_RUN, &connection->flags);
		drbd_err(connection, "--dry-run is not supported by peer");
		return -EOPNOTSUPP;
	}

	size = sizeof(*p);
	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	if (connection->agreed_pro_version >= 87) {
		size += (int)(strlen(nc->integrity_alg) + 1);
	}
	rcu_read_unlock();

	p = __conn_prepare_command(connection, size, DATA_STREAM);
	if (!p)
		return -EIO;
#ifdef _WIN32
    rcu_read_lock_w32_inner();
#else
	rcu_read_lock();
#endif
	nc = rcu_dereference(connection->transport.net_conf);

	p->protocol      = cpu_to_be32(nc->wire_protocol);
	p->after_sb_0p   = cpu_to_be32(nc->after_sb_0p);
	p->after_sb_1p   = cpu_to_be32(nc->after_sb_1p);
	p->after_sb_2p   = cpu_to_be32(nc->after_sb_2p);
	p->two_primaries = cpu_to_be32(nc->two_primaries);
	cf = 0;
	if (test_bit(CONN_DISCARD_MY_DATA, &connection->flags))
		cf |= CF_DISCARD_MY_DATA;
	if (test_bit(CONN_DRY_RUN, &connection->flags))
		cf |= CF_DRY_RUN;
	p->conn_flags    = cpu_to_be32(cf);

	if (connection->agreed_pro_version >= 87)
		strncpy(p->integrity_alg, nc->integrity_alg, SHARED_SECRET_MAX-1);
	rcu_read_unlock();

	return __send_command(connection, -1, cmd, DATA_STREAM);
}

int drbd_send_protocol(struct drbd_connection *connection)
{
	int err;

	mutex_lock(&connection->mutex[DATA_STREAM]);
	err = __drbd_send_protocol(connection, P_PROTOCOL);
	mutex_unlock(&connection->mutex[DATA_STREAM]);

	return err;
}

static int _drbd_send_uuids(struct drbd_peer_device *peer_device, u64 uuid_flags)
{
	struct drbd_device *device = peer_device->device;
	struct p_uuids *p;
	int i;

	if (!get_ldev_if_state(device, D_NEGOTIATING))
		return 0;

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p) {
		put_ldev(device);
		return -EIO;
	}

	spin_lock_irq(&device->ldev->md.uuid_lock);
	p->current_uuid = cpu_to_be64(drbd_current_uuid(device));
	p->bitmap_uuid = cpu_to_be64(drbd_bitmap_uuid(peer_device));
	for (i = 0; i < ARRAY_SIZE(p->history_uuids); i++)
		p->history_uuids[i] = cpu_to_be64(drbd_history_uuid(device, i));
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	peer_device->comm_bm_set = drbd_bm_total_weight(peer_device);
	p->dirty_bits = cpu_to_be64(peer_device->comm_bm_set);

	if (test_bit(DISCARD_MY_DATA, &peer_device->flags))
		uuid_flags |= UUID_FLAG_DISCARD_MY_DATA;
	if (test_bit(CRASHED_PRIMARY, &device->flags))
		uuid_flags |= UUID_FLAG_CRASHED_PRIMARY;
	if (!drbd_md_test_flag(device, MDF_CONSISTENT))
		uuid_flags |= UUID_FLAG_INCONSISTENT;
	if (drbd_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR))
		uuid_flags |= UUID_FLAG_PRIMARY_IO_ERROR;
	//DW-1874
	if (drbd_md_test_peer_flag(peer_device, MDF_PEER_IN_PROGRESS_SYNC))
		uuid_flags |= UUID_FLAG_IN_PROGRESS_SYNC;
	p->uuid_flags = cpu_to_be64(uuid_flags);

	put_ldev(device);

	return drbd_send_command(peer_device, P_UUIDS, DATA_STREAM);
}

static u64 __bitmap_uuid(struct drbd_device *device, int node_id) __must_hold(local)
{
	struct drbd_peer_device *peer_device;
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	u64 bitmap_uuid = peer_md[node_id].bitmap_uuid;

	/* Sending a bitmap_uuid of 0 means that we are in sync with that peer.
	   The recipient of this message might use this assumption to throw away it's
	   bitmap to that peer.

	   Send -1 instead if we are (resync target from that peer) not at the same
	   current uuid.
	   This corner case is relevant if we finish resync from an UpToDate peer first,
	   and the second resync (which was paused first) is from an Outdated node.
	   And that second resync gets canceled by the resync target due to the first
	   resync finished successfully.

	   Exceptions to the above are when the peer's UUID is not known yet
	 */

	rcu_read_lock();
	peer_device = peer_device_by_node_id(device, node_id);

	if (bitmap_uuid == 0 && peer_device &&
		peer_device->current_uuid != 0 &&
		(peer_device->current_uuid & ~UUID_PRIMARY) !=
		(drbd_current_uuid(device) & ~UUID_PRIMARY))
#ifdef _WIN32
	{
		// MODIFIED_BY_MANTECH DW-978: Set MDF_PEER_DIFF_CUR_UUID flag so that we're able to recognize -1 is sent.
		// MODIFIED_BY_MANTECH DW-1415 Set MDF_PEER_DIFF_CUR_UUID flag when only peer is in connected state to avoid exchanging uuid unlimitedly on the ring topology with flawed connection.
		if (peer_device->connection->cstate[NOW] == C_CONNECTED)
			peer_md[node_id].flags |= MDF_PEER_DIFF_CUR_UUID;

		bitmap_uuid = UINT64_MAX;
	}
#else
		bitmap_uuid = -1;
#endif

	rcu_read_unlock();

	return bitmap_uuid;
}

static int _drbd_send_uuids110(struct drbd_peer_device *peer_device, u64 uuid_flags, u64 node_mask)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_md *peer_md;
	struct p_uuids110 *p;
	ULONG_PTR pos = 0;
	ULONG_PTR i, bitmap_uuids_mask = 0;
#ifdef _WIN32
	u64 authoritative_mask = 0;
#else
	u64 authoritative_mask;
#endif
	int p_size = sizeof(*p);

	if (!get_ldev_if_state(device, D_NEGOTIATING))
		return drbd_send_current_uuid(peer_device, device->exposed_data_uuid,
		drbd_weak_nodes_device(device));

	peer_md = device->ldev->md.peers;

	p_size += (DRBD_PEERS_MAX + HISTORY_UUIDS) * sizeof(p->other_uuids[0]);
	p = drbd_prepare_command(peer_device, p_size, DATA_STREAM);
	if (!p) {
		put_ldev(device);
		return -EIO;
	}

	spin_lock_irq(&device->ldev->md.uuid_lock);
	p->current_uuid = cpu_to_be64(drbd_current_uuid(device));

	for (i = 0; i < DRBD_NODE_ID_MAX; i++) {
		if (peer_md[i].bitmap_index != -1 || peer_md[i].flags & MDF_NODE_EXISTS)
			bitmap_uuids_mask |= NODE_MASK(i);
	}

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1253: sizeof(bitmap_uuids_mask) is 8, it cannot be found all nodes. so, change it to DRBD_NODE_ID_MAX. 
	for_each_set_bit(i, (ULONG_PTR*)&bitmap_uuids_mask, DRBD_NODE_ID_MAX) {
#ifdef _WIN64
		BUG_ON_INT32_OVER(i);
#endif
#else
	for_each_set_bit(i, (unsigned long *)&bitmap_uuids_mask, sizeof(bitmap_uuids_mask))
#endif
		p->other_uuids[pos++] = cpu_to_be64(__bitmap_uuid(device, (int)i));
#ifdef _WIN32
	}
#endif

	for (i = 0; i < HISTORY_UUIDS; i++)
		p->other_uuids[pos++] = cpu_to_be64(drbd_history_uuid(device, (int)i));
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	p->bitmap_uuids_mask = cpu_to_be64(bitmap_uuids_mask);

	peer_device->comm_bm_set = drbd_bm_total_weight(peer_device);
	p->dirty_bits = cpu_to_be64(peer_device->comm_bm_set);
	if (test_bit(DISCARD_MY_DATA, &peer_device->flags))
		uuid_flags |= UUID_FLAG_DISCARD_MY_DATA;
#ifndef _WIN32_CRASHED_PRIMARY_SYNCSOURCE
	// MODIFIED_BY_MANTECH DW-1357: do not send UUID_FLAG_CRASHED_PRIMARY if I don't need to get synced from this peer.
	if (test_bit(CRASHED_PRIMARY, &device->flags) &&
		!drbd_md_test_peer_flag(peer_device, MDF_PEER_IGNORE_CRASHED_PRIMARY))
#else
	if (test_bit(CRASHED_PRIMARY, &device->flags))
#endif
		uuid_flags |= UUID_FLAG_CRASHED_PRIMARY;
	if (!drbd_md_test_flag(device, MDF_CONSISTENT))
		uuid_flags |= UUID_FLAG_INCONSISTENT;
	if (test_bit(RECONNECT, &peer_device->connection->flags))
		uuid_flags |= UUID_FLAG_RECONNECT;
	if (drbd_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR))
		uuid_flags |= UUID_FLAG_PRIMARY_IO_ERROR;
	if (drbd_device_stable(device, &authoritative_mask)) {
		uuid_flags |= UUID_FLAG_STABLE;
		p->node_mask = cpu_to_be64(node_mask);
	} else {
		D_ASSERT(peer_device, node_mask == 0);
		p->node_mask = cpu_to_be64(authoritative_mask);
	}
	//DW-1874
	if (drbd_md_test_peer_flag(peer_device, MDF_PEER_IN_PROGRESS_SYNC))
		uuid_flags |= UUID_FLAG_IN_PROGRESS_SYNC;

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1145: set UUID_FLAG_CONSISTENT_WITH_PRI if my disk is consistent with primary's
	if (is_consistent_with_primary(device))
		uuid_flags |= UUID_FLAG_CONSISTENT_WITH_PRI;
	// DW-1285 If MDF_PEER_INIT_SYNCT_BEGIN is on, send UUID_FLAG_INIT_SYNCT_BEGIN flag.
	if(drbd_md_test_peer_flag(peer_device, MDF_PEER_INIT_SYNCT_BEGIN))
		uuid_flags |= UUID_FLAG_INIT_SYNCT_BEGIN;
#endif

	p->uuid_flags = cpu_to_be64(uuid_flags);

	put_ldev(device);
#ifdef _WIN64
	BUG_ON_INT32_OVER(sizeof(*p) + (hweight64(bitmap_uuids_mask) + HISTORY_UUIDS) * sizeof(p->other_uuids[0]));
#endif
	p_size = (int)(sizeof(*p) + (hweight64(bitmap_uuids_mask) + HISTORY_UUIDS) * sizeof(p->other_uuids[0]));
	resize_prepared_command(peer_device->connection, DATA_STREAM, p_size);
	return drbd_send_command(peer_device, P_UUIDS110, DATA_STREAM);
}

int drbd_send_uuids(struct drbd_peer_device *peer_device, u64 uuid_flags, u64 node_mask)
{
	if (peer_device->connection->agreed_pro_version >= 110)
		return _drbd_send_uuids110(peer_device, uuid_flags, node_mask);
	else
		return _drbd_send_uuids(peer_device, uuid_flags);
}

void drbd_print_uuids(struct drbd_peer_device *peer_device, const char *text, const char *caller)
{
	struct drbd_device *device = peer_device->device;

	if (get_ldev_if_state(device, D_NEGOTIATING)) {
		drbd_info(peer_device, "%s, %s %016llX:%016llX:%016llX:%016llX\n",
			caller, text,
			  (unsigned long long)drbd_current_uuid(device),
			  (unsigned long long)drbd_bitmap_uuid(peer_device),
			  (unsigned long long)drbd_history_uuid(device, 0),
			  (unsigned long long)drbd_history_uuid(device, 1));
		put_ldev(device);
	} else {
		drbd_info(device, "%s, %s effective data uuid: %016llX\n",
			caller, text, 
			(unsigned long long)device->exposed_data_uuid);
	}
}

int drbd_send_current_uuid(struct drbd_peer_device *peer_device, u64 current_uuid, u64 weak_nodes)
{
	struct p_current_uuid *p;

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;

	p->uuid = cpu_to_be64(current_uuid);
	p->weak_nodes = cpu_to_be64(weak_nodes);
	return drbd_send_command(peer_device, P_CURRENT_UUID, DATA_STREAM);
}

void drbd_gen_and_send_sync_uuid(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct p_uuid *p;
	u64 uuid;

	D_ASSERT(device, device->disk_state[NOW] == D_UP_TO_DATE);

	uuid = drbd_bitmap_uuid(peer_device);
	if (uuid && uuid != UUID_JUST_CREATED)
		uuid = uuid + UUID_NEW_BM_OFFSET;
	else
		get_random_bytes(&uuid, sizeof(u64));
	drbd_uuid_set_bitmap(peer_device, uuid);
	drbd_print_uuids(peer_device, "updated sync UUID", __FUNCTION__);
	drbd_md_sync(device);

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (p) {
		p->uuid = cpu_to_be64(uuid);
		drbd_send_command(peer_device, P_SYNC_UUID, DATA_STREAM);
	}
}

/* All callers hold resource->conf_update */
int drbd_attach_peer_device(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct peer_device_conf *pdc;
	struct fifo_buffer *resync_plan = NULL;
	struct lru_cache *resync_lru = NULL;
	int err = -ENOMEM;

	pdc = rcu_dereference_protected(peer_device->conf,
		lockdep_is_held(&peer_device->device->resource->conf_update));
#ifdef _WIN32
    if (peer_device->rs_plan_s)
        resync_plan = peer_device->rs_plan_s;
    else
    	resync_plan = fifo_alloc((pdc->c_plan_ahead * 10 * SLEEP_TIME) / HZ, '88DW');
#else
	resync_plan = fifo_alloc((pdc->c_plan_ahead * 10 * SLEEP_TIME) / HZ);
#endif
	if (!resync_plan)
		goto out;
#ifdef _WIN32
	resync_lru = lc_create("resync", &drbd_bm_ext_cache,
			       1, 61, sizeof(struct bm_extent),
			       offsetof(struct bm_extent, lce));
#else
	resync_lru = lc_create("resync", drbd_bm_ext_cache,
			       1, 61, sizeof(struct bm_extent),
			       offsetof(struct bm_extent, lce));
#endif
	if (!resync_lru)
		goto out;
	rcu_assign_pointer(peer_device->rs_plan_s, resync_plan);
	peer_device->resync_lru = resync_lru;
	err = 0;

out:
	if (err) {
		kfree(resync_lru);
		kfree(resync_plan);
	}
	return err;
}

#ifndef _WIN32
/* communicated if (agreed_features & DRBD_FF_WSAME) */
void assign_p_sizes_qlim(struct drbd_device *device, struct p_sizes *p, struct request_queue *q)
{
	if (q) {
		p->qlim->physical_block_size = cpu_to_be32(queue_physical_block_size(q));
		p->qlim->logical_block_size = cpu_to_be32(queue_logical_block_size(q));
		p->qlim->alignment_offset = cpu_to_be32(queue_alignment_offset(q));
		p->qlim->io_min = cpu_to_be32(queue_io_min(q));
		p->qlim->io_opt = cpu_to_be32(queue_io_opt(q));
		p->qlim->discard_enabled = blk_queue_discard(q);
		p->qlim->discard_zeroes_data = queue_discard_zeroes_data(q);
#ifdef COMPAT_WRITE_SAME_CAPABLE
		p->qlim->write_same_capable = !!q->limits.max_write_same_sectors;
#else
		p->qlim->write_same_capable = 0;
#endif
	} else {
		q = device->rq_queue;
		p->qlim->physical_block_size = cpu_to_be32(queue_physical_block_size(q));
		p->qlim->logical_block_size = cpu_to_be32(queue_logical_block_size(q));
		p->qlim->alignment_offset = 0;
		p->qlim->io_min = cpu_to_be32(queue_io_min(q));
		p->qlim->io_opt = cpu_to_be32(queue_io_opt(q));
		p->qlim->discard_enabled = 0;
		p->qlim->discard_zeroes_data = 0;
		p->qlim->write_same_capable = 0;
	}
}
#endif

//int drbd_send_sizes(struct drbd_peer_device *peer_device, int trigger_reply, enum dds_flags flags)
int drbd_send_sizes(struct drbd_peer_device *peer_device,
			uint64_t u_size_diskless, enum dds_flags flags)
{
	struct drbd_device *device = peer_device->device;
	struct p_sizes *p;
	sector_t d_size, u_size;
	int q_order_type;
	unsigned int max_bio_size;
	unsigned int packet_size;

	packet_size = sizeof(*p);
	if (peer_device->connection->agreed_features & DRBD_FF_WSAME)
		packet_size += sizeof(p->qlim[0]);

	p = drbd_prepare_command(peer_device, packet_size, DATA_STREAM);
	if (!p)
		return -EIO;

	memset(p, 0, packet_size);
	if (get_ldev_if_state(device, D_NEGOTIATING)) {
		
		d_size = drbd_get_max_capacity(device->ldev);
		rcu_read_lock();
		u_size = rcu_dereference(device->ldev->disk_conf)->disk_size;
		rcu_read_unlock();
		q_order_type = drbd_queue_order_type(device);
#ifdef _WIN32
		// DW-1497 Fix max bio size to default 1MB, because we don't need to variable max bio config on Windows.
		// Since max_bio_size is an integer type, an overflow has occurred for the value of max_hw_sectors.
		// DW-1763 : set to DRBD_MAX_BIO_SIZE if larger than DRBD_MAX_BIO_SIZE.
		max_bio_size = (unsigned int)(min((queue_max_hw_sectors(device->ldev->backing_bdev->bd_disk->queue) << 9), DRBD_MAX_BIO_SIZE));
#else
		max_bio_size = queue_max_hw_sectors(q) << 9;
		max_bio_size = min(max_bio_size, DRBD_MAX_BIO_SIZE);
#endif
#ifndef _WIN32
		assign_p_sizes_qlim(device, p, q);
#endif
		put_ldev(device);
	} else {
		d_size = 0;
		u_size = u_size_diskless;
		q_order_type = QUEUE_ORDERED_NONE;
		max_bio_size = DRBD_MAX_BIO_SIZE; /* ... multiple BIOs per peer_request */
#ifndef _WIN32
		assign_p_sizes_qlim(device, p, NULL);
#endif
	}

	if (peer_device->connection->agreed_pro_version <= 94)
		max_bio_size = min(max_bio_size, DRBD_MAX_SIZE_H80_PACKET);
	else if (peer_device->connection->agreed_pro_version < 100)
		max_bio_size = min(max_bio_size, DRBD_MAX_BIO_SIZE_P95);

	p->d_size = cpu_to_be64(d_size);
	p->u_size = cpu_to_be64(u_size);
	/*
	TODO verify: this may be needed for v8 compatibility still.
	p->c_size = cpu_to_be64(trigger_reply ? 0 : drbd_get_capacity(device->this_bdev));
	*/
#ifdef _WIN32 
	// DW-1469 : For initial sync, set c_size to 0.
	if (drbd_current_uuid(device) == UUID_JUST_CREATED)
	{
		p->c_size = 0;	
	} 	
	else
	{
		p->c_size = cpu_to_be64(drbd_get_capacity(device->this_bdev));
	}
#else
	p->c_size = cpu_to_be64(drbd_get_capacity(device->this_bdev));
#endif
	p->max_bio_size = cpu_to_be32(max_bio_size);
	BUG_ON_UINT16_OVER(q_order_type);
	p->queue_order_type = cpu_to_be16((uint16_t)q_order_type);
	p->dds_flags = cpu_to_be16(flags);

	return drbd_send_command(peer_device, P_SIZES, DATA_STREAM);
}

int drbd_send_current_state(struct drbd_peer_device *peer_device)
{
	return drbd_send_state(peer_device, drbd_get_peer_device_state(peer_device, NOW));
}

static int send_state(struct drbd_connection *connection, int vnr, union drbd_state state)
{
	struct p_state *p;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;

	if (connection->agreed_pro_version < 110) {
		/* D_DETACHING was introduced with drbd-9.0 */
		if (state.disk > D_DETACHING)
			state.disk--;
		if (state.pdsk > D_DETACHING)
			state.pdsk--;
	}

	p->state = cpu_to_be32(state.i); /* Within the send mutex */
	return send_command(connection, vnr, P_STATE, DATA_STREAM);
}

int conn_send_state(struct drbd_connection *connection, union drbd_state state)
{
	BUG_ON(connection->agreed_pro_version < 100);
	return send_state(connection, -1, state);
}

/**
 * drbd_send_state() - Sends the drbd state to the peer
 * @device:	DRBD device.
 * @state:	state to send
 */
int drbd_send_state(struct drbd_peer_device *peer_device, union drbd_state state)
{
	return send_state(peer_device->connection, peer_device->device->vnr, state);
}

int conn_send_state_req(struct drbd_connection *connection, int vnr, enum drbd_packet cmd,
			union drbd_state mask, union drbd_state val)
{
	struct p_req_state *p;

	/* Protocols before version 100 only support one volume and connection.
	 * All state change requests are via P_STATE_CHG_REQ. */
	if (connection->agreed_pro_version < 100)
		cmd = P_STATE_CHG_REQ;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->mask = cpu_to_be32(mask.i);
	p->val = cpu_to_be32(val.i);

	return send_command(connection, vnr, cmd, DATA_STREAM);
}

int conn_send_twopc_request(struct drbd_connection *connection, int vnr, enum drbd_packet cmd,
			    struct p_twopc_request *request)
{
	struct p_twopc_request *p;

	drbd_debug(connection, "Sending %s request for state change %u\n",
		   drbd_packet_name(cmd),
		   be32_to_cpu(request->tid));

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	memcpy(p, request, sizeof(*request));

	return send_command(connection, vnr, cmd, DATA_STREAM);
}

void drbd_send_sr_reply(struct drbd_connection *connection, int vnr, enum drbd_state_rv retcode)
{
	struct p_req_state_reply *p;

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (p) {
		enum drbd_packet cmd = P_STATE_CHG_REPLY;

		if (connection->agreed_pro_version >= 100 && vnr < 0)
			cmd = P_CONN_ST_CHG_REPLY;

		p->retcode = cpu_to_be32(retcode);
		send_command(connection, vnr, cmd, CONTROL_STREAM);
	}
}

void drbd_send_twopc_reply(struct drbd_connection *connection,
			   enum drbd_packet cmd, struct twopc_reply *reply)
{
	struct p_twopc_reply *p;

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (p) {
		p->tid = cpu_to_be32(reply->tid);
		p->initiator_node_id = cpu_to_be32(reply->initiator_node_id);
		p->reachable_nodes = cpu_to_be64(reply->reachable_nodes);
		switch (connection->resource->twopc_type) {
		case TWOPC_STATE_CHANGE:
			p->primary_nodes = cpu_to_be64(reply->primary_nodes);
			p->weak_nodes = cpu_to_be64(reply->weak_nodes);
			break;
		case TWOPC_RESIZE:
			p->diskful_primary_nodes = cpu_to_be64(reply->diskful_primary_nodes);
			p->max_possible_size = cpu_to_be64(reply->max_possible_size);
			break;
		}
		send_command(connection, reply->vnr, cmd, CONTROL_STREAM);
	}
}

void drbd_send_peers_in_sync(struct drbd_peer_device *peer_device, u64 mask, sector_t sector, int size)
{
	struct p_peer_block_desc *p;

	p = drbd_prepare_command(peer_device, sizeof(*p), CONTROL_STREAM);
	if (p) {
		p->sector = cpu_to_be64(sector);
		p->mask = cpu_to_be64(mask);
		p->size = cpu_to_be32(size);
		p->pad = 0;
		drbd_send_command(peer_device, P_PEERS_IN_SYNC, CONTROL_STREAM);
	}
}

int drbd_send_peer_dagtag(struct drbd_connection *connection, struct drbd_connection *lost_peer)
{
	struct p_peer_dagtag *p;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;

	p->dagtag = cpu_to_be64(lost_peer->last_dagtag_sector);
	p->node_id = cpu_to_be32(lost_peer->peer_node_id);
#ifdef _WIN32_TRACE_PEER_DAGTAG
	WDRBD_INFO("drbd_send_peer_dagtag lost_peer:%p lost_peer->last_dagtag_sector:%llx lost_peer->peer_node_id:%d\n",lost_peer,lost_peer->last_dagtag_sector,lost_peer->peer_node_id);
#endif	
	return send_command(connection, -1, P_PEER_DAGTAG, DATA_STREAM);
}

static void dcbp_set_code(struct p_compressed_bm *p, enum drbd_bitmap_code code)
{
	BUG_ON(code & ~0xf);
	p->encoding = (uint8_t)((p->encoding & ~0xf) | code);
}

static void dcbp_set_start(struct p_compressed_bm *p, int set)
{
	p->encoding = (p->encoding & ~0x80) | (set ? 0x80 : 0);
}

static void dcbp_set_pad_bits(struct p_compressed_bm *p, int n)
{
	BUG_ON(n & ~0x7);
	p->encoding = (uint8_t)((p->encoding & (~0x7 << 4)) | (n << 4));
}

static int fill_bitmap_rle_bits(struct drbd_peer_device *peer_device,
				struct p_compressed_bm *p,
				unsigned int size,
				struct bm_xfer_ctx *c)
{
	struct bitstream bs;
#ifdef _WIN32
	ULONG_PTR plain_bits;
	ULONG_PTR tmp;
	ULONG_PTR rl;
	ULONG_PTR offset;
#else
	unsigned long plain_bits;
	unsigned long tmp;
	unsigned long rl;
#endif
	unsigned len;
	unsigned toggle;
	int bits, use_rle;

	/* may we use this feature? */
	rcu_read_lock();
	use_rle = rcu_dereference(peer_device->connection->transport.net_conf)->use_rle;
	rcu_read_unlock();
	if (!use_rle || peer_device->connection->agreed_pro_version < 90)
		return 0;

	if (c->bit_offset >= c->bm_bits)
		return 0; /* nothing to do. */

	/* use at most thus many bytes */
	bitstream_init(&bs, p->code, size, 0);
	memset(p->code, 0, size);
	/* plain bits covered in this code string */
	plain_bits = 0;

	/* p->encoding & 0x80 stores whether the first run length is set.
	 * bit offset is implicit.
	 * start with toggle == 2 to be able to tell the first iteration */
	toggle = 2;

	/* see how much plain bits we can stuff into one packet
	 * using RLE and VLI. */
	do {
		//tmp = (toggle == 0) ? _drbd_bm_find_next_zero(peer_device, c->bit_offset)
		//		    : _drbd_bm_find_next(peer_device, c->bit_offset);

		// DW-1979 to avoid lock occupancy, divide and find.
		offset = c->bit_offset;
		for (;;) {
			tmp = (toggle == 0) ? drbd_bm_range_find_next_zero(peer_device, offset, offset + RANGE_FIND_NEXT_BIT) :
				drbd_bm_range_find_next(peer_device, offset, offset + RANGE_FIND_NEXT_BIT);
			if (tmp >= c->bm_bits || tmp < (offset + RANGE_FIND_NEXT_BIT + 1))
				break;
			offset = tmp;
		}

		if (tmp > c->bm_bits)
			tmp = c->bm_bits;

		rl = tmp - c->bit_offset;
		if (toggle == 2) { /* first iteration */
			if (rl == 0) {
				/* the first checked bit was set,
				 * store start value, */
				dcbp_set_start(p, 1);
				/* but skip encoding of zero run length */
				toggle = !toggle;
				continue;
			}
			dcbp_set_start(p, 0);
		}

		/* paranoia: catch zero runlength.
		 * can only happen if bitmap is modified while we scan it. */
		if (rl == 0) {
			drbd_warn(peer_device, "unexpected zero runlength while encoding bitmap "
				"t:%u bo:%llu\n", toggle, (unsigned long long)c->bit_offset);
			// DW-2037 replication I/O can cause bitmap changes, in which case this code will restore.
			if (toggle == 0) {
				update_sync_bits(peer_device, offset, offset, SET_OUT_OF_SYNC, false);
				continue;
			}
			else {
				drbd_err(peer_device, "unexpected out-of-sync has occurred\n");
				return -1;
			}
		}

		bits = vli_encode_bits(&bs, rl);
		if (bits == -ENOBUFS) /* buffer full */
			break;
		if (bits <= 0) {
			drbd_err(peer_device, "error while encoding bitmap: %d\n", bits);
			return 0;
		}

		toggle = !toggle;
		plain_bits += rl;
		c->bit_offset = tmp;
	} while (c->bit_offset < c->bm_bits);

	BUG_ON(UINT_MAX < bs.cur.b - p->code + !!bs.cur.bit);
	len = (unsigned int)(bs.cur.b - p->code + !!bs.cur.bit);

	if (plain_bits < ((ULONG_PTR)len << 3)) {
		/* incompressible with this method.
		 * we need to rewind both word and bit position. */
		c->bit_offset -= plain_bits;
		bm_xfer_ctx_bit_to_word_offset(c);
		c->bit_offset = c->word_offset * BITS_PER_LONG;
		return 0;
	}

	/* RLE + VLI was able to compress it just fine.
	 * update c->word_offset. */
	bm_xfer_ctx_bit_to_word_offset(c);

	/* store pad_bits */
	dcbp_set_pad_bits(p, (8 - bs.cur.bit) & 0x7);

	return len;
}

/**
 * send_bitmap_rle_or_plain
 *
 * Return 0 when done, 1 when another iteration is needed, and a negative error
 * code upon failure.
 */
static int
send_bitmap_rle_or_plain(struct drbd_peer_device *peer_device, struct bm_xfer_ctx *c)
{
	struct drbd_device *device = peer_device->device;
	unsigned int header_size = drbd_header_size(peer_device->connection);
	struct p_compressed_bm *pc, *tpc;
	int len, err;

	tpc = (struct p_compressed_bm *)kzalloc(DRBD_SOCKET_BUFFER_SIZE, GFP_NOIO | __GFP_NOWARN, '70DW');

	if (!tpc) {
		drbd_err(peer_device, "allocate failed\n");
		return -ENOMEM;
	}

	len = fill_bitmap_rle_bits(peer_device, tpc, DRBD_SOCKET_BUFFER_SIZE - header_size - sizeof(*tpc), c);
	if (len < 0)
	{
#ifdef _WIN32
		drbd_err(peer_device, "unexpected len : %d \n", len);
#endif
		return -EIO;
	}

	// DW-1979
	mutex_lock(&peer_device->connection->mutex[DATA_STREAM]);

	pc = (struct p_compressed_bm *)
		(alloc_send_buffer(peer_device->connection, DRBD_SOCKET_BUFFER_SIZE, DATA_STREAM) + header_size);

	pc->encoding = tpc->encoding;
	memcpy(pc->code, tpc->code, DRBD_SOCKET_BUFFER_SIZE - header_size - sizeof(*pc));
	kfree(tpc);

	if (len) {
		dcbp_set_code(pc, RLE_VLI_Bits);
		resize_prepared_command(peer_device->connection, DATA_STREAM, sizeof(*pc) + len);
		err = __send_command(peer_device->connection, device->vnr,
				     P_COMPRESSED_BITMAP, DATA_STREAM);
#ifdef _WIN32
		if (err)
		{
			drbd_err(peer_device, "error sending P_COMPRESSED_BITMAP, e: %d \n", err);
		}
		
#endif
		c->packets[0]++;
		c->bytes[0] += header_size + sizeof(*pc) + len;

		if (c->bit_offset >= c->bm_bits)
			len = 0; /* DONE */
	} else {
		/* was not compressible.
		 * send a buffer full of plain text bits instead. */
		unsigned int data_size;
#ifdef _WIN32
		ULONG_PTR num_words;
        ULONG_PTR *pu = (ULONG_PTR *)pc;
#else
		unsigned long num_words;
		unsigned long *pu = (unsigned long *)pc;
#endif
		data_size = DRBD_SOCKET_BUFFER_SIZE - header_size;
		num_words = min_t(size_t, data_size / sizeof(*pu),
				  c->bm_words - c->word_offset);
		len = (int)(num_words * sizeof(*pu));
		if (len)
			drbd_bm_get_lel(peer_device, c->word_offset, num_words, pu);

		resize_prepared_command(peer_device->connection, DATA_STREAM, len);
		err = __send_command(peer_device->connection, device->vnr, P_BITMAP, DATA_STREAM);
#ifdef _WIN32
		if (err)
		{
			drbd_err(peer_device, "error sending P_BITMAP, e: %d \n", err);
		}		
#endif

		c->word_offset += num_words;
		c->bit_offset = c->word_offset * BITS_PER_LONG;

		c->packets[1]++;
		c->bytes[1] += header_size + len;

		if (c->bit_offset > c->bm_bits)
			c->bit_offset = c->bm_bits;
	}
	
	mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);

	if (!err) {
		if (len == 0) {
			INFO_bm_xfer_stats(peer_device, "send", c);
			return 0;
		} else
			return 1;
	}
	return -EIO;
}

void drbd_send_bitmap_source_complete(struct drbd_device *device, struct drbd_peer_device *peer_device, int err)
{
	UNREFERENCED_PARAMETER(device);

	// DW-2037 reconnect if the bitmap cannot be restored.
	if (err) {
		drbd_err(peer_device, "syncsource send bitmap failed err(%d)\n", err);
		change_cstate_ex(peer_device->connection, C_NETWORK_FAILURE, CS_HARD);
	}
}

void drbd_send_bitmap_target_complete(struct drbd_device *device, struct drbd_peer_device *peer_device, int err)
{
	UNREFERENCED_PARAMETER(device);

	if (err) {
		drbd_err(peer_device, "synctarget send bitmap failed err(%d)\n", err);
		change_cstate_ex(peer_device->connection, C_NETWORK_FAILURE, CS_HARD);
	}

	/* Omit CS_WAIT_COMPLETE and CS_SERIALIZE with this state
	* transition to avoid deadlocks. */

	if (peer_device->connection->agreed_pro_version < 110) {
		enum drbd_state_rv rv;
		rv = stable_change_repl_state(peer_device, L_WF_SYNC_UUID, CS_VERBOSE);
		D_ASSERT(device, rv == SS_SUCCESS);
	}
	else {
		//DW-1815 merge the peer_device bitmap into the same current_uuid.
		struct drbd_peer_device* pd;
		for_each_peer_device(pd, device) {
			if (pd == peer_device)
				continue;

			if (pd->current_uuid == peer_device->current_uuid) {
				int allow_size = 512;
				ULONG_PTR *bb = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG_PTR) * allow_size, '8EDW');

				if (bb == NULL) {
					drbd_err(peer_device, "bitmap bit buffer allocate failed\n");
					change_cstate_ex(peer_device->connection, C_NETWORK_FAILURE, CS_HARD);
					return;
				}

				memset(bb, 0, sizeof(ULONG_PTR) * allow_size);

				drbd_info(peer_device, "bitmap merge, from index(%d) out of sync(%llu), to bitmap index(%d) out of sync (%llu)\n",
					peer_device->bitmap_index, (unsigned long long)drbd_bm_total_weight(peer_device),
					pd->bitmap_index, (unsigned long long)drbd_bm_total_weight(pd));

				for (ULONG_PTR offset = drbd_bm_find_next(peer_device, 0); offset < drbd_bm_bits(device); offset += allow_size) {
					drbd_bm_get_lel(peer_device, offset, allow_size, bb);
					drbd_bm_merge_lel(pd, offset, allow_size, bb);
				}

				drbd_info(peer_device, "finished bitmap merge, to index(%d) out of sync (%llu)\n", pd->bitmap_index, (unsigned long long)drbd_bm_total_weight(pd));

				kfree2(bb);
			}
		}

		drbd_start_resync(peer_device, L_SYNC_TARGET);
	}
}

/* See the comment at receive_bitmap() */
static int _drbd_send_bitmap(struct drbd_device *device,
			     struct drbd_peer_device *peer_device)
{
	struct bm_xfer_ctx c;
	int err;

	if (!expect(device, device->bitmap))
	{
#ifdef _WIN32
		drbd_err(peer_device, "bitmap is NULL!\n");
#endif
		return false;
	}

	if (get_ldev(device)) {
		if (drbd_md_test_peer_flag(peer_device, MDF_PEER_FULL_SYNC)) {
			drbd_info(device, "Writing the whole bitmap, MDF_FullSync was set.\n");
			drbd_bm_set_many_bits(peer_device, 0, DRBD_END_OF_BITMAP);
			if (drbd_bm_write(device, NULL)) {
				/* write_bm did fail! Leave full sync flag set in Meta P_DATA
				 * but otherwise process as per normal - need to tell other
				 * side that a full resync is required! */
				drbd_err(device, "Failed to write bitmap to disk!\n");
			} else {
				drbd_md_clear_peer_flag(peer_device, MDF_PEER_FULL_SYNC);
				drbd_md_sync(device);
			}
		}
		put_ldev(device);
	}

#ifdef _WIN32
	memset(&c, 0, sizeof(struct bm_xfer_ctx));
#endif
	c = (struct bm_xfer_ctx) {
		.bm_bits = drbd_bm_bits(device),
		.bm_words = drbd_bm_words(device),
	};

	do {
		err = send_bitmap_rle_or_plain(peer_device, &c);
	} while (err > 0);

	return err == 0;
}

int drbd_send_bitmap(struct drbd_device *device, struct drbd_peer_device *peer_device)
{
	struct drbd_transport *peer_transport = &peer_device->connection->transport;
	int err = -1;

	if (peer_device->bitmap_index == -1) {
		drbd_err(peer_device, "No bitmap allocated in drbd_send_bitmap()!\n");
		return -EIO;
	}

	mutex_lock(&peer_device->connection->mutex[DATA_STREAM]);
	if (peer_transport->ops->stream_ok(peer_transport, DATA_STREAM)) {
		mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);
		// DW-1988 in synctarget, wait_for_recv_bitmap should not be used, so it has been modified to be set only under certain conditions.
		// DW-1979
		if (peer_device->repl_state[NOW] == L_WF_BITMAP_S ||
			peer_device->repl_state[NOW] == L_AHEAD)
			atomic_set(&peer_device->wait_for_recv_bitmap, 1);
		err = !_drbd_send_bitmap(device, peer_device);
	}
	else
		mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);

	return err;
}

void drbd_send_b_ack(struct drbd_connection *connection, u32 barrier_nr, u32 set_size)
{
	struct p_barrier_ack *p;

	if (connection->cstate[NOW] < C_CONNECTED)
		return;

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (!p)
		return;
	p->barrier = barrier_nr;
	p->set_size = cpu_to_be32(set_size);
	send_command(connection, -1, P_BARRIER_ACK, CONTROL_STREAM);
}

int drbd_send_rs_deallocated(struct drbd_peer_device *peer_device,
			     struct drbd_peer_request *peer_req)
{
	struct p_block_desc *p;

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(peer_req->i.sector);
	p->blksize = cpu_to_be32(peer_req->i.size);
	p->pad = 0;
	return drbd_send_command(peer_device, P_RS_DEALLOCATED, DATA_STREAM);
}

int drbd_send_drequest(struct drbd_peer_device *peer_device, int cmd,
		       sector_t sector, int size, u64 block_id)
{
	struct p_block_req *p;

#ifdef DRBD_TRACE
	WDRBD_TRACE("sz=%d sector=%lld\n", size, sector);
#endif
	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(sector);
	p->block_id = block_id;
	p->pad = 0;
	p->blksize = cpu_to_be32(size);
#ifdef _WIN32
    WDRBD_TRACE_RS("size(%d) cmd(%d) sector(0x%llx) block_id(%d)\n", size, cmd, sector, block_id);
#endif
	return drbd_send_command(peer_device, cmd, DATA_STREAM);
}

void *drbd_prepare_drequest_csum(struct drbd_peer_request *peer_req, int digest_size)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct p_block_req *p;

	p = drbd_prepare_command(peer_device, sizeof(*p) + digest_size, DATA_STREAM);
	if (!p)
		return NULL;

	p->sector = cpu_to_be64(peer_req->i.sector);
	p->block_id = peer_req->block_id; // DW-1942 used to notify source of io failure.
	p->blksize = cpu_to_be32(peer_req->i.size);

	return p + 1; /* digest should be placed behind the struct */
}

int drbd_send_ov_request(struct drbd_peer_device *peer_device, sector_t sector, int size)
{
	struct p_block_req *p;

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(sector);
	p->block_id = ID_SYNCER /* unused */;
	p->blksize = cpu_to_be32(size);
	return drbd_send_command(peer_device, P_OV_REQUEST, DATA_STREAM);
}

/* The idea of sendpage seems to be to put some kind of reference
 * to the page into the skb, and to hand it over to the NIC. In
 * this process get_page() gets called.
 *
 * As soon as the page was really sent over the network put_page()
 * gets called by some part of the network layer. [ NIC driver? ]
 *
 * [ get_page() / put_page() increment/decrement the count. If count
 *   reaches 0 the page will be freed. ]
 *
 * This works nicely with pages from FSs.
 * But this means that in protocol A we might signal IO completion too early!
 *
 * In order not to corrupt data during a resync we must make sure
 * that we do not reuse our own buffer pages (EEs) to early, therefore
 * we have the net_ee list.
 *
 * XFS seems to have problems, still, it submits pages with page_count == 0!
 * As a workaround, we disable sendpage on pages
 * with page_count == 0 or PageSlab.
 */

static int _drbd_send_page(struct drbd_peer_device *peer_device, struct page *page,
			    int offset, size_t size, unsigned msg_flags)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;
	int err;

#ifdef _WIN32
	err = tr_ops->send_page(transport, DATA_STREAM, page->addr, offset, size, msg_flags);
#else
	err = tr_ops->send_page(transport, DATA_STREAM, page, offset, size, msg_flags);
#endif
	if (!err) {
		peer_device->send_cnt += (unsigned int)(size >> 9);
	}

	return err;
}
#ifdef _WIN32 
//we don't need to consider page, care to only buffer in no_send_page
int _drbd_no_send_page(struct drbd_peer_device *peer_device, void * buffer,
			      int offset, size_t size, unsigned msg_flags)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;
	int err;

	WDRBD_TRACE_RS("offset(%d) size(%d)\n", offset, size);
	flush_send_buffer(connection, DATA_STREAM); 
	err = tr_ops->send_page(transport, DATA_STREAM, buffer, offset, size, msg_flags);
	if (!err) {
		peer_device->send_cnt += (unsigned int)(size >> 9);
	}
	return err;
}
#else
int _drbd_no_send_page(struct drbd_peer_device *peer_device, struct page *page,
			      int offset, size_t size, unsigned msg_flags)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_send_buffer *sbuf = &connection->send_buffer[DATA_STREAM];
	char *from_base;
	void *buffer2;
	int err;

	buffer2 = alloc_send_buffer(connection, size, DATA_STREAM);
	from_base = drbd_kmap_atomic(page, KM_USER0);
	memcpy(buffer2, from_base + offset, size);
	drbd_kunmap_atomic(from_base, KM_USER0);

	if (msg_flags & MSG_MORE) {
		sbuf->pos += sbuf->allocated_size;
		sbuf->allocated_size = 0;
		err = 0;
	} else {
		err = flush_send_buffer(connection, DATA_STREAM);
	}

	return err;
}
#endif

static int _drbd_send_bio(struct drbd_peer_device *peer_device, struct bio *bio)
{
	struct drbd_connection *connection = peer_device->connection;
#ifndef _WIN32
	DRBD_BIO_VEC_TYPE bvec;
	DRBD_ITER_TYPE iter;
#endif
	/* Flush send buffer and make sure PAGE_SIZE is available... */
	alloc_send_buffer(connection, PAGE_SIZE, DATA_STREAM);
	connection->send_buffer[DATA_STREAM].allocated_size = 0;

#ifdef _WIN32
	int err;
	err = _drbd_no_send_page(peer_device, bio->bio_databuf, 0, bio->bi_size, 0);
	if (err)
		return err;

	peer_device->send_cnt += (bio->bi_size) >> 9;
#else
	/* hint all but last page with MSG_MORE */
	bio_for_each_segment(bvec, bio, iter) {
		int err;

		err = _drbd_no_send_page(peer_device, bvec BVD bv_page,
					 bvec BVD bv_offset, bvec BVD bv_len,
					 bio_iter_last(bvec, iter) ? 0 : MSG_MORE);
		if (err)
			return err;
		/* WRITE_SAME has only one segment */
		if (bio_op(bio) == REQ_OP_WRITE_SAME)
			break;

		peer_device->send_cnt += (bvec BVD bv_len) >> 9;
	}
#endif
	return 0;
}

static int _drbd_send_zc_bio(struct drbd_peer_device *peer_device, struct bio *bio)
{

	/* e.g. XFS meta- & log-data is in slab pages, which have a
	 * page_count of 0 and/or have PageSlab() set.
	 * we cannot use send_page for those, as that does get_page();
	 * put_page(); and would cause either a VM_BUG directly, or
	 * __page_cache_release a page that would actually still be referenced
	 * by someone, leading to some obscure delayed Oops somewhere else. */
#ifdef _WIN32
	int err;
	err = _drbd_no_send_page(peer_device, bio->bio_databuf, 0, bio->bi_size, 0);
	if (err)
		return err;
	return 0;
#else
	if (!no_zc)
		bio_for_each_segment(bvec, bio, iter) {
			struct page *page = bvec BVD bv_page;

			if (page_count(page) < 1 || PageSlab(page)) {
				no_zc = true;
				break;
			}
		}

	if (no_zc) {
		return _drbd_send_bio(peer_device, bio);
	} else {
		struct drbd_connection *connection = peer_device->connection;
		struct drbd_transport *transport = &connection->transport;
		struct drbd_transport_ops *tr_ops = transport->ops;
		int err;

		flush_send_buffer(connection, DATA_STREAM);

		err = tr_ops->send_zc_bio(transport, bio);
		if (!err)
			peer_device->send_cnt += DRBD_BIO_BI_SIZE(bio) >> 9;

		return err;
	}
#endif
}

static int _drbd_send_zc_ee(struct drbd_peer_device *peer_device,
			    struct drbd_peer_request *peer_req)
{
	unsigned len = peer_req->i.size;
	int err;

	flush_send_buffer(peer_device->connection, DATA_STREAM);

#ifdef _WIN32
	// add bio-linked pointer to drbd_peer_request structure
	// bio-linked pointer(peer_req_databuf) is used to replace with page structure buffers
	err = _drbd_no_send_page(peer_device, peer_req->peer_req_databuf, 0, len, 0);
	if (err)
		return err;
#else
	/* hint all but last page with MSG_MORE */
	page_chain_for_each(page) {
		unsigned l = min_t(unsigned, len, PAGE_SIZE);
		if (page_chain_offset(page) != 0 ||
		    page_chain_size(page) != l) {
			drbd_err(peer_device, "FIXME page %p offset %u len %u\n",
				page, page_chain_offset(page), page_chain_size(page));
		}

		err = _drbd_send_page(peer_device, page, 0, l,
				      page_chain_next(page) ? MSG_MORE : 0);
		if (err)
			return err;
		len -= l;
	}
#endif
	return 0;
}

/* see also wire_flags_to_bio()
 * DRBD_REQ_*, because we need to semantically map the flags to data packet
 * flags and back. We may replicate to other kernel versions. */
static u32 bio_flags_to_wire(struct drbd_connection *connection, struct bio *bio)
{
	if (connection->agreed_pro_version >= 95)
		return  (bio->bi_opf & DRBD_REQ_SYNC ? DP_RW_SYNC : 0) |
			(bio->bi_opf & DRBD_REQ_UNPLUG ? DP_UNPLUG : 0) |
			(bio->bi_opf & DRBD_REQ_FUA ? DP_FUA : 0) |
			(bio->bi_opf & DRBD_REQ_PREFLUSH ? DP_FLUSH : 0) |
			(bio_op(bio) == REQ_OP_WRITE_SAME ? DP_WSAME : 0) |
			(bio_op(bio) == REQ_OP_DISCARD ? DP_DISCARD : 0);

	/* else: we used to communicate one bit only in older DRBD */
	return bio->bi_opf & (DRBD_REQ_SYNC | DRBD_REQ_UNPLUG) ? DP_RW_SYNC : 0;
}

/* Used to send write or TRIM aka REQ_DISCARD requests
 * R_PRIMARY -> Peer	(P_DATA, P_TRIM)
 */
int drbd_send_dblock(struct drbd_peer_device *peer_device, struct drbd_request *req)
{
	struct drbd_device *device = peer_device->device;
	struct p_trim *trim = NULL;
	struct p_data *p;
	struct p_wsame *wsame = NULL;
	void *digest_out = NULL;
	unsigned int dp_flags = 0;
	int digest_size = 0;
#ifdef _WIN32
	int err = 0;
#else
	int err;
#endif
	
	const unsigned s = drbd_req_state_by_peer_device(req, peer_device);

	if (req->master_bio->bi_rw & DRBD_REQ_DISCARD) {
		trim = drbd_prepare_command(peer_device, sizeof(*trim), DATA_STREAM);
		if (!trim)
			return -EIO;
		p = &trim->p_data;
		trim->size = cpu_to_be32(req->i.size);
	} else {
		if (peer_device->connection->integrity_tfm)
			digest_size = crypto_hash_digestsize(peer_device->connection->integrity_tfm);

		if (req->master_bio->bi_rw & DRBD_REQ_WSAME) {
			wsame = drbd_prepare_command(peer_device, sizeof(*wsame) + digest_size, DATA_STREAM);
			if (!wsame)
				return -EIO;
			p = &wsame->p_data;
			wsame->size = cpu_to_be32(req->i.size);
			digest_out = wsame + 1;
		} else {
			p = drbd_prepare_command(peer_device, sizeof(*p) + digest_size, DATA_STREAM);
			if (!p)
				return -EIO;
			digest_out = p + 1;
		}
	}

	p->sector = cpu_to_be64(req->i.sector);
#ifdef _WIN32
	p->block_id = (ULONG_PTR)req;
#else
	p->block_id = (unsigned long)req;
#endif
	p->seq_num = cpu_to_be32(atomic_inc_return(&peer_device->packet_seq));
	
	dp_flags = bio_flags_to_wire(peer_device->connection, req->master_bio);
	if (peer_device->repl_state[NOW] >= L_SYNC_SOURCE && peer_device->repl_state[NOW] <= L_PAUSED_SYNC_T)
		dp_flags |= DP_MAY_SET_IN_SYNC;
	if (peer_device->connection->agreed_pro_version >= 100) {
		if (s & RQ_EXP_RECEIVE_ACK)
			dp_flags |= DP_SEND_RECEIVE_ACK;
		if (s & RQ_EXP_WRITE_ACK || dp_flags & DP_MAY_SET_IN_SYNC)
			dp_flags |= DP_SEND_WRITE_ACK;
	}
	p->dp_flags = cpu_to_be32(dp_flags);

	if (trim) {
		err = __send_command(peer_device->connection, device->vnr, P_TRIM, DATA_STREAM);
		goto out;
	}

	if (digest_size && digest_out)
#ifdef _WIN32
		drbd_csum_bio(peer_device->connection->integrity_tfm, req, digest_out);
#else
		drbd_csum_bio(peer_device->connection->integrity_tfm, req->master_bio, digest_out);
#endif

	if (wsame) {
#ifndef _WIN32
		additional_size_command(peer_device->connection, DATA_STREAM,
					bio_iovec(req->master_bio) BVD bv_len);
		err = __send_command(peer_device->connection, device->vnr, P_WSAME, DATA_STREAM);
#else 
		//not support
#endif
	} else {
		additional_size_command(peer_device->connection, DATA_STREAM, req->i.size);
		err = __send_command(peer_device->connection, device->vnr, P_DATA, DATA_STREAM);
	}
	if (!err) {
		/* For protocol A, we have to memcpy the payload into
		 * socket buffers, as we may complete right away
		 * as soon as we handed it over to tcp, at which point the data
		 * pages may become invalid.
		 *
		 * For data-integrity enabled, we copy it as well, so we can be
		 * sure that even if the bio pages may still be modified, it
		 * won't change the data on the wire, thus if the digest checks
		 * out ok after sending on this side, but does not fit on the
		 * receiving side, we sure have detected corruption elsewhere.
		 */
		if (!(s & (RQ_EXP_RECEIVE_ACK | RQ_EXP_WRITE_ACK)) || digest_size)
#ifdef _WIN32
			err = _drbd_no_send_page(peer_device, req->req_databuf, 0, req->i.size, 0);
#else
			err = _drbd_send_bio(peer_device, req->master_bio);
#endif
		else
#ifdef _WIN32
			err = _drbd_no_send_page(peer_device, req->req_databuf, 0, req->i.size, 0);
#else
			err = _drbd_send_zc_bio(peer_device, req->master_bio);
#endif

#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-1012: Remove out of sync when data is sent, this is the newest one.
		if (!err)
			drbd_set_in_sync(peer_device, req->i.sector, req->i.size);
#endif

		/* double check digest, sometimes buffers have been modified in flight. */
		if (digest_size > 0 && digest_size <= 64) {
			/* 64 byte, 512 bit, is the largest digest size
			 * currently supported in kernel crypto. */
			unsigned char digest[64];
#ifdef _WIN32
			drbd_csum_bio(peer_device->connection->integrity_tfm, req, digest);
#else
			drbd_csum_bio(peer_device->connection->integrity_tfm, req->master_bio, digest);
#endif
			if (memcmp(p + 1, digest, digest_size)) {
				drbd_warn(device,
					"Digest mismatch, buffer modified by upper layers during write: %llus +%u\n",
					(unsigned long long)req->i.sector, req->i.size);
			}
		} /* else if (digest_size > 64) {
		     ... Be noisy about digest too large ...
		} */
	}
out:
	mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);

	return err;
}

/* answer packet, used to send data back for read requests:
 *  Peer       -> (diskless) R_PRIMARY   (P_DATA_REPLY)
 *  L_SYNC_SOURCE -> L_SYNC_TARGET         (P_RS_DATA_REPLY)
 */
int drbd_send_block(struct drbd_peer_device *peer_device, enum drbd_packet cmd,
		    struct drbd_peer_request *peer_req)
{
	struct p_data *p;
	int err;
	int digest_size;

	digest_size = peer_device->connection->integrity_tfm ?
		      crypto_hash_digestsize(peer_device->connection->integrity_tfm) : 0;

	p = drbd_prepare_command(peer_device, sizeof(*p) + digest_size, DATA_STREAM);

	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(peer_req->i.sector);
	p->block_id = peer_req->block_id;
	p->seq_num = 0;  /* unused */
	p->dp_flags = 0;
	if (digest_size)
#ifdef _WIN32
        drbd_csum_pages(peer_device->connection->integrity_tfm, peer_req, p + 1);
#else
		drbd_csum_pages(peer_device->connection->integrity_tfm, peer_req->page_chain.head, p + 1);
#endif
	additional_size_command(peer_device->connection, DATA_STREAM, peer_req->i.size);

	err = __send_command(peer_device->connection,
			     peer_device->device->vnr, cmd, DATA_STREAM);
	if (!err)
		err = _drbd_send_zc_ee(peer_device, peer_req);
	mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);

	return err;
}

int drbd_send_out_of_sync(struct drbd_peer_device *peer_device, struct drbd_interval *i)
{
	struct p_block_desc *p;

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(i->sector);
	p->blksize = cpu_to_be32(i->size);
	return drbd_send_command(peer_device, P_OUT_OF_SYNC, DATA_STREAM);
}

int drbd_send_dagtag(struct drbd_connection *connection, u64 dagtag)
{
	struct p_dagtag *p;

	if (connection->agreed_pro_version < 110)
		return 0;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->dagtag = cpu_to_be64(dagtag);
	return send_command(connection, -1, P_DAGTAG, DATA_STREAM);
}

/* primary_peer_present_and_not_two_primaries_allowed() */
static bool primary_peer_present(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	struct net_conf *nc;
	bool two_primaries, rv = false;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		nc = rcu_dereference(connection->transport.net_conf);
		two_primaries = nc ? nc->two_primaries : false;

		if (connection->peer_role[NOW] == R_PRIMARY && !two_primaries) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static bool any_disk_is_uptodate(struct drbd_device *device)
{
	bool ret = false;

	rcu_read_lock();
	if (device->disk_state[NOW] == D_UP_TO_DATE)
		ret = true;
	else {
		struct drbd_peer_device *peer_device;

		for_each_peer_device_rcu(peer_device, device) {
			if (peer_device->disk_state[NOW] == D_UP_TO_DATE) {
				ret = true;
				break;
			}
		}
	}
	rcu_read_unlock();

	return ret;
}

static int try_to_promote(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	long timeout = resource->res_opts.auto_promote_timeout * HZ / 10;
	int rv, retry = timeout / (HZ / 5); /* One try every 200ms */
	do {
		rv = drbd_set_role(resource, R_PRIMARY, false, NULL);
		if (rv >= SS_SUCCESS || timeout == 0) {
			resource->bPreSecondaryLock = FALSE;
			return rv;
		} else if (rv == SS_CW_FAILED_BY_PEER) {
			/* Probably udev has it open read-only on one of the peers */
			long t = schedule_timeout_interruptible(HZ / 5);
			if (t < 0)
				break;
			timeout -= HZ / 5;
		} else if (rv == SS_TWO_PRIMARIES) {
			/* Wait till the peer demoted itself */
#ifdef _WIN32
			wait_event_interruptible_timeout(timeout, resource->state_wait,
				resource->role[NOW] == R_PRIMARY ||
				(!primary_peer_present(resource) && any_disk_is_uptodate(device)),
				timeout);
#else
			timeout = wait_event_interruptible_timeout(resource->state_wait,
				resource->role[NOW] == R_PRIMARY ||
				(!primary_peer_present(resource) && any_disk_is_uptodate(device)),
				timeout);
#endif
			if (timeout <= 0)
				break;
		} else if (rv == SS_NO_UP_TO_DATE_DISK) {
			/* Wait until we get a connection established */
#ifdef _WIN32
			wait_event_interruptible_timeout(timeout, resource->state_wait,
				any_disk_is_uptodate(device), timeout);
#else
			timeout = wait_event_interruptible_timeout(resource->state_wait,
				any_disk_is_uptodate(device), timeout);
#endif
			if (timeout <= 0)
				break;	
		} else {
			return rv;
		}
	} while (--retry);
	return rv;
}

static int ro_open_cond(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;

	if (resource->role[NOW] != R_PRIMARY && primary_peer_present(resource) && !allow_oos)
		return -EMEDIUMTYPE;
	else if (any_disk_is_uptodate(device))
		return 0;
	else
		return -EAGAIN;
}

static int drbd_open(struct block_device *bdev, fmode_t mode)
{
	struct drbd_device *device = bdev->bd_disk->private_data;
	struct drbd_resource *resource = device->resource;
	unsigned long flags;
	int rv = 0;

	kref_get(&device->kref);
	kref_debug_get(&device->kref_debug, 9);

	if (resource->res_opts.auto_promote) {
		enum drbd_state_rv rv;
		/* Allow opening in read-only mode on an unconnected secondary.
		   This avoids split brain when the drbd volume gets opened
		   temporarily by udev while it scans for PV signatures. */

		if (mode & FMODE_WRITE) {
			if (resource->role[NOW] == R_SECONDARY) {
				rv = try_to_promote(device);
				if (rv < SS_SUCCESS)
					drbd_info(resource, "Auto-promote failed: %s\n",
					drbd_set_st_err_str(rv));
			}
		}
		else /* READ access only */ {
#ifdef _WIN32
			long timeo;
			wait_event_interruptible_timeout(timeo, resource->state_wait,
				ro_open_cond(device) != -EAGAIN,
				resource->res_opts.auto_promote_timeout * HZ / 10);
#else 
			wait_event_interruptible_timeout(resource->state_wait,
				ro_open_cond(device) != -EAGAIN,
				resource->res_opts.auto_promote_timeout * HZ / 10);
#endif 
		}
	} else if (resource->role[NOW] != R_PRIMARY && !(mode & FMODE_WRITE) && !allow_oos) {
		rv = -EMEDIUMTYPE;
		goto out;
	}

	down(&resource->state_sem);
	/* drbd_set_role() should be able to rely on nobody increasing rw_cnt */

	spin_lock_irqsave(&resource->req_lock, flags);
	/* to have a stable role and no race with updating open_cnt */

	if (test_bit(UNREGISTERED, &device->flags))
		rv = -ENODEV;

	if (mode & FMODE_WRITE) {
		if (resource->role[NOW] != R_PRIMARY)
			rv = -EROFS;
	} else /* READ access only */ {
		if (!any_disk_is_uptodate(device) ||
		    (resource->role[NOW] != R_PRIMARY &&
		     primary_peer_present(resource) &&
		     !allow_oos))
			rv = -EMEDIUMTYPE;
	}

	if (!rv) {
		kref_get(&device->kref);
		kref_debug_get(&device->kref_debug, 3);
		if (mode & FMODE_WRITE)
			device->open_rw_cnt++;
		else
			device->open_ro_cnt++;
	}
	spin_unlock_irqrestore(&resource->req_lock, flags);
	up(&resource->state_sem);

out:
	kref_debug_put(&device->kref_debug, 9);
	kref_put(&device->kref, drbd_destroy_device);

	return rv;
}

static void open_counts(struct drbd_resource *resource, int *rw_count_ptr, int *ro_count_ptr)
{
	struct drbd_device *device;
	int vnr, rw_count = 0, ro_count = 0;

#ifdef _WIN32
	idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr){
#else
	idr_for_each_entry(&resource->devices, device, vnr){
#endif
		rw_count += device->open_rw_cnt;
		ro_count += device->open_ro_cnt;
	}
	*rw_count_ptr = rw_count;
	*ro_count_ptr = ro_count;
}

static DRBD_RELEASE_RETURN drbd_release(struct gendisk *gd, fmode_t mode)
{
	struct drbd_device *device = gd->private_data;
	struct drbd_resource *resource = device->resource;
	unsigned long flags;
	int open_rw_cnt, open_ro_cnt;

	spin_lock_irqsave(&resource->req_lock, flags);
	if (mode & FMODE_WRITE)
		device->open_rw_cnt--;
	else
		device->open_ro_cnt--;

	open_counts(resource, &open_rw_cnt, &open_ro_cnt);
	spin_unlock_irqrestore(&resource->req_lock, flags);

	if (open_ro_cnt == 0)
#ifdef _WIN32
		wake_up(&resource->state_wait);
#else
		wake_up_all(&resource->state_wait);
#endif

	if (resource->res_opts.auto_promote) {
		enum drbd_state_rv rv;

		if (open_rw_cnt == 0 &&
		    resource->role[NOW] == R_PRIMARY &&
		    !test_bit(EXPLICIT_PRIMARY, &resource->flags)) {
			rv = drbd_set_role(resource, R_SECONDARY, false, NULL);
			if (rv < SS_SUCCESS)
				drbd_warn(resource, "Auto-demote failed: %s\n",
					  drbd_set_st_err_str(rv));
		}
	}
	kref_debug_put(&device->kref_debug, 3);
	kref_put(&device->kref, drbd_destroy_device);  /* might destroy the resource as well */
#ifndef COMPAT_DRBD_RELEASE_RETURNS_VOID
	return 0;
#endif
}

/* need to hold resource->req_lock */
void drbd_queue_unplug(struct drbd_device *device)
{
	UNREFERENCED_PARAMETER(device);

#ifndef _WIN32
	struct drbd_resource *resource = device->resource;
	struct drbd_connection *connection;
	u64 dagtag_sector;

	dagtag_sector = resource->dagtag_sector;

	for_each_connection(connection, resource) {
		/* use the "next" slot */
		unsigned int i = !connection->todo.unplug_slot;
		connection->todo.unplug_dagtag_sector[i] = dagtag_sector;
		wake_up(&connection->sender_work.q_wait);
	}
#endif	
}

#ifdef blk_queue_plugged
static void drbd_unplug_fn(struct request_queue *q)
{
	struct drbd_device *device = q->queuedata;
	struct drbd_resource *resource = device->resource;

	/* unplug FIRST */
	/* note: q->queue_lock == resource->req_lock */
	spin_lock_irq(&resource->req_lock);
	blk_remove_plug(q);

	/* only if connected */
	drbd_queue_unplug(device);
	spin_unlock_irq(&resource->req_lock);

	drbd_kick_lo(device);
}
#endif

static void drbd_set_defaults(struct drbd_device *device)
{
	device->disk_state[NOW] = D_DISKLESS;
}

void drbd_cleanup_device(struct drbd_device *device)
{
	device->al_writ_cnt = 0;
	device->bm_writ_cnt = 0;
	device->read_cnt = 0;
	device->writ_cnt = 0;

	if (device->bitmap) {
		/* maybe never allocated. */
		drbd_bm_resize(device, 0, 1);
		drbd_bm_free(device->bitmap);
		device->bitmap = NULL;
	}

	clear_bit(AL_SUSPENDED, &device->flags);
	drbd_set_defaults(device);
}


static void drbd_destroy_mempools(void)
{
#ifndef _WIN32
	struct page *page;

	while (drbd_pp_pool) {
		page = drbd_pp_pool;
		drbd_pp_pool = page_chain_next(page);
		__free_page(page);
		drbd_pp_vacant--;
	}
#else
    drbd_pp_vacant = 0;
#endif
	/* D_ASSERT(device, atomic_read(&drbd_pp_vacant)==0); */

#ifndef _WIN32
	if (drbd_md_io_bio_set)
		bioset_free(drbd_md_io_bio_set);
#endif
	if (drbd_md_io_page_pool)
		mempool_destroy(drbd_md_io_page_pool);
#ifndef _WIN32
	if (drbd_ee_mempool)
		mempool_destroy(drbd_ee_mempool);
	if (drbd_request_mempool)
		mempool_destroy(drbd_request_mempool);
	if (drbd_ee_cache)
		kmem_cache_destroy(drbd_ee_cache);
	if (drbd_request_cache)
		kmem_cache_destroy(drbd_request_cache);
	if (drbd_bm_ext_cache)
		kmem_cache_destroy(drbd_bm_ext_cache);
	if (drbd_al_ext_cache)
		kmem_cache_destroy(drbd_al_ext_cache);
#endif

#ifndef _WIN32
	drbd_md_io_bio_set   = NULL;
	drbd_md_io_page_pool = NULL;
	drbd_ee_mempool      = NULL;
	drbd_request_mempool = NULL;
	drbd_ee_cache        = NULL;
	drbd_request_cache   = NULL;
	drbd_bm_ext_cache    = NULL;
	drbd_al_ext_cache    = NULL;
#else
	ExDeleteNPagedLookasideList(&drbd_bm_ext_cache);
	ExDeleteNPagedLookasideList(&drbd_al_ext_cache);
	ExDeleteNPagedLookasideList(&drbd_request_mempool);
	ExDeleteNPagedLookasideList(&drbd_ee_mempool);
#endif

	return;
}

static int drbd_create_mempools(void)
{
#ifndef _WIN32
	struct page *page;
#endif
	const int number = (DRBD_MAX_BIO_SIZE/PAGE_SIZE) * minor_count;
#ifndef _WIN32
	int i;
#endif

	/* prepare our caches and mempools */
#ifndef _WIN32
	drbd_request_mempool = NULL;
	drbd_ee_cache        = NULL;
	drbd_request_cache   = NULL;
	drbd_bm_ext_cache    = NULL;
	drbd_al_ext_cache    = NULL;
	drbd_pp_pool         = NULL;
#endif
	drbd_md_io_page_pool = NULL;
	drbd_md_io_bio_set   = NULL;

	/* caches */
#ifdef _WIN32
	ExInitializeNPagedLookasideList(&drbd_bm_ext_cache, NULL, NULL,
		0, sizeof(struct bm_extent), '28DW', 0);
	ExInitializeNPagedLookasideList(&drbd_al_ext_cache, NULL, NULL,
		0, sizeof(struct lc_element), '38DW', 0);
	ExInitializeNPagedLookasideList(&drbd_request_mempool, NULL, NULL,
		0, sizeof(struct drbd_request), '48DW', 0);
	ExInitializeNPagedLookasideList(&drbd_ee_mempool, NULL, NULL,
		0, sizeof(struct drbd_peer_request), '58DW', 0);
#else
	drbd_request_cache = kmem_cache_create(
		"drbd_req", sizeof(struct drbd_request), 0, 0, NULL);
	if (drbd_request_cache == NULL)
		goto Enomem;

	drbd_ee_cache = kmem_cache_create(
		"drbd_ee", sizeof(struct drbd_peer_request), 0, 0, NULL);
	if (drbd_ee_cache == NULL)
		goto Enomem;

	drbd_bm_ext_cache = kmem_cache_create(
		"drbd_bm", sizeof(struct bm_extent), 0, 0, NULL);
	if (drbd_bm_ext_cache == NULL)
		goto Enomem;

	drbd_al_ext_cache = kmem_cache_create(
		"drbd_al", sizeof(struct lc_element), 0, 0, NULL);
	if (drbd_al_ext_cache == NULL)
		goto Enomem;
#endif

	/* mempools */
#ifndef _WIN32
	drbd_md_io_bio_set = bioset_create(DRBD_MIN_POOL_PAGES, 0);
	if (drbd_md_io_bio_set == NULL)
		goto Enomem;
#endif
	drbd_md_io_page_pool = mempool_create_page_pool(DRBD_MIN_POOL_PAGES, 0);
	if (drbd_md_io_page_pool == NULL)
		goto Enomem;


#ifndef _WIN32
	drbd_request_mempool = mempool_create_slab_pool(number, drbd_request_cache);
	if (drbd_request_mempool == NULL)
		goto Enomem;

	drbd_ee_mempool = mempool_create_slab_pool(number, drbd_ee_cache);
	if (drbd_ee_mempool == NULL)
		goto Enomem;
#endif

	/* drbd's page pool */
	spin_lock_init(&drbd_pp_lock);

#ifndef _WIN32
	for (i = 0; i < number; i++) {
		page = alloc_page(GFP_HIGHUSER);
		if (!page)
			goto Enomem;
		set_page_chain_next_offset_size(page, drbd_pp_pool, 0, 0);
		drbd_pp_pool = page;
	}
#endif
	drbd_pp_vacant = number;

	return 0;

Enomem:
	drbd_destroy_mempools(); /* in case we allocated some */
	return -ENOMEM;
}

static void free_peer_device(struct drbd_peer_device *peer_device)
{
	lc_destroy(peer_device->resync_lru);
	kfree(peer_device->rs_plan_s);
	kfree(peer_device->conf);
	kfree(peer_device);
}

/* caution. no locking. */
void drbd_destroy_device(struct kref *kref)
{
	struct drbd_device *device = container_of(kref, struct drbd_device, kref);
	struct drbd_resource *resource = device->resource;
	struct drbd_peer_device *peer_device, *tmp;


	WDRBD_TRACE("%s\n", __FUNCTION__);

#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
	//DW-1911
	struct drbd_marked_replicate *marked_rl, *t;
	list_for_each_entry_safe(struct drbd_marked_replicate, marked_rl, t, &(device->marked_rl_list), marked_rl_list) {
		list_del(&marked_rl->marked_rl_list);
		kfree2(marked_rl);
	}
#endif

	/* cleanup stuff that may have been allocated during
	 * device (re-)configuration or state changes */
	if (device->this_bdev)
#ifdef _WIN32
		// DW-1109: put bdev when device is being destroyed.
	{
		// DW-1300: nullify drbd_device of volume extention when destroy drbd device.
		PVOLUME_EXTENSION pvext = device->this_bdev->bd_disk->pDeviceExtension;
		if (pvext &&
			pvext->dev)
		{
			unsigned char oldIRQL = ExAcquireSpinLockExclusive(&device->this_bdev->bd_disk->drbd_device_ref_lock);
			pvext->dev->bd_disk->drbd_device = NULL;
			ExReleaseSpinLockExclusive(&device->this_bdev->bd_disk->drbd_device_ref_lock, oldIRQL);
		}

		blkdev_put(device->this_bdev, 0);
		device->this_bdev = NULL;
	}
#else
		bdput(device->this_bdev);
#endif

	drbd_backing_dev_free(device, device->ldev);
	device->ldev = NULL;


	lc_destroy(device->act_log);
	for_each_peer_device_safe(peer_device, tmp, device) {
		kref_debug_put(&peer_device->connection->kref_debug, 3);
		kref_put(&peer_device->connection->kref, drbd_destroy_connection);
		free_peer_device(peer_device);
	}

	if (device->bitmap) { /* should no longer be there. */
		drbd_bm_free(device->bitmap);
		device->bitmap = NULL;
	}
	__free_page(device->md_io.page);
	put_disk(device->vdisk);
	blk_cleanup_queue(device->rq_queue);
#ifdef _WIN32
	device->vdisk = NULL;
	device->rq_queue = NULL;
#endif
	kref_debug_destroy(&device->kref_debug);

	kfree(device);

	kref_debug_put(&resource->kref_debug, 4);
	kref_put(&resource->kref, drbd_destroy_resource);
}

void drbd_destroy_resource(struct kref *kref)
{
	struct drbd_resource *resource = container_of(kref, struct drbd_resource, kref);

	WDRBD_TRACE("%s\n", __FUNCTION__);

	idr_destroy(&resource->devices);
#ifndef _WIN32
	free_cpumask_var(resource->cpu_mask);
#endif
	kfree(resource->name);
	kref_debug_destroy(&resource->kref_debug);
	kfree(resource);
#ifndef _WIN32
	module_put(THIS_MODULE);
#endif
}

void drbd_free_resource(struct drbd_resource *resource)
{
	struct queued_twopc *q, *q1;
	struct drbd_connection *connection, *tmp;

	del_timer_sync(&resource->queued_twopc_timer);

	spin_lock_irq(&resource->queued_twopc_lock);
#ifdef _WIN32
    list_for_each_entry_safe(struct queued_twopc, q, q1, &resource->queued_twopc, w.list) {
#else
	list_for_each_entry_safe(q, q1, &resource->queued_twopc, w.list) {
#endif
		list_del(&q->w.list);
		kref_put(&q->connection->kref, drbd_destroy_connection);
		kfree(q);
	}
	spin_unlock_irq(&resource->queued_twopc_lock);

	drbd_thread_stop(&resource->worker);

#ifdef _WIN32_MULTIVOL_THREAD
	mvolTerminateThread(&resource->WorkThreadInfo);
#endif

#ifdef _WIN32
	list_for_each_entry_safe(struct drbd_connection, connection, tmp, &resource->twopc_parents, twopc_parent_list) {
#else
	list_for_each_entry_safe(connection, tmp, &resource->twopc_parents, twopc_parent_list) {
#endif

#ifdef _WIN32 //DW-1480
		list_del(&connection->twopc_parent_list);
#endif
		kref_debug_put(&connection->kref_debug, 9);
		kref_put(&connection->kref, drbd_destroy_connection);
	}
#ifdef _WIN32
    if (resource->peer_ack_req)
        ExFreeToNPagedLookasideList(&drbd_request_mempool, resource->peer_ack_req);
#else
	mempool_free(resource->peer_ack_req, drbd_request_mempool);
#endif
	del_timer_sync(&resource->twopc_timer);
	del_timer_sync(&resource->peer_ack_timer);
	del_timer_sync(&resource->repost_up_to_date_timer);
	kref_debug_put(&resource->kref_debug, 8);
	kref_put(&resource->kref, drbd_destroy_resource);
}

/* One global retry thread, if we need to push back some bio and have it
 * reinserted through our make request function.
 */
 #ifdef _WIN32
// move to drbd_windows.h
struct retry_worker retry;
#else
static struct retry_worker {
	struct workqueue_struct *wq;
	struct work_struct worker;

	spinlock_t lock;
	struct list_head writes;
} retry;
#endif

void drbd_req_destroy_lock(struct kref *kref)
{
	struct drbd_request *req = container_of(kref, struct drbd_request, kref);
	struct drbd_resource *resource = req->device->resource;

	spin_lock_irq(&resource->req_lock);
	drbd_req_destroy(kref);
	spin_unlock_irq(&resource->req_lock);
}

static void do_retry(struct work_struct *ws)
{
	struct retry_worker *retry = container_of(ws, struct retry_worker, worker);
	LIST_HEAD(writes);
	struct drbd_request *req, *tmp;

	spin_lock_irq(&retry->lock);
	list_splice_init(&retry->writes, &writes);
	spin_unlock_irq(&retry->lock);
#ifdef _WIN32
    list_for_each_entry_safe(struct drbd_request,  req, tmp, &writes, tl_requests) {
#else
	list_for_each_entry_safe(req, tmp, &writes, tl_requests) {
#endif
		struct drbd_device *device = req->device;
		struct bio *bio = req->master_bio;
		ULONG_PTR start_jif = req->start_jif;
		bool expected;

		expected =
			expect(device, atomic_read(&req->completion_ref) == 0) &&
			expect(device, req->rq_state[0] & RQ_POSTPONED) &&
			expect(device, (req->rq_state[0] & RQ_LOCAL_PENDING) == 0 ||
			       (req->rq_state[0] & RQ_LOCAL_ABORTED) != 0);

		if (!expected)
			drbd_err(device, "req=%p completion_ref=%d rq_state=%x\n",
				req, atomic_read(&req->completion_ref),
				req->rq_state[0]);

		/* We still need to put one kref associated with the
		 * "completion_ref" going zero in the code path that queued it
		 * here.  The request object may still be referenced by a
		 * frozen local req->private_bio, in case we force-detached.
		 */
		kref_put(&req->kref, drbd_req_destroy_lock);

		/* A single suspended or otherwise blocking device may stall
		 * all others as well.  Fortunately, this code path is to
		 * recover from a situation that "should not happen":
		 * concurrent writes in multi-primary setup.
		 * In a "normal" lifecycle, this workqueue is supposed to be
		 * destroyed without ever doing anything.
		 * If it turns out to be an issue anyways, we can do per
		 * resource (replication group) or per device (minor) retry
		 * workqueues instead.
		 */

		/* We are not just doing generic_make_request(),
		 * as we want to keep the start_time information. */
		inc_ap_bio(device, bio_data_dir(bio));
		__drbd_make_request(device, bio, start_jif);
	}
}

/* called via drbd_req_put_completion_ref(),
 * holds resource->req_lock */
void drbd_restart_request(struct drbd_request *req)
{
	unsigned long flags;
	spin_lock_irqsave(&retry.lock, flags);
	WDRBD_INFO("req(%p) req->nq_ref (%d)\n", req, atomic_read(&req->nq_ref));

#ifdef _WIN32_NETQUEUED_LOG
	atomic_set(&req->nq_ref, 0);
	list_del_init(&req->nq_requests);	
#endif
	
	list_move_tail(&req->tl_requests, &retry.writes);
	spin_unlock_irqrestore(&retry.lock, flags);

	/* Drop the extra reference that would otherwise
	 * have been dropped by complete_master_bio.
	 * do_retry() needs to grab a new one. */
	dec_ap_bio(req->device, bio_data_dir(req->master_bio));

	queue_work(retry.wq, &retry.worker);
}


static void drbd_cleanup(void)
{
	/* first remove proc,
	 * drbdsetup uses it's presence to detect
	 * whether DRBD is loaded.
	 * If we would get stuck in proc removal,
	 * but have netlink already deregistered,
	 * some drbdsetup commands may wait forever
	 * for an answer.
	 */
#ifdef _WIN32
	// not support
#else
	if (drbd_proc)
		remove_proc_entry("drbd", NULL);
#endif

	if (retry.wq)
		destroy_workqueue(retry.wq);

#ifndef _WIN32
	drbd_genl_unregister();
#endif
//  _WIN32_V9_DEBUGFS: minord is cleanup at this point, required to analyze it.
	drbd_debugfs_cleanup();

	drbd_destroy_mempools();
#ifndef _WIN32
	drbd_unregister_blkdev(DRBD_MAJOR, "drbd");
#endif
	idr_destroy(&drbd_devices);

	pr_info("module cleanup done.\n");
}

#ifdef _WIN32
void drbd_cleanup_by_win_shutdown(PVOLUME_EXTENSION VolumeExtension)
{
    WDRBD_INFO("Shutdown: IRQL(%d) device(%ws) Name(%wZ)\n",
        KeGetCurrentIrql(), VolumeExtension->PhysicalDeviceName, &VolumeExtension->MountPoint);

    if (retry.wq)
        destroy_workqueue(retry.wq);
    retry.wq = NULL;

	gbShutdown = TRUE;
}
#endif
/**
 * drbd_congested() - Callback for the flusher thread
 * @congested_data:	User data
 * @bdi_bits:		Bits the BDI flusher thread is currently interested in
 *
 * Returns 1<<WB_async_congested and/or 1<<WB_sync_congested if we are congested.
 */
static int drbd_congested(void *congested_data, int bdi_bits)
{
	UNREFERENCED_PARAMETER(bdi_bits);
	UNREFERENCED_PARAMETER(congested_data);

#ifndef _WIN32
	struct request_queue *q;
#endif
	int r = 0;

#ifdef _WIN32
	
	// WDRBD: not support data socket congestion
	// In V8.x, drbd_congested is called at drbd_seq_show, but In V9.x, not called , maybe replace with DEBUGFS
#else
	if (!may_inc_ap_bio(device)) {
		/* DRBD has frozen IO */
		r = bdi_bits;
		goto out;
	}

	if (test_bit(CALLBACK_PENDING, &device->resource->flags)) {
		r |= (1 << WB_async_congested);
		/* Without good local data, we would need to read from remote,
		 * and that would need the worker thread as well, which is
		 * currently blocked waiting for that usermode helper to
		 * finish.
		 */
		if (!get_ldev_if_state(device, D_UP_TO_DATE))
			r |= (1 << WB_sync_congested);
		else
			put_ldev(device);
		r &= bdi_bits;
		goto out;
	}

	if (get_ldev(device)) {
#ifdef _WIN32
        // In Linux, this drbd_congested callback is not recalled by bdi_congested.
        // bdi_congested just return bdi->state managed by kernel 
        // and so, we should support a similar result compared to bdi->state on Windows 
        //   - BDI_write_congested,	/* The write queue is getting full */
        //   - BDI_read_congested,	/* The read queue is getting full */
        // WDRBD don't support (no congestion)
        r = 0;  
#else
		q = bdev_get_queue(device->ldev->backing_bdev);
		r = bdi_congested(q->backing_dev_info, bdi_bits);
#endif
		put_ldev(device);
	}
#ifdef _WIN32_SEND_BUFFING 
#if 0
    if (test_bit(NET_CONGESTED, &mdev->tconn->flags)) {
        reason = 'n';
    }
#endif
#else
	if (bdi_bits & (1 << WB_async_congested)) {
		struct drbd_peer_device *peer_device;

		rcu_read_lock();
		for_each_peer_device_rcu(peer_device, device) {
			if (test_bit(NET_CONGESTED, &peer_device->connection->transport.flags)) {
				r |= (1 << WB_async_congested);
				break;
			}
		}
		rcu_read_unlock();
	}
#endif

out:
#endif
	return r;
}

static void drbd_init_workqueue(struct drbd_work_queue* wq)
{
	spin_lock_init(&wq->q_lock);
	INIT_LIST_HEAD(&wq->q);
	init_waitqueue_head(&wq->q_wait);
}

struct completion_work {
	struct drbd_work w;
	struct completion done;
};

static int w_complete(struct drbd_work *w, int cancel)
{
	UNREFERENCED_PARAMETER(cancel);

	struct completion_work *completion_work =
		container_of(w, struct completion_work, w);

	complete(&completion_work->done);
	return 0;
}

void drbd_queue_work(struct drbd_work_queue *q, struct drbd_work *w)
{
	unsigned long flags;

	spin_lock_irqsave(&q->q_lock, flags);
	list_add_tail(&w->list, &q->q);
	spin_unlock_irqrestore(&q->q_lock, flags);
	wake_up(&q->q_wait);
}

#ifdef _WIN32 // DW-1103 down from kernel with timeout
void drbd_flush_workqueue_timeout(struct drbd_resource* resource, struct drbd_work_queue *work_queue)
{
	struct completion_work completion_work;
	if (get_t_state(&resource->worker) != RUNNING) {
		return;
	}
	completion_work.w.cb = w_complete;
	init_completion(&completion_work.done);
	drbd_queue_work(work_queue, &completion_work.w);
	while (wait_for_completion_timeout(&completion_work.done, 100 ) == -DRBD_SIGKILL) {
    	WDRBD_INFO("DRBD_SIGKILL occurs. Ignore and wait for real event\n");
	}
}
#endif

#ifndef _WIN32
void drbd_flush_workqueue(struct drbd_work_queue *work_queue)
#else
void drbd_flush_workqueue(struct drbd_resource* resource, struct drbd_work_queue *work_queue)
#endif
{
	struct completion_work completion_work;
	
	if (get_t_state(&resource->worker) != RUNNING) {
		WDRBD_INFO("drbd_flush_workqueue &resource->worker != RUNNING return resource:%p\n",resource);
		return;
	}
	completion_work.w.cb = w_complete;
	init_completion(&completion_work.done);
	drbd_queue_work(work_queue, &completion_work.w);
#ifdef _WIN32 
	while (wait_for_completion(&completion_work.done) == -DRBD_SIGKILL) {
        WDRBD_INFO("DRBD_SIGKILL occurs. Ignore and wait for real event\n");
    }	
#else
	wait_for_completion(&completion_work.done);
#endif
}

struct drbd_resource *drbd_find_resource(const char *name)
{
	struct drbd_resource *resource;

	if (!name || !name[0])
		return NULL;

	rcu_read_lock();
	for_each_resource_rcu(resource, &drbd_resources) {
		if (!strcmp(resource->name, name)) {
			kref_get(&resource->kref);
			goto found;
		}
	}
	resource = NULL;
found:
	rcu_read_unlock();
	return resource;
}

static void drbd_put_send_buffers(struct drbd_connection *connection)
{
	unsigned int i;

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		if (connection->send_buffer[i].page) {
#ifndef _WIN32
			put_page(connection->send_buffer[i].page);
#endif
			//DW-1791 fix memory leak 
			__free_page(connection->send_buffer[i].page);
			connection->send_buffer[i].page = NULL;
		}
	}
}

static int drbd_alloc_send_buffers(struct drbd_connection *connection)
{
	unsigned int i;

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		struct page *page;

		page = alloc_page(GFP_KERNEL);
		if (!page) {
			drbd_put_send_buffers(connection);
			return -ENOMEM;
		}
		connection->send_buffer[i].page = page;
		connection->send_buffer[i].unsent =
		connection->send_buffer[i].pos = page_address(page);
	}

	return 0;
}

void drbd_flush_peer_acks(struct drbd_resource *resource)
{
	spin_lock_irq(&resource->req_lock);
	if (resource->peer_ack_req) {
		resource->last_peer_acked_dagtag = resource->peer_ack_req->dagtag_sector;
		drbd_queue_peer_ack(resource, resource->peer_ack_req);
		resource->peer_ack_req = NULL;
	}
	spin_unlock_irq(&resource->req_lock);
}
#ifdef _WIN32
static void peer_ack_timer_fn(PKDPC Dpc, PVOID data, PVOID arg1, PVOID arg2)
#else
static void peer_ack_timer_fn(unsigned long data)
#endif
{
	UNREFERENCED_PARAMETER(arg1);
	UNREFERENCED_PARAMETER(arg2);
	UNREFERENCED_PARAMETER(Dpc);

	struct drbd_resource *resource = (struct drbd_resource *) data;

	drbd_flush_peer_acks(resource);
}

void conn_free_crypto(struct drbd_connection *connection)
{
	crypto_free_hash(connection->csums_tfm);
	crypto_free_hash(connection->verify_tfm);
	crypto_free_hash(connection->cram_hmac_tfm);
	crypto_free_hash(connection->integrity_tfm);
	crypto_free_hash(connection->peer_integrity_tfm);
	kfree(connection->int_dig_in);
	kfree(connection->int_dig_vv);

	connection->csums_tfm = NULL;
	connection->verify_tfm = NULL;
	connection->cram_hmac_tfm = NULL;
	connection->integrity_tfm = NULL;
	connection->peer_integrity_tfm = NULL;
	connection->int_dig_in = NULL;
	connection->int_dig_vv = NULL;
}

void wake_all_device_misc(struct drbd_resource *resource)
{
	struct drbd_device *device;
	int vnr;
	rcu_read_lock();
#ifdef _WIN32
	idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr)
#else
	idr_for_each_entry(&resource->devices, device, vnr)
#endif
		wake_up(&device->misc_wait);
	rcu_read_unlock();
}

int set_resource_options(struct drbd_resource *resource, struct res_opts *res_opts)
{
#ifdef _WIN32
    resource->res_opts = *res_opts;
	return 0;
#else
	struct drbd_connection *connection;
	cpumask_var_t new_cpu_mask;
	int err;
	bool wake_device_misc = false;

	if (!zalloc_cpumask_var(&new_cpu_mask, GFP_KERNEL))
		return -ENOMEM;

	/* silently ignore cpu mask on UP kernel */
	if (nr_cpu_ids > 1 && res_opts->cpu_mask[0] != 0) {
		err = bitmap_parse(res_opts->cpu_mask, DRBD_CPU_MASK_SIZE,
				   cpumask_bits(new_cpu_mask), nr_cpu_ids);
		if (err == -EOVERFLOW) {
			/* So what. mask it out. */
			cpumask_var_t tmp_cpu_mask;
			if (zalloc_cpumask_var(&tmp_cpu_mask, GFP_KERNEL)) {
				cpumask_setall(tmp_cpu_mask);
				cpumask_and(new_cpu_mask, new_cpu_mask, tmp_cpu_mask);
				drbd_warn(resource, "Overflow in bitmap_parse(%.12s%s), truncating to %u bits\n",
					res_opts->cpu_mask,
					strlen(res_opts->cpu_mask) > 12 ? "..." : "",
					nr_cpu_ids);
				free_cpumask_var(tmp_cpu_mask);
				err = 0;
			}
		}
		if (err) {
			drbd_warn(resource, "bitmap_parse() failed with %d\n", err);
			/* retcode = ERR_CPU_MASK_PARSE; */
			goto fail;
		}
	}
	if (res_opts->nr_requests < DRBD_NR_REQUESTS_MIN)
		res_opts->nr_requests = DRBD_NR_REQUESTS_MIN;
	if (resource->res_opts.nr_requests < res_opts->nr_requests)
		wake_device_misc = true;
	
	resource->res_opts = *res_opts;
	if (cpumask_empty(new_cpu_mask))
		drbd_calc_cpu_mask(&new_cpu_mask);
	if (!cpumask_equal(resource->cpu_mask, new_cpu_mask)) {
		cpumask_copy(resource->cpu_mask, new_cpu_mask);
		rcu_read_lock();
		for_each_connection_rcu(connection, resource) {
			connection->receiver.reset_cpu_mask = 1;
			connection->ack_receiver.reset_cpu_mask = 1;
			connection->sender.reset_cpu_mask = 1;
		}
		rcu_read_unlock();
	}
	err = 0;
	if (wake_device_misc)
		wake_all_device_misc(resource);
	
fail:
	free_cpumask_var(new_cpu_mask);
	return err;
#endif
}

struct drbd_resource *drbd_create_resource(const char *name,
					   struct res_opts *res_opts)
{
	struct drbd_resource *resource;

#ifdef _WIN32
    resource = kzalloc(sizeof(struct drbd_resource), GFP_KERNEL, 'A0DW');
	resource->bPreSecondaryLock = FALSE;
	resource->bPreDismountLock = FALSE;
	atomic_set(&resource->bGetVolBitmapDone, true);
#else
	resource = kzalloc(sizeof(struct drbd_resource), GFP_KERNEL);
#endif
	if (!resource)
		goto fail;
	resource->name = kstrdup(name, GFP_KERNEL);
	if (!resource->name)
		goto fail_free_resource;
#ifndef _WIN32
	if (!zalloc_cpumask_var(&resource->cpu_mask, GFP_KERNEL))
		goto fail_free_name;
#endif
	kref_init(&resource->kref);
	kref_debug_init(&resource->kref_debug, &resource->kref, &kref_class_resource);
	idr_init(&resource->devices);
	INIT_LIST_HEAD(&resource->connections);
	INIT_LIST_HEAD(&resource->transfer_log);

#ifdef _WIN32_NETQUEUED_LOG
	INIT_LIST_HEAD(&resource->net_queued_log);
#endif	
	
	INIT_LIST_HEAD(&resource->peer_ack_list);
#ifdef _WIN32
    setup_timer(&resource->peer_ack_timer, peer_ack_timer_fn, resource);
	setup_timer(&resource->repost_up_to_date_timer, repost_up_to_date_fn, resource);
#else
	setup_timer(&resource->peer_ack_timer, peer_ack_timer_fn, (unsigned long) resource);
	setup_timer(&resource->repost_up_to_date_timer, repost_up_to_date_fn, (unsigned long)resource);
#endif
	sema_init(&resource->state_sem, 1);
	resource->role[NOW] = R_SECONDARY;
	if (set_resource_options(resource, res_opts))
		goto fail_free_name;
	resource->max_node_id = res_opts->node_id;
	resource->twopc_reply.initiator_node_id = -1;
	mutex_init(&resource->conf_update);
	mutex_init(&resource->adm_mutex);
#ifdef _WIN32
	// DW-1317
	mutex_init(&resource->vol_ctl_mutex);
#endif
	spin_lock_init(&resource->req_lock);
	INIT_LIST_HEAD(&resource->listeners);
	spin_lock_init(&resource->listeners_lock);
	init_waitqueue_head(&resource->state_wait);
	init_waitqueue_head(&resource->twopc_wait);
	init_waitqueue_head(&resource->barrier_wait);
	INIT_LIST_HEAD(&resource->twopc_parents);
#ifdef _WIN32
    setup_timer(&resource->twopc_timer, twopc_timer_fn, resource);
#else
	setup_timer(&resource->twopc_timer, twopc_timer_fn, (unsigned long) resource);
#endif
	INIT_LIST_HEAD(&resource->twopc_work.list);
	INIT_LIST_HEAD(&resource->queued_twopc);
	spin_lock_init(&resource->queued_twopc_lock);
#ifdef _WIN32
    setup_timer(&resource->queued_twopc_timer, queued_twopc_timer_fn, resource);
#else
	setup_timer(&resource->queued_twopc_timer, queued_twopc_timer_fn, (unsigned long) resource);
#endif
	drbd_init_workqueue(&resource->work);
	drbd_thread_init(resource, &resource->worker, drbd_worker, "worker");
	drbd_thread_start(&resource->worker);
	drbd_debugfs_resource_add(resource);

	list_add_tail_rcu(&resource->resources, &drbd_resources);

	atomic_set(&resource->req_write_cnt, 0);

	return resource;

fail_free_name:
	kfree(resource->name);
fail_free_resource:
	kfree(resource);
fail:
	return NULL;
}

/* caller must be under adm_mutex */
struct drbd_connection *drbd_create_connection(struct drbd_resource *resource,
					       struct drbd_transport_class *tc)
{
	struct drbd_connection *connection;
	int size;

	size = sizeof(*connection) - sizeof(connection->transport) + tc->instance_size;
#ifdef _WIN32
    connection = kzalloc(size, GFP_KERNEL, 'D0DW');
#else
	connection = kzalloc(size, GFP_KERNEL);
#endif
	if (!connection)
		return NULL;

	if (drbd_alloc_send_buffers(connection))
		goto fail;

#ifdef _WIN32
    connection->current_epoch = kzalloc(sizeof(struct drbd_epoch), GFP_KERNEL, 'E0DW');
#else
	connection->current_epoch = kzalloc(sizeof(struct drbd_epoch), GFP_KERNEL);
#endif
	if (!connection->current_epoch)
		goto fail;

	INIT_LIST_HEAD(&connection->current_epoch->list);
	connection->epochs = 1;
	spin_lock_init(&connection->epoch_lock);

	INIT_LIST_HEAD(&connection->todo.work_list);
	connection->todo.req = NULL;

	atomic_set64(&connection->ap_in_flight, 0);
	atomic_set64(&connection->rs_in_flight, 0);
	connection->send.seen_any_write_yet = false;
	connection->send.current_epoch_nr = 0;
	connection->send.current_epoch_writes = 0;
	connection->send.current_dagtag_sector = 0;

	connection->cstate[NOW] = C_STANDALONE;
	connection->peer_role[NOW] = R_UNKNOWN;
	init_waitqueue_head(&connection->ping_wait);
	idr_init(&connection->peer_devices);

	drbd_init_workqueue(&connection->sender_work);
	mutex_init(&connection->mutex[DATA_STREAM]);
	mutex_init(&connection->mutex[CONTROL_STREAM]);

	INIT_LIST_HEAD(&connection->connect_timer_work.list);
#ifdef _WIN32
	setup_timer(&connection->connect_timer, connect_timer_fn, connection);
#else
	setup_timer(&connection->connect_timer,
		    connect_timer_fn,
		    (unsigned long) connection);
#endif
	drbd_thread_init(resource, &connection->receiver, drbd_receiver, "receiver");
	connection->receiver.connection = connection;
	drbd_thread_init(resource, &connection->sender, drbd_sender, "sender");
	connection->sender.connection = connection;
	drbd_thread_init(resource, &connection->ack_receiver, drbd_ack_receiver, "ack_recv");
	connection->ack_receiver.connection = connection;
	INIT_LIST_HEAD(&connection->peer_requests);
	INIT_LIST_HEAD(&connection->connections);
	INIT_LIST_HEAD(&connection->active_ee);
	INIT_LIST_HEAD(&connection->sync_ee);
	INIT_LIST_HEAD(&connection->read_ee);
	INIT_LIST_HEAD(&connection->net_ee);
	INIT_LIST_HEAD(&connection->done_ee);
	INIT_LIST_HEAD(&connection->inactive_ee);	// DW-1696
	atomic_set(&connection->inacitve_ee_cnt, 0); // DW-1935
	init_waitqueue_head(&connection->ee_wait);

	kref_init(&connection->kref);
	kref_debug_init(&connection->kref_debug, &connection->kref, &kref_class_connection);

	INIT_WORK(&connection->peer_ack_work, drbd_send_peer_ack_wf);
	INIT_WORK(&connection->send_acks_work, drbd_send_acks_wf);

	kref_get(&resource->kref);
	kref_debug_get(&resource->kref_debug, 3);
	connection->resource = resource;

	INIT_LIST_HEAD(&connection->transport.paths);
	connection->transport.log_prefix = resource->name;
	if (tc->init(&connection->transport))
		goto fail;

	return connection;

fail:
	drbd_put_send_buffers(connection);
	kfree(connection->current_epoch);
	kfree(connection);

	return NULL;
}

/* free the transport specific members (e.g., sockets) of a connection */
void drbd_transport_shutdown(struct drbd_connection *connection, enum drbd_tr_free_op op)
{
#ifdef _WIN32
	// redefine struct drbd_tcp_transport, buffer. required to refactoring about base, pos field 
	struct buffer {
		void *base;
		void *pos;
	};

	struct drbd_tcp_transport {
		struct drbd_transport transport; /* Must be first! */
		spinlock_t paths_lock;
		ULONG_PTR flags;
		struct socket *stream[2];
		struct buffer rbuf[2];
	};

	// set socket quit signal first
	struct drbd_tcp_transport *tcp_transport =
		container_of(&connection->transport, struct drbd_tcp_transport, transport);
	if (tcp_transport)
	{
		if (tcp_transport->stream[DATA_STREAM])
			tcp_transport->stream[DATA_STREAM]->buffering_attr.quit = TRUE;

		if (tcp_transport->stream[CONTROL_STREAM])
			tcp_transport->stream[CONTROL_STREAM]->buffering_attr.quit = TRUE;
	}
	// this logic must be done before mutex lock(next line) is acuquired
#endif

	mutex_lock(&connection->mutex[DATA_STREAM]);
	mutex_lock(&connection->mutex[CONTROL_STREAM]);

#ifdef	_WIN32_SEND_BUFFING
	// bab is freed at ops->free (sock_release). and so, send-buffering threads must be terminated prior to ops->free.  
	// CONNECTION_RESET is occured at this point by stop_send_buffring 
	// connection->transport.ops->stop_send_buffring(&connection->transport);
#endif
	connection->transport.ops->free(&connection->transport, op);
#ifndef _WIN32
	if (op == DESTROY_TRANSPORT)
		drbd_put_transport_class(connection->transport.class);
#endif
	mutex_unlock(&connection->mutex[CONTROL_STREAM]);
	mutex_unlock(&connection->mutex[DATA_STREAM]);
}

void drbd_destroy_path(struct kref *kref)
{
	struct drbd_path *path = container_of(kref, struct drbd_path, kref);

	kfree(path);
}

void drbd_destroy_connection(struct kref *kref)
{
	struct drbd_connection *connection = container_of(kref, struct drbd_connection, kref);
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	int vnr;

	drbd_info(connection, "%s\n", __FUNCTION__);

	if (atomic_read(&connection->current_epoch->epoch_size) !=  0)
		drbd_err(connection, "epoch_size:%d\n", atomic_read(&connection->current_epoch->epoch_size));
	kfree(connection->current_epoch);

	// DW-1935 if the inactive_ee is not removed, a memory leak may occur, but BSOD may occur when removing it, so do not remove it. (priority of BSOD is higher than memory leak.)
	//	inacitve_ee processing logic not completed is required (cancellation, etc.)
	if (atomic_read(&connection->inacitve_ee_cnt)) {
		struct drbd_peer_request *peer_req, *t;
		drbd_info(connection, "inactive_ee count not completed:%d\n", atomic_read(&connection->inacitve_ee_cnt));

		spin_lock(&g_inactive_lock);
		list_for_each_entry_safe(struct drbd_peer_request, peer_req, t, &connection->inactive_ee, w.list) {
			set_bit(__EE_WAS_LOST_REQ, &peer_req->flags);
		}
		spin_unlock(&g_inactive_lock);
	}

#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		kref_debug_put(&peer_device->device->kref_debug, 1);

#ifdef _WIN32 // DW-1598 : set CONNECTION_ALREADY_FREED flags 
		set_bit(CONNECTION_ALREADY_FREED, &peer_device->flags); 
#endif
		kref_put(&peer_device->device->kref, drbd_destroy_device);
		free_peer_device(peer_device);

		//DW-1791 fix memory leak
		//DW-1934 remove unnecessary lock 
		idr_remove(&connection->peer_devices, vnr);
	}


	idr_destroy(&connection->peer_devices);

	kfree(connection->transport.net_conf);
	drbd_put_send_buffers(connection);
	conn_free_crypto(connection);
	kref_debug_destroy(&connection->kref_debug);
	//
	// destroy_bab
	//
	destroy_bab(connection);
	
	kfree(connection);
	kref_debug_put(&resource->kref_debug, 3);
	kref_put(&resource->kref, drbd_destroy_resource);
}

struct drbd_peer_device *create_peer_device(struct drbd_device *device, struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int err;
#ifdef _WIN32
    peer_device = kzalloc(sizeof(struct drbd_peer_device), GFP_KERNEL, 'F0DW');
#else
	peer_device = kzalloc(sizeof(struct drbd_peer_device), GFP_KERNEL);
#endif
	if (!peer_device)
		return NULL;

	peer_device->connection = connection;
	peer_device->device = device;
	peer_device->disk_state[NOW] = D_UNKNOWN;
	peer_device->repl_state[NOW] = L_OFF;
	peer_device->bm_ctx.count = 0;
	spin_lock_init(&peer_device->peer_seq_lock);

	//DW-1806 default value is TRUE
	KeInitializeEvent(&peer_device->state_initial_send_event, NotificationEvent, TRUE);
	err = drbd_create_peer_device_default_config(peer_device);
	if (err) {
		kfree(peer_device);
		return NULL;
	}

#ifndef _WIN32
	init_timer(&peer_device->start_resync_timer);
#endif
	peer_device->start_resync_timer.function = start_resync_timer_fn;
#ifdef _WIN32
    peer_device->start_resync_timer.data = peer_device;
#else
	peer_device->start_resync_timer.data = (unsigned long) peer_device;
#endif

	INIT_LIST_HEAD(&peer_device->resync_work.list);
	peer_device->resync_work.cb  = w_resync_timer;
#ifndef _WIN32
	init_timer(&peer_device->resync_timer);
#endif
	peer_device->resync_timer.function = resync_timer_fn;
#ifdef _WIN32
    peer_device->resync_timer.data = peer_device;
#else
	peer_device->resync_timer.data = (unsigned long) peer_device;
#endif
#ifdef _WIN32
    init_timer(&peer_device->start_resync_timer);
    init_timer(&peer_device->resync_timer);
#ifdef DBG
    memset(peer_device->start_resync_timer.name, 0, Q_NAME_SZ);
	strncpy(peer_device->start_resync_timer.name, "start_resync_timer", sizeof(peer_device->start_resync_timer.name) - 1);
    memset(peer_device->resync_timer.name, 0, Q_NAME_SZ);
	strncpy(peer_device->resync_timer.name, "resync_timer", sizeof(peer_device->resync_timer.name) - 1);
#endif
#endif

	INIT_LIST_HEAD(&peer_device->propagate_uuids_work.list);
	peer_device->propagate_uuids_work.cb = w_send_uuids;

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1191: to send disappeared out-of-sync which found when req_destroy.
	INIT_LIST_HEAD(&peer_device->send_oos_list);
	INIT_WORK(&peer_device->send_oos_work, drbd_send_out_of_sync_wf);
	spin_lock_init(&peer_device->send_oos_lock);
#endif

	// DW-2058
	atomic_set(&peer_device->rq_pending_oos_cnt, 0);

	atomic_set(&peer_device->ap_pending_cnt, 0);
	atomic_set(&peer_device->unacked_cnt, 0);
	atomic_set(&peer_device->rs_pending_cnt, 0);
	atomic_set(&peer_device->wait_for_actlog, 0);
	atomic_set(&peer_device->rs_sect_in, 0);	
	atomic_set(&peer_device->wait_for_recv_bitmap, 1);
	atomic_set(&peer_device->wait_for_recv_rs_reply, 0);

	peer_device->bitmap_index = -1;
	peer_device->resync_wenr = LC_FREE;
	peer_device->resync_finished_pdsk = D_UNKNOWN;

	return peer_device;
}

static int init_submitter(struct drbd_device *device)
{
	/* opencoded create_singlethread_workqueue(),
	 * to be able to use format string arguments */
	device->submit.wq =
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
#ifndef _WIN32
		alloc_ordered_workqueue("drbd%u_submit", WQ_MEM_RECLAIM, device->minor);
#else
		create_singlethread_workqueue("drbd_submit");
#endif
	if (!device->submit.wq)
		return -ENOMEM;
	INIT_WORK(&device->submit.worker, do_submit);
	INIT_LIST_HEAD(&device->submit.writes);
	INIT_LIST_HEAD(&device->submit.peer_writes);
	return 0;
}

enum drbd_ret_code drbd_create_device(struct drbd_config_context *adm_ctx, unsigned int minor,
				      struct device_conf *device_conf, struct drbd_device **p_device)
{
	struct drbd_resource *resource = adm_ctx->resource;
	struct drbd_connection *connection;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device, *tmp_peer_device;
	struct gendisk *disk;
#ifdef _WIN32
    struct request_queue *q = NULL;
#else
	struct request_queue *q;
#endif
	LIST_HEAD(peer_devices);
	LIST_HEAD(tmp);
	int id;
	int vnr = adm_ctx->volume;
	enum drbd_ret_code err = ERR_NOMEM;
	bool locked = false;
#ifdef _WIN32
    if ((minor < 1) || (minor > MINORMASK))
        return ERR_INVALID_REQUEST;
#endif
	device = minor_to_device(minor);
	if (device)
		return ERR_MINOR_OR_VOLUME_EXISTS;

	/* GFP_KERNEL, we are outside of all write-out paths */
#ifdef _WIN32
    device = kzalloc(sizeof(struct drbd_device), GFP_KERNEL, '01DW');
#else
	device = kzalloc(sizeof(struct drbd_device), GFP_KERNEL);
#endif
	if (!device)
		return ERR_NOMEM;
	kref_init(&device->kref);
	kref_debug_init(&device->kref_debug, &device->kref, &kref_class_device);

	kref_get(&resource->kref);
	kref_debug_get(&resource->kref_debug, 4);
	device->resource = resource;
	device->minor = minor;
	device->vnr = vnr;
	device->device_conf = *device_conf;

#ifdef PARANOIA
	SET_MDEV_MAGIC(device);
#endif

	drbd_set_defaults(device);

	atomic_set(&device->ap_bio_cnt[READ], 0);
	atomic_set(&device->ap_bio_cnt[WRITE], 0);
	atomic_set(&device->ap_actlog_cnt, 0);
	atomic_set(&device->local_cnt, 0);
	atomic_set(&device->rs_sect_ev, 0);
	atomic_set(&device->md_io.in_use, 0);

	spin_lock_init(&device->al_lock);
	mutex_init(&device->bm_resync_fo_mutex);
	mutex_init(&device->resync_pending_fo_mutex);
#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
	//DW-1901
	INIT_LIST_HEAD(&device->marked_rl_list);
	//DW-2042
	INIT_LIST_HEAD(&device->resync_pending_sectors);

	device->s_rl_bb = UINT64_MAX;
	device->e_rl_bb = 0;
	device->e_resync_bb = 0;
#endif
	INIT_LIST_HEAD(&device->pending_master_completion[0]);
	INIT_LIST_HEAD(&device->pending_master_completion[1]);
	INIT_LIST_HEAD(&device->pending_completion[0]);
	INIT_LIST_HEAD(&device->pending_completion[1]);

	
	atomic_set(&device->pending_bitmap_work.n, 0);
	spin_lock_init(&device->pending_bitmap_work.q_lock);
	INIT_LIST_HEAD(&device->pending_bitmap_work.q);

#ifndef _WIN32
	init_timer(&device->md_sync_timer);
	init_timer(&device->request_timer);
#endif
	device->md_sync_timer.function = md_sync_timer_fn;
#ifdef _WIN32
    device->md_sync_timer.data = device;
#else
	device->md_sync_timer.data = (unsigned long) device;
#endif
	device->request_timer.function = request_timer_fn;
#ifdef _WIN32
    device->request_timer.data = device;
#else
	device->request_timer.data = (unsigned long) device;
#endif

#ifdef _WIN32
    init_timer(&device->md_sync_timer);
    init_timer(&device->request_timer);
#ifdef DBG
    memset(device->md_sync_timer.name, 0, Q_NAME_SZ);
	strncpy(device->md_sync_timer.name, "md_sync_timer", sizeof(device->md_sync_timer.name) - 1);
    memset(device->request_timer.name, 0, Q_NAME_SZ);
	strncpy(device->request_timer.name, "request_timer", sizeof(device->request_timer.name) - 1);
#endif
#endif
	init_waitqueue_head(&device->misc_wait);
	init_waitqueue_head(&device->al_wait);
	init_waitqueue_head(&device->seq_wait);
#ifdef _WIN32
	// DW-1698 Only when drbd_device is created, it requests to update information about target device To fixup the frequency of calls to update_targetdev
    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor, TRUE);
	if (!pvext) {
		err = ERR_NO_DISK;
		drbd_err(device, "%d: Device has no disk.\n", err);
		goto out_no_disk;
	}
#endif
	// DW-1109: don't get request queue and gendisk from volume extension, allocate new one. it will be destroyed in drbd_destroy_device.
	q = blk_alloc_queue(GFP_KERNEL);
	if (!q)
		goto out_no_q;
	device->rq_queue = q;
	q->queuedata   = device;
	disk = alloc_disk(1);
	if (!disk)
		goto out_no_disk;

	device->vdisk = disk;

	set_disk_ro(disk, true);
	disk->queue = q;
#ifndef _WIN32
	disk->major = DRBD_MAJOR;
	disk->first_minor = minor;
#endif
	disk->fops = &drbd_ops;
	_snprintf(disk->disk_name, sizeof(disk->disk_name) - 1, "drbd%u", minor);
	disk->private_data = device;
#ifndef _WIN32
	device->this_bdev = bdget(MKDEV(DRBD_MAJOR, minor));
	/* we have no partitions. we contain only ourselves. */
	device->this_bdev->bd_contains = device->this_bdev;
	init_bdev_info(q->backing_dev_info, drbd_congested, device);
#endif
#ifdef _WIN32
	kref_get(&pvext->dev->kref);
	device->this_bdev = pvext->dev;
	q->logical_block_size = 512;
	// DW-1406 max_hw_sectors must be valued as number of maximum sectors.
	// DW-1510 recalculate this_bdev->d_size
	q->max_hw_sectors = ( device->this_bdev->d_size = get_targetdev_volsize(pvext) ) >> 9;
	WDRBD_INFO("device:%p q->max_hw_sectors: %llu sectors, device->this_bdev->d_size: %llu bytes\n", device, q->max_hw_sectors, device->this_bdev->d_size);
#endif
	q->backing_dev_info.congested_fn = drbd_congested;
	q->backing_dev_info.congested_data = device;

	blk_queue_make_request(q, drbd_make_request);
#ifdef REQ_FLUSH
	blk_queue_flush(q, REQ_FLUSH | REQ_FUA);
#endif
#ifndef _WIN32
	blk_queue_bounce_limit(q, BLK_BOUNCE_ANY);
#ifdef COMPAT_HAVE_BLK_QUEUE_MERGE_BVEC
	blk_queue_merge_bvec(q, drbd_merge_bvec);
#endif
#endif
	q->queue_lock = &resource->req_lock; /* needed since we use */
#ifdef blk_queue_plugged
		/* plugging on a queue, that actually has no requests! */
	q->unplug_fn = drbd_unplug_fn;
#endif

	device->md_io.page = alloc_page(GFP_KERNEL);
	if (!device->md_io.page)
		goto out_no_io_page;

	device->bitmap = drbd_bm_alloc();
	if (!device->bitmap)
		goto out_no_bitmap;
	device->read_requests = RB_ROOT;
	device->write_requests = RB_ROOT;

	BUG_ON(!mutex_is_locked(&resource->conf_update));
	for_each_connection(connection, resource) {
		peer_device = create_peer_device(device, connection);
		if (!peer_device)
			goto out_no_peer_device;
		list_add(&peer_device->peer_devices, &peer_devices);
	}

	/* Insert the new device into all idrs under req_lock
	   to guarantee a consistent object model. idr_preload() doesn't help
	   because it can only guarantee that a single idr_alloc() will
	   succeed. This fails (and will be retried) if no memory is
	   immediately available.
	   Keep in mid that RCU readers might find the device in the moment
	   we add it to the resources->devices IDR!
	*/

	INIT_LIST_HEAD(&device->peer_devices);
	INIT_LIST_HEAD(&device->pending_bitmap_io);

	atomic_set(&device->io_error_count, 0);

	locked = true;
	spin_lock_irq(&resource->req_lock);
	id = idr_alloc(&drbd_devices, device, minor, minor + 1, GFP_NOWAIT);
	if (id < 0) {
		if (id == -ENOSPC)
			err = ERR_MINOR_OR_VOLUME_EXISTS;
		goto out_no_minor_idr;
	}
	kref_get(&device->kref);
	kref_debug_get(&device->kref_debug, 1);

	id = idr_alloc(&resource->devices, device, vnr, vnr + 1, GFP_NOWAIT);
	if (id < 0) {
		if (id == -ENOSPC)
			err = ERR_MINOR_OR_VOLUME_EXISTS;
		goto out_idr_remove_minor;
	}
	kref_get(&device->kref);
	kref_debug_get(&device->kref_debug, 1);

#ifdef _WIN32
    list_for_each_entry_safe(struct drbd_peer_device, peer_device, tmp_peer_device, &peer_devices, peer_devices) {
#else
	list_for_each_entry_safe(peer_device, tmp_peer_device, &peer_devices, peer_devices) {
#endif
		connection = peer_device->connection;
		id = idr_alloc(&connection->peer_devices, peer_device,
			       device->vnr, device->vnr + 1, GFP_NOWAIT);
		if (id < 0)
			goto out_remove_peer_device;
		list_del(&peer_device->peer_devices);
		list_add_rcu(&peer_device->peer_devices, &device->peer_devices);
		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 3);
		kref_get(&device->kref);
		kref_debug_get(&device->kref_debug, 1);
	}
	spin_unlock_irq(&resource->req_lock);
	locked = false;

	if (init_submitter(device)) {
		err = ERR_NOMEM;
		goto out_remove_peer_device;
	}
#ifndef _WIN32
	add_disk(disk);
#endif
	for_each_peer_device(peer_device, device) {
		connection = peer_device->connection;
		peer_device->node_id = connection->peer_node_id;

		if (connection->cstate[NOW] >= C_CONNECTED)
			drbd_connected(peer_device);
	}

	drbd_debugfs_device_add(device);
	*p_device = device;
	return NO_ERROR;

out_remove_peer_device:
#ifdef _WIN32
    {
        synchronize_rcu_w32_wlock();
#endif
	list_add_rcu(&tmp, &device->peer_devices);
	list_del_init(&device->peer_devices);
	synchronize_rcu();
#ifdef _WIN32
        list_for_each_entry_safe(struct drbd_peer_device, peer_device, tmp_peer_device, &tmp, peer_devices) {
#else
	list_for_each_entry_safe(peer_device, tmp_peer_device, &tmp, peer_devices) {
#endif
		struct drbd_connection *connection = peer_device->connection;

		kref_debug_put(&connection->kref_debug, 3);
		kref_put(&connection->kref, drbd_destroy_connection);
		idr_remove(&connection->peer_devices, device->vnr);
		list_del(&peer_device->peer_devices);
		kfree(peer_device);
	}
#ifdef _WIN32
    }
#endif
out_idr_remove_minor:
	idr_remove(&drbd_devices, minor);

out_no_minor_idr:
	if (locked)
		spin_unlock_irq(&resource->req_lock);
#ifndef _WIN32
	synchronize_rcu();
#endif

out_no_peer_device:
#ifdef _WIN32
    list_for_each_entry_safe(struct drbd_peer_device, peer_device, tmp_peer_device, &peer_devices, peer_devices) {
#else
	list_for_each_entry_safe(peer_device, tmp_peer_device, &peer_devices, peer_devices) {
#endif
		list_del(&peer_device->peer_devices);
		kfree(peer_device);
	}

	drbd_bm_free(device->bitmap);
out_no_bitmap:
	__free_page(device->md_io.page);
out_no_io_page:
#ifndef _WIN32 
	put_disk(disk);
#endif
out_no_disk:
	blk_cleanup_queue(q);
out_no_q:
	kref_put(&resource->kref, drbd_destroy_resource);
	kfree(device);
	return err;
}

/**
 * drbd_unregister_device()  -  make a device "invisible"
 *
 * Remove the device from the drbd object model and unregister it in the
 * kernel.  Keep reference counts on device->kref; they are dropped in
 * drbd_put_device().
 */
void drbd_unregister_device(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	struct drbd_connection *connection;
	struct drbd_peer_device *peer_device;

	spin_lock_irq(&resource->req_lock);
	for_each_connection(connection, resource) {
		idr_remove(&connection->peer_devices, device->vnr);
	}
	idr_remove(&resource->devices, device->vnr);
	idr_remove(&drbd_devices, device_to_minor(device));
	spin_unlock_irq(&resource->req_lock);

	for_each_peer_device(peer_device, device)
		drbd_debugfs_peer_device_cleanup(peer_device);
	drbd_debugfs_device_cleanup(device);
	del_gendisk(device->vdisk);
}

void drbd_put_device(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	int refs = 3;

	destroy_workqueue(device->submit.wq);
	device->submit.wq = NULL;
	del_timer_sync(&device->request_timer);

	for_each_peer_device(peer_device, device)
		refs++;

	kref_debug_sub(&device->kref_debug, refs, 1);
	kref_sub(&device->kref, refs, drbd_destroy_device);
}

/**
 * drbd_unregister_connection()  -  make a connection "invisible"
 *
 * Remove the connection from the drbd object model.  Keep reference counts on
 * connection->kref; they are dropped in drbd_put_connection().
 */
void drbd_unregister_connection(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	LIST_HEAD(work_list);
	int vnr;

	// DW-1933 repositioned req_lock to resolve deadlock.
	// DW-1943 req_lock spinlock should precede the rcu lock.
	// false the locked parameter at end_state_change_locked() in wdrbd causes synchronization problems, the parameter is false if it is locked by recq_lock spinlock.
	spin_lock_irq(&resource->req_lock);
#ifdef _WIN32
	// DW-1465 Requires rcu wlock because list_del_rcu().
	// DW-1933 move code from del_connection() here
	synchronize_rcu_w32_wlock();
#endif
	set_bit(C_UNREGISTERED, &connection->flags);
	smp_wmb();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		list_del_rcu(&peer_device->peer_devices);
		list_add(&peer_device->peer_devices, &work_list);
	}

#ifdef _WIN32
	synchronize_rcu();
#endif
	list_del_rcu(&connection->connections);
	spin_unlock_irq(&resource->req_lock);
#ifdef _WIN32
    list_for_each_entry(struct drbd_peer_device, peer_device, &work_list, peer_devices)
#else
	list_for_each_entry(peer_device, &work_list, peer_devices)
#endif
		drbd_debugfs_peer_device_cleanup(peer_device);
	drbd_debugfs_connection_cleanup(connection);
}

void del_connect_timer(struct drbd_connection *connection)
{
	if (del_timer_sync(&connection->connect_timer)) {
		kref_debug_put(&connection->kref_debug, 11);
		kref_put(&connection->kref, drbd_destroy_connection);
	}
}

void drbd_put_connection(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr, rr, refs = 1;

	del_connect_timer(connection);
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr)
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr)
#endif
		refs++;

	rr = drbd_free_peer_reqs(connection->resource, &connection->done_ee, false);
	if (rr)
		drbd_err(connection, "%d EEs in done list found!\n", rr);

	rr = drbd_free_peer_reqs(connection->resource, &connection->net_ee, true);
	if (rr)
		drbd_err(connection, "%d EEs in net list found!\n", rr);
	drbd_transport_shutdown(connection, DESTROY_TRANSPORT);

	kref_debug_sub(&connection->kref_debug, refs - 1, 3);
	kref_debug_put(&connection->kref_debug, 10);
	kref_sub(&connection->kref, refs, drbd_destroy_connection);
}

#ifdef _WIN32
int __init drbd_init(void)
#else
static int __init drbd_init(void)
#endif
{
	int err;
#ifdef _WIN32
	nl_policy_init_by_manual();
	g_rcuLock = 0; // init RCU lock
	
	mutex_init(&g_genl_mutex);
	// DW-1998
	g_genl_run_cmd = 0;
	mutex_init(&g_genl_run_cmd_mutex);

	mutex_init(&notification_mutex);
	mutex_init(&att_mod_mutex); 
	// DW-1935
	spin_lock_init(&g_inactive_lock);
#endif

#ifdef _WIN32
	ratelimit_state_init(&drbd_ratelimit_state, DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);
#endif

#ifdef _WIN32
	ct_init_thread_list();
#endif

	initialize_kref_debugging();

	if (minor_count < DRBD_MINOR_COUNT_MIN || minor_count > DRBD_MINOR_COUNT_MAX) {
		pr_err("invalid minor_count (%u)\n", minor_count);
#ifdef MODULE
		return -EINVAL;
#else
		minor_count = DRBD_MINOR_COUNT_DEF;
#endif
	}
#ifdef _WIN32
    // not supported
#else
	err = register_blkdev(DRBD_MAJOR, "drbd");
	if (err) {
		pr_err("unable to register block device major %d\n",
		       DRBD_MAJOR);
		return err;
	}
#endif
	/*
	 * allocate all necessary structs
	 */
#ifdef _WIN32 
	strncpy(drbd_pp_wait.eventName, "drbd_pp_wait", sizeof(drbd_pp_wait.eventName) - 1);
#endif
	init_waitqueue_head(&drbd_pp_wait);
#ifdef _WIN32
	// not support
#else
	drbd_proc = NULL; /* play safe for drbd_cleanup */
#endif
	idr_init(&drbd_devices);

	mutex_init(&resources_mutex);
	INIT_LIST_HEAD(&drbd_resources);
#ifdef _WIN32
	// not supported
#else
	err = drbd_genl_register();
	if (err) {
		pr_err("unable to register generic netlink family\n");
		goto fail;
	}
#endif

	err = drbd_create_mempools();
	if (err)
		goto fail;

	err = -ENOMEM;
#ifdef _WIN32
	// not supported
#else
	drbd_proc = proc_create_data("drbd", S_IFREG | S_IRUGO , NULL, &drbd_proc_fops, NULL);
	if (!drbd_proc)	{
		pr_err("unable to register proc file\n");
		goto fail;
	}
#endif
	retry.wq = create_singlethread_workqueue("drbd-reissue");
	if (!retry.wq) {
		pr_err("unable to create retry workqueue\n");
		goto fail;
	}
	INIT_WORK(&retry.worker, do_retry);
	spin_lock_init(&retry.lock);
	INIT_LIST_HEAD(&retry.writes);

#ifdef _WIN32
	// DW-1105: need to detect changing volume letter and adjust it to VOLUME_EXTENSION.	
	if (!NT_SUCCESS(start_mnt_monitor()))
	{
		WDRBD_ERROR("could not start mount monitor\n");
		goto fail;
	}
#endif
#ifndef _WIN32
	if (drbd_debugfs_init())
		pr_notice("failed to initialize debugfs -- will not be available\n");
#endif
	pr_info("initialized. "
	       "Version: " REL_VERSION " (api:%d/proto:%d-%d)\n",
	       GENL_MAGIC_VERSION, PRO_VERSION_MIN, PRO_VERSION_MAX);
	pr_info("%s\n", drbd_buildtag());
	pr_info("registered as block device major %d\n", DRBD_MAJOR);
	return 0; /* Success! */

fail:
	drbd_cleanup();
	if (err == -ENOMEM)
		pr_err("ran out of memory\n");
	else
		pr_err("initialization failure\n");
	return err;
}

/* meta data management */

void drbd_md_write(struct drbd_device *device, void *b)
{
	struct meta_data_on_disk_9 *buffer = b;
	sector_t sector;
	int i;

	memset(buffer, 0, sizeof(*buffer));

	buffer->effective_size = cpu_to_be64(device->ldev->md.effective_size);
	buffer->current_uuid = cpu_to_be64(device->ldev->md.current_uuid);
	buffer->flags = cpu_to_be32(device->ldev->md.flags);
	buffer->magic = cpu_to_be32(DRBD_MD_MAGIC_09);

	buffer->md_size_sect  = cpu_to_be32(device->ldev->md.md_size_sect);
	buffer->al_offset     = cpu_to_be32(device->ldev->md.al_offset);
	buffer->al_nr_extents = cpu_to_be32(device->act_log->nr_elements);
	buffer->bm_bytes_per_bit = cpu_to_be32(BM_BLOCK_SIZE);
	buffer->device_uuid = cpu_to_be64(device->ldev->md.device_uuid);

	buffer->bm_offset = cpu_to_be32(device->ldev->md.bm_offset);
	buffer->la_peer_max_bio_size = cpu_to_be32(device->device_conf.max_bio_size);
	buffer->bm_max_peers = cpu_to_be32(device->bitmap->bm_max_peers);
	buffer->node_id = cpu_to_be32(device->ldev->md.node_id);
	for (i = 0; i < DRBD_NODE_ID_MAX; i++) {
		struct drbd_peer_md *peer_md = &device->ldev->md.peers[i];

		buffer->peers[i].bitmap_uuid = cpu_to_be64(peer_md->bitmap_uuid);
		buffer->peers[i].bitmap_dagtag = cpu_to_be64(peer_md->bitmap_dagtag);
		buffer->peers[i].flags = cpu_to_be32(peer_md->flags);
		buffer->peers[i].bitmap_index = cpu_to_be32(peer_md->bitmap_index);
	}
	BUILD_BUG_ON(ARRAY_SIZE(device->ldev->md.history_uuids) != ARRAY_SIZE(buffer->history_uuids));
	for (i = 0; i < ARRAY_SIZE(buffer->history_uuids); i++)
		buffer->history_uuids[i] = cpu_to_be64(device->ldev->md.history_uuids[i]);

	buffer->al_stripes = cpu_to_be32(device->ldev->md.al_stripes);
	buffer->al_stripe_size_4k = cpu_to_be32(device->ldev->md.al_stripe_size_4k);

	D_ASSERT(device, drbd_md_ss(device->ldev) == device->ldev->md.md_offset);
	sector = device->ldev->md.md_offset;

	if (drbd_md_sync_page_io(device, device->ldev, sector, REQ_OP_WRITE)) {
		/* this was a try anyways ... */
		drbd_err(device, "meta data update failed!\n");
		drbd_chk_io_error(device, 1, DRBD_META_IO_ERROR);
	}
}

/**
 * __drbd_md_sync() - Writes the meta data super block (conditionally) if the MD_DIRTY flag bit is set
 * @device:    DRBD device.
 * @maybe:    meta data may in fact be "clean", the actual write may be skipped.
 */
static void __drbd_md_sync(struct drbd_device *device, bool maybe)
{
	struct meta_data_on_disk_9 *buffer;

	/* Don't accidentally change the DRBD meta data layout. */
	BUILD_BUG_ON(DRBD_PEERS_MAX != 32);
	BUILD_BUG_ON(HISTORY_UUIDS != 32);
	BUILD_BUG_ON(sizeof(struct meta_data_on_disk_9) != 4096);

	del_timer(&device->md_sync_timer);
	/* timer may be rearmed by drbd_md_mark_dirty() now. */
	if (!test_and_clear_bit(MD_DIRTY, &device->flags) && maybe)
		return;

	/* We use here D_FAILED and not D_ATTACHING because we try to write
	 * metadata even if we detach due to a disk failure! */
	if (!get_ldev_if_state(device, D_DETACHING))
		return;

	buffer = drbd_md_get_buffer(device, __func__);
	if (!buffer)
		goto out;

	drbd_md_write(device, buffer);

	drbd_md_put_buffer(device);
out:
	put_ldev(device);
}

void drbd_md_sync(struct drbd_device *device)
{
	__drbd_md_sync(device, false);
}

void drbd_md_sync_if_dirty(struct drbd_device *device)
{
	__drbd_md_sync(device, true);
}

static int check_activity_log_stripe_size(struct drbd_device *device,
		struct meta_data_on_disk_9 *on_disk,
		struct drbd_md *in_core)
{
	u32 al_stripes = be32_to_cpu(on_disk->al_stripes);
	u32 al_stripe_size_4k = be32_to_cpu(on_disk->al_stripe_size_4k);
	u64 al_size_4k;

	/* both not set: default to old fixed size activity log */
	if (al_stripes == 0 && al_stripe_size_4k == 0) {
		al_stripes = 1;
		al_stripe_size_4k = (32768 >> 9)/8;
	}

	/* some paranoia plausibility checks */

	/* we need both values to be set */
	if (al_stripes == 0 || al_stripe_size_4k == 0)
		goto err;

	al_size_4k = (u64)(al_stripes * al_stripe_size_4k);

	/* Upper limit of activity log area, to avoid potential overflow
	 * problems in al_tr_number_to_on_disk_sector(). As right now, more
	 * than 72 * 4k blocks total only increases the amount of history,
	 * limiting this arbitrarily to 16 GB is not a real limitation ;-)  */
	if (al_size_4k > (16 * 1024 * 1024/4))
		goto err;

	/* Lower limit: we need at least 8 transaction slots (32kB)
	 * to not break existing setups */
	if (al_size_4k < (32768 >> 9)/8)
		goto err;

	in_core->al_stripe_size_4k = al_stripe_size_4k;
	in_core->al_stripes = al_stripes;
	in_core->al_size_4k = (u32)al_size_4k;

	return 0;
err:
	drbd_err(device, "invalid activity log striping: al_stripes=%u, al_stripe_size_4k=%u\n",
			al_stripes, al_stripe_size_4k);
	return -EINVAL;
}

static int check_offsets_and_sizes(struct drbd_device *device,
		struct meta_data_on_disk_9 *on_disk,
		struct drbd_backing_dev *bdev)
{
#ifdef _WIN32 // DW-1607
	sector_t capacity = drbd_get_md_capacity(bdev->md_bdev);
#else
	sector_t capacity = drbd_get_capacity(bdev->md_bdev);
#endif
	struct drbd_md *in_core = &bdev->md;
	u32 max_peers = be32_to_cpu(on_disk->bm_max_peers);
	s32 on_disk_al_sect;
	s32 on_disk_bm_sect;

	if (max_peers > DRBD_PEERS_MAX) {
		drbd_err(device, "bm_max_peers too high\n");
		goto err;
	}
	device->bitmap->bm_max_peers = max_peers;

	in_core->al_offset = be32_to_cpu(on_disk->al_offset);
	in_core->bm_offset = be32_to_cpu(on_disk->bm_offset);
	in_core->md_size_sect = be32_to_cpu(on_disk->md_size_sect);

	/* The on-disk size of the activity log, calculated from offsets, and
	 * the size of the activity log calculated from the stripe settings,
	 * should match.
	 * Though we could relax this a bit: it is ok, if the striped activity log
	 * fits in the available on-disk activity log size.
	 * Right now, that would break how resize is implemented.
	 * TODO: make drbd_determine_dev_size() (and the drbdmeta tool) aware
	 * of possible unused padding space in the on disk layout. */
	if (in_core->al_offset < 0) {
		if (in_core->bm_offset > in_core->al_offset)
			goto err;
		on_disk_al_sect = -in_core->al_offset;
		on_disk_bm_sect = in_core->al_offset - in_core->bm_offset;
	} else {
		if (in_core->al_offset != (4096 >> 9))
			goto err;
		if (in_core->bm_offset < in_core->al_offset + (s32)in_core->al_size_4k * (4096 >> 9))
			goto err;

		on_disk_al_sect = in_core->bm_offset - (4096 >> 9);
		on_disk_bm_sect = in_core->md_size_sect - in_core->bm_offset;
	}

	/* old fixed size meta data is exactly that: fixed. */
	if (in_core->meta_dev_idx >= 0) {
#ifdef _WIN32 // DW-1335
		if (in_core->md_size_sect != (256 << 20 >> 9)
#else
		if (in_core->md_size_sect != (128 << 20 >> 9)
#endif
		||  in_core->al_offset != (4096 >> 9)
		||  in_core->bm_offset != (4096 >> 9) + (32768 >> 9)
		||  in_core->al_stripes != 1
		||  in_core->al_stripe_size_4k != (32768 >> 12))
			goto err;
	}

	if (capacity < in_core->md_size_sect)
		goto err;
	if (capacity - in_core->md_size_sect < drbd_md_first_sector(bdev))
		goto err;

	/* should be aligned, and at least 32k */
	if ((on_disk_al_sect & 7) || (on_disk_al_sect < (32768 >> 9)))
		goto err;

	/* should fit (for now: exactly) into the available on-disk space;
	 * overflow prevention is in check_activity_log_stripe_size() above. */
	if (on_disk_al_sect != (int)(in_core->al_size_4k * (4096 >> 9)))
		goto err;

	/* again, should be aligned */
	if (in_core->bm_offset & 7)
		goto err;

	/* FIXME check for device grow with flex external meta data? */

	/* can the available bitmap space cover the last agreed device size? */
	if (on_disk_bm_sect < drbd_capacity_to_on_disk_bm_sect(
				in_core->effective_size, max_peers))
		goto err;

	return 0;

err:
	drbd_err(device, "meta data offsets don't make sense: idx=%d "
			"al_s=%u, al_sz4k=%u, al_offset=%d, bm_offset=%d, "
			"md_size_sect=%u, la_size=%llu, md_capacity=%llu\n",
			in_core->meta_dev_idx,
			in_core->al_stripes, in_core->al_stripe_size_4k,
			in_core->al_offset, in_core->bm_offset, in_core->md_size_sect,
			(unsigned long long)in_core->effective_size,
			(unsigned long long)capacity);

	return -EINVAL;
}


/**
 * drbd_md_read() - Reads in the meta data super block
 * @device:	DRBD device.
 * @bdev:	Device from which the meta data should be read in.
 *
 * Return NO_ERROR on success, and an enum drbd_ret_code in case
 * something goes wrong.
 *
 * Called exactly once during drbd_adm_attach(), while still being D_DISKLESS,
 * even before @bdev is assigned to @device->ldev.
 */
int drbd_md_read(struct drbd_device *device, struct drbd_backing_dev *bdev)
{
	struct meta_data_on_disk_9 *buffer;
	u32 magic, flags;
	int i, rv = NO_ERROR;
	int my_node_id = device->resource->res_opts.node_id;
	u32 max_peers;

	if (device->disk_state[NOW] != D_DISKLESS)
		return ERR_DISK_CONFIGURED;

	buffer = drbd_md_get_buffer(device, __func__);
	if (!buffer)
		return ERR_NOMEM;

	/* First, figure out where our meta data superblock is located,
	 * and read it. */
	bdev->md.meta_dev_idx = bdev->disk_conf->meta_dev_idx;
	bdev->md.md_offset = drbd_md_ss(bdev);
	/* Even for (flexible or indexed) external meta data,
	 * initially restrict us to the 4k superblock for now.
	 * Affects the paranoia out-of-range access check in drbd_md_sync_page_io(). */
	bdev->md.md_size_sect = 8;

	if (drbd_md_sync_page_io(device, bdev, bdev->md.md_offset,
		REQ_OP_READ)) {
		/* NOTE: can't do normal error processing here as this is
		   called BEFORE disk is attached */
		drbd_err(device, "Error while reading metadata.\n");
		rv = ERR_IO_MD_DISK;
		goto err;
	}

	magic = be32_to_cpu(buffer->magic);
	flags = be32_to_cpu(buffer->flags);
	if (magic == DRBD_MD_MAGIC_09 && !(flags & MDF_AL_CLEAN)) {
			/* btw: that's Activity Log clean, not "all" clean. */
		drbd_err(device, "Found unclean meta data. Did you \"drbdadm apply-al\"?\n");
		rv = ERR_MD_UNCLEAN;
		goto err;
	}
	rv = ERR_MD_INVALID;
	if (magic != DRBD_MD_MAGIC_09) {
		if (magic == DRBD_MD_MAGIC_07 ||
		    magic == DRBD_MD_MAGIC_08 ||
		    magic == DRBD_MD_MAGIC_84_UNCLEAN)
			drbd_err(device, "Found old meta data magic. Did you \"drbdadm create-md\"?\n");
		else
			drbd_err(device, "Meta data magic not found. Did you \"drbdadm create-md\"?\n");
		goto err;
	}

	if (be32_to_cpu(buffer->bm_bytes_per_bit) != BM_BLOCK_SIZE) {
		drbd_err(device, "unexpected bm_bytes_per_bit: %u (expected %u)\n",
		    be32_to_cpu(buffer->bm_bytes_per_bit), BM_BLOCK_SIZE);
		goto err;
	}

	if (check_activity_log_stripe_size(device, buffer, &bdev->md))
		goto err;
	if (check_offsets_and_sizes(device, buffer, bdev))
		goto err;


	bdev->md.effective_size = be64_to_cpu(buffer->effective_size);
	bdev->md.current_uuid = be64_to_cpu(buffer->current_uuid);
	bdev->md.flags = be32_to_cpu(buffer->flags);
	bdev->md.device_uuid = be64_to_cpu(buffer->device_uuid);
	bdev->md.node_id = be32_to_cpu(buffer->node_id);

	bdev->md.node_id = be32_to_cpu(buffer->node_id);

	if (bdev->md.node_id != -1 && bdev->md.node_id != my_node_id) {
		drbd_err(device, "ambiguous node id: meta-data: %d, config: %d\n",
			bdev->md.node_id, my_node_id);
		goto err;
	}

	max_peers = be32_to_cpu(buffer->bm_max_peers);
	for (i = 0; i < DRBD_NODE_ID_MAX; i++) {
		struct drbd_peer_md *peer_md = &bdev->md.peers[i];

		peer_md->bitmap_uuid = be64_to_cpu(buffer->peers[i].bitmap_uuid);
		peer_md->bitmap_dagtag = be64_to_cpu(buffer->peers[i].bitmap_dagtag);
		peer_md->flags = be32_to_cpu(buffer->peers[i].flags);
		peer_md->bitmap_index = be32_to_cpu(buffer->peers[i].bitmap_index);

		if (peer_md->bitmap_index == -1)
			continue;
		if (i == my_node_id) {
			drbd_warn(device, "my own node id (%d) should not have a bitmap index (%d)\n",
				my_node_id, peer_md->bitmap_index);
			goto err;
		}

		if (peer_md->bitmap_index < -1 || peer_md->bitmap_index >= (int)max_peers) {
			drbd_warn(device, "peer node id %d: bitmap index (%d) exceeds allocated bitmap slots (%d)\n",
				i, peer_md->bitmap_index, max_peers);
			goto err;
		}
		/* maybe: for each bitmap_index != -1, create a connection object
		 * with peer_node_id = i, unless already present. */
	}
	BUILD_BUG_ON(ARRAY_SIZE(bdev->md.history_uuids) != ARRAY_SIZE(buffer->history_uuids));
	for (i = 0; i < ARRAY_SIZE(buffer->history_uuids); i++)
		bdev->md.history_uuids[i] = be64_to_cpu(buffer->history_uuids[i]);

	rv = NO_ERROR;
 err:
	drbd_md_put_buffer(device);

	return rv;
}

/**
 * drbd_md_mark_dirty() - Mark meta data super block as dirty
 * @device:	DRBD device.
 *
 * Call this function if you change anything that should be written to
 * the meta-data super block. This function sets MD_DIRTY, and starts a
 * timer that ensures that within five seconds you have to call drbd_md_sync().
 */
#ifdef DRBD_DEBUG_MD_SYNC
void drbd_md_mark_dirty_(struct drbd_device *device, unsigned int line, const char *func)
{
	if (!test_and_set_bit(MD_DIRTY, &device->flags)) {
		mod_timer(&device->md_sync_timer, jiffies + HZ);
		device->last_md_mark_dirty.line = line;
		device->last_md_mark_dirty.func = func;
	}
}
#else
void drbd_md_mark_dirty(struct drbd_device *device)
{
	if (!test_and_set_bit(MD_DIRTY, &device->flags))
		mod_timer(&device->md_sync_timer, jiffies + 5*HZ);
}
#endif

void _drbd_uuid_push_history(struct drbd_device *device, u64 val) __must_hold(local)
{
	struct drbd_md *md = &device->ldev->md;
	int i;

	if (val == UUID_JUST_CREATED)
		return;
	val &= ~1;  /* The lowest bit only indicates that the node was primary */

	for (i = 0; i < ARRAY_SIZE(md->history_uuids); i++) {
		if (md->history_uuids[i] == val)
			return;
	}

	for (i = ARRAY_SIZE(md->history_uuids) - 1; i > 0; i--)
		md->history_uuids[i] = md->history_uuids[i - 1];
	md->history_uuids[i] = val;
}

u64 _drbd_uuid_pull_history(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_md *md = &device->ldev->md;
	u64 first_history_uuid;
	int i;

	first_history_uuid = md->history_uuids[0];
	for (i = 0; i < ARRAY_SIZE(md->history_uuids) - 1; i++)
		md->history_uuids[i] = md->history_uuids[i + 1];
	md->history_uuids[i] = 0;

	return first_history_uuid;
}

static void __drbd_uuid_set_current(struct drbd_device *device, u64 val)
{
	drbd_md_mark_dirty(device);
	if (device->resource->role[NOW] == R_PRIMARY)
		val |= UUID_PRIMARY;
	else
		val &= ~UUID_PRIMARY;

	device->ldev->md.current_uuid = val;
	drbd_set_exposed_data_uuid(device, val);
}

void __drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 val)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_md *peer_md = &device->ldev->md.peers[peer_device->node_id];

	drbd_md_mark_dirty(device);
	peer_md->bitmap_uuid = val;
	peer_md->bitmap_dagtag = val ? device->resource->dagtag_sector : 0;
}

void _drbd_uuid_set_current(struct drbd_device *device, u64 val) __must_hold(local)
{
	unsigned long flags;

	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);
	__drbd_uuid_set_current(device, val);
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);
}

void _drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 val) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	unsigned long flags;

	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);
	__drbd_uuid_set_bitmap(peer_device, val);
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);
}

void drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 uuid) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	unsigned long flags;
	u64 previous_uuid;

	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);
	previous_uuid = drbd_bitmap_uuid(peer_device);
	if (previous_uuid)
		_drbd_uuid_push_history(device, previous_uuid);
	__drbd_uuid_set_bitmap(peer_device, uuid);
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);
}

static u64 rotate_current_into_bitmap(struct drbd_device *device, u64 weak_nodes, u64 dagtag) __must_hold(local)
{
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	struct drbd_peer_device *peer_device;
	int node_id;
	u64 bm_uuid, got_new_bitmap_uuid = 0;
	bool do_it;

	rcu_read_lock();
	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if (node_id == device->ldev->md.node_id)
			continue;
#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-1360: skip considering to rotate uuid for node which doesn't exist.
		if (peer_md[node_id].bitmap_index == -1 &&
			!(peer_md[node_id].flags & MDF_NODE_EXISTS))
			continue;
#endif
		bm_uuid = peer_md[node_id].bitmap_uuid;
		if (bm_uuid)
			continue;
		peer_device = peer_device_by_node_id(device, node_id);
		if (peer_device) {
			enum drbd_disk_state pdsk = peer_device->disk_state[NOW];
			
			if (peer_device->bitmap_index == -1) {
				struct peer_device_conf *pdc;
				pdc = rcu_dereference(peer_device->conf);
				if (pdc && !pdc->bitmap)
					continue;
			}
			do_it = (pdsk <= D_UNKNOWN && pdsk != D_NEGOTIATING) ||
				(NODE_MASK(node_id) & weak_nodes);
#ifdef _WIN32
			// MODIFIED_BY_MANTECH DW-1195 : bump current uuid when disconnecting with inconsistent peer.
			do_it = do_it || ((peer_device->connection->cstate[NEW] < C_CONNECTED) && (pdsk == D_INCONSISTENT));
#endif
		} else {
			do_it = true;
		}
		if (do_it) {
			peer_md[node_id].bitmap_uuid =
				device->ldev->md.current_uuid != UUID_JUST_CREATED ?
				device->ldev->md.current_uuid : 0;
			if (peer_md[node_id].bitmap_uuid)
				peer_md[node_id].bitmap_dagtag = dagtag;
			drbd_md_mark_dirty(device);
			got_new_bitmap_uuid |= NODE_MASK(node_id);
		}
	}
	rcu_read_unlock();

	return got_new_bitmap_uuid;
}

static u64 initial_resync_nodes(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	u64 nodes = 0;

	for_each_peer_device(peer_device, device) {
		if (peer_device->disk_state[NOW] == D_INCONSISTENT &&
		    peer_device->repl_state[NOW] == L_ESTABLISHED)
			nodes |= NODE_MASK(peer_device->node_id);
	}

	return nodes;
}

u64 drbd_weak_nodes_device(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	u64 not_weak = NODE_MASK(device->resource->res_opts.node_id);

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum drbd_disk_state pdsk = peer_device->disk_state[NOW];
		if (!(pdsk <= D_FAILED || pdsk == D_UNKNOWN || pdsk == D_OUTDATED))
			not_weak |= NODE_MASK(peer_device->node_id);

	}
	rcu_read_unlock();

	return ~not_weak;
}


static void __drbd_uuid_new_current(struct drbd_device *device, bool forced, bool send, char* caller) __must_hold(local)
{
	struct drbd_peer_device *peer_device;
	u64 got_new_bitmap_uuid, weak_nodes, val;

	spin_lock_irq(&device->ldev->md.uuid_lock);
	got_new_bitmap_uuid = rotate_current_into_bitmap(device,
					forced ? initial_resync_nodes(device) : 0,
					device->resource->dagtag_sector);

	if (!got_new_bitmap_uuid) {
		spin_unlock_irq(&device->ldev->md.uuid_lock);
		return;
	}

	get_random_bytes(&val, sizeof(u64));
	__drbd_uuid_set_current(device, val);
	spin_unlock_irq(&device->ldev->md.uuid_lock);
	weak_nodes = drbd_weak_nodes_device(device);
	drbd_info(device, "%s, new current UUID: %016llX weak: %016llX\n", caller,
		  device->ldev->md.current_uuid, weak_nodes);

	/* get it to stable storage _now_ */
	drbd_md_sync(device);
	if (!send)
		return;

	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED)
			drbd_send_uuids(peer_device, forced ? 0 : UUID_FLAG_NEW_DATAGEN, weak_nodes);
	}
}

/**
 * drbd_uuid_new_current() - Creates a new current UUID
 * @device:	DRBD device.
 *
 * Creates a new current UUID, and rotates the old current UUID into
 * the bitmap slot. Causes an incremental resync upon next connect.
 * The caller must hold adm_mutex or conf_update
 */
void drbd_uuid_new_current(struct drbd_device *device, bool forced, char* caller)
{
	if (get_ldev_if_state(device, D_UP_TO_DATE)) {
		__drbd_uuid_new_current(device, forced, true, caller);
		put_ldev(device);
	} else {
		struct drbd_peer_device *peer_device;
		/* The peers will store the new current UUID... */
		u64 current_uuid, weak_nodes;
		get_random_bytes(&current_uuid, sizeof(u64));
		current_uuid &= ~UUID_PRIMARY;
		drbd_set_exposed_data_uuid(device, current_uuid);
		drbd_info(device, "%s, sending new current UUID: %016llX\n", caller, current_uuid);

		weak_nodes = drbd_weak_nodes_device(device);
		for_each_peer_device(peer_device, device) {
			drbd_send_current_uuid(peer_device, current_uuid, weak_nodes);
			peer_device->current_uuid = current_uuid; /* In case resync finishes soon */
		}
	}
}

void drbd_uuid_new_current_by_user(struct drbd_device *device)
{
	if (get_ldev(device)) {
		__drbd_uuid_new_current(device, false, false, __FUNCTION__);
		put_ldev(device);
	}
}

#ifdef _WIN32
// MODIFIED_BY_MANTECH DW-1145
void drbd_propagate_uuids(struct drbd_device *device, u64 nodes)
#else
static void drbd_propagate_uuids(struct drbd_device *device, u64 nodes)
#endif
{
	struct drbd_peer_device *peer_device;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (!(nodes & NODE_MASK(peer_device->node_id)))
			continue;
		if (peer_device->repl_state[NOW] < L_ESTABLISHED)
			continue;

		if (list_empty(&peer_device->propagate_uuids_work.list))
			drbd_queue_work(&peer_device->connection->sender_work,
					&peer_device->propagate_uuids_work);
	}
	rcu_read_unlock();
}

void drbd_uuid_received_new_current(struct drbd_peer_device *peer_device, u64 val, u64 weak_nodes) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_device *target;
	u64 dagtag = peer_device->connection->last_dagtag_sector;
	u64 got_new_bitmap_uuid = 0;
	bool set_current = true;

	spin_lock_irq(&device->ldev->md.uuid_lock);

	for_each_peer_device(target, device) {
		if (target->repl_state[NOW] == L_SYNC_TARGET ||
			target->repl_state[NOW] == L_PAUSED_SYNC_T ||
			//DW-1924 
			//Added a condition because there was a problem applying new UUID during synchronization.
			target->repl_state[NOW] == L_BEHIND ||
			target->repl_state[NOW] == L_WF_BITMAP_T) {
			target->current_uuid = val;
			set_current = false;
		}
	}

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1340: do not update current uuid if my disk is outdated. the node sent uuid has my current uuid as bitmap uuid, and will start resync as soon as we do handshake.
	if (device->disk_state[NOW] == D_OUTDATED) {
		set_current = false;
	}
#endif

	if (set_current) {
#ifndef _WIN32
		// MODIFIED_BY_MANTECH DW-1034: split-brain could be caused since old one's been extinguished, always preserve old one when setting new one.
		if (device->disk_state[NOW] == D_UP_TO_DATE)
#endif
			got_new_bitmap_uuid = rotate_current_into_bitmap(device, weak_nodes, dagtag);
		__drbd_uuid_set_current(device, val);
#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-837: Apply updated current uuid to meta disk.
		drbd_md_mark_dirty(device);
#endif
	}
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	if(set_current) {
		// MODIFIED_BY_MANTECH DW-977: Send current uuid as soon as set it to let the node which created uuid update mine.
		drbd_send_current_uuid(peer_device, val, drbd_weak_nodes_device(device));
	}
	else
		drbd_warn(peer_device, "receive new current but not update UUID: %016llX\n", peer_device->current_uuid);

	drbd_propagate_uuids(device, got_new_bitmap_uuid);
}

static u64 __set_bitmap_slots(struct drbd_device *device, u64 bitmap_uuid, u64 do_nodes) __must_hold(local)
{
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	u64 modified = 0;
	int node_id;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if (node_id == device->ldev->md.node_id)
			continue;
		if (!(do_nodes & NODE_MASK(node_id)))
			continue;

		if (peer_md[node_id].bitmap_uuid != bitmap_uuid) {
			_drbd_uuid_push_history(device, peer_md[node_id].bitmap_uuid);
			/* drbd_info(device, "bitmap[node_id=%d] = %llX\n", node_id, bitmap_uuid); */
			peer_md[node_id].bitmap_uuid = bitmap_uuid;
			peer_md[node_id].bitmap_dagtag =
				bitmap_uuid ? device->resource->dagtag_sector : 0;
			drbd_md_mark_dirty(device);
			modified |= NODE_MASK(node_id);
		}
	}

	return modified;
}

static u64 __test_bitmap_slots_of_peer(struct drbd_peer_device *peer_device) __must_hold(local)
{
	u64 set_bitmap_slots = 0;
	int node_id;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-1113: identical current uuid means they've cleared each other's bitmap uuid, while I haven't known it.
		struct drbd_peer_device *found_peer = peer_device_by_node_id(peer_device->device, node_id);
		if (peer_device->bitmap_uuids[node_id] &&
			found_peer &&
			((peer_device->current_uuid & ~UUID_PRIMARY) != (found_peer->current_uuid & ~UUID_PRIMARY)))
#else
		if (peer_device->bitmap_uuids[node_id])
#endif
			set_bitmap_slots |= NODE_MASK(node_id);
	}

	return set_bitmap_slots;
}


u64 drbd_uuid_resync_finished(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	u64 set_bitmap_slots, newer, equal;
	unsigned long flags;

	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);
	set_bitmap_slots = __test_bitmap_slots_of_peer(peer_device);
	newer = __set_bitmap_slots(device, drbd_current_uuid(device), set_bitmap_slots);
	equal = __set_bitmap_slots(device, 0, ~set_bitmap_slots);
	_drbd_uuid_push_history(device, drbd_current_uuid(device));
	__drbd_uuid_set_current(device, peer_device->current_uuid);
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);

	return newer;
}

static const char* name_of_node_id(struct drbd_resource *resource, int node_id)
{
	/* Caller need to hold rcu_read_lock */
	struct drbd_connection *connection = drbd_connection_by_node_id(resource, node_id);

	return connection ? rcu_dereference(connection->transport.net_conf)->name : "";
}

#ifdef _WIN32
void forget_bitmap(struct drbd_device *device, int node_id) __must_hold(local)
#else
static void forget_bitmap(struct drbd_device *device, int node_id) __must_hold(local)
#endif
{
	int bitmap_index = device->ldev->md.peers[node_id].bitmap_index;
	const char* name;

	/* DW-1843
	 * When an io error occurs on the primary node, oos is recorded with up_to_date maintained. 
	 * Therefore, when changing status to secondary, it is recognized as inconsistent oos and deleted through forget_bitmap. 
	 * To prevent it, use MDF_PRIMARY_IO_ERROR.
	 */
	if (_drbd_bm_total_weight(device, bitmap_index) == 0)
		return;

	spin_unlock_irq(&device->ldev->md.uuid_lock);
	rcu_read_lock();
	name = name_of_node_id(device->resource, node_id);
	drbd_info(device, "clearing bitmap UUID and content (%llu bits) for node %d (%s)(slot %d)\n",
		(unsigned long long)_drbd_bm_total_weight(device, bitmap_index), node_id, name, bitmap_index);
	rcu_read_unlock();
	drbd_suspend_io(device, WRITE_ONLY);
	drbd_bm_lock(device, "forget_bitmap()", BM_LOCK_TEST | BM_LOCK_SET);
	drbd_bm_clear_many_bits(device, bitmap_index, 0, DRBD_END_OF_BITMAP);
	drbd_bm_unlock(device);
	drbd_resume_io(device);
	drbd_md_mark_dirty(device);
	spin_lock_irq(&device->ldev->md.uuid_lock);
}
#ifndef _WIN32 
static void copy_bitmap(struct drbd_device *device, int from_id, int to_id) __must_hold(local)
{
	int from_index = device->ldev->md.peers[from_id].bitmap_index;
	int to_index = device->ldev->md.peers[to_id].bitmap_index;
	const char *from_name, *to_name;

	spin_unlock_irq(&device->ldev->md.uuid_lock);
	rcu_read_lock();
	from_name = name_of_node_id(device->resource, from_id);
	to_name = name_of_node_id(device->resource, to_id);
	drbd_info(device, "Node %d (%s) synced up to node %d (%s). copying bitmap slot %d to %d.\n",
		  to_id, to_name, from_id, from_name, from_index, to_index);
	rcu_read_unlock();
	drbd_suspend_io(device, WRITE_ONLY);
	drbd_bm_lock(device, "copy_bitmap()", BM_LOCK_ALL);
	drbd_bm_copy_slot(device, from_index, to_index);
	drbd_bm_unlock(device);
	drbd_resume_io(device);
	drbd_md_mark_dirty(device);
	spin_lock_irq(&device->ldev->md.uuid_lock);
}
#endif

static int find_node_id_by_bitmap_uuid(struct drbd_device *device, u64 bm_uuid) __must_hold(local)
{
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	int node_id;

	bm_uuid &= ~UUID_PRIMARY;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if ((peer_md[node_id].bitmap_uuid & ~UUID_PRIMARY) == bm_uuid &&
		    peer_md[node_id].bitmap_index != -1)
			return node_id;
	}

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if ((peer_md[node_id].bitmap_uuid & ~UUID_PRIMARY) == bm_uuid)
			return node_id;
	}

	return -1;
}

static bool node_connected(struct drbd_resource *resource, int node_id)
{
	struct drbd_connection *connection;
	bool r = false;

	rcu_read_lock();
	connection = drbd_connection_by_node_id(resource, node_id);
	if (connection)
		r = connection->cstate[NOW] == C_CONNECTED;
	rcu_read_unlock();

	return r;
}

#ifndef _WIN32 
static bool detect_copy_ops_on_peer(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	struct drbd_resource *resource = device->resource;
	int node_id1, node_id2, from_id;
	u64 peer_bm_uuid;
	bool modified = false;

	for (node_id1 = 0; node_id1 < DRBD_NODE_ID_MAX; node_id1++) {
		if (device->ldev->md.peers[node_id1].bitmap_index == -1)
			continue;

		if (node_connected(resource, node_id1))
			continue;

		peer_bm_uuid = peer_device->bitmap_uuids[node_id1] & ~UUID_PRIMARY;
		if (!peer_bm_uuid)
			continue;

		for (node_id2 = node_id1 + 1; node_id2 < DRBD_NODE_ID_MAX; node_id2++) {
			if (device->ldev->md.peers[node_id2].bitmap_index == -1)
				continue;

			if (node_connected(resource, node_id2))
				continue;

			if (peer_bm_uuid == (peer_device->bitmap_uuids[node_id2] & ~UUID_PRIMARY))
				goto found;
		}
	}
	return false;

found:
	from_id = find_node_id_by_bitmap_uuid(device, peer_bm_uuid);
	if (from_id == -1) {
		if (peer_md[node_id1].bitmap_uuid == 0 && peer_md[node_id2].bitmap_uuid == 0)
			return false;
		drbd_err(peer_device, "unexpected\n");
		drbd_err(peer_device, "In UUIDs from node %d found equal UUID (%llX) for nodes %d %d\n",
			 peer_device->node_id, peer_bm_uuid, node_id1, node_id2);
		drbd_err(peer_device, "I have %llX for node_id=%d\n",
			 peer_md[node_id1].bitmap_uuid, node_id1);
		drbd_err(peer_device, "I have %llX for node_id=%d\n",
			 peer_md[node_id2].bitmap_uuid, node_id2);
		return false;
	}

	if (peer_md[from_id].bitmap_index == -1)
		return false;

	if (from_id != node_id1 &&
	    peer_md[node_id1].bitmap_uuid != peer_bm_uuid) {
		peer_md[node_id1].bitmap_uuid = peer_bm_uuid;
		peer_md[node_id1].bitmap_dagtag = peer_md[from_id].bitmap_dagtag;
		copy_bitmap(device, from_id, node_id1);
		modified = true;

	}
	if (from_id != node_id2 &&
	    peer_md[node_id2].bitmap_uuid != peer_bm_uuid) {
		peer_md[node_id2].bitmap_uuid = peer_bm_uuid;
		peer_md[node_id2].bitmap_dagtag = peer_md[from_id].bitmap_dagtag;
		copy_bitmap(device, from_id, node_id2);
		modified = true;
	}

	return modified;
}
#endif

void drbd_uuid_detect_finished_resyncs(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	int node_id;
	bool write_bm = false;
	bool filled = false;

	spin_lock_irq(&device->ldev->md.uuid_lock);
	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if (node_id == device->ldev->md.node_id)
			continue;

		if (peer_md[node_id].bitmap_index == -1 && !(peer_md[node_id].flags & MDF_NODE_EXISTS))
			continue;

#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-978: Need to check if uuid has to be propagated even if bitmap_uuid is 0, it could be set -1 during sent, check the flag 'MDF_PEER_DIFF_CUR_UUID'.
		if (peer_device->bitmap_uuids[node_id] == 0 && (peer_md[node_id].bitmap_uuid != 0 || (peer_md[node_id].flags & MDF_PEER_DIFF_CUR_UUID))) {
#else
		if (peer_device->bitmap_uuids[node_id] == 0 && peer_md[node_id].bitmap_uuid != 0) {
#endif
			u64 peer_current_uuid = peer_device->current_uuid & ~UUID_PRIMARY;

			if (peer_current_uuid == (drbd_current_uuid(device) & ~UUID_PRIMARY)) {

#ifdef _WIN32
				// MODIFIED_BY_MANTECH DW-978, DW-979, DW-980
				// bitmap_uuid was already '0', just clear_flag and drbd_propagate_uuids().
				if((peer_md[node_id].bitmap_uuid == 0) && (peer_md[node_id].flags & MDF_PEER_DIFF_CUR_UUID))
					goto clear_flag;

#endif
				
				_drbd_uuid_push_history(device, peer_md[node_id].bitmap_uuid);
				peer_md[node_id].bitmap_uuid = 0;
				if (node_id == peer_device->node_id)
					drbd_print_uuids(peer_device, "updated UUIDs", __FUNCTION__);
				else if (peer_md[node_id].bitmap_index != -1)
#ifdef _WIN32				
				{
					// MODIFIED_BY_MANTECH DW-955, DW-1116, DW-1131: do not forget bitmap if peer is not forgettable state.
					struct drbd_peer_device *found_peer = peer_device_by_node_id(device, node_id);
					
					if (found_peer &&
						isForgettableReplState(found_peer->repl_state[NOW]) && !drbd_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR))
					{
						// MODIFIED_BY_MANTECH DW-955: print log to recognize where forget_bitmap is called.
						drbd_info(device, "bitmap will be cleared due to other resync, pdisk(%d), prepl(%d), peerdirty(%llu), pdvflag(%llx)\n", 
							found_peer->disk_state[NOW], found_peer->repl_state[NOW], found_peer->dirty_bits, (unsigned long long)found_peer->flags);
						forget_bitmap(device, node_id);
					}					
				}
#else
					forget_bitmap(device, node_id);
#endif
				else
					drbd_info(device, "Clearing bitmap UUID for node %d\n",
						  node_id);
				drbd_md_mark_dirty(device);
#ifdef _WIN32
clear_flag:
				// MODIFIED_BY_MANTECH DW-978: Clear the flag once we determine that uuid will be propagated.
				peer_md[node_id].flags &= ~MDF_PEER_DIFF_CUR_UUID;
#endif
				write_bm = true;
			}

#ifndef _WIN32
			// MODIFIED_BY_MANTECH DW-1099: copying bitmap has a defect, do sync whole out-of-sync until fixed.
			from_node_id = find_node_id_by_bitmap_uuid(device, peer_current_uuid);
			if (from_node_id != -1 && node_id != from_node_id &&
#ifdef _WIN32
				// MODIFIED_BY_MANTECH DW-978: Copying bitmap here assumed that bitmap uuid wasn't 0, check bitmap uuid again since flag 'MDF_PEER_DIFF_CUR_UUID' is added.
				peer_md[node_id].bitmap_uuid != 0 &&
#endif
			    dagtag_newer(peer_md[from_node_id].bitmap_dagtag,
					 peer_md[node_id].bitmap_dagtag)) {
				_drbd_uuid_push_history(device, peer_md[node_id].bitmap_uuid);
				peer_md[node_id].bitmap_uuid = peer_md[from_node_id].bitmap_uuid;
				peer_md[node_id].bitmap_dagtag = peer_md[from_node_id].bitmap_dagtag;
				if (peer_md[node_id].bitmap_index != -1 &&
				    peer_md[from_node_id].bitmap_index != -1)
					copy_bitmap(device, from_node_id, node_id);
				else
					drbd_info(device, "Node %d synced up to node %d.\n",
						  node_id, from_node_id);
				drbd_md_mark_dirty(device);
#ifdef _WIN32
				// MODIFIED_BY_MANTECH DW-978: Clear the flag once we determine that uuid will be propagated.
				peer_md[node_id].flags &= ~MDF_PEER_DIFF_CUR_UUID;
#endif
				filled = true;
			}
#endif
		}
	}

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-955: peer has already cleared my bitmap, or receiving peer_in_sync has been left out. no resync is needed.
	if (drbd_bm_total_weight(peer_device) &&
		peer_device->dirty_bits == 0 &&
		isForgettableReplState(peer_device->repl_state[NOW]) &&
		device->disk_state[NOW] > D_OUTDATED && // DW-1656 : no clearing bitmap when disk is Outdated.
		// DW-1633 : if the peer has lost a primary and becomes stable, the dstate of peer_device becomes D_CONSISTENT and UUID_FLAG_GOT_STABLE is set.
		// at this time, the reconciliation resync may work, so do not clear the bitmap.
		!((peer_device->disk_state[NOW] == D_CONSISTENT) && (peer_device->uuid_flags & UUID_FLAG_GOT_STABLE)) &&
		(device->disk_state[NOW] == peer_device->disk_state[NOW]) && // DW-1644, DW-1357 : clear bitmap when the disk state is same.
		!(peer_device->uuid_authoritative_nodes & NODE_MASK(device->resource->res_opts.node_id)) &&
#ifdef _WIN32_DISABLE_RESYNC_FROM_SECONDARY
		// MODIFIED_BY_MANTECH DW-1162: clear bitmap only when peer stays secondary.
		peer_device->connection->peer_role[NEW] == R_SECONDARY &&
#endif
		(peer_device->current_uuid & ~UUID_PRIMARY) ==
		(drbd_current_uuid(device) & ~UUID_PRIMARY))
	{
		int peer_node_id = peer_device->node_id;
		u64 peer_bm_uuid = peer_md[peer_node_id].bitmap_uuid;
		if (peer_bm_uuid)
			_drbd_uuid_push_history(device, peer_bm_uuid);
		if (peer_md[peer_node_id].bitmap_index != -1 && !drbd_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR))
		{
			drbd_info(peer_device, "bitmap will be cleared due to inconsistent out-of-sync, disk(%d)\n", device->disk_state[NOW]);
			forget_bitmap(device, peer_node_id);
		}
		drbd_md_mark_dirty(device);
	}

	// MODIFIED_BY_MANTECH DW-1145: clear bitmap if peer has consistent disk with primary's, peer will also clear bitmap.
	if (drbd_bm_total_weight(peer_device) &&
		peer_device->uuid_flags & UUID_FLAG_CONSISTENT_WITH_PRI &&
		is_consistent_with_primary(device) &&
		(peer_device->current_uuid & ~UUID_PRIMARY) ==
		(drbd_current_uuid(device) & ~UUID_PRIMARY))
	{
		int peer_node_id = peer_device->node_id;
		u64 peer_bm_uuid = peer_md[peer_node_id].bitmap_uuid;
		if (peer_bm_uuid)
			_drbd_uuid_push_history(device, peer_bm_uuid);
		if (peer_md[peer_node_id].bitmap_index != -1 && !drbd_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR))
		{
			drbd_info(peer_device, "bitmap will be cleared because peer has consistent disk with primary's\n");
			forget_bitmap(device, peer_node_id);
		}
		drbd_md_mark_dirty(device);

		if (peer_device->dirty_bits)
			filled = true;
	}

#else
	// MODIFIED_BY_MANTECH DW-1099: copying bitmap has a defect, do sync whole out-of-sync until fixed.
	write_bm |= detect_copy_ops_on_peer(peer_device);
#endif
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	if (write_bm || filled) {
		u64 to_nodes = filled ? -1 : ~NODE_MASK(peer_device->node_id);
		drbd_propagate_uuids(device, to_nodes);
		drbd_suspend_io(device, WRITE_ONLY);
		drbd_bm_lock(device, "detect_finished_resyncs()", BM_LOCK_BULK);
		drbd_bm_write(device, NULL);
		drbd_bm_unlock(device);
		drbd_resume_io(device);
	}
}

#ifdef _WIN32
// DW-1293: it performs fast invalidate(remote) when agreed protocol version is 112 or above, and fast sync options is enabled.
int drbd_bmio_set_all_or_fast(struct drbd_device *device, struct drbd_peer_device *peer_device) __must_hold(local)
{
	int nRet = 0;
	// DW-1293: queued bitmap work increases work count which may prevents io that we need to mount volume.
	bool dec_bm_work_n = false;

	if (atomic_read(&device->pending_bitmap_work.n))
	{
		dec_bm_work_n = true;
		atomic_dec(&device->pending_bitmap_work.n);
	}

	if (peer_device->repl_state[NOW] == L_STARTING_SYNC_S)
	{
		if (peer_device->connection->agreed_pro_version < 112 ||
			!isFastInitialSync() ||
			!SetOOSAllocatedCluster(device, peer_device, L_SYNC_SOURCE, false))
		{
			drbd_warn(peer_device, "can not perform fast invalidate(remote), protocol ver(%d), fastSyncOpt(%d)\n", peer_device->connection->agreed_pro_version, isFastInitialSync());
			if (dec_bm_work_n)
			{
				atomic_inc(&device->pending_bitmap_work.n);
				dec_bm_work_n = false;
			}
			nRet = drbd_bmio_set_n_write(device, peer_device);
		}
	}
	else if (peer_device->repl_state[NOW] == L_STARTING_SYNC_T)
	{
		if (peer_device->connection->agreed_pro_version < 112 ||
			!isFastInitialSync() ||
			!SetOOSAllocatedCluster(device, peer_device, L_SYNC_TARGET, false))
		{
			drbd_warn(peer_device, "can not perform fast invalidate(remote), protocol ver(%d), fastSyncOpt(%d)\n", peer_device->connection->agreed_pro_version, isFastInitialSync());
			if (dec_bm_work_n)
			{
				atomic_inc(&device->pending_bitmap_work.n);
				dec_bm_work_n = false;
			}
			nRet = drbd_bmio_set_all_n_write(device, peer_device);
		}
	}
	else
	{
		drbd_warn(peer_device, "unexpected repl state: %s\n", drbd_repl_str(peer_device->repl_state[NOW]));
	}

	if (dec_bm_work_n)
	{
		atomic_inc(&device->pending_bitmap_work.n);
		dec_bm_work_n = false;
	}

	return nRet;
}
#endif

int drbd_bmio_set_all_n_write(struct drbd_device *device,
			      struct drbd_peer_device *peer_device) __must_hold(local)
{
	UNREFERENCED_PARAMETER(peer_device);
#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1333: set whole bits and update resync extent.
	struct drbd_peer_device *p;
	
	// DW-1941 add rcu_read_lock()
	rcu_read_lock();
	for_each_peer_device_rcu(p, device) {
		if (!update_sync_bits(p, 0, drbd_bm_bits(device), SET_OUT_OF_SYNC, true))
		{
			drbd_err(device, "no sync bit has been set for peer(%d), set whole bits without updating resync extent instead.\n", p->node_id);
			drbd_bm_set_many_bits(p, 0, DRBD_END_OF_BITMAP);
		}
	}
	rcu_read_unlock();
#else
	drbd_bm_set_all(device);
#endif
	return drbd_bm_write(device, NULL);
}

/**
 * drbd_bmio_set_n_write() - io_fn for drbd_queue_bitmap_io() or drbd_bitmap_io()
 * @device:	DRBD device.
 *
 * Sets all bits in the bitmap and writes the whole bitmap to stable storage.
 */
int drbd_bmio_set_n_write(struct drbd_device *device,
			  struct drbd_peer_device *peer_device) __must_hold(local)
{
	int rv = -EIO;

	drbd_md_set_peer_flag(peer_device, MDF_PEER_FULL_SYNC);
	drbd_md_sync(device);
#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1333: set whole bits and update resync extent.
	if (!update_sync_bits(peer_device, 0, drbd_bm_bits(device), SET_OUT_OF_SYNC, false))
	{
		drbd_err(peer_device, "no sync bit has been set, set whole bits without updating resync extent instead.\n");
		drbd_bm_set_many_bits(peer_device, 0, DRBD_END_OF_BITMAP);
	}
#else
	drbd_bm_set_many_bits(peer_device, 0, -1UL);
#endif

	rv = drbd_bm_write(device, NULL);

	if (!rv) {
		drbd_md_clear_peer_flag(peer_device, MDF_PEER_FULL_SYNC);
		drbd_md_sync(device);
	}

	return rv;
}

#ifdef _WIN32
// DW-844
#define GetBitPos(bytes, bitsInByte)	((bytes * BITS_PER_BYTE) + bitsInByte)
			  
// set out-of-sync from provided bitmap
ULONG_PTR SetOOSFromBitmap(PVOLUME_BITMAP_BUFFER pBitmap, struct drbd_peer_device *peer_device)
{
	ULONG_PTR llStartBit = DRBD_END_OF_BITMAP, llEndBit = DRBD_END_OF_BITMAP;
	ULONG_PTR count = 0;
	PCHAR pByte = NULL;
	
	if (NULL == pBitmap ||
		NULL == pBitmap->Buffer ||
		NULL == peer_device)
	{
		drbd_err(peer_device, "Invalid parameter, pBitmap(0x%p), pBitmap->Buffer(0x%p) peer_device(0x%p)\n", pBitmap, pBitmap ? pBitmap->Buffer : NULL, peer_device);
		return UINT64_MAX;
	}

	pByte = (PCHAR)pBitmap->Buffer;
	
	// find continuously set bits and set out-of-sync.
	for (LONGLONG llBytePos = 0; llBytePos < pBitmap->BitmapSize.QuadPart; llBytePos++)
	{
		for (short llBitPosInByte = 0; llBitPosInByte < BITS_PER_BYTE; llBitPosInByte++)
		{
			CHAR pBit = (pByte[llBytePos] >> llBitPosInByte) & 0x1;

			// found first set bit.
			if (llStartBit == DRBD_END_OF_BITMAP && pBit == 1)
			{
				llStartBit = (ULONG_PTR)GetBitPos(llBytePos, llBitPosInByte);
				continue;
			}

			// found last set bit. set out-of-sync.
			if (llStartBit != DRBD_END_OF_BITMAP && pBit == 0)
			{
				llEndBit = (ULONG_PTR)GetBitPos(llBytePos, llBitPosInByte) - 1;
				count += update_sync_bits(peer_device, llStartBit, llEndBit, SET_OUT_OF_SYNC, false);

				llStartBit = DRBD_END_OF_BITMAP;
				llEndBit = DRBD_END_OF_BITMAP;
				continue;
			}
		}
	}

	// met last bit while finding zero bit.
	if (llStartBit != DRBD_END_OF_BITMAP)
	{
		llEndBit = (ULONG_PTR)pBitmap->BitmapSize.QuadPart * BITS_PER_BYTE - 1;	// last cluster
		count += update_sync_bits(peer_device, llStartBit, llEndBit, SET_OUT_OF_SYNC, false);

		llStartBit = DRBD_END_OF_BITMAP;
		llEndBit = DRBD_END_OF_BITMAP;
	}

	return count;
}

// set out-of-sync for allocated clusters.
bool SetOOSAllocatedCluster(struct drbd_device *device, struct drbd_peer_device *peer_device, enum drbd_repl_state side, bool bitmap_lock)
{
	bool bRet = false;
	PVOLUME_BITMAP_BUFFER pBitmap = NULL;
	ULONG_PTR count = 0;
	// DW-1317: to support fast sync from secondary sync source whose volume is NOT mounted.
	bool bSecondary = false;

	// DW-2017 in this function, to avoid deadlock a bitmap lock within the vol_ctl_mutex should not be used.
	// if bitmap_lock is true, it was called from drbd_receiver() and the object is guaranteed to be removed after completion
	if (!bitmap_lock)
		// DW-1317: prevent from writing smt on volume, such as being primary and getting resync data, it doesn't allow to dismount volume also.
		mutex_lock(&device->resource->vol_ctl_mutex);

	// DW-2017 after locking, access to the object shall be made.
	if (NULL == device ||
		NULL == peer_device ||
		(side != L_SYNC_SOURCE && side != L_SYNC_TARGET))
	{
		// DW-2017 change log output based on peer_device status
		if (peer_device)
			drbd_err(peer_device,"Invalid parameter side(%s)\n", drbd_repl_str(side));
		else
			WDRBD_ERROR("Invalid parameter side(%s)\n", drbd_repl_str(side));

		if (!bitmap_lock)
			mutex_unlock(&device->resource->vol_ctl_mutex);

		return false;
	}

#ifdef _WIN32_STABLE_SYNCSOURCE
	// DW-1317: inspect resync side first, before get the allocated bitmap.
#ifdef _WIN32_RCU_LOCKED	
	if (!drbd_inspect_resync_side(peer_device, side, NOW, false))
#else
	if (!drbd_inspect_resync_side(peer_device, side, NOW))
#endif
	{
		drbd_warn(peer_device, "can't be %s\n", drbd_repl_str(side));
		if (!bitmap_lock)
			mutex_unlock(&device->resource->vol_ctl_mutex);
		goto out;
	}
#endif

	// clear all bits before start initial sync. (clear bits only for this peer device)	
	if (bitmap_lock)
		drbd_bm_slot_lock(peer_device, "initial sync for allocated cluster", BM_LOCK_BULK);
	drbd_bm_clear_many_bits(peer_device->device, peer_device->bitmap_index, 0, DRBD_END_OF_BITMAP);
	drbd_bm_write(device, NULL);
	if (bitmap_lock) {
		drbd_bm_slot_unlock(peer_device);
		// DW-2017
		mutex_lock(&device->resource->vol_ctl_mutex);
	}

	if (device->resource->role[NOW] == R_SECONDARY)
	{
		// DW-1317: set read-only attribute and mount for temporary.
		if (side == L_SYNC_SOURCE)
		{
			drbd_info(peer_device,"I am a secondary sync source, will mount volume for temporary to get allocated clusters.\n");
			bSecondary = true;
		}
		else if (side == L_SYNC_TARGET)
		{
			drbd_info(peer_device,"I am a sync target, wait to receive source's bitmap\n");
			bRet = true;
			mutex_unlock(&device->resource->vol_ctl_mutex);
			goto out;			
		}
	}

	drbd_info(peer_device, "Writing the bitmap for allocated clusters.\n");

	do
	{
		if (bSecondary)
		{			
			mutex_lock(&att_mod_mutex);
			// set readonly attribute.
			if (!ChangeVolumeReadonly(device->minor, true))
			{
				drbd_err(peer_device, "Could not change volume read-only attribute\n");
				mutex_unlock(&att_mod_mutex);
				bSecondary = false;
				break;
			}
			// allow mount within getting volume bitmap.
			device->resource->bTempAllowMount = TRUE;			
		}

		// DW-1391
		atomic_set(&device->resource->bGetVolBitmapDone, false);

		// Get volume bitmap which is converted into 4kb cluster unit.
		pBitmap = (PVOLUME_BITMAP_BUFFER)GetVolumeBitmapForDrbd(device->minor, BM_BLOCK_SIZE);		
		if (NULL == pBitmap) {
			drbd_err(peer_device, "Could not get bitmap for drbd\n");
		}

		// DW-1391
		atomic_set(&device->resource->bGetVolBitmapDone, true);
		
		if (bSecondary)
		{
			// prevent from mounting volume.
			device->resource->bTempAllowMount = FALSE;

			// dismount volume.
			FsctlFlushDismountVolume(device->minor, false);

			// clear readonly attribute
			if (!ChangeVolumeReadonly(device->minor, false))
			{
				drbd_err(peer_device, "Read-only attribute for volume(minor: %d) had been set, but can't be reverted. force detach drbd disk\n", device->minor);
				if (device &&
					get_ldev_if_state(device, D_NEGOTIATING))
				{
					set_bit(FORCE_DETACH, &device->flags);
					change_disk_state(device, D_DETACHING, CS_HARD, NULL);
					put_ldev(device);
				}
			}
			mutex_unlock(&att_mod_mutex);
		}

	} while (false, false);

	// DW-1495: Change location due to deadlock(bm_change)
	// Set out-of-sync for allocated cluster.
	if (bitmap_lock) {
		// DW-2017
		mutex_unlock(&device->resource->vol_ctl_mutex);
		drbd_bm_lock(device, "Set out-of-sync for allocated cluster", BM_LOCK_CLEAR | BM_LOCK_BULK);
	}
	count = SetOOSFromBitmap(pBitmap, peer_device);
	if (bitmap_lock)
		drbd_bm_unlock(device);

	if (count == -1)
	{
		drbd_err(peer_device, "Could not set bits from gotten bitmap\n");
		bRet = false;
	}
	else{
		drbd_info(peer_device, "%llu bits(%llu KB) are set as out-of-sync\n", (unsigned long long)count, (unsigned long long)(count << (BM_BLOCK_SHIFT - 10)));
		bRet = true;
	}
		

	if (pBitmap)
	{
		ExFreePool(pBitmap);
		pBitmap = NULL;
	}

	if (!bitmap_lock)
		mutex_unlock(&device->resource->vol_ctl_mutex);
out:
	return bRet;
}
#endif	// _WIN32

/**
 * drbd_bmio_clear_all_n_write() - io_fn for drbd_queue_bitmap_io() or drbd_bitmap_io()
 * @device:	DRBD device.
 *
 * Clears all bits in the bitmap and writes the whole bitmap to stable storage.
 */
int drbd_bmio_clear_all_n_write(struct drbd_device *device,
			    struct drbd_peer_device *peer_device) __must_hold(local)
{
	UNREFERENCED_PARAMETER(peer_device);
	drbd_resume_al(device);
	drbd_bm_clear_all(device);
	return drbd_bm_write(device, NULL);
}

static int w_bitmap_io(struct drbd_work *w, int unused)
{
	UNREFERENCED_PARAMETER(unused);

	struct bm_io_work *work =
		container_of(w, struct bm_io_work, w);
	struct drbd_device *device = work->device;
	int rv = -EIO;

	// DW-1979 drbd_send_bitmap function does not lock.
	if (&drbd_send_bitmap == work->io_fn) {
		if (atomic_dec_and_test(&device->pending_bitmap_work.n))
			wake_up(&device->misc_wait);
	}

	if (get_ldev(device)) {
		if (work->flags & BM_LOCK_SINGLE_SLOT)
			drbd_bm_slot_lock(work->peer_device, work->why, work->flags);
		else
			drbd_bm_lock(device, work->why, work->flags);

		rv = work->io_fn(device, work->peer_device);

		if (work->flags & BM_LOCK_SINGLE_SLOT)
			drbd_bm_slot_unlock(work->peer_device);
		else
			drbd_bm_unlock(device);
		put_ldev(device);
	}

	if (work->done)
		work->done(device, work->peer_device, rv);

	// DW-1979
	if (&drbd_send_bitmap != work->io_fn) {
		if (atomic_dec_and_test(&device->pending_bitmap_work.n))
			wake_up(&device->misc_wait);
	}

	kfree(work);

	return 0;
}

void drbd_queue_pending_bitmap_work(struct drbd_device *device)
{
	unsigned long flags;

	spin_lock_irqsave(&device->pending_bitmap_work.q_lock, flags);
	spin_lock(&device->resource->work.q_lock);
	list_splice_tail_init(&device->pending_bitmap_work.q, &device->resource->work.q);
	spin_unlock(&device->resource->work.q_lock);
	spin_unlock_irqrestore(&device->pending_bitmap_work.q_lock, flags);
	wake_up(&device->resource->work.q_wait);
}

/**
 * drbd_queue_bitmap_io() - Queues an IO operation on the whole bitmap
 * @device:	DRBD device.
 * @io_fn:	IO callback to be called when bitmap IO is possible
 * @done:	callback to be called after the bitmap IO was performed
 * @why:	Descriptive text of the reason for doing the IO
 *
 * While IO on the bitmap happens we freeze application IO thus we ensure
 * that drbd_set_out_of_sync() can not be called. This function MAY ONLY be
 * called from sender context. It MUST NOT be used while a previous such
 * work is still pending!
 *
 * Its worker function encloses the call of io_fn() by get_ldev() and
 * put_ldev().
 */
void drbd_queue_bitmap_io(struct drbd_device *device,
			  int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
			  void (*done)(struct drbd_device *, struct drbd_peer_device *, int),
			  char *why, enum bm_flag flags,
			  struct drbd_peer_device *peer_device)
{
	struct bm_io_work *bm_io_work;

	// DW-1979 other threads are also used(drbd_receiver()), so i changed to the info level log to output
	//D_ASSERT(device, current == device->resource->worker.task);
	if (current == device->resource->worker.task)
		drbd_info(device, "%s, worker.task(%p), current(%p)\n", why ? why : "?", device->resource->worker.task, current);

#ifdef _WIN32    
	bm_io_work = kmalloc(sizeof(*bm_io_work), GFP_NOIO, '21DW');
	if(!bm_io_work) {
		drbd_err(device, "Could not allocate bm io work.\n");
		done(device, peer_device, -ENOMEM);
		return;
	}
#else
	bm_io_work = kmalloc(sizeof(*bm_io_work), GFP_NOIO);
	if (!bm_io_work) {
		done(device, peer_device, -ENOMEM);
		return;
	}
#endif
	bm_io_work->w.cb = w_bitmap_io;
	bm_io_work->device = device;
	bm_io_work->peer_device = peer_device;
	bm_io_work->io_fn = io_fn;
	bm_io_work->done = done;
	bm_io_work->why = why;
	bm_io_work->flags = flags;

	/*
	 * Whole-bitmap operations can only take place when there is no
	 * concurrent application I/O.  We ensure exclusion between the two
	 * types of I/O  with the following mechanism:
	 *
	 *  - device->ap_bio_cnt keeps track of the number of application I/O
	 *    requests in progress.
	 *
	 *  - A non-empty device->pending_bitmap_work list indicates that
	 *    whole-bitmap I/O operations are pending, and no new application
	 *    I/O should be started.  We make sure that the list doesn't appear
	 *    empty system wide before trying to queue the whole-bitmap I/O.
	 *
	 *  - In dec_ap_bio(), we decrement device->ap_bio_cnt.  If it reaches
	 *    zero and the device->pending_bitmap_work list is non-empty, we
	 *    queue the whole-bitmap operations.
	 *
	 *  - In inc_ap_bio(), we increment device->ap_bio_cnt before checking
	 *    if the device->pending_bitmap_work list is non-empty.  If
	 *    device->pending_bitmap_work is non-empty, we immediately call
	 *    dec_ap_bio().
	 *
	 * This ensures that whenver there is pending whole-bitmap I/O, we
	 * realize in dec_ap_bio().
	 *
	 */

	/* no one should accidentally schedule the next bitmap IO
	 * when it is only half-queued yet */
	atomic_inc(&device->ap_bio_cnt[WRITE]);
	atomic_inc(&device->pending_bitmap_work.n);
	spin_lock_irq(&device->pending_bitmap_work.q_lock);
	list_add_tail(&bm_io_work->w.list, &device->pending_bitmap_work.q);
	spin_unlock_irq(&device->pending_bitmap_work.q_lock);
	dec_ap_bio(device, WRITE);  /* may move to actual work queue */
}

/**
 * drbd_bitmap_io() -  Does an IO operation on the whole bitmap
 * @device:	DRBD device.
 * @io_fn:	IO callback to be called when bitmap IO is possible
 * @why:	Descriptive text of the reason for doing the IO
 *
 * freezes application IO while that the actual IO operations runs. This
 * functions MAY NOT be called from sender context.
 */
int drbd_bitmap_io(struct drbd_device *device,
		int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
		char *why, enum bm_flag flags,
		struct drbd_peer_device *peer_device)
{
	/* Only suspend io, if some operation is supposed to be locked out */
	const bool do_suspend_io = flags & (BM_LOCK_CLEAR|BM_LOCK_SET|BM_LOCK_TEST);
	int rv;

	D_ASSERT(device, current != device->resource->worker.task);

	if (do_suspend_io)
		drbd_suspend_io(device, WRITE_ONLY);

	if (flags & BM_LOCK_SINGLE_SLOT)
		drbd_bm_slot_lock(peer_device, why, flags);
	else
		drbd_bm_lock(device, why, flags);

	rv = io_fn(device, peer_device);

	if (flags & BM_LOCK_SINGLE_SLOT)
		drbd_bm_slot_unlock(peer_device);
	else
		drbd_bm_unlock(device);

	if (do_suspend_io)
		drbd_resume_io(device);

	return rv;
}

void drbd_md_set_flag(struct drbd_device *device, enum mdf_flag flag) __must_hold(local)
{
	if (!device->ldev) {
		drbd_warn(device, "ldev is null.\n");
		return;
	}

	if (((int)(device->ldev->md.flags) & flag) != flag) {
		drbd_md_mark_dirty(device);
		device->ldev->md.flags |= flag;
	}
}

void drbd_md_set_peer_flag(struct drbd_peer_device *peer_device,
			   enum mdf_peer_flag flag) __must_hold(local)
{
	struct drbd_md *md;
	struct drbd_device *device = peer_device->device;
	if (!device->ldev) {
		drbd_warn(peer_device, "ldev is null.\n");
		return;
	}

	md = &device->ldev->md;
	if (!(md->peers[peer_device->node_id].flags & flag)) {
		drbd_md_mark_dirty(device);
		md->peers[peer_device->node_id].flags |= flag;
	}
}

void drbd_md_clear_flag(struct drbd_device *device, enum mdf_flag flag) __must_hold(local)
{
	if (!device->ldev) {
		drbd_warn(device, "ldev is null.\n");
		return;
	}

	if ((device->ldev->md.flags & flag) != 0) {
		drbd_md_mark_dirty(device);
		device->ldev->md.flags &= ~flag;
	}
}

void drbd_md_clear_peer_flag(struct drbd_peer_device *peer_device,
			     enum mdf_peer_flag flag) __must_hold(local)
{
	struct drbd_md *md;
	struct drbd_device *device = peer_device->device;
	if (!device->ldev) {
		drbd_warn(peer_device, "ldev is null.\n");
		return;
	}

	md = &device->ldev->md;
	if (md->peers[peer_device->node_id].flags & flag) {
		drbd_md_mark_dirty(device);
		md->peers[peer_device->node_id].flags &= ~flag;
	}
}

int drbd_md_test_flag(struct drbd_device *device, enum mdf_flag flag)
{
	if (!device->ldev) {
		drbd_warn(device, "ldev is null.\n");
		return 0;
	}

	return (device->ldev->md.flags & flag) != 0;
}

bool drbd_md_test_peer_flag(struct drbd_peer_device *peer_device, enum mdf_peer_flag flag)
{
	struct drbd_md *md;

	if (!peer_device->device->ldev) {
		drbd_warn(peer_device, "ldev is null.\n");
		return false;
	}

	md = &peer_device->device->ldev->md;
	if (peer_device->bitmap_index == -1)
		return false;

	return md->peers[peer_device->node_id].flags & flag;
}
#ifdef _WIN32
static void md_sync_timer_fn(PKDPC Dpc, PVOID data, PVOID SystemArgument1, PVOID SystemArgument2)
#else
static void md_sync_timer_fn(unsigned long data)
#endif
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(Dpc);

	struct drbd_device *device = (struct drbd_device *) data;
	drbd_device_post_work(device, MD_SYNC);
}

/**
 * drbd_wait_misc  -  wait for a request or peer request to make progress
 * @device:	device associated with the request or peer request
 * @peer_device: NULL when waiting for a request; the peer device of the peer
 *		 request when waiting for a peer request
 * @i:		the struct drbd_interval embedded in struct drbd_request or
 *		struct drbd_peer_request
 */
int drbd_wait_misc(struct drbd_device *device, struct drbd_peer_device *peer_device, struct drbd_interval *i)
{
#ifndef _WIN32
	DEFINE_WAIT(wait);
#endif
	long timeout;

	rcu_read_lock();
	if (peer_device) {
		struct net_conf *net_conf = rcu_dereference(peer_device->connection->transport.net_conf);
		if (!net_conf) {
			rcu_read_unlock();
			return -ETIMEDOUT;
		}
		timeout = net_conf->ko_count ? net_conf->timeout * HZ / 10 * net_conf->ko_count :
					       MAX_SCHEDULE_TIMEOUT;
	} else {
		struct disk_conf *disk_conf = rcu_dereference(device->ldev->disk_conf);
		timeout = disk_conf->disk_timeout * HZ / 10;
	}
	rcu_read_unlock();

	/* Indicate to wake up device->misc_wait on progress.  */
	i->waiting = true;
#ifndef _WIN32
	prepare_to_wait(&device->misc_wait, &wait, TASK_INTERRUPTIBLE);
#endif
	spin_unlock_irq(&device->resource->req_lock);
#ifdef _WIN32
    timeout = schedule(&device->misc_wait, timeout, __FUNCTION__, __LINE__);
#else
	timeout = schedule_timeout(timeout);
#endif
#ifndef _WIN32
	finish_wait(&device->misc_wait, &wait);
#endif
	spin_lock_irq(&device->resource->req_lock);
	if (!timeout || (peer_device && peer_device->repl_state[NOW] < L_ESTABLISHED))
		return -ETIMEDOUT;
	if (signal_pending(current))
		return -ERESTARTSYS;
	return 0;
}

#ifndef __maybe_unused
#define __maybe_unused                  __attribute__((unused))
#endif
void lock_all_resources(void)
{
	struct drbd_resource *resource;

	mutex_lock(&resources_mutex);


	// [DW-759] irq disable is ported to continue DISPATCH_LEVEL by global lock
	local_irq_disable();
	for_each_resource(resource, &drbd_resources)
#ifdef _WIN32
		spin_lock_irq(&resource->req_lock);
#else
		spin_lock_nested(&resource->req_lock, i++);
#endif
}

void unlock_all_resources(void)
{
	struct drbd_resource *resource;

	for_each_resource(resource, &drbd_resources)
#ifdef _WIN32
		spin_unlock_irq(&resource->req_lock);
#else
		spin_unlock(&resource->req_lock);
#endif
	// [DW-759] irq enable. return to PASSIVE_LEVEL
	local_irq_enable();
#ifdef _WIN32
	WDRBD_TRACE_REQ_LOCK("local_irq_enable : CurrentIrql(%d)\n", KeGetCurrentIrql());
#endif
	mutex_unlock(&resources_mutex);
}


long twopc_timeout(struct drbd_resource *resource)
{
	return resource->res_opts.twopc_timeout * HZ/10;
}

u64 directly_connected_nodes(struct drbd_resource *resource, enum which_state which)
{
	u64 directly_connected = 0;
	struct drbd_connection *connection;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[which] < C_CONNECTED)
			continue;
		directly_connected |= NODE_MASK(connection->peer_node_id);
	}
	rcu_read_unlock();

	return directly_connected;
}

#ifdef CONFIG_DRBD_FAULT_INJECTION
/* Fault insertion support including random number generator shamelessly
 * stolen from kernel/rcutorture.c */
struct fault_random_state {
	unsigned long state;
	unsigned long count;
};

#define FAULT_RANDOM_MULT 39916801  /* prime */
#define FAULT_RANDOM_ADD	479001701 /* prime */
#define FAULT_RANDOM_REFRESH 10000

/*
 * Crude but fast random-number generator.  Uses a linear congruential
 * generator, with occasional help from get_random_bytes().
 */
static unsigned long
_drbd_fault_random(struct fault_random_state *rsp)
{
	long refresh;

	if (!rsp->count--) {
		get_random_bytes(&refresh, sizeof(refresh));
		rsp->state += refresh;
		rsp->count = FAULT_RANDOM_REFRESH;
	}
	rsp->state = rsp->state * FAULT_RANDOM_MULT + FAULT_RANDOM_ADD;
#ifdef _WIN32
    return rsp->state;
#else
	return swahw32(rsp->state);
#endif
}

static char *
_drbd_fault_str(unsigned int type) {
	static char *_faults[] = {
		[DRBD_FAULT_MD_WR] = "Meta-data write",
		[DRBD_FAULT_MD_RD] = "Meta-data read",
		[DRBD_FAULT_RS_WR] = "Resync write",
		[DRBD_FAULT_RS_RD] = "Resync read",
		[DRBD_FAULT_DT_WR] = "Data write",
		[DRBD_FAULT_DT_RD] = "Data read",
		[DRBD_FAULT_DT_RA] = "Data read ahead",
		[DRBD_FAULT_BM_ALLOC] = "BM allocation",
		[DRBD_FAULT_AL_EE] = "EE allocation",
		[DRBD_FAULT_RECEIVE] = "receive data corruption",
	};

	return (type < DRBD_FAULT_MAX) ? _faults[type] : "**Unknown**";
}

unsigned int
_drbd_insert_fault(struct drbd_device *device, unsigned int type)
{
	static struct fault_random_state rrs = {0, 0};

	unsigned int ret = (
		(fault_devs == 0 ||
			((1 << device_to_minor(device)) & fault_devs) != 0) &&
		((int)((_drbd_fault_random(&rrs) % 100) + 1) <= fault_rate));

	if (ret) {
		fault_count++;

		if (drbd_ratelimit())
			drbd_warn(device, "***Simulating %s failure\n",
				_drbd_fault_str(type));
	}

	return ret;
}
#endif
#ifndef _WIN32
module_init(drbd_init)
module_exit(drbd_cleanup)

/* For transport layer */
EXPORT_SYMBOL(drbd_destroy_connection);
EXPORT_SYMBOL(drbd_destroy_path);
#endif
