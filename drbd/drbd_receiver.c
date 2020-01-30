/*
   drbd_receiver.c

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
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef _WIN32
#include "windows/drbd.h"
#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"
#include "drbd_vli.h"
#include <linux-compat/list.h>
#include <drbd_transport.h>
#include <drbd_windows.h>
#else
#include <linux/module.h>

#include <linux/uaccess.h>
#include <net/sock.h>

#include <linux/drbd.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/in.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/pkt_sched.h>
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <net/ipv6.h>
#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"
#include "drbd_vli.h"
#include <linux/scatterlist.h>
#endif

#ifdef _WIN32
/* DW-1587
* Turns off the C6319 warning.
* The use of comma does not cause any performance problems or bugs,
* but keep the code as it is written.
*
* Turns off the C6387 warning.
* Even though pointer parameters need to contain NULLs, 
* they are treated as warnings.
*/
#pragma warning (disable: 6053 6319 6387 28719)
#endif

#define PRO_FEATURES (DRBD_FF_TRIM|DRBD_FF_THIN_RESYNC|DRBD_FF_WSAME)

struct flush_work {
	struct drbd_work w;
	struct drbd_epoch *epoch;
};

enum finish_epoch {
	FE_STILL_LIVE,
	FE_DESTROYED,
	FE_RECYCLED,
};

enum resync_reason {
	AFTER_UNSTABLE,
	DISKLESS_PRIMARY,
};

IO_COMPLETION_ROUTINE one_flush_endio;

int drbd_do_features(struct drbd_connection *connection);
int drbd_do_auth(struct drbd_connection *connection);

extern spinlock_t g_inactive_lock;

static enum finish_epoch drbd_may_finish_epoch(struct drbd_connection *, struct drbd_epoch *, enum epoch_event);
static int e_end_block(struct drbd_work *, int);
static void cleanup_unacked_peer_requests(struct drbd_connection *connection);
static void cleanup_peer_ack_list(struct drbd_connection *connection);
static ULONG_PTR node_ids_to_bitmap(struct drbd_device *device, u64 node_ids);
#ifdef _WIN32
static int process_twopc(struct drbd_connection *, struct twopc_reply *, struct packet_info *, ULONG_PTR);
static void drbd_resync(struct drbd_peer_device *, enum resync_reason) __must_hold(local);
#else
static int process_twopc(struct drbd_connection *, struct twopc_reply *, struct packet_info *, unsigned long);
static void drbd_resync(struct drbd_peer_device *, enum resync_reason) __must_hold(local);
#endif
static void drbd_unplug_all_devices(struct drbd_connection *connection);
static struct drbd_epoch *previous_epoch(struct drbd_connection *connection, struct drbd_epoch *epoch)
{
	struct drbd_epoch *prev;
	spin_lock(&connection->epoch_lock);
	prev = list_entry(epoch->list.prev, struct drbd_epoch, list);
	if (prev == epoch || prev == connection->current_epoch)
		prev = NULL;
	spin_unlock(&connection->epoch_lock);
	return prev;
}

#ifndef _WIN32 
/*
 * some helper functions to deal with single linked page lists,
 * page->private being our "next" pointer.
 */

/* If at least n pages are linked at head, get n pages off.
 * Otherwise, don't modify head, and return NULL.
 * Locking is the responsibility of the caller.
 */
static struct page *page_chain_del(struct page **head, int n)
{
	struct page *page;
#ifdef _WIN32
	struct page *tmp = NULL;
#else
	struct page *tmp;
#endif

	BUG_ON(!n);
	BUG_ON(!head);

	page = *head;

	if (!page)
		return NULL;

	while (page) {
		tmp = page_chain_next(page);
		set_page_chain_offset(page, 0);
		set_page_chain_size(page, 0);
		if (--n == 0)
			break; /* found sufficient pages */
		if (tmp == NULL)
			/* insufficient pages, don't use any of them. */
			return NULL;
		page = tmp;
	}

	/* add end of list marker for the returned list */
	set_page_chain_next(page, NULL);
	/* actual return value, and adjustment of head */
	page = *head;
	*head = tmp;
	return page;
}

/* may be used outside of locks to find the tail of a (usually short)
 * "private" page chain, before adding it back to a global chain head
 * with page_chain_add() under a spinlock. */
static struct page *page_chain_tail(struct page *page, int *len)
{
	struct page *tmp;
	int i = 1;
	while ((tmp = page_chain_next(page)))
		++i, page = tmp;
	if (len)
		*len = i;
	return page;
}

static int page_chain_free(struct page *page)
{
	struct page *tmp;
	int i = 0;
	page_chain_for_each_safe(page, tmp) {
#ifdef _WIN32 
		set_page_chain_next_offset_size(page, NULL, 0, 0);
		__free_page(page);
#else
		set_page_chain_next_offset_size(page, NULL, 0, 0);
		put_page(page);
#endif
		++i;
	}
	return i;
}

static void page_chain_add(struct page **head,
		struct page *chain_first, struct page *chain_last)
{
#if 1
	struct page *tmp;
	tmp = page_chain_tail(chain_first, NULL);
	BUG_ON(tmp != chain_last);
#endif

	/* add chain to head */
#ifdef _WIN32
	// unused!
#else
	set_page_chain_next(chain_last, *head);
#endif
	*head = chain_first;
}
#endif

#ifdef _WIN32
static void * __drbd_alloc_pages(unsigned int number)
{
	/* Yes, testing drbd_pp_vacant outside the lock is racy.
	* So what. It saves a spin_lock. */
	
	// DW-1457: checking drbd_pp_vacant has been removed, WDRBD has no allocated memory pool but allocates as it needs.
	void * mem = kmalloc(number * PAGE_SIZE, 0, '17DW');
	if (mem)
	{
		spin_lock(&drbd_pp_lock);
		drbd_pp_vacant -= (int)number;
		spin_unlock(&drbd_pp_lock);
		return mem;
	}	

	return NULL;
}
#else

static struct page *__drbd_alloc_pages(unsigned int number, gfp_t gfp_mask)
{
	struct page *page = NULL;
	struct page *tmp = NULL;
	unsigned int i = 0;

	/* Yes, testing drbd_pp_vacant outside the lock is racy.
	 * So what. It saves a spin_lock. */
	if (drbd_pp_vacant >= number) {
		spin_lock(&drbd_pp_lock);
		page = page_chain_del(&drbd_pp_pool, number);
		if (page)
			drbd_pp_vacant -= number;
		spin_unlock(&drbd_pp_lock);
		if (page)
			return page;
	}

	for (i = 0; i < number; i++) {
		tmp = alloc_page(gfp_mask);
		if (!tmp)
			break;
		set_page_chain_next_offset_size(tmp, page, 0, 0);
		page = tmp;
	}

	if (i == number)
		return page;

	/* Not enough pages immediately available this time.
	 * No need to jump around here, drbd_alloc_pages will retry this
	 * function "soon". */
	if (page) {
		tmp = page_chain_tail(page, NULL);
		spin_lock(&drbd_pp_lock);
		page_chain_add(&drbd_pp_pool, page, tmp);
		drbd_pp_vacant += i;
		spin_unlock(&drbd_pp_lock);
	}
	return NULL;
}

#endif
/* kick lower level device, if we have more than (arbitrary number)
 * reference counts on it, which typically are locally submitted io
 * requests.  don't use unacked_cnt, so we speed up proto A and B, too. */
static void maybe_kick_lo(struct drbd_device *device)
{
	struct disk_conf *dc;
	unsigned int watermark = 1000000;

	if (get_ldev(device)) {
		rcu_read_lock();
		dc = rcu_dereference(device->ldev->disk_conf);
		if (dc)
			min_not_zero(dc->unplug_watermark, watermark);
		rcu_read_unlock();

		if (atomic_read(&device->local_cnt) >= (int)watermark)
			drbd_kick_lo(device);
		put_ldev(device);
	}
}

static void reclaim_finished_net_peer_reqs(struct drbd_connection *connection,
					   struct list_head *to_be_freed)
{
	struct drbd_peer_request *peer_req, *tmp;

	/* The EEs are always appended to the end of the list. Since
	   they are sent in order over the wire, they have to finish
	   in order. As soon as we see the first not finished we can
	   stop to examine the list... */
#ifdef _WIN32
	list_for_each_entry_safe(struct drbd_peer_request, peer_req, tmp, &connection->net_ee, w.list) {
#else 
	list_for_each_entry_safe(peer_req, tmp, &connection->net_ee, w.list) {
#endif
		if (drbd_peer_req_has_active_page(peer_req))
			break;
		list_move(&peer_req->w.list, to_be_freed);
	}
}

static void drbd_reclaim_net_peer_reqs(struct drbd_connection *connection)
{
	UNREFERENCED_PARAMETER(connection);

#ifndef _WIN32   // No need to use in Windows
	LIST_HEAD(reclaimed);
	struct drbd_peer_request *peer_req, *t;
	struct drbd_resource *resource = connection->resource;

	spin_lock_irq(&resource->req_lock);
	reclaim_finished_net_peer_reqs(connection, &reclaimed);
	spin_unlock_irq(&resource->req_lock);

	list_for_each_entry_safe(peer_req, t, &reclaimed, w.list)
		drbd_free_net_peer_req(peer_req);
#endif
}

static void conn_maybe_kick_lo(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_device *device;
	int vnr;

	rcu_read_lock();
#ifdef _WIN32
	idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr)
#else
	idr_for_each_entry(&resource->devices, device, vnr)
#endif
		maybe_kick_lo(device);
	rcu_read_unlock();
}

/**
 * drbd_alloc_pages() - Returns @number pages, retries forever (or until signalled)
 * @device:	DRBD device.
 * @number:	number of pages requested
 * @gfp_mask:	how to allocate and whether to loop until we succeed
 *
 * Tries to allocate number pages, first from our own page pool, then from
 * the kernel.
 * Possibly retry until DRBD frees sufficient pages somewhere else.
 *
 * If this allocation would exceed the max_buffers setting, we throttle
 * allocation (schedule_timeout) to give the system some room to breathe.
 *
 * We do not use max-buffers as hard limit, because it could lead to
 * congestion and further to a distributed deadlock during online-verify or
 * (checksum based) resync, if the max-buffers, socket buffer sizes and
 * resync-rate settings are mis-configured.
 *
 * Returns a page chain linked via (struct drbd_page_chain*)&page->lru.
 */
#ifdef _WIN32
void* drbd_alloc_pages(struct drbd_transport *transport, unsigned int number, bool retry)
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);
	void* mem = NULL;
	
	unsigned int mxb;

	rcu_read_lock();
	mxb = rcu_dereference(transport->net_conf)->max_buffers;
	rcu_read_unlock();

	if ((unsigned int)atomic_read(&connection->pp_in_use) < mxb)
		mem = __drbd_alloc_pages(number);
	while (mem == NULL) {
		if ((unsigned int)atomic_read(&connection->pp_in_use) < mxb) {
			mem = __drbd_alloc_pages(number);
			if (mem)
				break;
		}

		if (!retry)
			break;

		if (signal_pending(current)) {
			drbd_warn(connection, "drbd_alloc_pages interrupted!\n");
			break;
		}

		// DW-1457: resync can be stuck with small max buffer beside resync rate, recover it "gracefully"(quoting Linux drbd commit 'facf4555')
		if (schedule_timeout(HZ / 10) == 0)
			mxb = UINT_MAX;

#ifdef _WIN32
		schedule(&drbd_pp_wait, HZ, __FUNCTION__, __LINE__);
#else
		schedule(&drbd_pp_wait, MAX_SCHEDULE_TIMEOUT, __FUNCTION__, __LINE__);
#endif
	}
	
	if (mem) {
		atomic_add(number, &connection->pp_in_use);
	}

	return mem;
}

#else
struct page *drbd_alloc_pages(struct drbd_transport *transport, unsigned int number,
			      gfp_t gfp_mask)
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);
	struct page *page = NULL;
	DEFINE_WAIT(wait);
	unsigned int mxb;

	rcu_read_lock();
	mxb = rcu_dereference(transport->net_conf)->max_buffers;
	rcu_read_unlock();

	if (atomic_read(&connection->pp_in_use) < mxb)
		page = __drbd_alloc_pages(number, gfp_mask & ~__GFP_RECLAIM);

	/* Try to keep the fast path fast, but occasionally we need
	 * to reclaim the pages we lended to the network stack. */
	if (page && atomic_read(&connection->pp_in_use_by_net) > 512)
		drbd_reclaim_net_peer_reqs(connection);

	while (page == NULL) {
		prepare_to_wait(&drbd_pp_wait, &wait, TASK_INTERRUPTIBLE);

		conn_maybe_kick_lo(connection);
		drbd_reclaim_net_peer_reqs(connection);

		if (atomic_read(&connection->pp_in_use) < mxb) {
			page = __drbd_alloc_pages(number, gfp_mask);
			if (page)
				break;
		}

		if (!(gfp_mask & __GFP_RECLAIM))
			break;

		if (signal_pending(current)) {
			drbd_warn(connection, "drbd_alloc_pages interrupted!\n");
			break;
		}

		if (schedule_timeout(HZ/10) == 0)
			mxb = UINT_MAX;
	}
	finish_wait(&drbd_pp_wait, &wait);

	if (page)
		atomic_add(number, &connection->pp_in_use);
	return page;
}

#endif
/* Must not be used from irq, as that may deadlock: see drbd_alloc_pages.
 * Is also used from inside an other spin_lock_irq(&resource->req_lock);
 * Either links the page chain back to the global pool,
 * or returns all pages to the system. */
#ifdef _WIN32
/* wdrbd actually don't allocate page pool. it only manage page_count for pool_size, and then it doesn't free memory
* this part is differnce with __drbd_free_peer_req().
*/
void drbd_free_pages(struct drbd_transport *transport, int page_count, int is_net) // redefinition with page_count param.
#else
void drbd_free_pages(struct drbd_transport *transport, struct page *page, int is_net)
#endif
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);
	atomic_t *a = is_net ? &connection->pp_in_use_by_net : &connection->pp_in_use;
	int i;

#ifdef _WIN32
	if (page_count <= 0)
		return;

	spin_lock(&drbd_pp_lock);
	drbd_pp_vacant += page_count;  // required to analyze drbd_pp_vacant.
	spin_unlock(&drbd_pp_lock);
	i = page_count;
#else
	if (page == NULL)
		return;

	if (drbd_pp_vacant > (DRBD_MAX_BIO_SIZE/PAGE_SIZE) * minor_count)
		i = page_chain_free(page);
	else {
		struct page *tmp;
		tmp = page_chain_tail(page, &i);
		spin_lock(&drbd_pp_lock);
		page_chain_add(&drbd_pp_pool, page, tmp);
		drbd_pp_vacant += i;
		spin_unlock(&drbd_pp_lock);
	}
#endif
	i = atomic_sub_return(i, a);
	if (i < 0)
	{
		drbd_warn(connection, "ASSERTION FAILED: %s: %d < 0\n",
			is_net ? "pp_in_use_by_net" : "pp_in_use", i);
#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-1239 : If pp_in_use is negative, set to 0.
		atomic_set(&connection->pp_in_use, 0);
#endif
	}

	wake_up(&drbd_pp_wait);
}

/*
You need to hold the req_lock:
 _drbd_wait_ee_list_empty()

You must not have the req_lock:
 drbd_free_peer_req()
 drbd_alloc_peer_req()
 drbd_free_peer_reqs()
 drbd_ee_fix_bhs()
 drbd_finish_peer_reqs()
 drbd_clear_done_ee()
 drbd_wait_ee_list_empty()
*/

/* normal: payload_size == request size (bi_size)
 * w_same: payload_size == logical_block_size
 * trim: payload_size == 0 */
struct drbd_peer_request *
drbd_alloc_peer_req(struct drbd_peer_device *peer_device, gfp_t gfp_mask) __must_hold(local)
{
	UNREFERENCED_PARAMETER(gfp_mask);

	struct drbd_device *device = peer_device->device;
	struct drbd_peer_request *peer_req;

	if (drbd_insert_fault(device, DRBD_FAULT_AL_EE))
		return NULL;
#ifdef _WIN32
	peer_req = ExAllocateFromNPagedLookasideList(&drbd_ee_mempool);
	if (!peer_req) {
		drbd_err(device, "%s: allocation failed\n", __func__);
		return NULL;
	}
#else
	peer_req = mempool_alloc(drbd_ee_mempool, gfp_mask & ~__GFP_HIGHMEM);
	if (!peer_req) {
		if (!(gfp_mask & __GFP_NOWARN))
			drbd_err(device, "%s: allocation failed\n", __func__);
		return NULL;
	}
#endif

	memset(peer_req, 0, sizeof(*peer_req));
	INIT_LIST_HEAD(&peer_req->w.list);
	drbd_clear_interval(&peer_req->i);
	INIT_LIST_HEAD(&peer_req->recv_order);
	INIT_LIST_HEAD(&peer_req->wait_for_actlog);
	peer_req->submit_jif = jiffies;
	peer_req->peer_device = peer_device;

	return peer_req;
}

void __drbd_free_peer_req(struct drbd_peer_request *peer_req, int is_net)
{
#ifndef _WIN32
	might_sleep();
#else
	// DW-1773 peer_request is managed as inactive_ee, so peer_req_databuf is modified to be released from drbd_free_peer_req()
	//if ( !(peer_req->flags & EE_WRITE) && peer_req->peer_req_databuf)	
	if (peer_req->peer_req_databuf) {
		kfree2(peer_req->peer_req_databuf);
	}
#endif

	if (peer_req->flags & EE_HAS_DIGEST)
		kfree(peer_req->digest);

	if (!(peer_req->flags & EE_WAS_LOST_REQ)) {
		struct drbd_peer_device *peer_device = peer_req->peer_device;

		D_ASSERT(peer_device, atomic_read(&peer_req->pending_bios) == 0);
		D_ASSERT(peer_device, drbd_interval_empty(&peer_req->i));

		//DW-1935
		drbd_free_page_chain(&peer_device->connection->transport, &peer_req->page_chain, is_net);
	}

#ifdef _WIN32
	ExFreeToNPagedLookasideList(&drbd_ee_mempool, peer_req);
#else
	mempool_free(peer_req, drbd_ee_mempool);
#endif

}

int drbd_free_peer_reqs(struct drbd_resource *resource, struct list_head *list, bool is_net_ee)
{
	LIST_HEAD(work_list);
	struct drbd_peer_request *peer_req, *t;
	int count = 0;

	spin_lock_irq(&resource->req_lock);
	list_splice_init(list, &work_list);
	spin_unlock_irq(&resource->req_lock);
#ifdef _WIN32
	list_for_each_entry_safe(struct drbd_peer_request, peer_req, t, &work_list, w.list) {
#else
	list_for_each_entry_safe(peer_req, t, &work_list, w.list) {
#endif
		__drbd_free_peer_req(peer_req, is_net_ee);
		count++;
	}
	return count;
}

/*
 * See also comments in _req_mod(,BARRIER_ACKED) and receive_Barrier.
 */
static int drbd_finish_peer_reqs(struct drbd_connection *connection)
{
	LIST_HEAD(work_list);
	LIST_HEAD(reclaimed);
	struct drbd_peer_request *peer_req, *t;
	int err = 0;
	int n = 0;

	spin_lock_irq(&connection->resource->req_lock);
	reclaim_finished_net_peer_reqs(connection, &reclaimed);
	list_splice_init(&connection->done_ee, &work_list);
	spin_unlock_irq(&connection->resource->req_lock);

#ifdef _WIN32
	list_for_each_entry_safe(struct drbd_peer_request, peer_req, t, &reclaimed, w.list)
		drbd_free_net_peer_req(peer_req);
#else 
	list_for_each_entry_safe(peer_req, t, &reclaimed, w.list)
		drbd_free_net_peer_req(peer_req);
#endif

	/* possible callbacks here:
	 * e_end_block, and e_end_resync_block, e_send_discard_write.
	 * all ignore the last argument.
	 */
#ifdef _WIN32
	list_for_each_entry_safe(struct drbd_peer_request, peer_req, t, &work_list, w.list) {
#else 
	list_for_each_entry_safe(peer_req, t, &work_list, w.list) {
#endif
		int err2;
		// MODIFIED_BY_MANTECH DW-1665: check callback function(e_end_block)
		bool epoch_put = (peer_req->w.cb == e_end_block) ? true : false;

		++n;
		/* list_del not necessary, next/prev members not touched */
		err2 = peer_req->w.cb(&peer_req->w, !!err);
		if (!err)
			err = err2;

		check_and_clear_io_error_in_secondary(peer_req->peer_device);

		if (!list_empty(&peer_req->recv_order)) {
#ifdef _WIN32
			// MODIFIED_BY_MANTECH DW-972: Gotten peer_req is not always allocated in current connection since the work_list is spliced from device->done_ee.
			// Provide peer_req associated transport to be freed from right connection.
			drbd_free_page_chain(&peer_req->peer_device->connection->transport, &peer_req->page_chain, 0);

			// MODIFIED_BY_MANTECH DW-1665: change the EV_PUT(e_end_block) setting location
			if (epoch_put) 
				drbd_may_finish_epoch(peer_req->peer_device->connection, peer_req->epoch, EV_PUT + (!!err ? EV_CLEANUP : 0));
#else
			drbd_free_page_chain(&connection->transport, &peer_req->page_chain, 0);
#endif
		} else {
			// MODIFIED_BY_MANTECH DW-1665: change the EV_PUT(e_end_block) setting location
			if (epoch_put) 
				drbd_may_finish_epoch(peer_req->peer_device->connection, peer_req->epoch, EV_PUT + (!!err ? EV_CLEANUP : 0));

			drbd_free_peer_req(peer_req);
		}
	}
	if (atomic_sub_and_test(n, &connection->done_ee_cnt))
		wake_up(&connection->ee_wait);

	return err;
}

static int drbd_recv(struct drbd_connection *connection, void **buf, size_t size, int flags)
{
	struct drbd_transport_ops *tr_ops = connection->transport.ops;
	int rv;

	rv = tr_ops->recv(&connection->transport, DATA_STREAM, buf, size, flags);

	if (rv < 0) {
		if (rv == -ECONNRESET)
			drbd_info(connection, "sock was reset by peer\n");
		else if (rv != -ERESTARTSYS)
			drbd_info(connection, "sock_recvmsg returned %d\n", rv);
	} else if (rv == 0) {
		if (test_bit(DISCONNECT_EXPECTED, &connection->flags)) {
			long t;
			rcu_read_lock();
			t = rcu_dereference(connection->transport.net_conf)->ping_timeo * HZ/10;
			rcu_read_unlock();
#ifdef _WIN32
			wait_event_timeout(t, connection->ping_wait, connection->cstate[NOW] < C_CONNECTED, t);
#else
			t = wait_event_timeout(connection->ping_wait, connection->cstate[NOW] < C_CONNECTED, t);
#endif
			if (t)
				goto out;
		}
		drbd_info(connection, "sock was shut down by peer\n");
	}

	if (rv != (int)size)
		change_cstate_ex(connection, C_BROKEN_PIPE, CS_HARD);

out:
	return rv;
}

static int drbd_recv_into(struct drbd_connection *connection, void *buf, size_t size)
{
	int err;

	err = drbd_recv(connection, &buf, size, CALLER_BUFFER);

	if (err != (int)size) {
		if (err >= 0)
			err = -EIO;
	} else
		err = 0;
	return err;
}

static int drbd_recv_all(struct drbd_connection *connection, void **buf, size_t size)
{
	int err;

	err = drbd_recv(connection, buf, size, 0);

	if (err != (int)size) {
		if (err >= 0)
			err = -EIO;
	} else
		err = 0;
	return err;
}

static int drbd_recv_all_warn(struct drbd_connection *connection, void **buf, size_t size)
{
	int err;

	err = drbd_recv_all(connection, buf, size);
	if (err && !signal_pending(current))
		drbd_warn(connection, "short read (expected size %d)\n", (int)size);
	return err;
}

static int decode_header(struct drbd_connection *, void *, struct packet_info *);

/* Gets called if a connection is established, or if a new minor gets created
   in a connection */
int drbd_connected(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	int err;

	atomic_set(&peer_device->packet_seq, 0);
	peer_device->peer_seq = 0;

	//DW-1806
	KeResetEvent(&peer_device->state_initial_send_event);
	err = drbd_send_sync_param(peer_device);
	if (!err)
		err = drbd_send_sizes(peer_device, 0, 0);
	if (!err)
		err = drbd_send_uuids(peer_device, 0, 0);
	if (!err) {
		err = drbd_send_current_state(peer_device);
		//DW-1806
		set_bit(INITIAL_STATE_SENT, &peer_device->flags);
	}
	//DW-1806
	KeSetEvent(&peer_device->state_initial_send_event, 0, FALSE);

	clear_bit(USE_DEGR_WFC_T, &peer_device->flags);
	clear_bit(RESIZE_PENDING, &peer_device->flags);
	mod_timer(&device->request_timer, jiffies + HZ); /* just start it here. */
	return err;
}
#ifdef _WIN32
void connect_timer_fn(PKDPC Dpc, PVOID data, PVOID arg1, PVOID arg2)
#else
void connect_timer_fn(unsigned long data)
#endif
{
	UNREFERENCED_PARAMETER(arg1);
	UNREFERENCED_PARAMETER(arg2);
	UNREFERENCED_PARAMETER(Dpc);

	if (data == NULL)
		return;

	struct drbd_connection *connection = (struct drbd_connection *) data;
	struct drbd_resource *resource = connection->resource;
	unsigned long irq_flags;

	spin_lock_irqsave(&resource->req_lock, irq_flags);
	drbd_queue_work(&connection->sender_work, &connection->connect_timer_work);
	spin_unlock_irqrestore(&resource->req_lock, irq_flags);
}

void conn_connect2(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	atomic_set64(&connection->ap_in_flight, 0);
	atomic_set64(&connection->rs_in_flight, 0);

	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		struct drbd_device *device = peer_device->device;
		kref_get(&device->kref);
		/* connection cannot go away: caller holds a reference. */
		rcu_read_unlock();
		drbd_connected(peer_device);
		rcu_read_lock();
		kref_put(&device->kref, drbd_destroy_device);
	}
	rcu_read_unlock();
}

void conn_disconnect(struct drbd_connection *connection);

int connect_work(struct drbd_work *work, int cancel)
{
	UNREFERENCED_PARAMETER(cancel);

	struct drbd_connection *connection =
		container_of(work, struct drbd_connection, connect_timer_work);
	enum drbd_state_rv rv;

	if (connection->cstate[NOW] != C_CONNECTING)
		goto out_put;

	rv = change_cstate_ex(connection, C_CONNECTED, CS_SERIALIZE | CS_VERBOSE | CS_DONT_RETRY);

	if (rv >= SS_SUCCESS) {
		conn_connect2(connection);
	} else if (rv == SS_TIMEOUT || rv == SS_CONCURRENT_ST_CHG) {
		if (connection->cstate[NOW] != C_CONNECTING)
			goto out_put;
		connection->connect_timer.expires = jiffies + HZ/20;
		add_timer(&connection->connect_timer);
		return 0; /* Return early. Keep the reference on the connection! */
#ifdef _WIN32_V9_DW_663_LINBIT_PATCH // _WIN32 // DW-663 from philipp.reisner@linbit.com 2016.05.03		
	} else if (rv == SS_TWO_PRIMARIES) { 
		change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
		drbd_alert(connection, "Split-Brain since more primaries than allowed; dropping connection!\n");
		drbd_khelper(NULL, connection, "split-brain");
#endif		
	} else {
		drbd_info(connection, "Failure to connect; retrying\n");
		change_cstate_ex(connection, C_NETWORK_FAILURE, CS_HARD);
	}

out_put:
	kref_debug_put(&connection->kref_debug, 11);
	kref_put(&connection->kref, drbd_destroy_connection);
	return 0;
}

/*
 * Returns true if we have a valid connection.
 */
static bool conn_connect(struct drbd_connection *connection)
{
	struct drbd_transport *transport = &connection->transport;
	struct drbd_resource *resource = connection->resource;
	int ping_timeo, ping_int, h, err, vnr, timeout;
	struct drbd_peer_device *peer_device;
	struct net_conf *nc;
	bool discard_my_data;
	bool have_mutex;

start:
	WDRBD_CONN_TRACE("conn_connect\n"); 
	have_mutex = false;

	clear_bit(DISCONNECT_EXPECTED, &connection->flags);
	if (change_cstate_ex(connection, C_CONNECTING, CS_VERBOSE) < SS_SUCCESS) {
		/* We do not have a network config. */
		return false;
	}

	/* Assume that the peer only understands protocol 80 until we know better.  */
	connection->agreed_pro_version = 80;

#ifdef _WIN32
	// DW-1398: initialize.
	atomic_set(&transport->listening_done, false);
#endif

	err = transport->ops->connect(transport);
	if (err == -EAGAIN) {
		if (connection->cstate[NOW] == C_DISCONNECTING)
			return false;
		goto retry;
	} else if (err < 0) {
		drbd_warn(connection, "Failed to initiate connection, err=%d\n", err);
#ifdef _WIN32 //DW-1608 : If cstate is already Networkfailure or Connecting, it will retry the connection.
		if (connection->cstate[NOW] == C_NETWORK_FAILURE || connection->cstate[NOW] == C_CONNECTING){
			drbd_warn(connection, "cstate is C_NETWORK_FAILURE or C_CONNECTING now goto retry;\n");
			goto retry;
		}
#endif
		goto abort;
	}

	connection->last_received = jiffies;

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	ping_timeo = nc->ping_timeo;
	ping_int = nc->ping_int;
	rcu_read_unlock();

	/* Make sure we are "uncorked", otherwise we risk timeouts,
	* in case this is a reconnect and we had been corked before. */
	drbd_uncork(connection, CONTROL_STREAM);
	drbd_uncork(connection, DATA_STREAM);
	
	/* Make sure the handshake happens without interference from other threads,
	* or the challenge respons authentication could be garbled. */
	mutex_lock(&connection->mutex[DATA_STREAM]);
	have_mutex = true;
	transport->ops->set_rcvtimeo(transport, DATA_STREAM, ping_timeo * 4 * HZ/10);
	transport->ops->set_rcvtimeo(transport, CONTROL_STREAM, ping_int * HZ);

	h = drbd_do_features(connection);
	if (h < 0)
		goto abort;
	if (h == 0)
		goto retry;

	if (connection->cram_hmac_tfm) {
		switch (drbd_do_auth(connection)) {
		case -1:
			drbd_err(connection, "Authentication of peer failed\n");
			goto abort;
		case 0:
			drbd_err(connection, "Authentication of peer failed, trying again.\n");
			goto retry;
		}
	}

	transport->ops->set_rcvtimeo(transport, DATA_STREAM, MAX_SCHEDULE_TIMEOUT);

	discard_my_data = test_bit(CONN_DISCARD_MY_DATA, &connection->flags);

	if (__drbd_send_protocol(connection, P_PROTOCOL) == -EOPNOTSUPP)
		goto abort;

#ifdef _WIN32
	rcu_read_lock_w32_inner();
#else
	rcu_read_lock();
#endif
#ifdef _WIN32
	idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		clear_bit(INITIAL_STATE_SENT, &peer_device->flags);
		clear_bit(INITIAL_STATE_RECEIVED, &peer_device->flags);
		//DW-1799
		clear_bit(INITIAL_SIZE_RECEIVED, &peer_device->flags);
		peer_device->bm_ctx.count = 0;
	}
#ifdef _WIN32
	idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif

		if (discard_my_data)
			set_bit(DISCARD_MY_DATA, &peer_device->flags);
		else
			clear_bit(DISCARD_MY_DATA, &peer_device->flags);
	}
	rcu_read_unlock();
	mutex_unlock(&connection->mutex[DATA_STREAM]);
	have_mutex = false;

#ifdef _WIN32_SEND_BUFFING
	// DW-1436 removing the protocol dependency of the send buffer thread
	if (nc->sndbuf_size >= DRBD_SNDBUF_SIZE_MIN) {
		bool send_buffring = FALSE;

		send_buffring = transport->ops->start_send_buffring(transport, nc->sndbuf_size);
		if (send_buffring)
			drbd_info(connection, "send-buffering ok size(%llu) cong_fill(%llu)\n", nc->sndbuf_size, (nc->cong_fill));
		else
			drbd_warn(connection, "send-buffering disabled\n");
	} else {
		drbd_warn(connection, "send-buffering disabled nc->sndbuf_size:%llu\n",nc->sndbuf_size);
	}
#endif

	drbd_thread_start(&connection->ack_receiver);
	connection->ack_sender =
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
#ifndef _WIN32
		alloc_ordered_workqueue("drbd_as_%s", WQ_MEM_RECLAIM, connection->resource->name);
#else
		create_singlethread_workqueue("drbd_ack_sender");
#endif
	if (!connection->ack_sender) {
		drbd_err(connection, "Failed to create workqueue ack_sender\n");
		goto abort;
	}

	if (connection->agreed_pro_version >= 110) {
		if (resource->res_opts.node_id < connection->peer_node_id) {
			kref_get(&connection->kref);
			kref_debug_get(&connection->kref_debug, 11);
			connection->connect_timer_work.cb = connect_work;
			timeout = twopc_retry_timeout(resource, 0);
			drbd_debug(connection, "Waiting for %ums to avoid transaction "
				   "conflicts\n", jiffies_to_msecs(timeout));
			connection->connect_timer.expires = jiffies + timeout;
			add_timer(&connection->connect_timer);
		}
#ifdef _WIN32 
		else
		{
			drbd_debug(connection, "Skip connect_work\n");
#if 0
			LARGE_INTEGER	nWaitTime;
			KTIMER ktimer;
			nWaitTime = RtlConvertLongToLargeInteger(RELATIVE(MILLISECONDS(200)));
			KeInitializeTimer(&ktimer);
			KeSetTimerEx(&ktimer, nWaitTime, 0, NULL);
			KeWaitForSingleObject(&ktimer, Executive, KernelMode, FALSE, NULL);
#endif
		}
#endif
	} else {
		enum drbd_state_rv rv;
		rv = change_cstate_ex(connection, C_CONNECTED,
				   CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE | CS_LOCAL_ONLY);
		if (rv < SS_SUCCESS || connection->cstate[NOW] != C_CONNECTED)
			goto retry;
		conn_connect2(connection);
	}
	return true;

retry:
	if (have_mutex)
		mutex_unlock(&connection->mutex[DATA_STREAM]);

	conn_disconnect(connection);
	schedule_timeout_interruptible(HZ);
#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1176: retrying connection doesn't make sense while receiver's restarting, returning false lets drbd re-enters connection once receiver goes running.
	if (get_t_state(&connection->receiver) == RESTARTING)
	{
		drbd_warn(connection, "could not retry connection since receiver is restarting\n");
		return false;
	}
#endif
	goto start;

abort:
	if (have_mutex)
		mutex_unlock(&connection->mutex[DATA_STREAM]);
	change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
	return false;
}

int decode_header(struct drbd_connection *connection, void *header, struct packet_info *pi)
{
	unsigned int header_size = drbd_header_size(connection);

	if (header_size == sizeof(struct p_header100) &&
	    *(__be32 *)header == cpu_to_be32(DRBD_MAGIC_100)) {
		struct p_header100 *h = header;
		if (h->pad != 0) {
			drbd_err(connection, "Header padding is not zero\n");
			return -EINVAL;
		}
		pi->vnr = (s16)be16_to_cpu(h->volume);
		pi->cmd = be16_to_cpu(h->command);
		pi->size = be32_to_cpu(h->length);
	} else if (header_size == sizeof(struct p_header95) &&
		   *(__be16 *)header == cpu_to_be16(DRBD_MAGIC_BIG)) {
		struct p_header95 *h = header;
		pi->cmd = be16_to_cpu(h->command);
		pi->size = be32_to_cpu(h->length);
		pi->vnr = 0;
	} else if (header_size == sizeof(struct p_header80) &&
		   *(__be32 *)header == cpu_to_be32(DRBD_MAGIC)) {
		struct p_header80 *h = header;
		pi->cmd = be16_to_cpu(h->command);
		pi->size = be16_to_cpu(h->length);
		pi->vnr = 0;
	} else {
		drbd_err(connection, "Wrong magic value 0x%08x in protocol version %d\n",
			 be32_to_cpu(*(__be32 *)header),
			 connection->agreed_pro_version);
		return -EINVAL;
	}
#ifdef _WIN32
	pi->data = (UCHAR *)header + header_size;
#else
	pi->data = header + header_size;
#endif
	return 0;
}

#ifdef blk_queue_plugged
static void drbd_unplug_all_devices(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_device *device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr) {
		kref_get(&device->kref);
		rcu_read_unlock();
		drbd_kick_lo(device);
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}
#else
static void drbd_unplug_all_devices(struct drbd_connection *connection)
{
	UNREFERENCED_PARAMETER(connection);

#ifndef _WIN32
	if (current->plug == &connection->receiver_plug) {
		blk_finish_plug(&connection->receiver_plug);
		blk_start_plug(&connection->receiver_plug);
	} /* else: maybe just schedule() ?? */
#endif	
}
#endif


static int drbd_recv_header(struct drbd_connection *connection, struct packet_info *pi)
{
	void *buffer;
	int err;

	err = drbd_recv_all_warn(connection, &buffer, drbd_header_size(connection));
	if(err)
		return err;

	err = decode_header(connection, buffer, pi);
	connection->last_received = jiffies;

	return err;
}

static int drbd_recv_header_maybe_unplug(struct drbd_connection *connection, struct packet_info *pi)
{
 	struct drbd_transport_ops *tr_ops = connection->transport.ops;
	unsigned int size = drbd_header_size(connection);
	void *buffer;
	int err;

#ifdef _WIN32
	err = tr_ops->recv(&connection->transport, DATA_STREAM, &buffer,
			   size, MSG_NOSIGNAL );
#else
	err = tr_ops->recv(&connection->transport, DATA_STREAM, &buffer,
			   size, MSG_NOSIGNAL | MSG_DONTWAIT);
#endif
	
	if (err != (int)size) {
		int rflags = 0;

		/* If we have nothing in the receive buffer now, to reduce
		 * application latency, try to drain the backend queues as
		 * quickly as possible, and let remote TCP know what we have
		 * received so far. */
		if (err == -EAGAIN) {
			tr_ops->hint(&connection->transport, DATA_STREAM, QUICKACK);
			drbd_unplug_all_devices(connection);
		} else if (err > 0) {
			size -= err;
			rflags |= GROW_BUFFER;
		}

		err = drbd_recv(connection, &buffer, size, rflags);
		if (err != (int)size) {
			if (err >= 0)
				err = -EIO;
		} else
			err = 0;

		if (err)
			return err;
	}
	
	err = decode_header(connection, buffer, pi);
	connection->last_received = jiffies;

	return err;
}

/* This is blkdev_issue_flush, but asynchronous.
 * We want to submit to all component volumes in parallel,
 * then wait for all completions.
 */
#ifdef _WIN32
NTSTATUS one_flush_endio(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
#else
BIO_ENDIO_TYPE one_flush_endio BIO_ENDIO_ARGS(struct bio *bio, int error)
#endif
{
#ifdef _WIN32
	struct bio *bio = NULL;
	int error = 0;

	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		bio = (struct bio *)Context;
		error = Irp->IoStatus.Status;
		//DW-1831 check whether bio->bi_bdev and bio->bi_bdev->bd_disk are null.
		if (bio && bio->bi_bdev && bio->bi_bdev->bd_disk) {
			if (bio->bi_bdev->bd_disk->pDeviceExtension != NULL) {
				IoReleaseRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);
			}
		}
	}
	else {
		error = (int)Context;
		bio = (struct bio *)Irp;
	}
#endif
	if (!bio)
		BIO_ENDIO_FN_RETURN;

	struct one_flush_context *octx = bio->bi_private;
	struct drbd_device *device = octx->device;
	struct issue_flush_context *ctx = octx->ctx;

	BIO_ENDIO_FN_START;

#ifdef _WIN32
	// DW-1961 Calculate and Log IO Latency
	if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY) 
		WDRBD_LATENCY("flush IO latency : minor(%u) %lldus\n", device->minor, timestamp_elapse(bio->flush_ts, timestamp()));

	if (NT_ERROR(error)) {
#else
	if (error) {
#endif
		if (ctx)
			ctx->error = error;
		drbd_err(device, "local disk FLUSH FAILED with status %08X\n", error);
	}

#ifdef _WIN32 // DW-1117 patch flush io memory leak
	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		if (Irp->MdlAddress != NULL) {
			PMDL mdl, nextMdl;
			for (mdl = Irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
				nextMdl = mdl->Next;
				MmUnlockPages(mdl);
				IoFreeMdl(mdl); // This function will also unmap pages.
			}
			Irp->MdlAddress = NULL;
		}
		IoFreeIrp(Irp);
	}
#endif
	
	bio_put(bio);

	//DW-1895
	//A match between barrier_nr and primary_node_id means that 
	//the barrier is currently waiting for the barrier.If you are not waiting, 
	//you do not need to do anything.
	if (octx->ctx_sync.barrier_nr == atomic_read64(&ctx->ctx_sync.barrier_nr) &&
		octx->ctx_sync.primary_node_id == atomic_read(&ctx->ctx_sync.primary_node_id)) {
		if (atomic_dec_and_test(&ctx->pending)) {
			complete(&ctx->done);
			//DW-1862 When ctx->pending becomes 0, it means that IO of all disks is completed.
		}
	}

	kfree(octx);
	clear_bit(FLUSH_PENDING, &device->flags);
	put_ldev(device);
	kref_put(&device->kref, drbd_destroy_device);

	BIO_ENDIO_FN_RETURN;
}

static void submit_one_flush(struct drbd_device *device, struct issue_flush_context *ctx)
{
#ifdef _WIN32
	struct bio *bio = bio_alloc(GFP_NOIO, 1, '77DW');
	struct one_flush_context *octx = kmalloc(sizeof(*octx), GFP_NOIO, '78DW');
#else
	struct bio *bio = bio_alloc(GFP_NOIO, 0);
	struct one_flush_context *octx = kmalloc(sizeof(*octx), GFP_NOIO);
#endif
	if (!bio || !octx) {
		drbd_warn(device, "Could not allocate a bio, CANNOT ISSUE FLUSH\n");
		/* FIXME: what else can I do now?  disconnecting or detaching
		 * really does not help to improve the state of the world, either.
		 */
		kfree(octx);
		if (bio)
			bio_put(bio);

		ctx->error = -ENOMEM;
		put_ldev(device);
		kref_put(&device->kref, drbd_destroy_device);
		return;
	}

	octx->device = device;
	octx->ctx = ctx;
	octx->ctx_sync.barrier_nr = atomic_read64(&ctx->ctx_sync.barrier_nr);
	octx->ctx_sync.primary_node_id = atomic_read(&ctx->ctx_sync.primary_node_id);
	bio->bi_bdev = device->ldev->backing_bdev;
	bio->bi_private = octx;
	bio->bi_end_io = one_flush_endio;
	// DW-1961 Save timestamp for flush IO latency measurement
	if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY)
		bio->flush_ts = timestamp();

	set_bit(FLUSH_PENDING, &device->flags);
	atomic_inc(&ctx->pending);
	bio_set_op_attrs(bio, REQ_OP_FLUSH, WRITE_FLUSH);
#ifdef _WIN32
	if(submit_bio(bio)) {
		bio_endio(bio, -EIO);
	}
#else
	submit_bio(bio);
#endif
}

static enum finish_epoch drbd_flush_after_epoch(struct drbd_connection *connection, struct drbd_epoch *epoch)
{
#ifdef _WIN32
	// skipped ldrbd ee63e9b, 7f33065
	// http://git.drbd.org/drbd-9.0.git/commit/ee63e9bd3ed3fc8f480ccdb756b9de1a81e80b62
	// http://git.drbd.org/drbd-9.0.git/commit/7f33065dd4cf8ddedbb025ee9b385d3af8fc3fb5
#endif
	struct drbd_resource *resource = connection->resource;
	
	if (resource->write_ordering >= WO_BDEV_FLUSH) {
		int vnr;
		struct drbd_device *device;
		
		kref_get(&resource->kref);
		atomic_set64(&resource->ctx_flush.ctx_sync.barrier_nr, epoch->barrier_nr);
		atomic_set(&resource->ctx_flush.ctx_sync.primary_node_id, connection->peer_node_id);
		resource->ctx_flush.error = 0;
		atomic_set(&resource->ctx_flush.pending, 1);
		init_completion(&resource->ctx_flush.done);

		rcu_read_lock();
#ifdef _WIN32
		idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
#else
		idr_for_each_entry(&resource->devices, device, vnr) {
#endif
			if (!get_ldev(device))
				continue;
			kref_get(&device->kref);
			rcu_read_unlock();

			submit_one_flush(device, &resource->ctx_flush);

#ifdef _WIN32
			rcu_read_lock_w32_inner();
#else
			rcu_read_lock();
#endif
		}
		rcu_read_unlock();

		/* Do we want to add a timeout,
		 * if disk-timeout is set? */

		if (!atomic_dec_and_test(&resource->ctx_flush.pending)) {
			long ret = wait_for_completion_no_reset_event(&resource->ctx_flush.done);
			if (ret == -DRBD_SIGKILL) {
				drbd_warn(resource, "thread signaled and no more wait pending:%d, barrier_nr:%lld, primary_node_id:%d\n", 
					atomic_read(&resource->ctx_flush.pending), atomic_read64(&resource->ctx_flush.ctx_sync.barrier_nr), atomic_read(&resource->ctx_flush.ctx_sync.primary_node_id));
			}
		}

		//DW-1895
		//The barrier_nr and primary_node_id are set to ctx and octx to ensure that they match in the completion routine.
		atomic_set64(&resource->ctx_flush.ctx_sync.barrier_nr, -1);
		atomic_set(&resource->ctx_flush.ctx_sync.primary_node_id, -1);

		kref_put(&resource->kref, drbd_destroy_resource);
		//DW-1862 When ctx->pending becomes 0, it means that IO of all disks is completed.

//		Comment out code that is not used in Windows.
//		if (ctx->error) {
			/* would rather check on EOPNOTSUPP, but that is not reliable.
			 * don't try again for ANY return value != 0
			 * if (rv == -EOPNOTSUPP) */
			/* Any error is already reported by bio_endio callback. */
//			drbd_bump_write_ordering(connection->resource, NULL, WO_DRAIN_IO);
//		}
	}

	return drbd_may_finish_epoch(connection, epoch, EV_BARRIER_DONE);
}

static int w_flush(struct drbd_work *w, int cancel)
{
	UNREFERENCED_PARAMETER(cancel);

	struct flush_work *fw = container_of(w, struct flush_work, w);
	struct drbd_epoch *epoch = fw->epoch;
	struct drbd_connection *connection = epoch->connection;

	kfree(fw);

	if (!test_and_set_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &epoch->flags))
		drbd_flush_after_epoch(connection, epoch);

	drbd_may_finish_epoch(connection, epoch, EV_PUT |
			      (connection->cstate[NOW] < C_CONNECTED ? EV_CLEANUP : 0));

	return 0;
}

/**
 * drbd_may_finish_epoch() - Applies an epoch_event to the epoch's state, eventually finishes it.
 * @connection:	DRBD connection.
 * @epoch:	Epoch object.
 * @ev:		Epoch event.
 */
static enum finish_epoch drbd_may_finish_epoch(struct drbd_connection *connection,
					       struct drbd_epoch *epoch,
					       enum epoch_event ev)
{
	int finish, epoch_size;
	struct drbd_epoch *next_epoch;
	int schedule_flush = 0;
	enum finish_epoch rv = FE_STILL_LIVE;
	struct drbd_resource *resource = connection->resource;

	spin_lock(&connection->epoch_lock);
	do {
		next_epoch = NULL;
		finish = 0;

		epoch_size = atomic_read(&epoch->epoch_size);

		switch (ev & ~EV_CLEANUP) {
		case EV_PUT:
			atomic_dec(&epoch->active);
			break;
		case EV_GOT_BARRIER_NR:
			set_bit(DE_HAVE_BARRIER_NUMBER, &epoch->flags);

			/* Special case: If we just switched from WO_BIO_BARRIER to
			   WO_BDEV_FLUSH we should not finish the current epoch */
			if (test_bit(DE_CONTAINS_A_BARRIER, &epoch->flags) && epoch_size == 1 &&
			    resource->write_ordering != WO_BIO_BARRIER &&
			    epoch == connection->current_epoch)
				clear_bit(DE_CONTAINS_A_BARRIER, &epoch->flags);
			break;
		case EV_BARRIER_DONE:
			set_bit(DE_BARRIER_IN_NEXT_EPOCH_DONE, &epoch->flags);
			break;
		case EV_BECAME_LAST:
			/* nothing to do*/
			break;
		}

		if (epoch_size != 0 &&
		    atomic_read(&epoch->active) == 0 &&
		    (test_bit(DE_HAVE_BARRIER_NUMBER, &epoch->flags) || ev & EV_CLEANUP) &&
		    epoch->list.prev == &connection->current_epoch->list &&
		    !test_bit(DE_IS_FINISHING, &epoch->flags)) {
			/* Nearly all conditions are met to finish that epoch... */
			if (test_bit(DE_BARRIER_IN_NEXT_EPOCH_DONE, &epoch->flags) ||
			    resource->write_ordering == WO_NONE ||
			    (epoch_size == 1 && test_bit(DE_CONTAINS_A_BARRIER, &epoch->flags)) ||
			    ev & EV_CLEANUP) {
				finish = 1;
				set_bit(DE_IS_FINISHING, &epoch->flags);
			} else if (!test_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &epoch->flags) &&
				 resource->write_ordering == WO_BIO_BARRIER) {
				atomic_inc(&epoch->active);
				schedule_flush = 1;
			}
		}
		if (finish) {
			if (!(ev & EV_CLEANUP)) {
				spin_unlock(&connection->epoch_lock);
				drbd_send_b_ack(epoch->connection, epoch->barrier_nr, epoch_size);
				spin_lock(&connection->epoch_lock);
			}
#if 0
			/* FIXME: dec unacked on connection, once we have
			 * something to count pending connection packets in. */
			if (test_bit(DE_HAVE_BARRIER_NUMBER, &epoch->flags))
				dec_unacked(epoch->connection);
#endif

			if (connection->current_epoch != epoch) {
				next_epoch = list_entry(epoch->list.next, struct drbd_epoch, list);
				list_del(&epoch->list);
				ev = EV_BECAME_LAST | (ev & EV_CLEANUP);
				connection->epochs--;
				kfree(epoch);

				if (rv == FE_STILL_LIVE)
					rv = FE_DESTROYED;
			} else {
				epoch->flags = 0;
				atomic_set(&epoch->epoch_size, 0);
				/* atomic_set(&epoch->active, 0); is alrady zero */
				if (rv == FE_STILL_LIVE)
					rv = FE_RECYCLED;
			}
		}

		if (!next_epoch)
			break;

		epoch = next_epoch;
	} while (true,true);

	spin_unlock(&connection->epoch_lock);

	if (schedule_flush) {
		struct flush_work *fw;
#ifdef _WIN32
        fw = kmalloc(sizeof(*fw), GFP_ATOMIC, 'F1DW');
#else
		fw = kmalloc(sizeof(*fw), GFP_ATOMIC);
#endif
		if (fw) {
			fw->w.cb = w_flush;
			fw->epoch = epoch;
			drbd_queue_work(&resource->work, &fw->w);
		} else {
			drbd_warn(resource, "Could not kmalloc a flush_work obj\n");
			set_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &epoch->flags);
			/* That is not a recursion, only one level */
			drbd_may_finish_epoch(connection, epoch, EV_BARRIER_DONE);
			drbd_may_finish_epoch(connection, epoch, EV_PUT);
		}
	}

	return rv;
}

static enum write_ordering_e
max_allowed_wo(struct drbd_backing_dev *bdev, enum write_ordering_e wo)
{
	struct disk_conf *dc;

	dc = rcu_dereference(bdev->disk_conf);

	if (wo == WO_BIO_BARRIER && !dc->disk_barrier)
		wo = WO_BDEV_FLUSH;
	if (wo == WO_BDEV_FLUSH && !dc->disk_flushes)
		wo = WO_DRAIN_IO;
	if (wo == WO_DRAIN_IO && !dc->disk_drain)
		wo = WO_NONE;

	return wo;
}

/**
 * drbd_bump_write_ordering() - Fall back to an other write ordering method
 * @resource:	DRBD resource.
 * @wo:		Write ordering method to try.
 */
void drbd_bump_write_ordering(struct drbd_resource *resource, struct drbd_backing_dev *bdev,
			      enum write_ordering_e wo) __must_hold(local)
{
	struct drbd_device *device;
	enum write_ordering_e pwo;
	int vnr, i = 0;
	static char *write_ordering_str[] = {
		[WO_NONE] = "none",
		[WO_DRAIN_IO] = "drain",
		[WO_BDEV_FLUSH] = "flush",
		[WO_BIO_BARRIER] = "barrier",
	};

	pwo = resource->write_ordering;
	if (wo != WO_BIO_BARRIER)
		wo = min(pwo, wo);
	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
#else
	idr_for_each_entry(&resource->devices, device, vnr) {
#endif
		if (i++ == 1 && wo == WO_BIO_BARRIER)
			wo = WO_BDEV_FLUSH; /* WO = barrier does not handle multiple volumes */

		if (get_ldev(device)) {
			wo = max_allowed_wo(device->ldev, wo);
			if (device->ldev == bdev)
				bdev = NULL;
			put_ldev(device);
		}
	}

	if (bdev)
		wo = max_allowed_wo(bdev, wo);

	rcu_read_unlock();

	resource->write_ordering = wo;
	if (pwo != resource->write_ordering || wo == WO_BIO_BARRIER)
		drbd_info(resource, "Method to ensure write ordering: %s\n", write_ordering_str[resource->write_ordering]);
}


/*
 * We *may* ignore the discard-zeroes-data setting, if so configured.
 *
 * Assumption is that it "discard_zeroes_data=0" is only because the backend
 * may ignore partial unaligned discards.
 *
 * LVM/DM thin as of at least
 *   LVM version:     2.02.115(2)-RHEL7 (2015-01-28)
 *   Library version: 1.02.93-RHEL7 (2015-01-28)
 *   Driver version:  4.29.0
 * still behaves this way.
 *
 * For unaligned (wrt. alignment and granularity) or too small discards,
 * we zero-out the initial (and/or) trailing unaligned partial chunks,
 * but discard all the aligned full chunks.
 *
 * At least for LVM/DM thin, the result is effectively "discard_zeroes_data=1".
 */
int drbd_issue_discard_or_zero_out(struct drbd_device *device, sector_t start, unsigned int nr_sectors, bool discard)
{
	UNREFERENCED_PARAMETER(start);
	UNREFERENCED_PARAMETER(nr_sectors);
	UNREFERENCED_PARAMETER(discard);
	UNREFERENCED_PARAMETER(device);

#ifdef QUEUE_FLAG_DISCARD
#endif
	int err = 0;

#ifndef _WIN32
	if (!discard)
		goto zero_out;

	/* Zero-sector (unknown) and one-sector granularities are the same.  */
	granularity = max(q->limits.discard_granularity >> 9, 1U);
	alignment = (bdev_discard_alignment(bdev) >> 9) % granularity;

	max_discard_sectors = min(q->limits.max_discard_sectors, (1U << 22));
	max_discard_sectors -= max_discard_sectors % granularity;
	if (unlikely(!max_discard_sectors))
		goto zero_out;

	if (nr_sectors < granularity)
		goto zero_out;

	tmp = start;
	if (sector_div(tmp, granularity) != alignment) {
		if (nr_sectors < 2*granularity)
			goto zero_out;
		/* start + gran - (start + gran - align) % gran */
		tmp = start + granularity - alignment;
		tmp = start + granularity - sector_div(tmp, granularity);

		nr = tmp - start;
		err |= blkdev_issue_zeroout(bdev, start, nr, GFP_NOIO, 0);
		nr_sectors -= nr;
		start = tmp;
	}
	while (nr_sectors >= granularity) {
		nr = min_t(sector_t, nr_sectors, max_discard_sectors);
		err |= blkdev_issue_discard(bdev, start, nr, GFP_NOIO, 0);
		nr_sectors -= nr;
		start += nr;
	}
 zero_out:
	if (nr_sectors) {
		err |= blkdev_issue_zeroout(bdev, start, nr_sectors, GFP_NOIO, 0);
	}
#endif
	return err != 0;
}

static bool can_do_reliable_discards(struct drbd_device *device)
{
#ifdef QUEUE_FLAG_DISCARD
	struct request_queue *q = bdev_get_queue(device->ldev->backing_bdev);
	struct disk_conf *dc;
	bool can_do;

	if (!blk_queue_discard(q))
		return false;

	if (queue_discard_zeroes_data(q))
		return true;

	rcu_read_lock();
	dc = rcu_dereference(device->ldev->disk_conf);
	can_do = dc->discard_zeroes_if_aligned;
	rcu_read_unlock();
	return can_do;
#else
	return false;
#endif
}

static void drbd_issue_peer_discard(struct drbd_device *device, struct drbd_peer_request *peer_req)
{
	/* If the backend cannot discard, or does not guarantee
	 * read-back zeroes in discarded ranges, we fall back to
	 * zero-out.  Unless configuration specifically requested
	 * otherwise. */
	if (!can_do_reliable_discards(device))
		peer_req->flags |= EE_IS_TRIM_USE_ZEROOUT;

	if (drbd_issue_discard_or_zero_out(device, peer_req->i.sector,
	    peer_req->i.size >> 9, !(peer_req->flags & EE_IS_TRIM_USE_ZEROOUT)))
		peer_req->flags |= EE_WAS_ERROR;
	drbd_endio_write_sec_final(peer_req);
}

static void drbd_issue_peer_wsame(struct drbd_device *device,
				  struct drbd_peer_request *peer_req)
{
#ifndef COMPAT_WRITE_SAME_CAPABLE
	/* We should have never received this request!  At least not until we
	 * implement an open-coded write-same equivalend submit loop, and tell
	 * our peer we were write_same_capable. */
	drbd_err(device, "received unsupported WRITE_SAME request\n");
	peer_req->flags |= EE_WAS_ERROR;
	drbd_endio_write_sec_final(peer_req);
#else
	struct block_device *bdev = device->ldev->backing_bdev;
	sector_t s = peer_req->i.sector;
	sector_t nr = peer_req->i.size >> 9;
	if (blkdev_issue_write_same(bdev, s, nr, GFP_NOIO, peer_req->page_chain.head))
		peer_req->flags |= EE_WAS_ERROR;
	drbd_endio_write_sec_final(peer_req);
#endif
}

static bool conn_wait_ee_cond(struct drbd_connection *connection, struct list_head *head)
{
	struct drbd_resource *resource = connection->resource;
	bool done;

	spin_lock_irq(&resource->req_lock);
	done = list_empty(head);
	spin_unlock_irq(&resource->req_lock);

	if (!done)
		drbd_unplug_all_devices(connection);

	return done;
}

#define CONN_WAIT_TIMEOUT 3

// DW-1682 Added 3 sec timeout for active_ee when disconnecting 
static long conn_wait_ee_empty_timeout(struct drbd_connection *connection, struct list_head *head)
{
	long t, timeout;	
	t = timeout = CONN_WAIT_TIMEOUT * HZ; // 3 sec
	wait_event_timeout(t, connection->ee_wait, conn_wait_ee_cond(connection, head), timeout);

	return t;
}

static void conn_wait_ee_empty(struct drbd_connection *connection, struct list_head *head)
{
	wait_event(connection->ee_wait, conn_wait_ee_cond(connection, head));
}

static void conn_wait_ee_empty_or_disconnect(struct drbd_connection *connection, struct list_head *head)
{
	wait_event(connection->ee_wait,
		conn_wait_ee_cond(connection, head) || connection->cstate[NOW] < C_CONNECTED);
}

// DW-1954 if ee is not empty, wait for CONN_WAIT_TIMEOUT seconds.
static void conn_wait_ee_empty_and_update_timeout(struct drbd_connection *connection, struct list_head *head)
{
	long res;
	ULONG_PTR ee_before_cnt = 0, ee_after_cnt = 0;
	struct drbd_peer_request *peer_req;
	unsigned int wait_cnt = 0;
	for (;;) {
		res = conn_wait_ee_empty_timeout(connection, head);
		if (res != 0) {
			break;
		}
		wait_cnt += 1;
		ee_after_cnt = 0;
		spin_lock(&connection->resource->req_lock);
		list_for_each_entry(struct drbd_peer_request, peer_req, head, w.list) {
			ee_after_cnt++;
		}
		spin_unlock(&connection->resource->req_lock);
		if (ee_before_cnt == ee_after_cnt) {
			drbd_debug(connection, "ee not empty, count(%llu), wait time(%u)\n", (unsigned long long)ee_after_cnt, wait_cnt * CONN_WAIT_TIMEOUT);
			break;
		}

		drbd_debug(connection, "ee count, before(%llu) : after(%llu), wait time(%u)\n", (unsigned long long)ee_before_cnt, (unsigned long long)ee_after_cnt, wait_cnt * CONN_WAIT_TIMEOUT);
		ee_before_cnt = ee_after_cnt;
	}
}

/**
 * drbd_submit_peer_request()
 * @device:	DRBD device.
 * @peer_req:	peer request
 * @op:		REQ_OP_READ, REQ_OP_WRITE, ...
 * @op_flags:	flag field, see bio->bi_opf
 *
 * May spread the pages to multiple bios,
 * depending on bio_add_page restrictions.
 *
 * Returns 0 if all bios have been submitted,
 * -ENOMEM if we could not allocate enough bios,
 * -ENOSPC (any better suggestion?) if we have not been able to bio_add_page a
 *  single page to an empty bio (which should never happen and likely indicates
 *  that the lower level IO stack is in some way broken). This has been observed
 *  on certain Xen deployments.
 *
 *  When this function returns 0, it "consumes" an ldev reference; the
 *  reference is released when the request completes.
 */
/* TODO allocate from our own bio_set. */
int drbd_submit_peer_request(struct drbd_device *device,
			     struct drbd_peer_request *peer_req,
				 const int op, const unsigned op_flags,
				 const int fault_type)
{
	struct bio *bios = NULL;
	struct bio *bio;
	struct page *page = peer_req->page_chain.head;
	sector_t sector = peer_req->i.sector;
	unsigned data_size = peer_req->i.size;
	unsigned n_bios = 0;
	unsigned nr_pages = peer_req->page_chain.nr_pages;
	int err = -ENOMEM;
#ifdef _WIN32 // DW-1598 : Do not submit peer_req if there is no connection
	if (test_bit(CONNECTION_ALREADY_FREED, &peer_req->peer_device->flags)){
		drbd_info(device, "node-id : %d, flag : CONNECTION_ALREADY_FREED\n", peer_req->peer_device->node_id);
		return 0; 
	}
#endif
	/* TRIM/DISCARD: for now, always use the helper function
	 * blkdev_issue_zeroout(..., discard=true).
	 * It's synchronous, but it does the right thing wrt. bio splitting.
	 * Correctness first, performance later.  Next step is to code an
	 * asynchronous variant of the same.
	 */
	if (peer_req->flags & (EE_IS_TRIM|EE_WRITE_SAME)) {
		struct drbd_connection *connection = peer_req->peer_device->connection;
		/* wait for all pending IO completions, before we start
		 * zeroing things out. */
		conn_wait_ee_empty(connection, &connection->active_ee);
		/* add it to the active list now,
		 * so we can find it to present it in debugfs */
		peer_req->submit_jif = jiffies;
		peer_req->flags |= EE_SUBMITTED;

		/* If this was a resync request from receive_rs_deallocated(),
		 * it is already on the sync_ee list */
		if (list_empty(&peer_req->w.list)) {
			spin_lock_irq(&device->resource->req_lock);
			list_add_tail(&peer_req->w.list, &connection->active_ee);
			spin_unlock_irq(&device->resource->req_lock);
		}

		if (peer_req->flags & EE_IS_TRIM)
			drbd_issue_peer_discard(device, peer_req);
		else /* EE_WRITE_SAME */
			drbd_issue_peer_wsame(device, peer_req);
		return 0;
	}

	/* In most cases, we will only need one bio.  But in case the lower
	 * level restrictions happen to be different at this offset on this
	 * side than those of the sending peer, we may need to submit the
	 * request in more than one bio.
	 *
	 * Plain bio_alloc is good enough here, this is no DRBD internally
	 * generated bio, but a bio allocated on behalf of the peer.
	 */
#ifndef _WIN32
next_bio:
#endif
	/* REQ_OP_WRITE_SAME and REQ_OP_DISCARD handled above.
	* REQ_OP_FLUSH (empty flush) not expected,
	* should have been mapped to a "drbd protocol barrier".
	* REQ_OP_SECURE_ERASE: I don't see how we could ever support that.
	*/
	if (!(op == REQ_OP_WRITE || op == REQ_OP_READ)) {
		drbd_err(device, "Invalid bio op received: 0x%x\n", op);
		err = -EINVAL;
		goto fail; 
	}

#ifdef _WIN32
    bio = bio_alloc(GFP_NOIO, nr_pages, '02DW');
#else
	bio = bio_alloc(GFP_NOIO, nr_pages);
#endif
	if (!bio) {
		drbd_err(device, "submit_ee: Allocation of a bio failed (nr_pages=%u)\n", nr_pages);
		goto fail;
	}
	/* > peer_req->i.sector, unless this is the first bio */
	DRBD_BIO_BI_SECTOR(bio) = sector;
	bio->bi_bdev = device->ldev->backing_bdev;
	/* we special case some flags in the multi-bio case, see below
	 * (REQ_UNPLUG, REQ_PREFLUSH, or BIO_RW_BARRIER in older kernels) */
	bio_set_op_attrs(bio, op, op_flags);
	bio->bi_private = peer_req;
	bio->bi_end_io = drbd_peer_request_endio;

	bio->bi_next = bios;
	bios = bio;
	++n_bios;
	bio->io_retry = device->resource->res_opts.io_error_retry_count;
	
#ifdef _WIN32 
	bio->bi_size = data_size;
    bio->bio_databuf = peer_req->peer_req_databuf = page;
    page = NULL;
#else
	page_chain_for_each(page) {
		unsigned off, len;
		int res;

		if (rw == READ) {
			set_page_chain_offset(page, 0);
			set_page_chain_size(page, min_t(unsigned, data_size, PAGE_SIZE));
		}
		off = page_chain_offset(page);
		len = page_chain_size(page);

		if (off > PAGE_SIZE || len > PAGE_SIZE - off || len > data_size || len == 0) {
			drbd_err(device, "invalid page chain: offset %u size %u remaining data_size %u\n",
					off, len, data_size);
			err = -EINVAL;
			goto fail;
		}

		res = bio_add_page(bio, page, len, off);
		if (res <= 0) {
			/* A single page must always be possible!
			 * But in case it fails anyways,
			 * we deal with it, and complain (below). */
			if (bio->bi_vcnt == 0) {
				drbd_err(device,
					"bio_add_page(%p, %p, %u, %u): %d (bi_vcnt %u bi_max_vecs %u bi_sector %llu, bi_flags 0x%lx)\n",
					bio, page, len, off, res, bio->bi_vcnt, bio->bi_max_vecs, (uint64_t)DRBD_BIO_BI_SECTOR(bio),
					 (unsigned long)bio->bi_flags);
				err = -ENOSPC;
				goto fail;
			}
			goto next_bio;
		}
		data_size -= len;
		sector += len >> 9;
		--nr_pages;
	}
	D_ASSERT(device, data_size == 0);
#endif
	D_ASSERT(device, page == NULL);

	atomic_set(&peer_req->pending_bios, n_bios);
	/* for debugfs: update timestamp, mark as submitted */
	peer_req->submit_jif = jiffies;

	// DW-1961 Save timestamp for IO latency measurement
	if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY)
		peer_req->io_request_ts = timestamp();
	peer_req->flags |= EE_SUBMITTED;
	do {
		bio = bios;
		bios = bios->bi_next;
		bio->bi_next = NULL;

		/* strip off REQ_UNPLUG unless it is the last bio */
		if (bios && DRBD_REQ_UNPLUG)
			bios->bi_opf &= ~DRBD_REQ_PREFLUSH;
		drbd_generic_make_request(device, fault_type, bio);

		/* strip off REQ_PREFLUSH,
		 * unless it is the first or last bio */
		if (bios && bios->bi_next)
			bios->bi_opf &= ~DRBD_REQ_PREFLUSH;
	} while (bios);
	maybe_kick_lo(device);
	return 0;

fail:
	while (bios) {
		bio = bios;
		bios = bios->bi_next;
		bio_put(bio);
	}
	return err;
}

static void drbd_remove_peer_req_interval(struct drbd_device *device,
					  struct drbd_peer_request *peer_req)
{
	struct drbd_interval *i = &peer_req->i;

	drbd_remove_interval(&device->write_requests, i);
	drbd_clear_interval(i);
	peer_req->flags &= ~EE_IN_INTERVAL_TREE;

	/* Wake up any processes waiting for this peer request to complete.  */
	if (i->waiting)
		wake_up(&device->misc_wait);
}

/**
 * w_e_reissue() - Worker callback; Resubmit a bio, without REQ_HARDBARRIER set
 * @device:	DRBD device.
 * @dw:		work object.
 * @cancel:	The connection will be closed anyways (unused in this callback)
 */
int w_e_reissue(struct drbd_work *w, int cancel) __releases(local)
{
	UNREFERENCED_PARAMETER(cancel);

	struct drbd_peer_request *peer_req =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	int err;
	/* We leave DE_CONTAINS_A_BARRIER and EE_IS_BARRIER in place,
	   (and DE_BARRIER_IN_NEXT_EPOCH_ISSUED in the previous Epoch)
	   so that we can finish that epoch in drbd_may_finish_epoch().
	   That is necessary if we already have a long chain of Epochs, before
	   we realize that BARRIER is actually not supported */

	/* As long as the -ENOTSUPP on the barrier is reported immediately
	   that will never trigger. If it is reported late, we will just
	   print that warning and continue correctly for all future requests
	   with WO_BDEV_FLUSH */
	if (previous_epoch(peer_device->connection, peer_req->epoch))
		drbd_warn(device, "Write ordering was not enforced (one time event)\n");

	/* we still have a local reference,
	 * get_ldev was done in receive_Data. */

	peer_req->w.cb = e_end_block;
	err = drbd_submit_peer_request(device, peer_req, REQ_OP_WRITE, 0, DRBD_FAULT_DT_WR);
	switch (err) {
	case -ENOMEM:
		peer_req->w.cb = w_e_reissue;
		drbd_queue_work(&peer_device->connection->sender_work,
				&peer_req->w);
		/* retry later; fall through */
	case 0:
		/* keep worker happy and connection up */
		return 0;

	case -ENOSPC:
		/* no other error expected, but anyways: */
	default:
		/* forget the object,
		 * and cause a "Network failure" */
		spin_lock_irq(&device->resource->req_lock);
		list_del(&peer_req->w.list);
		drbd_remove_peer_req_interval(device, peer_req);
		spin_unlock_irq(&device->resource->req_lock);
		drbd_al_complete_io(device, &peer_req->i);
		drbd_may_finish_epoch(peer_device->connection, peer_req->epoch, EV_PUT | EV_CLEANUP);
		drbd_free_peer_req(peer_req);
		drbd_err(device, "submit failed, triggering re-connect\n");
		return err;
	}
}

static void conn_wait_done_ee_empty(struct drbd_connection *connection)
{
	wait_event(connection->ee_wait, atomic_read(&connection->done_ee_cnt) == 0);
}

static int receive_Barrier(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_transport_ops *tr_ops = connection->transport.ops;
	int rv, issue_flush;
	struct p_barrier *p = pi->data;
	struct drbd_epoch *epoch;

	tr_ops->hint(&connection->transport, DATA_STREAM, QUICKACK);
	drbd_unplug_all_devices(connection);

	/* FIXME these are unacked on connection,
	 * not a specific (peer)device.
	 */
	connection->current_epoch->barrier_nr = p->barrier;
	connection->current_epoch->connection = connection;
	rv = drbd_may_finish_epoch(connection, connection->current_epoch, EV_GOT_BARRIER_NR);

	/* P_BARRIER_ACK may imply that the corresponding extent is dropped from
	 * the activity log, which means it would not be resynced in case the
	 * R_PRIMARY crashes now.
	 * Therefore we must send the barrier_ack after the barrier request was
	 * completed. */
	switch (connection->resource->write_ordering) {
	case WO_BIO_BARRIER:
	case WO_NONE:
		if (rv == FE_RECYCLED)
			return 0;
		break;

	case WO_BDEV_FLUSH:
	case WO_DRAIN_IO:
		if (rv == FE_STILL_LIVE) {
			set_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &connection->current_epoch->flags);
			conn_wait_ee_empty_or_disconnect(connection, &connection->active_ee);
			rv = drbd_flush_after_epoch(connection, connection->current_epoch);
		}
		if (rv == FE_RECYCLED)
			return 0;

		/* The ack_sender will send all the ACKs and barrier ACKs out, since
		   all EEs moved from the active_ee to the done_ee. We need to
		   provide a new epoch object for the EEs that come in soon */
		break;
	}

	/* receiver context, in the writeout path of the other node.
	 * avoid potential distributed deadlock */
#ifdef _WIN32
    epoch = kmalloc(sizeof(struct drbd_epoch), GFP_NOIO, '12DW');
#else
	epoch = kmalloc(sizeof(struct drbd_epoch), GFP_NOIO);
#endif
	if (!epoch) {
		drbd_warn(connection, "Allocation of an epoch failed, slowing down\n");
		issue_flush = !test_and_set_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &connection->current_epoch->flags);
		conn_wait_ee_empty_or_disconnect(connection, &connection->active_ee);
		if (issue_flush) {
			rv = drbd_flush_after_epoch(connection, connection->current_epoch);
			if (rv == FE_RECYCLED)
				return 0;
		}

		conn_wait_done_ee_empty(connection);

		return 0;
	}

	epoch->flags = 0;
	atomic_set(&epoch->epoch_size, 0);
	atomic_set(&epoch->active, 0);

	spin_lock(&connection->epoch_lock);
	if (atomic_read(&connection->current_epoch->epoch_size)) {
		list_add(&epoch->list, &connection->current_epoch->list);
		connection->current_epoch = epoch;
		connection->epochs++;
	} else {
		/* The current_epoch got recycled while we allocated this one... */
		kfree(epoch);
	}
	spin_unlock(&connection->epoch_lock);

	return 0;
}

/* pi->data points into some recv buffer, which may be
 * re-used/recycled/overwritten by the next receive operation.
 * (read_in_block via recv_resync_read) */
static void p_req_detail_from_pi(struct drbd_connection *connection,
		struct drbd_peer_request_details *d, struct packet_info *pi)
{
	struct p_trim *p = pi->data;
	bool is_trim_or_wsame = pi->cmd == P_TRIM || pi->cmd == P_WSAME;
	unsigned int digest_size =
		pi->cmd != P_TRIM && connection->peer_integrity_tfm ?
		crypto_hash_digestsize(connection->peer_integrity_tfm) : 0;

	d->sector = be64_to_cpu(p->p_data.sector);
	d->block_id = p->p_data.block_id;
	d->peer_seq = be32_to_cpu(p->p_data.seq_num);
	d->dp_flags = be32_to_cpu(p->p_data.dp_flags);
	d->length = pi->size;
	d->bi_size = is_trim_or_wsame ? be32_to_cpu(p->size) : pi->size - digest_size;
	d->digest_size = digest_size;

	WDRBD_TRACE("sector: %llu block_id: %llu peer_seq: %u dp_flags:%u length:%u bi_size:%u digest_size: %u\n",d->sector,d->block_id,d->peer_seq, d->dp_flags, d->length, d->bi_size, d->digest_size);
}

/* used from receive_RSDataReply (recv_resync_read)
 * and from receive_Data.
 * data_size: actual payload ("data in")
 * 	for normal writes that is bi_size.
 * 	for discards, that is zero.
 * 	for write same, it is logical_block_size.
 * both trim and write same have the bi_size ("data len to be affected")
 * as extra argument in the packet header.
 */
static struct drbd_peer_request *
read_in_block(struct drbd_peer_device *peer_device, struct drbd_peer_request_details *d) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	const uint64_t capacity = drbd_get_capacity(device->this_bdev);
	struct drbd_peer_request *peer_req;
	int err;
	void *dig_in = peer_device->connection->int_dig_in;
	void *dig_vv = peer_device->connection->int_dig_vv;
	struct drbd_transport *transport = &peer_device->connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;

	if (d->digest_size) {
		err = drbd_recv_into(peer_device->connection, dig_in, d->digest_size);
		if (err)
			return NULL;
	}

	if (!expect(peer_device, IS_ALIGNED(d->bi_size, 512)))
		return NULL;
	/* All "normal" requests should be smaller than DRBD_MAX_BIO_SIZE.
	 * TRIM (does not carry any payload: d->length == 0) maybe be bigger. */
	if (d->length && !expect(peer_device, d->bi_size <= DRBD_MAX_BIO_SIZE))
		return NULL;

	/* even though we trust our peer,
	 * we sometimes have to double check. */
	if (d->sector + (d->bi_size>>9) > capacity) {
		drbd_err(device, "request from peer beyond end of local disk: "
			"capacity: %llus < sector: %llus + size: %u\n",
			capacity, d->sector, d->bi_size);
		return NULL;
	}

	peer_req = drbd_alloc_peer_req(peer_device, GFP_TRY);
	if (!peer_req)
		return NULL;
	peer_req->i.size = d->bi_size; /* storage size */
	peer_req->i.sector = d->sector;
	peer_req->block_id = d->block_id;
	peer_req->flags |= EE_WRITE;
	// DW-1961 Save timestamp for IO latency measurement
	if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY)
		peer_req->created_ts = timestamp();
	if (d->length == 0)
		return peer_req;

	err = tr_ops->recv_pages(transport, &peer_req->page_chain, d->length - d->digest_size);
	if (err)
		goto fail;
#ifdef _WIN32
    else
        peer_req->peer_req_databuf = peer_req->page_chain.head;
#endif

	if (drbd_insert_fault(device, DRBD_FAULT_RECEIVE)) {
#ifdef _WIN32
		drbd_info(device, "Fault injection: Not supported\n");
#else
		struct page *page;
		unsigned long *data;
		drbd_err(device, "Fault injection: Corrupting data on receive, sector %llu\n",
				d->sector);
		page = peer_req->page_chain.head;
		data = kmap(page) + page_chain_offset(page);
		data[0] = ~data[0];
		kunmap(page);
#endif
	}

	if (d->digest_size) {
#ifdef _WIN32
        drbd_csum_pages(peer_device->connection->peer_integrity_tfm, peer_req, dig_vv);
#else
		drbd_csum_pages(peer_device->connection->peer_integrity_tfm, peer_req->page_chain.head, dig_vv);
#endif
		if (memcmp(dig_in, dig_vv, d->digest_size)) {
			drbd_err(device, "Digest integrity check FAILED: %llus +%u\n",
				d->sector, d->bi_size);
			goto fail;
		}
	}
	peer_device->recv_cnt += d->bi_size >> 9;
	return peer_req;

fail:
#ifdef _WIN32
	peer_req->peer_req_databuf = NULL;
#endif
	drbd_free_peer_req(peer_req);
	return NULL;
}

static int ignore_remaining_packet(struct drbd_connection *connection, int size)
{
	void *data_to_ignore;

	while (size) {
		int s = min_t(int, size, DRBD_SOCKET_BUFFER_SIZE);
		int rv = drbd_recv(connection, &data_to_ignore, s, 0);
		if (rv < 0)
			return rv;

		size -= rv;
	}

	return 0;
}

static int recv_dless_read(struct drbd_peer_device *peer_device, struct drbd_request *req,
			   sector_t sector, int data_size)
{
	UNREFERENCED_PARAMETER(sector);

	int digest_size, err;
	void *dig_in = peer_device->connection->int_dig_in;
	void *dig_vv = peer_device->connection->int_dig_vv;

	digest_size = 0;
	if (peer_device->connection->peer_integrity_tfm) {
		digest_size = crypto_hash_digestsize(peer_device->connection->peer_integrity_tfm);
		err = drbd_recv_into(peer_device->connection, dig_in, digest_size);
		if (err)
			return err;
		data_size -= digest_size;
	}

	/* optimistically update recv_cnt.  if receiving fails below,
	 * we disconnect anyways, and counters will be reset. */
	peer_device->recv_cnt += data_size >> 9;

#ifdef _WIN32
	if (req->master_bio->bio_databuf) {
#ifdef _WIN32
        err = drbd_recv_into(peer_device->connection, req->master_bio->bio_databuf, data_size);
#else
        err = drbd_recv_all_warn(peer_device->connection, req->master_bio->bio_databuf, data_size);
#endif
		if (err)
			return err;
		data_size = 0;
	}
	else {
		return -EINVAL;
	}
#else 
	bio = req->master_bio;
	D_ASSERT(peer_device->device, sector == DRBD_BIO_BI_SECTOR(bio));

	bio_for_each_segment(bvec, bio, iter) {
		void *mapped = kmap(bvec BVD bv_page) + bvec BVD bv_offset;
		expect = min_t(int, data_size, bvec BVD bv_len);
		err = drbd_recv_into(peer_device->connection, mapped, expect);
		kunmap(bvec BVD bv_page);
		if (err)
			return err;
		data_size -= expect;
	}
#endif

	if (digest_size) {
#ifdef _WIN32
		drbd_csum_bio(peer_device->connection->peer_integrity_tfm, req, dig_vv);
#else
		drbd_csum_bio(peer_device->connection->peer_integrity_tfm, bio, dig_vv);
#endif
		if (memcmp(dig_in, dig_vv, digest_size)) {
			drbd_err(peer_device, "Digest integrity check FAILED. Broken NICs?\n");
			return -EINVAL;
		}
	}

	D_ASSERT(peer_device->device, data_size == 0);
	return 0;
}

/*
 * e_end_resync_block() is called in ack_sender context via
 * drbd_finish_peer_reqs().
 */
static int e_end_resync_block(struct drbd_work *w, int unused)
{
	UNREFERENCED_PARAMETER(unused);

	struct drbd_peer_request *peer_req =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	sector_t sector = peer_req->i.sector;
	int err;

	D_ASSERT(device, drbd_interval_empty(&peer_req->i));

	// DW-1961 Calculate and Log IO Latency
	if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY) {
		peer_req->io_complete_ts = timestamp();
	}

	//DW-1846 send P_NEG_ACK if not sync target
	if (is_sync_target(peer_device)) {
		if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
			drbd_set_in_sync(peer_device, sector, peer_req->i.size);
			err = drbd_send_ack(peer_device, P_RS_WRITE_ACK, peer_req);
		}
		else {
			/* Record failure to sync */
			drbd_rs_failed_io(peer_device, sector, peer_req->i.size);

			err = drbd_send_ack(peer_device, P_NEG_ACK, peer_req);
		}
	}
	else {
		err = drbd_send_ack(peer_device, P_NEG_ACK, peer_req);
	}
	dec_unacked(peer_device);

	return err;
}

/**
* _drbd_send_ack() - Sends an ack packet
* @device:	DRBD device.
* @cmd:	Packet command code.
* @sector:	sector, needs to be in big endian byte order
* @blksize:	size in byte, needs to be in big endian byte order
* @block_id:	Id, big endian byte order
*/
static int _drbd_send_ack(struct drbd_peer_device *peer_device, enum drbd_packet cmd,
	u64 sector, u32 blksize, u64 block_id)
{
	struct p_block_ack *p;

	if (peer_device->repl_state[NOW] < L_ESTABLISHED)
		return -EIO;

	p = drbd_prepare_command(peer_device, sizeof(*p), CONTROL_STREAM);
	if (!p)
		return -EIO;
	p->sector = sector;
	p->block_id = block_id;
	p->blksize = blksize;
	p->seq_num = cpu_to_be32(atomic_inc_return(&peer_device->packet_seq));
	return drbd_send_command(peer_device, cmd, CONTROL_STREAM);
}

static int drbd_send_ack_dp(struct drbd_peer_device *peer_device, enum drbd_packet cmd, struct drbd_peer_request_details *d)
{
	return _drbd_send_ack(peer_device, cmd,
		cpu_to_be64(d->sector),
		cpu_to_be32(d->bi_size),
		d->block_id);
}

static bool drbd_send_ack_and_rs_failed(struct drbd_peer_device *peer_device, sector_t sector, uint64_t block_id)
{
	struct drbd_peer_request_details d;

	d.sector = sector;
	d.bi_size = BM_BLOCK_SIZE;
	d.block_id = block_id;

	drbd_set_out_of_sync(peer_device, sector, 1 << 9);
	drbd_rs_failed_io(peer_device, sector, 1 << 9);

	return drbd_send_ack_dp(peer_device, P_NEG_ACK, &d);
}


#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
static int split_e_end_resync_block(struct drbd_work *w, int unused)
{
	UNREFERENCED_PARAMETER(unused);

	struct drbd_peer_request *peer_req =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	sector_t sector = peer_req->i.sector;
	int err = 0;

	ULONG_PTR e_next_bb = peer_req->e_next_bb;

	D_ASSERT((struct drbd_device *)peer_device->device, drbd_interval_empty(&peer_req->i));

	drbd_debug(peer_device, "--bitmap bit : %llu ~ %llu\n", BM_SECT_TO_BIT(peer_req->i.sector), (BM_SECT_TO_BIT(peer_req->i.sector + (peer_req->i.size >> 9)) - 1));

	//DW-1911 do not apply DW-1846 for a split request when resync writing is complete.

	bool is_unmarked = peer_req->unmarked_count != NULL;

	//DW-1911 set to in sync when all the unmakred are written.
	if (peer_req->unmarked_count && 0 == atomic_dec_return(peer_req->unmarked_count)) {
		is_unmarked = false;

		//DW-1911 if there is a failure, set the EE_WAS_ERROR setting.
		if (atomic_read(peer_req->failed_unmarked) == 1)
			peer_req->flags |= EE_WAS_ERROR;

		drbd_debug(peer_device, "--finished unmarked s_bb(%llu), e_bb(%llu), sector(%llu), res(%s)\n", (unsigned long long)peer_req->s_bb, (unsigned long long)(peer_req->e_next_bb - 1), sector, (atomic_read(peer_req->failed_unmarked) == 1 ? "failed" : "success"));

		sector = BM_BIT_TO_SECT(BM_SECT_TO_BIT(peer_req->i.sector));
		peer_req->i.size = BM_SECT_PER_BIT << 9;

		kfree2(peer_req->unmarked_count);
		if (peer_req->failed_unmarked)
			kfree2(peer_req->failed_unmarked);

	}

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		if (!is_unmarked) {
			drbd_set_in_sync(peer_device, sector, peer_req->i.size);

			//DW-1815 set in sync for peer_device with the same current_uuid.
			struct drbd_peer_device* pd;
			for_each_peer_device(pd, peer_device->device) {
				if (pd == peer_device)
					continue;

				if (pd->current_uuid == peer_device->current_uuid) {
					drbd_set_in_sync(pd, sector, peer_req->i.size);
				}
			}

			if (!(peer_req->flags & EE_SPLIT_REQ) && !(peer_req->flags & EE_SPLIT_LAST_REQ))
				err = drbd_send_ack(peer_device, P_RS_WRITE_ACK, peer_req);
		}
	}
	else {
		//DW-1911 
		if (is_unmarked && peer_req->failed_unmarked)
			atomic_set(peer_req->failed_unmarked, 1);

		if (!is_unmarked) {
			drbd_rs_failed_io(peer_device, sector, peer_req->i.size);
			if (!(peer_req->flags & EE_SPLIT_REQ) && !(peer_req->flags & EE_SPLIT_LAST_REQ)) {
				err = drbd_send_ack(peer_device, P_NEG_ACK, peer_req);
			}
		}
	}

	//DW-1911 check split request
	if (peer_req->flags & EE_SPLIT_REQ || peer_req->flags & EE_SPLIT_LAST_REQ) {
		//DW-1911 check that all split requests are completed.
		if (peer_req->count && 0 == atomic_dec_return(peer_req->count)) {
			bool is_in_sync = false;	//true : in sync, false : out of sync
			ULONG_PTR s_bb = peer_req->s_bb;

			dec_unacked(peer_device);

			for (ULONG_PTR i_bb = peer_req->s_bb; i_bb < e_next_bb; i_bb++) {
				if (drbd_bm_test_bit(peer_device, i_bb) == 1) {
					if (is_in_sync == true && i_bb != peer_req->s_bb) {
					complete_end_sync:
						//DW-1601 If all of the data are sync, then P_RS_WRITE_ACK transmit.
						peer_req->i.sector = BM_BIT_TO_SECT(s_bb);
						peer_req->i.size = (unsigned int)BM_BIT_TO_SECT(i_bb - s_bb) << 9;
						drbd_debug(peer_device, "--set in sync, bitmap bit start : %llu, range : %llu ~ %llu, size %llu\n", 
							(unsigned long long)peer_req->s_bb, (unsigned long long)s_bb, (unsigned long long)(i_bb - 1), (unsigned long long)(BM_BIT_TO_SECT(i_bb - s_bb) << 9));
						if (i_bb == e_next_bb)
							peer_req->block_id = ID_SYNCER_SPLIT_DONE;
						else
							peer_req->block_id = ID_SYNCER_SPLIT;

						err = drbd_send_ack(peer_device, P_RS_WRITE_ACK, peer_req);
						s_bb = i_bb;
					}

					if ((i_bb + 1) == e_next_bb) {
						i_bb = e_next_bb;
						goto complete_end_out_of_sync;
					}

					is_in_sync = false;
				}
				else {
					if (is_in_sync == false && i_bb != peer_req->s_bb) {
					complete_end_out_of_sync:
						//DW-1601 If out of sync is found within range, it is set as a failure.
						peer_req->i.sector = BM_BIT_TO_SECT(s_bb);
						peer_req->i.size = (unsigned int)BM_BIT_TO_SECT(i_bb - s_bb) << 9;
						drbd_err(peer_device, "--set failed to I/O, bitmap bit start : %llu, range : %llu ~ %llu, size %llu\n", 
							(unsigned long long)peer_req->s_bb, (unsigned long long)s_bb, (unsigned long long)(i_bb - 1), (unsigned long long)(BM_BIT_TO_SECT(i_bb - s_bb) << 9));
						if (i_bb == e_next_bb)
							peer_req->block_id = ID_SYNCER_SPLIT_DONE;
						else
							peer_req->block_id = ID_SYNCER_SPLIT;

						err = drbd_send_ack(peer_device, P_NEG_ACK, peer_req);
						s_bb = i_bb;
					}

					if ((i_bb + 1) == e_next_bb) {
						i_bb = e_next_bb;
						goto complete_end_sync;
					}

					is_in_sync = true;
				}
			}

			if (peer_req->count)
				kfree2(peer_req->count);
		}
	}
	else {
		dec_unacked(peer_device);
	}
	
	return err;
}

static struct drbd_peer_request *split_read_in_block(struct drbd_peer_device *peer_device, struct drbd_peer_request *peer_request, sector_t sector, 
														ULONG_PTR offset, unsigned int size, ULONG_PTR s_bb, ULONG_PTR e_next_bb, ULONG_PTR flags, 
														atomic_t* split_count, char* verify) __must_hold(local)
{
	struct drbd_peer_request *split_peer_request;
	struct drbd_transport *transport = &peer_device->connection->transport;

	split_peer_request = drbd_alloc_peer_req(peer_device, GFP_TRY);

	if (!split_peer_request)
		return NULL;

	split_peer_request->i.size = size; /* storage size */
	split_peer_request->i.sector = sector;

	split_peer_request->flags |= EE_WRITE;
	split_peer_request->flags |= flags;

	// DW-1961 Save timestamp for IO latency measurement
	split_peer_request->block_id = peer_request->block_id;
	if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY)
		split_peer_request->created_ts = timestamp();

	drbd_alloc_page_chain(transport, &split_peer_request->page_chain, DIV_ROUND_UP(split_peer_request->i.size, PAGE_SIZE), GFP_TRY);
	if (split_peer_request->page_chain.head == NULL) {
		drbd_free_peer_req(split_peer_request);
		return NULL;
	}

	split_peer_request->peer_req_databuf = split_peer_request->page_chain.head;
	memcpy(split_peer_request->peer_req_databuf, (char*)peer_request->peer_req_databuf + offset, split_peer_request->i.size);
	split_peer_request->count = split_count;
	split_peer_request->s_bb = s_bb;
	split_peer_request->e_next_bb = e_next_bb;
	split_peer_request->unmarked_count = NULL;
	split_peer_request->failed_unmarked = NULL;

	split_peer_request->w.cb = split_e_end_resync_block;
	split_peer_request->submit_jif = jiffies;

	if (verify != NULL) {
		memcpy(verify + offset, (char*)peer_request->peer_req_databuf + offset, split_peer_request->i.size);
	}

	drbd_debug(peer_device, "##split request s_bb(%llu), e_bb(%llu), sector(%llu), offset(%llu), size(%u)\n", 
		(unsigned long long)s_bb, (unsigned long long)(e_next_bb - 1), sector, (unsigned long long)offset, size);

	return split_peer_request;
}

//DW-1928
static bool is_marked_rl_bb(struct drbd_peer_device *peer_device, struct drbd_marked_replicate **marked_rl, ULONG_PTR bb)
{
	list_for_each_entry(struct drbd_marked_replicate, (*marked_rl), &(peer_device->device->marked_rl_list), marked_rl_list) {
		if ((*marked_rl)->bb == bb) {
			return true;
		}
	}

	(*marked_rl) = NULL;
	return false;
}

static bool prepare_split_peer_request(struct drbd_peer_device *peer_device, ULONG_PTR s_bb, ULONG_PTR e_next_bb, atomic_t *split_count, ULONG_PTR* e_oos)
{
	bool find_isb = false;
	bool split_request = true;
	struct drbd_marked_replicate *marked_rl, *tmp;

	//DW-1911 
	list_for_each_entry_safe(struct drbd_marked_replicate, marked_rl, tmp, &(peer_device->device->marked_rl_list), marked_rl_list) {
		//DW-1911 set in sync if all the sector are marked.
		if (__popcnt(marked_rl->marked_rl) == (sizeof(marked_rl->marked_rl) * 8)) {
			drbd_set_in_sync(peer_device, BM_BIT_TO_SECT(marked_rl->bb), BM_SECT_PER_BIT << 9);
			list_del(&(marked_rl->marked_rl_list));
			kfree2(marked_rl);
			continue;
		}

		//DW-1911 if it is already in sync bit, remove it.
		if (drbd_bm_test_bit(peer_device, marked_rl->bb) == 0) {
			list_del(&marked_rl->marked_rl_list);
			kfree2(marked_rl);
			continue;
		}
	}

	//DW-1601 the last out of sync and split_cnt information are obtained before the resync write request.
	for (ULONG_PTR ibb = s_bb; ibb < e_next_bb; ibb++) {
		// DW-1928 modify split_count calculation method
		if (is_marked_rl_bb(peer_device, &marked_rl, ibb)) {
			for (u16 i = 0; i < sizeof(marked_rl->marked_rl) * 8; i++) {
				// DW-1911 obtain the end unmakred sector.
				if (!(marked_rl->marked_rl & 1 << i)) {
					if (marked_rl->end_unmarked_rl < i)
						marked_rl->end_unmarked_rl = i;

					atomic_inc(split_count);
				}
			}
			split_request = true;
			find_isb = true;

			*e_oos = ibb;
		}
		else if (drbd_bm_test_bit(peer_device, ibb) == 1) {
			if (split_request) {
				atomic_inc(split_count);
				split_request = false;
			}

			*e_oos = ibb;
		}
		else {
			drbd_debug(peer_device, "##find in sync bitmap bit : %llu, start (%llu) ~ end (%llu)\n",
				(unsigned long long)ibb,
				(unsigned long long)s_bb,
				(unsigned long long)(e_next_bb - 1));
			split_request = true;
			find_isb = true;
		}
	}

	return find_isb;
}

bool is_set_area_replicate_out_of_sync(struct drbd_device *device, ULONG_PTR s_bb, ULONG_PTR e_next_bb)
{
	//DW-1904 check that the resync data is within the out of sync range of the replication data.
	if (device->e_rl_bb > device->s_rl_bb) {
		if ((device->s_rl_bb <= s_bb && device->e_rl_bb >= s_bb)) {
			if (device->e_rl_bb <= (e_next_bb - 1)) {
				device->e_rl_bb = (s_bb - 1);
			}
			return true;
		}

		if (device->s_rl_bb <= (e_next_bb - 1) && device->e_rl_bb >= (e_next_bb - 1)) {
			if (device->s_rl_bb >= s_bb) {
				device->s_rl_bb = e_next_bb;
			}
			return true;
		}

		if ((device->s_rl_bb >= s_bb && device->e_rl_bb <= (e_next_bb - 1))) {
			device->s_rl_bb = UINT64_MAX;
			device->e_rl_bb = 0;
			return true;
		}
	}

	return false;
}
static int split_recv_resync_read(struct drbd_peer_device *peer_device, struct drbd_peer_request_details *d) __releases(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_request *peer_req;

	int err = 0;

	ULONG_PTR s_bb, e_next_bb, e_oos; //s_bb = start bitmap bit, e_next_bb = end bitmap bit next bit, e_oos = end out of sync bit 
	ULONG_PTR offset;

	int submit_count = 0;
	ULONG_PTR bits, mask;

	peer_req = read_in_block(peer_device, d);
	if (!peer_req) {
		drbd_err(peer_device, "failed to allocate peer_req\n");
		return -EIO;
	}

	if (test_bit(UNSTABLE_RESYNC, &peer_device->flags))
		clear_bit(STABLE_RESYNC, &device->flags);

	dec_rs_pending(peer_device);
	inc_unacked(peer_device);


	s_bb = (ULONG_PTR)BM_SECT_TO_BIT(d->sector);
	e_next_bb = d->bi_size == 0 ? s_bb : (ULONG_PTR)BM_SECT_TO_BIT(d->sector + (d->bi_size >> 9));
	e_oos = 0;

	//DW-1904 set e_resync_bb
	device->e_resync_bb = (e_next_bb - 1);

	if (d->bi_size < BM_BLOCK_SIZE) {
		drbd_warn(peer_device, "bug FIMXME!! bi_size(%lu) < BM_BLOCK_SIZE\n", d->bi_size);
	}

	//DW-1886
	peer_device->rs_recv_res += d->bi_size;

	if (peer_device->connection->agreed_pro_version >= 113 && 
		//DW-1904 if it is not affected by the replication data, it writes the resync data without check(split request, marked replicate list). 
		(!list_empty(&device->marked_rl_list) || is_set_area_replicate_out_of_sync(device, s_bb, e_next_bb))) {

		//DW-1601 
		//the number of peer_requests in the bitmap area that are released when the bitmap is found in the synchronization data.
		//the resyc data write complete routine determines that the active peer_request has completed when the corresponding split_count is zero. (ref. split_e_end_resync_block())
		atomic_t *split_count;

		split_count = kzalloc(sizeof(atomic_t), GFP_KERNEL, 'FFDW');
		if (!split_count) {
			drbd_err(peer_device, "failed to allocate split count\n");
			return -ENOMEM;
		}

		atomic_set(split_count, 0);

		//DW-1601 get the last out of sync bit, bit already synced, split request count information. (It must be called after prepare_garbage_bitmap_bit())
		if (prepare_split_peer_request(peer_device, s_bb, e_next_bb, split_count, &e_oos)) {

			bool s_split_request = false;
			bool is_all_sync = (atomic_read(split_count) == 0 ? true : false);
			struct drbd_peer_request *split_peer_req = NULL;
			struct drbd_marked_replicate *marked_rl;
			bool already_in_sync_bb = false;
			bool is_marked_bb = false;

			offset = s_bb;

			for (ULONG_PTR i_bb = offset = s_bb; i_bb < e_next_bb; i_bb++) {
				already_in_sync_bb = (drbd_bm_test_bit(peer_device, i_bb) == 0);
				is_marked_bb = is_marked_rl_bb(peer_device, &marked_rl, i_bb);

				if (is_marked_bb || already_in_sync_bb) {
					if (is_all_sync) {
						//DW-1886
						atomic_add64(d->bi_size, &peer_device->rs_written);

						//DW-1601 all data is synced.
						drbd_debug(peer_device, "##all, sync bitmap(%llu), start : %llu, end :%llu\n", (unsigned long long)i_bb, (unsigned long long)s_bb, (unsigned long long)(e_next_bb - 1));
						err = drbd_send_ack(peer_device, P_RS_WRITE_ACK, peer_req);
						drbd_rs_complete_io(peer_device, peer_req->i.sector, __FUNCTION__);
						atomic_add(d->bi_size >> 9, &device->rs_sect_ev); 
						drbd_free_peer_req(peer_req);
						dec_unacked(peer_device);

						kfree2(split_count);

						return err;
					}

					//DW-1886
					if (already_in_sync_bb)
						atomic_add64(BM_BLOCK_SIZE, &peer_device->rs_written);

				submit_peer:
					//DW-1601 if offset is set to out of sync previously, write request to split_peer_req for data in index now from the corresponding offset.
					if (s_split_request) {
						drbd_debug(peer_device, "##sync bitmap bit %llu, split request %llu ~ %lu, size %llu, start(%llu) ~ end(%llu), end out of sync(%llu)\n",
							(unsigned long long)(i_bb - 1), (unsigned long long)offset, (unsigned long long)(i_bb - 1), (unsigned long long)(BM_BIT_TO_SECT(i_bb - offset) << 9), (unsigned long long)s_bb, (unsigned long long)(e_next_bb - 1), (unsigned long long)e_oos);

						split_peer_req = split_read_in_block(peer_device, peer_req,
															BM_BIT_TO_SECT(offset), (BM_BIT_TO_SECT(offset - s_bb) << 9),
															(unsigned int)(BM_BIT_TO_SECT(i_bb - offset) << 9),
															s_bb,  e_next_bb, 
															((e_oos == (i_bb - 1) && !marked_rl ) ? EE_SPLIT_LAST_REQ : EE_SPLIT_REQ),
															split_count, NULL);

						if (!split_peer_req) {
							drbd_err(peer_device, "failed to alloc split_peer_req, %llu\n", (unsigned long long)i_bb);
							err = -ENOMEM;
							goto split_error_clear;
						}

						spin_lock_irq(&device->resource->req_lock);
						list_add_tail(&split_peer_req->w.list, &peer_device->connection->sync_ee);
						spin_unlock_irq(&device->resource->req_lock);

						atomic_add(split_peer_req->i.size << 9, &device->rs_sect_ev);

						//DW-1601, DW-1846 do not set out of sync unless it is a sync target.
						if (is_sync_target(peer_device))
							drbd_set_all_out_of_sync(device, split_peer_req->i.sector, split_peer_req->i.size);

						if (!drbd_submit_peer_request(device, split_peer_req, REQ_OP_WRITE, 0, DRBD_FAULT_RS_WR) == 0) {
							err = -EIO;
							drbd_err(device, "submit failed, triggering re-connect\n");
						error_clear:
							spin_lock_irq(&device->resource->req_lock);
							list_del(&split_peer_req->w.list);
							spin_unlock_irq(&device->resource->req_lock);
							drbd_free_peer_req(split_peer_req);

							//DW-1601 If the drbd_submit_peer_request() fails, remove split_count - submit_count from the previously acquired split_cnt and turn off split_cnt if 0.
						split_error_clear:
							//DW-1923 for interparameter synchronization, an additional 1 was added for the remaining count and modified to use atomic_dec_return.
							atomic_set(split_count, atomic_read(split_count) - (atomic_read(split_count) - submit_count) + 1);
							if (split_count && 0 == atomic_dec_return(split_count))
								kfree2(split_count);

							drbd_free_peer_req(peer_req);

							return err;
						}
						//DW-1601 submit_count is used for the split_cnt value in case of failure..
						submit_count += 1;
					}
					else
						atomic_add(BM_BLOCK_SIZE, &device->rs_sect_ev);

					if (marked_rl) {
						atomic_t *unmarked_count;
						atomic_t *failed_unmarked;

						unmarked_count = kzalloc(sizeof(atomic_t), GFP_KERNEL, 'FFDW');

						if (!unmarked_count) {
							drbd_err(peer_device, "failed to allocate unmakred_count\n");
							//DW-1923 to free allocation memory, go to the split_error_clean label.
							err = -ENOMEM;
							goto split_error_clear;
						}

						failed_unmarked = kzalloc(sizeof(atomic_t), GFP_KERNEL, 'FFDW');

						if (!failed_unmarked) {
							drbd_err(peer_device, "failed to allocate failed_unmarked\n");
							kfree2(unmarked_count);
							//DW-1923
							err = -ENOMEM;
							goto split_error_clear;
						}

						//DW-1911 unmakred sector counting
						atomic_set(unmarked_count, (sizeof(marked_rl->marked_rl) * 8) - __popcnt(marked_rl->marked_rl));
						atomic_set(failed_unmarked, 0);

						for (int i = 0; i < sizeof(marked_rl->marked_rl) * 8; i++) {
							//DW-1911 perform writing per unmarked sector.
							if (!(marked_rl->marked_rl & 1 << i)) {
								split_peer_req = split_read_in_block(peer_device, peer_req,
																	BM_BIT_TO_SECT(marked_rl->bb), 
																	((BM_BIT_TO_SECT(marked_rl->bb - s_bb) + i) << 9),
																	1 << 9,
																	s_bb, e_next_bb,
																	((marked_rl->bb == e_oos && marked_rl->end_unmarked_rl == i) ? EE_SPLIT_LAST_REQ : EE_SPLIT_REQ),
																	split_count, NULL);

								if (!split_peer_req) {
									drbd_err(peer_device, "failed to allocate split_peer_req, %llu\n", (unsigned long long)i_bb);
									atomic_set(unmarked_count, atomic_read(unmarked_count) - (atomic_read(unmarked_count) - submit_count) + 1);
									if (unmarked_count && 0 == atomic_dec_return(unmarked_count)) {
										kfree2(failed_unmarked);
										kfree2(unmarked_count);
									}

									err = -ENOMEM;
									goto split_error_clear;
								}

								split_peer_req->unmarked_count = unmarked_count;
								split_peer_req->failed_unmarked = failed_unmarked;

								spin_lock_irq(&device->resource->req_lock);
								list_add_tail(&split_peer_req->w.list, &peer_device->connection->sync_ee);
								spin_unlock_irq(&device->resource->req_lock);

								atomic_add(split_peer_req->i.size << 9, &device->rs_sect_ev);

								//DW-1916 if you receive resync data from peer_device other than syncsource, set out of sync for peer_device except for the current syncsource.
								mask = bits = DRBD_END_OF_BITMAP;

								if (!is_sync_target(peer_device)) {
									struct drbd_peer_device* pd;
									for_each_peer_device(pd, device) {
										if (pd != peer_device && is_sync_target(pd)) {
											drbd_info(peer_device, "resync with other nodes in progress\n");
											clear_bit(pd->bitmap_index, &bits);
											clear_bit(pd->bitmap_index, &mask); 
											break;
										}
									}
								}

								// DW-1928 set out of sync for split_request.
								drbd_set_sync(device, split_peer_req->i.sector, split_peer_req->i.size, bits, mask);

								drbd_debug(peer_device, "##unmarked bb(%llu), sector(%llu), offset(%d), count(%d)\n", 
									(unsigned long long)marked_rl->bb, (unsigned long long)BM_BIT_TO_SECT(marked_rl->bb) + i, i, atomic_read(unmarked_count));

								if (!drbd_submit_peer_request(device, split_peer_req, REQ_OP_WRITE, 0, DRBD_FAULT_RS_WR) == 0) {
									drbd_err(device, "unmarked, submit failed, triggering re-connect\n");
									//DW-1923 for interparameter synchronization, an additional 1 was added for the remaining count and modified to use atomic_dec_return.
									atomic_set(unmarked_count, atomic_read(unmarked_count) - (atomic_read(unmarked_count) - submit_count) + 1);
									if (unmarked_count && 0 == atomic_dec_return(unmarked_count)) {
										kfree2(failed_unmarked);
										kfree2(unmarked_count);
									}
									err = -EIO;
									goto error_clear;
								}

								submit_count += 1;
							}
							else {
								//DW-1886
								atomic_add64(1 << 9, &peer_device->rs_written);
							}
						}
					}

					// DW-1928 exit split because last out of sync request was made
					if (e_oos == (i_bb - 1))
						break;

					s_split_request = false;
				}
				else {
					if (s_split_request == false) {
						//DW-1601 set the first out of sync bit to offset.
						offset = i_bb;
						s_split_request = true;
					}

					if ((i_bb + 1) == e_next_bb) {
						i_bb += 1;
						goto submit_peer;
					}
				}
			}
		}
		else
			goto all_out_of_sync;
	}
	else {
	all_out_of_sync:
		/* corresponding dec_unacked() in e_end_resync_block()
		* respective _drbd_clear_done_ee */
		peer_req->w.cb = split_e_end_resync_block;
		peer_req->submit_jif = jiffies;

		spin_lock_irq(&device->resource->req_lock);
		list_add_tail(&peer_req->w.list, &peer_device->connection->sync_ee);
		spin_unlock_irq(&device->resource->req_lock);

		atomic_add(d->bi_size >> 9, &device->rs_sect_ev);

		/* Seting all peer out of sync here. Sync source peer will be set
		in sync when the write completes. Other peers will be set in
		sync by the sync source with a P_PEERS_IN_SYNC packet soon. */

		//DW-1916 if you receive resync data from peer_device other than syncsource, set out of sync for peer_device except for the current syncsource.
		mask = bits = DRBD_END_OF_BITMAP;

		if (!is_sync_target(peer_device)) {
			struct drbd_peer_device* pd;
			for_each_peer_device(pd, device) {
				if (pd != peer_device && is_sync_target(pd)) {
					drbd_info(peer_device, "resync with other nodes in progress\n");
					clear_bit(pd->bitmap_index, &bits);
					clear_bit(pd->bitmap_index, &mask);
					break;
				}
			}
		}

		drbd_set_sync(device, peer_req->i.sector, peer_req->i.size, bits, mask);

		if (drbd_submit_peer_request(device, peer_req, REQ_OP_WRITE, 0,
			DRBD_FAULT_RS_WR) == 0)
			return 0;

		drbd_err(device, "submit failed, triggering re-connect\n");
		/* don't care for the reason here */
		spin_lock_irq(&device->resource->req_lock);
		list_del(&peer_req->w.list);
		spin_unlock_irq(&device->resource->req_lock);

		drbd_free_peer_req(peer_req);
		return -EIO;
	}

	drbd_free_peer_req(peer_req);
	return 0;
}
#endif

static int recv_resync_read(struct drbd_peer_device *peer_device,
			    struct drbd_peer_request_details *d) __releases(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_request *peer_req;

	peer_req = read_in_block(peer_device, d);
	if (!peer_req)
		return -EIO;

	if (test_bit(UNSTABLE_RESYNC, &peer_device->flags))
		clear_bit(STABLE_RESYNC, &device->flags);

	dec_rs_pending(peer_device);

	inc_unacked(peer_device);
	/* corresponding dec_unacked() in e_end_resync_block()
	 * respective _drbd_clear_done_ee */

	peer_req->w.cb = e_end_resync_block;
	peer_req->submit_jif = jiffies;

	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&peer_req->w.list, &peer_device->connection->sync_ee);
	spin_unlock_irq(&device->resource->req_lock);

	atomic_add(d->bi_size >> 9, &device->rs_sect_ev);

	/* Seting all peer out of sync here. Sync source peer will be set
	   in sync when the write completes. Other peers will be set in
	   sync by the sync source with a P_PEERS_IN_SYNC packet soon. */

	//DW-1846 do not set out of sync unless it is a sync target.
	if (is_sync_target(peer_device)) {
		drbd_set_all_out_of_sync(device, peer_req->i.sector, peer_req->i.size);
	}

	if (drbd_submit_peer_request(device, peer_req, REQ_OP_WRITE, 0,
		DRBD_FAULT_RS_WR) == 0)
		return 0;

	/* don't care for the reason here */
	drbd_err(device, "submit failed, triggering re-connect\n");
	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	spin_unlock_irq(&device->resource->req_lock);

	drbd_free_peer_req(peer_req);
	return -EIO;
}

static struct drbd_request *
find_request(struct drbd_device *device, struct rb_root *root, u64 id,
	     sector_t sector, bool missing_ok, const char *func)
{
	struct drbd_request *req;

#ifdef _WIN32 
	req = (struct drbd_request *)(ULONG_PTR)id;
#else
	/* Request object according to our peer */
	req = (struct drbd_request *)(unsigned long)id;
#endif
	if (drbd_contains_interval(root, sector, &req->i) && req->i.local)
		return req;
	if (!missing_ok) {
		drbd_err(device, "%s: failed to find request 0x%llx, sector %llus\n", func,
			(unsigned long long)id, (unsigned long long)sector);
	}
	return NULL;
}

static int receive_DataReply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct drbd_request *req;
	sector_t sector;
	int err;
	struct p_data *p = pi->data;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	sector = be64_to_cpu(p->sector);

	spin_lock_irq(&device->resource->req_lock);
	req = find_request(device, &device->read_requests, p->block_id, sector, false, __func__);
	spin_unlock_irq(&device->resource->req_lock);
	if (unlikely(!req))
		return -EIO;

	/* drbd_remove_request_interval() is done in _req_may_be_done, to avoid
	 * special casing it there for the various failure cases.
	 * still no race with drbd_fail_pending_reads */
	err = recv_dless_read(peer_device, req, sector, pi->size);
	if (!err)
		req_mod(req, DATA_RECEIVED, peer_device);
	/* else: nothing. handled from drbd_disconnect...
	 * I don't think we may complete this just yet
	 * in case we are "on-disconnect: freeze" */

	return err;
}


static void drbd_send_ack_rp(struct drbd_peer_device *peer_device, enum drbd_packet cmd,
		      struct p_block_req *rp)
{
	_drbd_send_ack(peer_device, cmd, rp->sector, rp->blksize, rp->block_id);
}

/**
 * drbd_send_ack() - Sends an ack packet
 * @device:	DRBD device
 * @cmd:	packet command code
 * @peer_req:	peer request
 */
int drbd_send_ack(struct drbd_peer_device *peer_device, enum drbd_packet cmd,
		  struct drbd_peer_request *peer_req)
{
	return _drbd_send_ack(peer_device, cmd,
			      cpu_to_be64(peer_req->i.sector),
			      cpu_to_be32(peer_req->i.size),
			      peer_req->block_id);
}

/* This function misuses the block_id field to signal if the blocks
 * are is sync or not. */
int drbd_send_ack_ex(struct drbd_peer_device *peer_device, enum drbd_packet cmd,
		     sector_t sector, int blksize, u64 block_id)
{
	return _drbd_send_ack(peer_device, cmd,
			      cpu_to_be64(sector),
			      cpu_to_be32(blksize),
			      cpu_to_be64(block_id));
}

static int receive_RSDataReply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_request_details d;
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	int err;

	p_req_detail_from_pi(connection, &d, pi);
	pi->data = NULL;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	D_ASSERT(device, d.block_id == ID_SYNCER);

	if (get_ldev(device)) {
		// DW-1979
		atomic_set(&peer_device->wait_for_recv_rs_reply, 0);

		//DW-1845 disables the DW-1601 function. If enabled, you must set ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
		err = split_recv_resync_read(peer_device, &d);
#else
		err = recv_resync_read(peer_device, &d);
#endif
		if (err)
			put_ldev(device);
	} else {
		if (drbd_ratelimit())
			drbd_err(device, "Can not write resync data to local disk.\n");

		err = ignore_remaining_packet(connection, pi->size);

		drbd_send_ack_dp(peer_device, P_NEG_ACK, &d);
	}

	atomic_add(d.bi_size >> 9, &peer_device->rs_sect_in);

	return err;
}

static void restart_conflicting_writes(struct drbd_peer_request *peer_req)
{
	struct drbd_interval *i;
	struct drbd_request *req;
	struct drbd_device *device = peer_req->peer_device->device;
	const sector_t sector = peer_req->i.sector;
	const unsigned int size = peer_req->i.size;

	drbd_for_each_overlap(i, &device->write_requests, sector, size) {
		if (!i->local)
			continue;
		req = container_of(i, struct drbd_request, i);
		if ((req->rq_state[0] & RQ_LOCAL_PENDING) ||
		   !(req->rq_state[0] & RQ_POSTPONED))
			continue;
		/* as it is RQ_POSTPONED, this will cause it to
		 * be queued on the retry workqueue. */
		__req_mod(req, DISCARD_WRITE, peer_req->peer_device, NULL);
	}
}

/*
 * e_end_block() is called in ack_sender context via drbd_finish_peer_reqs().
 */
static int e_end_block(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct drbd_epoch *epoch;
	int err = 0, pcmd;

	if (peer_req->flags & EE_IS_BARRIER) {
		epoch = previous_epoch(peer_device->connection, peer_req->epoch);
		if (epoch)
			drbd_may_finish_epoch(peer_device->connection, epoch, EV_BARRIER_DONE + (cancel ? EV_CLEANUP : 0));
	}

	if (peer_req->flags & EE_SEND_WRITE_ACK) {
		if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {

#ifdef _WIN32
			// MODIFIED_BY_MANTECH DW-1012: Existing out of sync means that the data for current req is outdated.
			// Sending 'P_RS_WRITE_ACK' for replication data could break consistency since it removes newly set out of sync.
			pcmd = P_WRITE_ACK;
			err = drbd_send_ack(peer_device, pcmd, peer_req);
#else
			pcmd = (peer_device->repl_state[NOW] >= L_SYNC_SOURCE &&
				peer_device->repl_state[NOW] <= L_PAUSED_SYNC_T &&
				peer_req->flags & EE_MAY_SET_IN_SYNC) ?
				P_RS_WRITE_ACK : P_WRITE_ACK;
			err = drbd_send_ack(peer_device, pcmd, peer_req);
			if (pcmd == P_RS_WRITE_ACK)
				drbd_set_in_sync(peer_device, sector, peer_req->i.size);
#endif
		} else {
			err = drbd_send_ack(peer_device, P_NEG_ACK, peer_req);
			/* DW-1810
			 * Since the drbd_endio_write_sec_final function must be executed at both the replication and resync after the IO completion routine, 
			 * the OOS record for the IO error is set to drbd_endio_write_sec_final.
			 * And since duplicate records were made in e_end_block, they are deleted.
			 */

			/* we expect it to be marked out of sync anyways...
			 * maybe assert this?  */
		}
		dec_unacked(peer_device);
	}

	/* we delete from the conflict detection hash _after_ we sent out the
	 * P_WRITE_ACK / P_NEG_ACK, to get the sequence number right.  */
	if (peer_req->flags & EE_IN_INTERVAL_TREE) {
		spin_lock_irq(&device->resource->req_lock);
		D_ASSERT(device, !drbd_interval_empty(&peer_req->i));
		drbd_remove_peer_req_interval(device, peer_req); 
		if (peer_req->flags & EE_RESTART_REQUESTS)
			restart_conflicting_writes(peer_req);
		spin_unlock_irq(&device->resource->req_lock);
	} else
		D_ASSERT(device, drbd_interval_empty(&peer_req->i));

	// MODIFIED_BY_MANTECH DW-1665: P_DATA, P_BARRIER sync problem for protocol A, change call location to drbd_finish_peer_reqs()
	//drbd_may_finish_epoch(peer_device->connection, peer_req->epoch, EV_PUT + (cancel ? EV_CLEANUP : 0));

	return err;
}

static int e_send_ack(struct drbd_work *w, enum drbd_packet ack)
{
	struct drbd_peer_request *peer_req =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	int err;

	err = drbd_send_ack(peer_device, ack, peer_req);
	dec_unacked(peer_device);

	return err;
}

static int e_send_discard_write(struct drbd_work *w, int unused)
{
	UNREFERENCED_PARAMETER(unused);

	return e_send_ack(w, P_SUPERSEDED); 
}

static int e_send_retry_write(struct drbd_work *w, int unused)
{

	UNREFERENCED_PARAMETER(unused);

	struct drbd_peer_request *peer_request =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_connection *connection = peer_request->peer_device->connection;

	return e_send_ack(w, connection->agreed_pro_version >= 100 ?
			     P_RETRY_WRITE : P_SUPERSEDED);
}

static bool seq_greater(u32 a, u32 b)
{
	/*
	 * We assume 32-bit wrap-around here.
	 * For 24-bit wrap-around, we would have to shift:
	 *  a <<= 8; b <<= 8;
	 */
	return (s32)a - (s32)b > 0;
}

static u32 seq_max(u32 a, u32 b)
{
	return seq_greater(a, b) ? a : b;
}

static void update_peer_seq(struct drbd_peer_device *peer_device, unsigned int peer_seq)
{
	unsigned int newest_peer_seq;

	if (test_bit(RESOLVE_CONFLICTS, &peer_device->connection->transport.flags)) {
		spin_lock(&peer_device->peer_seq_lock);
		newest_peer_seq = seq_max(peer_device->peer_seq, peer_seq);
		peer_device->peer_seq = newest_peer_seq;
		spin_unlock(&peer_device->peer_seq_lock);
		/* wake up only if we actually changed peer_device->peer_seq */
		if (peer_seq == newest_peer_seq)
			wake_up(&peer_device->device->seq_wait);
	}
}

static inline int overlaps(sector_t s1, int l1, sector_t s2, int l2)
{
	return !((s1 + (l1>>9) <= s2) || (s1 >= s2 + (l2>>9)));
}

/* maybe change sync_ee into interval trees as well? */
static bool overlapping_resync_write(struct drbd_connection *connection, struct drbd_peer_request *peer_req)
{
	struct drbd_peer_request *rs_req;
	bool rv = false;

	/* Now only called in the fallback compatibility path, when the peer is
	* DRBD version 8, which also means it is the only peer.
	* If we wanted to use this in a scenario where we could potentially
	* have in-flight resync writes from multiple peers, we'd need to
	* iterate over all connections.
	* Fortunately we don't have to, because we have now mutually excluded
	* resync and application activity on a particular region using
	* device->act_log and peer_device->resync_lru.
	*/
	spin_lock_irq(&connection->resource->req_lock);
#ifdef _WIN32
	list_for_each_entry(struct drbd_peer_request, rs_req, &connection->sync_ee, w.list) {
#else
	list_for_each_entry(rs_req, &connection->sync_ee, w.list) {
#endif
		if (rs_req->peer_device != peer_req->peer_device)
			continue;
		if (overlaps(peer_req->i.sector, peer_req->i.size,
			     rs_req->i.sector, rs_req->i.size)) {
			rv = true;
			break;
		}
	}
	spin_unlock_irq(&connection->resource->req_lock);

	return rv;
}

/* Called from receive_Data.
 * Synchronize packets on sock with packets on msock.
 *
 * This is here so even when a P_DATA packet traveling via sock overtook an Ack
 * packet traveling on msock, they are still processed in the order they have
 * been sent.
 *
 * Note: we don't care for Ack packets overtaking P_DATA packets.
 *
 * In case packet_seq is larger than peer_device->peer_seq number, there are
 * outstanding packets on the msock. We wait for them to arrive.
 * In case we are the logically next packet, we update peer_device->peer_seq
 * ourselves. Correctly handles 32bit wrap around.
 *
 * Assume we have a 10 GBit connection, that is about 1<<30 byte per second,
 * about 1<<21 sectors per second. So "worst" case, we have 1<<3 == 8 seconds
 * for the 24bit wrap (historical atomic_t guarantee on some archs), and we have
 * 1<<9 == 512 seconds aka ages for the 32bit wrap around...
 *
 * returns 0 if we may process the packet,
 * -ERESTARTSYS if we were interrupted (by disconnect signal). */
static int wait_for_and_update_peer_seq(struct drbd_peer_device *peer_device, const u32 peer_seq)
{
	struct drbd_connection *connection = peer_device->connection;
#ifndef _WIN32
	DEFINE_WAIT(wait);
#endif
	long timeout;
	int ret = 0, tp;

	if (!test_bit(RESOLVE_CONFLICTS, &connection->transport.flags))
		return 0;

	spin_lock(&peer_device->peer_seq_lock);
	for (;;) {
		if (!seq_greater(peer_seq - 1, peer_device->peer_seq)) {
			peer_device->peer_seq = seq_max(peer_device->peer_seq, peer_seq);
			break;
		}

		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		rcu_read_lock();
		tp = rcu_dereference(connection->transport.net_conf)->two_primaries;
		rcu_read_unlock();

		if (!tp)
			break;
#ifndef _WIN32
		/* Only need to wait if two_primaries is enabled */
		prepare_to_wait(&peer_device->device->seq_wait, &wait, TASK_INTERRUPTIBLE);
#endif
		spin_unlock(&peer_device->peer_seq_lock);
#ifdef _WIN32
		rcu_read_lock_w32_inner();
#else
		rcu_read_lock();
#endif
		timeout = rcu_dereference(connection->transport.net_conf)->ping_timeo*HZ/10;
		rcu_read_unlock();
#ifdef _WIN32
		timeout = schedule(&peer_device->device->seq_wait, timeout, __FUNCTION__, __LINE__);
#else
		timeout = schedule_timeout(timeout);
#endif
		spin_lock(&peer_device->peer_seq_lock);
		if (!timeout) {
			ret = -ETIMEDOUT;
			drbd_err(peer_device, "Timed out waiting for missing ack packets; disconnecting\n");
			break;
		}
	}
	spin_unlock(&peer_device->peer_seq_lock);
#ifndef _WIN32
	finish_wait(&peer_device->device->seq_wait, &wait);
#endif
	return ret;
}

/* see also bio_flags_to_wire()
 * DRBD_REQ_*, because we need to semantically map the flags to data packet
 * flags and back. We may replicate to other kernel versions. */
static unsigned long wire_flags_to_bio_flags(struct drbd_connection *connection, u32 dpf)
{
	if (connection->agreed_pro_version >= 95)
		return  (dpf & DP_RW_SYNC ? DRBD_REQ_SYNC : 0) |
			(dpf & DP_UNPLUG ? DRBD_REQ_UNPLUG : 0) |
			(dpf & DP_FUA ? DRBD_REQ_FUA : 0) |
			(dpf & DP_FLUSH ? DRBD_REQ_PREFLUSH : 0);


	/* else: we used to communicate one bit only in older DRBD */
	return dpf & DP_RW_SYNC ? (DRBD_REQ_SYNC | DRBD_REQ_UNPLUG) : 0;
}

static int wire_flags_to_bio_op(u32 dpf)
{
	if (dpf & DP_DISCARD)
		return REQ_OP_DISCARD;
	else
		return REQ_OP_WRITE;
}

static void fail_postponed_requests(struct drbd_peer_request *peer_req)
{
	struct drbd_device *device = peer_req->peer_device->device;
	struct drbd_interval *i;
	const sector_t sector = peer_req->i.sector;
	const unsigned int size = peer_req->i.size;

    repeat:
	drbd_for_each_overlap(i, &device->write_requests, sector, size) {
		struct drbd_request *req;
		struct bio_and_error m;

		if (!i->local)
			continue;
		req = container_of(i, struct drbd_request, i);
		if (!(req->rq_state[0] & RQ_POSTPONED))
			continue;
		req->rq_state[0] &= ~RQ_POSTPONED;
		__req_mod(req, NEG_ACKED, peer_req->peer_device, &m);
		spin_unlock_irq(&device->resource->req_lock);
		if (m.bio)
#ifdef _WIN32
			complete_master_bio(device, &m, __func__, __LINE__);
#else
			complete_master_bio(device, &m);
#endif
		spin_lock_irq(&device->resource->req_lock);
		goto repeat;
	}
}

static int handle_write_conflicts(struct drbd_peer_request *peer_req)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	bool resolve_conflicts = test_bit(RESOLVE_CONFLICTS, &connection->transport.flags);
	sector_t sector = peer_req->i.sector;
	const unsigned int size = peer_req->i.size;
	struct drbd_interval *i;
	bool equal;
	int err;

	/*
	 * Inserting the peer request into the write_requests tree will prevent
	 * new conflicting local requests from being added.
	 */
	drbd_insert_interval(&device->write_requests, &peer_req->i);
	peer_req->flags |= EE_IN_INTERVAL_TREE;

    repeat:
	drbd_for_each_overlap(i, &device->write_requests, sector, size) {
		if (i == &peer_req->i)
			continue;
        	if (i->completed)
			continue;

		if (!i->local) {
			/*
			 * Our peer has sent a conflicting remote request; this
			 * should not happen in a two-node setup.  Wait for the
			 * earlier peer request to complete.
			 */
			err = drbd_wait_misc(device, peer_device, i);
			if (err)
				goto out;
			goto repeat;
		}

		equal = i->sector == sector && i->size == size;
		if (resolve_conflicts) {
			/*
			 * If the peer request is fully contained within the
			 * overlapping request, it can be discarded; otherwise,
			 * it will be retried once all overlapping requests
			 * have completed.
			 */
			bool discard = i->sector <= sector && i->sector +
				       (i->size >> 9) >= sector + (size >> 9);

			if (!equal)
				drbd_alert(device, "Concurrent writes detected: "
					       "local=%llus +%u, remote=%llus +%u, "
					       "assuming %s came first\n",
					  (unsigned long long)i->sector, i->size,
					  (unsigned long long)sector, size,
					  discard ? "local" : "remote");

			peer_req->w.cb = discard ? e_send_discard_write :
						   e_send_retry_write;
			atomic_inc(&connection->done_ee_cnt);
			list_add_tail(&peer_req->w.list, &connection->done_ee);
            		queue_work(connection->ack_sender, &connection->send_acks_work);

			err = -ENOENT;
			goto out;
		} else {
			struct drbd_request *req =
				container_of(i, struct drbd_request, i);

			if (!equal)
				drbd_alert(device, "Concurrent writes detected: "
					       "local=%llus +%u, remote=%llus +%u\n",
					  (unsigned long long)i->sector, i->size,
					  (unsigned long long)sector, size);

			if (req->rq_state[0] & RQ_LOCAL_PENDING ||
			    !(req->rq_state[0] & RQ_POSTPONED)) {
				/*
				 * Wait for the node with the discard flag to
				 * decide if this request will be discarded or
				 * retried.  Requests that are discarded will
				 * disappear from the write_requests tree.
				 *
				 * In addition, wait for the conflicting
				 * request to finish locally before submitting
				 * the conflicting peer request.
				 */
				err = drbd_wait_misc(device, NULL, &req->i);
				if (err) {
                    			begin_state_change_locked(connection->resource, CS_HARD);
					__change_cstate(connection, C_TIMEOUT);
#ifdef _WIN32_RCU_LOCKED
					end_state_change_locked(connection->resource, false, __FUNCTION__);
#else
					end_state_change_locked(connection->resource);
#endif
					fail_postponed_requests(peer_req);
					goto out;
				}
				goto repeat;
			}
			/*
			 * Remember to restart the conflicting requests after
			 * the new peer request has completed.
			 */
			peer_req->flags |= EE_RESTART_REQUESTS;
		}
	}
	err = 0;

    out:
	if (err)
		drbd_remove_peer_req_interval(device, peer_req);
	return err;
}

static void drbd_queue_peer_request(struct drbd_device *device, struct drbd_peer_request *peer_req)
{
	atomic_inc(&peer_req->peer_device->wait_for_actlog);
	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&peer_req->wait_for_actlog, &device->submit.peer_writes);
	spin_unlock_irq(&device->resource->req_lock);
	queue_work(device->submit.wq, &device->submit.worker);
	/* do_submit() may sleep internally on al_wait, too */
	wake_up(&device->al_wait);
}

/* mirrored write */
static int receive_Data(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct net_conf *nc;
	struct drbd_peer_request *peer_req;
	struct drbd_peer_request_details d;
	int op, op_flags;
	int err, tp;

#ifdef _WIN32 // DW-1502 bump the mirrored data after the ack_receiver has terminated.
	if(get_t_state(&connection->ack_receiver) != RUNNING) {
		WDRBD_INFO("ack_receiver is not running... bump mirrored data\n");
		return 0;
	}
#endif	
	peer_device = conn_peer_device(connection, pi->vnr);    
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	if (pi->cmd == P_TRIM)
		D_ASSERT(peer_device, pi->size == 0);

	p_req_detail_from_pi(connection, &d, pi);
	pi->data = NULL;

	if (!get_ldev(device)) {
		int err2;

		err = wait_for_and_update_peer_seq(peer_device, d.peer_seq);
		drbd_send_ack_dp(peer_device, P_NEG_ACK, &d);
#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-1012: Set out-of-sync when replication data hasn't been written on my disk, source node does same once it receives negative ack.
		drbd_set_out_of_sync(peer_device, d.sector, d.bi_size);
#endif
		atomic_inc(&connection->current_epoch->epoch_size);
		err2 = ignore_remaining_packet(connection, pi->size);
		if (!err)
			err = err2;
		return err;
	}

	/*
	 * Corresponding put_ldev done either below (on various errors), or in
	 * drbd_peer_request_endio, if we successfully submit the data at the
	 * end of this function.
	 */

	peer_req = read_in_block(peer_device, &d);
	if (!peer_req) {
		put_ldev(device);
		return -EIO;
	}
	if (pi->cmd == P_TRIM)
		peer_req->flags |= EE_IS_TRIM;
	else if (pi->cmd == P_WSAME)
		peer_req->flags |= EE_WRITE_SAME;

	peer_req->dagtag_sector = connection->last_dagtag_sector + (peer_req->i.size >> 9);
	connection->last_dagtag_sector = peer_req->dagtag_sector;

	peer_req->w.cb = e_end_block;
	peer_req->submit_jif = jiffies;
	peer_req->flags |= EE_APPLICATION;

	op = wire_flags_to_bio_op(d.dp_flags);
	op_flags = wire_flags_to_bio_flags(connection, d.dp_flags);
	if (pi->cmd == P_TRIM) {
		D_ASSERT(peer_device, peer_req->i.size > 0);
		D_ASSERT(peer_device, d.dp_flags & DP_DISCARD);
		D_ASSERT(peer_device, peer_req->page_chain.head == NULL);
		D_ASSERT(peer_device, peer_req->page_chain.nr_pages == 0);
	} else if (peer_req->page_chain.head == NULL) {
		/* Actually, this must not happen anymore,
		 * "empty" flushes are mapped to P_BARRIER,
		 * and should never end up here.
		 * Compat with old DRBD? */
		D_ASSERT(device, peer_req->i.size == 0);
		D_ASSERT(device, d.dp_flags & DP_FLUSH);
	}

	if (d.dp_flags & DP_MAY_SET_IN_SYNC)
		peer_req->flags |= EE_MAY_SET_IN_SYNC;

	/* last "fixes" to rw flags.
	 * Strip off BIO_RW_BARRIER unconditionally,
	 * it is not supposed to be here anyways.
	 * (Was FUA or FLUSH on the peer,
	 * and got translated to BARRIER on this side).
	 * Note that the epoch handling code below
	 * may add it again, though.
	 */
	op_flags &= ~DRBD_REQ_HARDBARRIER;

	spin_lock(&connection->epoch_lock);
	peer_req->epoch = connection->current_epoch;
	atomic_inc(&peer_req->epoch->epoch_size);
	atomic_inc(&peer_req->epoch->active);

	if (connection->resource->write_ordering == WO_BIO_BARRIER &&
	    atomic_read(&peer_req->epoch->epoch_size) == 1) {
		struct drbd_epoch *epoch;
		/* Issue a barrier if we start a new epoch, and the previous epoch
		   was not a epoch containing a single request which already was
		   a Barrier. */
		epoch = list_entry(peer_req->epoch->list.prev, struct drbd_epoch, list);
		if (epoch == peer_req->epoch) {
			set_bit(DE_CONTAINS_A_BARRIER, &peer_req->epoch->flags);
			op_flags |= DRBD_REQ_PREFLUSH | DRBD_REQ_FUA;
			peer_req->flags |= EE_IS_BARRIER;
		} else {
			if (atomic_read(&epoch->epoch_size) > 1 ||
			    !test_bit(DE_CONTAINS_A_BARRIER, &epoch->flags)) {
				set_bit(DE_BARRIER_IN_NEXT_EPOCH_ISSUED, &epoch->flags);
				set_bit(DE_CONTAINS_A_BARRIER, &peer_req->epoch->flags);
				op_flags |= DRBD_REQ_PREFLUSH | DRBD_REQ_FUA;
				peer_req->flags |= EE_IS_BARRIER;
			}
		}
	}
	spin_unlock(&connection->epoch_lock);

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	tp = nc->two_primaries;
	if (connection->agreed_pro_version < 100) {
		switch (nc->wire_protocol) {
		case DRBD_PROT_C:
			d.dp_flags |= DP_SEND_WRITE_ACK;
			break;
		case DRBD_PROT_B:
			d.dp_flags |= DP_SEND_RECEIVE_ACK;
			break;
		}
	}
	rcu_read_unlock();

	if (d.dp_flags & DP_SEND_WRITE_ACK) {
		peer_req->flags |= EE_SEND_WRITE_ACK;
		inc_unacked(peer_device);
		/* corresponding dec_unacked() in e_end_block()
		 * respective _drbd_clear_done_ee */
	}

	if (d.dp_flags & DP_SEND_RECEIVE_ACK) {
		/* I really don't like it that the receiver thread
		 * sends on the msock, but anyways */
		drbd_send_ack(peer_device, P_RECV_ACK, peer_req);
	}

	if (tp) {
		/* two primaries implies protocol C */
		D_ASSERT(device, d.dp_flags & DP_SEND_WRITE_ACK);
		err = wait_for_and_update_peer_seq(peer_device, d.peer_seq);
		if (err)
			goto out_interrupted;
		spin_lock_irq(&device->resource->req_lock);
		err = handle_write_conflicts(peer_req);
		if (err) {
			spin_unlock_irq(&device->resource->req_lock);
			if (err == -ENOENT) {
				put_ldev(device);
				return 0;
			}
			goto out_interrupted;
		}
	} else {
		update_peer_seq(peer_device, d.peer_seq);
		spin_lock_irq(&device->resource->req_lock);
	}
	/* TRIM and WRITE_SAME are processed synchronously,
	 * we wait for all pending requests, respectively wait for
	 * active_ee to become empty in drbd_submit_peer_request();
	 * better not add ourselves here. */
	if ((peer_req->flags & (EE_IS_TRIM|EE_WRITE_SAME)) == 0)
		list_add_tail(&peer_req->w.list, &connection->active_ee);
	if (connection->agreed_pro_version >= 110)
		list_add_tail(&peer_req->recv_order, &connection->peer_requests);
	spin_unlock_irq(&device->resource->req_lock);

	if (connection->agreed_pro_version < 110) {
		/* If the peer is DRBD 8, a sync target may need to drain
		* (overlapping) in-flight resync requests first.
		* With DRBD 9, the mutually exclusive references in resync lru
		* and activity log takes care of that already. */
	
		// DW-1250: wait until there's no resync on same sector, to prevent overlapped write.
		if (peer_device->repl_state[NOW] >= L_SYNC_TARGET)
			wait_event(connection->ee_wait, !overlapping_resync_write(connection, peer_req));
	}

	/* If we would need to block on the activity log,
	* we may queue this request for the submitter workqueue.
	* Remember the op_flags. */
	peer_req->op_flags = op_flags;

	/* In protocol < 110 (which is compat mode 8.4 <-> 9.0),
	 * we must not block in the activity log here, that would
	 * deadlock during an ongoing resync with the drbd_rs_begin_io
	 * we did when receiving the resync request.
	 *
	 * We still need to update the activity log, if ours is the
	 * only remaining disk, in which case there cannot be a resync,
	 * and the deadlock paths cannot be taken.
	 */
	if (connection->agreed_pro_version >= 110 ||
	    peer_device->disk_state[NOW] < D_INCONSISTENT) {
		/* For now, it is easier to still handle some "special" requests
		* "synchronously" from receiver context */
		if (peer_req->flags & (EE_IS_TRIM | EE_WRITE_SAME | EE_IS_BARRIER)) {
			err = drbd_al_begin_io_for_peer(peer_device, &peer_req->i);
			if (err)
			{
#ifdef _WIN32 // DW-1499 : Decrease unacked_cnt when returning an error. 
				drbd_err(peer_device, "disconnect during al begin io (err = %d)\n", err);
				if (peer_req->flags & EE_SEND_WRITE_ACK)
				{
					dec_unacked(peer_device);
				}
#endif
			goto disconnect_during_al_begin_io;
			}
		} else if (!drbd_al_begin_io_fastpath(device, &peer_req->i)) {
			peer_req->do_submit = true;
			drbd_queue_peer_request(device, peer_req);
			return 0;
		}
		peer_req->flags |= EE_IN_ACTLOG;
	}

	err = drbd_submit_peer_request(device, peer_req, op, op_flags,
		DRBD_FAULT_DT_WR);
	if (!err)
#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1012: The data just received is the newest, ignore previously received out-of-sync.
	{
		// DW-1979 do not set "in sync" before starting resync.
		if (peer_device->repl_state[NOW] == L_WF_BITMAP_T ||
			(peer_device->repl_state[NOW] == L_SYNC_TARGET && atomic_read(&peer_device->wait_for_recv_rs_reply))) {
			// DW-1979 set to D_INCONSISTENT when replication data occurs during resync start.
			if (peer_device->device->disk_state[NOW] != D_INCONSISTENT &&
				peer_device->device->disk_state[NEW] != D_INCONSISTENT) {
				unsigned long irq_flags;
				begin_state_change(peer_device->device->resource, &irq_flags, CS_VERBOSE);
				__change_disk_state(peer_device->device, D_INCONSISTENT, __FUNCTION__);
				end_state_change(peer_device->device->resource, &irq_flags, __FUNCTION__);
			}
		}
		else {
			ULONG_PTR in_sync = 0;

			//DW-1904
			in_sync = drbd_set_in_sync(peer_device, peer_req->i.sector, peer_req->i.size);

			//DW-1815 if the replication is in sync during resync, set it to peer_device with the same current_uuid. set to sync for peer_device that is the same current_uuid.
			if (is_sync_target(peer_device) && in_sync) {
				struct drbd_peer_device* pd;
				for_each_peer_device(pd, peer_device->device) {
					if (pd == peer_device)
						continue;

					if (pd->current_uuid == peer_device->current_uuid) {
						drbd_set_in_sync(pd, peer_req->i.sector, peer_req->i.size);
					}
				}
			}

			//DW-1601 if the status is L_SYNC_TARGET calculate
#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
			if (peer_device->connection->agreed_pro_version >= 113 && peer_device->repl_state[NOW] == L_SYNC_TARGET) {
				sector_t ssector, esector;
				ULONG_PTR s_bb, e_bb;

				ssector = peer_req->i.sector;
				esector = peer_req->i.sector + (peer_req->i.size >> 9);

				s_bb = (ULONG_PTR)BM_SECT_TO_BIT(ssector);
				e_bb = (ULONG_PTR)BM_SECT_TO_BIT(esector);

				//DW-1911 use e_bb instead of e_next_b for replication.
				if (BM_BIT_TO_SECT(e_bb) == esector)
					e_bb -= 1;

				//DW-1904 next resync data range(device->e_resync_bb ~ n_resync_bb)
				ULONG_PTR n_resync_bb = device->e_resync_bb + (ULONG_PTR)BM_SECT_TO_BIT((min((queue_max_hw_sectors(device->rq_queue) << 9), DRBD_MAX_BIO_SIZE)) >> 9);
				struct drbd_marked_replicate *marked_rl = NULL, *s_marked_rl = NULL, *e_marked_rl = NULL;

				if ((device->e_resync_bb < e_bb && n_resync_bb >= e_bb) ||
					(device->e_resync_bb < s_bb && n_resync_bb >= s_bb)) {
					//DW-1911 check if marked already exists.
					list_for_each_entry(struct drbd_marked_replicate, marked_rl, &(device->marked_rl_list), marked_rl_list) {
						if (marked_rl->bb == s_bb)
							s_marked_rl = marked_rl;
						if (marked_rl->bb == e_bb)
							e_marked_rl = marked_rl;

						if (s_marked_rl && e_marked_rl)
							break;
					}

					if ((BM_BIT_TO_SECT(s_bb) != ssector || (BM_BIT_TO_SECT(s_bb) == ssector && s_bb == s_bb)) &&
						drbd_bm_test_bit(peer_device, s_bb) == 1) {
						if (!s_marked_rl) {
							s_marked_rl = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct drbd_marked_replicate), 'E8DW');
							if (s_marked_rl != NULL) {
								s_marked_rl->bb = s_bb;
								s_marked_rl->marked_rl = 0;
								s_marked_rl->end_unmarked_rl = 0;
								list_add(&(s_marked_rl->marked_rl_list), &device->marked_rl_list);
							}
							else {
								drbd_err(peer_device, "failed to marked replicate allocate, bit : %llu\n", (unsigned long long)s_bb);
								return -ENOMEM;
							}
						}

						//DW-1911 set the bit to match the sector.
						u16 offset = (u16)(ssector - BM_BIT_TO_SECT(s_bb));;
						for (u16 i = offset; i < (offset + (peer_req->i.size >> 9)); i++) {
							if (BM_SECT_TO_BIT(BM_BIT_TO_SECT(s_bb) + i) != s_bb)
								break;
							s_marked_rl->marked_rl |= 1 << i;
						}
						drbd_debug(peer_device, "sbb marking bb(%llu), ssector(%llu), sector(%llu), size(%u), marked(%u), offset(%u)\n",
							(unsigned long long)s_marked_rl->bb, (unsigned long long)ssector, (unsigned long long)BM_BIT_TO_SECT(s_marked_rl->bb), (peer_req->i.size >> 9), s_marked_rl->marked_rl, offset);
					}

					if (s_bb != e_bb && BM_BIT_TO_SECT(BM_SECT_TO_BIT(esector)) != (esector - 1) &&
						drbd_bm_test_bit(peer_device, e_bb) == 1) {
						if (!e_marked_rl) {
							e_marked_rl = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct drbd_marked_replicate), 'E8DW');
							if (e_marked_rl != NULL) {
								e_marked_rl->bb = e_bb;
								e_marked_rl->marked_rl = 0;
								e_marked_rl->end_unmarked_rl = 0;
								list_add(&(e_marked_rl->marked_rl_list), &device->marked_rl_list);
							}
							else {
								drbd_err(peer_device, "failed to marked replicate allocate, bit : %llu\n", (unsigned long long)e_bb);
								return -ENOMEM;
							}
						}

						//DW-1911 set the bit to match the sector.
						for (u16 i = 0; i < (esector - BM_BIT_TO_SECT(e_bb)); i++) {
							e_marked_rl->marked_rl |= 1 << i;
						}
						drbd_debug(peer_device, "marking bb(%llu), esector(%llu), sector(%llu), size(%u), marked(%u), offset(%u)\n",
							(unsigned long long)e_marked_rl->bb, esector, (unsigned long long)BM_BIT_TO_SECT(e_marked_rl->bb), (peer_req->i.size >> 9), e_marked_rl->marked_rl, 0);
					}
				}

				//DW-1904
				if (in_sync) {
					//DW-1911 marked_rl bit is excluded.
					if (s_marked_rl != NULL)
						s_bb += 1;
					if (e_marked_rl != NULL)
						e_bb -= 1;

					if (device->s_rl_bb > s_bb)
						device->s_rl_bb = s_bb;
					if (device->e_rl_bb < e_bb)
						device->e_rl_bb = e_bb;
				}
			}
		}
#endif

#ifdef _WIN32_TRACE_PEER_DAGTAG
		WDRBD_INFO("receive_Data connection->last_dagtag_sector:%llx ack_receiver thread state:%d\n",connection->last_dagtag_sector, get_t_state(&connection->ack_receiver));
#endif
		return 0;
	}
#else
		return 0;
#endif

	/* don't care for the reason here */
	drbd_err(peer_device, "submit failed, triggering re-connect\n");
	drbd_al_complete_io(device, &peer_req->i);

disconnect_during_al_begin_io:
	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	list_del_init(&peer_req->recv_order);
	drbd_remove_peer_req_interval(device, peer_req);
	spin_unlock_irq(&device->resource->req_lock);

out_interrupted:
	drbd_may_finish_epoch(connection, peer_req->epoch, EV_PUT + EV_CLEANUP);
	put_ldev(device);
	drbd_free_peer_req(peer_req);
	return err;
}

/*
* To be called when __drbd_submit_peer_request() fails from submitter
* workqueue context.  Mimic what happens in the receive_Data() error path,
* when the submit happens directly in the receiver context.
*/
void drbd_cleanup_after_failed_submit_peer_request(struct drbd_peer_request *peer_req)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;

	if (drbd_ratelimit())
		drbd_err(peer_device, "submit failed, triggering re-connect\n");

	drbd_al_complete_io(device, &peer_req->i);

	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	list_del_init(&peer_req->recv_order);
	drbd_remove_peer_req_interval(device, peer_req);
	spin_unlock_irq(&device->resource->req_lock);

	drbd_may_finish_epoch(connection, peer_req->epoch, EV_PUT + EV_CLEANUP);
	put_ldev(device);
	drbd_free_peer_req(peer_req);
	change_cstate_ex(connection, C_PROTOCOL_ERROR, CS_HARD);
}

/* We may throttle resync, if the lower device seems to be busy,
 * and current sync rate is above c_min_rate.
 *
 * To decide whether or not the lower device is busy, we use a scheme similar
 * to MD RAID is_mddev_idle(): if the partition stats reveal "significant"
 * (more than 64 sectors) of activity we cannot account for with our own resync
 * activity, it obviously is "busy".
 *
 * The current sync rate used here uses only the most recent two step marks,
 * to have a short time average so we can react faster.
 */
bool drbd_rs_should_slow_down(struct drbd_peer_device *peer_device, sector_t sector,
			      bool throttle_if_app_is_waiting)
{
	bool throttle = drbd_rs_c_min_rate_throttle(peer_device);

	if (!throttle || throttle_if_app_is_waiting)
		return throttle;

	return !drbd_sector_has_priority(peer_device, sector);
}

bool drbd_rs_c_min_rate_throttle(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	unsigned long db, dt, dbdt;
	unsigned int c_min_rate;
#ifdef _WIN32
	int curr_events = 0;
#else
	int curr_events;
#endif

	rcu_read_lock();
	c_min_rate = rcu_dereference(peer_device->conf)->c_min_rate;
	rcu_read_unlock();

	/* feature disabled? */
	if (c_min_rate == 0)
		return false;

#ifdef _WIN32
	curr_events = drbd_backing_bdev_events(device)
		- atomic_read(&device->rs_sect_ev);
#else
	curr_events = drbd_backing_bdev_events(device->ldev->backing_bdev->bd_contains->bd_disk)
		    - atomic_read(&device->rs_sect_ev);
#endif

	if (atomic_read(&device->ap_actlog_cnt) || curr_events - peer_device->rs_last_events > 64) {
		ULONG_PTR rs_left;
		int i;

		peer_device->rs_last_events = curr_events;

		/* sync speed average over the last 2*DRBD_SYNC_MARK_STEP,
		 * approx. */
		i = (peer_device->rs_last_mark + DRBD_SYNC_MARKS-1) % DRBD_SYNC_MARKS;

		if (peer_device->repl_state[NOW] == L_VERIFY_S || peer_device->repl_state[NOW] == L_VERIFY_T)
			rs_left = peer_device->ov_left;
		else
			rs_left = drbd_bm_total_weight(peer_device) - peer_device->rs_failed;

		dt = ((long)jiffies - (long)peer_device->rs_mark_time[i]) / HZ;
		if (!dt)
			dt++;

		BUG_ON_UINT32_OVER(peer_device->rs_mark_left[i] - rs_left);

		db = (unsigned long)(peer_device->rs_mark_left[i] - rs_left);
		dbdt = Bit2KB(db/dt);

		if (dbdt > c_min_rate) {
			return true;
		}
	}
	return false;
}

static int receive_DataRequest(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	sector_t sector;
	sector_t capacity;
	struct drbd_peer_request *peer_req;
	struct digest_info *di = NULL;
	int size, verb;
#ifdef _WIN32
	unsigned int fault_type = 0;
#else
	unsigned int fault_type;
#endif
	struct p_block_req *p =	pi->data;
	enum drbd_disk_state min_d_state;
	int err;
	uint64_t block_id;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;
	capacity = drbd_get_capacity(device->this_bdev);

	sector = be64_to_cpu(p->sector);
	size   = be32_to_cpu(p->blksize);

	if (size <= 0 || !IS_ALIGNED(size, 512) || size > DRBD_MAX_BIO_SIZE) {
		drbd_err(device, "%s:%d: sector: %llus, size: %d\n", __FILE__, __LINE__,
				(unsigned long long)sector, size);
		return -EINVAL;
	}
	if (sector + (size>>9) > capacity) {
		drbd_err(device, "%s:%d: sector: %llus, size: %d\n", __FILE__, __LINE__,
				(unsigned long long)sector, size);
		return -EINVAL;
	}
#ifdef _WIN32
    WDRBD_TRACE_RS("cmd(%s) sector(0x%llx), size(%d)\n", drbd_packet_name(pi->cmd), sector, size);
#endif
	min_d_state = pi->cmd == P_DATA_REQUEST ? D_UP_TO_DATE : D_OUTDATED;
	if (!get_ldev_if_state(device, min_d_state)) {
		verb = 1;
		switch (pi->cmd) {
		case P_DATA_REQUEST:
			drbd_send_ack_rp(peer_device, P_NEG_DREPLY, p);
			break;
		case P_RS_THIN_REQ:
		case P_RS_DATA_REQUEST:
		case P_CSUM_RS_REQUEST:
		case P_OV_REQUEST:
			drbd_send_ack_rp(peer_device, P_NEG_RS_DREPLY , p);
			break;
		case P_OV_REPLY:
			verb = 0;
			dec_rs_pending(peer_device);
			drbd_send_ack_ex(peer_device, P_OV_RESULT, sector, size, ID_IN_SYNC);
			break;
		default:
			BUG();
		}
		if (verb && drbd_ratelimit())
			drbd_err(device, "Can not satisfy peer's read request, "
			    "no local data.\n");

		/* drain possibly payload */
		return ignore_remaining_packet(connection, pi->size);
	}

	peer_req = drbd_alloc_peer_req(peer_device, GFP_TRY);
	err = -ENOMEM;
	if (!peer_req)
		goto fail;
	if (size) {
		drbd_alloc_page_chain(&peer_device->connection->transport,
			&peer_req->page_chain, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
		if (!peer_req->page_chain.head)
			goto fail2;
#ifdef _WIN32
		peer_req->peer_req_databuf = peer_req->page_chain.head;
#endif
	}
#ifdef _WIN32
	else {
		peer_req->peer_req_databuf = NULL; 
	}
#endif
	peer_req->i.size = size;
	peer_req->i.sector = sector;
	peer_req->block_id = p->block_id;
	// DW-1961 Save timestamp for IO latency measuremen
	if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY)
		peer_req->created_ts = timestamp();
	/* no longer valid, about to call drbd_recv again for the digest... */
	p = pi->data = NULL;

	switch (pi->cmd) {
	case P_DATA_REQUEST:
		peer_req->w.cb = w_e_end_data_req;
		fault_type = DRBD_FAULT_DT_RD;
		/* application IO, don't drbd_rs_begin_io */
		peer_req->flags |= EE_APPLICATION;
		goto submit;

	case P_RS_THIN_REQ:
		/* If at some point in the future we have a smart way to
		   find out if this data block is completely deallocated,
		   then we would do something smarter here than reading
		   the block... */
		peer_req->flags |= EE_RS_THIN_REQ;
	case P_RS_DATA_REQUEST:
		//DW-1857 If P_RS_DATA_REQUEST is received, send P_RS_CANCEL unless L_SYNC_SOURCE.
		if (peer_device->repl_state[NOW] != L_SYNC_SOURCE) {
			err = drbd_send_ack(peer_device, P_RS_CANCEL, peer_req);
			/* If err is set, we will drop the connection... */
			goto fail3;
		}
		peer_req->w.cb = w_e_end_rsdata_req;
		fault_type = DRBD_FAULT_RS_RD;
		break;

	case P_OV_REPLY:
	case P_CSUM_RS_REQUEST:
		block_id = peer_req->block_id;
		fault_type = DRBD_FAULT_RS_RD;
#ifdef _WIN32
        di = kmalloc(sizeof(*di) + pi->size, GFP_NOIO, '42DW');
#else
		di = kmalloc(sizeof(*di) + pi->size, GFP_NOIO);
#endif
		err = -ENOMEM;
		if (!di)
			goto fail2;

		di->digest_size = pi->size;
		di->digest = (((char *)di)+sizeof(struct digest_info));

		peer_req->digest = di;
		peer_req->flags |= EE_HAS_DIGEST;

		err = drbd_recv_into(connection, di->digest, pi->size); 
		if (err)
			goto fail2;

		// DW-1942 Check for io failure on the SyncTarget.
		if (block_id == ID_CSUM_SYNC_IO_ERROR) {
			drbd_rs_failed_io(peer_device, peer_req->i.sector, peer_req->i.size);
			goto fail2;
		}

		if (pi->cmd == P_CSUM_RS_REQUEST) {
			D_ASSERT(device, connection->agreed_pro_version >= 89);
			peer_req->w.cb = w_e_end_csum_rs_req;
			/* remember to report stats in drbd_resync_finished */
			peer_device->use_csums = true;
		} else if (pi->cmd == P_OV_REPLY) {
			/* track progress, we may need to throttle */
			atomic_add(size >> 9, &peer_device->rs_sect_in);
			peer_req->w.cb = w_e_end_ov_reply;
			dec_rs_pending(peer_device);
			/* drbd_rs_begin_io done when we sent this request,
			 * but accounting still needs to be done. */
			goto submit_for_resync;
		}
		break;

	case P_OV_REQUEST:
		if (peer_device->ov_start_sector == ~(sector_t)0 &&
		    connection->agreed_pro_version >= 90) {
#ifdef _WIN32
			ULONG_PTR now = jiffies;
#else
			unsigned long now = jiffies;
#endif
			int i;
			peer_device->ov_start_sector = sector;
			peer_device->ov_position = sector;
			peer_device->ov_left = (ULONG_PTR)(drbd_bm_bits(device) - BM_SECT_TO_BIT(sector));
			peer_device->rs_total = peer_device->ov_left;
			for (i = 0; i < DRBD_SYNC_MARKS; i++) {
				peer_device->rs_mark_left[i] = peer_device->ov_left;
				peer_device->rs_mark_time[i] = now;
			}
			drbd_info(device, "Online Verify start sector: %llu\n",
					(unsigned long long)sector);
		}
		peer_req->w.cb = w_e_end_ov_req;
		fault_type = DRBD_FAULT_RS_RD;
		break;

	default:
		BUG();
	}

	/* Throttle, drbd_rs_begin_io and submit should become asynchronous
	 * wrt the receiver, but it is not as straightforward as it may seem.
	 * Various places in the resync start and stop logic assume resync
	 * requests are processed in order, requeuing this on the worker thread
	 * introduces a bunch of new code for synchronization between threads.
	 *
	 * Unlimited throttling before drbd_rs_begin_io may stall the resync
	 * "forever", throttling after drbd_rs_begin_io will lock that extent
	 * for application writes for the same time.  For now, just throttle
	 * here, where the rest of the code expects the receiver to sleep for
	 * a while, anyways.
	 */

	/* Throttle before drbd_rs_begin_io, as that locks out application IO;
	 * this defers syncer requests for some time, before letting at least
	 * on request through.  The resync controller on the receiving side
	 * will adapt to the incoming rate accordingly.
	 *
	 * We cannot throttle here if remote is Primary/SyncTarget:
	 * we would also throttle its application reads.
	 * In that case, throttling is done on the SyncTarget only.
	 */

	/* Even though this may be a resync request, we do add to "read_ee";
	 * "sync_ee" is only used for resync WRITEs.
	 * Add to list early, so debugfs can find this request
	 * even if we have to sleep below. */
	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&peer_req->w.list, &connection->read_ee);
	spin_unlock_irq(&device->resource->req_lock);

#if 0 //DW-1599 : Not use. Secondary node fails SendAsync() 
	update_receiver_timing_details(connection, drbd_rs_should_slow_down);
	if (connection->peer_role[NOW] != R_PRIMARY &&
	    drbd_rs_should_slow_down(peer_device, sector, false))
		schedule_timeout_uninterruptible(HZ/10);
#endif

	if (connection->agreed_pro_version >= 110) {
		/* In DRBD9 we may not sleep here in order to avoid deadlocks.
		   Instruct the SyncSource to retry */
#ifdef _WIN32 // MODIFIED_BY_MANTECH DW-953: replace drbd_try_rs_begin_io with drbd_rs_begin_io like version 8.4.x for only L_VERIFY_T
		if (peer_device->repl_state[NOW] == L_VERIFY_T)
		{
			if (drbd_rs_begin_io(peer_device, sector)) 
			{
				err = -EIO;
				goto fail3;
			}
		}
		else
		{
			err = drbd_try_rs_begin_io(peer_device, sector, false);
			if (err) {
				err = drbd_send_ack(peer_device, P_RS_CANCEL, peer_req);
				/* If err is set, we will drop the connection... */
				goto fail3;
			}
		}
#else
		err = drbd_try_rs_begin_io(peer_device, sector, false);
		if (err) {
			err = drbd_send_ack(peer_device, P_RS_CANCEL, peer_req);
			/* If err is set, we will drop the connection... */
			goto fail3;
		}
#endif
	} else {
		update_receiver_timing_details(connection, drbd_rs_begin_io);
		if (drbd_rs_begin_io(peer_device, sector)) {
			err = -EIO;
			goto fail3;
		}
	}

submit_for_resync:
	atomic_add(size >> 9, &device->rs_sect_ev);

submit:
	update_receiver_timing_details(connection, drbd_submit_peer_request);
	inc_unacked(peer_device);
	if (drbd_submit_peer_request(device, peer_req, REQ_OP_READ, 0,
		fault_type) == 0)
		return 0;

	/* don't care for the reason here */
	drbd_err(device, "submit failed, triggering re-connect\n");
	err = -EIO;

fail3:
	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	spin_unlock_irq(&device->resource->req_lock);
	/* no drbd_rs_complete_io(), we are dropping the connection anyways */
fail2:
	drbd_free_peer_req(peer_req);
fail:
	put_ldev(device);
	return err;
}

/**
 * drbd_asb_recover_0p  -  Recover after split-brain with no remaining primaries
 */
static int drbd_asb_recover_0p(struct drbd_peer_device *peer_device) __must_hold(local)
{
	const int node_id = peer_device->device->resource->res_opts.node_id;
	int self, peer, rv = -100;
	u64 ch_peer;
	ULONG_PTR ch_self;
	enum drbd_after_sb_p after_sb_0p;

	self = drbd_bitmap_uuid(peer_device) & UUID_PRIMARY;
	peer = peer_device->bitmap_uuids[node_id] & UUID_PRIMARY;

	ch_peer = peer_device->dirty_bits;
	ch_self = peer_device->comm_bm_set;

	rcu_read_lock();
	after_sb_0p = rcu_dereference(peer_device->connection->transport.net_conf)->after_sb_0p;
	rcu_read_unlock();
	switch (after_sb_0p) {
	case ASB_CONSENSUS:
	case ASB_DISCARD_SECONDARY:
	case ASB_CALL_HELPER:
	case ASB_VIOLENTLY:
		drbd_err(peer_device, "Configuration error.\n");
		break;
	case ASB_DISCONNECT:
		break;
	case ASB_DISCARD_YOUNGER_PRI:
		if (self == 0 && peer == 1) {
			rv = -2;
			break;
		}
		if (self == 1 && peer == 0) {
			rv =  2;
			break;
		}
		/* Else fall through to one of the other strategies... */
	case ASB_DISCARD_OLDER_PRI:
		if (self == 0 && peer == 1) {
			rv = 2;
			break;
		}
		if (self == 1 && peer == 0) {
			rv = -2;
			break;
		}
		/* Else fall through to one of the other strategies... */
		drbd_warn(peer_device, "Discard younger/older primary did not find a decision\n"
			  "Using discard-least-changes instead\n");
	case ASB_DISCARD_ZERO_CHG:
		if (ch_peer == 0 && ch_self == 0) {
			rv = test_bit(RESOLVE_CONFLICTS, &peer_device->connection->transport.flags)
				? -2 : 2;
			break;
		} else {
			if (ch_peer == 0) { rv =  2; break; }
			if (ch_self == 0) { rv = -2; break; }
		}
		if (after_sb_0p == ASB_DISCARD_ZERO_CHG)
			break;
	case ASB_DISCARD_LEAST_CHG:
		if	(ch_self < ch_peer)
			rv = -2;
		else if (ch_self > ch_peer)
			rv =  2;
		else /* ( ch_self == ch_peer ) */
		     /* Well, then use something else. */
			rv = test_bit(RESOLVE_CONFLICTS, &peer_device->connection->transport.flags)
				? -2 : 2;
		break;
	case ASB_DISCARD_LOCAL:
		rv = -2;
		break;
	case ASB_DISCARD_REMOTE:
		rv =  2;
	}

	return rv;
}

/**
 * drbd_asb_recover_1p  -  Recover after split-brain with one remaining primary
 */
static int drbd_asb_recover_1p(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_resource *resource = device->resource;
	int hg, rv = -100;
	enum drbd_after_sb_p after_sb_1p;

	rcu_read_lock();
	after_sb_1p = rcu_dereference(connection->transport.net_conf)->after_sb_1p;
	rcu_read_unlock();
	switch (after_sb_1p) {
	case ASB_DISCARD_YOUNGER_PRI:
	case ASB_DISCARD_OLDER_PRI:
	case ASB_DISCARD_LEAST_CHG:
	case ASB_DISCARD_LOCAL:
	case ASB_DISCARD_REMOTE:
	case ASB_DISCARD_ZERO_CHG:
		drbd_err(device, "Configuration error.\n");
		break;
	case ASB_DISCONNECT:
		break;
	case ASB_CONSENSUS:
		hg = drbd_asb_recover_0p(peer_device);
		if (hg == -2 && resource->role[NOW] == R_SECONDARY)
			rv = hg;
		if (hg ==  2 && resource->role[NOW] == R_PRIMARY)
			rv = hg;
		break;
	case ASB_VIOLENTLY:
		rv = drbd_asb_recover_0p(peer_device);
		break;
	case ASB_DISCARD_SECONDARY:
		return resource->role[NOW] == R_PRIMARY ? 2 : -2;
	case ASB_CALL_HELPER:
		hg = drbd_asb_recover_0p(peer_device);
		if (hg == -2 && resource->role[NOW] == R_PRIMARY) {
			enum drbd_state_rv rv2;

			 /* drbd_change_state() does not sleep while in SS_IN_TRANSIENT_STATE,
			  * we might be here in L_OFF which is transient.
			  * we do not need to wait for the after state change work either. */
			rv2 = change_role(resource, R_SECONDARY, CS_VERBOSE, false, NULL);
			if (rv2 != SS_SUCCESS) {
				drbd_khelper(device, connection, "pri-lost-after-sb");
			} else {
				drbd_warn(device, "Successfully gave up primary role.\n");
				rv = hg;
			}
		} else
			rv = hg;
	}

	return rv;
}

/**
 * drbd_asb_recover_2p  -  Recover after split-brain with two remaining primaries
 */
static int drbd_asb_recover_2p(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	int hg, rv = -100;
	enum drbd_after_sb_p after_sb_2p;

	rcu_read_lock();
	after_sb_2p = rcu_dereference(connection->transport.net_conf)->after_sb_2p;
	rcu_read_unlock();
	switch (after_sb_2p) {
	case ASB_DISCARD_YOUNGER_PRI:
	case ASB_DISCARD_OLDER_PRI:
	case ASB_DISCARD_LEAST_CHG:
	case ASB_DISCARD_LOCAL:
	case ASB_DISCARD_REMOTE:
	case ASB_CONSENSUS:
	case ASB_DISCARD_SECONDARY:
	case ASB_DISCARD_ZERO_CHG:
		drbd_err(device, "Configuration error.\n");
		break;
	case ASB_VIOLENTLY:
		rv = drbd_asb_recover_0p(peer_device);
		break;
	case ASB_DISCONNECT:
		break;
	case ASB_CALL_HELPER:
		hg = drbd_asb_recover_0p(peer_device);
		if (hg == -2) {
			enum drbd_state_rv rv2;

			 /* drbd_change_state() does not sleep while in SS_IN_TRANSIENT_STATE,
			  * we might be here in L_OFF which is transient.
			  * we do not need to wait for the after state change work either. */
			rv2 = change_role(device->resource, R_SECONDARY, CS_VERBOSE, false, NULL);
			if (rv2 != SS_SUCCESS) {
				drbd_khelper(device, connection, "pri-lost-after-sb");
			} else {
				drbd_warn(device, "Successfully gave up primary role.\n");
				rv = hg;
			}
		} else
			rv = hg;
	}

	return rv;
}

static void drbd_uuid_dump_self(struct drbd_peer_device *peer_device, u64 bits, u64 flags)
{
	struct drbd_device *device = peer_device->device;

	drbd_info(peer_device, "self %016llX:%016llX:%016llX:%016llX bits:%llu flags:%llX\n",
		  (unsigned long long)drbd_current_uuid(peer_device->device),
		  (unsigned long long)drbd_bitmap_uuid(peer_device),
		  (unsigned long long)drbd_history_uuid(device, 0),
		  (unsigned long long)drbd_history_uuid(device, 1),
		  (unsigned long long)bits,
		  (unsigned long long)flags);
}


static void drbd_uuid_dump_peer(struct drbd_peer_device *peer_device, u64 bits, u64 flags)
{
	const int node_id = peer_device->device->resource->res_opts.node_id;

	drbd_info(peer_device, "peer %016llX:%016llX:%016llX:%016llX bits:%llu flags:%llX\n",
	     (unsigned long long)peer_device->current_uuid,
	     (unsigned long long)peer_device->bitmap_uuids[node_id],
	     (unsigned long long)peer_device->history_uuids[0],
	     (unsigned long long)peer_device->history_uuids[1],
	     (unsigned long long)bits,
	     (unsigned long long)flags);
}

static int uuid_fixup_resync_end(struct drbd_peer_device *peer_device, int *rule_nr) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	const int node_id = device->resource->res_opts.node_id;

	if (peer_device->bitmap_uuids[node_id] == (u64)0 && drbd_bitmap_uuid(peer_device) != (u64)0) {

		if (peer_device->connection->agreed_pro_version < 91)
			return -1091;

		if ((drbd_bitmap_uuid(peer_device) & ~UUID_PRIMARY) ==
		    (peer_device->history_uuids[0] & ~UUID_PRIMARY) &&
		    (drbd_history_uuid(device, 0) & ~UUID_PRIMARY) ==
		    (peer_device->history_uuids[0] & ~UUID_PRIMARY)) {
			struct drbd_peer_md *peer_md = &device->ldev->md.peers[peer_device->node_id];

			drbd_info(device, "was SyncSource, missed the resync finished event, corrected myself:\n");
			_drbd_uuid_push_history(device, peer_md->bitmap_uuid);
			peer_md->bitmap_uuid = 0;

			drbd_uuid_dump_self(peer_device,
					    device->disk_state[NOW] >= D_NEGOTIATING ? drbd_bm_total_weight(peer_device) : 0, 0);
			*rule_nr = 34;
		} else {
			drbd_info(device, "was SyncSource (peer failed to write sync_uuid)\n");
			*rule_nr = 36;
		}

		return 2;
	}

	if (drbd_bitmap_uuid(peer_device) == (u64)0 && peer_device->bitmap_uuids[node_id] != (u64)0) {

		if (peer_device->connection->agreed_pro_version < 91)
			return -1091;

		if ((drbd_history_uuid(device, 0) & ~UUID_PRIMARY) ==
		    (peer_device->bitmap_uuids[node_id] & ~UUID_PRIMARY) &&
		    (drbd_history_uuid(device, 1) & ~UUID_PRIMARY) ==
		    (peer_device->history_uuids[0] & ~UUID_PRIMARY)) {
			int i;

			drbd_info(device, "was SyncTarget, peer missed the resync finished event, corrected peer:\n");

			for (i = ARRAY_SIZE(peer_device->history_uuids) - 1; i > 0; i--)
				peer_device->history_uuids[i] = peer_device->history_uuids[i - 1];
			peer_device->history_uuids[i] = peer_device->bitmap_uuids[node_id];
			peer_device->bitmap_uuids[node_id] = 0;

			drbd_uuid_dump_peer(peer_device, peer_device->dirty_bits, peer_device->uuid_flags);
			*rule_nr = 35;
		} else {
			drbd_info(device, "was SyncTarget (failed to write sync_uuid)\n");
			*rule_nr = 37;
		}

		return -2;
	}

	return -2000;
}

static int uuid_fixup_resync_start1(struct drbd_peer_device *peer_device, int *rule_nr) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	const int node_id = peer_device->device->resource->res_opts.node_id;
	u64 self, peer;

	self = drbd_current_uuid(device) & ~UUID_PRIMARY;
	peer = peer_device->history_uuids[0] & ~UUID_PRIMARY;

	if (self == peer) {
		if (peer_device->connection->agreed_pro_version < 96 ?
		    (drbd_history_uuid(device, 0) & ~UUID_PRIMARY) ==
		    (peer_device->history_uuids[1] & ~UUID_PRIMARY) :
		    peer + UUID_NEW_BM_OFFSET == (peer_device->bitmap_uuids[node_id] & ~UUID_PRIMARY)) {
			int i;

			/* The last P_SYNC_UUID did not get though. Undo the last start of
			   resync as sync source modifications of the peer's UUIDs. */
			*rule_nr = 51;

			if (peer_device->connection->agreed_pro_version < 91)
				return -1091;

			peer_device->bitmap_uuids[node_id] = peer_device->history_uuids[0];
			for (i = 0; i < ARRAY_SIZE(peer_device->history_uuids) - 1; i++)
				peer_device->history_uuids[i] = peer_device->history_uuids[i + 1];
			peer_device->history_uuids[i] = 0;

			drbd_info(device, "Lost last syncUUID packet, corrected:\n");
			drbd_uuid_dump_peer(peer_device, peer_device->dirty_bits, peer_device->uuid_flags);

			return -2;
		}
	}

	return -2000;
}

static int uuid_fixup_resync_start2(struct drbd_peer_device *peer_device, int *rule_nr) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	u64 self, peer;

	self = drbd_history_uuid(device, 0) & ~UUID_PRIMARY;
	peer = peer_device->current_uuid & ~UUID_PRIMARY;

	if (self == peer) {
		if (peer_device->connection->agreed_pro_version < 96 ?
		    (drbd_history_uuid(device, 1) & ~UUID_PRIMARY) ==
		    (peer_device->history_uuids[0] & ~UUID_PRIMARY) :
		    self + UUID_NEW_BM_OFFSET == (drbd_bitmap_uuid(peer_device) & ~UUID_PRIMARY)) {
			u64 bitmap_uuid;

			/* The last P_SYNC_UUID did not get though. Undo the last start of
			   resync as sync source modifications of our UUIDs. */
			*rule_nr = 71;

			if (peer_device->connection->agreed_pro_version < 91)
				return -1091;

			bitmap_uuid = _drbd_uuid_pull_history(peer_device);
			__drbd_uuid_set_bitmap(peer_device, bitmap_uuid);

			drbd_info(device, "Last syncUUID did not get through, corrected:\n");
			drbd_uuid_dump_self(peer_device,
					    device->disk_state[NOW] >= D_NEGOTIATING ? drbd_bm_total_weight(peer_device) : 0, 0);

			return 2;
		}
	}

	return -2000;
}

/*
  100	after split brain try auto recover
    4   L_SYNC_SOURCE copy BitMap from
    3	L_SYNC_SOURCE set BitMap
    2	L_SYNC_SOURCE use BitMap
    1   L_SYNC_SOURCE use BitMap, if it was a common power failure
    0	no Sync
   -1   L_SYNC_TARGET use BitMap, it if was a common power failure
   -2	L_SYNC_TARGET use BitMap
   -3	L_SYNC_TARGET set BitMap
   -4   L_SYNC_TARGET clear BitMap
 -100	after split brain, disconnect
-1000	unrelated data
-1091   requires proto 91
-1096   requires proto 96
 */
static int drbd_uuid_compare(struct drbd_peer_device *peer_device,
			     int *rule_nr, int *peer_node_id) __must_hold(local)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;
	const int node_id = device->resource->res_opts.node_id;
	u64 self, peer;
	int i, j;

	self = drbd_current_uuid(device) & ~UUID_PRIMARY;
	peer = peer_device->current_uuid & ~UUID_PRIMARY;

	/* Before DRBD 8.0.2 (from 2007), the uuid on sync targets was set to
	 * zero during resyncs for no good reason. */
	if (self == 0)
		self = UUID_JUST_CREATED;
	if (peer == 0)
		peer = UUID_JUST_CREATED;

	*rule_nr = 10;
	if (self == UUID_JUST_CREATED && peer == UUID_JUST_CREATED)
		return 0;

	*rule_nr = 20;
	if (self == UUID_JUST_CREATED)
		return -3;

	*rule_nr = 30;
	if (peer == UUID_JUST_CREATED)
		return 3;

	if (self == peer) {
		if (connection->agreed_pro_version < 110) {
			int rv = uuid_fixup_resync_end(peer_device, rule_nr);
			if (rv > -2000)
				return rv;
		}

		*rule_nr = 38;
		/* This is a safety net for the following two clauses */
		if (peer_device->uuid_flags & UUID_FLAG_RECONNECT &&
			test_bit(RECONNECT, &peer_device->connection->flags))
			return 0;

#ifndef _WIN32_CRASHED_PRIMARY_SYNCSOURCE
		/* Peer crashed as primary, I survived, resync from me */
		if (peer_device->uuid_flags & UUID_FLAG_CRASHED_PRIMARY &&
		    test_bit(RECONNECT, &peer_device->connection->flags))
			return 1;

		/* I am a crashed primary, peer survived, resync to me */
		if (test_bit(CRASHED_PRIMARY, &device->flags) &&
		    peer_device->uuid_flags & UUID_FLAG_RECONNECT)
			return -1;

		/* One of us had a connection to the other node before.
		   i.e. this is not a common power failure. */
		if (peer_device->uuid_flags & UUID_FLAG_RECONNECT ||
		    test_bit(RECONNECT, &peer_device->connection->flags))
			return 0;
#endif

		/* Common power [off|failure]? */
		*rule_nr = 40;
		if (test_bit(CRASHED_PRIMARY, &device->flags)) {
			if ((peer_device->uuid_flags & UUID_FLAG_CRASHED_PRIMARY) &&
			    test_bit(RESOLVE_CONFLICTS, &connection->transport.flags))
				return -1;
			return 1;
		} else if (peer_device->uuid_flags & UUID_FLAG_CRASHED_PRIMARY)
				return -1;
		else
			return 0;
	}

	*rule_nr = 50;
	peer = peer_device->bitmap_uuids[node_id] & ~UUID_PRIMARY;
	if (self == peer)
		return -2;

	*rule_nr = 52;
	for (i = 0; i < DRBD_PEERS_MAX; i++) {
		peer = peer_device->bitmap_uuids[i] & ~UUID_PRIMARY;
		if (self == peer) {
			*peer_node_id = i;
			return -4;
		}
	}

	if (connection->agreed_pro_version < 110) {
		int rv = uuid_fixup_resync_start1(peer_device, rule_nr);
		if (rv > -2000)
			return rv;
	}

	*rule_nr = 60;
	self = drbd_current_uuid(device) & ~UUID_PRIMARY;
	for (i = 0; i < ARRAY_SIZE(peer_device->history_uuids); i++) {
		peer = peer_device->history_uuids[i] & ~UUID_PRIMARY;
		if (self == peer)
			return -3;
	}

	*rule_nr = 70;
	self = drbd_bitmap_uuid(peer_device) & ~UUID_PRIMARY;
	peer = peer_device->current_uuid & ~UUID_PRIMARY;
	if (self == peer)
		return 2;

	*rule_nr = 72;
	for (i = 0; i < DRBD_NODE_ID_MAX; i++) {
		if (i == peer_device->node_id)
			continue;
		if (i == device->ldev->md.node_id)
			continue;
#ifndef _WIN32
		// MODIFIED_BY_MANTECH DW-1360: need to see bitmap uuid of node which are not assigned to a peer, some of those peers drive me to create new uuid while rotating uuid into their bitmap uuid.
		/* Skip bitmap indexes which are not assigned to a peer. */
		if (device->ldev->md.peers[i].bitmap_index == -1)
			continue;
#endif
		self = device->ldev->md.peers[i].bitmap_uuid & ~UUID_PRIMARY;
		if (self == peer) {
			*peer_node_id = i;
			return 4;
		}
	}

	if (connection->agreed_pro_version < 110) {
		int rv = uuid_fixup_resync_start2(peer_device, rule_nr);
		if (rv > -2000)
			return rv;
	}

	*rule_nr = 80;
	peer = peer_device->current_uuid & ~UUID_PRIMARY;
	for (i = 0; i < HISTORY_UUIDS; i++) {
		self = drbd_history_uuid(device, i) & ~UUID_PRIMARY;
		if (self == peer)
			return 3;
	}

	*rule_nr = 90;
	self = drbd_bitmap_uuid(peer_device) & ~UUID_PRIMARY;
	peer = peer_device->bitmap_uuids[node_id] & ~UUID_PRIMARY;
	if (self == peer && self != ((u64)0))
		return 100;

	*rule_nr = 100;
	for (i = 0; i < HISTORY_UUIDS; i++) {
		self = drbd_history_uuid(device, i) & ~UUID_PRIMARY;
		for (j = 0; j < ARRAY_SIZE(peer_device->history_uuids); j++) {
			peer = peer_device->history_uuids[j] & ~UUID_PRIMARY;
			if (self == peer)
				return -100;
		}
	}

	return -1000;
}

static void log_handshake(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	u64 uuid_flags = 0;

	if (test_bit(DISCARD_MY_DATA, &peer_device->flags))
       uuid_flags |= UUID_FLAG_DISCARD_MY_DATA;
	if (test_bit(CRASHED_PRIMARY, &device->flags))
       uuid_flags |= UUID_FLAG_CRASHED_PRIMARY;
	if (!drbd_md_test_flag(device, MDF_CONSISTENT))
       uuid_flags |= UUID_FLAG_INCONSISTENT;
	if (test_bit(RECONNECT, &peer_device->connection->flags))
       uuid_flags |= UUID_FLAG_RECONNECT;
	if (drbd_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR))
		uuid_flags |= UUID_FLAG_PRIMARY_IO_ERROR;
	if (drbd_device_stable(device, NULL))
       uuid_flags |= UUID_FLAG_STABLE;
	//DW-1874
	if (drbd_md_test_peer_flag(peer_device, MDF_PEER_IN_PROGRESS_SYNC))
		uuid_flags |= UUID_FLAG_IN_PROGRESS_SYNC;

	drbd_info(peer_device, "drbd_sync_handshake:\n");
	drbd_uuid_dump_self(peer_device, peer_device->comm_bm_set, uuid_flags);
	drbd_uuid_dump_peer(peer_device, peer_device->dirty_bits, peer_device->uuid_flags);
}

static int drbd_handshake(struct drbd_peer_device *peer_device,
			  int *rule_nr,
			  int *peer_node_id,
			  bool always_verbose) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	int hg;

	spin_lock_irq(&device->ldev->md.uuid_lock);
	if (always_verbose)
		log_handshake(peer_device);

	hg = drbd_uuid_compare(peer_device, rule_nr, peer_node_id);
	if (hg && !always_verbose)
		log_handshake(peer_device);
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	if (hg || always_verbose)
		drbd_info(peer_device, "uuid_compare()=%d by rule %d\n", hg, *rule_nr);

	return hg;
}

static bool is_resync_running(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	bool rv = false;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum drbd_repl_state repl_state = peer_device->repl_state[NOW];
		if (repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static int bitmap_mod_after_handshake(struct drbd_peer_device *peer_device, int hg, int peer_node_id)
{
	UNREFERENCED_PARAMETER(peer_node_id);

	struct drbd_device *device = peer_device->device;

	if (hg == 4) {
#ifndef _WIN32
		// MODIFIED_BY_MANTECH DW-1099: copying bitmap has a defect, do sync whole out-of-sync until fixed.
		int from = device->ldev->md.peers[peer_node_id].bitmap_index;

		if (from == -1 || peer_device->bitmap_index == -1)
			return 0;

		drbd_info(peer_device, "Peer synced up with node %d, copying bitmap\n", peer_node_id);
		drbd_suspend_io(device, WRITE_ONLY);
		drbd_bm_slot_lock(peer_device, "bm_copy_slot from sync_handshake", BM_LOCK_BULK);
		drbd_bm_copy_slot(device, from, peer_device->bitmap_index);
		drbd_bm_write(device, NULL);
		drbd_bm_slot_unlock(peer_device);
		drbd_resume_io(device);
#endif
	} else if (hg == -4) {
#ifndef _WIN32
		// MODIFIED_BY_MANTECH DW-1099: copying bitmap has a defect, do sync whole out-of-sync until fixed.
		drbd_info(peer_device, "synced up with node %d in the mean time\n", peer_node_id);
		drbd_suspend_io(device, WRITE_ONLY);
		drbd_bm_slot_lock(peer_device, "bm_clear_many_bits from sync_handshake", BM_LOCK_BULK);
		drbd_bm_clear_many_bits(peer_device, 0, -1UL);
		drbd_bm_write(device, NULL);
		drbd_bm_slot_unlock(peer_device);
		drbd_resume_io(device);
#endif
	} else if (abs(hg) >= 3) {
		if (hg == -3 &&
		    drbd_current_uuid(device) == UUID_JUST_CREATED &&
#ifdef _WIN32_STABLE_SYNCSOURCE
			// DW-1449 check stable sync source policy first, returning here is supposed to mean other resync is going to be started. (or violates stable sync source policy)
			(is_resync_running(device) || 
#ifdef _WIN32_RCU_LOCKED
			!drbd_inspect_resync_side(peer_device, L_SYNC_TARGET, NOW, false)))
#else
			!drbd_inspect_resync_side(peer_device, L_SYNC_TARGET, NOW)))
#endif
#else
			is_resync_running(device)
#endif
			return 0;

#ifdef _WIN32
		// DW-844: check if fast sync is enalbed every time we do initial sync.
		// set out-of-sync for allocated clusters.
		// DW-1285 If MDF_PEER_INIT_SYNCT_BEGIN is off, It must be first time inital sync case, and then set entire oos for fullsync or full used oos for fastsync.
		if( !(peer_device->uuid_flags & UUID_FLAG_INIT_SYNCT_BEGIN)) {
			if (!isFastInitialSync() ||
				!SetOOSAllocatedCluster(device, peer_device, hg>0?L_SYNC_SOURCE:L_SYNC_TARGET, true)) {			
				drbd_info(peer_device, "Writing the whole bitmap, full sync required after drbd_sync_handshake.\n");			
				if (drbd_bitmap_io(device, &drbd_bmio_set_n_write, "set_n_write from sync_handshake",
					BM_LOCK_CLEAR | BM_LOCK_BULK, peer_device))
					return -1;			
			}
		}
		
#else
		drbd_info(peer_device,
			  "Writing the whole bitmap, full sync required after drbd_sync_handshake.\n");
		if (drbd_bitmap_io(device, &drbd_bmio_set_n_write, "set_n_write from sync_handshake",
					BM_LOCK_CLEAR | BM_LOCK_BULK, peer_device))
			return -1;
#endif
	}
	return 0;
}

static enum drbd_repl_state goodness_to_repl_state(struct drbd_peer_device *peer_device,
						   enum drbd_role peer_role,
						   int hg)
{
	enum drbd_role role = peer_device->device->resource->role[NOW];
	enum drbd_repl_state rv;

	if (hg == 1 || hg == -1) {
		if (role == R_PRIMARY || peer_role == R_PRIMARY) {
			/* We have at least one primary, follow that with the resync decision */
			rv = peer_role == R_SECONDARY ? L_WF_BITMAP_S :
				role == R_SECONDARY ? L_WF_BITMAP_T :
				L_ESTABLISHED;
			return rv;
		}
		/* No current primary. Handle it as a common power failure, consider the
		   roles at crash time */
#ifdef _WIN32_DISABLE_RESYNC_FROM_SECONDARY
		// it repeatedly tries sync if CRASHED_PRIMARY bit is set and can't get sync, need to clear it and make it outdated.
		else if (hg == -1)
		{
			drbd_info(device, "I am crashed primary, but could not get sync. clear bit and get sync later\n");
			clear_bit(CRASHED_PRIMARY, &device->flags);
			begin_state_change(device->resource, &irq_flags, CS_VERBOSE);
			if (device->disk_state[NOW] > D_OUTDATED)
				__change_disk_state(device, D_OUTDATED);
			end_state_change(device->resource, &irq_flags);
		}
#endif
	}

#ifdef _WIN32_DISABLE_RESYNC_FROM_SECONDARY
	// MODIFIED_BY_MANTECH DW-1142: don't try to do sync if no primary.
	if (hg != 0 &&
		(role != R_PRIMARY && peer_role != R_PRIMARY))
	{
		drbd_info(peer_device, "both nodes are secondary, no resync, but %lu bits in bitmap\n", drbd_bm_total_weight(peer_device));

		// DW-1172, DW-1154 If sync is required from peer node, change the disk state to Inconsistent.
		if (hg < 0)
		{
			begin_state_change(device->resource, &irq_flags, CS_VERBOSE);
			if (device->disk_state[NOW] > D_OUTDATED)
				__change_disk_state(device, D_INCONSISTENT);
			end_state_change(device->resource, &irq_flags);

		}		
		rv = L_ESTABLISHED;
		return rv;
	}
#endif

	if (hg > 0) { /* become sync source. */
		rv = L_WF_BITMAP_S;
	} else if (hg < 0) { /* become sync target */
		rv = L_WF_BITMAP_T;
	} else {
		rv = L_ESTABLISHED;
		if (drbd_bitmap_uuid(peer_device)) {
			drbd_info(peer_device, "clearing bitmap UUID and bitmap content (%llu bits)\n",
				(unsigned long long)drbd_bm_total_weight(peer_device));
			drbd_uuid_set_bitmap(peer_device, 0);
			drbd_bm_clear_many_bits(peer_device->device, peer_device->bitmap_index, 0, DRBD_END_OF_BITMAP);
		} else if (drbd_bm_total_weight(peer_device)) {

			/* DW-1843
			 * If io-error occurs at the primary and the written oos is synchronized after demotion to secondary, 
			 * the value of "hg" is sent to 0 because both nodes are in UpToDate state and uuid is the same. 
			 * Here, we check the value of MDF_PEER_PRIMARY_IO_ERROR, UUID_FLAG_PRIMARY_IO_ERROR, and determine the role.
			 */
			if (drbd_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR)) {
				drbd_info(peer_device, "this node contain the oos generated by io-errors at primary.\n");
				rv = L_WF_BITMAP_S;
			}
			else if (peer_device->uuid_flags & UUID_FLAG_PRIMARY_IO_ERROR) {
				drbd_info(peer_device, "peer node contains the oos generated by io-errors at primary.\n");
				rv = L_WF_BITMAP_T;
			}
			else {
				//DW-1874 If the UUID is the same and the MDF_PEER_IN_PROGRESS_SYNC flag is set, the out of sync is meaningless because resync with other nodes is complete.
				if (drbd_md_test_peer_flag(peer_device, MDF_PEER_IN_PROGRESS_SYNC) ||
						peer_device->uuid_flags & UUID_FLAG_IN_PROGRESS_SYNC) {
					drbd_info(peer_device, "ended during synchronization and completed resync with other nodes, clearing bitmap UUID and bitmap content (%llu bits)\n",
						(unsigned long long)drbd_bm_total_weight(peer_device));
					drbd_uuid_set_bitmap(peer_device, 0);
					drbd_bm_clear_many_bits(peer_device->device, peer_device->bitmap_index, 0, DRBD_END_OF_BITMAP);
				}
				else {
					drbd_info(peer_device, "No resync, but %llu bits in bitmap!\n",
						(unsigned long long)drbd_bm_total_weight(peer_device));
				}
			}
		}
	}

	//DW-1874
	if (drbd_md_test_peer_flag(peer_device, MDF_PEER_IN_PROGRESS_SYNC))
		drbd_md_clear_peer_flag(peer_device, MDF_PEER_IN_PROGRESS_SYNC);
	
	return rv;
}

static void disk_states_to_goodness(struct drbd_device *device,
#ifndef _WIN32_CRASHED_PRIMARY_SYNCSOURCE
// MODIFIED_BY_MANTECH DW-1357: need to see peer device md flags.
					struct drbd_peer_device *peer_device,
#endif
				    enum drbd_disk_state peer_disk_state,
				    int *hg, int rule_nr)
{
	enum drbd_disk_state disk_state = device->disk_state[NOW];
	bool p = false;

#ifdef _WIN32
#ifndef _WIN32_CRASHED_PRIMARY_SYNCSOURCE
	/* MODIFIED_BY_MANTECH DW-1357: one of node is crashed primary, but need to ignore if..
		1. crashed primary's disk state is higher than peer's, crashed primary will be sync source.
		2. we've already done resync(by #1).
	*/
	if (abs(*hg) == 1)
	{
		if ((disk_state - peer_disk_state) * (*hg) < 0 ||
			drbd_md_test_peer_flag(peer_device, MDF_PEER_IGNORE_CRASHED_PRIMARY))
			*hg = 0;
	}		
#endif
#endif

	if (*hg != 0 && rule_nr != 40)
		return;

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1127: no resync if pdisk is D_UNKNOWN.
	if (peer_disk_state == D_UNKNOWN)
		return;
#endif

	/* rule_nr 40 means that the current UUIDs are equal. The decision
	   was found by looking at the crashed_primary bits.
	   The current disk states might give a better basis for decision-making! */

	if (disk_state == D_NEGOTIATING)
		disk_state = disk_state_from_md(device);

	if ((disk_state == D_INCONSISTENT && peer_disk_state > D_INCONSISTENT) ||
	    (peer_disk_state == D_INCONSISTENT && disk_state > D_INCONSISTENT)) {
		*hg = disk_state > D_INCONSISTENT ? 2 : -2;
		p = true;
	}

	if (p)
		drbd_info(device, "Becoming sync %s due to disk states.\n",
			  *hg > 0 ? "source" : "target");
}

#ifdef _WIN32
// MODIFIED_BY_MANTECH DW-1014: if we determined not to do sync in spite of existing out-of-sync, check couple of more states.
static void various_states_to_goodness(struct drbd_device *device,
						struct drbd_peer_device *peer_device,
						enum drbd_disk_state peer_disk_state,
						enum drbd_role peer_role,
						int *hg)
{
	enum drbd_disk_state disk_state = device->disk_state[NOW];
	int syncReason = 0;

	if (*hg != 0 || (drbd_bm_total_weight(peer_device) == 0 && peer_device->dirty_bits == 0))
		return;

	if (disk_state == D_NEGOTIATING)
		disk_state = disk_state_from_md(device);

	// 1. compare peer role.
	if (device->resource->role[NOW] == R_PRIMARY || peer_role == R_PRIMARY)
	{
		*hg = device->resource->role[NOW] == R_PRIMARY ? 2 : -2;
		syncReason = 1;
		goto out;
	}

	// 2. compare disk state.
#ifdef _WIN32 // DW-1633: no resync. D_CONSISTENT is temporary state.
	if (peer_disk_state == D_CONSISTENT || disk_state == D_CONSISTENT)
	{
		return;
	}
#endif
	
	// DW-1127: no resync if pdisk is D_UNKNOWN.	
	if (peer_disk_state != D_UNKNOWN &&
		peer_disk_state != disk_state &&
		(peer_disk_state >= D_OUTDATED || disk_state >= D_OUTDATED))
	{
		*hg = disk_state > peer_disk_state ? 2 : -2;
		syncReason = 2;
		goto out;
	}
	
	// MODIFIED_BY_MANTECH DW-955: no chance to in-sync consistent sector since peer_in_sync has been left out of receiving while disconnected.
	// 3. get rid of unnecessary out-of-sync.
	if (device->disk_state[NOW] == D_UP_TO_DATE &&
		peer_disk_state == D_UP_TO_DATE &&
		peer_device->dirty_bits == 0)
	{
		struct drbd_peer_md *peer_md = device->ldev->md.peers;
		int peer_node_id = 0;
		u64 peer_bm_uuid = 0;

		spin_lock_irq(&device->ldev->md.uuid_lock);
		peer_node_id = peer_device->node_id;
		peer_bm_uuid = peer_md[peer_node_id].bitmap_uuid;

		drbd_info(peer_device, "FIXME, both nodes are UpToDate, but have inconsistent bits set. clear it without resync\n");

		if (peer_bm_uuid)
			_drbd_uuid_push_history(device, peer_bm_uuid);
		if (peer_md[peer_node_id].bitmap_index != -1 && !drbd_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR))
		{
			drbd_info(peer_device, "bitmap will be cleared due to inconsistent out-of-sync\n");
			forget_bitmap(device, peer_node_id);
		}
		drbd_md_mark_dirty(device);
		spin_unlock_irq(&device->ldev->md.uuid_lock);
	}
out:
	if (*hg)
		drbd_info(device, "Becoming sync %s due to %s.\n",
		*hg > 0 ? "source" : "target",
		syncReason == 1 ? "role" : syncReason == 2 ? "disk states" : "unknown reason");
}
#endif

static enum drbd_repl_state drbd_attach_handshake(struct drbd_peer_device *peer_device,
						  enum drbd_disk_state peer_disk_state) __must_hold(local)
{
	int hg, rule_nr, peer_node_id;

	hg = drbd_handshake(peer_device, &rule_nr, &peer_node_id, true);

	if (hg < -4 || hg > 4)
		return -1;

	bitmap_mod_after_handshake(peer_device, hg, peer_node_id);
#ifndef _WIN32_CRASHED_PRIMARY_SYNCSOURCE
	disk_states_to_goodness(peer_device->device, peer_device, peer_disk_state, &hg, rule_nr);
#else
	disk_states_to_goodness(peer_device->device, peer_disk_state, &hg, rule_nr);
#endif

	return goodness_to_repl_state(peer_device, peer_device->connection->peer_role[NOW], hg);
}

/* drbd_sync_handshake() returns the new replication state on success, and -1
 * on failure.
 */
static enum drbd_repl_state drbd_sync_handshake(struct drbd_peer_device *peer_device,
						enum drbd_role peer_role,
						enum drbd_disk_state peer_disk_state) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	enum drbd_disk_state disk_state;
	struct net_conf *nc;
	int hg, rule_nr, rr_conflict, peer_node_id = 0, r;

	hg = drbd_handshake(peer_device, &rule_nr, &peer_node_id, true);

	disk_state = device->disk_state[NOW];
	if (disk_state == D_NEGOTIATING)
		disk_state = disk_state_from_md(device);

	if (hg == -1000) {
		drbd_alert(device, "Unrelated data, aborting!\n");
		return -1;
	}
	if (hg < -1000) {
		drbd_alert(device, "To resolve this both sides have to support at least protocol %d\n", -hg - 1000);
		return -1;
	}

#ifndef _WIN32_CRASHED_PRIMARY_SYNCSOURCE
	disk_states_to_goodness(device, peer_device, peer_disk_state, &hg, rule_nr);
#else
	disk_states_to_goodness(device, peer_disk_state, &hg, rule_nr);
#endif

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1014: to trigger sync when hg is 0 and oos exists, check more states as long as 'disk_states_to_goodness' doesn't cover all situations.
	various_states_to_goodness(device, peer_device, peer_disk_state, peer_role, &hg);	
#endif
	
#ifdef LINBIT_PATCH // It will not be used for a while because DW-1195 reproduced. 
	if (hg == 100 && (!drbd_device_stable(device, NULL) || !(peer_device->uuid_flags & UUID_FLAG_STABLE))) {
		drbd_warn(device, "Ignore Split-Brain, for now, at least one side unstable\n");
		hg = 0;
	}
#endif 

	if (abs(hg) == 100)
		drbd_khelper(device, connection, "initial-split-brain");

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);

	if (hg == 100 || (hg == -100 && nc->always_asbp)) {
		int pcount = (device->resource->role[NOW] == R_PRIMARY)
			   + (peer_role == R_PRIMARY);
		int forced = (hg == -100);

		switch (pcount) {
		case 0:
			hg = drbd_asb_recover_0p(peer_device);
			break;
		case 1:
			hg = drbd_asb_recover_1p(peer_device);
			break;
		case 2:
			hg = drbd_asb_recover_2p(peer_device);
			break;
		}
		if (abs(hg) < 100) {
			drbd_warn(device, "Split-Brain detected, %d primaries, "
			     "automatically solved. Sync from %s node\n",
			     pcount, (hg < 0) ? "peer" : "this");
			if (forced) {
				drbd_warn(device, "Doing a full sync, since"
				     " UUIDs where ambiguous.\n");
				hg = hg + (hg > 0 ? 1 : -1);
			}
		}
	}

	if (hg == -100) {
#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-1221 : If DISCARD_MY_DATA bit is set on both nodes, dropping connection.
		if (test_bit(DISCARD_MY_DATA, &peer_device->flags) &&
			(peer_device->uuid_flags & UUID_FLAG_DISCARD_MY_DATA)) {
			drbd_err(connection, "incompatible %s settings\n", "discard-my-data");
			rcu_read_unlock();
			return -1;
		}
#endif
		if (test_bit(DISCARD_MY_DATA, &peer_device->flags) &&
		    !(peer_device->uuid_flags & UUID_FLAG_DISCARD_MY_DATA))
			hg = -2;
		if (!test_bit(DISCARD_MY_DATA, &peer_device->flags) &&
		    (peer_device->uuid_flags & UUID_FLAG_DISCARD_MY_DATA))
			hg = 2;

		if (abs(hg) < 100)
			drbd_warn(device, "Split-Brain detected, manually solved. "
			     "Sync from %s node\n",
			     (hg < 0) ? "peer" : "this");
	}
#ifdef _WIN32 
	//MODIFIED_BY_MANTECH DW-1221 : If Split-Brain not detected, clearing DISCARD_MY_DATA bit.
	else
	{
		if (test_bit(DISCARD_MY_DATA, &peer_device->flags))
			clear_bit(DISCARD_MY_DATA, &peer_device->flags);
	}
#endif
	rr_conflict = nc->rr_conflict;
	rcu_read_unlock();

	if (hg == -100) {
		drbd_alert(device, "Split-Brain detected but unresolved, dropping connection!\n");
		drbd_khelper(device, connection, "split-brain");
		return -1;
	}

	if (hg <= -2 && /* by intention we do not use disk_state here. */
	    device->resource->role[NOW] == R_PRIMARY && device->disk_state[NOW] >= D_CONSISTENT) {
		switch (rr_conflict) {
		case ASB_CALL_HELPER:
			drbd_khelper(device, connection, "pri-lost");
			/* fall through */
		case ASB_DISCONNECT:
			drbd_err(device, "I shall become SyncTarget, but I am primary!\n");
			return -1;
		case ASB_VIOLENTLY:
			drbd_warn(device, "Becoming SyncTarget, violating the stable-data"
			     "assumption\n");
		}
	}

#ifdef _WIN32 // DW-1657 : If an inconsistent node tries to become a SyncSource, it will disconnect.
	if (hg == 3 && device->disk_state[NOW] < D_OUTDATED && 
		drbd_current_uuid(peer_device->device) != UUID_JUST_CREATED) {
		drbd_err(device, "I shall become SyncSource, but I am inconsistent!\n");
		return -1;
	}

	if (hg == -3 && peer_device->uuid_flags & UUID_FLAG_INCONSISTENT) {
		drbd_err(device, "I shall become SyncTarget, but peer is inconsistent!\n");
		return -1;
	}	
#endif

	if (test_bit(CONN_DRY_RUN, &connection->flags)) {
		if (hg == 0)
			drbd_info(device, "dry-run connect: No resync, would become Connected immediately.\n");
		else
			drbd_info(device, "dry-run connect: Would become %s, doing a %s resync.",
				 drbd_repl_str(hg > 0 ? L_SYNC_SOURCE : L_SYNC_TARGET),
				 abs(hg) >= 2 ? "full" : "bit-map based");
		return -1;
	}

	r = bitmap_mod_after_handshake(peer_device, hg, peer_node_id);
	if (r)
		return r;

	return goodness_to_repl_state(peer_device, peer_role, hg);
}

static enum drbd_after_sb_p convert_after_sb(enum drbd_after_sb_p peer)
{
	/* ASB_DISCARD_REMOTE - ASB_DISCARD_LOCAL is valid */
	if (peer == ASB_DISCARD_REMOTE)
		return ASB_DISCARD_LOCAL;

	/* any other things with ASB_DISCARD_REMOTE or ASB_DISCARD_LOCAL are invalid */
	if (peer == ASB_DISCARD_LOCAL)
		return ASB_DISCARD_REMOTE;

	/* everything else is valid if they are equal on both sides. */
	return peer;
}

static int receive_protocol(struct drbd_connection *connection, struct packet_info *pi)
{
	struct p_protocol *p = pi->data;
	enum drbd_after_sb_p p_after_sb_0p, p_after_sb_1p, p_after_sb_2p;
	int p_proto, p_discard_my_data, p_two_primaries, cf;
	struct net_conf *nc, *old_net_conf, *new_net_conf = NULL;
	char integrity_alg[SHARED_SECRET_MAX] = "";
	struct crypto_hash *peer_integrity_tfm = NULL;
	void *int_dig_in = NULL, *int_dig_vv = NULL;

#ifdef _WIN32
	KIRQL oldIrql_rLock1; // RCU_SPECIAL_CASE
#endif
	p_proto		= be32_to_cpu(p->protocol);
	p_after_sb_0p	= be32_to_cpu(p->after_sb_0p);
	p_after_sb_1p	= be32_to_cpu(p->after_sb_1p);
	p_after_sb_2p	= be32_to_cpu(p->after_sb_2p);
	p_two_primaries = be32_to_cpu(p->two_primaries);
	cf		= be32_to_cpu(p->conn_flags);
	p_discard_my_data = cf & CF_DISCARD_MY_DATA;

	if (connection->agreed_pro_version >= 87) {
		int err;

		if (pi->size > sizeof(integrity_alg))
			return -EIO;
		err = drbd_recv_into(connection, integrity_alg, pi->size);
		if (err)
			return err;
		integrity_alg[SHARED_SECRET_MAX - 1] = 0;
	}

	if (pi->cmd != P_PROTOCOL_UPDATE) {
		if (cf & CF_DRY_RUN)
			set_bit(CONN_DRY_RUN, &connection->flags);

#ifdef _WIN32
		// RCU_SPECIAL_CASE
		oldIrql_rLock1 = ExAcquireSpinLockShared(&g_rcuLock);
#else
		rcu_read_lock();
#endif
		nc = rcu_dereference(connection->transport.net_conf);

		if (p_proto != (int)nc->wire_protocol) {
			drbd_err(connection, "incompatible %s settings\n", "protocol");
			goto disconnect_rcu_unlock;
		}

		if (convert_after_sb(p_after_sb_0p) != (int)nc->after_sb_0p) {
			drbd_err(connection, "incompatible %s settings\n", "after-sb-0pri");
			goto disconnect_rcu_unlock;
		}

		if (convert_after_sb(p_after_sb_1p) != (int)nc->after_sb_1p) {
			drbd_err(connection, "incompatible %s settings\n", "after-sb-1pri");
			goto disconnect_rcu_unlock;
		}

		if (convert_after_sb(p_after_sb_2p) != (int)nc->after_sb_2p) {
			drbd_err(connection, "incompatible %s settings\n", "after-sb-2pri");
			goto disconnect_rcu_unlock;
		}

#ifndef _WIN32
		// MODIFIED_BY_MANTECH DW-1221 : move to drbd_sync_handshake()
		if (p_discard_my_data && test_bit(CONN_DISCARD_MY_DATA, &connection->flags)) {
			drbd_err(connection, "incompatible %s settings\n", "discard-my-data");
			goto disconnect_rcu_unlock;
		}
#endif

		if (p_two_primaries != nc->two_primaries) {
			drbd_err(connection, "incompatible %s settings\n", "allow-two-primaries");
			goto disconnect_rcu_unlock;
		}

		if (strcmp(integrity_alg, nc->integrity_alg)) {
			drbd_err(connection, "incompatible %s settings\n", "data-integrity-alg");
			goto disconnect_rcu_unlock;
		}
#ifdef _WIN32
		// RCU_SPECIAL_CASE
		ExReleaseSpinLockShared(&g_rcuLock, oldIrql_rLock1); 
#else
		rcu_read_unlock();
#endif
	}

	if (integrity_alg[0]) {
		int hash_size;

		/*
		 * We can only change the peer data integrity algorithm
		 * here.  Changing our own data integrity algorithm
		 * requires that we send a P_PROTOCOL_UPDATE packet at
		 * the same time; otherwise, the peer has no way to
		 * tell between which packets the algorithm should
		 * change.
		 */
#ifdef _WIN32
        peer_integrity_tfm = crypto_alloc_hash(integrity_alg, 0, CRYPTO_ALG_ASYNC, '52DW');
#else
		peer_integrity_tfm = crypto_alloc_hash(integrity_alg, 0, CRYPTO_ALG_ASYNC);
#endif
		if (IS_ERR(peer_integrity_tfm)) {
			peer_integrity_tfm = NULL;
			drbd_err(connection, "peer data-integrity-alg %s not supported\n",
				 integrity_alg);
			goto disconnect;
		}

		hash_size = crypto_hash_digestsize(peer_integrity_tfm);
#ifdef _WIN32
        int_dig_in = kmalloc(hash_size, GFP_KERNEL, '62DW');
        int_dig_vv = kmalloc(hash_size, GFP_KERNEL, '72DW');
#else
		int_dig_in = kmalloc(hash_size, GFP_KERNEL);
		int_dig_vv = kmalloc(hash_size, GFP_KERNEL);
#endif
		if (!(int_dig_in && int_dig_vv)) {
			drbd_err(connection, "Allocation of buffers for data integrity checking failed\n");
			goto disconnect;
		}
	}

#ifdef _WIN32
    new_net_conf = kmalloc(sizeof(struct net_conf), GFP_KERNEL, '82DW');
#else
	new_net_conf = kmalloc(sizeof(struct net_conf), GFP_KERNEL);
#endif
	if (!new_net_conf) {
		drbd_err(connection, "Allocation of new net_conf failed\n");
		goto disconnect;
	}

	if (mutex_lock_interruptible(&connection->resource->conf_update)) {
		drbd_err(connection, "Interrupted while waiting for conf_update\n");
		goto disconnect;
	}

	mutex_lock(&connection->mutex[DATA_STREAM]);
	old_net_conf = connection->transport.net_conf;
	*new_net_conf = *old_net_conf;

	new_net_conf->wire_protocol = p_proto;
	new_net_conf->after_sb_0p = convert_after_sb(p_after_sb_0p);
	new_net_conf->after_sb_1p = convert_after_sb(p_after_sb_1p);
	new_net_conf->after_sb_2p = convert_after_sb(p_after_sb_2p);
	new_net_conf->two_primaries = (char)p_two_primaries;

#ifdef _WIN32 
	synchronize_rcu_w32_wlock();
#endif
	rcu_assign_pointer(connection->transport.net_conf, new_net_conf);
#ifdef _WIN32 // DW-656  
    synchronize_rcu(); 
#endif
	mutex_unlock(&connection->mutex[DATA_STREAM]);
	mutex_unlock(&connection->resource->conf_update);

	crypto_free_hash(connection->peer_integrity_tfm);
	kfree(connection->int_dig_in);
	kfree(connection->int_dig_vv);
	connection->peer_integrity_tfm = peer_integrity_tfm;
	connection->int_dig_in = int_dig_in;
	connection->int_dig_vv = int_dig_vv;

	if (strcmp(old_net_conf->integrity_alg, integrity_alg))
		drbd_info(connection, "peer data-integrity-alg: %s\n",
			  integrity_alg[0] ? integrity_alg : "(none)");

#ifndef _WIN32 // DW-656  
	synchronize_rcu(); 
#endif
	kfree(old_net_conf);
	return 0;

disconnect_rcu_unlock:
#ifdef _WIN32
	// RCU_SPECIAL_CASE
	ExReleaseSpinLockShared(&g_rcuLock, oldIrql_rLock1); 
#else
	rcu_read_unlock();
#endif
disconnect:
	crypto_free_hash(peer_integrity_tfm);
	kfree(int_dig_in);
	kfree(int_dig_vv);
	change_cstate_ex(connection, C_DISCONNECTING, CS_HARD); 
	return -EIO;
}

/* helper function
 * input: alg name, feature name
 * return: NULL (alg name was "")
 *         ERR_PTR(error) if something goes wrong
 *         or the crypto hash ptr, if it worked out ok. */
static struct crypto_hash *drbd_crypto_alloc_digest_safe(const struct drbd_device *device,
		const char *alg, const char *name)
{
	struct crypto_hash *tfm;

	if (!alg[0])
		return NULL;

#ifdef _WIN32
	char* alg2 = (char*)alg;
	tfm = crypto_alloc_hash(alg2, 0, CRYPTO_ALG_ASYNC, 'A6DW');
#else
	tfm = crypto_alloc_hash(alg, 0, CRYPTO_ALG_ASYNC);
#endif
	if (IS_ERR(tfm)) {
		drbd_err(device, "Can not allocate \"%s\" as %s (reason: %ld)\n",
			alg, name, PTR_ERR(tfm));
		return tfm;
	}
	return tfm;
}

/*
 * config_unknown_volume  -  device configuration command for unknown volume
 *
 * When a device is added to an existing connection, the node on which the
 * device is added first will send configuration commands to its peer but the
 * peer will not know about the device yet.  It will warn and ignore these
 * commands.  Once the device is added on the second node, the second node will
 * send the same device configuration commands, but in the other direction.
 *
 * (We can also end up here if drbd is misconfigured.)
 */
static int config_unknown_volume(struct drbd_connection *connection, struct packet_info *pi)
{
	drbd_warn(connection, "%s packet received for volume %d, which is not configured locally\n",
		  drbd_packet_name(pi->cmd), pi->vnr);
	return ignore_remaining_packet(connection, pi->size);
}

static int receive_SyncParam(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_rs_param_95 *p;
	unsigned int header_size, data_size, exp_max_sz;
	struct crypto_hash *verify_tfm = NULL;
	struct crypto_hash *csums_tfm = NULL;
	struct net_conf *old_net_conf, *new_net_conf = NULL;
	struct peer_device_conf *old_peer_device_conf = NULL, *new_peer_device_conf = NULL;
	const int apv = connection->agreed_pro_version;
	struct fifo_buffer *old_plan = NULL, *new_plan = NULL;
	struct drbd_resource *resource = connection->resource;
	int fifo_size = 0;
	int err;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return config_unknown_volume(connection, pi);
	device = peer_device->device;

	exp_max_sz  = apv <= 87 ? sizeof(struct p_rs_param)
		    : apv == 88 ? sizeof(struct p_rs_param)
					+ SHARED_SECRET_MAX
		    : apv <= 94 ? sizeof(struct p_rs_param_89)
		    : /* apv >= 95 */ sizeof(struct p_rs_param_95);

	if (pi->size > exp_max_sz) {
		drbd_err(device, "SyncParam packet too long: received %u, expected <= %u bytes\n",
		    pi->size, exp_max_sz);
		return -EIO;
	}

	if (apv <= 88) {
		header_size = sizeof(struct p_rs_param);
		data_size = pi->size - header_size;
	} else if (apv <= 94) {
		header_size = sizeof(struct p_rs_param_89);
		data_size = pi->size - header_size;
		D_ASSERT(device, data_size == 0);
	} else {
		header_size = sizeof(struct p_rs_param_95);
		data_size = pi->size - header_size;
		D_ASSERT(device, data_size == 0);
	}

	err = drbd_recv_all(connection, (void **)&p, header_size + data_size);
	if (err)
		return err;

	err = mutex_lock_interruptible(&resource->conf_update);
	if (err) {
		drbd_err(connection, "Interrupted while waiting for conf_update\n");
		return err;
	}
	old_net_conf = connection->transport.net_conf;
	if (get_ldev(device)) {
#ifdef _WIN32
        new_peer_device_conf = kzalloc(sizeof(struct peer_device_conf), GFP_KERNEL, 'A2DW');
#else
		new_peer_device_conf = kzalloc(sizeof(struct peer_device_conf), GFP_KERNEL);
#endif
		if (!new_peer_device_conf) {
			put_ldev(device);
			mutex_unlock(&resource->conf_update);
			drbd_err(device, "Allocation of new peer_device_conf failed\n");
			return -ENOMEM;
		}
		/* With a non-zero new_peer_device_conf, we will call put_ldev() below.  */

		old_peer_device_conf = peer_device->conf;
		*new_peer_device_conf = *old_peer_device_conf;

		new_peer_device_conf->resync_rate = be32_to_cpu(p->resync_rate);
	}

	if (apv >= 88) {
		if (apv == 88) {
			if (data_size > SHARED_SECRET_MAX || data_size == 0) {
				drbd_err(device, "verify-alg too long, "
					 "peer wants %u, accepting only %u byte\n",
					 data_size, SHARED_SECRET_MAX);
				goto reconnect;
			}
			p->verify_alg[data_size] = 0;

		} else /* apv >= 89 */ {
			/* we still expect NUL terminated strings */
			/* but just in case someone tries to be evil */
			D_ASSERT(device, p->verify_alg[SHARED_SECRET_MAX-1] == 0);
			D_ASSERT(device, p->csums_alg[SHARED_SECRET_MAX-1] == 0);
			p->verify_alg[SHARED_SECRET_MAX-1] = 0;
			p->csums_alg[SHARED_SECRET_MAX-1] = 0;
		}

		if (strcmp(old_net_conf->verify_alg, p->verify_alg)) {
			if (peer_device->repl_state[NOW] == L_OFF) {
				drbd_err(device, "Different verify-alg settings. me=\"%s\" peer=\"%s\"\n",
				    old_net_conf->verify_alg, p->verify_alg);
				goto disconnect;
			}
			verify_tfm = drbd_crypto_alloc_digest_safe(device,
					p->verify_alg, "verify-alg");
			if (IS_ERR(verify_tfm)) {
				verify_tfm = NULL;
				goto disconnect;
			}
		}

		if (apv >= 89 && strcmp(old_net_conf->csums_alg, p->csums_alg)) {
			if (peer_device->repl_state[NOW] == L_OFF) {
				drbd_err(device, "Different csums-alg settings. me=\"%s\" peer=\"%s\"\n",
				    old_net_conf->csums_alg, p->csums_alg);
				goto disconnect;
			}
			csums_tfm = drbd_crypto_alloc_digest_safe(device,
					p->csums_alg, "csums-alg");
			if (IS_ERR(csums_tfm)) {
				csums_tfm = NULL;
				goto disconnect;
			}
		}

		if (apv > 94 && new_peer_device_conf) {
			new_peer_device_conf->c_plan_ahead = be32_to_cpu(p->c_plan_ahead);
			new_peer_device_conf->c_delay_target = be32_to_cpu(p->c_delay_target);
			new_peer_device_conf->c_fill_target = be32_to_cpu(p->c_fill_target);
			new_peer_device_conf->c_max_rate = be32_to_cpu(p->c_max_rate);

			fifo_size = (new_peer_device_conf->c_plan_ahead * 10 * SLEEP_TIME) / HZ;
			old_plan = rcu_dereference_protected(peer_device->rs_plan_s,
				lockdep_is_held(&resource->conf_update));
			if (!old_plan || fifo_size != (int)old_plan->size) {
#ifdef _WIN32
                new_plan = fifo_alloc(fifo_size, 'B2DW');
#else
				new_plan = fifo_alloc(fifo_size);
#endif
				if (!new_plan) {
					drbd_err(device, "kmalloc of fifo_buffer failed");
					goto disconnect;
				}
			}
		}

		if (verify_tfm || csums_tfm) {
#ifdef _WIN32
            new_net_conf = kzalloc(sizeof(struct net_conf), GFP_KERNEL, 'C2DW');
#else
			new_net_conf = kzalloc(sizeof(struct net_conf), GFP_KERNEL);
#endif
			if (!new_net_conf) {
				drbd_err(device, "Allocation of new net_conf failed\n");
				goto disconnect;
			}

			*new_net_conf = *old_net_conf;

			if (verify_tfm) {
				strncpy(new_net_conf->verify_alg, p->verify_alg, sizeof(new_net_conf->verify_alg) - 1);
				new_net_conf->verify_alg_len = (__u32)(strlen(p->verify_alg) + 1);
				crypto_free_hash(connection->verify_tfm);
				connection->verify_tfm = verify_tfm;
				drbd_info(device, "using verify-alg: \"%s\"\n", p->verify_alg);
			}
			if (csums_tfm) {
				strncpy(new_net_conf->csums_alg, p->csums_alg, sizeof(new_net_conf->csums_alg) - 1);
				new_net_conf->csums_alg_len = (__u32)(strlen(p->csums_alg) + 1);
				crypto_free_hash(connection->csums_tfm);
				connection->csums_tfm = csums_tfm;
				drbd_info(device, "using csums-alg: \"%s\"\n", p->csums_alg);
			}
#ifdef _WIN32
			synchronize_rcu_w32_wlock();
#endif
			rcu_assign_pointer(connection->transport.net_conf, new_net_conf);
#ifdef _WIN32
			synchronize_rcu();
#endif
		}
	}

#ifdef _WIN32
	synchronize_rcu_w32_wlock();
#endif
	if (new_peer_device_conf) {
		drbd_info(peer_device, "sync, resync_rate : %uk, c_plan_ahead : %uk, c_delay_target : %uk, c_fill_target : %us, c_max_rate : %uk, c_min_rate : %uk\n",
			new_peer_device_conf->resync_rate, new_peer_device_conf->c_plan_ahead, new_peer_device_conf->c_delay_target,
			new_peer_device_conf->c_fill_target, new_peer_device_conf->c_max_rate, new_peer_device_conf->c_min_rate);
		rcu_assign_pointer(peer_device->conf, new_peer_device_conf);
		put_ldev(device);
	}

	if (new_plan)
		rcu_assign_pointer(peer_device->rs_plan_s, new_plan);

	mutex_unlock(&resource->conf_update);
	synchronize_rcu();
	if (new_net_conf)
		kfree(old_net_conf);
	kfree(old_peer_device_conf);
	if (new_plan)
		kfree(old_plan);

	return 0;

reconnect:
	if (new_peer_device_conf) {
		put_ldev(device);
		kfree(new_peer_device_conf);
	}
	mutex_unlock(&resource->conf_update);
	return -EIO;

disconnect:
	kfree(new_plan);
	if (new_peer_device_conf) {
		put_ldev(device);
		kfree(new_peer_device_conf);
	}
	mutex_unlock(&resource->conf_update);
	/* just for completeness: actually not needed,
	 * as this is not reached if csums_tfm was ok. */
	crypto_free_hash(csums_tfm);
	/* but free the verify_tfm again, if csums_tfm did not work out */
	crypto_free_hash(verify_tfm);
	change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
	return -EIO;
}

static void drbd_setup_order_type(struct drbd_device *device, int peer)
{
	UNREFERENCED_PARAMETER(device);
	UNREFERENCED_PARAMETER(peer);
	/* sorry, we currently have no working implementation
	 * of distributed TCQ */
}

/* warn if the arguments differ by more than 12.5% */
static void warn_if_differ_considerably(struct drbd_peer_device *peer_device,
	const char *s, sector_t a, sector_t b)
{
	sector_t d;
	if (a == 0 || b == 0)
		return;
	d = (a > b) ? (a - b) : (b - a);
	if (d > (a>>3) || d > (b>>3))
		drbd_warn(peer_device, "Considerable difference in %s: %llu bytes vs. %llu bytes\n", s,
             (unsigned long long)(a<<9), (unsigned long long)(b<<9));
}

/* Maximum bio size that a protocol version supports. */
static unsigned int conn_max_bio_size(struct drbd_connection *connection)
{
	if (connection->agreed_pro_version >= 100)
		return DRBD_MAX_BIO_SIZE;
	else if (connection->agreed_pro_version >= 95)
		return DRBD_MAX_BIO_SIZE_P95;
	else
		return DRBD_MAX_SIZE_H80_PACKET;
}

static struct drbd_peer_device *get_neighbor_device(struct drbd_device *device,
		enum drbd_neighbor neighbor)
{
	s32 self_id, peer_id, pivot;
	struct drbd_peer_device *peer_device, *peer_device_ret = NULL;

	if (!get_ldev(device))
		return NULL;
	self_id = device->ldev->md.node_id;
	put_ldev(device);

	pivot = neighbor == NEXT_LOWER ? 0 : neighbor == NEXT_HIGHER ? S32_MAX : -1;
	if (pivot == -1)
		return NULL;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		bool found_new = false;
		peer_id = peer_device->node_id;

		if (neighbor == NEXT_LOWER && peer_id < self_id && peer_id >= pivot)
			found_new = true;
		else if (neighbor == NEXT_HIGHER && peer_id > self_id && peer_id <= pivot)
			found_new = true;

		if (found_new && peer_device->disk_state[NOW] >= D_INCONSISTENT) {
			pivot = peer_id;
			peer_device_ret = peer_device;
		}
	}
	rcu_read_unlock();

	return peer_device_ret;
}

static void maybe_trigger_resync(struct drbd_device *device, struct drbd_peer_device *peer_device, bool grew, bool skip)
{
	if (!peer_device)
		return;
	if (peer_device->repl_state[NOW] <= L_OFF)
		return;
	if (test_and_clear_bit(RESIZE_PENDING, &peer_device->flags) ||
		(grew && peer_device->repl_state[NOW] == L_ESTABLISHED)) {
		if (peer_device->disk_state[NOW] >= D_INCONSISTENT &&
			device->disk_state[NOW] >= D_INCONSISTENT) {
			if (skip)
				drbd_info(peer_device, "Resync of new storage suppressed with --assume-clean\n");
			else
				resync_after_online_grow(peer_device);
		} else
		set_bit(RESYNC_AFTER_NEG, &peer_device->flags);
	}
}

static int receive_sizes(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device, *peer_device_it = NULL;
	struct drbd_device *device;
	struct p_sizes *p = pi->data;
	struct o_qlim *o = (connection->agreed_features & DRBD_FF_WSAME) ? p->qlim : NULL;
	uint64_t p_size, p_usize, p_csize;
	uint64_t my_usize, my_max_size, cur_size;
	enum determine_dev_size dd = DS_UNCHANGED;
	bool should_send_sizes = false;
	enum dds_flags ddsf;
	unsigned int protocol_max_bio_size;
	bool have_ldev = false;
	bool have_mutex = false;
	bool is_handshake;
#ifdef _WIN32
	int err = 0;
#else 
	int err;
#endif
	u64 im;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return config_unknown_volume(connection, pi);
	device = peer_device->device;

	err = mutex_lock_interruptible(&connection->resource->conf_update);
	if (err) {
		drbd_err(connection, "Interrupted while waiting for conf_update\n");
		goto out;
	}
	have_mutex = true;

	/* just store the peer's disk size for now.
	 * we still need to figure out whether we accept that. */
	p_size = be64_to_cpu(p->d_size);
	p_usize = be64_to_cpu(p->u_size);
	p_csize = be64_to_cpu(p->c_size);

	peer_device->d_size = p_size;
	peer_device->u_size = p_usize;
	peer_device->c_size = p_csize;

	/* Ignore "current" size for calculating "max" size. */
	/* If it used to have a disk, but now is detached, don't revert back to zero. */

	if (p_size)
		peer_device->max_size = p_size;

	cur_size = drbd_get_capacity(device->this_bdev);
    drbd_info(device, "current_mydisk_size: %llu bytes\n", (unsigned long long)(cur_size<<9));
    drbd_info(peer_device, "peer_current_size: %llu bytes peer_user_size: %llu bytes peer_disk_size: %llu bytes peer_max_size: %llu bytes\n",
            (unsigned long long)(p_csize<<9),
            (unsigned long long)(p_usize<<9),
            (unsigned long long)(p_size<<9),
            (unsigned long long)(peer_device->max_size<<9));
	
	if ((p_size && p_csize > p_size) || (p_usize && p_csize > p_usize)) {
		drbd_warn(peer_device, "Peer sent bogus sizes, disconnecting\n");
		goto disconnect;
	}

	/* The protocol version limits how big requests can be.  In addition,
	* peers before protocol version 94 cannot split large requests into
	* multiple bios; their reported max_bio_size is a hard limit.
	*/
	protocol_max_bio_size = conn_max_bio_size(connection);
	peer_device->max_bio_size = min(be32_to_cpu(p->max_bio_size), protocol_max_bio_size);
	ddsf = be16_to_cpu(p->dds_flags);

	is_handshake = (peer_device->repl_state[NOW] == L_OFF);
	/* Maybe the peer knows something about peers I cannot currently see. */
	ddsf |= DDSF_IGNORE_PEER_CONSTRAINTS;
	//DW-1799
	set_bit(INITIAL_SIZE_RECEIVED, &peer_device->flags); 
	if (get_ldev(device)) {
		sector_t new_size;

		have_ldev = true;

		rcu_read_lock();
		my_usize = rcu_dereference(device->ldev->disk_conf)->disk_size;
		rcu_read_unlock();
		
		my_max_size = drbd_get_max_capacity(device->ldev);
		        drbd_info(peer_device, "md_effective_size: %llu my_user_size: %llu my_max_size: %llu\n",
			(unsigned long long)device->ldev->md.effective_size,
			(unsigned long long)my_usize,
			(unsigned long long)my_max_size);

		if (peer_device->disk_state[NOW] > D_DISKLESS)
			warn_if_differ_considerably(peer_device, "lower level device sizes",
					p_size, my_max_size);
			warn_if_differ_considerably(peer_device, "user requested size",
					    p_usize, my_usize);

		if (is_handshake)
			p_usize = min_not_zero(my_usize, p_usize);

		if (p_usize == 0) {
			/* Peer may reset usize to zero only if it has a backend.
			 * Because a diskless node has no disk config,
			 * and always sends zero. */
			if (p_size == 0)
				p_usize = my_usize;
		}

		new_size = drbd_new_dev_size(device, p_csize, p_usize, ddsf);

		/* Never shrink a device with usable data during connect.
		   But allow online shrinking if we are connected. */
		if (new_size < cur_size &&
		    device->disk_state[NOW] >= D_OUTDATED &&
#ifdef _WIN32 // DW-1469 : allowed if discard_my_data option.
		    !test_bit(DISCARD_MY_DATA, &peer_device->flags) &&
#endif
		    peer_device->repl_state[NOW] < L_ESTABLISHED) {
            drbd_err(peer_device, "The peer's disk size is too small! (%llu bytes < %llu bytes)\n",
                    (unsigned long long)(new_size<<9), (unsigned long long)(cur_size<<9));
			goto disconnect;
		}

		/* Disconnect, if we cannot grow to the peer's current size */
		if (my_max_size < p_csize && !is_handshake) {
			drbd_err(peer_device, "Peer's size larger than my maximum capacity (%llu < %llu sectors)\n",
				(unsigned long long)my_max_size, (unsigned long long)p_csize);
			goto disconnect;
		}

		if (my_usize != p_usize) {
			struct disk_conf *old_disk_conf, *new_disk_conf;
#ifdef _WIN32
            new_disk_conf = kzalloc(sizeof(struct disk_conf), GFP_KERNEL, 'D2DW');
#else
			new_disk_conf = kzalloc(sizeof(struct disk_conf), GFP_KERNEL);
#endif
			if (!new_disk_conf) {
				drbd_err(device, "Allocation of new disk_conf failed\n");
				err = -ENOMEM;
				goto out;
			}
			
			old_disk_conf = device->ldev->disk_conf;
			*new_disk_conf = *old_disk_conf;
			new_disk_conf->disk_size = p_usize;
#ifdef _WIN32
			synchronize_rcu_w32_wlock(); 
#endif
			rcu_assign_pointer(device->ldev->disk_conf, new_disk_conf);
			synchronize_rcu();
			kfree(old_disk_conf);

			drbd_info(peer_device, "Peer sets u_size to %llu sectors\n",
				(unsigned long long)p_usize);
			/* Do not set should_send_sizes here. That might cause packet storms */
		}
	}		

	/* Leave drbd_reconsider_queue_parameters() before drbd_determine_dev_size().
	   In case we cleared the QUEUE_FLAG_DISCARD from our queue in
	   drbd_reconsider_queue_parameters(), we can be sure that after
	   drbd_determine_dev_size() no REQ_DISCARDs are in the queue. */
	if (have_ldev) {
		drbd_reconsider_queue_parameters(device, device->ldev, o);
		drbd_info(peer_device, "calling drbd_determine_dev_size()\n");		
		dd = drbd_determine_dev_size(device, p_csize, ddsf, NULL);

		if (dd == DS_GREW || dd == DS_SHRUNK)
			should_send_sizes = true;

		if (dd == DS_ERROR) {
			err = -EIO;
			goto out;
		}
		drbd_md_sync_if_dirty(device);
	} else {
		uint64_t size = 0;

		drbd_reconsider_queue_parameters(device, NULL, o);
		/* In case I am diskless, need to accept the peer's *current* size.
		 *
		 * At this point, the peer knows more about my disk, or at
		 * least about what we last agreed upon, than myself.
		 * So if his c_size is less than his d_size, the most likely
		 * reason is that *my* d_size was smaller last time we checked,
		 * or some other peer does not (yet) have enough room.
		 */
		size = p_csize;
		size = min_not_zero(size, p_usize);
		size = min_not_zero(size, p_size);
				
		if (size != drbd_get_capacity(device->this_bdev)) {
			char ppb[10];
			should_send_sizes = true;
			drbd_set_my_capacity(device, size);
			drbd_info(device, "size = %s (%llu KB)\n", ppsize(ppb, sizeof(ppb), size >> 1),
				(unsigned long long)size >> 1);
		}
	}

	if (device->device_conf.max_bio_size > protocol_max_bio_size ||
	    (connection->agreed_pro_version < 94 &&
	     device->device_conf.max_bio_size > peer_device->max_bio_size)) {
		drbd_err(device, "Peer cannot deal with requests bigger than %u. "
			 "Please reduce max_bio_size in the configuration.\n",
			 peer_device->max_bio_size);
		goto disconnect;
	}

	if (have_ldev) {
		if (device->ldev->known_size != drbd_get_capacity(device->ldev->backing_bdev)) {
			device->ldev->known_size = drbd_get_capacity(device->ldev->backing_bdev);
			should_send_sizes = true;
		}

		drbd_setup_order_type(device, be16_to_cpu(p->queue_order_type));
	}

	cur_size = drbd_get_capacity(device->this_bdev);
	
	for_each_peer_device_ref(peer_device_it, im, device) {
		struct drbd_connection *con_it = peer_device_it->connection;

		/* drop cached max_size, if we already grew beyond it */
		if (peer_device_it->max_size < cur_size)
			peer_device_it->max_size = 0;

		if (con_it->cstate[NOW] < C_CONNECTED)
			continue;

		/* Send size updates only if something relevant has changed.
		* TODO: only tell the sender thread to do so,
		* or we may end up in a distributed deadlock on congestion. */
		if (should_send_sizes)
			drbd_send_sizes(peer_device_it, p_usize, ddsf);
	}

	maybe_trigger_resync(device, get_neighbor_device(device, NEXT_HIGHER),
			dd == DS_GREW, ddsf & DDSF_NO_RESYNC);
	maybe_trigger_resync(device, get_neighbor_device(device, NEXT_LOWER),
			dd == DS_GREW, ddsf & DDSF_NO_RESYNC);
	err = 0;

out:
	if (have_ldev)
		put_ldev(device);
	if (have_mutex)
		mutex_unlock(&connection->resource->conf_update);	
	return err;

disconnect:
	/* don't let a rejected peer confuse future handshakes with different peers. */
	peer_device->max_size = 0;
	change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
	err = -EIO;
	goto out;
}

static void drbd_resync(struct drbd_peer_device *peer_device,
			enum resync_reason reason) __must_hold(local)
{
	enum drbd_role peer_role = peer_device->connection->peer_role[NOW];
	enum drbd_repl_state new_repl_state;
	enum drbd_disk_state peer_disk_state;
	int hg, rule_nr, peer_node_id;
	enum drbd_state_rv rv;

	hg = drbd_handshake(peer_device, &rule_nr, &peer_node_id, reason == DISKLESS_PRIMARY);

#ifdef _WIN32
#ifndef _WIN32_CRASHED_PRIMARY_SYNCSOURCE
	// DW-1306: need to start resync in spite of identical current uuid, try to find the resync side.
	if (reason == AFTER_UNSTABLE)
	{
		disk_states_to_goodness(peer_device->device, peer_device, peer_device->disk_state[NOW], &hg, rule_nr);
		various_states_to_goodness(peer_device->device, peer_device, peer_device->disk_state[NOW], peer_device->connection->peer_role[NOW], &hg);
	}
#else
	if (!hg && reason == AFTER_UNSTABLE)
	{
		disk_states_to_goodness(peer_device->device, peer_device->disk_state[NOW], &hg, rule_nr);
		various_states_to_goodness(peer_device->device, peer_device, peer_device->disk_state[NOW], peer_device->connection->peer_role[NOW], &hg);
	}
#endif
#endif
	new_repl_state = hg < -4 || hg > 4 ? -1 : goodness_to_repl_state(peer_device, peer_role, hg);

	if (new_repl_state == -1) {
		drbd_info(peer_device, "Unexpected result of handshake() %d!\n", new_repl_state);
#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-1360: destroy connection for conflicted data.
		change_cstate_ex(peer_device->connection, C_DISCONNECTING, CS_HARD);
#endif
		return;
	} else if (new_repl_state != L_ESTABLISHED) {
		bitmap_mod_after_handshake(peer_device, hg, peer_node_id);
		drbd_info(peer_device, "Becoming %s %s\n", drbd_repl_str(new_repl_state),
			  reason == AFTER_UNSTABLE ? "after unstable" : "because primary is diskless");
	}
	peer_disk_state = peer_device->disk_state[NOW];
	if (new_repl_state == L_ESTABLISHED && peer_disk_state >= D_CONSISTENT &&
		peer_device->device->disk_state[NOW] == D_OUTDATED) {
		/* No resync with up-to-date peer -> I should be consistent or up-to-date as well.
		   Note: Former unstable (but up-to-date) nodes become consistent for a short
		   time after loosing their primary peer. Therefore consider consistent here
		   as well. */
		drbd_info(peer_device, "Upgrading local disk to %s after unstable/weak (and no resync).\n",
				drbd_disk_str(peer_disk_state));
		change_disk_state(peer_device->device, peer_disk_state, CS_VERBOSE, NULL);
		return;
	}

	rv = change_repl_state(peer_device, new_repl_state, CS_VERBOSE);
	if ((rv == SS_NOTHING_TO_DO || rv == SS_RESYNC_RUNNING) &&
	    (new_repl_state == L_WF_BITMAP_S || new_repl_state == L_WF_BITMAP_T)) {
		/* Those events might happen very quickly. In case we are still processing
		   the previous resync we need to re-enter that state. Schedule sending of
		   the bitmap here explicitly */
		// DW-2026 remove unnecessary resync again
		//peer_device->resync_again++;
		drbd_info(peer_device, "...resync is already in progress.\n");
	}
}

#ifdef _WIN32_DISABLE_RESYNC_FROM_SECONDARY
// MODIFIED_BY_MANTECH DW-1148: one of node has gone primary, compare bitmap and start resync when necessary.
static void drbd_resync_after_promotion(struct drbd_peer_device *peer_device, enum drbd_repl_state side)
{
	enum drbd_repl_state new_repl_state;
	enum drbd_state_rv rv;

	new_repl_state = side == L_SYNC_SOURCE ? L_WF_BITMAP_S : side == L_SYNC_TARGET ? L_WF_BITMAP_T : -1;

	if (new_repl_state == -1)
	{
		drbd_info(peer_device, "Invalid resync side %s\n", drbd_repl_str(side));
		return;
	}

	drbd_info(peer_device, "Becoming %s after one node promoted\n", drbd_repl_str(new_repl_state));
	
	// DW-1228: sync as much as set out-of-sync isn't enough for some cases, do initial sync instead.
	if (new_repl_state == L_WF_BITMAP_S)
	{
		int hg, rule_nr, peer_node_id = 0;
		hg = drbd_handshake(peer_device, &rule_nr, &peer_node_id, false);

		if (abs(hg) >= 100 ||
			abs(hg) == 3)
		{
			hg = 3;
			bitmap_mod_after_handshake(peer_device, hg, peer_node_id);
		}
	}

	rv = change_repl_state(peer_device, new_repl_state, CS_VERBOSE);
	if (rv == SS_NOTHING_TO_DO || rv == SS_RESYNC_RUNNING) {
		peer_device->resync_again++;
		drbd_info(peer_device, "...postponing this until current resync finished\n");
	}
}
#endif

#ifdef _WIN32_STABLE_SYNCSOURCE
// DW-1315: we got new authoritative node, compare bitmap and start resync.
static void drbd_resync_authoritative(struct drbd_peer_device *peer_device, enum drbd_repl_state side)
{
	enum drbd_repl_state new_repl_state;
	enum drbd_state_rv rv;
	int hg, rule_nr, peer_node_id = 0;

	new_repl_state = side == L_SYNC_SOURCE ? L_WF_BITMAP_S : side == L_SYNC_TARGET ? L_WF_BITMAP_T : -1;

	if (new_repl_state == -1)
	{
		drbd_info(peer_device, "Invalid resync side %s\n", drbd_repl_str(side));
		return;
	}

	hg = drbd_handshake(peer_device, &rule_nr, &peer_node_id, false);

	if (abs(hg) >= 100)
	{
		drbd_err(peer_device, "Can not start resync due to unexpected handshake result(%d)\n", hg);
		// MODIFIED_BY_MANTECH DW-1360: destroy connection for conflicted data.
		change_cstate_ex(peer_device->connection, C_DISCONNECTING, CS_HARD);
		return;
	}

	drbd_info(peer_device, "Becoming %s due to authoritative node changed\n", drbd_repl_str(new_repl_state));

	if (new_repl_state == L_WF_BITMAP_S)
	{
		if (abs(hg) == 3)
		{
			hg = 3;
			bitmap_mod_after_handshake(peer_device, hg, peer_node_id);
		}
	}

	rv = change_repl_state(peer_device, new_repl_state, CS_VERBOSE);
	if (rv == SS_NOTHING_TO_DO || rv == SS_RESYNC_RUNNING) {
		// DW-2026 remove unnecessary resync again
		//peer_device->resync_again++;
		drbd_info(peer_device, "...resync is already in progress.\n");
	}
}
#endif

static void update_bitmap_slot_of_peer(struct drbd_peer_device *peer_device, int node_id, u64 bitmap_uuid)
{
	if (peer_device->bitmap_uuids[node_id] && bitmap_uuid == 0) {
		/* If we learn from a neighbor that it no longer has a bitmap
		   against a third node, we need to deduce from that knowledge
		   that in the other direction the bitmap was cleared as well.
		 */
		struct drbd_peer_device *peer_device2;

		rcu_read_lock();
		peer_device2 = peer_device_by_node_id(peer_device->device, node_id);
		if (peer_device2) {
			int node_id2 = peer_device->connection->peer_node_id;
			peer_device2->bitmap_uuids[node_id2] = 0;
		}
		rcu_read_unlock();
	}
	peer_device->bitmap_uuids[node_id] = bitmap_uuid;
}

static int __receive_uuids(struct drbd_peer_device *peer_device, u64 node_mask)
{
	enum drbd_repl_state repl_state = peer_device->repl_state[NOW];
	struct drbd_device *device = peer_device->device;
	int updated_uuids = 0, err = 0;
	bool bad_server;

	bad_server =
		repl_state < L_ESTABLISHED &&
		device->disk_state[NOW] < D_INCONSISTENT &&
		device->resource->role[NOW] == R_PRIMARY &&
		(device->exposed_data_uuid & ~UUID_PRIMARY) !=
		(peer_device->current_uuid & ~UUID_PRIMARY);

	if (peer_device->connection->agreed_pro_version < 110 && bad_server) {
		drbd_err(device, "Can only connect to data with current UUID=%016llX\n",
		    (unsigned long long)device->exposed_data_uuid);
		change_cstate_ex(peer_device->connection, C_DISCONNECTING, CS_HARD);
		return -EIO;
	}

	if (get_ldev(device)) {
		int skip_initial_sync =
			repl_state == L_ESTABLISHED &&
			peer_device->connection->agreed_pro_version >= 90 &&
			drbd_current_uuid(device) == UUID_JUST_CREATED &&
			(peer_device->uuid_flags & UUID_FLAG_SKIP_INITIAL_SYNC);
		if (skip_initial_sync) {
			unsigned long irq_flags;

			drbd_info(device, "Accepted new current UUID, preparing to skip initial sync\n");
			drbd_bitmap_io(device, &drbd_bmio_clear_all_n_write,
					"clear_n_write from receive_uuids",
					BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK, NULL);
			_drbd_uuid_set_current(device, peer_device->current_uuid);
			_drbd_uuid_set_bitmap(peer_device, 0);
			begin_state_change(device->resource, &irq_flags, CS_VERBOSE);
			/* FIXME: Note that req_lock was not taken here before! */
			__change_disk_state(device, D_UP_TO_DATE, __FUNCTION__);
			__change_peer_disk_state(peer_device, D_UP_TO_DATE, __FUNCTION__);
			end_state_change(device->resource, &irq_flags, __FUNCTION__);
			updated_uuids = 1;
		}

		if (peer_device->uuid_flags & UUID_FLAG_NEW_DATAGEN) {
			drbd_warn(peer_device, "received new current UUID: %016llX\n", peer_device->current_uuid);
			drbd_uuid_received_new_current(peer_device, peer_device->current_uuid, node_mask);
		}

		if (device->disk_state[NOW] > D_OUTDATED) {
			int hg, unused_int;
			hg = drbd_uuid_compare(peer_device, &unused_int, &unused_int);

			if (hg == -3 || hg == -2) {
				struct drbd_resource *resource = device->resource;
				unsigned long irq_flags;

				begin_state_change(resource, &irq_flags, CS_VERBOSE);
				if (device->disk_state[NEW] > D_OUTDATED)
					__change_disk_state(device, D_OUTDATED, __FUNCTION__);
				end_state_change(resource, &irq_flags, __FUNCTION__);
			}
		}

#ifdef _WIN32_DISABLE_RESYNC_FROM_SECONDARY
		// MODIFIED_BY_MANTECH DW-1162: setting 'UUID_FLAG_PROMOTED' means resync is about to start, uuid will be sent again when resync's done.
		if (!(peer_device->uuid_flags & UUID_FLAG_PROMOTED))
#endif
		drbd_uuid_detect_finished_resyncs(peer_device);

		drbd_md_sync_if_dirty(device);
		put_ldev(device);
	} else if (device->disk_state[NOW] < D_INCONSISTENT && !bad_server &&
		   peer_device->current_uuid != device->exposed_data_uuid) {
		struct drbd_resource *resource = device->resource;

		spin_lock_irq(&resource->req_lock);
		if (resource->state_change_flags) {
			drbd_info(peer_device, "Delaying update of exposed data uuid\n");
			device->next_exposed_data_uuid = peer_device->current_uuid;
		} else
			updated_uuids = drbd_set_exposed_data_uuid(device, peer_device->current_uuid);
		spin_unlock_irq(&resource->req_lock);

	}

	if (updated_uuids)
		drbd_print_uuids(peer_device, "receiver updated UUIDs to", __FUNCTION__);

	peer_device->uuid_authoritative_nodes =
		peer_device->uuid_flags & UUID_FLAG_STABLE ? 0 : node_mask;

	if ((repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) &&
	    !(peer_device->uuid_flags & UUID_FLAG_STABLE) &&
	    !drbd_stable_sync_source_present(peer_device, NOW))
		set_bit(UNSTABLE_RESYNC, &peer_device->flags);

	return err;
}

static int receive_uuids(struct drbd_connection *connection, struct packet_info *pi)
{
	const int node_id = connection->resource->res_opts.node_id;
	struct drbd_peer_device *peer_device;
	struct p_uuids *p = pi->data;
	int history_uuids, i;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return config_unknown_volume(connection, pi);

	history_uuids = min_t(int, HISTORY_UUIDS_V08,
			      ARRAY_SIZE(peer_device->history_uuids));

	peer_device->current_uuid = be64_to_cpu(p->current_uuid);
	peer_device->bitmap_uuids[node_id] = be64_to_cpu(p->bitmap_uuid);
	for (i = 0; i < history_uuids; i++)
		peer_device->history_uuids[i] = be64_to_cpu(p->history_uuids[i]);
	for (; i < ARRAY_SIZE(peer_device->history_uuids); i++)
		peer_device->history_uuids[i] = 0;
	peer_device->dirty_bits = be64_to_cpu(p->dirty_bits);
	peer_device->uuid_flags = be64_to_cpu(p->uuid_flags) | UUID_FLAG_STABLE;
	peer_device->uuids_received = true;

	return __receive_uuids(peer_device, 0);
}

static int receive_uuids110(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct p_uuids110 *p = pi->data;
	int bitmap_uuids, history_uuids, rest, i, pos, err;
	u64 bitmap_uuids_mask;
	struct drbd_peer_md *peer_md = NULL;
	struct drbd_device *device;


	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return config_unknown_volume(connection, pi);

	device = peer_device->device;

	peer_device->current_uuid = be64_to_cpu(p->current_uuid);
	peer_device->dirty_bits = be64_to_cpu(p->dirty_bits);
#ifdef _WIN32_STABLE_SYNCSOURCE
	// DW-1315: need to update authoritative nodes earlier than uuid flag.
	peer_device->uuid_authoritative_nodes = (p->uuid_flags & UUID_FLAG_STABLE) ? 0 : be64_to_cpu(p->node_mask);
#endif
	peer_device->uuid_flags = be64_to_cpu(p->uuid_flags);
	bitmap_uuids_mask = be64_to_cpu(p->bitmap_uuids_mask);
	if (bitmap_uuids_mask & ~(NODE_MASK(DRBD_PEERS_MAX) - 1))
		return -EIO;
#ifdef _WIN64
	BUG_ON_INT32_OVER(hweight64(bitmap_uuids_mask));
#endif
	bitmap_uuids = (int)hweight64(bitmap_uuids_mask);

	if (pi->size / sizeof(p->other_uuids[0]) < (unsigned int)bitmap_uuids)
		return -EIO;
	history_uuids = pi->size / sizeof(p->other_uuids[0]) - bitmap_uuids;
	if (history_uuids > ARRAY_SIZE(peer_device->history_uuids))
		history_uuids = ARRAY_SIZE(peer_device->history_uuids);

	err = drbd_recv_into(connection, p->other_uuids,
			     (bitmap_uuids + history_uuids) *
			     sizeof(p->other_uuids[0]));
	if (err)
		return err;

	rest = pi->size - (bitmap_uuids + history_uuids) * sizeof(p->other_uuids[0]);
	if (rest && !ignore_remaining_packet(connection, rest))
		return -EIO;

	if (get_ldev(device))
		peer_md = device->ldev->md.peers;
	pos = 0;
	for (i = 0; i < ARRAY_SIZE(peer_device->bitmap_uuids); i++) {
		u64 bitmap_uuid;

		if (bitmap_uuids_mask & NODE_MASK(i)) {
#ifdef _WIN32
            bitmap_uuid = be64_to_cpu(p->other_uuids[pos]);
            pos++;
#else
			bitmap_uuid = be64_to_cpu(p->other_uuids[pos++]);
#endif
			if (peer_md && peer_md[i].bitmap_index == -1)
				peer_md[i].flags |= MDF_NODE_EXISTS;
		} else {
			bitmap_uuid = 0;
		}

		update_bitmap_slot_of_peer(peer_device, i, bitmap_uuid);
	}
	if (peer_md)
		put_ldev(device);

	for (i = 0; i < history_uuids; i++)
#ifdef _WIN32
    {
        peer_device->history_uuids[i] = be64_to_cpu(p->other_uuids[pos]);
        pos++;
    }
#else
		peer_device->history_uuids[i] = be64_to_cpu(p->other_uuids[pos++]);
#endif
	while (i < ARRAY_SIZE(peer_device->history_uuids))
		peer_device->history_uuids[i++] = 0;
#if 0  // DW-593, DW-1321 : cause twopc timeout, roll back
    struct drbd_resource *resource = device->resource;
    down(&resource->state_sem);
    peer_device->uuids_received = true;
    up(&resource->state_sem);
#else
	peer_device->uuids_received = true;
#endif

	err = __receive_uuids(peer_device, be64_to_cpu(p->node_mask));

#ifdef _WIN32 
	// MODIFIED_BY_MANTECH DW-1306: to avoid race with removing flag in sanitize_state(Linux drbd commit:7d60f61). with got stable flag, need resync after unstable to be triggered.
	if (be64_to_cpu(p->uuid_flags) & UUID_FLAG_GOT_STABLE &&
		!test_bit(RECONCILIATION_RESYNC, &peer_device->flags)) {	// MODIFIED_BY_MANTECH DW-891
#else
	if (peer_device->uuid_flags & UUID_FLAG_GOT_STABLE) { 
#endif
		struct drbd_device *device = peer_device->device;
		
		if (peer_device->repl_state[NOW] == L_ESTABLISHED &&
		    drbd_device_stable(device, NULL) && get_ldev(device)) {
			// DW-1666: The local state value is not updated on the peer, resulting in the CONSISTNET state after sending drbd_send_uuids (UUID_FLAG_RESYNC, 0).
			// Local status updates are sent from a separate thread to a peer and issues arise due to time differences.
			// Send local state to peer before sending drbd_send_uids (UUID_FLAG_RESYNC, 0) for issue resolution.
			drbd_send_state(peer_device, drbd_get_device_state(device, NOW));
			drbd_send_uuids(peer_device, UUID_FLAG_RESYNC, 0);
			drbd_resync(peer_device, AFTER_UNSTABLE);
			put_ldev(device);
		}
	}
	
#ifdef _WIN32 // MODIFIED_BY_MANTECH DW-891
	if (peer_device->uuid_flags & UUID_FLAG_RESYNC &&
#ifdef _WIN32_DISABLE_RESYNC_FROM_SECONDARY
		// MODIFIED_BY_MANTECH DW-1148: added checking flag to segregate resync reason.
		!(peer_device->uuid_flags & UUID_FLAG_PROMOTED) &&
#endif
#ifdef _WIN32_STABLE_SYNCSOURCE
		// DW-1315: UUID_FLAG_RESYNC is also used to start resync when authoritative node is changed, do not trigger resync here.
		!(peer_device->uuid_flags & UUID_FLAG_AUTHORITATIVE) &&
#endif
		!test_bit(RECONCILIATION_RESYNC, &peer_device->flags)) {
#else
	if (peer_device->uuid_flags & UUID_FLAG_RESYNC) { 
#endif
		if (get_ldev(device)) {
			bool dp = peer_device->uuid_flags & UUID_FLAG_DISKLESS_PRIMARY;
			drbd_resync(peer_device, dp ? DISKLESS_PRIMARY : AFTER_UNSTABLE);
			put_ldev(device);
		}
	}

#ifdef _WIN32_DISABLE_RESYNC_FROM_SECONDARY
	// MODIFIED_BY_MANTECH DW-1148: start resync when one node has been promoted.
	// be synctarget if only UUID_FLAG_PROMOTED bit is set, and be syncsource if both UUID_FLAG_PROMOTED and UUID_FLAG_RESYNC bits are set.
	if (peer_device->uuid_flags & UUID_FLAG_PROMOTED)
	{
		if (peer_device->uuid_flags & UUID_FLAG_RESYNC)
		{
			if (get_ldev(device))
			{
				drbd_resync_after_promotion(peer_device, L_SYNC_SOURCE);
				put_ldev(device);
			}
		}
		else
		{
			if (peer_device->repl_state[NOW] == L_ESTABLISHED &&				
				get_ldev(device))
			{
				drbd_send_uuids(peer_device, UUID_FLAG_PROMOTED | UUID_FLAG_RESYNC, 0);
				drbd_resync_after_promotion(peer_device, L_SYNC_TARGET);
				put_ldev(device);
			}
		}
	}
#endif

#ifdef _WIN32_STABLE_SYNCSOURCE
	// DW-1315: abort resync if peer gets unsyncable state.
	if ((peer_device->repl_state[NOW] >= L_STARTING_SYNC_S && peer_device->repl_state[NOW] <= L_WF_BITMAP_T) ||
		(peer_device->repl_state[NOW] >= L_SYNC_SOURCE && peer_device->repl_state[NOW] <= L_PAUSED_SYNC_T))
	{
#ifdef _WIN32_RCU_LOCKED
		if (!drbd_inspect_resync_side(peer_device, peer_device->repl_state[NOW], NOW, false))
#else
		if (!drbd_inspect_resync_side(peer_device, peer_device->repl_state[NOW], NOW))
#endif
		{
			drbd_info(peer_device, "Resync will be aborted since peer goes unsyncable.\n");

			unsigned long irq_flags;
			begin_state_change(device->resource, &irq_flags, CS_VERBOSE);
			__change_repl_state_and_auto_cstate(peer_device, L_ESTABLISHED, __FUNCTION__);
			end_state_change(device->resource, &irq_flags, __FUNCTION__);
		}
	}

	// DW-1315: resume resync when one node became peer's authoritative node.
	if ((peer_device->uuid_flags & UUID_FLAG_AUTHORITATIVE))
	{	
		if (peer_device->uuid_flags & UUID_FLAG_RESYNC)
		{
			if (get_ldev(device))
			{
				drbd_resync_authoritative(peer_device, L_SYNC_TARGET);
				put_ldev(device);
			}
		}
		else
		{
			if (peer_device->repl_state[NOW] == L_ESTABLISHED &&
#ifdef _WIN32_RCU_LOCKED
				drbd_inspect_resync_side(peer_device, L_SYNC_SOURCE, NOW, false) &&
#else
				drbd_inspect_resync_side(peer_device, L_SYNC_SOURCE, NOW) &&
#endif
				get_ldev(device))
			{
				drbd_send_uuids(peer_device, UUID_FLAG_AUTHORITATIVE | UUID_FLAG_RESYNC, 0);
				drbd_resync_authoritative(peer_device, L_SYNC_SOURCE);
				put_ldev(device);
			}
		}
	}
#endif

	return err;
}

/**
 * convert_state() - Converts the peer's view of the cluster state to our point of view
 * @peer_state:	The state as seen by the peer.
 */
static union drbd_state convert_state(union drbd_state peer_state)
{
	union drbd_state state;

	static enum drbd_conn_state c_tab[] = {
		[L_OFF] = L_OFF,
		[L_ESTABLISHED] = L_ESTABLISHED,

		[L_STARTING_SYNC_S] = L_STARTING_SYNC_T,
		[L_STARTING_SYNC_T] = L_STARTING_SYNC_S,
		[C_DISCONNECTING] = C_TEAR_DOWN, /* C_NETWORK_FAILURE, */
		[C_CONNECTING] = C_CONNECTING,
		[L_VERIFY_S]       = L_VERIFY_T,
		[C_MASK]   = C_MASK,
	};

	state.i = peer_state.i;

	state.conn = c_tab[peer_state.conn];
	state.peer = peer_state.role;
	state.role = peer_state.peer;
	state.pdsk = peer_state.disk;
	state.disk = peer_state.pdsk;
	state.peer_isp = (peer_state.aftr_isp | peer_state.user_isp);

	return state;
}

static enum drbd_state_rv
__change_connection_state(struct drbd_connection *connection,
			  union drbd_state mask, union drbd_state val,
			  enum chg_state_flags flags)
{
	UNREFERENCED_PARAMETER(flags);

	struct drbd_resource *resource = connection->resource;

	if (mask.role) {
		/* not allowed */
	}
	if (mask.susp) {
		mask.susp ^= -1;
		__change_io_susp_user(resource, val.susp);
	}
	if (mask.susp_nod) {
		mask.susp_nod ^= -1;
		__change_io_susp_no_data(resource, val.susp_nod);
	}
	if (mask.susp_fen) {
		mask.susp_fen ^= -1;
		__change_io_susp_fencing(connection, val.susp_fen);
	}
	if (mask.disk) {
		/* Handled in __change_peer_device_state(). */
		mask.disk ^= -1;
	}
	if (mask.conn) {
		mask.conn ^= -1;
		__change_cstate(connection,
				min_t(enum drbd_conn_state, val.conn, C_CONNECTED));
	}
	if (mask.pdsk) {
		/* Handled in __change_peer_device_state(). */
		mask.pdsk ^= -1;
	}
	if (mask.peer) {
		mask.peer ^= -1;
		__change_peer_role(connection, val.peer, __FUNCTION__);
	}
	if (mask.i) {
		drbd_info(connection, "Remote state change: request %u/%u not "
		"understood\n", mask.i, val.i & mask.i);
		return SS_NOT_SUPPORTED;
	}
	return SS_SUCCESS;
}

static enum drbd_state_rv
__change_peer_device_state(struct drbd_peer_device *peer_device,
			   union drbd_state mask, union drbd_state val)
{
	struct drbd_device *device = peer_device->device;

	if (mask.peer) {
		/* Handled in __change_connection_state(). */
		mask.peer ^= -1;
	}
	if (mask.disk) {
		mask.disk ^= -1;
		__change_disk_state(device, val.disk, __FUNCTION__);
	}

	if (mask.conn) {
		mask.conn ^= -1;
		__change_repl_state_and_auto_cstate(peer_device,
			max_t(enum drbd_repl_state, val.conn, L_OFF), __FUNCTION__);
	}
	if (mask.pdsk) {
		mask.pdsk ^= -1;
		__change_peer_disk_state(peer_device, val.pdsk, __FUNCTION__);
	}
	if (mask.user_isp) {
		mask.user_isp ^= -1;
		__change_resync_susp_user(peer_device, val.user_isp, __FUNCTION__);
	}
	if (mask.peer_isp) {
		mask.peer_isp ^= -1;
		__change_resync_susp_peer(peer_device, val.peer_isp, __FUNCTION__);
	}
	if (mask.aftr_isp) {
		mask.aftr_isp ^= -1;
		__change_resync_susp_dependency(peer_device, val.aftr_isp, __FUNCTION__);
	}
	if (mask.i) {
		drbd_info(peer_device, "Remote state change: request %u/%u not "
		"understood\n", mask.i, val.i & mask.i);
		return SS_NOT_SUPPORTED;
	}
	return SS_SUCCESS;
}

/**
 * change_connection_state()  -  change state of a connection and all its peer devices
 *
 * Also changes the state of the peer devices' devices and of the resource.
 * Cluster-wide state changes are not supported.
 */
static enum drbd_state_rv
change_connection_state(struct drbd_connection *connection,
			union drbd_state mask,
			union drbd_state val,
			struct twopc_reply *reply,
			enum chg_state_flags flags)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	unsigned long irq_flags;
	enum drbd_state_rv rv;
	int vnr;

	mask = convert_state(mask);
	val = convert_state(val);
retry:
	begin_state_change(resource, &irq_flags, flags);
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		rv = __change_peer_device_state(peer_device, mask, val);
		if (rv < SS_SUCCESS)
			goto fail;
	}
	rv = __change_connection_state(connection, mask, val, flags);
	if (rv < SS_SUCCESS)
		goto fail;

	if (reply) {
		u64 directly_reachable = directly_connected_nodes(resource, NEW) |
			NODE_MASK(resource->res_opts.node_id);

		if (reply->primary_nodes & ~directly_reachable)
			__outdate_myself(resource);
	}

	rv = end_state_change(resource, &irq_flags, __FUNCTION__);
out:

	if (rv == SS_NO_UP_TO_DATE_DISK && resource->role[NOW] != R_PRIMARY) {
#ifdef _WIN32
		long t = 0;
#else
		long t;
#endif
		/* Most probably udev opened it read-only. That might happen
		if it was demoted very recently. Wait up to one second. */
#ifdef _WIN32
		wait_event_interruptible_timeout(t, resource->state_wait,
			drbd_open_ro_count(resource) == 0,
			HZ);
#else
		t = wait_event_interruptible_timeout(resource->state_wait,
			drbd_open_ro_count(resource) == 0,
			HZ);
#endif
		if (t > 0)
			goto retry;
	}

	return rv;
fail:
	abort_state_change(resource, &irq_flags, __FUNCTION__);
	goto out;
}

/**
 * change_peer_device_state()  -  change state of a peer and its connection
 *
 * Also changes the state of the peer device's device and of the resource.
 * Cluster-wide state changes are not supported.
 */
static enum drbd_state_rv
change_peer_device_state(struct drbd_peer_device *peer_device,
			 union drbd_state mask,
			 union drbd_state val,
			 enum chg_state_flags flags)
{
	struct drbd_connection *connection = peer_device->connection;
	unsigned long irq_flags;
	enum drbd_state_rv rv;

	mask = convert_state(mask);
	val = convert_state(val);

	begin_state_change(connection->resource, &irq_flags, flags);
	rv = __change_peer_device_state(peer_device, mask, val);
	if (rv < SS_SUCCESS)
		goto fail;
	rv = __change_connection_state(connection, mask, val, flags);
	if (rv < SS_SUCCESS)
		goto fail;
	rv = end_state_change(connection->resource, &irq_flags, __FUNCTION__);
out:
	return rv;
fail:
	abort_state_change(connection->resource, &irq_flags, __FUNCTION__);
	goto out;
}

static int receive_req_state(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device = NULL;
	struct p_req_state *p = pi->data;
	union drbd_state mask, val;
	enum chg_state_flags flags = CS_VERBOSE | CS_LOCAL_ONLY | CS_TWOPC;
	enum drbd_state_rv rv;
	int vnr = -1;

	if (!expect(connection, connection->agreed_pro_version < 110)) {
		drbd_err(connection, "Packet %s not allowed in protocol version %d\n",
			 drbd_packet_name(pi->cmd),
			 connection->agreed_pro_version);
		return -EIO;
	}

	mask.i = be32_to_cpu(p->mask);
	val.i = be32_to_cpu(p->val);

	/* P_STATE_CHG_REQ packets must have a valid vnr.  P_CONN_ST_CHG_REQ
	 * packets have an undefined vnr. */
	if (pi->cmd == P_STATE_CHG_REQ) {
		peer_device = conn_peer_device(connection, pi->vnr);
		if (!peer_device) {
			if (mask.i == ((union drbd_state){{.conn = conn_MASK}}).i &&
			    val.i == ((union drbd_state){{.conn = L_OFF}}).i) {
				/* The peer removed this volume, we do not have it... */
				drbd_send_sr_reply(connection, vnr, SS_NOTHING_TO_DO);
				return 0;
			}

			return -EIO;
		}
		vnr = peer_device->device->vnr;
	}

	rv = SS_SUCCESS;
	spin_lock_irq(&resource->req_lock);
	if (resource->remote_state_change)
		rv = SS_CONCURRENT_ST_CHG;
	else
		resource->remote_state_change = true;
	spin_unlock_irq(&resource->req_lock);

	if (rv != SS_SUCCESS) {
		drbd_info(connection, "Rejecting concurrent remote state change\n");
		drbd_send_sr_reply(connection, vnr, rv);
		return 0;
	}

	/* Send the reply before carrying out the state change: this is needed
	 * for connection state changes which close the network connection.  */
	if (peer_device) {
		rv = change_peer_device_state(peer_device, mask, val, flags | CS_PREPARE);
		drbd_send_sr_reply(connection, vnr, rv);
		rv = change_peer_device_state(peer_device, mask, val, flags | CS_PREPARED);
		if (rv >= SS_SUCCESS)
			drbd_md_sync_if_dirty(peer_device->device);
	} else {
		flags |= CS_IGN_OUTD_FAIL;
		rv = change_connection_state(connection, mask, val, NULL, flags | CS_PREPARE);
		drbd_send_sr_reply(connection, vnr, rv);
		change_connection_state(connection, mask, val, NULL, flags | CS_PREPARED);
	}

	spin_lock_irq(&resource->req_lock);
	resource->remote_state_change = false;
	spin_unlock_irq(&resource->req_lock);
	wake_up(&resource->twopc_wait);
	queue_queued_twopc(resource);

	return 0;
}

int abort_nested_twopc_work(struct drbd_work *work, int cancel)
{
	UNREFERENCED_PARAMETER(cancel);

	struct drbd_resource *resource =
		container_of(work, struct drbd_resource, twopc_work);
	bool prepared = false;

	spin_lock_irq(&resource->req_lock);
	if (resource->twopc_reply.initiator_node_id != -1) {
		struct drbd_connection *connection, *tmp;
		resource->remote_state_change = false;
		resource->twopc_reply.initiator_node_id = -1;
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
		INIT_LIST_HEAD(&resource->twopc_parents);

		prepared = true;
	}
	resource->twopc_work.cb = NULL;
	spin_unlock_irq(&resource->req_lock);
	wake_up(&resource->twopc_wait);
	queue_queued_twopc(resource);

	if (prepared)
		abort_prepared_state_change(resource);
	return 0;
}
#ifdef _WIN32
void twopc_timer_fn(PKDPC Dpc, PVOID data, PVOID arg1, PVOID arg2)
#else
void twopc_timer_fn(unsigned long data)
#endif
{
#ifdef _WIN32
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);
#endif

	if (data == NULL)
		return;

	struct drbd_resource *resource = (struct drbd_resource *) data;
	unsigned long irq_flags;

	spin_lock_irqsave(&resource->req_lock, irq_flags);
	if (resource->twopc_work.cb == NULL) {
		drbd_err(resource, "Two-phase commit %u timeout\n",
			   resource->twopc_reply.tid);
		resource->twopc_work.cb = abort_nested_twopc_work;
		drbd_queue_work(&resource->work, &resource->twopc_work);
	} else {
		mod_timer(&resource->twopc_timer, jiffies + HZ/10);
	}
	spin_unlock_irqrestore(&resource->req_lock, irq_flags);
}

static enum drbd_state_rv outdate_if_weak(struct drbd_resource *resource,
					  struct twopc_reply *reply,
					  enum chg_state_flags flags)
{
	if (reply->primary_nodes & ~reply->reachable_nodes) {
		unsigned long irq_flags;

		begin_state_change(resource, &irq_flags, flags);
		__outdate_myself(resource);
		return end_state_change(resource, &irq_flags, __FUNCTION__);
	}

	return SS_NOTHING_TO_DO;
}

bool drbd_have_local_disk(struct drbd_resource *resource)
{
	struct drbd_device *device;
	int vnr;

	rcu_read_lock();

#ifdef _WIN32
    idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
#else
	idr_for_each_entry(&resource->devices, device, vnr) {
#endif
		if (device->disk_state[NOW] > D_DISKLESS) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

static enum drbd_state_rv
far_away_change(struct drbd_connection *connection, union drbd_state mask,
		union drbd_state val, struct twopc_reply *reply,
		enum chg_state_flags flags)
{
	struct drbd_resource *resource = connection->resource;
	int vnr = resource->twopc_reply.vnr;

	if (mask.i == 0 && val.i == 0 &&
		resource->role[NEW] == R_PRIMARY && vnr == -1) {
		/* A node far away test if there are primaries. I am the guy he
		is concerned about... He learned about me in the CS_PREPARE phase.
		Since he is commiting it I know that he is outdated now... */
		struct drbd_connection *affected_connection;
		int initiator_node_id = resource->twopc_reply.initiator_node_id;

		affected_connection = drbd_get_connection_by_node_id(resource, initiator_node_id);
		if (affected_connection) {
			unsigned long irq_flags;
			enum drbd_state_rv rv;

			begin_state_change(resource, &irq_flags, flags);
			__change_peer_disk_states(affected_connection, D_OUTDATED);
			rv = end_state_change(resource, &irq_flags, __FUNCTION__);
			kref_put(&affected_connection->kref, drbd_destroy_connection);
			return rv;
		}
	}

	if (flags & CS_PREPARE && mask.role == role_MASK && val.role == R_PRIMARY &&
		resource->role[NEW] == R_PRIMARY) {
		struct net_conf *nc;

		nc = rcu_dereference(connection->transport.net_conf);
		if (!nc || !nc->two_primaries)
			return SS_TWO_PRIMARIES;

		/* A node further away wants to become primary. In case I am
		 primary allow it only when I am diskless. See
		 also check_primaries_distances() in drbd_state.c */
		if (drbd_have_local_disk(resource))
			return SS_WEAKLY_CONNECTED;
	}
	return outdate_if_weak(resource, reply, flags);
}

enum csc_rv {
	CSC_CLEAR,
	CSC_REJECT,
	CSC_ABORT_LOCAL,
	CSC_QUEUE,
	CSC_TID_MISS,
	CSC_MATCH,
	//DW-1894
	CSC_UPDATE = CSC_MATCH,
};

static enum csc_rv
check_concurrent_transactions(struct drbd_resource *resource, struct twopc_reply *new_r)
{
	struct twopc_reply *ongoing = &resource->twopc_reply;

	if (!resource->remote_state_change)
		return CSC_CLEAR;

	if (new_r->initiator_node_id < ongoing->initiator_node_id) {
		if ((unsigned int)ongoing->initiator_node_id == resource->res_opts.node_id)
		{
#ifdef _WIN32_TWOPC
			drbd_info(resource, "[TWOPC] CSC_ABORT_LOCAL! new_r->initiator_node_id (%d) ongoing->initiator_node_id (%d)\n",
					new_r->initiator_node_id, ongoing->initiator_node_id);
#endif
			return CSC_ABORT_LOCAL;
		}
		else
		{
#ifdef _WIN32_TWOPC
			drbd_info(resource, "[TWOPC] CSC_QUEUE! new_r->initiator_node_id (%d) ongoing->initiator_node_id (%d)\n",
					new_r->initiator_node_id, ongoing->initiator_node_id);
#endif
			return CSC_QUEUE;
		}
	} else if (new_r->initiator_node_id > ongoing->initiator_node_id) {
		//DW-1894 if the old request is disconnected, remove it and process the new request.
		if (ongoing->is_disconnect && new_r->tid != ongoing->tid) {
			drbd_info(resource, "[TWOPC] CSC_UPDATE! new_r->initiator_node_id (%d), new_r->tid (%u)\n",
				new_r->initiator_node_id, new_r->tid);
			del_timer(&resource->twopc_timer);
			clear_remote_state_change_without_lock(resource);
			return CSC_UPDATE;
		}
#ifdef _WIN32_TWOPC
		drbd_info(resource, "[TWOPC] CSC_REJECT! new_r->initiator_node_id (%d) ongoing->initiator_node_id (%d)\n",
					new_r->initiator_node_id, ongoing->initiator_node_id);
#endif	
		return CSC_REJECT;
	}
	if (new_r->tid != ongoing->tid)
	{
#ifdef _WIN32_TWOPC
		drbd_info(resource, "[TWOPC] CSC_TID_MISS! new_r->tid (%u) ongoing->tid (%u)\n",
					new_r->tid, ongoing->tid);
#endif	
		return CSC_TID_MISS;
	}

	return CSC_MATCH;
}

enum alt_rv {
	ALT_LOCKED,
	ALT_MATCH,
	ALT_TIMEOUT,
};


static enum alt_rv when_done_lock(struct drbd_resource *resource, unsigned int for_tid)
{
	spin_lock_irq(&resource->req_lock);
	if (!resource->remote_state_change)
		return ALT_LOCKED;
	spin_unlock_irq(&resource->req_lock);
	if (resource->twopc_reply.tid == for_tid)
		return ALT_MATCH;

	return ALT_TIMEOUT;
}

static enum alt_rv abort_local_transaction(struct drbd_resource *resource, unsigned int for_tid)
{
	long t = twopc_timeout(resource) / 8;
	enum alt_rv rv;

	set_bit(TWOPC_ABORT_LOCAL, &resource->flags);
	spin_unlock_irq(&resource->req_lock);
	wake_up(&resource->state_wait);
#ifdef _WIN32
	wait_event_timeout(t, resource->twopc_wait, 
		(rv = when_done_lock(resource, for_tid)) != ALT_TIMEOUT, t);
#else
	t = wait_event_timeout(resource->twopc_wait, when_done_lock(resource), t);
#endif
	clear_bit(TWOPC_ABORT_LOCAL, &resource->flags);
	return rv;
}

static void arm_queue_twopc_timer(struct drbd_resource *resource)
{
	struct queued_twopc *q;
	q = list_first_entry_or_null(&resource->queued_twopc, struct queued_twopc, w.list);

	if (q) {
		unsigned long t = twopc_timeout(resource) / 4;
		mod_timer(&resource->queued_twopc_timer, q->start_jif + t);
	} else {
		del_timer(&resource->queued_twopc_timer);
	}
}

static int queue_twopc(struct drbd_connection *connection, struct twopc_reply *twopc, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct queued_twopc *q;
	bool was_empty, already_queued = false;

	spin_lock_irq(&resource->queued_twopc_lock);
#ifdef _WIN32
	list_for_each_entry(struct queued_twopc, q, &resource->queued_twopc, w.list) {
#else
	list_for_each_entry(q, &resource->queued_twopc, w.list) {
#endif
		if (q->reply.tid == twopc->tid &&
		    q->reply.initiator_node_id == twopc->initiator_node_id &&
			q->connection == connection)
			already_queued = true;
	}
	spin_unlock_irq(&resource->queued_twopc_lock);

	if (already_queued)
		return 0;

#ifdef _WIN32
    q = kmalloc(sizeof(*q), GFP_NOIO, 'E2DW');
#else
	q = kmalloc(sizeof(*q), GFP_NOIO);
#endif
	if (!q)
		return -ENOMEM;

	q->reply = *twopc;
	q->packet_data = *(struct p_twopc_request *)pi->data;
	q->packet_info = *pi;
	q->packet_info.data = &q->packet_data;
	kref_get(&connection->kref);
	q->connection = connection;
	q->start_jif = jiffies;

	spin_lock_irq(&resource->queued_twopc_lock);
	was_empty = list_empty(&resource->queued_twopc);
	list_add_tail(&q->w.list, &resource->queued_twopc);
	if (was_empty)
		arm_queue_twopc_timer(resource);
	spin_unlock_irq(&resource->queued_twopc_lock);

	return 0;
}

static int queued_twopc_work(struct drbd_work *w, int cancel)
{
	struct queued_twopc *q = container_of(w, struct queued_twopc, w), *q2, *tmp;
	struct drbd_connection *connection = q->connection;
	struct drbd_resource *resource = connection->resource; 
	unsigned long t = twopc_timeout(connection->resource) / 4;
	LIST_HEAD(work_list); 

	/* Look for more for the same TID... */
	spin_lock_irq(&resource->queued_twopc_lock); 
#ifdef _WIN32
	list_for_each_entry_safe(struct queued_twopc, q2, tmp, &resource->queued_twopc, w.list){
#else
	list_for_each_entry_safe(q2, tmp, &resource->queued_twopc, w.list){
#endif 
		if (q2->reply.tid == q->reply.tid &&
			q2->reply.initiator_node_id == q->reply.initiator_node_id)
			list_move_tail(&q2->w.list, &work_list); 
	}
	spin_unlock_irq(&resource->queued_twopc_lock); 


	while (true, true){
		if (jiffies - q->start_jif >= t || cancel) {
			if (!cancel)
				drbd_info(connection, "Rejecting concurrent "
				"remote state change %u because of "
				"state change %u takes too long\n",
				q->reply.tid,
				connection->resource->twopc_reply.tid);
			drbd_send_twopc_reply(connection, P_TWOPC_RETRY, &q->reply);
		}
		else {
			process_twopc(connection, &q->reply, &q->packet_info, q->start_jif);
		}

		kref_put(&connection->kref, drbd_destroy_connection);
#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-1466: need to clear starting_queued_twopc when it is being freed.
		spin_lock_irq(&resource->req_lock);
		if (resource->starting_queued_twopc == q)
			resource->starting_queued_twopc = NULL;
		spin_unlock_irq(&resource->req_lock);
#endif
		kfree(q);

		q = list_first_entry_or_null(&work_list, struct queued_twopc, w.list); 
		if (q) {
			list_del(&q->w.list); 
			connection = q->connection; 
		}
		else
			break; 
	}
	return 0;
}
#ifdef _WIN32
void queued_twopc_timer_fn(PKDPC Dpc, PVOID data, PVOID arg1, PVOID arg2)
#else
void queued_twopc_timer_fn(unsigned long data)
#endif
{
	UNREFERENCED_PARAMETER(arg1);
	UNREFERENCED_PARAMETER(arg2);
	UNREFERENCED_PARAMETER(Dpc);

	if (data == NULL)
		return;

	struct drbd_resource *resource = (struct drbd_resource *) data;
	struct queued_twopc *q;
	unsigned long irq_flags;
	unsigned long t = twopc_timeout(resource) / 4;

	spin_lock_irqsave(&resource->queued_twopc_lock, irq_flags);
	q = list_first_entry_or_null(&resource->queued_twopc, struct queued_twopc, w.list);
	if (q) {
		if (jiffies - q->start_jif >= t){
			resource->starting_queued_twopc = q; 
			list_del(&q->w.list);
		}
#ifdef _WIN32 
		// DW-1467 : If you add q not deleted from queued_twopc list to work list, queued_twopc list will be broken.
		else
		{
			q = NULL;
		}
#endif
	}
	spin_unlock_irqrestore(&resource->queued_twopc_lock, irq_flags);

	if (q) {
		q->w.cb = &queued_twopc_work;
		drbd_queue_work(&resource->work , &q->w);
	}
}

void queue_queued_twopc(struct drbd_resource *resource)
{
	struct queued_twopc *q;
	unsigned long irq_flags;

	spin_lock_irqsave(&resource->queued_twopc_lock, irq_flags);
	q = list_first_entry_or_null(&resource->queued_twopc, struct queued_twopc, w.list);
	if (q) {
		resource->starting_queued_twopc = q;
#ifdef _WIN32
		smp_mb();
#else
		mb();
#endif
		list_del(&q->w.list);
		arm_queue_twopc_timer(resource);
	}
	spin_unlock_irqrestore(&resource->queued_twopc_lock, irq_flags);

	if (!q)
		return;

	q->w.cb = &queued_twopc_work;
	drbd_queue_work(&resource->work , &q->w);
}

static int abort_starting_twopc(struct drbd_resource *resource, struct twopc_reply *twopc)
{
	struct queued_twopc *q = resource->starting_queued_twopc;

	if (q && q->reply.tid == twopc->tid) {
		q->reply.is_aborted = 1;
		return 0;
	}

	return -ENOENT;
}

static int abort_queued_twopc(struct drbd_resource *resource, struct twopc_reply *twopc)
{
	struct queued_twopc *q;
	unsigned long irq_flags;

	spin_lock_irqsave(&resource->queued_twopc_lock, irq_flags);
#ifdef _WIN32
	list_for_each_entry(struct queued_twopc, q, &resource->queued_twopc, w.list) {
#else
	list_for_each_entry(q, &resource->queued_twopc, w.list) {
#endif
		if (q->reply.tid == twopc->tid) {
			list_del(&q->w.list);
			goto found;
		}
	}
	q = NULL;
found:
	spin_unlock_irqrestore(&resource->queued_twopc_lock, irq_flags);

	if (q) {
		kref_put(&q->connection->kref, drbd_destroy_connection);
		kfree(q);
		return 0;
	}

	return -ENOENT;
}

static int receive_twopc(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct p_twopc_request *p = pi->data;
	struct twopc_reply reply;
	int rv;

	reply.vnr = pi->vnr;
	reply.tid = be32_to_cpu(p->tid);
	reply.initiator_node_id = be32_to_cpu(p->initiator_node_id);
	reply.target_node_id = be32_to_cpu(p->target_node_id);
	reply.reachable_nodes = directly_connected_nodes(resource, NOW) |
				NODE_MASK(resource->res_opts.node_id);
	reply.primary_nodes = 0;
	reply.weak_nodes = 0;
	reply.is_disconnect = 0;
	reply.is_aborted = 0;

	rv = process_twopc(connection, &reply, pi, jiffies);

	return rv;
}

static void nested_twopc_abort(struct drbd_resource *resource, int vnr, enum drbd_packet cmd,
			       struct p_twopc_request *request)
{
	struct drbd_connection *connection;
	u64 nodes_to_reach, reach_immediately, im;

	spin_lock_irq(&resource->req_lock);
	nodes_to_reach = be64_to_cpu(request->nodes_to_reach);
	reach_immediately = directly_connected_nodes(resource, NOW) & nodes_to_reach;
	nodes_to_reach &= ~(reach_immediately | NODE_MASK(resource->res_opts.node_id));
	request->nodes_to_reach = cpu_to_be64(nodes_to_reach);
	spin_unlock_irq(&resource->req_lock);

	for_each_connection_ref(connection, im, resource) {
		u64 mask = NODE_MASK(connection->peer_node_id);
		if (reach_immediately & mask)
			conn_send_twopc_request(connection, vnr, cmd, request);
	}
}

static bool is_prepare(enum drbd_packet cmd)
{
    return cmd == P_TWOPC_PREP_RSZ || cmd == P_TWOPC_PREPARE;
}


enum determine_dev_size
drbd_commit_size_change(struct drbd_device *device, struct resize_parms *rs, u64 nodes_to_reach)
{
	struct twopc_resize *tr = &device->resource->twopc_resize;
    enum determine_dev_size dd;
    uint64_t my_usize;

    if (!get_ldev(device)) {
        char ppb[10];

		drbd_set_my_capacity(device, tr->new_size);
		drbd_info(device, "size = %s (%llu KB)\n", ppsize(ppb, sizeof(ppb), tr->new_size >> 1),
			(unsigned long long)tr->new_size >> 1);
        return DS_UNCHANGED; /* Not entirely true, but we are diskless... */
    }

    rcu_read_lock();
    my_usize = rcu_dereference(device->ldev->disk_conf)->disk_size;
    rcu_read_unlock();

	if (my_usize != tr->user_size) {
        struct disk_conf *old_disk_conf, *new_disk_conf;

#ifdef _WIN32
		new_disk_conf = kzalloc(sizeof(struct disk_conf), GFP_KERNEL, 'E7DW');
#else
        new_disk_conf = kzalloc(sizeof(struct disk_conf), GFP_KERNEL);
#endif
        if (!new_disk_conf) {
            drbd_err(device, "Allocation of new disk_conf failed\n");
			device->ldev->disk_conf->disk_size = tr->user_size;
            goto cont;
        }

        old_disk_conf = device->ldev->disk_conf;
        *new_disk_conf = *old_disk_conf;
		new_disk_conf->disk_size = tr->user_size;

#ifdef _WIN32
		synchronize_rcu_w32_wlock();
#endif
        rcu_assign_pointer(device->ldev->disk_conf, new_disk_conf);
        synchronize_rcu();
        kfree(old_disk_conf);

        drbd_info(device, "New u_size %llu sectors\n",
			(unsigned long long)tr->user_size);
    }
cont:
	dd = drbd_determine_dev_size(device, tr->new_size, tr->dds_flags | DDSF_2PC, rs);

	if (dd > DS_UNCHANGED) { /* DS_SHRUNK, DS_GREW, DS_GREW_FROM_ZERO */
		struct drbd_peer_device *peer_device;
		u64 im;

		for_each_peer_device_ref(peer_device, im, device) {
			if (peer_device->repl_state[NOW] != L_ESTABLISHED ||
				peer_device->disk_state[NOW] < D_INCONSISTENT)
				continue;

			/* update cached sizes, relevant for the next handshake
			* of a currently unconnected peeer. */
			peer_device->c_size = tr->new_size;
			peer_device->u_size = tr->user_size;
			if (dd >= DS_GREW) {
				if (tr->new_size > peer_device->d_size)
					peer_device->d_size = tr->new_size;

				if (tr->new_size > peer_device->max_size)
					peer_device->max_size = tr->new_size;
			}
			else if (dd == DS_SHRUNK) {
				if (tr->new_size < peer_device->d_size)
					peer_device->d_size = tr->new_size;

				if (tr->new_size < peer_device->max_size)
					peer_device->max_size = tr->new_size;
			}
		}
	}
	
	if (dd == DS_GREW && !(tr->dds_flags & DDSF_NO_RESYNC)) {
		struct drbd_resource *resource = device->resource;
		const int my_node_id = resource->res_opts.node_id;
		struct drbd_peer_device *peer_device;
		u64 im;

		for_each_peer_device_ref(peer_device, im, device) {
			if (peer_device->repl_state[NOW] != L_ESTABLISHED ||
				peer_device->disk_state[NOW] < D_INCONSISTENT)
				continue;

			if (tr->diskful_primary_nodes) {
				if (tr->diskful_primary_nodes & NODE_MASK(my_node_id)) {
					enum drbd_repl_state resync;
					if (peer_device->connection->peer_role[NOW] == R_SECONDARY) {
						resync = L_SYNC_SOURCE;
					}
					else /* peer == R_PRIMARY */ {
						resync = peer_device->node_id < my_node_id ?
						L_SYNC_TARGET : L_SYNC_SOURCE;
					}
					drbd_start_resync(peer_device, resync);
				}
				else {
					if (peer_device->connection->peer_role[NOW] == R_PRIMARY)
						drbd_start_resync(peer_device, L_SYNC_TARGET);
					/* else  no resync */
				}
			}
			else {
				if (resource->twopc_parent_nodes & NODE_MASK(peer_device->node_id))
					drbd_start_resync(peer_device, L_SYNC_TARGET);
				else if (nodes_to_reach & NODE_MASK(peer_device->node_id))
					drbd_start_resync(peer_device, L_SYNC_SOURCE);
				/* else  no resync */
			}
		}
	}

    put_ldev(device);
    return dd;
}

enum drbd_state_rv drbd_support_2pc_resize(struct drbd_resource *resource)
{
    struct drbd_connection *connection;
    enum drbd_state_rv rv = SS_SUCCESS;

    rcu_read_lock();
    for_each_connection_rcu(connection, resource) {
        if (connection->cstate[NOW] == C_CONNECTED &&
            connection->agreed_pro_version < 112) {
            rv = SS_NOT_SUPPORTED;
            break;
        }
    }
    rcu_read_unlock();

    return rv;
}

static int process_twopc(struct drbd_connection *connection,
			 struct twopc_reply *reply,
			 struct packet_info *pi,
#ifdef _WIN32
             ULONG_PTR receive_jif)
#else
			 unsigned long receive_jif)
#endif
{
	if (connection == NULL) {
		WDRBD_ERROR("process_twopc connection is null\n");
	}

	struct drbd_connection *affected_connection = connection;
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device = NULL;
	struct p_twopc_request *p = pi->data;
#ifdef _WIN32
	union drbd_state mask = { 0, };
	union drbd_state val = { 0, };
#else
	union drbd_state mask = {}, val = {};
#endif
	enum chg_state_flags flags = CS_VERBOSE | CS_LOCAL_ONLY;
	enum drbd_state_rv rv = SS_SUCCESS;
	enum csc_rv csc_rv;


	/* Check for concurrent transactions and duplicate packets. */
	spin_lock_irq(&resource->req_lock);
	
	csc_rv = check_concurrent_transactions(resource, reply);

#ifdef _WIN32_TWOPC
	drbd_info(resource, "[TWOPC:%u] target_node_id (%d) csc_rv (%d) primary_nodes (%d) pi->cmd (%s)\n", 
					reply->tid, reply->target_node_id, csc_rv, reply->primary_nodes, drbd_packet_name(pi->cmd));
#endif
	if (csc_rv == CSC_CLEAR && pi->cmd != P_TWOPC_ABORT) {
		if (!is_prepare(pi->cmd)) {
			/* We have committed or aborted this transaction already. */
			spin_unlock_irq(&resource->req_lock);
			drbd_debug(connection, "Ignoring %s packet %u\n",
				   drbd_packet_name(pi->cmd),
				   reply->tid);
#ifdef _WIN32 // DW-1291 provide LastPrimary Information for Peer Primary P_TWOPC_COMMIT
			if(resource->role[NEW] == R_SECONDARY && reply->primary_nodes != 0 ) {
				struct drbd_device *device;
				int vnr;
				drbd_info(resource, "Peer node is Primary. LastPrimary flag set [TWOPC:%u] target_node_id (%d) primary_nodes (%d) pi->cmd (%s)\n", 
					reply->tid, reply->target_node_id, reply->primary_nodes, drbd_packet_name(pi->cmd));
				idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
					if(get_ldev_if_state(device, D_NEGOTIATING)) {
						drbd_md_clear_flag (device, MDF_LAST_PRIMARY );
						put_ldev(device);		
						drbd_md_sync_if_dirty(device);
					} else {
						drbd_info(resource, "LastPrimary got it! But disk state is diskless or failed device->disk_state:%d\n",device->disk_state[NEW]);
					}
				} 
			}
#endif			
			return 0;
		}
		if (reply->is_aborted) {
			spin_unlock_irq(&resource->req_lock);
			return 0;
		}
		resource->starting_queued_twopc = NULL;
		resource->remote_state_change = true;
		resource->twopc_type = pi->cmd == P_TWOPC_PREPARE ? TWOPC_STATE_CHANGE : TWOPC_RESIZE;
		resource->twopc_prepare_reply_cmd = 0;
		resource->twopc_parent_nodes = NODE_MASK(connection->peer_node_id);
		clear_bit(TWOPC_EXECUTED, &resource->flags);
	} else if (csc_rv == CSC_MATCH && !is_prepare(pi->cmd)) {
		flags |= CS_PREPARED;

		if (test_and_set_bit(TWOPC_EXECUTED, &resource->flags)) {
			spin_unlock_irq(&resource->req_lock);
			drbd_info(connection, "Ignoring redundant %s packet %u.\n",
					drbd_packet_name(pi->cmd),
					reply->tid);
			return 0;
		}
	} else if (csc_rv == CSC_ABORT_LOCAL && is_prepare(pi->cmd)) {
		enum alt_rv alt_rv;

		drbd_info(connection, "Aborting local state change %u to yield to remote "
			  "state change %u.\n",
			  resource->twopc_reply.tid,
			  reply->tid);
		alt_rv = abort_local_transaction(resource, reply->tid);
		if (alt_rv == ALT_MATCH) {
			/* abort_local_transaction() comes back unlocked in this case ... */
			goto match; 
		} else if (alt_rv == ALT_TIMEOUT){
			/* abort_local_transaction() comes back unlocked in this case ... */
			drbd_info(connection, "Aborting local state change %u "
				  "failed. Rejecting remote state change %u.\n",
				  resource->twopc_reply.tid,
				  reply->tid);
			drbd_send_twopc_reply(connection, P_TWOPC_RETRY, reply);
			return 0;
		}
		/*abort_local_transaction() returned with the req_lock */
		if (reply->is_aborted) {
			spin_unlock_irq(&resource->req_lock);
			return 0;
		}
		resource->starting_queued_twopc = NULL;
		resource->remote_state_change = true;
		resource->twopc_type = pi->cmd == P_TWOPC_PREPARE ? TWOPC_STATE_CHANGE : TWOPC_RESIZE;
		resource->twopc_parent_nodes = NODE_MASK(connection->peer_node_id);
		resource->twopc_prepare_reply_cmd = 0;
		clear_bit(TWOPC_EXECUTED, &resource->flags);
	} else if (pi->cmd == P_TWOPC_ABORT) {
		/* crc_rc != CRC_MATCH */
		int err;

		err = abort_starting_twopc(resource, reply);
		spin_unlock_irq(&resource->req_lock);
		if (err) {
			err = abort_queued_twopc(resource, reply);
			if (err)
				drbd_info(connection, "Ignoring %s packet %u.\n",
					  drbd_packet_name(pi->cmd),
					  reply->tid);
		}

#ifdef _WIN32_TWOPC
		drbd_info(resource, "[TWOPC:%u] target_node_id (%d) abort_starting_twopc \n", 
					reply->tid, reply->target_node_id);
#endif
		nested_twopc_abort(resource, pi->vnr, pi->cmd, p);
		return 0;
	} else {
		spin_unlock_irq(&resource->req_lock);

		if (csc_rv == CSC_REJECT) {
		reject:
			drbd_info(connection, "Rejecting concurrent "
				  "remote state change %u because of "
				  "state change %u\n",
				  reply->tid,
				  resource->twopc_reply.tid);
			drbd_send_twopc_reply(connection, P_TWOPC_RETRY, reply);
			return 0;
		}

		if (is_prepare(pi->cmd)) {
			if (csc_rv == CSC_QUEUE) {
				int err = queue_twopc(connection, reply, pi);
				if (err)
					goto reject;
			} else if (csc_rv == CSC_TID_MISS) {
				goto reject;
			} else if (csc_rv == CSC_MATCH) {
				/* We have prepared this transaction already. */
				enum drbd_packet reply_cmd;

			match: 
				spin_lock_irq(&resource->req_lock);
				resource->twopc_parent_nodes |= NODE_MASK(connection->peer_node_id);
				reply_cmd = resource->twopc_prepare_reply_cmd;
				if (!reply_cmd) {
					kref_get(&connection->kref);
					kref_debug_get(&connection->kref_debug, 9);
#ifdef _WIN32	// DW-1480 : Do not add duplicate twopc_parent_list to twopc_parents.
					if(list_add_valid(&connection->twopc_parent_list, &resource->twopc_parents))
					{	
						list_add(&connection->twopc_parent_list,
							&resource->twopc_parents);
					}
					else
					{
						drbd_info(connection, "twopc_parent_list(%p) already added.\n", &connection->twopc_parent_list);
						kref_debug_put(&connection->kref_debug, 9);
						kref_put(&connection->kref, drbd_destroy_connection);
					}
#else
					list_add(&connection->twopc_parent_list,
						&resource->twopc_parents);
#endif
				}
				spin_unlock_irq(&resource->req_lock);


				if (reply_cmd){
					drbd_send_twopc_reply(connection, reply_cmd,
						&resource->twopc_reply);
				}else {
					/* if a node sends us a prepare, that means he has
					prepared this himsilf successfully. */
					
#ifdef _WIN32 // DW-1411 : Not supported dual primaries, set TWOPC_NO bit when local node is Primary. 
					if (resource->role[NOW] == R_PRIMARY && val.role == R_PRIMARY){
						set_bit(TWOPC_NO, &connection->flags);
					}
					else{
						set_bit(TWOPC_YES, &connection->flags);
					}
#else
					set_bit(TWOPC_YES, &connection->flags);
#endif
					if (cluster_wide_reply_ready(resource)) {
						if (resource->twopc_work.cb == NULL) {
							resource->twopc_work.cb = nested_twopc_work;
							drbd_queue_work(&resource->work, &resource->twopc_work);
						}
					}
				}
			}
		} else {
			drbd_info(connection, "Ignoring %s packet %u "
				  "current processing state change %u\n",
				  drbd_packet_name(pi->cmd),
				  reply->tid,
				  resource->twopc_reply.tid);
		}
		return 0;
	}

	if (reply->initiator_node_id != (int)connection->peer_node_id) {
		/*
		 * This is an indirect request.  Unless we are directly
		 * connected to the initiator as well as indirectly, we don't
		 * have connection or peer device objects for this peer.
		 */
		for_each_connection(affected_connection, resource) {
			/* for_each_connection() protected by holding req_lock here */
			if (reply->initiator_node_id == (int)affected_connection->peer_node_id)
				goto directly_connected;
		}
		/* only indirectly connected */
		affected_connection = NULL;
	}

    directly_connected:
	if (reply->target_node_id != -1 &&
		reply->target_node_id != (int)resource->res_opts.node_id) {
		affected_connection = NULL;
	}

	if (resource->twopc_type == TWOPC_STATE_CHANGE) {
		mask.i = be32_to_cpu(p->mask);
		val.i = be32_to_cpu(p->val);
	}
	
	if (affected_connection && affected_connection->cstate[NOW] < C_CONNECTED &&
		mask.conn == 0)
		affected_connection = NULL;

	if (mask.conn == conn_MASK) {
		u64 m = NODE_MASK(reply->initiator_node_id);

		if (val.conn == C_CONNECTED)
			reply->reachable_nodes |= m;
		if (val.conn == C_DISCONNECTING) {
			reply->reachable_nodes &= ~m;
			reply->is_disconnect = 1;
		}
	}

	if (pi->vnr != -1 && affected_connection) {
		peer_device = conn_peer_device(affected_connection, pi->vnr);
		/* If we do not know the peer_device, then we are fine with
		   whatever is going on in the cluster. E.g. detach and del-minor
		   one each node, one after the other */

		affected_connection = NULL; /* It is intended for a peer_device! */
	}

	if (pi->cmd == P_TWOPC_PREPARE) {
		if ((mask.peer == role_MASK && val.peer == R_PRIMARY) ||
		    (mask.peer != role_MASK && resource->role[NOW] == R_PRIMARY)) {
			reply->primary_nodes = NODE_MASK(resource->res_opts.node_id);
			reply->weak_nodes = ~reply->reachable_nodes;
		}
	}

	if (pi->cmd == P_TWOPC_PREP_RSZ) {
		struct drbd_device *device;
#ifdef _WIN32
		device = (peer_device ? peer_device : conn_peer_device(connection, pi->vnr))->device;
#else
		device = (peer_device ?: conn_peer_device(connection, pi->vnr))->device;
#endif
		if (get_ldev(device)) {
			if (resource->role[NOW] == R_PRIMARY)
				reply->diskful_primary_nodes = NODE_MASK(resource->res_opts.node_id);
			reply->max_possible_size = drbd_local_max_size(device);
			put_ldev(device);
		}
		else {
			reply->max_possible_size = DRBD_MAX_SECTORS_FLEX;
			reply->diskful_primary_nodes = 0;
		}
		resource->twopc_resize.dds_flags = be16_to_cpu(p->dds_flags);
		resource->twopc_resize.user_size = be64_to_cpu(p->user_size);
	}


	resource->twopc_reply = *reply;
	spin_unlock_irq(&resource->req_lock);

	switch(pi->cmd) {
	case P_TWOPC_PREPARE:
		drbd_info(connection, "Preparing remote state change %u "
			  "(primary_nodes=%lX, weak_nodes=%lX)\n",
			  reply->tid,
			  (unsigned long)reply->primary_nodes,
			  (unsigned long)reply->weak_nodes);
		flags |= CS_PREPARE;
		break;
	case P_TWOPC_PREP_RSZ:
		drbd_info(connection, "Preparing remote state change %u "
			"(local_max_size = %llu KiB)\n",
			reply->tid, (unsigned long long)reply->max_possible_size >> 1);
		flags |= CS_PREPARE;
		break;
	case P_TWOPC_ABORT:
		drbd_info(connection, "Aborting remote state change %u\n",
			  reply->tid);
		flags |= CS_ABORT;
		break;
	case P_TWOPC_COMMIT:
		drbd_info(connection, "Committing remote state change %u\n",
			  reply->tid);
		break;
	default:
		BUG();
	}


#ifdef _WIN32_TWOPC
	drbd_info(resource, "[TWOPC:%u] target_node_id(%d) conn(%s) repl(%s) disk(%s) pdsk(%s) role(%s) peer(%s) flags (%d) \n",
				reply->tid,
				reply->target_node_id,
				mask.conn == conn_MASK ? drbd_conn_str(val.conn) : "-",
				mask.conn == conn_MASK ? ((val.conn < conn_MASK && val.conn > C_CONNECTED) ? drbd_repl_str(val.conn) : "-") : "-",
				mask.disk == disk_MASK ? drbd_disk_str(val.disk) : "-",
				mask.pdsk == pdsk_MASK ? drbd_disk_str(val.pdsk) : "-",
				mask.role == role_MASK ? drbd_role_str(val.role) : "-",
				mask.peer == peer_MASK ? drbd_role_str(val.peer) : "-",
				flags);
#endif
		
	switch (resource->twopc_type) {
	case TWOPC_STATE_CHANGE:
		if (flags & CS_PREPARED)
			reply->primary_nodes = be64_to_cpu(p->primary_nodes);

		if (peer_device)
			rv = change_peer_device_state(peer_device, mask, val, flags);
		else if (affected_connection)
			rv = change_connection_state(affected_connection,
			mask, val, reply, flags | CS_IGN_OUTD_FAIL);
		else
			rv = far_away_change(connection, mask, val, reply, flags);
		break;
	case TWOPC_RESIZE:
		if (flags & CS_PREPARE)
			rv = drbd_support_2pc_resize(resource);		
		break;
	}
	
	// DW-1948 set standalone and split-brain after two primary check
	if (rv == SS_TWO_PRIMARIES) {
		change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
		drbd_alert(connection, "Split-Brain since more primaries than allowed; dropping connection!\n");
		drbd_khelper(NULL, connection, "split-brain");
		return 0;
	}

	if (flags & CS_PREPARE) {
		spin_lock_irq(&resource->req_lock);
		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 9);
#ifdef _WIN32	//DW-1480 : Do not add duplicate twopc_parent_list to twopc_parents.
		if (list_add_valid(&connection->twopc_parent_list, &resource->twopc_parents))
		{						
			list_add(&connection->twopc_parent_list, &resource->twopc_parents);
		}
		else
		{
			drbd_info(connection, "twopc_parent_list(%p) already added.\n", &connection->twopc_parent_list);
			kref_debug_put(&connection->kref_debug, 9);
			kref_put(&connection->kref, drbd_destroy_connection);
		}
#else
		list_add(&connection->twopc_parent_list, &resource->twopc_parents);
#endif
		mod_timer(&resource->twopc_timer, receive_jif + twopc_timeout(resource));

		spin_unlock_irq(&resource->req_lock);

		if (rv >= SS_SUCCESS) {
			nested_twopc_request(resource, pi->vnr, pi->cmd, p);
		} else {
			enum drbd_packet cmd = (rv == SS_IN_TRANSIENT_STATE) ?
				P_TWOPC_RETRY : P_TWOPC_NO;
#ifdef _WIN32 // DW-1411 : when we get the prepare packet mutiple times, miss set twopc_prepare_reply_cmd. 
			if (cmd == P_TWOPC_NO)
				resource->twopc_prepare_reply_cmd = cmd;
#endif 
			drbd_send_twopc_reply(connection, cmd, reply);
		}
	} else {
		if (flags & CS_PREPARED)
			del_timer(&resource->twopc_timer);

		nested_twopc_request(resource, pi->vnr, pi->cmd, p);

		if (resource->twopc_type == TWOPC_RESIZE && flags & CS_PREPARED && !(flags & CS_ABORT)) {
			struct twopc_resize *tr = &resource->twopc_resize;
			struct drbd_device *device;

			tr->diskful_primary_nodes = be64_to_cpu(p->diskful_primary_nodes);
			tr->new_size = be64_to_cpu(p->exposed_size);
#ifdef _WIN32
			device = (peer_device ? peer_device : conn_peer_device(connection, pi->vnr))->device;
#else
			device = (peer_device ? : conn_peer_device(connection, pi->vnr))->device;
#endif
			drbd_commit_size_change(device, NULL, be64_to_cpu(p->nodes_to_reach));
			rv = SS_SUCCESS;
		}

		clear_remote_state_change(resource);

#ifdef _WIN32 // DW-1291 provide LastPrimary Information for Peer Primary P_TWOPC_COMMIT
		if( (resource->role[NEW] != R_PRIMARY) && (reply->primary_nodes != 0) ) {
			struct drbd_device *device;
			int vnr;
			drbd_info(resource, "Peer node is Primary. LastPrimary flag set [TWOPC:%u] after clear_remote_state_change target_node_id (%d) primary_nodes (%d) pi->cmd (%s)\n", 
				reply->tid, reply->target_node_id, reply->primary_nodes, drbd_packet_name(pi->cmd));
			idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
				if(get_ldev_if_state(device, D_NEGOTIATING)) {
					drbd_md_clear_flag (device, MDF_LAST_PRIMARY );
					put_ldev(device);
					drbd_md_sync_if_dirty(device);
				} else {
					drbd_info(resource, "LastPrimary got it! But disk state is diskless or failed device->disk_state:%d\n", device->disk_state[NEW]);
				}
			}
		}
#endif
		if (peer_device && rv >= SS_SUCCESS && !(flags & CS_ABORT))
			drbd_md_sync_if_dirty(peer_device->device);

		if (rv >= SS_SUCCESS && !(flags & CS_ABORT)) {
			struct drbd_device *device;
			int vnr;

			if (affected_connection &&
			    mask.conn == conn_MASK && val.conn == C_CONNECTED)
				conn_connect2(connection);

#ifdef _WIN32
            idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
#else
			idr_for_each_entry(&resource->devices, device, vnr) {
#endif
				u64 nedu = device->next_exposed_data_uuid;
				if (!nedu)
					continue;
				if (device->disk_state[NOW] < D_INCONSISTENT)
					drbd_set_exposed_data_uuid(device, nedu);
				device->next_exposed_data_uuid = 0;
			}
		}
	}

	return 0;
}

static void try_to_get_resynced(struct drbd_device *device)
{
	int best_hg = -3000;
	struct drbd_peer_device *best_peer_device = NULL;
	struct drbd_peer_device *peer_device;

	if (!get_ldev(device))
		return;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		int hg, rule_nr, peer_node_id;
		if (peer_device->disk_state[NOW] == D_UP_TO_DATE) {
			hg = drbd_uuid_compare(peer_device, &rule_nr, &peer_node_id);
			drbd_info(peer_device, "hg = %d\n", hg);
			if (hg <= 0 && hg > best_hg) {
				best_hg = hg;
				best_peer_device = peer_device;
			}
		}
	}
	rcu_read_unlock();
	peer_device = best_peer_device;

	if (peer_device) {
		drbd_resync(peer_device, DISKLESS_PRIMARY);
		drbd_send_uuids(peer_device, UUID_FLAG_RESYNC | UUID_FLAG_DISKLESS_PRIMARY, 0);
	}
	put_ldev(device);
}


static int receive_state(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device = NULL;
	enum drbd_repl_state *repl_state;
	struct drbd_device *device = NULL;
	struct p_state *p = pi->data;
	union drbd_state old_peer_state, peer_state;
	enum drbd_disk_state peer_disk_state, new_disk_state = D_MASK;
	enum drbd_repl_state new_repl_state;
	bool peer_was_resync_target, try_to_get_resync = false;
	int rv;

	if (pi->vnr != -1) {
		peer_device = conn_peer_device(connection, pi->vnr);
		if (!peer_device)
			return config_unknown_volume(connection, pi);
		device = peer_device->device;
	}

	peer_state.i = be32_to_cpu(p->state);

	if (connection->agreed_pro_version < 110) {
		/* Before drbd-9.0 there was no D_DETACHING it was D_FAILED... */
		if (peer_state.disk >= D_DETACHING)
			peer_state.disk++;
		if (peer_state.pdsk >= D_DETACHING)
			peer_state.pdsk++;
	}

	if (pi->vnr == -1) {
		if (peer_state.role == R_SECONDARY) {
			unsigned long irq_flags;

			begin_state_change(resource, &irq_flags, CS_HARD | CS_VERBOSE);
			__change_peer_role(connection, R_SECONDARY, __FUNCTION__);
			rv = end_state_change(resource, &irq_flags, __FUNCTION__);
			if (rv < SS_SUCCESS)
				goto fail;
		}
		return 0;
    }

	peer_disk_state = peer_state.disk;
	if (peer_state.disk == D_NEGOTIATING) {
		peer_disk_state = peer_device->uuid_flags & UUID_FLAG_INCONSISTENT ?
			D_INCONSISTENT : D_CONSISTENT;
		drbd_info(device, "real peer disk state = %s\n", drbd_disk_str(peer_disk_state));
	}

	spin_lock_irq(&resource->req_lock);
	old_peer_state = drbd_get_peer_device_state(peer_device, NOW);
	spin_unlock_irq(&resource->req_lock);
 retry:
	new_repl_state = max_t(enum drbd_repl_state, old_peer_state.conn, L_OFF);

	/* If some other part of the code (ack_receiver thread, timeout)
	 * already decided to close the connection again,
	 * we must not "re-establish" it here. */
	if (old_peer_state.conn <= C_TEAR_DOWN)
		return -ECONNRESET;

	peer_was_resync_target =
		connection->agreed_pro_version >= 110 ?
		peer_device->last_repl_state == L_SYNC_TARGET ||
		peer_device->last_repl_state == L_PAUSED_SYNC_T
		:
		true;
	/* If this is the "end of sync" confirmation, usually the peer disk
	 * was D_INCONSISTENT or D_CONSISTENT. (Since the peer might be
	 * weak we do not know anything about its new disk state)
	 */
	if (peer_was_resync_target &&
	    (old_peer_state.pdsk == D_INCONSISTENT || old_peer_state.pdsk == D_CONSISTENT) &&
	    old_peer_state.conn > L_ESTABLISHED && old_peer_state.disk >= D_OUTDATED) {
		/* If we are (becoming) SyncSource, but peer is still in sync
		 * preparation, ignore its uptodate-ness to avoid flapping, it
		 * will change to inconsistent once the peer reaches active
		 * syncing states.
		 * It may have changed syncer-paused flags, however, so we
		 * cannot ignore this completely. */
		if (peer_state.conn > L_ESTABLISHED &&
		    peer_state.conn < L_SYNC_SOURCE)
			peer_disk_state = D_INCONSISTENT;

		/* if peer_state changes to connected at the same time,
		 * it explicitly notifies us that it finished resync.
		 * Maybe we should finish it up, too? */
		else if (peer_state.conn == L_ESTABLISHED) {
			bool finish_now = false;

			if (old_peer_state.conn == L_WF_BITMAP_S) {
				spin_lock_irq(&resource->req_lock);
				if (peer_device->repl_state[NOW] == L_WF_BITMAP_S)
					peer_device->resync_finished_pdsk = peer_state.disk;
				else if (peer_device->repl_state[NOW] == L_SYNC_SOURCE)
					finish_now = true;
				spin_unlock_irq(&resource->req_lock);
			}

			if (finish_now || old_peer_state.conn == L_SYNC_SOURCE ||
			    old_peer_state.conn == L_PAUSED_SYNC_S) {
				/* TODO: Since DRBD9 we experience that SyncSource still has
				   bits set... NEED TO UNDERSTAND AND FIX! */
				if (drbd_bm_total_weight(peer_device) > peer_device->rs_failed)
				{
					// DW-1199: print log for remaining out-of-sync to recogsize which sector has to be traced
					drbd_info(peer_device, "SyncSource still sees bits set!! FIXME\n");
					if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_OOS)
					{
						ULONG_PTR bit = 0;
						sector_t sector = 0;
						ULONG_PTR bm_resync_fo = 0;

						do
						{
							bit = drbd_bm_find_next(peer_device, bm_resync_fo);
							if (bit == DRBD_END_OF_BITMAP)
								break;

							sector = BM_BIT_TO_SECT(bit);

							printk("%s["OOS_TRACE_STRING"] pnode-id(%d), bitmap_index(%d), out-of-sync for sector(%llu) is remaining\n", KERN_OOS,
								peer_device->node_id, peer_device->bitmap_index, sector);

							bm_resync_fo = bit + 1;

						} while (true, true);
					}
				}

				drbd_resync_finished(peer_device, peer_state.disk);
				peer_device->last_repl_state = peer_state.conn;
			}
			return 0;
		}
	}

	/* explicit verify finished notification, stop sector reached. */
	if (old_peer_state.conn == L_VERIFY_T && old_peer_state.disk == D_UP_TO_DATE &&
	    peer_state.conn == C_CONNECTED && peer_disk_state == D_UP_TO_DATE) {
		ov_out_of_sync_print(peer_device);
		drbd_resync_finished(peer_device, D_MASK);
		peer_device->last_repl_state = peer_state.conn;
		return 0;
	}

	/* Start resync after AHEAD/BEHIND */
	if (connection->agreed_pro_version >= 110 &&
#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-1085 fix resync stop in the state of 'PausedSyncS/Behind'.
		// L_PAUSED_SYNC_S also call drbd_start_resync(). L_BEHIND will transition to L_PAUSED_SYNC_T.
		(peer_state.conn == L_SYNC_SOURCE || peer_state.conn == L_PAUSED_SYNC_S) &&
		// DW-2003 resync is also initiated when the current status is L_ESTABLISHED.
		(old_peer_state.conn == L_ESTABLISHED || 
		old_peer_state.conn == L_BEHIND)) {
#else
		peer_state.conn == L_SYNC_SOURCE && old_peer_state.conn == L_BEHIND) {
#endif
		drbd_info(peer_device, "peer is SyncSource. change to SyncTarget\n"); // DW-1518
		drbd_start_resync(peer_device, L_SYNC_TARGET);
		return 0;
	}

	/* peer says his disk is inconsistent, while we think it is uptodate,
	 * and this happens while the peer still thinks we have a sync going on,
	 * but we think we are already done with the sync.
	 * We ignore this to avoid flapping pdsk.
	 * This should not happen, if the peer is a recent version of drbd. */
	if (old_peer_state.pdsk == D_UP_TO_DATE && peer_disk_state == D_INCONSISTENT &&
	    old_peer_state.conn == L_ESTABLISHED && peer_state.conn > L_SYNC_SOURCE)
		peer_disk_state = D_UP_TO_DATE;

	if (new_repl_state == L_OFF)
		new_repl_state = L_ESTABLISHED;

	if (peer_state.conn == L_AHEAD)
	{
		if (old_peer_state.conn != L_BEHIND)
		{
			drbd_info(peer_device, "peer is Ahead. change to Behind mode\n"); // DW-1518
		}
		new_repl_state = L_BEHIND;
	}

	if (peer_device->uuids_received &&
	    peer_state.disk >= D_NEGOTIATING &&
	    get_ldev_if_state(device, D_NEGOTIATING)) {
		bool consider_resync;

		/* if we established a new connection */
		consider_resync = (old_peer_state.conn < L_ESTABLISHED);
		/* if we have both been inconsistent, and the peer has been
		 * forced to be UpToDate with --force */
#ifdef _WIN32 // DW-778 
		if (device->disk_state[NOW] == D_INCONSISTENT || peer_state.disk == D_INCONSISTENT &&
			// DW-1359: to avoid start resync when it's already running.
			(peer_state.conn < L_SYNC_SOURCE || peer_state.conn > L_PAUSED_SYNC_T))
#endif
			consider_resync |= test_bit(CONSIDER_RESYNC, &peer_device->flags);
		/* if we had been plain connected, and the admin requested to
		 * start a sync by "invalidate" or "invalidate-remote" */
		consider_resync |= (old_peer_state.conn == L_ESTABLISHED &&
				    (peer_state.conn == L_STARTING_SYNC_S ||
				     peer_state.conn == L_STARTING_SYNC_T));

#ifdef _WIN32 // DW-1093 MODIFIED_BY_MANTECH detour 2-primary SB
		if( (peer_state.role == R_PRIMARY) && (device->resource->role[NOW] == R_PRIMARY) ) {
			drbd_err(device, "2 primary is not allowed.\n");
			put_ldev(device);
			goto fail;
		}
#endif
		if (consider_resync) {
			new_repl_state = drbd_sync_handshake(peer_device, peer_state.role, peer_disk_state);
		} else if (old_peer_state.conn == L_ESTABLISHED &&
			   (peer_state.disk == D_NEGOTIATING ||
			    old_peer_state.disk == D_NEGOTIATING)) {
			new_repl_state = drbd_attach_handshake(peer_device, peer_disk_state);
			if (new_repl_state == L_ESTABLISHED && device->disk_state[NOW] == D_UP_TO_DATE)
				peer_disk_state = D_UP_TO_DATE;
		}

		put_ldev(device);
		if (new_repl_state == -1) {
			new_repl_state = L_ESTABLISHED;
			if (device->disk_state[NOW] == D_NEGOTIATING) {
				new_repl_state = L_NEG_NO_RESULT;
			} else if (peer_state.disk == D_NEGOTIATING) {
				if (connection->agreed_pro_version < 110) {
					drbd_err(device, "Disk attach process on the peer node was aborted.\n");
					peer_state.disk = D_DISKLESS;
					peer_disk_state = D_DISKLESS;
				} else {
					/* The peer will decide later and let us know... */
					peer_disk_state = D_NEGOTIATING;
				}
			} else {
				if (test_and_clear_bit(CONN_DRY_RUN, &connection->flags))
					return -EIO;
				D_ASSERT(device, old_peer_state.conn == L_OFF);
				goto fail;
			}
		}

		if (device->disk_state[NOW] == D_NEGOTIATING) {
			set_bit(NEGOTIATION_RESULT_TOUCHED, &resource->flags);
			peer_device->negotiation_result = new_repl_state;
		}
	} else if (peer_state.role == R_PRIMARY &&
		peer_device->disk_state[NOW] == D_UNKNOWN && peer_state.disk == D_DISKLESS &&
		device->disk_state[NOW] >= D_NEGOTIATING && device->disk_state[NOW] < D_UP_TO_DATE) {
		/* I got connected to a diskless primary */
		if (peer_device->current_uuid == drbd_current_uuid(device)) {
			drbd_info(peer_device, "Upgrading local disk to D_UP_TO_DATE since current UUID matches.\n");
			new_disk_state = D_UP_TO_DATE;
		}
		else {
			/* Try to get a resync from some other node that is D_UP_TO_DATE. */
			try_to_get_resync = true;
		}
	}

	spin_lock_irq(&resource->req_lock);
	begin_state_change_locked(resource, CS_VERBOSE);
	if (old_peer_state.i != drbd_get_peer_device_state(peer_device, NOW).i) {
		old_peer_state = drbd_get_peer_device_state(peer_device, NOW);
#ifdef _WIN32_RCU_LOCKED
		abort_state_change_locked(resource, false, __FUNCTION__);
#else
		abort_state_change_locked(resource);
#endif
		spin_unlock_irq(&resource->req_lock);
		goto retry;
	}
	clear_bit(CONSIDER_RESYNC, &peer_device->flags);
	if (new_disk_state != D_MASK)
		__change_disk_state(device, new_disk_state, __FUNCTION__);
	if (device->disk_state[NOW] != D_NEGOTIATING)
		__change_repl_state_and_auto_cstate(peer_device, new_repl_state, __FUNCTION__);
	if (connection->peer_role[NOW] == R_UNKNOWN || peer_state.role == R_SECONDARY)
		__change_peer_role(connection, peer_state.role, __FUNCTION__);
	__change_peer_disk_state(peer_device, peer_disk_state, __FUNCTION__);
	__change_resync_susp_peer(peer_device, peer_state.aftr_isp | peer_state.user_isp, __FUNCTION__);
	repl_state = peer_device->repl_state;
	if (repl_state[OLD] < L_ESTABLISHED && repl_state[NEW] >= L_ESTABLISHED)
		resource->state_change_flags |= CS_HARD;
	if (peer_device->disk_state[NEW] == D_CONSISTENT &&
	    drbd_suspended(device) &&
	    repl_state[OLD] < L_ESTABLISHED && repl_state[NEW] == L_ESTABLISHED &&
	    test_and_clear_bit(NEW_CUR_UUID, &device->flags)) {
		unsigned long irq_flags;

		/* Do not allow RESEND for a rebooted peer. We can only allow this
		   for temporary network outages! */
#ifdef _WIN32_RCU_LOCKED
		abort_state_change_locked(resource, false, __FUNCTION__);
#else
		abort_state_change_locked(resource);
#endif
		spin_unlock_irq(&resource->req_lock);

		drbd_err(device, "Aborting Connect, can not thaw IO with an only Consistent peer\n");
		tl_clear(connection);
		mutex_lock(&resource->conf_update);
		drbd_uuid_new_current(device, false, __FUNCTION__);
		mutex_unlock(&resource->conf_update);
		begin_state_change(resource, &irq_flags, CS_HARD);
		__change_cstate(connection, C_PROTOCOL_ERROR);
		__change_io_susp_user(resource, false);
		end_state_change(resource, &irq_flags, __FUNCTION__);
		return -EIO;
	}

#ifdef _WIN32 // DW-1447
	peer_device->last_repl_state = peer_state.conn;
#endif

	
#ifdef _WIN32_RCU_LOCKED
	rv = end_state_change_locked(resource, false, __FUNCTION__);
#else
	rv = end_state_change_locked(resource);
#endif
	new_repl_state = peer_device->repl_state[NOW];
	set_bit(INITIAL_STATE_RECEIVED, &peer_device->flags);
	spin_unlock_irq(&resource->req_lock);

	if (rv < SS_SUCCESS)
	{
#ifdef _WIN32 // DW-1447
		peer_device->last_repl_state = old_peer_state.conn;
		// DW-1529 : if old connection state is C_CONNECTING, change cstate to NETWORK_FAILURE instead of DISCONNECTING
		// DISCONNECTING makes cstate STANDALONE
		// DW-1888 if the return value is SS_NEED_CONNECTION, reconnect it.
		if (connection->cstate[NOW] == C_CONNECTING || rv == SS_NEED_CONNECTION){
			drbd_info(peer_device, "connection->cstate[OLD] == C_CONNECTING, change cstate to NETWORK_FAILURE instead of DISCONNECTING\n");
			goto fail_network_failure;
		}
#endif
		goto fail;
	}

#ifdef _WIN32_STABLE_SYNCSOURCE
	// DW-1341 if UNSTABLE_TRIGGER_CP bit is set , send uuids(unstable node triggering for Crashed primary wiered case).
	if(test_and_clear_bit(UNSTABLE_TRIGGER_CP, &peer_device->flags)) {
		struct drbd_device *device2 = peer_device->device;
		struct drbd_peer_device *peer_device2;
		u64 im;
		drbd_send_uuids(peer_device, 0, 0);
		for_each_peer_device_ref(peer_device2, im, device2) {
			if (peer_device2->connection->cstate[NOW] == C_CONNECTED) {
				drbd_send_current_state(peer_device2);
			}
		}
	}
#endif

	if (old_peer_state.conn > L_OFF) {
		if (new_repl_state > L_ESTABLISHED && peer_state.conn <= L_ESTABLISHED &&
		    peer_state.disk != D_NEGOTIATING ) {
			/* we want resync, peer has not yet decided to sync... */
			/* Nowadays only used when forcing a node into primary role and
			   setting its disk to UpToDate with that */
			drbd_send_uuids(peer_device, 0, 0);
			drbd_send_current_state(peer_device);
		}
	}

	clear_bit(DISCARD_MY_DATA, &peer_device->flags);

	if (try_to_get_resync)
		try_to_get_resynced(device);

	drbd_md_sync(device); /* update connected indicator, effective_size, ... */

#ifndef _WIN32 // DW-1447 : moved to before end_state_change_locked()
	peer_device->last_repl_state = peer_state.conn;
#endif
	return 0;

#ifdef _WIN32 // DW-1529
fail_network_failure: 
	change_cstate_ex(connection, C_NETWORK_FAILURE, CS_HARD);
	return -EIO;
#endif 

fail:
	change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
	return -EIO;
}

static int receive_sync_uuid(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_uuid *p = pi->data;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	wait_event(device->misc_wait,
		   peer_device->repl_state[NOW] == L_WF_SYNC_UUID ||
		   peer_device->repl_state[NOW] == L_BEHIND ||
		   peer_device->repl_state[NOW] < L_ESTABLISHED ||
		   device->disk_state[NOW] < D_NEGOTIATING);

	/* D_ASSERT(device,  peer_device->repl_state[NOW] == L_WF_SYNC_UUID ); */

	/* Here the _drbd_uuid_ functions are right, current should
	   _not_ be rotated into the history */
	if (get_ldev_if_state(device, D_NEGOTIATING)) {
		_drbd_uuid_set_current(device, be64_to_cpu(p->uuid));
		_drbd_uuid_set_bitmap(peer_device, 0UL);

		drbd_print_uuids(peer_device, "updated sync uuid", __FUNCTION__);
		drbd_start_resync(peer_device, L_SYNC_TARGET);

		put_ldev(device);
	} else
		drbd_err(device, "Ignoring SyncUUID packet!\n");

	return 0;
}

/**
 * receive_bitmap_plain
 *
 * Return 0 when done, 1 when another iteration is needed, and a negative error
 * code upon failure.
 */
static int
receive_bitmap_plain(struct drbd_peer_device *peer_device, unsigned int size,
		     struct bm_xfer_ctx *c)
{
#ifdef _WIN32
	ULONG_PTR *p;
#else
	unsigned long *p;
#endif
	unsigned int data_size = DRBD_SOCKET_BUFFER_SIZE -
				 drbd_header_size(peer_device->connection);
	ULONG_PTR num_words = min_t(size_t, data_size / (unsigned int)sizeof(*p),
				       c->bm_words - c->word_offset);
	ULONG_PTR want = num_words * sizeof(*p);
	int err;


	if (want != size) {
		drbd_err(peer_device, "%s:want (%llu) != size (%u)\n", __func__, (unsigned long long)want, size);
		return -EIO;
	}
	if (want == 0)
		return 0;
	err = drbd_recv_all(peer_device->connection, (void **)&p, want);
	if (err)
		return err;

	drbd_bm_merge_lel(peer_device, c->word_offset, num_words, p);

	c->word_offset += num_words;
	c->bit_offset = c->word_offset * BITS_PER_LONG;
	if (c->bit_offset > c->bm_bits)
		c->bit_offset = c->bm_bits;

	return 1;
}

static enum drbd_bitmap_code dcbp_get_code(struct p_compressed_bm *p)
{
	return (enum drbd_bitmap_code)(p->encoding & 0x0f);
}

static int dcbp_get_start(struct p_compressed_bm *p)
{
	return (p->encoding & 0x80) != 0;
}

static int dcbp_get_pad_bits(struct p_compressed_bm *p)
{
	return (p->encoding >> 4) & 0x7;
}

/**
 * recv_bm_rle_bits
 *
 * Return 0 when done, 1 when another iteration is needed, and a negative error
 * code upon failure.
 */
static int
recv_bm_rle_bits(struct drbd_peer_device *peer_device,
		struct p_compressed_bm *p,
		 struct bm_xfer_ctx *c,
		 unsigned int len)
{
	struct bitstream bs;
	u64 look_ahead;
	u64 rl;
	u64 tmp;
#ifdef _WIN32
	ULONG_PTR s = c->bit_offset;
	ULONG_PTR e;
#else
	unsigned long s = c->bit_offset;
	unsigned long e;
#endif
	int toggle = dcbp_get_start(p);
	int have;
	int bits;

	bitstream_init(&bs, p->code, len, dcbp_get_pad_bits(p));

	bits = bitstream_get_bits(&bs, &look_ahead, 64);
	if (bits < 0)
		return -EIO;

	for (have = bits; have > 0; s += (ULONG_PTR)rl, toggle = !toggle) {
		bits = (int)vli_decode_bits(&rl, look_ahead);
		if (bits <= 0)
			return -EIO;

		if (toggle) {
			e = s + (ULONG_PTR)rl -1;
			if (e >= c->bm_bits) {
				drbd_err(peer_device, "bitmap overflow (e:%lu) while decoding bm RLE packet\n", e);
				return -EIO;
			}
			drbd_bm_set_many_bits(peer_device, s, e);
		}

		if (have < bits) {
			drbd_err(peer_device, "bitmap decoding error: h:%d b:%d la:0x%08llx l:%u/%u\n",
				have, bits, look_ahead,
				(unsigned int)(bs.cur.b - p->code),
				(unsigned int)bs.buf_len);
			return -EIO;
		}
		/* if we consumed all 64 bits, assign 0; >> 64 is "undefined"; */
		if (likely(bits < 64))
			look_ahead >>= bits;
		else
			look_ahead = 0;
		have -= bits;

		bits = bitstream_get_bits(&bs, &tmp, 64 - have);
		if (bits < 0)
			return -EIO;
		look_ahead |= tmp << have;
		have += bits;
	}

	c->bit_offset = s;
	bm_xfer_ctx_bit_to_word_offset(c);

	return (s != c->bm_bits);
}

/**
 * decode_bitmap_c
 *
 * Return 0 when done, 1 when another iteration is needed, and a negative error
 * code upon failure.
 */
static int
decode_bitmap_c(struct drbd_peer_device *peer_device,
		struct p_compressed_bm *p,
		struct bm_xfer_ctx *c,
		unsigned int len)
{
	if (dcbp_get_code(p) == RLE_VLI_Bits)
		return recv_bm_rle_bits(peer_device, p, c, len - sizeof(*p));

	/* other variants had been implemented for evaluation,
	 * but have been dropped as this one turned out to be "best"
	 * during all our tests. */

	drbd_err(peer_device, "receive_bitmap_c: unknown encoding %u\n", p->encoding);
	change_cstate_ex(peer_device->connection, C_PROTOCOL_ERROR, CS_HARD);
	return -EIO;
}

void INFO_bm_xfer_stats(struct drbd_peer_device *peer_device,
		const char *direction, struct bm_xfer_ctx *c)
{
	/* what would it take to transfer it "plaintext" */
	unsigned int header_size = drbd_header_size(peer_device->connection);
	unsigned int data_size = DRBD_SOCKET_BUFFER_SIZE - header_size;
#ifdef _WIN32
	unsigned long long plain =
		header_size * (DIV_ROUND_UP(c->bm_words, data_size) + 1) + c->bm_words * sizeof(ULONG_PTR);
#else
	unsigned int plain =
		header_size * (DIV_ROUND_UP(c->bm_words, data_size) + 1) +
		c->bm_words * sizeof(unsigned long);
#endif
	unsigned long long total = c->bytes[0] + c->bytes[1];
	unsigned long long r;

	/* total can not be zero. but just in case: */
	if (total == 0)
		return;

	/* don't report if not compressed */
	if (total >= plain)
		return;

	/* total < plain. check for overflow, still */
	r = (total > UINT_MAX/1000) ? (total / (plain/1000))
		                    : (1000 * total / plain);

	if (r > 1000)
		r = 1000;

	r = 1000 - r;
	drbd_info(peer_device, "%s bitmap stats [Bytes(packets)]: plain %u(%u), RLE %u(%u), "
	     "total %u; compression: %u.%u%%\n",
			direction,
			c->bytes[1], c->packets[1],
			c->bytes[0], c->packets[0],
			total, r/10, r % 10);
}

static enum drbd_disk_state read_disk_state(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	enum drbd_disk_state disk_state;

	spin_lock_irq(&resource->req_lock);
	disk_state = device->disk_state[NOW];
	spin_unlock_irq(&resource->req_lock);

	return disk_state;
}

// DW-1981
static int receive_bitmap_finished(struct drbd_connection *connection, struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	if (!device)
		return -EIO;


	peer_device->bm_ctx.count = 0;
	INFO_bm_xfer_stats(peer_device, "receive", &peer_device->bm_ctx);

	if (peer_device->repl_state[NOW] == L_WF_BITMAP_T ||
		// DW-1979
		peer_device->repl_state[NOW] == L_BEHIND) {
		// DW-1979
		atomic_set(&peer_device->wait_for_recv_rs_reply, 1);

		drbd_queue_bitmap_io(device, &drbd_send_bitmap, &drbd_send_bitmap_target_complete,
			"send_bitmap (WFBitMapT)",
			BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK | BM_LOCK_SINGLE_SLOT | BM_LOCK_POINTLESS,
			peer_device);
	}
	else if (peer_device->repl_state[NOW] != L_WF_BITMAP_S &&
		// DW-1979
		peer_device->repl_state[NOW] != L_AHEAD) {
		/* admin may have requested C_DISCONNECTING,
		* other threads may have noticed network errors */
		drbd_info(peer_device, "unexpected repl_state (%s) in receive_bitmap\n",
			drbd_repl_str(peer_device->repl_state[NOW]));
		// DW-1613 reconnect the UUID because it might not be received properly due to a synchronization issue.
		// DW-2014 error return for reconnect
		change_cstate_ex(connection, C_NETWORK_FAILURE, CS_HARD);
		return -EAGAIN;
	}

	if (peer_device->repl_state[NOW] == L_WF_BITMAP_S ||
		// DW-1979
		peer_device->repl_state[NOW] == L_AHEAD) {
		drbd_start_resync(peer_device, L_SYNC_SOURCE);
	}

	// DW-1979
	atomic_set(&peer_device->wait_for_recv_bitmap, 0);

	return 0;
}

/* Since we are processing the bitfield from lower addresses to higher,
it does not matter if the process it in 32 bit chunks or 64 bit
chunks as long as it is little endian. (Understand it as byte stream,
beginning with the lowest byte...) If we would use big endian
we would need to process it from the highest address to the lowest,
in order to be agnostic to the 32 vs 64 bits issue.

returns 0 on failure, 1 if we successfully received it. */
static int receive_bitmap(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	int err;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	if (peer_device->bitmap_index == -1) {
		drbd_err(peer_device, "No bitmap allocated in receive_bitmap()!\n");
		return -EIO;
	}
	device = peer_device->device;

#ifdef _WIN32 
	//	memset(&c, 0, sizeof(struct bm_xfer_ctx));
#endif
	/* Final repl_states become visible when the disk leaves NEGOTIATING state */
#ifdef _WIN32
	int ret;
	wait_event_interruptible(ret, device->resource->state_wait,
		read_disk_state(device) != D_NEGOTIATING);
#else
	wait_event_interruptible(device->resource->state_wait,
		read_disk_state(device) != D_NEGOTIATING);
#endif

	drbd_bm_slot_lock(peer_device, "receive bitmap", BM_LOCK_CLEAR | BM_LOCK_BULK | BM_LOCK_POINTLESS);
	/* you are supposed to send additional out-of-sync information
	* if you actually set bits during this phase */

	if (peer_device->bm_ctx.count == 0) {
		memset(&peer_device->bm_ctx, 0, sizeof(struct bm_xfer_ctx));

		peer_device->bm_ctx.bm_bits = drbd_bm_bits(device);
		peer_device->bm_ctx.bm_words = drbd_bm_words(device);
	}

	peer_device->bm_ctx.count++;

	if (pi->cmd == P_BITMAP) {
		err = receive_bitmap_plain(peer_device, pi->size, &peer_device->bm_ctx);
	}
	else if (pi->cmd == P_COMPRESSED_BITMAP) {
		/* MAYBE: sanity check that we speak proto >= 90,
		* and the feature is enabled! */
		struct p_compressed_bm *p;

		if (pi->size > DRBD_SOCKET_BUFFER_SIZE - drbd_header_size(connection)) {
			drbd_err(device, "ReportCBitmap packet too large\n");
			err = -EIO;
			goto out;
		}
		if (pi->size <= sizeof(*p)) {
			drbd_err(device, "ReportCBitmap packet too small (l:%u)\n", pi->size);
			err = -EIO;
			goto out;
		}
		err = drbd_recv_all(connection, (void **)&p, pi->size);
		if (err)
			goto out;
		err = decode_bitmap_c(peer_device, p, &peer_device->bm_ctx, pi->size);
	}
	else {
		drbd_warn(device, "receive_bitmap: cmd neither ReportBitMap nor ReportCBitMap (is 0x%x)", pi->cmd);
		err = -EIO;
		goto out;
	}

	peer_device->bm_ctx.packets[pi->cmd == P_BITMAP]++;
	peer_device->bm_ctx.bytes[pi->cmd == P_BITMAP] += drbd_header_size(connection) + pi->size;

	if (err <= 0) {
		if (err < 0)
			goto out;

		err = receive_bitmap_finished(connection, peer_device);
	}
	else
		err = 0;

out:
	drbd_bm_slot_unlock(peer_device);
	return err;
}


static int receive_skip(struct drbd_connection *connection, struct packet_info *pi)
{
	drbd_warn(connection, "skipping unknown optional packet type %d, l: %d!\n",
		 pi->cmd, pi->size);

	return ignore_remaining_packet(connection, pi->size);
}

static int receive_UnplugRemote(struct drbd_connection *connection, struct packet_info *pi)
{
	UNREFERENCED_PARAMETER(pi);

	struct drbd_transport *transport = &connection->transport;

	/* Make sure we've acked all the data associated
	 * with the data requests being unplugged */
	transport->ops->hint(transport, DATA_STREAM, QUICKACK);

	/* just unplug all devices always, regardless which volume number */
	drbd_unplug_all_devices(connection);

	return 0;
}

static int receive_out_of_sync(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_desc *p = pi->data;
	sector_t sector; 
	ULONG_PTR bit; 
#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1354
	bool bResetTimer = false;
#endif

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;
	
	sector = be64_to_cpu(p->sector); 
	switch (peer_device->repl_state[NOW]) {
	case L_WF_SYNC_UUID:
	case L_WF_BITMAP_T:
	case L_BEHIND:
		break; 
	case L_SYNC_TARGET: 
		mutex_lock(&device->bm_resync_fo_mutex);
#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-1354: I am a sync target and find offset points the end, does mean no more requeueing resync timer.
		bResetTimer = (device->bm_resync_fo == drbd_bm_bits(device));
#endif
		bit = (ULONG_PTR)BM_SECT_TO_BIT(sector);
		if (bit < device->bm_resync_fo)
			device->bm_resync_fo = bit; 
		mutex_unlock(&device->bm_resync_fo_mutex);
		break; 
	default:
#ifdef _WIN32
		drbd_info(device, "ASSERT FAILED cstate = %s, expected: WFSyncUUID|WFBitMapT|Behind\n",
				drbd_repl_str(peer_device->repl_state[NOW]));
#else
		drbd_err(device, "ASSERT FAILED cstate = %s, expected: WFSyncUUID|WFBitMapT|Behind\n",
				drbd_repl_str(peer_device->repl_state[NOW]));
#endif
	}
	drbd_set_out_of_sync(peer_device, sector, be32_to_cpu(p->blksize)); 

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1354: new out-of-sync has been set and resync timer has been expired, 
	if (bResetTimer)
	{
		drbd_info(peer_device, "received out-of-sync has been set after resync timer has been expired, restart timer to send rs request for rest\n");
		mod_timer(&peer_device->resync_timer, jiffies + SLEEP_TIME);
	}
#endif

	return 0;
}

static int receive_dagtag(struct drbd_connection *connection, struct packet_info *pi)
{
	struct p_dagtag *p = pi->data;

	connection->last_dagtag_sector = be64_to_cpu(p->dagtag);
	return 0;
}

struct drbd_connection *drbd_connection_by_node_id(struct drbd_resource *resource, int node_id)
{
	/* Caller needs to hold rcu_read_lock(), conf_update */
	struct drbd_connection *connection;

	for_each_connection_rcu(connection, resource) {
		if (connection->peer_node_id == (unsigned int)node_id)
			return connection;
	}

	return NULL;
}

struct drbd_connection *drbd_get_connection_by_node_id(struct drbd_resource *resource, int node_id)
{
	struct drbd_connection *connection;

	rcu_read_lock();
	connection = drbd_connection_by_node_id(resource, node_id);
	if (connection)
		kref_get(&connection->kref);
	rcu_read_unlock();

	return connection;
}

static int receive_peer_dagtag(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	enum drbd_repl_state new_repl_state;
	struct p_peer_dagtag *p = pi->data;
	struct drbd_connection *lost_peer;
	s64 dagtag_offset;
	int vnr = 0;

	lost_peer = drbd_get_connection_by_node_id(resource, be32_to_cpu(p->node_id));
	if (!lost_peer)
		return 0;

	kref_debug_get(&lost_peer->kref_debug, 12);

	if (lost_peer->cstate[NOW] == C_CONNECTED) {
		drbd_ping_peer(lost_peer);
		if (lost_peer->cstate[NOW] == C_CONNECTED)
			goto out;
	}

#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		if (peer_device->repl_state[NOW] > L_ESTABLISHED)
			goto out;
		if (peer_device->current_uuid != drbd_current_uuid(peer_device->device))
			goto out;
	}

	/* Need to wait until the other receiver thread has called the
	   cleanup_unacked_peer_requests() function */
	wait_event(resource->state_wait,
		   lost_peer->cstate[NOW] <= C_UNCONNECTED || lost_peer->cstate[NOW] == C_CONNECTING);

	dagtag_offset = (s64)lost_peer->last_dagtag_sector - (s64)be64_to_cpu(p->dagtag);
	if (dagtag_offset > 0)
		new_repl_state = L_WF_BITMAP_S;
	else if (dagtag_offset < 0)
		new_repl_state = L_WF_BITMAP_T;
	else
		new_repl_state = L_ESTABLISHED;

	if (new_repl_state != L_ESTABLISHED) {
		unsigned long irq_flags;


#ifdef _WIN32 // MODIFIED_BY_MANTECH DW-891
		/* If cannot change the state of peer node to L_WF_BITMAP_S, do not change the local node's repl_state to L_WF_BITMAP_T. */
		idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
			if ((new_repl_state == L_WF_BITMAP_T) && (peer_device->disk_state[NOW] <= D_INCONSISTENT))
			{
				goto out;
			}
		}
#endif		

#ifdef _WIN32_TRACE_PEER_DAGTAG
		drbd_info(connection, "Reconciliation resync because \'%s\' disappeared. (o=%d) lost_peer:%p lost_peer->last_dagtag_sector:0x%llx be64_to_cpu(p->dagtag):%llx\n",
			  lost_peer->transport.net_conf->name, (int)dagtag_offset, lost_peer, lost_peer->last_dagtag_sector, be64_to_cpu(p->dagtag));
#else
		drbd_info(connection, "Reconciliation resync because \'%s\' disappeared. (o=%d)\n",
 				lost_peer->transport.net_conf->name, (int)dagtag_offset);
#endif

		begin_state_change(resource, &irq_flags, CS_VERBOSE);
#ifdef _WIN32
        idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
		idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
			__change_repl_state_and_auto_cstate(peer_device, new_repl_state, __FUNCTION__);
			set_bit(RECONCILIATION_RESYNC, &peer_device->flags);
		}
#ifdef _WIN32 // DW-1632: If the RECONCILIATION_RESYNC flag is set, it will not be updated with the new UUID after resynchronization.
			  // If the change to WFBitMapS fails, disable the RECONCILIATION_RESYNC flag.
		enum drbd_status_rv rv = end_state_change(resource, &irq_flags, __FUNCTION__);
		idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
			if (new_repl_state == L_WF_BITMAP_S && test_bit(RECONCILIATION_RESYNC, &peer_device->flags)){
				if(rv != SS_SUCCESS){
					drbd_debug(peer_device, "Disable RECONCILIATION_RESYNC flag.\n");
					clear_bit(RECONCILIATION_RESYNC, &peer_device->flags);
				}
			}
		}
#else 
		end_state_change(resource, &irq_flags);
#endif	
	} else {
#ifdef _WIN32_TRACE_PEER_DAGTAG	
		drbd_info(connection, "No reconciliation resync even though \'%s\' disappeared. (o=%d) lost_peer:%p lost_peer->last_dagtag_sector:0x%llx be64_to_cpu(p->dagtag):%llx\n",
			  lost_peer->transport.net_conf->name, (int)dagtag_offset, lost_peer, lost_peer->last_dagtag_sector, be64_to_cpu(p->dagtag));
#else
		drbd_info(connection, "No reconciliation resync even though \'%s\' disappeared. (o=%d)\n",
			lost_peer->transport.net_conf->name, (int)dagtag_offset);
#endif


#ifdef _WIN32
        idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr)
#else
		idr_for_each_entry(&connection->peer_devices, peer_device, vnr)
#endif
		{	
#ifdef _WIN32
			// MODIFIED_BY_MANTECH DW-1340 : no clearing bitmap when disk is inconsistent.
			// DW-1365 : fixup secondary's diskless case for crashed primary.
			// DW-1644 : if the peer's disk_state is inconsistent, no clearing bitmap.
			// DW-2031 add put_ldev() due to ldev leak occurrence
			if (peer_device->disk_state[NOW] > D_INCONSISTENT && get_ldev_if_state(peer_device->device, D_OUTDATED)) {
				drbd_bm_clear_many_bits(peer_device->device, peer_device->bitmap_index, 0, DRBD_END_OF_BITMAP);
				put_ldev (peer_device->device);
			} else {
				drbd_info(connection, "No drbd_bm_clear_many_bits, disk_state:%d peer disk_state:%d\n",
							peer_device->device->disk_state[NOW], peer_device->disk_state[NOW]);
			}
#else		
			drbd_bm_clear_many_bits(peer_device, 0, -1UL);
#endif
		}
	}

out:
	kref_debug_put(&lost_peer->kref_debug, 12);
	kref_put(&lost_peer->kref, drbd_destroy_connection);
	return 0;
}

/* Accept a new current UUID generated on a diskless node, that just became primary
(or during handshake) */
static int receive_current_uuid(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_current_uuid *p = pi->data;
	u64 current_uuid, weak_nodes;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	current_uuid = be64_to_cpu(p->uuid);
	weak_nodes = be64_to_cpu(p->weak_nodes);
#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-977: Newly created uuid hasn't been updated for peer device, do it as soon as peer sends its uuid which means it was adopted for peer's current uuid.
	peer_device->current_uuid = current_uuid;
#endif

	if (connection->peer_role[NOW] == R_UNKNOWN)
		return 0;

	// DW-1975 If the current uuid is updated, the remaining bitmap uuid is also removed.
	if (current_uuid == drbd_current_uuid(device)) {
		struct drbd_device *device = peer_device->device;
		// DW-2009 initialize the bitmap uuid only in specific condition
		if (drbd_current_uuid(device) != 0 && device->ldev) {
			struct drbd_peer_md *peer_md = &device->ldev->md.peers[peer_device->node_id];
			if (peer_md->bitmap_uuid != 0) {
				drbd_info(peer_device, "Clear bitmap_uuid (cur_uuid:%016llX bm_uuid:%016llX)\n", current_uuid, peer_md->bitmap_uuid);
				drbd_uuid_set_bitmap(peer_device, 0);
			}
		}

		return 0;
	}
#ifndef _WIN32
	// MODIFIED_BY_MANTECH DW-977
	peer_device->current_uuid = current_uuid;
#endif

	if (get_ldev_if_state(device, D_UP_TO_DATE)) {
		if (connection->peer_role[NOW] == R_PRIMARY) {
			drbd_warn(peer_device, "received new current UUID: %016llX "
				  "weak_nodes=%016llX\n", current_uuid, weak_nodes);
			drbd_uuid_received_new_current(peer_device, current_uuid, weak_nodes);
			drbd_md_sync_if_dirty(device);
		}
		put_ldev(device);
	} else if (device->disk_state[NOW] == D_DISKLESS && resource->role[NOW] == R_PRIMARY) {
		drbd_set_exposed_data_uuid(device, peer_device->current_uuid);
	}

	return 0;
}

static int receive_rs_deallocated(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct p_block_desc *p = pi->data;
	struct drbd_device *device;
	sector_t sector;
	int size, err = 0;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	sector = be64_to_cpu(p->sector);
	size = be32_to_cpu(p->blksize);

	dec_rs_pending(peer_device);

	if (get_ldev(device)) {
		struct drbd_peer_request *peer_req;

		peer_req = drbd_alloc_peer_req(peer_device, GFP_NOIO);
		if (!peer_req) {
			put_ldev(device);
			return -ENOMEM;
		}

		peer_req->i.size = size;
		peer_req->i.sector = sector;
		peer_req->block_id = ID_SYNCER;
#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
		peer_req->w.cb = split_e_end_resync_block;
#else
		peer_req->w.cb = e_end_resync_block;
#endif

		peer_req->submit_jif = jiffies;
		peer_req->flags |= EE_IS_TRIM;

		spin_lock_irq(&device->resource->req_lock);
		list_add_tail(&peer_req->w.list, &connection->sync_ee);
		spin_unlock_irq(&device->resource->req_lock);

		atomic_add(pi->size >> 9, &device->rs_sect_ev);
		err = drbd_submit_peer_request(device, peer_req, REQ_OP_DISCARD,
			0, DRBD_FAULT_RS_WR);

		if (err) {
			spin_lock_irq(&device->resource->req_lock);
			list_del(&peer_req->w.list);
			spin_unlock_irq(&device->resource->req_lock);

			drbd_free_peer_req(peer_req);
			put_ldev(device);
			err = 0;
			goto fail;
		}

		inc_unacked(peer_device);

		/* No put_ldev() here. Gets called in drbd_endio_write_sec_final(),
		   as well as drbd_rs_complete_io() */
	} else {
	fail:
		drbd_rs_complete_io(peer_device, sector, __FUNCTION__);
		drbd_send_ack_ex(peer_device, P_NEG_ACK, sector, size, ID_SYNCER);
	}

	atomic_add(size >> 9, &peer_device->rs_sect_in);

	return err;
}

struct data_cmd {
	int expect_payload;
	unsigned int pkt_size;
	int (*fn)(struct drbd_connection *, struct packet_info *);
};

static struct data_cmd drbd_cmd_handler[] = {
	[P_DATA]	    = { 1, sizeof(struct p_data), receive_Data },
	[P_DATA_REPLY]	    = { 1, sizeof(struct p_data), receive_DataReply },
	[P_RS_DATA_REPLY]   = { 1, sizeof(struct p_data), receive_RSDataReply } ,
	[P_BARRIER]	    = { 0, sizeof(struct p_barrier), receive_Barrier } ,
	[P_BITMAP]	    = { 1, 0, receive_bitmap } ,
	[P_COMPRESSED_BITMAP] = { 1, 0, receive_bitmap } ,
	[P_UNPLUG_REMOTE]   = { 0, 0, receive_UnplugRemote },
	[P_DATA_REQUEST]    = { 0, sizeof(struct p_block_req), receive_DataRequest },
	[P_RS_DATA_REQUEST] = { 0, sizeof(struct p_block_req), receive_DataRequest },
	[P_SYNC_PARAM]	    = { 1, 0, receive_SyncParam },
	[P_SYNC_PARAM89]    = { 1, 0, receive_SyncParam },
	[P_PROTOCOL]        = { 1, sizeof(struct p_protocol), receive_protocol },
	[P_UUIDS]	    = { 0, sizeof(struct p_uuids), receive_uuids },
	[P_SIZES]	    = { 0, sizeof(struct p_sizes), receive_sizes },
	[P_STATE]	    = { 0, sizeof(struct p_state), receive_state },
	[P_STATE_CHG_REQ]   = { 0, sizeof(struct p_req_state), receive_req_state },
	[P_SYNC_UUID]       = { 0, sizeof(struct p_uuid), receive_sync_uuid },
	[P_OV_REQUEST]      = { 0, sizeof(struct p_block_req), receive_DataRequest },
	[P_OV_REPLY]        = { 1, sizeof(struct p_block_req), receive_DataRequest },
	[P_CSUM_RS_REQUEST] = { 1, sizeof(struct p_block_req), receive_DataRequest },
	[P_RS_THIN_REQ]     = { 0, sizeof(struct p_block_req), receive_DataRequest },
	[P_DELAY_PROBE]     = { 0, sizeof(struct p_delay_probe93), receive_skip },
	[P_OUT_OF_SYNC]     = { 0, sizeof(struct p_block_desc), receive_out_of_sync },
	[P_CONN_ST_CHG_REQ] = { 0, sizeof(struct p_req_state), receive_req_state },
	[P_PROTOCOL_UPDATE] = { 1, sizeof(struct p_protocol), receive_protocol },
	[P_TWOPC_PREPARE] = { 0, sizeof(struct p_twopc_request), receive_twopc },
	[P_TWOPC_PREP_RSZ] = { 0, sizeof(struct p_twopc_request), receive_twopc },
	[P_TWOPC_ABORT] = { 0, sizeof(struct p_twopc_request), receive_twopc },
	[P_DAGTAG]	    = { 0, sizeof(struct p_dagtag), receive_dagtag },
	[P_UUIDS110]	    = { 1, sizeof(struct p_uuids110), receive_uuids110 },
	[P_PEER_DAGTAG]     = { 0, sizeof(struct p_peer_dagtag), receive_peer_dagtag },
	[P_CURRENT_UUID]    = { 0, sizeof(struct p_current_uuid), receive_current_uuid },
	[P_TWOPC_COMMIT]    = { 0, sizeof(struct p_twopc_request), receive_twopc },
	[P_TRIM]	    = { 0, sizeof(struct p_trim), receive_Data },
	[P_RS_DEALLOCATED]  = { 0, sizeof(struct p_block_desc), receive_rs_deallocated },
	[P_WSAME]	    = { 1, sizeof(struct p_wsame), receive_Data },
};

static void drbdd(struct drbd_connection *connection)
{
	struct packet_info pi;
	size_t shs; /* sub header size */
	int err;

	while (get_t_state(&connection->receiver) == RUNNING) {
		struct data_cmd const *cmd;

		drbd_thread_current_set_cpu(&connection->receiver);
#ifndef _WIN32
		update_receiver_timing_details(connection, drbd_recv_header_maybe_unplug);
		if (drbd_recv_header_maybe_unplug(connection, &pi))
			goto err_out;
#else
		update_receiver_timing_details(connection, drbd_recv_header);
		if (drbd_recv_header(connection, &pi))
			goto err_out;
#endif
		cmd = &drbd_cmd_handler[pi.cmd];
		if (unlikely(pi.cmd >= ARRAY_SIZE(drbd_cmd_handler) || !cmd->fn)) {
			drbd_err(connection, "Unexpected data packet %s (0x%04x)",
				 drbd_packet_name(pi.cmd), pi.cmd);
			goto err_out;
		}

		shs = cmd->pkt_size;
		if (pi.cmd == P_SIZES && connection->agreed_features & DRBD_FF_WSAME)
			shs += sizeof(struct o_qlim);
		if (pi.size > shs && !cmd->expect_payload) {
			drbd_err(connection, "No payload expected %s l:%d\n",
				 drbd_packet_name(pi.cmd), pi.size);
			goto err_out;
		}
		if (pi.size < shs) {
			drbd_err(connection, "%s: unexpected packet size, expected:%d received:%d\n",
				 drbd_packet_name(pi.cmd), (int)shs, pi.size);
			goto err_out;
		}

		if (shs) {
			update_receiver_timing_details(connection, drbd_recv_all_warn);
			err = drbd_recv_all_warn(connection, &pi.data, shs);
			if (err)
				goto err_out;
			pi.size -= (unsigned int)shs;
		}

		update_receiver_timing_details(connection, cmd->fn);
#ifdef _WIN32
		drbd_debug(connection, "receiving %s, size: %u vnr: %d\n", drbd_packet_name(pi.cmd), pi.size, pi.vnr);
#endif
		err = cmd->fn(connection, &pi);
		if (err) {
			drbd_err(connection, "error receiving %s, e: %d l: %u!\n",
				 drbd_packet_name(pi.cmd), err, pi.size);
			goto err_out;
		}
	}
	return;

    err_out:
	change_cstate_ex(connection, C_PROTOCOL_ERROR, CS_HARD);
}

static void cleanup_resync_leftovers(struct drbd_peer_device *peer_device)
{
	/* We do not have data structures that would allow us to
	* get the rs_pending_cnt down to 0 again.
	*  * On L_SYNC_TARGET we do not have any data structures describing
	*    the pending RSDataRequest's we have sent.
	*  * On L_SYNC_SOURCE there is no data structure that tracks
	*    the P_RS_DATA_REPLY blocks that we sent to the SyncTarget.
	*  And no, it is not the sum of the reference counts in the
	*  resync_LRU. The resync_LRU tracks the whole operation including
	*  the disk-IO, while the rs_pending_cnt only tracks the blocks
	*  on the fly. */
	drbd_rs_cancel_all(peer_device);
	peer_device->rs_total = 0;
	peer_device->rs_failed = 0;
	atomic_set(&peer_device->rs_pending_cnt, 0);
	wake_up(&peer_device->device->misc_wait);

	// DW-1663  : When the "DPC function" is running, "del_timer_sync()" does not wait but cancels only the timer in the queue and releases the resource, resulting in "BSOD".
	// Add the mutex so that "del_timer_sync()" can be called after terminating "DPC function".
	mutex_lock(&peer_device->device->bm_resync_fo_mutex);
	del_timer_sync(&peer_device->resync_timer);
	mutex_unlock(&peer_device->device->bm_resync_fo_mutex);

#ifdef _WIN32
	resync_timer_fn(NULL, (PVOID)peer_device, NULL, NULL);
#else
	resync_timer_fn((unsigned long)peer_device);
#endif 
	del_timer_sync(&peer_device->start_resync_timer);

	//DW-1886
	if (peer_device->rs_send_req != peer_device->rs_recv_res ||
		peer_device->rs_recv_res != (ULONG_PTR)atomic_read64(&peer_device->rs_written)) {
		drbd_info(peer_device, "incomplete resync exit, rs_send_req(%llu), rs_recv_res(%llu), rs_written(%lld)\n",
			(unsigned long long)peer_device->rs_send_req, (unsigned long long)peer_device->rs_recv_res, atomic_read64(&peer_device->rs_written));
	}
	
}

static void drain_resync_activity(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	// DW-2035 if DISCONN_NO_WAIT_RESYNC is set, don't wait for sync_ee.
	if (test_bit(DISCONN_NO_WAIT_RESYNC, &connection->flags)) {
		/* verify or resync related peer requests are read_ee or sync_ee,
		* drain them first */
		conn_wait_ee_empty(connection, &connection->sync_ee);
	}
	conn_wait_ee_empty(connection, &connection->read_ee);

	rcu_read_lock();
#ifdef _WIN32
	idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif 
		struct drbd_device *device = peer_device->device;

		kref_get(&device->kref);
		rcu_read_unlock();

		cleanup_resync_leftovers(peer_device);

		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}

static void peer_device_disconnected(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;

	/* need to do it again, drbd_finish_peer_reqs() may have populated it
	* again via drbd_try_clear_on_disk_bm(). */
	drbd_rs_cancel_all(peer_device);

	peer_device->uuids_received = false;

	if (!drbd_suspended(device))
		tl_clear(peer_device->connection);

	drbd_md_sync(device);

	if (get_ldev(device)) {
		drbd_bitmap_io(device, &drbd_bm_write_copy_pages, "write from disconnected",
			BM_LOCK_BULK | BM_LOCK_SINGLE_SLOT, peer_device);
		put_ldev(device);
	}
}

void conn_disconnect(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	enum drbd_conn_state oc;
	unsigned long irq_flags;
	int vnr, i;

	WDRBD_CONN_TRACE("conn_disconnect\n"); 

	clear_bit(CONN_DRY_RUN, &connection->flags);
	clear_bit(CONN_DISCARD_MY_DATA, &connection->flags);

	if (connection->cstate[NOW] == C_STANDALONE)
		return;

	/* We are about to start the cleanup after connection loss.
	 * Make sure drbd_make_request knows about that.
	 * Usually we should be in some network failure state already,
	 * but just in case we are not, we fix it up here.
	 */	

	change_cstate_ex(connection, C_NETWORK_FAILURE, CS_HARD);

#ifdef _WIN32
	// DW-1398: closing listening socket busts accepted socket, put those sockets here instead.
	dtt_put_listeners(&connection->transport);
#endif

	del_connect_timer(connection);

	/* ack_receiver does not clean up anything. it must not interfere, either */
	drbd_thread_stop(&connection->ack_receiver);
	if (connection->ack_sender) {
		destroy_workqueue(connection->ack_sender);
		connection->ack_sender = NULL;
	}

	drbd_transport_shutdown(connection, CLOSE_CONNECTION);
	drbd_drop_unsent(connection);

	//DW-1894 remove incomplete requests.
	if (resource->twopc_reply.initiator_node_id == (int)connection->peer_node_id) {
		del_timer(&resource->twopc_timer);
		clear_remote_state_change(resource);
	}

	/* Wait for current activity to cease.  This includes waiting for
	* peer_request queued to the submitter workqueue. */

	// DW-1954 wait CONN_WAIT_TIMEOUT (default 3 seconds) and keep waiting if ee is not empty and ee is the same as before.
	conn_wait_ee_empty_and_update_timeout(connection, &connection->active_ee);

	// DW-1874 call after active_ee wait
	drain_resync_activity(connection);

	// DW-1696 add the incomplete active_ee, sync_ee, read_ee
	spin_lock(&resource->req_lock);	
	// DW-1732 initialization active_ee(bitmap, al) 
	struct drbd_peer_request *peer_req;

	// DW-1935
	spin_lock(&g_inactive_lock);
	if (!list_empty(&connection->active_ee)) {
		list_for_each_entry(struct drbd_peer_request, peer_req, &connection->active_ee, w.list) {
			struct drbd_peer_device *peer_device = peer_req->peer_device;
			struct drbd_device *device = peer_device->device;

			//DW-1812 set inactive_ee to out of sync.
			drbd_set_out_of_sync(peer_device, peer_req->i.sector, peer_req->i.size);
			list_del(&peer_req->recv_order);

			drbd_info(device, "add, active_ee => inactive_ee(%p), sector(%llu), size(%u)\n", peer_req, peer_req->i.sector, peer_req->i.size);
		}

		list_splice_init(&connection->active_ee, &connection->inactive_ee);
	}

	// DW-1920 
	if (!list_empty(&connection->sync_ee)) {
		list_for_each_entry(struct drbd_peer_request, peer_req, &connection->sync_ee, w.list) {
			struct drbd_device *device = peer_req->peer_device->device;
			drbd_info(device, "add, sync_ee => inactive_ee(%p), sector(%llu), size(%u)\n", peer_req, peer_req->i.sector, peer_req->i.size);
		}
		list_splice_init(&connection->sync_ee, &connection->inactive_ee);
	}

	if (!list_empty(&connection->read_ee)) {
		list_for_each_entry(struct drbd_peer_request, peer_req, &connection->read_ee, w.list) {
			struct drbd_device *device = peer_req->peer_device->device;
			drbd_info(device, "add, read_ee => inactive_ee(%p), sector(%llu), size(%u)\n", peer_req, peer_req->i.sector, peer_req->i.size);
		}
		// DW-1735 If the list is not empty because it has been moved to inactive_ee, it as a bug
		list_splice_init(&connection->read_ee, &connection->inactive_ee);
	}

	// DW-1935
	atomic_set(&connection->inacitve_ee_cnt, 0);
	list_for_each_entry(struct drbd_peer_request, peer_req, &connection->inactive_ee, w.list) {
		set_bit(__EE_WAS_INACTIVE_REQ, &peer_req->flags);
		atomic_inc(&connection->inacitve_ee_cnt);
	}
	spin_unlock(&g_inactive_lock);
	spin_unlock(&resource->req_lock);

	/* wait for all w_e_end_data_req, w_e_end_rsdata_req, w_send_barrier,
	* w_make_resync_request etc. which may still be on the worker queue
	* to be "canceled" */
#ifdef _WIN32
	drbd_flush_workqueue(resource, &connection->sender_work);
#else 
	drbd_flush_workqueue(&connection->sender_work);
#endif 

	drbd_finish_peer_reqs(connection);

	/* This second workqueue flush is necessary, since drbd_finish_peer_reqs()
	might have issued a work again. The one before drbd_finish_peer_reqs() is
	necessary to reclaim net_ee in drbd_finish_peer_reqs(). */

#ifdef _WIN32
	drbd_flush_workqueue(resource, &connection->sender_work);
#else 
	drbd_flush_workqueue(&connection->sender_work);
#endif 

	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		struct drbd_device *device = peer_device->device;

		kref_get(&device->kref);
		rcu_read_unlock();

		// DW-2026 Initialize resync_again
		peer_device->resync_again = 0;

		// DW-1979
		atomic_set(&peer_device->wait_for_recv_bitmap, 0);
		atomic_set(&peer_device->wait_for_recv_rs_reply, 0);

		// DW-1965 initialize values that need to be answered or set after completion of I/O.
		atomic_set(&peer_device->unacked_cnt, 0);
		atomic_set(&peer_device->rs_pending_cnt, 0);
		atomic_set(&peer_device->rs_sect_in, 0);

		peer_device_disconnected(peer_device);
	
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();

	i = drbd_free_peer_reqs(resource, &connection->read_ee, true);
	if (i)
		drbd_err(connection, "read_ee not empty, killed %d entries\n", i);
	i = drbd_free_peer_reqs(resource, &connection->active_ee, true);
	if (i)
		drbd_err(connection, "active_ee not empty, killed %d entries\n", i);
	i = drbd_free_peer_reqs(resource, &connection->sync_ee, true);
	if (i)
		drbd_err(connection, "sync_ee not empty, killed %d entries\n", i);
	i = drbd_free_peer_reqs(resource, &connection->net_ee, true);
	if (i)
		drbd_err(connection, "net_ee not empty, killed %d entries\n", i);

	cleanup_unacked_peer_requests(connection);
	cleanup_peer_ack_list(connection);

	i = atomic_read(&connection->pp_in_use);
	if (i)
		drbd_info(connection, "pp_in_use = %d, expected 0\n", i);
	i = atomic_read(&connection->pp_in_use_by_net);
	if (i)
		drbd_info(connection, "pp_in_use_by_net = %d, expected 0\n", i);

	if (!list_empty(&connection->current_epoch->list)) {
		drbd_err(connection, "ASSERTION FAILED: connection->current_epoch->list not empty\n");

		//DW-1812 if the epoch list is not empty, remove it.
		struct drbd_epoch *epoch;
		list_for_each_entry(struct drbd_epoch, epoch, &connection->current_epoch->list, list) {
			drbd_info(connection, "ASSERTION FAILED: remove epoch barrier_nr : %u, epochs:%u\n", epoch->barrier_nr, connection->epochs);
			list_del(&epoch->list);
			kfree(epoch);
			connection->epochs--;
			if (list_empty(&connection->current_epoch->list))
				break;
		}
	}

	/* ok, no more ee's on the fly, it is safe to reset the epoch_size */
	atomic_set(&connection->current_epoch->epoch_size, 0);

	//DW-1812 initialize current_epoch.
	connection->current_epoch->barrier_nr = 0;
	connection->current_epoch->flags = 0;
	atomic_set(&connection->current_epoch->active, 0);

	connection->send.seen_any_write_yet = false;

	// DW-2035
	clear_bit(DISCONN_NO_WAIT_RESYNC, &connection->flags);

	drbd_info(connection, "Connection closed\n");

	if (resource->role[NOW] == R_PRIMARY && conn_highest_pdsk(connection) >= D_UNKNOWN)
		conn_try_outdate_peer_async(connection);

	begin_state_change(resource, &irq_flags, CS_VERBOSE | CS_LOCAL_ONLY);
	oc = connection->cstate[NOW];
	if (oc >= C_UNCONNECTED) {
		__change_cstate(connection, C_UNCONNECTED);
		/* drbd_receiver() has to be restarted after it returns */
		drbd_thread_restart_nowait(&connection->receiver);
	}
	end_state_change(resource, &irq_flags, __FUNCTION__);

	if (oc == C_DISCONNECTING)
		change_cstate_ex(connection, C_STANDALONE, CS_VERBOSE | CS_HARD | CS_LOCAL_ONLY);
}

/*
 * We support PRO_VERSION_MIN to PRO_VERSION_MAX. The protocol version
 * we can agree on is stored in agreed_pro_version.
 *
 * feature flags and the reserved array should be enough room for future
 * enhancements of the handshake protocol, and possible plugins...
 *
 * for now, they are expected to be zero, but ignored.
 */
static int drbd_send_features(struct drbd_connection *connection)
{
	struct p_connection_features *p;

	p = __conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	memset(p, 0, sizeof(*p));
	p->protocol_min = cpu_to_be32(PRO_VERSION_MIN);
	p->protocol_max = cpu_to_be32(PRO_VERSION_MAX);
	p->sender_node_id = cpu_to_be32(connection->resource->res_opts.node_id);
	p->receiver_node_id = cpu_to_be32(connection->peer_node_id);
	p->feature_flags = cpu_to_be32(PRO_FEATURES);
	return __send_command(connection, -1, P_CONNECTION_FEATURES, DATA_STREAM);
}

/*
 * return values:
 *   1 yes, we have a valid connection
 *   0 oops, did not work out, please try again
 *  -1 peer talks different language,
 *     no point in trying again, please go standalone.
 */
int drbd_do_features(struct drbd_connection *connection)
{
	/* ASSERT current == connection->receiver ... */
	struct drbd_resource *resource = connection->resource;
	struct p_connection_features *p;
	const int expect = sizeof(struct p_connection_features);
	struct packet_info pi;
	int err;

	err = drbd_send_features(connection);
	if (err){
		WDRBD_CONN_TRACE("fail drbd_send_feature err = %d\n", err); 
		return 0;
	}
	WDRBD_CONN_TRACE("success drbd_send_feature\n");

	err = drbd_recv_header(connection, &pi);
	if (err) {
		WDRBD_CONN_TRACE("fail drbd_recv_header \n");
		if (err == -EAGAIN)
			drbd_err(connection, "timeout while waiting for feature packet\n");
		return 0;
	}
	WDRBD_CONN_TRACE("success drbd_recv_header\n");

	if (pi.cmd != P_CONNECTION_FEATURES) {
		drbd_err(connection, "expected ConnectionFeatures packet, received: %s (0x%04x)\n",
			 drbd_packet_name(pi.cmd), pi.cmd);
		return -1;
	}

	if (pi.size != (unsigned int)expect) {
		drbd_err(connection, "expected ConnectionFeatures length: %u, received: %u\n",
		     expect, pi.size);
		return -1;
	}

	err = drbd_recv_all_warn(connection, (void **)&p, expect);
	if (err)
		return 0;

	p->protocol_min = be32_to_cpu(p->protocol_min);
	p->protocol_max = be32_to_cpu(p->protocol_max);
	if (p->protocol_max == 0)
		p->protocol_max = p->protocol_min;

	if (PRO_VERSION_MAX < p->protocol_min ||
	    PRO_VERSION_MIN > p->protocol_max) {
		drbd_err(connection, "incompatible DRBD dialects: "
		    "I support %d-%d, peer supports %d-%d\n",
		    PRO_VERSION_MIN, PRO_VERSION_MAX,
		    p->protocol_min, p->protocol_max);
		return -1;
	}

	connection->agreed_pro_version = min_t(int, PRO_VERSION_MAX, p->protocol_max);
	connection->agreed_features = PRO_FEATURES & be32_to_cpu(p->feature_flags);

	if (connection->agreed_pro_version < 110) {
		struct drbd_connection *connection2;
		bool multiple = false;

		rcu_read_lock();
		for_each_connection_rcu(connection2, resource) {
			if (connection == connection2)
				continue;
			multiple = true;
		}
		rcu_read_unlock();

		if (multiple) {
			drbd_err(connection, "Peer supports protocols %d-%d, but "
				 "multiple connections are only supported in protocol "
				 "110 and above\n", p->protocol_min, p->protocol_max);
			return -1;
		}
	}

	if (connection->agreed_pro_version >= 110) {
		if (be32_to_cpu(p->sender_node_id) != connection->peer_node_id) {
			drbd_err(connection, "Peer presented a node_id of %d instead of %d\n",
				 be32_to_cpu(p->sender_node_id), connection->peer_node_id);
			return 0;
		}
		if (be32_to_cpu(p->receiver_node_id) != resource->res_opts.node_id) {
			drbd_err(connection, "Peer expects me to have a node_id of %d instead of %d\n",
				 be32_to_cpu(p->receiver_node_id), resource->res_opts.node_id);
			return 0;
		}
	}

	drbd_info(connection, "Handshake to peer %d successful: "
		  "Agreed network protocol version %d\n",
		  connection->peer_node_id,
		  connection->agreed_pro_version);


	drbd_info(connection, "Feature flags enabled on protocol level: 0x%x%s%s%s.\n",
		  connection->agreed_features,
		  connection->agreed_features & DRBD_FF_TRIM ? " TRIM" : "",
		  connection->agreed_features & DRBD_FF_THIN_RESYNC ? " THIN_RESYNC" : "",
		  connection->agreed_features & DRBD_FF_WSAME ? " WRITE_SAME" :
		  connection->agreed_features ? "" : " none");

	return 1;
}

#if !defined(CONFIG_CRYPTO_HMAC) && !defined(CONFIG_CRYPTO_HMAC_MODULE)
int drbd_do_auth(struct drbd_connection *connection)
{
	drbd_err(connection, "This kernel was build without CONFIG_CRYPTO_HMAC.\n");
	drbd_err(connection, "You need to disable 'cram-hmac-alg' in drbd.conf.\n");
	return -1;
}
#else
#define CHALLENGE_LEN 64 /* must be multiple of 4 */

/* Return value:
	1 - auth succeeded,
	0 - failed, try again (network error),
	-1 - auth failed, don't try again.
*/

struct auth_challenge {
	char d[CHALLENGE_LEN];
	u32 i;
} __attribute__((packed));

int drbd_do_auth(struct drbd_connection *connection)
{
	struct auth_challenge my_challenge, *peers_ch = NULL;
	struct scatterlist sg;
	void *response;
	char *right_response = NULL;
	unsigned int key_len;
	char secret[SHARED_SECRET_MAX]; /* 64 byte */
	unsigned int resp_size;
	struct hash_desc desc;
	struct packet_info pi;
	struct net_conf *nc;
	int err, rv, dig_size;
	bool peer_is_drbd_9 = connection->agreed_pro_version >= 110;
	void *packet_body;

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	key_len = strlen(nc->shared_secret);
	memcpy(secret, nc->shared_secret, key_len);
	rcu_read_unlock();

	desc.tfm = connection->cram_hmac_tfm;
	desc.flags = 0;

	rv = crypto_hash_setkey(connection->cram_hmac_tfm, (u8 *)secret, key_len);
	if (rv) {
		drbd_err(connection, "crypto_hash_setkey() failed with %d\n", rv);
		rv = -1;
		goto fail;
	}

	get_random_bytes(my_challenge.d, sizeof(my_challenge.d));

	packet_body = __conn_prepare_command(connection, sizeof(my_challenge.d), DATA_STREAM);
	if (!packet_body) {
		rv = 0;
		goto fail;
	}
	memcpy(packet_body, my_challenge.d, sizeof(my_challenge.d));

	rv = !__send_command(connection, -1, P_AUTH_CHALLENGE, DATA_STREAM);
	if (!rv)
		goto fail;

	err = drbd_recv_header(connection, &pi);
	if (err) {
		rv = 0;
		goto fail;
	}

	if (pi.cmd != P_AUTH_CHALLENGE) {
		drbd_err(connection, "expected AuthChallenge packet, received: %s (0x%04x)\n",
			 drbd_packet_name(pi.cmd), pi.cmd);
		rv = 0;
		goto fail;
	}

	if (pi.size != sizeof(peers_ch->d)) {
		drbd_err(connection, "unexpected AuthChallenge payload.\n");
		rv = -1;
		goto fail;
	}
#ifdef _WIN32
	peers_ch = kmalloc(sizeof(*peers_ch), GFP_NOIO, '98DW');
#else
	peers_ch = kmalloc(sizeof(*peers_ch), GFP_NOIO);
#endif
	if (peers_ch == NULL) {
		drbd_err(connection, "kmalloc of peers_ch failed\n");
		rv = -1;
		goto fail;
	}

	err = drbd_recv_into(connection, peers_ch->d, sizeof(peers_ch->d));
	if (err) {
		rv = 0;
		goto fail;
	}

	if (!memcmp(my_challenge.d, peers_ch->d, sizeof(my_challenge.d))) {
		drbd_err(connection, "Peer presented the same challenge!\n");
		rv = -1;
		goto fail;
	}

	resp_size = crypto_hash_digestsize(connection->cram_hmac_tfm);
	response = __conn_prepare_command(connection, resp_size, DATA_STREAM);
	if (!response) {
		rv = 0;
		goto fail;
	}

	sg_init_table(&sg, 1);
	dig_size = pi.size;
	if (peer_is_drbd_9) {
		peers_ch->i = cpu_to_be32(connection->resource->res_opts.node_id);
		dig_size += sizeof(peers_ch->i);
	}
	sg_set_buf(&sg, peers_ch, dig_size);

	rv = crypto_hash_digest(&desc, &sg, sg.length, response);
	if (rv) {
		drbd_err(connection, "crypto_hash_digest() failed with %d\n", rv);
		rv = -1;
		goto fail;
	}

	rv = !__send_command(connection, -1, P_AUTH_RESPONSE, DATA_STREAM);
	if (!rv)
		goto fail;

	err = drbd_recv_header(connection, &pi);
	if (err) {
		rv = 0;
		goto fail;
	}

	if (pi.cmd != P_AUTH_RESPONSE) {
		drbd_err(connection, "expected AuthResponse packet, received: %s (0x%04x)\n",
			 drbd_packet_name(pi.cmd), pi.cmd);
		rv = 0;
		goto fail;
	}

	if (pi.size != resp_size) {
		drbd_err(connection, "expected AuthResponse payload of %u bytes, received %u\n",
				resp_size, pi.size);
		rv = 0;
		goto fail;
	}

	err = drbd_recv_all(connection, &response, resp_size);
	if (err) {
		rv = 0;
		goto fail;
	}
#ifdef _WIN32
	right_response = kmalloc(resp_size, GFP_NOIO, 'A8DW' );
#else
	right_response = kmalloc(resp_size, GFP_NOIO);
#endif
	if (right_response == NULL) {
		drbd_err(connection, "kmalloc of right_response failed\n");
		rv = -1;
		goto fail;
	}

	dig_size = sizeof(my_challenge.d);
	if (peer_is_drbd_9) {
		my_challenge.i = cpu_to_be32(connection->peer_node_id);
		dig_size += sizeof(my_challenge.i);
	}
	sg_set_buf(&sg, &my_challenge, dig_size);

	rv = crypto_hash_digest(&desc, &sg, sg.length, right_response);
	if (rv) {
		drbd_err(connection, "crypto_hash_digest() failed with %d\n", rv);
		rv = -1;
		goto fail;
	}

	rv = !memcmp(response, right_response, resp_size);

	if (rv)
		drbd_info(connection, "Peer authenticated using %d bytes HMAC\n",
		     resp_size);
	else
		rv = -1;

 fail:
	kfree(peers_ch);
	kfree(right_response);

	return rv;
}
#endif

int drbd_receiver(struct drbd_thread *thi)
{
	struct drbd_connection *connection = thi->connection;

	if (conn_connect(connection)) {

#ifndef _WIN32		
		blk_start_plug(&connection->receiver_plug);
#endif
		drbdd(connection);

#ifndef _WIN32
		blk_finish_plug(&connection->receiver_plug);
#endif
	}

	conn_disconnect(connection);
	return 0;
}

/* ********* acknowledge sender ******** */

void req_destroy_after_send_peer_ack(struct kref *kref)
{
	struct drbd_request *req = container_of(kref, struct drbd_request, kref);
	list_del(&req->tl_requests);
#ifdef _WIN32
    if (req->req_databuf)
    {
        kfree2(req->req_databuf);
    }

	// DW-1925 improvement req-buf-size
	atomic_dec(&req->device->resource->req_write_cnt);
    ExFreeToNPagedLookasideList(&drbd_request_mempool, req);
	
#else
	mempool_free(req, drbd_request_mempool);
#endif
}

static int process_peer_ack_list(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_request *req, *tmp;
	unsigned int idx;
	int err = 0;

	idx = 1 + connection->peer_node_id;

	spin_lock_irq(&resource->req_lock);
	req = list_first_entry(&resource->peer_ack_list, struct drbd_request, tl_requests);
	while (&req->tl_requests != &resource->peer_ack_list) {
		if (!(req->rq_state[idx] & RQ_PEER_ACK)) {
#ifdef _WIN32
            req = list_next_entry(struct drbd_request, req, tl_requests);
#else
			req = list_next_entry(req, tl_requests);
#endif
			continue;
		}
		req->rq_state[idx] &= ~RQ_PEER_ACK;
		spin_unlock_irq(&resource->req_lock);

		err = drbd_send_peer_ack(connection, req);

		spin_lock_irq(&resource->req_lock);
#ifdef _WIN32
        tmp = list_next_entry(struct drbd_request, req, tl_requests);
#else
		tmp = list_next_entry(req, tl_requests);
#endif
		kref_put(&req->kref, req_destroy_after_send_peer_ack);
		if (err)
			break;
		req = tmp;
	}
    	spin_unlock_irq(&resource->req_lock);
	return err;
}

static int got_peers_in_sync(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_peer_block_desc *p = pi->data;
	sector_t sector;
	u64 in_sync_b;
	int size;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;

	device = peer_device->device;

	if (get_ldev(device)) {
		sector = be64_to_cpu(p->sector);
		size = be32_to_cpu(p->size);
		in_sync_b = node_ids_to_bitmap(device, be64_to_cpu(p->mask));

		drbd_set_sync(device, sector, size, 0, (ULONG_PTR)in_sync_b);
		put_ldev(device);
	}

	return 0;
}

static int got_RqSReply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct p_req_state_reply *p = pi->data;
	int retcode = be32_to_cpu(p->retcode);

	if (retcode >= SS_SUCCESS)
		set_bit(TWOPC_YES, &connection->flags);
	else {
		set_bit(TWOPC_NO, &connection->flags);
		drbd_debug(connection, "Requested state change failed by peer: %s (%d)\n",
			   drbd_set_st_err_str(retcode), retcode);
	}

	wake_up(&connection->resource->state_wait);
	wake_up(&connection->ping_wait);

	return 0;
}

static int got_twopc_reply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct p_twopc_reply *p = pi->data;

	spin_lock_irq(&resource->req_lock);
	if ((unsigned int)resource->twopc_reply.initiator_node_id == be32_to_cpu(p->initiator_node_id) &&
	    resource->twopc_reply.tid == be32_to_cpu(p->tid)) {
		drbd_debug(connection, "Got a %s reply for state change %u\n",
			   drbd_packet_name(pi->cmd),
			   resource->twopc_reply.tid);

		if (pi->cmd == P_TWOPC_YES) {
			struct drbd_peer_device *peer_device;
			u64 reachable_nodes;
			u64 max_size;

			switch (resource->twopc_type) {
			case TWOPC_STATE_CHANGE:
				reachable_nodes =
					be64_to_cpu(p->reachable_nodes);

				if (resource->res_opts.node_id ==
					(unsigned int)resource->twopc_reply.initiator_node_id &&
					connection->peer_node_id ==
					(unsigned int)resource->twopc_reply.target_node_id) {
					resource->twopc_reply.target_reachable_nodes |=
						reachable_nodes;
				}
				else {
					resource->twopc_reply.reachable_nodes |=
						reachable_nodes;
				}
				resource->twopc_reply.primary_nodes |=
					be64_to_cpu(p->primary_nodes);
				resource->twopc_reply.weak_nodes |=
					be64_to_cpu(p->weak_nodes);
				break;
			case TWOPC_RESIZE:
				resource->twopc_reply.diskful_primary_nodes |=
					be64_to_cpu(p->diskful_primary_nodes);
				max_size = be64_to_cpu(p->max_possible_size);
				resource->twopc_reply.max_possible_size =
					min_t(sector_t, resource->twopc_reply.max_possible_size,
					max_size);
				peer_device = conn_peer_device(connection, resource->twopc_reply.vnr);
				if (peer_device)
					peer_device->max_size = max_size;
				break;
			}
		}

		if (pi->cmd == P_TWOPC_YES)
			set_bit(TWOPC_YES, &connection->flags);
		else if (pi->cmd == P_TWOPC_NO)
			set_bit(TWOPC_NO, &connection->flags);
		else if (pi->cmd == P_TWOPC_RETRY)
			set_bit(TWOPC_RETRY, &connection->flags);
		if (cluster_wide_reply_ready(resource)) {
			int my_node_id = resource->res_opts.node_id;
			if (resource->twopc_reply.initiator_node_id == my_node_id) {
				wake_up(&resource->state_wait);
			} else if (resource->twopc_work.cb == NULL) {
				/* in case the timeout timer was not quicker in queuing the work... */
				resource->twopc_work.cb = nested_twopc_work;
				drbd_queue_work(&resource->work, &resource->twopc_work);
			}
		}
	} else {
		drbd_debug(connection, "Ignoring %s reply for state change %u\n",
			   drbd_packet_name(pi->cmd),
			   be32_to_cpu(p->tid));
	}
	spin_unlock_irq(&resource->req_lock);

	return 0;
}

void twopc_connection_down(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
#ifndef _WIN32
	assert_spin_locked(&resource->req_lock);
#endif
	if (resource->twopc_reply.initiator_node_id != -1 &&
	    test_bit(TWOPC_PREPARED, &connection->flags)) {
#ifdef _WIN32_SIMPLE_TWOPC // DW-1408
		set_bit(TWOPC_NO, &connection->flags);
#else
		set_bit(TWOPC_RETRY, &connection->flags);
#endif
		if (cluster_wide_reply_ready(resource)) {
			int my_node_id = resource->res_opts.node_id;
			if (resource->twopc_reply.initiator_node_id == my_node_id) {
				wake_up(&resource->state_wait);
			} else if (resource->twopc_work.cb == NULL) {
				/* in case the timeout timer was not quicker in queuing the work... */
				resource->twopc_work.cb = nested_twopc_work;
				drbd_queue_work(&resource->work, &resource->twopc_work);
			}
		}
	}
}

static int got_Ping(struct drbd_connection *connection, struct packet_info *pi)
{
	UNREFERENCED_PARAMETER(pi);
	return drbd_send_ping_ack(connection);

}

static int got_PingAck(struct drbd_connection *connection, struct packet_info *pi)
{
	UNREFERENCED_PARAMETER(pi);
	if (!test_and_set_bit(GOT_PING_ACK, &connection->flags))
		wake_up(&connection->ping_wait);

	return 0;
}

static int got_IsInSync(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_ack *p = pi->data;
	sector_t sector = be64_to_cpu(p->sector);
	int blksize = be32_to_cpu(p->blksize);

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	D_ASSERT(device, connection->agreed_pro_version >= 89);

	update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

	if (get_ldev(device)) {
		drbd_rs_complete_io(peer_device, sector, __FUNCTION__);
		drbd_set_in_sync(peer_device, sector, blksize);
		/* rs_same_csums is supposed to count in units of BM_BLOCK_SIZE */
		peer_device->rs_same_csum += (blksize >> BM_BLOCK_SHIFT);
		// DW-1942 applied to release io-error value.
		check_and_clear_io_error_in_secondary(peer_device);
		put_ldev(device);
	}
	dec_rs_pending(peer_device);
	atomic_add(blksize >> 9, &peer_device->rs_sect_in);

	return 0;
}

static int
validate_req_change_req_state(struct drbd_peer_device *peer_device, u64 id, sector_t sector,
			      struct rb_root *root, const char *func,
			      enum drbd_req_event what, bool missing_ok)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_request *req;
	struct bio_and_error m;

	spin_lock_irq(&device->resource->req_lock);
	req = find_request(device, root, id, sector, missing_ok, func);
	if (unlikely(!req)) {
		spin_unlock_irq(&device->resource->req_lock);
		return -EIO;
	}
#ifdef DRBD_TRACE	
	WDRBD_TRACE("(%s) validate_req_change_req_state: before __req_mod! IRQL(%d) \n", current->comm, KeGetCurrentIrql());
#endif
	__req_mod(req, what, peer_device, &m);
	spin_unlock_irq(&device->resource->req_lock);

#ifdef DRBD_TRACE	
	WDRBD_TRACE("(%s) validate_req_change_req_state: after __req_mod! IRQL(%d) \n", current->comm, KeGetCurrentIrql());
#endif

	if (m.bio)
#ifdef _WIN32
		complete_master_bio(device, &m, __func__, __LINE__);
#else
		complete_master_bio(device, &m);
#endif

	return 0;
}

// DW-1929
static void try_change_ahead_to_sync_source(struct drbd_connection *connection)
{
	int vnr;
	struct drbd_peer_device *peer_device;

	rcu_read_lock();
	// DW-1929 check AHEAD_TO_SYNC_SOURCE in connection unit.
	idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
		if (peer_device->repl_state[NOW] == L_AHEAD &&
			// DW-1817 When exiting AHEAD mode, check only the replicated data.
			//There is no need to wait until the buffer is completely emptied, so it is not necessary to check the synchronization data. 
			//And most of the time, replication data will occupy most of it by DRBD's sync rate controller.
			// DW-1929 add connection->rs_in_flight
			(atomic_read64(&connection->rs_in_flight) + atomic_read64(&connection->ap_in_flight)) == 0 &&
			!test_and_set_bit(AHEAD_TO_SYNC_SOURCE, &peer_device->flags)) {
			peer_device->start_resync_side = L_SYNC_SOURCE;
			peer_device->start_resync_timer.expires = jiffies + HZ;
			add_timer(&peer_device->start_resync_timer);
		}
	}
	rcu_read_unlock();
}

static int got_BlockAck(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_ack *p = pi->data;
	sector_t sector = be64_to_cpu(p->sector);
	int blksize = be32_to_cpu(p->blksize);
#ifdef _WIN32
	enum drbd_req_event what = 0;
#else
	enum drbd_req_event what;
#endif
	
#ifdef DRBD_TRACE
	WDRBD_TRACE("pi-cmd 0x%x(%s) sect:0x%llx sz:%d\n", pi->cmd, drbd_packet_name(pi->cmd), sector, blksize);
#endif

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
	//DW-1601 ID_SYNCER_SPLIT_DONE == ID_SYNCER
	if (connection->agreed_pro_version >= 113) {
		if (p->block_id != ID_SYNCER_SPLIT)
			update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

		if (p->block_id == ID_SYNCER_SPLIT || p->block_id == ID_SYNCER_SPLIT_DONE) {
			drbd_set_in_sync(peer_device, sector, blksize);
			//DW-1601 add DW-1859
			if (device->resource->role[NOW] == R_PRIMARY)
				check_and_clear_io_error_in_primary(device);
			else
				check_and_clear_io_error_in_secondary(peer_device);

			if (p->block_id == ID_SYNCER_SPLIT_DONE) 
				dec_rs_pending(peer_device);

			//DW-1601 add DW-1817
			if (atomic_sub_return64(blksize, &connection->rs_in_flight) < 0)
				atomic_set64(&connection->rs_in_flight, 0);

			//DW-1929
			try_change_ahead_to_sync_source(connection);

			return 0;
		}
	}
	else 
#endif
	{
		update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

		if (p->block_id == ID_SYNCER) {
			drbd_set_in_sync(peer_device, sector, blksize);

			if(device->resource->role[NOW] == R_PRIMARY)
				check_and_clear_io_error_in_primary(device);
			else
				check_and_clear_io_error_in_secondary(peer_device);
			dec_rs_pending(peer_device);
			//DW-1817 
			//At this point, it means that the synchronization data has been removed from the send buffer because the synchronization transfer is complete.
			if (atomic_sub_return64(blksize, &connection->rs_in_flight) < 0)
				atomic_set64(&connection->rs_in_flight, 0);

			//DW-1929
			try_change_ahead_to_sync_source(connection);

			

			return 0;
		}
	}


	switch (pi->cmd) {
	case P_RS_WRITE_ACK:
		what = WRITE_ACKED_BY_PEER_AND_SIS;
		break;
	case P_WRITE_ACK:
		what = WRITE_ACKED_BY_PEER;
		break;
	case P_RECV_ACK:
		what = RECV_ACKED_BY_PEER;
		break;
	case P_SUPERSEDED:
		what = DISCARD_WRITE;
		break;
	case P_RETRY_WRITE:
		what = POSTPONE_WRITE;
		break;
	default:
		BUG();
	}

	return validate_req_change_req_state(peer_device, p->block_id, sector,
					     &device->write_requests, __func__,
					     what, false);
}

static int got_NegAck(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_ack *p = pi->data;
	sector_t sector = be64_to_cpu(p->sector);
	int size = be32_to_cpu(p->blksize);
	int err;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	//DW-1601 
#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
	if (connection->agreed_pro_version >= 113) {
		if (p->block_id != ID_SYNCER_SPLIT)
			update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

		if (peer_device->disk_state[NOW] == D_UP_TO_DATE)
			set_bit(GOT_NEG_ACK, &peer_device->flags);

		if (p->block_id == ID_SYNCER_SPLIT || p->block_id == ID_SYNCER_SPLIT_DONE) {
			drbd_info(connection, "drbd_rs_failed_io secotr : %llu, size %d\n", sector, size);
			drbd_rs_failed_io(peer_device, sector, size);
			if (p->block_id == ID_SYNCER_SPLIT_DONE)
				dec_rs_pending(peer_device);

			//DW-1601 add DW-1817
			if (atomic_sub_return64(size, &connection->rs_in_flight) < 0)
				atomic_set64(&connection->rs_in_flight, 0);

			//DW-1929
			try_change_ahead_to_sync_source(connection);

			return 0;
		}

	}
	else 
#endif
	{
		update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

		if (peer_device->disk_state[NOW] == D_UP_TO_DATE)
			set_bit(GOT_NEG_ACK, &peer_device->flags);

		if (p->block_id == ID_SYNCER) {
			dec_rs_pending(peer_device);
			drbd_rs_failed_io(peer_device, sector, size);

			//DW-1817
			//This means that the resync data is definitely free from send-buffer.
			if (atomic_sub_return64(size, &connection->rs_in_flight) < 0)
				atomic_set64(&connection->rs_in_flight, 0);

			//DW-1929
			try_change_ahead_to_sync_source(connection);

			return 0;
		}
	}

	err = validate_req_change_req_state(peer_device, p->block_id, sector,
					    &device->write_requests, __func__,
					    NEG_ACKED, true);
#ifdef _WIN32
	// MODIFIED_BY_MANTECH: Set out-of-sync if peer sent negative ack for this request, doesn't matter req exists or not.
	drbd_set_out_of_sync(peer_device, sector, size);
#else
	if (err) {
		/* Protocol A has no P_WRITE_ACKs, but has P_NEG_ACKs.
		   The master bio might already be completed, therefore the
		   request is no longer in the collision hash. */
		/* In Protocol B we might already have got a P_RECV_ACK
		   but then get a P_NEG_ACK afterwards. */
		drbd_set_out_of_sync(peer_device, sector, size);
	}
#endif
	return 0;
}

static int got_NegDReply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_ack *p = pi->data;
	sector_t sector = be64_to_cpu(p->sector);

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

	drbd_err(device, "Got NegDReply; Sector %llus, len %u.\n",
		 (unsigned long long)sector, be32_to_cpu(p->blksize));

	return validate_req_change_req_state(peer_device, p->block_id, sector,
					     &device->read_requests, __func__,
					     NEG_ACKED, false);
}

static int got_NegRSDReply(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	sector_t sector;
	int size;
	struct p_block_ack *p = pi->data;
	ULONG_PTR bit;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	sector = be64_to_cpu(p->sector);
	size = be32_to_cpu(p->blksize);

	update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

	dec_rs_pending(peer_device);

	if (get_ldev_if_state(device, D_DETACHING)) {
		drbd_rs_complete_io(peer_device, sector, __FUNCTION__);

		//DW-1886
		if (is_sync_target(peer_device))
			peer_device->rs_send_req -= size;

		switch (pi->cmd) {
		case P_NEG_RS_DREPLY:
			drbd_rs_failed_io(peer_device, sector, size);

			// DW-1946 fix bug that Synchronization stops when SyncSource io-error occurs continuously.
			// Increase rs_sect_in to decrease the value of rs_in_flight normally in drbd_rs_number_requests().
			atomic_add(size >> 9, &peer_device->rs_sect_in);

			break;
		case P_RS_CANCEL:
			//DW-1807 Ignore P_RS_CANCEL if peer_device is not in resync.
			//DW-1846 receive data when synchronization is in progress.
			if (is_sync_target(peer_device)) {
				bit = (ULONG_PTR)BM_SECT_TO_BIT(sector);

				mutex_lock(&device->bm_resync_fo_mutex);
				device->bm_resync_fo = min(device->bm_resync_fo, bit);
				mutex_unlock(&device->bm_resync_fo_mutex);

				atomic_add(size >> 9, &peer_device->rs_sect_in);
				mod_timer(&peer_device->resync_timer, jiffies + SLEEP_TIME);
			}
			break;
		default:
			BUG();
		}
		put_ldev(device);
	}

	return 0;
}

static int got_BarrierAck(struct drbd_connection *connection, struct packet_info *pi)
{
	struct p_barrier_ack *p = pi->data;

#ifdef DRBD_TRACE
	WDRBD_TRACE("do tl_release\n");
#endif
	tl_release(connection, p->barrier, be32_to_cpu(p->set_size));

	try_change_ahead_to_sync_source(connection);

	return 0;
}

static int got_OVResult(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct p_block_ack *p = pi->data;
	sector_t sector;
	int size;

	peer_device = conn_peer_device(connection, pi->vnr);
	if (!peer_device)
		return -EIO;
	device = peer_device->device;

	sector = be64_to_cpu(p->sector);
	size = be32_to_cpu(p->blksize);

	update_peer_seq(peer_device, be32_to_cpu(p->seq_num));

	if (be64_to_cpu(p->block_id) == ID_OUT_OF_SYNC)
		drbd_ov_out_of_sync_found(peer_device, sector, size);
	else
		ov_out_of_sync_print(peer_device);

	if (!get_ldev(device))
		return 0;

	drbd_rs_complete_io(peer_device, sector, __FUNCTION__);
	dec_rs_pending(peer_device);

	--peer_device->ov_left;

	/* let's advance progress step marks only for every other megabyte */
	if ((peer_device->ov_left & 0x200) == 0x200)
		drbd_advance_rs_marks(peer_device, peer_device->ov_left);

	if (peer_device->ov_left == 0) {
#ifdef _WIN32
        struct drbd_peer_device_work *dw = kmalloc(sizeof(*dw), GFP_NOIO, 'F2DW');
#else
		struct drbd_peer_device_work *dw = kmalloc(sizeof(*dw), GFP_NOIO);
#endif
		if (dw) {
			dw->w.cb = w_ov_finished;
			dw->peer_device = peer_device;
			drbd_queue_work(&connection->sender_work, &dw->w);
		} else {
			drbd_err(device, "kmalloc(dw) failed.");
			ov_out_of_sync_print(peer_device);
			drbd_resync_finished(peer_device, D_MASK);
		}
	}
	put_ldev(device);
	return 0;
}

static int got_skip(struct drbd_connection *connection, struct packet_info *pi)
{
	UNREFERENCED_PARAMETER(pi);
	UNREFERENCED_PARAMETER(connection);
	return 0;
}

static ULONG_PTR node_ids_to_bitmap(struct drbd_device *device, u64 node_ids) __must_hold(local)
{
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	ULONG_PTR bitmap_bits = 0;
	ULONG_PTR node_id;

#ifdef _WIN32
	for_each_set_bit(node_id, (ULONG_PTR *)&node_ids, DRBD_NODE_ID_MAX) {
#else
	for_each_set_bit(node_id, (unsigned long *)&node_ids, DRBD_NODE_ID_MAX) {
#endif
		int bitmap_bit = peer_md[node_id].bitmap_index;
		if (bitmap_bit >= 0)
			bitmap_bits |= NODE_MASK(bitmap_bit);
	}
	return bitmap_bits;
}



static int w_send_out_of_sync(struct drbd_work *w, int cancel)
{
	UNREFERENCED_PARAMETER(cancel);

	struct drbd_peer_request *peer_req =
		container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->send_oos_peer_device;
	struct drbd_device *device = peer_device->device;
	u64 in_sync = peer_req->send_oos_in_sync;
	int err;

	err = drbd_send_out_of_sync(peer_device, &peer_req->i);
	peer_req->sent_oos_nodes |= NODE_MASK(peer_device->node_id);

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (!(NODE_MASK(peer_device->node_id) & in_sync) &&
			is_sync_source(peer_device) &&
			!(peer_req->sent_oos_nodes & NODE_MASK(peer_device->node_id))) {
			rcu_read_unlock();
			peer_req->send_oos_peer_device = peer_device;
			drbd_queue_work(&peer_device->connection->sender_work,
				&peer_req->w);
			return err;
		}
	}
	rcu_read_unlock();
	drbd_free_peer_req(peer_req);

	return err;
}

static void notify_sync_targets_or_free(struct drbd_peer_request *peer_req, u64 in_sync)
{
	struct drbd_device *device = peer_req->peer_device->device;
	struct drbd_peer_device *peer_device;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (!(NODE_MASK(peer_device->node_id) & in_sync) &&
			is_sync_source(peer_device)) {
			rcu_read_unlock();
			peer_req->sent_oos_nodes = 0;
			peer_req->send_oos_peer_device = peer_device;
			peer_req->send_oos_in_sync = in_sync;
			peer_req->w.cb = w_send_out_of_sync;
			drbd_queue_work(&peer_device->connection->sender_work,
				&peer_req->w);
			return;
		}
	}
	rcu_read_unlock();
	drbd_free_peer_req(peer_req);
}


static int got_peer_ack(struct drbd_connection *connection, struct packet_info *pi)
{
	struct drbd_resource *resource = connection->resource;
	struct p_peer_ack *p = pi->data;
	u64 dagtag, in_sync;
	struct drbd_peer_request *peer_req, *tmp;
#ifdef _WIN32
	struct list_head work_list = { 0, }; 
#else
	struct list_head work_list;
#endif

	dagtag = be64_to_cpu(p->dagtag);
	in_sync = be64_to_cpu(p->mask);
#ifdef _WIN32_TRACE_PEER_DAGTAG    
	WDRBD_INFO("got_peer_ack dagtag:%llx in_sync:%llx\n", dagtag, in_sync);
#endif
	
	spin_lock_irq(&resource->req_lock);
#ifdef _WIN32
	list_for_each_entry(struct drbd_peer_request, peer_req, &connection->peer_requests, recv_order) {
#else
	list_for_each_entry(peer_req, &connection->peer_requests, recv_order) {
#endif
		if (dagtag == peer_req->dagtag_sector)
			goto found;
	}
	spin_unlock_irq(&resource->req_lock);

	drbd_err(connection, "peer request with dagtag %llu not found\n", dagtag);
	return -EIO;

found:
	list_cut_position(&work_list, &connection->peer_requests, &peer_req->recv_order);
	spin_unlock_irq(&resource->req_lock);

#ifdef _WIN32	
	list_for_each_entry_safe(struct drbd_peer_request, peer_req, tmp, &work_list, recv_order) {
#else
	list_for_each_entry_safe(peer_req, tmp, &work_list, recv_order) {
#endif
		struct drbd_peer_device *peer_device = peer_req->peer_device;
		ULONG_PTR in_sync_b;
		//DW-1872 you must set the device that matches the peer_request.
		struct drbd_device *device = peer_req->peer_device->device;
#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-1099: Do not set or clear sender's out-of-sync, it's only for managing neighbor's out-of-sync.
		ULONG_PTR set_sync_mask = INTPTR_MAX;
#endif    

		if (get_ldev(device)) {
			in_sync_b = node_ids_to_bitmap(device, in_sync);
#ifdef _WIN32
			// MODIFIED_BY_MANTECH DW-1099: Do not set or clear sender's out-of-sync, it's only for managing neighbor's out-of-sync.
			clear_bit(peer_device->bitmap_index, &set_sync_mask);
			drbd_set_sync(device, peer_req->i.sector,
				peer_req->i.size, ~in_sync_b, (ULONG_PTR)set_sync_mask);
#ifdef _WIN32_TRACE_PEER_DAGTAG			
			WDRBD_INFO("got_peer_ack drbd_set_sync device:%p, peer_req->i.sector:%llx, peer_req->i.size:%d, in_sync_b:%llx, set_sync_mask:%llx\n", 
				device, peer_req->i.sector, peer_req->i.size, in_sync_b, set_sync_mask);
#endif

#else
			drbd_set_sync(device, peer_req->i.sector,
				      peer_req->i.size, ~in_sync_b, -1);
#endif
			drbd_al_complete_io(device, &peer_req->i);
			put_ldev(device);
		}
		list_del(&peer_req->recv_order);
		notify_sync_targets_or_free(peer_req, in_sync);
	}

	return 0;
}

/* Caller has to hold resource->req_lock */
void apply_unacked_peer_requests(struct drbd_connection *connection)
{
	struct drbd_peer_request *peer_req;
#ifdef _WIN32
	list_for_each_entry(struct drbd_peer_request, peer_req, &connection->peer_requests, recv_order) {
#else
	list_for_each_entry(peer_req, &connection->peer_requests, recv_order) {
#endif
		struct drbd_peer_device *peer_device = peer_req->peer_device;
		struct drbd_device *device = peer_device->device;
		int bitmap_index = peer_device->bitmap_index;
		ULONG_PTR mask = ~(bitmap_index != -1 ? 1UL << bitmap_index : 0UL);

		drbd_set_sync(device, peer_req->i.sector, peer_req->i.size,
			      mask, mask);
	}
}

static void cleanup_unacked_peer_requests(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_request *peer_req, *tmp;

	LIST_HEAD(work_list);

	spin_lock_irq(&resource->req_lock);
	list_splice_init(&connection->peer_requests, &work_list);
	spin_unlock_irq(&resource->req_lock);
#ifdef _WIN32
	list_for_each_entry_safe(struct drbd_peer_request, peer_req, tmp, &work_list, recv_order) {
#else
	list_for_each_entry_safe(peer_req, tmp, &work_list, recv_order) {
#endif
		struct drbd_peer_device *peer_device = peer_req->peer_device;
		struct drbd_device *device = peer_device->device;
		int bitmap_index = peer_device->bitmap_index;
		ULONG_PTR mask = ~(bitmap_index != -1 ? 1UL << bitmap_index : 0UL);

		if (get_ldev(device)) {
			drbd_set_sync(device, peer_req->i.sector, peer_req->i.size,
				mask, mask);
			drbd_al_complete_io(device, &peer_req->i);
			put_ldev(device);
		}
		list_del(&peer_req->recv_order);
		notify_sync_targets_or_free(peer_req, 0);
	}
}

static void destroy_request(struct kref *kref)
{
	struct drbd_request *req =
		container_of(kref, struct drbd_request, kref);

	list_del(&req->tl_requests);
#ifdef _WIN32
    if (req->req_databuf)
    {
        kfree2(req->req_databuf);
    }

	// DW-1925 improvement req-buf-size
	atomic_dec(&req->device->resource->req_write_cnt);
    ExFreeToNPagedLookasideList(&drbd_request_mempool, req);

#else
	mempool_free(req, drbd_request_mempool);
#endif
}

static void cleanup_peer_ack_list(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_request *req, *tmp;
	int idx;

	spin_lock_irq(&resource->req_lock);
	idx = 1 + connection->peer_node_id;
#ifdef _WIN32
	list_for_each_entry_safe(struct drbd_request, req, tmp, &resource->peer_ack_list, tl_requests) {
#else
	list_for_each_entry_safe(req, tmp, &resource->peer_ack_list, tl_requests) {
#endif
		if (!(req->rq_state[idx] & RQ_PEER_ACK))
			continue;
		req->rq_state[idx] &= ~RQ_PEER_ACK;
		kref_put(&req->kref, destroy_request);
	}
	spin_unlock_irq(&resource->req_lock);
}

struct meta_sock_cmd {
	size_t pkt_size;
	int (*fn)(struct drbd_connection *connection, struct packet_info *);
};

static void set_rcvtimeo(struct drbd_connection *connection, bool ping_timeout)
{
	long t;
	struct net_conf *nc;
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;


	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	t = ping_timeout ? nc->ping_timeo : nc->ping_int;
	rcu_read_unlock();

	t *= HZ;
	if (ping_timeout)
		t /= 10;

	tr_ops->set_rcvtimeo(transport, CONTROL_STREAM, t);
}

static void set_ping_timeout(struct drbd_connection *connection)
{
	set_rcvtimeo(connection, 1);
}

static void set_idle_timeout(struct drbd_connection *connection)
{
	set_rcvtimeo(connection, 0);
}

static struct meta_sock_cmd ack_receiver_tbl[] = {
	[P_PING]	    = { 0, got_Ping },
	[P_PING_ACK]	    = { 0, got_PingAck },
	[P_RECV_ACK]	    = { sizeof(struct p_block_ack), got_BlockAck },
	[P_WRITE_ACK]	    = { sizeof(struct p_block_ack), got_BlockAck },
	[P_RS_WRITE_ACK]    = { sizeof(struct p_block_ack), got_BlockAck },
	[P_SUPERSEDED]      = { sizeof(struct p_block_ack), got_BlockAck },
	[P_NEG_ACK]	    = { sizeof(struct p_block_ack), got_NegAck },
	[P_NEG_DREPLY]	    = { sizeof(struct p_block_ack), got_NegDReply },
	[P_NEG_RS_DREPLY]   = { sizeof(struct p_block_ack), got_NegRSDReply },
	[P_OV_RESULT]	    = { sizeof(struct p_block_ack), got_OVResult },
	[P_BARRIER_ACK]	    = { sizeof(struct p_barrier_ack), got_BarrierAck },
	[P_STATE_CHG_REPLY] = { sizeof(struct p_req_state_reply), got_RqSReply },
	[P_RS_IS_IN_SYNC]   = { sizeof(struct p_block_ack), got_IsInSync },
	[P_DELAY_PROBE]     = { sizeof(struct p_delay_probe93), got_skip },
	[P_RS_CANCEL]       = { sizeof(struct p_block_ack), got_NegRSDReply },
	[P_CONN_ST_CHG_REPLY]={ sizeof(struct p_req_state_reply), got_RqSReply },
	[P_RETRY_WRITE]	    = { sizeof(struct p_block_ack), got_BlockAck },
	[P_PEER_ACK]	    = { sizeof(struct p_peer_ack), got_peer_ack },
	[P_PEERS_IN_SYNC]   = { sizeof(struct p_peer_block_desc), got_peers_in_sync },
	[P_TWOPC_YES]       = { sizeof(struct p_twopc_reply), got_twopc_reply },
	[P_TWOPC_NO]        = { sizeof(struct p_twopc_reply), got_twopc_reply },
	[P_TWOPC_RETRY]     = { sizeof(struct p_twopc_reply), got_twopc_reply },
};

int drbd_ack_receiver(struct drbd_thread *thi)
{
	struct drbd_connection *connection = thi->connection;
	struct meta_sock_cmd *cmd = NULL;
	struct packet_info pi;
#ifdef _WIN32
    ULONG_PTR pre_recv_jif;
#else
	unsigned long pre_recv_jif;
#endif
	int rv;
	void *buffer;
	int received = 0, rflags = 0;
	unsigned int header_size = drbd_header_size(connection);
	int expect   = header_size;
	bool ping_timeout_active = false;
#ifndef _WIN32
	struct sched_param param = { .sched_priority = 2 };
#endif
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;

#ifndef _WIN32
	rv = sched_setscheduler(current, SCHED_RR, &param);
	if (rv < 0)
		drbd_err(connection, "drbd_ack_receiver: ERROR set priority, ret=%d\n", rv);
#endif

	while (get_t_state(thi) == RUNNING) {
		drbd_thread_current_set_cpu(thi);

		drbd_reclaim_net_peer_reqs(connection);

#ifdef _WIN32
		// DW-1539 alarm req-buf overflow and disconnect
		if (connection->resource->breqbuf_overflow_alarm == TRUE) {
			drbd_err(connection, "drbd_resource:%p drbd_req overflow alarm\n");
			if (connection->resource->res_opts.on_req_write_congestion == ORWC_DISCONNECT) 	// DW-1925 DISCONNECT or not based on on-req-write-congestion
				goto reconnect;
		}
#endif
		if (test_and_clear_bit(SEND_PING, &connection->flags)) {
#ifdef _WIN32
			int ping_ret;
			ping_ret = drbd_send_ping(connection);
			if (ping_ret) {
				if (ping_ret == -EINTR && current->sig == SIGXCPU)
				{
					WDRBD_INFO("got SIGXCPU during ping\n");
					flush_signals(current);
				}
#else
			if (drbd_send_ping(connection)) {
#endif
				drbd_err(connection, "drbd_send_ping has failed (%d)\n", ping_ret);
				goto reconnect;
			}
			set_ping_timeout(connection);
			ping_timeout_active = true;
		}

		pre_recv_jif = jiffies;
		rv = tr_ops->recv(transport, CONTROL_STREAM, &buffer, expect - received, rflags);
        
		/* Note:
		 * -EINTR	 (on meta) we got a signal
		 * -EAGAIN	 (on meta) rcvtimeo expired
		 * -ECONNRESET	 other side closed the connection
		 * -ERESTARTSYS  (on data) we got a signal
		 * rv <  0	 other than above: unexpected error!
		 * rv == expected: full header or command
		 * rv <  expected: "woken" by signal during receive
		 * rv == 0	 : "connection shut down by peer"
		 */
		if (likely(rv > 0)) {
			received += rv;

			if (received < expect)
				rflags = GROW_BUFFER;

		} else if (rv == 0) {
			if (test_bit(DISCONNECT_EXPECTED, &connection->flags)) {
				long t;
				rcu_read_lock();
				t = rcu_dereference(connection->transport.net_conf)->ping_timeo * HZ/10;
				rcu_read_unlock();
#ifdef _WIN32
				wait_event_timeout(t, connection->ping_wait, 
				               connection->cstate[NOW] < C_CONNECTED, 
							   t);
#else
				t = wait_event_timeout(connection->ping_wait,
						       connection->cstate[NOW] < C_CONNECTED,
						       t);
#endif
				if (t)
					break;
			}
			drbd_err(connection, "meta connection shut down by peer.\n");
			goto reconnect;
		} else if (rv == -EAGAIN) {
			/* If the data socket received something meanwhile,
			 * that is good enough: peer is still alive. */

			if (time_after(connection->last_received, pre_recv_jif))
				continue;
			if (ping_timeout_active) {
				drbd_err(connection, "PingAck did not arrive in time.\n");
				goto reconnect;
			}
			set_bit(SEND_PING, &connection->flags);
			continue;
		} else if (rv == -EINTR) {
			/* maybe drbd_thread_stop(): the while condition will notice.
			 * maybe woken for send_ping: we'll send a ping above,
			 * and change the rcvtimeo */
#ifdef _WIN32
			if (current->sig == SIGXCPU)
			{
				//WDRBD_INFO("got SIGXCPU during rx.\n");
			}
#endif
			flush_signals(current);
			continue;
		} else {
			drbd_err(connection, "sock_recvmsg returned %d\n", rv);
			goto reconnect;
		}

		if (received == expect && cmd == NULL) {
			if (decode_header(connection, buffer, &pi))
				goto reconnect;

			cmd = &ack_receiver_tbl[pi.cmd];
			if (pi.cmd >= ARRAY_SIZE(ack_receiver_tbl) || !cmd->fn) {
				drbd_err(connection, "Unexpected meta packet %s (0x%04x)\n",
					 drbd_packet_name(pi.cmd), pi.cmd);
				goto disconnect;
			}
			expect = (int)(header_size + cmd->pkt_size);
			if (pi.size != expect - header_size) {
				drbd_err(connection, "Wrong packet size on meta (c: %d, l: %u)\n",
					pi.cmd, pi.size);
				goto reconnect;
			}
			rflags = 0;
		}
		if (received == expect) {
#ifdef _WIN32
			int err = 0;
#else
			bool err;
#endif
			pi.data = buffer;
			if (cmd) {
#ifdef _WIN32
				drbd_debug(connection, "receiving %s, l: %d\n", drbd_packet_name(pi.cmd), pi.size); 
#endif
				err = cmd->fn(connection, &pi);
				if (err)
					drbd_debug(connection, "receiving error e: %d\n", err);
			}

			if (err) {
#ifdef _WIN32

				if (err == -EINTR && current->sig == SIGXCPU)
				{
					//WDRBD_INFO("got SIGXCPU during fn(%s)\n", drbd_packet_name(pi.cmd));
					flush_signals(current);
					goto ignore_sig;
				}
#endif
#ifndef _WIN32
				drbd_err(connection, "%pf failed\n", cmd->fn);
#endif
				goto reconnect;
			}
#ifdef _WIN32
		ignore_sig:
#endif
			connection->last_received = jiffies;

			if (cmd == &ack_receiver_tbl[P_PING_ACK]) {
				set_idle_timeout(connection);
				ping_timeout_active = false;
			}

			received = 0;
			expect = header_size;
			cmd = NULL;
			rflags = 0;
		}
	}

	if (false, false) {
reconnect:
		change_cstate_ex(connection, C_NETWORK_FAILURE, CS_HARD);
	}
	if (false,false) {
disconnect:
		change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
	}

	drbd_info(connection, "ack_receiver terminated\n");

	return 0;
}

void drbd_send_acks_wf(struct work_struct *ws)
{
	struct drbd_connection *connection =
		container_of(ws, struct drbd_connection, send_acks_work);
	struct drbd_transport *transport = &connection->transport;
	struct net_conf *nc;
	int tcp_cork, err;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	tcp_cork = nc->tcp_cork;
	rcu_read_unlock();

	/* TODO: conditionally cork; it may hurt latency if we cork without
	   much to send */
	if (tcp_cork)
		drbd_cork(connection, CONTROL_STREAM);
	err = drbd_finish_peer_reqs(connection);
	
	/* but unconditionally uncork unless disabled */
	if (tcp_cork)
		drbd_uncork(connection, CONTROL_STREAM);

#ifdef _WIN32
	if (err)
		change_cstate_ex(connection, C_NETWORK_FAILURE, CS_HARD); // _WIN32 // DW-637 "change_state(C_DISCONNECTING)" is a problem that go to standalone status on disconnecting phase.
#else
	if (err)
		change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
#endif
}

void drbd_send_peer_ack_wf(struct work_struct *ws)
{
	struct drbd_connection *connection =
		container_of(ws, struct drbd_connection, peer_ack_work);

	if (process_peer_ack_list(connection)){
#ifdef _WIN32 // MODIFIED_BY_MANTECH DW-1301: avoid a connection to go Standalone.  	
		//DW-1785 If it is not already in C_DISCONNECTING state, change it.
		if (connection->cstate[NOW] != C_DISCONNECTING) {
			drbd_debug(connection, "change the connection state to C_UNCONNECTED\n");
			__change_cstate(connection, C_UNCONNECTED);
		}
#else 
		change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
#endif 
	}
}

#ifdef _WIN32
// MODIFIED_BY_MANTECH DW-1191: send queued out-of-syncs, it doesn't rely on drbd request.
void drbd_send_out_of_sync_wf(struct work_struct *ws)
{
	struct drbd_peer_device *peer_device =
		container_of(ws, struct drbd_peer_device, send_oos_work);
	struct drbd_oos_no_req *send_oos, *tmp;

	spin_lock_irq(&peer_device->send_oos_lock);
	send_oos = list_first_entry(&peer_device->send_oos_list, struct drbd_oos_no_req, oos_list_head);

	while (&send_oos->oos_list_head != &peer_device->send_oos_list)
	{
		struct drbd_interval interval;
		interval.sector = send_oos->sector;
		interval.size = send_oos->size;

		spin_unlock_irq(&peer_device->send_oos_lock);

		drbd_send_out_of_sync(peer_device, &interval);

		spin_lock_irq(&peer_device->send_oos_lock);
		
		tmp = list_next_entry(struct drbd_oos_no_req, send_oos, oos_list_head);

		list_del(&send_oos->oos_list_head);
		kfree(send_oos);

		send_oos = tmp;
	}
	spin_unlock_irq(&peer_device->send_oos_lock);
}
#endif

#ifndef _WIN32
EXPORT_SYMBOL(drbd_alloc_pages); /* for transports */
EXPORT_SYMBOL(drbd_free_pages);
#endif
