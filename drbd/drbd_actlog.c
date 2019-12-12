﻿/*
   drbd_actlog.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2003-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 2003-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2003-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

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
#include "drbd_windows.h"
#include "drbd_wingenl.h"
#include "windows/drbd.h"
#include "linux-compat/drbd_endian.h"
#include "linux-compat/idr.h"
#else
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/drbd.h>
#include <linux/drbd_limits.h>
#include <linux/dynamic_debug.h>
#endif
#include "drbd_int.h"
#include "./drbd-kernel-compat/drbd_wrappers.h"

enum al_transaction_types {
	AL_TR_UPDATE = 0,
	AL_TR_INITIALIZED = 0xffff
};
/* all fields on disc in big endian */
#ifdef _WIN32
#pragma pack (push, 1)
#define __packed
#endif
struct __packed al_transaction_on_disk {
	/* don't we all like magic */
	__be32	magic;

	/* to identify the most recent transaction block
	 * in the on disk ring buffer */
	__be32	tr_number;

	/* checksum on the full 4k block, with this field set to 0. */
	__be32	crc32c;

	/* type of transaction, special transaction types like:
	 * purge-all, set-all-idle, set-all-active, ... to-be-defined
	 * see also enum al_transaction_types */
	__be16	transaction_type;

	/* we currently allow only a few thousand extents,
	 * so 16bit will be enough for the slot number. */

	/* how many updates in this transaction */
	__be16	n_updates;

	/* maximum slot number, "al-extents" in drbd.conf speak.
	 * Having this in each transaction should make reconfiguration
	 * of that parameter easier. */
	__be16	context_size;

	/* slot number the context starts with */
	__be16	context_start_slot_nr;

	/* Some reserved bytes.  Expected usage is a 64bit counter of
	 * sectors-written since device creation, and other data generation tag
	 * supporting usage */
#ifndef _WIN32
	__be32	__reserved[4];
#else
	__be32	__reserved_win32[4];
#endif

	/* --- 36 byte used --- */

	/* Reserve space for up to AL_UPDATES_PER_TRANSACTION changes
	 * in one transaction, then use the remaining byte in the 4k block for
	 * context information.  "Flexible" number of updates per transaction
	 * does not help, as we have to account for the case when all update
	 * slots are used anyways, so it would only complicate code without
	 * additional benefit.
	 */
	__be16	update_slot_nr[AL_UPDATES_PER_TRANSACTION];

	/* but the extent number is 32bit, which at an extent size of 4 MiB
	 * allows to cover device sizes of up to 2**54 Byte (16 PiB) */
	__be32	update_extent_nr[AL_UPDATES_PER_TRANSACTION];

	/* --- 420 bytes used (36 + 64*6) --- */

	/* 4096 - 420 = 3676 = 919 * 4 */
	__be32	context[AL_CONTEXT_PER_TRANSACTION];
};

#ifdef _WIN32
#pragma pack (pop)
#undef __packed
#endif



struct update_peers_work {
       struct drbd_work w;
       struct drbd_peer_device *peer_device;
       unsigned int enr;
};

void *drbd_md_get_buffer(struct drbd_device *device, const char *intent)
{
	int r;
	long t;
	
	// DW-1961 Measure how long the metadisk waits for use
	if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY)
		device->md_io.prepare_ts = timestamp();
#ifdef _WIN32
    wait_event_timeout(t, device->misc_wait,
        (r = atomic_cmpxchg(&device->md_io.in_use, 0, 1)) == 0 ||
        device->disk_state[NOW] <= D_FAILED,
        HZ * 10);
#else
	t = wait_event_timeout(device->misc_wait,
			(r = atomic_cmpxchg(&device->md_io.in_use, 0, 1)) == 0 ||
			device->disk_state[NOW] <= D_FAILED,
			HZ * 10);
#endif
	if (t == 0)
		drbd_err(device, "Waited 10 Seconds for md_buffer! BUG?, %s\n", intent);

	if (r)
		return NULL;

	device->md_io.current_use = intent;

	return page_address(device->md_io.page);
}

void drbd_md_put_buffer(struct drbd_device *device)
{
	if (atomic_dec_and_test(&device->md_io.in_use))
		wake_up(&device->misc_wait);
}

void wait_until_done_or_force_detached(struct drbd_device *device, struct drbd_backing_dev *bdev,
				       unsigned int *done)
{
	long dt;

	rcu_read_lock();
	dt = rcu_dereference(bdev->disk_conf)->disk_timeout;
	rcu_read_unlock();
	dt = dt * HZ / 10;
	if (dt == 0)
		dt = MAX_SCHEDULE_TIMEOUT;

#ifdef _WIN32
    wait_event_timeout(dt, device->misc_wait,
        *done || test_bit(FORCE_DETACH, &device->flags), dt);
#else
	dt = wait_event_timeout(device->misc_wait,
			*done || test_bit(FORCE_DETACH, &device->flags), dt);
#endif

	if (dt == 0) {
		drbd_err(device, "meta-data IO operation timed out\n");
		drbd_chk_io_error(device, 1, DRBD_FORCE_DETACH);
	}
}

static int _drbd_md_sync_page_io(struct drbd_device *device,
				 struct drbd_backing_dev *bdev,
				 sector_t sector, int op)
{
	struct bio *bio;
	/* we do all our meta data IO in aligned 4k blocks. */
	const int size = 4096;
	int err, op_flags = 0;

	if ((op == REQ_OP_WRITE) && !test_bit(MD_NO_FUA, &device->flags))
		op_flags |= DRBD_REQ_FUA | DRBD_REQ_PREFLUSH;
	op_flags |= DRBD_REQ_UNPLUG | DRBD_REQ_SYNC | REQ_NOIDLE;

#ifdef COMPAT_MAYBE_RETRY_HARDBARRIER
	/* < 2.6.36, "barrier" semantic may fail with EOPNOTSUPP */
 retry:
#endif
	device->md_io.done = 0;
	device->md_io.error = -ENODEV;
#ifdef _WIN32
    bio = bio_alloc_drbd(GFP_NOIO, '30DW');
    if (!bio)
    {
        return -ENODEV;
    }
#else
	bio = bio_alloc_drbd(GFP_NOIO);
#endif
	bio->bi_bdev = bdev->md_bdev;
	DRBD_BIO_BI_SECTOR(bio) = sector;
	err = -EIO;
	if (bio_add_page(bio, device->md_io.page, size, 0) != size)
		goto out;
	bio->bi_private = device;
	bio->bi_end_io = drbd_md_endio;
	bio->io_retry = device->resource->res_opts.io_error_retry_count;
	bio_set_op_attrs(bio, op, op_flags);

	if (op != REQ_OP_WRITE && device->disk_state[NOW] == D_DISKLESS && device->ldev == NULL)
		/* special case, drbd_md_read() during drbd_adm_attach(): no get_ldev */
		;
	else if (!get_ldev_if_state(device, D_ATTACHING)) {
		/* Corresponding put_ldev in drbd_md_endio() */
		drbd_err(device, "ASSERT FAILED: get_ldev_if_state() == 1 in _drbd_md_sync_page_io()\n");
		err = -ENODEV;
		goto out;
	}

	bio_get(bio); /* one bio_put() is in the completion handler */
	atomic_inc(&device->md_io.in_use); /* drbd_md_put_buffer() is in the completion handler */
	// DW-1961 Save timestamp for IO latency measurement
	if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY)
		device->md_io.io_request_ts = timestamp();

	if (drbd_insert_fault(device, (op == REQ_OP_WRITE) ? DRBD_FAULT_MD_WR : DRBD_FAULT_MD_RD))
		bio_endio(bio, -EIO);
#ifndef _WIN32
	else
		submit_bio(bio);
#else
	else {
		if (submit_bio(bio)) {
			bio_endio(bio, -EIO);
		}
	}
#endif

	wait_until_done_or_force_detached(device, bdev, &device->md_io.done);
	// DW-1961 Calculate and Log IO Latency
	if (atomic_read(&g_featurelog_flag) & FEATURELOG_FLAG_LATENCY) {
		device->md_io.io_complete_ts = timestamp();
		WDRBD_LATENCY("md IO latency : type(%s) prepare(%lldus) disk io(%lldus)\n", (op == REQ_OP_WRITE) ? "write" : "read", timestamp_elapse(device->md_io.prepare_ts, device->md_io.io_request_ts), timestamp_elapse(device->md_io.io_request_ts, device->md_io.io_complete_ts));
	}
	
	err = device->md_io.error;
#ifdef _WIN32
    if(err == STATUS_NO_SUCH_DEVICE) {
		// DW-1396: referencing bio causes BSOD as long as bio has already been freed once it's been submitted, we don't need volume device name which is already removed also.
        drbd_err(device, "cannot find meta volume\n");
        return err;
    }
#endif

#ifdef COMPAT_MAYBE_RETRY_HARDBARRIER
	/* check for unsupported barrier op.
	 * would rather check on EOPNOTSUPP, but that is not reliable.
	 * don't try again for ANY return value != 0 */
	if (err && device->md_io.done && (bio->bi_opf & DRBD_REQ_HARDBARRIER)) {
		/* Try again with no barrier */
		drbd_warn(device, "Barriers not supported on meta data device - disabling\n");
		set_bit(MD_NO_FUA, &device->flags);
		op_flags &= ~DRBD_REQ_HARDBARRIER;
		bio_put(bio);
		goto retry;
	}
#endif
#ifdef _WIN32
	return err;
#endif
 out:
	bio_put(bio);
	return err;
}

int drbd_md_sync_page_io(struct drbd_device *device, struct drbd_backing_dev *bdev,
			 sector_t sector, int op)
{
	int err;
	D_ASSERT(device, atomic_read(&device->md_io.in_use) == 1);

	if (!bdev->md_bdev) {
		if (drbd_ratelimit())
			drbd_err(device, "bdev->md_bdev==NULL\n");
		return -EIO;
	}
#ifdef _WIN32
	drbd_dbg(device, "meta_data io: %s [0x%p]:%s(,%llus,%s) %pS\n",
	     current->comm, current->pid, __func__,
		 (unsigned long long)sector, (op == REQ_OP_WRITE) ? "WRITE" : "READ",
	     (void*)_RET_IP_ );
#else
	drbd_dbg(device, "meta_data io: %s [%d]:%s(,%llus,%s) %pS\n",
	     current->comm, current->pid, __func__,
		 (unsigned long long)sector, (op == REQ_OP_WRITE) ? "WRITE" : "READ",
	     (void*)_RET_IP_ );
#endif

	if (sector < drbd_md_first_sector(bdev) ||
	    sector + 7 > drbd_md_last_sector(bdev))
		drbd_alert(device, "%s [%d]:%s(,%llus,%s) out of range md access!\n",
		     current->comm, current->pid, __func__,
		     (unsigned long long)sector, 
			 (op == REQ_OP_WRITE) ? "WRITE" : "READ");

	err = _drbd_md_sync_page_io(device, bdev, sector, op);
	if (err) {
		drbd_err(device, "drbd_md_sync_page_io(,%llus,%s) failed with error %d\n",
		    (unsigned long long)sector,
			(op == REQ_OP_WRITE) ? "WRITE" : "READ", err);
	}
	return err;
}

struct get_activity_log_ref_ctx {
	/* in: which extent on which device? */
	struct drbd_device *device;
	unsigned int enr;
	bool nonblock;

	/* out: do we need to wake_up(&device->al_wait)? */
	bool wake_up;
};
static struct bm_extent*
find_active_resync_extent(struct get_activity_log_ref_ctx *al_ctx)
{
	struct drbd_peer_device *peer_device;
	struct lc_element *tmp;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, al_ctx->device) {
		if (peer_device == NULL)
			goto out;
		//DW-1601 If greater than 112, remove act_log and resync_lru associations
#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
		if (peer_device->connection->agreed_pro_version <= 112) 
#endif
		{
			tmp = lc_find(peer_device->resync_lru, al_ctx->enr / AL_EXT_PER_BM_SECT);
			if (unlikely(tmp != NULL)) {
				struct bm_extent  *bm_ext = lc_entry(tmp, struct bm_extent, lce);
				if (test_bit(BME_NO_WRITES, &bm_ext->flags)) {
					if (peer_device->resync_wenr == tmp->lc_number) {
						peer_device->resync_wenr = LC_FREE;
						int lc_put_result = lc_put(peer_device->resync_lru, &bm_ext->lce);
						if (lc_put_result == 0) {
							bm_ext->flags = 0;
							al_ctx->wake_up = true;
							peer_device->resync_locked--;
							continue;
						}
						else if (lc_put_result < 0) {
							WDRBD_ERROR("lc_put return error.\n");
							continue;
						}
					}
					rcu_read_unlock();
					WDRBD_TRACE_AL("return bm_ext, bm_ext->lce.lc_number = %lu, bm_ext->lce.refcnt = %lu\n", bm_ext->lce.lc_number, bm_ext->lce.refcnt);
					return bm_ext;
				}
			}
		}
	}
out:
	rcu_read_unlock();
	WDRBD_TRACE_AL("return NULL\n");
	return NULL;
}

void
set_bme_priority(struct get_activity_log_ref_ctx *al_ctx)
{
	struct drbd_peer_device *peer_device;
	struct lc_element *tmp;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, al_ctx->device) {
		//DW-1601 If greater than 112, remove act_log and resync_lru associations
#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
		if (peer_device->connection->agreed_pro_version <= 112)
#endif
		{
			tmp = lc_find(peer_device->resync_lru, al_ctx->enr / AL_EXT_PER_BM_SECT);
			if (tmp) {
				struct bm_extent  *bm_ext = lc_entry(tmp, struct bm_extent, lce);
				if (test_bit(BME_NO_WRITES, &bm_ext->flags)
					&& !test_and_set_bit(BME_PRIORITY, &bm_ext->flags))
					al_ctx->wake_up = true;
			}
		}
	}
	rcu_read_unlock();
}

static
struct lc_element *__al_get(struct get_activity_log_ref_ctx *al_ctx)
{
	struct drbd_device *device = al_ctx->device;
	struct lc_element *al_ext = NULL;
	struct bm_extent *bm_ext;

	spin_lock_irq(&device->al_lock);
	bm_ext = find_active_resync_extent(al_ctx);
	if (bm_ext) {
		set_bme_priority(al_ctx);
		goto out;
	}

	if (al_ctx->nonblock)
		al_ext = lc_try_get(device->act_log, al_ctx->enr);
	else
		al_ext = lc_get(device->act_log, al_ctx->enr);
out: 
	spin_unlock_irq(&device->al_lock);
	if (al_ctx->wake_up)
		wake_up(&device->al_wait);
	return al_ext;
}

static
struct lc_element *_al_get_nonblock(struct drbd_device *device, unsigned int enr)
{
	struct get_activity_log_ref_ctx al_ctx =
	{ .device = device, .enr = enr, .nonblock = true };
	return __al_get(&al_ctx);
}

static
struct lc_element *_al_get(struct drbd_device *device, unsigned int enr)
{
	struct get_activity_log_ref_ctx al_ctx =
	{ .device = device, .enr = enr, .nonblock = false };
	return __al_get(&al_ctx);
}

bool drbd_al_begin_io_fastpath(struct drbd_device *device, struct drbd_interval *i)
{
	/* for bios crossing activity log extent boundaries,
	 * we may need to activate two extents in one go */
	ULONG_PTR first = (ULONG_PTR)i->sector >> (AL_EXTENT_SHIFT - 9);
	ULONG_PTR last = i->size == 0 ? first : (ULONG_PTR)(i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT - 9);
	
	D_ASSERT(device, first <= last);
	D_ASSERT(device, atomic_read(&device->local_cnt) > 0);

	/* FIXME figure out a fast path for bios crossing AL extent boundaries */
	if (first != last)
		return false;
#ifdef _WIN64
	BUG_ON_UINT32_OVER(first);
#endif
	return _al_get_nonblock(device, (unsigned int)first) != NULL;
}


#if (PAGE_SHIFT + 3) < (AL_EXTENT_SHIFT - BM_BLOCK_SHIFT)
/* Currently BM_BLOCK_SHIFT, BM_EXT_SHIFT and AL_EXTENT_SHIFT
 * are still coupled, or assume too much about their relation.
 * Code below will not work if this is violated.
 * Will be cleaned up with some followup patch.
 */
# error FIXME
#endif

static ULONG_PTR al_extent_to_bm_bit(unsigned int al_enr)
{
	return (ULONG_PTR)al_enr << (AL_EXTENT_SHIFT - BM_BLOCK_SHIFT);
}

static sector_t al_tr_number_to_on_disk_sector(struct drbd_device *device)
{
	const unsigned int stripes = device->ldev->md.al_stripes;
	const unsigned int stripe_size_4kB = device->ldev->md.al_stripe_size_4k;

	/* transaction number, modulo on-disk ring buffer wrap around */
	unsigned int t = device->al_tr_number % (device->ldev->md.al_size_4k);

	/* ... to aligned 4k on disk block */
	t = ((t % stripes) * stripe_size_4kB) + t/stripes;

	/* ... to 512 byte sector in activity log */
	t *= 8;

	/* ... plus offset to the on disk position */
	return device->ldev->md.md_offset + device->ldev->md.al_offset + t;
}

static int __al_write_transaction(struct drbd_device *device, struct al_transaction_on_disk *buffer)
{
	struct lc_element *e;
	sector_t sector;
	int mx;
	unsigned extent_nr;
	unsigned crc = 0;
	int err = 0;
	unsigned short i;

	memset(buffer, 0, sizeof(*buffer));
	buffer->magic = cpu_to_be32(DRBD_AL_MAGIC);
	buffer->tr_number = cpu_to_be32(device->al_tr_number);

	i = 0;

	drbd_bm_reset_al_hints(device);

	/* Even though no one can start to change this list
	 * once we set the LC_LOCKED -- from drbd_al_begin_io(),
	 * lc_try_lock_for_transaction() --, someone may still
	 * be in the process of changing it. */
	spin_lock_irq(&device->al_lock);
#ifdef _WIN32
    list_for_each_entry(struct lc_element, e, &device->act_log->to_be_changed, list) {
#else
	list_for_each_entry(e, &device->act_log->to_be_changed, list) {
#endif
		if (i == AL_UPDATES_PER_TRANSACTION) {
			i++;
			break;
		}
		BUG_ON_UINT16_OVER(e->lc_index);
		//DW-1918 the value of lc_new_number MAX should be verified by UINT32.
		BUG_ON_UINT32_OVER(e->lc_new_number);

		buffer->update_slot_nr[i] = cpu_to_be16((u16)e->lc_index);
		buffer->update_extent_nr[i] = cpu_to_be32((u32)e->lc_new_number);
		if (e->lc_number != LC_FREE) {
			ULONG_PTR start, end;

			start = al_extent_to_bm_bit(e->lc_number);
			end = al_extent_to_bm_bit(e->lc_number + 1) - 1;
			drbd_bm_mark_range_for_writeout(device, start, end);
		}
		i++;
	}
	spin_unlock_irq(&device->al_lock);
	BUG_ON(i > AL_UPDATES_PER_TRANSACTION);

	buffer->n_updates = cpu_to_be16(i);
	for ( ; i < AL_UPDATES_PER_TRANSACTION; i++) {
		buffer->update_slot_nr[i] = cpu_to_be16(UINT16_MAX);
		buffer->update_extent_nr[i] = cpu_to_be32(LC_FREE);
	}

	BUG_ON_UINT16_OVER(device->act_log->nr_elements);
	BUG_ON_UINT16_OVER(device->al_tr_cycle);

	buffer->context_size = cpu_to_be16((u16)device->act_log->nr_elements);
	buffer->context_start_slot_nr = cpu_to_be16((u16)device->al_tr_cycle);

	mx = min_t(int, AL_CONTEXT_PER_TRANSACTION,
		   device->act_log->nr_elements - device->al_tr_cycle);
	for (i = 0; i < mx; i++) {
		unsigned idx = device->al_tr_cycle + i;
		extent_nr = lc_element_by_index(device->act_log, idx)->lc_number;
		buffer->context[i] = cpu_to_be32(extent_nr);
	}
	for (; i < AL_CONTEXT_PER_TRANSACTION; i++)
		buffer->context[i] = cpu_to_be32(LC_FREE);

	device->al_tr_cycle += AL_CONTEXT_PER_TRANSACTION;
	if (device->al_tr_cycle >= device->act_log->nr_elements)
		device->al_tr_cycle = 0;

	sector = al_tr_number_to_on_disk_sector(device);
#ifdef _WIN32
	crc = crc32c(0, (uint8_t*)buffer, 4096);
#else
	crc = crc32c(0, buffer, 4096);
#endif
	buffer->crc32c = cpu_to_be32(crc);

	if (drbd_bm_write_hinted(device))
		err = -EIO;
	else {
		bool write_al_updates;
		rcu_read_lock();
		write_al_updates = rcu_dereference(device->ldev->disk_conf)->al_updates;
		rcu_read_unlock();
		if (write_al_updates) {
			if (drbd_md_sync_page_io(device, device->ldev, sector, REQ_OP_WRITE)) {
				err = -EIO;
				drbd_chk_io_error(device, 1, DRBD_META_IO_ERROR);
			} else {
				device->al_tr_number++;
				device->al_writ_cnt++;
			}
		}
	}

	return err;
}

static int al_write_transaction(struct drbd_device *device)
{
	struct al_transaction_on_disk *buffer;
	int err;

	if (!get_ldev(device)) {
		drbd_err(device, "disk is %s, cannot start al transaction\n",
			drbd_disk_str(device->disk_state[NOW]));
		return -EIO;
	}

	/* The bitmap write may have failed, causing a state change. */
	if (device->disk_state[NOW] < D_INCONSISTENT) {
		drbd_err(device,
			"disk is %s, cannot write al transaction\n",
			drbd_disk_str(device->disk_state[NOW]));
		put_ldev(device);
		return -EIO;
	}

	/* protects md_io_buffer, al_tr_cycle, ... */
	buffer = drbd_md_get_buffer(device, __func__);
	if (!buffer) {
		drbd_err(device, "disk failed while waiting for md_io buffer\n");
		put_ldev(device);
		return -ENODEV;
	}

	err = __al_write_transaction(device, buffer);

	drbd_md_put_buffer(device);
	put_ldev(device);

	return err;
}

static int bm_e_weight(struct drbd_peer_device *peer_device, ULONG_PTR enr);

bool drbd_al_try_lock(struct drbd_device *device)
{
	bool locked;

	spin_lock_irq(&device->al_lock);
	locked = lc_try_lock(device->act_log);
	spin_unlock_irq(&device->al_lock);

	return locked;
}

bool drbd_al_try_lock_for_transaction(struct drbd_device *device)
{
	bool locked;

	spin_lock_irq(&device->al_lock);
	locked = lc_try_lock_for_transaction(device->act_log);
	spin_unlock_irq(&device->al_lock);

	return locked;
}


void drbd_al_begin_io_commit(struct drbd_device *device)
{
	bool locked = drbd_al_try_lock_for_transaction(device);

	wait_event(device->al_wait,
		device->act_log->pending_changes == 0 || locked);

	if (locked) {
		/* Double check: it may have been committed by someone else
		 * while we were waiting for the lock. */
		if (device->act_log->pending_changes) {
			bool write_al_updates;

			rcu_read_lock();
			write_al_updates = rcu_dereference(device->ldev->disk_conf)->al_updates;
			rcu_read_unlock();

			if (write_al_updates)
				al_write_transaction(device);
			spin_lock_irq(&device->al_lock);
			/* FIXME
			if (err)
				we need an "lc_cancel" here;
			*/
			lc_committed(device->act_log);
			spin_unlock_irq(&device->al_lock);
		}
		lc_unlock(device->act_log);
		wake_up(&device->al_wait);
	}
}

bool put_actlog(struct drbd_device *device, unsigned int first, unsigned int last)
{
	struct lc_element *extent;
	unsigned long flags;
	unsigned int enr;
	bool wake = false;

	D_ASSERT(device, first <= last);
	spin_lock_irqsave(&device->al_lock, flags);
	for (enr = first; enr <= last; enr++) {
		extent = lc_find(device->act_log, enr);
		if (!extent || extent->refcnt <= 0) {
			drbd_err(device, "al_complete_io() called on inactive extent %u\n", enr);
			continue;
		}
		WDRBD_TRACE_AL("called lc_put extent->lc_number= %lu, extent->refcnt = %lu\n", extent->lc_number, extent->refcnt); 
		int lc_put_result = lc_put(device->act_log, extent);
		if (lc_put_result == 0)
			wake = true;
	}
	spin_unlock_irqrestore(&device->al_lock, flags);
	if (wake)
		wake_up(&device->al_wait);

	return wake;
}

/**
* drbd_al_begin_io_for_peer() - Gets (a) reference(s) to AL extent(s)
* @peer_device:	DRBD peer device to be targeted
* @i:			interval to check and register
*
* Ensures that the extents covered by the interval @i are hot in the
* activity log. This function makes sure the area is not active by any
* resync operation on any connection.
*/
int drbd_al_begin_io_for_peer(struct drbd_peer_device *peer_device, struct drbd_interval *i)
{
	struct drbd_device *device = peer_device->device;
	ULONG_PTR first = (ULONG_PTR)i->sector >> (AL_EXTENT_SHIFT - 9);
	ULONG_PTR last = i->size == 0 ? first : (ULONG_PTR)(i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT - 9);
	ULONG_PTR enr;
	bool need_transaction = false;

	D_ASSERT(peer_device, first <= last);
	D_ASSERT(peer_device, atomic_read(&device->local_cnt) > 0);

#ifdef _WIN64
	BUG_ON_UINT32_OVER(first);
	BUG_ON_UINT32_OVER(last);
#endif
	for (enr = first; enr <= last; enr++) {
		struct lc_element *al_ext;
		wait_event(device->al_wait,
				(al_ext = _al_get(device, (unsigned int)enr)) != NULL ||
				peer_device->connection->cstate[NOW] < C_CONNECTED);
		if (al_ext == NULL) {
			if (enr > first)
				put_actlog(device, (unsigned int)first, (unsigned int)(enr - 1));
			return -ECONNABORTED;
		}
		if (al_ext->lc_number != enr)
			need_transaction = true;
	}

	if (need_transaction)
		drbd_al_begin_io_commit(device);
	return 0;

}

int drbd_al_begin_io_nonblock(struct drbd_device *device, struct drbd_interval *i)
{
	struct lru_cache *al = device->act_log;
	struct bm_extent *bm_ext;
	/* for bios crossing activity log extent boundaries,
	 * we may need to activate two extents in one go */
	ULONG_PTR first = (ULONG_PTR)i->sector >> (AL_EXTENT_SHIFT - 9);
	ULONG_PTR last = i->size == 0 ? first : (ULONG_PTR)(i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT - 9);
	ULONG_PTR nr_al_extents;
	unsigned available_update_slots;
	struct get_activity_log_ref_ctx al_ctx = { .device = device, };
	ULONG_PTR enr;

	D_ASSERT(device, first <= last);
#ifdef _WIN64
	BUG_ON_UINT32_OVER(first);
	BUG_ON_UINT32_OVER(last);
#endif
	nr_al_extents = 1 + last - first; /* worst case: all touched extends are cold. */

#ifdef _WIN32 // DW-1513 : If the used value is greater than nr_elements, set available_update_slots to 0.
	if (al->nr_elements < al->used)
	{
		available_update_slots = 0;
		WDRBD_WARN("al->used is greater than nr_elements, set available_update_slots to 0.\n");
	}
	else
	{
		available_update_slots = min(al->nr_elements - al->used,
					al->max_pending_changes - al->pending_changes);
	}
#else
	available_update_slots = min(al->nr_elements - al->used,
				al->max_pending_changes - al->pending_changes);
#endif

	/* We want all necessary updates for a given request within the same transaction
	 * We could first check how many updates are *actually* needed,
	 * and use that instead of the worst-case nr_al_extents */
	if (available_update_slots < nr_al_extents) {
		/* Too many activity log extents are currently "hot".
		 *
		 * If we have accumulated pending changes already,
		 * we made progress.
		 *
		 * If we cannot get even a single pending change through,
		 * stop the fast path until we made some progress,
		 * or requests to "cold" extents could be starved. */
		if (!al->pending_changes)
			set_bit(__LC_STARVING, &device->act_log->flags);

		// DW-1945 fixup that Log debug logs when pending_changes are insufficient.
		// because insufficient of slots for pending_changes can occur frequently.
		if (al->max_pending_changes - al->pending_changes < nr_al_extents)
			drbd_dbg(device, "insufficient al_extent slots for 'pending_changes' nr_al_extents:%llu pending:%lu\n", (unsigned long long)nr_al_extents, al->pending_changes);
		else
			drbd_info(device, "insufficient al_extent slots for 'used' nr_al_extents:%llu used:%lu\n", (unsigned long long)nr_al_extents, al->used);

		return -ENOBUFS;
	}

	/* Is resync active in this area? */
	for (enr = first; enr <= last; enr++) {
		al_ctx.enr = (unsigned int)enr;
		bm_ext = find_active_resync_extent(&al_ctx);
		if (unlikely(bm_ext != NULL)) {
			set_bme_priority(&al_ctx);
			drbd_debug(device, "active resync extent enr : %llu\n", (unsigned long long)enr);
			if (al_ctx.wake_up)
				return -EBUSY;
			return -EWOULDBLOCK;
		}
	}


#ifdef _WIN32 // DW-1513 : At this point, LC_STARVING flag should be cleared. Otherwise, LOGIC BUG occurs.
	if (test_bit(__LC_STARVING, &device->act_log->flags))
	{
		clear_bit(__LC_STARVING, &device->act_log->flags);
	}
#endif

	/* Checkout the refcounts.
	 * Given that we checked for available elements and update slots above,
	 * this has to be successful. */
	for (enr = first; enr <= last; enr++) {
		struct lc_element *al_ext;
		al_ext = lc_get_cumulative(device->act_log, (unsigned int)enr);
		if (!al_ext)
#ifdef _WIN32
			drbd_err(device, "LOGIC BUG for enr=%llu (LC_STARVING=%d LC_LOCKED=%d used=%u pending_changes=%u lc->free=%d lc->lru=%d)\n", 
						(unsigned long long)enr, 
						test_bit(__LC_STARVING, &device->act_log->flags),
						test_bit(__LC_LOCKED, &device->act_log->flags),
						device->act_log->used,
						device->act_log->pending_changes,
						!list_empty(&device->act_log->free),
						!list_empty(&device->act_log->lru)
			);
#else
			drbd_err(device, "LOGIC BUG for enr=%u\n", enr);
#endif
	}
	return 0;
}

/* put activity log extent references corresponding to interval i, return true
 * if at least one extent is now unreferenced. */
bool drbd_al_complete_io(struct drbd_device *device, struct drbd_interval *i)
{
	/* for bios crossing activity log extent boundaries,
	 * we may need to activate two extents in one go */
	ULONG_PTR first = (ULONG_PTR)i->sector >> (AL_EXTENT_SHIFT - 9);
	ULONG_PTR last = i->size == 0 ? first : (ULONG_PTR)(i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT - 9);
#ifdef _WIN64
	BUG_ON_UINT32_OVER(first);
	BUG_ON_UINT32_OVER(last);
#endif
	WDRBD_TRACE_AL("first = %llu last = %llu i->size = %u\n", (unsigned long long)first, (unsigned long long)last, i->size);

	return put_actlog(device, (unsigned int)first, (unsigned int)last);
}

static int _try_lc_del(struct drbd_device *device, struct lc_element *al_ext)
{
	int rv;

	spin_lock_irq(&device->al_lock);
	rv = (al_ext->refcnt == 0);
	if (likely(rv))
		lc_del(device->act_log, al_ext);
	spin_unlock_irq(&device->al_lock);

	return rv;
}

/**
 * drbd_al_shrink() - Removes all active extents form the activity log
 * @device:	DRBD device.
 *
 * Removes all active extents form the activity log, waiting until
 * the reference count of each entry dropped to 0 first, of course.
 *
 * You need to lock device->act_log with lc_try_lock() / lc_unlock()
 */
void drbd_al_shrink(struct drbd_device *device)
{
	struct lc_element *al_ext;
	unsigned int i;

	D_ASSERT(device, test_bit(__LC_LOCKED, &device->act_log->flags));

	for (i = 0; i < device->act_log->nr_elements; i++) {
		al_ext = lc_element_by_index(device->act_log, i);
		if (al_ext->lc_number == LC_FREE)
			continue;
		wait_event(device->al_wait, _try_lc_del(device, al_ext));
	}

	wake_up(&device->al_wait);
}

static bool extent_in_sync(struct drbd_peer_device *peer_device, unsigned int rs_enr)
{
	if (peer_device->repl_state[NOW] == L_ESTABLISHED) {
		if (drbd_bm_total_weight(peer_device) == 0)
			return true;
		if (bm_e_weight(peer_device, rs_enr) == 0)
			return true;
	} else if (peer_device->repl_state[NOW] == L_SYNC_SOURCE ||
		peer_device->repl_state[NOW] == L_SYNC_TARGET) {
		bool rv = false;

		if (!drbd_try_rs_begin_io(peer_device, BM_EXT_TO_SECT(rs_enr), false)) {
			struct bm_extent *bm_ext;
			struct lc_element *e;

			e = lc_find(peer_device->resync_lru, rs_enr);
			bm_ext = lc_entry(e, struct bm_extent, lce);
			rv = (bm_ext->rs_left == 0);
			drbd_rs_complete_io(peer_device, BM_EXT_TO_SECT(rs_enr), __FUNCTION__);
		}

		return rv;
	}
#ifdef _WIN32
		// MODIFIED_BY_MANTECH DW-955: Need to send peer_in_sync to PausedSyncTarget and UpToDate node.
		else if (peer_device->repl_state[NOW] == L_PAUSED_SYNC_T) {
			if (peer_device->disk_state[NOW] == D_UP_TO_DATE)
				return true;
		}
#endif

	return false;
}

static void
consider_sending_peers_in_sync(struct drbd_peer_device *peer_device, unsigned int rs_enr)
{
	struct drbd_device *device = peer_device->device;
	u64 mask = NODE_MASK(peer_device->node_id), im;
	struct drbd_peer_device *p;
	int size_sect;

	if (peer_device->connection->agreed_pro_version < 110)
		return;

	for_each_peer_device_ref(p, im, device) {
		if (p == peer_device)
			continue;
		if (extent_in_sync(p, rs_enr))
			mask |= NODE_MASK(p->node_id);
	}

	size_sect = (int)(min(BM_SECT_PER_EXT,
			drbd_get_capacity(device->this_bdev) - BM_EXT_TO_SECT(rs_enr)));

	for_each_peer_device_ref(p, im, device) {
		if (mask & NODE_MASK(p->node_id))
			drbd_send_peers_in_sync(p, mask, BM_EXT_TO_SECT(rs_enr), size_sect << 9);
	}
}

int drbd_al_initialize(struct drbd_device *device, void *buffer)
{
	struct al_transaction_on_disk *al = buffer;
	struct drbd_md *md = &device->ldev->md;
	int al_size_4k = md->al_stripes * md->al_stripe_size_4k;
	int i;

	__al_write_transaction(device, al);
	/* There may or may not have been a pending transaction. */
	spin_lock_irq(&device->al_lock);
	lc_committed(device->act_log);
	spin_unlock_irq(&device->al_lock);

	/* The rest of the transactions will have an empty "updates" list, and
	 * are written out only to provide the context, and to initialize the
	 * on-disk ring buffer. */
	for (i = 1; i < al_size_4k; i++) {
		int err = __al_write_transaction(device, al);
		if (err)
			return err;
	}
	return 0;
}

static int w_update_peers(struct drbd_work *w, int unused)
{
		UNREFERENCED_PARAMETER(unused);
       struct update_peers_work *upw = container_of(w, struct update_peers_work, w);
       struct drbd_peer_device *peer_device = upw->peer_device;
       struct drbd_device *device = peer_device->device;
       struct drbd_connection *connection = peer_device->connection;

       consider_sending_peers_in_sync(peer_device, upw->enr);

       kfree(upw);

       kref_debug_put(&device->kref_debug, 5);
       kref_put(&device->kref, drbd_destroy_device);

       kref_debug_put(&connection->kref_debug, 14);
       kref_put(&connection->kref, drbd_destroy_connection);

       return 0;
}

/* inherently racy...
 * return value may be already out-of-date when this function returns.
 * but the general usage is that this is only use during a cstate when bits are
 * only cleared, not set, and typically only care for the case when the return
 * value is zero, or we already "locked" this "bitmap extent" by other means.
 *
 * enr is bm-extent number, since we chose to name one sector (512 bytes)
 * worth of the bitmap a "bitmap extent".
 *
 * TODO
 * I think since we use it like a reference count, we should use the real
 * reference count of some bitmap extent element from some lru instead...
 *
 */

static int bm_e_weight(struct drbd_peer_device *peer_device, ULONG_PTR enr)
{
	ULONG_PTR start, end;
	int count;

	start = enr << (BM_EXT_SHIFT - BM_BLOCK_SHIFT);
	end = ((enr + 1) << (BM_EXT_SHIFT - BM_BLOCK_SHIFT)) - 1;
	count = (unsigned int)drbd_bm_count_bits(peer_device->device, peer_device->bitmap_index, start, end);
#if DUMP_MD >= 3
	drbd_info(peer_device, "enr=%lu weight=%d\n", enr, count);
#endif
	return count;
}

static const char *drbd_change_sync_fname[] = {
	[RECORD_RS_FAILED] = "drbd_rs_failed_io",
	[SET_IN_SYNC] = "drbd_set_in_sync",
	[SET_OUT_OF_SYNC] = "drbd_set_out_of_sync"
};


/* ATTENTION. The AL's extents are 4MB each, while the extents in the
 * resync LRU-cache are 128MB each.
 * The caller of this function has to hold an get_ldev() reference.
 *
 * Adjusts the caching members ->rs_left (success) or ->rs_failed (!success),
 * potentially pulling in (and recounting the corresponding bits)
 * this resync extent into the resync extent lru cache.
 *
 * Returns whether all bits have been cleared for this resync extent,
 * precisely: (rs_left <= rs_failed)
 *
 * TODO will be obsoleted once we have a caching lru of the on disk bitmap
 */
static bool update_rs_extent(struct drbd_peer_device *peer_device,
		unsigned int enr, int count, update_sync_bits_mode mode)
{
	struct drbd_device *device = peer_device->device;
	struct lc_element *e;

	D_ASSERT(device, atomic_read(&device->local_cnt));

	/* When setting out-of-sync bits,
	 * we don't need it cached (lc_find).
	 * But if it is present in the cache,
	 * we should update the cached bit count.
	 * Otherwise, that extent should be in the resync extent lru cache
	 * already -- or we want to pull it in if necessary -- (lc_get),
	 * then update and check rs_left and rs_failed. */
	if (mode == SET_OUT_OF_SYNC)
		e = lc_find(peer_device->resync_lru, enr);
	else
		e = lc_get(peer_device->resync_lru, enr);
	if (e) {
		struct bm_extent *ext = lc_entry(e, struct bm_extent, lce);
		if (ext->lce.lc_number == enr) {
			if (mode == SET_IN_SYNC)
				ext->rs_left -= count;
			else if (mode == SET_OUT_OF_SYNC)
				ext->rs_left += count;
			else
				ext->rs_failed += count;
			if (ext->rs_left < ext->rs_failed) {
				struct drbd_connection *connection = peer_device->connection;
				drbd_warn(peer_device, "BAD! enr=%u rs_left=%d "
				    "rs_failed=%d count=%d cstate=%s %s\n",
				     ext->lce.lc_number, ext->rs_left,
				     ext->rs_failed, count,
				     drbd_conn_str(connection->cstate[NOW]),
				     drbd_repl_str(peer_device->repl_state[NOW]));

				/* We don't expect to be able to clear more bits
				 * than have been set when we originally counted
				 * the set bits to cache that value in ext->rs_left.
				 * Whatever the reason (disconnect during resync,
				 * delayed local completion of an application write),
				 * try to fix it up by recounting here. */
				ext->rs_left = bm_e_weight(peer_device, enr);
			}
		} else {
			/* Normally this element should be in the cache,
			 * since drbd_rs_begin_io() pulled it already in.
			 *
			 * But maybe an application write finished, and we set
			 * something outside the resync lru_cache in sync.
			 */
			int rs_left = bm_e_weight(peer_device, enr);
			if (ext->flags != 0) {
				drbd_warn(device, "changing resync lce: %u[%d;%02lx]"
				     " -> %u[%d;00]\n",
				     ext->lce.lc_number, ext->rs_left,
				     ext->flags, enr, rs_left);
				ext->flags = 0;
			}
			if (ext->rs_failed) {
				drbd_warn(device, "Kicking resync_lru element enr=%u "
				     "out with rs_failed=%d\n",
				     ext->lce.lc_number, ext->rs_failed);
			}
			ext->rs_left = rs_left;
			ext->rs_failed = (mode == RECORD_RS_FAILED) ? count : 0;
			/* we don't keep a persistent log of the resync lru,
			 * we can commit any change right away. */
			lc_committed(peer_device->resync_lru);
		}
		if (mode != SET_OUT_OF_SYNC)
			lc_put(peer_device->resync_lru, &ext->lce);
		/* no race, we are within the al_lock! */

		if (ext->rs_left <= ext->rs_failed){
#ifdef _WIN32
			// DW-1640 : Node that are not synctarget or syncsource send P_PEERS_IN_SYNC packtet to synctarget, causing a disk inconsistency. 
			// Only sync source can send P_PEERS_IN_SYNC to peers. In WDRBD, it can be guaranteed that only primary is sync source. 
			if (device->resource->role[NOW] == R_PRIMARY ||
				// DW-1873 change P_PEERS_IN_SYNC send conditions
				is_sync_source(peer_device)) { //peer_device->repl_state[NOW] == L_SYNC_SOURCE){	
				struct update_peers_work *upw;
				upw = kmalloc(sizeof(*upw), GFP_ATOMIC | __GFP_NOWARN, '40DW');
#else
			struct update_peers_work *upw;
			upw = kmalloc(sizeof(*upw), GFP_ATOMIC | __GFP_NOWARN);
#endif
				if (upw) {
					upw->enr = ext->lce.lc_number;
					upw->w.cb = w_update_peers;

					kref_get(&peer_device->device->kref);
					kref_debug_get(&peer_device->device->kref_debug, 5);

					kref_get(&peer_device->connection->kref);
					kref_debug_get(&peer_device->connection->kref_debug, 14);

					upw->peer_device = peer_device;
					drbd_queue_work(&device->resource->work, &upw->w);
				}
				else {
					if (drbd_ratelimit())
						drbd_warn(peer_device, "kmalloc(udw) failed.\n");
				}

				ext->rs_failed = 0;
				return true;
#ifdef _WIN32 // DW-1640
			}
			else {
				return true;
			}
#endif 
		}
	} else if (mode != SET_OUT_OF_SYNC) {
		/* be quiet if lc_find() did not find it. */
		drbd_err(device, "lc_get() failed! locked=%u/%u flags=%llu\n",
		    peer_device->resync_locked,
		    peer_device->resync_lru->nr_elements,
		    (unsigned long long)peer_device->resync_lru->flags);
	}
	return false;
}

#ifdef _WIN32
void drbd_advance_rs_marks(struct drbd_peer_device *peer_device, ULONG_PTR still_to_go)
#else
void drbd_advance_rs_marks(struct drbd_peer_device *peer_device, unsigned long still_to_go)
#endif
{
#ifdef _WIN32
    ULONG_PTR now = jiffies;
    ULONG_PTR last = peer_device->rs_mark_time[peer_device->rs_last_mark];
#else
	unsigned long now = jiffies;
	unsigned long last = peer_device->rs_mark_time[peer_device->rs_last_mark];
#endif
	int next = (peer_device->rs_last_mark + 1) % DRBD_SYNC_MARKS;
	if (time_after_eq(now, last + DRBD_SYNC_MARK_STEP)) {
		if (peer_device->rs_mark_left[peer_device->rs_last_mark] != still_to_go &&
		    peer_device->repl_state[NOW] != L_PAUSED_SYNC_T &&
		    peer_device->repl_state[NOW] != L_PAUSED_SYNC_S) {
			peer_device->rs_mark_time[next] = now;
			peer_device->rs_mark_left[next] = still_to_go;
			peer_device->rs_last_mark = next;
		}
	}
}

/* It is called lazy update, so don't do write-out too often. */
static bool lazy_bitmap_update_due(struct drbd_peer_device *peer_device)
{
	return time_after(jiffies, peer_device->rs_last_writeout + 2*HZ);
}

static void maybe_schedule_on_disk_bitmap_update(struct drbd_peer_device *peer_device,
						 bool rs_done)
{
	if (rs_done) {
		if (peer_device->connection->agreed_pro_version <= 95 ||
			is_sync_target_state(peer_device, NOW)) {
			//DW-1908 check for duplicate completion
			if (test_bit(RS_DONE, &peer_device->flags))
				return;
			set_bit(RS_DONE, &peer_device->flags);
		}
			/* and also set RS_PROGRESS below */

		/* Else: rather wait for explicit notification via receive_state,
		 * to avoid uuids-rotated-too-fast causing full resync
		 * in next handshake, in case the replication link breaks
		 * at the most unfortunate time... */
	} else if (!lazy_bitmap_update_due(peer_device))
		return;

	drbd_peer_device_post_work(peer_device, RS_PROGRESS);
}


#ifdef _WIN32
// DW-844
ULONG_PTR update_sync_bits(struct drbd_peer_device *peer_device,
		ULONG_PTR sbnr, ULONG_PTR ebnr,
		update_sync_bits_mode mode, bool locked)
#else
static int update_sync_bits(struct drbd_peer_device *peer_device,
		unsigned long sbnr, unsigned long ebnr,
		enum update_sync_bits_mode mode)
#endif
{
	/*
	 * We keep a count of set bits per resync-extent in the ->rs_left
	 * caching member, so we need to loop and work within the resync extent
	 * alignment. Typically this loop will execute exactly once.
	 */
	struct drbd_device *device = peer_device->device;
	unsigned long flags;
	ULONG_PTR count = 0;
	unsigned int cleared = 0;
	while (sbnr <= ebnr) {
		/* set temporary boundary bit number to last bit number within
		 * the resync extent of the current start bit number,
		 * but cap at provided end bit number */
		ULONG_PTR tbnr = min(ebnr, sbnr | BM_BLOCKS_PER_BM_EXT_MASK);
		int c;
		int bmi = peer_device->bitmap_index;

		if (mode == RECORD_RS_FAILED)
			/* Only called from drbd_rs_failed_io(), bits
			 * supposedly still set.  Recount, maybe some
			 * of the bits have been successfully cleared
			 * by application IO meanwhile.
			 */
			c = (int)drbd_bm_count_bits(device, bmi, sbnr, tbnr);
		else if (mode == SET_IN_SYNC)
			c = (int)drbd_bm_clear_bits(device, bmi, sbnr, tbnr);
		else /* if (mode == SET_OUT_OF_SYNC) */
			c = (int)drbd_bm_set_bits(device, bmi, sbnr, tbnr);

		if (c) {
			spin_lock_irqsave(&device->al_lock, flags);
			cleared += update_rs_extent(peer_device, (unsigned int)BM_BIT_TO_EXT(sbnr), c, mode);
			spin_unlock_irqrestore(&device->al_lock, flags);
			count += c;
		}
		sbnr = tbnr + 1;
	}

	if (count) {
		//DW-1775 If not SET_OUT_OF_SYNC, check resync completion.
		if (mode != SET_OUT_OF_SYNC) {
			if (mode == RECORD_RS_FAILED)
				peer_device->rs_failed += count;

			ULONG_PTR still_to_go = drbd_bm_total_weight(peer_device);
			bool rs_is_done = (still_to_go <= peer_device->rs_failed);

			if (mode == SET_IN_SYNC) 
				drbd_advance_rs_marks(peer_device, still_to_go);

			if ((mode == SET_IN_SYNC && cleared) || rs_is_done) {
				maybe_schedule_on_disk_bitmap_update(peer_device, rs_is_done);
			}
		}

		wake_up(&device->al_wait);
	}
	else {
		//DW-1761 calls wake_up() to resolve the al_wait timeout when duplicate "SET_OUT_OF_SYNC"
		if (peer_device->repl_state[NOW] == L_AHEAD && mode == SET_OUT_OF_SYNC) {
			struct net_conf *nc;

			// DW-1941
#ifdef _WIN32
			unsigned char oldIrql_rLock = 0;

			if (!locked)
				rcu_read_lock_w32_inner();
#else // _LIN
			rcu_read_lock();
#endif
			nc = rcu_dereference(peer_device->connection->transport.net_conf);

#ifdef _WIN32
			if (!locked)
#endif
				rcu_read_unlock();

			if (device->act_log->used < nc->cong_extents)
				wake_up(&device->al_wait);
		}
	}
	return count;
}

static bool plausible_request_size(int size)
{
	return size > 0
		&& size <= DRBD_MAX_BATCH_BIO_SIZE
		&& IS_ALIGNED(size, 512);
}

/* clear the bit corresponding to the piece of storage in question:
 * size byte of data starting from sector.  Only clear a bits of the affected
 * one ore more _aligned_ BM_BLOCK_SIZE blocks.
 *
 * called by worker on L_SYNC_TARGET and receiver on SyncSource.
 *
 */
ULONG_PTR __drbd_change_sync(struct drbd_peer_device *peer_device, sector_t sector, int size,
		update_sync_bits_mode mode)
{
	/* Is called from worker and receiver context _only_ */
	struct drbd_device *device = peer_device->device;
	ULONG_PTR sbnr, ebnr, lbnr;
	ULONG_PTR count = 0;
	sector_t esector, nr_sectors;

	/* This would be an empty REQ_OP_FLUSH, be silent. */
	if ((mode == SET_OUT_OF_SYNC) && size == 0)
		return 0;

	if (!plausible_request_size(size)) {
		drbd_err(device, "%s: sector=%llus size=%u nonsense!\n",
				drbd_change_sync_fname[mode],
				(unsigned long long)sector, size);
		return 0;
	}

	if (!get_ldev(device))
#ifdef _WIN32_DEBUG_OOS
		// MODIFIED_BY_MANTECH DW-1153: add error log
	{
		drbd_err(device, "get_ldev failed, sector(%llu)\n", sector);
		return 0; /* no disk, no metadata, no bitmap to manipulate bits in */
	}
#else
		return 0; /* no disk, no metadata, no bitmap to manipulate bits in */
#endif

	nr_sectors = drbd_get_capacity(device->this_bdev);
	esector = sector + (size >> 9) - 1;

	if (!expect(peer_device, sector < nr_sectors))
#ifdef _WIN32_DEBUG_OOS
		// MODIFIED_BY_MANTECH DW-1153: add error log
	{
		drbd_err(peer_device, "unexpected error, sector(%llu) < nr_sectors(%llu)\n", sector, nr_sectors);
		goto out;
	}
#else
		goto out;
#endif
	if (!expect(peer_device, esector < nr_sectors))
		esector = nr_sectors - 1;

	lbnr = (ULONG_PTR)BM_SECT_TO_BIT(nr_sectors - 1);

	if (mode == SET_IN_SYNC) {
		/* Round up start sector, round down end sector.  We make sure
		 * we only clear full, aligned, BM_BLOCK_SIZE blocks. */
		if (unlikely(esector < BM_SECT_PER_BIT-1))
#ifdef _WIN32_DEBUG_OOS
			// MODIFIED_BY_MANTECH DW-1153: add error log
		{
			drbd_err(peer_device, "unexpected error, sector(%llu), esector(%llu)\n", sector, esector);
			goto out;
		}
#else
			goto out;
#endif
		if (unlikely(esector == (nr_sectors-1)))
			ebnr = lbnr;
		else
			ebnr = (ULONG_PTR)BM_SECT_TO_BIT(esector - (BM_SECT_PER_BIT - 1));
		sbnr = (ULONG_PTR)BM_SECT_TO_BIT(sector + BM_SECT_PER_BIT - 1);
	} else {
		/* We set it out of sync, or record resync failure.
		 * Should not round anything here. */
		sbnr = (ULONG_PTR)BM_SECT_TO_BIT(sector);
		ebnr = (ULONG_PTR)BM_SECT_TO_BIT(esector);
	}

#ifndef _WIN64
	BUG_ON_UINT32_OVER(sbnr);
	BUG_ON_UINT32_OVER(ebnr);
#endif

	count = update_sync_bits(peer_device, sbnr, ebnr, mode, false);
out:
	put_ldev(device);
	return count;
}

bool drbd_set_all_out_of_sync(struct drbd_device *device, sector_t sector, int size)
{
	return drbd_set_sync(device, sector, size, DRBD_END_OF_BITMAP, DRBD_END_OF_BITMAP);
}

/**
 * drbd_set_sync  -  Set a disk range in or out of sync
 * @device:	DRBD device
 * @sector:	start sector of disk range
 * @size:	size of disk range in bytes
 * @bits:	bit values to use by bitmap index
 * @mask:	bitmap indexes to modify (mask set)
 */
#ifdef _WIN32
// MODIFIED_BY_MANTECH DW-1191: caller needs to determine the peers that oos has been set.
unsigned long drbd_set_sync(struct drbd_device *device, sector_t sector, int size,
		   ULONG_PTR bits, ULONG_PTR mask)
#else
bool drbd_set_sync(struct drbd_device *device, sector_t sector, int size,
		   unsigned long bits, unsigned long mask)
#endif
{
	ULONG_PTR set_start, set_end, clear_start, clear_end;
	sector_t esector, nr_sectors;
#ifdef _WIN32
	unsigned long set_bits = 0;
#else
	bool set = false;
#endif
	struct drbd_peer_device *peer_device;
	//DW-1871
	bool skip_clear = false;
#ifndef _WIN32
	mask &= (1 << device->bitmap->bm_max_peers) - 1;
#endif
	if (size <= 0 || !IS_ALIGNED(size, 512)) {
		drbd_err(device, "%s sector: %llus, size: %d\n",
			 __func__, (unsigned long long)sector, size);
		return false;
	}

	if (!get_ldev(device))
#ifdef _WIN32_DEBUG_OOS
		// MODIFIED_BY_MANTECH DW-1153: add error log
	{
		drbd_err(device, "get_ldev failed, sector(%llu)\n", sector);
		return false; /* no disk, no metadata, no bitmap to set bits in */
	}
#else
		return false; /* no disk, no metadata, no bitmap to set bits in */
#endif
#ifdef _WIN32
	mask &= (1 << device->bitmap->bm_max_peers) - 1;
#endif
	nr_sectors = drbd_get_capacity(device->this_bdev);
	esector = sector + (size >> 9) - 1;

	if (!expect(device, sector < nr_sectors))
#ifdef _WIN32_DEBUG_OOS
		// MODIFIED_BY_MANTECH DW-1153: add error log
	{
		drbd_err(device, "unexpected error, sector(%llu) < nr_sectors(%llu)\n", sector, nr_sectors);
		goto out;
	}
#else
		goto out;
#endif
	if (!expect(device, esector < nr_sectors))
		esector = nr_sectors - 1;

	/* For marking sectors as out of sync, we need to round up. */
	set_start = (ULONG_PTR)BM_SECT_TO_BIT(sector);
	set_end = (ULONG_PTR)BM_SECT_TO_BIT(esector);


	/* For marking sectors as in sync, we need to round down except when we
	 * reach the end of the device: The last bit in the bitmap does not
	 * account for sectors past the end of the device.
	 * CLEAR_END can become negative here. */
	clear_start = (ULONG_PTR)BM_SECT_TO_BIT(sector + BM_SECT_PER_BIT - 1);
	if (esector == nr_sectors - 1)
		clear_end = (ULONG_PTR)BM_SECT_TO_BIT(esector);
	else {
		clear_end = (ULONG_PTR)BM_SECT_TO_BIT(esector + 1);
		//DW-1871 if clear_end is zero, you do not need to call it. update_sync_bits(), drbd_bm_clear_bits()
		if (clear_end == 0)
			skip_clear = true;
		else
			clear_end -= 1;
	}
	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		int bitmap_index = peer_device->bitmap_index;

		if (bitmap_index == -1)
			continue;

		if (!test_and_clear_bit(bitmap_index, &mask))
			continue;

		if (test_bit(bitmap_index, &bits))
#ifdef _WIN32
			// MODIFIED_BY_MANTECH DW-1191: caller needs to know if the bits has been set at least.
		{
			if (update_sync_bits(peer_device, set_start, set_end, SET_OUT_OF_SYNC, true) > 0)
				set_bits |= (1 << bitmap_index);
		}
#else
			update_sync_bits(peer_device, set_start, set_end, SET_OUT_OF_SYNC);
#endif
		//DW-1871
		else if (clear_start <= clear_end && !skip_clear)
			update_sync_bits(peer_device, clear_start, clear_end, SET_IN_SYNC, true);
	}
	rcu_read_unlock();
	if (mask) {
		ULONG_PTR bitmap_index;
#ifdef _WIN32
		for_each_set_bit(bitmap_index, (ULONG_PTR*)&mask, BITS_PER_LONG) {
#else 
		for_each_set_bit(bitmap_index, &mask, BITS_PER_LONG) {
#endif
#ifdef _WIN64
			BUG_ON_UINT32_OVER(bitmap_index);
#endif
			if (test_bit((unsigned int)bitmap_index, &bits))
				drbd_bm_set_bits(device, (unsigned int)bitmap_index, set_start, set_end);
			//DW-1871
			else if (clear_start <= clear_end && !skip_clear)
				drbd_bm_clear_bits(device, (unsigned int)bitmap_index, clear_start, clear_end);
		}
	}

out:
	put_ldev(device);

#ifdef _WIN32
	return set_bits;
#else
	return set;
#endif
}

static
struct bm_extent *_bme_get(struct drbd_peer_device *peer_device, unsigned int enr)
{
	struct drbd_device *device = peer_device->device;
	struct lc_element *e;
	struct bm_extent *bm_ext;
	int wakeup = 0;
	ULONG_PTR rs_flags;

	spin_lock_irq(&device->al_lock);
	if (peer_device->resync_locked > peer_device->resync_lru->nr_elements/2) {
		spin_unlock_irq(&device->al_lock);
		return NULL;
	}
	e = lc_get(peer_device->resync_lru, enr);
	bm_ext = e ? lc_entry(e, struct bm_extent, lce) : NULL;
	if (bm_ext) {
		if (bm_ext->lce.lc_number != enr) {
			bm_ext->rs_left = bm_e_weight(peer_device, enr);
			bm_ext->rs_failed = 0;
			lc_committed(peer_device->resync_lru);
			wakeup = 1;
		}
		if (bm_ext->lce.refcnt == 1)
			peer_device->resync_locked++;
		set_bit(BME_NO_WRITES, &bm_ext->flags);
	}
	rs_flags = peer_device->resync_lru->flags;
	spin_unlock_irq(&device->al_lock);
	if (wakeup)
		wake_up(&device->al_wait);

	if (!bm_ext) {
		if (rs_flags & LC_STARVING)
			drbd_warn(peer_device, "Have to wait for element"
			     " (resync LRU too small?)\n");
		BUG_ON(rs_flags & LC_LOCKED);
	}

	return bm_ext;
}

static int _is_in_al(struct drbd_device *device, unsigned int enr)
{
	int rv;

	spin_lock_irq(&device->al_lock);
	rv = lc_is_used(device->act_log, enr);
	spin_unlock_irq(&device->al_lock);

	return rv;
}

/**
 * drbd_rs_begin_io() - Gets an extent in the resync LRU cache and sets it to BME_LOCKED
 *
 * This functions sleeps on al_wait. Returns 0 on success, -EINTR if interrupted.
 */
int drbd_rs_begin_io(struct drbd_peer_device *peer_device, sector_t sector)
{
	struct drbd_device *device = peer_device->device;
	ULONG_PTR enr = (ULONG_PTR)BM_SECT_TO_EXT(sector);
	struct bm_extent *bm_ext;
	int i, sig;
	bool sa;
#ifdef _WIN64
	BUG_ON_UINT32_OVER((enr * AL_EXT_PER_BM_SECT + AL_EXT_PER_BM_SECT));
#endif
retry:
#ifdef _WIN32
    wait_event_interruptible(sig, device->al_wait,
        (bm_ext = _bme_get(peer_device, (unsigned int)enr)));
#else
	sig = wait_event_interruptible(device->al_wait,
			(bm_ext = _bme_get(peer_device, enr)));
#endif
	if (sig)
		return -EINTR;

	if (test_bit(BME_LOCKED, &bm_ext->flags))
		return 0;

	/* step aside only while we are above c-min-rate; unless disabled. */
	sa = drbd_rs_c_min_rate_throttle(peer_device);

	for (i = 0; i < AL_EXT_PER_BM_SECT; i++) {
#ifdef _WIN32
        wait_event_interruptible(sig, device->al_wait,
            !_is_in_al(device, (unsigned int)(enr * AL_EXT_PER_BM_SECT + i)) ||
            (sa && test_bit(BME_PRIORITY, &bm_ext->flags)));
#else
		sig = wait_event_interruptible(device->al_wait,
					       !_is_in_al(device, enr * AL_EXT_PER_BM_SECT + i) ||
					       (sa && test_bit(BME_PRIORITY, &bm_ext->flags)));
#endif
		if (sig || (sa && test_bit(BME_PRIORITY, &bm_ext->flags))) {
			spin_lock_irq(&device->al_lock);
			int lc_put_result = lc_put(peer_device->resync_lru, &bm_ext->lce);
			if (lc_put_result == 0) {
				bm_ext->flags = 0; /* clears BME_NO_WRITES and eventually BME_PRIORITY */
				peer_device->resync_locked--;
				wake_up(&device->al_wait);
			}
			else if (lc_put_result < 0) {
				WDRBD_ERROR("lc_put return error.\n");
				spin_unlock_irq(&device->al_lock);
				return -EINTR;
			}
			spin_unlock_irq(&device->al_lock);
			if (sig)
				return -EINTR;
			if (schedule_timeout_interruptible(HZ/10))
				return -EINTR;
			goto retry;
		}
	}
	set_bit(BME_LOCKED, &bm_ext->flags);
	return 0;
}

/**
 * drbd_try_rs_begin_io() - Gets an extent in the resync LRU cache, does not sleep
 *
 * Gets an extent in the resync LRU cache, sets it to BME_NO_WRITES, then
 * tries to set it to BME_LOCKED. Returns 0 upon success, and -EAGAIN
 * if there is still application IO going on in this area.
 */
int drbd_try_rs_begin_io(struct drbd_peer_device *peer_device, sector_t sector, bool throttle)
{
	struct drbd_device *device = peer_device->device;
	ULONG_PTR enr = (ULONG_PTR)BM_SECT_TO_EXT(sector);
	const ULONG_PTR al_enr = enr * AL_EXT_PER_BM_SECT;
	struct lc_element *e;
	struct bm_extent *bm_ext;
	int i;

	if (throttle)
		throttle = drbd_rs_should_slow_down(peer_device, sector, true);

	/* If we need to throttle, a half-locked (only marked BME_NO_WRITES,
	 * not yet BME_LOCKED) extent needs to be kicked out explicitly if we
	 * need to throttle. There is at most one such half-locked extent,
	 * which is remembered in resync_wenr. */

	if (throttle && peer_device->resync_wenr != enr)
		return -EAGAIN;

#ifdef _WIN64
	BUG_ON_UINT32_OVER(enr);
	BUG_ON_UINT32_OVER(al_enr);
#endif

	spin_lock_irq(&device->al_lock);
	if (peer_device->resync_wenr != LC_FREE && peer_device->resync_wenr != enr) {
		/* in case you have very heavy scattered io, it may
		 * stall the syncer undefined if we give up the ref count
		 * when we try again and requeue.
		 *
		 * if we don't give up the refcount, but the next time
		 * we are scheduled this extent has been "synced" by new
		 * application writes, we'd miss the lc_put on the
		 * extent we keep the refcount on.
		 * so we remembered which extent we had to try again, and
		 * if the next requested one is something else, we do
		 * the lc_put here...
		 * we also have to wake_up
		 */

		e = lc_find(peer_device->resync_lru, peer_device->resync_wenr);
		bm_ext = e ? lc_entry(e, struct bm_extent, lce) : NULL;
		if (bm_ext) {
			D_ASSERT(device, !test_bit(BME_LOCKED, &bm_ext->flags));
			D_ASSERT(device, test_bit(BME_NO_WRITES, &bm_ext->flags));
			clear_bit(BME_NO_WRITES, &bm_ext->flags);
			peer_device->resync_wenr = LC_FREE;
			int lc_put_result = lc_put(peer_device->resync_lru, &bm_ext->lce);
			if (lc_put_result == 0) {
				bm_ext->flags = 0;
				peer_device->resync_locked--;
			}
			else if (lc_put_result < 0) {
				WDRBD_ERROR("lc_put return error.\n");
				goto out;
			}
			 
			wake_up(&device->al_wait);
		} else {
			drbd_alert(device, "LOGIC BUG\n");
		}
	}
	/* TRY. */
	e = lc_try_get(peer_device->resync_lru, (unsigned int)enr);
	bm_ext = e ? lc_entry(e, struct bm_extent, lce) : NULL;
	if (bm_ext) {
		if (test_bit(BME_LOCKED, &bm_ext->flags))
			goto proceed;
		if (!test_and_set_bit(BME_NO_WRITES, &bm_ext->flags)) {
			peer_device->resync_locked++;
		} else {
			/* we did set the BME_NO_WRITES,
			 * but then could not set BME_LOCKED,
			 * so we tried again.
			 * drop the extra reference. */
			bm_ext->lce.refcnt--;
			D_ASSERT(device, bm_ext->lce.refcnt > 0);
		}
		goto check_al;
	} else {
		/* do we rather want to try later? */
		if (peer_device->resync_locked > peer_device->resync_lru->nr_elements-3)
			goto try_again;
		/* Do or do not. There is no try. -- Yoda */
		e = lc_get(peer_device->resync_lru, (unsigned int)enr);
		bm_ext = e ? lc_entry(e, struct bm_extent, lce) : NULL;
		if (!bm_ext) {
			const ULONG_PTR rs_flags = peer_device->resync_lru->flags;
			if (rs_flags & LC_STARVING)
				drbd_warn(device, "Have to wait for element"
				     " (resync LRU too small?)\n");
			BUG_ON(rs_flags & LC_LOCKED);
			goto try_again;
		}
		if (bm_ext->lce.lc_number != enr) {
			bm_ext->rs_left = bm_e_weight(peer_device, (unsigned int)enr);
			bm_ext->rs_failed = 0;
			lc_committed(peer_device->resync_lru);
			wake_up(&device->al_wait);
			D_ASSERT(device, test_bit(BME_LOCKED, &bm_ext->flags) == 0);
		}
		set_bit(BME_NO_WRITES, &bm_ext->flags);
		D_ASSERT(device, bm_ext->lce.refcnt == 1);
		peer_device->resync_locked++;
		goto check_al;
	}
check_al:
	//DW-1601 If greater than 112, remove act_log and resync_lru associations
#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
	if (peer_device->connection->agreed_pro_version <= 112) 
#endif
	{
		for (i = 0; i < AL_EXT_PER_BM_SECT; i++) {
			if (lc_is_used(device->act_log, (unsigned int)(al_enr + i))){
				WDRBD_TRACE_AL("check_al sector = %lu, enr = %llu, al_enr + 1 = %llu and goto try_again\n", sector, (unsigned long long)enr, (unsigned long long)al_enr + i);
				goto try_again;
			}
		}
	}
	set_bit(BME_LOCKED, &bm_ext->flags);
proceed:
	WDRBD_TRACE_AL("proceed sector = %lu, enr = %llu\n", sector, (unsigned long long)enr);
	peer_device->resync_wenr = LC_FREE;
	spin_unlock_irq(&device->al_lock);
	return 0;

try_again:
	if (bm_ext) {
		if (throttle ||
		    (test_bit(BME_PRIORITY, &bm_ext->flags) && bm_ext->lce.refcnt == 1)) {
			D_ASSERT(peer_device, !test_bit(BME_LOCKED, &bm_ext->flags));
			D_ASSERT(peer_device, test_bit(BME_NO_WRITES, &bm_ext->flags));
			clear_bit(BME_NO_WRITES, &bm_ext->flags);
			clear_bit(BME_PRIORITY, &bm_ext->flags);
			peer_device->resync_wenr = LC_FREE;
			int lc_put_result = lc_put(peer_device->resync_lru, &bm_ext->lce);
			if (lc_put_result == 0) {
				bm_ext->flags = 0;
				peer_device->resync_locked--;
			}
			else if (lc_put_result < 0){
				goto out;
			}
			wake_up(&device->al_wait);
		}
		else
			peer_device->resync_wenr = (unsigned int)enr;
	}
out:
	spin_unlock_irq(&device->al_lock);
	return -EAGAIN;
}

void drbd_rs_complete_io(struct drbd_peer_device *peer_device, sector_t sector, char *caller)
{
	struct drbd_device *device = peer_device->device;
	ULONG_PTR enr = (ULONG_PTR)BM_SECT_TO_EXT(sector);
	struct lc_element *e;
	struct bm_extent *bm_ext;
	unsigned long flags;

#ifdef _WIN64
	BUG_ON_UINT32_OVER(enr);
#endif
	spin_lock_irqsave(&device->al_lock, flags);
	e = lc_find(peer_device->resync_lru, (unsigned int)enr);
	bm_ext = e ? lc_entry(e, struct bm_extent, lce) : NULL;
	if (!bm_ext) {
		spin_unlock_irqrestore(&device->al_lock, flags);
		if (drbd_ratelimit())
			drbd_err(device, "%s => drbd_rs_complete_io() called, but extent not found\n", caller);
		return;
	}

	if (bm_ext->lce.refcnt == 0) {
		spin_unlock_irqrestore(&device->al_lock, flags);
		drbd_err(device, "%s => drbd_rs_complete_io(,%llu [=%llu], %llu) called, "
		    "but refcnt is 0!?\n", 
			caller, (unsigned long long)sector, (unsigned long long)enr, (ULONG_PTR)BM_SECT_TO_BIT(sector));
		return;
	}

	if (lc_put(peer_device->resync_lru, &bm_ext->lce) == 0) {
		bm_ext->flags = 0; /* clear BME_LOCKED, BME_NO_WRITES and BME_PRIORITY */
		peer_device->resync_locked--;
		wake_up(&device->al_wait);
	}

	spin_unlock_irqrestore(&device->al_lock, flags);
}

/**
 * drbd_rs_cancel_all() - Removes all extents from the resync LRU (even BME_LOCKED)
 */
void drbd_rs_cancel_all(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	spin_lock_irq(&device->al_lock);

	if (get_ldev_if_state(device, D_DETACHING)) { /* Makes sure ->resync is there. */
		lc_reset(peer_device->resync_lru);
		put_ldev(device);
	}
	peer_device->resync_locked = 0;
	peer_device->resync_wenr = LC_FREE;
	spin_unlock_irq(&device->al_lock);
	wake_up(&device->al_wait);
}

/**
 * drbd_rs_del_all() - Gracefully remove all extents from the resync LRU
 *
 * Returns 0 upon success, -EAGAIN if at least one reference count was
 * not zero.
 */
int drbd_rs_del_all(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct lc_element *e;
	struct bm_extent *bm_ext;
	unsigned int i;

	spin_lock_irq(&device->al_lock);

	if (get_ldev_if_state(device, D_DETACHING)) {
		/* ok, ->resync is there. */
		for (i = 0; i < peer_device->resync_lru->nr_elements; i++) {
			e = lc_element_by_index(peer_device->resync_lru, i);
			bm_ext = lc_entry(e, struct bm_extent, lce);
			if (bm_ext->lce.lc_number == LC_FREE)
				continue;
			if (bm_ext->lce.lc_number == peer_device->resync_wenr) {
				drbd_info(peer_device, "dropping %u in drbd_rs_del_all, apparently"
				     " got 'synced' by application io\n",
				     peer_device->resync_wenr);
				D_ASSERT(peer_device, !test_bit(BME_LOCKED, &bm_ext->flags));
				D_ASSERT(peer_device, test_bit(BME_NO_WRITES, &bm_ext->flags));
				clear_bit(BME_NO_WRITES, &bm_ext->flags);
				peer_device->resync_wenr = LC_FREE;
				lc_put(peer_device->resync_lru, &bm_ext->lce);
			}
			if (bm_ext->lce.refcnt != 0) {
				drbd_info(peer_device, "Retrying drbd_rs_del_all() later. "
				     "refcnt=%u\n", bm_ext->lce.refcnt);
				put_ldev(device);
				spin_unlock_irq(&device->al_lock);
				return -EAGAIN;
			}
			D_ASSERT(peer_device, !test_bit(BME_LOCKED, &bm_ext->flags));
			D_ASSERT(peer_device, !test_bit(BME_NO_WRITES, &bm_ext->flags));
			lc_del(peer_device->resync_lru, &bm_ext->lce);
		}
		D_ASSERT(peer_device, peer_device->resync_lru->used == 0);
		put_ldev(device);
	}
	spin_unlock_irq(&device->al_lock);
	wake_up(&device->al_wait);

	return 0;
}

bool drbd_sector_has_priority(struct drbd_peer_device *peer_device, sector_t sector)
{
	struct drbd_device *device = peer_device->device;
	struct lc_element *tmp;
	bool has_priority = false;
#ifdef _WIN64
	BUG_ON_UINT32_OVER(BM_SECT_TO_EXT(sector));
#endif
	spin_lock_irq(&device->al_lock);
	tmp = lc_find(peer_device->resync_lru, (unsigned int)BM_SECT_TO_EXT(sector));
	if (tmp) {
		struct bm_extent *bm_ext = lc_entry(tmp, struct bm_extent, lce);
		has_priority = test_bit(BME_PRIORITY, &bm_ext->flags);
	}
	spin_unlock_irq(&device->al_lock);
	return has_priority;
}
