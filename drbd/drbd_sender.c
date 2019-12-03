/*
   drbd_sender.c

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
#include <linux-compat/sched.h>
#include <linux-compat/wait.h>
#include <drbd_windows.h>
#else
#include <linux/module.h>
#include <linux/drbd.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#endif
#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"

#ifdef _WIN32
/* DW-1587
* Turns off the C6319 warning caused by code analysis.
* The use of comma does not cause any performance problems or bugs,
* but keep the code as it is written.
*/
#pragma warning (disable: 6319)
#endif

static int make_ov_request(struct drbd_peer_device *, int);
static int make_resync_request(struct drbd_peer_device *, int);
static void maybe_send_barrier(struct drbd_connection *, unsigned int);
static void process_io_error(struct bio *bio, struct drbd_device *device, unsigned char disk_type, int error);

/* endio handlers:
 *   drbd_md_endio (defined here)
 *   drbd_request_endio (defined here)
 *   drbd_peer_request_endio (defined here)
 *   drbd_bm_endio (defined in drbd_bitmap.c)
 *
 * For all these callbacks, note the following:
 * The callbacks will be called in irq context by the IDE drivers,
 * and in Softirqs/Tasklets/BH context by the SCSI drivers.
 * Try to get the locking right :)
 *
 */

struct mutex resources_mutex;
spinlock_t g_inactive_lock; // DW-1935

/* used for synchronous meta data and bitmap IO
 * submitted by drbd_md_sync_page_io()
 */
#ifdef _WIN32
NTSTATUS drbd_md_endio(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
#else 
BIO_ENDIO_TYPE drbd_md_endio BIO_ENDIO_ARGS(struct bio *bio, int error)
#endif
{
	struct drbd_device *device;
#ifdef _WIN32
    struct bio *bio = NULL;
    int error = 0;
#ifdef DRBD_TRACE
    WDRBD_TRACE("BIO_ENDIO_FN_START:Thread(%s) drbd_md_io_complete IRQL(%d) .............\n", current->comm, KeGetCurrentIrql());
#endif

	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
        error = Irp->IoStatus.Status;
		bio = (struct bio *)Context;
		//
		//	Simulation Local Disk I/O Error Point. disk error simluation type 3
		//
		if(gSimulDiskIoError.ErrorFlag && gSimulDiskIoError.ErrorType == SIMUL_DISK_IO_ERROR_TYPE3) {
			if(IsDiskError()) {
				WDRBD_ERROR("SimulDiskIoError: Meta Data I/O Error type3.....ErrorFlag:%d ErrorCount:%d\n", gSimulDiskIoError.ErrorFlag, gSimulDiskIoError.ErrorCount);
				error = STATUS_UNSUCCESSFUL;
			}
		}
// DW-1830
// Disable this code because io hang occurs during IRP reuse.
#ifdef RETRY_WRITE_IO
		if(NT_ERROR(error)) {
			if( (bio->bi_rw & WRITE) && bio->io_retry ) {
				RetryAsyncWriteRequest(bio, Irp, error, "drbd_md_endio");
				return STATUS_MORE_PROCESSING_REQUIRED;
			}
		}
#endif		
    } else {
        error = (int)Context;
        bio = (struct bio *)Irp;
    }
#endif
	if (!bio)
		BIO_ENDIO_FN_RETURN;

	/* DW-1822
	 * The generic_make_request calls IoAcquireRemoveLock before the IRP is created
	 * and is freed from the completion routine functions.
	 * However, retry I/O operations are performed without RemoveLock,
	 * because the retry routine will work after the release.
	 * IoReleaseRemoveLock must be moved so that it is released after the retry.
	 */
	//DW-1831 check whether bio->bi_bdev and bio->bi_bdev->bd_disk are null.
	if (bio && bio->bi_bdev && bio->bi_bdev->bd_disk) {
		if (bio->bi_bdev->bd_disk->pDeviceExtension != NULL) {
			IoReleaseRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);
		}
	}

	BIO_ENDIO_FN_START;

	device = bio->bi_private;
	device->md_io.error = error;

	if(NT_ERROR(error)) {
		process_io_error(bio, device, VOLUME_TYPE_META, error);
	}
	
	if (device->ldev) /* special case: drbd_md_read() during drbd_adm_attach() */
		put_ldev(device);

#ifdef _WIN32
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

#ifdef _WIN32
	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		bio_put(bio);
	}
#else
	bio_put(bio);
#endif

	/* We grabbed an extra reference in _drbd_md_sync_page_io() to be able
	 * to timeout on the lower level device, and eventually detach from it.
	 * If this io completion runs after that timeout expired, this
	 * drbd_md_put_buffer() may allow us to finally try and re-attach.
	 * During normal operation, this only puts that extra reference
	 * down to 1 again.
	 * Make sure we first drop the reference, and only then signal
	 * completion, or we may (in drbd_al_read_log()) cycle so fast into the
	 * next drbd_md_sync_page_io(), that we trigger the
	 * ASSERT(atomic_read(&mdev->md_io_in_use) == 1) there.
	 */
	drbd_md_put_buffer(device);
#ifdef DRBD_TRACE
    WDRBD_TRACE("drbd_md_io_complete: md_io->done(%d) bio se:0x%llx sz:%d\n", device->md_io.done, bio->bi_sector, bio->bi_size);
#endif
	device->md_io.done = 1;
	wake_up(&device->misc_wait);
	
#ifdef DRBD_TRACE	
	{
		static int cnt = 0;
		WDRBD_TRACE("drbd_md_endio done.(%d)................!!!\n", cnt++);
	}
#endif
	BIO_ENDIO_FN_RETURN;
}

/* reads on behalf of the partner,
 * "submitted" by the receiver
 */
static void drbd_endio_read_sec_final(struct drbd_peer_request *peer_req) __releases(local)
{
	unsigned long flags = 0;
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct drbd_connection *connection;

	spin_lock(&g_inactive_lock);
	if (test_bit(__EE_WAS_INACTIVE_REQ, &peer_req->flags)) {
		if (!test_bit(__EE_WAS_LOST_REQ, &peer_req->flags)) {

			peer_device = peer_req->peer_device;
			device = peer_device->device;
			connection = peer_device->connection;

			//DW-1735 : In case of the same peer_request, destroy it in inactive_ee and exit the function.
			struct drbd_peer_request *p_req, *t_inative;

			list_for_each_entry_safe(struct drbd_peer_request, p_req, t_inative, &connection->inactive_ee, w.list) {
				if (peer_req == p_req) {
					drbd_info(device, "destroy, read inactive_ee(%p), sector(%llu), size(%d)\n", peer_req, peer_req->i.sector, peer_req->i.size);
					// DW-1935
					list_del(&peer_req->w.list);
					drbd_free_peer_req(peer_req);
					atomic_dec(&connection->inacitve_ee_cnt);
					put_ldev(device);
					break;
				}
			}
		}
		else {
			WDRBD_INFO("destroy, read lost inactive_ee(%p), sector(%llu), size(%d)\n", peer_req, peer_req->i.sector, peer_req->i.size);
			drbd_free_peer_req(peer_req);
		}

		spin_unlock(&g_inactive_lock);
		return;
	}
	spin_unlock(&g_inactive_lock);

	// DW-1935
	// TODO - peer_device, connection object can be removed while in use if subsequent operation of the function is later than completion of del_connection() and adm_detach().
	peer_device = peer_req->peer_device;
	device = peer_device->device;
	connection = peer_device->connection;

	spin_lock_irqsave(&device->resource->req_lock, flags);
	device->read_cnt += peer_req->i.size >> 9;
	list_del(&peer_req->w.list);
	if (list_empty(&connection->read_ee))
		wake_up(&connection->ee_wait);
	if (test_bit(__EE_WAS_ERROR, &peer_req->flags)) {
		atomic_inc(&device->io_error_count);
		drbd_md_set_flag(device, MDF_IO_ERROR);
		//DW-1843 set MDF_PRIMARY_IO_ERROR flag when reading IO error at primary.
		if (device->resource->role[NOW] == R_PRIMARY) {
			drbd_md_set_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR);
		}
		__drbd_chk_io_error(device, DRBD_READ_ERROR);
	}
	spin_unlock_irqrestore(&device->resource->req_lock, flags);

	drbd_queue_work(&connection->sender_work, &peer_req->w);
	put_ldev(device);
}

static int is_failed_barrier(int ee_flags)
{
	return (ee_flags & (EE_IS_BARRIER|EE_WAS_ERROR|EE_RESUBMITTED|EE_IS_TRIM))
		== (EE_IS_BARRIER|EE_WAS_ERROR);
}

/* writes on behalf of the partner, or resync writes,
 * "submitted" by the receiver, final stage.  */
void drbd_endio_write_sec_final(struct drbd_peer_request *peer_req) __releases(local)
{
	long lock_flags = 0;
	ULONG_PTR flags = 0;
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	struct drbd_connection *connection;
	sector_t sector;
	int do_wake = 0;
	u64 block_id;
	// DW-1928 
	unsigned int size;
	// DW-1696 In case of the same peer_request, destroy it in inactive_ee and exit the function.
	// DW-1935
	spin_lock(&g_inactive_lock);
	if (test_bit(__EE_WAS_INACTIVE_REQ, &peer_req->flags)) {
		if (!test_bit(__EE_WAS_LOST_REQ, &peer_req->flags)) {
			struct drbd_peer_request *p_req, *t_inative;

			peer_device = peer_req->peer_device;
			device = peer_device->device;
			connection = peer_device->connection;

			list_for_each_entry_safe(struct drbd_peer_request, p_req, t_inative, &connection->inactive_ee, w.list) {
				if (peer_req == p_req) {
					if (peer_req->block_id != ID_SYNCER) {
						//DW-1920 in inactive_ee, the replication data calls drbd_al_complete_io() upon completion of the write.
						drbd_al_complete_io(device, &peer_req->i);
						drbd_info(device, "destroy, active_ee => inactive_ee(%p), sector(%llu), size(%d)\n", peer_req, peer_req->i.sector, peer_req->i.size);
					}
					else {
						drbd_info(device, "destroy, sync_ee => inactive_ee(%p), sector(%llu), size(%d)\n", peer_req, peer_req->i.sector, peer_req->i.size);
					}
					// DW-1935
					list_del(&peer_req->w.list);
					drbd_free_peer_req(peer_req);
					atomic_dec(&connection->inacitve_ee_cnt);
					put_ldev(device);
					break;
				}
			}
		}
		else {
			WDRBD_INFO("destroy, wrtie inactive_ee(%p), sector(%llu), size(%d)\n", peer_req, peer_req->i.sector, peer_req->i.size);
			drbd_free_peer_req(peer_req);
		}
		spin_unlock(&g_inactive_lock);
		return;
	}
	spin_unlock(&g_inactive_lock);

	peer_device = peer_req->peer_device;
	device = peer_device->device;
	connection = peer_device->connection;

	/* if this is a failed barrier request, disable use of barriers,
	 * and schedule for resubmission */
#ifdef _WIN64
	BUG_ON_UINT32_OVER(peer_req->flags);
#endif
	if (is_failed_barrier((int)peer_req->flags)) {
		drbd_bump_write_ordering(device->resource, device->ldev, WO_BDEV_FLUSH);
		spin_lock_irqsave(&device->resource->req_lock, lock_flags);
		list_del(&peer_req->w.list);
		peer_req->flags = (peer_req->flags & ~EE_WAS_ERROR) | EE_RESUBMITTED;
		peer_req->w.cb = w_e_reissue;
		/* put_ldev actually happens below, once we come here again. */
		__release(local);
		spin_unlock_irqrestore(&device->resource->req_lock, lock_flags);
		drbd_queue_work(&connection->sender_work, &peer_req->w);
		return;
	}

	/* after we moved peer_req to done_ee,
	 * we may no longer access it,
	 * it may be freed/reused already!
	 * (as soon as we release the req_lock) */

	//DW-1601 the last split uses the sector of the first bit for resync_lru matching.
	if (peer_req->flags & EE_SPLIT_LAST_REQ)
		sector = BM_BIT_TO_SECT(peer_req->s_bb);
	else
		sector = peer_req->i.sector;

	block_id = peer_req->block_id;
	flags = peer_req->flags;

	if (flags & EE_WAS_ERROR) {
		//DW-1842 __EE_SEND_WRITE_ACK should be used only for replication.
		if (block_id != ID_SYNCER) {
			/* In protocol != C, we usually do not send write acks.
			* In case of a write error, send the neg ack anyways. */
			if (!__test_and_set_bit(__EE_SEND_WRITE_ACK, &peer_req->flags))
				inc_unacked(peer_device);
		}
		/* DW-1810
		 * There is no case where this flag is set because of WRITE SAME, TRIM. 
           Therefore, the flag EE_WAS_ERROR means that an IO ERROR occurred. 
		   In order to synchronize the Secondaries at the time of primary failure, 
		   OOS for IO error is recorded for all nodes.
		 */
		drbd_set_all_out_of_sync(device, peer_req->i.sector, peer_req->i.size);
		atomic_inc(&device->io_error_count);
		drbd_md_set_flag(device, MDF_IO_ERROR);
    }

	check_and_clear_io_error_in_secondary(peer_device);

	spin_lock_irqsave(&device->resource->req_lock, lock_flags);
	device->writ_cnt += peer_req->i.size >> 9;
	atomic_inc(&connection->done_ee_cnt);
	//DW-1928 
	size = peer_req->i.size;
	list_move_tail(&peer_req->w.list, &connection->done_ee);

	/*
	 * Do not remove from the write_requests tree here: we did not send the
	 * Ack yet and did not wake possibly waiting conflicting requests.
	 * Removed from the tree from "drbd_process_done_ee" within the
	 * appropriate callback (e_end_block/e_end_resync_block) or from
	 * _drbd_clear_done_ee.
	 */

	if (block_id == ID_SYNCER)
		do_wake = list_empty(&connection->sync_ee);
	else
		do_wake = list_empty(&connection->active_ee);

	/* FIXME do we want to detach for failed REQ_DISCARD?
	* ((peer_req->flags & (EE_WAS_ERROR|EE_IS_TRIM)) == EE_WAS_ERROR) */
	if (flags & EE_WAS_ERROR)
		__drbd_chk_io_error(device, DRBD_WRITE_ERROR);

	if (connection->cstate[NOW] == C_CONNECTED)
		queue_work(connection->ack_sender, &connection->send_acks_work);
	spin_unlock_irqrestore(&device->resource->req_lock, lock_flags);

	//DW-1601 calls drbd_rs_complete_io() after all data is complete.
	//DW-1886
	if (block_id == ID_SYNCER) {
		if (!(flags & EE_SPLIT_REQ))
			drbd_rs_complete_io(peer_device, sector, __FUNCTION__);
		//DW-1928
		atomic_add64(size, &peer_device->rs_written);
	}

	if (do_wake) 
		wake_up(&connection->ee_wait);

	//DW-1903 EE_SPLIT_REQ is a duplicate request and does not call put_ldev().
	if (!(flags & EE_SPLIT_REQ))
		put_ldev(device);
}

/* writes on behalf of the partner, or resync writes,
 * "submitted" by the receiver.
 */
#ifdef _WIN32
BIO_ENDIO_TYPE drbd_peer_request_endio(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
#else
BIO_ENDIO_TYPE drbd_peer_request_endio BIO_ENDIO_ARGS(struct bio *bio, int error)
#endif
{
#ifdef _WIN32
	struct bio *bio = NULL;
	int error = 0;
#ifdef DRBD_TRACE
	WDRBD_TRACE("BIO_ENDIO_FN_START:Thread(%s) drbd_peer_request_endio: IRQL(%d) ..............\n",  current->comm, KeGetCurrentIrql());
#endif
	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		error = Irp->IoStatus.Status;
		bio = (struct bio *)Context;
		//
		//	Simulation Local Disk I/O Error Point. disk error simluation type 2
		//
		if(gSimulDiskIoError.ErrorFlag && gSimulDiskIoError.ErrorType == SIMUL_DISK_IO_ERROR_TYPE2) {
			if(IsDiskError()) {
				WDRBD_ERROR("SimulDiskIoError: Peer Request I/O Error type2.....ErrorFlag:%d ErrorCount:%d\n", gSimulDiskIoError.ErrorFlag, gSimulDiskIoError.ErrorCount);
				error = STATUS_UNSUCCESSFUL;
			}
		}
// DW-1830
// Disable this code because io hang occurs during IRP reuse.
#ifdef RETRY_WRITE_IO
		// DW-1716 retry if an write I/O error occurs.
		if (NT_ERROR(error)) {
			if( (bio->bi_rw & WRITE) && bio->io_retry ) {
				RetryAsyncWriteRequest(bio, Irp, error, "drbd_peer_request_endio");
				return STATUS_MORE_PROCESSING_REQUIRED;
			}
		}
#endif
	} else {
		error = (int)Context;
		bio = (struct bio *)Irp;
	}
#endif
	if (!bio)
		BIO_ENDIO_FN_RETURN;

	/* DW-1822
	 * The generic_make_request calls IoAcquireRemoveLock before the IRP is created
 	 * and is freed from the completion routine functions.
	 * However, retry I/O operations are performed without RemoveLock,
	 * because the retry routine will work after the release.
	 * IoReleaseRemoveLock must be moved so that it is released after the retry.
	 */
	//DW-1831 check whether bio->bi_bdev and bio->bi_bdev->bd_disk are null.
	if (bio && bio->bi_bdev && bio->bi_bdev->bd_disk) {
		if (bio->bi_bdev->bd_disk->pDeviceExtension != NULL) {
			IoReleaseRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);
		}
	}

	struct drbd_peer_request *peer_req = bio->bi_private;
	struct drbd_device *device = peer_req->peer_device->device;
	bool is_write = bio_data_dir(bio) == WRITE;
	bool is_discard = bio_op(bio) == REQ_OP_DISCARD;

	BIO_ENDIO_FN_START;
#ifdef _WIN32 
	if (NT_ERROR(error) && drbd_ratelimit())
#else
	if (error && drbd_ratelimit())
#endif
		drbd_warn(device, "%s: error=0x%08X sec=%llus size:%d\n",
				is_write ? (is_discard ? "discard" : "write")
					: "read", error,
				(unsigned long long)peer_req->i.sector, peer_req->i.size);

#ifdef _WIN32
	if (NT_ERROR(error)) {
#else
	if (error) {
#endif
		set_bit(__EE_WAS_ERROR, &peer_req->flags);
		process_io_error(bio, device, VOLUME_TYPE_REPL, error);
	}

#ifdef _WIN32
	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		if (Irp->MdlAddress != NULL) {
			PMDL mdl, nextMdl;
			for (mdl = Irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
				nextMdl = mdl->Next;
				MmUnlockPages(mdl);
				IoFreeMdl(mdl); // This function will also unmap pages.
			}
			Irp->MdlAddress = NULL;

			// DW-1695 fix PFN_LIST_CORRUPT-9A bugcheck by releasing the peer_req_databuf when EE_WRITE peer_req is completed.
			// for case, peer_req_databuf may be released before the write completion. 
			// DW-1773 peer_request is managed as inactive_ee, so peer_req_databuf is modified to be released from drbd_free_peer_req()
			//if(peer_req->flags & EE_WRITE) {
			//	kfree2 (peer_req->peer_req_databuf);
			//}
		}
		IoFreeIrp(Irp);
	}

#endif

	bio_put(bio); /* no need for the bio anymore */

#ifdef _WIN32 // DW-1598 : Prevent the function below from referencing a connection that already freed.
	if (test_bit(CONNECTION_ALREADY_FREED, &peer_req->peer_device->flags)){
		BIO_ENDIO_FN_RETURN;
	}
#endif

	if (atomic_dec_and_test(&peer_req->pending_bios)) {
		if (is_write)
			drbd_endio_write_sec_final(peer_req);
		else
			drbd_endio_read_sec_final(peer_req);
	}
#ifdef DRBD_TRACE
	{
		static int cnt = 0;
		WDRBD_TRACE("drbd_peer_request_endio done.(%d).............!!!\n", cnt++);
	}
#endif
	BIO_ENDIO_FN_RETURN;
}

void drbd_panic_after_delayed_completion_of_aborted_request(struct drbd_device *device)
{
#ifdef _WIN32
	WDRBD_ERROR("drbd%u %s / %u", device->minor, device->resource->name, device->vnr);
	panic("potential random memory corruption caused by delayed completion of aborted local request\n");
#else
	panic("drbd%u %s/%u potential random memory corruption caused by delayed completion of aborted local request\n",
		device->minor, device->resource->name, device->vnr);
#endif
}


/* read, readA or write requests on R_PRIMARY coming from drbd_make_request
 */
#ifdef _WIN32
NTSTATUS drbd_request_endio(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
#else
BIO_ENDIO_TYPE drbd_request_endio BIO_ENDIO_ARGS(struct bio *bio, int error)
#endif
{
	unsigned long flags;
#ifdef _WIN32
	struct drbd_request *req = NULL;
	struct drbd_device *device = NULL;
	struct bio_and_error m;
	enum drbd_req_event what;
	int uptodate = 0; 
	struct bio *bio = NULL;
	int error = 0;
#ifdef DRBD_TRACE
	WDRBD_TRACE("BIO_ENDIO_FN_START:Thread(%s) drbd_request_endio: IRQL(%d) ................\n", current->comm, KeGetCurrentIrql());
#endif

	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		bio = (struct bio *)Context;
		error = Irp->IoStatus.Status;
		//
		//	Simulation Local Disk I/O Error Point. disk error simluation type 1
		//
		if(gSimulDiskIoError.ErrorFlag && gSimulDiskIoError.ErrorType == SIMUL_DISK_IO_ERROR_TYPE1) {
			if(IsDiskError()) {
				WDRBD_ERROR("SimulDiskIoError: Local I/O Error type1.....ErrorFlag:%d ErrorCount:%d\n",gSimulDiskIoError.ErrorFlag,gSimulDiskIoError.ErrorCount);
				error = STATUS_UNSUCCESSFUL;
			}
		}
// DW-1830
// Disable this code because io hang occurs during IRP reuse.
#ifdef RETRY_WRITE_IO		
		// DW-1716 retry if an write I/O error occurs.
		if (NT_ERROR(error)) {
			if( (bio->bi_rw & WRITE) && bio->io_retry ) {
				RetryAsyncWriteRequest(bio, Irp, error, "drbd_request_endio");
				return STATUS_MORE_PROCESSING_REQUIRED;
			}
		}
#endif	
	} else {
		error = (int)Context;
		bio = (struct bio *)Irp;
	}

	if (!bio)
		BIO_ENDIO_FN_RETURN;

	/* DW-1822
	 * The generic_make_request calls IoAcquireRemoveLock before the IRP is created
	 * and is freed from the completion routine functions.
	 * However, retry I/O operations are performed without RemoveLock,
	 * because the retry routine will work after the release.
	 * IoReleaseRemoveLock must be moved so that it is released after the retry.
	 */
	//DW-1831 check whether bio->bi_bdev and bio->bi_bdev->bd_disk are null.
	if (bio && bio->bi_bdev && bio->bi_bdev->bd_disk) {
		if (bio->bi_bdev->bd_disk->pDeviceExtension != NULL) {
			IoReleaseRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);
		}
	}

	req = bio->bi_private; 
	device = req->device;
	uptodate = bio_flagged(bio, BIO_UPTODATE);
#else
	struct drbd_request *req = bio->bi_private;
	struct drbd_device *device = req->device;
	struct bio_and_error m;
	enum drbd_req_event what;
#endif

	BIO_ENDIO_FN_START;

	/* If this request was aborted locally before,
	 * but now was completed "successfully",
	 * chances are that this caused arbitrary data corruption.
	 *
	 * "aborting" requests, or force-detaching the disk, is intended for
	 * completely blocked/hung local backing devices which do no longer
	 * complete requests at all, not even do error completions.  In this
	 * situation, usually a hard-reset and failover is the only way out.
	 *
	 * By "aborting", basically faking a local error-completion,
	 * we allow for a more graceful swichover by cleanly migrating services.
	 * Still the affected node has to be rebooted "soon".
	 *
	 * By completing these requests, we allow the upper layers to re-use
	 * the associated data pages.
	 *
	 * If later the local backing device "recovers", and now DMAs some data
	 * from disk into the original request pages, in the best case it will
	 * just put random data into unused pages; but typically it will corrupt
	 * meanwhile completely unrelated data, causing all sorts of damage.
	 *
	 * Which means delayed successful completion,
	 * especially for READ requests,
	 * is a reason to panic().
	 *
	 * We assume that a delayed *error* completion is OK,
	 * though we still will complain noisily about it.
	 */
	if (unlikely(req->rq_state[0] & RQ_LOCAL_ABORTED)) {
		if (drbd_ratelimit())
			drbd_emerg(device, "delayed completion of aborted local request; disk-timeout may be too aggressive\n");

		if (!error)
			drbd_panic_after_delayed_completion_of_aborted_request(device);
	}

	/* to avoid recursion in __req_mod */
#ifdef _WIN32 // DW-1706 By NT_ERROR(), reduce the error sensitivity to I/O.
	if (NT_ERROR(error)) {
#else
	if (unlikely(error)) {
#endif
		switch (bio_op(bio)) {
		case REQ_OP_DISCARD:
			if (error == -EOPNOTSUPP)
				what = DISCARD_COMPLETED_NOTSUPP;
			else
				what = DISCARD_COMPLETED_WITH_ERROR;
			break;
		case REQ_OP_READ:
			if (bio->bi_opf & REQ_RAHEAD)
				what = READ_AHEAD_COMPLETED_WITH_ERROR;
			else
				what = READ_COMPLETED_WITH_ERROR;
			break;
		default:
			what = WRITE_COMPLETED_WITH_ERROR;
			break;
		}

		process_io_error(bio, device, VOLUME_TYPE_REPL, error);
	}
	else {
		what = COMPLETED_OK;
	}

#ifdef _WIN32
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

	bio_put(req->private_bio);
	req->private_bio = ERR_PTR(error);

	/* not req_mod(), we need irqsave here! */
	spin_lock_irqsave(&device->resource->req_lock, flags);
#ifdef DRBD_TRACE	
	WDRBD_TRACE("(%s) drbd_request_endio: before __req_mod! IRQL(%d) \n", current->comm, KeGetCurrentIrql());
#endif
	__req_mod(req, what, NULL, &m);
	spin_unlock_irqrestore(&device->resource->req_lock, flags);
	put_ldev(device);

	if (m.bio)
#ifdef _WIN32
		complete_master_bio(device, &m, __FUNCTION__, __LINE__);
#else
		complete_master_bio(device, &m);
#endif

#ifdef DRBD_TRACE	
	{
		static int cnt = 0;
		WDRBD_TRACE("drbd_request_endio done.(%d).................IRQL(%d)!!!\n", cnt++, KeGetCurrentIrql());
	}
#endif
	BIO_ENDIO_FN_RETURN;
}

#ifdef _WIN32
void drbd_csum_pages(struct crypto_hash *tfm, struct drbd_peer_request *peer_req, void *digest)
#else
void drbd_csum_pages(struct crypto_hash *tfm, struct page *page, void *digest)
#endif
{
	UNREFERENCED_PARAMETER(tfm);

#ifdef _WIN32
	*(uint32_t *)digest = crc32c(0, peer_req->peer_req_databuf, peer_req->i.size);
#else
	struct hash_desc desc;
	struct scatterlist sg;

	desc.tfm = tfm;
	desc.flags = 0;

	sg_init_table(&sg, 1);
	crypto_hash_init(&desc);

	page_chain_for_each(page) {
		unsigned off = page_chain_offset(page);
		unsigned len = page_chain_size(page);
		sg_set_page(&sg, page, len, off);
		crypto_hash_update(&desc, &sg, sg.length);
	}
	crypto_hash_final(&desc, digest);
#endif
}

#ifdef _WIN32
void drbd_csum_bio(struct crypto_hash *tfm, struct drbd_request *req, void *digest)
#else
void drbd_csum_bio(struct crypto_hash *tfm, struct bio *bio, void *digest)
#endif
{
	UNREFERENCED_PARAMETER(tfm);
#ifdef _WIN32
	struct hash_desc desc;
#else
	DRBD_BIO_VEC_TYPE bvec;
	DRBD_ITER_TYPE iter;
	struct hash_desc desc;
	struct scatterlist sg;
#endif

#ifdef _WIN32 
	if (req->req_databuf)
		crypto_hash_update(&desc, (struct scatterlist *)req->req_databuf, req->i.size);
	crypto_hash_final(&desc, digest);
#else
	desc.tfm = tfm;
	desc.flags = 0;

	sg_init_table(&sg, 1);
	crypto_hash_init(&desc);

	bio_for_each_segment(bvec, bio, iter) {
		sg_set_page(&sg, bvec BVD bv_page, bvec BVD bv_len, bvec BVD bv_offset);
		crypto_hash_update(&desc, &sg, sg.length);
		/* WRITE_SAME has only one segment,
		 * checksum the payload only once. */
		if (bio_op(bio) == REQ_OP_WRITE_SAME)
			break;
	}
	crypto_hash_final(&desc, digest);
#endif
}

/* MAYBE merge common code with w_e_end_ov_req */
static int w_e_send_csum(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	int digest_size;
	void *digest;
	int err = 0;

	if (unlikely(cancel))
		goto out;

	if (unlikely((peer_req->flags & EE_WAS_ERROR) != 0)) {
		// DW-1942 fix bug that checksum synchronization stops when SyncTarget io-error occurs continuously.
		// Send the packet with block_id set to ID_CSUM_SYNC_IO_ERROR.
		atomic_add(peer_req->i.size >> 9, &peer_device->rs_sect_in);
		drbd_rs_failed_io(peer_device, peer_req->i.sector, peer_req->i.size);
		drbd_rs_complete_io(peer_device, peer_req->i.sector, __FUNCTION__);
		peer_req->block_id = ID_CSUM_SYNC_IO_ERROR;
		if (peer_device->connection->agreed_pro_version < 113)
			goto out;
	}

	digest_size = crypto_hash_digestsize(peer_device->connection->csums_tfm);
	digest = drbd_prepare_drequest_csum(peer_req, digest_size);
	if (digest) {
#ifdef _WIN32
        drbd_csum_pages(peer_device->connection->csums_tfm, peer_req, digest);
#else
		drbd_csum_pages(peer_device->connection->csums_tfm, peer_req->page_chain.head, digest);
#endif
		// DW-1942 Do not receive ack if send io fail notification packet.
		if (likely((peer_req->flags & EE_WAS_ERROR) == 0))
			inc_rs_pending(peer_device);
		/* Free peer_req and pages before send.
		 * In case we block on congestion, we could otherwise run into
		 * some distributed deadlock, if the other side blocks on
		 * congestion as well, because our receiver blocks in
		 * drbd_alloc_pages due to pp_in_use > max_buffers. */
		drbd_free_peer_req(peer_req);
		peer_req = NULL;
		err = drbd_send_command(peer_device, P_CSUM_RS_REQUEST, DATA_STREAM);
	} else {
		drbd_err(peer_device, "kmalloc() of digest failed.\n");
		err = -ENOMEM;
	}

out:
	if (peer_req)
		drbd_free_peer_req(peer_req);

	if (unlikely(err))
		drbd_err(peer_device, "drbd_send_drequest(..., csum) failed\n");
	return err;
}

static int read_for_csum(struct drbd_peer_device *peer_device, sector_t sector, int size)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_request *peer_req;

	if (!get_ldev(device))
		return -EIO;

	/* Do not wait if no memory is immediately available.  */
	peer_req = drbd_alloc_peer_req(peer_device, GFP_TRY & ~__GFP_RECLAIM);
	if (!peer_req) {
		drbd_err(peer_device, "failed to allocate peer request\n");
		goto defer;
	}
#ifdef _WIN32
    if (size) {
        drbd_alloc_page_chain(&peer_device->connection->transport,
            &peer_req->page_chain, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
		if (!peer_req->page_chain.head) {
			drbd_err(peer_device, "failed to allocate page chain\n");
			goto defer2;
		}
        peer_req->peer_req_databuf = peer_req->page_chain.head;
    } else  {
        peer_req->peer_req_databuf = NULL;
    }
#else
	if (size) {
		drbd_alloc_page_chain(&peer_device->connection->transport,
			&peer_req->page_chain, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
		if (!peer_req->page_chain.head)
			goto defer2;
	}
#endif
	peer_req->i.size = size;
	peer_req->i.sector = sector;
	peer_req->block_id = ID_SYNCER; /* unused */

	peer_req->w.cb = w_e_send_csum;
	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&peer_req->w.list, &peer_device->connection->read_ee);
	spin_unlock_irq(&device->resource->req_lock);

	atomic_add(size >> 9, &device->rs_sect_ev);
	if (drbd_submit_peer_request(device, peer_req, REQ_OP_READ, 0,
		DRBD_FAULT_RS_RD) == 0)
		return 0;

	drbd_err(peer_device, "failed to submit peer request\n");
	/* If it failed because of ENOMEM, retry should help.  If it failed
	 * because bio_add_page failed (probably broken lower level driver),
	 * retry may or may not help.
	 * If it does not, you may need to force disconnect. */
	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	spin_unlock_irq(&device->resource->req_lock);

defer2:
	drbd_free_peer_req(peer_req);
defer:
	put_ldev(device);
	return -EAGAIN;
}

int w_resync_timer(struct drbd_work *w, int cancel)
{
	struct drbd_peer_device *peer_device =
		container_of(w, struct drbd_peer_device, resync_work);
	struct drbd_device *device = peer_device->device;

	mutex_lock(&device->bm_resync_fo_mutex);

	switch (peer_device->repl_state[NOW]) {
	case L_VERIFY_S:
		make_ov_request(peer_device, cancel);
		break;
	case L_SYNC_TARGET:
#ifdef _WIN32
		// DW-1317: try to get volume control mutex, reset timer if failed.
		if (mutex_trylock(&device->resource->vol_ctl_mutex))
		{
			mutex_unlock(&device->resource->vol_ctl_mutex);
			make_resync_request(peer_device, cancel);
		}
		else		
			mod_timer(&peer_device->resync_timer, jiffies);
		
#else
		make_resync_request(peer_device, cancel);
#endif		
		break;
	default:
		break;
	}

	mutex_unlock(&device->bm_resync_fo_mutex);

	return 0;
}

int w_send_uuids(struct drbd_work *w, int cancel)
{
	UNREFERENCED_PARAMETER(cancel);

	struct drbd_peer_device *peer_device =
		container_of(w, struct drbd_peer_device, propagate_uuids_work);

	if (peer_device->repl_state[NOW] < L_ESTABLISHED ||
	    !test_bit(INITIAL_STATE_SENT, &peer_device->flags))
		return 0;

	drbd_send_uuids(peer_device, 0, 0);

	return 0;
}

#ifdef _WIN32
void resync_timer_fn(PKDPC Dpc, PVOID data, PVOID SystemArgument1, PVOID SystemArgument2)
#else
void resync_timer_fn(unsigned long data)
#endif
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(Dpc);

	if (data == NULL)
		return;

	struct drbd_peer_device *peer_device = (struct drbd_peer_device *) data;

	drbd_queue_work_if_unqueued(
		&peer_device->connection->sender_work,
		&peer_device->resync_work);
}

static void fifo_set(struct fifo_buffer *fb, int value)
{
	unsigned int i;

	for (i = 0; i < fb->size; i++)
		fb->values[i] = value;
}

static int fifo_push(struct fifo_buffer *fb, int value)
{
	int ov;

	ov = fb->values[fb->head_index];
	fb->values[fb->head_index++] = value;

	if (fb->head_index >= fb->size)
		fb->head_index = 0;

	return ov;
}

static void fifo_add_val(struct fifo_buffer *fb, int value)
{
	unsigned int i;

	for (i = 0; i < fb->size; i++)
		fb->values[i] += value;
}
#ifdef _WIN32
struct fifo_buffer *fifo_alloc(int fifo_size, ULONG Tag)
#else
struct fifo_buffer *fifo_alloc(int fifo_size)
#endif
{
	struct fifo_buffer *fb;
#ifdef _WIN32
    fb = kzalloc(sizeof(struct fifo_buffer) + sizeof(int) * fifo_size, GFP_NOIO, Tag);
#else
	fb = kzalloc(sizeof(struct fifo_buffer) + sizeof(int) * fifo_size, GFP_NOIO);
#endif
	if (!fb)
		return NULL;

	fb->head_index = 0;
	fb->size = fifo_size;
	fb->total = 0;

	return fb;
}

static int drbd_rs_controller(struct drbd_peer_device *peer_device, unsigned int sect_in)
{
	struct peer_device_conf *pdc;
	unsigned int want;     /* The number of sectors we want in-flight */
	int req_sect; /* Number of sectors to request in this turn */
	int correction; /* Number of sectors more we need in-flight */
	int cps; /* correction per invocation of drbd_rs_controller() */
	int steps; /* Number of time steps to plan ahead */
	int curr_corr;
	int max_sect;
	struct fifo_buffer *plan;
#ifdef _WIN32
	// required to analyze next two lines that removed in V9
	//sect_in = atomic_xchg(&mdev->rs_sect_in, 0); /* Number of sectors that came in */
	//mdev->rs_in_flight -= sect_in;
#endif
	pdc = rcu_dereference(peer_device->conf);
	plan = rcu_dereference(peer_device->rs_plan_s);

	steps = plan->size; /* (pdc->c_plan_ahead * 10 * SLEEP_TIME) / HZ; */

	if (peer_device->rs_in_flight + sect_in == 0) { /* At start of resync */
		want = ((pdc->resync_rate * 2 * SLEEP_TIME) / HZ) * steps;
	} else { /* normal path */
		want = pdc->c_fill_target ? pdc->c_fill_target :
			sect_in * pdc->c_delay_target * HZ / (SLEEP_TIME * 10);
	}

	correction = want - peer_device->rs_in_flight - plan->total;

	/* Plan ahead */
	cps = correction / steps;
	fifo_add_val(plan, cps);
	plan->total += cps * steps;

	/* What we do in this step */
	curr_corr = fifo_push(plan, 0);
#ifdef _WIN32
	curr_corr = max_t(int, curr_corr, 8);	// minimum 8
#endif
	plan->total -= curr_corr;
	req_sect = sect_in + curr_corr;
	if (req_sect < 0)
		req_sect = 0;

	max_sect = (pdc->c_max_rate * 2 * SLEEP_TIME) / HZ;
	if (req_sect > max_sect)
		req_sect = max_sect;
#ifdef _WIN32
    WDRBD_TRACE_TR("sect_in=%5u, %5d, corr(%d) cps(%d) curr_c(%d) rs(%d)\n",
         sect_in, peer_device->rs_in_flight, correction, cps, curr_corr, req_sect);
#endif
	/*
	drbd_warn(device, "si=%u if=%d wa=%u co=%d st=%d cps=%d pl=%d cc=%d rs=%d\n",
		 sect_in, peer_device->rs_in_flight, want, correction,
		 steps, cps, peer_device->rs_planed, curr_corr, req_sect);
	*/

	return req_sect;
}

static int drbd_rs_number_requests(struct drbd_peer_device *peer_device)
{
	struct net_conf *nc;
	unsigned int sect_in;  /* Number of sectors that came in since the last turn */
	int number, mxb;

	sect_in = atomic_xchg(&peer_device->rs_sect_in, 0);
	peer_device->rs_in_flight -= sect_in;

	rcu_read_lock();
	nc = rcu_dereference(peer_device->connection->transport.net_conf);
	mxb = nc ? nc->max_buffers : 0;
	if (rcu_dereference(peer_device->rs_plan_s)->size) {
		number = drbd_rs_controller(peer_device, sect_in) >> (BM_BLOCK_SHIFT - 9);
		peer_device->c_sync_rate = number * HZ * (BM_BLOCK_SIZE / 1024) / SLEEP_TIME;
	} else {
		peer_device->c_sync_rate = rcu_dereference(peer_device->conf)->resync_rate;
		number = SLEEP_TIME * peer_device->c_sync_rate  / ((BM_BLOCK_SIZE / 1024) * HZ);
	}
	rcu_read_unlock();

	/* Don't have more than "max-buffers"/2 in-flight.
	 * Otherwise we may cause the remote site to stall on drbd_alloc_pages(),
	 * potentially causing a distributed deadlock on congestion during
	 * online-verify or (checksum-based) resync, if max-buffers,
	 * socket buffer sizes and resync rate settings are mis-configured. */
	/* note that "number" is in units of "BM_BLOCK_SIZE" (which is 4k),
	 * mxb (as used here, and in drbd_alloc_pages on the peer) is
	 * "number of pages" (typically also 4k),
	 * but "rs_in_flight" is in "sectors" (512 Byte). */
	if (mxb - peer_device->rs_in_flight/8 < number)
		number = mxb - peer_device->rs_in_flight/8;

	return number;
}

static int make_resync_request(struct drbd_peer_device *peer_device, int cancel)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_transport *transport = &peer_device->connection->transport;
#ifdef _WIN32
	ULONG_PTR bit;
#else
	unsigned long bit;
#endif
	sector_t sector;
	const sector_t capacity = drbd_get_capacity(device->this_bdev);
	unsigned int max_bio_size, size;
	int number, rollback_i;
	int align, requeue = 0;
	int i = 0;
	int discard_granularity = 0;
#ifdef _WIN32
	WDRBD_TRACE_TM("timer callback jiffies(%llu)\n", jiffies);
#endif

	if (unlikely(cancel)) {
		drbd_info(peer_device, "resync cacnel.\n");
		return 0;
	}

	if (peer_device->rs_total == 0) {
		/* empty resync? */
		drbd_info(peer_device, "finished because it's rs_total empty\n");
		drbd_resync_finished(peer_device, D_MASK);
		return 0;
	}

	if (!get_ldev(device)) {
		/* Since we only need to access device->rsync a
		   get_ldev_if_state(device,D_FAILED) would be sufficient, but
		   to continue resync with a broken disk makes no sense at
		   all */
		drbd_err(device, "Disk broke down during resync!\n");
		return 0;
	}

	if (peer_device->connection->agreed_features & DRBD_FF_THIN_RESYNC) {
		rcu_read_lock();
		discard_granularity = rcu_dereference(device->ldev->disk_conf)->rs_discard_granularity;
		rcu_read_unlock();
	}

	max_bio_size = (unsigned int)(min((queue_max_hw_sectors(device->rq_queue) << 9), DRBD_MAX_BIO_SIZE));
	number = drbd_rs_number_requests(peer_device);
#ifdef _WIN32
    WDRBD_TRACE_TR("number(%d)\n", number);
#endif
	if (number <= 0)
		goto requeue;

	for (i = 0; i < number; i++) {
		/* Stop generating RS requests, when half of the send buffer is filled */
		mutex_lock(&peer_device->connection->mutex[DATA_STREAM]);
		if (transport->ops->stream_ok(transport, DATA_STREAM)) {
			struct drbd_transport_stats transport_stats;
#ifdef _WIN32
			signed long long queued, sndbuf;
#else
			int queued, sndbuf;
#endif
			transport->ops->stats(transport, &transport_stats);
			queued = transport_stats.send_buffer_used;
			sndbuf = transport_stats.send_buffer_size;
#ifdef _WIN32
			WDRBD_TRACE_TR("make_resync_request: %d/%d: queued=%lld sndbuf=%lld\n", i, number, queued, sndbuf);
#endif
			if (queued > sndbuf / 2) {
				requeue = 1;
				transport->ops->hint(transport, DATA_STREAM, NOSPACE);
			}
		} else
			requeue = 1;
		mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);
		if (requeue)
			goto requeue;

next_sector:
		size = BM_BLOCK_SIZE;
		bit  = drbd_bm_find_next(peer_device, device->bm_resync_fo);

		if (bit == DRBD_END_OF_BITMAP) {
			device->bm_resync_fo = drbd_bm_bits(device);
			drbd_info(peer_device, "DRBD_END_OF_BITMAP, device->bm_resync_fo : %lu, bm_set : %lu\n", device->bm_resync_fo, drbd_bm_total_weight(peer_device));
			put_ldev(device);
			return 0;
		}

		sector = BM_BIT_TO_SECT(bit);

		if (drbd_try_rs_begin_io(peer_device, sector, true)) {
			device->bm_resync_fo = bit;
			goto requeue;
		}
		device->bm_resync_fo = bit + 1;

		if (unlikely(drbd_bm_test_bit(peer_device, bit) == 0)) {
			drbd_rs_complete_io(peer_device, sector, __FUNCTION__);
			goto next_sector;
		}

#if DRBD_MAX_BIO_SIZE > BM_BLOCK_SIZE
		/* try to find some adjacent bits.
		 * we stop if we have already the maximum req size.
		 *
		 * Additionally always align bigger requests, in order to
		 * be prepared for all stripe sizes of software RAIDs.
		 */
		align = 1;
		rollback_i = i;
		while (i < number) {
			if (size + BM_BLOCK_SIZE > max_bio_size)
				break;

			/* Be always aligned */
			if (sector & ((1<<(align+3))-1))
				break;

			if (discard_granularity && size == (unsigned int)discard_granularity)
				break;

			/* do not cross extent boundaries */
			if (((bit+1) & BM_BLOCKS_PER_BM_EXT_MASK) == 0)
				break;
			/* now, is it actually dirty, after all?
			 * caution, drbd_bm_test_bit is tri-state for some
			 * obscure reason; ( b == 0 ) would get the out-of-band
			 * only accidentally right because of the "oddly sized"
			 * adjustment below */
			if (drbd_bm_test_bit(peer_device, bit + 1) != 1)
				break;
			bit++;
			size += BM_BLOCK_SIZE;
			if ((unsigned int)(BM_BLOCK_SIZE << align) <= size)
				align++;
			i++;
		}
		/* if we merged some,
		 * reset the offset to start the next drbd_bm_find_next from */
		if (size > BM_BLOCK_SIZE)
			device->bm_resync_fo = bit + 1;
#endif

		/* adjust very last sectors, in case we are oddly sized */
		if (sector + (size>>9) > capacity)
			size = (unsigned int)(capacity-sector)<<9;

		if (peer_device->use_csums) {
			switch (read_for_csum(peer_device, sector, size)) {
			case -EIO: /* Disk failure */
				put_ldev(device);
				return -EIO;
			case -EAGAIN: /* allocation failed, or ldev busy */
				drbd_rs_complete_io(peer_device, sector, __FUNCTION__);
				device->bm_resync_fo = (ULONG_PTR)BM_SECT_TO_BIT(sector);
				i = rollback_i;
				goto requeue;
			case 0:
				/* everything ok */
				break;
			default:
				BUG();
			}
		} else {
			int err;

			inc_rs_pending(peer_device);
			err = drbd_send_drequest(peer_device,
						(size == (unsigned int)discard_granularity) ? P_RS_THIN_REQ : P_RS_DATA_REQUEST,
						 sector, size, ID_SYNCER);
			if (err) {
				drbd_err(peer_device, "drbd_send_drequest() failed, aborting...\n");
				dec_rs_pending(peer_device);
				put_ldev(device);
				return err;
			}
			//DW-1886
			peer_device->rs_send_req += size;
		}
	}

	if (device->bm_resync_fo >= drbd_bm_bits(device)) {
		/* last syncer _request_ was sent,
		 * but the P_RS_DATA_REPLY not yet received.  sync will end (and
		 * next sync group will resume), as soon as we receive the last
		 * resync data block, and the last bit is cleared.
		 * until then resync "work" is "inactive" ...
		 */
		drbd_info(peer_device, "P_RS_DATA_REPLY not received??,  device->bm_resync_fo : %lu, bm_set : %lu\n", device->bm_resync_fo, drbd_bm_total_weight(peer_device));
		put_ldev(device);
		return 0;
	}

 requeue:
	peer_device->rs_in_flight += (i << (BM_BLOCK_SHIFT - 9));
	mod_timer(&peer_device->resync_timer, jiffies + SLEEP_TIME);
	put_ldev(device);
	return 0;
}

static int make_ov_request(struct drbd_peer_device *peer_device, int cancel)
{
	struct drbd_device *device = peer_device->device;
	int number, i, size;
	sector_t sector;
	const sector_t capacity = drbd_get_capacity(device->this_bdev);
	bool stop_sector_reached = false;

	if (unlikely(cancel))
		return 1;

	number = drbd_rs_number_requests(peer_device);

	sector = peer_device->ov_position;
	for (i = 0; i < number; i++) {
		if (sector >= capacity)
			return 1;

		/* We check for "finished" only in the reply path:
		 * w_e_end_ov_reply().
		 * We need to send at least one request out. */
		stop_sector_reached = i > 0
			&& verify_can_do_stop_sector(peer_device)
			&& sector >= peer_device->ov_stop_sector;
		if (stop_sector_reached)
			break;

#if 0 	
		// V8 style code. performace: decrease P_OV_REQUEST count, increase network thoughput per 1 time
		size = 1024*1024; 
		//size =  1024*256;  // for flowcontrol
#endif
		size = BM_BLOCK_SIZE;

		if (drbd_try_rs_begin_io(peer_device, sector, true)) {
			peer_device->ov_position = sector;
			goto requeue;
		}

		if (sector + (size >> 9) > capacity) {
			BUG_ON(UINT_MAX < (capacity - sector) << 9);
			size = (unsigned int)(capacity - sector) << 9;
		}

		inc_rs_pending(peer_device);
		if (drbd_send_ov_request(peer_device, sector, size)) {
			dec_rs_pending(peer_device);
			return 0;
		}
		sector += BM_SECT_PER_BIT;
	}
	peer_device->ov_position = sector;

 requeue:
	peer_device->rs_in_flight += (i << (BM_BLOCK_SHIFT - 9));
	if (i == 0 || !stop_sector_reached)
		mod_timer(&peer_device->resync_timer, jiffies + SLEEP_TIME);
	return 1;
}

int w_ov_finished(struct drbd_work *w, int cancel)
{
	UNREFERENCED_PARAMETER(cancel);

	struct drbd_peer_device_work *dw =
		container_of(w, struct drbd_peer_device_work, w);
	struct drbd_peer_device *peer_device = dw->peer_device;
	kfree(dw);
	ov_out_of_sync_print(peer_device);
	drbd_resync_finished(peer_device, D_MASK);

	return 0;
}

struct resync_finished_work {
	struct drbd_peer_device_work pdw;
	enum drbd_disk_state new_peer_disk_state;
};

static int w_resync_finished(struct drbd_work *w, int cancel)
{
	UNREFERENCED_PARAMETER(cancel);

	struct resync_finished_work *rfw = container_of(
		container_of(w, struct drbd_peer_device_work, w),
		struct resync_finished_work, pdw);

	drbd_resync_finished(rfw->pdw.peer_device, rfw->new_peer_disk_state);
	kfree(rfw);

	return 0;
}

void drbd_ping_peer(struct drbd_connection *connection)
{
	clear_bit(GOT_PING_ACK, &connection->flags);
	request_ping(connection);
	wait_event(connection->ping_wait,
		   test_bit(GOT_PING_ACK, &connection->flags) ||
		   connection->cstate[NOW] < C_CONNECTED);
}

/* caller needs to hold rcu_read_lock, req_lock, adm_mutex or conf_update */
struct drbd_peer_device *peer_device_by_node_id(struct drbd_device *device, int node_id)
{
	struct drbd_peer_device *peer_device;

	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->node_id == node_id)
			return peer_device;
	}

	return NULL;
}

static void __outdate_peer_disk_by_mask(struct drbd_device *device, u64 nodes)
{
	struct drbd_peer_device *peer_device;
	int node_id;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if (!(nodes & NODE_MASK(node_id)))
			continue;
		peer_device = peer_device_by_node_id(device, node_id);
		if (peer_device && peer_device->disk_state[NEW] >= D_CONSISTENT)
			__change_peer_disk_state(peer_device, D_OUTDATED, __FUNCTION__);
	}
}

/* An annoying corner case is if we are resync target towards a bunch
   of nodes. One of the resyncs finished as STABLE_RESYNC, the others
   as UNSTABLE_RESYNC. */
static bool was_resync_stable(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;

	if (test_bit(UNSTABLE_RESYNC, &peer_device->flags) &&
	    !test_bit(STABLE_RESYNC, &device->flags))
		return false;

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1113: clear UNSTABLE_RESYNC flag for all peers that I'm getting synced with and have set primary as authoritative node since I have consistent disk with primary.
	if (peer_device->connection->peer_role[NOW] == R_PRIMARY)
	{
		struct drbd_peer_device *found_peer = NULL;
		for_each_peer_device_rcu(found_peer, device)
		{
			enum drbd_repl_state repl_state = found_peer->repl_state[NOW];
			u64 authoritative_nodes = found_peer->uuid_authoritative_nodes;

			if (found_peer == peer_device)
				continue;

			if (test_bit(UNSTABLE_RESYNC, &found_peer->flags) &&
				(repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) &&
				authoritative_nodes & NODE_MASK(peer_device->node_id))
				clear_bit(UNSTABLE_RESYNC, &found_peer->flags);
		}
	}
#endif

	set_bit(STABLE_RESYNC, &device->flags);
	/* that STABLE_RESYNC bit gets reset if in any other ongoing resync
	   we receive something from a resync source that is marked with
	   UNSTABLE RESYNC. */

	return true;
}

#ifdef _WIN32
// MODIFIED_BY_MANTECH DW-955: need to upgrade disk state after unstable resync.
static void sanitize_state_after_unstable_resync(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_device *found_peer = NULL;
	
	// unstable resync's done, does mean primary node exists. try to find it.
	for_each_peer_device_rcu(found_peer, device)
	{
		// my disk is consistent with primary's, adopt it's disk state.
		if (found_peer->connection->peer_role[NOW] == R_PRIMARY &&
			drbd_bm_total_weight(found_peer) == 0)
		{
			__change_disk_state(device, found_peer->disk_state[NOW], __FUNCTION__);
			return;
		}
	}

	// I have no connection with primary, but disk is consistent with unstable node. I may be outdated.
	if (drbd_bm_total_weight(peer_device) == 0 &&
		device->disk_state[NOW] < D_OUTDATED &&
		peer_device->disk_state[NOW] >= D_OUTDATED)
		__change_disk_state(device, D_OUTDATED, __FUNCTION__);
}
#endif

static void __cancel_other_resyncs(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;

	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NEW] == L_PAUSED_SYNC_T)
#ifdef _WIN32
		{
			// MODIFIED_BY_MANTECH DW-955: canceling other resync may causes out-oof-sync remained, clear the bitmap since no need.
			struct drbd_peer_md *peer_md = device->ldev->md.peers;
			int peer_node_id = 0;
			u64 peer_bm_uuid = 0;

			spin_lock_irq(&device->ldev->md.uuid_lock);
			peer_node_id = peer_device->node_id;
			peer_bm_uuid = peer_md[peer_node_id].bitmap_uuid;

			if (peer_bm_uuid)
				_drbd_uuid_push_history(device, peer_bm_uuid);
			if (peer_md[peer_node_id].bitmap_index != -1 && !drbd_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR))
			{
				drbd_info(peer_device, "bitmap will be cleared due to resync cancelation\n");
				forget_bitmap(device, peer_node_id);
			}
			drbd_md_mark_dirty(device);
			spin_unlock_irq(&device->ldev->md.uuid_lock);

			__change_repl_state_and_auto_cstate(peer_device, L_ESTABLISHED, __FUNCTION__);
		}
#else
			__change_repl_state_and_auto_cstate(peer_device, L_ESTABLISHED);
#endif
	}
}

static void init_resync_stable_bits(struct drbd_peer_device *first_target_pd)
{
	struct drbd_device *device = first_target_pd->device;
	struct drbd_peer_device *peer_device;

	clear_bit(UNSTABLE_RESYNC, &first_target_pd->flags);

	/* Clear the device wide STABLE_RESYNC flag when becoming
	   resync target on the first peer_device. */
	for_each_peer_device(peer_device, device) {
		enum drbd_repl_state repl_state = peer_device->repl_state[NOW];
		if (peer_device == first_target_pd)
			continue;
		if (repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T)
			return;
	}
	clear_bit(STABLE_RESYNC, &device->flags);
}

int drbd_resync_finished(struct drbd_peer_device *peer_device,
			 enum drbd_disk_state new_peer_disk_state)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	enum drbd_repl_state *repl_state = peer_device->repl_state;
	enum drbd_repl_state old_repl_state = L_ESTABLISHED;
#ifdef _WIN32
	ULONG_PTR db, dt, dbdt;
	ULONG_PTR n_oos;
#else
	unsigned long db, dt, dbdt;
	unsigned long n_oos;
#endif
	char *khelper_cmd = NULL;
	int verify_done = 0;


	if (repl_state[NOW] == L_SYNC_SOURCE || repl_state[NOW] == L_PAUSED_SYNC_S) {
		/* Make sure all queued w_update_peers()/consider_sending_peers_in_sync()
		   executed before killing the resync_lru with drbd_rs_del_all() */
		if (current == device->resource->worker.task)
			goto queue_on_sender_workq;
		else
#ifdef _WIN32
			drbd_flush_workqueue(device->resource, &device->resource->work);
#else
			drbd_flush_workqueue(&device->resource->work);
#endif
			
	}

	/* Remove all elements from the resync LRU. Since future actions
	 * might set bits in the (main) bitmap, then the entries in the
	 * resync LRU would be wrong. */
	if (drbd_rs_del_all(peer_device)) {
		struct resync_finished_work *rfw;

		/* In case this is not possible now, most probably because
		 * there are P_RS_DATA_REPLY Packets lingering on the sender's
		 * queue (or even the read operations for those packets
		 * is not finished by now).   Retry in 100ms. */

		drbd_kick_lo(device);
		schedule_timeout_interruptible(HZ / 10);
	queue_on_sender_workq:
#ifdef _WIN32
        rfw = kmalloc(sizeof(*rfw), GFP_ATOMIC, '13DW');
#else
		rfw = kmalloc(sizeof(*rfw), GFP_ATOMIC);
#endif
		if (rfw) {
			rfw->pdw.w.cb = w_resync_finished;
			rfw->pdw.peer_device = peer_device;
			rfw->new_peer_disk_state = new_peer_disk_state;
			drbd_queue_work(&connection->sender_work, &rfw->pdw.w);
			return 1;
		}
		drbd_err(peer_device, "Warn failed to kmalloc(dw).\n");
	}

	dt = (jiffies - peer_device->rs_start - peer_device->rs_paused) / HZ;
	if (dt <= 0)
		dt = 1;
	db = peer_device->rs_total;
	/* adjust for verify start and stop sectors, respective reached position */
	if (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T)
		db -= peer_device->ov_left;

	dbdt = Bit2KB(db/dt);
	peer_device->rs_paused /= HZ;

	if (!get_ldev(device))
		goto out;

	drbd_ping_peer(connection);

	spin_lock_irq(&device->resource->req_lock);

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1198 : If repl_state is L_AHEAD, do not finish resync. Keep the L_AHEAD.
	if (repl_state[NOW] == L_AHEAD)
	{
		drbd_info(peer_device, "I am ahead, do not finish resync.\n"); // DW-1518
		put_ldev(device);
		spin_unlock_irq(&device->resource->req_lock);	
		return 1;
	}
#endif
	
	begin_state_change_locked(device->resource, CS_VERBOSE);
	old_repl_state = repl_state[NOW];

	verify_done = (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T);

	/* This protects us against multiple calls (that can happen in the presence
	   of application IO), and against connectivity loss just before we arrive here. */
	if (peer_device->repl_state[NOW] <= L_ESTABLISHED)
		goto out_unlock;
	__change_repl_state_and_auto_cstate(peer_device, L_ESTABLISHED, __FUNCTION__);

#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
	drbd_info(peer_device, "%s done (total %lu sec; paused %lu sec; %lu K/sec), hit bit (in sync %llu; marked rl %llu)\n",
	     verify_done ? "Online verify" : "Resync",
		 dt + peer_device->rs_paused, peer_device->rs_paused, dbdt, device->h_insync_bb, device->h_marked_bb);
#else
	drbd_info(peer_device, "%s done (total %lu sec; paused %lu sec; %lu K/sec)\n",
		verify_done ? "Online verify" : "Resync", dt + peer_device->rs_paused, peer_device->rs_paused, dbdt);
#endif

	n_oos = drbd_bm_total_weight(peer_device);

	if (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T) {
		if (n_oos) {
			drbd_alert(peer_device, "Online verify found %lu %dk block out of sync!\n",
			      n_oos, Bit2KB(1));
			khelper_cmd = "out-of-sync";
		}
	} else {
#ifdef _WIN32
		if (!((n_oos - peer_device->rs_failed) == 0))
		{
			DbgPrint("_WIN32_v9_CHECK: n_oos=%Iu rs_failed=%Iu. Ignore assert ##########\n", n_oos, peer_device->rs_failed);
		}
#else
		D_ASSERT(peer_device, (n_oos - peer_device->rs_failed) == 0);
#endif

		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T)
			khelper_cmd = "after-resync-target";

		if (peer_device->use_csums && peer_device->rs_total) {
#ifdef _WIN32
			const ULONG_PTR s = peer_device->rs_same_csum;
			const ULONG_PTR t = peer_device->rs_total;
#else
			const unsigned long s = peer_device->rs_same_csum;
			const unsigned long t = peer_device->rs_total;
#endif
			const ULONG_PTR ratio =
				(t == 0)     ? 0 :
			(t < 100000) ? ((s*100)/t) : (s/(t/100));
			drbd_info(peer_device, "%lu %% had equal checksums, eliminated: %luK; "
			     "transferred %luK total %luK\n",
			     ratio,
			     Bit2KB(peer_device->rs_same_csum),
			     Bit2KB(peer_device->rs_total - peer_device->rs_same_csum),
			     Bit2KB(peer_device->rs_total));
		}
	}

	if (peer_device->rs_failed) {
		drbd_info(peer_device, "            %lu failed blocks\n", peer_device->rs_failed);

		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T) {
			__change_disk_state(device, D_INCONSISTENT, __FUNCTION__);
			__change_peer_disk_state(peer_device, D_UP_TO_DATE, __FUNCTION__);
		} else {
			__change_disk_state(device, D_UP_TO_DATE, __FUNCTION__);
			__change_peer_disk_state(peer_device, D_INCONSISTENT, __FUNCTION__);
		}
		peer_device->resync_again++;
	}
	else {
		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T) {
			bool stable_resync = was_resync_stable(peer_device);
			if (stable_resync)
				__change_disk_state(device, peer_device->disk_state[NOW], __FUNCTION__);
#ifdef _WIN32
			// MODIFIED_BY_MANTECH DW-955: need to upgrade disk state after unstable resync.
			else
				sanitize_state_after_unstable_resync(peer_device);
#endif

			if (device->disk_state[NEW] == D_UP_TO_DATE)
				__cancel_other_resyncs(device);

			if (stable_resync &&
			    !test_bit(RECONCILIATION_RESYNC, &peer_device->flags) &&
#ifdef _WIN32
				// MODIFIED_BY_MANTECH DW-1034: we've already had the newest one.
				((drbd_current_uuid(device) & ~UUID_PRIMARY) != (peer_device->current_uuid & ~UUID_PRIMARY)) &&
#endif
			    peer_device->uuids_received) {
				u64 newer = drbd_uuid_resync_finished(peer_device);
#ifdef _WIN32
				// MODIFIED_BY_MANTECH DW-1216: no downgrade if uuid flags contains belows because
				// 1. receiver updates newly created uuid unless it is being gotten sync, downgrading shouldn't(or might not) affect.
				if (peer_device->uuid_flags & UUID_FLAG_NEW_DATAGEN
#ifdef _WIN32_DISABLE_RESYNC_FROM_SECONDARY
				// 2. one node goes primary and resync will be started for all secondaries. no downgrading is necessary.
					|| peer_device->uuid_flags & UUID_FLAG_PROMOTED
#endif
					)
					newer = 0;
#endif
				__outdate_peer_disk_by_mask(device, newer);
			} else {
				if (!peer_device->uuids_received)
					drbd_err(peer_device, "BUG: uuids were not received!\n");

				if (test_bit(UNSTABLE_RESYNC, &peer_device->flags))
					drbd_info(peer_device, "Peer was unstable during resync\n");
			}

			if (stable_resync && peer_device->uuids_received) {
				/* Now the two UUID sets are equal, update what we
				 * know of the peer. */
				const int node_id = device->resource->res_opts.node_id;
				int i;

				drbd_print_uuids(peer_device, "updated UUIDs", __FUNCTION__);
				peer_device->current_uuid = drbd_current_uuid(device);
				peer_device->bitmap_uuids[node_id] = drbd_bitmap_uuid(peer_device);
				for (i = 0; i < ARRAY_SIZE(peer_device->history_uuids); i++)
					peer_device->history_uuids[i] =
						drbd_history_uuid(device, i);
			}
		} else if (repl_state[NOW] == L_SYNC_SOURCE || repl_state[NOW] == L_PAUSED_SYNC_S) {
			if (new_peer_disk_state != D_MASK)
				__change_peer_disk_state(peer_device, new_peer_disk_state, __FUNCTION__);
			if (peer_device->connection->agreed_pro_version < 110) {
				drbd_uuid_set_bitmap(peer_device, 0UL);
				drbd_print_uuids(peer_device, "updated UUIDs", __FUNCTION__);
			}
		}
	}

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-955: clear resync aborted flag when just resync is done.
	clear_bit(RESYNC_ABORTED, &peer_device->flags);
#endif

out_unlock:
#ifdef _WIN32_RCU_LOCKED
	end_state_change_locked(device->resource, false, __FUNCTION__);
#else
	end_state_change_locked(device->resource);
#endif

	put_ldev(device);

	peer_device->rs_total  = 0;
	peer_device->rs_failed = 0;
	peer_device->rs_paused = 0;

	if (peer_device->resync_again) {
		enum drbd_repl_state new_repl_state =
			old_repl_state == L_SYNC_TARGET || old_repl_state == L_PAUSED_SYNC_T ?
			L_WF_BITMAP_T :
			old_repl_state == L_SYNC_SOURCE || old_repl_state == L_PAUSED_SYNC_S ?
			L_WF_BITMAP_S : L_ESTABLISHED;

		if (new_repl_state != L_ESTABLISHED) {
			peer_device->resync_again--;
			begin_state_change_locked(device->resource, CS_VERBOSE);
			__change_repl_state_and_auto_cstate(peer_device, new_repl_state, __FUNCTION__);
#ifdef _WIN32_RCU_LOCKED
			end_state_change_locked(device->resource, false, __FUNCTION__);
#else
			end_state_change_locked(device->resource);
#endif
		}
	}
	spin_unlock_irq(&device->resource->req_lock);

out:
	/* reset start sector, if we reached end of device */
	if (verify_done && peer_device->ov_left == 0)
		peer_device->ov_start_sector = 0;

	drbd_md_sync_if_dirty(device);

	if (khelper_cmd)
		drbd_khelper(device, connection, khelper_cmd);

	/* If we have been sync source, and have an effective fencing-policy,
	 * once *all* volumes are back in sync, call "unfence". */
	if (old_repl_state == L_SYNC_SOURCE || old_repl_state == L_PAUSED_SYNC_S) {
		enum drbd_disk_state disk_state = D_MASK;
		enum drbd_disk_state pdsk_state = D_MASK;
		enum drbd_fencing_policy fencing_policy = FP_DONT_CARE;

		rcu_read_lock();
		fencing_policy = connection->fencing_policy;
		if (fencing_policy != FP_DONT_CARE) {
			struct drbd_peer_device *peer_device;
			int vnr;
#ifdef _WIN32
			idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
			idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
				struct drbd_device *device = peer_device->device;
				disk_state = min_t(enum drbd_disk_state, disk_state, device->disk_state[NOW]);
				pdsk_state = min_t(enum drbd_disk_state, pdsk_state, peer_device->disk_state[NOW]);
			}
		}
		rcu_read_unlock();
		if (disk_state == D_UP_TO_DATE && pdsk_state == D_UP_TO_DATE)
			drbd_khelper(NULL, connection, "unfence-peer");

		//DW-1874
		drbd_md_clear_peer_flag(peer_device, MDF_PEER_IN_PROGRESS_SYNC);
	}

	return 1;
}

/* helper */
static void move_to_net_ee_or_free(struct drbd_connection *connection, struct drbd_peer_request *peer_req)
{
	if (drbd_peer_req_has_active_page(peer_req)) {
		/* This might happen if sendpage() has not finished */
		int i = DIV_ROUND_UP(peer_req->i.size, PAGE_SIZE);
		atomic_add(i, &connection->pp_in_use_by_net);
		atomic_sub(i, &connection->pp_in_use);
		spin_lock_irq(&connection->resource->req_lock);
		list_add_tail(&peer_req->w.list, &peer_req->peer_device->connection->net_ee);
		spin_unlock_irq(&connection->resource->req_lock);
		wake_up(&drbd_pp_wait);
	} else
		drbd_free_peer_req(peer_req);
}

/**
 * w_e_end_data_req() - Worker callback, to send a P_DATA_REPLY packet in response to a P_DATA_REQUEST
 * @w:		work object.
 * @cancel:	The connection will be closed anyways
 */
int w_e_end_data_req(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	int err;

	if (unlikely(cancel)) {
		drbd_free_peer_req(peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		err = drbd_send_block(peer_device, P_DATA_REPLY, peer_req);
	} else {
		if (drbd_ratelimit())
			drbd_err(peer_device, "Sending NegDReply. sector=%llus.\n",
			    (unsigned long long)peer_req->i.sector);

		err = drbd_send_ack(peer_device, P_NEG_DREPLY, peer_req);
	}

	dec_unacked(peer_device);

	move_to_net_ee_or_free(peer_device->connection, peer_req);

	if (unlikely(err))
		drbd_err(peer_device, "drbd_send_block() failed\n");
	return err;
}

static bool all_zero(struct drbd_peer_request *peer_req)
{
	UNREFERENCED_PARAMETER(peer_req);
#ifdef _WIN32
	return false;
#else
	struct page *page = peer_req->page_chain.head;
	unsigned int len = peer_req->i.size;

	page_chain_for_each(page) {
		unsigned int l = min_t(unsigned int, len, PAGE_SIZE);
		unsigned int i, words = l / sizeof(long);
		unsigned long *d;

		d = drbd_kmap_atomic(page, KM_USER1);
		for (i = 0; i < words; i++) {
			if (d[i]) {
				drbd_kunmap_atomic(d, KM_USER1);
				return false;
			}
		}
		drbd_kunmap_atomic(d, KM_USER1);
		len -= l;
	}

	return true;
#endif
}

/**
 * w_e_end_rsdata_req() - Worker callback to send a P_RS_DATA_REPLY packet in response to a P_RS_DATA_REQUEST
 * @w:		work object.
 * @cancel:	The connection will be closed anyways
 */
int w_e_end_rsdata_req(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	int err = 0;

	if (unlikely(cancel)) {
		drbd_free_peer_req(peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (get_ldev_if_state(device, D_DETACHING)) {
		drbd_rs_complete_io(peer_device, peer_req->i.sector, __FUNCTION__);
		put_ldev(device);
	}

	if (peer_device->repl_state[NOW] == L_AHEAD) {
		err = drbd_send_ack(peer_device, P_RS_CANCEL, peer_req);
	}
	else if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		//DW-1807 send P_RS_CANCEL if resync is not in progress
		//DW-1846 The request should also be processed when the resync is stopped.
		if (!is_sync_source(peer_device)) {
			err = drbd_send_ack(peer_device, P_RS_CANCEL, peer_req);
		}
		else {
			if (likely(peer_device->disk_state[NOW] >= D_INCONSISTENT)) {

				// DW-1938 fix potential rs_in_flight incorrect calculation
				inc_rs_pending(peer_device);
				//DW-1817
				//Add the data size to rs_in_flight before sending the resync data.
				atomic_add64(peer_req->i.size, &peer_device->connection->rs_in_flight);

				if (peer_req->flags & EE_RS_THIN_REQ && all_zero(peer_req))
					err = drbd_send_rs_deallocated(peer_device, peer_req);
				else
					err = drbd_send_block(peer_device, P_RS_DATA_REPLY, peer_req);
				
				// DW-1938 fix potential rs_in_flight incorrect calculation
				if (err) {
					dec_rs_pending(peer_device);
					atomic_sub64(peer_req->i.size, &peer_device->connection->rs_in_flight);
				}
			}
			else {
				if (drbd_ratelimit())
					drbd_err(peer_device, "Not sending RSDataReply, "
					"partner DISKLESS!\n");
				err = 0;
			}
		}
	} else {
		if (drbd_ratelimit())
			drbd_err(peer_device, "Sending NegRSDReply. sector %llus.\n",
			    (unsigned long long)peer_req->i.sector);

		err = drbd_send_ack(peer_device, P_NEG_RS_DREPLY, peer_req);

		/* update resync data with failure */
		drbd_rs_failed_io(peer_device, peer_req->i.sector, peer_req->i.size);
	}

	dec_unacked(peer_device);

	move_to_net_ee_or_free(peer_device->connection, peer_req);

	if (unlikely(err))
		drbd_err(peer_device, "drbd_send_block() failed\n");
	return err;
}

int w_e_end_csum_rs_req(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct digest_info *di;
#ifdef _WIN32
	int digest_size = 0; 
#else
	int digest_size;
#endif
	
	void *digest = NULL;
	int err, eq = 0;

	if (unlikely(cancel)) {
		drbd_info(peer_device, "cancel csum rs req, sector : %lu\n", peer_req->i.sector);
		drbd_free_peer_req(peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (get_ldev(device)) {
		drbd_rs_complete_io(peer_device, peer_req->i.sector, __FUNCTION__);
		put_ldev(device);
	}

	di = peer_req->digest;

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		/* quick hack to try to avoid a race against reconfiguration.
		 * a real fix would be much more involved,
		 * introducing more locking mechanisms */
		if (peer_device->connection->csums_tfm) {
			digest_size = crypto_hash_digestsize(peer_device->connection->csums_tfm);
			D_ASSERT(device, digest_size == di->digest_size);
#ifdef _WIN32
            digest = kmalloc(digest_size, GFP_NOIO, '23DW');
#else
			digest = kmalloc(digest_size, GFP_NOIO);
#endif
			if (digest) {
#ifdef _WIN32
				drbd_csum_pages(peer_device->connection->csums_tfm, peer_req, digest);
#else
				drbd_csum_pages(peer_device->connection->csums_tfm, peer_req->page_chain.head, digest);
#endif
				eq = !memcmp(digest, di->digest, digest_size);
				kfree(digest);
			}
		}

		if (eq) {
			drbd_set_in_sync(peer_device, peer_req->i.sector, peer_req->i.size);
			/* rs_same_csums unit is BM_BLOCK_SIZE */
			peer_device->rs_same_csum += peer_req->i.size >> BM_BLOCK_SHIFT;
			err = drbd_send_ack(peer_device, P_RS_IS_IN_SYNC, peer_req);
			// DW-1942 applied to release io-error value.
			check_and_clear_io_error_in_primary(device);
		} else {
			inc_rs_pending(peer_device);
			peer_req->block_id = ID_SYNCER; /* By setting block_id, digest pointer becomes invalid! */
			peer_req->flags &= ~EE_HAS_DIGEST; /* This peer request no longer has a digest pointer */
			kfree(di);
			err = drbd_send_block(peer_device, P_RS_DATA_REPLY, peer_req);
		}
	} else {
		err = drbd_send_ack(peer_device, P_NEG_RS_DREPLY, peer_req);
		if (drbd_ratelimit())
			drbd_err(device, "Sending NegDReply. I guess it gets messy.\n");
		// DW-1942 fix bug that checksum synchronization stops when SyncSource io-error occurs continuously.
		drbd_rs_failed_io(peer_device, peer_req->i.sector, peer_req->i.size);
	}

	dec_unacked(peer_device);
	move_to_net_ee_or_free(peer_device->connection, peer_req);

	if (unlikely(err))
		drbd_err(device, "drbd_send_block/ack() failed\n");
	return err;
}

int w_e_end_ov_req(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	int digest_size;
	void *digest;
	int err = 0;

	if (unlikely(cancel))
		goto out;

	digest_size = crypto_hash_digestsize(peer_device->connection->verify_tfm);
	/* FIXME if this allocation fails, online verify will not terminate! */
	digest = drbd_prepare_drequest_csum(peer_req, digest_size);
	if (!digest) {
		err = -ENOMEM;
		goto out;
	}

	if (!(peer_req->flags & EE_WAS_ERROR))
#ifdef _WIN32
        drbd_csum_pages(peer_device->connection->verify_tfm, peer_req, digest);
#else
		drbd_csum_pages(peer_device->connection->verify_tfm, peer_req->page_chain.head, digest);
#endif
	else
		memset(digest, 0, digest_size);

	/* Free peer_req and pages before send.
	 * In case we block on congestion, we could otherwise run into
	 * some distributed deadlock, if the other side blocks on
	 * congestion as well, because our receiver blocks in
	 * drbd_alloc_pages due to pp_in_use > max_buffers. */
	drbd_free_peer_req(peer_req);
	peer_req = NULL;

	inc_rs_pending(peer_device);
	err = drbd_send_command(peer_device, P_OV_REPLY, DATA_STREAM);
	if (err)
		dec_rs_pending(peer_device);

out:
	if (peer_req)
		drbd_free_peer_req(peer_req);
	dec_unacked(peer_device);
	return err;
}

void drbd_ov_out_of_sync_found(struct drbd_peer_device *peer_device, sector_t sector, int size)
{
	if (peer_device->ov_last_oos_start + peer_device->ov_last_oos_size == sector) {
		peer_device->ov_last_oos_size += size>>9;
	} else {
		peer_device->ov_last_oos_start = sector;
		peer_device->ov_last_oos_size = size>>9;
	}
	drbd_set_out_of_sync(peer_device, sector, size);
}

int w_e_end_ov_reply(struct drbd_work *w, int cancel)
{
	struct drbd_peer_request *peer_req = container_of(w, struct drbd_peer_request, w);
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device->device;
	struct digest_info *di;
	void *digest;
	sector_t sector = peer_req->i.sector;
	unsigned int size = peer_req->i.size;
	int digest_size;
	int err, eq = 0;
	bool stop_sector_reached = false;

	if (unlikely(cancel)) {
		drbd_free_peer_req(peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	/* after "cancel", because after drbd_disconnect/drbd_rs_cancel_all
	 * the resync lru has been cleaned up already */
	if (get_ldev(device)) {
		drbd_rs_complete_io(peer_device, peer_req->i.sector, __FUNCTION__);
		put_ldev(device);
	}

	di = peer_req->digest;

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		digest_size = crypto_hash_digestsize(peer_device->connection->verify_tfm);
#ifdef _WIN32
        digest = kmalloc(digest_size, GFP_NOIO, '33DW');
#else
		digest = kmalloc(digest_size, GFP_NOIO);
#endif
		if (digest) {
#ifdef _WIN32
            drbd_csum_pages(peer_device->connection->verify_tfm, peer_req, digest);
#else
			drbd_csum_pages(peer_device->connection->verify_tfm, peer_req->page_chain.head, digest);
#endif

			D_ASSERT(device, digest_size == di->digest_size);
			eq = !memcmp(digest, di->digest, digest_size);
			kfree(digest);
		}
	}

	/* Free peer_req and pages before send.
	 * In case we block on congestion, we could otherwise run into
	 * some distributed deadlock, if the other side blocks on
	 * congestion as well, because our receiver blocks in
	 * drbd_alloc_pages due to pp_in_use > max_buffers. */
	drbd_free_peer_req(peer_req);
	if (!eq)
		drbd_ov_out_of_sync_found(peer_device, sector, size);
	else
		ov_out_of_sync_print(peer_device);

	err = drbd_send_ack_ex(peer_device, P_OV_RESULT, sector, size,
			       eq ? ID_IN_SYNC : ID_OUT_OF_SYNC);

	dec_unacked(peer_device);

	--peer_device->ov_left;

	/* let's advance progress step marks only for every other megabyte */
	if ((peer_device->ov_left & 0x200) == 0x200)
		drbd_advance_rs_marks(peer_device, peer_device->ov_left);

	stop_sector_reached = verify_can_do_stop_sector(peer_device) &&
		(sector + (size>>9)) >= peer_device->ov_stop_sector;

	if (peer_device->ov_left == 0 || stop_sector_reached) {
		ov_out_of_sync_print(peer_device);
		drbd_resync_finished(peer_device, D_MASK);
	}

	return err;
}

/* FIXME
 * We need to track the number of pending barrier acks,
 * and to be able to wait for them.
 * See also comment in drbd_adm_attach before drbd_suspend_io.
 */
static int drbd_send_barrier(struct drbd_connection *connection)
{
	struct p_barrier *p;
	int err;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;

	p->barrier = connection->send.current_epoch_nr;
	p->pad = 0;
	connection->send.last_sent_epoch_nr = connection->send.current_epoch_nr;
	connection->send.current_epoch_writes = 0;
	connection->send.last_sent_barrier_jif = jiffies;

	set_bit(BARRIER_ACK_PENDING, &connection->flags);
	err = send_command(connection, -1, P_BARRIER, DATA_STREAM);
	if (err) {
		clear_bit(BARRIER_ACK_PENDING, &connection->flags);
		wake_up(&connection->resource->barrier_wait);
	}
	return err;
}

static bool need_unplug(struct drbd_connection *connection)
{
	UNREFERENCED_PARAMETER(connection);

#ifndef _WIN32
	unsigned i = connection->todo.unplug_slot;
	return dagtag_newer_eq(connection->send.current_dagtag_sector,
			connection->todo.unplug_dagtag_sector[i]);
#else
	return FALSE;
#endif
}

static void maybe_send_unplug_remote(struct drbd_connection *connection, bool send_anyways)
{
	UNREFERENCED_PARAMETER(connection);
	UNREFERENCED_PARAMETER(send_anyways);

#ifndef _WIN32
	if (need_unplug(connection)) {
		/* Yes, this is non-atomic wrt. its use in drbd_unplug_fn.
		 * We save a spin_lock_irq, and worst case
		 * we occasionally miss an unplug event. */

		/* Paranoia: to avoid a continuous stream of unplug-hints,
		 * in case we never get any unplug events */
		connection->todo.unplug_dagtag_sector[connection->todo.unplug_slot] =
			connection->send.current_dagtag_sector + (1ULL << 63);
		/* advance the current unplug slot */
		connection->todo.unplug_slot ^= 1;
	} else if (!send_anyways)
		return;
 
	if (connection->cstate[NOW] < C_CONNECTED)
		return;

	if (!conn_prepare_command(connection, 0, DATA_STREAM))
		return;

	send_command(connection, -1, P_UNPLUG_REMOTE, DATA_STREAM);
#endif
}
 
static bool __drbd_may_sync_now(struct drbd_peer_device *peer_device)
{
	struct drbd_device *other_device = peer_device->device;
	int ret = true;
#ifndef _WIN32 // DW-900 to avoid the recursive lock
	rcu_read_lock();
#endif
	while (true, true) {
		struct drbd_peer_device *other_peer_device;
		int resync_after;

		if (!other_device->ldev || other_device->disk_state[NOW] == D_DISKLESS)
			break;
		resync_after = rcu_dereference(other_device->ldev->disk_conf)->resync_after;
		if (resync_after == -1)
			break;
		other_device = minor_to_device(resync_after);
		if (!other_device)
			break;
		other_peer_device = conn_peer_device(peer_device->connection, other_device->vnr);
		if ((other_peer_device->repl_state[NOW] >= L_SYNC_SOURCE &&
		     other_peer_device->repl_state[NOW] <= L_PAUSED_SYNC_T) ||
		    other_peer_device->resync_susp_dependency[NOW] ||
		    other_peer_device->resync_susp_peer[NOW] ||
		    other_peer_device->resync_susp_user[NOW]) {
			drbd_info(peer_device, "another(node_id:%d) peer device is in progress for resync\n", other_peer_device->node_id);
			ret = false;
			break;
		}
	}
#ifndef _WIN32 // DW-900 to avoid the recursive lock
	rcu_read_unlock();
#endif

	return ret;
}

/**
 * drbd_pause_after() - Pause resync on all devices that may not resync now
 * @device:	DRBD device.
 *
 * Called from process context only (admin command and after_state_ch).
 */
static bool drbd_pause_after(struct drbd_device *device)
{
	UNREFERENCED_PARAMETER(device);

	struct drbd_device *other_device;
	bool changed = false;
	int vnr;

	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_device *, &drbd_devices, other_device, vnr) {
#else
	idr_for_each_entry(&drbd_devices, other_device, vnr) {
#endif
		struct drbd_peer_device *other_peer_device;

		begin_state_change_locked(other_device->resource, CS_HARD);
		if (other_device->disk_state[NOW] == D_DISKLESS) {
#ifdef _WIN32_RCU_LOCKED
			abort_state_change_locked(other_device->resource, true, __FUNCTION__);
#else
			abort_state_change_locked(other_device->resource);
#endif
			continue;
		}
		for_each_peer_device(other_peer_device, other_device) {
			if (other_peer_device->repl_state[NOW] == L_OFF)
				continue;
			if (!__drbd_may_sync_now(other_peer_device))
				__change_resync_susp_dependency(other_peer_device, true, __FUNCTION__);
		}
#ifdef _WIN32_RCU_LOCKED
		if (end_state_change_locked(other_device->resource, true, __FUNCTION__) != SS_NOTHING_TO_DO)
#else
		if (end_state_change_locked(other_device->resource) != SS_NOTHING_TO_DO)
#endif
			changed = true;
	}
	rcu_read_unlock();
	return changed;
}

/**
 * drbd_resume_next() - Resume resync on all devices that may resync now
 * @device:	DRBD device.
 *
 * Called from process context only (admin command and sender).
 */
static bool drbd_resume_next(struct drbd_device *device)
{
	UNREFERENCED_PARAMETER(device);

	struct drbd_device *other_device;
	bool changed = false;
	int vnr;

	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_device *, &drbd_devices, other_device, vnr) {
#else
	idr_for_each_entry(&drbd_devices, other_device, vnr) {
#endif
		struct drbd_peer_device *other_peer_device;

		begin_state_change_locked(other_device->resource, CS_HARD);
		if (other_device->disk_state[NOW] == D_DISKLESS) {
#ifdef _WIN32_RCU_LOCKED
			abort_state_change_locked(other_device->resource, true, __FUNCTION__);
#else
			abort_state_change_locked(other_device->resource);
#endif
			continue;
		}
		for_each_peer_device(other_peer_device, other_device) {
			if (other_peer_device->repl_state[NOW] == L_OFF)
				continue;
			if (other_peer_device->resync_susp_dependency[NOW] &&
			    __drbd_may_sync_now(other_peer_device))
				__change_resync_susp_dependency(other_peer_device, false, __FUNCTION__);
		}
#ifdef _WIN32_RCU_LOCKED
		if (end_state_change_locked(other_device->resource, true, __FUNCTION__) != SS_NOTHING_TO_DO)
#else
		if (end_state_change_locked(other_device->resource) != SS_NOTHING_TO_DO)
#endif
			changed = true;
	}
	rcu_read_unlock();
	return changed;
}

void resume_next_sg(struct drbd_device *device)
{
	lock_all_resources();
	drbd_resume_next(device);
	unlock_all_resources();
}

void suspend_other_sg(struct drbd_device *device)
{
	lock_all_resources();
	drbd_pause_after(device);
	unlock_all_resources();
}

/* caller must hold resources_mutex */
enum drbd_ret_code drbd_resync_after_valid(struct drbd_device *device, int resync_after)
{
	struct drbd_device *other_device;
	int rv = NO_ERROR;

	if (resync_after == -1)
		return NO_ERROR;
	if (resync_after < -1)
		return ERR_RESYNC_AFTER;
	other_device = minor_to_device(resync_after);
	if (!other_device)
		return ERR_RESYNC_AFTER;

	/* check for loops */
	rcu_read_lock();
	while (true,true) {
		if (other_device == device) {
			rv = ERR_RESYNC_AFTER_CYCLE;
			break;
		}

		/* You are free to depend on diskless, non-existing,
		 * or not yet/no longer existing minors.
		 * We only reject dependency loops.
		 * We cannot follow the dependency chain beyond a detached or
		 * missing minor.
		 */
		if (!other_device)
			break;

		if (!get_ldev_if_state(other_device, D_NEGOTIATING))
			break;
		resync_after = rcu_dereference(other_device->ldev->disk_conf)->resync_after;
		put_ldev(other_device);

		/* dependency chain ends here, no cycles. */
		if (resync_after == -1)
			break;

		/* follow the dependency chain */
		other_device = minor_to_device(resync_after);
	}
	rcu_read_unlock();

	return rv;
}

/* caller must hold resources_mutex */
void drbd_resync_after_changed(struct drbd_device *device)
{
	while (drbd_pause_after(device) || drbd_resume_next(device))
		/* do nothing */ ;
}

void drbd_rs_controller_reset(struct drbd_peer_device *peer_device)
{
	struct fifo_buffer *plan;

	atomic_set(&peer_device->rs_sect_in, 0);
	atomic_set(&peer_device->device->rs_sect_ev, 0);  /* FIXME: ??? */
	peer_device->rs_in_flight = 0;
#ifdef _WIN32	
	peer_device->rs_last_events =
		drbd_backing_bdev_events(peer_device->device);
#else
	peer_device->rs_last_events =
		drbd_backing_bdev_events(peer_device->device->ldev->backing_bdev->bd_contains->bd_disk);
#endif

	/* Updating the RCU protected object in place is necessary since
	   this function gets called from atomic context.
	   It is valid since all other updates also lead to an completely
	   empty fifo */
	rcu_read_lock();
	plan = rcu_dereference(peer_device->rs_plan_s);
	plan->total = 0;
	fifo_set(plan, 0);
	rcu_read_unlock();
}

#ifdef _WIN32
void start_resync_timer_fn(PKDPC Dpc, PVOID data, PVOID SystemArgument1, PVOID SystemArgument2)
#else
void start_resync_timer_fn(unsigned long data)
#endif
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(Dpc);

	if (data == NULL)
		return;

	struct drbd_peer_device *peer_device = (struct drbd_peer_device *) data;
	drbd_info(peer_device, "post RS_START to the peer_device work\n"); // DW-1518
	drbd_peer_device_post_work(peer_device, RS_START);
}

bool drbd_stable_sync_source_present(struct drbd_peer_device *except_peer_device, enum which_state which)
{
	u64 authoritative_nodes = except_peer_device->uuid_authoritative_nodes;
	struct drbd_device *device = except_peer_device->device;
	struct drbd_peer_device *peer_device;
	bool rv = false;

	/* If a peer considers himself as unstable and sees me as an authoritative
	   node, then we have a stable resync source! */
	if (authoritative_nodes & NODE_MASK(device->resource->res_opts.node_id))
		return true;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum drbd_repl_state repl_state;
		struct net_conf *nc;

		if (peer_device == except_peer_device)
			continue;

		repl_state = peer_device->repl_state[which];

		if (repl_state >= L_ESTABLISHED && repl_state < L_AHEAD) {
			if (authoritative_nodes & NODE_MASK(peer_device->node_id)) {
				rv = true;
				break;
			}

			nc = rcu_dereference(peer_device->connection->transport.net_conf);
			/* Restricting the clause the two_primaries not allowed, otherwise
			   we need to ensure here that we are neighbor of all primaries,
			   and that is a lot more challenging. */

			if ((!nc->two_primaries &&
			     peer_device->connection->peer_role[which] == R_PRIMARY) ||
			    ((repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) &&
			     peer_device->uuid_flags & UUID_FLAG_STABLE)) {
				rv = true;
				break;
			}
		}
	}
	rcu_read_unlock();

	return rv;
}

static void do_start_resync(struct drbd_peer_device *peer_device)
{

	if (atomic_read(&peer_device->unacked_cnt) ||
	    atomic_read(&peer_device->rs_pending_cnt)) {
		drbd_warn(peer_device, "postponing start_resync ... unacked : %d, pending : %d\n", atomic_read(&peer_device->unacked_cnt), atomic_read(&peer_device->rs_pending_cnt));
		peer_device->start_resync_timer.expires = jiffies + HZ/10;
		add_timer(&peer_device->start_resync_timer);
		return;
	}

	drbd_info(peer_device, "starting resync ...\n"); // DW-1518
	drbd_start_resync(peer_device, peer_device->start_resync_side);
#ifdef _WIN32
	// DW-1619 : moved to drbd_start_resync()
	//clear_bit(AHEAD_TO_SYNC_SOURCE, &peer_device->flags);
#else
	clear_bit(AHEAD_TO_SYNC_SOURCE, &device->flags);
#endif
}

static bool use_checksum_based_resync(struct drbd_connection *connection, struct drbd_device *device)
{
	bool csums_after_crash_only;
	rcu_read_lock();
	csums_after_crash_only = rcu_dereference(connection->transport.net_conf)->csums_after_crash_only;
	rcu_read_unlock();
	return connection->agreed_pro_version >= 89 &&		/* supported? */
		connection->csums_tfm &&			/* configured? */
		(csums_after_crash_only == false		/* use for each resync? */
		 || test_bit(CRASHED_PRIMARY, &device->flags));	/* or only after Primary crash? */
}

#ifdef _WIN32_STABLE_SYNCSOURCE
/**	DW-1314
* drbd_inspect_resync_side() - Check stability if resync can be started.
* rule for resync - Sync source must be stable and authoritative of sync target if sync target is unstable.
* DW-1315: need to also inspect if I will be able to be resync side. (state[NEW])
*/
#ifdef _WIN32_RCU_LOCKED
bool drbd_inspect_resync_side(struct drbd_peer_device *peer_device, enum drbd_repl_state replState, enum which_state which, bool locked)
#else
bool drbd_inspect_resync_side(struct drbd_peer_device *peer_device, enum drbd_repl_state replState, enum which_state which)
#endif
{
	struct drbd_device *device = peer_device->device;
	enum drbd_repl_state side = 0;
	u64 authoritative = 0;

	// no start resync if I haven't received uuid from peer.	
	if (!peer_device->uuids_received)
	{
		drbd_info(peer_device, "I have not yet received uuid from peer, can not be %s\n", drbd_repl_str(replState));
		return false;
	}

	switch (replState)
	{
		case L_STARTING_SYNC_T:
		case L_WF_BITMAP_T:
		case L_SYNC_TARGET:
		case L_PAUSED_SYNC_T:
			side = L_SYNC_TARGET;
			break;
		case L_STARTING_SYNC_S:
		case L_WF_BITMAP_S:
		case L_SYNC_SOURCE:
		case L_PAUSED_SYNC_S:
			side = L_SYNC_SOURCE;
			break;
		case L_VERIFY_S:    // need to deal with verification state.
		case L_VERIFY_T:
			return true;
		default:
			drbd_info(peer_device, "unexpected repl_state (%s)\n", drbd_repl_str(replState));
			return false;
	}
	
	if (side == L_SYNC_TARGET)
	{
		if (!(peer_device->uuid_flags & UUID_FLAG_STABLE))
		{
			drbd_info(peer_device, "Sync source is unstable, can not be %s, uuid_flags(%llx), authoritative(%llx)\n",
				drbd_repl_str(replState), peer_device->uuid_flags, peer_device->uuid_authoritative_nodes);
			return false;
		}

#ifdef _WIN32_RCU_LOCKED
		if (!drbd_device_stable_ex(device, &authoritative, which, locked) &&
#else
		if (!drbd_device_stable_ex(device, &authoritative, which) &&
#endif
			!(NODE_MASK(peer_device->node_id) & authoritative))
		{
			drbd_info(peer_device, "I am unstable and sync source is not my authoritative node, can not be %s, authoritative(%llx)\n",
				drbd_repl_str(replState), authoritative);
			return false;
		}
	}
	else if (side == L_SYNC_SOURCE)
	{
#ifdef _WIN32_RCU_LOCKED
		if (!drbd_device_stable_ex(device, &authoritative, which, locked))
#else
		if (!drbd_device_stable_ex(device, &authoritative, which))
#endif
		{
			drbd_info(peer_device, "I am unstable, can not be %s, authoritative(%llx)\n", drbd_repl_str(replState), authoritative);
			return false;
		}

		if (!(peer_device->uuid_flags & UUID_FLAG_STABLE) &&
			!(NODE_MASK(device->resource->res_opts.node_id) & peer_device->uuid_authoritative_nodes))
		{
			drbd_info(peer_device, "Sync target is unstable and I am not its authoritative node, can not be %s, uuid_flags(%llx), authoritative(%llx)\n",
				drbd_repl_str(replState), peer_device->uuid_flags, peer_device->uuid_authoritative_nodes);
			return false;			
		}
	}

	return true;
}
#endif

/**
 * drbd_start_resync() - Start the resync process
 * @side:	Either L_SYNC_SOURCE or L_SYNC_TARGET
 *
 * This function might bring you directly into one of the
 * C_PAUSED_SYNC_* states.
 */
void drbd_start_resync(struct drbd_peer_device *peer_device, enum drbd_repl_state side)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	enum drbd_disk_state finished_resync_pdsk = D_UNKNOWN;
	enum drbd_repl_state repl_state;
	int r;


#ifdef _WIN32 // DW-1619 : clear AHEAD_TO_SYNC_SOURCE bit when start resync.
	clear_bit(AHEAD_TO_SYNC_SOURCE, &peer_device->flags);
#endif	

	spin_lock_irq(&device->resource->req_lock);
	repl_state = peer_device->repl_state[NOW];
	spin_unlock_irq(&device->resource->req_lock);
	if (repl_state < L_ESTABLISHED) {
		/* Connection closed meanwhile. */
		drbd_err(peer_device, "Unable to start resync since it is not connected\n"); // DW-1518
		return;
	}
	if (repl_state >= L_SYNC_SOURCE && repl_state < L_AHEAD) {
		drbd_err(peer_device, "Resync already running!\n");
		return;
	}

#ifdef _WIN32_DISABLE_RESYNC_FROM_SECONDARY
	// MODIFIED_BY_MANTECH DW-1142: don't start resync if resync source side node is not primary.
	if ((side == L_SYNC_TARGET && peer_device->connection->peer_role[NOW] != R_PRIMARY) ||
		(side == L_SYNC_SOURCE && device->resource->role[NOW] != R_PRIMARY))
	{
		drbd_info(peer_device, "Unable to start resync since SyncSource node is NOT primary\n");

		unsigned long irq_flags;

		begin_state_change(device->resource, &irq_flags, CS_VERBOSE);
		__change_repl_state_and_auto_cstate(peer_device, L_ESTABLISHED);
		end_state_change(device->resource, &irq_flags);
		return;
	}
#endif

#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-955: clear resync aborted flag when just starting resync.
	clear_bit(RESYNC_ABORTED, &peer_device->flags);
#endif

	if (!test_bit(B_RS_H_DONE, &peer_device->flags)) {
		if (side == L_SYNC_TARGET) {
			/* Since application IO was locked out during L_WF_BITMAP_T and
			   L_WF_SYNC_UUID we are still unmodified. Before going to L_SYNC_TARGET
			   we check that we might make the data inconsistent. */
			r = drbd_khelper(device, connection, "before-resync-target");
#ifdef _WIN32
			r = r << 8;
#endif
			r = (r >> 8) & 0xff;
			if (r > 0) {
				drbd_info(device, "before-resync-target handler returned %d, "
					 "dropping connection.\n", r);
				change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
				return;
			}
		} else /* L_SYNC_SOURCE */ {
			r = drbd_khelper(device, connection, "before-resync-source");
#ifdef _WIN32
			r = r << 8;
#endif
			r = (r >> 8) & 0xff;
			if (r > 0) {
				if (r == 3) {
					drbd_info(device, "before-resync-source handler returned %d, "
						 "ignoring. Old userland tools?", r);
				} else {
					drbd_info(device, "before-resync-source handler returned %d, "
						 "dropping connection.\n", r);
					change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
					return;
				}
			}
		}
	}

	if (down_trylock(&device->resource->state_sem)) {
		/* Retry later and let the worker make progress in the
		 * meantime; two-phase commits depend on that.  */
		drbd_info(peer_device, "Retry later\n"); // DW-1518
		set_bit(B_RS_H_DONE, &peer_device->flags);
		peer_device->start_resync_side = side;
		peer_device->start_resync_timer.expires = jiffies + HZ/5;
		add_timer(&peer_device->start_resync_timer);
		return;
	}
	lock_all_resources();
	clear_bit(B_RS_H_DONE, &peer_device->flags);
	if (connection->cstate[NOW] < C_CONNECTED ||
	    !get_ldev_if_state(device, D_NEGOTIATING)) {
		unlock_all_resources();
		goto out;
	}

#ifdef _WIN32_STABLE_SYNCSOURCE
	// DW-1314: check stable sync source rules.
#ifdef _WIN32_RCU_LOCKED
	if (!drbd_inspect_resync_side(peer_device, side, NOW, false))
#else
	if (!drbd_inspect_resync_side(peer_device, side, NOW))
#endif
	{
		drbd_warn(peer_device, "could not start resync.\n");

		// turn back the replication state to L_ESTABLISHED
		if (peer_device->repl_state[NOW] > L_ESTABLISHED)
		{
			begin_state_change_locked(device->resource, CS_VERBOSE);
			__change_repl_state_and_auto_cstate(peer_device, L_ESTABLISHED, __FUNCTION__);
#ifdef _WIN32_RCU_LOCKED
			end_state_change_locked(device->resource, false, __FUNCTION__);
#else
			end_state_change_locked(device->resource);
#endif
		}
		unlock_all_resources();
		goto out;
	}
#endif

	begin_state_change_locked(device->resource, CS_VERBOSE);
#ifdef _WIN32 // DW-900 to avoid the recursive lock
	rcu_read_lock();
#endif
	__change_resync_susp_dependency(peer_device, !__drbd_may_sync_now(peer_device), __FUNCTION__);
#ifdef _WIN32 // DW-900 to avoid the recursive lock
	rcu_read_unlock();
#endif
	__change_repl_state_and_auto_cstate(peer_device, side, __FUNCTION__);
	if (side == L_SYNC_TARGET) {
#ifdef ACT_LOG_TO_RESYNC_LRU_RELATIVITY_DISABLE
		if (peer_device->connection->agreed_pro_version >= 113) {
			//DW-1911
			struct drbd_marked_replicate *marked_rl, *t;
			list_for_each_entry_safe(struct drbd_marked_replicate, marked_rl, t, &(device->marked_rl_list), marked_rl_list) {
				list_del(&marked_rl->marked_rl_list);
				kfree2(marked_rl);
			}

			device->s_rl_bb = UINT64_MAX;
			device->e_rl_bb = 0;
			//DW-1908 set start out of sync bit
			device->e_resync_bb = drbd_bm_find_next(peer_device, 0);
			//DW-1908
			device->h_marked_bb = 0;
			device->h_insync_bb = 0;
		}
#endif
		__change_disk_state(device, D_INCONSISTENT, __FUNCTION__);
		init_resync_stable_bits(peer_device);
	} else /* side == L_SYNC_SOURCE */
		__change_peer_disk_state(peer_device, D_INCONSISTENT, __FUNCTION__);
	finished_resync_pdsk = peer_device->resync_finished_pdsk;
	peer_device->resync_finished_pdsk = D_UNKNOWN;
#ifdef _WIN32_RCU_LOCKED
	r = end_state_change_locked(device->resource, false, __FUNCTION__);
#else
	r = end_state_change_locked(device->resource);
#endif
	repl_state = peer_device->repl_state[NOW];

	if (repl_state < L_ESTABLISHED)
		r = SS_UNKNOWN_ERROR;

	if (r == SS_SUCCESS) {
		drbd_pause_after(device);
		/* Forget potentially stale cached per resync extent bit-counts.
		 * Open coded drbd_rs_cancel_all(device), we already have IRQs
		 * disabled, and know the disk state is ok. */
		spin_lock(&device->al_lock);
		lc_reset(peer_device->resync_lru);
		peer_device->resync_locked = 0;
		peer_device->resync_wenr = LC_FREE;
		spin_unlock(&device->al_lock);
	}

	unlock_all_resources();

	if (r == SS_SUCCESS) {
#ifdef _WIN32 // DW-1285 set MDF_PEER_INIT_SYNCT_BEGIN 
		if( (side == L_SYNC_TARGET) 
			&& (peer_device->device->ldev->md.current_uuid == UUID_JUST_CREATED) ) { 
			drbd_md_set_peer_flag (peer_device, MDF_PEER_INIT_SYNCT_BEGIN);
		}
#endif
		drbd_info(peer_device, "Began resync as %s (will sync %lu KB [%lu bits set]).\n",
		     drbd_repl_str(repl_state),
		     (unsigned long) peer_device->rs_total << (BM_BLOCK_SHIFT-10),
		     (unsigned long) peer_device->rs_total);
		if (side == L_SYNC_TARGET) {
			//DW-1846 bm_resync_fo must be locked and set.
			mutex_lock(&device->bm_resync_fo_mutex);
			device->bm_resync_fo = 0;
			mutex_unlock(&device->bm_resync_fo_mutex);
			peer_device->use_csums = use_checksum_based_resync(connection, device);
		} else {
			peer_device->use_csums = false;
			//DW-1874
			drbd_md_set_peer_flag(peer_device, MDF_PEER_IN_PROGRESS_SYNC);
		}

		if ((side == L_SYNC_TARGET || side == L_PAUSED_SYNC_T) &&
		    !(peer_device->uuid_flags & UUID_FLAG_STABLE) &&
		    !drbd_stable_sync_source_present(peer_device, NOW))
			set_bit(UNSTABLE_RESYNC, &peer_device->flags);

		/* Since protocol 96, we must serialize drbd_gen_and_send_sync_uuid
		 * with w_send_oos, or the sync target will get confused as to
		 * how much bits to resync.  We cannot do that always, because for an
		 * empty resync and protocol < 95, we need to do it here, as we call
		 * drbd_resync_finished from here in that case.
		 * We drbd_gen_and_send_sync_uuid here for protocol < 96,
		 * and from after_state_ch otherwise. */
		if (side == L_SYNC_SOURCE && connection->agreed_pro_version < 96)
			drbd_gen_and_send_sync_uuid(peer_device);

		if (connection->agreed_pro_version < 95 && peer_device->rs_total == 0) {
			/* This still has a race (about when exactly the peers
			 * detect connection loss) that can lead to a full sync
			 * on next handshake. In 8.3.9 we fixed this with explicit
			 * resync-finished notifications, but the fix
			 * introduces a protocol change.  Sleeping for some
			 * time longer than the ping interval + timeout on the
			 * SyncSource, to give the SyncTarget the chance to
			 * detect connection loss, then waiting for a ping
			 * response (implicit in drbd_resync_finished) reduces
			 * the race considerably, but does not solve it. */
			if (side == L_SYNC_SOURCE) {
				struct net_conf *nc;
				int timeo;

				rcu_read_lock();
				nc = rcu_dereference(connection->transport.net_conf);
				timeo = nc->ping_int * HZ + nc->ping_timeo * HZ / 9;
				rcu_read_unlock();
				schedule_timeout_interruptible(timeo);
			}
			drbd_resync_finished(peer_device, D_MASK);
		}

		/* ns.conn may already be != peer_device->repl_state[NOW],
		 * we may have been paused in between, or become paused until
		 * the timer triggers.
		 * No matter, that is handled in resync_timer_fn() */
		if (repl_state == L_SYNC_TARGET)
			mod_timer(&peer_device->resync_timer, jiffies);

		drbd_md_sync_if_dirty(device);
	}
	else
	{
		drbd_err(peer_device, "Unable to start resync as %s (err = %d)\n", drbd_repl_str(repl_state), r); // DW-1518
	}

	put_ldev(device);
    out:
	up(&device->resource->state_sem);
	if (finished_resync_pdsk != D_UNKNOWN)
		drbd_resync_finished(peer_device, finished_resync_pdsk);
}

static void update_on_disk_bitmap(struct drbd_peer_device *peer_device, bool resync_done)
{
	struct drbd_device *device = peer_device->device;
	peer_device->rs_last_writeout = jiffies;

	if (!get_ldev(device))
		return;

	drbd_bm_write_lazy(device, 0);

	if (resync_done && is_sync_state(peer_device, NOW))
		drbd_resync_finished(peer_device, D_MASK);

	/* update timestamp, in case it took a while to write out stuff */
	peer_device->rs_last_writeout = jiffies;
	put_ldev(device);
}

static void drbd_ldev_destroy(struct drbd_device *device)
{
        struct drbd_peer_device *peer_device;

        rcu_read_lock();
        for_each_peer_device_rcu(peer_device, device) {
                lc_destroy(peer_device->resync_lru);
                peer_device->resync_lru = NULL;
        }
        rcu_read_unlock();
        lc_destroy(device->act_log);
        device->act_log = NULL;
	__acquire(local);
	drbd_backing_dev_free(device, device->ldev);
	device->ldev = NULL;
	__release(local);

        clear_bit(GOING_DISKLESS, &device->flags);
	wake_up(&device->misc_wait);
}

static void go_diskless(struct drbd_device *device)
{
	D_ASSERT(device, device->disk_state[NOW] == D_FAILED ||
			 device->disk_state[NOW] == D_DETACHING);
	/* we cannot assert local_cnt == 0 here, as get_ldev_if_state will
	 * inc/dec it frequently. Once we are D_DISKLESS, no one will touch
	 * the protected members anymore, though, so once put_ldev reaches zero
	 * again, it will be safe to free them. */

	/* Try to write changed bitmap pages, read errors may have just
	 * set some bits outside the area covered by the activity log.
	 *
	 * If we have an IO error during the bitmap writeout,
	 * we will want a full sync next time, just in case.
	 * (Do we want a specific meta data flag for this?)
	 *
	 * If that does not make it to stable storage either,
	 * we cannot do anything about that anymore.
	 *
	 * We still need to check if both bitmap and ldev are present, we may
	 * end up here after a failed attach, before ldev was even assigned.
	 */
	if (device->bitmap && device->ldev) {
		if (drbd_bitmap_io_from_worker(device, drbd_bm_write,
					       "detach",
					       BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK,
					       NULL)) {
			if (test_bit(CRASHED_PRIMARY, &device->flags)) {
				struct drbd_peer_device *peer_device;

				rcu_read_lock();
				for_each_peer_device_rcu(peer_device, device)
					drbd_md_set_peer_flag(peer_device, MDF_PEER_FULL_SYNC);
				rcu_read_unlock();
				drbd_md_sync_if_dirty(device);
			}
		}
	}

	change_disk_state(device, D_DISKLESS, CS_HARD, NULL);
}

static int do_md_sync(struct drbd_device *device)
{
	drbd_warn(device, "md_sync_timer expired! Worker calls drbd_md_sync().\n");
#ifdef DRBD_DEBUG_MD_SYNC
	drbd_warn(device, "last md_mark_dirty: %s:%u\n",
		device->last_md_mark_dirty.func, device->last_md_mark_dirty.line);
#endif
	drbd_md_sync(device);
	return 0;
}

#ifdef _WIN32
void repost_up_to_date_fn(PKDPC Dpc, PVOID data, PVOID arg1, PVOID arg2)
#else 
void repost_up_to_date_fn(unsigned long data)
#endif 
{
	UNREFERENCED_PARAMETER(arg1);
	UNREFERENCED_PARAMETER(arg2);
	UNREFERENCED_PARAMETER(Dpc);

	struct drbd_resource *resource = (struct drbd_resource *) data;

	drbd_post_work(resource, TRY_BECOME_UP_TO_DATE);
}

static int try_become_up_to_date(struct drbd_resource *resource)
{
	enum drbd_state_rv rv;

	/* Doing a two_phase_commit from worker context is only possible
	 * if twopc_work is not queued. Let it get executed first.
	 *
	 * Avoid deadlock on state_sem, in case someone holds it while
	 * waiting for the completion of some after-state-change work.
	 */

	if (list_empty(&resource->twopc_work.list)) {
		if (down_trylock(&resource->state_sem))
			goto repost;
		rv = change_from_consistent(resource, CS_ALREADY_SERIALIZED |
			CS_VERBOSE | CS_SERIALIZE | CS_DONT_RETRY);
		up(&resource->state_sem);
		if (rv == SS_TIMEOUT || rv == SS_CONCURRENT_ST_CHG)
			goto repost;
	} else {
	repost:
		mod_timer(&resource->repost_up_to_date_timer, jiffies + HZ / 10);
	}

	return 0;
}

/* only called from drbd_worker thread, no locking */
void __update_timing_details(
		struct drbd_thread_timing_details *tdp,
		unsigned int *cb_nr,
		void *cb,
		const char *fn, const unsigned int line)
{
	unsigned int i = *cb_nr % DRBD_THREAD_DETAILS_HIST;
	struct drbd_thread_timing_details *td = tdp + i;

	td->start_jif = jiffies;
	td->cb_addr = cb;
	td->caller_fn = fn;
	td->line = line;
	td->cb_nr = *cb_nr;

	i = (i+1) % DRBD_THREAD_DETAILS_HIST;
	td = tdp + i;
	memset(td, 0, sizeof(*td));

	++(*cb_nr);
}
#ifdef _WIN32
static void do_device_work(struct drbd_device *device, const ULONG_PTR todo)
#else
static void do_device_work(struct drbd_device *device, const unsigned long todo)
#endif

{
	if (test_bit(MD_SYNC, &todo))
		do_md_sync(device);
	if (test_bit(GO_DISKLESS, &todo))
		go_diskless(device);
	if (test_bit(DESTROY_DISK, &todo))
		drbd_ldev_destroy(device);
}
#ifdef _WIN32
static void do_peer_device_work(struct drbd_peer_device *peer_device, const ULONG_PTR todo)
#else
static void do_peer_device_work(struct drbd_peer_device *peer_device, const unsigned long todo)
#endif
{
	if (test_bit(RS_DONE, &todo) ||
	    test_bit(RS_PROGRESS, &todo))
		update_on_disk_bitmap(peer_device, test_bit(RS_DONE, &todo));
	if (test_bit(RS_START, &todo))
		do_start_resync(peer_device);
}

#define DRBD_RESOURCE_WORK_MASK	\
	(1UL << TRY_BECOME_UP_TO_DATE)

#define DRBD_DEVICE_WORK_MASK	\
	((1UL << GO_DISKLESS)	\
	|(1UL << DESTROY_DISK)	\
	|(1UL << MD_SYNC)	\
	)

#define DRBD_PEER_DEVICE_WORK_MASK	\
	((1UL << RS_START)		\
	|(1UL << RS_PROGRESS)		\
	|(1UL << RS_DONE)		\
	)
#ifdef _WIN32
static ULONG_PTR get_work_bits(const ULONG_PTR mask, ULONG_PTR *flags)
#else
static unsigned long get_work_bits(const unsigned long mask, unsigned long *flags)
#endif

{
#ifdef _WIN32
	ULONG_PTR old, new;
#else
	unsigned long old, new;
#endif
	do {
		old = *flags;
		new = old & ~mask;
#ifdef _WIN64
		BUG_ON_UINT32_OVER(old);
		BUG_ON_UINT32_OVER(new);
#endif
#ifdef _WIN32
	} while (atomic_cmpxchg((atomic_t *)flags, (int)old, (int)new) != (int)old);
#else
	} while (cmpxchg(flags, old, new) != old);
#endif
	return old & mask;
}

static void __do_unqueued_peer_device_work(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		struct drbd_device *device = peer_device->device;
#ifdef _WIN32
		ULONG_PTR todo = get_work_bits(DRBD_PEER_DEVICE_WORK_MASK, &peer_device->flags);
#else
		unsigned long todo = get_work_bits(DRBD_PEER_DEVICE_WORK_MASK, &peer_device->flags);
#endif
		
		if (!todo)
			continue;

		kref_get(&device->kref);
		rcu_read_unlock();
		do_peer_device_work(peer_device, todo);
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}

static void do_unqueued_peer_device_work(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	u64 im;

	for_each_connection_ref(connection, im, resource)
		__do_unqueued_peer_device_work(connection);
}

static void do_unqueued_device_work(struct drbd_resource *resource)
{
	struct drbd_device *device;
	int vnr;

	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
#else
	idr_for_each_entry(&resource->devices, device, vnr) {
#endif

#ifdef _WIN32
		ULONG_PTR todo = get_work_bits(DRBD_DEVICE_WORK_MASK, &device->flags);
#else
		unsigned long todo = get_work_bits(DRBD_DEVICE_WORK_MASK, &device->flags);
#endif
		
		if (!todo)
			continue;

		kref_get(&device->kref);
		rcu_read_unlock();
		do_device_work(device, todo);
		kref_put(&device->kref, drbd_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}

static void do_unqueued_resource_work(struct drbd_resource *resource)
{
#ifdef _WIN32
	ULONG_PTR todo = get_work_bits(DRBD_RESOURCE_WORK_MASK, &resource->flags);
#else
	unsigned long todo = get_work_bits(DRBD_RESOURCE_WORK_MASK, &resource->flags);
#endif
	

	if (test_bit(TRY_BECOME_UP_TO_DATE, &todo))
		try_become_up_to_date(resource);
}

static bool dequeue_work_batch(struct drbd_work_queue *queue, struct list_head *work_list)
{
	spin_lock_irq(&queue->q_lock);
	list_splice_tail_init(&queue->q, work_list);
	spin_unlock_irq(&queue->q_lock);
	return !list_empty(work_list);
}

static struct drbd_request *__next_request_for_connection(
		struct drbd_connection *connection, struct drbd_request *r)
{
#ifdef _WIN32    
#ifdef _WIN32_NETQUEUED_LOG
    r = list_prepare_entry(struct drbd_request, r, &connection->resource->net_queued_log, nq_requests);
#else
    r = list_prepare_entry(struct drbd_request, r, &connection->resource->transfer_log, tl_requests);
#endif
#else
	r = list_prepare_entry(r, &connection->resource->transfer_log, tl_requests);
#endif

#ifdef _WIN32 
#ifdef _WIN32_NETQUEUED_LOG
	list_for_each_entry_continue(struct drbd_request, r, &connection->resource->net_queued_log, nq_requests) {
#else
	list_for_each_entry_continue(struct drbd_request, r, &connection->resource->transfer_log, tl_requests) {
#endif
#else
	list_for_each_entry_continue(r, &connection->resource->transfer_log, tl_requests) {
#endif
		int vnr = r->device->vnr;
		struct drbd_peer_device *peer_device = conn_peer_device(connection, vnr);
		unsigned s = drbd_req_state_by_peer_device(r, peer_device);
		if (!(s & RQ_NET_QUEUED))
			continue;
		return r;
	}
	return NULL;
}

/* holds req_lock on entry, may give up and reaquire temporarily */
static struct drbd_request *tl_mark_for_resend_by_connection(struct drbd_connection *connection)
{
	struct bio_and_error m;
#ifdef _WIN32
	struct drbd_request *req = NULL;
#else
	struct drbd_request *req;
#endif
	struct drbd_request *req_oldest = NULL;
	struct drbd_request *tmp = NULL;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	unsigned s;

	/* In the unlikely case that we need to give up the spinlock
	 * temporarily below, we need to restart the loop, as the request
	 * pointer, or any next pointers, may become invalid meanwhile.
	 *
	 * We can restart from a known safe position, though:
	 * the last request we successfully marked for resend,
	 * without it disappearing.
	 */
restart:
#ifdef _WIN32
    req = list_prepare_entry(struct drbd_request, tmp, &connection->resource->transfer_log, tl_requests);
#else
	req = list_prepare_entry(tmp, &connection->resource->transfer_log, tl_requests);
#endif

#ifdef _WIN32
	list_for_each_entry_continue(struct drbd_request, req, &connection->resource->transfer_log, tl_requests) {
#else
	list_for_each_entry_continue(req, &connection->resource->transfer_log, tl_requests) {
#endif
		/* potentially needed in complete_master_bio below */
		device = req->device;
		peer_device = conn_peer_device(connection, device->vnr);
		s = drbd_req_state_by_peer_device(req, peer_device);

		if (!(s & RQ_NET_MASK))
			continue;

		/* if it is marked QUEUED, it can not be an old one,
		 * so we can stop marking for RESEND here. */
		if (s & RQ_NET_QUEUED)
			break;

		/* Skip old requests which are uninteresting for this connection.
		 * Could happen, if this connection was restarted,
		 * while some other connection was lagging seriously. */
		if (s & RQ_NET_DONE)
			continue;

		/* FIXME what about QUEUE_FOR_SEND_OOS?
		 * Is it even possible to encounter those here?
		 * It should not.
		 */
		if (drbd_req_is_write(req))
			expect(peer_device, s & RQ_EXP_BARR_ACK);

		__req_mod(req, RESEND, peer_device, &m);

		/* If this is now RQ_NET_PENDING (it should), it won't
		 * disappear, even if we give up the spinlock below. */
		if (drbd_req_state_by_peer_device(req, peer_device) & RQ_NET_PENDING)
			tmp = req;

		/* We crunch through a potentially very long list, so be nice
		 * and eventually temporarily give up the spinlock/re-enable
		 * interrupts.
		 *
		 * Also, in the very unlikely case that trying to mark it for
		 * RESEND actually caused this request to be finished off, we
		 * complete the master bio, outside of the lock. */
		if (m.bio || need_resched()) {
			spin_unlock_irq(&connection->resource->req_lock);
			if (m.bio)
#ifdef _WIN32
				complete_master_bio(device, &m, __func__, __LINE__ );
#else
				complete_master_bio(device, &m);
#endif
			cond_resched();
			spin_lock_irq(&connection->resource->req_lock);
			goto restart;
		}
		if (!req_oldest)
			req_oldest = req;
	}
	return req_oldest;
}

static struct drbd_request *tl_next_request_for_connection(struct drbd_connection *connection)
{
	if (connection->todo.req_next == TL_NEXT_REQUEST_RESEND)
		connection->todo.req_next = tl_mark_for_resend_by_connection(connection);

	else if (connection->todo.req_next == NULL)
		connection->todo.req_next = __next_request_for_connection(connection, NULL);

	connection->todo.req = connection->todo.req_next;

	/* advancement of todo.req_next happens in advance_conn_req_next(),
	 * called from mod_rq_state() */

	return connection->todo.req;
}

static void maybe_send_state_afer_ahead(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
#ifdef _WIN32
	idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else 
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		if (test_and_clear_bit(SEND_STATE_AFTER_AHEAD, &peer_device->flags)) {
			peer_device->todo.was_ahead = false;
			rcu_read_unlock();
			drbd_send_current_state(peer_device);
			rcu_read_lock();
		}
	}
	rcu_read_unlock();
}

/* This finds the next not yet processed request from
 * connection->resource->transfer_log.
 * It also moves all currently queued connection->sender_work
 * to connection->todo.work_list.
 */
static bool check_sender_todo(struct drbd_connection *connection)
{
	tl_next_request_for_connection(connection);

	/* we did lock_irq above already. */
	/* FIXME can we get rid of this additional lock? */
	spin_lock(&connection->sender_work.q_lock);
	list_splice_tail_init(&connection->sender_work.q, &connection->todo.work_list);
	spin_unlock(&connection->sender_work.q_lock);

	return connection->todo.req
#ifndef _WIN32
		|| need_unplug(connection)
#endif		
		|| !list_empty(&connection->todo.work_list);
}

static void wait_for_sender_todo(struct drbd_connection *connection)
{
#ifndef _WIN32
	DEFINE_WAIT(wait);
#endif
	struct net_conf *nc;
	int uncork, cork;
	bool got_something = 0;

	spin_lock_irq(&connection->resource->req_lock);
	got_something = check_sender_todo(connection);
	spin_unlock_irq(&connection->resource->req_lock);
	if (got_something)
		return;

	/* Still nothing to do?
	 * Maybe we still need to close the current epoch,
	 * even if no new requests are queued yet.
	 *
	 * Also, poke TCP, just in case.
	 * Then wait for new work (or signal). */
	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	uncork = nc ? nc->tcp_cork : 0;
	rcu_read_unlock();
	if (uncork)
		drbd_uncork(connection, DATA_STREAM);

	for (;;) {
		int send_barrier;
#ifndef _WIN32
		prepare_to_wait(&connection->sender_work.q_wait, &wait,
				TASK_INTERRUPTIBLE);
#endif
		spin_lock_irq(&connection->resource->req_lock);
		if (check_sender_todo(connection) || signal_pending(current)) {
			spin_unlock_irq(&connection->resource->req_lock);
			break;
		}

		/* We found nothing new to do, no to-be-communicated request,
		 * no other work item.  We may still need to close the last
		 * epoch.  Next incoming request epoch will be connection ->
		 * current transfer log epoch number.  If that is different
		 * from the epoch of the last request we communicated, it is
		 * safe to send the epoch separating barrier now.
		 */
		send_barrier =
			atomic_read(&connection->resource->current_tle_nr) !=
			connection->send.current_epoch_nr;
		spin_unlock_irq(&connection->resource->req_lock);

		if (send_barrier)
			maybe_send_barrier(connection,
					connection->send.current_epoch_nr + 1);

		if (test_and_clear_bit(SEND_STATE_AFTER_AHEAD_C, &connection->flags))
			maybe_send_state_afer_ahead(connection);

		/* drbd_send() may have called flush_signals() */
		if (get_t_state(&connection->sender) != RUNNING)
			break;

#ifdef _WIN32
		schedule(&connection->sender_work.q_wait, SENDER_SCHEDULE_TIMEOUT, __FUNCTION__, __LINE__); 
#else
		schedule();
#endif
		/* may be woken up for other things but new work, too,
		 * e.g. if the current epoch got closed.
		 * In which case we send the barrier above. */
	}
#ifndef _WIN32
	finish_wait(&connection->sender_work.q_wait, &wait);
#endif

	/* someone may have changed the config while we have been waiting above. */
#ifdef _WIN32
	rcu_read_lock_w32_inner();
#else
	rcu_read_lock();
#endif
	nc = rcu_dereference(connection->transport.net_conf);
	cork = nc ? nc->tcp_cork : 0;
	rcu_read_unlock();

	if (cork)
		drbd_cork(connection, DATA_STREAM);
	else if (!uncork)
		drbd_uncork(connection, DATA_STREAM);
}

static void re_init_if_first_write(struct drbd_connection *connection, unsigned int epoch)
{
	if (!connection->send.seen_any_write_yet) {
		connection->send.seen_any_write_yet = true;
		connection->send.current_epoch_nr = epoch;
		connection->send.current_epoch_writes = 0;
		connection->send.last_sent_barrier_jif = jiffies;
		connection->send.current_dagtag_sector =
			connection->resource->dagtag_sector - ((BIO_MAX_PAGES << PAGE_SHIFT) >> 9) - 1;
	}
}

static void maybe_send_barrier(struct drbd_connection *connection, unsigned int epoch)
{
	/* re-init if first write on this connection */
	if (!connection->send.seen_any_write_yet)
		return;
	if (connection->send.current_epoch_nr != (int)epoch) {
		if (connection->send.current_epoch_writes)
			drbd_send_barrier(connection);
		connection->send.current_epoch_nr = epoch;
	}
}

static int process_one_request(struct drbd_connection *connection)
{
	struct bio_and_error m;
	struct drbd_request *req = connection->todo.req;
	struct drbd_device *device = req->device;
	struct drbd_peer_device *peer_device =
			conn_peer_device(connection, device->vnr);
	unsigned s = drbd_req_state_by_peer_device(req, peer_device);
#ifndef _WIN32
	bool do_send_unplug = req->rq_state[0] & RQ_UNPLUG;
#endif
	int err;
	enum drbd_req_event what;

	req->pre_send_jif[peer_device->node_id] = jiffies;
	if (drbd_req_is_write(req)) {
		/* If a WRITE does not expect a barrier ack,
		 * we are supposed to only send an "out of sync" info packet */
		if (s & RQ_EXP_BARR_ACK) {
			u64 current_dagtag_sector =
				req->dagtag_sector - (req->i.size >> 9);

			re_init_if_first_write(connection, req->epoch);
			maybe_send_barrier(connection, req->epoch);
			if (current_dagtag_sector != connection->send.current_dagtag_sector)
				drbd_send_dagtag(connection, current_dagtag_sector);

			connection->send.current_epoch_writes++;
			connection->send.current_dagtag_sector = req->dagtag_sector;

			if (peer_device->todo.was_ahead) {
				clear_bit(SEND_STATE_AFTER_AHEAD, &peer_device->flags);
				peer_device->todo.was_ahead = false;
				drbd_send_current_state(peer_device);
			}

			err = drbd_send_dblock(peer_device, req);
			what = err ? SEND_FAILED : HANDED_OVER_TO_NETWORK;

#ifdef _WIN32
			// MODIFIED_BY_MANTECH DW-1237: data block has been sent(or failed), put request databuf ref.
			if (0 == atomic_dec(&req->req_databuf_ref) &&
				(req->rq_state[0] & RQ_LOCAL_COMPLETED))
			{
				kfree2(req->req_databuf);
			}
#endif

		} else {
			/* this time, no connection->send.current_epoch_writes++;
			 * If it was sent, it was the closing barrier for the last
			 * replicated epoch, before we went into AHEAD mode.
			 * No more barriers will be sent, until we leave AHEAD mode again. */
			maybe_send_barrier(connection, req->epoch);

			if (!peer_device->todo.was_ahead) {
				peer_device->todo.was_ahead = true;
				drbd_send_current_state(peer_device);
			}
			err = drbd_send_out_of_sync(peer_device, &req->i);
			what = OOS_HANDED_TO_NETWORK;
		}
	} else {
		maybe_send_barrier(connection, req->epoch);
#ifdef _WIN32
        err = drbd_send_drequest(peer_device, P_DATA_REQUEST,
            req->i.sector, req->i.size, (ULONG_PTR)req);
#else
		err = drbd_send_drequest(peer_device, P_DATA_REQUEST,
				req->i.sector, req->i.size, (unsigned long)req);
#endif
		what = err ? SEND_FAILED : HANDED_OVER_TO_NETWORK;
	}

	spin_lock_irq(&connection->resource->req_lock);
	__req_mod(req, what, peer_device, &m);

	/* As we hold the request lock anyways here,
	 * this is a convenient place to check for new things to do. */
	check_sender_todo(connection);

	spin_unlock_irq(&connection->resource->req_lock);

	if (m.bio)
#ifdef _WIN32
		complete_master_bio(device, &m, __func__, __LINE__ );
#else
		complete_master_bio(device, &m);
#endif

#ifndef _WIN32
	do_send_unplug = do_send_unplug && what == HANDED_OVER_TO_NETWORK;
	maybe_send_unplug_remote(connection, do_send_unplug);
#endif
	return err;
}

static int process_sender_todo(struct drbd_connection *connection)
{
	struct drbd_work *w = NULL;

	/* Process all currently pending work items,
	 * or requests from the transfer log.
	 *
	 * Right now, work items do not require any strict ordering wrt. the
	 * request stream, so lets just do simple interleaved processing.
	 *
	 * Stop processing as soon as an error is encountered.
	 */

	if (!connection->todo.req) {
#ifndef _WIN32
		update_sender_timing_details(connection, maybe_send_unplug_remote);
		maybe_send_unplug_remote(connection, false);
#endif
	}

	else if (list_empty(&connection->todo.work_list)) {
		int ret = 0;
		ret = process_one_request(connection);
		update_sender_timing_details(connection, process_one_request);
		return ret;
	}

	while (!list_empty(&connection->todo.work_list)) {
		int err;

		w = list_first_entry(&connection->todo.work_list, struct drbd_work, list);
		list_del_init(&w->list);
		update_sender_timing_details(connection, w->cb);
		err = w->cb(w, connection->cstate[NOW] < C_CONNECTED);
		if (err)
			return err;

		/* If we would need strict ordering for work items, we could
		 * add a dagtag member to struct drbd_work, and serialize based on that.
		 * && !dagtag_newer(connection->todo.req->dagtag_sector, w->dagtag_sector))
		 * to the following condition. */
		if (connection->todo.req) {
			update_sender_timing_details(connection, process_one_request);
			err = process_one_request(connection);
		}
		if (err)
			return err;
	}

	return 0;
}

int drbd_sender(struct drbd_thread *thi)
{
	struct drbd_connection *connection = thi->connection;
	struct drbd_work *w;
	struct drbd_peer_device *peer_device;
	int vnr;
	int err;

	/* Should we drop this? Or reset even more stuff? */
	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		peer_device->send_cnt = 0;
		peer_device->recv_cnt = 0;
	}
	rcu_read_unlock();

	while (get_t_state(thi) == RUNNING) {
		drbd_thread_current_set_cpu(thi);
		if (list_empty(&connection->todo.work_list) &&
		    connection->todo.req == NULL) {
			update_sender_timing_details(connection, wait_for_sender_todo);
			wait_for_sender_todo(connection);
		}

		if (signal_pending(current)) {
			flush_signals(current);
			if (get_t_state(thi) == RUNNING) {
				drbd_warn(connection, "Sender got an unexpected signal\n");
				continue;
			}
			break;
		}

		if (get_t_state(thi) != RUNNING)
			break;

		err = process_sender_todo(connection);
		if (err)
			change_cstate_ex(connection, C_NETWORK_FAILURE, CS_HARD);
	}

	/* cleanup all currently unprocessed requests */
	if (!connection->todo.req) {
		spin_lock_irq(&connection->resource->req_lock);
		tl_next_request_for_connection(connection);
		spin_unlock_irq(&connection->resource->req_lock);
	}
	while (connection->todo.req) {
		struct bio_and_error m;
		struct drbd_request *req = connection->todo.req;
		struct drbd_device *device = req->device;
		peer_device = conn_peer_device(connection, device->vnr);

		spin_lock_irq(&connection->resource->req_lock);
		tl_next_request_for_connection(connection);
		__req_mod(req, SEND_CANCELED, peer_device, &m);
		spin_unlock_irq(&connection->resource->req_lock);
		if (m.bio)
#ifdef _WIN32
			complete_master_bio(device, &m, __func__, __LINE__ );
#else
			complete_master_bio(device, &m);
#endif
	}

	/* cancel all still pending works */
	do {
		while (!list_empty(&connection->todo.work_list)) {
			w = list_first_entry(&connection->todo.work_list, struct drbd_work, list);
			list_del_init(&w->list);
			w->cb(w, 1);
		}
		dequeue_work_batch(&connection->sender_work, &connection->todo.work_list);
	} while (!list_empty(&connection->todo.work_list));

	return 0;
}

int drbd_worker(struct drbd_thread *thi)
{
	LIST_HEAD(work_list);
	struct drbd_resource *resource = thi->resource;
	struct drbd_work *w;
	bool is_null_callback_print = false;

	while (get_t_state(thi) == RUNNING) {
		drbd_thread_current_set_cpu(thi);

		if (list_empty(&work_list)) {
			bool w, r, d, p;

			update_worker_timing_details(resource, dequeue_work_batch);
#ifdef _WIN32
            int sig;
			wait_event_interruptible(sig, resource->work.q_wait,
				(w = dequeue_work_batch(&resource->work, &work_list),
				r = test_and_clear_bit(RESOURCE_WORK_PENDING, &resource->flags),
				d = test_and_clear_bit(DEVICE_WORK_PENDING, &resource->flags),
				p = test_and_clear_bit(PEER_DEVICE_WORK_PENDING, &resource->flags),
				w || r || d || p));
#else
			wait_event_interruptible(resource->work.q_wait,
				(w = dequeue_work_batch(&resource->work, &work_list),
				 r = test_and_clear_bit(RESOURCE_WORK_PENDING, &resource->flags),
				 d = test_and_clear_bit(DEVICE_WORK_PENDING, &resource->flags),
				 p = test_and_clear_bit(PEER_DEVICE_WORK_PENDING, &resource->flags),
				 w || r || d || p));

#endif
			if (p) {
				update_worker_timing_details(resource, do_unqueued_peer_device_work);
				do_unqueued_peer_device_work(resource);
			}

			if (d) {
				update_worker_timing_details(resource, do_unqueued_device_work);
				do_unqueued_device_work(resource);
			}
			if (r) {
				update_worker_timing_details(resource, do_unqueued_resource_work);
				do_unqueued_resource_work(resource);
			}
		}

		if (signal_pending(current)) {
			flush_signals(current);
			if (get_t_state(thi) == RUNNING) {
				drbd_warn(resource, "Worker got an unexpected signal\n");
				continue;
			}
			break;
		}

		if (get_t_state(thi) != RUNNING)
			break;

		is_null_callback_print = false;

		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct drbd_work, list);
			list_del_init(&w->list);
			update_worker_timing_details(resource, w->cb);
#ifdef _WIN32 // DW- fix callback pointer's NULL case
			if (w->cb != NULL) {
				w->cb(w, 0);
			}
			else {
				// DW-1953 logs are printed only once per work_list.
				if (is_null_callback_print == false) {
					// DW-1953 do not use "break" because you must call a non-null callback.
					drbd_warn(resource, "worker got an null-callback list. resource name (%s), twopc_work(%p) : w(%p)\n", resource->name, &(resource->twopc_work), w);
					is_null_callback_print = true;
				}
			}
#else
			w->cb(w, 0);
#endif
		}
	}

	do {
		if (test_and_clear_bit(RESOURCE_WORK_PENDING, &resource->flags)) {
			update_worker_timing_details(resource, do_unqueued_resource_work);
			do_unqueued_resource_work(resource);
		}
		if (test_and_clear_bit(DEVICE_WORK_PENDING, &resource->flags)) {
			update_worker_timing_details(resource, do_unqueued_device_work);
			do_unqueued_device_work(resource);
		}
		if (test_and_clear_bit(PEER_DEVICE_WORK_PENDING, &resource->flags)) {
			update_worker_timing_details(resource, do_unqueued_peer_device_work);
			do_unqueued_peer_device_work(resource);
		}
		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct drbd_work, list);
			list_del_init(&w->list);
			update_worker_timing_details(resource, w->cb);
			w->cb(w, 1);
		}
		dequeue_work_batch(&resource->work, &work_list);
	} while (!list_empty(&work_list) ||
		 test_bit(DEVICE_WORK_PENDING, &resource->flags) ||
		 test_bit(PEER_DEVICE_WORK_PENDING, &resource->flags));

	return 0;
}

/* DW-1755 When a disk error occurs, 
 * transfers the event to the work thread queue.
 */
static void process_io_error(struct bio *bio, struct drbd_device *device, unsigned char disk_type, int error)
{
	drbd_queue_notify_io_error_occurred(device, disk_type, (bio->bi_rw & WRITE) ? WRITE : READ, error, bio->bi_sector, bio->bi_size);
}

