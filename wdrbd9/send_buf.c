#include "drbd_windrv.h"
#include "wsk2.h"
#include "drbd_wingenl.h"
#include "linux-compat/drbd_endian.h"
#include "linux-compat/idr.h"
#include "disp.h" 
#include "drbd_int.h"
#include "send_buf.h"	
#include <linux/drbd_limits.h>

#ifdef _WIN32_SEND_BUFFING
#define EnterCriticalSection mutex_lock
#define LeaveCriticalSection mutex_unlock

#define MAX_ONETIME_SEND_BUF	(1024*1024*10) // 10MB

ring_buffer *create_ring_buffer(char *name, unsigned int length)
{
	ring_buffer *ring;
	int sz = sizeof(*ring) + length;

	if (length == 0 || length > DRBD_SNDBUF_SIZE_MAX)
	{
		printk(KERN_ERR "WDRBD_ERRO: [%s] bab(%s) size(%d) is bad. max(%d)\n", __FUNCTION__, name, length, DRBD_SNDBUF_SIZE_MAX);
		return NULL;
	}

	ring = (ring_buffer *) ExAllocatePoolWithTag(NonPagedPool, sz, 'WD73');
	if (ring)
	{
		ring->mem = (char*)(ring + 1);
		ring->length = length + 1;
		ring->read_pos = 0;
		ring->write_pos = 0;
		ring->que = 0;
		ring->deque = 0;
		ring->seq = 0;
		ring->name = name;

#ifdef _WIN32_TMP_DEBUG_MUTEX
		mutex_init(&ring->cs, "sendbuf");
#else
		mutex_init(&ring->cs);
#endif
		KeInitializeEvent(&ring->event, SynchronizationEvent, FALSE);
		printk(KERN_INFO "WDRBD_INFO: [%s] bab(%s) size(%d)\n", __FUNCTION__,  name, sz);
#ifdef SENDBUF_TRACE
		INIT_LIST_HEAD(&ring->send_req_list);
#endif
		ring->static_big_buf = (char *) ExAllocatePoolWithTag(NonPagedPool, MAX_ONETIME_SEND_BUF, 'WD74');
		if (!ring->static_big_buf)
		{
			ExFreePool(ring);
			printk(KERN_ERR "WDRBD_ERRO: [%s] bab(%s) static_big_buf alloc(%d) failed.\n", __FUNCTION__, name, MAX_ONETIME_SEND_BUF);
			return NULL;
		}
	}
	else
	{
		printk(KERN_ERR "WDRBD_ERRO: [%s] bab(%s) memory allocation failed. please check sndbuf-size %u(0x%X).\n", __FUNCTION__, name, sz, sz);
	}
	return ring;
}

void destroy_ring_buffer(ring_buffer *ring)
{
	if (ring)
	{
		ExFreePool(ring);
	}
}

unsigned int get_ring_buffer_size(ring_buffer *ring)
{
	unsigned int s;
	if (!ring)
	{
		return 0;
	}

	EnterCriticalSection(&ring->cs);
	s = (ring->write_pos - ring->read_pos + ring->length) % ring->length;
	LeaveCriticalSection(&ring->cs);

	return s;
}

void write_ring_buffer(ring_buffer *ring, const char *data, int len)
{
	unsigned int remain;

	EnterCriticalSection(&ring->cs);
	remain = (ring->read_pos - ring->write_pos - 1 + ring->length) % ring->length;
	if (remain < len)
	{
		len = remain;
	}

	if (len > 0)
	{
		remain = ring->length - ring->write_pos;
		if (remain < len)
		{
			memcpy(ring->mem + (ring->write_pos), data, remain);
			memcpy(ring->mem, data + remain, len - remain);
		}
		else
		{
			memcpy(ring->mem + ring->write_pos, data, len);
		}

		ring->write_pos += len;
		ring->write_pos %= ring->length;
	}
	else
	{
		WDRBD_ERROR("unexpected bab case\n");
		BUG();
	}

	ring->que++;
	ring->seq++;
	ring->sk_wmem_queued = (ring->write_pos - ring->read_pos + ring->length) % ring->length; 
	LeaveCriticalSection(&ring->cs);
}

void read_ring_buffer(ring_buffer *ring, char *data, int len)
{
	unsigned int remain;

	EnterCriticalSection(&ring->cs);
	remain = ring->length - ring->read_pos;
	if (remain < len)
	{
		memcpy(data, ring->mem + ring->read_pos, remain);
		memcpy(data + remain, ring->mem, len - remain);
	}
	else
		memcpy(data, ring->mem + ring->read_pos, len);

	ring->read_pos += len;
	ring->read_pos %= ring->length;
	ring->sk_wmem_queued = (ring->write_pos - ring->read_pos + ring->length) % ring->length;
	LeaveCriticalSection(&ring->cs);
}

LONG NTAPI send_buf(
	__in struct drbd_tconn *tconn,
	__in struct socket	*socket,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout
)
{
	struct ring_buffer *bab = socket->bab;
	PWSK_SOCKET	WskSocket = socket->sk;

	if (tconn->receiver.send_buf_thread_handle == NULL || bab == NULL)
	{
		return Send(WskSocket, Buffer, BufferSize, 0, Timeout);
	}

	int highwater = bab->length * 99 / 100; // 99%
	int data_sz = get_ring_buffer_size(bab);

	if ((data_sz + BufferSize) > highwater ) 
	{
		LARGE_INTEGER	nWaitTime;
		LARGE_INTEGER	*pTime = NULL;
		int i;
		int retry;

		if (Timeout <= 100)
		{
			Timeout = 6000; // MAX 6 sec
		}

		nWaitTime = RtlConvertLongToLargeInteger(-1 * 100 * 1000 * 10); // 0.1 sec
		pTime = &nWaitTime;
		retry = Timeout / 100; // unit: 0.1 sec

		for (i = 0; i < retry; i++)
		{
			KTIMER ktimer;
			KeInitializeTimer(&ktimer);
			KeSetTimerEx(&ktimer, nWaitTime, 0, NULL);
			KeWaitForSingleObject(&ktimer, Executive, KernelMode, FALSE, NULL);

			data_sz = get_ring_buffer_size(bab);
			if ((data_sz + BufferSize) > highwater)
			{
				// TODO: 출력부하 무시, 안정화 이후 제거
				//printk("WDRBD_WARN: [%s] bab(%s) overflow. retry(%d/%d). bab:total(%d) queued(%d) requested(%d) highwater(%d)", __FUNCTION__, bab->name, i, retry, bab->length, data_sz, BufferSize, highwater);
			}
			else
			{
				// TODO: 출력부하 무시, 안정화 이후 제거
				printk(KERN_WARNING "WDRBD_WARN: [%s] bab(%s) overflow resolved at loop(%d/%d).\n", __FUNCTION__, bab->name, i, retry);
				goto buffering;
			}
		}
		printk(KERN_ERR "WDRBD_ERRO: [%s] bab(%s) send timeout.\n", __FUNCTION__, bab->name);
		return -EAGAIN;
	}

#ifdef SENDBUF_TRACE
	struct _send_req *req = (struct _send_req *) kcalloc(1, sizeof(struct _send_req), 0, 'X2DW');
	if (!req)
	{
		WDRBD_ERROR("bab(%d) malloc failed!\n", sizeof(struct _send_req));
		return -EAGAIN;
	}
	req->who = sender_id;
	req->seq = bab->seq;
	req->buf = bab->write_pos * bab->frame_size;
	req->size = BufferSize;

	EnterCriticalSection(&bab->cs);
	list_add(&req->list, &bab->send_req_list);
	LeaveCriticalSection(&bab->cs);
#endif

buffering:
	write_ring_buffer(bab, Buffer, BufferSize); 
	KeSetEvent(&bab->event, 0, FALSE);
	return BufferSize;
}

//
// send buffring thread
//

void do_send(PWSK_SOCKET sock, struct ring_buffer *bab, int timeout)
{
	int ret = 0, bab_peek = 0;

	if (bab == NULL)
	{
		printk(KERN_ERR "WDRBD_ERRO: [%s] bab is null.\n", __FUNCTION__);
		return;
	}

#ifdef SENDBUF_TRACE 
	EnterCriticalSection(&bab->cs);
	if (!list_empty(&bab->send_req_list))
	{
		struct _send_req *req, *tmp;
		int accu = 0;
		int loop = 0;
		char sbuf[1024] = { 0 };
		int pos;
		int big = 0;

		list_for_each_entry_safe(struct _send_req, req, tmp, &bab->send_req_list, list)
		{
			loop++;
			if (((pos = strlen(sbuf)) + 10) > 1024 )
			{
				DbgPrint("SENDBUF_TRACE: who list(%d) too big. ignore!\n", loop); // ASYNC 일 경우 발생!
				list_del(&req->list);
				kfree(req);
				big = 1;
				break;
			}
			sprintf(sbuf + pos, "%1d(%d) ", req->who, req->size); // reverse list

			accu += req->size;
			list_del(&req->list);
			kfree(req);
		}

		if (!big)
		{
			DbgPrint("SENDBUF_TRACE: do_send: %4s req=%3d accu sz=%d list=%s\n", bab->name, loop, accu, sbuf);
		}
	}
	LeaveCriticalSection(&bab->cs);
#endif

	int txloop = 0;

	while (1)
	{ 
		int tx_sz = 0;

		txloop++;
		bab_peek = get_ring_buffer_size(bab);
		if (bab_peek == 0)
		{
			break;
		}

		if (bab_peek > MAX_ONETIME_SEND_BUF)
		{
			// data too big!
			tx_sz = MAX_ONETIME_SEND_BUF;
		}
		else
		{
			tx_sz = bab_peek;
		}

		read_ring_buffer(bab, bab->static_big_buf, tx_sz);
		ret = Send(sock, bab->static_big_buf, tx_sz, 0, timeout);
		
		if (ret != tx_sz)
		{
			printk(KERN_WARNING "WDRBD_WARN: [%s] count mismatch. request=(%d) sent=(%d)\n", __FUNCTION__, tx_sz, ret);
			// will be recovered by upper drbd protocol 
		}
	}
}

VOID NTAPI send_buf_thread(PVOID p)
{
	struct drbd_tconn *tconn = (struct drbd_tconn *)p;
	PWSK_SOCKET	Socket = (PWSK_SOCKET)tconn->data.socket->sk;
	LONG readcount;
	NTSTATUS status;
	LARGE_INTEGER nWaitTime;
	LARGE_INTEGER *pTime;

	KeSetEvent(&tconn->receiver.send_buf_thr_start_event, 0, FALSE);
	nWaitTime = RtlConvertLongToLargeInteger(-10 * 1000 * 1000 * 10);
	pTime = &nWaitTime;

	#define MAX_EVT		3

	PVOID waitObjects[MAX_EVT];
	waitObjects[0] = &tconn->receiver.send_buf_kill_event;
	waitObjects[1] = &tconn->data.socket->bab->event;
	waitObjects[2] = &tconn->meta.socket->bab->event;

	while (TRUE)
	{
		status = KeWaitForMultipleObjects(MAX_EVT, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);
		switch (status)
		{
		case STATUS_TIMEOUT:
			break;

		case STATUS_WAIT_0:
			printk(KERN_INFO "WDRBD_INFO: [%s] response kill ack event!\n", __FUNCTION__);
			KeSetEvent(&tconn->receiver.send_buf_killack_event, 0, FALSE);
			goto done;

		case (STATUS_WAIT_0 + 1):
			do_send(tconn->data.socket->sk, tconn->data.socket->bab, tconn->data.socket->sk_linux_attr->sk_sndtimeo);
			break;

		case (STATUS_WAIT_0 + 2):
			do_send(tconn->meta.socket->sk, tconn->meta.socket->bab, tconn->meta.socket->sk_linux_attr->sk_sndtimeo);
			break;

		default:
			printk(KERN_ERR "WDRBD_ERRO: [%s] unexpected wakwup case(0x%x). ignore.\n", __FUNCTION__, status);
		}
	}

done:
	printk(KERN_INFO "WDRBD_INFO: [%s] done.\n", __FUNCTION__);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

#endif // _WIN32_SEND_BUFFING