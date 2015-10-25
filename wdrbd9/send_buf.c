#include "drbd_windows.h"
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

#define MAX_ONETIME_SEND_BUF	(64*1024) // (1024*1024*10) // 10MB

ring_buffer *create_ring_buffer(char *name, unsigned int length)
{
	ring_buffer *ring;
	int sz = sizeof(*ring) + length;

	if (length == 0 || length > DRBD_SNDBUF_SIZE_MAX)
	{
		WDRBD_ERROR("bab(%s) size(%d) is bad. max(%d)\n", name, length, DRBD_SNDBUF_SIZE_MAX);
		return NULL;
	}

	ring = (ring_buffer *) ExAllocatePoolWithTag(NonPagedPool, sz, 'WD73');
	if (ring)
	{
		ring->mem = (char*) (ring + 1);
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
		WDRBD_INFO("bab(%s) size(%d)\n", name, length);
#ifdef SENDBUF_TRACE
		INIT_LIST_HEAD(&ring->send_req_list);
#endif
		ring->static_big_buf = (char *) ExAllocatePoolWithTag(NonPagedPool, MAX_ONETIME_SEND_BUF, 'WD74');
		if (!ring->static_big_buf)
		{
			ExFreePool(ring);
			WDRBD_ERROR("bab(%s): alloc(%d) failed.\n", name, MAX_ONETIME_SEND_BUF);
			return NULL;
		}
	}
	else
	{
		WDRBD_ERROR("bab(%s):alloc(%u) failed\n", name, sz);
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

int send_buf(struct drbd_transport *transport, enum drbd_stream stream, struct socket *socket, PVOID buf, ULONG size)
{
	// struct drbd_connection *connection = container_of(transport, struct drbd_connection, transport);
	struct _buffering_attr *buffering_attr = &socket->buffering_attr;
	ULONG timeout = socket->sk_linux_attr->sk_sndtimeo;

#if 0 //WDRBD_TRACE_IP4
	{
		extern char * get_ip4(char *buf, struct sockaddr_in *sockaddr);
		char sbuf[64], dbuf[64];
		DbgPrint("WDRBD_TEST: send_buf:(%s:%d) %s -> %s\n",
			socket->name, size,
			get_ip4(sbuf, &list_first_entry_or_null(&transport->paths, struct drbd_path, list)->my_addr),
			get_ip4(dbuf, &list_first_entry_or_null(&transport->paths, struct drbd_path, list)->peer_addr));
	}
#endif

	if (buffering_attr->send_buf_thread_handle == NULL || buffering_attr->bab == NULL)
	{
		static int tmp = 0;
		if (tmp++ < 500) // V9_CHECK!!
		{
			WDRBD_TRACE_SB("send buf: disabled. sb thread=%p bab=%p (tmp:%d)\n", buffering_attr->send_buf_thread_handle, buffering_attr->bab, tmp);
		}
		return Send(socket->sk, buf, size, 0, timeout, NULL);
	}

	unsigned long long  tmp = (long long) buffering_attr->bab->length * 99;
	int highwater = (unsigned long long)tmp / 100; // 99% // refacto: global
	int data_sz = get_ring_buffer_size(buffering_attr->bab);

	if ((data_sz + size) > highwater)
	{
		int retry = 0;
		while (1)
		{
			// TODO: 출력부하 무시, 안정화 이후 제거
			WDRBD_WARN("bab(%s) overflow. retry(%d). bab:total(%d) queued(%d) requested(%d) highwater(%d)", buffering_attr->bab->name, retry, buffering_attr->bab->length, data_sz, size, highwater);

			LARGE_INTEGER	nWaitTime;
			KTIMER ktimer;
			nWaitTime = RtlConvertLongToLargeInteger(-1 * 1000 * socket->sk_linux_attr->sk_sndtimeo * 10);
			KeInitializeTimer(&ktimer);
			KeSetTimerEx(&ktimer, nWaitTime, 0, NULL);
			KeWaitForSingleObject(&ktimer, Executive, KernelMode, FALSE, NULL);
			WDRBD_WARN("time done!\n");

			// V8: if (we_should_drop_the_connection(tconn, socket))
			if (drbd_stream_send_timed_out(transport, stream)) // V9 
			{
				WDRBD_ERROR("bab(%s) we_should_drop_the_connection.\n", buffering_attr->bab->name);
				return -EAGAIN;
			}

			data_sz = get_ring_buffer_size(buffering_attr->bab);
			if ((data_sz + size) > highwater)
			{
				retry++;
				continue;
			}
			else
			{
				// TODO: 출력부하 무시, 안정화 이후 제거
				WDRBD_WARN("bab(%s) overflow resolved at loop %d. bab:total(%d) queued(%d) requested(%d) highwater(%d)\n", buffering_attr->bab->name, retry, buffering_attr->bab->length, data_sz, size, highwater);
				goto buffering;
			}
		}
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
	write_ring_buffer(buffering_attr->bab, buf, size);
	KeSetEvent(&buffering_attr->ring_buf_event, 0, FALSE);
	return size;
}

int do_send(PWSK_SOCKET sock, struct ring_buffer *bab, int timeout, KEVENT *send_buf_kill_event)
{
	int ret = 0, bab_peek = 0;

	if (bab == NULL)
	{
		WDRBD_ERROR("bab is null.\n");
		return 0;
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
			if (((pos = strlen(sbuf)) + 10) > 1024)
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
		ret = Send(sock, bab->static_big_buf, tx_sz, 0, timeout, send_buf_kill_event);
		if (ret == -EINTR)
		{
			return -EINTR;
		}

		if (ret != tx_sz)
		{
			WDRBD_WARN("count mismatch. request=(%d) sent=(%d)\n", tx_sz, ret);
			// will be recovered by upper drbd protocol 
		}
	}
	return 0;
}

//
// send buffring thread
//

VOID NTAPI send_buf_thread(PVOID p)
{
	struct _buffering_attr *buffering_attr = (struct _buffering_attr *)p;
	struct socket *socket = container_of(buffering_attr, struct socket, buffering_attr);
	LONG readcount;
	NTSTATUS status;
	LARGE_INTEGER nWaitTime;
	LARGE_INTEGER *pTime;

	KeSetEvent(&buffering_attr->send_buf_thr_start_event, 0, FALSE);
	nWaitTime = RtlConvertLongToLargeInteger(-10 * 1000 * 1000 * 10);
	pTime = &nWaitTime;

#define MAX_EVT		2
	PVOID waitObjects[MAX_EVT];
	waitObjects[0] = &buffering_attr->send_buf_kill_event;
	waitObjects[1] = &buffering_attr->ring_buf_event;

	while (TRUE)
	{
		status = KeWaitForMultipleObjects(MAX_EVT, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);
		switch (status)
		{
		case STATUS_TIMEOUT:
			break;

		case STATUS_WAIT_0:
			WDRBD_INFO("response kill-ack-event\n");
			goto done;

		case (STATUS_WAIT_0 + 1) :
			if (do_send(socket->sk, buffering_attr->bab, socket->sk_linux_attr->sk_sndtimeo, &buffering_attr->send_buf_kill_event) == -EINTR)
			{
				goto done;
			}
			break;

		default:
			WDRBD_ERROR("unexpected wakwup case(0x%x). ignore.\n", status);
		}
	}

done:
	KeSetEvent(&buffering_attr->send_buf_killack_event, 0, FALSE);
	WDRBD_INFO("sendbuf thread done.!!\n");
	PsTerminateSystemThread(STATUS_SUCCESS);
}

#endif // _WIN32_SEND_BUFFING