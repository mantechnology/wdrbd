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

#define MAX_ONETIME_SEND_BUF	(1024*1024*10) // 10MB //(64*1024) // 64K // (1024*1024*10) // 10MB

ring_buffer *create_ring_buffer(char *name, unsigned int length)
{
	ring_buffer *ring;
	int sz = sizeof(*ring) + length;

	if (length == 0 || length > DRBD_SNDBUF_SIZE_MAX)
	{
		WDRBD_ERROR("bab(%s) size(%d) is bad. max(%d)\n", name, length, DRBD_SNDBUF_SIZE_MAX);
		return NULL;
	}

	ring = (ring_buffer *) ExAllocatePoolWithTag(NonPagedPool, sz, '37DW');
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
		//WDRBD_INFO("bab(%s) size(%d)\n", name, length);
#ifdef SENDBUF_TRACE
		INIT_LIST_HEAD(&ring->send_req_list);
#endif
		ring->static_big_buf = (char *) ExAllocatePoolWithTag(NonPagedPool, MAX_ONETIME_SEND_BUF, '47DW');
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
			kfree(ring->static_big_buf);
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

int write_ring_buffer(struct drbd_transport *transport, enum drbd_stream stream, ring_buffer *ring, const char *data, int len, int highwater, int retry)
{
	unsigned int remain;
	int ringbuf_size = 0;
	LARGE_INTEGER	Interval;
	Interval.QuadPart = (-1 * 20 * 10000);   // wait 20ms relative

	EnterCriticalSection(&ring->cs);

	ringbuf_size = (ring->write_pos - ring->read_pos + ring->length) % ring->length;

	if ((ringbuf_size + len) > highwater) {

		LeaveCriticalSection(&ring->cs);
		while (!drbd_stream_send_timed_out(transport, stream)) {
			int loop = 0;
			for (loop = 0; loop < retry; loop++) {
				KeDelayExecutionThread(KernelMode, FALSE, &Interval);
				//KTIMER ktimer;
				//KeInitializeTimer(&ktimer);
				//KeSetTimerEx(&ktimer, Interval, 0, NULL);
				//KeWaitForSingleObject(&ktimer, Executive, KernelMode, FALSE, NULL);
				EnterCriticalSection(&ring->cs);
				ringbuf_size = (ring->write_pos - ring->read_pos + ring->length) % ring->length;
				if ((ringbuf_size + len) > highwater) {
				} else {
					goto $GO_BUFFERING;
				}
				LeaveCriticalSection(&ring->cs);
			}
		}
		
		return -EAGAIN;
	}

$GO_BUFFERING:
	////////////////////////////////////////////////////////////////////////////////
	remain = (ring->read_pos - ring->write_pos - 1 + ring->length) % ring->length;
	if (remain < len) {
		len = remain;
	}

	if (len > 0) {
		remain = ring->length - ring->write_pos;
		if (remain < len) {
			memcpy(ring->mem + (ring->write_pos), data, remain);
			memcpy(ring->mem, data + remain, len - remain);
		} else {
			memcpy(ring->mem + ring->write_pos, data, len);
		}

		ring->write_pos += len;
		ring->write_pos %= ring->length;
	}
	else {
		WDRBD_ERROR("unexpected bab case\n");
		BUG();
	}

	ring->que++;
	ring->seq++;
	ring->sk_wmem_queued = (ring->write_pos - ring->read_pos + ring->length) % ring->length;

	LeaveCriticalSection(&ring->cs);

	return len;
}

unsigned long read_ring_buffer(IN ring_buffer *ring, OUT char *data, OUT unsigned int* pLen)
{
	unsigned int remain;
	unsigned int ringbuf_size = 0;
	unsigned int tx_sz = 0;

	EnterCriticalSection(&ring->cs);
	ringbuf_size = (ring->write_pos - ring->read_pos + ring->length) % ring->length;
	
	if (ringbuf_size == 0) {
		LeaveCriticalSection(&ring->cs);
		return 0;
	}
 
	tx_sz = (ringbuf_size > MAX_ONETIME_SEND_BUF) ? MAX_ONETIME_SEND_BUF : ringbuf_size;

	remain = ring->length - ring->read_pos;
	if (remain < tx_sz) {
		memcpy(data, ring->mem + ring->read_pos, remain);
		memcpy(data + remain, ring->mem, tx_sz - remain);
	}
	else {
		memcpy(data, ring->mem + ring->read_pos, tx_sz);
	}

	ring->read_pos += tx_sz;
	ring->read_pos %= ring->length;
	ring->sk_wmem_queued = (ring->write_pos - ring->read_pos + ring->length) % ring->length;

	*pLen = tx_sz;

	LeaveCriticalSection(&ring->cs);
	
	return 1;

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
		return Send(socket->sk, buf, size, 0, timeout, NULL, transport, stream);
	}

	unsigned long long  tmp = (long long)buffering_attr->bab->length * 99;
	int highwater = (unsigned long long)tmp / 100; // 99% // refacto: global
	// 기존에 비해 buffer write time 대기시간을 줄이고 재시도 횟수를 늘려 송신버퍼링 타임아웃 설정에 맞춤.(성능 관련 튜닝 포인트)
	int retry = socket->sk_linux_attr->sk_sndtimeo / 20; //retry default count : 6000/20 = 300 => write buffer delay time : 20ms => 300*20ms = 6sec
#if 0
	int data_sz = get_ring_buffer_size(buffering_attr->bab);

	if ((data_sz + size) > highwater)
	{
		int ko_retry = 0;
		while (!drbd_stream_send_timed_out(transport, stream))
		{
			LARGE_INTEGER	nWaitTime;
			KTIMER ktimer;
			int retry;
			int loop;
			nWaitTime = RtlConvertLongToLargeInteger(-1 * 100 * 1000 * 10); // unit 0.1 sec
			retry = socket->sk_linux_attr->sk_sndtimeo / 100; // unit 0.1 sec //TODO: check min/max value?

			// TODO: 출력부하 무시, 안정화 이후 제거
			WDRBD_WARN("bab(%s) OV. ko_retry(%d). bab:total(%d) queued(%d) requested(%d) highwater(%d) peek tx(%d)",
				buffering_attr->bab->name, ko_retry, buffering_attr->bab->length, data_sz, size, highwater, retry);

			for (loop = 0; loop < retry; loop++)
			{
				KTIMER ktimer;
				KeInitializeTimer(&ktimer);
				KeSetTimerEx(&ktimer, nWaitTime, 0, NULL);
				KeWaitForSingleObject(&ktimer, Executive, KernelMode, FALSE, NULL);
				data_sz = get_ring_buffer_size(buffering_attr->bab);
				if ((data_sz + size) > highwater)
				{
					continue;
				}
				else
				{
					// TODO: 출력부하 무시, 안정화 이후 제거
					WDRBD_WARN("bab(%s) OV resolved at loop %d. bab:total(%d) queued(%d) requested(%d) highwater(%d)\n", buffering_attr->bab->name, retry, buffering_attr->bab->length, data_sz, size, highwater);
					goto buffering;
				}
			}
		}
		WDRBD_ERROR("bab(%s) we_should_drop_the_connection. timeout!\n", buffering_attr->bab->name);
		return -EAGAIN;
	}
#endif
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

//buffering:
	//write_ring_buffer(buffering_attr->bab, buf, size);

	size = write_ring_buffer(transport, stream, buffering_attr->bab, buf, size, highwater, retry);

	KeSetEvent(&buffering_attr->ring_buf_event, 0, FALSE);
	return size;

}

int do_send(PIRP pReuseIrp, PWSK_SOCKET sock, struct ring_buffer *bab, int timeout, KEVENT *send_buf_kill_event)
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
		unsigned int tx_sz = 0;

		txloop++;
		
		if (!read_ring_buffer(bab, bab->static_big_buf, &tx_sz)) {
			break;
		}
		//ret = Send(sock, bab->static_big_buf, tx_sz, 0, timeout, send_buf_kill_event, NULL, 0);
		ret = SendEx(pReuseIrp, sock, bab->static_big_buf, tx_sz, 0, NULL, 0);
		if (ret == -EINTR)
		{
			ret = -EINTR;
			break;
		}

		if (ret != tx_sz)
		{
			ret = 0;
			if (ret < 0)
			{
				WDRBD_WARN("Send Error(%d)\n", ret);
				break;
			}
			else
			{
				WDRBD_WARN("Tx mismatch. req(%d) sent(%d)\n", tx_sz, ret);
				// will be recovered by upper drbd protocol 
			}
		}
	}

	return ret;
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

	//KeSetPriorityThread(KeGetCurrentThread(), HIGH_PRIORITY);
	//WDRBD_INFO("start send_buf_thread\n");
	KeSetEvent(&buffering_attr->send_buf_thr_start_event, 0, FALSE);
	nWaitTime = RtlConvertLongToLargeInteger(-10 * 1000 * 1000 * 10);
	pTime = &nWaitTime;

#define MAX_EVT		2
	PVOID waitObjects[MAX_EVT];
	waitObjects[0] = &buffering_attr->send_buf_kill_event;
	waitObjects[1] = &buffering_attr->ring_buf_event;

	// 패킷을 한번에 하나씩만 보내는 구조이므로, Irp 재사용 하여 중복되는 Irp 할당/해제 코드를 개선.
	PIRP		pReuseIrp = IoAllocateIrp(1, FALSE);
	if (pReuseIrp == NULL) {
		WDRBD_ERROR("WSK alloc. reuse Irp is NULL.\n");
		return;
	}

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
			if (do_send(pReuseIrp , socket->sk, buffering_attr->bab, socket->sk_linux_attr->sk_sndtimeo, &buffering_attr->send_buf_kill_event) == -EINTR)
			{
				goto done;
			}
			break;

		default:
			WDRBD_ERROR("unexpected wakwup case(0x%x). ignore.\n", status);
		}
	}

done:

	IoFreeIrp(pReuseIrp);

	WDRBD_INFO("send_buf_killack_event!\n");
	KeSetEvent(&buffering_attr->send_buf_killack_event, 0, FALSE);
	WDRBD_INFO("sendbuf thread done.!!\n");
	PsTerminateSystemThread(STATUS_SUCCESS);
}

#endif // _WIN32_SEND_BUFFING