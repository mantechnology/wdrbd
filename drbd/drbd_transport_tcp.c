/*
   drbd_transport_tcp.c

   This file is part of DRBD.

   Copyright (C) 2014, LINBIT HA-Solutions GmbH.

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
#include <linux/drbd_genl_api.h>
#include <drbd_protocol.h>
#include <drbd_transport.h>
#include "drbd_wrappers.h"
#include <wsk2.h>
#include <linux-compat\drbd_endian.h>
#include <drbd_int.h>
#include <linux/drbd_limits.h>
#else
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/pkt_sched.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/highmem.h>
#include <linux/drbd_genl_api.h>
#include <drbd_protocol.h>
#include <drbd_transport.h>
#include "drbd_wrappers.h"
#endif

#ifndef _WIN32
MODULE_AUTHOR("Philipp Reisner <philipp.reisner@linbit.com>");
MODULE_AUTHOR("Lars Ellenberg <lars.ellenberg@linbit.com>");
MODULE_AUTHOR("Roland Kammerer <roland.kammerer@linbit.com>");
MODULE_DESCRIPTION("TCP (SDP, SSOCKS) transport layer for DRBD");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
#endif

struct buffer {
	void *base;
	void *pos;
};

#define DTT_CONNECTING 1

struct drbd_tcp_transport {
	struct drbd_transport transport; /* Must be first! */
	struct mutex paths_mutex;
#ifdef _WIN32_V9
	ULONG_PTR flags;
#else
	unsigned long flags;
#endif
	
	struct socket *stream[2];
	struct buffer rbuf[2];
};

struct dtt_listener {
	struct drbd_listener listener;
	void (*original_sk_state_change)(struct sock *sk);
	struct socket *s_listen;
#ifdef _WIN32_V9
	WSK_SOCKET* paccept_socket;
#endif
};

struct dtt_wait_first {
	wait_queue_head_t wait;
	struct drbd_transport *transport;
};

struct dtt_path {
	struct drbd_path path;

	struct drbd_waiter waiter;
	struct socket *socket;
	struct dtt_wait_first *first;
};

static int dtt_init(struct drbd_transport *transport);
static void dtt_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op);
static int dtt_connect(struct drbd_transport *transport);
static int dtt_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags);
static int dtt_recv_pages(struct drbd_transport *transport, struct drbd_page_chain_head *chain, size_t size);
static void dtt_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats);
static void dtt_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout);
static long dtt_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream);
static int dtt_send_page(struct drbd_transport *transport, enum drbd_stream, struct page *page,
		int offset, size_t size, unsigned msg_flags);
static int dtt_send_zc_bio(struct drbd_transport *, struct bio *bio);
static bool dtt_stream_ok(struct drbd_transport *transport, enum drbd_stream stream);
static bool dtt_hint(struct drbd_transport *transport, enum drbd_stream stream, enum drbd_tr_hints hint);
static void dtt_debugfs_show(struct drbd_transport *transport, struct seq_file *m);
static void dtt_update_congested(struct drbd_tcp_transport *tcp_transport);
static int dtt_add_path(struct drbd_transport *, struct drbd_path *path);
static int dtt_remove_path(struct drbd_transport *, struct drbd_path *);

#ifdef _WIN32_SEND_BUFFING
static bool dtt_start_send_buffring(struct drbd_transport *, int size);
static void dtt_stop_send_buffring(struct drbd_transport *);
#endif
static struct drbd_transport_class tcp_transport_class = {
	.name = "tcp",
	.instance_size = sizeof(struct drbd_tcp_transport),
	.path_instance_size = sizeof(struct dtt_path),
#ifndef _WIN32_V9 // tcp_transport_class 의 module 필드 어떻게 처리할지 검토필요. => module 필드 제거
	.module = THIS_MODULE,
#endif
	.init = dtt_init,
	.list = LIST_HEAD_INIT(tcp_transport_class.list),
};

static struct drbd_transport_ops dtt_ops = {
	.free = dtt_free,
	.connect = dtt_connect,
	.recv = dtt_recv,
	.recv_pages = dtt_recv_pages,
	.stats = dtt_stats,
	.set_rcvtimeo = dtt_set_rcvtimeo,
	.get_rcvtimeo = dtt_get_rcvtimeo,
	.send_page = dtt_send_page,
	.send_zc_bio = dtt_send_zc_bio,
	.stream_ok = dtt_stream_ok,
	.hint = dtt_hint,
	.debugfs_show = dtt_debugfs_show,
	.add_path = dtt_add_path,
	.remove_path = dtt_remove_path,
#ifdef _WIN32_SEND_BUFFING
	.start_send_buffring = dtt_start_send_buffring,
	.stop_send_buffring = dtt_stop_send_buffring,
#endif
};


static void dtt_nodelay(struct socket *socket)
{
	int val = 1;
#ifdef _WIN32_V9 // kernel_setsockopt linux kernel func. V9 포팅 필요.
	// nagle disable 은 기존 V8 방식으로 처리.
#else
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
#endif
}

int dtt_init(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;
#ifdef _WIN32_TMP_DEBUG_MUTEX
	mutex_init(&tcp_transport->paths_mutex, "paths_mutex");
#else
	mutex_init(&tcp_transport->paths_mutex);
#endif
	tcp_transport->transport.ops = &dtt_ops;
	tcp_transport->transport.class = &tcp_transport_class;
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
#ifdef _WIN32_V9 //적절한지 검토 필요. 할당이 실패했을 때 하단의 kfree 에서 제대로 해제가 되는지 확인 필요. => 해제 관련 문제 확인, 수정 완료.
		void *buffer = kzalloc(4096, GFP_KERNEL, '09DW');
		if (!buffer) {
			//DATA_STREAM 할당 실패 시 하단에서 해제 할 때 NULL 체크하기 위함. 
			// => DATA_STREAM 할당 성공, CONTROL_STREAM 할당 실패 했을 때에는 기존 코드가 문제 없다. 그러나 DATA_STREAM 할당 부터 실패 했을 경우엔 하단의 kfree 에서 잘못된 메모리가 넘겨질 가능성이 있다.
			tcp_transport->rbuf[i].base = NULL; // base가 NULL 초기화 보장이 되는지 모르겠다. 확실히 하기 위해.
			WDRBD_WARN("dtt_init kzalloc %s allocation fail\n", i ? "CONTROL_STREAM" : "DATA_STREAM" );
			goto fail;
		}
#else 
		void *buffer = (void *)__get_free_page(GFP_KERNEL);
		if (!buffer)
			goto fail;
#endif
		tcp_transport->rbuf[i].base = buffer;
		tcp_transport->rbuf[i].pos = buffer;
	}

	return 0;
fail:
#ifdef _WIN32_V9 // 
	kfree2(tcp_transport->rbuf[0].base);
#else
	free_page((unsigned long)tcp_transport->rbuf[0].base);
#endif
	return -ENOMEM;
}

static void dtt_free_one_sock(struct socket *socket)
{
	if (socket) {
		// 함수 scope 를 벗어난 rcu 해제... V9 포팅필요.
		// lock 획득이 제대로 되고 있는지...dtt_free_one_sock 호출 부 확인 필요 => rcu lock 에 대한 이해 부족으로 인한 주석.
		// synchronize_rcu_w32_wlock 방식의 V8 구현 반영 
		// synchronize_rcu(); // _WIN32_V9_PATCH_2_CHECK:JHKIM: 코멘트 풀여야함, 확인!
        // kmpak synchronize_rcu()를 대체할 만한 방식이 아직 마땅히 없어 임시로 5초 delay 사용
        //LARGE_INTEGER Interval = { .QuadPart = RELATIVE(SECONDS(3)) };
        //KeDelayExecutionThread(KernelMode, FALSE, &Interval);

		kernel_sock_shutdown(socket, SHUT_RDWR);
#ifdef _WIN32_SEND_BUFFING
        struct _buffering_attr *attr = &socket->buffering_attr;
        if (attr->send_buf_thread_handle)
        {
            KeSetEvent(&attr->send_buf_kill_event, 0, FALSE);
            KeWaitForSingleObject(&attr->send_buf_killack_event, Executive, KernelMode, FALSE, NULL);
            attr->send_buf_thread_handle = NULL;
        }
#endif
		sock_release(socket);
	}
}

static void dtt_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;
	struct drbd_path *drbd_path;
	/* free the socket specific stuff,
	 * mutexes are handled by caller */

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		if (tcp_transport->stream[i]) {
			dtt_free_one_sock(tcp_transport->stream[i]);
			tcp_transport->stream[i] = NULL;
		}
	}

	mutex_lock(&tcp_transport->paths_mutex);
#ifdef _WIN32_V9_PATCH_1
	list_for_each_entry(struct drbd_path, drbd_path, &transport->paths, list) {
#else
	list_for_each_entry(drbd_path, &transport->paths, list) {
#endif
		bool was_established = drbd_path->established;
		drbd_path->established = false;
		if (was_established)
			drbd_path_event(transport, drbd_path);
	}

	if (free_op == DESTROY_TRANSPORT) {
		struct drbd_path *tmp;

		for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
#ifdef _WIN32_V9 
			kfree((void *)tcp_transport->rbuf[i].base);
#else
			free_page((unsigned long)tcp_transport->rbuf[i].base);
#endif	
			tcp_transport->rbuf[i].base = NULL;
		}
#ifdef _WIN32_V9_PATCH_1
		list_for_each_entry_safe(struct drbd_path, drbd_path, tmp, &transport->paths, list) {
#else
		list_for_each_entry_safe(drbd_path, tmp, &transport->paths, list) {
#endif
			list_del(&drbd_path->list);
			kref_put(&drbd_path->kref, drbd_destroy_path);
		}
	}
	mutex_unlock(&tcp_transport->paths_mutex);
}

//한번 더 재 검토 필요.
static int _dtt_send(struct drbd_tcp_transport *tcp_transport, struct socket *socket,
		      void *buf, size_t size, unsigned msg_flags)
{
#ifdef _WIN32
	size_t iov_len = size;
	char* DataBuffer = (char*)buf;
#else
	struct kvec iov;
	struct msghdr msg;
#endif
	int rv, sent = 0;

	/* THINK  if (signal_pending) return ... ? */
#ifdef _WIN32 
	// not support. V8 기존 구현 유지.
#else
	iov.iov_base = buf;
	iov.iov_len  = size;

	msg.msg_name       = NULL;
	msg.msg_namelen    = 0;
	msg.msg_control    = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags      = msg_flags | MSG_NOSIGNAL;
#endif

	/* THINK  if (signal_pending) return ... ? */

	do {
		/* STRANGE
		 * tcp_sendmsg does _not_ use its size parameter at all ?
		 *
		 * -EAGAIN on timeout, -EINTR on signal.
		 */
/* THINK
 * do we need to block DRBD_SIG if sock == &meta.socket ??
 * otherwise wake_asender() might interrupt some send_*Ack !
 */
#ifdef _WIN32
#ifdef _WIN32_SEND_BUFFING
		 // _dtt_send 는 dtt_connect 시점의 dtt_send_first_packet 에 의해서만 사용!! 송신버퍼링 적용 직전 임!!!
		rv = Send(socket->sk, DataBuffer, iov_len, 0, socket->sk_linux_attr->sk_sndtimeo, NULL, NULL, 0);
#else
#if 1 // 최초 연결 단계에서만 사용! stream 방향이 불필요
		rv = Send(socket->sk, DataBuffer, iov_len, 0, socket->sk_linux_attr->sk_sndtimeo, NULL, &tcp_transport->transport, 0);
#else // old V8 org
		rv = Send(socket->sk, DataBuffer, iov_len, 0, socket->sk_linux_attr->sk_sndtimeo);
        WDRBD_TRACE_RS("kernel_sendmsg(%d) socket(0x%p) iov_len(%d)\n", rv, socket, iov_len);
#endif
#endif
#else
		rv = kernel_sendmsg(socket, &msg, &iov, 1, size);
		if (rv == -EAGAIN) {
			struct drbd_transport *transport = &tcp_transport->transport;
			enum drbd_stream stream =
				tcp_transport->stream[DATA_STREAM] == socket ?
					DATA_STREAM : CONTROL_STREAM;

			if (drbd_stream_send_timed_out(transport, stream))
				break;
			else
				continue;
		}
#endif
		if (rv == -EINTR) {
			flush_signals(current);
			rv = 0;
		}
		if (rv < 0)
			break;
		sent += rv;
#ifdef _WIN32 //기존 구현 유지
		DataBuffer += rv;
		iov_len -= rv;
#else
		iov.iov_base += rv;
		iov.iov_len  -= rv;
#endif
	} while (sent < size);

	if (rv <= 0)
		return rv;

	return sent;
}

static int dtt_recv_short(struct socket *socket, void *buf, size_t size, int flags)
{
#ifndef _WIN32
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = size,
	};
	struct msghdr msg = {
		.msg_flags = (flags ? flags : MSG_WAITALL | MSG_NOSIGNAL)
	};
#endif

#ifdef _WIN32
	flags = WSK_FLAG_WAITALL;
	return Receive(socket->sk, buf, size, flags, socket->sk_linux_attr->sk_rcvtimeo);
#else
	return kernel_recvmsg(socket, &msg, &iov, 1, size, msg.msg_flags);
#endif
}

// V8의 drbd_recv_short 가 dtt_recv , dtt_recv_short 로 대체 되었다. 추후 V8의 drbd_recv_short 를 참고하여 포팅한다.
static int dtt_recv(struct drbd_transport *transport, enum drbd_stream stream, void **buf, size_t size, int flags)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];
#ifdef _WIN32_V9
	UCHAR *buffer = NULL; 
#else
	void *buffer;
#endif
	int rv;

	if (flags & CALLER_BUFFER) {
		buffer = *buf;
		rv = dtt_recv_short(socket, buffer, size, flags & ~CALLER_BUFFER);
	} else if (flags & GROW_BUFFER) {
		TR_ASSERT(transport, *buf == tcp_transport->rbuf[stream].base);
		buffer = tcp_transport->rbuf[stream].pos;
#ifdef _WIN32_V9
        TR_ASSERT(transport, (buffer - (UCHAR*)*buf) + size <= PAGE_SIZE);//gcc void* 연산은 기본 1바이트 연산.
#else
		TR_ASSERT(transport, (buffer - *buf) + size <= PAGE_SIZE);
#endif
		rv = dtt_recv_short(socket, buffer, size, flags & ~GROW_BUFFER);
	} else {
		buffer = tcp_transport->rbuf[stream].base;

		rv = dtt_recv_short(socket, buffer, size, flags);
		if (rv > 0)
			*buf = buffer;
	}

	if (rv > 0)
		tcp_transport->rbuf[stream].pos = buffer + rv;

	return rv;
}

static int dtt_recv_pages(struct drbd_transport *transport, struct drbd_page_chain_head *chain, size_t size)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[DATA_STREAM];

// WIN32_V9_PATCH_1_CHECK: drbd_alloc_pages 변경부분 재 확인!dtt_recv_short(socket, page 확인!
	struct page *page;
	int err;

	drbd_alloc_page_chain(transport, chain, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
	page = chain->head;
	if (!page)
		return -ENOMEM;
#ifdef _WIN32
	// 기존 drbd_recv_all_warn 으로 처리되던 부분이 dtt_recv_short 로 간략하게 처리되고 있다.(drbd_recv_all_warn 내부로직이 복잡) 차이점에 대한 추후 분석 필요.
	err = dtt_recv_short(socket, page, size, 0); // *peer_req_databuf 포인터 버퍼 , size 값 유효성 디버깅 필요
	WDRBD_TRACE_RS("kernel_recvmsg(%d) socket(0x%p) size(%d) all_pages(0x%p)\n", err, socket, size, page);
    if (err < 0) {
		goto fail;
	}
#else
	page_chain_for_each(page) {
		size_t len = min_t(int, size, PAGE_SIZE);
		void *data = kmap(page);
		err = dtt_recv_short(socket, data, len, 0);
		kunmap(page);
		set_page_chain_offset(page, 0);
		set_page_chain_size(page, len);
		if (err < 0)
			goto fail;
		size -= len;
	}
#endif
	return 0;
fail:
	drbd_free_page_chain(transport, chain, 0);
#ifdef _WIN32_V9 //JHKIM: 이 함수에서 할당된 페이지 카운트는 free_page로 감산하고, 실제 할당된 메모리는 별도로 제거한다.
	kfree(page); // WIN32_V9_PATCH_2_CHECK!!! 
#endif
	return err;
}

static void dtt_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[DATA_STREAM];

	if (socket) {
#ifdef _WIN32_V9
		struct sock *sk = socket->sk_linux_attr;
#else
		struct sock *sk = socket->sk;
		struct tcp_sock *tp = tcp_sk(sk);

		stats->unread_received = tp->rcv_nxt - tp->copied_seq;
		stats->unacked_send = tp->write_seq - tp->snd_una;
#endif
		// TCP 전송 상태를 확인하여 부가 동작(dtt_hint)을 취할 수 있는 기능. => WSK 에 제공 기능이 없음. 현재로서는 포팅하지 않아도 무방. 추후 검토.
		// unread_received, unacked_send 정보 열람용. send_buffer_size, send_buffer_used 는 두 값을 비교하여 TCP 전송에 부하가 걸려있는 상태에 따라 dtt_hint 호출.
		stats->send_buffer_size = sk->sk_sndbuf;
#ifdef _WIN32_SEND_BUFFING
		{
			struct _buffering_attr *buffering_attr = &tcp_transport->stream[DATA_STREAM]->buffering_attr;
			struct ring_buffer *bab = buffering_attr->bab;

			if (bab)
			{
				stats->send_buffer_used = bab->sk_wmem_queued;
			}
			else
			{
				stats->send_buffer_used = 0; // JHKIM: don't know how to get WSK tx buffer usage yet. Ignore it.
			}
		}
#else
		stats->send_buffer_used = sk->sk_wmem_queued;
#endif
	}
}

static void dtt_setbufsize(struct socket *socket, unsigned int snd,
			   unsigned int rcv)
{
// [choi] V8 drbd_setbufsize 적용
#ifdef _WIN32
    if (snd) { 
        socket->sk_linux_attr->sk_sndbuf = snd;
    }
    else {  // kmpak temp.
        socket->sk_linux_attr->sk_sndbuf = 16384;
    }

    if (rcv) {
        ControlSocket(socket->sk, WskSetOption, SO_RCVBUF, SOL_SOCKET,
            sizeof(unsigned int), &rcv, 0, NULL, NULL);
    }
#else
	/* open coded SO_SNDBUF, SO_RCVBUF */
	if (snd) {
		socket->sk->sk_sndbuf = snd;
		socket->sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
	}
	if (rcv) {
		socket->sk->sk_rcvbuf = rcv;
		socket->sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
	}
#endif
}

static int dtt_try_connect(struct dtt_path *path, struct socket **ret_socket)
{
	struct drbd_transport *transport = path->waiter.transport;
	const char *what;
	struct socket *socket;
#ifdef _WIN32_V9
	struct sockaddr_storage_win my_addr, peer_addr;
	SOCKADDR_IN	LocalAddress = { 0 };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
#else
	struct sockaddr_storage my_addr, peer_addr;
#endif
	struct net_conf *nc;
	int err;
	int sndbuf_size, rcvbuf_size, connect_int;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EIO;
	}

#ifdef _WIN32_SEND_BUFFING
	if (nc->sndbuf_size < DRBD_SNDBUF_SIZE_DEF)
	{
		if (nc->sndbuf_size > 0)
		{
			tr_warn(transport, "sndbuf_size(%d) -> (%d)\n", nc->sndbuf_size, DRBD_SNDBUF_SIZE_DEF);
			nc->sndbuf_size = DRBD_SNDBUF_SIZE_DEF; // kmpak shared lock 잡아두고 이렇게 assign 하면 문제 없을까?
		}
	}
#endif

	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	connect_int = nc->connect_int;
	rcu_read_unlock();

	my_addr = path->path.my_addr;
	if (my_addr.ss_family == AF_INET6)
		((struct sockaddr_in6 *)&my_addr)->sin6_port = 0;
	else
		((struct sockaddr_in *)&my_addr)->sin_port = 0; /* AF_INET & AF_SCI */

	/* In some cases, the network stack can end up overwriting
	   peer_addr.ss_family, so use a copy here. */
	peer_addr = path->path.peer_addr;

	what = "sock_create_kern";
#ifdef _WIN32
	socket = kzalloc(sizeof(struct socket), 0, '42DW');
	if (!socket) {
		err = -ENOMEM; 
		goto out;
	}
	sprintf(socket->name, "conn_sock\0");
	socket->sk_linux_attr = 0;
	err = 0;
	
#ifdef _WIN32_V9_IPV6
	if (my_addr.ss_family == AF_INET6) {
		socket->sk = CreateSocket(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSK_FLAG_CONNECTION_SOCKET);
	} else {
		socket->sk = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSK_FLAG_CONNECTION_SOCKET);
	}
#else
	socket->sk = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSK_FLAG_CONNECTION_SOCKET);
#endif

	if (socket->sk == NULL) {
		err = -1;
		goto out;
	}

	socket->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '52DW');
	if (!socket->sk_linux_attr) {
		err = -ENOMEM;
		goto out;
	}
	socket->sk_linux_attr->sk_rcvtimeo =
		socket->sk_linux_attr->sk_sndtimeo = connect_int * HZ;
#else
	err = sock_create_kern(&init_net, my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &socket);
	if (err < 0) {
		socket = NULL;
		goto out;
	}

	socket->sk->sk_rcvtimeo =
	socket->sk->sk_sndtimeo = connect_int * HZ;
#endif
	dtt_setbufsize(socket, sndbuf_size, rcvbuf_size);

	/* explicitly bind to the configured IP as source IP
	*  for the outgoing connections.
	*  This is needed for multihomed hosts and to be
	*  able to use lo: interfaces for drbd.
	* Make sure to use 0 as port number, so linux selects
	*  a free one dynamically.
	*/
	what = "bind before connect";
#ifdef _WIN32
#ifdef _WIN32_V9_IPV6
	status = Bind(socket->sk, (PSOCKADDR)&my_addr);
#else
	LocalAddress.sin_family = AF_INET;
	LocalAddress.sin_addr.s_addr = INADDR_ANY;
	LocalAddress.sin_port = HTONS(0);

	status = Bind(socket->sk, (PSOCKADDR)&LocalAddress);
#endif
	if (!NT_SUCCESS(status)) {
		WDRBD_ERROR("Bind() failed with status 0x%08X \n", status);
		err = -EINVAL;
		goto out;
	}
#else
	err = socket->ops->bind(socket, (struct sockaddr *) &my_addr, path->path.my_addr_len);
#endif
	if (err < 0)
		goto out;

	/* connect may fail, peer not yet available.
	 * stay C_CONNECTING, don't go Disconnecting! */
	what = "connect";
#ifdef _WIN32
	status = Connect(socket->sk, (struct sockaddr *) &peer_addr);
	if (!NT_SUCCESS(status)) {
		err = status;
		switch (status) {
		case STATUS_CONNECTION_REFUSED: err = -ECONNREFUSED; break;
		case STATUS_INVALID_DEVICE_STATE: err = -EAGAIN; break;
		case STATUS_NETWORK_UNREACHABLE: err = -ENETUNREACH; break;
		case STATUS_HOST_UNREACHABLE: err = -EHOSTUNREACH; break;
		default: err = -EINVAL; break;
		}
	} else {
		if (status == STATUS_TIMEOUT) { 
			err = -ETIMEDOUT; 
		} else { 
			if (status == 0) {
				err = 0; // Connect ok 
			} else {
				err = -EINVAL;
			}
		}
	}
#else
	err = socket->ops->connect(socket, (struct sockaddr *) &peer_addr,
				   path->path.peer_addr_len, 0);
#endif
	if (err < 0) {
		switch (err) {
		case -ETIMEDOUT:
		case -EINPROGRESS:
		case -EINTR:
		case -ERESTARTSYS:
		case -ECONNREFUSED:
		case -ENETUNREACH:
		case -EHOSTDOWN:
		case -EHOSTUNREACH:
			err = -EAGAIN;
		}
	}

out:
	if (err < 0) {
		if (socket)
			sock_release(socket);
		if (err != -EAGAIN)
			tr_err(transport, "%s failed, err = %d\n", what, err);
	} else {
		*ret_socket = socket;
	}

	return err;
}

static int dtt_send_first_packet(struct drbd_tcp_transport *tcp_transport, struct socket *socket,
			     enum drbd_packet cmd, enum drbd_stream stream)
{
	struct p_header80 h;
	int msg_flags = 0;
	int err;

	if (!socket)
		return -EIO;

	h.magic = cpu_to_be32(DRBD_MAGIC);
	h.command = cpu_to_be16(cmd);
	h.length = 0;

	err = _dtt_send(tcp_transport, socket, &h, sizeof(h), msg_flags);

	return err;
}

/**
 * dtt_socket_ok_or_free() - Free the socket if its connection is not okay
 * @sock:	pointer to the pointer to the socket.
 */
static bool dtt_socket_ok_or_free(struct socket **socket)
{
	int rr;
	char tb[4];

	if (!*socket)
		return false;

#ifdef _WIN32 // 기존 구현 유지 ??? 소켓의 상태를 확인하고 상태가 유효하지 않으면 free 시키는 로직 => 소켓 상태 확인이...BACKLOG 정보 확인으로 가능한가?... history 를 알려주세요~...
#if 0   // kmpak. sekim과 협의 후 이 로직으로 socket ok test하기에는 의도가 다르다고 결론.
    // 하지만 다음의 로직은 보강해야 하므로 우선 disable
    if ((rr = SendLocal((*socket)->sk, tb, 1, 0, 3000)) != 1)
    {
        WDRBD_INFO("socket(%s) is ok. but send error(%d)\n", (*socket)->name, rr);
        sock_release(*socket);
        *socket = NULL;
        return false;
    }

    if ((rr = Receive((*socket)->sk, tb, 1, 0, 5000)) != 1)
    {
        WDRBD_INFO("socket(%s) is ok. but recv timeout(%d)!\n", (*socket)->name, rr);
        sock_release(*socket);
        *socket = NULL;
        return false;
    }
#else
    SIZE_T out = 0;
    NTSTATUS Status = ControlSocket( (*socket)->sk, WskIoctl, SIO_WSK_QUERY_RECEIVE_BACKLOG, 0, 0, NULL, sizeof(SIZE_T), &out, NULL );
	if (!NT_SUCCESS(Status)) {
        WDRBD_ERROR("socket(0x%p), ControlSocket(%s): SIO_WSK_QUERY_RECEIVE_BACKLOG failed=0x%x\n", (*socket), (*socket)->name, Status); // _WIN32
        sock_release(*socket);
        *socket = NULL;
        return false;
	}

    WDRBD_TRACE_SK("socket(0x%p) wsk(0x%p) ControlSocket(%s): backlog=%d\n", (*socket), (*socket)->sk, (*socket)->name, out); // _WIN32
#endif
    return true;
#else
	rr = dtt_recv_short(*socket, tb, 4, MSG_DONTWAIT | MSG_PEEK);

	if (rr > 0 || rr == -EAGAIN) {
		return true;
	} else {
		sock_release(*socket);
		*socket = NULL;
		return false;
	}
#endif
}

static bool dtt_connection_established(struct drbd_transport *transport,
				       struct socket **socket1,
				       struct socket **socket2,
				       struct dtt_path **first_path)
{
	struct net_conf *nc;
	int timeout, good = 0;

	if (!*socket1 || !*socket2)
		return false;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
#ifdef _WIN32
	timeout = (nc->sock_check_timeo ? nc->sock_check_timeo : nc->ping_timeo) * HZ / 10;
#else
	timeout = (nc->sock_check_timeo ?: nc->ping_timeo) * HZ / 10;
#endif
	rcu_read_unlock();
	schedule_timeout_interruptible(timeout);

	good += dtt_socket_ok_or_free(socket1);
	good += dtt_socket_ok_or_free(socket2);

#if 0 // kmpak move to dtt_socket_ok_or_free
    //def _WIN32_V9_PATCH_1 // JHKIM: 일단 임시초치를 사용하고 추후 패치 내용을 적용예정 -> 일단 패치방식을 우선 적용힘-> 연결 이후 송신 오류와 같은 유사문제 발생하여 다시 V9 수정본을 반영함
#if _WIN32_V9 //JHKIM:임시조치: 연결된 소켓이 정상인지 실제 통신으로 재확인한다. 추후 재정리.
	int ret;
	char buf = 0x77;

	if ((ret = SendLocal((*socket1)->sk, &buf, 1, 0, 3000)) != 1)
	{
		WDRBD_INFO("socket1(%s) is ok. but send error(%d)", (*socket1)->name, ret);
		sock_release(*socket1);
		*socket1 = 0;
		return false;
	}

	if ((ret = Receive((*socket1)->sk, &buf, 1, 0, 5000)) != 1)
	{
		WDRBD_INFO("socket1(%s) is ok. but recv timeout(%d)!", (*socket1)->name, ret);
		sock_release(*socket1);
		*socket1 = 0;
		return false;
	}

	if ((ret = SendLocal((*socket2)->sk, &buf, 1, 0, 3000)) != 1)
	{
		WDRBD_INFO("socket2(%s) is ok. but send error(%d)!", (*socket2)->name, ret);
		sock_release(*socket2);
		*socket2 = 0;
		return false;
	}

	if ((ret = Receive((*socket2)->sk, &buf, 1, 0, 5000)) != 1)
	{
		WDRBD_INFO("socket2(%s) is ok. but recv timeout(%d)!", (*socket2)->name, ret);
		sock_release(*socket2);
		*socket2 = 0;
		return false;
	}

	if (good == 0)
		*first_path = NULL;

	return *socket1 && *socket2;
#endif
#else
	if (good == 0)
		*first_path = NULL;

	return good == 2;
#endif
}

static struct dtt_path *dtt_wait_connect_cond(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_listener *listener;
	struct drbd_path *drbd_path;
#ifdef _WIN32_V9
	struct dtt_path *path = 0;
#else
	struct dtt_path *path;
#endif
	bool rv = false;

	mutex_lock(&tcp_transport->paths_mutex);
	
	// _WIN32_V9_PATCH_1_CHECK: 많이 변경됨, 리스너 관련 V9 포팅에 영향은 없는지 확인!
#ifdef _WIN32_V9_PATCH_1
	list_for_each_entry(struct drbd_path, drbd_path, &transport->paths, list) {
#else
	list_for_each_entry(drbd_path, &transport->paths, list) {
#endif
		path = container_of(drbd_path, struct dtt_path, path);
		listener = path->waiter.listener;
#if 0 // WDRBD_TRACE_CO
		extern char * get_ip4(char *buf, struct sockaddr_in *sockaddr);
		char sbuf[64], dbuf[64];
		WDRBD_TRACE_CO("[%p]dtt_wait_connect_cond: peer:%s sname=%s accept=%d\n", KeGetCurrentThread(), get_ip4(sbuf, &path->path.peer_addr), path->socket->name, listener->pending_accepts);		
#endif
		spin_lock_bh(&listener->waiters_lock);
		rv = listener->pending_accepts > 0 || path->socket != NULL;
		spin_unlock_bh(&listener->waiters_lock);

		if (rv)
			break;
	}
	mutex_unlock(&tcp_transport->paths_mutex);

	return rv ? path : NULL;
}

static void unregister_state_change(struct sock *sock, struct dtt_listener *listener)
{
#ifdef _WIN32
	// not support => 지원하지 않는 이유?
#else 
	write_lock_bh(&sock->sk_callback_lock);
	sock->sk_state_change = listener->original_sk_state_change;
	sock->sk_user_data = NULL;
	write_unlock_bh(&sock->sk_callback_lock);
#endif
}

static int dtt_wait_for_connect(struct dtt_wait_first *waiter, struct socket **socket,
				struct dtt_path **ret_path)
{
	struct drbd_transport *transport = waiter->transport;
#ifdef _WIN32_V9
	struct sockaddr_storage_win my_addr, peer_addr;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PWSK_SOCKET paccept_socket = NULL;
#else
	struct sockaddr_storage peer_addr;
#endif
	int connect_int, peer_addr_len, err = 0;
	long timeo;
    struct socket *s_estab = NULL; 
	struct net_conf *nc;
	struct drbd_waiter *waiter2_gen;
	struct dtt_listener *listener;
	struct dtt_path *path = NULL;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EINVAL;
	}
	connect_int = nc->connect_int;
	rcu_read_unlock();

	timeo = connect_int * HZ;
	timeo += (prandom_u32() & 1) ? timeo / 7 : -timeo / 7; /* 28.5% random jitter */

retry:
#ifdef _WIN32
    atomic_set(&(transport->listening), 1);
	// WIN32_V9_PATCH_1_CHECK: waiter->wait 가 적절한가?
	wait_event_interruptible_timeout(timeo, waiter->wait, 
		(path = dtt_wait_connect_cond(transport)),
			timeo);
	atomic_set(&(transport->listening), 0);
#else
	timeo = wait_event_interruptible_timeout(waiter->wait,
			(path = dtt_wait_connect_cond(transport)),
			timeo);
#endif
#ifdef _WIN32_V9_PATCH_1
	if (-DRBD_SIGKILL == timeo) 
	{ 
		return -DRBD_SIGKILL;
	}
#endif
#ifdef _WIN32_V9
    if (-ETIMEDOUT == timeo)
#else
	if (timeo <= 0)
#endif
		return -EAGAIN;

	listener = container_of(path->waiter.listener, struct dtt_listener, listener);
	spin_lock_bh(&listener->listener.waiters_lock);
	if (path->socket) {
		s_estab = path->socket;
		path->socket = NULL;
	} else if (listener->listener.pending_accepts > 0) { //pending_accepts 가 AcceptEvent callback에서 증가된다.
		listener->listener.pending_accepts--;
		spin_unlock_bh(&listener->listener.waiters_lock);

		s_estab = NULL;
#ifdef _WIN32_V9
		// Accept 하고, s_estab 구조를 생성한다.
		// _WIN32_V9_PATCH_1_CHECL: JHKIM: 일단 my_addr 사용안함으로 코멘트!
		// my_addr = dtt_path(waiter->waiter.transport)->my_addr; // my_addr 가 이전 시점에 잘 들어가 있는 지 검증 필요.=> 잘 들어가 있음.
#ifdef _WIN32_V9_IPV6		
		memset(&peer_addr, 0, sizeof(struct sockaddr_storage_win));
#else
		memset(&peer_addr, 0, sizeof(struct sockaddr_in));
#endif
		// Accept Event Callback 에서 paccept_socket 을 저장해 두었다. 
		//paccept_socket = Accept(listener->s_listen->sk, (PSOCKADDR)&my_addr, (PSOCKADDR)&peer_addr, status, timeo / HZ);
		// 
		if (listener->paccept_socket) {
			s_estab = kzalloc(sizeof(struct socket), 0, 'D6DW');
			if (!s_estab) {
				return -ENOMEM;
			}
			s_estab->sk = listener->paccept_socket;
			sprintf(s_estab->name, "estab_sock");
			s_estab->sk_linux_attr = kzalloc(sizeof(struct sock), 0, 'B6DW');
			if (!s_estab->sk_linux_attr) {
				kfree(s_estab);
				return -ENOMEM;
			}
#ifdef _WIN32_SEND_BUFFING
			if (nc->sndbuf_size < DRBD_SNDBUF_SIZE_DEF)
			{
				if (nc->sndbuf_size > 0)
				{
					tr_warn(transport, "sndbuf_size(%d) -> (%d)\n", nc->sndbuf_size, DRBD_SNDBUF_SIZE_DEF);
					nc->sndbuf_size = DRBD_SNDBUF_SIZE_DEF;
				}
			}
			dtt_setbufsize(s_estab, nc->sndbuf_size, nc->rcvbuf_size);
#endif
            s_estab->sk_linux_attr->sk_sndbuf = 16384;  // kmpak temp.
		}
		else {
			if (status == STATUS_TIMEOUT) {
				err = -EAGAIN;
			}
			else {
				err = -1;
			}
		}
#else
		err = kernel_accept(listener->s_listen, &s_estab, 0);
#endif
		if (err < 0)
			return err;

		/* The established socket inherits the sk_state_change callback
		   from the listening socket. */
#ifdef _WIN32
		unregister_state_change(s_estab->sk_linux_attr, listener); // unregister_state_change 가 V8에서 내부 구현이 안되었다. => V9 포팅 여부 검토 필요 
		status = GetRemoteAddress(s_estab->sk, (PSOCKADDR)&peer_addr); //V8에 없던 s_estab->ops->getname 구현. Accept 를 하고 peer 주소를 다시 획득한다. 분석 필요. 
		if(status != STATUS_SUCCESS) {
			kfree(s_estab->sk_linux_attr);
			kfree(s_estab);
			return -1;
		}
#else
		unregister_state_change(s_estab->sk, listener);

		s_estab->ops->getname(s_estab, (struct sockaddr *)&peer_addr, &peer_addr_len, 2);
#endif
		spin_lock_bh(&listener->listener.waiters_lock);
		waiter2_gen = drbd_find_waiter_by_addr(&listener->listener, &peer_addr);
		if (!waiter2_gen) {
			struct sockaddr_in6 *from_sin6;
			struct sockaddr_in *from_sin;

			switch (peer_addr.ss_family) {
			case AF_INET6:
				from_sin6 = (struct sockaddr_in6 *)&peer_addr;
				tr_err(transport, "Closing unexpected connection from "
				       "%pI6\n", &from_sin6->sin6_addr);
				break;
			default:
				from_sin = (struct sockaddr_in *)&peer_addr;
				tr_err(transport, "Closing unexpected connection from "
					 "%pI4\n", &from_sin->sin_addr);
				break;
			}

			goto retry_locked;
		}
		if (waiter2_gen != &path->waiter) {
			struct dtt_path *path2 =
				container_of(waiter2_gen, struct dtt_path, waiter);

			if (path2->socket) {
				tr_err(path2->waiter.transport,
					 "Receiver busy; rejecting incoming connection\n");
				goto retry_locked;
			}
			path2->socket = s_estab;
			s_estab = NULL;
			wake_up(&path2->waiter.wait);
			goto retry_locked;
		}
	}
	WDRBD_TRACE_CO("%p dtt_wait_for_connect ok done.\n", KeGetCurrentThread());
	spin_unlock_bh(&listener->listener.waiters_lock);
	*socket = s_estab;
	*ret_path = path;
	return 0;

retry_locked:
	spin_unlock_bh(&listener->listener.waiters_lock);
	if (s_estab) {
		sock_release(s_estab);
		s_estab = NULL;
	}
	goto retry;
}

static int dtt_receive_first_packet(struct drbd_tcp_transport *tcp_transport, struct socket *socket)
{
	struct drbd_transport *transport = &tcp_transport->transport;
	struct p_header80 *h = tcp_transport->rbuf[DATA_STREAM].base;
	const unsigned int header_size = sizeof(*h);
	struct net_conf *nc;
	int err;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EIO;
	}
#ifdef _WIN32_V9
	socket->sk_linux_attr->sk_rcvtimeo = nc->ping_timeo * 4 * HZ / 10;
#else
	socket->sk->sk_rcvtimeo = nc->ping_timeo * 4 * HZ / 10;
#endif
	rcu_read_unlock();

	err = dtt_recv_short(socket, h, header_size, 0);
    WDRBD_TRACE_SK("socket(0x%p) err(%d) header_size(%d)\n", socket, err, header_size);
	if (err != header_size) {
		if (err >= 0)
			err = -EIO;
		return err;
	}
	if (h->magic != cpu_to_be32(DRBD_MAGIC)) {
		tr_err(transport, "Wrong magic value 0x%08x in receive_first_packet\n",
			 be32_to_cpu(h->magic));
		return -EINVAL;
	}
	return be16_to_cpu(h->command);
}

#ifdef _WIN32_V9
NTSTATUS WSKAPI
dtt_incoming_connection (
    _In_  PVOID         SocketContext,
    _In_  ULONG         Flags,
    _In_  PSOCKADDR     LocalAddress,
    _In_  PSOCKADDR     RemoteAddress,
    _In_opt_  PWSK_SOCKET AcceptSocket,
    _Outptr_result_maybenull_ PVOID *AcceptSocketContext,
    _Outptr_result_maybenull_ CONST WSK_CLIENT_CONNECTION_DISPATCH **AcceptSocketDispatch
)
#else
static void dtt_incoming_connection(struct sock *sock)
#endif
{
#ifdef _WIN32_V9
    struct socket * s_estab = kzalloc(sizeof(struct socket), 0, 'E6DW');

    if (!s_estab)
    {
        return STATUS_REQUEST_NOT_ACCEPTED;
    }

    s_estab->sk = AcceptSocket;
    sprintf(s_estab->name, "estab_sock");
    s_estab->sk_linux_attr = kzalloc(sizeof(struct sock), 0, 'C6DW');

    if (s_estab->sk_linux_attr)
    {
        s_estab->sk_linux_attr->sk_sndbuf = 16384;  // kmpak temp.
    }
    else
    {
        kfree(s_estab);
        return STATUS_REQUEST_NOT_ACCEPTED;
    }
#if 1 // JHKIM:원본 방식 변경부분 // _WIN32_V9_PATCH_1: 다시 패치된 원본을 유지하는 방법으로 시험
    // 일단 V8 구현을 따라간다. => state change 관련 구현에 대한 V9 포팅 여부 추후 검토 필요. => Accept Event Callback 방식 적용. 2015.9.9 sekim
    struct dtt_listener *listener = (struct dtt_listener *)SocketContext; //context 설정 dtt_listener 로...

    spin_lock(&listener->listener.waiters_lock);
    struct drbd_waiter *waiter = drbd_find_waiter_by_addr(&listener->listener, (struct sockaddr_storage_win*)RemoteAddress);
    struct dtt_path * path = container_of(waiter, struct dtt_path, waiter);

    if (path)
    {
        path->socket = s_estab;
    }
    else
    {
        listener->listener.pending_accepts++;
        listener->paccept_socket = AcceptSocket;
    }
    wake_up(&waiter->wait);
	spin_unlock(&listener->listener.waiters_lock);
    WDRBD_TRACE_SK("waiter(0x%p) s_estab(0x%p) wsk(0x%p) wake!!!!\n", waiter, s_estab, AcceptSocket);

	return STATUS_SUCCESS;
#else
	// JHKIM: 패치된 원본 방식 유지부분
#ifdef _WIN32_V9
	struct dtt_listener *listener = (struct dtt_listener *)SocketContext;

	if (AcceptSocket) {
#else
	struct dtt_listener *listener = sock->sk_user_data;
	void (*state_change)(struct sock *sock);

	state_change = listener->original_sk_state_change;
	if (sock->sk_state == TCP_ESTABLISHED) {
#endif
		struct drbd_waiter *waiter;
		struct dtt_path *path;

		spin_lock(&listener->listener.waiters_lock);
		listener->listener.pending_accepts++;
#ifdef _WIN32_V9
		listener->paccept_socket = AcceptSocket;
#endif
		waiter = list_entry(listener->listener.waiters.next, struct drbd_waiter, list);
#ifdef _WIN32_V9
		if (!waiter)
		{
			spin_unlock(&listener->listener.waiters_lock);
			return STATUS_REQUEST_NOT_ACCEPTED; 
		}
#endif
#ifdef _WIN32_V9_PATCH_1
		path = container_of(waiter, struct dtt_path, waiter);
		if (path->first)
		{ // TEST
			WDRBD_TRACE_CO("%p path->first incomming ok! wake_up!!\n", KeGetCurrentThread());
			wake_up(&path->first->wait);
		} // TEST
		else // TEST
		{
			WDRBD_TRACE_CO("it not a first! Don't wake_up!\n");
			panic("dtt_incoming_connection test!!!"); // TEST: 어떤 경우인가? 일단 중지.
		}
#else
		wake_up(&waiter->wait); // V9 old.
#endif
		spin_unlock(&listener->listener.waiters_lock);
#ifdef _WIN32_V9
		return STATUS_SUCCESS;
#endif
	}
	
#ifdef _WIN32_V9
	//WskCloseSocket(AcceptSocket);
	return STATUS_REQUEST_NOT_ACCEPTED;
#else
	state_change(sock);
#endif
#endif
#else
	struct dtt_listener *listener = sock->sk_user_data;
	void (*state_change)(struct sock *sock);

	state_change = listener->original_sk_state_change;
	if (sock->sk_state == TCP_ESTABLISHED) {
		struct drbd_waiter *waiter;
		struct dtt_path *path;

		spin_lock(&listener->listener.waiters_lock);
		listener->listener.pending_accepts++;
		waiter = list_first_entry(&listener->listener.waiters, struct drbd_waiter, list);
		path = container_of(waiter, struct dtt_path, waiter);
		if (path->first)
			wake_up(&path->first->wait);
		spin_unlock(&listener->listener.waiters_lock);
	}
	state_change(sock);
#endif
}

static void dtt_destroy_listener(struct drbd_listener *generic_listener)
{
	struct dtt_listener *listener =
		container_of(generic_listener, struct dtt_listener, listener);

#ifdef _WIN32_V9
    unregister_state_change(listener->s_listen->sk_linux_attr, listener);
#else
	unregister_state_change(listener->s_listen->sk, listener);
#endif
	sock_release(listener->s_listen);
	kfree(listener);
}

#ifdef _WIN32
// A listening socket's WskInspectEvent event callback function
WSK_INSPECT_ACTION WSKAPI
dtt_inspect_incoming(
    PVOID SocketContext,
    PSOCKADDR LocalAddress,
    PSOCKADDR RemoteAddress,
    PWSK_INSPECT_ID InspectID
)
{
    // Check for a valid inspect ID
    if (NULL == InspectID)
    {
        return WskInspectReject;
    }

    WSK_INSPECT_ACTION action = WskInspectAccept;
    struct dtt_listener *listener = (struct dtt_listener *)SocketContext;

    spin_lock(&listener->listener.waiters_lock);
	struct drbd_waiter *waiter = drbd_find_waiter_by_addr(&listener->listener, (struct sockaddr_storage_win*)RemoteAddress);
    if (!waiter || !atomic_read(&waiter->transport->listening))
    {
        action = WskInspectReject;
        goto out;
    }

    atomic_set(&waiter->transport->listening, 0);
out:
    spin_unlock(&listener->listener.waiters_lock);
 
    return action;
}

// A listening socket's WskAbortEvent event callback function
NTSTATUS WSKAPI
dtt_abort_inspect_incoming(
    PVOID SocketContext,
    PWSK_INSPECT_ID InspectID
)
{
    // Terminate the inspection for the incoming connection
    // request with a matching inspect ID. To test for a matching
    // inspect ID, the contents of the WSK_INSPECT_ID structures
    // must be compared, not the pointers to the structures.
    return STATUS_SUCCESS;
}

WSK_CLIENT_LISTEN_DISPATCH dispatch = {
	dtt_incoming_connection,
    dtt_inspect_incoming,       // WskInspectEvent is required only if conditional-accept is used.
    dtt_abort_inspect_incoming  // WskAbortEvent is required only if conditional-accept is used.
};
#endif


static int dtt_create_listener(struct drbd_transport *transport,
			       const struct sockaddr *addr,
			       struct drbd_listener **ret_listener)
{
#ifdef _WIN32
	int err = 0, sndbuf_size, rcvbuf_size; //err 0으로 임시 초기화.
	struct sockaddr_storage_win my_addr;
	NTSTATUS status;
#else
	int err, sndbuf_size, rcvbuf_size, addr_len;
	struct sockaddr_storage my_addr;
#endif
	struct dtt_listener *listener = NULL;
	struct socket *s_listen;
	struct net_conf *nc;
	const char *what;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return -EINVAL;
	}
	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	rcu_read_unlock();

#ifdef _WIN32_V9_PATCH_1
	my_addr = *(struct sockaddr_storage_win *)addr;
#else
	my_addr = *(struct sockaddr_storage *)addr;
#endif

	what = "sock_create_kern";
#ifdef _WIN32
    s_listen = kzalloc(sizeof(struct socket), 0, '87DW');
    if (!s_listen)
    {
        err = -ENOMEM;
        goto out;
    }
    sprintf(s_listen->name, "listen_sock\0");
    s_listen->sk_linux_attr = 0;
    err = 0;
	listener = kzalloc(sizeof(struct dtt_listener), 0, 'F6DW');
	if (!listener) {
        err = -ENOMEM;
        goto out;
    }
#ifdef _WIN32_V9_IPV6
	if (my_addr.ss_family == AF_INET6) {
		s_listen->sk = CreateSocket(AF_INET6, SOCK_STREAM, IPPROTO_TCP, (PVOID*)listener, &dispatch, WSK_FLAG_LISTEN_SOCKET); // this is listen socket
	} else {
		s_listen->sk = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, (PVOID*)listener, &dispatch, WSK_FLAG_LISTEN_SOCKET); // this is listen socket
	}
#else 
	s_listen->sk = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, listener, &dispatch, WSK_FLAG_LISTEN_SOCKET); // this is listen socket
#endif
    if (s_listen->sk == NULL) {
        err = -1;
        goto out;
    }

    status = SetConditionalAccept(s_listen->sk, 1);
	if (!NT_SUCCESS(status))
    {
		WDRBD_ERROR("Failed to set SO_CONDITIONAL_ACCEPT. err(0x%x)\n", status);
        err = status;
        goto out;
    }
    s_listen->sk_linux_attr = kzalloc(sizeof(struct sock), 0, '72DW');
    if (!s_listen->sk_linux_attr)
    {
        err = -ENOMEM;
        goto out;
    }
#else
	err = sock_create_kern(&init_net, my_addr.ss_family, SOCK_STREAM, IPPROTO_TCP, &s_listen);
	if (err) {
		s_listen = NULL;
		goto out;
	}
#endif

#ifdef _WIN32
    s_listen->sk_linux_attr->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
	LONG InputBuffer = 1;
    status = ControlSocket(s_listen->sk, WskSetOption, SO_REUSEADDR, SOL_SOCKET, sizeof(ULONG), &InputBuffer, 0, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        WDRBD_ERROR("ControlSocket: s_listen socket SO_REUSEADDR: failed=0x%x\n", status); // EVENTLOG
        err = -1;
        goto out;
    }
#else
	s_listen->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
#endif
	dtt_setbufsize(s_listen, sndbuf_size, rcvbuf_size);

	what = "bind before listen";
#ifdef _WIN32
	status = Bind(s_listen->sk, (PSOCKADDR)&my_addr);
	if (!NT_SUCCESS(status)) {
    	if(my_addr.ss_family == AF_INET) {
			WDRBD_ERROR("AF_INET Failed to socket Bind(). err(0x%x) %02X.%02X.%02X.%02X:0x%X%X\n", status, (UCHAR)my_addr.__data[2], (UCHAR)my_addr.__data[3], (UCHAR)my_addr.__data[4], (UCHAR)my_addr.__data[5],(UCHAR)my_addr.__data[0],(UCHAR)my_addr.__data[1]);
    	} else {
			WDRBD_ERROR("AF_INET6 Failed to socket Bind(). err(0x%x) [%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X]:0x%X%X\n", status, (UCHAR)my_addr.__data[2],(UCHAR)my_addr.__data[3], (UCHAR)my_addr.__data[4],(UCHAR)my_addr.__data[5],
																		(UCHAR)my_addr.__data[6],(UCHAR)my_addr.__data[7], (UCHAR)my_addr.__data[8],(UCHAR)my_addr.__data[9],
																		(UCHAR)my_addr.__data[10],(UCHAR)my_addr.__data[11], (UCHAR)my_addr.__data[12],(UCHAR)my_addr.__data[13],
																		(UCHAR)my_addr.__data[14],(UCHAR)my_addr.__data[15],(UCHAR)my_addr.__data[16],(UCHAR)my_addr.__data[17],
																		(UCHAR)my_addr.__data[0], (UCHAR)my_addr.__data[1]);
    	}
		LARGE_INTEGER	Interval;
		Interval.QuadPart = (-1 * 100 * 10000);   // 0.1 sec
		KeDelayExecutionThread(KernelMode, FALSE, &Interval);
		err = -EADDRINUSE;//DW-835 fix standalone issue after reboot. (retry to connect)
        goto out;
    } else {
        status = SetEventCallbacks(s_listen->sk, WSK_EVENT_ACCEPT);
    	if (!NT_SUCCESS(status)) {
            WDRBD_ERROR("Failed to set WSK_EVENT_ACCEPT. err(0x%x)\n", status);
    		err = status;
            goto out;
    	}
    }
#else
	addr_len = addr->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6)
		: sizeof(struct sockaddr_in);

	err = s_listen->ops->bind(s_listen, (struct sockaddr *)&my_addr, addr_len);
#endif
	if (err < 0)
		goto out;

	what = "kmalloc";
    // listener 는 CreateSocket 이전시점에 할당하여 소켓 컨텍스트 인자로 넘겨주므로 메모리 할당 코드 CreateSocket 이전에서 수행. sekim
#ifndef _WIN32_V9
	listener = kmalloc(sizeof(*listener), GFP_KERNEL);
	if (!listener) {
		err = -ENOMEM;
		goto out;
	}
#endif

	listener->s_listen = s_listen;
    
	// 이 시점에 event callback을 설정하면 안된다... dtt_create_listener 가 완료되고
    // drbd_get_listener 안에서 초기화 될 코드가 다 수행되고 난 후 이벤트 콜백을 설정해야 
	// event callback(dtt_incoming_connection) 안의 코드수행이 안전하다.

    // kmpak 2015.11.03 소켓 bind 후에는 사용해도 되는 것을 확인하여
    // bind 직후 WSK_EVENT_ACCEPT 설정하였습니다.

#ifndef _WIN32
	write_lock_bh(&s_listen->sk->sk_callback_lock);
	listener->original_sk_state_change = s_listen->sk->sk_state_change;
	s_listen->sk->sk_state_change = dtt_incoming_connection;
	s_listen->sk->sk_user_data = listener;
	write_unlock_bh(&s_listen->sk->sk_callback_lock);

	what = "listen";
	err = s_listen->ops->listen(s_listen, 5);
	if (err < 0)
		goto out;
#endif
	listener->listener.listen_addr = my_addr;
	listener->listener.destroy = dtt_destroy_listener;

	*ret_listener = &listener->listener;
	return 0;
out:
	if (s_listen)
		sock_release(s_listen);

	if (err < 0 &&
	    err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS && err != -EADDRINUSE)
		tr_err(transport, "%s failed, err = %d\n", what, err);

	kfree(listener);

	return err;
}

static void dtt_put_listeners(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_path *drbd_path;

	mutex_lock(&tcp_transport->paths_mutex);
	clear_bit(DTT_CONNECTING, &tcp_transport->flags);

#ifdef _WIN32_V9_PATCH_1
	list_for_each_entry(struct drbd_path, drbd_path, &transport->paths, list) {
#else
	list_for_each_entry(drbd_path, &transport->paths, list) {
#endif
		struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);

		path->first = NULL;
		drbd_put_listener(&path->waiter);
		if (path->socket) {
			sock_release(path->socket);
			path->socket = NULL;
		}
#ifdef _WIN32_V9_PATCH_1 // : JHKIM: 확인!!!!
    	//kfree(waiter);
#endif
	}
	mutex_unlock(&tcp_transport->paths_mutex);
}

static struct dtt_path *dtt_next_path(struct drbd_tcp_transport *tcp_transport, struct dtt_path *path)
{
	struct drbd_transport *transport = &tcp_transport->transport;
	struct drbd_path *drbd_path;

	mutex_lock(&tcp_transport->paths_mutex);
	if (list_is_last(&path->path.list, &transport->paths))
		drbd_path = list_first_entry(&transport->paths, struct drbd_path, list);
	else
#ifdef _WIN32_V9_PATCH_1
		drbd_path = list_next_entry(struct drbd_path, &path->path, list);
#else
		drbd_path = list_next_entry(&path->path, list);
#endif
	mutex_unlock(&tcp_transport->paths_mutex);

	return container_of(drbd_path, struct dtt_path, path);
}
#ifdef _WIN32_V9
extern char * get_ip4(char *buf, struct sockaddr_in *sockaddr);
extern char * get_ip6(char *buf, struct sockaddr_in6 *sockaddr);
#endif

static int dtt_connect(struct drbd_transport *transport)
{
#ifdef _WIN32
	NTSTATUS status;
#endif
#if 1 // PATCH!!!!!
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_path *drbd_path;
	struct dtt_path *connect_to_path, *first_path = NULL;
	struct socket *dsocket, *csocket;
	struct net_conf *nc;
	struct dtt_wait_first waiter; // _WIN32_V9_PATCH_1_CHECK: 스택영역인데 문제 없는가?
	int timeout, err;
	bool ok;
#ifdef _WIN32_V9
	char sbuf[128], dbuf[128];
	ok = FALSE;
#endif
	dsocket = NULL;
	csocket = NULL;

	waiter.transport = transport;
	init_waitqueue_head(&waiter.wait);

	mutex_lock(&tcp_transport->paths_mutex);
	set_bit(DTT_CONNECTING, &tcp_transport->flags);

	err = -EDESTADDRREQ;
	if (list_empty(&transport->paths))
		goto out_unlock;

#ifdef _WIN32_V9_PATCH_1
	list_for_each_entry(struct drbd_path, drbd_path, &transport->paths, list) {
#else
	list_for_each_entry(drbd_path, &transport->paths, list) {
#endif
		struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);
		
		{
#ifdef _WIN32_V9_IPV6
			// WDRBD_TRACE_CO
			if (path->path.my_addr.ss_family == AF_INET6) {
				WDRBD_TRACE_IP4("WDRBD_TEST: dtt_connect: path: %s -> %s.\n", get_ip6(sbuf, (struct sockaddr_in6*)&path->path.my_addr), get_ip6(dbuf, (struct sockaddr_in6*)&path->path.peer_addr));
			}
			else {
				WDRBD_TRACE_IP4("WDRBD_TEST: dtt_connect: path: %s -> %s.\n", get_ip4(sbuf, (struct sockaddr_in*)&path->path.my_addr), get_ip4(dbuf, (struct sockaddr_in*)&path->path.peer_addr));
			}
			// WDRBD_TRACE_CO
#else
			extern char * get_ip4(char *buf, struct sockaddr_in *sockaddr);
			WDRBD_TRACE_IP4("WDRBD_TEST: dtt_connect: path: %s -> %s.\n", get_ip4(sbuf, &path->path.my_addr), get_ip4(dbuf, &path->path.peer_addr));
#endif
		}

		path->first = &waiter;
		err = drbd_get_listener(&path->waiter, (struct sockaddr *)&drbd_path->my_addr,
					dtt_create_listener);
		if (err)
			goto out_unlock;
	}

	drbd_path = list_first_entry(&transport->paths, struct drbd_path, list);
	{//
#ifdef _WIN32_V9_IPV6
		if (drbd_path->my_addr.ss_family == AF_INET6) {
			WDRBD_TRACE_IP4("WDRBD_TEST: drbd_path: %s -> %s \n", get_ip6(sbuf, (struct sockaddr_in6*)&drbd_path->my_addr), get_ip6(dbuf, (struct sockaddr_in6*)&drbd_path->peer_addr));
		} else {
			WDRBD_TRACE_IP4("WDRBD_TEST: drbd_path: %s -> %s \n", get_ip4(sbuf, (struct sockaddr_in*)&drbd_path->my_addr), get_ip4(dbuf, (struct sockaddr_in*)&drbd_path->peer_addr));
		}
#else
		WDRBD_TRACE_IP4("WDRBD_TEST: drbd_path: %s -> %s \n", get_ip4(sbuf, &drbd_path->my_addr), get_ip4(dbuf, &drbd_path->peer_addr));
#endif
	}//

	connect_to_path = container_of(drbd_path, struct dtt_path, path);
	{//
#ifdef _WIN32_V9_IPV6
		if(connect_to_path->path.my_addr.ss_family == AF_INET6) {
			WDRBD_TRACE_IP4("WDRBD_TEST: connect_to_path: %s -> %s \n", get_ip6(sbuf, (struct sockaddr_in6*)&connect_to_path->path.my_addr), get_ip6(dbuf, (struct sockaddr_in6*)&connect_to_path->path.peer_addr));
		} else {
			WDRBD_TRACE_IP4("WDRBD_TEST: connect_to_path: %s -> %s \n", get_ip4(sbuf, (struct sockaddr_in*)&connect_to_path->path.my_addr), get_ip4(dbuf, (struct sockaddr_in*)&connect_to_path->path.peer_addr));
		}
#else
		WDRBD_TRACE_IP4("WDRBD_TEST: connect_to_path: %s -> %s \n", get_ip4(sbuf, &connect_to_path->path.my_addr), get_ip4(dbuf, &connect_to_path->path.peer_addr));
#endif
	}//

	mutex_unlock(&tcp_transport->paths_mutex);// _WIN32_V9_PATCH_2
#else
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct drbd_path *drbd_path;
	struct dtt_path *connect_to_path, *first_path = NULL;
	struct socket *dsocket, *csocket;
	struct net_conf *nc;
#ifdef _WIN32_V9
	struct dtt_path * waiter = kzalloc(sizeof(struct dtt_path), 0, '97DW');
    if (!waiter)
        return -ENOMEM;
#else
	struct dtt_wait_first waiter;
#endif
	int timeout, err;
	bool ok;

	dsocket = NULL;
	csocket = NULL;

	if (list_empty(&transport->paths))
		return -EDESTADDRREQ;
#ifdef _WIN32_V9_PATCH_1
	waiter->waiter.transport = transport;
	init_waitqueue_head(&waiter->waiter.wait);
#else
	waiter.transport = transport;
	init_waitqueue_head(&waiter.wait);
#endif

#ifdef _WIN32_V9_PATCH_1
	list_for_each_entry(struct drbd_path, drbd_path, &transport->paths, list) {
#else
	list_for_each_entry(drbd_path, &transport->paths, list) {
#endif
		struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);
#ifdef _WIN32_V9_PATCH_1
		path->first = waiter; // JHKIM: 양단의 자료구조 의도적인 불일치 검토
#else
		path->first = &waiter;
#endif
		err = drbd_get_listener(&path->waiter, (struct sockaddr *)&drbd_path->my_addr,
					dtt_create_listener);
		if (err)
			goto out;
	}

	drbd_path = list_first_entry(&transport->paths, struct drbd_path, list);
	connect_to_path = container_of(drbd_path, struct dtt_path, path);
	mutex_unlock(&tcp_transport->paths_mutex);

#ifdef _WIN32_V9_PATCH_1_CHECK // 리스너 시작 지점으로 다시 이동.
#ifdef _WIN32_V9
	struct dtt_listener* dttlistener = container_of(waiter->waiter.listener, struct dtt_listener, listener);
	status = SetEventCallbacks(dttlistener->s_listen->sk, WSK_EVENT_ACCEPT);
	if (!NT_SUCCESS(status)) {
		err = -EAGAIN;
		goto out;
	}
#endif
#endif
#endif

	do {
		struct socket *s = NULL;

		err = dtt_try_connect(connect_to_path, &s);
		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
#ifdef WDRBD_TRACE_IP4
			{
				// _WIN32_V9_PATCH_1: 추후정리
#ifdef _WIN32_V9_IPV6
				if (connect_to_path->path.my_addr.ss_family == AF_INET6) {
					WDRBD_TRACE_IP4("WDRBD_TEST: Connected: %s -> %s\n", get_ip6(sbuf, (struct sockaddr_in6*)&connect_to_path->path.my_addr), get_ip6(dbuf, (struct sockaddr_in6*)&connect_to_path->path.peer_addr));
				} else {
					WDRBD_TRACE_IP4("WDRBD_TEST: Connected: %s -> %s\n", get_ip4(sbuf, (struct sockaddr_in*)&connect_to_path->path.my_addr), get_ip4(dbuf, (struct sockaddr_in*)&connect_to_path->path.peer_addr));
				}
#else
				WDRBD_TRACE_IP4("WDRBD_TEST: Connected: %s -> %s\n", get_ip4(sbuf, &connect_to_path->path.my_addr), get_ip4(dbuf, &connect_to_path->path.peer_addr));
#endif
			}
#endif
			if (!first_path) {
				first_path = connect_to_path;
			} else if (first_path != connect_to_path) {
				tr_warn(transport, "initial pathes crossed A\n");
				sock_release(s);
				connect_to_path = first_path;
				continue;
			}

			if (!dsocket) {
				dsocket = s;
#ifdef _WIN32 // V8 적용. DW-154 관련 수정사항.
                sprintf(dsocket->name, "data_sock\0");//DEBUG
                if (dtt_send_first_packet(tcp_transport, dsocket, P_INITIAL_DATA, DATA_STREAM) <= 0)
                {
                    sock_release(s);
                    dsocket = 0;
                    goto retry;
                }
#else
				dtt_send_first_packet(tcp_transport, dsocket, P_INITIAL_DATA, DATA_STREAM);
#endif
			} else if (!csocket) {
				clear_bit(RESOLVE_CONFLICTS, &transport->flags);
				csocket = s;
#ifdef _WIN32 // V8 적용. DW-154 관련 수정사항.
                sprintf(csocket->name, "meta_sock\0");//DEBUG
                if (dtt_send_first_packet(tcp_transport, csocket, P_INITIAL_META, CONTROL_STREAM) <= 0)
                {
                    sock_release(s);
                    csocket = 0;
                    goto retry;
                }
#else
				dtt_send_first_packet(tcp_transport, csocket, P_INITIAL_META, CONTROL_STREAM);
#endif
			} else {
				tr_err(transport, "Logic error in conn_connect()\n");
				goto out_eagain;
			}
		} else if (!first_path)
			connect_to_path = dtt_next_path(tcp_transport, connect_to_path);

		if (dtt_connection_established(transport, &dsocket, &csocket, &first_path))
			break;

retry:
		s = NULL;
#ifdef _WIN32_V9_PATCH_1_CHECK
        err = dtt_wait_for_connect(waiter, &s, &connect_to_path);
#else
		err = dtt_wait_for_connect(&waiter, &s, &connect_to_path);
#endif
		if (err < 0 && err != -EAGAIN)
			goto out;

		if (s) {
#ifdef WDRBD_TRACE_IP4 
			{
#ifdef _WIN32_V9_IPV6
				if (connect_to_path->path.my_addr.ss_family == AF_INET6) {
					WDRBD_TRACE_IP4("WDRBD_TEST:(%p) Accepted:  %s <- %s\n", KeGetCurrentThread(), get_ip6(sbuf, (struct sockaddr_in6*)&connect_to_path->path.my_addr), get_ip6(dbuf, (struct sockaddr_in6*)&connect_to_path->path.peer_addr));
				} else {
					WDRBD_TRACE_IP4("WDRBD_TEST:(%p) Accepted:  %s <- %s\n", KeGetCurrentThread(), get_ip4(sbuf, (struct sockaddr_in*)&connect_to_path->path.my_addr), get_ip4(dbuf, (struct sockaddr_in*)&connect_to_path->path.peer_addr));
				}				
#else
				WDRBD_TRACE_IP4("WDRBD_TEST:(%p) Accepted:  %s <- %s\n", KeGetCurrentThread(), get_ip4(sbuf, &connect_to_path->path.my_addr), get_ip4(dbuf, &connect_to_path->path.peer_addr));
#endif				
			}
#endif
			int fp = dtt_receive_first_packet(tcp_transport, s);

			if (!first_path) {
				first_path = connect_to_path;
			} else if (first_path != connect_to_path) {
				tr_warn(transport, "initial pathes crossed P\n");
				sock_release(s);
				connect_to_path = first_path;
				goto randomize;
			}
			dtt_socket_ok_or_free(&dsocket);
			dtt_socket_ok_or_free(&csocket);
			switch (fp) {
			case P_INITIAL_DATA:
				if (dsocket) {
					tr_warn(transport, "initial packet S crossed\n");
					sock_release(dsocket);
					dsocket = s;
					goto randomize;
				}
				dsocket = s;
				break;
			case P_INITIAL_META:
				set_bit(RESOLVE_CONFLICTS, &transport->flags);
				if (csocket) {
					tr_warn(transport, "initial packet M crossed\n");
					sock_release(csocket);
					csocket = s;
					goto randomize;
				}
				csocket = s;
				break;
			default:
				tr_warn(transport, "Error receiving initial packet\n");
				sock_release(s);
randomize:
				if (prandom_u32() & 1)
					goto retry;
			}
		}

		if (drbd_should_abort_listening(transport))
			goto out_eagain;

		ok = dtt_connection_established(transport, &dsocket, &csocket, &first_path);
	} while (!ok);
#if 0   // kmpak No need to event disable because it will be released socket.
#ifdef _WIN32 // dtt_put_listener 하기 전에 이벤트 콜백 해제
	status = SetEventCallbacks(dttlistener->s_listen->sk, WSK_EVENT_ACCEPT | WSK_EVENT_DISABLE);
	if (!NT_SUCCESS(status)) {
		WDRBD_ERROR("WSK_EVENT_DISABLE failed=0x%x\n", status);
		//goto out; // listener 를 해제해야 하므로 일 단 진행 한다.
	}
#endif
#endif
	TR_ASSERT(transport, first_path == connect_to_path);
	connect_to_path->path.established = true;
	drbd_path_event(transport, &connect_to_path->path);
#ifdef _WIN32_V9 // _WIN32_V9_PATCH_1
	dtt_put_listeners(transport);
#else
	dtt_put_listeners(transport);
#endif

#ifdef _WIN32
    LONG InputBuffer = 1;
    status = ControlSocket(dsocket->sk, WskSetOption, SO_REUSEADDR, SOL_SOCKET, sizeof(ULONG), &InputBuffer, 0, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        WDRBD_ERROR("ControlSocket: SO_REUSEADDR: failed=0x%x\n", status); // EVENTLOG
        goto out;
    }

    status = ControlSocket(csocket->sk, WskSetOption, SO_REUSEADDR, SOL_SOCKET, sizeof(ULONG), &InputBuffer, 0, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        WDRBD_ERROR("ControlSocket: SO_REUSEADDR: failed=0x%x\n", status); // EVENTLOG
        goto out;
    }
#else
	dsocket->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
	csocket->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */

	dsocket->sk->sk_allocation = GFP_NOIO;
	csocket->sk->sk_allocation = GFP_NOIO;

	dsocket->sk->sk_priority = TC_PRIO_INTERACTIVE_BULK;
	csocket->sk->sk_priority = TC_PRIO_INTERACTIVE;
#endif
	/* NOT YET ...
	 * sock.socket->sk->sk_sndtimeo = transport->net_conf->timeout*HZ/10;
	 * sock.socket->sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;
	 * first set it to the P_CONNECTION_FEATURES timeout,
	 * which we set to 4x the configured ping_timeout. */

	/* we don't want delays.
	 * we use TCP_CORK where appropriate, though */
	dtt_nodelay(dsocket);
	dtt_nodelay(csocket);

	tcp_transport->stream[DATA_STREAM] = dsocket;
	tcp_transport->stream[CONTROL_STREAM] = csocket;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);

	timeout = nc->timeout * HZ / 10;
	rcu_read_unlock();

#ifdef _WIN32
	dsocket->sk_linux_attr->sk_sndtimeo = timeout;
	csocket->sk_linux_attr->sk_sndtimeo = timeout;
#else
	dsocket->sk->sk_sndtimeo = timeout;
	csocket->sk->sk_sndtimeo = timeout;
#endif

	return 0;

out_eagain:
	err = -EAGAIN;

	if (0) {
out_unlock:
		mutex_unlock(&tcp_transport->paths_mutex);
	}
out:
	dtt_put_listeners(transport);

	if (dsocket)
		sock_release(dsocket);
	if (csocket)
		sock_release(csocket);

	return err;
}

static void dtt_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];
#ifdef _WIN32_V9
	socket->sk_linux_attr->sk_rcvtimeo = timeout;
#else
	socket->sk->sk_rcvtimeo = timeout;
#endif
}

static long dtt_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];
#ifdef _WIN32_V9
	return socket->sk_linux_attr->sk_rcvtimeo;
#else
	return socket->sk->sk_rcvtimeo;
#endif
}

static bool dtt_stream_ok(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);

	struct socket *socket = tcp_transport->stream[stream];

	return socket && socket->sk;
}

static void dtt_update_congested(struct drbd_tcp_transport *tcp_transport)
{
#ifdef _WIN32
#if 0 
	// WDRBD: not support data socket congestion
	struct sock *sock = tcp_transport->stream[DATA_STREAM]->sk_linux_attr;
	struct _buffering_attr *buffering_attr = &tcp_transport->stream[DATA_STREAM]->buffering_attr;
	struct ring_buffer *bab = buffering_attr->bab;

    int sk_wmem_queued = 0;
    if (bab)
    {
        sk_wmem_queued = bab->sk_wmem_queued;
    }
	else
	{
		// JHKIM: don't know how to get WSK tx buffer usage yet. Ignore it.
	}
	
	WDRBD_TRACE_TR("dtt_update_congested:  sndbuf=%d sk_wmem_queued=%d\n", sock->sk_sndbuf, sk_wmem_queued);

	if (sk_wmem_queued > sock->sk_sndbuf * 4 / 5) // reached 80%
    {
		set_bit(NET_CONGESTED, &tcp_transport->transport.flags);
    }
#endif
#else
	struct sock *sock = tcp_transport->stream[DATA_STREAM]->sk;

	if (sock->sk_wmem_queued > sock->sk_sndbuf * 4 / 5)
		set_bit(NET_CONGESTED, &tcp_transport->transport.flags);
#endif
}

// 기존 V8 에서 xxx_send_page 가 사용되지 않고는 있으나... V9 포팅에서 다시 확인이 필요하다. => BUG 처리하고, _drbd_no_send_page 로 유도한다.
// _drbd_no_send_page 는 결국 dtt_send_page 를 호출하게 된다.... dtt 계층에서 기존의 V8 의 _drbd_no_send_page 를 구현해줄 함수가 필요.
// V8 은 no_send_page 방식의 경우 drbd_sendall/drbd_send 를 호출하여 V9 기준의 _dtt_send 를 호출하는 구조이다.
// V9 은 no_send_page 방식의 경우에도 dtt_send_page 를 호출하여 send_page 방식과 동일한 인터페이스를 사용하게 되어 있다.
// _dtt_send 는 dtt_connect 시점의 dtt_send_first_packet 에 의해서만 사용된다.
// V9은 no_send_page, send_page 두 방식 다 dtt_send_page 로 단일 인터페이스를 사용하여 전송한다.

// kmpak
// 이 함수에서는 page 구조체로 argument를 받지만 실은 실제 buffer의 주소를 받도록 한다.
// 상위에서 bio_databuf,req_databuf,peer_req_databuf 를 주는 경우에 대해서도 처리하기 위함.
static int dtt_send_page(struct drbd_transport *transport, enum drbd_stream stream,
			 struct page *page, int offset, size_t size, unsigned msg_flags)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct socket *socket = tcp_transport->stream[stream];

#ifdef _WIN32_V9
	if(!socket) { // DW-674 safely uncork operation, if socket is not NULL.(drbd 8.4.x referenced)
		return -EIO;
	}
#endif
	
#ifndef _WIN32
	mm_segment_t oldfs = get_fs();
#endif
	int len = size;
	int err = -EIO;

	msg_flags |= MSG_NOSIGNAL;
	dtt_update_congested(tcp_transport);
#ifndef _WIN32
	set_fs(KERNEL_DS);
#endif
	do {
		int sent;
#ifdef _WIN32
		if (stream == DATA_STREAM)
		{
			// ignore rcu_dereference
			transport->ko_count = transport->net_conf->ko_count;
		}

#ifdef _WIN32_SEND_BUFFING 
		sent = send_buf(transport, stream, socket, (void *)((unsigned char *)(page) +offset), len);
		// WIN32_SEND_ERR_FIX: we_should_drop_the_connection 부분을 send_buf 내에서 처리, 
		// send_buf 외부에서 처리하면 재 송신이 발생하기 때문임.
#else
#if 1 
		sent = Send(socket->sk, (void *)((unsigned char *)(page) + offset), len, 0, socket->sk_linux_attr->sk_sndtimeo, NULL, transport, stream);
#else // old V8 org
		sent = Send(socket->sk, (void *)((unsigned char *)(page) + offset), len, 0, socket->sk_linux_attr->sk_sndtimeo);
		WDRBD_TRACE_TR("sendpage sent(%d/%d) offset(%d) socket(0x%p)\n", sent, len, offset, socket);
#endif
#endif
#else
		sent = socket->ops->sendpage(socket, page, offset, len, msg_flags);
#endif
		if (sent <= 0) {
#ifdef _WIN32_SEND_BUFFING
			if (sent == -EAGAIN) 
			{
				break;
			}
#else
			if (sent == -EAGAIN) {
				if (drbd_stream_send_timed_out(transport, stream))
					break;
				continue;
			}
#endif
			tr_warn(transport, "%s: size=%d len=%d sent=%d\n",
			     __func__, (int)size, len, sent);
			if (sent < 0)
				err = sent;
			break;
		}
		len    -= sent;
		offset += sent;
	} while (len > 0 /* THINK && peer_device->repl_state[NOW] >= L_ESTABLISHED */);
#ifndef _WIN32
	set_fs(oldfs);
#endif
	clear_bit(NET_CONGESTED, &tcp_transport->transport.flags);

	if (len == 0)
		err = 0;

	return err;
}

static int dtt_send_zc_bio(struct drbd_transport *transport, struct bio *bio)
{
	DRBD_BIO_VEC_TYPE bvec;
	DRBD_ITER_TYPE iter;

	bio_for_each_segment(bvec, bio, iter) {
		int err;

		err = dtt_send_page(transport, DATA_STREAM, bvec BVD bv_page,
				      bvec BVD bv_offset, bvec BVD bv_len,
				      bio_iter_last(bvec, iter) ? 0 : MSG_MORE);
		if (err)
			return err;

		if (bio->bi_rw & DRBD_REQ_WSAME)
			break;
	}
	return 0;
}

static void dtt_cork(struct socket *socket)
{
#ifndef _WIN32 // not support.
	int val = 1;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val));
#endif
}

static void dtt_uncork(struct socket *socket)
{
#ifndef _WIN32 // not support.
	int val = 0;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_CORK, (char *)&val, sizeof(val));
#endif
}

static void dtt_quickack(struct socket *socket)
{
#ifndef _WIN32 // not support.
	int val = 2;
	(void) kernel_setsockopt(socket, SOL_TCP, TCP_QUICKACK, (char *)&val, sizeof(val));
#endif
}

static bool dtt_hint(struct drbd_transport *transport, enum drbd_stream stream,
		enum drbd_tr_hints hint)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	bool rv = true;
	struct socket *socket = tcp_transport->stream[stream];

	if (!socket)
		return false;

	switch (hint) {
	case CORK:
		dtt_cork(socket);
		break;
	case UNCORK:
		dtt_uncork(socket);
		break;
	case NODELAY:
		dtt_nodelay(socket);
		break;
	case NOSPACE:
#ifndef _WIN32 // not support. SOCK_NOSPACE 옵션 필요한지 다시 검토 요망. _WIN32_V9
		if (socket->sk->sk_socket)
			set_bit(SOCK_NOSPACE, &socket->sk->sk_socket->flags);
#endif
		break;
	case QUICKACK:
		dtt_quickack(socket);
		break;
	default: /* not implemented, but should not trigger error handling */
		return true;
	}

	return rv;
}

static void dtt_debugfs_show_stream(struct seq_file *m, struct socket *socket)
{
#ifndef _WIN32 // 필요한지 추후 검토
	struct sock *sk = socket->sk;
	struct tcp_sock *tp = tcp_sk(sk);

	seq_printf(m, "unread receive buffer: %u Byte\n",
		   tp->rcv_nxt - tp->copied_seq);
	seq_printf(m, "unacked send buffer: %u Byte\n",
		   tp->write_seq - tp->snd_una);
	seq_printf(m, "send buffer size: %u Byte\n", sk->sk_sndbuf);
	seq_printf(m, "send buffer used: %u Byte\n", sk->sk_wmem_queued);
#endif
}

static void dtt_debugfs_show(struct drbd_transport *transport, struct seq_file *m)
{
#ifndef _WIN32 // 필요한지 추후 검토
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	enum drbd_stream i;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		struct socket *socket = tcp_transport->stream[i];

		if (socket) {
			seq_printf(m, "%s stream\n", i == DATA_STREAM ? "data" : "control");
			dtt_debugfs_show_stream(m, socket);
		}
	}
#endif
}

static int dtt_add_path(struct drbd_transport *transport, struct drbd_path *drbd_path)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);
	int err = 0;

	path->waiter.transport = transport;
	drbd_path->established = false;

	mutex_lock(&tcp_transport->paths_mutex);
	if (test_bit(DTT_CONNECTING, &tcp_transport->flags)) {
		err = drbd_get_listener(&path->waiter, (struct sockaddr *)&drbd_path->my_addr,
					dtt_create_listener);
		if (err)
			goto out_unlock;
	}

	list_add(&drbd_path->list, &transport->paths);

out_unlock:
	mutex_unlock(&tcp_transport->paths_mutex);

	return err;
}

static int dtt_remove_path(struct drbd_transport *transport, struct drbd_path *drbd_path)
{
	struct drbd_tcp_transport *tcp_transport =
		container_of(transport, struct drbd_tcp_transport, transport);
	struct dtt_path *path = container_of(drbd_path, struct dtt_path, path);

	if (drbd_path->established)
		return -EBUSY;

	mutex_lock(&tcp_transport->paths_mutex);
	list_del_init(&drbd_path->list);
	drbd_put_listener(&path->waiter);
	mutex_unlock(&tcp_transport->paths_mutex);

	return 0;
}

#ifdef _WIN32_V9
int __init dtt_initialize(void)
#else
static int __init dtt_initialize(void)
#endif
{
	return drbd_register_transport_class(&tcp_transport_class,
					     DRBD_TRANSPORT_API_VERSION,
					     sizeof(struct drbd_transport));
}

static void __exit dtt_cleanup(void)
{
	drbd_unregister_transport_class(&tcp_transport_class);
}

#ifdef _WIN32_SEND_BUFFING

extern VOID NTAPI send_buf_thread(PVOID p);

static bool dtt_start_send_buffring(struct drbd_transport *transport, int size)
{
	struct drbd_tcp_transport *tcp_transport = container_of(transport, struct drbd_tcp_transport, transport);

	if (size > 0 )
	{
		int i;
		for (int i = 0; i < 2; i++)
		{
			if (tcp_transport->stream[i] != NULL) // ASSERT
			{
				struct _buffering_attr *attr = &tcp_transport->stream[i]->buffering_attr;

				if (attr->bab != NULL)
				{
					tr_warn(transport, "Unexpected: send buffer bab(%s) already exists!\n", tcp_transport->stream[i]->name);
					BUG(); // JHKIM: 안정화후 제거.
				}

				if (attr->send_buf_thread_handle != NULL)
				{
					tr_warn(transport, "Unexpected: send buffer thread(%s) already exists!\n", tcp_transport->stream[i]->name);
					BUG(); // JHKIM: 안정화후 제거.
				}

				if (i == CONTROL_STREAM)
				{
					size = 1024 * 5120; // meta bab is about 5MB
				}

				if ((attr->bab = create_ring_buffer(tcp_transport->stream[i]->name, size)) != NULL)
				{
					KeInitializeEvent(&attr->send_buf_kill_event, SynchronizationEvent, FALSE);
					KeInitializeEvent(&attr->send_buf_killack_event, SynchronizationEvent, FALSE);
					KeInitializeEvent(&attr->send_buf_thr_start_event, SynchronizationEvent, FALSE);
					KeInitializeEvent(&attr->ring_buf_event, SynchronizationEvent, FALSE);

					NTSTATUS Status = PsCreateSystemThread(&attr->send_buf_thread_handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, send_buf_thread, attr);
					if (!NT_SUCCESS(Status)) {
						tr_warn(transport, "send-buffering: create thread(%s) failed(0x%08X)\n", tcp_transport->stream[i]->name, Status);
						destroy_ring_buffer(attr->bab);
						attr->bab = NULL;
						return FALSE;
					}

					// wait send buffering thread start...
					KeWaitForSingleObject(&attr->send_buf_thr_start_event, Executive, KernelMode, FALSE, NULL);
				}
				else
				{
					if (i == CONTROL_STREAM)
					{
						attr = &tcp_transport->stream[DATA_STREAM]->buffering_attr;

						// kill DATA_STREAM thread
						KeSetEvent(&attr->send_buf_kill_event, 0, FALSE);
						//WDRBD_INFO("wait for send_buffering_data_thread(%s) ack\n", tcp_transport->stream[i]->name);
						KeWaitForSingleObject(&attr->send_buf_killack_event, Executive, KernelMode, FALSE, NULL);
						//WDRBD_INFO("send_buffering_data_thread(%s) acked\n", tcp_transport->stream[i]->name);
						attr->send_buf_thread_handle = NULL;
						
						// free DATA_STREAM bab
						destroy_ring_buffer(attr->bab);
						attr->bab = NULL;
					}
					return FALSE;
				}
			}
			else
			{
				tr_warn(transport, "Unexpected: send buffer socket(channel:%d) is null!\n", i);
				BUG(); // JHKIM: 안정화후 제거.
			}
		}
		return TRUE;
	}
	return FALSE;
}

static void dtt_stop_send_buffring(struct drbd_transport *transport)
{
	struct drbd_tcp_transport *tcp_transport = container_of(transport, struct drbd_tcp_transport, transport);
	struct _buffering_attr *attr;
	int err_ret = 0;
	int i;

	for (int i = 0; i < 2; i++)
	{
		if (tcp_transport->stream[i] != NULL)
		{
			attr = &tcp_transport->stream[i]->buffering_attr;

			if (attr->send_buf_thread_handle != NULL)
			{
				KeSetEvent(&attr->send_buf_kill_event, 0, FALSE);
				//WDRBD_INFO("wait for send_buffering_data_thread(%s) ack\n", tcp_transport->stream[i]->name);
				KeWaitForSingleObject(&attr->send_buf_killack_event, Executive, KernelMode, FALSE, NULL);
				//WDRBD_INFO("send_buffering_data_thread(%s) acked\n", tcp_transport->stream[i]->name);
				attr->send_buf_thread_handle = NULL;
			}
			else
			{
				WDRBD_WARN("No send_buffering thread(%s)\n", tcp_transport->stream[i]->name);
			}
		}
		else
		{
			//WDRBD_WARN("No stream(channel:%d)\n", i);
		}
	}
	return;
}
#endif // _WIN32_SEND_BUFFING

#ifndef _WIN32
module_init(dtt_initialize)
module_exit(dtt_cleanup)
#endif
