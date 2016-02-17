#ifdef _WIN32

#include <drbd_transport.h>
#include "drbd_int.h"

#else
#include <linux/module.h>
#endif

#ifndef _WIN32
MODULE_AUTHOR("xxx");
MODULE_DESCRIPTION("xxx transport layer for DRBD");
MODULE_LICENSE("GPL");
#endif

struct drbd_xxx_transport {
	struct drbd_transport transport;
	/* xxx */
};

struct xxx_listener {
	struct drbd_listener listener;
	/* xxx */
};

struct xxx_waiter {
	struct drbd_waiter waiter;
	/* xxx */
};

static struct drbd_transport *xxx_create(struct drbd_connection* connection);
static void xxx_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op);
static int xxx_connect(struct drbd_transport *transport);
static int xxx_recv(struct drbd_transport *transport, enum drbd_stream stream, void *buf, size_t size, int flags);
static void xxx_stats(struct drbd_transport* transport, struct drbd_transport_stats *stats);
static void xxx_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout);
static long xxx_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream);
static int xxx_send_page(struct drbd_transport *transport, enum drbd_stream stream, struct page *page,
		    int offset, size_t size, unsigned msg_flags);
static bool xxx_stream_ok(struct drbd_transport *transport, enum drbd_stream stream);
static bool xxx_hint(struct drbd_transport *transport, enum drbd_stream stream, enum drbd_tr_hints hint);


static struct drbd_transport_class xxx_transport_class = {
	.name = "xxx",
#ifdef _WIN32_CHECK // drbd_transport_class 구조체에 create 필드가 존재하지 않는다. 이해되지 않는 부분.
	.create = xxx_create,
#endif
	.list = LIST_HEAD_INIT(xxx_transport_class.list),
};

static struct drbd_transport_ops xxx_ops = {
	.free = xxx_free,
	.connect = xxx_connect,
	.recv = xxx_recv,
	.stats = xxx_stats,
	.set_rcvtimeo = xxx_set_rcvtimeo,
	.get_rcvtimeo = xxx_get_rcvtimeo,
	.send_page = xxx_send_page,
	.stream_ok = xxx_stream_ok,
	.hint = xxx_hint,
};


static struct drbd_transport *xxx_create(struct drbd_connection* connection)
{
	struct drbd_xxx_transport *xxx_transport;

#ifdef _WIN32_TODO //V9 포팅 필요. try_module_get is linux kernel func., THIS_MODULE is linux define
	if (!try_module_get(THIS_MODULE))
		return NULL;
#endif

	xxx_transport = kzalloc(sizeof(struct drbd_xxx_transport), GFP_KERNEL);
	if (!xxx_transport) {
#ifdef _WIN32_TODO //V9 포팅 필요. module_put is linux kernel func., THIS_MODULE is linux define
		module_put(THIS_MODULE);
#endif
		return NULL;
	}

	xxx_transport->transport.ops = &xxx_ops;
#ifdef _WIN32_CHECK // drbd_transport_class 구조체에 connection 필드가 존재하지 않는다. 이해되지 않는 부분.
	xxx_transport->transport.connection = connection;
#endif
	return &xxx_transport->transport;
}

static void xxx_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op)
{
	struct drbd_xxx_transport *xxx_transport =
		container_of(transport, struct drbd_xxx_transport, transport);

	/* disconnect here */

	if (free_op == DESTROY_TRANSPORT) {
		kfree(xxx_transport);
#ifdef _WIN32_TODO //V9 포팅 필요. module_put is linux kernel func., THIS_MODULE is linux define
		module_put(THIS_MODULE);
#endif
	}
}

static int xxx_send(struct drbd_transport *transport, enum drbd_stream stream, void *buf, size_t size, unsigned msg_flags)
{
	struct drbd_xxx_transport *xxx_transport =
		container_of(transport, struct drbd_xxx_transport, transport);

	return 0;
}

static int xxx_recv(struct drbd_transport *transport, enum drbd_stream stream, void *buf, size_t size, int flags)
{
	struct drbd_xxx_transport *xxx_transport =
		container_of(transport, struct drbd_xxx_transport, transport);

	return 0;
}

static void xxx_stats(struct drbd_transport* transport, struct drbd_transport_stats *stats)
{
}

static int xxx_connect(struct drbd_transport *transport)
{
	struct drbd_xxx_transport *xxx_transport =
		container_of(transport, struct drbd_xxx_transport, transport);

	return true;
}

static void xxx_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream, long timeout)
{
}

static long xxx_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream)
{
	return 0;
}

static bool xxx_stream_ok(struct drbd_transport *transport, enum drbd_stream stream)
{
	return true;
}

static int xxx_send_page(struct drbd_transport *transport, enum drbd_stream stream, struct page *page,
		    int offset, size_t size, unsigned msg_flags)
{
	return 0;
}

static bool xxx_hint(struct drbd_transport *transport, enum drbd_stream stream,
		enum drbd_tr_hints hint)
{
	switch (hint) {
	default: /* not implemented, but should not trigger error handling */
		return true;
	}
	return true;
}

static int __init xxx_init(void)
{
#ifdef _WIN32
	return 0; // 임시 리턴 0으로 처리. _WIN32_CHECK
#else
	return drbd_register_transport_class(&xxx_transport_class);
#endif
}

static void __exit xxx_cleanup(void)
{
	drbd_unregister_transport_class(&xxx_transport_class);
}

#ifdef _WIN32_CHECK
module_init(xxx_init)
module_exit(xxx_cleanup)
#endif