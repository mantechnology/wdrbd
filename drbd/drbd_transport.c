#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt
#ifdef _WIN32
#include "linux-compat/spinlock.h"
#else
#include <linux/spinlock.h>
#include <linux/module.h>
#include <net/ipv6.h>
#endif
#include <drbd_transport.h>
#include <drbd_int.h>

static LIST_HEAD(transport_classes);
#ifdef _WIN32
extern int __init dtt_initialize(void);
KSPIN_LOCK	transport_classes_lock;
#else
static DECLARE_RWSEM(transport_classes_lock);
#endif

static struct drbd_transport_class *__find_transport_class(const char *transport_name)
{
	struct drbd_transport_class *transport_class;

#ifdef _WIN32
	list_for_each_entry(struct drbd_transport_class, transport_class, &transport_classes, list)
#else
	list_for_each_entry(transport_class, &transport_classes, list)
#endif
		if (!strcmp(transport_class->name, transport_name))
			return transport_class;

	return NULL;
}

int drbd_register_transport_class(struct drbd_transport_class *transport_class, int version,
				  int drbd_transport_size)
{
	int rv = 0;
	if (version != DRBD_TRANSPORT_API_VERSION) {
		pr_err("DRBD_TRANSPORT_API_VERSION not compatible\n");
		return -EINVAL;
	}

	if (drbd_transport_size != sizeof(struct drbd_transport)) {
		pr_err("sizeof(drbd_transport) not compatible\n");
		return -EINVAL;
	}

	down_write(&transport_classes_lock);
	if (__find_transport_class(transport_class->name)) {
		pr_err("transport class '%s' already registered\n", transport_class->name);
		rv = -EEXIST;
	} else
		list_add_tail(&transport_class->list, &transport_classes);
	up_write(&transport_classes_lock);
	return rv;
}

void drbd_unregister_transport_class(struct drbd_transport_class *transport_class)
{
	down_write(&transport_classes_lock);
	if (!__find_transport_class(transport_class->name)) {
		pr_crit("unregistering unknown transport class '%s'\n",
			transport_class->name);
		BUG();
	}
	list_del_init(&transport_class->list);
	up_write(&transport_classes_lock);
}

static struct drbd_transport_class *get_transport_class(const char *name)
{
	struct drbd_transport_class *tc;

	down_read(&transport_classes_lock);
	tc = __find_transport_class(name);
#ifdef _WIN32
    // try_module_get() not support!
#else
	if (tc && !try_module_get(tc->module))
		tc = NULL;
#endif
	up_read(&transport_classes_lock);
	return tc;
}

struct drbd_transport_class *drbd_get_transport_class(const char *name)
{
	struct drbd_transport_class *tc = get_transport_class(name);

	if (!tc) {
#ifdef _WIN32
		// request_module is not support
		dtt_initialize();
#else
		request_module("drbd_transport_%s", name);
#endif
		tc = get_transport_class(name);
	}

	return tc;
}

#ifndef _WIN32
void drbd_put_transport_class(struct drbd_transport_class *tc)
{
	/* convenient in the error cleanup path */
	if (!tc)
		return;
	down_read(&transport_classes_lock);
	module_put(tc->module);
	up_read(&transport_classes_lock);
}
#endif

void drbd_print_transports_loaded(struct seq_file *seq)
{
	struct drbd_transport_class *tc;

	down_read(&transport_classes_lock);

	seq_puts(seq, "Transports (api:" __stringify(DRBD_TRANSPORT_API_VERSION) "):");
#ifdef _WIN32
	list_for_each_entry(struct drbd_transport_class, tc, &transport_classes, list) {
#else
	list_for_each_entry(tc, &transport_classes, list) {
#endif
#ifdef _WIN32
		seq_printf(seq, " %s ", tc->name);
#else
		seq_printf(seq, " %s (%s)", tc->name,
				tc->module->version ? tc->module->version : "NONE");
#endif
	}
	seq_putc(seq, '\n');

	up_read(&transport_classes_lock);
}

#ifdef _WIN32
static bool addr_equal(const struct sockaddr_storage_win *addr1, const struct sockaddr_storage_win *addr2)
#else
static bool addr_equal(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2)
#endif
{
	if (addr1->ss_family != addr2->ss_family)
		return false;

	if (addr1->ss_family == AF_INET6) {
		const struct sockaddr_in6 *v6a1 = (const struct sockaddr_in6 *)addr1;
		const struct sockaddr_in6 *v6a2 = (const struct sockaddr_in6 *)addr2;
#ifdef _WIN32
		if (!IN6_ADDR_EQUAL(&v6a1->sin6_addr, &v6a2->sin6_addr))
#else
		if (!ipv6_addr_equal(&v6a1->sin6_addr, &v6a2->sin6_addr))
#endif
			return false;
#ifdef _WIN32
		else if (IN6_IS_ADDR_LINKLOCAL(&v6a1->sin6_addr))
#else
		else if (ipv6_addr_type(&v6a1->sin6_addr) & IPV6_ADDR_LINKLOCAL)
#endif
			return v6a1->sin6_scope_id == v6a2->sin6_scope_id;
		return true;
	} else /* AF_INET, AF_SSOCKS, AF_SDP */ {
		const struct sockaddr_in *v4a1 = (const struct sockaddr_in *)addr1;
		const struct sockaddr_in *v4a2 = (const struct sockaddr_in *)addr2;

		return v4a1->sin_addr.s_addr == v4a2->sin_addr.s_addr;
	}
}

#ifdef _WIN32
bool addr_and_port_equal(const struct sockaddr_storage_win *addr1, const struct sockaddr_storage_win *addr2)
#else
static bool addr_and_port_equal(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2)
#endif
{
	if (!addr_equal(addr1, addr2))
		return false;

	if (addr1->ss_family == AF_INET6) {
		const struct sockaddr_in6 *v6a1 = (const struct sockaddr_in6 *)addr1;
		const struct sockaddr_in6 *v6a2 = (const struct sockaddr_in6 *)addr2;

		return v6a1->sin6_port == v6a2->sin6_port;
	} else /* AF_INET, AF_SSOCKS, AF_SDP */ {
		const struct sockaddr_in *v4a1 = (const struct sockaddr_in *)addr1;
		const struct sockaddr_in *v4a2 = (const struct sockaddr_in *)addr2;

		return v4a1->sin_port == v4a2->sin_port;
	}

	return false;
}

static struct drbd_listener *find_listener(struct drbd_connection *connection,
					   const struct sockaddr_storage *addr)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_listener *listener;
#ifdef _WIN32
	list_for_each_entry(struct drbd_listener, listener, &resource->listeners, list) {
		if (addr_and_port_equal(&listener->listen_addr, (const struct sockaddr_storage_win *)addr)) {
#if 0 // reference V8.x org 
	struct drbd_path *path;
#ifdef _WIN32
	list_for_each_entry(struct drbd_listener, listener, &resource->listeners, list) {
		list_for_each_entry(struct drbd_path, path, &connection->transport.paths, list) {
#else
	list_for_each_entry(listener, &resource->listeners, list) {
		list_for_each_entry(path, &connection->transport.paths, list) {
#endif
			if (addr_and_port_equal(&listener->listen_addr, &path->my_addr)) {
				kref_get(&listener->kref);
				return listener;
			}
#endif // V8 org
#else
	list_for_each_entry(listener, &resource->listeners, list) {
		if (addr_and_port_equal(&listener->listen_addr, addr)) {
#endif
		
			kref_get(&listener->kref);
			return listener;
		}
	}
	return NULL;
}

int drbd_get_listener(struct drbd_transport *transport, struct drbd_path *path,
	int(*create_listener)(struct drbd_transport *, const struct sockaddr *addr, struct drbd_listener **))
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);
	struct sockaddr *addr = (struct sockaddr *)&path->my_addr;
	struct drbd_resource *resource = connection->resource;
	struct drbd_listener *listener, *new_listener = NULL;
	int err, tries = 0;

	while (true, true) {
		spin_lock_bh(&resource->listeners_lock);
		listener = find_listener(connection, (struct sockaddr_storage *)addr);
		if (!listener && new_listener) {
			list_add(&new_listener->list, &resource->listeners);
			listener = new_listener;
			new_listener = NULL;
		}
		if (listener) {
			list_add(&path->listener_link, &listener->waiters);
			path->listener = listener;
		}
		spin_unlock_bh(&resource->listeners_lock);

		if (new_listener)
			new_listener->destroy(new_listener);

		if (listener)
			return 0;

		err = create_listener(transport, addr, &new_listener);
		if (err) {
			if (err == -EADDRINUSE && ++tries < 3) {
				schedule_timeout_uninterruptible(HZ / 20);
				continue;
			}
			return err;
		}

		kref_init(&new_listener->kref);
		INIT_LIST_HEAD(&new_listener->waiters);
		new_listener->resource = resource;
		new_listener->pending_accepts = 0;
		spin_lock_init(&new_listener->waiters_lock);
	}
}

static void drbd_listener_destroy(struct kref *kref)
{
	struct drbd_listener *listener = container_of(kref, struct drbd_listener, kref);
	struct drbd_resource *resource = listener->resource;

	spin_lock_bh(&resource->listeners_lock);
	list_del(&listener->list);
	spin_unlock_bh(&resource->listeners_lock);

	listener->destroy(listener);
}

void drbd_put_listener(struct drbd_path *path)
{
	struct drbd_resource *resource;
	struct drbd_listener *listener;

#ifdef _WIN32
	// DW-1538: Sometimes null values come in. 
	if (!path)
		return;

	listener = (struct drbd_listener*)xchg((LONG_PTR*)&path->listener, (LONG_PTR)NULL);
#else
	listener = xchg(&path->listener, NULL);
#endif
	if (!listener)
		return;

	resource = listener->resource;
	spin_lock_bh(&resource->listeners_lock);
	list_del(&path->listener_link);
	spin_unlock_bh(&resource->listeners_lock);
	kref_put(&listener->kref, drbd_listener_destroy);
}

#ifdef _WIN32
extern char * get_ip4(char *buf, struct sockaddr_in *sockaddr);
extern char * get_ip6(char *buf, struct sockaddr_in6 *sockaddr);
#endif

#ifdef _WIN32
struct drbd_path *drbd_find_path_by_addr(struct drbd_listener *listener, struct sockaddr_storage_win *addr)
#else
struct drbd_waiter *drbd_find_waiter_by_addr(struct drbd_listener *listener, struct sockaddr_storage *addr)
#endif
{
	struct drbd_path *path;

#ifdef _WIN32
	// DW-1481 fix listener->list's NULL dereference, sanity check 
	if(!addr || !listener || (listener->list.next == NULL) ) {
		return NULL;
	}
	list_for_each_entry(struct drbd_path, path, &listener->waiters, listener_link) {
		//WDRBD_TRACE_CO("[%p] drbd_find_waiter_by_addr: pathr=%p\n", KeGetCurrentThread(), path);
#else
	list_for_each_entry(path, &listener->waiters, listener_link) {
#endif

#ifdef _WIN32
			char sbuf[128], dbuf[128];
			if (path->peer_addr.ss_family == AF_INET6) {
				WDRBD_TRACE_CO("[%p] path->peer:%s addr:%s \n", KeGetCurrentThread(), get_ip6(sbuf, (struct sockaddr_in6*)&path->peer_addr), get_ip6(dbuf, (struct sockaddr_in6*)addr));
			} else {
				WDRBD_TRACE_CO("[%p] path->peer:%s addr:%s \n", KeGetCurrentThread(), get_ip4(sbuf, (struct sockaddr_in*)&path->peer_addr), get_ip4(dbuf, (struct sockaddr_in*)addr));
			}
#endif
			if (addr_equal(&path->peer_addr, addr))
				return path;
	}

	return NULL;
}

/**
 * drbd_stream_send_timed_out() - Tells transport if the connection should stay alive
 * @connection:	DRBD connection to operate on.
 * @stream:     DATA_STREAM or CONTROL_STREAM
 *
 * When it returns true, the transport should return -EAGAIN to its caller of the
 * send function. When it returns false the transport should keep on trying to
 * get the packet through.
 */
bool drbd_stream_send_timed_out(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);
	bool drop_it;

	drop_it = stream == CONTROL_STREAM
		|| !connection->ack_receiver.task
		|| get_t_state(&connection->ack_receiver) != RUNNING
		|| connection->cstate[NOW] < C_CONNECTED;

	if (drop_it)
		return true;

	drop_it = !--connection->transport.ko_count;
	if (!drop_it) {
		drbd_err(connection, "[%s/%d] sending time expired, ko = %u\n",
			 current->comm, current->pid, connection->transport.ko_count);
		request_ping(connection);
	}

	return drop_it;

}

bool drbd_should_abort_listening(struct drbd_transport *transport)
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);
	bool abort = false;

	if (connection->cstate[NOW] <= C_DISCONNECTING)
		abort = true;
	if (signal_pending(current)) {
		flush_signals(current);
		smp_rmb();
		if (get_t_state(&connection->receiver) == EXITING)
			abort = true;
	}

	return abort;
}

/* Called by a transport if a path was established / disconnected */
void drbd_path_event(struct drbd_transport *transport, struct drbd_path *path)
{
	struct drbd_connection *connection =
		container_of(transport, struct drbd_connection, transport);

	notify_path(connection, path, NOTIFY_CHANGE);
}

#ifndef _WIN32
/* Network transport abstractions */
EXPORT_SYMBOL_GPL(drbd_register_transport_class);
EXPORT_SYMBOL_GPL(drbd_unregister_transport_class);
EXPORT_SYMBOL_GPL(drbd_get_listener);
EXPORT_SYMBOL_GPL(drbd_put_listener);
EXPORT_SYMBOL_GPL(drbd_find_path_by_addr);
EXPORT_SYMBOL_GPL(drbd_stream_send_timed_out);
EXPORT_SYMBOL_GPL(drbd_should_abort_listening);
EXPORT_SYMBOL_GPL(drbd_path_event);
#endif