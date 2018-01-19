#ifndef DRBD_TRANSPORT_H
#define DRBD_TRANSPORT_H
#ifdef _WIN32
#include "linux-compat/list.h"
#include "linux-compat/wait.h"
#include "drbd_windows.h"
#else
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/socket.h>
#endif

/* Whenever touch this file in a non-trivial way, increase the
   DRBD_TRANSPORT_API_VERSION
   So that transport compiled against an older version of this
   header will no longer load in a module that assumes a newer
   version. */
#define DRBD_TRANSPORT_API_VERSION 14

/* MSG_MSG_DONTROUTE and MSG_PROBE are not used by DRBD. I.e.
   we can reuse these flags for our purposes */
#define CALLER_BUFFER  MSG_DONTROUTE
#define GROW_BUFFER    MSG_PROBE

#ifdef _WIN32
#define SOCKET_SND_DEF_BUFFER 		(16384)
#endif
/*
 * gfp_mask for allocating memory with no write-out.
 *
 * When drbd allocates memory on behalf of the peer, we prevent it from causing
 * write-out because in a criss-cross setup, the write-out could lead to memory
 * pressure on the peer, eventually leading to deadlock.
 */
#define GFP_TRY	(__GFP_HIGHMEM | __GFP_NOWARN | __GFP_RECLAIM)
#ifdef _WIN32
#define tr_printk(level, transport, fmt, ...)  do {		\
	rcu_read_lock();					\
	printk(level "drbd %s: " fmt,			\
	       rcu_dereference((transport)->net_conf)->name,	\
	       __VA_ARGS__);					\
	rcu_read_unlock();					\
	}while (0)

#define tr_err(transport, fmt, ...) \
	tr_printk(KERN_ERR, transport, fmt, ## __VA_ARGS__)
#define tr_warn(transport, fmt, ...) \
	tr_printk(KERN_WARNING, transport, fmt, ## __VA_ARGS__)
#define tr_info(transport, fmt, ...) \
	tr_printk(KERN_INFO, transport, fmt, ## __VA_ARGS__)
#else
#define tr_printk(level, transport, fmt, args...)  ({		\
	rcu_read_lock();					\
	printk(level "drbd %s %s:%s: " fmt,			\
	       (transport)->log_prefix,				\
	       (transport)->class->name,			\
	       rcu_dereference((transport)->net_conf)->name,	\
	       ## args);					\
	rcu_read_unlock();					\
	})

#define tr_err(transport, fmt, args...) \
	tr_printk(KERN_ERR, transport, fmt, ## args)
#define tr_warn(transport, fmt, args...) \
	tr_printk(KERN_WARNING, transport, fmt, ## args)
#define tr_info(transport, fmt, args...) \
	tr_printk(KERN_INFO, transport, fmt, ## args)
#endif
#define TR_ASSERT(x, exp)							\
	do {									\
		if (!(exp))							\
			tr_err(x, "ASSERTION %s FAILED in %s\n", 		\
				 #exp, __func__);				\
	} while (0)

struct drbd_resource;
struct drbd_connection;
struct drbd_peer_device;

enum drbd_stream {
	DATA_STREAM,
	CONTROL_STREAM
};

enum drbd_tr_hints {
	CORK,
	UNCORK,
	NODELAY,
	NOSPACE,
	QUICKACK
};

enum { /* bits in the flags word */
	NET_CONGESTED,		/* The data socket is congested */
	RESOLVE_CONFLICTS,	/* Set on one node, cleared on the peer! */
#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-1204: flag to flush send buffer when disconnecting.
	DISCONNECT_FLUSH,
#endif
};

enum drbd_tr_free_op {
	CLOSE_CONNECTION,
	DESTROY_TRANSPORT
};


/* A transport might wrap its own data structure around this. Having
   this base class as its first member. */
struct drbd_path {
#ifdef _WIN32
	struct sockaddr_storage_win my_addr;
	struct sockaddr_storage_win peer_addr;
#else
	struct sockaddr_storage my_addr;
	struct sockaddr_storage peer_addr;
#endif
	struct kref kref;

	int my_addr_len;
	int peer_addr_len;
	bool established; /* updated by the transport */

	struct list_head list;
};

/* Each transport implementation should embed a struct drbd_transport
   into it's instance data structure. */
struct drbd_transport {
	struct drbd_transport_ops *ops;
	struct drbd_transport_class *class;

	struct list_head paths;

	const char *log_prefix;		/* resource name */
	struct net_conf *net_conf;	/* content protected by rcu */

	/* These members are intended to be updated by the transport: */
	unsigned int ko_count;
#ifdef _WIN32
	ULONG_PTR flags;
#else
	unsigned long flags;
#endif
	
#ifdef _WIN32
	// DW-1398: accepted all peers and listening socket is no longer available.
	atomic_t listening_done;
#endif
};

struct drbd_transport_stats {
	int unread_received;
	int unacked_send;
	int send_buffer_size;
	int send_buffer_used;
};

/* argument to ->recv_pages() */
struct drbd_page_chain_head {
	struct page *head; // WIN32:used by void pointer to memory which alloccated by malloc()
	unsigned int nr_pages;
};

struct drbd_transport_ops {
	void (*free)(struct drbd_transport *, enum drbd_tr_free_op free_op);
	int (*connect)(struct drbd_transport *);

/**
 * recv() - Receive data via the transport
 * @transport:	The transport to use
 * @stream:	The stream within the transport to use. Ether DATA_STREAM or CONTROL_STREAM
 * @buf:	The function will place here the pointer to the data area
 * @size:	Number of byte to receive
 * @msg_flags:	Bitmask of CALLER_BUFFER, GROW_BUFFER and MSG_DONTWAIT
 *
 * recv() returns the requests data in a buffer (owned by the transport).
 * You may pass MSG_DONTWAIT as flags.  Usually with the next call to recv()
 * or recv_pages() on the same stream, the buffer may no longer be accessed
 * by the caller. I.e. it is reclaimed by the transport.
 *
 * If the transport was not capable of fulfilling the complete "wish" of the
 * caller (that means it returned a smaller size that size), the caller may
 * call recv() again with the flag GROW_BUFFER, and *buf as returned by the
 * previous call.
 * Note1: This can happen if MSG_DONTWAIT was used, or if a receive timeout
 *	was we with set_rcvtimeo().
 * Note2: recv() is free to re-locate the buffer in such a call. I.e. to
 *	modify *buf. Then it copies the content received so far to the new
 *	memory location.
 *
 * Last not least the caller may also pass an arbitrary pointer in *buf with
 * the CALLER_BUFFER flag. This is expected to be used for small amounts
 * of data only
 *
 * Upon success the function returns the bytes read. Upon error the return
 * code is negative. A 0 indicates that the socket was closed by the remote
 * side.
 */
	int (*recv)(struct drbd_transport *, enum drbd_stream, void **buf, size_t size, int flags);

/**
 * recv_pages() - Receive bulk data via the transport's DATA_STREAM
 * @peer_device: Identify the transport and the device
 * @page_chain:	Here recv_pages() will place the page chain head and length
 * @size:	Number of bytes to receive
 *
 * recv_pages() will return the requested amount of data from DATA_STREAM,
 * and place it into pages allocated with drbd_alloc_pages().
 *
 * Upon success the function returns 0. Upon error the function returns a
 * negative value
 */
	int (*recv_pages)(struct drbd_transport *, struct drbd_page_chain_head *, size_t size);

	void (*stats)(struct drbd_transport *, struct drbd_transport_stats *stats);
	void (*set_rcvtimeo)(struct drbd_transport *, enum drbd_stream, long timeout);
	long (*get_rcvtimeo)(struct drbd_transport *, enum drbd_stream);
	int (*send_page)(struct drbd_transport *, enum drbd_stream, struct page *,
			 int offset, size_t size, unsigned msg_flags);
	int (*send_zc_bio)(struct drbd_transport *, struct bio *bio);
	bool (*stream_ok)(struct drbd_transport *, enum drbd_stream);
	bool (*hint)(struct drbd_transport *, enum drbd_stream, enum drbd_tr_hints hint);
	void (*debugfs_show)(struct drbd_transport *, struct seq_file *m);
	int (*add_path)(struct drbd_transport *, struct drbd_path *path);
	int (*remove_path)(struct drbd_transport *, struct drbd_path *path);
#ifdef _WIN32_SEND_BUFFING 
	bool (*start_send_buffring)(struct drbd_transport *, int size);
	void (*stop_send_buffring)(struct drbd_transport *);
#endif
};

struct drbd_transport_class {
	const char *name;
	const int instance_size;
	const int path_instance_size;
#ifndef _WIN32 
	struct module *module;
#endif
	int (*init)(struct drbd_transport *);
	struct list_head list;
};


/* An "abstract base class" for transport implementations. I.e. it
   should be embedded into a transport specific representation of a
   listening "socket" */
struct drbd_listener {
	struct kref kref;
	struct drbd_resource *resource;
	struct list_head list; /* link for resource->listeners */
	struct list_head waiters; /* list head for waiter structs*/
	spinlock_t waiters_lock;
	int pending_accepts;
#ifdef _WIN32
    struct sockaddr_storage_win listen_addr;
#else
	struct sockaddr_storage listen_addr;
#endif
	void (*destroy)(struct drbd_listener *);
};

/* This represents a drbd receiver thread that is waiting for an
   incoming connection attempt. Again, should be embedded into a
   implementation object */
struct drbd_waiter {
	struct drbd_transport *transport;
	wait_queue_head_t wait;
	struct list_head list;
	struct drbd_listener *listener;
};

/* drbd_main.c */
extern void drbd_destroy_path(struct kref *kref);

/* drbd_transport.c */
extern int drbd_register_transport_class(struct drbd_transport_class *transport_class,
					 int api_version,
					 int drbd_transport_size);
extern void drbd_unregister_transport_class(struct drbd_transport_class *transport_class);
extern struct drbd_transport_class *drbd_get_transport_class(const char *transport_name);
extern void drbd_put_transport_class(struct drbd_transport_class *);
extern void drbd_print_transports_loaded(struct seq_file *seq);
#ifdef _WIN32 // DW-1498
extern bool addr_and_port_equal(const struct sockaddr_storage_win *addr1, const struct sockaddr_storage_win *addr2);
#endif
extern int drbd_get_listener(struct drbd_waiter *waiter,
			     const struct sockaddr *addr,
			     int (*create_fn)(struct drbd_transport *, const struct sockaddr *, struct drbd_listener **));
extern void drbd_put_listener(struct drbd_waiter *waiter);
#ifdef _WIN32
extern struct drbd_waiter *drbd_find_waiter_by_addr(struct drbd_listener *, struct sockaddr_storage_win *);
#else
extern struct drbd_waiter *drbd_find_waiter_by_addr(struct drbd_listener *, struct sockaddr_storage *);
#endif
extern bool drbd_stream_send_timed_out(struct drbd_transport *transport, enum drbd_stream stream);
extern bool drbd_should_abort_listening(struct drbd_transport *transport);
extern void drbd_path_event(struct drbd_transport *transport, struct drbd_path *path);

/* drbd_receiver.c*/
#ifdef _WIN32
extern void* drbd_alloc_pages(struct drbd_transport *, unsigned int, bool);
extern void drbd_free_pages(struct drbd_transport *transport, int page_count, int is_net);
#else
extern struct page *drbd_alloc_pages(struct drbd_transport *, unsigned int, gfp_t);
extern void drbd_free_pages(struct drbd_transport *transport, struct page *page, int is_net);
#endif
static inline void drbd_alloc_page_chain(struct drbd_transport *t,
	struct drbd_page_chain_head *chain, unsigned int nr, gfp_t gfp_flags)
{
	chain->head = drbd_alloc_pages(t, nr, gfp_flags);
	chain->nr_pages = chain->head ? nr : 0;
}

static inline void drbd_free_page_chain(struct drbd_transport *transport, struct drbd_page_chain_head *chain, int is_net)
{
#ifdef _WIN32 
	// MODIFIED_BY_MANTECH DW-1239 : decrease nr_pages before drbd_free_pages().
	int page_count = atomic_xchg((atomic_t *)&chain->nr_pages, 0);
	drbd_free_pages(transport, page_count, is_net);
	chain->head = NULL;
#else
	drbd_free_pages(transport, chain->head, is_net);
	chain->head = NULL;
	chain->nr_pages = 0;
#endif
}

/*
 * Some helper functions to deal with our page chains.
 */
/* Our transports may sometimes need to only partially use a page.
 * We need to express that somehow.  Use this struct, and "graft" it into
 * struct page at page->lru.
 *
 * According to include/linux/mm.h:
 *  | A page may be used by anyone else who does a __get_free_page().
 *  | In this case, page_count still tracks the references, and should only
 *  | be used through the normal accessor functions. The top bits of page->flags
 *  | and page->virtual store page management information, but all other fields
 *  | are unused and could be used privately, carefully. The management of this
 *  | page is the responsibility of the one who allocated it, and those who have
 *  | subsequently been given references to it.
 * (we do alloc_page(), that is equivalent).
 *
 * Red Hat struct page is different from upstream (layout and members) :(
 * So I am not too sure about the "all other fields", and it is not as easy to
 * find a place where sizeof(struct drbd_page_chain) would fit on all archs and
 * distribution-changed layouts.
 *
 * But (upstream) struct page also says:
 *  | struct list_head lru;   * ...
 *  |       * Can be used as a generic list
 *  |       * by the page owner.
 *
 * On 32bit, use unsigned short for offset and size,
 * to still fit in sizeof(page->lru).
 */

/* grafted over struct page.lru */
struct drbd_page_chain {
	struct page *next;	/* next page in chain, if any */
#ifdef CONFIG_64BIT
	unsigned int offset;	/* start offset of data within this page */
	unsigned int size;	/* number of data bytes within this page */
#else
#if PAGE_SIZE > (1U<<16)
#error "won't work."
#endif
	unsigned short offset;	/* start offset of data within this page */
	unsigned short size;	/* number of data bytes within this page */
#endif
};

#ifndef _WIN32
static inline void dummy_for_buildbug(void)
{
	struct page *dummy;
	BUILD_BUG_ON(sizeof(struct drbd_page_chain) > sizeof(dummy->lru));
}
#endif

#define page_chain_next(page) \
	(((struct drbd_page_chain*)&(page)->lru)->next)
#define page_chain_size(page) \
	(((struct drbd_page_chain*)&(page)->lru)->size)
#define page_chain_offset(page) \
	(((struct drbd_page_chain*)&(page)->lru)->offset)
#define set_page_chain_next(page, v) \
	(((struct drbd_page_chain*)&(page)->lru)->next = (v))
#define set_page_chain_size(page, v) \
	(((struct drbd_page_chain*)&(page)->lru)->size = (v))
#define set_page_chain_offset(page, v) \
	(((struct drbd_page_chain*)&(page)->lru)->offset = (v))
#define set_page_chain_next_offset_size(page, n, o, s)	\
	*((struct drbd_page_chain*)&(page)->lru) =	\
	((struct drbd_page_chain) {			\
		.next = (n),				\
		.offset = (o),				\
		.size = (s),				\
	 })
#ifndef _WIN32
#define page_chain_for_each(page) \
	for (; page && ({ prefetch(page_chain_next(page)); 1; }); \
			page = page_chain_next(page))
#define page_chain_for_each_safe(page, n) \
	for (; page && ({ n = page_chain_next(page); 1; }); page = n)
#else
#define page_chain_for_each(page) \
	for (; page ; page = page_chain_next(page))
#define page_chain_for_each_safe(page, n) \
	for (; page && ( n = page_chain_next(page)); page = n) 
#endif

#ifndef SK_CAN_REUSE
/* This constant was introduced by Pavel Emelyanov <xemul@parallels.com> on
   Thu Apr 19 03:39:36 2012 +0000. Before the release of linux-3.5
   commit 4a17fd52 sock: Introduce named constants for sk_reuse */
#define SK_CAN_REUSE   1
#endif

#endif
