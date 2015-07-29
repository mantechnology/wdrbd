#ifndef __WIN32_SEND_BUFFING_H
#define __WIN32_SEND_BUFFING_H

#include "drbd_windrv.h"	
#include "wsk2.h"	

#define SENDER_IS_RECV			0
#define SENDER_IS_ASEND			1
#define SENDER_IS_WORKER		2
#define SENDER_IS_SUMBIT		3
#define SENDER_IS_OTHER			4
#define SENDER_IS_UNDEF			-1

// #define SENDBUF_TRACE // trace send buffring 

#ifdef SENDBUF_TRACE
struct _send_req {
	int seq;
	char *who;
	char *tconn;
	char *buf;
	int size;
	struct list_head list;
};
#endif

struct ring_buffer {
	char *name;
	char *mem;
	unsigned int length;
	unsigned int read_pos;
	unsigned int write_pos;
	struct mutex cs;
	KEVENT event;
	int que;
	int deque;
	int seq;
	char *static_big_buf;
	unsigned int sk_wmem_queued;
#ifdef SENDBUF_TRACE
	struct list_head send_req_list;
#endif
};

typedef struct ring_buffer  ring_buffer;

extern void read_ring_buffer(ring_buffer *ring, char *data, int len);
extern ring_buffer *create_ring_buffer(char *name, unsigned int length);
extern void destroy_ring_buffer(ring_buffer *ring);
extern int get_ring_buffer_size(ring_buffer *ring);
extern void write_ring_buffer(ring_buffer *ring, const char *data, int len);

LONG NTAPI send_buf(
	__in struct drbd_tconn *tconn,
	__in struct	socket *socket,
	__in PVOID			Buffer,
	__in ULONG			BufferSize,
	__in ULONG			Flags,
	__in ULONG			Timeout
);

#endif