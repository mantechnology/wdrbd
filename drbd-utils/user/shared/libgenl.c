﻿#ifdef _WIN32
#include <windows.h>
#include <errno.h>
#include "drbdtool_common.h"
#include <arpa/inet.h>
#define DRBD_EVENT_SOCKET_STRING	"DRBD_EVENTS"
#endif
#include "libgenl.h"

#include <sys/types.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>

int genl_join_mc_group(struct genl_sock *s, const char *name) {
#ifdef _WIN32
	// not support
	int len = send(s->s_fd, DRBD_EVENT_SOCKET_STRING, strlen(DRBD_EVENT_SOCKET_STRING), 0);

#ifdef NL_PACKET_MSG
    UTRACE("sending DRBD_EVENT_SOCKET_STRING. len(%d)\n", len);
#endif

	if (len != strlen(DRBD_EVENT_SOCKET_STRING)) {
		perror("send genl_join_mc_group error"); 
		return -1;
	}
	return len;
#else
	int g_id;
	int i;

	BUG_ON(!s || !s->s_family);
	for (i = 0; i < 32; i++) {
		if (!s->s_family->mc_groups[i].id)
			continue;
		if (strcmp(s->s_family->mc_groups[i].name, name))
			continue;

		g_id = s->s_family->mc_groups[i].id;
		return setsockopt(s->s_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
				&g_id, sizeof(g_id));
	}
	return -2;
#endif
}

#define DO_OR_LOG_AND_FAIL(x) \
	do {							\
		int err = x;					\
		if (err) {					\
			dbg(1, "%s failed: %d %s\n",		\
				#x, err, strerror(errno));	\
			goto fail;				\
		}						\
		} while(false)

#ifdef _WIN32
int get_netlink_port()
{
    DWORD value, port = NETLINK_PORT;
    HKEY hKey;
    DWORD status;
    DWORD type = REG_DWORD;
    DWORD size = sizeof(DWORD);
    const CHAR * registryPath = "SYSTEM\\CurrentControlSet\\Services\\drbd";
    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, registryPath, NULL, KEY_ALL_ACCESS, &hKey);
    if (status == ERROR_SUCCESS)
    {
        status = RegQueryValueEx(hKey, TEXT("netlink_tcp_port"), NULL, &type, (LPBYTE)&value, &size);
        if (status == ERROR_SUCCESS)
        {
            port = value;
        }
    }
    
    RegCloseKey(hKey);
    return htons(port);
}
#endif

static struct genl_sock *genl_connect(__u32 nl_groups)
{
	struct genl_sock *s = calloc(1, sizeof(*s));
	socklen_t sock_len;
	int bsz = 1 << 20;

	if (!s)
		return NULL;

	/* autobind; kernel is responsible to give us something unique
	 * in bind() below. */
	s->s_local.nl_pid = 0;
	s->s_local.nl_family = AF_NETLINK;
	/*
	 * If we want to receive multicast traffic on this socket, kernels
	 * before v2.6.23-rc1 require us to indicate which multicast groups we
	 * are interested in in nl_groups.
	 */
	s->s_local.nl_groups = nl_groups;
	s->s_peer.nl_family = AF_NETLINK;
	/* start with some sane sequence number */
	s->s_seq_expect = s->s_seq_next = time(0);

#ifndef _WIN32
	s->s_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC);
	if (s->s_fd == -1)
		goto fail;

	sock_len = sizeof(s->s_local);
	DO_OR_LOG_AND_FAIL(setsockopt(s->s_fd, SOL_SOCKET, SO_SNDBUF, &bsz, sizeof(bsz)));
	DO_OR_LOG_AND_FAIL(setsockopt(s->s_fd, SOL_SOCKET, SO_RCVBUF, &bsz, sizeof(bsz)));
	DO_OR_LOG_AND_FAIL(bind(s->s_fd, (struct sockaddr*) &s->s_local, sizeof(s->s_local)));
	DO_OR_LOG_AND_FAIL(getsockname(s->s_fd, (struct sockaddr*) &s->s_local, &sock_len));
#else
	/* Create the windows TCP socket */
	if ((s->s_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		goto fail;
	}

	struct sockaddr_in sendsocket;
	memset(&sendsocket, 0, sizeof(sendsocket));
	sendsocket.sin_family = AF_INET;
	sendsocket.sin_addr.s_addr = inet_addr("127.0.0.1");
    sendsocket.sin_port = get_netlink_port();
    
	if (connect(s->s_fd, (struct sockaddr *) &sendsocket, sizeof(sendsocket)) < 0) {
		perror("connect");
		return NULL;
	}
#endif

	dbg(3, "bound socket to nl_pid:%u, my pid:%u, len:%u, sizeof:%u\n",
		s->s_local.nl_pid, getpid(),
		(unsigned)sock_len, (unsigned)sizeof(s->s_local));

	return s;

fail:
	free(s);
	return NULL;
}
#undef DO_OR_LOG_AND_FAIL

static int do_send(int fd, const void *buf, int len)
{
	int c;
	while ((c = write(fd, buf, len)) < len) {
		if (c == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		buf += c;
		len -= c;
	}
	return 0;
}

int genl_send(struct genl_sock *s, struct msg_buff *msg)
{
	struct nlmsghdr *n = (struct nlmsghdr *)msg->data;

	n->nlmsg_len = msg->tail - msg->data;
	n->nlmsg_flags |= NLM_F_REQUEST;
	n->nlmsg_seq = s->s_seq_expect = s->s_seq_next++;
	n->nlmsg_pid = 0x5744; // magic code 'WD'

#define LOCAL_DEBUG_LEVEL 3
#if LOCAL_DEBUG_LEVEL <= DEBUG_LEVEL
	struct genlmsghdr *g = nlmsg_data(n);

	dbg(LOCAL_DEBUG_LEVEL, "sending %smessage, pid:%u seq:%u, g.cmd/version:%u/%u",
			n->nlmsg_type == GENL_ID_CTRL ? "ctrl " : "",
			n->nlmsg_pid, n->nlmsg_seq, g->cmd, g->version);
#ifdef NL_PACKET_MSG
    UTRACE("len(%d), type(0x%x), pid(%d), seq(%d), flags(0x%x), cmd(%d), version(%d)\n",
        n->nlmsg_len, n->nlmsg_type, n->nlmsg_pid, n->nlmsg_seq, n->nlmsg_flags, g->cmd, g->version);
#endif
#endif

	return do_send(s->s_fd, msg->data, n->nlmsg_len);
}

/* "inspired" by libnl nl_recv()
 * You pass in one iovec, which may contain pre-allocated buffer space,
 * obtained by malloc(). It will be realloc()ed on demand.
 * Caller is responsible for free()ing it up on return,
 * regardless of return code.
 */
int genl_recv_timeout(struct genl_sock *s, struct iovec *iov, int timeout_ms)
{
	struct sockaddr_nl addr;
	struct pollfd pfd;
	int flags = 0;
	int nre = 0;

	struct msghdr msg = {
		.msg_name = &addr,
		.msg_namelen = sizeof(struct sockaddr_nl),
		.msg_iov = iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};
	int n;

	if (!iov->iov_len) {
		iov->iov_len = DEFAULT_MSG_SIZE;
		iov->iov_base = malloc(iov->iov_len);
	}

	flags = MSG_PEEK;
retry:
	// DW-2071 
	memset(iov->iov_base, 0, iov->iov_len);

	pfd.fd = s->s_fd;
	pfd.events = POLLIN;
	if ((poll(&pfd, 1, timeout_ms) != 1) || !(pfd.revents & POLLIN))
		return 0; /* which is E_RCV_TIMEDOUT */

	/* for most cases this method will memcopy twice, as the default buffer
	 * is large enough.  But for those few other cases, we now have a
	 * chance to realloc before the rest of the datagram is discarded.
	 */
	n = recvmsg(s->s_fd, &msg, flags);
	if (!n)
		return 0;
	else if (n < 0) {
		if (errno == EINTR) {
			dbg(3, "recvmsg() returned EINTR, retrying\n");
#ifdef _WIN32
            return -EINTR;
#else
			goto retry;
#endif
		} else if (errno == EAGAIN) {
			dbg(3, "recvmsg() returned EAGAIN, aborting\n");
			return 0;
		} else if (errno == ENOBUFS) {
			dbg(3, "recvmsg() returned ENOBUFS\n");
			return -E_RCV_ENOBUFS;
		} else {
			dbg(3, "recvmsg() returned %d, errno = %d\n", n, errno);
			return -E_RCV_FAILED;
		}
	}

	// DW-2071 error if header is not read after 3 retries
	if (n < sizeof(struct nlmsghdr) && flags == MSG_PEEK) {
		if (nre >= 3) {
			dbg(3, "failed to read nlmsghdr(%u)\n", n);
			return -E_RCV_FAILED;
		}
		nre++;
		goto retry;
	}

	struct nlmsghdr *nlh = (struct nlmsghdr *)iov->iov_base;

	if (iov->iov_len < (unsigned)n ||
		msg.msg_flags & MSG_TRUNC) {
#ifdef _WIN32
		// DW-2071 MSG_TRUNC flag is treated as an error if the MSG_PEEK flag is not set.
		if (flags == 0) {
			// DW-2071 if you finish reading one nlmsghdr and body, complete it
			if (nlh->nlmsg_len <= n) 
				goto finished;

			dbg(3, "failed because the response(%u) length is greater than the requested(%u) length\n", iov->iov_len, (unsigned)n);
			return -E_RCV_ENOBUFS;
		}
		// DW-2071 read one at a time.
		if (iov->iov_len < nlh->nlmsg_len) {
			iov->iov_base = realloc(iov->iov_base, nlh->nlmsg_len);
			if (!iov->iov_base)
				return -E_RCV_ENOBUFS;
		}
		iov->iov_len = nlh->nlmsg_len;

		// DW-2071
		flags = 0;
#else
		/* Provided buffer is not long enough, enlarge it
		* and try again. */
		iov->iov_len *= 2;
		iov->iov_base = realloc(iov->iov_base, iov->iov_len);
#endif
		goto retry;
	} else if (flags != 0) {
		/* Buffer is big enough, do the actual reading */
#ifdef _WIN32
		size_t len = nlh->nlmsg_len;
		// DW-2071 read one at a time.
		if (iov->iov_len < nlh->nlmsg_len) {
			iov->iov_base = realloc(iov->iov_base, len);
			if (!iov->iov_base)
				return -E_RCV_ENOBUFS;
		}
		iov->iov_len = len; // resize to rx only one reaponse
#endif
		flags = 0;
		goto retry;
	}

finished:
	//DW-2071 if less data is received than the requested data, it is treated as an error.
	if (nlh->nlmsg_len > n) {
		dbg(3, "failed because received a res(%u) smaller than req(%u)\n", n, nlh->nlmsg_len);
		return -E_RCV_FAILED;
	}

	if (msg.msg_namelen != sizeof(struct sockaddr_nl))
		return -E_RCV_NO_SOURCE_ADDR;

#ifndef _WIN32
	if (addr.nl_pid != 0) {
		dbg(3, "ignoring message from sender pid %u != 0\n",
				addr.nl_pid);
		goto retry;
	}
#endif
	return n;
}


/* Note that one datagram may contain multiple netlink messages
 * (e.g. for a dump response). This only checks the _first_ message,
 * caller has to iterate over multiple messages with nlmsg_for_each_msg()
 * when necessary. */
int genl_recv_msgs(struct genl_sock *s, struct iovec *iov, char **err_desc, int timeout_ms)
{
	struct nlmsghdr *nlh;
	int c = genl_recv_timeout(s, iov, timeout_ms);
	if (c <= 0) {
		if (err_desc)
			*err_desc = (c == -E_RCV_TIMEDOUT)
				? "timed out waiting for reply"
				: (c == -E_RCV_NO_SOURCE_ADDR)
				? "no source address!"
				: ( c == -E_RCV_ENOBUFS)
			        ? "packets droped, socket receive buffer overrun"
				: "failed to receive netlink reply";
		return c;
	}

	nlh = (struct nlmsghdr*)iov->iov_base;
	if (!nlmsg_ok(nlh, c)) {
		if (err_desc)
			*err_desc = "truncated message in netlink reply";
		return -E_RCV_MSG_TRUNC;
	}
#ifdef NL_PACKET_MSG
    struct genlmsghdr * hdr = nlmsg_data(nlh);
    UTRACE("len(%d), type(0x%x), flags(0x%x), seq(%d), pid(%d), cmd(%d), version(%d)\n",    
        nlh->nlmsg_len, nlh->nlmsg_type, nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid, hdr->cmd, hdr->version);
#endif
	if (s->s_seq_expect && nlh->nlmsg_seq != s->s_seq_expect) {
		dbg(2, "sequence mismatch: 0x%x != 0x%x, type:%x flags:%x sportid:%x\n",
			nlh->nlmsg_seq, s->s_seq_expect, nlh->nlmsg_type, nlh->nlmsg_flags, nlh->nlmsg_pid);
		if (err_desc)
			*err_desc = "sequence mismatch in netlink reply";
		return -E_RCV_SEQ_MISMATCH;
	}

	if (nlh->nlmsg_type == NLMSG_NOOP ||
	    nlh->nlmsg_type == NLMSG_OVERRUN) {
		if (err_desc)
			*err_desc = "unexpected message type in reply";
		return -E_RCV_UNEXPECTED_TYPE;
	}
	if (nlh->nlmsg_type == NLMSG_DONE)
		return -E_RCV_NLMSG_DONE;

	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = nlmsg_data(nlh);
		errno = -e->error;
		if (!errno)
			/* happens if you request NLM_F_ACK */
			dbg(3, "got a positive ACK message for seq:%u",
					s->s_seq_expect);
		else {
			dbg(3, "got a NACK message for seq:%u, error:%d",
					s->s_seq_expect, e->error);
			if (err_desc)
				*err_desc = strerror(errno);
		}
		return -E_RCV_ERROR_REPLY;
	}

	/* good reply message(s) */
	dbg(3, "received a good message for seq:%u", s->s_seq_expect);
	return c;
}

static struct genl_family genl_ctrl = {
        .id = GENL_ID_CTRL,
        .name = "nlctrl",
        .version = 0x2,
        .maxattr = CTRL_ATTR_MAX,
};

struct genl_sock *genl_connect_to_family(struct genl_family *family)
{
	struct genl_sock *s = NULL;
#ifndef _WIN32
	struct msg_buff *msg;
	struct nlmsghdr *nlh;
	struct nlattr *nla;
	struct iovec iov = { .iov_len = 0 };
	int rem;

	BUG_ON(!family);
	BUG_ON(!strlen(family->name));

	msg = msg_new(DEFAULT_MSG_SIZE);
	if (!msg) {
		dbg(1, "could not allocate genl message");
		goto out;
	}
#endif

	s = genl_connect(family->nl_groups);
	if (!s) {
		dbg(1, "error creating netlink socket");
#ifndef _WIN32
		goto out;
#endif
	}
#ifdef _WIN32
	else
	{
		s->s_family = family;
	}
	return s;
#endif

#ifndef _WIN32
	genlmsg_put(msg, &genl_ctrl, 0, CTRL_CMD_GETFAMILY);

	nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family->name);
	if (genl_send(s, msg)) {
		dbg(1, "failed to send netlink message");
		free(s);
		s = NULL;
		goto out;
	}

	if (genl_recv_msgs(s, &iov, NULL, 3000) <= 0) {
		close(s->s_fd);
		free(s);
		s = NULL;
		goto out;
	}


	nlh = (struct nlmsghdr*)iov.iov_base;
	nla_for_each_attr(nla, nlmsg_attrdata(nlh, GENL_HDRLEN),
			nlmsg_attrlen(nlh, GENL_HDRLEN), rem) {
		switch (nla_type(nla)) {
		case CTRL_ATTR_FAMILY_ID:
			family->id = nla_get_u16(nla);
			dbg(2, "'%s' genl family id: %d", family->name, family->id);
			break;
		case CTRL_ATTR_FAMILY_NAME:
			break;
#ifdef HAVE_CTRL_ATTR_VERSION
		case CTRL_ATTR_VERSION:
			family->version = nla_get_u32(nla);
			dbg(2, "'%s' genl family version: %d", family->name, family->version);
			break;
#endif
#ifdef HAVE_CTRL_ATTR_HDRSIZE
		case CTRL_ATTR_HDRSIZE:
			family->hdrsize = nla_get_u32(nla);
			dbg(2, "'%s' genl family hdrsize: %d", family->name, family->hdrsize);
			break;
#endif
#ifdef HAVE_CTRL_ATTR_MCAST_GROUPS
		case CTRL_ATTR_MCAST_GROUPS:
			{
			static struct nla_policy policy[] = {
				[CTRL_ATTR_MCAST_GRP_NAME] = { .type = NLA_NUL_STRING, .len = GENL_NAMSIZ },
				[CTRL_ATTR_MCAST_GRP_ID] = { .type = NLA_U32 },
			};
			struct nlattr *ntb[__CTRL_ATTR_MCAST_GRP_MAX];
			struct nlattr *idx;
			int tmp;
			int i = 0;
			nla_for_each_nested(idx, nla, tmp) {
				BUG_ON(i >= 32);
				nla_parse_nested(ntb, CTRL_ATTR_MCAST_GRP_MAX, idx, policy);
				if (ntb[CTRL_ATTR_MCAST_GRP_NAME] &&
				    ntb[CTRL_ATTR_MCAST_GRP_ID]) {
					struct genl_multicast_group *grp = &family->mc_groups[i++];
					grp->id = nla_get_u32(ntb[CTRL_ATTR_MCAST_GRP_ID]);
					nla_strlcpy(grp->name, ntb[CTRL_ATTR_MCAST_GRP_NAME],
							sizeof(grp->name));
					dbg(2, "'%s'-'%s' multicast group found (id: %u)\n",
						family->name, grp->name, grp->id);
				}
			}
			break;
			};
#endif
		default: ;
		}
	}

	if (!family->id)
		dbg(1, "genl family '%s' not found", family->name);
	else
		s->s_family = family;

out:
	free(iov.iov_base);
	msg_free(msg);

	return s;
#endif
}

/*
 * Stripped down copy from linux-2.6.32/lib/nlattr.c
 * skb -> "msg_buff"
 *	- Lars Ellenberg
 *
 * NETLINK      Netlink attributes
 *
 *		Authors:	Thomas Graf <tgraf@suug.ch>
 *				Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 */

#include <string.h>
#ifndef _WIN32
#include <linux/types.h>
#endif

static __u16 nla_attr_minlen[NLA_TYPE_MAX+1] __read_mostly = {
	[NLA_U8]	= sizeof(__u8),
	[NLA_U16]	= sizeof(__u16),
	[NLA_U32]	= sizeof(__u32),
	[NLA_U64]	= sizeof(__u64),
	[NLA_NESTED]	= NLA_HDRLEN,
};

static int validate_nla(struct nlattr *nla, int maxtype,
			const struct nla_policy *policy)
{
	const struct nla_policy *pt;
	int minlen = 0, attrlen = nla_len(nla), type = nla_type(nla);

	if (type <= 0 || type > maxtype)
		return 0;

	pt = &policy[type];

	BUG_ON(pt->type > NLA_TYPE_MAX);

	switch (pt->type) {
	case NLA_FLAG:
		if (attrlen > 0)
			return -ERANGE;
		break;

	case NLA_NUL_STRING:
		if (pt->len)
			minlen = min_t(int, attrlen, pt->len + 1);
		else
			minlen = attrlen;

		if (!minlen || memchr(nla_data(nla), '\0', minlen) == NULL)
			return -EINVAL;
		/* fall through */

	case NLA_STRING:
		if (attrlen < 1)
			return -ERANGE;

		if (pt->len) {
			char *buf = nla_data(nla);

			if (buf[attrlen - 1] == '\0')
				attrlen--;

			if (attrlen > pt->len)
				return -ERANGE;
		}
		break;

	case NLA_BINARY:
		if (pt->len && attrlen > pt->len)
			return -ERANGE;
		break;

	case NLA_NESTED_COMPAT:
		if (attrlen < pt->len)
			return -ERANGE;
		if (attrlen < NLA_ALIGN(pt->len))
			break;
		if (attrlen < NLA_ALIGN(pt->len) + NLA_HDRLEN)
			return -ERANGE;
		nla = nla_data(nla) + NLA_ALIGN(pt->len);
		if (attrlen < NLA_ALIGN(pt->len) + NLA_HDRLEN + nla_len(nla))
			return -ERANGE;
		break;
	case NLA_NESTED:
		/* a nested attributes is allowed to be empty; if its not,
		 * it must have a size of at least NLA_HDRLEN.
		 */
		if (attrlen == 0)
			break;
	default:
		if (pt->len)
			minlen = pt->len;
		else if (pt->type != NLA_UNSPEC)
			minlen = nla_attr_minlen[pt->type];

		if (attrlen < minlen)
			return -ERANGE;
	}

	return 0;
}

/**
 * nla_validate - Validate a stream of attributes
 * @head: head of attribute stream
 * @len: length of attribute stream
 * @maxtype: maximum attribute type to be expected
 * @policy: validation policy
 *
 * Validates all attributes in the specified attribute stream against the
 * specified policy. Attributes with a type exceeding maxtype will be
 * ignored. See documenation of struct nla_policy for more details.
 *
 * Returns 0 on success or a negative error code.
 */
int nla_validate(struct nlattr *head, int len, int maxtype,
		 const struct nla_policy *policy)
{
	struct nlattr *nla;
	int rem, err;

	nla_for_each_attr(nla, head, len, rem) {
		err = validate_nla(nla, maxtype, policy);
		if (err < 0)
			goto errout;
	}

	err = 0;
errout:
	return err;
}

/**
 * nla_policy_len - Determin the max. length of a policy
 * @policy: policy to use
 * @n: number of policies
 *
 * Determines the max. length of the policy.  It is currently used
 * to allocated Netlink buffers roughly the size of the actual
 * message.
 *
 * Returns 0 on success or a negative error code.
 */
int
nla_policy_len(const struct nla_policy *p, int n)
{
	int i, len = 0;

	for (i = 0; i < n; i++, p++) {
		if (p->len)
			len += nla_total_size(p->len);
		else if (nla_attr_minlen[p->type])
			len += nla_total_size(nla_attr_minlen[p->type]);
	}

	return len;
}

/**
 * nla_parse - Parse a stream of attributes into a tb buffer
 * @tb: destination array with maxtype+1 elements
 * @maxtype: maximum attribute type to be expected
 * @head: head of attribute stream
 * @len: length of attribute stream
 * @policy: validation policy
 *
 * Parses a stream of attributes and stores a pointer to each attribute in
 * the tb array accessable via the attribute type. Attributes with a type
 * exceeding maxtype will be silently ignored for backwards compatibility
 * reasons. policy may be set to NULL if no validation is required.
 *
 * Returns 0 on success or a negative error code.
 */
int nla_parse(struct nlattr *tb[], int maxtype, struct nlattr *head, int len,
	      const struct nla_policy *policy)
{
	struct nlattr *nla;
	int rem, err;

	memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

	nla_for_each_attr(nla, head, len, rem) {
		__u16 type = nla_type(nla);

		if (type > 0 && type <= maxtype) {
			if (policy) {
				err = validate_nla(nla, maxtype, policy);
				if (err < 0)
					goto errout;
			}

			tb[type] = nla;
		}
	}

	if (unlikely(rem > 0))
		dbg(1, "netlink: %d bytes leftover after parsing "
		       "attributes.\n", rem);

	err = 0;
errout:
	if (err)
		dbg(1, "netlink: policy violation t:%d[%x] e:%d\n",
				nla_type(nla), nla->nla_type, err);
	return err;
}

/**
 * nla_find - Find a specific attribute in a stream of attributes
 * @head: head of attribute stream
 * @len: length of attribute stream
 * @attrtype: type of attribute to look for
 *
 * Returns the first attribute in the stream matching the specified type.
 */
struct nlattr *nla_find(struct nlattr *head, int len, int attrtype)
{
	struct nlattr *nla;
	int rem;

	nla_for_each_attr(nla, head, len, rem)
		if (nla_type(nla) == attrtype)
			return nla;

	return NULL;
}

/**
 * nla_strlcpy - Copy string attribute payload into a sized buffer
 * @dst: where to copy the string to
 * @nla: attribute to copy the string from
 * @dstsize: size of destination buffer
 *
 * Copies at most dstsize - 1 bytes into the destination buffer.
 * The result is always a valid NUL-terminated string. Unlike
 * strlcpy the destination buffer is always padded out.
 *
 * Returns the length of the source buffer.
 */
size_t nla_strlcpy(char *dst, const struct nlattr *nla, size_t dstsize)
{
	size_t srclen = nla_len(nla);
	char *src = nla_data(nla);

	if (srclen > 0 && src[srclen - 1] == '\0')
		srclen--;

	if (dstsize > 0) {
		size_t len = (srclen >= dstsize) ? dstsize - 1 : srclen;

		memset(dst, 0, dstsize);
		memcpy(dst, src, len);
	}

	return srclen;
}

/**
 * nla_memcpy - Copy a netlink attribute into another memory area
 * @dest: where to copy to memcpy
 * @src: netlink attribute to copy from
 * @count: size of the destination area
 *
 * Note: The number of bytes copied is limited by the length of
 *       attribute's payload. memcpy
 *
 * Returns the number of bytes copied.
 */
int nla_memcpy(void *dest, const struct nlattr *src, int count)
{
	int minlen = min_t(int, count, nla_len(src));

	memcpy(dest, nla_data(src), minlen);

	return minlen;
}

/**
 * nla_memcmp - Compare an attribute with sized memory area
 * @nla: netlink attribute
 * @data: memory area
 * @size: size of memory area
 */
int nla_memcmp(const struct nlattr *nla, const void *data,
			     size_t size)
{
	int d = nla_len(nla) - size;

	if (d == 0)
		d = memcmp(nla_data(nla), data, size);

	return d;
}

/**
 * nla_strcmp - Compare a string attribute against a string
 * @nla: netlink string attribute
 * @str: another string
 */
int nla_strcmp(const struct nlattr *nla, const char *str)
{
	int len = strlen(str) + 1;
	int d = nla_len(nla) - len;

	if (d == 0)
		d = memcmp(nla_data(nla), str, len);

	return d;
}

/**
 * __nla_reserve - reserve room for attribute on the msg
 * @msg: message buffer to reserve room on
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 *
 * Adds a netlink attribute header to a message buffer and reserves
 * room for the payload but does not copy it.
 *
 * The caller is responsible to ensure that the msg provides enough
 * tailroom for the attribute header and payload.
 */
struct nlattr *__nla_reserve(struct msg_buff *msg, int attrtype, int attrlen)
{
	struct nlattr *nla;

	nla = (struct nlattr *) msg_put(msg, nla_total_size(attrlen));
	nla->nla_type = attrtype;
	nla->nla_len = nla_attr_size(attrlen);

	memset((unsigned char *) nla + nla->nla_len, 0, nla_padlen(attrlen));

	return nla;
}

/**
 * __nla_reserve_nohdr - reserve room for attribute without header
 * @msg: message buffer to reserve room on
 * @attrlen: length of attribute payload
 *
 * Reserves room for attribute payload without a header.
 *
 * The caller is responsible to ensure that the msg provides enough
 * tailroom for the payload.
 */
void *__nla_reserve_nohdr(struct msg_buff *msg, int attrlen)
{
	void *start;

	start = msg_put(msg, NLA_ALIGN(attrlen));
	memset(start, 0, NLA_ALIGN(attrlen));

	return start;
}

/**
 * nla_reserve - reserve room for attribute on the msg
 * @msg: message buffer to reserve room on
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 *
 * Adds a netlink attribute header to a message buffer and reserves
 * room for the payload but does not copy it.
 *
 * Returns NULL if the tailroom of the msg is insufficient to store
 * the attribute header and payload.
 */
struct nlattr *nla_reserve(struct msg_buff *msg, int attrtype, int attrlen)
{
	if (unlikely(msg_tailroom(msg) < nla_total_size(attrlen)))
		return NULL;

	return __nla_reserve(msg, attrtype, attrlen);
}

/**
 * nla_reserve_nohdr - reserve room for attribute without header
 * @msg: message buffer to reserve room on
 * @attrlen: length of attribute payload
 *
 * Reserves room for attribute payload without a header.
 *
 * Returns NULL if the tailroom of the msg is insufficient to store
 * the attribute payload.
 */
void *nla_reserve_nohdr(struct msg_buff *msg, int attrlen)
{
	if (unlikely(msg_tailroom(msg) < NLA_ALIGN(attrlen)))
		return NULL;

	return __nla_reserve_nohdr(msg, attrlen);
}

/**
 * __nla_put - Add a netlink attribute to a message buffer
 * @msg: message buffer to add attribute to
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 *
 * The caller is responsible to ensure that the msg provides enough
 * tailroom for the attribute header and payload.
 */
void __nla_put(struct msg_buff *msg, int attrtype, int attrlen,
			     const void *data)
{
	struct nlattr *nla;

	nla = __nla_reserve(msg, attrtype, attrlen);
	memcpy(nla_data(nla), data, attrlen);
}

/**
 * __nla_put_nohdr - Add a netlink attribute without header
 * @msg: message buffer to add attribute to
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 *
 * The caller is responsible to ensure that the msg provides enough
 * tailroom for the attribute payload.
 */
void __nla_put_nohdr(struct msg_buff *msg, int attrlen, const void *data)
{
	void *start;

	start = __nla_reserve_nohdr(msg, attrlen);
	memcpy(start, data, attrlen);
}

/**
 * nla_put - Add a netlink attribute to a message buffer
 * @msg: message buffer to add attribute to
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 *
 * Returns -EMSGSIZE if the tailroom of the msg is insufficient to store
 * the attribute header and payload.
 */
int nla_put(struct msg_buff *msg, int attrtype, int attrlen, const void *data)
{
	if (unlikely(msg_tailroom(msg) < nla_total_size(attrlen)))
		return -EMSGSIZE;

	__nla_put(msg, attrtype, attrlen, data);
	return 0;
}

/* TODO add an architecture/platform blacklist */
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1

#define IS_ALIGNED(x, a)                (((x) & ((typeof(x))(a) - 1)) == 0)
/**
* nla_need_padding_for_64bit - test 64-bit alignment of the next attribute
* @msg: message buffer the message is stored in
*
* Return true if padding is needed to align the next attribute (nla_data()) to
* a 64-bit aligned area.
*/
static inline bool nla_need_padding_for_64bit(struct msg_buff *msg)
{
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	/* The nlattr header is 4 bytes in size, that's why we test
	* if the msg->data _is_ aligned.  A NOP attribute, plus
	* nlattr header for next attribute, will make nla_data()
	* 8-byte aligned.
	*/
	if (IS_ALIGNED((unsigned long)msg_tail_pointer(msg), 8))
		return true;
#endif
	return false;
}

/**
* nla_align_64bit - 64-bit align the nla_data() of next attribute
* @msg: message buffer the message is stored in
* @padattr: attribute type for the padding
*
* Conditionally emit a padding netlink attribute in order to make
* the next attribute we emit have a 64-bit aligned nla_data() area.
* This will only be done in architectures which do not have
* CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS defined.
*
* Returns zero on success or a negative error code.
*/
static inline int nla_align_64bit(struct msg_buff *msg, int padattr)
{
	if (nla_need_padding_for_64bit(msg) &&
		!nla_reserve(msg, padattr, 0))
		return -EMSGSIZE;

	return 0;
}

/**
* nla_total_size_64bit - total length of attribute including padding
* @payload: length of payload
*/
static inline int nla_total_size_64bit(int payload)
{
	return NLA_ALIGN(nla_attr_size(payload))
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
		+ NLA_ALIGN(nla_attr_size(0))
#endif
		;
}

/**
* __nla_reserve_64bit - reserve room for attribute on the msg and align it
* @msg: message buffer to reserve room on
* @attrtype: attribute type
* @attrlen: length of attribute payload
* @padattr: attribute type for the padding
*
* Adds a netlink attribute header to a socket buffer and reserves
* room for the payload but does not copy it. It also ensure that this
* attribute will have a 64-bit aligned nla_data() area.
*
* The caller is responsible to ensure that the msg provides enough
* tailroom for the attribute header and payload.
*/
struct nlattr *__nla_reserve_64bit(struct msg_buff *msg, int attrtype,
	int attrlen, int padattr)
{
	if (nla_need_padding_for_64bit(msg))
		nla_align_64bit(msg, padattr);

	return __nla_reserve(msg, attrtype, attrlen);
}

/**
* __nla_put_64bit - Add a netlink attribute to a socket buffer and align it
* @msg: message buffer to add attribute to
* @attrtype: attribute type
* @attrlen: length of attribute payload
* @data: head of attribute payload
* @padattr: attribute type for the padding
*
* The caller is responsible to ensure that the msg provides enough
* tailroom for the attribute header and payload.
*/
void __nla_put_64bit(struct msg_buff *msg, int attrtype, int attrlen,
	const void *data, int padattr)
{
	struct nlattr *nla;

	nla = __nla_reserve_64bit(msg, attrtype, attrlen, padattr);
	memcpy(nla_data(nla), data, attrlen);
}

/**
* nla_put_64bit - Add a netlink attribute to a socket buffer and align it
* @msg: message buffer to add attribute to
* @attrtype: attribute type
* @attrlen: length of attribute payload
* @data: head of attribute payload
* @padattr: attribute type for the padding
*
* Returns -EMSGSIZE if the tailroom of the msg is insufficient to store
* the attribute header and payload.
*/
int nla_put_64bit(struct msg_buff *msg, int attrtype, int attrlen,
	const void *data, int padattr)
{
	size_t len;

	if (nla_need_padding_for_64bit(msg))
		len = nla_total_size_64bit(attrlen);
	else
		len = nla_total_size(attrlen);
	if (unlikely(msg_tailroom(msg) < len))
		return -EMSGSIZE;

	__nla_put_64bit(msg, attrtype, attrlen, data, padattr);
	return 0;
}


/**
 * nla_put_nohdr - Add a netlink attribute without header
 * @msg: message buffer to add attribute to
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 *
 * Returns -EMSGSIZE if the tailroom of the msg is insufficient to store
 * the attribute payload.
 */
int nla_put_nohdr(struct msg_buff *msg, int attrlen, const void *data)
{
	if (unlikely(msg_tailroom(msg) < NLA_ALIGN(attrlen)))
		return -EMSGSIZE;

	__nla_put_nohdr(msg, attrlen, data);
	return 0;
}

/**
 * nla_append - Add a netlink attribute without header or padding
 * @msg: message buffer to add attribute to
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 *
 * Returns -EMSGSIZE if the tailroom of the msg is insufficient to store
 * the attribute payload.
 */
int nla_append(struct msg_buff *msg, int attrlen, const void *data)
{
	if (unlikely(msg_tailroom(msg) < NLA_ALIGN(attrlen)))
		return -EMSGSIZE;

	memcpy(msg_put(msg, attrlen), data, attrlen);
	return 0;
}
