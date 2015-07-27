#ifndef __DRBD_WINGENL_H__
#define __DRBD_WINGENL_H__

#define BLKSSZGET			1

#define NETLINK_PORT			5678

#define NLM_F_REQUEST			1       /* It is request message.       */
#define NLM_F_MULTI			    2       /* Multipart message, terminated by NLMSG_DONE */
#define NLM_F_ACK			    4       /* Reply with ack, with zero or error code */
#define NLM_F_ECHO			    8       /* Echo this request            */
#define NLM_F_DUMP_INTR			16      /* Dump was inconsistent due to sequence change */
 
/* Modifiers to GET request */
#define NLM_F_ROOT			    0x100   /* specify tree root    */
#define NLM_F_MATCH			    0x200   /* return all matching  */
#define NLM_F_ATOMIC			0x400   /* atomic GET           */
#define NLM_F_DUMP			(NLM_F_ROOT|NLM_F_MATCH)

 /* Modifiers to NEW request */
#define NLM_F_REPLACE			0x100   /* Override existing            */
#define NLM_F_EXCL			    0x200   /* Do not touch, if it exists   */
#define NLM_F_CREATE			0x400   /* Create, if it does not exist */
#define NLM_F_APPEND			0x800   /* Add to end of list           */

#define NLMSG_ALIGNTO			4U
#define NLMSG_ALIGN(_len)		(((_len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1))
#define NLMSG_HDRLEN			((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(_len)		((_len)+NLMSG_ALIGN(NLMSG_HDRLEN))
#define NLMSG_SPACE(_len)		NLMSG_ALIGN(NLMSG_LENGTH(_len))
#define NLMSG_DATA(_nlh)		((void*)(((char*)_nlh) + NLMSG_LENGTH(0)))
#define NLMSG_NEXT(_nlh,_len)	((_len) -= NLMSG_ALIGN((_nlh)->nlmsg_len), \
					                (struct nlmsghdr*)(((char*)(_nlh)) + NLMSG_ALIGN((_nlh)->nlmsg_len)))
#define NLMSG_OK(_nlh,_len)		((_len) >= (int)sizeof(struct nlmsghdr) && \
						            (_nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
						            (_nlh)->nlmsg_len <= (_len))
#define NLMSG_PAYLOAD(_nlh,_len)	((_nlh)->nlmsg_len - NLMSG_SPACE((_len)))

#define NLA_F_NESTED			(1 << 15)
#define NLA_F_NET_BYTEORDER		(1 << 14)
#define NLA_TYPE_MASK			~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

#define NLA_ALIGNTO			    4
#define NLA_ALIGN(_len)			(((_len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN			    ((int) NLA_ALIGN(sizeof(struct nlattr)))

#define GENL_NAMSIZ			    16      /* length of family name */

#define NLMSG_NOOP			    0x1     /* Nothing.             */
#define NLMSG_ERROR			    0x2     /* Error                */
#define NLMSG_DONE			    0x3     /* End of a dump        */
#define NLMSG_OVERRUN			0x4     /* Data lost            */
#define NLMSG_MIN_TYPE			0x10    /* < 0x10: reserved control messages */

#define CAP_SYS_ADMIN			4
#define NLMSG_GOODSIZE			PAGE_SIZE

#define NLMSG_ALIGN(_len)		(((_len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1))
#define GENL_HDRLEN			    NLMSG_ALIGN(sizeof(struct genlmsghdr))

#define nla_nest_cancel(_X,_Y)	__noop

enum {
	CTRL_CMD_UNSPEC,
	CTRL_CMD_NEWFAMILY,
	CTRL_CMD_DELFAMILY,
	CTRL_CMD_GETFAMILY,
	CTRL_CMD_NEWOPS,
	CTRL_CMD_DELOPS,
	CTRL_CMD_GETOPS,
	CTRL_CMD_NEWMCAST_GRP,
	CTRL_CMD_DELMCAST_GRP,
	CTRL_CMD_GETMCAST_GRP, /* unused */
	CTRL_ATTR_FAMILY_NAME,
	CTRL_ATTR_FAMILY_ID,
	__CTRL_CMD_MAX,
};

struct sk_buff
{
    int len;		// DRBD_DOC: app, kernelê°?msg_buff êµí™˜???ë£Œêµ¬ì¡° ?¼ì¹˜ë¥??„í•¨. len ???œì™¸?˜ê³  app ë¡??„ì†¡
    unsigned int tail;
    unsigned int end;

    unsigned char data[0];
};

struct nlattr {
	__u16   nla_len;
	__u16   nla_type;
};

struct genlmsghdr {
	__u8    cmd;
	__u8    version;
	__u16   reserved;
};

struct nlmsghdr {
	__u32  nlmsg_len;      /* Length of message including header */
	__u16  nlmsg_type;     /* Message content */
	__u16  nlmsg_flags;    /* Additional flags */
	__u32  nlmsg_seq;      /* Sequence number */
	__u32  nlmsg_pid;      /* Sending process port ID */
};

struct nlmsgerr {
	int  error;
	struct nlmsghdr msg;
};

struct netlink_callback {
	struct sk_buff          *skb;
	const struct nlmsghdr   *nlh;
	ULONG_PTR               args[6];
};

#endif __DRBD_WINGENL_H__
