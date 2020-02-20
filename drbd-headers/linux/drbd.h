﻿/*
  drbd.h
  Kernel module for 2.6.x Kernels

  This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

  Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
  Copyright (C) 2001-2008, Philipp Reisner <philipp.reisner@linbit.com>.
  Copyright (C) 2001-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

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
#ifndef DRBD_H
#define DRBD_H

#include <asm/types.h>

#ifdef __KERNEL__
#include <linux/types.h>
#include <asm/byteorder.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>

/* Although the Linux source code makes a difference between
   generic endianness and the bitfields' endianness, there is no
   architecture as of Linux-2.6.24-rc4 where the bitfields' endianness
   does not match the generic endianness. */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __LITTLE_ENDIAN_BITFIELD
#elif __BYTE_ORDER == __BIG_ENDIAN
#define __BIG_ENDIAN_BITFIELD
#else
# error "sorry, weird endianness on this box"
#endif

#endif

enum drbd_io_error_p {
	EP_PASS_ON, /* FIXME should the better be named "Ignore"? */
	EP_CALL_HELPER,
	EP_DETACH,
	EP_PASSTHROUGH
};

enum drbd_fencing_policy {
	FP_DONT_CARE = 0,
	FP_RESOURCE,
	FP_STONITH
};

enum drbd_disconnect_p {
	DP_RECONNECT,
	DP_DROP_NET_CONF,
	DP_FREEZE_IO
};

enum drbd_after_sb_p {
	ASB_DISCONNECT,
	ASB_DISCARD_YOUNGER_PRI,
	ASB_DISCARD_OLDER_PRI,
	ASB_DISCARD_ZERO_CHG,
	ASB_DISCARD_LEAST_CHG,
	ASB_DISCARD_LOCAL,
	ASB_DISCARD_REMOTE,
	ASB_CONSENSUS,
	ASB_DISCARD_SECONDARY,
	ASB_CALL_HELPER,
	ASB_VIOLENTLY
};

enum drbd_on_no_data {
	OND_IO_ERROR,
	OND_SUSPEND_IO
};

enum drbd_on_no_quorum {
	ONQ_IO_ERROR = OND_IO_ERROR,
	ONQ_SUSPEND_IO = OND_SUSPEND_IO
};

enum drbd_on_congestion {
	OC_BLOCK,
	OC_PULL_AHEAD,
	OC_DISCONNECT,
};

// DW-1925
enum drbd_on_req_write_congestion {
	ORWC_DISCONNECT,
	ORWC_BLOCK,
};

enum drbd_read_balancing {
	RB_PREFER_LOCAL,
	RB_PREFER_REMOTE,
	RB_ROUND_ROBIN,
	RB_LEAST_PENDING,
	RB_CONGESTED_REMOTE,
	RB_32K_STRIPING,
	RB_64K_STRIPING,
	RB_128K_STRIPING,
	RB_256K_STRIPING,
	RB_512K_STRIPING,
	RB_1M_STRIPING,
};

/* KEEP the order, do not delete or insert. Only append. */
enum drbd_ret_code {
	ERR_CODE_BASE		= 100,
	NO_ERROR		= 101,
	ERR_LOCAL_ADDR		= 102,
	ERR_PEER_ADDR		= 103,
	ERR_OPEN_DISK		= 104,
	ERR_OPEN_MD_DISK	= 105,
	ERR_DISK_NOT_BDEV	= 107,
	ERR_MD_NOT_BDEV		= 108,
	ERR_DISK_TOO_SMALL	= 111,
	ERR_MD_DISK_TOO_SMALL	= 112,
	ERR_BDCLAIM_DISK	= 114,
	ERR_BDCLAIM_MD_DISK	= 115,
	ERR_MD_IDX_INVALID	= 116,
	ERR_IO_MD_DISK		= 118,
	ERR_MD_INVALID          = 119,
	ERR_AUTH_ALG		= 120,
	ERR_AUTH_ALG_ND		= 121,
	ERR_NOMEM		= 122,
	ERR_DISCARD_IMPOSSIBLE	= 123,
	ERR_DISK_CONFIGURED	= 124,
	ERR_NET_CONFIGURED	= 125,
	ERR_MANDATORY_TAG	= 126,
	ERR_MINOR_INVALID	= 127,
	ERR_INTR		= 129, /* EINTR */
	ERR_RESIZE_RESYNC	= 130,
	ERR_NO_PRIMARY		= 131,
	ERR_RESYNC_AFTER	= 132,
	ERR_RESYNC_AFTER_CYCLE	= 133,
	ERR_PAUSE_IS_SET	= 134,
	ERR_PAUSE_IS_CLEAR	= 135,
	ERR_PACKET_NR		= 137,
	ERR_NO_DISK		= 138,
	ERR_NOT_PROTO_C		= 139,
	ERR_NOMEM_BITMAP	= 140,
	ERR_INTEGRITY_ALG	= 141, /* DRBD 8.2 only */
	ERR_INTEGRITY_ALG_ND	= 142, /* DRBD 8.2 only */
	ERR_CPU_MASK_PARSE	= 143, /* DRBD 8.2 only */
	ERR_CSUMS_ALG		= 144, /* DRBD 8.2 only */
	ERR_CSUMS_ALG_ND	= 145, /* DRBD 8.2 only */
	ERR_VERIFY_ALG		= 146, /* DRBD 8.2 only */
	ERR_VERIFY_ALG_ND	= 147, /* DRBD 8.2 only */
	ERR_CSUMS_RESYNC_RUNNING= 148, /* DRBD 8.2 only */
	ERR_VERIFY_RUNNING	= 149, /* DRBD 8.2 only */
	ERR_DATA_NOT_CURRENT	= 150,
	ERR_CONNECTED		= 151, /* DRBD 8.3 only */
	ERR_PERM		= 152,
	ERR_NEED_APV_93		= 153,
	ERR_STONITH_AND_PROT_A  = 154,
	ERR_CONG_NOT_PROTO_A	= 155,
	ERR_PIC_AFTER_DEP	= 156,
	ERR_PIC_PEER_DEP	= 157,
	ERR_RES_NOT_KNOWN	= 158,
	ERR_RES_IN_USE		= 159,
	ERR_MINOR_CONFIGURED    = 160,
	ERR_MINOR_OR_VOLUME_EXISTS = 161,
	ERR_INVALID_REQUEST	= 162,
	ERR_NEED_APV_100	= 163,
	ERR_NEED_ALLOW_TWO_PRI  = 164,
	ERR_MD_UNCLEAN          = 165,
	ERR_MD_LAYOUT_CONNECTED = 166,
	ERR_MD_LAYOUT_TOO_BIG   = 167,
	ERR_MD_LAYOUT_TOO_SMALL = 168,
	ERR_MD_LAYOUT_NO_FIT    = 169,
	ERR_IMPLICIT_SHRINK     = 170,
	ERR_INVALID_PEER_NODE_ID = 171,
	ERR_CREATE_TRANSPORT    = 172,
	ERR_LOCAL_AND_PEER_ADDR = 173,
	ERR_SNDBUF_SIZE_TOO_SMALL = 174, 
	ERR_CANT_CHANGE_SNDBUF_SIZE_WHEN_CONNECTED = 175,
	ERR_CANT_CHANGE_SNDBUF_SIZE_WITHOUT_DEL_PEER = 176,
	/* insert new ones above this line */
	AFTER_LAST_ERR_CODE
};

#define DRBD_PROT_A   1
#define DRBD_PROT_B   2
#define DRBD_PROT_C   3

enum drbd_role {
	R_UNKNOWN = 0,
	R_PRIMARY = 1,     /* role */
	R_SECONDARY = 2,   /* role */
	R_MASK = 3,
};

/* The order of these constants is important.
 * The lower ones (< C_CONNECTED) indicate
 * that there is no socket!
 * >= C_CONNECTED ==> There is a socket
 */
enum drbd_conn_state {
	C_STANDALONE,
	C_DISCONNECTING,  /* Temporary state on the way to C_STANDALONE. */
	C_UNCONNECTED,    /* >= C_UNCONNECTED -> inc_net() succeeds */

	/* These temporary states are used on the way
	 * from C_CONNECTED to C_UNCONNECTED.
	 * The 'disconnect reason' states
	 * I do not allow to change between them. */
	C_TIMEOUT,
	C_BROKEN_PIPE,
	C_NETWORK_FAILURE,
	C_PROTOCOL_ERROR,
	C_TEAR_DOWN,

	C_CONNECTING,

	C_CONNECTED, /* we have a socket */

	C_MASK = 31,
};

enum drbd_repl_state {
	L_NEGOTIATING = C_CONNECTED, /* used for peer_device->negotiation_result only */
	L_OFF = C_CONNECTED,

	L_ESTABLISHED,      /* we have introduced each other */
	L_STARTING_SYNC_S,  /* starting full sync by admin request. */
	L_STARTING_SYNC_T,  /* starting full sync by admin request. */
	L_WF_BITMAP_S,
	L_WF_BITMAP_T,
	L_WF_SYNC_UUID,

	/* All SyncStates are tested with this comparison
	 * xx >= L_SYNC_SOURCE && xx <= L_PAUSED_SYNC_T */
	L_SYNC_SOURCE,
	L_SYNC_TARGET,
	L_VERIFY_S,
	L_VERIFY_T,
	L_PAUSED_SYNC_S,
	L_PAUSED_SYNC_T,

	L_AHEAD,
	L_BEHIND,
	L_NEG_NO_RESULT = L_BEHIND,  /* used for peer_device->negotiation_result only */
};

enum drbd_disk_state {
	D_DISKLESS,
	D_ATTACHING,      /* In the process of reading the meta-data */
	D_DETACHING,      /* Added in protocol version 110 */
	D_FAILED,         /* Becomes D_DISKLESS as soon as we told it the peer */
			  /* when >= D_FAILED it is legal to access device->ldev */
	D_NEGOTIATING,    /* Late attaching state, we need to talk to the peer */
	D_INCONSISTENT,
	D_OUTDATED,
	D_UNKNOWN,       /* Only used for the peer, never for myself */
	D_CONSISTENT,     /* Might be D_OUTDATED, might be D_UP_TO_DATE ... */
	D_UP_TO_DATE,       /* Only this disk state allows applications' IO ! */
	D_MASK = 15
};

union drbd_state {
/* According to gcc's docs is the ...
 * The order of allocation of bit-fields within a unit (C90 6.5.2.1, C99 6.7.2.1).
 * Determined by ABI.
 * pointed out by Maxim Uvarov q<muvarov@ru.mvista.com>
 * even though we transmit as "cpu_to_be32(state)",
 * the offsets of the bitfields still need to be swapped
 * on different endianness.
 */
	struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		unsigned role:2 ;   /* 3/4	 primary/secondary/unknown */
		unsigned peer:2 ;   /* 3/4	 primary/secondary/unknown */
		unsigned conn:5 ;   /* 17/32	 cstates */
		unsigned disk:4 ;   /* 8/16	 from D_DISKLESS to D_UP_TO_DATE */
		unsigned pdsk:4 ;   /* 8/16	 from D_DISKLESS to D_UP_TO_DATE */
		unsigned susp:1 ;   /* 2/2	 IO suspended no/yes (by user) */
		unsigned aftr_isp:1 ; /* isp .. imposed sync pause */
		unsigned peer_isp:1 ;
		unsigned user_isp:1 ;
		unsigned susp_nod:1 ; /* IO suspended because no data */
		unsigned susp_fen:1 ; /* IO suspended because fence peer handler runs*/
		unsigned _pad:9;   /* 0	 unused */
#elif defined(__BIG_ENDIAN_BITFIELD)
		unsigned _pad:9;
		unsigned susp_fen:1 ;
		unsigned susp_nod:1 ;
		unsigned user_isp:1 ;
		unsigned peer_isp:1 ;
		unsigned aftr_isp:1 ; /* isp .. imposed sync pause */
		unsigned susp:1 ;   /* 2/2	 IO suspended  no/yes */
		unsigned pdsk:4 ;   /* 8/16	 from D_DISKLESS to D_UP_TO_DATE */
		unsigned disk:4 ;   /* 8/16	 from D_DISKLESS to D_UP_TO_DATE */
		unsigned conn:5 ;   /* 17/32	 cstates */
		unsigned peer:2 ;   /* 3/4	 primary/secondary/unknown */
		unsigned role:2 ;   /* 3/4	 primary/secondary/unknown */
#else
# error "this endianness is not supported"
#endif
	};
	unsigned int i;
};

enum drbd_state_rv {
	SS_CW_NO_NEED = 4,
	SS_CW_SUCCESS = 3,
	SS_NOTHING_TO_DO = 2,
	SS_SUCCESS = 1,
	SS_UNKNOWN_ERROR = 0, /* Used to sleep longer in _drbd_request_state */
	SS_TWO_PRIMARIES = -1,
	SS_NO_UP_TO_DATE_DISK = -2,
	SS_NO_LOCAL_DISK = -4,
	SS_NO_REMOTE_DISK = -5,
	SS_CONNECTED_OUTDATES = -6,
	SS_PRIMARY_NOP = -7,
	SS_RESYNC_RUNNING = -8,
	SS_ALREADY_STANDALONE = -9,
	SS_CW_FAILED_BY_PEER = -10,
	SS_IS_DISKLESS = -11,
	SS_DEVICE_IN_USE = -12,
	SS_NO_NET_CONFIG = -13,
	SS_NO_VERIFY_ALG = -14,       /* drbd-8.2 only */
	SS_NEED_CONNECTION = -15,
	SS_LOWER_THAN_OUTDATED = -16,
	SS_NOT_SUPPORTED = -17,
	SS_IN_TRANSIENT_STATE = -18,  /* Retry after the next state change */
	SS_CONCURRENT_ST_CHG = -19,   /* Concurrent cluster side state change! */
	SS_O_VOL_PEER_PRI = -20,
	SS_INTERRUPTED = -21,	/* interrupted in stable_state_change() */
	SS_PRIMARY_READER = -22,
	SS_TIMEOUT = -23,
	SS_WEAKLY_CONNECTED = -24,
	SS_NO_QUORUM = -25,
	SS_AFTER_LAST_ERROR = -26,    /* Keep this at bottom */
};

#define SHARED_SECRET_MAX 64

enum mdf_flag {
	MDF_CONSISTENT =	1 << 0,
	MDF_PRIMARY_IND =	1 << 1,
	MDF_WAS_UP_TO_DATE =	1 << 4,
	MDF_CRASHED_PRIMARY =	1 << 6,
	MDF_AL_CLEAN =		1 << 7,
	MDF_AL_DISABLED =       1 << 8,
#ifdef _WIN32
	MDF_LAST_PRIMARY = 1 << 16,
	MDF_IO_ERROR = 1 << 17,				/* DW-1843 since the io_error_count of the device structure is initialized when down, it is saved as an mdf flag to hold the value.*/
#endif
};

enum mdf_peer_flag {
	MDF_PEER_CONNECTED =	1 << 0,
	MDF_PEER_OUTDATED =	1 << 1,
	MDF_PEER_FENCING =	1 << 2,
	MDF_PEER_FULL_SYNC =	1 << 3,
	MDF_PEER_DEVICE_SEEN =	1 << 4,
#ifdef _WIN32
	// MODIFIED_BY_MANTECH DW-978: Bitmap uuid is set as -1 and sent to peers when it's 0 and current uuid doesn't match.
	// It needs to be cleared when resync's done and gets matched current uuid.
	// This flag indicates that above situation so that uuid will be propagated once resync is finished.
	MDF_PEER_DIFF_CUR_UUID = 1 << 5,
	// DW-2044 need to get synced from this peer
	MDF_CRASHED_PRIMARY_WORK_PENDING = 1 << 6,
#endif
	MDF_NODE_EXISTS =       1 << 16, /* */
#ifdef _WIN32
	MDF_PEER_INIT_SYNCT_BEGIN = 1 << 17,
	MDF_PEER_IN_PROGRESS_SYNC = 1 << 18,			//DW-1874 
													//when the connection is lost during synchronization and the synctarget is complete synchronizing with another node, 
													//it is used to determine the unnecessary out of sync removal when reconnected.
#endif
	
};

#define DRBD_PEERS_MAX 32
#define DRBD_NODE_ID_MAX DRBD_PEERS_MAX

enum drbd_uuid_index {
	UI_CURRENT,
	UI_BITMAP,
	UI_HISTORY_START,
	UI_HISTORY_END,
	UI_SIZE,      /* nl-packet: number of dirty bits */
	UI_FLAGS,     /* nl-packet: flags */
	UI_EXTENDED_SIZE   /* Everything. */
};

#define HISTORY_UUIDS_V08 (UI_HISTORY_END - UI_HISTORY_START + 1)
#define HISTORY_UUIDS DRBD_PEERS_MAX

enum drbd_timeout_flag {
	UT_DEFAULT      = 0,
	UT_DEGRADED     = 1,
	UT_PEER_OUTDATED = 2,
};

#define UUID_JUST_CREATED ((__u64)4)
#define UUID_PRIMARY ((__u64)1)

enum write_ordering_e {
	WO_NONE,
	WO_DRAIN_IO,
	WO_BDEV_FLUSH,
	WO_BIO_BARRIER
};

enum drbd_notification_type {
	NOTIFY_EXISTS,
	NOTIFY_CREATE,
	NOTIFY_CHANGE,
	NOTIFY_DESTROY,
	NOTIFY_CALL,
	NOTIFY_RESPONSE,
	NOTIFY_ERROR,

	NOTIFY_CONTINUES = 0x8000,
	NOTIFY_FLAGS = NOTIFY_CONTINUES,
};

/* These values are part of the ABI! */
enum drbd_peer_state {
	P_INCONSISTENT = 3,
	P_OUTDATED = 4,
	P_DOWN = 5,
	P_PRIMARY = 6,
	P_FENCING = 7,
};

/* magic numbers used in meta data and network packets */
#define DRBD_MAGIC 0x83740267
#define DRBD_MAGIC_BIG 0x835a
#define DRBD_MAGIC_100 0x8620ec20

#define DRBD_MD_MAGIC_07   (DRBD_MAGIC+3)
#define DRBD_MD_MAGIC_08   (DRBD_MAGIC+4)
#define DRBD_MD_MAGIC_84_UNCLEAN	(DRBD_MAGIC+5)
#define DRBD_MD_MAGIC_09   (DRBD_MAGIC+6)

/* how I came up with this magic?
 * base64 decode "actlog==" ;) */
#define DRBD_AL_MAGIC 0x69cb65a2

/* these are of type "int" */
#define DRBD_MD_INDEX_INTERNAL -1
#define DRBD_MD_INDEX_FLEX_EXT -2
#define DRBD_MD_INDEX_FLEX_INT -3

#define DRBD_CPU_MASK_SIZE 32

#define DRBD_MAX_BIO_SIZE (1U << 20)

#define QOU_OFF 0
#define QOU_MAJORITY 1024
#define QOU_ALL 1025

#endif
