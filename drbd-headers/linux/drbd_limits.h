﻿/*
  drbd_limits.h
  This file is part of DRBD by Philipp Reisner and Lars Ellenberg.
*/

/*
 * Our current limitations.
 * Some of them are hard limits,
 * some of them are arbitrary range limits, that make it easier to provide
 * feedback about nonsense settings for certain configurable values.
 */

#ifndef DRBD_LIMITS_H
#define DRBD_LIMITS_H 1

#define DEBUG_RANGE_CHECK 0

#define DRBD_MINOR_COUNT_MIN 1
#define DRBD_MINOR_COUNT_MAX 255
#define DRBD_MINOR_COUNT_DEF 32
#define DRBD_MINOR_COUNT_SCALE '1'

#define DRBD_VOLUME_MAX 65535

#define DRBD_DIALOG_REFRESH_MIN 0
#define DRBD_DIALOG_REFRESH_MAX 600
#define DRBD_DIALOG_REFRESH_SCALE '1'

/* valid port number */
#define DRBD_PORT_MIN 1
#define DRBD_PORT_MAX 0xffff
#define DRBD_PORT_SCALE '1'

/* startup { */
  /* if you want more than 3.4 days, disable */
#define DRBD_WFC_TIMEOUT_MIN 0
#define DRBD_WFC_TIMEOUT_MAX 300000
#define DRBD_WFC_TIMEOUT_DEF 0
#define DRBD_WFC_TIMEOUT_SCALE '1'

#define DRBD_DEGR_WFC_TIMEOUT_MIN 0
#define DRBD_DEGR_WFC_TIMEOUT_MAX 300000
#define DRBD_DEGR_WFC_TIMEOUT_DEF 0
#define DRBD_DEGR_WFC_TIMEOUT_SCALE '1'

#define DRBD_OUTDATED_WFC_TIMEOUT_MIN 0
#define DRBD_OUTDATED_WFC_TIMEOUT_MAX 300000
#define DRBD_OUTDATED_WFC_TIMEOUT_DEF 0
#define DRBD_OUTDATED_WFC_TIMEOUT_SCALE '1'
/* }*/

/* net { */
  /* timeout, unit centi seconds
   * more than one minute timeout is not useful */
#define DRBD_TIMEOUT_MIN 1
#define DRBD_TIMEOUT_MAX 600
#ifdef _WIN32  
// DW-1524 fix infinite send retry on low-bandwith
#define DRBD_TIMEOUT_DEF (50)     /* 5 seconds */
#else
#define DRBD_TIMEOUT_DEF 60       /* 6 seconds */
#endif
#define DRBD_TIMEOUT_SCALE '1'

 /* If backing disk takes longer than disk_timeout, mark the disk as failed */
#define DRBD_DISK_TIMEOUT_MIN 0    /* 0 = disabled */
#define DRBD_DISK_TIMEOUT_MAX 6000 /* 10 Minutes */
#define DRBD_DISK_TIMEOUT_DEF 0    /* disabled */
#define DRBD_DISK_TIMEOUT_SCALE '1'

  /* active connection retries when C_CONNECTING */
#define DRBD_CONNECT_INT_MIN 1
#define DRBD_CONNECT_INT_MAX 120
#ifdef _WIN32
//DW-915
#define DRBD_CONNECT_INT_DEF 3   /* seconds */
#else
#define DRBD_CONNECT_INT_DEF 10   /* seconds */
#endif
#define DRBD_CONNECT_INT_SCALE '1'

  /* keep-alive probes when idle */
#define DRBD_PING_INT_MIN 1
#define DRBD_PING_INT_MAX 120
#ifdef _WIN32
#define DRBD_PING_INT_DEF 3
#else
#define DRBD_PING_INT_DEF 10
#endif
#define DRBD_PING_INT_SCALE '1'

 /* timeout for the ping packets.*/
#define DRBD_PING_TIMEO_MIN  1
#define DRBD_PING_TIMEO_MAX  300
#ifdef _WIN32
//DW-763
#define DRBD_PING_TIMEO_DEF  30 /* 1/10 seconds */
#else
#define DRBD_PING_TIMEO_DEF  5
#endif
#define DRBD_PING_TIMEO_SCALE '1'

  /* max number of write requests between write barriers */
#define DRBD_MAX_EPOCH_SIZE_MIN 1
#define DRBD_MAX_EPOCH_SIZE_MAX 20000
#ifdef _WIN32 // DW-1695 Increase a max-epoch-size's default value by increasing the max-buffers'.
#define DRBD_MAX_EPOCH_SIZE_DEF 16000
#else
#define DRBD_MAX_EPOCH_SIZE_DEF 2048
#endif
#define DRBD_MAX_EPOCH_SIZE_SCALE '1'


#if _WIN32

#ifdef _WIN64 
// DW-1422 set limit send buffer max size to be within 32-bit variable, since config treats it as 32-bit var also.
// to have this over 32-bit, re-define this as '((unsigned long long)64 << 30) and modify all arguments(include read data from config) to 64-bit var. 
#define DRBD_SNDBUF_SIZE_MAX  (0xFFFFFFFFFF)
/* DW-1436 sndbuf-size default value is set to 0, minimum value is set to 10M when used */
#define DRBD_SNDBUF_SIZE_DEF	0 
#define DRBD_SNDBUF_SIZE_MIN  (1024*1024*10)
#else
#define DRBD_SNDBUF_SIZE_MAX  (1024*1024*1024*2LLU)
#define DRBD_SNDBUF_SIZE_DEF  0
/* I don't think that a tcp send buffer of more than 10M is useful */
#define DRBD_SNDBUF_SIZE_MIN   (1024*1024*10)
#endif

#else
#define DRBD_SNDBUF_SIZE_MAX  (10<<20)
#define DRBD_SNDBUF_SIZE_DEF  0
#define DRBD_SNDBUF_SIZE_MIN  0 // DW-1719 add missing definitions (support linux)
#endif
#define DRBD_SNDBUF_SIZE_SCALE '1'

#define DRBD_RCVBUF_SIZE_MIN  0
#define DRBD_RCVBUF_SIZE_MAX  (10<<20)
#define DRBD_RCVBUF_SIZE_DEF  0
#define DRBD_RCVBUF_SIZE_SCALE '1'

  /* @4k PageSize -> 128kB - 512MB */
#define DRBD_MAX_BUFFERS_MIN  32
#define DRBD_MAX_BUFFERS_MAX  131072
#ifdef _WIN32 // DW-1695 Takes the value of max-buffers sufficiently.
#define DRBD_MAX_BUFFERS_DEF  16000
#else
#define DRBD_MAX_BUFFERS_DEF  2048
#endif
#define DRBD_MAX_BUFFERS_SCALE '1'

  /* @4k PageSize -> 4kB - 512MB */
#define DRBD_UNPLUG_WATERMARK_MIN  1
#define DRBD_UNPLUG_WATERMARK_MAX  131072
#define DRBD_UNPLUG_WATERMARK_DEF (DRBD_MAX_BUFFERS_DEF/16)
#define DRBD_UNPLUG_WATERMARK_SCALE '1'

  /* 0 is disabled.
   * 200 should be more than enough even for very short timeouts */
#define DRBD_KO_COUNT_MIN  0
#define DRBD_KO_COUNT_MAX  200
#ifdef _WIN32 // DW-988 adjust default ko_count value, because connection timeout is so long for somecase. 
#define DRBD_KO_COUNT_DEF  5 // DW-1208 3 -> 5 
#else
#define DRBD_KO_COUNT_DEF  7
#endif
#define DRBD_KO_COUNT_SCALE '1'
/* } */

/* syncer { */
  /* FIXME allow rate to be zero? */
#define DRBD_RESYNC_RATE_MIN 1
/* channel bonding 10 GbE, or other hardware */
#define DRBD_RESYNC_RATE_MAX (4 << 20)

#if 0 // DW-1543 rollback resync-rate's default value
#ifdef _WIN32 // DW-1188 we need to adjust resync-rate in normal 1G network.
#define DRBD_RESYNC_RATE_DEF (100*1024)
#else
#define DRBD_RESYNC_RATE_DEF 250
#endif
#endif

#define DRBD_RESYNC_RATE_DEF 250
#define DRBD_RESYNC_RATE_SCALE 'k'  /* kilobytes */

  /* less than 67 would hit performance unnecessarily. */
#define DRBD_AL_EXTENTS_MIN  67
  /* we use u16 as "slot number", (u16)~0 is "FREE".
   * If you use >= 292 kB on-disk ring buffer,
   * this is the maximum you can use: */
#define DRBD_AL_EXTENTS_MAX  0xfffe
#ifdef _WIN32 // DW-1513
#define DRBD_AL_EXTENTS_DEF  6001
#else
#define DRBD_AL_EXTENTS_DEF  1237
#endif
#define DRBD_AL_EXTENTS_SCALE '1'

#define DRBD_MINOR_NUMBER_MIN  -1
#define DRBD_MINOR_NUMBER_MAX  ((1 << 20) - 1)
#define DRBD_MINOR_NUMBER_DEF  -1
#define DRBD_MINOR_NUMBER_SCALE '1'

/* } */

/* drbdsetup XY resize -d Z
 * you are free to reduce the device size to nothing, if you want to.
 * the upper limit with 64bit kernel, enough ram and flexible meta data
 * is 1 PiB, currently. */
/* DRBD_MAX_SECTORS */
#define DRBD_DISK_SIZE_MIN  0
#define DRBD_DISK_SIZE_MAX  (1 * (2LLU << 40))
#define DRBD_DISK_SIZE_DEF  0 /* = disabled = no user size... */
#define DRBD_DISK_SIZE_SCALE 's'  /* sectors */
#ifdef _WIN32
// WDRBD_DOC: when Disk I/O fail on Windows, A continous retry I/O occured in EP_PASS_ON config.(DW-463) so, EP_DETACH is suitable for WDRBD
#endif
#define DRBD_ON_IO_ERROR_DEF EP_PASSTHROUGH 
#define DRBD_FENCING_DEF FP_DONT_CARE
#define DRBD_AFTER_SB_0P_DEF ASB_DISCONNECT
#define DRBD_AFTER_SB_1P_DEF ASB_DISCONNECT
#define DRBD_AFTER_SB_2P_DEF ASB_DISCONNECT
#define DRBD_RR_CONFLICT_DEF ASB_DISCONNECT
#define DRBD_ON_NO_DATA_DEF OND_IO_ERROR
#define DRBD_ON_CONGESTION_DEF OC_BLOCK
#define DRBD_READ_BALANCING_DEF RB_PREFER_LOCAL
#define DRBD_ON_REQ_WRITE_CONGESTION_DEF ORWC_DISCONNECT	// DW-1925

#define DRBD_MAX_BIO_BVECS_MIN 0
#define DRBD_MAX_BIO_BVECS_MAX 128
#define DRBD_MAX_BIO_BVECS_DEF 0
#define DRBD_MAX_BIO_BVECS_SCALE '1'

#define DRBD_C_PLAN_AHEAD_MIN  0
#define DRBD_C_PLAN_AHEAD_MAX  300

#if 0 // DW-1543 rollback default c-plan-ahead value
#ifdef _WIN32 // DW-1039 a continuos resync throuput is required.
#define DRBD_C_PLAN_AHEAD_DEF  0
#else
#define DRBD_C_PLAN_AHEAD_DEF  20
#endif
#endif

#define DRBD_C_PLAN_AHEAD_DEF  20
#define DRBD_C_PLAN_AHEAD_SCALE '1'

#define DRBD_C_DELAY_TARGET_MIN 1
#define DRBD_C_DELAY_TARGET_MAX 100
#define DRBD_C_DELAY_TARGET_DEF 10
#define DRBD_C_DELAY_TARGET_SCALE '1'

#define DRBD_C_FILL_TARGET_MIN 0
#define DRBD_C_FILL_TARGET_MAX (1<<20) /* 500MByte in sec */
#define DRBD_C_FILL_TARGET_DEF 100 /* Try to place 50KiB in socket send buffer during resync */
#define DRBD_C_FILL_TARGET_SCALE 's'  /* sectors */

#define DRBD_C_MAX_RATE_MIN     250
#define DRBD_C_MAX_RATE_MAX     (4 << 20)
#define DRBD_C_MAX_RATE_DEF     102400
#define DRBD_C_MAX_RATE_SCALE	'k'  /* kilobytes */

#define DRBD_C_MIN_RATE_MIN     0
#define DRBD_C_MIN_RATE_MAX     (4 << 20)

#if 0 // DW-1543 rollback c-min-rate default vaule
#ifdef _WIN32 // MODIFIED_BY_MANTECH DW-1041 
#define DRBD_C_MIN_RATE_DEF     0
#else
#define DRBD_C_MIN_RATE_DEF     250
#endif
#endif
#define DRBD_C_MIN_RATE_DEF     250
#define DRBD_C_MIN_RATE_SCALE	'k'  /* kilobytes */

#define DRBD_CONG_FILL_MIN	0
//#define DRBD_CONG_FILL_MAX	(10<<21) /* 10GByte in sectors */
#define DRBD_CONG_FILL_MAX 	(0xFFFFFFFFFF)
#define DRBD_CONG_FILL_DEF	0
//#define DRBD_CONG_FILL_SCALE	's'  /* sectors */
#define DRBD_CONG_FILL_SCALE	'1'

#define DRBD_CONG_EXTENTS_MIN	DRBD_AL_EXTENTS_MIN
#define DRBD_CONG_EXTENTS_MAX	DRBD_AL_EXTENTS_MAX
#define DRBD_CONG_EXTENTS_DEF	DRBD_AL_EXTENTS_DEF
#define DRBD_CONG_EXTENTS_SCALE DRBD_AL_EXTENTS_SCALE

#define DRBD_PROTOCOL_DEF DRBD_PROT_C

#define DRBD_DISK_BARRIER_DEF	0
#define DRBD_DISK_FLUSHES_DEF	0		// DW-1967
#define DRBD_DISK_DRAIN_DEF	1
#define DRBD_DISK_DISKLESS_DEF    0
#define DRBD_MD_FLUSHES_DEF	1
#ifdef _WIN32 // DW-1652 : change the default value of tcp-cork to no
#define DRBD_TCP_CORK_DEF	0
#else
#define DRBD_TCP_CORK_DEF	1
#endif
#define DRBD_AL_UPDATES_DEF     1
/* We used to ignore the discard_zeroes_data setting.
 * To not change established (and expected) behaviour,
 * by default assume that, for discard_zeroes_data=0,
 * we can make that an effective discard_zeroes_data=1,
 * if we only explicitly zero-out unaligned partial chunks. */
#define DRBD_DISCARD_ZEROES_IF_ALIGNED_DEF 1

/* Some backends pretend to support WRITE SAME,
* but fail such requests when they are actually submitted.
* This is to tell DRBD to not even try. */
#define DRBD_DISABLE_WRITE_SAME_DEF 0

#define DRBD_ALLOW_TWO_PRIMARIES_DEF	0
#define DRBD_ALWAYS_ASBP_DEF	0
#define DRBD_USE_RLE_DEF	1
#define DRBD_CSUMS_AFTER_CRASH_ONLY_DEF 0
#define DRBD_AUTO_PROMOTE_DEF	1
#define DRBD_BITMAP_DEF         1

#ifdef _WIN32 // DW-1249: auto-start by svc
#define DRBD_SVC_AUTOSTART_DEF 1
// DW-1716
#define DRBD_IO_ERROR_RETRY_COUNT_MIN 		0
#define DRBD_IO_ERROR_RETRY_COUNT_DEF		3
#define DRBD_IO_ERROR_RETRY_COUNT_MAX		100
#define DRBD_IO_ERROR_RETRY_COUNT_SCALE		'1'
#endif

#define DRBD_NR_REQUESTS_MIN	4
#ifdef _WIN32 // DW-836 MODIFIED_BY_MANTECH 
#define DRBD_NR_REQUESTS_DEF	1000
#else
#define DRBD_NR_REQUESTS_DEF	8000
#endif
#define DRBD_NR_REQUESTS_MAX	-1U
#define DRBD_NR_REQUESTS_SCALE	'1'

#define DRBD_MAX_BIO_SIZE_DEF	DRBD_MAX_BIO_SIZE
#define DRBD_MAX_BIO_SIZE_MIN	(1 << 9)
#define DRBD_MAX_BIO_SIZE_MAX	DRBD_MAX_BIO_SIZE
#define DRBD_MAX_BIO_SIZE_SCALE '1'

#ifdef _WIN32
// MODIFIED_BY_MANTECH DW-1200 DW-1539: request buffer maximum size, 10MB ~ 10GB, default : 100MB
#define DRBD_MAX_REQ_WRITE_CNT_MIN        10000     
#define DRBD_MAX_REQ_WRITE_CNT_DEF        100000
#define DRBD_MAX_REQ_WRITE_CNT_MAX        1000000
#define DRBD_MAX_REQ_WRITE_CNT_SCALE        '1'

#define DRBD_MAX_REQ_WRITE_MB_MIN        10
#define DRBD_MAX_REQ_WRITE_MB_DEF        100
#define DRBD_MAX_REQ_WRITE_MB_MAX        10240
#define DRBD_MAX_REQ_WRITE_MB_SCALE        '1'

#endif

#define DRBD_NODE_ID_DEF		0
#define DRBD_NODE_ID_MIN		0
#ifndef DRBD_NODE_ID_MAX /* Is also defined in drbd.h */
#define DRBD_NODE_ID_MAX		DRBD_PEERS_MAX
#endif
#define DRBD_NODE_ID_SCALE		'1'

#define DRBD_PEER_ACK_WINDOW_DEF	4096   /* 2 MiByte */
#define DRBD_PEER_ACK_WINDOW_MIN	2048   /* 1 MiByte */
#define DRBD_PEER_ACK_WINDOW_MAX	204800 /* 100 MiByte */
#define DRBD_PEER_ACK_WINDOW_SCALE 's' /* sectors*/

#define DRBD_PEER_ACK_DELAY_DEF	100    /* 100ms */
#define DRBD_PEER_ACK_DELAY_MIN 1
#define DRBD_PEER_ACK_DELAY_MAX 10000  /* 10 seconds */
#define DRBD_PEER_ACK_DELAY_SCALE '1' /* milliseconds */

/* Two-phase commit timeout (1/10 seconds). */
#define DRBD_TWOPC_TIMEOUT_MIN	50
#define DRBD_TWOPC_TIMEOUT_MAX	600
#ifdef _WIN32 // MODIFIED_BY_MANTECH DW-1204 adjust 2pc timout default value
#define DRBD_TWOPC_TIMEOUT_DEF	50
#else
#define DRBD_TWOPC_TIMEOUT_DEF	300
#endif
#define DRBD_TWOPC_TIMEOUT_SCALE '1'

#define DRBD_TWOPC_RETRY_TIMEOUT_MIN 1
#define DRBD_TWOPC_RETRY_TIMEOUT_MAX 50
#define DRBD_TWOPC_RETRY_TIMEOUT_DEF 1
#define DRBD_TWOPC_RETRY_TIMEOUT_SCALE '1'

#define DRBD_SYNC_FROM_NID_DEF -1
#define DRBD_SYNC_FROM_NID_MIN -1
#define DRBD_SYNC_FROM_NID_MAX DRBD_PEERS_MAX
#define DRBD_SYNC_FROM_NID_SCALE '1'

#define DRBD_AL_STRIPES_MIN     1
#define DRBD_AL_STRIPES_MAX     1024
#define DRBD_AL_STRIPES_DEF     1
#define DRBD_AL_STRIPES_SCALE   '1'

#define DRBD_AL_STRIPE_SIZE_MIN   4
#define DRBD_AL_STRIPE_SIZE_MAX   16777216
#define DRBD_AL_STRIPE_SIZE_DEF   32
#define DRBD_AL_STRIPE_SIZE_SCALE 'k' /* kilobytes */

#define DRBD_SOCKET_CHECK_TIMEO_MIN 0
#define DRBD_SOCKET_CHECK_TIMEO_MAX DRBD_PING_TIMEO_MAX
#define DRBD_SOCKET_CHECK_TIMEO_DEF 0
#define DRBD_SOCKET_CHECK_TIMEO_SCALE '1'

/* Auto promote timeout (1/10 seconds). */
#define DRBD_AUTO_PROMOTE_TIMEOUT_MIN 0
#define DRBD_AUTO_PROMOTE_TIMEOUT_MAX 600
#define DRBD_AUTO_PROMOTE_TIMEOUT_DEF 20
#define DRBD_AUTO_PROMOTE_TIMEOUT_SCALE '1'

#define DRBD_RS_DISCARD_GRANULARITY_MIN 0
#define DRBD_RS_DISCARD_GRANULARITY_MAX (1<<20)  /* 1MiByte */
#define DRBD_RS_DISCARD_GRANULARITY_DEF 0     /* disabled by default */
#define DRBD_RS_DISCARD_GRANULARITY_SCALE '1' /* bytes */

#define DRBD_QUORUM_MIN 0
#define DRBD_QUORUM_MAX QOU_ALL /* Note: user visible min/max different */
#define DRBD_QUORUM_DEF QOU_OFF /* kernel min/max includes symbolic values */
#define DRBD_QUORUM_SCALE '1' /* nodes */

/* By default freeze IO, if set error all IOs as quick as possible */
#define DRBD_ON_NO_QUORUM_DEF ONQ_SUSPEND_IO

#endif
