﻿/*
 * General overview:
 * full generic netlink message:
 * |nlmsghdr|genlmsghdr|<payload>
 *
 * payload:
 * |optional fixed size family header|<sequence of netlink attributes>
 *
 * sequence of netlink attributes:
 * I chose to have all "top level" attributes NLA_NESTED,
 * corresponding to some real struct.
 * So we have a sequence of |tla, len|<nested nla sequence>
 *
 * nested nla sequence:
 * may be empty, or contain a sequence of netlink attributes
 * representing the struct fields.
 *
 * The tag number of any field (regardless of containing struct)
 * will be available as T_ ## field_name,
 * so you cannot have the same field name in two differnt structs.
 *
 * The tag numbers themselves are per struct, though,
 * so should always begin at 1 (not 0, that is the special "NLA_UNSPEC" type,
 * which we won't use here).
 * The tag numbers are used as index in the respective nla_policy array.
 *
 * GENL_struct(tag_name, tag_number, struct name, struct fields) - struct and policy
 *	genl_magic_struct.h
 *		generates the struct declaration,
 *		generates an entry in the tla enum,
 *	genl_magic_func.h
 *		generates an entry in the static tla policy
 *		with .type = NLA_NESTED
 *		generates the static <struct_name>_nl_policy definition,
 *		and static conversion functions
 *
 *	genl_magic_func.h
 *
 * GENL_mc_group(group)
 *	genl_magic_struct.h
 *		does nothing
 *	genl_magic_func.h
 *		defines and registers the mcast group,
 *		and provides a send helper
 *
 * GENL_notification(op_name, op_num, mcast_group, tla list)
 *	These are notifications to userspace.
 *
 *	genl_magic_struct.h
 *		generates an entry in the genl_ops enum,
 *	genl_magic_func.h
 *		does nothing
 *
 *	mcast group: the name of the mcast group this notification should be
 *	expected on
 *	tla list: the list of expected top level attributes,
 *	for documentation and sanity checking.
 *
 * GENL_op(op_name, op_num, flags and handler, tla list) - "genl operations"
 *	These are requests from userspace.
 *
 *	_op and _notification share the same "number space",
 *	op_nr will be assigned to "genlmsghdr->cmd"
 *
 *	genl_magic_struct.h
 *		generates an entry in the genl_ops enum,
 *	genl_magic_func.h
 *		generates an entry in the static genl_ops array,
 *		and static register/unregister functions to
 *		genl_register_family_with_ops().
 *
 *	flags and handler:
 *		GENL_op_init( .doit = x, .dumpit = y, .flags = something)
 *		GENL_doit(x) => .dumpit = NULL, .flags = GENL_ADMIN_PERM
 *	tla list: the list of expected top level attributes,
 *	for documentation and sanity checking.
 */

/*
 * STRUCTS
 */

/* this is sent kernel -> userland on various error conditions, and contains
 * informational textual info, which is supposedly human readable.
 * The computer relevant return code is in the drbd_genlmsghdr.
 */
GENL_struct(DRBD_NLA_CFG_REPLY, 1, drbd_cfg_reply,
		/* "arbitrary" size strings, nla_policy.len = 0 */
	__str_field(1, DRBD_GENLA_F_MANDATORY,	info_text, 0)
)

/* Configuration requests typically need a context to operate on.
 * Possible keys are device minor (fits in the drbd_genlmsghdr),
 * the replication link (aka connection) name,
 * and/or the replication group (aka resource) name,
 * and the volume id within the resource. */
GENL_struct(DRBD_NLA_CFG_CONTEXT, 2, drbd_cfg_context,
	__u32_field(6, DRBD_GENLA_F_MANDATORY,	ctx_peer_node_id)
	__u32_field(1, DRBD_GENLA_F_MANDATORY,	ctx_volume)
	__str_field(2, DRBD_GENLA_F_MANDATORY,	ctx_resource_name, 128)
	__bin_field(3, DRBD_GENLA_F_MANDATORY,	ctx_my_addr, 128)
	__bin_field(4, DRBD_GENLA_F_MANDATORY,	ctx_peer_addr, 128)
	__str_field_def(5, 0, ctx_conn_name, SHARED_SECRET_MAX)
)

GENL_struct(DRBD_NLA_DISK_CONF, 3, disk_conf,
	__str_field(1, DRBD_F_REQUIRED | DRBD_F_INVARIANT,	backing_dev,	128)
	__str_field(2, DRBD_F_REQUIRED | DRBD_F_INVARIANT,	meta_dev,	128)
	__s32_field(3, DRBD_F_REQUIRED | DRBD_F_INVARIANT,	meta_dev_idx)

	/* use the resize command to try and change the disk_size */
	__u64_field(4, DRBD_GENLA_F_MANDATORY | DRBD_F_INVARIANT,	disk_size)
	/*__u32_field(5, DRBD_GENLA_F_MANDATORY | DRBD_F_INVARIANT,	max_bio_bvecs)*/

	__u32_field_def(6, DRBD_GENLA_F_MANDATORY,	on_io_error, DRBD_ON_IO_ERROR_DEF)
	/*__u32_field_def(7, DRBD_GENLA_F_MANDATORY,	fencing_policy, DRBD_FENCING_DEF)*/

	__s32_field_def(9,	DRBD_GENLA_F_MANDATORY,	resync_after, DRBD_MINOR_NUMBER_DEF)
	__u32_field_def(10,	DRBD_GENLA_F_MANDATORY,	al_extents, DRBD_AL_EXTENTS_DEF)

	__flg_field_def(16, DRBD_GENLA_F_MANDATORY,	disk_barrier, DRBD_DISK_BARRIER_DEF)
	__flg_field_def(17, DRBD_GENLA_F_MANDATORY,	disk_flushes, DRBD_DISK_FLUSHES_DEF)
	__flg_field_def(18, DRBD_GENLA_F_MANDATORY,	disk_drain, DRBD_DISK_DRAIN_DEF)
	__flg_field_def(19, DRBD_GENLA_F_MANDATORY,	md_flushes, DRBD_MD_FLUSHES_DEF)
	__u32_field_def(20,	DRBD_GENLA_F_MANDATORY,	disk_timeout, DRBD_DISK_TIMEOUT_DEF)
	__u32_field_def(21, DRBD_GENLA_F_MANDATORY,     read_balancing, DRBD_READ_BALANCING_DEF)
	__u32_field_def(22,	DRBD_GENLA_F_MANDATORY,	unplug_watermark, DRBD_UNPLUG_WATERMARK_DEF)
	__u32_field_def(25, 0 /* OPTIONAL */,           rs_discard_granularity, DRBD_RS_DISCARD_GRANULARITY_DEF)
	__flg_field_def(23,     0 /* OPTIONAL */,	al_updates, DRBD_AL_UPDATES_DEF)
	__flg_field_def(24,     0 /* OPTIONAL */,       discard_zeroes_if_aligned, DRBD_DISCARD_ZEROES_IF_ALIGNED_DEF)
	__flg_field_def(26, 0 /* OPTIONAL */, disable_write_same, DRBD_DISABLE_WRITE_SAME_DEF)
)

GENL_struct(DRBD_NLA_RESOURCE_OPTS, 4, res_opts,
	__str_field_def(1,	DRBD_GENLA_F_MANDATORY,	cpu_mask,       DRBD_CPU_MASK_SIZE)
	__u32_field_def(2,	DRBD_GENLA_F_MANDATORY,	on_no_data, DRBD_ON_NO_DATA_DEF)
	__flg_field_def(3,	DRBD_GENLA_F_MANDATORY,	auto_promote, DRBD_AUTO_PROMOTE_DEF)
	__u32_field(4,		DRBD_F_REQUIRED | DRBD_F_INVARIANT,	node_id)
	__u32_field_def(5,	DRBD_GENLA_F_MANDATORY,	peer_ack_window, DRBD_PEER_ACK_WINDOW_DEF)
	__u32_field_def(6,	DRBD_GENLA_F_MANDATORY,	twopc_timeout, DRBD_TWOPC_TIMEOUT_DEF)
	__u32_field_def(7,	DRBD_GENLA_F_MANDATORY, twopc_retry_timeout, DRBD_TWOPC_RETRY_TIMEOUT_DEF)
	__u32_field_def(8,	0 /* OPTIONAL */,	peer_ack_delay, DRBD_PEER_ACK_DELAY_DEF)
	__u32_field_def(9,	0 /* OPTIONAL */,	auto_promote_timeout, DRBD_AUTO_PROMOTE_TIMEOUT_DEF)
	__u32_field_def(10,    0 /* OPTIONAL */,    nr_requests, DRBD_NR_REQUESTS_DEF)
	__s32_field_def(11, 0 /* OPTIONAL */, quorum, DRBD_QUORUM_DEF)
	__u32_field_def(12, 0 /* OPTIONAL */, on_no_quorum, DRBD_ON_NO_QUORUM_DEF)
	__u32_field_def(13, 0 /* OPTIONAL */, req_buf_size, DRBD_REQ_BUF_SIZE_DEF)        /* MODIFIED_BY_MANTECH DW-1200: request buffer maximum size */
	__flg_field_def(14, 0 /* OPTIONAL */, svc_autostart, DRBD_SVC_AUTOSTART_DEF)	  /* DW-1249: auto-start by svc*/
	__u32_field_def(15, 0 /* OPTIONAL */, io_error_retry_count, DRBD_IO_ERROR_RETRY_COUNT_DEF)        /* DW-1716: retry count for I/O error*/
)

GENL_struct(DRBD_NLA_NET_CONF, 5, net_conf,
	__str_field_def(1,	DRBD_GENLA_F_MANDATORY | DRBD_F_SENSITIVE,
						shared_secret,	SHARED_SECRET_MAX)
	__str_field_def(2,	DRBD_GENLA_F_MANDATORY,	cram_hmac_alg,	SHARED_SECRET_MAX)
	__str_field_def(3,	DRBD_GENLA_F_MANDATORY,	integrity_alg,	SHARED_SECRET_MAX)
	__str_field_def(4,	DRBD_GENLA_F_MANDATORY,	verify_alg,     SHARED_SECRET_MAX)
	__str_field_def(5,	DRBD_GENLA_F_MANDATORY,	csums_alg,	SHARED_SECRET_MAX)
	__u32_field_def(6,	DRBD_GENLA_F_MANDATORY,	wire_protocol, DRBD_PROTOCOL_DEF)
	__u32_field_def(7,	DRBD_GENLA_F_MANDATORY,	connect_int, DRBD_CONNECT_INT_DEF)
	__u32_field_def(8,	DRBD_GENLA_F_MANDATORY,	timeout, DRBD_TIMEOUT_DEF)
	__u32_field_def(9,	DRBD_GENLA_F_MANDATORY,	ping_int, DRBD_PING_INT_DEF)
	__u32_field_def(10,	DRBD_GENLA_F_MANDATORY,	ping_timeo, DRBD_PING_TIMEO_DEF)
	//__u32_field_def(11,	DRBD_GENLA_F_MANDATORY,	sndbuf_size, DRBD_SNDBUF_SIZE_DEF)
	__u64_field(11,	DRBD_GENLA_F_MANDATORY,	sndbuf_size)
	__u32_field_def(12,	DRBD_GENLA_F_MANDATORY,	rcvbuf_size, DRBD_RCVBUF_SIZE_DEF)
	__u32_field_def(13,	DRBD_GENLA_F_MANDATORY,	ko_count, DRBD_KO_COUNT_DEF)
	__u32_field_def(15,	DRBD_GENLA_F_MANDATORY,	max_epoch_size, DRBD_MAX_EPOCH_SIZE_DEF)
	__u32_field_def(17,	DRBD_GENLA_F_MANDATORY,	after_sb_0p, DRBD_AFTER_SB_0P_DEF)
	__u32_field_def(18,	DRBD_GENLA_F_MANDATORY,	after_sb_1p, DRBD_AFTER_SB_1P_DEF)
	__u32_field_def(19,	DRBD_GENLA_F_MANDATORY,	after_sb_2p, DRBD_AFTER_SB_2P_DEF)
	__u32_field_def(20,	DRBD_GENLA_F_MANDATORY,	rr_conflict, DRBD_RR_CONFLICT_DEF)
	__u32_field_def(21,	DRBD_GENLA_F_MANDATORY,	on_congestion, DRBD_ON_CONGESTION_DEF)
	//__u32_field_def(22,	DRBD_GENLA_F_MANDATORY,	cong_fill, DRBD_CONG_FILL_DEF)
	__u64_field(22,	DRBD_GENLA_F_MANDATORY,	cong_fill)
	__u32_field_def(23,	DRBD_GENLA_F_MANDATORY,	cong_extents, DRBD_CONG_EXTENTS_DEF)
	__flg_field_def(24, DRBD_GENLA_F_MANDATORY,	two_primaries, DRBD_ALLOW_TWO_PRIMARIES_DEF)
	__flg_field_def(26, DRBD_GENLA_F_MANDATORY,	tcp_cork, DRBD_TCP_CORK_DEF)
	__flg_field_def(27, DRBD_GENLA_F_MANDATORY,	always_asbp, DRBD_ALWAYS_ASBP_DEF)
	__flg_field_def(29,	DRBD_GENLA_F_MANDATORY,	use_rle, DRBD_USE_RLE_DEF)
	__u32_field_def(30,	DRBD_GENLA_F_MANDATORY,	fencing_policy, DRBD_FENCING_DEF)
	__str_field_def(31,	DRBD_GENLA_F_MANDATORY, name, SHARED_SECRET_MAX)
	/* moved into ctx_peer_node_id: __u32_field(32,		DRBD_F_REQUIRED | DRBD_F_INVARIANT,	peer_node_id) */
	__flg_field_def(33, 0 /* OPTIONAL */,	csums_after_crash_only, DRBD_CSUMS_AFTER_CRASH_ONLY_DEF)
	__u32_field_def(34, 0 /* OPTIONAL */, sock_check_timeo, DRBD_SOCKET_CHECK_TIMEO_DEF)
	__str_field_def(35, DRBD_F_INVARIANT, transport_name, SHARED_SECRET_MAX)
	__u32_field_def(36, 0 /* OPTIONAL */, max_buffers, DRBD_MAX_BUFFERS_DEF)
)

GENL_struct(DRBD_NLA_SET_ROLE_PARMS, 6, set_role_parms,
	__flg_field(1, DRBD_GENLA_F_MANDATORY,	assume_uptodate)
)

GENL_struct(DRBD_NLA_RESIZE_PARMS, 7, resize_parms,
	__u64_field(1, DRBD_GENLA_F_MANDATORY,	resize_size)
	__flg_field(2, DRBD_GENLA_F_MANDATORY,	resize_force)
	__flg_field(3, DRBD_GENLA_F_MANDATORY,	no_resync)
	__u32_field_def(4, 0 /* OPTIONAL */, al_stripes, DRBD_AL_STRIPES_DEF)
	__u32_field_def(5, 0 /* OPTIONAL */, al_stripe_size, DRBD_AL_STRIPE_SIZE_DEF)
)

GENL_struct(DRBD_NLA_START_OV_PARMS, 9, start_ov_parms,
	__u64_field(1, DRBD_GENLA_F_MANDATORY,	ov_start_sector)
	__u64_field(2, DRBD_GENLA_F_MANDATORY,	ov_stop_sector)
)

GENL_struct(DRBD_NLA_NEW_C_UUID_PARMS, 10, new_c_uuid_parms,
	__flg_field(1, DRBD_GENLA_F_MANDATORY, clear_bm)
)

GENL_struct(DRBD_NLA_TIMEOUT_PARMS, 11, timeout_parms,
	__u32_field(1,	DRBD_F_REQUIRED,	timeout_type)
)

GENL_struct(DRBD_NLA_DISCONNECT_PARMS, 12, disconnect_parms,
	__flg_field(1, DRBD_GENLA_F_MANDATORY,	force_disconnect)
)

GENL_struct(DRBD_NLA_DETACH_PARMS, 13, detach_parms,
	__flg_field(1, DRBD_GENLA_F_MANDATORY,	force_detach)
)

GENL_struct(DRBD_NLA_DEVICE_CONF, 14, device_conf,
	__u32_field_def(1, DRBD_F_INVARIANT,	max_bio_size, DRBD_MAX_BIO_SIZE_DEF)
	__flg_field_def(2, 0 /* OPTIONAL */, intentional_diskless, DRBD_DISK_DISKLESS_DEF)
)

GENL_struct(DRBD_NLA_RESOURCE_INFO, 15, resource_info,
	__u32_field(1, 0, res_role)
	__flg_field(2, 0, res_susp)
	__flg_field(3, 0, res_susp_nod)
	__flg_field(4, 0, res_susp_fen)
	__flg_field(5, 0, res_susp_quorum)
)

GENL_struct(DRBD_NLA_DEVICE_INFO, 16, device_info,
	__u32_field(1, 0, dev_disk_state)
	__flg_field(2, 0, is_intentional_diskless)
	__s32_field(3, 0, io_error_count)
)

GENL_struct(DRBD_NLA_CONNECTION_INFO, 17, connection_info,
	__u32_field(1, 0, conn_connection_state)
	__u32_field(2, 0, conn_role)
)

GENL_struct(DRBD_NLA_PEER_DEVICE_INFO, 18, peer_device_info,
	__u32_field(1, 0, peer_repl_state)
	__u32_field(2, 0, peer_disk_state)
	__u32_field(3, 0, peer_resync_susp_user)
	__u32_field(4, 0, peer_resync_susp_peer)
	__u32_field(5, 0, peer_resync_susp_dependency)
	__flg_field(6, 0, peer_is_intentional_diskless)
)

GENL_struct(DRBD_NLA_RESOURCE_STATISTICS, 19, resource_statistics,
	__u32_field(1, 0, res_stat_write_ordering)
)

GENL_struct(DRBD_NLA_DEVICE_STATISTICS, 20, device_statistics,
	__u64_field(1, 0, dev_size)  /* (sectors) */
	__u64_field(2, 0, dev_read)  /* (sectors) */
	__u64_field(3, 0, dev_write)  /* (sectors) */
	__u64_field(4, 0, dev_al_writes)  /* activity log writes (count) */
	__u64_field(5, 0, dev_bm_writes)  /*  bitmap writes  (count) */
	__u32_field(6, 0, dev_upper_pending)  /* application requests in progress */
	__u32_field(7, 0, dev_lower_pending)  /* backing device requests in progress */
	__flg_field(8, 0, dev_upper_blocked)
	__flg_field(9, 0, dev_lower_blocked)
	__flg_field(10, 0, dev_al_suspended)  /* activity log suspended */
	__u64_field(11, 0, dev_exposed_data_uuid)
	__u64_field(12, 0, dev_current_uuid)
	__u32_field(13, 0, dev_disk_flags)
	__bin_field(14, 0, history_uuids, HISTORY_UUIDS * sizeof(__u64))
)

GENL_struct(DRBD_NLA_CONNECTION_STATISTICS, 21, connection_statistics,
	__flg_field(1, 0, conn_congested)
)

GENL_struct(DRBD_NLA_PEER_DEVICE_STATISTICS, 22, peer_device_statistics,
	__u64_field(1, 0, peer_dev_received)  /* sectors */
	__u64_field(2, 0, peer_dev_sent)  /* sectors */
	__u32_field(3, 0, peer_dev_pending)  /* number of requests */
	__u32_field(4, 0, peer_dev_unacked)  /* number of requests */
	__u64_field(5, 0, peer_dev_out_of_sync)  /* sectors */
	__u64_field(6, 0, peer_dev_resync_failed)  /* sectors */
	__u64_field(7, 0, peer_dev_bitmap_uuid)
	__u32_field(9, 0, peer_dev_flags)
)

GENL_struct(DRBD_NLA_NOTIFICATION_HEADER, 23, drbd_notification_header,
	__u32_field(1, DRBD_GENLA_F_MANDATORY, nh_type)
)

GENL_struct(DRBD_NLA_HELPER, 24, drbd_helper_info,
	__str_field(1, DRBD_GENLA_F_MANDATORY, helper_name, 32)
	__u32_field(2, DRBD_GENLA_F_MANDATORY, helper_status)
)

GENL_struct(DRBD_NLA_INVALIDATE_PARMS, 25, invalidate_parms,
	__s32_field_def(1, DRBD_GENLA_F_MANDATORY, sync_from_peer_node_id, DRBD_SYNC_FROM_NID_DEF)
)

GENL_struct(DRBD_NLA_FORGET_PEER_PARMS, 26, forget_peer_parms,
	__s32_field_def(1, DRBD_GENLA_F_MANDATORY, forget_peer_node_id, DRBD_SYNC_FROM_NID_DEF)
)

GENL_struct(DRBD_NLA_PEER_DEVICE_OPTS, 27, peer_device_conf,
	__u32_field_def(1,	DRBD_GENLA_F_MANDATORY,	resync_rate, DRBD_RESYNC_RATE_DEF)
	__u32_field_def(2,	DRBD_GENLA_F_MANDATORY,	c_plan_ahead, DRBD_C_PLAN_AHEAD_DEF)
	__u32_field_def(3,	DRBD_GENLA_F_MANDATORY,	c_delay_target, DRBD_C_DELAY_TARGET_DEF)
	__u32_field_def(4,	DRBD_GENLA_F_MANDATORY,	c_fill_target, DRBD_C_FILL_TARGET_DEF)
	__u32_field_def(5,	DRBD_GENLA_F_MANDATORY,	c_max_rate, DRBD_C_MAX_RATE_DEF)
	__u32_field_def(6,	DRBD_GENLA_F_MANDATORY,	c_min_rate, DRBD_C_MIN_RATE_DEF)
	__flg_field_def(7, 0 /* OPTIONAL */, bitmap, DRBD_BITMAP_DEF)
)

GENL_struct(DRBD_NLA_PATH_PARMS, 28, path_parms,
	__bin_field(1, DRBD_GENLA_F_MANDATORY,	my_addr, 128)
	__bin_field(2, DRBD_GENLA_F_MANDATORY,	peer_addr, 128)
)

GENL_struct(DRBD_NLA_CONNECT_PARMS, 29, connect_parms,
	__flg_field_def(1,	DRBD_GENLA_F_MANDATORY,	tentative, 0)
	__flg_field_def(2,	DRBD_GENLA_F_MANDATORY,	discard_my_data, 0)
)

GENL_struct(DRBD_NLA_PATH_INFO, 30, drbd_path_info,
	__flg_field(1, 0, path_established)
)

GENL_struct(DRBD_NLA_IO_ERROR, 31, drbd_io_error_info,
	__s32_field(1, DRBD_GENLA_F_MANDATORY, error_code)
	__u32_field(2, DRBD_GENLA_F_MANDATORY, size)
	__u64_field(3, DRBD_GENLA_F_MANDATORY, sector)
	__u8_field(4, DRBD_GENLA_F_MANDATORY, disk_type)
	__u8_field(5, DRBD_GENLA_F_MANDATORY, io_type)
	__u8_field(6, DRBD_GENLA_F_MANDATORY, is_cleared)
)

/*
 * Notifications and commands (genlmsghdr->cmd)
 */
 // 
#ifdef _WIN32 
	// skip compile error!
#else
GENL_mc_group(events)
#endif

	/* add DRBD minor devices as volumes to resources */
GENL_op(DRBD_ADM_NEW_MINOR, 5, GENL_doit(drbd_adm_new_minor),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_DEVICE_CONF, DRBD_GENLA_F_MANDATORY))
GENL_op(DRBD_ADM_DEL_MINOR, 6, GENL_doit(drbd_adm_del_minor),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED))

	/* add or delete resources */
GENL_op(DRBD_ADM_NEW_RESOURCE, 7, GENL_doit(drbd_adm_new_resource),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED))
GENL_op(DRBD_ADM_DEL_RESOURCE, 8, GENL_doit(drbd_adm_del_resource),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED))

GENL_op(DRBD_ADM_RESOURCE_OPTS, 9,
	GENL_doit(drbd_adm_resource_opts),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_RESOURCE_OPTS, DRBD_GENLA_F_MANDATORY)
)

GENL_op(DRBD_ADM_NEW_PEER, 44, GENL_doit(drbd_adm_new_peer),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_NET_CONF, DRBD_GENLA_F_MANDATORY)
)

GENL_op(DRBD_ADM_NEW_PATH, 45, GENL_doit(drbd_adm_new_path),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_PATH_PARMS, DRBD_F_REQUIRED)
)

GENL_op(DRBD_ADM_DEL_PEER, 46, GENL_doit(drbd_adm_del_peer),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_DISCONNECT_PARMS, DRBD_GENLA_F_MANDATORY)
)

GENL_op(DRBD_ADM_DEL_PATH, 47, GENL_doit(drbd_adm_del_path),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_PATH_PARMS, DRBD_F_REQUIRED)
)

GENL_op(DRBD_ADM_CONNECT, 10, GENL_doit(drbd_adm_connect),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_CONNECT_PARMS, DRBD_GENLA_F_MANDATORY)
)

GENL_op(
	DRBD_ADM_CHG_NET_OPTS, 29,
	GENL_doit(drbd_adm_net_opts),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_NET_CONF, DRBD_F_REQUIRED)
)

GENL_op(DRBD_ADM_DISCONNECT, 11, GENL_doit(drbd_adm_disconnect),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_DISCONNECT_PARMS, DRBD_GENLA_F_MANDATORY)
)

GENL_op(DRBD_ADM_ATTACH, 12,
	GENL_doit(drbd_adm_attach),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_DISK_CONF, DRBD_F_REQUIRED)
)

GENL_op(DRBD_ADM_CHG_DISK_OPTS, 28,
	GENL_doit(drbd_adm_disk_opts),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_DISK_OPTS, DRBD_F_REQUIRED)
)

GENL_op(
	DRBD_ADM_RESIZE, 13,
	GENL_doit(drbd_adm_resize),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_RESIZE_PARMS, DRBD_GENLA_F_MANDATORY)
)

GENL_op(
	DRBD_ADM_PRIMARY, 14,
	GENL_doit(drbd_adm_set_role),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_SET_ROLE_PARMS, DRBD_F_REQUIRED)
)

GENL_op(
	DRBD_ADM_SECONDARY, 15,
	GENL_doit(drbd_adm_set_role),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_SET_ROLE_PARMS, DRBD_F_REQUIRED)
)

GENL_op(
	DRBD_ADM_NEW_C_UUID, 16,
	GENL_doit(drbd_adm_new_c_uuid),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_NEW_C_UUID_PARMS, DRBD_GENLA_F_MANDATORY)
)

GENL_op(
	DRBD_ADM_START_OV, 17,
	GENL_doit(drbd_adm_start_ov),
	GENL_tla_expected(DRBD_NLA_START_OV_PARMS, DRBD_GENLA_F_MANDATORY)
)

GENL_op(DRBD_ADM_DETACH,	18, GENL_doit(drbd_adm_detach),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_DETACH_PARMS, DRBD_GENLA_F_MANDATORY))

GENL_op(DRBD_ADM_INVALIDATE,	19, GENL_doit(drbd_adm_invalidate),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_INVALIDATE_PARMS, DRBD_F_REQUIRED))

GENL_op(DRBD_ADM_INVAL_PEER,	20, GENL_doit(drbd_adm_invalidate_peer),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED))
GENL_op(DRBD_ADM_PAUSE_SYNC,	21, GENL_doit(drbd_adm_pause_sync),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED))
GENL_op(DRBD_ADM_RESUME_SYNC,	22, GENL_doit(drbd_adm_resume_sync),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED))
GENL_op(DRBD_ADM_SUSPEND_IO,	23, GENL_doit(drbd_adm_suspend_io),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED))
GENL_op(DRBD_ADM_RESUME_IO,	24, GENL_doit(drbd_adm_resume_io),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED))
GENL_op(DRBD_ADM_OUTDATE,	25, GENL_doit(drbd_adm_outdate),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED))
GENL_op(DRBD_ADM_GET_TIMEOUT_TYPE, 26, GENL_doit(drbd_adm_get_timeout_type),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED))
GENL_op(DRBD_ADM_DOWN,		27, GENL_doit(drbd_adm_down),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED))

GENL_op(DRBD_ADM_GET_RESOURCES, 30,
	GENL_op_init(
		.dumpit = drbd_adm_dump_resources,
	),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_GENLA_F_MANDATORY)
	GENL_tla_expected(DRBD_NLA_RESOURCE_INFO, DRBD_GENLA_F_MANDATORY)
	GENL_tla_expected(DRBD_NLA_RESOURCE_STATISTICS, DRBD_GENLA_F_MANDATORY))

GENL_op(DRBD_ADM_GET_DEVICES, 31,
	GENL_op_init(
		.dumpit = drbd_adm_dump_devices,
		.done = drbd_adm_dump_devices_done,
	),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_GENLA_F_MANDATORY)
	GENL_tla_expected(DRBD_NLA_DEVICE_INFO, DRBD_GENLA_F_MANDATORY)
	GENL_tla_expected(DRBD_NLA_DEVICE_STATISTICS, DRBD_GENLA_F_MANDATORY))

GENL_op(DRBD_ADM_GET_CONNECTIONS, 32,
	GENL_op_init(
		.dumpit = drbd_adm_dump_connections,
		.done = drbd_adm_dump_connections_done,
	),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_GENLA_F_MANDATORY)
	GENL_tla_expected(DRBD_NLA_CONNECTION_INFO, DRBD_GENLA_F_MANDATORY)
	GENL_tla_expected(DRBD_NLA_CONNECTION_STATISTICS, DRBD_GENLA_F_MANDATORY))

GENL_op(DRBD_ADM_GET_PEER_DEVICES, 33,
	GENL_op_init(
		.dumpit = drbd_adm_dump_peer_devices,
		.done = drbd_adm_dump_peer_devices_done,
	),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_GENLA_F_MANDATORY)
	GENL_tla_expected(DRBD_NLA_PEER_DEVICE_INFO, DRBD_GENLA_F_MANDATORY)
	GENL_tla_expected(DRBD_NLA_PEER_DEVICE_STATISTICS, DRBD_GENLA_F_MANDATORY))

GENL_notification(
	DRBD_RESOURCE_STATE, 34, events,
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_NOTIFICATION_HEADER, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_RESOURCE_INFO, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_RESOURCE_STATISTICS, DRBD_F_REQUIRED))

GENL_notification(
	DRBD_DEVICE_STATE, 35, events,
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_NOTIFICATION_HEADER, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_DEVICE_INFO, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_DEVICE_STATISTICS, DRBD_F_REQUIRED))

GENL_notification(
	DRBD_CONNECTION_STATE, 36, events,
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_NOTIFICATION_HEADER, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_PATH_PARMS, DRBD_GENLA_F_MANDATORY)
	GENL_tla_expected(DRBD_NLA_CONNECTION_INFO, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_CONNECTION_STATISTICS, DRBD_F_REQUIRED))

GENL_notification(
	DRBD_PEER_DEVICE_STATE, 37, events,
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_NOTIFICATION_HEADER, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_PEER_DEVICE_INFO, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_PEER_DEVICE_STATISTICS, DRBD_F_REQUIRED))

GENL_op(
	DRBD_ADM_GET_INITIAL_STATE, 38,
	GENL_op_init(
		.dumpit = drbd_adm_get_initial_state,
		.done = drbd_adm_get_initial_state_done,
	),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_GENLA_F_MANDATORY))

GENL_notification(
	DRBD_HELPER, 40, events,
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_HELPER, DRBD_F_REQUIRED))

GENL_notification(
	DRBD_INITIAL_STATE_DONE, 41, events,
	GENL_tla_expected(DRBD_NLA_NOTIFICATION_HEADER, DRBD_F_REQUIRED))

GENL_op(DRBD_ADM_FORGET_PEER,		42, GENL_doit(drbd_adm_forget_peer),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_FORGET_PEER_PARMS, DRBD_F_REQUIRED))

GENL_op(DRBD_ADM_CHG_PEER_DEVICE_OPTS, 43,
	GENL_doit(drbd_adm_peer_device_opts),
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_PEER_DEVICE_OPTS, DRBD_F_REQUIRED))

GENL_notification(
	DRBD_PATH_STATE, 48, events,
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_PATH_INFO, DRBD_F_REQUIRED))

GENL_notification(
	DRBD_IO_ERROR, 49, events,
	GENL_tla_expected(DRBD_NLA_CFG_CONTEXT, DRBD_F_REQUIRED)
	GENL_tla_expected(DRBD_NLA_IO_ERROR, DRBD_F_REQUIRED))