﻿/*
   drbd_nl.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt
#ifdef _WIN32
#include "windows/drbd.h"
#define		ERR_LOCAL_AND_PEER_ADDR 173	
#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"
#include "drbd_state_change.h"
#include "drbd_debugfs.h"
#include "drbd_transport.h"
#include "linux/drbd_limits.h"
#include "Proto.h"
#else
#include <linux/module.h>
#include <linux/drbd.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/blkpg.h>
#include <linux/cpumask.h>
#include <linux/random.h>
#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"
#include "drbd_state_change.h"
#include "drbd_debugfs.h"
#include "drbd_transport.h"
#include <asm/unaligned.h>
#include <linux/drbd_limits.h>
#include <linux/kthread.h>
#include <linux/security.h>
#include <net/genetlink.h>
#endif

#ifdef _WIN32
/* DW-1587
* Turns off the C6319 warning caused by code analysis.
* The use of comma does not cause any performance problems or bugs,
* but keep the code as it is written.
*/
#pragma warning (disable: 6053 6319 28719)
#endif

#ifdef _WIN32
bool capable(int cap)
{
	UNREFERENCED_PARAMETER(cap);
    // not supported
    return false;
}
#endif

/* .doit */
// int drbd_adm_create_resource(struct sk_buff *skb, struct genl_info *info);
// int drbd_adm_delete_resource(struct sk_buff *skb, struct genl_info *info);

int drbd_adm_new_minor(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_del_minor(struct sk_buff *skb, struct genl_info *info);

int drbd_adm_new_resource(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_del_resource(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_down(struct sk_buff *skb, struct genl_info *info);

int drbd_adm_set_role(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_attach(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_disk_opts(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_detach(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_connect(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_new_peer(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_del_peer(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_new_path(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_del_path(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_net_opts(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_peer_device_opts(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_resize(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_start_ov(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_new_c_uuid(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_disconnect(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_invalidate(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_invalidate_peer(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_pause_sync(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_resume_sync(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_suspend_io(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_resume_io(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_outdate(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_resource_opts(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_get_status(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_get_timeout_type(struct sk_buff *skb, struct genl_info *info);
int drbd_adm_forget_peer(struct sk_buff *skb, struct genl_info *info);
/* .dumpit */
int drbd_adm_dump_resources(struct sk_buff *skb, struct netlink_callback *cb);
int drbd_adm_dump_devices(struct sk_buff *skb, struct netlink_callback *cb);
int drbd_adm_dump_devices_done(struct netlink_callback *cb);
int drbd_adm_dump_connections(struct sk_buff *skb, struct netlink_callback *cb);
int drbd_adm_dump_connections_done(struct netlink_callback *cb);
int drbd_adm_dump_peer_devices(struct sk_buff *skb, struct netlink_callback *cb);
int drbd_adm_dump_peer_devices_done(struct netlink_callback *cb);
int drbd_adm_get_initial_state(struct sk_buff *skb, struct netlink_callback *cb);
int drbd_adm_get_initial_state_done(struct netlink_callback *cb);

#ifdef _WIN32
KSTART_ROUTINE _try_outdate_peer_async;
#endif

#include <linux/drbd_genl_api.h>
#include "drbd_nla.h"
#include <linux/genl_magic_func.h>

atomic_t drbd_genl_seq = ATOMIC_INIT(2); /* two. */

#ifdef _WIN32 
// noti mutex 
struct mutex notification_mutex;
#else
DEFINE_MUTEX(notification_mutex);
#endif

/* used blkdev_get_by_path, to claim our meta data device(s) */
static char *drbd_m_holder = "Hands off! this is DRBD's meta data device.";

#ifdef _WIN32
int drbd_adm_send_reply(struct sk_buff *skb, struct genl_info *info)
#else
static void drbd_adm_send_reply(struct sk_buff *skb, struct genl_info *info)
#endif
{
	genlmsg_end(skb, genlmsg_data(nlmsg_data(nlmsg_hdr(skb))));
#ifdef NL_PACKET_MSG
    {
        struct nlmsghdr * pnlh = (struct nlmsghdr *)skb->data;
        struct genlmsghdr * pgenlh = nlmsg_data(pnlh);

        WDRBD_TRACE("len(%d), type(0x%x), flags(0x%x), seq(%d), pid(%d), cmd(%d), version(%d)\n",
            pnlh->nlmsg_len, pnlh->nlmsg_type, pnlh->nlmsg_flags, pnlh->nlmsg_seq, pnlh->nlmsg_pid, pgenlh->cmd, pgenlh->version);

        if (pnlh->nlmsg_flags & NLM_F_ECHO)
        {
            WDRBD_TRACE("done\n", 0);
            return 0;
        }
    }
#endif
	if (genlmsg_reply(skb, info)) {
		pr_err("error sending genl reply\n");
		return -1;
	} 

	return 0;
	
}

/* Used on a fresh "drbd_adm_prepare"d reply_skb, this cannot fail: The only
 * reason it could fail was no space in skb, and there are 4k available. */
static int drbd_msg_put_info(struct sk_buff *skb, const char *info)
{
	struct nlattr *nla;
	int err = -EMSGSIZE;

	if (!info || !info[0])
		return 0;

	nla = nla_nest_start(skb, DRBD_NLA_CFG_REPLY);
	if (!nla)
		return err;

	err = nla_put_string(skb, T_info_text, info);
	if (err) {
		nla_nest_cancel(skb, nla);
		return err;
	} else
		nla_nest_end(skb, nla);
	return 0;
}

static int drbd_adm_finish(struct drbd_config_context *, struct genl_info *, int);

extern struct genl_ops drbd_genl_ops[];

#ifdef COMPAT_HAVE_SECURITY_NETLINK_RECV
#define drbd_security_netlink_recv(skb, cap) \
	security_netlink_recv(skb, cap)
#else
#ifndef _WIN32
/* see
 * fd77846 security: remove the security_netlink_recv hook as it is equivalent to capable()
 */
static inline bool drbd_security_netlink_recv(struct sk_buff *skb, int cap)
{
	return !capable(cap);
}
#endif
#endif


static struct drbd_path *first_path(struct drbd_connection *connection)
{
	/* Ideally this function is removed at a later point in time.
	   It was introduced when replacing the single address pair
	   with a list of address pairs (or paths). */

	return list_first_entry_or_null(&connection->transport.paths, struct drbd_path, list);
}

/* This would be a good candidate for a "pre_doit" hook,
 * and per-family private info->pointers.
 * But we need to stay compatible with older kernels.
 * If it returns successfully, adm_ctx members are valid.
 */
#define DRBD_ADM_NEED_MINOR        (1 << 0)
#define DRBD_ADM_NEED_RESOURCE     (1 << 1)
#define DRBD_ADM_NEED_CONNECTION   (1 << 2)
#define DRBD_ADM_NEED_PEER_DEVICE  (1 << 3)
#define DRBD_ADM_NEED_PEER_NODE    (1 << 4)
#define DRBD_ADM_IGNORE_VERSION    (1 << 5)
static int drbd_adm_prepare(struct drbd_config_context *adm_ctx,
	struct sk_buff *skb, struct genl_info *info, unsigned flags)
{
	UNREFERENCED_PARAMETER(skb);

	struct drbd_genlmsghdr *d_in = info->userhdr;
	const u8 cmd = info->genlhdr->cmd;
	int err;

	memset(adm_ctx, 0, sizeof(*adm_ctx));
#ifndef _WIN32
	/*
	 * genl_rcv_msg() only checks if commands with the GENL_ADMIN_PERM flag
	 * set have CAP_NET_ADMIN; we also require CAP_SYS_ADMIN for
	 * administrative commands.
	 */
	if ((drbd_genl_ops[cmd].flags & GENL_ADMIN_PERM) &&
	    drbd_security_netlink_recv(skb, CAP_SYS_ADMIN))
		return -EPERM;
#endif

	adm_ctx->reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

	if (!adm_ctx->reply_skb) {
		err = -ENOMEM;
		goto fail;
	}
#ifdef _WIN32
	adm_ctx->reply_dh = genlmsg_put_reply((struct msg_buff *)adm_ctx->reply_skb,
		info, &drbd_genl_family, 0, cmd);
#else
	adm_ctx->reply_dh = genlmsg_put_reply(adm_ctx->reply_skb,
		info, &drbd_genl_family, 0, cmd);
#endif
	
	/* put of a few bytes into a fresh skb of >= 4k will always succeed.
	 * but anyways */
	if (!adm_ctx->reply_dh) {
		err = -ENOMEM;
		goto fail;
	}

	if (info->genlhdr->version != GENL_MAGIC_VERSION && (flags & DRBD_ADM_IGNORE_VERSION) == 0) {
		drbd_msg_put_info(adm_ctx->reply_skb, "Wrong API version, upgrade your drbd utils.");
		err = -EINVAL;
		goto fail;
	}

	if (flags & DRBD_ADM_NEED_PEER_DEVICE)
		flags |= DRBD_ADM_NEED_CONNECTION;
	if (flags & DRBD_ADM_NEED_CONNECTION)
		flags |= DRBD_ADM_NEED_PEER_NODE;
	if (flags & DRBD_ADM_NEED_PEER_NODE)
		flags |= DRBD_ADM_NEED_RESOURCE;

	adm_ctx->reply_dh->minor = d_in->minor;
	adm_ctx->reply_dh->ret_code = NO_ERROR;

	adm_ctx->volume = VOLUME_UNSPECIFIED;
	adm_ctx->peer_node_id = PEER_NODE_ID_UNSPECIFIED;
	if (info->attrs[DRBD_NLA_CFG_CONTEXT]) {
		struct nlattr *nla;
		/* parse and validate only */
		err = drbd_cfg_context_from_attrs(NULL, info);
		if (err)
			goto fail;

		/* It was present, and valid,
		 * copy it over to the reply skb. */
		err = nla_put_nohdr(adm_ctx->reply_skb,
				info->attrs[DRBD_NLA_CFG_CONTEXT]->nla_len,
				info->attrs[DRBD_NLA_CFG_CONTEXT]);
		if (err)
			goto fail;

		/* and assign stuff to the adm_ctx */
		nla = nested_attr_tb[__nla_type(T_ctx_volume)];
		if (nla)
			adm_ctx->volume = nla_get_u32(nla);
		nla = nested_attr_tb[__nla_type(T_ctx_peer_node_id)];
		if (nla)
			adm_ctx->peer_node_id = nla_get_u32(nla);
		nla = nested_attr_tb[__nla_type(T_ctx_resource_name)];
		if (nla)
			adm_ctx->resource_name = nla_data(nla);
	}

	if (adm_ctx->resource_name) {
		adm_ctx->resource = drbd_find_resource(adm_ctx->resource_name);
		if (adm_ctx->resource)
			kref_debug_get(&adm_ctx->resource->kref_debug, 2);
	}

	adm_ctx->minor = d_in->minor;
	rcu_read_lock();
	adm_ctx->device = minor_to_device(d_in->minor);
	if (adm_ctx->device) {
		kref_get(&adm_ctx->device->kref);
		kref_debug_get(&adm_ctx->device->kref_debug, 4);
	}
	rcu_read_unlock();

	if (!adm_ctx->device && (flags & DRBD_ADM_NEED_MINOR)) {
		drbd_msg_put_info(adm_ctx->reply_skb, "unknown minor");
		err = ERR_MINOR_INVALID;
		goto finish;
	}
	if (!adm_ctx->resource && (flags & DRBD_ADM_NEED_RESOURCE)) {
		drbd_msg_put_info(adm_ctx->reply_skb, "unknown resource");
		err = ERR_INVALID_REQUEST;
		if (adm_ctx->resource_name)
			err = ERR_RES_NOT_KNOWN;
		goto finish;
	}
	if (adm_ctx->peer_node_id != PEER_NODE_ID_UNSPECIFIED) {
		/* peer_node_id is unsigned int */
		if (adm_ctx->peer_node_id >= DRBD_NODE_ID_MAX) {
			drbd_msg_put_info(adm_ctx->reply_skb, "peer node id out of range");
			err = ERR_INVALID_REQUEST;
			goto finish;
		}
		if (adm_ctx->resource && adm_ctx->peer_node_id == adm_ctx->resource->res_opts.node_id) {
			drbd_msg_put_info(adm_ctx->reply_skb, "peer node id cannot be my own node id");
			err = ERR_INVALID_REQUEST;
			goto finish;
		}
		adm_ctx->connection = drbd_get_connection_by_node_id(adm_ctx->resource, adm_ctx->peer_node_id);
		if (adm_ctx->connection)
			kref_debug_get(&adm_ctx->connection->kref_debug, 2);
	} else if (flags & DRBD_ADM_NEED_PEER_NODE) {
		drbd_msg_put_info(adm_ctx->reply_skb, "peer node id missing");
		err = ERR_INVALID_REQUEST;
		goto finish;
	}
	if (flags & DRBD_ADM_NEED_CONNECTION) {
		if (!adm_ctx->connection) {
			drbd_msg_put_info(adm_ctx->reply_skb, "unknown connection");
			err = ERR_INVALID_REQUEST;
			goto finish;
		}
	}
	if (flags & DRBD_ADM_NEED_PEER_DEVICE) {
		rcu_read_lock();
		if (adm_ctx->volume != VOLUME_UNSPECIFIED)
			adm_ctx->peer_device =
				idr_find(&adm_ctx->connection->peer_devices,
					 adm_ctx->volume);
		if (!adm_ctx->peer_device) {
			drbd_msg_put_info(adm_ctx->reply_skb, "unknown volume");
			err = ERR_INVALID_REQUEST;
			rcu_read_unlock();
			goto finish;
		}
		if (!adm_ctx->device) {
			adm_ctx->device = adm_ctx->peer_device->device;
			kref_get(&adm_ctx->device->kref);
			kref_debug_get(&adm_ctx->device->kref_debug, 4);
		}
		rcu_read_unlock();
	}

	/* some more paranoia, if the request was over-determined */
	if (adm_ctx->device && adm_ctx->resource && adm_ctx->device->resource && 
	    adm_ctx->device->resource != adm_ctx->resource) {
		pr_warning("request: minor=%u, resource=%s; but that minor belongs to resource %s\n",
				adm_ctx->minor, adm_ctx->resource->name,
				adm_ctx->device->resource->name);
		drbd_msg_put_info(adm_ctx->reply_skb, "minor exists in different resource");
		err = ERR_INVALID_REQUEST;
		goto finish;
	}
	if (adm_ctx->device && adm_ctx->device->resource && 
	    adm_ctx->volume != VOLUME_UNSPECIFIED &&
	    adm_ctx->volume != adm_ctx->device->vnr) {
		pr_warning("request: minor=%u, volume=%u; but that minor is volume %u in %s\n",
				adm_ctx->minor, adm_ctx->volume,
				adm_ctx->device->vnr,
				adm_ctx->device->resource->name);
		drbd_msg_put_info(adm_ctx->reply_skb, "minor exists as different volume");
		err = ERR_INVALID_REQUEST;
		goto finish;
	}
	if (adm_ctx->device && adm_ctx->peer_device &&
		adm_ctx->resource && adm_ctx->resource->name &&
	    adm_ctx->peer_device->device != adm_ctx->device) {
		drbd_msg_put_info(adm_ctx->reply_skb, "peer_device->device != device");
		pr_warning("request: minor=%u, resource=%s, volume=%u, peer_node=%u; device != peer_device->device\n",
				adm_ctx->minor, adm_ctx->resource->name,
				adm_ctx->device->vnr, adm_ctx->peer_node_id);
		err = ERR_INVALID_REQUEST;
		goto finish;
	}

	/* still, provide adm_ctx->resource always, if possible. */
	if (!adm_ctx->resource) {
		adm_ctx->resource = adm_ctx->device ? adm_ctx->device->resource
			: adm_ctx->connection ? adm_ctx->connection->resource : NULL;
		if (adm_ctx->resource) {
			kref_get(&adm_ctx->resource->kref);
			kref_debug_get(&adm_ctx->resource->kref_debug, 2);
		}
	}

	return NO_ERROR;

fail:
	nlmsg_free(adm_ctx->reply_skb);
	adm_ctx->reply_skb = NULL;
	return err;

finish:
	return drbd_adm_finish(adm_ctx, info, err);
}

static int drbd_adm_finish(struct drbd_config_context *adm_ctx, struct genl_info *info, int retcode)
{
#ifdef _WIN32
	if (retcode < SS_SUCCESS)
	{
		struct drbd_resource *resource = adm_ctx->resource;		
		drbd_err(resource, "cmd(%u) error: %s\n", info->genlhdr->cmd, drbd_set_st_err_str(retcode));
	}
#endif

	if (adm_ctx->device) {
		kref_debug_put(&adm_ctx->device->kref_debug, 4);
		kref_put(&adm_ctx->device->kref, drbd_destroy_device);
		adm_ctx->device = NULL;
	}
	if (adm_ctx->connection) {
		kref_debug_put(&adm_ctx->connection->kref_debug, 2);
		kref_put(&adm_ctx->connection->kref, drbd_destroy_connection);
		adm_ctx->connection = NULL;
	}
	if (adm_ctx->resource) {
		kref_debug_put(&adm_ctx->resource->kref_debug, 2);
		kref_put(&adm_ctx->resource->kref, drbd_destroy_resource);
		adm_ctx->resource = NULL;
	}

	if (!adm_ctx->reply_skb)
		return -ENOMEM;

	adm_ctx->reply_dh->ret_code = retcode;
	drbd_adm_send_reply(adm_ctx->reply_skb, info);
#ifdef _WIN32 // DW-211 fix memory leak
	nlmsg_free(adm_ctx->reply_skb);
#endif
	adm_ctx->reply_skb = NULL;
	return 0;
}
#ifdef _WIN32
struct drbd_resource* get_resource_from_genl_info(struct genl_info* info)
{
	char *resource_name = NULL;
	struct nlattr *nla = NULL;
	int err;

	if (info->attrs[DRBD_NLA_CFG_CONTEXT]) {
		err = drbd_cfg_context_from_attrs(NULL, info);
		if (err) {
			return NULL;
		}
		nla = nested_attr_tb[__nla_type(T_ctx_resource_name)];
		if (nla) {
			resource_name = nla_data(nla);
			if (resource_name) {
				return drbd_find_resource(resource_name);
			}
		}
	}
	return NULL;
}
#endif

static void conn_md_sync(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		struct drbd_device *device = peer_device->device;
		kref_get(&device->kref);
		rcu_read_unlock();
		drbd_md_sync_if_dirty(device);
		kref_put(&device->kref, drbd_destroy_device);
#ifdef _WIN32
        rcu_read_lock_w32_inner();
#else
		rcu_read_lock();
#endif
	}
	rcu_read_unlock();
}

/* Try to figure out where we are happy to become primary.
   This is unsed by the crm-fence-peer mechanism
*/
static u64 up_to_date_nodes(struct drbd_device *device, bool op_is_fence)
{
	struct drbd_resource *resource = device->resource;
	const int my_node_id = resource->res_opts.node_id;
	u64 mask = NODE_MASK(my_node_id);

	if (resource->role[NOW] == R_PRIMARY || op_is_fence) {
		struct drbd_peer_device *peer_device;

		rcu_read_lock();
		for_each_peer_device_rcu(peer_device, device) {
			enum drbd_disk_state pdsk = peer_device->disk_state[NOW];
			if (pdsk == D_UP_TO_DATE)
				mask |= NODE_MASK(peer_device->node_id);
		}
		rcu_read_unlock();
	} else if (device->disk_state[NOW] == D_UP_TO_DATE) {
		struct drbd_peer_md *peer_md = device->ldev->md.peers;
		int node_id;

		for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
			struct drbd_peer_device *peer_device;
			if (node_id == my_node_id)
				continue;

			peer_device = peer_device_by_node_id(device, node_id);

			if ((peer_device && peer_device->disk_state[NOW] == D_UP_TO_DATE) ||
			    (peer_md[node_id].flags & MDF_NODE_EXISTS &&
			     peer_md[node_id].bitmap_uuid == 0))
				mask |= NODE_MASK(node_id);
		}
	} else
		  mask = 0;

	return mask;
}

/* Buffer to construct the environment of a user-space helper in. */
struct env {
	char *buffer;
	int size, pos;
};

/* Print into an env buffer. */
#ifdef _WIN32
static int env_print(struct env *env, const char *fmt, ...)
#else
static __printf(2, 3) int env_print(struct env *env, const char *fmt, ...)
#endif
{
	va_list args;
	int pos, ret;

	pos = env->pos;
	if (pos < 0)
		return pos;
	va_start(args, fmt);
#ifdef _WIN32
	ret = _vsnprintf(env->buffer + pos, env->size - pos - 1, fmt, args);
#else
	ret = vsnprintf(env->buffer + pos, env->size - pos, fmt, args);
#endif
	va_end(args);
	if (ret < 0) {
		env->pos = ret;
		goto out;
	}
	if (ret >= env->size - pos) {
		ret = env->pos = -ENOMEM;
		goto out;
	}
	env->pos += ret + 1;
    out:
	return ret;
}

/* Put env variables for an address into an env buffer. */
#ifdef _WIN32
static void env_print_address(struct env *env, const char *prefix,
            struct sockaddr_storage_win *storage)
#else
static void env_print_address(struct env *env, const char *prefix,
			      struct sockaddr_storage *storage)
#endif
{
	const char *afs;

	switch (storage->ss_family) {
	case AF_INET6:
		afs = "ipv6";
		env_print(env, "%sADDRESS=%pI6", prefix,
			  &((struct sockaddr_in6 *)storage)->sin6_addr);
		break;
	case AF_INET:
		afs = "ipv4";
		env_print(env, "%sADDRESS=%pI4", prefix,
			  &((struct sockaddr_in *)storage)->sin_addr);
		break;
	default:
		afs = "ssocks";
		env_print(env, "%sADDRESS=%pI4", prefix,
			  &((struct sockaddr_in *)storage)->sin_addr);
	}
	env_print(env, "%sAF=%s", prefix, afs);
}

/* Construct char **envp inside an env buffer. */
static char **make_envp(struct env *env)
{
	char **envp, *b;
	unsigned int n;

	if (env->pos < 0)
		return NULL;
	if (env->pos >= env->size)
		goto out_nomem;
	env->buffer[env->pos++] = 0;
	for (b = env->buffer, n = 1; *b; n++)
		b = strchr(b, 0) + 1;
	if (env->size - env->pos < (int)(sizeof(envp) * n))
		goto out_nomem;
	envp = (char **)(env->buffer + env->size) - n;

	for (b = env->buffer; *b; ) {
		*envp++ = b;
		b = strchr(b, 0) + 1;
	}
	*envp++ = NULL;
	return envp - n;

    out_nomem:
	env->pos = -ENOMEM;
	return NULL;
}

/* Macro refers to local variables peer_device, device and connection! */
#ifdef _WIN32
#define magic_printk(level, fmt, args, ...)				\
	if (peer_device)						\
		__drbd_printk_peer_device(level, peer_device, fmt, args); \
	else if (device)						\
		__drbd_printk_device(level, device, fmt, args);		\
	else								\
		__drbd_printk_connection(level, connection, fmt, args);
#else
#define magic_printk(level, fmt, args...)				\
	if (peer_device)						\
		__drbd_printk_peer_device(level, peer_device, fmt, args); \
	else if (device)						\
		__drbd_printk_device(level, device, fmt, args);		\
	else								\
		__drbd_printk_connection(level, connection, fmt, args);
#endif

int drbd_khelper(struct drbd_device *device, struct drbd_connection *connection, char *cmd)
{
	struct drbd_resource *resource = device ? device->resource : connection->resource;
	char *argv[] = {usermode_helper, cmd, resource->name, NULL };
	struct drbd_peer_device *peer_device = NULL;
	struct env env = { .size = PAGE_SIZE };
	char **envp;
	int ret;

    enlarge_buffer:
#ifdef _WIN32
    env.buffer = (char *)kmalloc(env.size, 0, '77DW');
#else
	env.buffer = (char *)__get_free_pages(GFP_NOIO, get_order(env.size));
#endif
	if (!env.buffer) {
		ret = -ENOMEM;
		goto out_err;
	}
	env.pos = 0;

	rcu_read_lock();
	env_print(&env, "HOME=/");
	env_print(&env, "TERM=linux");
	env_print(&env, "PATH=/sbin:/usr/sbin:/bin:/usr/bin");
	if (device) {
		env_print(&env, "DRBD_MINOR=%u", device_to_minor(device));
		env_print(&env, "DRBD_VOLUME=%u", device->vnr);
		if (get_ldev(device)) {
			struct disk_conf *disk_conf =
				rcu_dereference(device->ldev->disk_conf);
			env_print(&env, "DRBD_BACKING_DEV=%s",
				  disk_conf->backing_dev);
			put_ldev(device);
		}
	}
	if (connection) {
		struct drbd_path *path = first_path(connection);
		if (path) {
			/* TO BE DELETED */
			env_print_address(&env, "DRBD_MY_", &path->my_addr);
			env_print_address(&env, "DRBD_PEER_", &path->peer_addr);
		}
		env_print(&env, "DRBD_PEER_NODE_ID=%u", connection->peer_node_id);
	}
	if (connection && !device) {
		struct drbd_peer_device *peer_device;
		int vnr;

#ifdef _WIN32
        idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
		idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
			struct drbd_device *device = peer_device->device;

			env_print(&env, "DRBD_MINOR_%u=%u",
				  vnr, peer_device->device->minor);
			if (get_ldev(device)) {
				struct disk_conf *disk_conf =
					rcu_dereference(device->ldev->disk_conf);
				env_print(&env, "DRBD_BACKING_DEV_%u=%s",
					  vnr, disk_conf->backing_dev);
				put_ldev(device);
			}
		}
	}
	rcu_read_unlock();

	if (strstr(cmd, "fence") && connection) {
		bool op_is_fence = strcmp(cmd, "fence-peer") == 0;
		struct drbd_peer_device *peer_device;
		u64 mask = UINT64_MAX;
		int vnr;
#ifdef _WIN32
		idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
		idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
			struct drbd_device *device = peer_device->device;

			if (get_ldev(device)) {
				u64 m = up_to_date_nodes(device, op_is_fence);
				if (m)
					mask &= m;
				put_ldev(device);
				/* Yes we outright ignore volumes that are not up-to-date
				   on a single node. */
			}
		}
		env_print(&env, "UP_TO_DATE_NODES=0x%08llX", mask);
	}

	envp = make_envp(&env);
	if (!envp) {
		if (env.pos == -ENOMEM) {
#ifdef _WIN32
            kfree(env.buffer);
#else
			free_pages((unsigned long)env.buffer, get_order(env.size));
#endif
			env.size += PAGE_SIZE;
			goto enlarge_buffer;
		}
		ret = env.pos;
		goto out_err;
	}

	if (current == resource->worker.task)
		set_bit(CALLBACK_PENDING, &resource->flags);

	/* The helper may take some time.
	 * write out any unsynced meta data changes now */
	if (device)
		drbd_md_sync_if_dirty(device);
	else if (connection)
		conn_md_sync(connection);

	if (connection && device)
		peer_device = conn_peer_device(connection, device->vnr);

#ifndef _WIN32
	magic_printk(KERN_INFO, "helper command: %s %s\n", usermode_helper, cmd);
#endif
	notify_helper(NOTIFY_CALL, device, connection, cmd, 0);
#ifdef _WIN32_HANDLER_TIMEOUT
	if (g_handler_use) {
		ret = call_usermodehelper(usermode_helper, argv, envp, UMH_WAIT_PROC);
	}
	ret = 0;
#else
	ret = call_usermodehelper(usermode_helper, argv, envp, UMH_WAIT_PROC);
#endif
#ifndef _WIN32
	magic_printk(ret ? KERN_WARNING : KERN_INFO,
		     "helper command: %s %s exit code %u (0x%x)\n",
		     usermode_helper, cmd,
		     (ret >> 8) & 0xff, ret);
#endif
	notify_helper(NOTIFY_RESPONSE, device, connection, cmd, ret);

	if (current == resource->worker.task)
		clear_bit(CALLBACK_PENDING, &resource->flags);

	if (ret < 0) /* Ignore any ERRNOs we got. */
		ret = 0;
#ifdef _WIN32
    kfree(env.buffer);
#else
	free_pages((unsigned long)env.buffer, get_order(env.size));
#endif
	return ret;

    out_err:
	drbd_err(resource, "Could not call %s user-space helper: error %d"
		 "out of memory\n", cmd, ret);
	return 0;
}

#undef magic_printk

static bool initial_states_pending(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;
	bool pending = false;

	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		if (test_bit(INITIAL_STATE_SENT, &peer_device->flags) &&
		    !test_bit(INITIAL_STATE_RECEIVED, &peer_device->flags)) {
			pending = true;
			break;
		}
	}
	rcu_read_unlock();
	return pending;
}

static bool intentional_diskless(struct drbd_resource *resource)
{
	bool intentional_diskless = true;
	struct drbd_device *device;
	int vnr;

	rcu_read_lock();

#ifdef _WIN32
	idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
#else
	idr_for_each_entry(&resource->devices, device, vnr) {
#endif
		if (!device->device_conf.intentional_diskless) {
			intentional_diskless = false;
			break;
		}
	}
	rcu_read_unlock();

	return intentional_diskless;
}

bool conn_try_outdate_peer(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
#ifdef _WIN32
    ULONG_PTR last_reconnect_jif;
#else
	unsigned long last_reconnect_jif;
#endif
	enum drbd_fencing_policy fencing_policy;
	enum drbd_disk_state disk_state;
	char *ex_to_string;
	int r;
	unsigned long irq_flags;

	spin_lock_irq(&resource->req_lock);
	if (connection->cstate[NOW] >= C_CONNECTED) {
		drbd_err(connection, "Expected cstate < C_CONNECTED\n");
		spin_unlock_irq(&resource->req_lock);
		return false;
	}

	last_reconnect_jif = connection->last_reconnect_jif;

	disk_state = conn_highest_disk(connection);
	if (disk_state < D_CONSISTENT &&
		!(disk_state == D_DISKLESS && intentional_diskless(resource))) {
		begin_state_change_locked(resource, CS_VERBOSE | CS_HARD);
		__change_io_susp_fencing(connection, false);
		/* We are no longer suspended due to the fencing policy.
		 * We may still be suspended due to the on-no-data-accessible policy.
		 * If that was OND_IO_ERROR, fail pending requests. */
		if (!resource_is_suspended(resource, NOW))
			_tl_restart(connection, CONNECTION_LOST_WHILE_PENDING);
#ifdef _WIN32_RCU_LOCKED
		end_state_change_locked(resource, false, __FUNCTION__);
#else
		end_state_change_locked(resource);
#endif
		spin_unlock_irq(&resource->req_lock);
		return false;
	}
	spin_unlock_irq(&resource->req_lock);

	fencing_policy = connection->fencing_policy;
	if (fencing_policy == FP_DONT_CARE)
		return true;

	r = drbd_khelper(NULL, connection, "fence-peer");

#ifdef _WIN32
	r = r << 8;
#endif
	begin_state_change(resource, &irq_flags, CS_VERBOSE);
	switch ((r>>8) & 0xff) {
	case P_INCONSISTENT: /* peer is inconsistent */
		ex_to_string = "peer is inconsistent or worse";
		__change_peer_disk_states(connection, D_INCONSISTENT);
		break;
	case P_OUTDATED: /* peer got outdated, or was already outdated */
		ex_to_string = "peer was fenced";
		__change_peer_disk_states(connection, D_OUTDATED);
		break;
	case P_DOWN: /* peer was down */
		if (conn_highest_disk(connection) == D_UP_TO_DATE) {
			/* we will(have) create(d) a new UUID anyways... */
			ex_to_string = "peer is unreachable, assumed to be dead";
			__change_peer_disk_states(connection, D_OUTDATED);
		} else {
			ex_to_string = "peer unreachable, doing nothing since disk != UpToDate";
		}
		break;
	case P_PRIMARY: /* Peer is primary, voluntarily outdate myself.
		 * This is useful when an unconnected R_SECONDARY is asked to
		 * become R_PRIMARY, but finds the other peer being active. */
		ex_to_string = "peer is active";
		drbd_warn(connection, "Peer is primary, outdating myself.\n");
		__change_disk_states(resource, D_OUTDATED);
		break;
	case P_FENCING:
		/* THINK: do we need to handle this
		 * like case 4 P_OUTDATED, or more like case 5 P_DOWN? */
		if (fencing_policy != FP_STONITH)
			drbd_err(connection, "fence-peer() = 7 && fencing != Stonith !!!\n");
		ex_to_string = "peer was stonithed";
		__change_peer_disk_states(connection, D_OUTDATED);
		break;
	default:
		/* The script is broken ... */
		drbd_err(connection, "fence-peer helper broken, returned %d\n", (r>>8)&0xff);
		abort_state_change(resource, &irq_flags, __FUNCTION__);
		return false; /* Eventually leave IO frozen */
	}

	drbd_info(connection, "fence-peer helper returned %d (%s)\n",
		  (r>>8) & 0xff, ex_to_string);

	if (connection->cstate[NOW] >= C_CONNECTED ||
	    initial_states_pending(connection)) {
		/* connection re-established; do not fence */
		goto abort;
	}
	if (connection->last_reconnect_jif != last_reconnect_jif) {
		/* In case the connection was established and dropped
		   while the fence-peer handler was running, ignore it */
		drbd_info(connection, "Ignoring fence-peer exit code\n");
		goto abort;
	}

	end_state_change(resource, &irq_flags, __FUNCTION__);

	goto out;
 abort:
	abort_state_change(resource, &irq_flags, __FUNCTION__);
 out:
	return conn_highest_pdsk(connection) <= D_OUTDATED;
}

#ifdef _WIN32
void _try_outdate_peer_async(void *data)
#else
static int _try_outdate_peer_async(void *data)
#endif
{
	struct drbd_connection *connection = (struct drbd_connection *)data;

	conn_try_outdate_peer(connection);

	kref_debug_put(&connection->kref_debug, 4);
	kref_put(&connection->kref, drbd_destroy_connection);
#ifdef _WIN32
	PsTerminateSystemThread(STATUS_SUCCESS); 
#else
	return 0;
#endif
}

void conn_try_outdate_peer_async(struct drbd_connection *connection)
{
	kref_get(&connection->kref);
	kref_debug_get(&connection->kref_debug, 4);
#ifdef _WIN32
	HANDLE		hThread = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	Status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, _try_outdate_peer_async, (void *)connection);
	if (!NT_SUCCESS(Status))
	{
		WDRBD_ERROR("PsCreateSystemThread(_try_outdate_peer_async) failed with status 0x%08X\n", Status);

        kref_put(&connection->kref, drbd_destroy_connection);
	}
	else
		ZwClose (hThread);
#else
	/* We may just have force_sig()'ed this thread
	 * to get it out of some blocking network function.
	 * Clear signals; otherwise kthread_run(), which internally uses
	 * wait_on_completion_killable(), will mistake our pending signal
	 * for a new fatal signal and fail. */
	flush_signals(current);
	opa = kthread_run(_try_outdate_peer_async, connection, "drbd_async_h");
	if (IS_ERR(opa)) {
		drbd_err(connection, "out of mem, failed to invoke fence-peer helper\n");
		kref_debug_put(&connection->kref_debug, 4);
		kref_put(&connection->kref, drbd_destroy_connection);
	}
#endif
}

static bool barrier_pending(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	bool rv = false;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (test_bit(BARRIER_ACK_PENDING, &connection->flags)) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

#ifdef _WIN32 // DW-1103 down from kernel with timeout
static bool wait_for_peer_disk_updates_timeout(struct drbd_resource *resource)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	int vnr;
	unsigned char oldIrql_rLock;
	long time_out = 100;
	int retry_count = 0;
restart:
	if(retry_count == 2) { // retry 2 times and if it expired, return FALSE
		return FALSE;
	}
	oldIrql_rLock = ExAcquireSpinLockShared(&g_rcuLock);
	
	idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
		for_each_peer_device_rcu(peer_device, device) {
			if (test_bit(GOT_NEG_ACK, &peer_device->flags)) {
				clear_bit(GOT_NEG_ACK, &peer_device->flags);
				ExReleaseSpinLockShared(&g_rcuLock, oldIrql_rLock);
				wait_event_timeout(time_out, resource->state_wait, peer_device->disk_state[NOW] < D_UP_TO_DATE, time_out);
				retry_count++;
				goto restart;
			}
		}
	}

	ExReleaseSpinLockShared(&g_rcuLock, oldIrql_rLock);
	return TRUE;
}
#endif

static void wait_for_peer_disk_updates(struct drbd_resource *resource)
{
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;
	int vnr;
#ifdef _WIN32
	unsigned char oldIrql_rLock;
#endif

restart:
#ifdef _WIN32
	oldIrql_rLock = ExAcquireSpinLockShared(&g_rcuLock);
#else
	rcu_read_lock();
#endif
	
	
#ifdef _WIN32
	idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
#else	
	idr_for_each_entry(&resource->devices, device, vnr) {
#endif	
		for_each_peer_device_rcu(peer_device, device) {
			if (test_bit(GOT_NEG_ACK, &peer_device->flags)) {
				clear_bit(GOT_NEG_ACK, &peer_device->flags);
#ifdef _WIN32
				ExReleaseSpinLockShared(&g_rcuLock, oldIrql_rLock);
#else
				rcu_read_unlock();
#endif
				wait_event(resource->state_wait, peer_device->disk_state[NOW] < D_UP_TO_DATE);
				goto restart;
			}
		}
	}
#ifdef _WIN32
	ExReleaseSpinLockShared(&g_rcuLock, oldIrql_rLock);
#else
	rcu_read_unlock();
#endif
}

enum drbd_state_rv
drbd_set_role(struct drbd_resource *resource, enum drbd_role role, bool force, struct sk_buff *reply_skb)
{
	struct drbd_device *device;
	int vnr;
	const int max_tries = 4;
	enum drbd_state_rv rv = SS_UNKNOWN_ERROR;
	int try_val = 0;
	int forced = 0;
	bool with_force = false;
#ifdef _WIN32
	char *err_str = NULL;
	long timeout = 10 * HZ;
#else
	const char *err_str = NULL;
#endif
	enum chg_state_flags flags = CS_ALREADY_SERIALIZED | CS_DONT_RETRY | CS_WAIT_COMPLETE;


retry:
	down(&resource->state_sem);

	if (role == R_PRIMARY) {
		struct drbd_connection *connection;

		/* Detect dead peers as soon as possible.  */

		rcu_read_lock();
		for_each_connection_rcu(connection, resource)
			request_ping(connection);
		rcu_read_unlock();
	} else /* (role == R_SECONDARY) */ {
		if (start_new_tl_epoch(resource)) {
			struct drbd_connection *connection;
			u64 im;
#ifdef _WIN32
			for_each_connection_ref(connection, im, resource)
				drbd_flush_workqueue(resource, &connection->sender_work);
		}
		// DW-1626 : A long wait occurs when the barrier is delayed. Wait 10 seconds.
		wait_event_timeout(timeout, resource->barrier_wait, !barrier_pending(resource), timeout);

		if (!timeout){
			WDRBD_WARN("Failed to set secondary role due to barrier ack pending timeout(10s).\n");
			rv = SS_BARRIER_ACK_PENDING_TIMEOUT;
			goto out;
		}

		/* After waiting for pending barriers, we got any possible NEG_ACKs,
			and see them in wait_for_peer_disk_updates() */
		// DW-1460 fixup infinate wait when network connection is disconnected.
		wait_for_peer_disk_updates_timeout(resource);
#else
			for_each_connection_ref(connection, im, resource)
				drbd_flush_workqueue(&connection->sender_work);
		}
		wait_event(resource->barrier_wait, !barrier_pending(resource));

		/* After waiting for pending barriers, we got any possible NEG_ACKs,
			and see them in wait_for_peer_disk_updates() */
		wait_for_peer_disk_updates(resource);
#endif 
		/* In case switching from R_PRIMARY to R_SECONDARY works
		   out, there is no rw opener at this point. Thus, no new
		   writes can come in. -> Flushing queued peer acks is
		   necessary and sufficient.
		   The cluster wide role change required packets to be
		   received by the aserder. -> We can be sure that the
		   peer_acks queued on asender's TODO list go out before
		   we send the two phase commit packet.
		*/
		drbd_flush_peer_acks(resource);
	}

	while (try_val++ < max_tries) {
		if (try_val == max_tries - 1)
			flags |= CS_VERBOSE;

		if (err_str) {
			kfree(err_str);
			err_str = NULL;
		}
#ifdef _WIN32 // DW-1605
		stable_state_change(rv, resource,
			change_role(resource, role, flags, with_force, &err_str));
#else
		rv = stable_state_change(resource,
			change_role(resource, role, flags, with_force, &err_str));
#endif

		if (rv == SS_CONCURRENT_ST_CHG)
			continue;

		if (rv == SS_TIMEOUT) {
			long timeout = twopc_retry_timeout(resource, try_val);
			/* It might be that the receiver tries to start resync, and
			   sleeps on state_sem. Give it up, and retry in a short
			   while */
			up(&resource->state_sem);
			schedule_timeout_interruptible(timeout);
			goto retry;
		}
		/* in case we first succeeded to outdate,
		 * but now suddenly could establish a connection */
		if (rv == SS_CW_FAILED_BY_PEER) {
			with_force = false;
			continue;
		}

		if (rv == SS_NO_UP_TO_DATE_DISK && force && !with_force) {
#ifdef _WIN32 // DW-
            u64 im;
            idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr)
            {
                struct drbd_peer_device *peer_device;
                for_each_peer_device_ref(peer_device, im, device) {
					unsigned long long p_size = peer_device->max_size << 9; // volume size in bytes
                    unsigned long long l_size = get_targetdev_volsize(device->this_bdev->bd_disk->pDeviceExtension); // volume size in bytes
					// DW-1323: abort initial full sync when target disk is smaller than source
					// If p_size is nonzero, it was connected with the peer.
                    if ((drbd_current_uuid(device) == UUID_JUST_CREATED) && 
						(p_size != 0) && 
						(l_size > p_size))
                    {
                        rv = SS_TARGET_DISK_TOO_SMALL;
                    }
                }
            }
			
			if (rv == SS_TARGET_DISK_TOO_SMALL)
			{
                        goto out;
			}
#endif
			with_force = true;
			forced = 1;
			continue;
		}

		if (rv == SS_NO_UP_TO_DATE_DISK && !with_force) {
			struct drbd_connection *connection;
			u64 im;

			up(&resource->state_sem); /* Allow connect while fencing */
			for_each_connection_ref(connection, im, resource) {
				struct drbd_peer_device *peer_device;
				int vnr;

				if (conn_highest_pdsk(connection) != D_UNKNOWN)
					continue;

#ifdef _WIN32
                idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
				idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
					struct drbd_device *device = peer_device->device;

					if (device->disk_state[NOW] != D_CONSISTENT)
						continue;

					if (conn_try_outdate_peer(connection))
						with_force = true;
				}
			}
			down(&resource->state_sem);
			if (with_force)
				continue;
		}

		if (rv == SS_NOTHING_TO_DO)
			goto out;
		if (rv == SS_PRIMARY_NOP && !with_force) {
			struct drbd_connection *connection;
			u64 im;

			up(&resource->state_sem); /* Allow connect while fencing */
			for_each_connection_ref(connection, im, resource) {
				if (!conn_try_outdate_peer(connection) && force) {
					drbd_warn(connection, "Forced into split brain situation!\n");
					with_force = true;
				}
			}
			down(&resource->state_sem);
			if (with_force)
				continue;
		}

		if (rv == SS_TWO_PRIMARIES) {
			struct drbd_connection *connection;
			struct net_conf *nc;
			unsigned int timeout = 0;

			/*
			 * Catch the case where we discover that the other
			 * primary has died soon after the state change
			 * failure: retry once after a short timeout.
			 */

			rcu_read_lock();
			for_each_connection_rcu(connection, resource) {
				nc = rcu_dereference(connection->transport.net_conf);
				if (nc && nc->ping_timeo > timeout)
					timeout = nc->ping_timeo;
			}
			rcu_read_unlock();
			timeout = timeout * HZ / 10;
			if (timeout == 0)
				timeout = 1;

			schedule_timeout_interruptible(timeout);
			if (try_val < max_tries)
				try_val = max_tries - 1;
			continue;
		}

		if (rv < SS_SUCCESS && !(flags & CS_VERBOSE)) {
			flags |= CS_VERBOSE;
			continue;
		}
		break;
	}

	if (rv < SS_SUCCESS)
		goto out;

	if (forced)
		drbd_warn(resource, "Forced to consider local data as UpToDate!\n");

	if (role == R_SECONDARY) {
#ifdef _WIN32
        idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
#else
		idr_for_each_entry(&resource->devices, device, vnr) {
#endif
			if (get_ldev(device)) {
				device->ldev->md.current_uuid &= ~UUID_PRIMARY;
				put_ldev(device);
			}
		}
	} else {
		struct drbd_connection *connection;

		rcu_read_lock();
		for_each_connection_rcu(connection, resource)
			clear_bit(CONN_DISCARD_MY_DATA, &connection->flags);
		rcu_read_unlock();

#ifdef _WIN32
		// DW-1609 : It has been modified to function similar to 8.4.x for younger primary 
		idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
			struct drbd_peer_device *peer_device;
			u64 im;
			bool younger_primary = false; // Add a younger_primary variable to create a new UUID if the condition is met.

			// If secondary node was promoted from Uptodate state under the following conditions, 
			// it is hard to distinguish younger primary.
			for_each_peer_device_ref(peer_device, im, device) {
				if ((peer_device->connection->cstate[NOW] < C_CONNECTED || 
					peer_device->disk_state[NOW] <= D_FAILED) 
					&& (device->ldev->md.peers[peer_device->node_id].bitmap_uuid == 0)) {
					if (younger_primary == false){
						younger_primary = true; 
						//DW-1850
						//If for_each_peer_device_ref exits to break, 
						//the reference count should be decremented.
						kref_put(&peer_device->connection->kref, drbd_destroy_connection);
						break; 
					}
				}
			} 

			if (forced || younger_primary == true)
				drbd_uuid_new_current(device, true);
			else
				set_bit(NEW_CUR_UUID, &device->flags);
			
			// MODIFIED_BY_MANTECH DW-1154 : set UUID_PRIMARY when promote a resource to primary role.
			if (get_ldev(device)) {
				device->ldev->md.current_uuid |= UUID_PRIMARY;
				put_ldev(device);
			}
		}
#else
		idr_for_each_entry(&resource->devices, device, vnr) {
			if (forced)
				drbd_uuid_new_current(device, true);
			else
				set_bit(NEW_CUR_UUID, &device->flags);
		}
#endif 
	}

#ifdef _WIN32
    idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
#else
	idr_for_each_entry(&resource->devices, device, vnr) {
#endif
		 struct drbd_peer_device *peer_device;
		 u64 im;

		 for_each_peer_device_ref(peer_device, im, device) {
			/* writeout of activity log covered areas of the bitmap
			 * to stable storage done in after state change already */

			if (peer_device->connection->cstate[NOW] == C_CONNECTED) {
				/* if this was forced, we should consider sync */
				if (forced) {
					drbd_send_uuids(peer_device, 0, 0);
					set_bit(CONSIDER_RESYNC, &peer_device->flags);
				}
				drbd_send_current_state(peer_device);
			}
		}
	}

#ifdef _WIN32
    idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
#else
	idr_for_each_entry(&resource->devices, device, vnr) {
#endif
#ifdef _WIN32 
		// MODIFIED_BY_MANTECH DW-1154 : After changing role, writes the meta data.
		drbd_md_sync(device);
#else
		drbd_md_sync_if_dirty(device);
#endif
		set_disk_ro(device->vdisk, role == R_SECONDARY);
		if (!resource->res_opts.auto_promote && role == R_PRIMARY)
			drbd_kobject_uevent(device);
	}

out:
	up(&resource->state_sem);
	if (err_str) {
		if (reply_skb)
			drbd_msg_put_info(reply_skb, err_str);
		kfree(err_str);
	}
	return rv;
}

#ifdef _WIN32 // DW-1103 down from kernel with timeout
enum drbd_state_rv
drbd_set_secondary_from_shutdown(struct drbd_resource *resource)
{
	struct drbd_device *device;
	int vnr;
	const int max_tries = 1;
	enum drbd_state_rv rv = SS_UNKNOWN_ERROR;
	int try_val = 0;
	bool with_force = true;
	long time_out = 1000;


retry:
	down(&resource->state_sem);

	// step 1 : flush sender work queue with timeout
	if (start_new_tl_epoch(resource)) {
		struct drbd_connection *connection;
		u64 im;

		for_each_connection_ref(connection, im, resource)
			drbd_flush_workqueue_timeout(resource, &connection->sender_work);
	}
	// step 2 : wait barrier pending with timeout
	wait_event_timeout(time_out, resource->barrier_wait, !barrier_pending(resource), time_out);
	if(!time_out) {
		WDRBD_INFO("drbd_set_secondary_from_shutdown wait_event_timeout\n ");
		goto out;
	}
	/* After waiting for pending barriers, we got any possible NEG_ACKs,
	   and see them in wait_for_peer_disk_updates() */
	// step 3 : wait for updating peer disk with timeout   
	if(!wait_for_peer_disk_updates_timeout(resource)) {
		WDRBD_INFO("drbd_set_secondary_from_shutdown wait_for_peer_disk_updates_timeout\n ");
		goto out;
	}
	
	/* In case switching from R_PRIMARY to R_SECONDARY works
	   out, there is no rw opener at this point. Thus, no new
	   writes can come in. -> Flushing queued peer acks is
	   necessary and sufficient.
	   The cluster wide role change required packets to be
	   received by the aserder. -> We can be sure that the
	   peer_acks queued on asender's TODO list go out before
	   we send the two phase commit packet.
	*/
	// step 4 : flush peer acks
	drbd_flush_peer_acks(resource);
	
	// step 5 : change role with timeout , just retry 1 time.
	while (try_val++ < max_tries) {
		// step 5-1 : change role with timeout
#ifdef _WIN32 // DW-1605
		stable_state_change(rv, resource,
			change_role_timeout(resource, R_SECONDARY,
				CS_ALREADY_SERIALIZED | CS_DONT_RETRY | CS_WAIT_COMPLETE,
				with_force));
#else
		rv = stable_state_change(resource,
			change_role_timeout(resource, R_SECONDARY,
				CS_ALREADY_SERIALIZED | CS_DONT_RETRY | CS_WAIT_COMPLETE,
				with_force));
#endif

		if (rv == SS_CONCURRENT_ST_CHG)
			continue;

		if (rv == SS_TIMEOUT) {
			long timeout = twopc_retry_timeout(resource, try_val);
			/* It might be that the receiver tries to start resync, and
			   sleeps on state_sem. Give it up, and retry in a short
			   while */
			up(&resource->state_sem);
			schedule_timeout_interruptible(timeout);
			// step 5-2 : retry
			goto retry;
		}
		/* in case we first succeeded to outdate,
		 * but now suddenly could establish a connection */
		if (rv == SS_CW_FAILED_BY_PEER) {
			with_force = false;
			continue;
		}

		if (rv == SS_NOTHING_TO_DO)
			goto out;
		
		if (rv < SS_SUCCESS) {
#ifdef _WIN32 // DW-1605
			stable_state_change(rv, resource,
				change_role_timeout(resource, R_SECONDARY,
					CS_VERBOSE | CS_ALREADY_SERIALIZED |
					CS_DONT_RETRY | CS_WAIT_COMPLETE,
					with_force));
#else
			rv = stable_state_change(resource,
				change_role_timeout(resource, R_SECONDARY,
					CS_VERBOSE | CS_ALREADY_SERIALIZED |
					CS_DONT_RETRY | CS_WAIT_COMPLETE,
					with_force));
#endif

			if (rv < SS_SUCCESS)
				goto out;
		}
		break;
	}

	if (rv < SS_SUCCESS) {
		WDRBD_ERROR("drbd_set_secondary_from_shutdown change_role_timeout fail\n ");
		goto out;
	}

    idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
		if (get_ldev(device)) {
			device->ldev->md.current_uuid &= ~UUID_PRIMARY;
			put_ldev(device);
		}
	}


	// step 6 : if it connected, send a current state to each peer. 
    idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
		 struct drbd_peer_device *peer_device;
		 u64 im;

		 for_each_peer_device_ref(peer_device, im, device) {
			/* writeout of activity log covered areas of the bitmap
			 * to stable storage done in after state change already */

			if (peer_device->connection->cstate[NOW] == C_CONNECTED) {
				drbd_send_current_state(peer_device);
			}
		}
	}

	// step 7 : sync meta-data
    idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
		drbd_md_sync_if_dirty(device);
		set_disk_ro(device->vdisk, true);
	}

out:
	up(&resource->state_sem);
	return rv;
}
#endif

static const char *from_attrs_err_to_txt(int err)
{
	return	err == -ENOMSG ? "required attribute missing" :
		err == -EOPNOTSUPP ? "unknown mandatory attribute" :
		err == -EEXIST ? "can not change invariant setting" :
		"invalid attribute value";
}

int drbd_adm_set_role(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct set_role_parms parms;
	int err;
	enum drbd_state_rv retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	memset(&parms, 0, sizeof(parms));
	if (info->attrs[DRBD_NLA_SET_ROLE_PARMS]) {
		err = set_role_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out;
		}
	}
	mutex_lock(&adm_ctx.resource->adm_mutex);
#ifdef _WIN32
	// DW-1317: acquire volume control mutex, not to conflict to (dis)mount volume.
	mutex_lock(&adm_ctx.resource->vol_ctl_mutex);
#endif

	if (info->genlhdr->cmd == DRBD_ADM_PRIMARY) {
#ifdef _WIN32 // DW-839 not support diskless Primary
		int vnr;
		struct drbd_device * device;
		idr_for_each_entry(struct drbd_device *, &adm_ctx.resource->devices, device, vnr)
		{
			if (D_DISKLESS == device->disk_state[NOW])
			{
				retcode = SS_IS_DISKLESS;
				goto fail;
			}
		}
#endif
		retcode = drbd_set_role(adm_ctx.resource, R_PRIMARY, parms.assume_uptodate,
			adm_ctx.reply_skb);
		if (retcode >= SS_SUCCESS) {
			set_bit(EXPLICIT_PRIMARY, &adm_ctx.resource->flags);
			adm_ctx.resource->bPreSecondaryLock = FALSE;
		}
#ifdef _WIN32
        else if (retcode == SS_TARGET_DISK_TOO_SMALL)
            goto fail;

		idr_for_each_entry(struct drbd_device *, &adm_ctx.resource->devices, device, vnr)
		{
			PVOLUME_EXTENSION pvext = get_targetdev_by_minor(device->minor, FALSE);
			if (pvext)
			{
				SetDrbdlockIoBlock(pvext, FALSE);
			}
		}
#endif
#if 0 // _WIN32 // DW-778
        int vnr;
        struct drbd_device * device;
        idr_for_each_entry(struct drbd_device *, &adm_ctx.resource->devices, device, vnr)
        {
            if (D_DISKLESS != device->disk_state[NOW])
                FsctlCreateVolume(device->minor);
        }
#endif
	} else {
#ifdef _WIN32_MVFL
#ifdef _WIN32_MULTI_VOLUME        
		int vnr;
		retcode = SS_SUCCESS;
		struct drbd_device * device;

		// DW-1327: 
		idr_for_each_entry(struct drbd_device *, &adm_ctx.resource->devices, device, vnr)
		{
			PVOLUME_EXTENSION pvext = get_targetdev_by_minor(device->minor, FALSE);
			if (pvext)
			{
				SetDrbdlockIoBlock(pvext, TRUE);
			}
		}

		idr_for_each_entry(struct drbd_device *, &adm_ctx.resource->devices, device, vnr)
		{
			if (device->disk_state[NOW] == D_DISKLESS)
			{
				continue;
			}
			if (!NT_SUCCESS(FsctlLockVolume(device->minor)))
			{
				continue;
			}
		}

		idr_for_each_entry(struct drbd_device *, &adm_ctx.resource->devices, device, vnr)
		{
			if (device->disk_state[NOW] == D_DISKLESS)
			{
				continue;
			}			
			adm_ctx.resource->bPreDismountLock = TRUE;
			NTSTATUS status = FsctlFlushDismountVolume(device->minor, true);			
			if (!NT_SUCCESS(status))
			{
				retcode = SS_UNKNOWN_ERROR;
				adm_ctx.resource->bPreDismountLock = FALSE;
				break;
			}			
		}
		
		if (retcode == SS_SUCCESS) {
			adm_ctx.resource->bPreSecondaryLock = TRUE;
			retcode = drbd_set_role(adm_ctx.resource, R_SECONDARY, false, adm_ctx.reply_skb);
			adm_ctx.resource->bPreSecondaryLock = FALSE;
			adm_ctx.resource->bPreDismountLock = FALSE;
		}

		idr_for_each_entry(struct drbd_device *, &adm_ctx.resource->devices, device, vnr)
		{
			if (device->disk_state[NOW] == D_DISKLESS)
			{
				continue;
			}
			FsctlUnlockVolume(device->minor);
		}

		
#else
        int vnr;
        struct drbd_device * device;
        idr_for_each_entry(struct drbd_device *, &adm_ctx.resource->devices, device, vnr)
        {
            if (D_DISKLESS == device->disk_state[NOW])
            {
                retcode = drbd_set_role(adm_ctx.resource, R_SECONDARY, false);
            }
            else if (NT_SUCCESS(FsctlLockVolume(device->minor)))
            {
                if (retcode < SS_SUCCESS) {
                    FsctlUnlockVolume(device->minor);
                    goto fail;
                }
				adm_ctx.resource->bPreDismountLock = TRUE;
                NTSTATUS status = FsctlFlushDismountVolume(device->minor, true);
				adm_ctx.resource->bPreSecondaryLock = TRUE;
                FsctlUnlockVolume(device->minor);

                if (!NT_SUCCESS(status)) {
                    retcode = SS_UNKNOWN_ERROR;
					adm_ctx.resource->bPreDismountLock = FALSE;
                    goto fail;
                }
				retcode = drbd_set_role(adm_ctx.resource, R_SECONDARY, false);
				adm_ctx.resource->bPreSecondaryLock = FALSE;
				adm_ctx.resource->bPreDismountLock = FALSE;
            }
			else
            {
                retcode = SS_DEVICE_IN_USE;
            }
			
        }
#endif
#else
		retcode = drbd_set_role(adm_ctx.resource, R_SECONDARY, false);
#endif
		if (retcode >= SS_SUCCESS)
			clear_bit(EXPLICIT_PRIMARY, &adm_ctx.resource->flags);
	}

#ifdef _WIN32
fail:
	// DW-1317
	mutex_unlock(&adm_ctx.resource->vol_ctl_mutex);
#endif
	mutex_unlock(&adm_ctx.resource->adm_mutex);
out:
	drbd_adm_finish(&adm_ctx, info, (enum drbd_ret_code)retcode);
	return 0;
}

u64 drbd_capacity_to_on_disk_bm_sect(u64 capacity_sect, unsigned int max_peers)
{
	u64 bits, bytes;

	/* round up storage sectors to full "bitmap sectors per bit", then
	 * convert to number of bits needed, and round that up to 64bit words
	 * to ease interoperability between 32bit and 64bit architectures.
	 */
	bits = ALIGN(BM_SECT_TO_BIT(ALIGN(capacity_sect, BM_SECT_PER_BIT)), 64);

	/* convert to bytes, multiply by number of peers,
	 * and, because we do all our meta data IO in 4k blocks,
	 * round up to full 4k
	 */
	bytes = ALIGN(bits / 8 * max_peers, 4096);

	/* convert to number of sectors */
	return bytes >> 9;
}

/* Initializes the md.*_offset members, so we are able to find
 * the on disk meta data.
 *
 * We currently have two possible layouts:
 * external:
 *   |----------- md_size_sect ------------------|
 *   [ 4k superblock ][ activity log ][  Bitmap  ]
 *   | al_offset == 8 |
 *   | bm_offset = al_offset + X      |
 *  ==> bitmap sectors = md_size_sect - bm_offset
 *
 * internal:
 *            |----------- md_size_sect ------------------|
 * [data.....][  Bitmap  ][ activity log ][ 4k superblock ]
 *                        | al_offset < 0 |
 *            | bm_offset = al_offset - Y |
 *  ==> bitmap sectors = Y = al_offset - bm_offset
 *
 *  Activity log size used to be fixed 32kB,
 *  but is about to become configurable.
 */
void drbd_md_set_sector_offsets(struct drbd_device *device,
				struct drbd_backing_dev *bdev)
{
	sector_t md_size_sect = 0;
	unsigned int al_size_sect = bdev->md.al_size_4k * 8;
	int max_peers;

	if (device->bitmap)
		max_peers = device->bitmap->bm_max_peers;
	else
		max_peers = 1;

	bdev->md.md_offset = drbd_md_ss(bdev);

	switch (bdev->md.meta_dev_idx) {
	default:
		/* v07 style fixed size indexed meta data */
		/* FIXME we should drop support for this! */
#ifdef _WIN32 // DW-1335
		bdev->md.md_size_sect = (256 << 20 >> 9);
#else
		bdev->md.md_size_sect = (128 << 20 >> 9);
#endif
		bdev->md.al_offset = (4096 >> 9);
		bdev->md.bm_offset = (4096 >> 9) + al_size_sect;
		break;
	case DRBD_MD_INDEX_FLEX_EXT:
		/* just occupy the full device; unit: sectors */
#ifdef _WIN32 // DW-1607
		bdev->md.md_size_sect = (u32)drbd_get_md_capacity(bdev->md_bdev);
#else
		bdev->md.md_size_sect = drbd_get_capacity(bdev->md_bdev);
#endif
		bdev->md.al_offset = (4096 >> 9);
		bdev->md.bm_offset = (4096 >> 9) + al_size_sect;
		break;
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		bdev->md.al_offset = (~al_size_sect + 1);

		/* enough bitmap to cover the storage,
		 * plus the "drbd meta data super block",
		 * and the activity log; */
		md_size_sect = drbd_capacity_to_on_disk_bm_sect(
				drbd_get_capacity(bdev->backing_bdev),
				max_peers)
			+ (4096 >> 9) + al_size_sect;

		bdev->md.md_size_sect = (u32)md_size_sect;
		/* bitmap offset is adjusted by 'super' block size */
		bdev->md.bm_offset   = (s32)(~md_size_sect + 1) + (4096 >> 9);
		break;
	}
}

/* input size is expected to be in KB */
char *ppsize(char *buf, size_t len, unsigned long long size)
{
	/* Needs 9 bytes at max including trailing NUL:
	 * -1ULL ==> "16384 EB" */
	static char units[] = { 'K', 'M', 'G', 'T', 'P', 'E' };
	int base = 0;
	while (size >= 10000 && base < sizeof(units)-1) {
		/* shift + round */
		size = (size >> 10) + !!(size & (1<<9));
		base++;
	}

	_snprintf(buf, len-1, "%u %cB", (unsigned)size, units[base]);

	return buf;
}

/* The receiver may call drbd_suspend_io(device, WRITE_ONLY).
 * It should not call drbd_suspend_io(device, READ_AND_WRITE) since
 * if the node is an D_INCONSISTENT R_PRIMARY (L_SYNC_TARGET) it
 * may need to issue remote READs. Those is turn need the receiver
 * to complete. -> calling drbd_suspend_io(device, READ_AND_WRITE) deadlocks.
 */
/* Note these are not to be confused with
 * drbd_adm_suspend_io/drbd_adm_resume_io,
 * which are (sub) state changes triggered by admin (drbdsetup),
 * and can be long lived.
 * This changes an device->flag, is triggered by drbd internals,
 * and should be short-lived. */
/* It needs to be a counter, since multiple threads might
   independently suspend and resume IO. */
void drbd_suspend_io(struct drbd_device *device, enum suspend_scope ss)
{
	atomic_inc(&device->suspend_cnt);
	if (drbd_suspended(device))
		return;
	wait_event(device->misc_wait,
		   (atomic_read(&device->ap_bio_cnt[WRITE]) +
		    ss == READ_AND_WRITE ? atomic_read(&device->ap_bio_cnt[READ]) : 0) == 0);
}

void drbd_resume_io(struct drbd_device *device)
{
	if (atomic_dec_and_test(&device->suspend_cnt))
		wake_up(&device->misc_wait);
}

/**
 * effective_disk_size_determined()  -  is the effective disk size "fixed" already?
 *
 * When a device is configured in a cluster, the size of the replicated disk is
 * determined by the minimum size of the disks on all nodes.  Additional nodes
 * can be added, and this can still change the effective size of the replicated
 * disk.
 *
 * When the disk on any node becomes D_UP_TO_DATE, the effective disk size
 * becomes "fixed".  It is written to the metadata so that it will not be
 * forgotten across node restarts.  Further nodes can only be added if their
 * disks are big enough.
 */
static bool effective_disk_size_determined(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	bool rv = false;

	if (device->ldev->md.effective_size != 0)
		return true;
	if (device->disk_state[NEW] == D_UP_TO_DATE)
		return true;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->disk_state[NEW] == D_UP_TO_DATE) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

/**
 * drbd_determine_dev_size() -  Sets the right device size obeying all constraints
 * @device:	DRBD device.
 *
 * You should call drbd_md_sync() after calling this function.
 */
enum determine_dev_size
drbd_determine_dev_size(struct drbd_device *device, sector_t peer_current_size,
		enum dds_flags flags, struct resize_parms *rs) __must_hold(local)
{
	struct md_offsets_and_sizes {
		u64 effective_size;
		u64 md_offset;
		s32 al_offset;
		s32 bm_offset;
		u32 md_size_sect;

		u32 al_stripes;
		u32 al_stripe_size_4k;
	} prev;
	sector_t u_size, size;
	struct drbd_md *md = &device->ldev->md;
	char ppb[10];
	void *buffer;

	int md_moved, la_size_changed;
	enum determine_dev_size rv = DS_UNCHANGED;

	/* We may change the on-disk offsets of our meta data below.  Lock out
	 * anything that may cause meta data IO, to avoid acting on incomplete
	 * layout changes or scribbling over meta data that is in the process
	 * of being moved.
	 *
	 * Move is not exactly correct, btw, currently we have all our meta
	 * data in core memory, to "move" it we just write it all out, there
	 * are no reads. */
	drbd_suspend_io(device, READ_AND_WRITE);
	buffer = drbd_md_get_buffer(device, __func__); /* Lock meta-data IO */
	if (!buffer) {
		drbd_resume_io(device);
		return DS_ERROR;
	}

	/* remember current offset and sizes */
	prev.effective_size = md->effective_size;
	prev.md_offset = md->md_offset;
	prev.al_offset = md->al_offset;
	prev.bm_offset = md->bm_offset;
	prev.md_size_sect = md->md_size_sect;
	prev.al_stripes = md->al_stripes;
	prev.al_stripe_size_4k = md->al_stripe_size_4k;

	if (rs) {
		/* rs is non NULL if we should change the AL layout only */
		md->al_stripes = rs->al_stripes;
		md->al_stripe_size_4k = rs->al_stripe_size / 4;
		md->al_size_4k = (u64)rs->al_stripes * rs->al_stripe_size / 4;
	}

	drbd_md_set_sector_offsets(device, device->ldev);

	rcu_read_lock();
	u_size = rcu_dereference(device->ldev->disk_conf)->disk_size;
	rcu_read_unlock();
	size = drbd_new_dev_size(device, peer_current_size, u_size, flags);

	if (size < prev.effective_size) {
		if (rs && u_size == 0) {
			/* Remove "rs &&" later. This check should always be active, but
			   right now the receiver expects the permissive behavior */
			drbd_warn(device, "Implicit shrink not allowed. "
				 "Use --size=%llus for explicit shrink.\n",
				 (unsigned long long)size);
			rv = DS_ERROR_SHRINK;
		}
		if (u_size > size)
			rv = DS_ERROR_SPACE_MD;
		if (rv != DS_UNCHANGED)
			goto err_out;
	}

	if (drbd_get_capacity(device->this_bdev) != size ||
	    drbd_bm_capacity(device) != size) {
		int err;
		err = drbd_bm_resize(device, size, !(flags & DDSF_NO_RESYNC));
		if (unlikely(err)) {
			/* currently there is only one error: ENOMEM! */
			size = drbd_bm_capacity(device);
			if (size == 0) {
				drbd_err(device, "OUT OF MEMORY! "
				    "Could not allocate bitmap!\n");
			} else {
				drbd_err(device, "BM resizing failed. "
				    "Leaving size unchanged\n");
			}
			rv = DS_ERROR;
		}
		/* racy, see comments above. */
		drbd_set_my_capacity(device, size);
		if (effective_disk_size_determined(device)) {
			md->effective_size = size;
			drbd_info(device, "size = %s (%llu KB)\n", ppsize(ppb, sizeof(ppb), size >> 1),
			     (unsigned long long)size >> 1);
		}
	}
	if (rv <= DS_ERROR)
		goto err_out;

	la_size_changed = (prev.effective_size != md->effective_size);

	md_moved = prev.md_offset    != md->md_offset
		|| prev.md_size_sect != md->md_size_sect;

	if (la_size_changed || md_moved || rs) {
		int i;
		bool prev_al_disabled = 0;
		u32 prev_peer_full_sync = 0;

		/* We do some synchronous IO below, which may take some time.
		 * Clear the timer, to avoid scary "timer expired!" messages,
		 * "Superblock" is written out at least twice below, anyways. */
		del_timer(&device->md_sync_timer);

		/* We won't change the "al-extents" setting, we just may need
		 * to move the on-disk location of the activity log ringbuffer.
		 * Lock for transaction is good enough, it may well be "dirty"
		 * or even "starving". */
		wait_event(device->al_wait, drbd_al_try_lock_for_transaction(device));

		/* mark current on-disk bitmap and activity log as unreliable */
		prev_al_disabled = !!(md->flags & MDF_AL_DISABLED);
		md->flags |= MDF_AL_DISABLED;
		for (i = 0; i < DRBD_PEERS_MAX; i++) {
			if (md->peers[i].flags & MDF_PEER_FULL_SYNC)
				prev_peer_full_sync |= 1 << i;
			else
				md->peers[i].flags |= MDF_PEER_FULL_SYNC;
		}
		drbd_md_write(device, buffer);

		drbd_al_initialize(device, buffer);

		drbd_info(device, "Writing the whole bitmap, %s\n",
			 la_size_changed && md_moved ? "size changed and md moved" :
			 la_size_changed ? "size changed" : "md moved");
		/* next line implicitly does drbd_suspend_io()+drbd_resume_io() */
		drbd_bitmap_io(device, md_moved ? &drbd_bm_write_all : &drbd_bm_write,
			       "size changed", BM_LOCK_ALL, NULL);

		/* on-disk bitmap and activity log is authoritative again
		 * (unless there was an IO error meanwhile...) */
		if (!prev_al_disabled)
			md->flags &= ~MDF_AL_DISABLED;
		for (i = 0; i < DRBD_PEERS_MAX; i++) {
			if (0 == (prev_peer_full_sync & (1 << i)))
				md->peers[i].flags &= ~MDF_PEER_FULL_SYNC;
		}
		drbd_md_write(device, buffer);

		if (rs)
			drbd_info(device, "Changed AL layout to al-stripes = %d, al-stripe-size-kB = %d\n",
				 md->al_stripes, md->al_stripe_size_4k * 4);
	}

	if (size > prev.effective_size)
		rv = prev.effective_size ? DS_GREW : DS_GREW_FROM_ZERO;
	if (size < prev.effective_size)
		rv = DS_SHRUNK;


	if (false,false) {
	err_out:
		/* restore previous offset and sizes */
		md->effective_size = prev.effective_size;
		md->md_offset = prev.md_offset;
		md->al_offset = prev.al_offset;
		md->bm_offset = prev.bm_offset;
		md->md_size_sect = prev.md_size_sect;
		md->al_stripes = prev.al_stripes;
		md->al_stripe_size_4k = prev.al_stripe_size_4k;
		md->al_size_4k = (u64)prev.al_stripes * prev.al_stripe_size_4k;
	}
	lc_unlock(device->act_log);
	wake_up(&device->al_wait);
	drbd_md_put_buffer(device);
	drbd_resume_io(device);

	return rv;
}

/**
 * all_known_peer_devices_connected()
 *
 * Check if all peer devices that have bitmap slots assigned in the metadata
 * are connected.
 */
static bool get_max_agreeable_size(struct drbd_device *device, uint64_t *max) __must_hold(local)
{
	int node_id;
	bool all_known;

	all_known = true;
	rcu_read_lock();
	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		struct drbd_peer_md *peer_md = &device->ldev->md.peers[node_id];
		struct drbd_peer_device *peer_device;

		if (device->ldev->md.node_id == node_id) {
			drbd_info(device, "my node_id: %u\n", node_id);
			continue; /* skip myself... */
		}
		/* Have we met this peer node id before? */
		if (peer_md->bitmap_index == -1)
			continue;
		peer_device = peer_device_by_node_id(device, node_id);
		if (peer_device) {
			enum drbd_disk_state pdsk = peer_device->disk_state[NOW];
			drbd_info(peer_device, "node_id: %u idx: %u bm-uuid: 0x%llx flags: 0x%x max_size: %llu (%s)\n",
					node_id,
					peer_md->bitmap_index,
					peer_md->bitmap_uuid,
					peer_md->flags,
					peer_device->max_size,
					drbd_disk_str(pdsk));

			/* Note: in receive_sizes during connection handshake,
			 * repl_state may still be L_OFF;
			 * double check on cstate ... */
			if ((peer_device->repl_state[NOW] >= L_ESTABLISHED ||
				peer_device->connection->cstate[NOW] >= C_CONNECTED) &&
				//DW-1799
				test_bit(INITIAL_SIZE_RECEIVED, &peer_device->flags)) {
				/* If we still can see it, consider its last
				 * known size, even if it may have meanwhile
				 * detached from its disk.
				 * If we no longer see it, we may want to
				 * ignore the size we last knew, and
				 * "assume_peer_has_space".  */
#ifdef _WIN32
				if ((drbd_current_uuid(device) == UUID_JUST_CREATED) && peer_device->c_size)
				{
					// MODIFIED_BY_MANTECH DW-1337: peer has already been agreed and has smaller current size. this node needs to also accept already agreed size.
					// DW-1469 : only for initial sync
					*max = min_not_zero(*max, peer_device->c_size);
				}
				else 
				{
					*max = min_not_zero(*max, peer_device->max_size);
				}
#else
				*max = min_not_zero(*max, peer_device->max_size);
#endif				
				continue;
			}
		} else {
			drbd_info(device, "node_id: %u idx: %u bm-uuid: 0x%llx flags: 0x%x (not currently reachable)\n",
					node_id,
					peer_md->bitmap_index,
					peer_md->bitmap_uuid,
					peer_md->flags);
		}
		/* Even the currently diskless peer does not really know if it
		 * is diskless on purpose (a "DRBD client") or if it just was
		 * not possible to attach (backend device gone for some
		 * reason).  But we remember in our meta data if we have ever
		 * seen a peer disk for this peer.  If we did not ever see a
		 * peer disk, assume that's intentional. */
		if ((peer_md->flags & MDF_PEER_DEVICE_SEEN) == 0)
			continue;

		all_known = false;
		/* don't break yet, min aggregation may still find a peer */
	}
	rcu_read_unlock();
	return all_known;
}

#if 0
#define DDUMP_LLU(d, x) do { drbd_info(d, "%u: " #x ": %llu\n", __LINE__, (unsigned long long)x); } while (0)
#else
#define DDUMP_LLU(d, x) do { } while (false,false)
#endif

/* MUST hold a reference on ldev. */

sector_t
drbd_new_dev_size(struct drbd_device *device,
		sector_t current_size, /* need at least this much */
		sector_t user_capped_size, /* want (at most) this much */
		enum dds_flags flags) __must_hold(local)
{
	struct drbd_resource *resource = device->resource;
	uint64_t p_size = 0;
	uint64_t la_size = device->ldev->md.effective_size; /* last agreed size */
	uint64_t m_size; /* my size */
	uint64_t size = 0;
	bool all_known_connected;

	if (flags & DDSF_2PC)
		return resource->twopc_resize.new_size;

	m_size = drbd_get_max_capacity(device->ldev);
	all_known_connected = get_max_agreeable_size(device, &p_size);

	if (all_known_connected) {
		/* If we currently can see all peer devices,
		 * and p_size is still 0, apparently all our peers have been
		 * diskless, always.  If we have the only persistent backend,
		 * only our size counts. */
		DDUMP_LLU(device, p_size);
		DDUMP_LLU(device, m_size);
		p_size = min_not_zero(p_size, m_size);
	} else if (flags & DDSF_ASSUME_UNCONNECTED_PEER_HAS_SPACE) {
		DDUMP_LLU(device, p_size);
		DDUMP_LLU(device, m_size);
		DDUMP_LLU(device, la_size);
		p_size = min_not_zero(p_size, m_size);
		if (p_size > la_size)
			drbd_warn(device, "Resize forced while not fully connected!\n");
	} else {
		DDUMP_LLU(device, p_size);
		DDUMP_LLU(device, m_size);
		DDUMP_LLU(device, la_size);
		/* We currently cannot see all peer devices,
		 * fall back to what we last agreed upon. */
		p_size = min_not_zero(p_size, la_size);
	}

	DDUMP_LLU(device, p_size);
	DDUMP_LLU(device, m_size);
	size = min_not_zero(p_size, m_size);
	DDUMP_LLU(device, size);


	if (size == 0)
		drbd_err(device, "All nodes diskless!\n");

	if (flags & DDSF_IGNORE_PEER_CONSTRAINTS) {
		if (current_size > size
			&&  current_size <= m_size)
			size = current_size;
	}

	if (user_capped_size > size)
		drbd_err(device, "Requested disk size is too big (%llu > %llu)kiB\n",
		(unsigned long long)user_capped_size >> 1,
		(unsigned long long)size >> 1);
	else if (user_capped_size)
		size = user_capped_size;

	return size;
}

/**
 * drbd_check_al_size() - Ensures that the AL is of the right size
 * @device:	DRBD device.
 *
 * Returns -EBUSY if current al lru is still used, -ENOMEM when allocation
 * failed, and 0 on success. You should call drbd_md_sync() after you called
 * this function.
 */
static int drbd_check_al_size(struct drbd_device *device, struct disk_conf *dc)
{
	struct lru_cache *n, *t;
	struct lc_element *e;
	unsigned int in_use;
	unsigned int i;

	if (device->act_log &&
	    device->act_log->nr_elements == dc->al_extents)
		return 0;

	in_use = 0;
	t = device->act_log;
#ifdef _WIN32
    n = lc_create("act_log", &drbd_al_ext_cache, AL_UPDATES_PER_TRANSACTION,
        dc->al_extents, sizeof(struct lc_element), 0);
#else
	n = lc_create("act_log", drbd_al_ext_cache, AL_UPDATES_PER_TRANSACTION,
		dc->al_extents, sizeof(struct lc_element), 0);
#endif
	if (n == NULL) {
		drbd_err(device, "Cannot allocate act_log lru!\n");
		return -ENOMEM;
	}
	spin_lock_irq(&device->al_lock);
	if (t) {
		for (i = 0; i < t->nr_elements; i++) {
			e = lc_element_by_index(t, i);
			if (e->refcnt)
				drbd_err(device, "refcnt(%d)==%d\n",
				    e->lc_number, e->refcnt);
			in_use += e->refcnt;
		}
	}
	if (!in_use)
		device->act_log = n;
	spin_unlock_irq(&device->al_lock);
	if (in_use) {
		drbd_err(device, "Activity log still in use!\n");
		lc_destroy(n);
		return -EBUSY;
	} else {
		lc_destroy(t);
	}
	drbd_md_mark_dirty(device); /* we changed device->act_log->nr_elemens */
	return 0;
}

static u32 common_connection_features(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	u32 features = UINT32_MAX;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[NOW] < C_CONNECTED)
			continue;
		features &= connection->agreed_features;
	}
	rcu_read_unlock();

	return features;
}

static void blk_queue_discard_granularity(struct request_queue *q, unsigned int granularity)
{
	q->limits.discard_granularity = granularity;
}

static unsigned int drbd_max_discard_sectors(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	unsigned int s = DRBD_MAX_BBIO_SECTORS;

	/* when we introduced WRITE_SAME support, we also bumped
	 * our maximum supported batch bio size used for discards. */
	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (!(connection->agreed_features & DRBD_FF_WSAME)) {
			/* before, with DRBD <= 8.4.6, we only allowed up to one AL_EXTENT_SIZE. */
			s = AL_EXTENT_SIZE >> 9;
		}
	}
	rcu_read_unlock();

	return s;
}

#ifndef _WIN32
static void decide_on_discard_support(struct drbd_device *device,
			struct request_queue *q,
			struct request_queue *b,
			bool discard_zeroes_if_aligned)
{
	/* q = drbd device queue (device->rq_queue)
	 * b = backing device queue (device->ldev->backing_bdev->bd_disk->queue),
	 *     or NULL if diskless
	 */
	bool can_do = b ? blk_queue_discard(b) : true;

	if (can_do && b && !queue_discard_zeroes_data(b) && !discard_zeroes_if_aligned) {
		can_do = false;
		drbd_info(device, "discard_zeroes_data=0 and discard_zeroes_if_aligned=no: disabling discards\n");
	}
	if (can_do && !(common_connection_features(device->resource) & DRBD_FF_TRIM)) {
		can_do = false;
		drbd_info(device, "peer DRBD too old, does not support TRIM: disabling discards\n");
	}
	if (can_do) {
		/* We don't care for the granularity, really.
		 * Stacking limits below should fix it for the local
		 * device.  Whether or not it is a suitable granularity
		 * on the remote device is not our problem, really. If
		 * you care, you need to use devices with similar
		 * topology on all peers. */
		blk_queue_discard_granularity(q, 512);
		q->limits.max_discard_sectors = drbd_max_discard_sectors(device->resource);
		queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, q);
	} else {
		queue_flag_clear_unlocked(QUEUE_FLAG_DISCARD, q);
		blk_queue_discard_granularity(q, 0);
		q->limits.max_discard_sectors = 0;
	}
}

static void fixup_discard_if_not_supported(struct request_queue *q)
{
	/* To avoid confusion, if this queue does not support discard, clear
	 * max_discard_sectors, which is what lsblk -D reports to the user.
	 * Older kernels got this wrong in "stack limits".
	 * */
	if (!blk_queue_discard(q)) {
		blk_queue_max_discard_sectors(q, 0);
		blk_queue_discard_granularity(q, 0);
	}
}

static void decide_on_write_same_support(struct drbd_device *device,
			struct request_queue *q,
			struct request_queue *b, struct o_qlim *o,
			bool disable_write_same)
{
#ifndef COMPAT_WRITE_SAME_CAPABLE
	drbd_dbg(device, "This kernel is too old, no WRITE_SAME support.\n");
#else
	bool can_do = b ? b->limits.max_write_same_sectors : true;

	if (can_do && disable_write_same) {
		can_do = false;
		drbd_info(peer_device, "WRITE_SAME disabled by config\n");
	}

	if (can_do && !(common_connection_features(device->resource) & DRBD_FF_WSAME)) {
		can_do = false;
		drbd_info(device, "peer does not support WRITE_SAME\n");
	}

	if (o) {
		/* logical block size; queue_logical_block_size(NULL) is 512 */
		unsigned int peer_lbs = be32_to_cpu(o->logical_block_size);
		unsigned int me_lbs_b = queue_logical_block_size(b);
		unsigned int me_lbs = queue_logical_block_size(q);

		if (me_lbs_b != me_lbs) {
			drbd_warn(device,
				"logical block size of local backend does not match (drbd:%u, backend:%u); was this a late attach?\n",
				me_lbs, me_lbs_b);
			/* rather disable write same than trigger some BUG_ON later in the scsi layer. */
			can_do = false;
		}
		if (me_lbs_b != peer_lbs) {
			drbd_warn(device, "logical block sizes do not match (me:%u, peer:%u); this may cause problems.\n",
				me_lbs, peer_lbs);
			if (can_do) {
				drbd_dbg(device, "logical block size mismatch: WRITE_SAME disabled.\n");
				can_do = false;
			}
			me_lbs = max(me_lbs, me_lbs_b);
			/* We cannot change the logical block size of an in-use queue.
			 * We can only hope that access happens to be properly aligned.
			 * If not, the peer will likely produce an IO error, and detach. */
			if (peer_lbs > me_lbs) {
				if (device->resource->role[NOW] != R_PRIMARY) {
					blk_queue_logical_block_size(q, peer_lbs);
					drbd_warn(device, "logical block size set to %u\n", peer_lbs);
				} else {
					drbd_warn(device,
						"current Primary must NOT adjust logical block size (%u -> %u); hope for the best.\n",
						me_lbs, peer_lbs);
				}
			}
		}
		if (can_do && !o->write_same_capable) {
			/* If we introduce an open-coded write-same loop on the receiving side,
			 * the peer would present itself as "capable". */
			drbd_dbg(device, "WRITE_SAME disabled (peer device not capable)\n");
			can_do = false;
		}
	}

	blk_queue_max_write_same_sectors(q, can_do ? DRBD_MAX_BBIO_SECTORS : 0);
#endif
}
#endif

static void drbd_setup_queue_param(struct drbd_device *device, struct drbd_backing_dev *bdev,
				   unsigned int max_bio_size, struct o_qlim *o)
{
	UNREFERENCED_PARAMETER(o);
	struct request_queue * const q = device->rq_queue;
	unsigned int max_hw_sectors = max_bio_size >> 9;
	struct request_queue *b = NULL;
	struct disk_conf *dc;
	bool discard_zeroes_if_aligned = true;
	bool disable_write_same = false;

	if (bdev) {
		b = bdev->backing_bdev->bd_disk->queue;

		max_hw_sectors = (unsigned int)(min(queue_max_hw_sectors(b), max_bio_size >> 9));
		rcu_read_lock();
		dc = rcu_dereference(device->ldev->disk_conf);
		discard_zeroes_if_aligned = dc->discard_zeroes_if_aligned;
		disable_write_same = dc->disable_write_same;
		rcu_read_unlock();

		blk_set_stacking_limits(&q->limits);
	}

	blk_queue_max_hw_sectors(q, max_hw_sectors);
	/* This is the workaround for "bio would need to, but cannot, be split" */
#ifndef _WIN32
	blk_queue_segment_boundary(q, PAGE_CACHE_SIZE-1);
	decide_on_discard_support(device, q, b, discard_zeroes_if_aligned);
	decide_on_write_same_support(device, q, b, o, disable_write_same);

	if (b) {
		blk_queue_stack_limits(q, b);
		adjust_ra_pages(q, b);
	}
	fixup_discard_if_not_supported(q);
#endif
}

void drbd_reconsider_queue_parameters(struct drbd_device *device, struct drbd_backing_dev *bdev, struct o_qlim *o)
{
	unsigned int max_bio_size = device->device_conf.max_bio_size;
	struct drbd_peer_device *peer_device;

	if (bdev) {
		max_bio_size = (unsigned int)(min(max_bio_size,
			queue_max_hw_sectors(bdev->backing_bdev->bd_disk->queue) << 9));
	}

	spin_lock_irq(&device->resource->req_lock);
	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED)
			max_bio_size = min(max_bio_size, peer_device->max_bio_size);
	}
	spin_unlock_irq(&device->resource->req_lock);

	drbd_setup_queue_param(device, bdev, max_bio_size, o);
}

/* Make sure IO is suspended before calling this function(). */
static void drbd_try_suspend_al(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	bool suspend = true;
	int max_peers = device->bitmap->bm_max_peers, bitmap_index;

	for (bitmap_index = 0; bitmap_index < max_peers; bitmap_index++) {
		if (_drbd_bm_total_weight(device, bitmap_index) !=
		    drbd_bm_bits(device))
			return;
	}

	if (!drbd_al_try_lock(device)) {
		drbd_warn(device, "Failed to lock al in %s()", __func__);
		return;
	}

	drbd_al_shrink(device);
	spin_lock_irq(&device->resource->req_lock);
	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED) {
			suspend = false;
			break;
		}
	}
	if (suspend)
		suspend = !test_and_set_bit(AL_SUSPENDED, &device->flags);
	spin_unlock_irq(&device->resource->req_lock);
	lc_unlock(device->act_log);

	if (suspend)
		drbd_info(device, "Suspended AL updates\n");
}


static bool should_set_defaults(struct genl_info *info)
{
	unsigned flags = ((struct drbd_genlmsghdr*)info->userhdr)->flags;
	return 0 != (flags & DRBD_GENL_F_SET_DEFAULTS);
}

static unsigned int drbd_al_extents_max(struct drbd_backing_dev *bdev)
{
	/* This is limited by 16 bit "slot" numbers,
	 * and by available on-disk context storage.
	 *
	 * Also (u16)~0 is special (denotes a "free" extent).
	 *
	 * One transaction occupies one 4kB on-disk block,
	 * we have n such blocks in the on disk ring buffer,
	 * the "current" transaction may fail (n-1),
	 * and there is 919 slot numbers context information per transaction.
	 *
	 * 72 transaction blocks amounts to more than 2**16 context slots,
	 * so cap there first.
	 */
	const unsigned int max_al_nr = DRBD_AL_EXTENTS_MAX;
	const unsigned int sufficient_on_disk =
		(max_al_nr + AL_CONTEXT_PER_TRANSACTION -1)
		/AL_CONTEXT_PER_TRANSACTION;

	unsigned int al_size_4k = bdev->md.al_size_4k;

	if (al_size_4k > sufficient_on_disk)
		return max_al_nr;

	return (al_size_4k - 1) * AL_CONTEXT_PER_TRANSACTION;
}

static bool write_ordering_changed(struct disk_conf *a, struct disk_conf *b)
{
	return	a->disk_barrier != b->disk_barrier ||
		a->disk_flushes != b->disk_flushes ||
		a->disk_drain != b->disk_drain;
}

static void sanitize_disk_conf(struct drbd_device *device, struct disk_conf *disk_conf,
			       struct drbd_backing_dev *nbc)
{
	struct request_queue * const q = nbc->backing_bdev->bd_disk->queue;

	if (disk_conf->al_extents < DRBD_AL_EXTENTS_MIN)
		disk_conf->al_extents = DRBD_AL_EXTENTS_MIN;
	if (disk_conf->al_extents > drbd_al_extents_max(nbc))
		disk_conf->al_extents = drbd_al_extents_max(nbc);

	if (!blk_queue_discard(q) ||
	    (!queue_discard_zeroes_data(q) && !disk_conf->discard_zeroes_if_aligned)) {
		if (disk_conf->rs_discard_granularity) {
			disk_conf->rs_discard_granularity = 0; /* disable feature */
			drbd_info(device, "rs_discard_granularity feature disabled\n");
		}
	}

	if (disk_conf->rs_discard_granularity) {
		int orig_value = disk_conf->rs_discard_granularity;
		int remainder;

		if (q->limits.discard_granularity > disk_conf->rs_discard_granularity)
			disk_conf->rs_discard_granularity = q->limits.discard_granularity;

		remainder = disk_conf->rs_discard_granularity % q->limits.discard_granularity;
		disk_conf->rs_discard_granularity += remainder;

		if (disk_conf->rs_discard_granularity > q->limits.max_discard_sectors << 9)
			disk_conf->rs_discard_granularity = q->limits.max_discard_sectors << 9;

		if (disk_conf->rs_discard_granularity != (unsigned int)orig_value)
			drbd_info(device, "rs_discard_granularity changed to %d\n",
				  disk_conf->rs_discard_granularity);
	}
}

int drbd_adm_disk_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;
	struct drbd_device *device;
	struct drbd_resource *resource;
	struct disk_conf *new_disk_conf, *old_disk_conf;
	struct drbd_peer_device *peer_device;
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	device = adm_ctx.device;
	resource = device->resource;
	mutex_lock(&adm_ctx.resource->adm_mutex);

	/* we also need a disk
	 * to change the options on */
	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto out;
	}
#ifdef _WIN32
    new_disk_conf = kmalloc(sizeof(struct disk_conf), GFP_KERNEL, '51DW');
#else
	new_disk_conf = kmalloc(sizeof(struct disk_conf), GFP_KERNEL);
#endif
	if (!new_disk_conf) {
		retcode = ERR_NOMEM;
		goto fail;
	}

	mutex_lock(&resource->conf_update);
	old_disk_conf = device->ldev->disk_conf;
	*new_disk_conf = *old_disk_conf;
	if (should_set_defaults(info))
		set_disk_conf_defaults(new_disk_conf);

	err = disk_conf_from_attrs_for_change(new_disk_conf, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail_unlock;
	}

	sanitize_disk_conf(device, new_disk_conf, device->ldev);

	drbd_suspend_io(device, READ_AND_WRITE);
	wait_event(device->al_wait, drbd_al_try_lock(device));
	drbd_al_shrink(device);
	err = drbd_check_al_size(device, new_disk_conf);
	lc_unlock(device->act_log);
	wake_up(&device->al_wait);
	drbd_resume_io(device);

	if (err) {
		retcode = ERR_NOMEM;
		goto fail_unlock;
	}

	lock_all_resources();
	retcode = drbd_resync_after_valid(device, new_disk_conf->resync_after);
	if (retcode == NO_ERROR) {
#ifdef _WIN32
		synchronize_rcu_w32_wlock();
#endif
		rcu_assign_pointer(device->ldev->disk_conf, new_disk_conf);
#ifdef _WIN32
		synchronize_rcu();
#endif
		drbd_resync_after_changed(device);
	}
	unlock_all_resources();

	if (retcode != NO_ERROR)
		goto fail_unlock;

	mutex_unlock(&resource->conf_update);

	if (new_disk_conf->al_updates)
		device->ldev->md.flags &= ~MDF_AL_DISABLED;
	else
		device->ldev->md.flags |= MDF_AL_DISABLED;

	if (new_disk_conf->md_flushes)
		clear_bit(MD_NO_FUA, &device->flags);
	else
		set_bit(MD_NO_FUA, &device->flags);

	if (write_ordering_changed(old_disk_conf, new_disk_conf))
		drbd_bump_write_ordering(device->resource, NULL, WO_BIO_BARRIER);

	if (old_disk_conf->discard_zeroes_if_aligned != new_disk_conf->discard_zeroes_if_aligned
		|| old_disk_conf->disable_write_same != new_disk_conf->disable_write_same)
		drbd_reconsider_queue_parameters(device, device->ldev, NULL);

	drbd_md_sync_if_dirty(device);

	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED)
			drbd_send_sync_param(peer_device);
	}

#ifdef _WIN32
	// skip synchronize_rcu 
#else
	synchronize_rcu();
#endif
	kfree(old_disk_conf);
	mod_timer(&device->request_timer, jiffies + HZ);
	goto success;

fail_unlock:
	mutex_unlock(&resource->conf_update);
 fail:
	kfree(new_disk_conf);
success:
#ifdef _WIN32
    //if (retcode != NO_ERROR)	
	//	synchronize_rcu();
#else
	if (retcode != NO_ERROR)
		synchronize_rcu();
#endif
	put_ldev(device);
out:
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static void mutex_unlock_cond(struct mutex *mutex, bool *have_mutex)
{
	if (*have_mutex) {
		mutex_unlock(mutex);
		*have_mutex = false;
	}
}

static void update_resource_dagtag(struct drbd_resource *resource, struct drbd_backing_dev *bdev)
{
	u64 dagtag = 0;
	int node_id;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		struct drbd_peer_md *peer_md;
		if (bdev->md.node_id == node_id)
			continue;

		peer_md = &bdev->md.peers[node_id];

		if (peer_md->bitmap_uuid)
			dagtag = max(peer_md->bitmap_dagtag, dagtag);
	}
	if (dagtag > resource->dagtag_sector)
		resource->dagtag_sector = dagtag;
}

static int used_bitmap_slots(struct drbd_backing_dev *bdev)
{
	int node_id;
	int used = 0;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		struct drbd_peer_md *peer_md = &bdev->md.peers[node_id];

		if (peer_md->bitmap_index != -1)
			used++;
	}

	return used;
}

static bool bitmap_index_vacant(struct drbd_backing_dev *bdev, int bitmap_index)
{
	int node_id;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		struct drbd_peer_md *peer_md = &bdev->md.peers[node_id];

		if (peer_md->bitmap_index == bitmap_index)
			return false;
	}
	return true;
}

static int
allocate_bitmap_index(struct drbd_peer_device *peer_device,
struct drbd_backing_dev *nbc)
{
	struct drbd_device *device = peer_device->device;
	const int peer_node_id = peer_device->connection->peer_node_id;
	unsigned int bitmap_index;

	for (bitmap_index = 0; bitmap_index < device->bitmap->bm_max_peers; bitmap_index++) {
		if (bitmap_index_vacant(nbc, bitmap_index)) {
			struct drbd_peer_md *peer_md = &nbc->md.peers[peer_node_id];

			peer_md->bitmap_index = bitmap_index;
			peer_device->bitmap_index = bitmap_index;
			peer_md->flags &= ~MDF_NODE_EXISTS; /* it is a peer now */
			return 0;
		}
	}
	drbd_err(peer_device, "Not enough free bitmap slots\n");
	return -ENOSPC;
}

static struct block_device *open_backing_dev(struct drbd_device *device,
		const char *bdev_path, void *claim_ptr, bool do_bd_link)
{
	struct block_device *bdev;
	int err = 0;

	bdev = blkdev_get_by_path(bdev_path,
				  FMODE_READ | FMODE_WRITE | FMODE_EXCL, claim_ptr, FALSE);
	if (IS_ERR(bdev)) {
		drbd_err(device, "open(\"%s\") failed with %ld\n",
				bdev_path, PTR_ERR(bdev));
		return bdev;
	}

	// DW-1109: inc ref when open it.
	kref_get(&bdev->kref);

	if (!do_bd_link)
		return bdev;

#if   defined(COMPAT_HAVE_BD_UNLINK_DISK_HOLDER)
	err = bd_link_disk_holder(bdev, device->vdisk);
#elif defined(COMPAT_HAVE_BD_CLAIM_BY_DISK)
	err = bd_claim_by_disk(bdev, claim_ptr, device->vdisk);
#endif
	if (err) {
		blkdev_put(bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
		drbd_err(device, "bd_link_disk_holder(\"%s\", ...) failed with %d\n",
				bdev_path, err);
		bdev = ERR_PTR(err);
	}
#if 0 // DW-1510 The bd_contains value is not appropriate when the device size is updated. Return bdev.
#ifdef _WIN32
	if (bdev->bd_contains) {
		return bdev->bd_contains;
	}
#endif
#endif
	return bdev;
}

bool want_bitmap(struct drbd_peer_device *peer_device)
{
	UNREFERENCED_PARAMETER(peer_device);
#ifndef _WIN32 
	bool want_bitmap = false;

	rcu_read_lock();
	pdc = rcu_dereference(peer_device->conf);
	if (pdc)
		want_bitmap |= pdc->bitmap;
	rcu_read_unlock();
#else // TODO_WIN : Disable bitmap = no options temporary 
	bool want_bitmap = true;
#endif 
	return want_bitmap;
}

static int open_backing_devices(struct drbd_device *device,
		struct disk_conf *new_disk_conf,
		struct drbd_backing_dev *nbc)
{
	struct block_device *bdev;

	bdev = open_backing_dev(device, new_disk_conf->backing_dev, device, true);
	if (IS_ERR(bdev))
		return ERR_OPEN_DISK;
	
	nbc->backing_bdev = bdev;
#ifdef _WIN32
	// DW-1277: mark that this will be using as replication volume.
	set_bit(VOLUME_TYPE_REPL, &bdev->bd_disk->pDeviceExtension->Flag);
#endif

	/*
	 * meta_dev_idx >= 0: external fixed size, possibly multiple
	 * drbd sharing one meta device.  TODO in that case, paranoia
	 * check that [md_bdev, meta_dev_idx] is not yet used by some
	 * other drbd minor!  (if you use drbd.conf + drbdadm, that
	 * should check it for you already; but if you don't, or
	 * someone fooled it, we need to double check here)
	 */
	bdev = open_backing_dev(device, new_disk_conf->meta_dev,
		/* claim ptr: device, if claimed exclusively; shared drbd_m_holder,
		 * if potentially shared with other drbd minors */
			(new_disk_conf->meta_dev_idx < 0) ? (void*)device : (void*)drbd_m_holder,
		/* avoid double bd_claim_by_disk() for the same (source,target) tuple,
		 * as would happen with internal metadata. */
			(new_disk_conf->meta_dev_idx != DRBD_MD_INDEX_FLEX_INT &&
			 new_disk_conf->meta_dev_idx != DRBD_MD_INDEX_INTERNAL));
	if (IS_ERR(bdev))
		return ERR_OPEN_MD_DISK;
	nbc->md_bdev = bdev;
#ifdef _WIN32
	// DW-1277: mark that this will be using as meta volume.
	set_bit(VOLUME_TYPE_META, &bdev->bd_disk->pDeviceExtension->Flag);
	bdev->bd_disk->private_data = nbc;		// for removing
#endif
	return NO_ERROR;
}

static void close_backing_dev(struct drbd_device *device, struct block_device *bdev,
	bool do_bd_unlink)
{
	UNREFERENCED_PARAMETER(device);

	if (!bdev)
		return;
	if (do_bd_unlink) {
#if   defined(COMPAT_HAVE_BD_UNLINK_DISK_HOLDER)
		bd_unlink_disk_holder(bdev, device->vdisk);
#elif defined(COMPAT_HAVE_BD_CLAIM_BY_DISK)
		bd_release_from_disk(bdev, device->vdisk);
#endif
	}
	blkdev_put(bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
}

void drbd_backing_dev_free(struct drbd_device *device, struct drbd_backing_dev *ldev)
{
	if (ldev == NULL)
		return;
#ifdef _WIN32
	if (ldev->md_bdev) {
		// Unlink not to be referred when removing meta volume
		struct block_device * bd = ldev->md_bdev;
		bd->bd_disk->private_data = NULL;
	}
#endif

	close_backing_dev(device, ldev->md_bdev, ldev->md_bdev != ldev->backing_bdev);
	close_backing_dev(device, ldev->backing_bdev, true);

	kfree(ldev->disk_conf);
	kfree(ldev);
}

static void discard_not_wanted_bitmap_uuids(struct drbd_device *device, struct drbd_backing_dev *ldev)
{
	struct drbd_peer_md *peer_md = ldev->md.peers;
	struct drbd_peer_device *peer_device;
	int node_id;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		peer_device = peer_device_by_node_id(device, node_id);
		if (peer_device && peer_md[node_id].bitmap_uuid && !want_bitmap(peer_device))
			peer_md[node_id].bitmap_uuid = 0;
	}
}

int drbd_adm_attach(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_device *device;
	struct drbd_resource *resource;
	int err;
	enum drbd_ret_code retcode;
	enum determine_dev_size dd;
	sector_t max_possible_sectors;
	sector_t min_md_device_sectors;
	struct drbd_backing_dev *nbc; /* new_backing_conf */
	struct disk_conf *new_disk_conf = NULL;
	enum drbd_state_rv rv;
	struct drbd_peer_device *peer_device;
	unsigned int slots_needed = 0;
	bool have_conf_update = false;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;
	device = adm_ctx.device;
	resource = device->resource;
	mutex_lock(&resource->adm_mutex);

	/* allocation not in the IO path, drbdsetup context */
#ifdef _WIN32
    nbc = kzalloc(sizeof(struct drbd_backing_dev), GFP_KERNEL, '61DW');
#else
	nbc = kzalloc(sizeof(struct drbd_backing_dev), GFP_KERNEL);
#endif
	if (!nbc) {
		retcode = ERR_NOMEM;
		goto fail;
	}
	spin_lock_init(&nbc->md.uuid_lock);

#ifdef _WIN32
    new_disk_conf = kzalloc(sizeof(struct disk_conf), GFP_KERNEL, '71DW');
#else
	new_disk_conf = kzalloc(sizeof(struct disk_conf), GFP_KERNEL);
#endif
	if (!new_disk_conf) {
		retcode = ERR_NOMEM;
		goto fail;
	}
	nbc->disk_conf = new_disk_conf;

	set_disk_conf_defaults(new_disk_conf);
	err = disk_conf_from_attrs(new_disk_conf, info);
	if (err) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	if (new_disk_conf->meta_dev_idx < DRBD_MD_INDEX_FLEX_INT) {
		retcode = ERR_MD_IDX_INVALID;
		goto fail;
	}

	lock_all_resources();
	retcode = drbd_resync_after_valid(device, new_disk_conf->resync_after);
	unlock_all_resources();
	if (retcode != NO_ERROR)
		goto fail;

	retcode = open_backing_devices(device, new_disk_conf, nbc);
	if (retcode != NO_ERROR)
		goto fail;

	if ((nbc->backing_bdev == nbc->md_bdev) !=
	    (new_disk_conf->meta_dev_idx == DRBD_MD_INDEX_INTERNAL ||
	     new_disk_conf->meta_dev_idx == DRBD_MD_INDEX_FLEX_INT)) {
		retcode = ERR_MD_IDX_INVALID;
		goto fail;
	}

	/* if you want to reconfigure, please tear down first */
	if (device->disk_state[NOW] > D_DISKLESS) {
		retcode = ERR_DISK_CONFIGURED;
		goto fail;
	}
	/* It may just now have detached because of IO error.  Make sure
	 * drbd_ldev_destroy is done already, we may end up here very fast,
	 * e.g. if someone calls attach from the on-io-error handler,
	 * to realize a "hot spare" feature (not that I'd recommend that) */
	wait_event(device->misc_wait, !test_bit(GOING_DISKLESS, &device->flags));

	/* make sure there is no leftover from previous force-detach attempts */
	clear_bit(FORCE_DETACH, &device->flags);

	/* and no leftover from previously aborted resync or verify, either */
	for_each_peer_device(peer_device, device) {
		peer_device->rs_total = 0;
		peer_device->rs_failed = 0;
		atomic_set(&peer_device->rs_pending_cnt, 0);
	}

	if (!device->bitmap) {
		device->bitmap = drbd_bm_alloc();
		if (!device->bitmap) {
			retcode = ERR_NOMEM;
			goto fail;
		}
	}

	/* Read our meta data super block early.
	 * This also sets other on-disk offsets. */
	retcode = drbd_md_read(device, nbc);
	if (retcode != NO_ERROR)
		goto fail;

	discard_not_wanted_bitmap_uuids(device, nbc);
	sanitize_disk_conf(device, new_disk_conf, nbc);

	if (drbd_get_max_capacity(nbc) < new_disk_conf->disk_size) {
		drbd_err(device, "max capacity %llu smaller than disk size %llu\n",
			(unsigned long long) drbd_get_max_capacity(nbc),
			(unsigned long long) new_disk_conf->disk_size);
		retcode = ERR_DISK_TOO_SMALL;
		goto fail;
	}

	if (new_disk_conf->meta_dev_idx < 0) {
		max_possible_sectors = DRBD_MAX_SECTORS_FLEX;
		/* at least one MB, otherwise it does not make sense */
		min_md_device_sectors = (2<<10);
	} else {
		max_possible_sectors = DRBD_MAX_SECTORS;
#ifdef _WIN32 // DW-1335
		min_md_device_sectors = (256 << 20 >> 9) * (new_disk_conf->meta_dev_idx + 1);
#else
		min_md_device_sectors = (128 << 20 >> 9) * (new_disk_conf->meta_dev_idx + 1);
#endif
	}

#ifdef _WIN32 // DW-1607
	if (drbd_get_md_capacity(nbc->md_bdev) < min_md_device_sectors) {
#else
	if (drbd_get_capacity(nbc->md_bdev) < min_md_device_sectors) {
#endif
		retcode = ERR_MD_DISK_TOO_SMALL;
		drbd_warn(device, "refusing attach: md-device too small, "
		     "at least %llu sectors needed for this meta-disk type\n",
		     (unsigned long long) min_md_device_sectors);
		goto fail;
	}

	/* Make sure the new disk is big enough
	 * (we may currently be R_PRIMARY with no local disk...) */
	if (drbd_get_max_capacity(nbc) <
	    drbd_get_capacity(device->this_bdev)) {
		drbd_err(device,
			"Current (diskless) capacity %llu, cannot attach smaller (%llu) disk\n",
			(unsigned long long)drbd_get_capacity(device->this_bdev),
			(unsigned long long)drbd_get_max_capacity(nbc));
		retcode = ERR_DISK_TOO_SMALL;
		goto fail;
	}

	nbc->known_size = drbd_get_capacity(nbc->backing_bdev);

	if (nbc->known_size > max_possible_sectors) {
		drbd_warn(device, "==> truncating very big lower level device "
			"to currently maximum possible %llu sectors <==\n",
			(unsigned long long) max_possible_sectors);
		if (new_disk_conf->meta_dev_idx >= 0)
			drbd_warn(device, "==>> using internal or flexible "
				      "meta data may help <<==\n");
	}

	drbd_suspend_io(device, READ_AND_WRITE);
	wait_event(resource->barrier_wait, !barrier_pending(resource));
	for_each_peer_device(peer_device, device)
		wait_event(device->misc_wait,
			   (!atomic_read(&peer_device->ap_pending_cnt) ||
			    drbd_suspended(device)));
	/* and for other previously queued resource work */
#ifdef _WIN32
	drbd_flush_workqueue(resource, &resource->work);
#else
	drbd_flush_workqueue(&resource->work);
#endif

#ifdef _WIN32 // DW-1605
	stable_state_change(rv, resource,
		change_disk_state(device, D_ATTACHING, CS_VERBOSE | CS_SERIALIZE, NULL));
#else
	rv = stable_state_change(resource,
		change_disk_state(device, D_ATTACHING, CS_VERBOSE | CS_SERIALIZE, NULL));
#endif

	retcode = rv;  /* FIXME: Type mismatch. */
	if (rv >= SS_SUCCESS)
		update_resource_dagtag(resource, nbc);
	drbd_resume_io(device);
	if (rv < SS_SUCCESS)
		goto fail;

	if (!get_ldev_if_state(device, D_ATTACHING))
		goto force_diskless;
#ifdef _WIN32_MVFL
	struct drbd_genlmsghdr *dh = info->userhdr;
	if (do_add_minor(dh->minor)) {
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		PVOLUME_EXTENSION pvext = get_targetdev_by_minor(dh->minor, FALSE);
		if (pvext) {
			// DW-1461: set volume protection when attaching.
			SetDrbdlockIoBlock(pvext, resource->role[NOW] == R_PRIMARY ? FALSE : TRUE);
#ifdef _WIN32_MULTIVOL_THREAD
			pvext->WorkThreadInfo = &resource->WorkThreadInfo;

			FsctlLockVolume(dh->minor);

			pvext->Active = TRUE;
			status = FsctlFlushDismountVolume(dh->minor, true);

			FsctlUnlockVolume(dh->minor);

			if (!NT_SUCCESS(status)) {
				retcode = ERR_RES_NOT_KNOWN;
				goto force_diskless_dec;
			}
			
#else
			status = mvolInitializeThread(pvext, &pvext->WorkThreadInfo, mvolWorkThread);
			if (NT_SUCCESS(status)) {
				FsctlLockVolume(dh->minor);

				pvext->Active = TRUE;
				status = FsctlFlushDismountVolume(dh->minor, true);

				FsctlUnlockVolume(dh->minor);

				if (!NT_SUCCESS(status)) {
					retcode = ERR_RES_NOT_KNOWN;
					goto force_diskless_dec;
				}
			}
			else if (STATUS_DEVICE_ALREADY_ATTACHED == status) {
				struct block_device * bd = pvext->dev;
				if (bd) {
					// required to analyze that this job is done at this point
					//bd->bd_disk->fops->open(bd, FMODE_WRITE);
					//bd->bd_disk->fops->release(bd->bd_disk, FMODE_WRITE);
				}
			}
			else {
				WDRBD_WARN("Failed to initialize WorkThread. status(0x%x)\n", status);
			}
#endif
		}
	}
#endif
	drbd_info(device, "Maximum number of peer devices = %u\n",
		  device->bitmap->bm_max_peers);

	mutex_lock(&resource->conf_update);
	have_conf_update = true;

	/* Make sure the local node id matches or is unassigned */
	if (nbc->md.node_id != -1 && (unsigned int)nbc->md.node_id != resource->res_opts.node_id) {
		drbd_err(device, "Local node id %d differs from local "
			 "node id %d on device\n",
			 resource->res_opts.node_id,
			 nbc->md.node_id);
		retcode = ERR_INVALID_REQUEST;
		goto force_diskless_dec;
	}

	/* Make sure no bitmap slot has our own node id */
	if (nbc->md.peers[resource->res_opts.node_id].bitmap_index != -1) {
		drbd_err(device, "There is a bitmap for my own node id (%d)\n",
			 resource->res_opts.node_id);
		retcode = ERR_INVALID_REQUEST;
		goto force_diskless_dec;
	}

	/* Make sure we have a bitmap slot for each peer id */
	for_each_peer_device(peer_device, device) {
		struct drbd_connection *connection = peer_device->connection;
		int bitmap_index;

		bitmap_index = nbc->md.peers[connection->peer_node_id].bitmap_index;
		if (bitmap_index != -1)
			peer_device->bitmap_index = bitmap_index;
		else if (want_bitmap(peer_device))
			slots_needed++;
	}
	if (slots_needed) {
		unsigned int slots_available = device->bitmap->bm_max_peers - used_bitmap_slots(nbc);

		if (slots_needed > slots_available) {
			drbd_err(device, "Not enough free bitmap "
				 "slots (available=%d, needed=%d)\n",
				 slots_available,
				 slots_needed);
			retcode = ERR_INVALID_REQUEST;
			goto force_diskless_dec;
		}
		for_each_peer_device(peer_device, device) {
			if (peer_device->bitmap_index != -1 || !want_bitmap(peer_device))
				continue;

			err = allocate_bitmap_index(peer_device, nbc); 
			if (err){
				retcode = ERR_INVALID_REQUEST;
				goto force_diskless_dec;
			}
		}
	}

	/* Assign the local node id (if not assigned already) */
	nbc->md.node_id = resource->res_opts.node_id;

	if (resource->role[NOW] == R_PRIMARY && device->exposed_data_uuid &&
	    (device->exposed_data_uuid & ~UUID_PRIMARY) !=
	    (nbc->md.current_uuid & ~UUID_PRIMARY)) {
		int data_present = false;
		for_each_peer_device(peer_device, device) {
			if (peer_device->disk_state[NOW] == D_UP_TO_DATE)
				data_present = true;
		}
		if (!data_present) {
			drbd_err(device, "Can only attach to data with current UUID=%016llX\n",
				 (unsigned long long)device->exposed_data_uuid);
			retcode = ERR_DATA_NOT_CURRENT;
			goto force_diskless_dec;
		}
	}

	/* Since we are diskless, fix the activity log first... */
	if (drbd_check_al_size(device, new_disk_conf)) {
		retcode = ERR_NOMEM;
		goto force_diskless_dec;
	}

	/* Point of no return reached.
	 * Devices and memory are no longer released by error cleanup below.
	 * now device takes over responsibility, and the state engine should
	 * clean it up somewhere.  */
	D_ASSERT(device, device->ldev == NULL);
	device->ldev = nbc;
	nbc = NULL;
	new_disk_conf = NULL;

#ifdef _WIN32
	// DW-1376: this_bdev indicates block device of replication volume, which can be removed anytime. need to get newly created block device.
	if (device->this_bdev->bd_disk->pDeviceExtension != device->ldev->backing_bdev->bd_disk->pDeviceExtension)
	{
		// DW-1376: put old one.
		blkdev_put(device->this_bdev, 0);

		// DW-1376: get new one.
		device->this_bdev = device->ldev->backing_bdev->bd_parent?device->ldev->backing_bdev->bd_parent : device->ldev->backing_bdev;
		kref_get(&device->this_bdev->kref);
	}

	// DW-1300: set drbd device to access from volume extention
	unsigned char oldIRQL = ExAcquireSpinLockExclusive(&device->this_bdev->bd_disk->drbd_device_ref_lock);	
	device->this_bdev->bd_disk->drbd_device = device;
	ExReleaseSpinLockExclusive(&device->this_bdev->bd_disk->drbd_device_ref_lock, oldIRQL);
#endif
	for_each_peer_device(peer_device, device) {
		err = drbd_attach_peer_device(peer_device);
		if (err) {
			retcode = ERR_NOMEM;
			goto force_diskless_dec;
		}
	}

	mutex_unlock(&resource->conf_update);
	have_conf_update = false;

	lock_all_resources();
	retcode = drbd_resync_after_valid(device, device->ldev->disk_conf->resync_after);
	if (retcode != NO_ERROR) {
		unlock_all_resources();
		goto force_diskless_dec;
	}

	/* Reset the "barriers don't work" bits here, then force meta data to
	 * be written, to ensure we determine if barriers are supported. */
	if (device->ldev->disk_conf->md_flushes)
		clear_bit(MD_NO_FUA, &device->flags);
	else
		set_bit(MD_NO_FUA, &device->flags);

	drbd_resync_after_changed(device);
	drbd_bump_write_ordering(resource, device->ldev, WO_BIO_BARRIER);
	unlock_all_resources();

	/* Prevent shrinking of consistent devices ! */
	{
	unsigned long long nsz = drbd_new_dev_size(device, 0, device->ldev->disk_conf->disk_size, 0);
	unsigned long long eff = device->ldev->md.effective_size;
	if (drbd_md_test_flag(device, MDF_CONSISTENT) && nsz < eff) {
		drbd_warn(device,
			"refusing to truncate a consistent device (%llu < %llu)\n",
			nsz, eff);		
		retcode = ERR_DISK_TOO_SMALL;
		goto force_diskless_dec;
	}
	}

	if (drbd_md_test_flag(device, MDF_CRASHED_PRIMARY))
		set_bit(CRASHED_PRIMARY, &device->flags);
	else
		clear_bit(CRASHED_PRIMARY, &device->flags);

	if (drbd_md_test_flag(device, MDF_PRIMARY_IND) &&
	    !(resource->role[NOW] == R_PRIMARY && resource->susp_nod[NOW]) &&
	    !device->exposed_data_uuid && !test_bit(NEW_CUR_UUID, &device->flags))
#ifndef _WIN32_CRASHED_PRIMARY_SYNCSOURCE
	// MODIFIED_BY_MANTECH DW-1357: this is initialzing crashed primary. set crashed primary flag and clear all peer's ignoring flags.
	{
		set_bit(CRASHED_PRIMARY, &device->flags);

		struct drbd_md *md = &device->ldev->md;
		int node_id = 0;

		for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++)
			md->peers[node_id].flags &= ~MDF_PEER_IGNORE_CRASHED_PRIMARY;

		// it will change to outdate.
		md->flags &= ~MDF_WAS_UP_TO_DATE;
		
		drbd_md_mark_dirty(device);
	}
#else
		set_bit(CRASHED_PRIMARY, &device->flags);
#endif

	device->read_cnt = 0;
	device->writ_cnt = 0;

	drbd_reconsider_queue_parameters(device, device->ldev, NULL);

	/* If I am currently not R_PRIMARY,
	 * but meta data primary indicator is set,
	 * I just now recover from a hard crash,
	 * and have been R_PRIMARY before that crash.
	 *
	 * Now, if I had no connection before that crash
	 * (have been degraded R_PRIMARY), chances are that
	 * I won't find my peer now either.
	 *
	 * In that case, and _only_ in that case,
	 * we use the degr-wfc-timeout instead of the default,
	 * so we can automatically recover from a crash of a
	 * degraded but active "cluster" after a certain timeout.
	 */
	for_each_peer_device(peer_device, device) {
		clear_bit(USE_DEGR_WFC_T, &peer_device->flags);
		if (resource->role[NOW] != R_PRIMARY &&
		    drbd_md_test_flag(device, MDF_PRIMARY_IND) &&
		    !drbd_md_test_peer_flag(peer_device, MDF_PEER_CONNECTED))
			set_bit(USE_DEGR_WFC_T, &peer_device->flags);
	}

	dd = drbd_determine_dev_size(device, 0, 0, NULL);
	if (dd == DS_ERROR) {
		retcode = ERR_NOMEM_BITMAP;
		goto force_diskless_dec;
	} else if (dd == DS_GREW) {
		for_each_peer_device(peer_device, device)
			set_bit(RESYNC_AFTER_NEG, &peer_device->flags);
	}

	if (drbd_bitmap_io(device, &drbd_bm_read,
		"read from attaching", BM_LOCK_ALL,
		NULL)) {
		retcode = ERR_IO_MD_DISK;
		goto force_diskless_dec;
	}

	for_each_peer_device(peer_device, device) {
		if ((test_bit(CRASHED_PRIMARY, &device->flags) &&
		     drbd_md_test_flag(device, MDF_AL_DISABLED)) ||
		    drbd_md_test_peer_flag(peer_device, MDF_PEER_FULL_SYNC)) {
			drbd_info(peer_device, "Assuming that all blocks are out of sync "
				  "(aka FullSync)\n");
			if (drbd_bitmap_io(device, &drbd_bmio_set_n_write,
				"set_n_write from attaching", BM_LOCK_ALL,
				peer_device)) {
				retcode = ERR_IO_MD_DISK;
				goto force_diskless_dec;
			}
		}
	}

	drbd_try_suspend_al(device); /* IO is still suspended here... */

#ifdef _WIN32
    unsigned char oldIrql_rLock1; // RCU_SPECIAL_CASE
    oldIrql_rLock1 = ExAcquireSpinLockShared(&g_rcuLock);
#else
	rcu_read_lock();
#endif
	if (rcu_dereference(device->ldev->disk_conf)->al_updates)
		device->ldev->md.flags &= ~MDF_AL_DISABLED;
	else
		device->ldev->md.flags |= MDF_AL_DISABLED;
#ifdef _WIN32
    // RCU_SPECIAL_CASE
    ExReleaseSpinLockShared(&g_rcuLock, oldIrql_rLock1);
#else
	rcu_read_unlock();
#endif

	/* change_disk_state uses disk_state_from_md(device); in case D_NEGOTIATING not
	   necessary, and falls back to a local state change */
#ifdef _WIN32 // DW-1605
	stable_state_change(rv, resource,
		change_disk_state(device, D_NEGOTIATING, CS_VERBOSE | CS_SERIALIZE, NULL));
#else
	rv = stable_state_change(resource,
		change_disk_state(device, D_NEGOTIATING, CS_VERBOSE | CS_SERIALIZE, NULL));
#endif


	if (rv < SS_SUCCESS)
		goto force_diskless_dec;

	mod_timer(&device->request_timer, jiffies + HZ);

	if (resource->role[NOW] == R_PRIMARY)
		device->ldev->md.current_uuid |= UUID_PRIMARY;
	else
		device->ldev->md.current_uuid &= ~UUID_PRIMARY;

	drbd_md_sync(device);

	drbd_kobject_uevent(device);
	put_ldev(device);
	mutex_unlock(&resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;

 force_diskless_dec:
	put_ldev(device);
 force_diskless:
	change_disk_state(device, D_DISKLESS, CS_HARD, NULL);
 fail:
	mutex_unlock_cond(&resource->conf_update, &have_conf_update);
	drbd_backing_dev_free(device, nbc);
	mutex_unlock(&resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum drbd_disk_state get_disk_state(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	enum drbd_disk_state disk_state;

	spin_lock_irq(&resource->req_lock);
	disk_state = device->disk_state[NOW];
	spin_unlock_irq(&resource->req_lock);
	return disk_state;
}

static int adm_detach(struct drbd_device *device, int force, struct sk_buff *reply_skb)
{
	enum drbd_state_rv retcode;
#ifdef _WIN32
	long timeo = 3*HZ;
	char *err_str = NULL;
	int ret = 0;
#else
	const char *err_str = NULL;
	int ret;
#endif

	if (force) {
		set_bit(FORCE_DETACH, &device->flags);
		change_disk_state(device, D_DETACHING, CS_HARD, NULL);
		retcode = SS_SUCCESS;
		goto out;
	}

	drbd_suspend_io(device, READ_AND_WRITE); /* so no-one is stuck in drbd_al_begin_io */
#ifdef _WIN32 // DW-1605
	stable_state_change(retcode, device->resource,
		change_disk_state(device, D_DETACHING,
			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE, &err_str));
#else
	retcode = stable_state_change(device->resource,
		change_disk_state(device, D_DETACHING,
			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE, &err_str));
#endif

	/* D_DETACHING will transition to DISKLESS. */
	drbd_resume_io(device);
#ifdef _WIN32 // DW-1046 detour adm_detach hang
	wait_event_interruptible_timeout(timeo, device->misc_wait,
						 get_disk_state(device) != D_DETACHING,
						 timeo);
	WDRBD_INFO("wait_event_interruptible_timeout timeo:%d device->disk_state[NOW]:%d\n", timeo, device->disk_state[NOW]);
#else
	ret = wait_event_interruptible(device->misc_wait,
			get_disk_state(device) != D_DETACHING);
#endif
	if (retcode >= SS_SUCCESS)
		drbd_cleanup_device(device);
	if (retcode == SS_IS_DISKLESS)
		retcode = SS_NOTHING_TO_DO;
	if (ret)
		retcode = ERR_INTR;
out:
	if (err_str) {
		drbd_msg_put_info(reply_skb, err_str);
		kfree(err_str);
	}
	return retcode;
}

/* Detaching the disk is a process in multiple stages.  First we need to lock
 * out application IO, in-flight IO, IO stuck in drbd_al_begin_io.
 * Then we transition to D_DISKLESS, and wait for put_ldev() to return all
 * internal references as well.
 * Only then we have finally detached. */
int drbd_adm_detach(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;
#ifdef _WIN32
    struct detach_parms parms = { 0 };
#else
	struct detach_parms parms = { };
#endif
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	if (info->attrs[DRBD_NLA_DETACH_PARMS]) {
		err = detach_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out;
		}
	}

#ifdef _WIN32 // DW-839 not support diskless Primary
	struct drbd_peer_device *peer_device = NULL;
	for_each_peer_device(peer_device, adm_ctx.device) {
		if (peer_device->repl_state[NOW] > L_OFF && adm_ctx.device->resource->role[NOW] == R_PRIMARY) {
			retcode = SS_CONNECTED_DISKLESS;
			goto out;
		}
	}
#endif


	mutex_lock(&adm_ctx.resource->adm_mutex);
	retcode = adm_detach(adm_ctx.device, parms.force_detach, adm_ctx.reply_skb);
	mutex_unlock(&adm_ctx.resource->adm_mutex);
out:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static bool conn_resync_running(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	bool rv = false;
	int vnr;

	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		if (peer_device->repl_state[NOW] == L_SYNC_SOURCE ||
		    peer_device->repl_state[NOW] == L_SYNC_TARGET ||
		    peer_device->repl_state[NOW] == L_PAUSED_SYNC_S ||
		    peer_device->repl_state[NOW] == L_PAUSED_SYNC_T) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static bool conn_ov_running(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	bool rv = false;
	int vnr;

	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
#endif
		if (peer_device->repl_state[NOW] == L_VERIFY_S ||
		    peer_device->repl_state[NOW] == L_VERIFY_T) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static enum drbd_ret_code
_check_net_options(struct drbd_connection *connection, struct net_conf *old_net_conf, struct net_conf *new_net_conf)
{
	if (old_net_conf && connection->cstate[NOW] == C_CONNECTED && connection->agreed_pro_version < 100) {
		if (new_net_conf->wire_protocol != old_net_conf->wire_protocol)
			return ERR_NEED_APV_100;

		if (new_net_conf->two_primaries != old_net_conf->two_primaries)
			return ERR_NEED_APV_100;

		if (!new_net_conf->integrity_alg != !old_net_conf->integrity_alg)
			return ERR_NEED_APV_100;

		if (strcmp(new_net_conf->integrity_alg, old_net_conf->integrity_alg))
			return ERR_NEED_APV_100;
	}

	if (!new_net_conf->two_primaries &&
	    connection->resource->role[NOW] == R_PRIMARY &&
	    connection->peer_role[NOW] == R_PRIMARY)
		return ERR_NEED_ALLOW_TWO_PRI;

	if (new_net_conf->two_primaries &&
	    (new_net_conf->wire_protocol != DRBD_PROT_C))
		return ERR_NOT_PROTO_C;

	if (new_net_conf->wire_protocol == DRBD_PROT_A &&
	    new_net_conf->fencing_policy == FP_STONITH)
		return ERR_STONITH_AND_PROT_A;

	if (new_net_conf->on_congestion != OC_BLOCK &&
	    new_net_conf->wire_protocol != DRBD_PROT_A)
		return ERR_CONG_NOT_PROTO_A;

#ifdef _WIN32 // DW-1436 sndbuf-size must be at least 10M 
	if (new_net_conf->sndbuf_size < DRBD_SNDBUF_SIZE_MIN && new_net_conf->sndbuf_size > 0){
		return ERR_SNDBUF_SIZE_TOO_SMALL;
	}
#endif 

	return NO_ERROR;
}

static enum drbd_ret_code
check_net_options(struct drbd_connection *connection, struct net_conf *new_net_conf)
{
	enum drbd_ret_code rv;
	struct drbd_peer_device *peer_device;
	int i;

	rcu_read_lock();
	rv = _check_net_options(connection, rcu_dereference(connection->transport.net_conf), new_net_conf);
	rcu_read_unlock();

	/* connection->peer_devices protected by resource->conf_update here */
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, i) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, i) {
#endif
		struct drbd_device *device = peer_device->device;
		if (!device->bitmap) {
			device->bitmap = drbd_bm_alloc();
			if (!device->bitmap)
				return ERR_NOMEM;
		}
	}

	return rv;
}

struct crypto {
	struct crypto_hash *verify_tfm;
	struct crypto_hash *csums_tfm;
	struct crypto_hash *cram_hmac_tfm;
	struct crypto_hash *integrity_tfm;
};

static int
alloc_hash(struct crypto_hash **tfm, char *tfm_name, int err_alg)
{
	if (!tfm_name[0])
		return NO_ERROR;
#ifdef _WIN32
    *tfm = crypto_alloc_hash(tfm_name, 0, CRYPTO_ALG_ASYNC, '41DW');
#else
	*tfm = crypto_alloc_hash(tfm_name, 0, CRYPTO_ALG_ASYNC);
#endif
	if (IS_ERR(*tfm)) {
		*tfm = NULL;
		return err_alg;
	}

	return NO_ERROR;
}

static enum drbd_ret_code
alloc_crypto(struct crypto *crypto, struct net_conf *new_net_conf)
{
#ifdef _WIN32
#define CRYPTO_MAX_ALG_NAME             64
#endif
	char hmac_name[CRYPTO_MAX_ALG_NAME];
	enum drbd_ret_code rv;

	rv = alloc_hash(&crypto->csums_tfm, new_net_conf->csums_alg,
		       ERR_CSUMS_ALG);
	if (rv != NO_ERROR)
		return rv;
	rv = alloc_hash(&crypto->verify_tfm, new_net_conf->verify_alg,
		       ERR_VERIFY_ALG);
	if (rv != NO_ERROR)
		return rv;
	rv = alloc_hash(&crypto->integrity_tfm, new_net_conf->integrity_alg,
		       ERR_INTEGRITY_ALG);
	if (rv != NO_ERROR)
		return rv;
	if (new_net_conf->cram_hmac_alg[0] != 0) {
		_snprintf(hmac_name, CRYPTO_MAX_ALG_NAME-1, "hmac(%s)",
			 new_net_conf->cram_hmac_alg);

		rv = alloc_hash(&crypto->cram_hmac_tfm, hmac_name,
			       ERR_AUTH_ALG);
	}

	return rv;
}

static void free_crypto(struct crypto *crypto)
{
	crypto_free_hash(crypto->cram_hmac_tfm);
	crypto_free_hash(crypto->integrity_tfm);
	crypto_free_hash(crypto->csums_tfm);
	crypto_free_hash(crypto->verify_tfm);
}

int drbd_adm_net_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;
	struct drbd_connection *connection;
	struct net_conf *old_net_conf, *new_net_conf = NULL;
	int err;
	int ovr; /* online verify running */
	int rsr; /* re-sync running */
#ifdef _WIN32
    struct crypto crypto = { 0 };
#else
	struct crypto crypto = { };
#endif
	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	connection = adm_ctx.connection;
	mutex_lock(&adm_ctx.resource->adm_mutex);
	
#ifdef _WIN32
    new_net_conf = kzalloc(sizeof(struct net_conf), GFP_KERNEL, 'A1DW');
#else
	new_net_conf = kzalloc(sizeof(struct net_conf), GFP_KERNEL);
#endif
	if (!new_net_conf) {
		retcode = ERR_NOMEM;
		goto out;
	}
#ifdef _WIN32
	drbd_flush_workqueue(adm_ctx.resource, &connection->sender_work);
#else
	drbd_flush_workqueue(&connection->sender_work);
#endif

	mutex_lock(&connection->resource->conf_update);
	mutex_lock(&connection->mutex[DATA_STREAM]);
	old_net_conf = connection->transport.net_conf;

	if (!old_net_conf) {
		drbd_msg_put_info(adm_ctx.reply_skb, "net conf missing, try connect");
		retcode = ERR_INVALID_REQUEST;
		goto fail;
	}

	*new_net_conf = *old_net_conf;
	if (should_set_defaults(info))
		set_net_conf_defaults(new_net_conf);

	err = net_conf_from_attrs_for_change(new_net_conf, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	retcode = check_net_options(connection, new_net_conf);
	if (retcode != NO_ERROR)
		goto fail;


#ifdef _WIN32 
	// DW-1436 unable to change send buffer size dynamically
	if (connection->cstate[NOW] >= C_CONNECTED){
		if (old_net_conf->sndbuf_size != new_net_conf->sndbuf_size){
			retcode = ERR_CANT_CHANGE_SNDBUF_SIZE_WHEN_CONNECTED;
			goto fail;
		}
	}

	// DW-1927 If the send buffer is not NULL, the del-peer command has not been executed.
	if (connection->ptxbab[DATA_STREAM] != NULL) {
		if (old_net_conf->sndbuf_size != new_net_conf->sndbuf_size){
			retcode = ERR_CANT_CHANGE_SNDBUF_SIZE_WITHOUT_DEL_PEER;
			goto fail;
		}
	}

#endif

	/* re-sync running */
	rsr = conn_resync_running(connection);
	if (rsr && strcmp(new_net_conf->csums_alg, old_net_conf->csums_alg)) {
		retcode = ERR_CSUMS_RESYNC_RUNNING;
		goto fail;
	}

	/* online verify running */
	ovr = conn_ov_running(connection);
	if (ovr && strcmp(new_net_conf->verify_alg, old_net_conf->verify_alg)) {
		retcode = ERR_VERIFY_RUNNING;
		goto fail;
	}

	retcode = alloc_crypto(&crypto, new_net_conf);
	if (retcode != NO_ERROR)
		goto fail;

#ifdef _WIN32
	synchronize_rcu_w32_wlock();
#endif
	rcu_assign_pointer(connection->transport.net_conf, new_net_conf);
	connection->fencing_policy = new_net_conf->fencing_policy;
#ifdef _WIN32
	synchronize_rcu();
#endif

	if (!rsr) {
		crypto_free_hash(connection->csums_tfm);
		connection->csums_tfm = crypto.csums_tfm;
		crypto.csums_tfm = NULL;
	}
	if (!ovr) {
		crypto_free_hash(connection->verify_tfm);
		connection->verify_tfm = crypto.verify_tfm;
		crypto.verify_tfm = NULL;
	}

	crypto_free_hash(connection->integrity_tfm);
	connection->integrity_tfm = crypto.integrity_tfm;
	if (connection->cstate[NOW] >= C_CONNECTED && connection->agreed_pro_version >= 100)
		/* Do this without trying to take connection->data.mutex again.  */
		__drbd_send_protocol(connection, P_PROTOCOL_UPDATE);

	crypto_free_hash(connection->cram_hmac_tfm);
	connection->cram_hmac_tfm = crypto.cram_hmac_tfm;

	mutex_unlock(&connection->mutex[DATA_STREAM]);
	mutex_unlock(&connection->resource->conf_update);
#ifndef _WIN32
	synchronize_rcu();
#endif
	kfree(old_net_conf);

	if (connection->cstate[NOW] >= C_CONNECTED) {
		struct drbd_peer_device *peer_device;
		int vnr;

#ifdef _WIN32
        idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr)
#else
		idr_for_each_entry(&connection->peer_devices, peer_device, vnr)
#endif
			drbd_send_sync_param(peer_device);
	}

	goto out;

 fail:
	mutex_unlock(&connection->mutex[DATA_STREAM]);
	mutex_unlock(&connection->resource->conf_update);
	free_crypto(&crypto);
	kfree(new_net_conf);
 out:
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int adjust_resync_fifo(struct drbd_peer_device *peer_device,
			      struct peer_device_conf *conf,
			      struct fifo_buffer **pp_old_plan)
{
	struct fifo_buffer *old_plan, *new_plan = NULL;
	int fifo_size;

	fifo_size = (conf->c_plan_ahead * 10 * SLEEP_TIME) / HZ;

	old_plan = rcu_dereference_protected(peer_device->rs_plan_s,
			     lockdep_is_held(&peer_device->connection->resource->conf_update));
	if (!old_plan || (unsigned int)fifo_size != old_plan->size) {
#ifdef _WIN32
        new_plan = fifo_alloc(fifo_size, '81DW');
#else
		new_plan = fifo_alloc(fifo_size);
#endif
		if (!new_plan) {
			drbd_err(peer_device, "kmalloc of fifo_buffer failed");
			return -ENOMEM;
		}
		rcu_assign_pointer(peer_device->rs_plan_s, new_plan);
		if (pp_old_plan)
			*pp_old_plan = old_plan;
	}

	return 0;
}

int drbd_adm_peer_device_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;
	struct drbd_peer_device *peer_device;
	struct peer_device_conf *old_peer_device_conf, *new_peer_device_conf = NULL;
	struct fifo_buffer *old_plan = NULL;
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	peer_device = adm_ctx.peer_device;

	mutex_lock(&adm_ctx.resource->adm_mutex);
	mutex_lock(&adm_ctx.resource->conf_update);

#ifdef _WIN32
    new_peer_device_conf = kzalloc(sizeof(struct peer_device_conf), GFP_KERNEL, '91DW');
#else
	new_peer_device_conf = kzalloc(sizeof(struct peer_device_conf), GFP_KERNEL);
#endif
	if (!new_peer_device_conf)
		goto fail;

	old_peer_device_conf = peer_device->conf;
	*new_peer_device_conf = *old_peer_device_conf;
	if (should_set_defaults(info))
		set_peer_device_conf_defaults(new_peer_device_conf);

	err = peer_device_conf_from_attrs_for_change(new_peer_device_conf, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail_ret_set;
	}

	if (!expect(peer_device, new_peer_device_conf->resync_rate >= 1))
		new_peer_device_conf->resync_rate = 1;

	if (new_peer_device_conf->c_plan_ahead > DRBD_C_PLAN_AHEAD_MAX)
		new_peer_device_conf->c_plan_ahead = DRBD_C_PLAN_AHEAD_MAX;

	err = adjust_resync_fifo(peer_device, new_peer_device_conf, &old_plan);
	if (err)
		goto fail;
#ifdef _WIN32
	synchronize_rcu_w32_wlock();
#endif
	drbd_info(peer_device, "new, resync_rate : %uk, c_plan_ahead : %uk, c_delay_target : %uk, c_fill_target : %uk, c_max_rate : %uk, c_min_rate : %uk\n", 
		new_peer_device_conf->resync_rate, new_peer_device_conf->c_plan_ahead, new_peer_device_conf->c_delay_target, 
		new_peer_device_conf->c_fill_target, new_peer_device_conf->c_max_rate, new_peer_device_conf->c_min_rate);

	rcu_assign_pointer(peer_device->conf, new_peer_device_conf);

	synchronize_rcu();
	kfree(old_peer_device_conf);
	kfree(old_plan);

	if (false,false) {
fail:
		retcode = ERR_NOMEM;
fail_ret_set:
		kfree(new_peer_device_conf);
	}

	mutex_unlock(&adm_ctx.resource->conf_update);
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;

}

int drbd_create_peer_device_default_config(struct drbd_peer_device *peer_device)
{
	struct peer_device_conf *conf;
	int err;

#ifdef _WIN32
    conf = kzalloc(sizeof(*conf), GFP_KERNEL, 'B1DW');
#else
	conf = kzalloc(sizeof(*conf), GFP_KERNEL);
#endif
	if (!conf)
		return -ENOMEM;

	set_peer_device_conf_defaults(conf);
	err = adjust_resync_fifo(peer_device, conf, NULL);
	if (err)
		return err;

	drbd_info(peer_device, "default, resync_rate : %uk, c_plan_ahead : %uk, c_delay_target : %uk, c_fill_target : %uk, c_max_rate : %uk, c_min_rate : %uk\n",
		conf->resync_rate, conf->c_plan_ahead, conf->c_delay_target,
		conf->c_fill_target, conf->c_max_rate, conf->c_min_rate);

	peer_device->conf = conf;

	return 0;
}

static void connection_to_info(struct connection_info *info,
			       struct drbd_connection *connection)
{
	info->conn_connection_state = connection->cstate[NOW];
	info->conn_role = connection->peer_role[NOW];
}

static void peer_device_to_info(struct peer_device_info *info,
				struct drbd_peer_device *peer_device)
{
	info->peer_repl_state = peer_device->repl_state[NOW];
	info->peer_disk_state = peer_device->disk_state[NOW];
	info->peer_resync_susp_user = peer_device->resync_susp_user[NOW];
	info->peer_resync_susp_peer = peer_device->resync_susp_peer[NOW];
	info->peer_resync_susp_dependency = peer_device->resync_susp_dependency[NOW];
	info->peer_is_intentional_diskless = !want_bitmap(peer_device);
}

static bool is_resync_target_in_other_connection(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_device *p;

	for_each_peer_device(p, device) {
		if (p == peer_device)
			continue;

		if (p->repl_state[NEW] == L_SYNC_TARGET)
			return true;
	}

	return false;
}

static int adm_new_connection(struct drbd_connection **ret_conn,
		struct drbd_config_context *adm_ctx, struct genl_info *info)
{
	struct connection_info connection_info;
	enum drbd_notification_type flags;
	unsigned int peer_devices = 0;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	struct net_conf *old_net_conf, *new_net_conf = NULL;
	struct crypto crypto = { NULL, };
	struct drbd_connection *connection;
	enum drbd_ret_code retcode;
	int i, err;
	char *transport_name;
	struct drbd_transport_class *tr_class;

	*ret_conn = NULL;
	if (adm_ctx->connection) {
#ifdef _WIN32
        struct drbd_resource * resource = adm_ctx->resource;
        drbd_err(resource, "Connection for peer node id %d already exists\n",
            adm_ctx->peer_node_id);
#else
		drbd_err(adm_ctx->resource, "Connection for peer node id %d already exists\n",
			 adm_ctx->peer_node_id);
#endif
		return ERR_INVALID_REQUEST;
	}

	/* allocation not in the IO path, drbdsetup / netlink process context */
#ifdef _WIN32
    new_net_conf = kzalloc(sizeof(*new_net_conf), GFP_KERNEL, 'E1DW');
#else
	new_net_conf = kzalloc(sizeof(*new_net_conf), GFP_KERNEL);
#endif
	if (!new_net_conf)
		return ERR_NOMEM;

	set_net_conf_defaults(new_net_conf);

	err = net_conf_from_attrs(new_net_conf, info);
	if (err) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx->reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	transport_name = new_net_conf->transport_name[0] ? new_net_conf->transport_name : "tcp";
	tr_class = drbd_get_transport_class(transport_name);
	if (!tr_class) {
		retcode = ERR_CREATE_TRANSPORT;
		goto fail;
	}

	connection = drbd_create_connection(adm_ctx->resource, tr_class);
	if (!connection) {
		retcode = ERR_NOMEM;
		goto fail_put_transport;
	}
	connection->peer_node_id = adm_ctx->peer_node_id;
	/* transport class reference now owned by connection,
	 * prevent double cleanup. */
	tr_class = NULL;

	retcode = check_net_options(connection, new_net_conf);
	if (retcode != NO_ERROR)
		goto fail_free_connection;

	retcode = alloc_crypto(&crypto, new_net_conf);
	if (retcode != NO_ERROR)
		goto fail_free_connection;

	((char *)new_net_conf->shared_secret)[SHARED_SECRET_MAX-1] = 0;

	mutex_lock(&adm_ctx->resource->conf_update);
#ifdef _WIN32
    idr_for_each_entry(struct drbd_device *, &adm_ctx->resource->devices, device, i) {
#else
	idr_for_each_entry(&adm_ctx->resource->devices, device, i) {
#endif
		int id;

		retcode = ERR_NOMEM;
		peer_device = create_peer_device(device, connection);
		if (!peer_device)
			goto unlock_fail_free_connection;
		id = idr_alloc(&connection->peer_devices, peer_device,
			       device->vnr, device->vnr + 1, GFP_KERNEL);
		if (id < 0)
			goto unlock_fail_free_connection;
	}

#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, i) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, i) {
#endif
		struct drbd_device *device = peer_device->device;

		peer_device->resync_susp_other_c[NOW] =
			is_resync_target_in_other_connection(peer_device);
		list_add_rcu(&peer_device->peer_devices, &device->peer_devices);
		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 3);
		kref_get(&device->kref);
		kref_debug_get(&device->kref_debug, 1);
		peer_devices++;
		peer_device->node_id = connection->peer_node_id;
	}
	spin_lock_irq(&adm_ctx->resource->req_lock);
	list_add_tail_rcu(&connection->connections, &adm_ctx->resource->connections);
	spin_unlock_irq(&adm_ctx->resource->req_lock);

	old_net_conf = connection->transport.net_conf;
	if (old_net_conf) {
		retcode = ERR_NET_CONFIGURED;
		goto unlock_fail_free_connection;
	}
	rcu_assign_pointer(connection->transport.net_conf, new_net_conf);
	connection->fencing_policy = new_net_conf->fencing_policy;

	connection->cram_hmac_tfm = crypto.cram_hmac_tfm;
	connection->integrity_tfm = crypto.integrity_tfm;
	connection->csums_tfm = crypto.csums_tfm;
	connection->verify_tfm = crypto.verify_tfm;

	/* transferred ownership. prevent double cleanup. */
	new_net_conf = NULL;
	memset(&crypto, 0, sizeof(crypto));

	if (connection->peer_node_id > adm_ctx->resource->max_node_id)
		adm_ctx->resource->max_node_id = connection->peer_node_id;

	/* Set bitmap_index if it was allocated previously */
#ifdef _WIN32
	idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, i) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, i) {
#endif
		unsigned int bitmap_index;

		device = peer_device->device;
		if (!get_ldev(device))
			continue;

		bitmap_index = device->ldev->md.peers[adm_ctx->peer_node_id].bitmap_index;
		if (bitmap_index != -1)
			peer_device->bitmap_index = bitmap_index;
		put_ldev(device); 
	}

	connection_to_info(&connection_info, connection);
	flags = (peer_devices--) ? NOTIFY_CONTINUES : 0;
	mutex_lock(&notification_mutex);
	notify_connection_state(NULL, 0, connection, &connection_info, NOTIFY_CREATE | flags);
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, i) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, i) {
#endif
		struct peer_device_info peer_device_info;

		peer_device_to_info(&peer_device_info, peer_device);
		flags = (peer_devices--) ? NOTIFY_CONTINUES : 0;
		notify_peer_device_state(NULL, 0, peer_device, &peer_device_info, NOTIFY_CREATE | flags);
	}
	mutex_unlock(&notification_mutex);

#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, i) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, i) {
#endif
		if (get_ldev_if_state(peer_device->device, D_NEGOTIATING)) {
			err = drbd_attach_peer_device(peer_device);
			put_ldev(peer_device->device);
			if (err) {
				retcode = ERR_NOMEM;
				goto unlock_fail_free_connection;
			}
		}
		peer_device->send_cnt = 0;
		peer_device->recv_cnt = 0;
	}
	mutex_unlock(&adm_ctx->resource->conf_update);

	// 
	// alloc_bab
	//
	if(alloc_bab(connection, connection->transport.net_conf)) {
	} else {
	}
	
	drbd_debugfs_connection_add(connection); /* after ->net_conf was assigned */
	drbd_thread_start(&connection->sender);
	*ret_conn = connection;
	return NO_ERROR;

unlock_fail_free_connection:
	mutex_unlock(&adm_ctx->resource->conf_update);
fail_free_connection:
	if (!list_empty(&connection->connections)) {
		drbd_unregister_connection(connection);
#ifndef _WIN32
		synchronize_rcu();
#endif
	}
	drbd_put_connection(connection);
fail_put_transport:
#ifndef _WIN32 // not support.
	drbd_put_transport_class(tr_class);
#endif
fail:
	free_crypto(&crypto);
	kfree(new_net_conf);

	return retcode;
}

#ifdef _WIN32
bool addr_eq_nla(const struct sockaddr_storage_win *addr, const int addr_len, const struct nlattr *nla)
#else
bool addr_eq_nla(const struct sockaddr_storage *addr, const int addr_len, const struct nlattr *nla)
#endif
{
	return	nla_len(nla) == addr_len && memcmp(nla_data(nla), addr, addr_len) == 0;
}

static enum drbd_ret_code
check_path_against_nla(const struct drbd_path *path,
		       const struct nlattr *my_addr, const struct nlattr *peer_addr)
{
	enum drbd_ret_code ret = NO_ERROR;

	if (addr_eq_nla(&path->my_addr, path->my_addr_len, my_addr))
		ret = ERR_LOCAL_ADDR;
	if (addr_eq_nla(&path->peer_addr, path->peer_addr_len, peer_addr))
		ret = (ret == ERR_LOCAL_ADDR ? ERR_LOCAL_AND_PEER_ADDR : ERR_PEER_ADDR);
	return ret;
}

static enum drbd_ret_code
check_path_usable(const struct drbd_config_context *adm_ctx,
		  const struct nlattr *my_addr, const struct nlattr *peer_addr)
{
	struct drbd_resource *resource;
	struct drbd_connection *connection;
	enum drbd_ret_code retcode;

	if (!(my_addr && peer_addr)) {
		drbd_msg_put_info(adm_ctx->reply_skb, "connection endpoint(s) missing");
		return ERR_INVALID_REQUEST;
	}

	/* No need for _rcu here. All reconfiguration is
	 * strictly serialized on resources_mutex. We are protected against
	 * concurrent reconfiguration/addition/deletion */
	for_each_resource(resource, &drbd_resources) {
		for_each_connection(connection, resource) {
			struct drbd_path *path;
#ifdef _WIN32
            list_for_each_entry(struct drbd_path, path, &connection->transport.paths, list) {
#else
			list_for_each_entry(path, &connection->transport.paths, list) {
#endif
				retcode = check_path_against_nla(path, my_addr, peer_addr);
				if (retcode == NO_ERROR)
					continue;
				/* Within the same resource, it is ok to use
				 * the same endpoint several times */
				if (retcode != ERR_LOCAL_AND_PEER_ADDR &&
				    resource == adm_ctx->resource)
					continue;
				return retcode;
			}
		}
	}
	return NO_ERROR;
}

static enum drbd_ret_code
adm_add_path(struct drbd_config_context *adm_ctx,  struct genl_info *info)
{
	struct drbd_transport *transport = &adm_ctx->connection->transport;
	struct nlattr *my_addr = NULL, *peer_addr = NULL;
	struct drbd_path *path;
	enum drbd_ret_code retcode;
	int err;

	/* parse and validate only */
	err = path_parms_from_attrs(NULL, info);
	if (err) {
		drbd_msg_put_info(adm_ctx->reply_skb, from_attrs_err_to_txt(err));
		return ERR_MANDATORY_TAG;
	}
	my_addr = nested_attr_tb[__nla_type(T_my_addr)];
	peer_addr = nested_attr_tb[__nla_type(T_peer_addr)];

	retcode = check_path_usable(adm_ctx, my_addr, peer_addr);
	if (retcode != NO_ERROR)
		return retcode;

#ifdef _WIN32
    path = kzalloc(transport->class->path_instance_size, GFP_KERNEL, '57DW');
#else
	path = kzalloc(transport->class->path_instance_size, GFP_KERNEL);
#endif
	if (!path)
		return ERR_NOMEM;

	path->my_addr_len = (int)nla_len(my_addr);
	memcpy(&path->my_addr, nla_data(my_addr), path->my_addr_len);
	path->peer_addr_len = nla_len(peer_addr);
	memcpy(&path->peer_addr, nla_data(peer_addr), path->peer_addr_len);

	kref_init(&path->kref);

	err = transport->ops->add_path(transport, path);
	if (err) {
		kref_put(&path->kref, drbd_destroy_path);
#ifdef _WIN32
        struct drbd_connection * connection = adm_ctx->connection;
        drbd_err(connection, "add_path() failed with %d\n", err);
#else
		drbd_err(adm_ctx->connection, "add_path() failed with %d\n", err);
#endif
		drbd_msg_put_info(adm_ctx->reply_skb, "add_path on transport failed");
		return ERR_INVALID_REQUEST;
	}
	notify_path(adm_ctx->connection, path, NOTIFY_CREATE);
	return NO_ERROR;
}

int drbd_adm_connect(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct connect_parms parms = { 0, };
	struct drbd_peer_device *peer_device;
	struct drbd_connection *connection;
	enum drbd_ret_code retcode;
	enum drbd_conn_state cstate;
	int i, err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	connection = adm_ctx.connection;
	cstate = connection->cstate[NOW];
	if (cstate != C_STANDALONE) {
#ifndef _WIN32	// MODIFIED_BY_MANTECH DW-1292 : skip if cstate is not StandAlone
		retcode = ERR_NET_CONFIGURED;
#endif
#ifdef _WIN32 /* MODIFIED_BY_MANTECH DW-1574 : Returns an error message to the user in the disconnecting status */
			  /* Disconnecting status will soon change the standalone status */
		if (cstate == C_DISCONNECTING){
			retcode = ERR_NET_CONFIGURED;
		}
#endif
		goto out;
	}

	if (first_path(connection) == NULL) {
		drbd_msg_put_info(adm_ctx.reply_skb, "connection endpoint(s) missing");
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}

	if (info->attrs[DRBD_NLA_CONNECT_PARMS]) {
		err = connect_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out;
		}
	}
	if (parms.discard_my_data) {
		if (adm_ctx.resource->role[NOW] == R_PRIMARY) {
			retcode = ERR_DISCARD_IMPOSSIBLE;
			goto out;
		}
		set_bit(CONN_DISCARD_MY_DATA, &connection->flags);
	}
	if (parms.tentative)
		set_bit(CONN_DRY_RUN, &connection->flags);

	/* Eventually allocate bitmap indexes for the peer_devices here */
#ifdef _WIN32
	idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, i) {
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, i) {
#endif 
		struct drbd_device *device;

		if (peer_device->bitmap_index != -1 || !want_bitmap(peer_device))
			continue;

		device = peer_device->device;
		if (!get_ldev(device))
			continue;

		err = allocate_bitmap_index(peer_device, device->ldev);
		put_ldev(device);
		if (err) {
			retcode = ERR_INVALID_REQUEST;
			goto out;
		}
		drbd_md_mark_dirty(device);
	}

	retcode = change_cstate_ex(connection, C_UNCONNECTED, CS_VERBOSE);

out:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_new_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_connection *connection;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_NODE);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);

	if (adm_ctx.connection) {
		retcode = ERR_INVALID_REQUEST;
		drbd_msg_put_info(adm_ctx.reply_skb, "peer connection already exists");
	} else {
		retcode = adm_new_connection(&connection, &adm_ctx, info);
	}

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_new_path(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	/* remote transport endpoints need to be globaly unique */
	mutex_lock(&resources_mutex);
	mutex_lock(&adm_ctx.resource->adm_mutex);

	retcode = adm_add_path(&adm_ctx, info);

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	mutex_unlock(&resources_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum drbd_ret_code
adm_del_path(struct drbd_config_context *adm_ctx,  struct genl_info *info)
{
	struct drbd_connection *connection = adm_ctx->connection;
	struct drbd_transport *transport = &connection->transport;
	struct nlattr *my_addr = NULL, *peer_addr = NULL;
#ifdef _WIN32
	struct drbd_path *path = NULL; 
#else
	struct drbd_path *path;
#endif
	int nr_paths = 0;
	int err;

	/* parse and validate only */
	err = path_parms_from_attrs(NULL, info);
	if (err) {
		drbd_msg_put_info(adm_ctx->reply_skb, from_attrs_err_to_txt(err));
		return ERR_MANDATORY_TAG;
	}
	my_addr = nested_attr_tb[__nla_type(T_my_addr)];
	peer_addr = nested_attr_tb[__nla_type(T_peer_addr)];
#ifdef _WIN32
	list_for_each_entry(struct drbd_path, path, &transport->paths, list)
#else
	list_for_each_entry(path, &transport->paths, list)
#endif
		nr_paths++;

	if (nr_paths == 1 && connection->cstate[NOW] >= C_CONNECTING) {
		drbd_msg_put_info(adm_ctx->reply_skb,
				  "Can not delete last path, use disconnect first!");
		return ERR_INVALID_REQUEST;
	}
	
	err = -ENOENT;
#ifdef _WIN32
    list_for_each_entry(struct drbd_path, path, &transport->paths, list) {
#else
	list_for_each_entry(path, &transport->paths, list) {
#endif
		if (!addr_eq_nla(&path->my_addr, path->my_addr_len, my_addr))
			continue;
		if (!addr_eq_nla(&path->peer_addr, path->peer_addr_len, peer_addr))
			continue;

		err = transport->ops->remove_path(transport, path);
		if (err)
			break;
#ifndef _WIN32
		synchronize_rcu();
#endif
		/* Transport modules might use RCU on the path list.
		   We do the synchronize_rcu() here in the generic code */
		INIT_LIST_HEAD(&path->list);
		notify_path(connection, path, NOTIFY_DESTROY);
		kref_put(&path->kref, drbd_destroy_path);
		return NO_ERROR;
	}

	drbd_err(connection, "del_path() failed with %d\n", err);
	drbd_msg_put_info(adm_ctx->reply_skb,
			  err == -ENOENT ? "no such path" : "del_path on transport failed");
	return ERR_INVALID_REQUEST;
}

int drbd_adm_del_path(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	/* remote transport endpoints need to be globaly unique */
	mutex_lock(&resources_mutex);
	mutex_lock(&adm_ctx.resource->adm_mutex);

	retcode = adm_del_path(&adm_ctx, info);

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	mutex_unlock(&resources_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_open_ro_count(struct drbd_resource *resource)
{
	struct drbd_device *device;
	int vnr, open_ro_cnt = 0;

	spin_lock_irq(&resource->req_lock);
#ifdef _WIN32
	idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr)
#else
	idr_for_each_entry(&resource->devices, device, vnr)
#endif
		open_ro_cnt += device->open_ro_cnt;
	spin_unlock_irq(&resource->req_lock);

	return open_ro_cnt;
}


static enum drbd_state_rv conn_try_disconnect(struct drbd_connection *connection, bool force,
					      struct sk_buff *reply_skb)
{
	struct drbd_resource *resource = connection->resource;
	enum drbd_conn_state cstate;
	enum drbd_state_rv rv;
	enum chg_state_flags flags = force ? CS_HARD : 0;
#ifdef _WIN32
	char *err_str = NULL;
	long t = 0;
#else
	const char *err_str = NULL;
	long t;
#endif 

repeat:
	//DW-1874
	if (flags)
		set_bit(FORCE_DISCONNECT, &connection->flags);

	rv = change_cstate_es(connection, C_DISCONNECTING, flags, &err_str, __FUNCTION__);
	switch (rv) {
	case SS_CW_FAILED_BY_PEER:
		spin_lock_irq(&resource->req_lock);
		cstate = connection->cstate[NOW];
		spin_unlock_irq(&resource->req_lock);
		if (cstate < C_CONNECTED)
			goto repeat;
		break; 
	case SS_NO_UP_TO_DATE_DISK:
		if (resource->role[NOW] == R_PRIMARY)
			break;
		/* Most probably udev opened it read-only. That might happen
		if it was demoted very recently. Wait up to one second. */
#ifdef _WIN32
		wait_event_interruptible_timeout(t, resource->state_wait,
			drbd_open_ro_count(resource) == 0,
			HZ);
#else
		t = wait_event_interruptible_timeout(resource->state_wait,
			drbd_open_ro_count(resource) == 0,
			HZ);
#endif
		if (t <= 0)
			break;
		goto repeat;
	case SS_ALREADY_STANDALONE:
		rv = SS_SUCCESS;
		break;
	case SS_IS_DISKLESS:
	case SS_LOWER_THAN_OUTDATED:
		rv = change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
		break;
	case SS_NO_QUORUM:
		if (!(flags & CS_VERBOSE)) {
			flags |= CS_VERBOSE;
			goto repeat;
		}
		break;
	default:;
		/* no special handling necessary */
	}

	if (rv >= SS_SUCCESS)
#ifdef _WIN32
	{
		long timeo;
		// DW-1574: Increase the wait time from 1 second to 3 seconds.
		wait_event_interruptible_timeout(timeo, resource->state_wait,
						 connection->cstate[NOW] == C_STANDALONE,
						 3*HZ);
	}
#else
		wait_event_interruptible_timeout(resource->state_wait,
						 connection->cstate[NOW] == C_STANDALONE,
						 HZ);
#endif
	if (err_str) {
		drbd_msg_put_info(reply_skb, err_str);
		kfree(err_str);
	}

	return rv;
}

/* this cann only be called immediately after a successful
 * conn_try_disconnect, within the same resource->adm_mutex */
void del_connection(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	enum drbd_state_rv rv2;
	int vnr;

	/* No one else can reconfigure the network while I am here.
	 * The state handling only uses drbd_thread_stop_nowait(),
	 * we want to really wait here until the receiver is no more.
	 */
	drbd_thread_stop(&connection->receiver);

	/* Race breaker.  This additional state change request may be
	 * necessary, if this was a forced disconnect during a receiver
	 * restart.  We may have "killed" the receiver thread just
	 * after drbd_receiver() returned.  Typically, we should be
	 * C_STANDALONE already, now, and this becomes a no-op.
	 */
	rv2 = change_cstate_ex(connection, C_STANDALONE, CS_VERBOSE | CS_HARD);
	if (rv2 < SS_SUCCESS)
		drbd_err(connection,
			"unexpected rv2=%d in del_connection()\n",
			rv2);
	/* Make sure the sender thread has actually stopped: state
	 * handling only does drbd_thread_stop_nowait().
	 */
	drbd_thread_stop(&connection->sender);

	drbd_unregister_connection(connection);

	/*
	 * Flush the resource work queue to make sure that no more
	 * events like state change notifications for this connection
	 * are queued: we want the "destroy" event to come last.
	 */
#ifdef _WIN32
	drbd_flush_workqueue(resource, &resource->work);
#else
	drbd_flush_workqueue(&resource->work);
#endif
	
	mutex_lock(&notification_mutex);
#ifdef _WIN32
    idr_for_each_entry(struct drbd_peer_device *, &connection->peer_devices, peer_device, vnr)
#else
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr)
#endif
		notify_peer_device_state(NULL, 0, peer_device, NULL,
					 NOTIFY_DESTROY | NOTIFY_CONTINUES);
	notify_connection_state(NULL, 0, connection, NULL, NOTIFY_DESTROY);
	mutex_unlock(&notification_mutex);
#ifdef _WIN32
	//_WIN32_V9_RCU //(1) synchronize_rcu_w32_wlock() is disabled, because Assertion: *** DPC watchdog timeout
#else
	synchronize_rcu();
#endif
	drbd_put_connection(connection);
}

int adm_disconnect(struct sk_buff *skb, struct genl_info *info, bool destroy)
{
	struct drbd_config_context adm_ctx;
	struct disconnect_parms parms;
	struct drbd_connection *connection;
	enum drbd_state_rv rv;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	memset(&parms, 0, sizeof(parms));
	if (info->attrs[DRBD_NLA_DISCONNECT_PARMS]) {
		int err = disconnect_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto fail;
		}
	}

	connection = adm_ctx.connection;
	mutex_lock(&adm_ctx.resource->adm_mutex);
	rv = conn_try_disconnect(connection, parms.force_disconnect, adm_ctx.reply_skb);
	if (rv >= SS_SUCCESS && destroy) {
		mutex_lock(&connection->resource->conf_update);
		del_connection(connection);
		mutex_unlock(&connection->resource->conf_update);
	}
	if (rv < SS_SUCCESS)
		retcode = rv;  /* FIXME: Type mismatch. */
	else
		retcode = NO_ERROR;
	mutex_unlock(&adm_ctx.resource->adm_mutex);
 fail:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_disconnect(struct sk_buff *skb, struct genl_info *info)
{
	return adm_disconnect(skb, info, 0);
}

int drbd_adm_del_peer(struct sk_buff *skb, struct genl_info *info)
{
	return adm_disconnect(skb, info, 1);
}

void resync_after_online_grow(struct drbd_peer_device *peer_device)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_device *device = peer_device->device;
	bool sync_source = false;
	s32 peer_id;

	drbd_info(peer_device, "Resync of new storage after online grow\n");
	if (device->resource->role[NOW] != connection->peer_role[NOW])
		sync_source = (device->resource->role[NOW] == R_PRIMARY);
	else if (connection->agreed_pro_version < 111)
		sync_source = test_bit(RESOLVE_CONFLICTS,
				&peer_device->connection->transport.flags);
	else if (get_ldev(device)) {
		/* multiple or no primaries, proto new enough, resolve by node-id */
		s32 self_id = device->ldev->md.node_id;
		put_ldev(device);
		peer_id = peer_device->node_id;

		sync_source = self_id < peer_id ? 1 : 0;
	}

	if (!sync_source && connection->agreed_pro_version < 110) {
		stable_change_repl_state(peer_device, L_WF_SYNC_UUID,
					 CS_VERBOSE | CS_SERIALIZE);
		return;
	}
	drbd_start_resync(peer_device, sync_source ? L_SYNC_SOURCE : L_SYNC_TARGET);
}

sector_t drbd_local_max_size(struct drbd_device *device) __must_hold(local)
{
	struct drbd_backing_dev *tmp_bdev;
	sector_t s;
#ifdef _WIN32
	tmp_bdev = kmalloc(sizeof(struct drbd_backing_dev), GFP_ATOMIC, '97DW');
#else
	tmp_bdev = kmalloc(sizeof(struct drbd_backing_dev), GFP_ATOMIC);

#endif
	if (!tmp_bdev)
		return 0;

	*tmp_bdev = *device->ldev;
	drbd_md_set_sector_offsets(device, tmp_bdev);
	s = drbd_get_max_capacity(tmp_bdev);
	kfree(tmp_bdev);

	return s;
}

int drbd_adm_resize(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
////	struct disk_conf *old_disk_conf, *new_disk_conf = NULL;
//	struct resize_parms rs;
//	struct drbd_device *device;
	enum drbd_ret_code retcode;
//	enum determine_dev_size dd;
//	bool change_al_layout = false;
//	enum dds_flags ddsf;
//	sector_t u_size;
//	int err;
//	struct drbd_peer_device *peer_device;
//	bool resolve_by_node_id = true;
//	bool has_up_to_date_primary;
//	bool traditional_resize = false;
//	sector_t local_max_size;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

#ifdef _WIN32
	// DW-1469 disable drbd_adm_resize
	drbd_msg_put_info(adm_ctx.reply_skb, "cmd(drbd_adm_resize) error: not support.\n");
	drbd_adm_finish(&adm_ctx, info, ERR_INVALID_REQUEST);
	return 0;
#endif
	
	//mutex_lock(&adm_ctx.resource->adm_mutex);
	//device = adm_ctx.device;
	//if (!get_ldev(device)) {
	//	retcode = ERR_NO_DISK;
	//	goto fail;
	//}
	//
	//memset(&rs, 0, sizeof(struct resize_parms));
	//rs.al_stripes = device->ldev->md.al_stripes;
	//rs.al_stripe_size = device->ldev->md.al_stripe_size_4k * 4;
	//if (info->attrs[DRBD_NLA_RESIZE_PARMS]) {
	//	err = resize_parms_from_attrs(&rs, info);
	//	if (err) {
	//		retcode = ERR_MANDATORY_TAG;
	//		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
	//		goto fail_ldev;
	//	}
	//}
	//
	//device = adm_ctx.device;
	//for_each_peer_device(peer_device, device) {
	//	if (peer_device->repl_state[NOW] > L_ESTABLISHED) {
	//		retcode = ERR_RESIZE_RESYNC;
	//		goto fail_ldev;
	//	}
	//}
	//
	//local_max_size = drbd_local_max_size(device);
	//if (rs.resize_size && local_max_size < (sector_t)rs.resize_size) {
	//	drbd_err(device, "requested %llu sectors, backend seems only able to support %llu\n",
	//		(unsigned long long)(sector_t)rs.resize_size,
	//		(unsigned long long)local_max_size);
	//	retcode = ERR_DISK_TOO_SMALL;
	//	goto fail_ldev;
	//}
	//
	///* Maybe I could serve as sync source myself? */
	//has_up_to_date_primary =
	//	device->resource->role[NOW] == R_PRIMARY &&
	//	device->disk_state[NOW] == D_UP_TO_DATE;
	//
	//if (!has_up_to_date_primary) {
	//	for_each_peer_device(peer_device, device) {
	//		/* ignore unless connection is fully established */
	//		if (peer_device->repl_state[NOW] < L_ESTABLISHED)
	//			continue;
	//		if (peer_device->connection->agreed_pro_version < 111) {
	//			resolve_by_node_id = false;
	//			if (peer_device->connection->peer_role[NOW] == R_PRIMARY                
	//			&&  peer_device->disk_state[NOW] == D_UP_TO_DATE) {
	//				has_up_to_date_primary = true;
	//				break;
	//			}
	//		}
	//	}
	//}
	//if (!has_up_to_date_primary && !resolve_by_node_id) {
	//	retcode = ERR_NO_PRIMARY;
	//	goto fail_ldev;
	//}
	//
	//for_each_peer_device(peer_device, device) {
	//	struct drbd_connection *connection = peer_device->connection;
	//	if (rs.no_resync &&
	//		connection->cstate[NOW] == C_CONNECTED &&
	//		connection->agreed_pro_version < 93) {
	//		retcode = ERR_NEED_APV_93;
	//		goto fail_ldev;
	//	}
	//}
	//
	//rcu_read_lock();
	//u_size = rcu_dereference(device->ldev->disk_conf)->disk_size;
	//rcu_read_unlock();
	//if (u_size != (sector_t)rs.resize_size) {
//#ifdef _WIN32
    //    new_disk_conf = kmalloc(sizeof(struct disk_conf), GFP_KERNEL, 'C1DW');
//#else
	//	new_disk_conf = kmalloc(sizeof(struct disk_conf), GFP_KERNEL);
//#endif
	//	if (!new_disk_conf) {
	//		retcode = ERR_NOMEM;
	//		goto fail_ldev;
	//	}
	//}
	//
	//if (device->ldev->md.al_stripes != rs.al_stripes ||
	//    device->ldev->md.al_stripe_size_4k != rs.al_stripe_size / 4) {
	//	u32 al_size_k = rs.al_stripes * rs.al_stripe_size;
	//
	//	if (al_size_k > (16 * 1024 * 1024)) {
	//		retcode = ERR_MD_LAYOUT_TOO_BIG;
	//		goto fail_ldev;
	//	}
	//
	//	if (al_size_k < (32768 >> 10)) {
	//		retcode = ERR_MD_LAYOUT_TOO_SMALL;
	//		goto fail_ldev;
	//	}
	//
	//	/* Removed this pre-condition while merging from 8.4 to 9.0
	//	if (device->state.conn != C_CONNECTED && !rs.resize_force) {
	//		retcode = ERR_MD_LAYOUT_CONNECTED;
	//		goto fail_ldev;
	//	} */
	//
	//	change_al_layout = true;
	//}
	//
	//device->ldev->known_size = drbd_get_capacity(device->ldev->backing_bdev);
	//
	//if (new_disk_conf) {
	//	mutex_lock(&device->resource->conf_update);
	//	old_disk_conf = device->ldev->disk_conf;
	//	*new_disk_conf = *old_disk_conf;
	//	new_disk_conf->disk_size = (sector_t)rs.resize_size;
//#ifdef _WIN32
	//	synchronize_rcu_w32_wlock();
//#endif
	//	rcu_assign_pointer(device->ldev->disk_conf, new_disk_conf);
	//	mutex_unlock(&device->resource->conf_update);
	//	synchronize_rcu();
	//	kfree(old_disk_conf);
	//	new_disk_conf = NULL;
	//}
	//
	//ddsf = (rs.resize_force ? DDSF_ASSUME_UNCONNECTED_PEER_HAS_SPACE : 0)
	//	| (rs.no_resync ? DDSF_NO_RESYNC : 0);
	//
	//dd = change_cluster_wide_device_size(device, local_max_size, rs.resize_size, ddsf,
	//			change_al_layout ? &rs : NULL);
	//if (dd == DS_2PC_NOT_SUPPORTED) {
	//	traditional_resize = true;
	//	dd = drbd_determine_dev_size(device, 0, ddsf, change_al_layout ? &rs : NULL);
	//}
	//
	//drbd_md_sync_if_dirty(device);
	//put_ldev(device);
	//if (dd == DS_ERROR) {
	//	retcode = ERR_NOMEM_BITMAP;
	//	goto fail;
	//} else if (dd == DS_ERROR_SPACE_MD) {
	//	retcode = ERR_MD_LAYOUT_NO_FIT;
	//	goto fail;
	//} else if (dd == DS_ERROR_SHRINK) {
	//	retcode = ERR_IMPLICIT_SHRINK;
	//	goto fail;
	//} else if (dd == DS_2PC_ERR) {
	//	retcode = SS_INTERRUPTED;
	//	goto fail;
	//}
	//
	//if (traditional_resize) {
	//	for_each_peer_device(peer_device, device) {
	//		if (peer_device->repl_state[NOW] == L_ESTABLISHED) {
	//			if (dd == DS_GREW)
	//				set_bit(RESIZE_PENDING, &peer_device->flags);
	//			drbd_send_uuids(peer_device, 0, 0);
	//			drbd_send_sizes(peer_device, rs.resize_size, ddsf);
	//		}
	//	}
	//}
	//
 //fail:
	//mutex_unlock(&adm_ctx.resource->adm_mutex);
	//drbd_adm_finish(&adm_ctx, info, retcode);
	//return 0;

 //fail_ldev:
	//put_ldev(device);
	//kfree(new_disk_conf);
	//goto fail;
}

int drbd_adm_resource_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;
	struct res_opts res_opts;
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	res_opts = adm_ctx.resource->res_opts;
	if (should_set_defaults(info))
		set_res_opts_defaults(&res_opts);

	err = res_opts_from_attrs_for_change(&res_opts, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	mutex_lock(&adm_ctx.resource->adm_mutex);
	err = set_resource_options(adm_ctx.resource, &res_opts);
	if (err) {
		retcode = ERR_INVALID_REQUEST;
		if (err == -ENOMEM)
			retcode = ERR_NOMEM;
	}
	mutex_unlock(&adm_ctx.resource->adm_mutex);

fail:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum drbd_state_rv invalidate_resync(struct drbd_peer_device *peer_device)
{
	struct drbd_resource *resource = peer_device->connection->resource;
	enum drbd_state_rv rv;

#ifdef _WIN32_DISABLE_RESYNC_FROM_SECONDARY
	// MODIFIED_BY_MANTECH DW-1142: don't start 'invalidate' if peer is not primary.
	if (peer_device->connection->peer_role[NOW] != R_PRIMARY)
		return SS_RESYNC_FROM_SECONDARY;
#endif

#ifdef _WIN32
	drbd_flush_workqueue(resource, &peer_device->connection->sender_work);
#else
	drbd_flush_workqueue(&peer_device->connection->sender_work);
#endif

	rv = change_repl_state(peer_device, L_STARTING_SYNC_T, CS_SERIALIZE);

	if (rv < SS_SUCCESS && rv != SS_NEED_CONNECTION)
		rv = stable_change_repl_state(peer_device, L_STARTING_SYNC_T,
			CS_VERBOSE | CS_SERIALIZE);
#ifdef _WIN32
	int t;
    wait_event_interruptible(t, resource->state_wait,
        peer_device->repl_state[NOW] != L_STARTING_SYNC_T);

	UNREFERENCED_PARAMETER(t);
#else
	wait_event_interruptible(resource->state_wait,
				 peer_device->repl_state[NOW] != L_STARTING_SYNC_T);
#endif
	return rv;
}

static enum drbd_state_rv invalidate_no_resync(struct drbd_device *device) __must_hold(local)
{
	struct drbd_resource *resource = device->resource;
	struct drbd_peer_device *peer_device;
	struct drbd_connection *connection;
	unsigned long irq_flags;
	enum drbd_state_rv rv;

	begin_state_change(resource, &irq_flags, CS_VERBOSE);
	for_each_connection(connection, resource) {
		peer_device = conn_peer_device(connection, device->vnr);
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED) {
			abort_state_change(resource, &irq_flags, __FUNCTION__);
			return SS_UNKNOWN_ERROR;
		}
	}
	__change_disk_state(device, D_INCONSISTENT, __FUNCTION__);
	rv = end_state_change(resource, &irq_flags, __FUNCTION__);

	if (rv >= SS_SUCCESS) {
		drbd_bitmap_io(device, &drbd_bmio_set_all_n_write,
			       "set_n_write from invalidate",
			       BM_LOCK_CLEAR | BM_LOCK_BULK,
			       NULL);
	}

	return rv;
}

int drbd_adm_invalidate(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_peer_device *sync_from_peer_device = NULL;
	struct drbd_resource *resource;
	struct drbd_device *device;
	int retcode = 0; /* enum drbd_ret_code rsp. enum drbd_state_rv */

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	device = adm_ctx.device;

	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto out_no_ldev;
	}

#ifdef _WIN32_STABLE_SYNCSOURCE
	struct drbd_peer_device *peer_device;
	for_each_peer_device(peer_device, device) {
		enum drbd_repl_state *repl_state = peer_device->repl_state;
		if ((repl_state[NEW] >= L_STARTING_SYNC_S && repl_state[NEW] <= L_WF_BITMAP_T) ||
			(repl_state[NEW] >= L_SYNC_SOURCE && repl_state[NEW] <= L_PAUSED_SYNC_T))
		{
#ifdef _WIN32_RCU_LOCKED
			if (repl_state[NOW] >= L_ESTABLISHED && !drbd_inspect_resync_side(peer_device, repl_state[NEW], NEW, false))
#else
			if (repl_state[NOW] >= L_ESTABLISHED && !drbd_inspect_resync_side(peer_device, repl_state[NEW], NEW))
#endif
				retcode = ERR_CODE_BASE;
				goto out_no_ldev;
		}
	}
#endif

	resource = device->resource;

	mutex_lock(&resource->adm_mutex);

	if (info->attrs[DRBD_NLA_INVALIDATE_PARMS]) {
#ifdef _WIN32
        struct invalidate_parms inv = { 0 };
#else
		struct invalidate_parms inv = {};
#endif
		int err;

		inv.sync_from_peer_node_id = -1;
		err = invalidate_parms_from_attrs(&inv, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out_no_resume;
		}

		if (inv.sync_from_peer_node_id != -1) {
			struct drbd_connection *connection =
				drbd_connection_by_node_id(resource, inv.sync_from_peer_node_id);
#ifdef _WIN32 // MODIFIED_BY_MANTECH DW-1134 fix crash for invalid peer node id
			if(connection == NULL) {
				retcode = ERR_INVALID_PEER_NODE_ID;
				drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
				goto out_no_resume;
			}
#endif			
			sync_from_peer_device = conn_peer_device(connection, device->vnr);
		}
	}

	/* If there is still bitmap IO pending, probably because of a previous
	 * resync just being finished, wait for it before requesting a new resync.
	 * Also wait for its after_state_ch(). */
	drbd_suspend_io(device, READ_AND_WRITE);
	wait_event(device->misc_wait, !atomic_read(&device->pending_bitmap_work.n));

	if (sync_from_peer_device) {
		retcode = invalidate_resync(sync_from_peer_device);
	} else {
		int retry = 3;
		do {
			struct drbd_connection *connection;
#ifdef _WIN32 // MODIFIED_BY_MANTECH DW-907
			int success = 0;
#endif

			for_each_connection(connection, resource) {
				struct drbd_peer_device *peer_device;

				peer_device = conn_peer_device(connection, device->vnr);
				retcode = invalidate_resync(peer_device);
				if (retcode >= SS_SUCCESS)
#ifdef _WIN32	
				// MODIFIED_BY_MANTECH DW-907: implicitly request to get synced to all peers, as a way of hedging first source node put out.
				{
					success = retcode;
				}
#else
					goto out;
#endif
			}
#ifdef _WIN32
			// MODIFIED_BY_MANTECH DW-907: retcode will be success at least one succeeded peer.
			if (success)
			{
				retcode = success;
				goto out;
			}
#endif

			if (retcode != SS_NEED_CONNECTION)
				break;

			retcode = invalidate_no_resync(device);
		} while (retcode == SS_UNKNOWN_ERROR && retry--);
	}

out:
	drbd_resume_io(device);
out_no_resume:
	mutex_unlock(&resource->adm_mutex);
	put_ldev(device);
out_no_ldev:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int drbd_bmio_set_susp_al(struct drbd_device *device, struct drbd_peer_device *peer_device) __must_hold(local)
{
	int rv;

	rv = drbd_bmio_set_n_write(device, peer_device);
	drbd_try_suspend_al(device);
	return rv;
}

int drbd_adm_invalidate_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_peer_device *peer_device;
	struct drbd_resource *resource;
	struct drbd_device *device;
	int retcode; /* enum drbd_ret_code rsp. enum drbd_state_rv */
#ifdef _WIN32
	// DW-1391
	long timeo = 5*HZ;
#endif

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	peer_device = adm_ctx.peer_device;
	device = peer_device->device;
	resource = device->resource;

#ifdef _WIN32_DISABLE_RESYNC_FROM_SECONDARY
	// MODIFIED_BY_MANTECH DW-1142: don't start 'invalidate peer' if I'm not primary.
	if (resource->role[NOW] != R_PRIMARY)
	{
		retcode = SS_RESYNC_FROM_SECONDARY;
		goto out;
	}
#endif
#ifdef _WIN32_STABLE_SYNCSOURCE
	struct drbd_peer_device *temp_peer_device;
	for_each_peer_device(temp_peer_device, device) {
		enum drbd_role *role = resource->role;
		enum drbd_repl_state *repl_state = temp_peer_device->repl_state;

		if (role[NOW] == R_SECONDARY && (repl_state[NOW] == L_STARTING_SYNC_T || repl_state[NOW] == L_WF_BITMAP_T) ||
			(repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T || repl_state[NOW] == L_VERIFY_T))
		{
			retcode = ERR_CODE_BASE;
			goto out;
		}
	}
#endif
	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto out;
	}

	mutex_lock(&resource->adm_mutex);

	drbd_suspend_io(device, READ_AND_WRITE);
	wait_event(device->misc_wait, !atomic_read(&device->pending_bitmap_work.n));
#ifdef _WIN32
	drbd_flush_workqueue(resource, &peer_device->connection->sender_work);
#else
	drbd_flush_workqueue(&peer_device->connection->sender_work);
#endif
	
	retcode = stable_change_repl_state(peer_device, L_STARTING_SYNC_S, CS_SERIALIZE);

	if (retcode < SS_SUCCESS) {
		if (retcode == SS_NEED_CONNECTION && resource->role[NOW] == R_PRIMARY) {
			/* The peer will get a resync upon connect anyways.
			 * Just make that into a full resync. */
			retcode = change_peer_disk_state(peer_device, D_INCONSISTENT,
							 CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE);
			if (retcode >= SS_SUCCESS) {
				if (drbd_bitmap_io(adm_ctx.device, &drbd_bmio_set_susp_al,
						   "set_n_write from invalidate_peer",
						   BM_LOCK_CLEAR | BM_LOCK_BULK, peer_device))
					retcode = ERR_IO_MD_DISK;
			}
		} else
			retcode = stable_change_repl_state(peer_device, L_STARTING_SYNC_S,
							   CS_VERBOSE | CS_SERIALIZE);
	}
	drbd_resume_io(device);

#ifdef _WIN32
	if (retcode >= SS_SUCCESS)
	{
		// DW-1391 : wait for bm_io_work to complete, then run the next invalidate peer. 
		wait_event_interruptible_timeout(retcode, resource->state_wait, 
				peer_device->repl_state[NOW] != L_STARTING_SYNC_S,
				timeo);
		if (-DRBD_SIGKILL == retcode)
		{ 
			retcode = SS_INTERRUPTED;
		}
		else if (-ETIMEDOUT == retcode)
		{
			retcode = SS_TIMEOUT;
		}
		else
		{
			retcode = SS_SUCCESS;
		}
	}
		
#endif
	
	mutex_unlock(&resource->adm_mutex);
	put_ldev(device);
out:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_pause_sync(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_peer_device *peer_device;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);

	peer_device = adm_ctx.peer_device;
	if (change_resync_susp_user(peer_device, true,
		CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE, __FUNCTION__) == SS_NOTHING_TO_DO)
		retcode = ERR_PAUSE_IS_SET;

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_resume_sync(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_peer_device *peer_device;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);

	peer_device = adm_ctx.peer_device;
	if (change_resync_susp_user(peer_device, false,
			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE, __FUNCTION__) == SS_NOTHING_TO_DO) {

		if (peer_device->repl_state[NOW] == L_PAUSED_SYNC_S ||
		    peer_device->repl_state[NOW] == L_PAUSED_SYNC_T) {
			if (peer_device->resync_susp_dependency[NOW])
				retcode = ERR_PIC_AFTER_DEP;
			else if (peer_device->resync_susp_peer[NOW])
				retcode = ERR_PIC_PEER_DEP;
			else
				retcode = ERR_PAUSE_IS_CLEAR;
		} else {
			retcode = ERR_PAUSE_IS_CLEAR;
		}
	}

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_suspend_io(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_resource *resource;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;
	resource = adm_ctx.device->resource;

#ifdef _WIN32
	// DW-1361 disable drbd_adm_suspend_io
	drbd_err(resource, "cmd(%u) error: drbd_adm_suspend_io not support.\n", info->genlhdr->cmd);
	drbd_adm_finish(&adm_ctx, info, -ENOMSG);
	return -ENOMSG;
#endif
	
//	mutex_lock(&resource->adm_mutex);
//#ifdef _WIN32 // DW-1605
//	stable_state_change(retcode, resource,
//		change_io_susp_user(resource, true,
//			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE));
//#else
//	retcode = stable_state_change(resource,
//		change_io_susp_user(resource, true,
//			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE));
//#endif
//
//	mutex_unlock(&resource->adm_mutex);
//	drbd_adm_finish(&adm_ctx, info, retcode);
//	return 0;
}

int drbd_adm_resume_io(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
//	struct drbd_connection *connection;
	struct drbd_resource *resource;
//	struct drbd_device *device;
//	unsigned long irq_flags;
	int retcode; /* enum drbd_ret_code rsp. enum drbd_state_rv */

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

#ifdef _WIN32
	// DW-1361 disable drbd_adm_resume_io
	resource = adm_ctx.device->resource;
	drbd_err(resource, "cmd(%u) error: drbd_adm_resume_io not support.\n", info->genlhdr->cmd);
	drbd_adm_finish(&adm_ctx, info, -ENOMSG);
	return -ENOMSG;
#endif

//	mutex_lock(&adm_ctx.resource->adm_mutex);
//	device = adm_ctx.device;
//	resource = device->resource;
//	if (test_and_clear_bit(NEW_CUR_UUID, &device->flags))
//		drbd_uuid_new_current(device, false);
//	drbd_suspend_io(device, READ_AND_WRITE);
//	begin_state_change(resource, &irq_flags, CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE);
//	__change_io_susp_user(resource, false);
//	__change_io_susp_no_data(resource, false);
//	for_each_connection(connection, resource)
//		__change_io_susp_fencing(connection, false);
//	__change_io_susp_quorum(device, false);
//	/* TODO: Throw away queued IO requests... */
//	retcode = end_state_change(resource, &irq_flags);
//	if (retcode == SS_SUCCESS) {
//		struct drbd_peer_device *peer_device;
//
//		for_each_peer_device(peer_device, device) {
//			struct drbd_connection *connection = peer_device->connection;
//
//			if (peer_device->repl_state[NOW] < L_ESTABLISHED)
//				tl_clear(connection);
//			if (device->disk_state[NOW] == D_DISKLESS ||
//			    device->disk_state[NOW] == D_FAILED ||
//			    device->disk_state[NOW] == D_DETACHING)
//				tl_restart(connection, FAIL_FROZEN_DISK_IO);
//		}
//	}
//	drbd_resume_io(device);
//	mutex_unlock(&adm_ctx.resource->adm_mutex);
//	drbd_adm_finish(&adm_ctx, info, retcode);
//	return 0;
}

int drbd_adm_outdate(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;
	mutex_lock(&adm_ctx.resource->adm_mutex);
#ifdef _WIN32 // DW-1605
	stable_state_change(retcode, adm_ctx.device->resource,
		change_disk_state(adm_ctx.device, D_OUTDATED,
			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE, NULL));
#else
	retcode = stable_state_change(adm_ctx.device->resource,
		change_disk_state(adm_ctx.device, D_OUTDATED,
			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE, NULL));
#endif

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int nla_put_drbd_cfg_context(struct sk_buff *skb,
				    struct drbd_resource *resource,
				    struct drbd_connection *connection,
				    struct drbd_device *device,
				    struct drbd_path *path)
{
	struct nlattr *nla;
	nla = nla_nest_start(skb, DRBD_NLA_CFG_CONTEXT);
	if (!nla)
		goto nla_put_failure;
	if (device)
		nla_put_u32(skb, T_ctx_volume, device->vnr);
	if (resource)
		nla_put_string(skb, T_ctx_resource_name, resource->name);
	if (connection) {
		nla_put_u32(skb, T_ctx_peer_node_id, connection->peer_node_id);
		rcu_read_lock();
		if (connection->transport.net_conf && connection->transport.net_conf->name)
			nla_put_string(skb, T_ctx_conn_name, connection->transport.net_conf->name);
		rcu_read_unlock();
	}
	if (path) {
		nla_put(skb, T_ctx_my_addr, path->my_addr_len, &path->my_addr);
		nla_put(skb, T_ctx_peer_addr, path->peer_addr_len, &path->peer_addr);
	}
	nla_nest_end(skb, nla);
	return 0;

nla_put_failure:
	if (nla)
		nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

/*
 * The generic netlink dump callbacks are called outside the genl_lock(), so
 * they cannot use the simple attribute parsing code which uses global
 * attribute tables.
 */
static struct nlattr *find_cfg_context_attr(const struct nlmsghdr *nlh, int attr)
{
	const unsigned hdrlen = GENL_HDRLEN + GENL_MAGIC_FAMILY_HDRSZ;
	const int maxtype = ARRAY_SIZE(drbd_cfg_context_nl_policy) - 1;
	struct nlattr *nla;

	nla = nla_find(nlmsg_attrdata(nlh, hdrlen), nlmsg_attrlen(nlh, hdrlen),
		       DRBD_NLA_CFG_CONTEXT);
	if (!nla)
		return NULL;
	return drbd_nla_find_nested(maxtype, nla, __nla_type(attr));
}

static void resource_to_info(struct resource_info *, struct drbd_resource *);

int drbd_adm_dump_resources(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct drbd_genlmsghdr *dh;
	struct drbd_resource *resource;
	struct resource_info resource_info;
	struct resource_statistics resource_statistics;
	int err;

	rcu_read_lock();
	if (cb->args[0]) {
		for_each_resource_rcu(resource, &drbd_resources)
			if (resource == (struct drbd_resource *)cb->args[0])
				goto found_resource;
		err = 0;  /* resource was probably deleted */
		goto out;
	}
	resource = list_entry(&drbd_resources,
			      struct drbd_resource, resources);

found_resource:
#ifdef _WIN32
    //list_for_each_entry_continue_rcu(struct drbd_resource, resource, &drbd_resources, resources) {
    //    goto put_result;
    //}
	resource = list_entry_rcu(resource->resources.next, struct drbd_resource, resources); 
	if (&resource->resources != (&drbd_resources))
		goto put_result;
#else
	list_for_each_entry_continue_rcu(resource, &drbd_resources, resources) {
		goto put_result;
	}
#endif
	err = 0;
	goto out;

put_result:
#ifdef _WIN32
	dh = genlmsg_put((struct msg_buff*)skb, NETLINK_CB_PORTID(cb->skb),
		cb->nlh->nlmsg_seq, &drbd_genl_family,
		NLM_F_MULTI, DRBD_ADM_GET_RESOURCES);
#else
	dh = genlmsg_put(skb, NETLINK_CB_PORTID(cb->skb),
		cb->nlh->nlmsg_seq, &drbd_genl_family,
		NLM_F_MULTI, DRBD_ADM_GET_RESOURCES);
#endif
	
	err = -ENOMEM;
	if (!dh)
		goto out;
	dh->minor = UINT32_MAX;
	dh->ret_code = NO_ERROR;

	// DW-1932 modify deadlock of rcu_read_lock
	rcu_read_unlock();
	err = nla_put_drbd_cfg_context(skb, resource, NULL, NULL, NULL);
	rcu_read_lock_w32_inner();

	if (err)
		goto out;
	err = res_opts_to_skb(skb, &resource->res_opts, !capable(CAP_SYS_ADMIN));
	if (err)
		goto out;
	resource_to_info(&resource_info, resource);
	err = resource_info_to_skb(skb, &resource_info, !capable(CAP_SYS_ADMIN));
	if (err)
		goto out;
	resource_statistics.res_stat_write_ordering = resource->write_ordering;
	resource_statistics.res_stat_req_write_cnt = resource->req_write_cnt;
	err = resource_statistics_to_skb(skb, &resource_statistics, !capable(CAP_SYS_ADMIN));
	if (err)
		goto out;
#ifdef _WIN32
    cb->args[0] = (LONG_PTR)resource;
#else
	cb->args[0] = (long)resource;
#endif
	genlmsg_end(skb, dh);
	err = 0;

out:
	rcu_read_unlock();
	if (err)
		return err;
	return skb->len;
}

static void device_to_statistics(struct device_statistics *s,
				 struct drbd_device *device)
{
	memset(s, 0, sizeof(*s));
	s->dev_upper_blocked = !may_inc_ap_bio(device);
	if (get_ldev(device)) {
		struct drbd_md *md = &device->ldev->md;
		u64 *history_uuids = (u64 *)s->history_uuids;
		struct request_queue *q;
		int n;

		spin_lock_irq(&md->uuid_lock);
		s->dev_current_uuid = md->current_uuid;
		BUILD_BUG_ON(sizeof(s->history_uuids) != sizeof(md->history_uuids));
		for (n = 0; n < ARRAY_SIZE(md->history_uuids); n++)
			history_uuids[n] = md->history_uuids[n];
		s->history_uuids_len = sizeof(s->history_uuids);
		spin_unlock_irq(&md->uuid_lock);

		s->dev_disk_flags = md->flags;
		q = bdev_get_queue(device->ldev->backing_bdev);
#ifndef _WIN32  // not support
		s->dev_lower_blocked =
			bdi_congested(q->backing_dev_info,
				      (1 << WB_async_congested) |
				      (1 << WB_sync_congested));
#endif
		put_ldev(device);
	}
	s->dev_size = drbd_get_capacity(device->this_bdev);
	s->dev_read = device->read_cnt;
	s->dev_write = device->writ_cnt;
	s->dev_al_writes = device->al_writ_cnt;
	s->dev_bm_writes = device->bm_writ_cnt;
	s->dev_upper_pending = atomic_read(&device->ap_bio_cnt[READ]) +
		atomic_read(&device->ap_bio_cnt[WRITE]);
	s->dev_lower_pending = atomic_read(&device->local_cnt);
	s->dev_al_suspended = test_bit(AL_SUSPENDED, &device->flags);
	s->dev_exposed_data_uuid = device->exposed_data_uuid;
}

static int put_resource_in_arg0(struct netlink_callback *cb, int holder_nr)
{
	if (cb->args[0]) {
		struct drbd_resource *resource =
			(struct drbd_resource *)cb->args[0];
		kref_debug_put(&resource->kref_debug, holder_nr); /* , 6); , 7); */
		kref_put(&resource->kref, drbd_destroy_resource);
	}

	return 0;
}

int drbd_adm_dump_devices_done(struct netlink_callback *cb) {
	return put_resource_in_arg0(cb, 7);
}

int drbd_adm_dump_devices(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *resource_filter;
	struct drbd_resource *resource;
#ifdef _WIN32
    struct drbd_device *device = NULL; 
	int minor = 0, err = 0, retcode = 0;
#else
	struct drbd_device *uninitialized_var(device);
	int minor, err, retcode;
#endif
	
	struct drbd_genlmsghdr *dh;
	struct device_info device_info;
	struct device_statistics device_statistics;
	struct idr *idr_to_search;

	resource = (struct drbd_resource *)cb->args[0];

	rcu_read_lock();
	if (!cb->args[0] && !cb->args[1]) {
		resource_filter = find_cfg_context_attr(cb->nlh, T_ctx_resource_name);
		if (resource_filter) {
			retcode = ERR_RES_NOT_KNOWN;
#ifdef _WIN32 // DW-900 to avoid the recursive lock
			rcu_read_unlock();
#endif
			resource = drbd_find_resource(nla_data(resource_filter));
#ifdef _WIN32 // DW-900 to avoid the recursive lock
			rcu_read_lock_w32_inner();
#endif
			if (!resource)
				goto put_result;
			kref_debug_get(&resource->kref_debug, 7);
#ifdef _WIN32
            cb->args[0] = (LONG_PTR)resource;
#else
			cb->args[0] = (long)resource;
#endif
		}
	}
#ifdef _WIN64
	BUG_ON_INT32_OVER(cb->args[1]);
#endif
	minor = (int)cb->args[1];
	idr_to_search = resource ? &resource->devices : &drbd_devices;
	device = idr_get_next(idr_to_search, &minor);
	if (!device) {
		err = 0;
		goto out;
	}
//#ifdef _WIN32
//    idr_for_each_entry_continue(struct drbd_device *, idr_to_search, device, minor) {
//#else
//	idr_for_each_entry_continue(idr_to_search, device, minor) {
//#endif
//		retcode = NO_ERROR;
//		goto put_result;  /* only one iteration */
//	}

	device = (struct drbd_device *)idr_get_next((idr_to_search), &(minor));
	if (device) {
			retcode = NO_ERROR;
			goto put_result;  /* only one iteration */
	}

	err = 0;
	goto out;  /* no more devices */

put_result:
#ifdef _WIN32
	dh = genlmsg_put((struct msg_buff*)skb, NETLINK_CB_PORTID(cb->skb),
		cb->nlh->nlmsg_seq, &drbd_genl_family,
		NLM_F_MULTI, DRBD_ADM_GET_DEVICES);
#else
	dh = genlmsg_put(skb, NETLINK_CB_PORTID(cb->skb),
		cb->nlh->nlmsg_seq, &drbd_genl_family,
		NLM_F_MULTI, DRBD_ADM_GET_DEVICES);
#endif
	
	err = -ENOMEM;
	if (!dh)
		goto out;
	dh->ret_code = retcode;
	dh->minor = UINT32_MAX;
	if (retcode == NO_ERROR) {
		dh->minor = device->minor;

		// DW-1932 modify deadlock of rcu_read_lock
		rcu_read_unlock();
		err = nla_put_drbd_cfg_context(skb, device->resource, NULL, device, NULL); 
		rcu_read_lock_w32_inner();

		if (err)
			goto out;
		if (get_ldev(device)) {
			struct disk_conf *disk_conf =
				rcu_dereference(device->ldev->disk_conf);

			err = disk_conf_to_skb(skb, disk_conf, !capable(CAP_SYS_ADMIN));
			put_ldev(device);
			if (err)
				goto out;
		}
		err = device_conf_to_skb(skb, &device->device_conf, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		device_to_info(&device_info, device);
		err = device_info_to_skb(skb, &device_info, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
#ifdef _WIN32 // DW-900 to avoid the recursive lock
		rcu_read_unlock();
#endif
		device_to_statistics(&device_statistics, device);
#ifdef _WIN32 // DW-900 to avoid the recursive lock
		rcu_read_lock_w32_inner();
#endif
		err = device_statistics_to_skb(skb, &device_statistics, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		cb->args[1] = minor + 1;
	}
	genlmsg_end(skb, dh);
	err = 0;

out:
	rcu_read_unlock();
	if (err)
		return err;
	return skb->len;
}

int drbd_adm_dump_connections_done(struct netlink_callback *cb)
{
	return put_resource_in_arg0(cb, 6);
}

int connection_paths_to_skb(struct sk_buff *skb, struct drbd_connection *connection)
{
	struct drbd_path *path;
	struct nlattr *tla = nla_nest_start(skb, DRBD_NLA_PATH_PARMS);
	if (!tla)
		goto nla_put_failure;

	/* array of such paths. */
#ifdef _WIN32
    list_for_each_entry(struct drbd_path, path, &connection->transport.paths, list) {
#else
	list_for_each_entry(path, &connection->transport.paths, list) {
#endif
		if (nla_put(skb, T_my_addr, path->my_addr_len, &path->my_addr))
			goto nla_put_failure;
		if (nla_put(skb, T_peer_addr, path->peer_addr_len, &path->peer_addr))
			goto nla_put_failure;
	}
	nla_nest_end(skb, tla);
	return 0;

nla_put_failure:
	if (tla)
		nla_nest_cancel(skb, tla);
	return -EMSGSIZE;
}

enum { SINGLE_RESOURCE, ITERATE_RESOURCES };

int drbd_adm_dump_connections(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *resource_filter;
	struct drbd_resource *resource = NULL, *next_resource;
#ifdef _WIN32
    struct drbd_connection *connection;
	connection = NULL; 
#else
	struct drbd_connection *uninitialized_var(connection);
#endif
	int err = 0, retcode;
	struct drbd_genlmsghdr *dh;
	struct connection_info connection_info;
	struct connection_statistics connection_statistics;

	rcu_read_lock();
	resource = (struct drbd_resource *)cb->args[0];
	if (!cb->args[0]) {
		resource_filter = find_cfg_context_attr(cb->nlh, T_ctx_resource_name);
		if (resource_filter) {
			retcode = ERR_RES_NOT_KNOWN;
#ifdef _WIN32 // DW-900 to avoid the recursive lock
			rcu_read_unlock();
#endif
			resource = drbd_find_resource(nla_data(resource_filter));
#ifdef _WIN32 // DW-900 to avoid the recursive lock
			rcu_read_lock_w32_inner();
#endif
			if (!resource)
				goto put_result;
			kref_debug_get(&resource->kref_debug, 6);
#ifdef _WIN32
            cb->args[0] = (LONG_PTR)resource;
#else
			cb->args[0] = (long)resource;
#endif
			cb->args[1] = SINGLE_RESOURCE;
		}
	}
	if (!resource) {
		if (list_empty(&drbd_resources))
			goto out;
		resource = list_first_entry(&drbd_resources, struct drbd_resource, resources);
		kref_get(&resource->kref);
		kref_debug_get(&resource->kref_debug, 6);
#ifdef _WIN32
        cb->args[0] = (LONG_PTR)resource;
#else
		cb->args[0] = (long)resource;
#endif
		cb->args[1] = ITERATE_RESOURCES;
	}

    next_resource:
	rcu_read_unlock();
	mutex_lock(&resource->conf_update);
#ifdef _WIN32
    rcu_read_lock_w32_inner();
#else
	rcu_read_lock();
#endif
	if (cb->args[2]) {
		for_each_connection_rcu(connection, resource)
			if (connection == (struct drbd_connection *)cb->args[2])
				goto found_connection;
		/* connection was probably deleted */
		goto no_more_connections;
	}
	connection = list_entry(&resource->connections, struct drbd_connection, connections);

found_connection:
#ifdef _WIN32
    //list_for_each_entry_continue_rcu(struct drbd_connection, connection, &resource->connections, connections) {
    //    retcode = NO_ERROR;
    //    goto put_result;  /* only one iteration */
    //}

	connection = list_entry_rcu(connection->connections.next, struct drbd_connection, connections);
	if(&connection->connections != &(resource->connections)) {        
		retcode = NO_ERROR;
		goto put_result;  /* only one iteration */
	}

#else
	list_for_each_entry_continue_rcu(connection, &resource->connections, connections) {
		retcode = NO_ERROR;
		goto put_result;  /* only one iteration */
	}
#endif

no_more_connections:
	if (cb->args[1] == ITERATE_RESOURCES) {
		for_each_resource_rcu(next_resource, &drbd_resources) {
			if (next_resource == resource)
				goto found_resource;
		}
		/* resource was probably deleted */
	}
	goto out;

found_resource:
//#ifdef _WIN32
//    list_for_each_entry_continue_rcu(struct drbd_resource, next_resource, &drbd_resources, resources) {
//#else
//	list_for_each_entry_continue_rcu(next_resource, &drbd_resources, resources) {
//#endif
//		mutex_unlock(&resource->conf_update);
//		kref_debug_put(&resource->kref_debug, 6);
//		kref_put(&resource->kref, drbd_destroy_resource);
//		resource = next_resource;
//		kref_get(&resource->kref);
//		kref_debug_get(&resource->kref_debug, 6);
//#ifdef _WIN32
//        cb->args[0] = (LONG_PTR)resource;
//#else
//		cb->args[0] = (long)resource;
//#endif
//		cb->args[2] = 0;
//		goto next_resource;
//	}

	next_resource = list_entry_rcu(next_resource->resources.next, struct drbd_resource, resources);
	if (&next_resource->resources != &(drbd_resources)) {
		mutex_unlock(&resource->conf_update);
		kref_debug_put(&resource->kref_debug, 6);
		kref_put(&resource->kref, drbd_destroy_resource);
		resource = next_resource;
		kref_get(&resource->kref);
		kref_debug_get(&resource->kref_debug, 6);
#ifdef _WIN32
		cb->args[0] = (LONG_PTR)resource;
#else
		cb->args[0] = (long)resource;
#endif
		cb->args[2] = 0;
		goto next_resource;
	}

	goto out;  /* no more resources */

put_result:
#ifdef _WIN32
	dh = genlmsg_put((struct msg_buff*)skb, NETLINK_CB_PORTID(cb->skb),
		cb->nlh->nlmsg_seq, &drbd_genl_family,
		NLM_F_MULTI, DRBD_ADM_GET_CONNECTIONS);
#else
	dh = genlmsg_put(skb, NETLINK_CB_PORTID(cb->skb),
		cb->nlh->nlmsg_seq, &drbd_genl_family,
		NLM_F_MULTI, DRBD_ADM_GET_CONNECTIONS);
#endif
	
	err = -ENOMEM;
	if (!dh)
		goto out;
	dh->ret_code = retcode;
	dh->minor = UINT32_MAX;
	if (retcode == NO_ERROR) {
		struct net_conf *net_conf;

		// DW-1932 modify deadlock of rcu_read_lock
		rcu_read_unlock();
		err = nla_put_drbd_cfg_context(skb, resource, connection, NULL, NULL);
		rcu_read_lock_w32_inner();

		if (err)
			goto out;
		net_conf = rcu_dereference(connection->transport.net_conf);
		if (net_conf) {
			err = net_conf_to_skb(skb, net_conf, !capable(CAP_SYS_ADMIN));
			if (err)
				goto out;
		}
		connection_to_info(&connection_info, connection);
		connection_paths_to_skb(skb, connection);
		err = connection_info_to_skb(skb, &connection_info, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		connection_statistics.conn_congested = test_bit(NET_CONGESTED, &connection->transport.flags);
		err = connection_statistics_to_skb(skb, &connection_statistics, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
#ifdef _WIN32
        cb->args[2] = (LONG_PTR)connection;
#else
		cb->args[2] = (long)connection;
#endif
	}
	genlmsg_end(skb, dh);
	err = 0;

out:
	rcu_read_unlock();
	if (resource)
		mutex_unlock(&resource->conf_update);
	if (err)
		return err;
	return skb->len;
}

static void peer_device_to_statistics(struct peer_device_statistics *s,
				      struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;

	memset(s, 0, sizeof(*s));
	s->peer_dev_received = peer_device->recv_cnt;
	s->peer_dev_sent = peer_device->send_cnt;
	s->peer_dev_pending = atomic_read(&peer_device->ap_pending_cnt) +
			      atomic_read(&peer_device->rs_pending_cnt);
	s->peer_dev_unacked = atomic_read(&peer_device->unacked_cnt);
#ifdef _WIN32 
	// MODIFIED_BY_MANTECH DW-953
	if (peer_device->repl_state[NOW] == L_VERIFY_S)
	{
		s->peer_dev_out_of_sync = drbd_bm_bits(device) - BM_SECT_TO_BIT(peer_device->ov_position);
	}
	else if (peer_device->repl_state[NOW] == L_VERIFY_T)
	{
		s->peer_dev_out_of_sync = peer_device->ov_left << (BM_BLOCK_SHIFT - 9);
	}
	else
	{
		s->peer_dev_out_of_sync = drbd_bm_total_weight(peer_device) << (BM_BLOCK_SHIFT - 9);
	}
#else
	s->peer_dev_out_of_sync = drbd_bm_total_weight(peer_device) << (BM_BLOCK_SHIFT - 9);
#endif
	s->peer_dev_resync_failed = peer_device->rs_failed << (BM_BLOCK_SHIFT - 9);
	if (get_ldev(device)) {
		struct drbd_md *md = &device->ldev->md;
		struct drbd_peer_md *peer_md = &md->peers[peer_device->node_id];

		spin_lock_irq(&md->uuid_lock);
		s->peer_dev_bitmap_uuid = peer_md->bitmap_uuid;
		spin_unlock_irq(&md->uuid_lock);
		s->peer_dev_flags = peer_md->flags;
		put_ldev(device);
	}
}

int drbd_adm_dump_peer_devices_done(struct netlink_callback *cb)
{
	return put_resource_in_arg0(cb, 9);
}

int drbd_adm_dump_peer_devices(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *resource_filter;
	struct drbd_resource *resource;
#ifdef _WIN32
    struct drbd_device *device = NULL;
#else
	struct drbd_device *uninitialized_var(device);
#endif
	struct drbd_peer_device *peer_device = NULL;
#ifdef _WIN32
	int minor = 0, err = 0, retcode = 0;
#else
	int minor, err, retcode;
#endif
	
	struct drbd_genlmsghdr *dh;
	struct idr *idr_to_search;

	resource = (struct drbd_resource *)cb->args[0];

	rcu_read_lock();
	if (!cb->args[0] && !cb->args[1]) {
		resource_filter = find_cfg_context_attr(cb->nlh, T_ctx_resource_name);
		if (resource_filter) {
			retcode = ERR_RES_NOT_KNOWN;
#ifdef _WIN32 // DW-900 to avoid the recursive lock
			rcu_read_unlock();
#endif
			resource = drbd_find_resource(nla_data(resource_filter));
#ifdef _WIN32 // DW-900 to avoid the recursive lock
			rcu_read_lock_w32_inner();
#endif
			if (!resource)
				goto put_result;

			kref_debug_get(&resource->kref_debug, 9);
		}
#ifdef _WIN32
        cb->args[0] = (LONG_PTR)resource;
#else
		cb->args[0] = (long)resource;
#endif
	}
#ifdef _WIN64
	BUG_ON_INT32_OVER(cb->args[1]);
#endif
	minor = (int)cb->args[1];
	idr_to_search = resource ? &resource->devices : &drbd_devices;
	device = idr_find(idr_to_search, minor);
	if (!device) {
next_device:
		minor++;
		cb->args[2] = 0;
		device = idr_get_next(idr_to_search, &minor);
		if (!device) {
			err = 0;
			goto out;
		}
	}
	if (cb->args[2]) {
		for_each_peer_device_rcu(peer_device, device)
			if (peer_device == (struct drbd_peer_device *)cb->args[2])
				goto found_peer_device;
		/* peer device was probably deleted */
		goto next_device;
	}
	/* Make peer_device point to the list head (not the first entry). */
	peer_device = list_entry(&device->peer_devices, struct drbd_peer_device, peer_devices);

found_peer_device:
#ifdef _WIN32
    //list_for_each_entry_continue_rcu(struct drbd_peer_device, peer_device, &device->peer_devices, peer_devices) {
    //    retcode = NO_ERROR;
    //    goto put_result;  /* only one iteration */
    //}

	peer_device = list_entry_rcu(peer_device->peer_devices.next, struct drbd_peer_device, peer_devices);
	if (&peer_device->peer_devices != &(device->peer_devices)) {
		retcode = NO_ERROR;
		goto put_result;  /* only one iteration */
	}


#else
	list_for_each_entry_continue_rcu(peer_device, &device->peer_devices, peer_devices) {
		retcode = NO_ERROR;
		goto put_result;  /* only one iteration */
	}
#endif
	goto next_device;

put_result:
#ifdef _WIN32
	dh = genlmsg_put((struct msg_buff*)skb, NETLINK_CB_PORTID(cb->skb),
		cb->nlh->nlmsg_seq, &drbd_genl_family,
		NLM_F_MULTI, DRBD_ADM_GET_PEER_DEVICES);
#else
	dh = genlmsg_put(skb, NETLINK_CB_PORTID(cb->skb),
		cb->nlh->nlmsg_seq, &drbd_genl_family,
		NLM_F_MULTI, DRBD_ADM_GET_PEER_DEVICES);
#endif
	
	err = -ENOMEM;
	if (!dh)
		goto out;
	dh->ret_code = retcode;
	dh->minor = UINT32_MAX;
	if (retcode == NO_ERROR) {
		struct peer_device_info peer_device_info;
		struct peer_device_statistics peer_device_statistics;
		struct peer_device_conf *peer_device_conf;

		dh->minor = minor;
#ifdef _WIN32 // DW-900 to avoid the recursive lock
		rcu_read_unlock();
#endif
		err = nla_put_drbd_cfg_context(skb, device->resource, peer_device->connection, device, NULL);
#ifdef _WIN32 // DW-900 to avoid the recursive lock
		rcu_read_lock_w32_inner();
#endif
		if (err)
			goto out;
		peer_device_to_info(&peer_device_info, peer_device);
		err = peer_device_info_to_skb(skb, &peer_device_info, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		peer_device_to_statistics(&peer_device_statistics, peer_device);
		err = peer_device_statistics_to_skb(skb, &peer_device_statistics, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		peer_device_conf = rcu_dereference(peer_device->conf);
		if (peer_device_conf) {
			err = peer_device_conf_to_skb(skb, peer_device_conf, !capable(CAP_SYS_ADMIN));
			if (err)
				goto out;
		}

		cb->args[1] = minor;
#ifdef _WIN32
        cb->args[2] = (LONG_PTR)peer_device;
#else
		cb->args[2] = (long)peer_device;
#endif
	}
	genlmsg_end(skb, dh);
	err = 0;

out:
	rcu_read_unlock();
	if (err)
		return err;
	return skb->len;
}

int drbd_adm_get_timeout_type(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_peer_device *peer_device;
	enum drbd_ret_code retcode;
	struct timeout_parms tp;
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;
	peer_device = adm_ctx.peer_device;

	tp.timeout_type =
		peer_device->disk_state[NOW] == D_OUTDATED ? UT_PEER_OUTDATED :
		test_bit(USE_DEGR_WFC_T, &peer_device->flags) ? UT_DEGRADED :
		UT_DEFAULT;

	err = timeout_parms_to_priv_skb(adm_ctx.reply_skb, &tp);
	if (err) {
		nlmsg_free(adm_ctx.reply_skb);
		return err;
	}

	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int drbd_adm_start_ov(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	enum drbd_ret_code retcode;
	struct start_ov_parms parms;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	peer_device = adm_ctx.peer_device;
	device = peer_device->device;

	/* resume from last known position, if possible */
	parms.ov_start_sector = peer_device->ov_start_sector;
	parms.ov_stop_sector = ULLONG_MAX;
	if (info->attrs[DRBD_NLA_START_OV_PARMS]) {
		int err = start_ov_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out;
		} 
	}
	mutex_lock(&adm_ctx.resource->adm_mutex);

	/* w_make_ov_request expects position to be aligned */
	peer_device->ov_start_sector = parms.ov_start_sector & ~(BM_SECT_PER_BIT-1);
	peer_device->ov_stop_sector = parms.ov_stop_sector;

	/* If there is still bitmap IO pending, e.g. previous resync or verify
	 * just being finished, wait for it before requesting a new resync. */
	drbd_suspend_io(device, READ_AND_WRITE);
	wait_event(device->misc_wait, !atomic_read(&device->pending_bitmap_work.n));
	retcode = stable_change_repl_state(peer_device,
		L_VERIFY_S, CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE);
	drbd_resume_io(device);

	mutex_unlock(&adm_ctx.resource->adm_mutex);
out:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static bool should_skip_initial_sync(struct drbd_peer_device *peer_device)
{
	return peer_device->repl_state[NOW] == L_ESTABLISHED &&
	       peer_device->connection->agreed_pro_version >= 90 &&
	       drbd_current_uuid(peer_device->device) == UUID_JUST_CREATED;
}

int drbd_adm_new_c_uuid(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	enum drbd_ret_code retcode;
	int err;
	struct new_c_uuid_parms args;
	u64 nodes = 0, diskfull = 0;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	device = adm_ctx.device;
	memset(&args, 0, sizeof(args));
	if (info->attrs[DRBD_NLA_NEW_C_UUID_PARMS]) {
		err = new_c_uuid_parms_from_attrs(&args, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out_nolock;
		}
	}

	mutex_lock(&adm_ctx.resource->adm_mutex);
	down(&device->resource->state_sem);

	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto out;
	}

	/* this is "skip initial sync", assume to be clean */
	for_each_peer_device(peer_device, device) {
		if (args.clear_bm && should_skip_initial_sync(peer_device)) {
			if (peer_device->disk_state[NOW] >= D_INCONSISTENT) {
				drbd_info(peer_device, "Preparing to skip initial sync\n");
				diskfull |= NODE_MASK(peer_device->node_id);
			}
			nodes |= NODE_MASK(peer_device->node_id);
		} else if (peer_device->repl_state[NOW] != L_OFF) {
			retcode = ERR_CONNECTED;
			goto out_dec;
		}

	}

	for_each_peer_device(peer_device, device)
		drbd_uuid_set_bitmap(peer_device, 0); /* Rotate UI_BITMAP to History 1, etc... */
	drbd_uuid_new_current_by_user(device); /* New current, previous to UI_BITMAP */

	if (args.clear_bm) {
		unsigned long irq_flags;

		err = drbd_bitmap_io(device, &drbd_bmio_clear_all_n_write,
			"clear_n_write from new_c_uuid", BM_LOCK_ALL, NULL);
		if (err) {
			drbd_err(device, "Writing bitmap failed with %d\n",err);
			retcode = ERR_IO_MD_DISK;
		}
		for_each_peer_device(peer_device, device) {
			if (NODE_MASK(peer_device->node_id) & nodes) {
				if (NODE_MASK(peer_device->node_id) & diskfull)
					drbd_send_uuids(peer_device, UUID_FLAG_SKIP_INITIAL_SYNC, 0);
				_drbd_uuid_set_bitmap(peer_device, 0);
				drbd_print_uuids(peer_device, "cleared bitmap UUID", __FUNCTION__);
			}
		}
		begin_state_change(device->resource, &irq_flags, CS_VERBOSE);
		__change_disk_state(device, D_UP_TO_DATE, __FUNCTION__);
		for_each_peer_device(peer_device, device) {
			if (NODE_MASK(peer_device->node_id) & diskfull)
				__change_peer_disk_state(peer_device, D_UP_TO_DATE, __FUNCTION__);
		}
		end_state_change(device->resource, &irq_flags, __FUNCTION__);
	}

	drbd_md_sync_if_dirty(device);
out_dec:
	put_ldev(device);
out:
	up(&device->resource->state_sem);
out_nolock:
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum drbd_ret_code
drbd_check_resource_name(struct drbd_config_context *adm_ctx)
{
	const char *name = adm_ctx->resource_name;
	if (!name || !name[0]) {
		drbd_msg_put_info(adm_ctx->reply_skb, "resource name missing");
		return ERR_MANDATORY_TAG;
	}
	/* As we want to use these in sysfs/configfs/debugfs,
	 * we must not allow slashes. */
	if (strchr(name, '/')) {
		drbd_msg_put_info(adm_ctx->reply_skb, "invalid resource name");
		return ERR_INVALID_REQUEST;
	}
	return NO_ERROR;
}

static void resource_to_info(struct resource_info *info,
			     struct drbd_resource *resource)
{
	info->res_role = resource->role[NOW];
	info->res_susp = resource->susp[NOW];
	info->res_susp_nod = resource->susp_nod[NOW];
	info->res_susp_fen = is_suspended_fen(resource, NOW);
	info->res_susp_quorum = is_suspended_quorum(resource, NOW);
}

int drbd_adm_new_resource(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_resource *resource;
	enum drbd_ret_code retcode;
	struct res_opts res_opts;
	int err;

#ifdef _PARALLEL_OPS
	mutex_lock(&resources_mutex);
#endif
	retcode = drbd_adm_prepare(&adm_ctx, skb, info, 0);
	if (!adm_ctx.reply_skb) {
#ifdef _PARALLEL_OPS
		mutex_unlock(&resources_mutex);
#endif		
		return retcode;
	}

	set_res_opts_defaults(&res_opts);
	err = res_opts_from_attrs(&res_opts, info);
	if (err) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto out;
	}

	retcode = drbd_check_resource_name(&adm_ctx);
	if (retcode != NO_ERROR)
		goto out;

	if (adm_ctx.resource)
		goto out;
#ifdef _WIN32
    if (res_opts.node_id >= DRBD_NODE_ID_MAX) {
#else
	if (res_opts.node_id < 0 || res_opts.node_id >= DRBD_NODE_ID_MAX) {
#endif
		pr_err("drbd: invalid node id (%d)\n", res_opts.node_id);
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}
#ifndef _WIN32
	if (!try_module_get(THIS_MODULE)) {
		pr_err("drbd: Could not get a module reference\n");
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}
#endif

#ifndef _PARALLEL_OPS
	mutex_lock(&resources_mutex);
#endif
	resource = drbd_create_resource(adm_ctx.resource_name, &res_opts);
#ifndef _PARALLEL_OPS
	mutex_unlock(&resources_mutex);
#endif
	if (resource) {
		struct resource_info resource_info;

		mutex_lock(&notification_mutex);
		resource_to_info(&resource_info, resource);
		notify_resource_state(NULL, 0, resource, &resource_info, NOTIFY_CREATE);
		mutex_unlock(&notification_mutex);

#ifdef _WIN32_MULTIVOL_THREAD
		NTSTATUS status;
		status = mvolInitializeThread(&resource->WorkThreadInfo, mvolWorkThread);
		if (!NT_SUCCESS(status)) {
			WDRBD_WARN("Failed to initialize WorkThread. status(0x%x)\n", status);
		}
#endif
		
	} else {
#ifndef _WIN32
		module_put(THIS_MODULE);
#endif
		retcode = ERR_NOMEM;
	}

out:
#ifdef _PARALLEL_OPS
	mutex_unlock(&resources_mutex);
#endif
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

void device_to_info(struct device_info *info,
			   struct drbd_device *device)
{
	info->dev_disk_state = device->disk_state[NOW];
	info->is_intentional_diskless = device->device_conf.intentional_diskless;
	info->io_error_count = atomic_read(&device->io_error_count); /* DW-1755 Pass the value for use when outputting the disk error count at the status command. */
}

int drbd_adm_new_minor(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_genlmsghdr *dh = info->userhdr;
	struct device_conf device_conf;
	struct drbd_resource *resource;
	struct drbd_device *device;
	enum drbd_ret_code retcode;
	int err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	set_device_conf_defaults(&device_conf);
	err = device_conf_from_attrs(&device_conf, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto out;
	}

	if (dh->minor > MINORMASK) {
		drbd_msg_put_info(adm_ctx.reply_skb, "requested minor out of range");
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}
	if (adm_ctx.volume > DRBD_VOLUME_MAX) {
		drbd_msg_put_info(adm_ctx.reply_skb, "requested volume id out of range");
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}

	if (adm_ctx.device)
		goto out;

	resource = adm_ctx.resource;
	mutex_lock(&resource->conf_update);
	for(;;) {
		retcode = drbd_create_device(&adm_ctx, dh->minor, &device_conf, &device);
		if (retcode != ERR_NOMEM ||
		    schedule_timeout_interruptible(HZ / 10))
			break;
		/* Keep retrying until the memory allocations eventually succeed. */
	}
	if (retcode == NO_ERROR) {
		struct drbd_peer_device *peer_device;
		struct device_info info;
		unsigned int peer_devices = 0;
		enum drbd_notification_type flags;

		for_each_peer_device(peer_device, device)
			peer_devices++;

		device_to_info(&info, device);
		mutex_lock(&notification_mutex);
		flags = (peer_devices--) ? NOTIFY_CONTINUES : 0;
		notify_device_state(NULL, 0, device, &info, NOTIFY_CREATE | flags);
		for_each_peer_device(peer_device, device) {
			struct peer_device_info peer_device_info;

			peer_device_to_info(&peer_device_info, peer_device);
			flags = (peer_devices--) ? NOTIFY_CONTINUES : 0;
			notify_peer_device_state(NULL, 0, peer_device, &peer_device_info,
						 NOTIFY_CREATE | flags);
		}
		mutex_unlock(&notification_mutex);
	}
	mutex_unlock(&resource->conf_update);
out:
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum drbd_ret_code adm_del_minor(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	struct drbd_peer_device *peer_device;
	enum drbd_ret_code ret;
	u64 im;

	spin_lock_irq(&resource->req_lock);
	if (device->disk_state[NOW] == D_DISKLESS &&
	    device->open_ro_cnt == 0 && device->open_rw_cnt == 0) {
		set_bit(UNREGISTERED, &device->flags);
		ret = NO_ERROR;
	} else {
		ret = ERR_MINOR_CONFIGURED;
	}
	spin_unlock_irq(&resource->req_lock);

	if (ret != NO_ERROR)
		return ret;

	for_each_peer_device_ref(peer_device, im, device)
		stable_change_repl_state(peer_device, L_OFF,
					 CS_VERBOSE | CS_WAIT_COMPLETE);

	/*
	 * Flush the resource work queue to make sure that no more events like
	 * state change notifications for this device are queued: we want the
	 * "destroy" event to come last.
	 */
#ifdef _WIN32
	drbd_flush_workqueue(resource, &resource->work);
#else
	drbd_flush_workqueue(&resource->work);
#endif
	
#ifdef _WIN32
    //synchronize_rcu_w32_wlock(); 	// _WIN32_V9_RCU //(2) this code is disabled for spinlock hang 
#endif
	drbd_unregister_device(device);

	mutex_lock(&notification_mutex);
	for_each_peer_device_ref(peer_device, im, device)
		notify_peer_device_state(NULL, 0, peer_device, NULL,
					 NOTIFY_DESTROY | NOTIFY_CONTINUES);
	notify_device_state(NULL, 0, device, NULL, NOTIFY_DESTROY);
	mutex_unlock(&notification_mutex);
#ifdef _WIN32
	// _WIN32_V9_RCU //(3)
#else
	synchronize_rcu();
#endif
	drbd_put_device(device);

	return ret;
}

int drbd_adm_del_minor(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);
	retcode = adm_del_minor(adm_ctx.device);
	mutex_unlock(&adm_ctx.resource->adm_mutex);

	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int adm_del_resource(struct drbd_resource *resource)
{
	int err;

	/*
	 * Flush the resource work queue to make sure that no more events like
	 * state change notifications are queued: we want the "destroy" event
	 * to come last.
	 */
#ifdef _WIN32
	drbd_flush_workqueue(resource, &resource->work);
#else
	drbd_flush_workqueue(&resource->work);
#endif
	
	mutex_lock(&resources_mutex);
	err = ERR_NET_CONFIGURED;
	if (!list_empty(&resource->connections))
		goto out;
	err = ERR_RES_IN_USE;
	if (!idr_is_empty(&resource->devices))
		goto out;
	err = NO_ERROR;

	mutex_lock(&notification_mutex);
	notify_resource_state(NULL, 0, resource, NULL, NOTIFY_DESTROY);
	mutex_unlock(&notification_mutex);

#ifdef _WIN32
    synchronize_rcu_w32_wlock();
#endif
	list_del_rcu(&resource->resources);
	drbd_debugfs_resource_cleanup(resource);
	synchronize_rcu();
	drbd_free_resource(resource);
out:
	mutex_unlock(&resources_mutex);
	return err;
}

int drbd_adm_down(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_resource *resource;
	struct drbd_connection *connection;
	struct drbd_device *device;
	int retcode; /* enum drbd_ret_code rsp. enum drbd_state_rv */
	enum drbd_ret_code ret;
	int i;
	u64 im;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info,
			DRBD_ADM_NEED_RESOURCE | DRBD_ADM_IGNORE_VERSION);
	if (!adm_ctx.reply_skb)
		return retcode;

	resource = adm_ctx.resource;

	mutex_lock(&resource->adm_mutex);
#ifdef _WIN32
	// DW-1317: acquire volume control mutex, not to conflict to (dis)mount volume.
	mutex_lock(&adm_ctx.resource->vol_ctl_mutex);
#endif

#ifdef _WIN32
	if (get_t_state(&resource->worker) != RUNNING) {		
		drbd_msg_put_info(adm_ctx.reply_skb, "resource already down");
		retcode = SS_NOTHING_TO_DO;
		goto out;
	}
#endif
	
	/* demote */
#ifdef _WIN32_MVFL
    // continue to dismount volume after drbdadm down is done.

#ifdef _WIN32_MULTI_VOLUME    
	int vnr;
	retcode = SS_SUCCESS;

	// DW-1461: set volume protection when going down. 
	idr_for_each_entry(struct drbd_device *, &adm_ctx.resource->devices, device, vnr)
	{
		PVOLUME_EXTENSION pvext = get_targetdev_by_minor(device->minor, FALSE);
		if (pvext)
		{
			SetDrbdlockIoBlock(pvext, TRUE);
		}
	}

	idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr)
	{
		if (device->disk_state[NOW] == D_DISKLESS)
		{
			continue;
		}
		if (!NT_SUCCESS(FsctlLockVolume(device->minor)))
		{
			continue;
		}
	}

	idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr)
	{
		if (device->disk_state[NOW] == D_DISKLESS)
		{
			continue;
		}

		resource->bPreDismountLock = TRUE;
		NTSTATUS status = FsctlFlushDismountVolume(device->minor, true);			
		if (!NT_SUCCESS(status))
		{
			retcode = SS_UNKNOWN_ERROR;
			resource->bPreDismountLock = FALSE;
			break;
		}		
	}
				
	if (retcode == SS_SUCCESS) {
		resource->bPreSecondaryLock = TRUE;
		retcode = drbd_set_role(resource, R_SECONDARY, false, adm_ctx.reply_skb);
		if (retcode < SS_SUCCESS)
		{
			drbd_msg_put_info(adm_ctx.reply_skb, "failed to demote");
		}
		resource->bPreSecondaryLock = FALSE;
		resource->bPreDismountLock = FALSE;
	}

	idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr)
	{
		if (device->disk_state[NOW] == D_DISKLESS)
		{
			continue;
		}
		FsctlUnlockVolume(device->minor);
	}

	
	if(retcode < SS_SUCCESS)
	{
		goto out;
	}
#else
    idr_for_each_entry(struct drbd_device *, &resource->devices, device, i)
    {
		PVOLUME_EXTENSION pvext = get_targetdev_by_minor(device->minor);
		if (pvext)
		{
			SetDrbdlockIoBlock(pvext, TRUE);
		}

        if (D_DISKLESS == device->disk_state[NOW])
        {
            retcode = drbd_set_role(resource, R_SECONDARY, false);
        }
        else if (NT_SUCCESS(FsctlLockVolume(device->minor)))
        {
            
			resource->bPreDismountLock = TRUE;
            NTSTATUS status = FsctlFlushDismountVolume(device->minor, true);
			resource->bPreSecondaryLock = TRUE;
            FsctlUnlockVolume(device->minor);

            if (!NT_SUCCESS(status))
            {
                retcode = ERR_RES_NOT_KNOWN;
				resource->bPreDismountLock = FALSE;
                goto out;
            }

			retcode = drbd_set_role(resource, R_SECONDARY, false);
			resource->bPreSecondaryLock = FALSE;
			resource->bPreDismountLock = FALSE;
			if (retcode < SS_SUCCESS)
            {
                drbd_msg_put_info(adm_ctx.reply_skb, "failed to demote");
                FsctlUnlockVolume(device->minor);
                goto out;
            }
        }
        else
        {
            retcode = ERR_RES_IN_USE;
            goto out;
        }
    }
#endif
#else
	retcode = drbd_set_role(resource, R_SECONDARY, false);
	if (retcode < SS_SUCCESS) {
		drbd_msg_put_info(adm_ctx.reply_skb, "failed to demote");
		goto out;
	}
#endif

	for_each_connection_ref(connection, im, resource) {
		retcode = conn_try_disconnect(connection, 0, adm_ctx.reply_skb);
		if (retcode >= SS_SUCCESS) {

			mutex_lock(&resource->conf_update);
#ifdef _WIN32
			// DW-1931 vol_ctl_mutex deadlock in function SetOOSAllocatedCluster()
			mutex_unlock(&adm_ctx.resource->vol_ctl_mutex);
#endif
			del_connection(connection);
#ifdef _WIN32
			// DW-1931  
			mutex_lock(&adm_ctx.resource->vol_ctl_mutex);

#endif
			mutex_unlock(&resource->conf_update);
		} else {
			drbd_info(connection, "conn_try_disconnect retcode : %d, connection ref : %d\n", retcode, connection->kref);
			kref_debug_put(&connection->kref_debug, 13);
			kref_put(&connection->kref, drbd_destroy_connection);
			goto out;
		}
	}

	
	/* detach and delete minor */
	rcu_read_lock();
#ifdef _WIN32
    idr_for_each_entry(struct drbd_device *, &resource->devices, device, i) {
#else
	idr_for_each_entry(&resource->devices, device, i) {
#endif
		kref_get(&device->kref);
		rcu_read_unlock();
		retcode = adm_detach(device, 0, adm_ctx.reply_skb);
		mutex_lock(&resource->conf_update);
		ret = adm_del_minor(device);
		mutex_unlock(&resource->conf_update);
		kref_put(&device->kref, drbd_destroy_device);
		if (retcode < SS_SUCCESS || retcode > NO_ERROR) {
			drbd_msg_put_info(adm_ctx.reply_skb, "failed to detach");
			goto out;
		}
		if (ret != NO_ERROR) {
			/* "can not happen" */
			drbd_msg_put_info(adm_ctx.reply_skb, "failed to delete volume");
			goto out;
		}
		rcu_read_lock();
	}
	rcu_read_unlock();

	mutex_lock(&resource->conf_update);
	retcode = adm_del_resource(resource);
	/* holding a reference to resource in adm_crx until drbd_adm_finish() */
	mutex_unlock(&resource->conf_update);
out:
#ifdef _WIN32
	// DW-1317
	mutex_unlock(&adm_ctx.resource->vol_ctl_mutex);
#endif
	mutex_unlock(&resource->adm_mutex);
	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}


int drbd_adm_del_resource(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	enum drbd_ret_code retcode;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	retcode = adm_del_resource(adm_ctx.resource);

	drbd_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int nla_put_notification_header(struct sk_buff *msg,
				       enum drbd_notification_type type)
{
	struct drbd_notification_header nh = {
		.nh_type = type,
	};

	return drbd_notification_header_to_skb(msg, &nh, true);
}

void notify_resource_state(struct sk_buff *skb,
			   unsigned int seq,
			   struct drbd_resource *resource,
			   struct resource_info *resource_info,
			   enum drbd_notification_type type)
{
	struct resource_statistics resource_statistics;
	struct drbd_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&drbd_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
#ifdef _WIN32
	dh = genlmsg_put((struct msg_buff*)skb, 0, seq, &drbd_genl_family, 0, DRBD_RESOURCE_STATE);
#else
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_RESOURCE_STATE);
#endif
	
	if (!dh)
		goto nla_put_failure;
	dh->minor = UINT32_MAX;
	dh->ret_code = NO_ERROR;
	if (nla_put_drbd_cfg_context(skb, resource, NULL, NULL, NULL) ||
	    nla_put_notification_header(skb, type) ||
	    ((type & ~NOTIFY_FLAGS) != NOTIFY_DESTROY &&
	     resource_info_to_skb(skb, resource_info, true)))
		goto nla_put_failure;
	resource_statistics.res_stat_write_ordering = resource->write_ordering;
	resource_statistics.res_stat_req_write_cnt = resource->req_write_cnt;
	err = resource_statistics_to_skb(skb, &resource_statistics, !capable(CAP_SYS_ADMIN));
	if (err)
		goto nla_put_failure;
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

nla_put_failure:
	nlmsg_free(skb);
failed:
	drbd_err(resource, "Error %d while broadcasting event. Event seq:%u\n",
			err, seq);
}

void notify_device_state(struct sk_buff *skb,
			 unsigned int seq,
			 struct drbd_device *device,
			 struct device_info *device_info,
			 enum drbd_notification_type type)
{
	struct device_statistics device_statistics;
	struct drbd_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&drbd_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
#ifdef _WIN32
	dh = genlmsg_put((struct msg_buff*)skb, 0, seq, &drbd_genl_family, 0, DRBD_DEVICE_STATE);
#else
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_DEVICE_STATE);
#endif
	
	if (!dh)
		goto nla_put_failure;
	dh->minor = device->minor;
	dh->ret_code = NO_ERROR;
	if (nla_put_drbd_cfg_context(skb, device->resource, NULL, device, NULL) ||
	    nla_put_notification_header(skb, type) ||
	    ((type & ~NOTIFY_FLAGS) != NOTIFY_DESTROY &&
	     device_info_to_skb(skb, device_info, true)))
		goto nla_put_failure;
	device_to_statistics(&device_statistics, device);
	device_statistics_to_skb(skb, &device_statistics, !capable(CAP_SYS_ADMIN));
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

nla_put_failure:
	nlmsg_free(skb);
failed:
	drbd_err(device, "Error %d while broadcasting event. Event seq:%u\n",
		 err, seq);
}

/* open coded path_parms_to_skb() iterating of the list */
void notify_connection_state(struct sk_buff *skb,
			     unsigned int seq,
			     struct drbd_connection *connection,
			     struct connection_info *connection_info,
			     enum drbd_notification_type type)
{
	struct connection_statistics connection_statistics;
	struct drbd_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&drbd_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
#ifdef _WIN32
	dh = genlmsg_put((struct msg_buff*)skb, 0, seq, &drbd_genl_family, 0, DRBD_CONNECTION_STATE);
#else
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_CONNECTION_STATE);
#endif
	
	if (!dh)
		goto nla_put_failure;
	dh->minor = UINT32_MAX;
	dh->ret_code = NO_ERROR;
	if (nla_put_drbd_cfg_context(skb, connection->resource, connection, NULL, NULL) ||
	    nla_put_notification_header(skb, type) ||
	    ((type & ~NOTIFY_FLAGS) != NOTIFY_DESTROY &&
	     connection_info_to_skb(skb, connection_info, true)))
		goto nla_put_failure;
	connection_paths_to_skb(skb, connection);
	connection_statistics.conn_congested = test_bit(NET_CONGESTED, &connection->transport.flags);
	connection_statistics_to_skb(skb, &connection_statistics, !capable(CAP_SYS_ADMIN));
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

nla_put_failure:
	nlmsg_free(skb);
failed:
	drbd_err(connection, "Error %d while broadcasting event. Event seq:%u\n",
		 err, seq);
}

void notify_peer_device_state(struct sk_buff *skb,
			      unsigned int seq,
			      struct drbd_peer_device *peer_device,
			      struct peer_device_info *peer_device_info,
			      enum drbd_notification_type type)
{
	struct peer_device_statistics peer_device_statistics;
	struct drbd_resource *resource = peer_device->device->resource;
	struct drbd_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&drbd_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
#ifdef _WIN32
	dh = genlmsg_put((struct msg_buff*)skb, 0, seq, &drbd_genl_family, 0, DRBD_PEER_DEVICE_STATE);
#else
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_PEER_DEVICE_STATE);
#endif
	
	if (!dh)
		goto nla_put_failure;
	dh->minor = UINT32_MAX;
	dh->ret_code = NO_ERROR;
	if (nla_put_drbd_cfg_context(skb, resource, peer_device->connection, peer_device->device, NULL) ||
	    nla_put_notification_header(skb, type) ||
	    ((type & ~NOTIFY_FLAGS) != NOTIFY_DESTROY &&
	     peer_device_info_to_skb(skb, peer_device_info, true)))
		goto nla_put_failure;
	peer_device_to_statistics(&peer_device_statistics, peer_device);
	peer_device_statistics_to_skb(skb, &peer_device_statistics, !capable(CAP_SYS_ADMIN));
	genlmsg_end(skb, dh);
	if (multicast) {
		err = drbd_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

nla_put_failure:
	nlmsg_free(skb);
failed:
	drbd_err(peer_device, "Error %d while broadcasting event. Event seq:%u\n",
		 err, seq);
}
				  
void notify_io_error(struct drbd_device *device, struct drbd_io_error *io_error)
{
	struct drbd_io_error_info io_error_info;
	io_error_info.error_code = io_error->error_code;
	io_error_info.sector = io_error->sector;
	io_error_info.size = io_error->size;
	io_error_info.disk_type = io_error->disk_type;
	io_error_info.io_type = io_error->io_type;
	io_error_info.is_cleared = io_error->is_cleared;
	
	unsigned int seq = atomic_inc_return(&drbd_genl_seq);
	struct sk_buff *skb = NULL;
	struct drbd_genlmsghdr *dh;
	int err;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
	err = -ENOMEM;
	if (!skb)
		goto fail;

	err = -EMSGSIZE;
#ifdef _WIN32
	dh = genlmsg_put((struct msg_buff*)skb, 0, seq, &drbd_genl_family, 0, DRBD_IO_ERROR);
#else
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_PATH_STATE);
#endif
	
	if (!dh)
		goto fail;

	dh->minor = device->minor;
	dh->ret_code = NO_ERROR;
	mutex_lock(&notification_mutex);
	if (nla_put_drbd_cfg_context(skb, device->resource, NULL, device, NULL) ||
		nla_put_notification_header(skb, NOTIFY_ERROR) ||
		drbd_io_error_info_to_skb(skb, &io_error_info, true))
		goto unlock_fail;

	genlmsg_end(skb, dh);
	err = drbd_genl_multicast_events(skb, GFP_NOWAIT);
	skb = NULL;
	/* skb has been consumed or freed in netlink_broadcast() */
	if (err && err != -ESRCH)
		goto unlock_fail;
	mutex_unlock(&notification_mutex);
	return;

unlock_fail:
	mutex_unlock(&notification_mutex);
fail:
#ifdef _WIN32 // DW-1556 fix DV crash, NULL dereference
	if(skb)
		nlmsg_free(skb);
#else 
	nlmsg_free(skb);
#endif
}

void notify_path(struct drbd_connection *connection, struct drbd_path *path,
		 enum drbd_notification_type type)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_path_info path_info;
	unsigned int seq = atomic_inc_return(&drbd_genl_seq);
	struct sk_buff *skb = NULL;
	struct drbd_genlmsghdr *dh;
	int err;

	path_info.path_established = path->established;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
	err = -ENOMEM;
	if (!skb)
		goto fail;

	err = -EMSGSIZE;
#ifdef _WIN32
	dh = genlmsg_put((struct msg_buff*)skb, 0, seq, &drbd_genl_family, 0, DRBD_PATH_STATE);
#else
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_PATH_STATE);
#endif
	
	if (!dh)
		goto fail;

	dh->minor = UINT32_MAX;
	dh->ret_code = NO_ERROR;
	mutex_lock(&notification_mutex);
	if (nla_put_drbd_cfg_context(skb, resource, connection, NULL, path) ||
	    nla_put_notification_header(skb, type) ||
	    drbd_path_info_to_skb(skb, &path_info, true))
		goto unlock_fail;

	genlmsg_end(skb, dh);
	err = drbd_genl_multicast_events(skb, GFP_NOWAIT);
	skb = NULL;
	/* skb has been consumed or freed in netlink_broadcast() */
	if (err && err != -ESRCH)
		goto unlock_fail;
	mutex_unlock(&notification_mutex);
	return;

unlock_fail:
	mutex_unlock(&notification_mutex);
fail:
#ifdef _WIN32 // DW-1556 fix DV crash, NULL dereference
	if(skb)
		nlmsg_free(skb);
#else 
	nlmsg_free(skb);
#endif
	drbd_err(resource, "Error %d while broadcasting event. Event seq:%u\n",
		 err, seq);
}

void notify_helper(enum drbd_notification_type type,
		   struct drbd_device *device, struct drbd_connection *connection,
		   const char *name, int status)
{
	struct drbd_resource *resource = device ? device->resource : connection->resource;
	struct drbd_helper_info helper_info;
	unsigned int seq = atomic_inc_return(&drbd_genl_seq);
	struct sk_buff *skb = NULL;
	struct drbd_genlmsghdr *dh;
	int err;

#ifdef _WIN32
	strncpy(helper_info.helper_name, name, sizeof(helper_info.helper_name) - 1);
    helper_info.helper_name[sizeof(helper_info.helper_name) - 1] = '\0';
#else
	strlcpy(helper_info.helper_name, name, sizeof(helper_info.helper_name));
#endif
	helper_info.helper_name_len = (__u32)(min(strlen(name), sizeof(helper_info.helper_name)));
	helper_info.helper_status = status;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
	err = -ENOMEM;
	if (!skb)
		goto fail;

	err = -EMSGSIZE;
#ifdef _WIN32
	dh = genlmsg_put((struct msg_buff*)skb, 0, seq, &drbd_genl_family, 0, DRBD_HELPER);
#else
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_HELPER);
#endif
	
	if (!dh)
		goto fail;
	dh->minor = device ? device->minor : -1;
	dh->ret_code = NO_ERROR;
	mutex_lock(&notification_mutex);
	if (nla_put_drbd_cfg_context(skb, resource, connection, device, NULL) ||
	    nla_put_notification_header(skb, type) ||
	    drbd_helper_info_to_skb(skb, &helper_info, true))
		goto unlock_fail;
	genlmsg_end(skb, dh);
	err = drbd_genl_multicast_events(skb, GFP_NOWAIT);
	skb = NULL;
	/* skb has been consumed or freed in netlink_broadcast() */
	if (err && err != -ESRCH)
		goto unlock_fail;
	mutex_unlock(&notification_mutex);
	return;

unlock_fail:
	mutex_unlock(&notification_mutex);
fail:
#ifdef _WIN32 // DW-1556 fix DV crash, NULL dereference
	if(skb)
		nlmsg_free(skb);
#else 
	nlmsg_free(skb);
#endif
	drbd_err(resource, "Error %d while broadcasting event. Event seq:%u\n",
		 err, seq);
}

static void notify_initial_state_done(struct sk_buff *skb, unsigned int seq)
{
	struct drbd_genlmsghdr *dh;
	int err;

	err = -EMSGSIZE;
#ifdef _WIN32
	dh = genlmsg_put((struct msg_buff*)skb, 0, seq, &drbd_genl_family, 0, DRBD_INITIAL_STATE_DONE);
#else
	dh = genlmsg_put(skb, 0, seq, &drbd_genl_family, 0, DRBD_INITIAL_STATE_DONE);
#endif
	
	if (!dh)
		goto nla_put_failure;
	dh->minor = UINT32_MAX;
	dh->ret_code = NO_ERROR;
	if (nla_put_notification_header(skb, NOTIFY_EXISTS))
		goto nla_put_failure;
	genlmsg_end(skb, dh);
	return;

nla_put_failure:
	nlmsg_free(skb);
	pr_err("Error %d sending event. Event seq:%u\n", err, seq);
}

static void free_state_changes(struct list_head *list)
{
	while (!list_empty(list)) {
		struct drbd_state_change *state_change =
			list_first_entry(list, struct drbd_state_change, list);
		list_del(&state_change->list);
		forget_state_change(state_change);
	}
}

static unsigned int notifications_for_state_change(struct drbd_state_change *state_change)
{
	return 1 +
	       state_change->n_connections +
	       state_change->n_devices +
	       state_change->n_devices * state_change->n_connections;
}

static int get_initial_state(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct drbd_state_change *state_change = (struct drbd_state_change *)cb->args[0];
	ULONG_PTR seq = cb->args[2];
	ULONG_PTR n;
	enum drbd_notification_type flags = 0;

	/* There is no need for taking notification_mutex here: it doesn't
	   matter if the initial state events mix with later state chage
	   events; we can always tell the events apart by the NOTIFY_EXISTS
	   flag. */
#ifdef _WIN64
	BUG_ON_UINT32_OVER(seq);
#endif

	cb->args[5]--;
	if (cb->args[5] == 1) {
		notify_initial_state_done(skb, (unsigned int)seq);
		goto out;
	}
	n = cb->args[4]++;
	if (cb->args[4] < cb->args[3])
		flags |= NOTIFY_CONTINUES;
	if (n < 1) {
		notify_resource_state_change(skb, (unsigned int)seq, state_change,
					     NOTIFY_EXISTS | flags);
		goto next;
	}
	n--;
	if (n < state_change->n_connections) {
		notify_connection_state_change(skb, (unsigned int)seq, &state_change->connections[n],
					       NOTIFY_EXISTS | flags);
		goto next;
	}
	n -= state_change->n_connections;
	if (n < state_change->n_devices) {
		notify_device_state_change(skb, (unsigned int)seq, &state_change->devices[n],
					   NOTIFY_EXISTS | flags);
		goto next;
	}
	n -= state_change->n_devices;
	if (n < state_change->n_devices * state_change->n_connections) {
		notify_peer_device_state_change(skb, (unsigned int)seq, &state_change->peer_devices[n],
						NOTIFY_EXISTS | flags);
		goto next;
	}

next:
	if (cb->args[4] == cb->args[3]) {
		struct drbd_state_change *next_state_change =
			list_entry(state_change->list.next,
				   struct drbd_state_change, list);
#ifdef _WIN32
        cb->args[0] = (LONG_PTR)next_state_change;
#else
		cb->args[0] = (long)next_state_change;
#endif
		cb->args[3] = notifications_for_state_change(next_state_change);
		cb->args[4] = 0;
	}
out:
	return skb->len;
}

int drbd_adm_get_initial_state_done(struct netlink_callback *cb)
{
	LIST_HEAD(head);
	if (cb->args[0]) {
		struct drbd_state_change *state_change =
			(struct drbd_state_change *)cb->args[0];
		cb->args[0] = 0;

		/* connect list to head */
		list_add(&head, &state_change->list);
		free_state_changes(&head);
	}
	return 0;
}

int drbd_adm_get_initial_state(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct drbd_resource *resource;
	LIST_HEAD(head);

	if (cb->args[5] >= 1) {
		if (cb->args[5] > 1)
			return get_initial_state(skb, cb);
		return 0;
	}

	cb->args[5] = 2;  /* number of iterations */
	mutex_lock(&resources_mutex);
	for_each_resource(resource, &drbd_resources) {
		struct drbd_state_change *state_change;

		state_change = remember_state_change(resource, GFP_KERNEL);
		if (!state_change) {
			if (!list_empty(&head))
				free_state_changes(&head);
			mutex_unlock(&resources_mutex);
			return -ENOMEM;
		}
		copy_old_to_new_state_change(state_change);
		list_add_tail(&state_change->list, &head);
		cb->args[5] += notifications_for_state_change(state_change);
	}
	mutex_unlock(&resources_mutex);

	if (!list_empty(&head)) {
		struct drbd_state_change *state_change =
			list_entry(head.next, struct drbd_state_change, list);
#ifdef _WIN32
        cb->args[0] = (LONG_PTR)state_change;
#else
		cb->args[0] = (long)state_change;
#endif
		cb->args[3] = notifications_for_state_change(state_change);
		list_del(&head);  /* detach list from head */
	}

	cb->args[2] = cb->nlh->nlmsg_seq;
	return get_initial_state(skb, cb);
}

int drbd_adm_forget_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct drbd_config_context adm_ctx;
	struct drbd_resource *resource;
	struct drbd_device *device;
#ifdef _WIN32
    struct forget_peer_parms parms = { 0 };
#else
	struct forget_peer_parms parms = { };
#endif
	enum drbd_state_rv retcode;
	int vnr, peer_node_id, err;

	retcode = drbd_adm_prepare(&adm_ctx, skb, info, DRBD_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	resource = adm_ctx.resource;

	err = forget_peer_parms_from_attrs(&parms, info);
	if (err) {
		retcode = ERR_MANDATORY_TAG;
		drbd_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto out_no_adm;
	}

	mutex_lock(&resource->adm_mutex);

	peer_node_id = parms.forget_peer_node_id;
	if (drbd_connection_by_node_id(resource, peer_node_id)) {
		retcode = ERR_NET_CONFIGURED;
		goto out;
	}

	if (peer_node_id < 0 || peer_node_id >= DRBD_NODE_ID_MAX) {
		retcode = ERR_INVALID_PEER_NODE_ID;
		goto out;
	}

#ifdef _WIN32
    idr_for_each_entry(struct drbd_device *, &resource->devices, device, vnr) {
#else
	idr_for_each_entry(&resource->devices, device, vnr) {
#endif
		struct drbd_peer_md *peer_md;

		if (!get_ldev(device))
			continue;

		peer_md = &device->ldev->md.peers[peer_node_id];
		if (peer_md->bitmap_index == -1) {
			put_ldev(device);
			retcode = ERR_INVALID_PEER_NODE_ID;
			break;
		}

		peer_md->bitmap_uuid = 0;
		peer_md->flags = 0;
		peer_md->bitmap_index = -1;

		drbd_md_sync(device);
		put_ldev(device);
	}
out:
	mutex_unlock(&resource->adm_mutex);
out_no_adm:
	drbd_adm_finish(&adm_ctx, info, (enum drbd_ret_code)retcode);
	return 0;

}
#ifdef _WIN32
// DW-1229: using global attr may cause BSOD when we receive plural netlink requests. use local attr.
int drbd_tla_parse(struct nlmsghdr *nlh, struct nlattr **attr)
{
    drbd_genl_family.id = nlh->nlmsg_type;

	return nla_parse(attr, ARRAY_SIZE(drbd_tla_nl_policy) - 1,
        nlmsg_attrdata(nlh, GENL_HDRLEN + drbd_genl_family.hdrsize),
        nlmsg_attrlen(nlh, GENL_HDRLEN + drbd_genl_family.hdrsize),
        drbd_tla_nl_policy);
}

void nl_policy_init_by_manual()
{
    extern void manual_nl_policy_init(void);
    manual_nl_policy_init();
}

struct genl_ops * get_drbd_genl_ops(u8 cmd)
{
    for (int i = 0; i < sizeof(drbd_genl_ops) / sizeof((drbd_genl_ops)[0]); i++)
    {
        if (drbd_genl_ops[i].cmd == cmd)
        {
            return &drbd_genl_ops[i];
        }
    }

    return NULL;
}
#endif
