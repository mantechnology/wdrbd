#ifdef _WIN32
#include "linux-compat/kernel.h"
#else
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#endif
#include "drbd_int.h"

#ifdef CONFIG_DEBUG_FS
int __init drbd_debugfs_init(void);
void drbd_debugfs_cleanup(void);

void drbd_debugfs_resource_add(struct drbd_resource *resource);
void drbd_debugfs_resource_cleanup(struct drbd_resource *resource);

void drbd_debugfs_connection_add(struct drbd_connection *connection);
void drbd_debugfs_connection_cleanup(struct drbd_connection *connection);

void drbd_debugfs_device_add(struct drbd_device *device);
void drbd_debugfs_device_cleanup(struct drbd_device *device);

void drbd_debugfs_peer_device_add(struct drbd_peer_device *peer_device);
void drbd_debugfs_peer_device_cleanup(struct drbd_peer_device *peer_device);
#else
#ifdef _WIN32
static __inline int drbd_debugfs_init(void) { return -ENODEV; }
#else
static inline int __init drbd_debugfs_init(void) { return -ENODEV; }
#endif
static inline void drbd_debugfs_cleanup(void) { }

static inline void drbd_debugfs_resource_add(struct drbd_resource *resource) { }
static inline void drbd_debugfs_resource_cleanup(struct drbd_resource *resource) { }

static inline void drbd_debugfs_connection_add(struct drbd_connection *connection) { }
static inline void drbd_debugfs_connection_cleanup(struct drbd_connection *connection) { }

static inline void drbd_debugfs_device_add(struct drbd_device *device) { }
static inline void drbd_debugfs_device_cleanup(struct drbd_device *device) { }

static inline void drbd_debugfs_peer_device_add(struct drbd_peer_device *peer_device) { }
static inline void drbd_debugfs_peer_device_cleanup(struct drbd_peer_device *peer_device) { }

#endif
