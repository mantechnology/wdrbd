/* user/shared/config.h.  Generated from config.h.in by configure.  */
/* user/shared/config.h.in.  Generated from configure.ac by autoheader.  */

/* Local configuration directory. Commonly /etc or /usr/local/etc */
#define DRBD_CONFIG_DIR "/etc"

/* Include support for drbd-8.3 kernel code */
#define DRBD_LEGACY_83 1

/* Include support for drbd-8.4 kernel code */
#define DRBD_LEGACY_84 1

/* Local state directory. Commonly /var/lib/drbd or /usr/local/var/lib/drbd */
#define DRBD_LIB_DIR "/var/lib/drbd"

/* Local lock directory. Commonly /var/lock or /usr/local/var/lock */
#define DRBD_LOCK_DIR "/var/lock"

/* Runtime state directory. Commonly /var/run/drbd or /usr/local/var/run/drbd
   */
#define DRBD_RUN_DIR "/var/run/drbd"

/* Does genetlink provide CTRL_CMD_DELMCAST_GRP already */
/* #undef HAVE_CTRL_CMD_DELMCAST_GRP */

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "drbd-dev@lists.linbit.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "DRBD"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "DRBD 8.9.3"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "drbd"

/* Define to the version of this package. */
#define PACKAGE_VERSION "8.9.3"
