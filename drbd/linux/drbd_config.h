/*
  drbd_config.h
  DRBD's compile time configuration.

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

#ifndef DRBD_CONFIG_H
#define DRBD_CONFIG_H

extern const char *drbd_buildtag(void);

/* Necessary to build the external module against >= Linux-2.6.33 */
#ifdef REL_VERSION
#undef REL_VERSION
#undef API_VERSION
#undef PRO_VERSION_MIN
#undef PRO_VERSION_MAX
#endif

/* End of external module for 2.6.33 stuff */

#define REL_VERSION "9.0.6"
#define PRO_VERSION_MIN 86
// DW-1293: protocol version 112 starts to support fast invalidate(remote)
// DW-1845 disables the DW-1601 function. If enabled, you must set ACT_LOG_TO_RESYNC_LRU_RELATIVITY_ENABLE 
//#define ACT_LOG_TO_RESYNC_LRU_RELATIVITY_ENABLE 
// DW-1601: protocol version 113 remove association to act_log and resync_lru
// PRO_VERSION_MAX is the maximum version allowed. If the protocol is changed or the feature is incompatible with the sub-version, you must increase that version.
#define PRO_VERSION_MAX 113

#ifndef __CHECKER__   /* for a sparse run, we need all STATICs */
#define DBG_ALL_SYMBOLS /* no static functs, improves quality of OOPS traces */
#endif

/* Dump all cstate changes */
#define DUMP_MD 2

/* some extra checks
#define PARANOIA
 */

/* Enable fault insertion code */
#ifndef CONFIG_DRBD_FAULT_INJECTION
#define CONFIG_DRBD_FAULT_INJECTION 1
#endif

/* CONFIG_KREF_DEBUG has to be enabled in Kbuild */
#ifndef _WIN32
#ifdef __KERNEL__
#include "compat.h"
#endif
#endif
#endif
