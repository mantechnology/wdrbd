#ifndef __DRBD_NLA_H
#define __DRBD_NLA_H
#ifdef _WIN32
#include "drbd_wingenl.h"
#endif

extern int drbd_nla_parse_nested(struct nlattr *tb[], int maxtype, struct nlattr *nla,
				 const struct nla_policy *policy);
extern struct nlattr *drbd_nla_find_nested(int maxtype, struct nlattr *nla, int attrtype);

#endif  /* __DRBD_NLA_H */
