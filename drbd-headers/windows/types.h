#ifndef _WINDOWS_TYPES_H
#define _WINDOWS_TYPES_H

#include <ctype.h>
#include <stdbool.h>
typedef signed char		    __s8;
typedef unsigned char		__u8;
typedef signed short		__s16;
typedef unsigned short		__u16;
typedef signed int		    __s32;
typedef unsigned int		__u32;
typedef signed long long	__s64;
typedef unsigned long long	__u64;
typedef signed char		    s8;
typedef unsigned char		u8;
typedef signed short		s16;
typedef unsigned short		u16;
typedef signed int		    s32;
typedef unsigned int		u32;
typedef signed long long	s64;
typedef unsigned long long	u64;
typedef unsigned long long	sector_t;

typedef __u16		__le16;
typedef __u16		__be16;
typedef __u32		__le32;
typedef __u32		__be32;
typedef __u64		__le64;
typedef __u64		__be64;


typedef		__u8		u_int8_t;
typedef		__s8		int8_t;
typedef		__u16		u_int16_t;
typedef		__s16		int16_t;
typedef		__u32		u_int32_t;
typedef		__s32		int32_t;

typedef		__u8		uint8_t;
typedef		__u16		uint16_t;
typedef		__u32		uint32_t;

//#if defined(__GNUC__)
typedef		__u64		uint64_t;
typedef		__u64		u_int64_t;
typedef		__s64		int64_t;
//#endif


///

#endif