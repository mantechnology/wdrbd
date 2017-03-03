

#if DBG
#define DRBDLOCK_LOG_MAXLEN 260
#define DRBDLOCK_LOG_PREFIX "[Drbdlock]"
void drbdlock_print_log(const char * format, ...);
#else
#define DRBDLOCK_PRINT_LOG( _string )
#endif
