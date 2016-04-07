#pragma warning (disable : 4221 4706)

struct loglink_msg_list {
	char  *buf;
	struct list_head list;
};

struct loglink_worker {
	struct workqueue_struct *wq;
	struct work_struct worker;
	struct list_head loglist;
};

extern int g_loglink_tcp_port;
extern int g_loglink_usage;
extern struct loglink_worker loglink;
extern struct mutex loglink_mutex;
extern NPAGED_LOOKASIDE_LIST linklog_printk_msg;
extern void LogLink_Sender(struct work_struct *ws);
extern DWORD msgids[];
extern VOID NTAPI LogLink_ListenThread(PVOID p);

#define LOGLINK_TIMEOUT		3000

#define	LOGLINK_NOT_USED	0	// kernel level log with multi-line
#define	LOGLINK_DUAL		1	// kernel level log + user level log
#define	LOGLINK_OLNY		2	// user level log, eventname = application/drbdService
#define	LOGLINK_NEW_NAME	3	// user level log, save drbd event only
#define	LOGLINK_2OUT		4	// user level log, save one event to two eventlog 