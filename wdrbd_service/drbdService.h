;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//


//
// Define the severity codes
//


//
// MessageId: ONELINE_INFO
//
// MessageText:
//
// %1.
//
#define ONELINE_INFO                     0x400003E9L

//
// MessageId: MSG_SERVICE_START
//
// MessageText:
//
// DRBD Daemon Service start.
//
#define MSG_SERVICE_START                0x400003EAL

//
// MessageId: MSG_ACCEPT_TCP
//
// MessageText:
//
// test accept mesg (%1) (%2) (%3).
//
#define MSG_ACCEPT_TCP                   0x400003EBL

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
//
// MessageId: ONELINE_WARNING
//
// MessageText:
//
// %1.
//
#define ONELINE_WARNING                  0x400007D1L

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
//
// MessageId: ONELINE_ERROR
//
// MessageText:
//
// %1.
//
#define ONELINE_ERROR                    0xC0000BB9L

extern VOID WriteLog(wchar_t* pMsg);

extern int SockListener(unsigned short *servPort);

extern DWORD StartRegistryCleaner();
extern DWORD StopRegistryCleaner();