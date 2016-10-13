
#ifndef __LOG_MANAGER__
#define __LOG_MANAGER__

#define	MAX_RECORD_BUFFER_SIZE	0x10000
#define	MAX_TIMESTAMP_LEN		24	// mm/dd/yyyy hh:mm:ss.mmm
#define MAX_LOGDATA_LEN			1024
#define LOG_FILE_EXT			_T(".log")

DWORD CreateLogFromEventLog(LPCSTR pszProviderName);
DWORD WriteLogWithRecordBuf(HANDLE hLogFile, LPCTSTR pszProviderName, PBYTE pBuffer, DWORD dwBytesRead);
void GetTimestamp(const DWORD Time, WCHAR DisplayString[]);
DWORD WriteLogToFile(HANDLE hLogFile, LPCTSTR pszTimeStamp, PBYTE pszData);
DWORD GetCurrentFilePath(LPCTSTR pszLogFileName, PTSTR pszLogFileFullPath);
DWORD WriteEventLog(LPCSTR pszProviderName, LPCSTR pszData);

#endif