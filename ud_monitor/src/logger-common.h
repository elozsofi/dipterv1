#pragma once
#include <stdio.h>
#include <syslog.h>
#include <mutex>

typedef enum tyLOG
{
	LOG_FILE = 0,
	LOG_SYS = 1
} tyLOG;

class SGA_Logger
{
public:
	SGA_Logger(const char *flog, tyLOG ltype, bool _bLock=false);
	SGA_Logger();
	~SGA_Logger();
	void WRITE_LOG(int priority, const char *format, ...);
	void WRITE_DEBUG(const char *pbuff, int size);

	char *GetDate_toStr(unsigned int ts);

private:
	char temps[64];
	char *GetDate_toStr(char *astr);
	FILE *fdbg;
	bool bLock;
	std::mutex dbg_mtx;
	tyLOG ltype;
};