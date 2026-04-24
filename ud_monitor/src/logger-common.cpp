#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string>
#include <time.h>
#include "logger-common.h"

// Write to log

SGA_Logger::SGA_Logger(const char *flog, tyLOG type, bool _bLock)
{
	ltype = type;
	bLock = _bLock;

	switch (ltype)
	{
		case LOG_FILE:
			{
				std::string fstr = flog;
				fdbg = fopen(std::string(fstr + ".log").c_str(), "at");
				if (fdbg == NULL){
					printf("fdbg null\n");
					exit(1);
				}
				bLock = _bLock;
			}
			break;
		case LOG_SYS:
			openlog(flog, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);
			break;
		default: 
			break;
	}
}

SGA_Logger::SGA_Logger()
{
	fdbg = NULL;
	bLock = false;
}

SGA_Logger::~SGA_Logger()
{
	if (fdbg)
	{
		fclose(fdbg);
		fdbg = NULL;
	}
	if (ltype == LOG_SYS)
		closelog();
}

// Get date in string
char *SGA_Logger::GetDate_toStr(char *astr)
{
	time_t  tnow;
	struct tm *atm;

	tnow = time(NULL);
	atm = localtime(&tnow);
	sprintf(astr, "%d-%.2d-%.2dT%.2d:%.2d:%.2d", atm->tm_year + 1900, atm->tm_mon + 1, atm->tm_mday, atm->tm_hour, atm->tm_min, atm->tm_sec);

	return astr;
}

char *SGA_Logger::GetDate_toStr(unsigned int ts)
{
	time_t  tnow = ts;
	struct tm *atm;

//	tnow = time(NULL);
	atm = localtime(&tnow);
	sprintf(temps, "%d-%.2d-%.2dT%.2d:%.2d:%.2d", atm->tm_year + 1900, atm->tm_mon + 1, atm->tm_mday, atm->tm_hour, atm->tm_min, atm->tm_sec);

	return temps;
}


void SGA_Logger::WRITE_LOG(int priority, const char *format, ...)
{
	if (format == NULL){
        fprintf(stderr, "Error: format string is NULL\n");
        return;
	}

	char temps[32];
	va_list args1, args2;
	va_start(args1, format);
	if (bLock)
		dbg_mtx.lock();
	GetDate_toStr(temps);
	va_copy(args2, args1);
	switch (ltype)
	{
	case LOG_FILE:
		if (fdbg)
		{
			fprintf(fdbg, "%s ", temps);
			vfprintf(fdbg, format, args2);
			fflush(fdbg);
		}
		break;
	case LOG_SYS:
		vsyslog(priority, format, args2);
		break;
	}
	va_end(args2);
	printf("%s ", temps);
	vprintf(format, args1);
	if (bLock)
		dbg_mtx.unlock();
	va_end(args1);
}

void SGA_Logger::WRITE_DEBUG(const char *pbuff, int size)
{

}
