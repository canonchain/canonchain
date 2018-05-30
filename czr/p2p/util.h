#pragma once
#ifndef __UTIL_H__
#define __UTIL_H__

//#define _CRT_SECURE_NO_DEPRECATE	// remove warning C4996, 

#include "ostype.h"
//#include "UtilPdu.h"
#include "lock.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory>
#include <string.h>
#include <vector>
#include <list>
//#include "slog/slog_api.h"
#ifndef _WIN32
#include <strings.h>
#endif

#include <sys/stat.h>
#include <assert.h>
#include  "logging.h"


#ifdef _WIN32
#define	snprintf	sprintf_s
#else
#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#endif

#define NOTUSED_ARG(v) ((void)v)		// used this to remove warning C4100, unreferenced parameter

/// yunfan modify end 
class CRefObject
{
public:
	CRefObject();
	virtual ~CRefObject();

	void SetLock(CLock* lock) { m_lock = lock; }
	void AddRef();
	void ReleaseRef();
private:
	int				m_refCount;
	CLock*	m_lock;
};


uint64_t get_tick_count();
void util_sleep(uint32_t millisecond);

void RenameThread(const char* name);

/**
* .. and a wrapper that just calls func once
*/
template <typename Callable> void TraceThread(const char* name, Callable func)
{
	std::string s = strprintf("bitcoin-%s", name);
	RenameThread(s.c_str());
	//LogPrintf("%s thread start\n", name);
	printf("%s thread start\n", name);
	func();
	//LogPrintf("%s thread exit\n", name);
	printf("%s thread start\n", name);
	
}


template <typename T, typename... Args>
std::unique_ptr<T> MakeUnique(Args&&... args)
{
	return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}


#endif
