#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sga_cyclicbuffer.h"

#define THREAD_FENCE_RELEASE()    std::atomic_thread_fence(std::memory_order_release)
#define THREAD_FENCE_ACQUIRE()    std::atomic_thread_fence(std::memory_order_acquire)

void CYC_LOCK(tycyclicbuffer *pbuff)	
{
	pbuff->plock->lock();
}

void CYC_UNLOCK(tycyclicbuffer *pbuff) 
{
	pbuff->plock->unlock();
}

bool CYC_Init(tycyclicbuffer *pbuff, unsigned int size)
{
	pbuff->buffer_size = size;
	pbuff->buffer_fill = 0;

	pbuff->plock = new std::mutex();

	pbuff->pbuffer = (unsigned char *)malloc(size);
	if (!pbuff->pbuffer)
		return false;

	pbuff->pwrite = pbuff->pread = pbuff->pbuffer;
	pbuff->pbuffer_end = pbuff->pbuffer + size;
	return true;
}

void CYC_DeInit(tycyclicbuffer *pbuff)
{
	if (pbuff->plock)
	{
		delete pbuff->plock;
		pbuff->plock = NULL;
	}
	if (pbuff->pbuffer)
	{
		free(pbuff->pbuffer);
		pbuff->pbuffer = NULL;
	}
}

unsigned int CYC_GetBuffer_2End(tycyclicbuffer *pbuff) { return (unsigned int)(pbuff->pbuffer_end - pbuff->pread);}
unsigned int CYC_GetBuffer_Fill(tycyclicbuffer *pbuff) { return pbuff->buffer_fill.load(std::memory_order_relaxed); }
unsigned int CYC_GetBuffer_Free(tycyclicbuffer *pbuff) { return pbuff->buffer_size-pbuff->buffer_fill.load(std::memory_order_relaxed); }

unsigned char *CYC_GetWPtr(tycyclicbuffer *pbuff)
{
unsigned int toend = (pbuff->pbuffer_end - pbuff->pwrite);

if (toend < MAX_PACKET_SIZE) pbuff->pwrite = pbuff->pbuffer; // cycle buffer :P

return pbuff->pwrite;

}

unsigned char *CYC_GetRPtr(tycyclicbuffer *pbuff)
{
unsigned int toend = (pbuff->pbuffer_end - pbuff->pread);

if (toend < MAX_PACKET_SIZE) pbuff->pread = pbuff->pbuffer; // cycle buffer :P

THREAD_FENCE_ACQUIRE();

return pbuff->pread;

}

void CYC_AddWPtr(tycyclicbuffer *pbuff, unsigned int size)
{
	pbuff->pwrite += size;

	THREAD_FENCE_RELEASE();

	pbuff->buffer_fill.fetch_add(size, std::memory_order_relaxed);
}


bool CYC_Write(tycyclicbuffer *pbuff, const unsigned char *pdata, const unsigned int size)
{

if (CYC_GetBuffer_Free(pbuff) < MAX_PACKET_SIZE) // no place -> drop
	return false;

unsigned int toend = (pbuff->pbuffer_end - pbuff->pwrite);

if (toend < MAX_PACKET_SIZE) pbuff->pwrite = pbuff->pbuffer; // cycle buffer :P

memcpy(pbuff->pwrite, pdata, size);
pbuff->pwrite += size;

THREAD_FENCE_RELEASE();

pbuff->buffer_fill.fetch_add(size, std::memory_order_relaxed);

return true;
}

bool CYC_WritewPeek(tycyclicbuffer *pbuff, const unsigned int size)
{

if (CYC_GetBuffer_Free(pbuff) < MAX_PACKET_SIZE) // no place -> drop
	return false;

unsigned int toend = (pbuff->pbuffer_end - pbuff->pwrite);

if (toend < MAX_PACKET_SIZE) pbuff->pwrite = pbuff->pbuffer; // cycle buffer :P

pbuff->pwrite += size;

THREAD_FENCE_RELEASE();

pbuff->buffer_fill.fetch_add(size, std::memory_order_relaxed);

return true;
}

unsigned char *CYC_Read(tycyclicbuffer *pbuff, const unsigned int size)
{

if (!pbuff->buffer_fill.load(std::memory_order_relaxed))
 	return NULL;

unsigned int toend = (pbuff->pbuffer_end - pbuff->pread);

if (toend < MAX_PACKET_SIZE) pbuff->pread = pbuff->pbuffer;

unsigned char *pret = pbuff->pread;

pbuff->buffer_fill.fetch_sub(size, std::memory_order_relaxed);

THREAD_FENCE_ACQUIRE();

pbuff->pread += size;

return pret;
}

unsigned char *CYC_ReadwPeek(tycyclicbuffer *pbuff, const unsigned int size)
{

unsigned char *pret = pbuff->pread;

pbuff->buffer_fill.fetch_sub(size, std::memory_order_relaxed);

THREAD_FENCE_ACQUIRE();

pbuff->pread += size;

return pret;
}

unsigned char *CYC_Peek(tycyclicbuffer *pbuff, const unsigned int size)
{
	if (pbuff->buffer_fill.load(std::memory_order_relaxed) < size)
		return NULL;

	unsigned int toend = (pbuff->pbuffer_end - pbuff->pread);

	if (toend < MAX_PACKET_SIZE) pbuff->pread = pbuff->pbuffer;

	return pbuff->pread;
}

void CYC_Empty(tycyclicbuffer *pbuff)
{
	pbuff->buffer_fill = 0;
	pbuff->pwrite = pbuff->pbuffer;
	pbuff->pread = pbuff->pbuffer;
}
