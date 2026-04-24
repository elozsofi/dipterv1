#include <inttypes.h>
#include <stdbool.h>
#include <atomic>
#include <mutex>

#define MAX_PACKET_SIZE  32*1024+256 // cycle buffer, when free space is less than that

#pragma pack( push, 1 )

typedef struct tycyclicbuffer
{
	std::mutex *plock;
	unsigned char *pbuffer;
	unsigned char *pbuffer_end;
	unsigned int buffer_size;
	std::atomic<unsigned int> buffer_fill;
	unsigned char *pwrite;
	unsigned char *pread;
} tycyclicbuffer;

#pragma pack( pop )

	void CYC_LOCK(tycyclicbuffer *pbuff);
	void CYC_UNLOCK(tycyclicbuffer *pbuff);

	bool CYC_Init(tycyclicbuffer *pbuff, unsigned int size);
	void CYC_DeInit(tycyclicbuffer *pbuff);
	bool CYC_Write(tycyclicbuffer *pbuff, const unsigned char *pdata, const unsigned int size);
	unsigned char *CYC_GetRPtr(tycyclicbuffer *pbuff);
	unsigned char *CYC_GetWPtr(tycyclicbuffer *pbuff);
	void CYC_AddWPtr(tycyclicbuffer *pbuff, unsigned int size);
	unsigned char *CYC_Read(tycyclicbuffer *pbuff, const unsigned int size);
	unsigned char *CYC_ReadwPeek(tycyclicbuffer *pbuff, const unsigned int size);
	unsigned char *CYC_Peek(tycyclicbuffer *pbuff, const unsigned int size);
	void CYC_Empty(tycyclicbuffer *pbuff);

	unsigned int CYC_GetBuffer_2End(tycyclicbuffer *pbuff);
	unsigned int CYC_GetBuffer_Fill(tycyclicbuffer *pbuff);
	unsigned int CYC_GetBuffer_Free(tycyclicbuffer *pbuff);

