#include <stdio.h>
#include <cstring>
#include "packet_stream.h"

void PACKET_stream::BUFFER_Setup(const char *if_name, /*const unsigned int linkid,*/ char pck_type, unsigned int bufsize)
{
	lfqueue_init(&queue);

    sinfo.ifname = if_name;
    sinfo.type = (tystr_type)pck_type;

	sinfo.dropcount = 0;
	sinfo.packetid = 0;

    sinfo.str_state = STREAM_OPEN;

}

void PACKET_stream::BUFFER_Clear()
{
	char *pbuff;
	while ((pbuff = (char *)lfqueue_single_deq(&queue) ) != NULL)
	{
		free(pbuff);
	}
}

bool PACKET_stream::BUFFER_Open()
{
//    CYC_Empty(pbuff);
	BUFFER_Clear();

    switch(sinfo.type)
    {
    case TYPE_PACKETSTREAM:
    break;

    case TYPE_TAPPERPACKET:
    break;

    case TYPE_ADG:
	   Packet_ADG::Add_Hname(sinfo.ifname.c_str());
    break;

    default:
        return false;
    }
    sinfo.str_state = STREAM_DATA;

    return true;
}

void PACKET_stream::BUFFER_Close()
{
//   CYC_DeInit(pbuff);
	BUFFER_Clear();
	lfqueue_destroy(&queue);

   sinfo.str_state = STREAM_END;
}

unsigned int PACKET_stream::calculateChecksum(void *pData, unsigned int uLength)
{
	unsigned int uChecksum = 0;
	for (unsigned int i = 0; i < uLength; ++i)
	{
		uChecksum += *((unsigned char *)pData + i);
	}
	return uChecksum;
}

char *PACKET_stream::Add_PacketStream(pkt_trace_metadata *pmeta, unsigned long long ts, unsigned char *pdata, unsigned int packetid)
{
	char *pbuff;
    unsigned int cap_len = pmeta->cap_len;
    unsigned int pkt_len = pmeta->pkt_len;
    int length = (cap_len & 0x7) ? ((cap_len & ~0x7ul) + 8) : cap_len;
    length += sizeof(StreamedPacketv2);
    
    pbuff = (char *)malloc(length);

    if (!pbuff)
        return NULL;

    StreamedPacketv2 *phdr = (StreamedPacketv2 *)pbuff;
    phdr->dwMagicCode = STPCK2_Magic;
    phdr->eType = 1; // TODO
    phdr->_1[0] = phdr->_1[1] = 0;
    phdr->byPacketSource = 0; // TODO!
    phdr->uPacketCounter = packetid;
    phdr->stLink = pmeta->linkid;
//    phdr->stLink |= (pmeta->dir<<24);
    phdr->ftTimestamp = ts;
    phdr->uCheckSum = 0;
    phdr->uLength = cap_len;
    phdr->uOriginalLength = pkt_len;

    memcpy(phdr + 1, pdata, cap_len);

    phdr->uCheckSum = calculateChecksum(phdr, sizeof(StreamedPacketv2) + cap_len);
    return pbuff;
}

char *PACKET_stream::Add_TapperPacket(pkt_trace_metadata *pmeta, unsigned long long ts, unsigned char *pdata, unsigned int packetid)
{
unsigned int offset = 12;
char *pbuff;

    if (pmeta->cap_len < 32) return NULL;

    if (*(unsigned short *)&pdata[offset] == ETH_VLAN)
        offset += 4;

    if (*(unsigned short *)&pdata[offset] == ETH_IPv4  || *(unsigned short *)&pdata[offset] == ETH_IPv6) // IPv4, IPv6
        offset += 2;
    else 
        return NULL; // no IP found...

    unsigned int cap_len = pmeta->cap_len - offset;
    unsigned int pkt_len = pmeta->pkt_len;

    int length = cap_len + sizeof(TapperPacket);
    
    pbuff = (char *)malloc(length);

    if (!pbuff)
        return NULL;

    TapperPacket *phdr = (TapperPacket *)pbuff;
    phdr->dwMagicCode = TP_Magic;
    phdr->dwType = 0; // IP
    phdr->dwCounter = packetid;
    phdr->unLinkId = pmeta->linkid;
//    phdr->unLinkId |= (pmeta->dir<<24);
    phdr->ftTimestamp = ts;
    phdr->iTimeBias = 0;
    phdr->wReserved = 0;
    phdr->dwCheckSum = 0;
    phdr->dwLength = cap_len;

    memcpy(phdr + 1, pdata+offset, cap_len);

    phdr->dwCheckSum = calculateChecksum(phdr, length);

    return pbuff;
}

bool PACKET_stream::BUFFER_Write(unsigned char *pdata, pkt_trace_metadata *pmeta, struct timespec *pts)
{
char *pbuff;

if (sinfo.str_state != STREAM_DATA) 
{
    sinfo.dropcount++;
    return false;
}

//int buffer_length = CYC_GetBuffer_Free(pbuff) - MAX_PACKET_SIZE;
if (lfqueue_size(&queue) > MAX_QUEUED_PACKETS)
{
    sinfo.dropcount++;
    return false;
}

//CYC_LOCK(pbuff);

switch(sinfo.type)
{
    case TYPE_PACKETSTREAM:
    {
        unsigned long long ts = (pts->tv_sec+cuSecFrom1601To1970)*10000000ULL + pts->tv_nsec/100;
        pbuff = Add_PacketStream(pmeta, ts, pdata, sinfo.packetid);
    }
    break;

    case TYPE_TAPPERPACKET:
    {
        unsigned long long ts = (pts->tv_sec+cuSecFrom1601To1970)*10000000ULL + pts->tv_nsec/100;
        pbuff = Add_TapperPacket(pmeta, ts, pdata, sinfo.packetid);
    }
    break;

    case TYPE_ADG:
    {
        unsigned long long ts = (pts->tv_sec * NSEC_IN_SEC) + pts->tv_nsec;
        pbuff = Packet_ADG::Add_Packet(pmeta, ts, pdata, sinfo.packetid);
    }
    break;

    default:
//    	CYC_UNLOCK(pbuff);
        return false;
}

if (!pbuff)
{
    sinfo.dropcount++;
//    CYC_UNLOCK(pbuff);
    return false;
}
if (lfqueue_enq(&queue, pbuff) != 0)
{
    sinfo.dropcount++;
//    CYC_UNLOCK(pbuff);
    return false;
}
sinfo.packetid++;


//CYC_AddWPtr(pbuff, total_length);
//CYC_UNLOCK(pbuff);

return true;
}

char *PACKET_stream::BUFFER_Read(unsigned int &total_length)
{
    unsigned int size;

	char *pbuff = (char *)lfqueue_single_deq(&queue);

	if (!pbuff) return NULL;

    switch(sinfo.type)
    {
        case TYPE_PACKETSTREAM:
        {
            StreamedPacketv2 *phdr = (StreamedPacketv2 *)pbuff;
            total_length = phdr->getPaddedLength() + sizeof(StreamedPacketv2);
        }
        break;

        case TYPE_TAPPERPACKET:
        {
            TapperPacket *phdr = (TapperPacket *)pbuff;
            total_length = phdr->dwLength + sizeof(TapperPacket);
        }
        break;

        case TYPE_ADG:
        {
            ADG_DatagramHeader *phdr = (ADG_DatagramHeader *)pbuff;
            total_length = phdr->length;
        }
        break;

        default:
        return NULL;
        break;
    }
    return pbuff;

}
