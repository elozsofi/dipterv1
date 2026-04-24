#pragma once

#include <string>
#include <inttypes.h>
#include <stdbool.h>
#include "packet_adg.h"
#include "lfqueue.h"

#define NSEC_IN_SEC     1000000000ULL

#define ETH_IPv4		0x0008
#define ETH_IPv6		0xDD86
#define ETH_VLAN 		0x0081

#define MAX_QUEUED_PACKETS		100000

typedef enum tystr_state
{
	STREAM_OPEN = 0,
	STREAM_DATA = 1,
	STREAM_END = 2
} tystr_state;

typedef enum tystr_type : char
{
	TYPE_PACKETSTREAM = 0,
	TYPE_TAPPERPACKET = 1,
	TYPE_ADG = 2
} tystr_type;
/*
struct tystrtype_wname
{
	tystr_type type;
	char name[];
};

const strtype_wname[] = {(TYPE_PACKETSTREAM,"packetstream"),(TYPE_TAPPERPACKET, "tapperpacket"),(TYPE_ADG, "adg")};
*/
typedef struct stream_info
{
	std::string ifname;
	tystr_state str_state;
	tystr_type type;
	unsigned int delta_nsec;
//	unsigned int linkid;
	unsigned int dropcount;
	unsigned int packetid;
} stream_info;

#pragma pack( push, 1 )

// 1. PacketStream format
const unsigned int STPCK2_Magic = 0x07172738;

typedef struct StreamedPacketv2
	{
			unsigned int	dwMagicCode;		// cMagic
			unsigned char 	eType;
			unsigned char	_1[2];				// reserved, zero
			unsigned char	byPacketSource;		// packet counters counted independently by packet source
			unsigned int	uPacketCounter;		// started from 0, incremented by 1 for each packet sent
			unsigned int	stLink;
			unsigned long long	ftTimestamp;		// timestamp of capturing, FILETIME format, in GMT
			unsigned int	uCheckSum;			// simple sum of all bytes above and below, including abyData
			unsigned short	uLength;			// number of useful bytes without padding
			unsigned short	uOriginalLength;	// number of bytes in original captured packet
			unsigned getPaddedLength()		{ return (uLength & 0x7) ? ((uLength & ~0x7ul) + 8) : uLength; }
			unsigned getTotalLength()		{ return sizeof(StreamedPacketv2) + uLength; }
			unsigned getTotalPaddedLength()	{ return sizeof(StreamedPacketv2) + getPaddedLength(); }
	} StreamedPacketv2;

// 2. TapperPacket format
const unsigned int TP_Magic = 0x11223397;

typedef struct TapperPacket
	{
		unsigned int	dwMagicCode;		// cMagic
		unsigned int	dwType;
		unsigned int	dwCounter;		// started from 0, incremented by 1 for each packet sent
		unsigned int	unLinkId;
		unsigned long long	ftTimestamp;		// timestamp of capturing, FILETIME format, in GMT
		unsigned short	iTimeBias;
		unsigned short  wReserved;
		unsigned int	dwCheckSum;			// simple sum of all bytes above and below, including abyData
		unsigned int	dwLength;			// size of transferred data in bytes (available data length)
	} TapperPacket;

#pragma pack( pop )

////

class PACKET_stream : public Packet_ADG
{
public:
//	PACKET_stream();
//	~PACKET_stream();

	void BUFFER_Setup(const char *if_name, /*const unsigned int linkid,*/ char pck_type, unsigned int bufsize);
//	void BUFFER_SetLinkId(const unsigned int linkid) { sinfo.linkid = linkid; }
	void BUFFER_SetType(char pck_type) { sinfo.type = (tystr_type)pck_type; }
	bool BUFFER_Open();
	void BUFFER_Halt() { sinfo.str_state = STREAM_OPEN; }
	void BUFFER_Clear();
	void BUFFER_Close();
	bool BUFFER_Write(unsigned char *pdata, pkt_trace_metadata *pmeta, struct timespec *pts);
	char *BUFFER_Read(unsigned int &total_length);
// 

private:
	unsigned int calculateChecksum(void *pData, unsigned int uLength);
    char *Add_PacketStream(pkt_trace_metadata *pmeta, unsigned long long ts, unsigned char *pdata, unsigned int packetid);
    char *Add_TapperPacket(pkt_trace_metadata *pmeta, unsigned long long ts, unsigned char *pdata, unsigned int packetid);

	stream_info sinfo;
	lfqueue_t queue;
};
