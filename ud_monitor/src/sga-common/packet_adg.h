#pragma once

#include "../sga_taps.h"
#include <vector>

const unsigned char datagramVer = 2;
const unsigned char undefCID = 0xFF;
const unsigned char undefAID = 0xFF;

#define APPID_COMMON    2

#define APPID_PMETA     18 

// 1. CaptureInfo
#define CONTENT_CAPINFO  8
// 2. Payload
#define CONTENT_PAYLOAD  7

// 3. VTAP specific
#define CONTENT_HNAME  0 // hostname
#define CONTENT_IFNAME 1 // iface name
#define CONTENT_TC_EXT_1 2 // TC extension 1

#pragma pack(push,1)

typedef struct ADG_DatagramHeader
{
    unsigned char version;
    unsigned int length : 28;
    unsigned int crypted : 1;
    unsigned int compressed : 1;
    unsigned int _ : 2;
} ADG_DatagramHeader;

typedef struct ADG_ContentId 
{
    unsigned char appId;
    unsigned char contentId;
} ADG_ContentId;

typedef struct ADG_Content : ADG_ContentId 
{
    unsigned short length;
} ADG_Content;

// 

typedef enum ADG_ProtocolId : unsigned short
{
        unknown = 0,
        stream= 1,
        ethernet= 2,
        ip4= 3,
        ip6= 4,
        udp= 5,
        tcp= 6,
        sctp= 7,
        diameter= 8,
        s1ap= 9,
        sip= 10,
        coap= 11,
        http= 12,
        gtpc= 13,
        gtpu= 14,
        pfcp= 15,
        json= 16,
        m3ua= 17,
        ngap= 18,
        http2= 19,
        multipart= 20
 } ADG_ProtocolId;


typedef struct ADG_Payload : ADG_Content 
{
    ADG_ProtocolId protocolId;
} ADG_Payload;

typedef struct ADG_CaptureInfo : ADG_Content 
{
//    typedef char LinkName[4];
    unsigned int linkName;
    bool direction;
    unsigned long long timestamp;
    unsigned int originalLength;
    unsigned int ordinalNumber;
} ADG_CaptureInfo;

typedef struct ADG_MetaInfo : ADG_Content
{
} ADG_MetaInfo;


#pragma pack(pop)

class Packet_ADG
{

public:
    void Add_Iface(const char *ifname);
    void Add_Hname(const char *hname);
    char *Add_Packet(pkt_trace_metadata *pmeta, unsigned long long ts, unsigned char *pdata, unsigned int packetid);
//    unsigned char *Add_Packet_Ext(unsigned char *pbuff) { return pbuff; } // redefine if needed
    unsigned int Get_PacketLen(unsigned char *pbuff, int buff_size);

private:
    unsigned int Get_Fixlen();
    //
    std::vector<std::string> iflist;
    std::vector<unsigned int> iflist_len;
    std::string shname;
    unsigned int shname_len;
};