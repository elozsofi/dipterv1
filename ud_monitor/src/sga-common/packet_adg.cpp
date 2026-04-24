#include "packet_adg.h"

unsigned int Packet_ADG::Get_Fixlen()
{
	return sizeof(ADG_DatagramHeader) + sizeof(ADG_CaptureInfo) + sizeof(ADG_Payload) + sizeof(ADG_MetaInfo) + shname_len;
}

void Packet_ADG::Add_Hname(const char *hname)
{
	shname = hname;
	shname_len = strlen(hname);
}

void Packet_ADG::Add_Iface(const char *ifname)
{
	iflist.push_back(ifname);
	iflist_len.push_back(strlen(ifname));
}

unsigned int Packet_ADG::Get_PacketLen(unsigned char *pbuff, int buff_size)
{
	if (buff_size < sizeof(ADG_DatagramHeader))
		return 0;

ADG_DatagramHeader *phdr = (ADG_DatagramHeader *)pbuff;

return phdr->length;

}

char *Packet_ADG::Add_Packet(pkt_trace_metadata *pmeta, unsigned long long ts, unsigned char *pdata, unsigned int packetid)
{
	char *pbuff;
	unsigned int data_size = pmeta->cap_len;
	int length = Get_Fixlen() + data_size; // ++ metainfo
	unsigned int ifindex = pmeta->ifindex - 1;
	if (ifindex < iflist.size())
	{
		length += sizeof(ADG_MetaInfo) + iflist_len[ifindex];
	}
#ifdef HAVE_TC_EXT_1
	length += sizeof(ADG_MetaInfo) + sizeof(tytc_ext_1) + 8;
#endif

    pbuff = (char *)malloc(length);

    if (!pbuff)
        return NULL;

ADG_DatagramHeader *phdr = (ADG_DatagramHeader *)pbuff;

phdr->version = 2;
phdr->length = length;
phdr->crypted = phdr->compressed = 0;

ADG_CaptureInfo *pcinfo = (ADG_CaptureInfo *)(phdr+1);

pcinfo->appId = APPID_COMMON;
pcinfo->contentId = CONTENT_CAPINFO;
pcinfo->length = sizeof(ADG_CaptureInfo);

pcinfo->linkName = (pmeta->linkid&0x00FFFFFF);
pcinfo->direction = (pmeta->linkid>>24);
pcinfo->timestamp = ts;
pcinfo->originalLength = data_size;
pcinfo->ordinalNumber = packetid;

unsigned int metalen = shname_len;
ADG_MetaInfo *pminfo = (ADG_MetaInfo *)(pcinfo+1);
pminfo->appId = APPID_PMETA;
pminfo->contentId = CONTENT_HNAME;
pminfo->length = sizeof(ADG_MetaInfo) + metalen;
memcpy(pminfo+1,shname.c_str(), metalen);

if (ifindex < iflist.size())
{
	pminfo = (ADG_MetaInfo *)((char *)(pminfo+1)+metalen);
	metalen = iflist_len[ifindex];
	pminfo->appId = APPID_PMETA;
	pminfo->contentId = CONTENT_IFNAME;
	pminfo->length = sizeof(ADG_MetaInfo) + metalen;	
	memcpy(pminfo+1,iflist[ifindex].c_str(), metalen);
}

#ifdef HAVE_TC_EXT_1
	pminfo = (ADG_MetaInfo *)((char *)(pminfo+1)+metalen);
	metalen = sizeof(tytc_ext_1);
	memcpy(pminfo+1, &pmeta->tc_ext_1, metalen);
	*(unsigned long long *)((char *)(pminfo+1)+metalen) = pmeta->ts;
	metalen += 8;
	pminfo->appId = APPID_PMETA;
	pminfo->contentId = CONTENT_TC_EXT_1;
	pminfo->length = sizeof(ADG_MetaInfo) + metalen;
#endif

//ADG_Payload *ppload = (ADG_Payload *)ADG_Add_Ext((char *)(pminfo+1)+metalen);
ADG_Payload *ppload = (ADG_Payload *)((char *)(pminfo+1)+metalen);

ppload->appId = APPID_COMMON;
ppload->contentId = CONTENT_PAYLOAD;
ppload->length = sizeof(ADG_Payload) + data_size;
ppload->protocolId = ADG_ProtocolId::ethernet;

memcpy(ppload+1, pdata, data_size);

return pbuff;
}
