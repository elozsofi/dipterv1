#pragma once

#ifndef __bpf__
    #include "sga-common/sga_xdp.h"
#else

#define PIN_GLOBAL_NS           2

struct bpf_elf_map {
        __u32 type;
        __u32 size_key;
        __u32 size_value;
        __u32 max_elem;
        __u32 flags;
        __u32 id;
        __u32 pinning;
};  

#endif

extern const char *IP4_TABLE;
extern const char *IP6_TABLE;
extern const char *RULE_TABLE;
extern const char *PERF_MAP;
extern const char *VTAP_DATA;

#define MAX_CPUS		256
#define MAX_CAPLEN		32*1024-64

#define DATA_MONITOR	0
#define DATA_PCKLIMIT   1
#define CNTR_PCK_ALL	2
#define CNTR_PCK_EVENT	3

typedef struct vtap_data
{
	unsigned int addr;
	unsigned short port;
	unsigned short res;
} vtap_data;


#define MDF_DIRECTION_FEXIT 1

#pragma pack(push,1)

typedef struct AID // alias-ID lookup
{
	unsigned int val1;
	unsigned int val2;
} AID;

typedef struct AID_wcntr
{
	unsigned int val1;
	unsigned int val2;
	unsigned long long cntr;
} AID_wcntr;

typedef struct CIDR4
{
	unsigned int cidr;
	unsigned short port;
	unsigned int ip;
} CIDR4;

typedef struct CIDR6
{
	unsigned int cidr;
	unsigned short port;
	unsigned char ip[16];
} CIDR6;

// optional metadata extensions!
#ifdef HAVE_TC_EXT_1
	typedef struct tytc_ext_1
	{
		unsigned int vlan_present;
		unsigned int vlan_tci;
		unsigned int ingress_ifindex;
		unsigned int _res;
	} tytc_ext_1;
#endif

//#ifdef HAVE_XDP_EXT_1
//#endif

typedef struct pkt_trace_metadata {
	unsigned int linkid;
	unsigned int pkt_len;
	unsigned int cap_len;
	unsigned short dir;
	unsigned short ifindex;
	unsigned long long ts;
	unsigned int lost;
#ifdef HAVE_TC_EXT_1
	tytc_ext_1 tc_ext_1;
#endif
} pkt_trace_metadata;

typedef struct pkt_trace_data
{
	struct pkt_trace_metadata meta;
	char data[MAX_CAPLEN];
} pkt_trace_data;

#pragma pack(pop)

#ifndef __bpf__
typedef struct perf_sample_event {
	struct perf_event_header header;
	unsigned long long time;
	unsigned int size;
	struct pkt_trace_metadata metadata;
	unsigned char packet[];
} perf_sample_event;

typedef struct perf_lost_event {
	struct perf_event_header header;
	unsigned long long id;
	unsigned long long lost;
} perf_lost_event;
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
({ \
	const typeof(((type *)0)->member) *__mptr = (ptr); \
	(type *)((char *)__mptr - offsetof(type, member)); \
})
#endif