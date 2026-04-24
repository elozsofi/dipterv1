/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __COMMON_H
#define __COMMON_H

//Progs
#define LAW_INTER       1
#define DEBUG_TR        2
#define SNI_EXTR        3
#define GTPC_ASS        4
#define DNS_CAP         5
#define QOS_LOGIC       6
#define WIRE_MONITOR    7

//Debug counters
#define FATERR_CTR      0
#define BAD_PKT_CTR     1
#define DONTCARE_CTR    2
#define GTPU_IN_CTR     3
#define GTPU_OUT_CTR    4
#define INGRESS_FIRES   5
#define PULL_DATA_ERR   6
#define IP_DECODE_ERR   7
#define MAPID_ERR       8
#define UPDATE_UDP_ERR  9
#define UPDATE_TCP_ERR  10
#define GTPC_CTR        11
#define SES_REQ_CTR     12
#define SES_RESP_CTR    13
#define GTPC_ASS_SUC    14
#define HANDSHAKE       15
#define CLIENT_HELLO    16
#define SNI_ERR         17
#define DNS             18
#define FILTER          19
#define WIRED_CONN      20
#define NEXT_MAPID      21
#define MAPID_NEG1      22
#define MAPID_SUCC      23
#define TAILCALL_ERR    24
#define OUTER_MAP_ERR   25
#define NEW_SERVICE_ERR 26
//                      ...
#define ENABLE_KERNEL   31

//Program related defines
#define MAX_USERS       20000 // 1048576 (=2^20)
#define MAX_NODE_IPS    20000
#define MAX_SERVICES    100
#define SNI_SIZE        20
#define ARRAY_MAP_MAX_ENTRIES 32
#define MAPID_THREADS   20 // GC threads
#define AGGR_TIME       20 // clear users every 20 seconds

//Misc
#define ZERO 0

#define ULLONG_MAX 18446744073709551615ULL
#define s_min(x, y) ((x) < (y) ? x : y)
#define s_max(x, y) ((x) > (y) ? x : y)
#define htons(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntons(x) ((__le16)___constant_swab16((x)))
#define ntonl(x) ((__le32)___constant_swab32((x)))

// macros for protocol types
#define ETH_P_8021Q      0x8100 // VLAN
#define ETH_P_MPLS_UC    0x8847 // MPLS Unicast
#define ETH_P_IP         0x0800 // IPv4
#define ETH_P_IPV6       0x86DD // IPv6
#define VXLAN_PORT       4789   // Standard VXLAN UDP port

#include <linux/types.h>

// VLAN header
struct vlan_hdr {
    __be16 h_vlan_TCI;          // VLAN Tag Control Information (VID, PCP, DEI)
    __be16 h_vlan_encapsulated_proto; // Next protocol 
};

// VXLAN header
struct vxlanhdr {
    __be32 vx_flags;
    __be32 vx_vni; // VXLAN Network Identifier
};

#include <linux/ipv6.h>

struct inner_pthread{
    int omap_fd; // dest ip addr
    unsigned int start; // protocol
    unsigned int end; // destination port
};

struct service_meta {
    struct in6_addr service_addr; // service ip addr
    unsigned char protocol; // protocol
    unsigned int service_port; // service port
};

/* header info from inner packet */
struct h_info {
    struct in6_addr saddr;
    struct in6_addr daddr;
    unsigned char protocol;
    unsigned int dport;
    unsigned int sport;
};

struct jitter_calc {
    unsigned long long rx_t_prev;       // Previous timestamp
    unsigned long long rx_t_prev2;      // Second previous timestamp
    unsigned long long rx_jitter;       // Jitter value for TO_UE (ns)
    unsigned char rx_first_packet;      // Flag for first packet
    unsigned char rx_second_packet;     // Flag for second packet
};

struct service_info {
    struct jitter_calc jit_calc;
    char sni[SNI_SIZE];
    unsigned long long rx_first_ts;
    unsigned long long tx_first_ts;
    unsigned long long rx_latest_ts;
    unsigned long long tx_latest_ts;
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
    unsigned int rx_packets;
    unsigned int tx_packets;
    unsigned long long rx_inter_packet_sum;
    unsigned long long tx_inter_packet_sum;
    unsigned int rx_latest_tcp_seq;
    unsigned int tx_latest_tcp_seq;
    unsigned int rx_tcp_retrans;
    unsigned int tx_tcp_retrans;
    unsigned long long rtt_measuring;
    __u8  tcp_state;
}__attribute__((packed));

/* TCP states */
#define INITIAL             0
#define SYN_SENT            1
#define SYN_ACK_RECEIVED    2
#define ESTABLISHED         3

typedef struct ipv4_lpm_key {
    unsigned int prefixlen;
    unsigned int data;
} ipv4_lpm_key;

typedef struct ipv6_lpm_key {
    unsigned int prefixlen;
    struct in6_addr data;
} ipv6_lpm_key;

typedef struct mapid_session {
    __u32 map_num;
    __u16 flags;
    __u64 first_ts;
} mapid_session;
struct user_reverse_lookup {
    struct ipv6_lpm_key user_addr;
    __u64 first_ts;
} __attribute__((packed));


typedef struct {
    int rev_fd;
    int mapid_fd;
    int outer_fd;
    int freelist_fd;
    unsigned int wid;     // worker id [0..MAPID_THREADS-1]
    unsigned int workers; // MAPID_THREADS
} gc_arg_t;

/* General GTP protocol related definitions. */
#define GTP1U_PORT	    0x6808 // GTP-U uses port 2152
#define GTP2C_PORT	    0x4B08 // GTP-C uses port 2123
#define GTP_TPDU	    255 // G-PDU messages type
#define GTPIE_RECOVERY	14
#define GTP1_F_NPDU	    0x01
#define GTP1_F_SEQ	    0x02
#define GTP1_F_EXTHDR	0x04
#define GTP1_F_MASK     0x07

// Packet directions
#define TO_UE           0
#define TO_INTERNET     1

struct gtp1_header {	/* According to 3GPP TS 29.060. */
	unsigned char	flags;
	unsigned char	type;
	unsigned short	length; // be
	unsigned int	tid; // be
} __attribute__((packed));

struct gtp2c_header {	/* According to 3GPP TS 29.060. */
	unsigned char	flags;
	unsigned char	type;
	unsigned short	length; // be
	unsigned int	teid; // be
    unsigned char	sqn[3]; // be
    unsigned char	spare; 
} __attribute__((packed));

/* According to 3GPP TS 29.060. */
struct gtpc_info {	
	struct ipv6_lpm_key	ipv6_addr;
	struct ipv6_lpm_key	ipv4_addr;
	unsigned long long  imsi;
	unsigned long long	msisdn;
    unsigned long long	imei;
    unsigned char       PDN_type;
    unsigned char       state; 
};

/* According to 3GPP TS 29.060. */
struct gtpc_flowkey {	
	unsigned int    reqIP; //IP of the session requester
	unsigned int    respIP;
	unsigned short  reqport;
	unsigned short	respport;
    unsigned char   sqn[3]; 
};

struct dispatcher_arg {
    struct ipv6_lpm_key uIP;
    struct mapid_session user_info;
    unsigned long long boot_delta;
    unsigned int outer_fd;
};

struct tail_args{
    struct gtpc_flowkey gtpc_flowkey;
    unsigned int next_header_off;
    struct service_meta serv_dirs;
    struct in6_addr user_ip;
    char tls[1600];
    unsigned int direction;
    unsigned int reason;
    struct h_info hdr_info;
    int node_sum;
};

#endif /* __COMMON_H */