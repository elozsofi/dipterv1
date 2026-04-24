#include <stddef.h>
#include "common.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/gtp.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/gtp.h>
#include <linux/in6.h>
#include <linux/udp.h>

#include <linux/if_vlan.h>
#include <linux/mpls.h>
#include <linux/if_tunnel.h>

#include <linux/pkt_cls.h>  // For TC
#include "../libbpf/src/bpf_helpers.h"
#include "../libbpf/src/bpf_endian.h"

#include "sga_dump_tc.c"

/* check output: sudo cat /sys/kernel/debug/tracing/trace_pipe */
#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Tails
struct { /* A map to hold programs for tail calls */
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 32);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} func_map SEC(".maps");
struct { /* A map to store arguments of tail cails */
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tail_args);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tail_arg_map SEC(".maps");

struct inner_map_struct { /* inner map template */
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct service_meta)); 
    __uint(value_size, sizeof(struct service_info));
    __uint(max_entries, MAX_SERVICES); /* 1000 is enough here */
} inner_map SEC(".maps");

struct { /* outer map */
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32)); /* Must be u32 because it's inner map id */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, MAX_USERS); /* 2^20 */
    __array(values, struct inner_map_struct);
} outer_map SEC(".maps") = {
    .values = { &inner_map }
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * */
struct { /* map for connecting inner maps with users */
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key); /* source IPv6 address */
    __type(value, struct mapid_session); /* entry id in outer map, NEED SPINLOCK */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAX_USERS); /* 2^20 */
} mapid SEC(".maps");

struct free_ptr {
    struct bpf_spin_lock semaphore;
    __u32 free;
};
struct { /* map for storing first&last empty entry in outer map */
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32); // key is 0
    __type(value, struct free_ptr); // spin lock?
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 2); /* 0 is first, 1 is last */
} freelist_map SEC(".maps");

struct { /* reverse mapid lookup */
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32); /* key is map num in outer map */
    __type(value, struct user_reverse_lookup); /* user ip + timestamp */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, MAX_USERS); /* 2^20 */
} rev_lookup SEC(".maps");
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct { /* map for storing UPF ip addresses */
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key); 
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAX_NODE_IPS); /* num of node addresses generated in user space */
} nodes SEC(".maps");

struct { /* helper map for reporting program stats  */
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, unsigned int);
    __type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} reporter SEC(".maps");

struct { /* Map for create session assembly */
    __uint(type, BPF_MAP_TYPE_LRU_HASH); /* Least recently used hash map should suffice for housekeeping */
    __type(key, struct gtpc_flowkey); 
    __type(value, struct gtpc_info);
    __uint(max_entries, 3*MAX_USERS);
    __uint(pinning, LIBBPF_PIN_BY_NAME); /* Temporary pinning for debugging */
} gtpc_ass SEC(".maps");

struct { /* Map for IPvX-IMSI */
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key); /* IPv4 addresses stored as IPv6 */
    __type(value, __u64); /* IMSI stored as standard BCD encoding with 1111 padding */
    __uint(max_entries, 3*MAX_USERS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME); /* Temporary pinning for debugging */
} ip_imsi SEC(".maps");

struct { /* map for identifying users for lawful interception/debug trace */
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key); /* user's IPv6 address */
    __type(value, __u32); /* 0=nothing 1=LI 2=debug trace */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAX_USERS); /* 2^20 */
} tracing_info SEC(".maps");

/* increments debug counter */
static __always_inline void prog_stats(unsigned int reg_num){
    unsigned int reg_num_val = reg_num;
	unsigned int *value = bpf_map_lookup_elem(&reporter, &reg_num_val);
	if (value) { *value += 1; }
}

/* Get next free entry id from outer map */
static __always_inline __s32 next_free_mapid() {
    prog_stats(NEXT_MAPID);
    __u32 first_key = 0;
    __u32 last_key = 1;

    struct free_ptr *last = bpf_map_lookup_elem(&freelist_map, &last_key);
    struct free_ptr *first = bpf_map_lookup_elem(&freelist_map, &first_key);
    
    if (!first || !last) {
        return -1;
    }

    __s32 mapid = -1;

    bpf_spin_lock(&first->semaphore);

    if (first->free != last->free) {
        mapid = first->free;
        first->free = (first->free + 1) % MAX_USERS;
    }

    bpf_spin_unlock(&first->semaphore);

    if (mapid == -1) {
        prog_stats(MAPID_NEG1);
    } else {
        prog_stats(MAPID_SUCC);
    }
    return mapid;
}

/* return node value associated to ip address (eNodeB, gNodeB, UPF, SGSN, n/a) or 12 if entry not found */
static __always_inline unsigned int node_value(ipv4_lpm_key ipaddr){
    /*    Node values:
        eNodeB : 1
        gNodeB : 2
        UPF : 4
        MME(SGSN) GN : 7
        (Unknown) : 12 */
    unsigned int* node_addresses = bpf_map_lookup_elem(&nodes, &ipaddr);
    if (node_addresses) { return *node_addresses; }
    return 12;
}

static __always_inline void EWMA_jitter(struct jitter_calc *calc, __u64 now) {
    if (calc->rx_first_packet) {
        calc->rx_t_prev = now;
        calc->rx_first_packet = 0;
        calc->rx_jitter = 0;
    } else if (calc->rx_second_packet) {
        calc->rx_t_prev2 = calc->rx_t_prev;
        calc->rx_t_prev = now;
        calc->rx_second_packet = 0;
        calc->rx_jitter = 0;
    } else {
        /* computing inter-arrival difference and apply EWMA: J <- J + (|D_i| - J)/16 */
        __u64 inter_arrival_current = now - calc->rx_t_prev;
        __u64 inter_arrival_prev = calc->rx_t_prev - calc->rx_t_prev2;
        __u64 abs_D_i = 0;
        if ( inter_arrival_current > inter_arrival_prev ) {
            abs_D_i = inter_arrival_current - inter_arrival_prev;
        } else {
            abs_D_i = inter_arrival_prev - inter_arrival_current;
        }
        calc->rx_jitter = ((abs_D_i + 15*calc->rx_jitter) / 16); // EWMA with weight 1/16
        calc->rx_t_prev2 = calc->rx_t_prev;
        calc->rx_t_prev = now;
    }
}

/* calculate technology used */
__u16 add_nodeval(__u16 flags, int node_sum){
    /* Valid node sums : 5: 4G+HR, 6: 5G+HR, 11: 2G+HR, 16: 4G+R, 19: 2G+R
       possible flag values: 
        0: HR,
        1: R,
        2-9: reserved for future use,
        10: 2G,
        11:3G,
        12:4G,
        13:5G,
        14-15: reserved for future use */
    switch (node_sum) {
        case 5:
            flags = flags | 0x1001;
            break;
        case 6:
            flags = flags | 0x2001;
            break;
        case 11:
            flags = flags | 0x401;
            break;
        case 16:
            flags = flags | 0x1002;
            break;
        case 19:
            flags = flags | 0x402;
            break;
        default:
            return flags;
    }
    return flags;
}

/* check if ip is UE (starting with 10.0) */
static __always_inline int is_user_ip(struct in6_addr* ip) {
    // For IPv4 mapped to IPv6, check the last 32 bits (in6_u.u6_addr32[3])
    // IPv4 10.0.x.x maps to 0x0A00xxxx in network byte order
    if (ip->in6_u.u6_addr16[5] == bpf_htons(0xffff)) { // IPv4-mapped IPv6
        __u32 ipv4_addr = bpf_ntohl(ip->in6_u.u6_addr32[3]);
        return (ipv4_addr & 0xffff0000) == 0x0a000000; // Check if starts with 10.0
    }
    // For native IPv6, no special handling for 10.0 (adjust if needed)
    return 0;
}

/* decodes IPvX headers, moves next_header to the start of the L4 header */
static __always_inline void* decode_ip(void* next_header, void* data, void* data_end, struct h_info* hdr_info) {
    if (next_header + 1 > data_end) {
        prog_stats(BAD_PKT_CTR);
        return NULL;
    }
    char version = ((*(char*)next_header) & 0xF0);
    
    if (version == 0x40) { /* check IPv4 */
        struct iphdr* inner_ip = (struct iphdr *)next_header;
        if ((void *)inner_ip + sizeof(struct iphdr) > data_end) {
            prog_stats(BAD_PKT_CTR);
            return NULL;
        }
        if (inner_ip->ihl < 5 || inner_ip->ihl > 15) {
            prog_stats(BAD_PKT_CTR);
            return NULL;
        }
        hdr_info->daddr.in6_u.u6_addr32[3] = inner_ip->daddr;
        hdr_info->saddr.in6_u.u6_addr32[3] = inner_ip->saddr;
        hdr_info->daddr.in6_u.u6_addr16[5] = 0xffff;
        hdr_info->saddr.in6_u.u6_addr16[5] = 0xffff;
        hdr_info->protocol = inner_ip->protocol;
        next_header = (next_header + (inner_ip->ihl * 4));
    } else if (version == 0x60) { /* check IPv6 */
        struct ipv6hdr* inner_ipv6 = (struct ipv6hdr*)next_header;
        if ((void *)inner_ipv6 + sizeof(struct ipv6hdr) > data_end) {
            prog_stats(BAD_PKT_CTR);
            return NULL;
        }
        hdr_info->daddr = inner_ipv6->daddr;
        hdr_info->saddr = inner_ipv6->saddr;
        hdr_info->protocol = inner_ipv6->nexthdr;
        next_header = (next_header + sizeof(struct ipv6hdr));
    } else {
        prog_stats(FATERR_CTR);
        prog_stats(IP_DECODE_ERR); 
        return NULL; 
    }
    return next_header;
}

/* Decodes GTP-C header and assembles create session transactions and creates IP-IMSI map*/
SEC("classifier")
int gtpc_assembler(struct __sk_buff *skb){
    __u32 index = 0;
    struct tail_args* tail_args = (struct tail_args*)bpf_map_lookup_elem(&tail_arg_map, &index);
    if(!tail_args) { return TC_ACT_OK; }
    unsigned int next_header_off = tail_args->next_header_off;
    // Compute pointers to data and data_end
    void* data = (void*)(unsigned long) skb->data;
    void* data_end = (void*)(long)skb->data_end;
    void* next_header = 0;
    if(next_header_off < 70000){next_header = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);}
    else{return TC_ACT_OK;}
    struct gtpc_flowkey* key = &tail_args->gtpc_flowkey;
    if (next_header + sizeof(struct gtp2c_header) + 4 > data_end){prog_stats(BAD_PKT_CTR); return TC_ACT_OK;}
    struct gtp2c_header* gtp2c = (struct gtp2c_header*)next_header;
    if ((gtp2c->flags & 0xE0) != 0x40){return TC_ACT_OK;} //Not GTP2C, we dont care
    prog_stats(GTPC_CTR);
    if (gtp2c->type != 32 && gtp2c->type != 33){return TC_ACT_OK;} //Not session creation, we dont care
    void *current_IE = next_header + sizeof(struct gtp2c_header);
    struct gtpc_info info = {0};
    info.imsi = ULLONG_MAX;
    info.imei = ULLONG_MAX;
    info.msisdn = ULLONG_MAX;
    unsigned char cause = 0;
    unsigned char IE = 0;
    unsigned short length = 0;
    for(unsigned char i = 0; i < 12; i++){

        if ((current_IE + 4) > data_end){break;} //End of packet
        //length = *(short*)(current_IE + 1); Casting only works on aligned data which GTP-C is fucking not
        if (bpf_probe_read_kernel((void *)&length, 1, current_IE + 2) < 0){prog_stats(FATERR_CTR); return TC_ACT_OK;}
        if (bpf_probe_read_kernel((void *)&length + 1, 2, current_IE + 1) < 0){prog_stats(FATERR_CTR); return TC_ACT_OK;} 
        if (bpf_probe_read_kernel((void *)&IE, 1, current_IE) < 0){prog_stats(FATERR_CTR); return TC_ACT_OK;}
        if ((current_IE + 4 + length) > data_end){ 
            prog_stats(FATERR_CTR); 
            return TC_ACT_OK;
        }
          

        if (IE == 75){ //IMEI
            if (length > 8){ prog_stats(FATERR_CTR); return TC_ACT_OK;}
            bpf_probe_read_kernel((void *)&info.imei, length, current_IE + 4);
            
        }
        if (IE == 1){ //IMSI
            if (length > 8){prog_stats(SES_REQ_CTR);return TC_ACT_OK;}
            bpf_probe_read_kernel((void *)&info.imsi, length, current_IE + 4);
        }
        if (IE == 76){ //MSISDN
            if (length > 8){prog_stats(SES_RESP_CTR);return TC_ACT_OK;}
            bpf_probe_read_kernel((void *)&info.msisdn, length, current_IE + 4);
        }
        if (IE == 79){ //PAA
            if ((current_IE + 5) > data_end){prog_stats(GTPU_IN_CTR); return TC_ACT_OK;}
            bpf_probe_read_kernel((void *)&info.PDN_type, 1, current_IE + 4);
            switch (info.PDN_type) {
            case 0x01: //IPv4
                {
                if ((current_IE + 4 + 5) > data_end || length != 5){prog_stats(GTPU_IN_CTR); return TC_ACT_OK;}
                bpf_probe_read_kernel((void *)&info.ipv4_addr.data.in6_u.u6_addr32[3], 4, current_IE + 5);
                info.ipv4_addr.data.in6_u.u6_addr16[5] = 0xffff;
                break;
                }
            case 0x02: //IPv6
                {
                if ((current_IE + 4 + 18) > data_end || length != 18){prog_stats(GTPU_OUT_CTR); return TC_ACT_OK;}
                bpf_probe_read_kernel((void *)&info.ipv6_addr.data, 16, current_IE + 6);
                break;
                }
            case 0x03: //IPv4v6
                {
                if ((current_IE + 4 + 22) > data_end || length != 22){prog_stats(SES_RESP_CTR); return TC_ACT_OK;}
                bpf_probe_read_kernel((void *)&info.ipv6_addr.data, 16, current_IE + 6);
                bpf_probe_read_kernel((void *)&info.ipv4_addr.data.in6_u.u6_addr32[3], 4, current_IE + 22);
                info.ipv4_addr.data.in6_u.u6_addr16[5] = 0xffff;
                break;
                }
            default:
                return TC_ACT_OK;
            }
        }
        if (IE == 2){ //Cause
            if (length != 2){return TC_ACT_OK;}
            bpf_probe_read_kernel((void *)&cause, 1, current_IE + 4);
        }
        current_IE += (4 + length); 
    }
    bpf_probe_read_kernel((void *)&info.ipv6_addr.data, 16, current_IE + 6);
    __builtin_memcpy((void *)&key->sqn, (void *)&gtp2c->sqn, 3);
    if (gtp2c->type == 32 && info.msisdn != ULLONG_MAX && info.imsi != ULLONG_MAX && info.imei != ULLONG_MAX){ //Request, checking mandatory IE, assembler logic
        info.state = SES_REQ_CTR;
        prog_stats(SES_REQ_CTR);} 
    if (gtp2c->type == 33 && (info.PDN_type == 1 || info.PDN_type == 2 || info.PDN_type == 3)){ //Response, checking mandatory IE, assembler logic
        info.state = SES_RESP_CTR;
        prog_stats(SES_RESP_CTR);}
    if (info.state != 0){
        struct gtpc_info* info_p = bpf_map_lookup_elem(&gtpc_ass, key);
        if(info_p == 0){
            int ret = bpf_map_update_elem(&gtpc_ass, key, &info, BPF_NOEXIST);
            if (ret < 0) { prog_stats(FATERR_CTR); return TC_ACT_OK;}
        }
        else{
            if(info_p->state == 0 || info.state == info_p->state){
                int ret = bpf_map_update_elem(&gtpc_ass, key, &info, BPF_ANY);
                if (ret < 0) { prog_stats(FATERR_CTR); return TC_ACT_OK;}
            }
            else if(info_p->state == SES_REQ_CTR && info.state == SES_RESP_CTR){
                info_p->state = 0;
                info.ipv4_addr.prefixlen = 128;
                info.ipv6_addr.prefixlen = 64;
                switch (info.PDN_type) {
                case 1: //IPv4
                    {bpf_map_update_elem(&ip_imsi, &info.ipv4_addr, &info_p->imsi, BPF_ANY);prog_stats(GTPC_ASS_SUC);break;}
                case 2: //IPv6
                    {bpf_map_update_elem(&ip_imsi, &info.ipv6_addr, &info_p->imsi, BPF_ANY);prog_stats(GTPC_ASS_SUC);break;}
                case 3: //IPv4v6
                {
                    bpf_map_update_elem(&ip_imsi, &info.ipv4_addr, &info_p->imsi, BPF_ANY);
                    bpf_map_update_elem(&ip_imsi, &info.ipv6_addr, &info_p->imsi, BPF_ANY);
                    prog_stats(GTPC_ASS_SUC);
                    break;
                }
                default:
                    return TC_ACT_OK;
                }  
            }
            else if(info_p->state == SES_RESP_CTR && info.state == SES_REQ_CTR){
                info_p->state = 0;
                info_p->ipv4_addr.prefixlen = 128;
                info_p->ipv6_addr.prefixlen = 64;
                switch (info.PDN_type) {
                case 1: //IPv4
                    {bpf_map_update_elem(&ip_imsi, &info_p->ipv4_addr, &info.imsi, BPF_ANY);prog_stats(GTPC_ASS_SUC);break;}
                case 2: //IPv6
                    {bpf_map_update_elem(&ip_imsi, &info_p->ipv6_addr, &info.imsi, BPF_ANY);prog_stats(GTPC_ASS_SUC);break;}
                case 3: //IPv4v6
                    {
                    bpf_map_update_elem(&ip_imsi, &info_p->ipv4_addr, &info.imsi, BPF_ANY);
                    bpf_map_update_elem(&ip_imsi, &info_p->ipv6_addr, &info.imsi, BPF_ANY);
                    prog_stats(GTPC_ASS_SUC);break;
                    }
                default:
                    return TC_ACT_OK;
                }  
            }
        }
    }
     
    //IP-IMSI loading
    return TC_ACT_OK;
}

/* Decodes SNI */
SEC("classifier")
int sni_extractor(struct __sk_buff *skb){
    __u32 index = ZERO;
    struct tail_args* tail_args = (struct tail_args*)bpf_map_lookup_elem(&tail_arg_map, &index);
    if (!tail_args) { prog_stats(FATERR_CTR); prog_stats(TAILCALL_ERR); return TC_ACT_OK; }
    unsigned int next_header_off = tail_args->next_header_off;
    
    unsigned int load = skb->len;
    if (load < 32){ prog_stats(FATERR_CTR); prog_stats(SNI_ERR); return TC_ACT_OK; }
    else if (load > 1600)
    {
        load = 1600;
    }
    int ret = bpf_skb_load_bytes(skb, 0, (void*)tail_args->tls, load);
    if (ret < 0) { prog_stats(FATERR_CTR); prog_stats(SNI_ERR); return TC_ACT_OK; }

    void* data = (void*)(unsigned long) tail_args->tls + next_header_off;
    void* data_end = data + skb->len;
    
    __u8 handshake_type = 0;
    data = data + 5; /* current pos is at handshake type */
    if (bpf_probe_read_kernel(&handshake_type, sizeof(handshake_type), data) != 0){
        prog_stats(FATERR_CTR);
        prog_stats(SNI_ERR);
        return TC_ACT_OK;
    }

    if (handshake_type != 0x01)  { /* not Client Hello */
        return TC_ACT_OK;
    }
 
    prog_stats(CLIENT_HELLO);

    __u8 session_id_length;
    data = data + 38; /* now at session_id_length, 38 = length + version + random(32B) */
    bpf_probe_read_kernel(&session_id_length, sizeof(session_id_length), data);
    data = data + session_id_length + 1; /* now at cipher_suites_length */

    volatile __u16 cipher_suites_length = 0;
    bpf_probe_read_kernel((void *)&cipher_suites_length, sizeof(cipher_suites_length), data);
    cipher_suites_length = htons(cipher_suites_length);
    data = data + sizeof(cipher_suites_length) + cipher_suites_length; /* now at compression_methods_length */
    __u8 compression_methods_length = 0;

    bpf_probe_read_kernel(&compression_methods_length, sizeof(compression_methods_length), data);

    data = data + compression_methods_length + sizeof(compression_methods_length); /* now at extensions_length */

    __u16 extensions_length = 0;
    bpf_probe_read_kernel(&extensions_length, sizeof(extensions_length), data);
    extensions_length = htons(extensions_length);
    data = data + 2; /* now at extensions */

    // find inner map for user
    ipv6_lpm_key UE_src_ip = {0};
    UE_src_ip.prefixlen = 128;
    UE_src_ip.data = tail_args->user_ip;
    mapid_session new_mapnum = {0};
    mapid_session* inner_map_number = bpf_map_lookup_elem(&mapid, &UE_src_ip);
    if (!inner_map_number) { /* user must be already created in main function */
        prog_stats(FATERR_CTR);
        prog_stats(MAPID_ERR);
        return TC_ACT_OK;
    }
    else {
        new_mapnum.map_num = inner_map_number->map_num;
    }
    unsigned int* inner_fd = bpf_map_lookup_elem(&outer_map, &new_mapnum.map_num);
    if (!inner_fd) { prog_stats(SNI_ERR); return TC_ACT_OK; }

    char sni[SNI_SIZE] = {0}; /* buffer for server name */
    __u16 extension_type = 0;
    __u16 current_ext_len = 0;
    unsigned int offset = 0;
    void* sni_data = NULL;
    __u16 sni_length = 0;
    
    for( unsigned char i = 0; i < 12; i++){ /* Iterating over the extensions to find server_name (type 0) */

        bpf_probe_read_kernel(&extension_type, sizeof(extension_type), data);
        bpf_probe_read_kernel(&current_ext_len, sizeof(current_ext_len), data + 2);

        extension_type = htons(extension_type);
        current_ext_len= htons(current_ext_len);
        
        if (extension_type != 0 && current_ext_len >= 0 && current_ext_len < 1000) { /* not sni */
            data = data + 4 + current_ext_len; /* skip current extension type+len+data */
            continue; 
        }
        
        bpf_probe_read_kernel(&sni_length, sizeof(sni_length), data + 7);
        sni_data = data + 9; /* hostname */
        sni_length = htons(sni_length);

        if (sni_length > SNI_SIZE) { prog_stats(SNI_ERR); return TC_ACT_OK; }
        bpf_probe_read_kernel(sni, sni_length, sni_data);

        // fill inner map
        struct service_info* service = bpf_map_lookup_elem(inner_fd, &tail_args->serv_dirs);
        if ( !service ) { prog_stats(SNI_ERR); return TC_ACT_OK; }
        __builtin_memcpy((void *)&service->sni, (void *)sni, SNI_SIZE);

        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

/* dumps DNS packets */
SEC("classifier")
int dns_capture(struct __sk_buff *skb){
    __u32 index = ZERO;
    struct tail_args* tail_args = (struct tail_args*)bpf_map_lookup_elem(&tail_arg_map, &index);
    if (!tail_args) { prog_stats(FATERR_CTR); prog_stats(TAILCALL_ERR); return TC_ACT_OK; }

    if (tail_args->reason == 1){ /* dns capture */
        dump(skb, tail_args->direction);
    }
    return TC_ACT_OK;
}

/* decodes L4 header and structures service informations, then uploads it to inner map */
static __always_inline int decode_L4(struct __sk_buff* skb, void* next_header, struct h_info* hdr_info, unsigned int* inner_fd, unsigned int len, int direction) {
    __u64 ts = bpf_ktime_get_ns();
    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    struct service_meta service_dirs = {0};
    __u32 user_port = 0;
    service_dirs.protocol = hdr_info->protocol;
    if (direction == TO_INTERNET) { service_dirs.service_addr = hdr_info->daddr; }
    else { service_dirs.service_addr = hdr_info->saddr; }
    
    if ((void*)next_header < data || (void*)next_header >= data_end) {
        prog_stats(BAD_PKT_CTR);
        return -1;
    }

    if(hdr_info->protocol == 17 || hdr_info->protocol == 6) { // UDP or TCP
        if ((void*)next_header + 2 > data_end) {
            prog_stats(BAD_PKT_CTR);
            return TC_ACT_OK;
        }
        
        unsigned short src;
        if (bpf_probe_read_kernel(&src, sizeof(src), next_header) < 0) {
            prog_stats(BAD_PKT_CTR);
            return TC_ACT_OK;
        }

        if ((void*)next_header + 4 > data_end) {
            prog_stats(BAD_PKT_CTR);
            return TC_ACT_OK;
        }

        unsigned short dest;
        if (bpf_probe_read_kernel(&dest, sizeof(dest), (void*)next_header + 2) < 0) {
            prog_stats(BAD_PKT_CTR);
            return TC_ACT_OK;
        }

        if (direction == TO_INTERNET) {
            service_dirs.service_port = dest;
            user_port = src;
        } else {
            service_dirs.service_port = src;
            user_port = dest;
        }
    }
    
    struct tcphdr* inner_tcp = NULL;
    if (hdr_info->protocol == 6) { // TCP
        if ((void *)next_header + sizeof(struct tcphdr) > (void *)(long)skb->data_end) {
            prog_stats(BAD_PKT_CTR);
            return -1;
        }
        inner_tcp = (struct tcphdr *)next_header;
    }

    struct service_info* service_data = bpf_map_lookup_elem(inner_fd, &service_dirs);
    struct service_info newservice = {0};

    // creating entry for new user
    if (!service_data) {
        bpf_map_update_elem(inner_fd, &service_dirs, &newservice, BPF_ANY);
        if (direction == TO_UE) {
            newservice.rx_first_ts = ts;
            newservice.jit_calc.rx_first_packet = 1;
            newservice.jit_calc.rx_second_packet = 1;
            newservice.jit_calc.rx_t_prev = ts;
            if (inner_tcp) {
                if ((void*)inner_tcp + 8 > data_end) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }
                if (bpf_probe_read_kernel(&newservice.rx_latest_tcp_seq, sizeof(newservice.rx_latest_tcp_seq), (void*)inner_tcp + 4) < 0) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }
                newservice.tcp_state = INITIAL;
            }
        }
        else { // TO_INTERNET
            newservice.tx_first_ts = ts;
            newservice.jit_calc.rx_first_packet = 1;
            newservice.jit_calc.rx_second_packet = 1;
            newservice.jit_calc.rx_t_prev = ts;
            if (inner_tcp) {
                if ((void*)inner_tcp + 14 > data_end) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }
                if (bpf_probe_read_kernel(&newservice.tx_latest_tcp_seq, sizeof(newservice.tx_latest_tcp_seq), (void*)inner_tcp + 4) < 0) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }
                newservice.tcp_state = INITIAL;
    
                __u16 tcp_flags_word = 0;
                if (bpf_probe_read_kernel(&tcp_flags_word, sizeof(tcp_flags_word), (void*)inner_tcp + 12) < 0) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }
                __u8 tcp_flags = tcp_flags_word >> 8;
                __u8 syn = (tcp_flags >> 1) & 0x1; // SYN is bit 1
                __u8 ack = (tcp_flags >> 4) & 0x1; // ACK is bit 4
    
                if (syn == 1 && newservice.tcp_state == INITIAL && ack == 0) {
                    newservice.rtt_measuring = ts;
                    newservice.tcp_state = SYN_SENT;
                }
            }
        }
        service_data = &newservice;
        bpf_map_update_elem(inner_fd, &service_dirs, &newservice, BPF_ANY);
        service_data = bpf_map_lookup_elem(inner_fd, &service_dirs);
        if (!service_data) {
            prog_stats(FATERR_CTR);
            prog_stats(NEW_SERVICE_ERR);
            return TC_ACT_OK;
        }
    }

    // user entry already exists
    if (service_data) {
        if (direction == TO_UE) {

            struct jitter_calc jitter_local;
            __builtin_memcpy(&jitter_local, &service_data->jit_calc, sizeof(jitter_local));
            EWMA_jitter(&jitter_local, ts);
            __builtin_memcpy(&service_data->jit_calc, &jitter_local, sizeof(jitter_local));

            //EWMA_jitter(&service_data->jit_calc, ts);
            
            service_data->rx_bytes += len;
            service_data->rx_packets += 1;
            if (inner_tcp) {
                if ((void*)inner_tcp + sizeof(struct tcphdr) > data_end) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }
            
                __u32 tcp_seq = 0;
                if (bpf_probe_read_kernel(&tcp_seq, sizeof(tcp_seq), (void*)inner_tcp + 4) < 0) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }
            
                if (tcp_seq < service_data->rx_latest_tcp_seq) {
                    service_data->rx_tcp_retrans += 1;
                }
                service_data->rx_latest_tcp_seq = tcp_seq;
            }
            service_data->rx_latest_ts = ts;
        } 
        else { // TO_INTERNET

            struct jitter_calc jitter_local;
            __builtin_memcpy(&jitter_local, &service_data->jit_calc, sizeof(jitter_local));
            EWMA_jitter(&jitter_local, ts);
            __builtin_memcpy(&service_data->jit_calc, &jitter_local, sizeof(jitter_local));

            //EWMA_jitter(&service_data->jit_calc, ts);

            service_data->tx_bytes += len;
            service_data->tx_packets += 1;
            service_data->tx_latest_ts = ts;
            if (inner_tcp) {
                if ((void*)inner_tcp + 14 > data_end) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }

                __u16 tcp_flags_word = 0;
                if (bpf_probe_read_kernel(&tcp_flags_word, sizeof(tcp_flags_word), (void*)inner_tcp + 12) < 0) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }

                __u8 tcp_flags = tcp_flags_word >> 8;
                __u8 syn = (tcp_flags >> 1) & 0x1; // SYN is bit 1
                __u8 ack = (tcp_flags >> 4) & 0x1; // ACK is bit 4
                
                if (syn == 1 && service_data->tcp_state == SYN_SENT && ack == 0) {
                    service_data->rtt_measuring = ts;
                }
                if (syn == 0 && service_data->tcp_state == SYN_SENT && ack == 1) {
                    service_data->tcp_state = ESTABLISHED;
                    service_data->rtt_measuring = ts - service_data->rtt_measuring;
                }
                
                __u32 tcp_seq = 0;
                if (bpf_probe_read_kernel(&tcp_seq, sizeof(tcp_seq), (void*)inner_tcp + 4) < 0) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }

                if (tcp_seq < service_data->tx_latest_tcp_seq) {
                    service_data->tx_tcp_retrans += 1;
                }
                service_data->tx_latest_tcp_seq = tcp_seq;
            }
        }

        if (inner_tcp) {
            if ((void*)inner_tcp + 14 > data_end) {
                prog_stats(BAD_PKT_CTR);
                return TC_ACT_OK;
            }
            
            __u16 tcp_flags_word = 0;
            if (bpf_probe_read_kernel(&tcp_flags_word, sizeof(tcp_flags_word), (void*)inner_tcp + 12) < 0) {
                prog_stats(BAD_PKT_CTR);
                return TC_ACT_OK;
            }
    
            // Extract doff (upper 4 bits) and convert to bytes (multiply by 4)
            int tcp_header_len = (bpf_ntohs(tcp_flags_word) >> 12) * 4;
            
            void* tls_record_header = (void*)inner_tcp + tcp_header_len;
            if (tls_record_header + 1 > (void*)(long)skb->data_end) { return TC_ACT_OK; }
            
            __u8 tls_content_type = 0;
            bpf_probe_read_kernel(&tls_content_type, sizeof(tls_content_type), tls_record_header);
            
            // Entrypoint for SNI extractor
            if (service_dirs.service_port == 0xBB01 && tls_content_type == 0x16) { // Service port is 443 + Handshake protocol
                prog_stats(HANDSHAKE);
                __u32 sni_index = 0;
                struct tail_args* tail_args = (struct tail_args*)bpf_map_lookup_elem(&tail_arg_map, &sni_index);
                if (!tail_args) {
                    return -1;
                }
                tail_args->next_header_off = ((void*)inner_tcp + tcp_header_len) - data;
                tail_args->serv_dirs.protocol = service_dirs.protocol;
                tail_args->serv_dirs.service_addr.in6_u = service_dirs.service_addr.in6_u;
                tail_args->serv_dirs.service_port = service_dirs.service_port;
                if (direction == TO_INTERNET) { tail_args->user_ip = hdr_info->saddr; } 
                else { tail_args->user_ip = hdr_info->daddr; }
                    
                int ret = bpf_map_update_elem(&tail_arg_map, &sni_index, tail_args, BPF_ANY);
                if (ret < 0) { prog_stats(FATERR_CTR); prog_stats(TAILCALL_ERR); return -1; }
                sni_index = SNI_EXTR;
                bpf_tail_call(skb, &func_map, sni_index);
                prog_stats(FATERR_CTR);
                prog_stats(TAILCALL_ERR);
                return TC_ACT_OK;
            }
        }
    }

    // Entrypoint for DNS capture (protocol is tcp/udp and port is 53)
    if ( ((hdr_info->protocol == 17) || (hdr_info->protocol == 6)) && ((service_dirs.service_port == 0x3500) || (user_port == 0x3500))){
        prog_stats(DNS);
        __u32 dns_index = 0;
        struct tail_args* tail_args = (struct tail_args*)bpf_map_lookup_elem(&tail_arg_map, &dns_index);
        if (!tail_args) { return -1; }

        tail_args->reason = 1; // dns cap
        tail_args->direction = direction; // to UE is 0 (ingress), to Internet is 1 (egress)
        
        int ret = bpf_map_update_elem(&tail_arg_map, &dns_index, tail_args, BPF_ANY);
        if (ret < 0) { prog_stats(FATERR_CTR); prog_stats(TAILCALL_ERR); return -1;}
        dns_index = DNS_CAP;
        bpf_tail_call(skb, &func_map, dns_index);
        prog_stats(FATERR_CTR);
        prog_stats(TAILCALL_ERR);
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

SEC("classifier")
int lawful_interception(struct __sk_buff* skb){
    __u32 index = ZERO;
    struct tail_args* tail_args = (struct tail_args*)bpf_map_lookup_elem(&tail_arg_map, &index);
    if (!tail_args) { prog_stats(FATERR_CTR); prog_stats(TAILCALL_ERR); return TC_ACT_OK; }
    dump(skb, tail_args->direction);
    return TC_ACT_OK;
}

SEC("classifier")
int debug_trace(struct __sk_buff* skb){
    __u32 index = ZERO;
    struct tail_args* tail_args = (struct tail_args*)bpf_map_lookup_elem(&tail_arg_map, &index);
    if (!tail_args) { prog_stats(FATERR_CTR); prog_stats(TAILCALL_ERR); return TC_ACT_OK; }
    // Ide Laca kell
    //dump(skb, tail_args->direction);
    return TC_ACT_OK;
}

/* assigns map number to new user, if user is already logged, queries fd of user's map,
   then calls l4 protocol decoding function */
SEC("classifier")
int qos_logic(struct __sk_buff* skb){
    __u64 ts = bpf_ktime_get_ns();
    __u32 index = ZERO;
    struct tail_args* tail_args = (struct tail_args*)bpf_map_lookup_elem(&tail_arg_map, &index);
    if (!tail_args) { prog_stats(FATERR_CTR); prog_stats(TAILCALL_ERR); return TC_ACT_OK; }
    
    unsigned int next_header_off = tail_args->next_header_off;
    struct h_info hdr_info = tail_args->hdr_info;
    struct in6_addr ue_ip = tail_args->user_ip;
    int dir = tail_args->direction;
    int node_sum = tail_args->node_sum;
    
    ipv6_lpm_key UE_src_ip = {0};
    UE_src_ip.prefixlen = 128;
    UE_src_ip.data = ue_ip;

    mapid_session new_mapnum = {0};
    mapid_session* inner_map_number = bpf_map_lookup_elem(&mapid, &UE_src_ip);

    int ret = 0;
    if (!inner_map_number) { // log new user
        /*struct in6_addr first_elem_addr = {0};
        struct ipv6_lpm_key first_elem = {128, first_elem_addr};
        inner_map_number = bpf_map_lookup_elem(&mapid, &first_elem);

        if (!inner_map_number) { // first element containing the size of the map should always exist
            prog_stats(FATERR_CTR); prog_stats(MAPID_ERR);
            return -1;
        }

        new_mapnum.map_num = inner_map_number->map_num;
        new_mapnum.flags = add_nodeval(new_mapnum.flags, node_sum);

        ret = bpf_map_update_elem(&mapid, &UE_src_ip, &new_mapnum, BPF_NOEXIST);
        if (ret < 0) { prog_stats(FATERR_CTR); prog_stats(MAPID_ERR); return -1; }
        inner_map_number->map_num += 1;*/

        // assigning inner map number using free pointers
        new_mapnum.map_num = next_free_mapid();
        if (new_mapnum.map_num == -1 ) { 
            prog_stats(FATERR_CTR); 
            return -1; 
        }
        new_mapnum.flags = add_nodeval(new_mapnum.flags, node_sum);
        new_mapnum.first_ts = ts;
        ret = bpf_map_update_elem(&mapid, &UE_src_ip, &new_mapnum, BPF_NOEXIST);
        if (ret < 0) { bpf_printk("Failed to update mapid: %d", ret); prog_stats(FATERR_CTR); prog_stats(MAPID_ERR); return -1; }

        // Filling reverse lookup map
        __u32 idx = new_mapnum.map_num;
        struct user_reverse_lookup rev = {0};
        rev.first_ts = ts;
        rev.user_addr = UE_src_ip;
        
        ret = bpf_map_update_elem(&rev_lookup, &idx, &rev, BPF_ANY);
        if (ret < 0) { bpf_printk("Failed to update rev_lookup: %d", ret); prog_stats(FATERR_CTR); prog_stats(MAPID_ERR); return -1; }

        struct user_reverse_lookup* lu = bpf_map_lookup_elem(&rev_lookup, &idx);
        if (!lu) { bpf_printk("Failed to lookup reverse lookup entry"); prog_stats(MAPID_ERR); return TC_ACT_OK; }
        __u32 lu_addr_sum = 0;
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            lu_addr_sum += lu->user_addr.data.s6_addr[i];
        }
        
        __u32 addr_sum = 0;
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            addr_sum += rev.user_addr.data.s6_addr[i];
        }
    }
    else  {  // entry already exists for current user
        new_mapnum.map_num = inner_map_number->map_num;
        inner_map_number->flags = add_nodeval(inner_map_number->flags, node_sum);
    }

    unsigned int* inner_fd = bpf_map_lookup_elem(&outer_map, &new_mapnum.map_num);
    if (!inner_fd) { 
        prog_stats(FATERR_CTR);
        prog_stats(OUTER_MAP_ERR);
        return TC_ACT_OK; 
    }

    if (next_header_off > skb->len) { return TC_ACT_OK; }
    else {
        void* next_header = (void*)(long)(skb->data) + next_header_off;
        ret = decode_L4(skb, next_header, &hdr_info, inner_fd, skb->len, dir);
        if ( ret == -1) { return -1; }
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

/* decodes gtpu hdr then calls inner headers decoder (inner ip, inner tcp/udp) */
static __always_inline int gtpu_decoder(struct __sk_buff* skb, struct gtp1_header* gtpu, unsigned int len, void* data_end, int direction, int node_sum) {
    void* next_header_start = (void *)gtpu + 8;

    unsigned char examined_bit = gtpu->flags & 0x10; // check protocol type
    if (examined_bit == 0) { // if PT is 0, GTP' is discarded
        prog_stats(DONTCARE_CTR);
        return TC_ACT_OK;
    }

    examined_bit = gtpu->flags & 0x1; // check N-PDU flag
    if (examined_bit != 0) {
        next_header_start = next_header_start + 1;
    }

    examined_bit = gtpu->flags & 0x2; // check SEQ flag
    if (examined_bit != 0) {
        next_header_start = next_header_start + 2;
    }

    examined_bit = gtpu->flags & 0x4; // check EXT HDR flag
    for (unsigned char i = 0; i <= 25; i++) {
        unsigned char len; // length of the whole extension header
        if (examined_bit == 0) {
            break;
        }

        if ((next_header_start + 1) > data_end) {
            prog_stats(BAD_PKT_CTR);
            return -1;
        }

        len = ((*((unsigned char *)next_header_start)) * 4) - 1;

        if ((next_header_start + len + 4) > data_end) {
            prog_stats(BAD_PKT_CTR);
            return -1;
        }
        unsigned char* next_ext_hdr_type = (unsigned char*)next_header_start + len;
        examined_bit = *next_ext_hdr_type;
        next_header_start = (next_header_start + (len + 1));
    }

    if ((next_header_start + 4) > data_end) {
        prog_stats(BAD_PKT_CTR);
        return -1;
    }

    if (direction == 1) { prog_stats(GTPU_IN_CTR); }
    else { prog_stats(GTPU_OUT_CTR); }

    struct h_info hdr_info = {0};
    void* data = (void*)(long)skb->data;
    next_header_start = decode_ip(next_header_start, data, data_end, &hdr_info);
    if (!next_header_start) {
        return TC_ACT_OK;
    }

    /* entrypoint for gtp-u pipeline tailcall */
    __u32 gtpu_index = 0;
    struct tail_args* tail_args = (struct tail_args*)bpf_map_lookup_elem(&tail_arg_map, &gtpu_index);
    if (!tail_args) { return -1; }
    tail_args->direction = direction;
    tail_args->hdr_info = hdr_info;
    tail_args->next_header_off = (unsigned int)((char*)next_header_start - (char*)data);
    tail_args->user_ip = (direction == TO_INTERNET) ? hdr_info.saddr : hdr_info.daddr;
    tail_args->node_sum = node_sum;

    int ret = bpf_map_update_elem(&tail_arg_map, &gtpu_index, tail_args, BPF_ANY);
    if (ret < 0) { prog_stats(FATERR_CTR); prog_stats(TAILCALL_ERR); return -1; }
    gtpu_index = QOS_LOGIC;
    bpf_tail_call(skb, &func_map, gtpu_index);

    return TC_ACT_OK;
}

/* checks the protocols, ports & ip addresses, if packet is not GTP/broadcast/etc 
   returns TC_ACT_OK else goes to gtp header parser */
static __always_inline int packet_interesting(struct __sk_buff *skb){

    if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
        prog_stats(DONTCARE_CTR);
        return TC_ACT_OK;
    }

    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    struct ethhdr* eth = data;
    __u32 offset = sizeof(struct ethhdr);

    if (data + offset > data_end) {
        prog_stats(BAD_PKT_CTR);
        return -1; 
    }

	if (eth->h_proto != (0x0008)) { /* IPv4 packets only (outer IP) */
        prog_stats(DONTCARE_CTR);
        return TC_ACT_OK; 
    }

    offset += sizeof(struct iphdr);
    if (data + offset > data_end) {
        prog_stats(BAD_PKT_CTR);
        return -1;
    }
    struct iphdr* ip = data + sizeof(struct ethhdr); /* get outer IPv4 header */

    if (ip->protocol != 17) {
        prog_stats(DONTCARE_CTR);
        return TC_ACT_OK; 
    }

    volatile unsigned int node_sum = 0;
    int direction = 0;
    ipv4_lpm_key srcIP = {32, ip->saddr};
    node_sum += node_value(srcIP);
    if (node_sum == 4){ direction = TO_UE; }
    else { direction = TO_INTERNET; }

    ipv4_lpm_key dstIP = {32, ip->daddr};
    node_sum += node_value(dstIP);
    
    // Valid node sums: 5: 4G+HR, 6: 5G+HR, 11: 2G+HR, 16: 4G+R, 19: 2G+R, other is uninteresting
    if ( (node_sum != 5 ) && (node_sum != 6 ) && (node_sum != 11 ) && (node_sum != 16 ) && (node_sum != 19 )){
        prog_stats(DONTCARE_CTR);
        return TC_ACT_OK;
    }

    offset += sizeof(struct udphdr);
    if (data + offset > data_end) {
        prog_stats(BAD_PKT_CTR);
        return -1; 
    }

    struct udphdr* udp = (void *)ip + (ip->ihl*4);
     if ((void *)udp + sizeof(struct udphdr) > data_end) {
        prog_stats(BAD_PKT_CTR);
        return -1;
    }

    // Entrypoint for GTPC assembler
    if ((udp->dest == GTP2C_PORT) || (udp->source == GTP2C_PORT)) {
        __u32 index = 0;
        struct tail_args* tail_args = (struct tail_args*)bpf_map_lookup_elem(&tail_arg_map, &index);
        if(!tail_args) { return TC_ACT_OK; }
        tail_args->next_header_off = ((void *)udp + sizeof(struct udphdr)) - data;
        
        if(direction == TO_UE) {
            tail_args->gtpc_flowkey.reqIP = ip->daddr;
            tail_args->gtpc_flowkey.respIP = ip->saddr;
            tail_args->gtpc_flowkey.reqport = udp->dest;
            tail_args->gtpc_flowkey.respport = udp->source;
        }
        else {
            tail_args->gtpc_flowkey.reqIP = ip->saddr;
            tail_args->gtpc_flowkey.respIP = ip->daddr;
            tail_args->gtpc_flowkey.reqport = udp->source;
            tail_args->gtpc_flowkey.respport = udp->dest;
        }
        int ret = bpf_map_update_elem(&tail_arg_map, &index, tail_args, BPF_ANY);
        if (ret < 0) { prog_stats(FATERR_CTR); prog_stats(TAILCALL_ERR); return -1;}
        index = GTPC_ASS;
        bpf_tail_call(skb, &func_map, index);
        prog_stats(FATERR_CTR);
        prog_stats(TAILCALL_ERR);
        return TC_ACT_OK;
    }

    if ((udp->dest != GTP1U_PORT) ) {
        prog_stats(DONTCARE_CTR);
        return TC_ACT_OK;
    }

    offset += sizeof(struct gtp1_header);
    if (data + offset > data_end) {
        prog_stats(BAD_PKT_CTR);
        return -1; 
    }

    struct gtp1_header* gtpu = (void *)udp + sizeof(udp);
    if ((void *)gtpu + sizeof(struct gtp1_header) > data_end) {
        prog_stats(BAD_PKT_CTR);
        return -1;
    }

    if (gtpu->type != 0xFF){ // G-PDU is 255 msg type
        prog_stats(DONTCARE_CTR);
        return TC_ACT_OK;
    }

    return gtpu_decoder(skb, gtpu, skb->len, data_end, direction, node_sum);
}

SEC("classifier")
int monitor_mnet(struct __sk_buff *skb) {
    prog_stats(INGRESS_FIRES);
    unsigned int kernel_index = ENABLE_KERNEL;
    unsigned int* kernel_value = bpf_map_lookup_elem(&reporter, &kernel_index);
    if (kernel_value && *kernel_value == 1) {
        packet_interesting(skb);
    }
    return TC_ACT_OK;
}

SEC("classifier")
int monitor_wnet(struct __sk_buff *skb) {
    prog_stats(INGRESS_FIRES);

    unsigned int kernel_index = ENABLE_KERNEL;
    unsigned int* kernel_value = bpf_map_lookup_elem(&reporter, &kernel_index);
    if (!kernel_value || *kernel_value != 1) {
        return TC_ACT_OK; 
    }

    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    void* next_header = data;

    // start with eth
    struct ethhdr* eth = next_header;
    if (next_header + sizeof(struct ethhdr) > data_end) {
        prog_stats(BAD_PKT_CTR);
        return TC_ACT_OK;
    }
    next_header += sizeof(struct ethhdr);

    __u16 proto = bpf_ntohs(eth->h_proto);
    __u32 vlan_count = 0;

    // handling vlan tags
    for (vlan_count = 0; vlan_count < 4 && proto == ETH_P_8021Q; vlan_count++) {
        struct vlan_hdr* inner_vlan = next_header;
        if (next_header + sizeof(struct vlan_hdr) > data_end) {
            prog_stats(BAD_PKT_CTR);
            return TC_ACT_OK;
        }
        proto = bpf_ntohs(inner_vlan->h_vlan_encapsulated_proto);
        next_header += sizeof(struct vlan_hdr);
    }

    // handling mpls headers
    if (proto == ETH_P_MPLS_UC) {
        __u32 mpls_count = 0;
        for (mpls_count = 0; mpls_count < 10; mpls_count++) {
            if (next_header + sizeof(struct mpls_label) > data_end) {
                prog_stats(BAD_PKT_CTR);
                return TC_ACT_OK;
            }
            struct mpls_label* mpls = next_header;
            next_header += sizeof(struct mpls_label);
            __u32 label = bpf_ntohl(mpls->entry);
            if (label & 0x100) { // reached bottom of mpls stack
                if (next_header + sizeof(__u16) > data_end) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }
                proto = bpf_ntohs(*(__u16*)next_header);
                break;
            }
        }
    }

    if (proto == ETH_P_IP) {
        if (next_header + sizeof(struct iphdr) > data_end) {
            prog_stats(DONTCARE_CTR);
            return TC_ACT_OK;
        }

        // parse IP version and IHL
        __u8 ver_ihl = *(__u8*)next_header;
        __u8 ihl = ver_ihl & 0x0F;
        __u8 version = ver_ihl >> 4;
        if (version != 4 || ihl < 5 || ihl > 15) {
            prog_stats(BAD_PKT_CTR);
            return TC_ACT_OK;
        }

        __u8 ip_proto = *(__u8*)(next_header + 9); // protocol field at byte offset 9

        // VXLAN parsing shortcut
        if (proto == ETH_P_IP && ip_proto == IPPROTO_UDP) {
            void* udp_hdr = next_header + ihl * 4;
            if (udp_hdr + sizeof(struct udphdr) > data_end) {
                prog_stats(BAD_PKT_CTR);
                return TC_ACT_OK;
            }
            struct udphdr* udp = udp_hdr;
            if (bpf_ntohs(udp->dest) == VXLAN_PORT || bpf_ntohs(udp->source) == VXLAN_PORT) {
                struct vxlanhdr* vxlan = udp_hdr + sizeof(struct udphdr);
                if ((void*)vxlan + sizeof(struct vxlanhdr) > data_end) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }
                next_header = (void*)vxlan + sizeof(struct vxlanhdr);
                struct ethhdr* inner_eth = next_header;
                if ((void*)inner_eth + sizeof(struct ethhdr) > data_end) {
                    prog_stats(BAD_PKT_CTR);
                    return TC_ACT_OK;
                }
                proto = bpf_ntohs(inner_eth->h_proto);
                next_header += sizeof(struct ethhdr);

                if (proto != ETH_P_IP && proto != ETH_P_IPV6) {
                    prog_stats(DONTCARE_CTR);
                    return TC_ACT_OK;
                }

                for (vlan_count = 0; vlan_count < 4 && proto == ETH_P_8021Q; vlan_count++) {
                    struct vlan_hdr* inner_vlan = next_header;
                    if ((void*)inner_vlan + sizeof(struct vlan_hdr) > data_end) {
                        prog_stats(BAD_PKT_CTR);
                        return TC_ACT_OK;
                    }
                    proto = bpf_ntohs(inner_vlan->h_vlan_encapsulated_proto);
                    next_header += sizeof(struct vlan_hdr);
                }
            }
        }

    } else if (proto == ETH_P_IPV6) {
        if (next_header + 1 > data_end) {
            prog_stats(BAD_PKT_CTR);
            return TC_ACT_OK;
        }

        __u8 version = *(__u8*)next_header >> 4;
        if (version != 6) {
            prog_stats(BAD_PKT_CTR);
            return TC_ACT_OK;
        }

        // IPv6 header is fixed 40 bytes
        if (next_header + 40 > data_end) {
            prog_stats(BAD_PKT_CTR);
            return TC_ACT_OK;
        }

        __u8 ip_proto = *(__u8*)(next_header + 6); // Next Header field in IPv6
    } else {
        prog_stats(DONTCARE_CTR);
        return TC_ACT_OK;
    }

    // check if there is enough space for ip header
    if (next_header + sizeof(struct iphdr) > data_end) {
        prog_stats(BAD_PKT_CTR);
        return TC_ACT_OK;
    }

    // check if there is enough space for ip version
    if (next_header + 1 > data_end) {
        prog_stats(BAD_PKT_CTR);
        return TC_ACT_OK;
    }

    // decoding ip header
    struct h_info hdr_info = {0};
    next_header = decode_ip(next_header, data, data_end, &hdr_info);
    if (!next_header) {
        return TC_ACT_OK;
    }

    // determining packet direction based on ip addr (10.0.x.x is UE)
    int direction;
    if (is_user_ip(&hdr_info.saddr)) {
        direction = TO_INTERNET;
    } else if (is_user_ip(&hdr_info.daddr)) {
        direction = TO_UE;
    } else {
        direction = (skb->ingress_ifindex) ? TO_UE : TO_INTERNET;
    }

    struct ipv6_lpm_key user_ip = {0}; // extracting user ip
    user_ip.prefixlen = 128;
    user_ip.data = (direction == TO_INTERNET) ? hdr_info.saddr : hdr_info.daddr;

    prog_stats(WIRED_CONN);

    // QoS_LOGIC tailcall
    __u32 qos_index = 0;
    struct tail_args* tail_args = (struct tail_args*)bpf_map_lookup_elem(&tail_arg_map, &qos_index);
    if (!tail_args) {
        prog_stats(FATERR_CTR);
        prog_stats(TAILCALL_ERR);
        return TC_ACT_OK;
    }
    tail_args->next_header_off = (unsigned int)((char*)next_header - (char*)data);
    tail_args->hdr_info = hdr_info;
    tail_args->user_ip = user_ip.data;
    tail_args->direction = direction;
    tail_args->node_sum = 0; // Wired traffic no node_sum
    int ret = bpf_map_update_elem(&tail_arg_map, &qos_index, tail_args, BPF_ANY);
    if (ret < 0) {
        prog_stats(FATERR_CTR);
        prog_stats(TAILCALL_ERR);
        return TC_ACT_OK;
    }
    qos_index = QOS_LOGIC;
    bpf_tail_call(skb, &func_map, qos_index);
    prog_stats(FATERR_CTR);
    prog_stats(TAILCALL_ERR);
    return TC_ACT_OK;
}