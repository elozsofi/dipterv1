#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "sga_taps.h"
#include "common.h"

//#define IPPROTO_GRE 47
#define GREPROTO_ERSPAN1_LE	0xBE88

#define ETH_P_IP_LE			0x0008
#define ETH_P_IPV6_LE		0xDD86
#define ETH_P_VLAN_LE       0x0081

/* check output:
   sudo cat /sys/kernel/debug/tracing/trace_pipe */
#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

/*****************************************************************************
 * Local definitions and global variables
 *****************************************************************************/

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 /* 1 MB */);
	__uint(pinning, LIBBPF_PIN_BY_NAME);	
} sga_tc_ring_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct pkt_trace_data);
//	__uint(map_flags, BPF_F_NO_PREALLOC);
//	__uint(pinning, LIBBPF_PIN_BY_NAME);		
} sga_tc_packet_heap SEC(".maps");

// 1. TRIE MAP for port+IP-prefix lookup (2*2 lookups 4 every packet...)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __type(key, struct CIDR4);
    __type(value, struct AID_wcntr);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sga_tc_lip4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __type(key, struct CIDR6);
    __type(value, struct AID_wcntr);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sga_tc_lip6 SEC(".maps");

// 2. HASH MAP for alias(uint) matching for src/dst (1 lookup 4 every packet...)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct AID);
    __type(value, struct AID_wcntr);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sga_tc_lrule SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, int);
    __type(value, struct vtap_data);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sga_tc_data SEC(".maps");


/*****************************************************************************
 * .data section value storing the capture configuration
 *****************************************************************************/

static __always_inline char check_l4(unsigned char proto)
{
	switch (proto)
	{
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		return 1;

	default:
		return 0;
	}
}

static __always_inline char get_packet_islimited()
{
	int lkey = DATA_PCKLIMIT;

	unsigned int *pval = bpf_map_lookup_elem(&sga_tc_data, &lkey);
	// pval[0] = limit
	// pval[1] = actual
	if (!pval || pval[1] >= pval[0])
	{
		return 1;
	}
	pval[1]++;
	return 0;
}


static unsigned int xdp_filter(void *data, void *data_end)
{
	struct ethhdr *eth;
	struct CIDR4 key4;
	struct CIDR6 key6;
	struct AID id = {0,};
	struct AID_wcntr *plookup;
	unsigned int temp;
	unsigned short ports[2];

	__u64 nh_off = sizeof(struct ethhdr);

	if ( (data + nh_off + 4) > data_end) 
		return 0;

	eth = (struct ethhdr *)data;

	__u16 h_proto = eth->h_proto;

	if (h_proto == (ETH_P_VLAN_LE))
	{
		h_proto = *(unsigned short *)(data + nh_off + 2);
		nh_off += 4;
	}

	if (h_proto == (ETH_P_IP_LE)) 
	{
		struct iphdr *iph = data + nh_off;

		if (data + nh_off + sizeof(struct iphdr) > data_end)
			return 0;
		
		if (check_l4(iph->protocol) && (iph->frag_off&0xFF1F) == 0 && ((data + nh_off + sizeof(struct iphdr) + 4) < data_end))
		{
			ports[0] = *(unsigned short *)(data + nh_off + sizeof(struct iphdr));
			ports[1] = *(unsigned short *)(data + nh_off + sizeof(struct iphdr) + 2);
		}
		else
		{
			ports[0] = ports[1] = 0;
		}

// 0. Check Monitor address ...
		int mkey = DATA_MONITOR;
		vtap_data *pdata = bpf_map_lookup_elem(&sga_tc_data, &mkey);
		if (pdata && ( ( pdata->addr == iph->saddr && pdata->port == ports[0] ) || ( pdata->addr == iph->daddr && pdata->port == ports[1] ) ) )
			return 0;

// 1.  [sport & IP-src+pfx]
		key4.cidr = 32 + 16;
		key4.ip = iph->saddr;
		key4.port = ports[0];
		plookup = bpf_map_lookup_elem(&sga_tc_lip4, &key4);
		if ( plookup ) // WL match -> capture
		{
			id.val1 = plookup->val1;
			plookup->cntr++;
		}
		else if (ports[0]) // 1/2 lookup wo port
		{
			key4.port = 0;
			plookup = bpf_map_lookup_elem(&sga_tc_lip4, &key4);
			if (plookup)
			{
				id.val1 = plookup->val1;
				plookup->cntr++;
			}
//			else // no match...
//				return 0;
		}

// 2. [dport & IP-dst+pfx]
		key4.ip = iph->daddr;
		key4.port = ports[1];
		plookup = bpf_map_lookup_elem(&sga_tc_lip4, &key4);
		if ( plookup ) // WL match -> capture
		{
			id.val2 = plookup->val1;
			plookup->cntr++;
		}
		else if (ports[1]) // 2/2 lookup wo port
		{
			key4.port = 0;
			plookup = bpf_map_lookup_elem(&sga_tc_lip4, &key4);
			if (plookup)
			{
				id.val2 = plookup->val1;
				plookup->cntr++;
			}
//			else // no match...
//				return 0;
		}
	}
	else if (h_proto == (ETH_P_IPV6_LE))
	{
		struct ipv6hdr *ip6h = data + nh_off;

		if (data + nh_off + sizeof(struct ipv6hdr) + 4 > data_end)
		    return 0;

		if (check_l4(ip6h->nexthdr))
		{
			ports[0] = *(unsigned short *)(data + nh_off + sizeof(struct ipv6hdr));
			ports[1] = *(unsigned short *)(data + nh_off + sizeof(struct ipv6hdr) + 2);
		}
		else
		{
			ports[0] = ports[1] = 0;
		}

// 1.  [sport & IP-src+pfx]
		key6.cidr = 128 + 16;
		__builtin_memcpy(key6.ip, &ip6h->saddr, 16);
		key6.port = ports[0];
		plookup = bpf_map_lookup_elem(&sga_tc_lip6, &key6);
		if ( plookup ) // WL match -> capture
		{
			id.val1 = plookup->val1;
			plookup->cntr++;
		}
		else if (ports[0]) // 1/2 lookup wo port
		{
			key6.port = 0;
			plookup = bpf_map_lookup_elem(&sga_tc_lip6, &key6);
			if (plookup)
			{
				id.val1 = plookup->val1;
				plookup->cntr++;
			}
//			else // no match...
//				return 0;
		}

// 2. [dport & IP-dst-pfx]
		__builtin_memcpy(key6.ip, &ip6h->daddr, 16);
		key6.port = ports[1];
		plookup = bpf_map_lookup_elem(&sga_tc_lip6, &key6);
		if ( plookup ) // WL match -> capture
		{
			id.val2 = plookup->val1;
			plookup->cntr++;
		}
		else if (ports[1]) // 2/2 lookup wo port
		{
			key6.port = 0;
			plookup = bpf_map_lookup_elem(&sga_tc_lip6, &key6);
			if (plookup)
			{
				id.val2 = plookup->val1;
				plookup->cntr++;
			}
//			else // no match...
//				return 0;
		}

	}
	else
	{
		return 0; // do not capture non-IP traffic
	}

// 3. [alias lookups]
	// check if A is no match
	if (!id.val1)
	{
		id.val1 = id.val2;
		id.val2 = 0;
	}
	// check ( [A&B] )
	plookup = bpf_map_lookup_elem(&sga_tc_lrule, &id);
	if ( plookup ) // ALIAS match -> capture
	{
		plookup->cntr++;
		return plookup->val1;
	}

	if (id.val1 && id.val2)
	{
		// check other direction ( [B&A] )
		temp = id.val1;
		id.val1 = id.val2;
		id.val2 = temp;
		plookup = bpf_map_lookup_elem(&sga_tc_lrule, &id);
		if ( plookup ) // ALIAS match -> capture
		{
			plookup->cntr++;
			return (plookup->val1 | (1 << 24));
		}
		// search for half-matches ( [A&*],[B&*] )
		id.val2 = 0;
		plookup = bpf_map_lookup_elem(&sga_tc_lrule, &id);
		if ( plookup ) // ALIAS match -> capture
		{
			plookup->cntr++;
			return (plookup->val1 | (1 << 24));
		}
		id.val1 = temp;
		plookup = bpf_map_lookup_elem(&sga_tc_lrule, &id);
		if ( plookup ) // ALIAS match -> capture
		{
			plookup->cntr++;
			return plookup->val1;
		}
	}
	//Check if */* has been enabled
	id.val1 = 0;
	id.val2 = 0;
	plookup = bpf_map_lookup_elem(&sga_tc_lrule, &id);
	if ( plookup ) // ALIAS match -> capture
	{
		plookup->cntr++;
		return plookup->val1;
	}

	// do not capture rest?
	return 0;
}

static unsigned int pck_lost = 0;

static int dump(struct __sk_buff *xdp, unsigned short dir)
{
	unsigned int linkid;
	void *data;
	void *data_end;
	int zero = 0;

	__u32 length = xdp->len;
	if (length < 32)
	{
//		length = 32; // just to trict verifier...
		return TC_ACT_OK;
	}
	else if (length > MAX_CAPLEN)
	{
		length = MAX_CAPLEN;
	}

	__u32 caplen = (length < 64)?length:64;
	struct pkt_trace_data* pck_buffer;

	if (caplen > (__u32)(xdp->data_end - xdp->data))
	{
		struct pkt_trace_data* pck_buffer = bpf_map_lookup_elem(&sga_tc_packet_heap, &zero);
		if (!pck_buffer) return TC_ACT_OK;

		 if (bpf_skb_load_bytes(xdp, 0, pck_buffer->data, caplen) < 0)
		 	return TC_ACT_OK;
		 data = (void *)pck_buffer->data;
		 data_end = (void *)pck_buffer->data+caplen;
	}
	else
	{
		pck_buffer = NULL;
		data = (void *)(long)xdp->data;
		data_end = (void *)(long)xdp->data_end;
	}

	linkid = xdp_filter(data, data_end);

	int skey = CNTR_PCK_ALL;
	unsigned long long *pcntr = bpf_map_lookup_elem(&sga_tc_data, &skey);
	if (pcntr)
		(*pcntr)++;

	if (linkid && !get_packet_islimited())
	{
		if (!pck_buffer)
		{
			pck_buffer = bpf_map_lookup_elem(&sga_tc_packet_heap, &zero);
			if (!pck_buffer) return TC_ACT_OK;
		}

		if (bpf_skb_load_bytes(xdp, 0, pck_buffer->data, length) < 0)
		 	return TC_ACT_OK;

		pck_buffer->meta.linkid = linkid;
		pck_buffer->meta.dir = dir;
		pck_buffer->meta.ifindex = (unsigned short)xdp->ifindex;
		pck_buffer->meta.ts = bpf_ktime_get_ns();
		pck_buffer->meta.pkt_len = (__u32)xdp->len;
		pck_buffer->meta.cap_len = length;
		pck_buffer->meta.lost = pck_lost;

#ifdef HAVE_TC_EXT_1
		pck_buffer->meta.tc_ext_1.vlan_present = xdp->vlan_present;
		pck_buffer->meta.tc_ext_1.vlan_tci = xdp->vlan_tci;
		pck_buffer->meta.tc_ext_1.ingress_ifindex = xdp->ingress_ifindex;
		pck_buffer->meta.tc_ext_1._res = 0;
#endif
		if (bpf_ringbuf_output(&sga_tc_ring_map, pck_buffer, sizeof(pck_buffer->meta) + length, 0) < 0)
			pck_lost++;
		else
			pck_lost = 0;

		skey = CNTR_PCK_EVENT;
		pcntr = bpf_map_lookup_elem(&sga_tc_data, &skey);
		if (pcntr)
			(*pcntr)++;
	}

	return TC_ACT_OK;
}

/*****************************************************************************
 * TC trace program
 *****************************************************************************/
/*
SEC("egress")
int sga_dump_out(struct __sk_buff *xdp)
{
	return dump(xdp, 1);
}

SEC("ingress")
int sga_dump_in(struct __sk_buff *xdp)
{
	return dump(xdp, 0);
}
*/

/*****************************************************************************
 * License
 *****************************************************************************/
char _license[] SEC("license") = "GPL";
