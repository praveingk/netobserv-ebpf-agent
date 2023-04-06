/*
    Flows v2. A Flow-metric generator using TC.

    This program can be hooked on to TC ingress/egress hook to monitor packets
    to/from an interface.

    Logic:
        1) Store flow information in a per-cpu hash map.
        2) Upon flow completion (tcp->fin event), evict the entry from map, and
           send to userspace through ringbuffer.
           Eviction for non-tcp flows need to done by userspace
        3) When the map is full, we send the new flow entry to userspace via ringbuffer,
            until an entry is available.
        4) When hash collision is detected, we send the new entry to userpace via ringbuffer.
*/
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <string.h>
#include <stdbool.h>
#include <linux/if_ether.h>

#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "flow.h"

#define DISCARD 1
#define SUBMIT 0

// according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define INGRESS 0
#define EGRESS 1

// Flags according to RFC 9293 & https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08
#define ACK_FLAG 0x10
#define URG_FLAG 0x20
#define ECE_FLAG 0x40
#define CWR_FLAG 0x80
// Custom flags exported
#define SYN_ACK_FLAG 0x100
#define FIN_ACK_FLAG 0x200
#define RST_ACK_FLAG 0x400

// SCTP protocol header structure, its defined here because its not
// exported by the kernel headers like other protocols.
struct sctphdr {
    __be16 source;
    __be16 dest;
    __be32 vtag;
    __le32 checksum;
};

// Common Ringbuffer as a conduit for ingress/egress flows to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} direct_flows SEC(".maps");


// Perf Buffer to submit packet payloads to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} packet_payloads SEC(".maps");

// Key: the flow identifier. Value: the flow metrics for that identifier.
// The userspace will aggregate them into a single flow.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, flow_metrics);
} aggregated_flows SEC(".maps");

// Constant definitions, to be overridden by the invoker
volatile const u32 sampling = 0;
volatile const u8 trace_messages = 0;

const u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

// sets the TCP header flags for connection information
// returns true if connection timestamp needs to be stored
static inline bool set_flags(struct tcphdr *th, int direction, u16 *flags) {
    //If both ACK and SYN are set, then it is server -> client communication during 3-way handshake. 
    if (th->ack && th->syn) {
        *flags |= SYN_ACK_FLAG;
        return true;
    } else if (th->ack && th->fin ) {
        // If both ACK and FIN are set, then it is graceful termination from server.
        *flags |= FIN_ACK_FLAG;
    } else if (th->ack && th->rst ) {
        // If both ACK and RST are set, then it is abrupt connection termination. 
        *flags |= RST_ACK_FLAG;
    } else if (th->fin) {
        *flags |= FIN_FLAG;
    } else if (th->syn) {
        *flags |= SYN_FLAG;
    } else if (th->ack) {
        *flags |= ACK_FLAG;
        if (direction == INGRESS && th->seq == 1) {
            return true;
        }
    } else if (th->rst) {
        *flags |= RST_FLAG;
    } else if (th->psh) {
        *flags |= PSH_FLAG;
    } else if (th->urg) {
        *flags |= URG_FLAG;
    } else if (th->ece) {
        *flags |= ECE_FLAG;
    } else if (th->cwr) {
        *flags |= CWR_FLAG;
    }
}
// sets flow fields from IPv4 header information
static inline int fill_iphdr(struct iphdr *ip, void *data_end, flow_id *id, u16 *flags) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }
    return false;
}

// L4_info structure contains L4 headers parsed information.
struct l4_info_t {
    // TCP/UDP/SCTP source port in host byte order
    u16 src_port;
    // TCP/UDP/SCTP destination port in host byte order
    u16 dst_port;
    // ICMPv4/ICMPv6 type value
    u8 icmp_type;
    // ICMPv4/ICMPv6 code value
    u8 icmp_code;
    // TCP flags
    u16 flags;
	// Connection timestamp capture
	bool conn_tstamp; 
};

// Extract L4 info for the supported protocols
static inline void fill_l4info(void *l4_hdr_start, void *data_end, u8 direction, u8 protocol,
                               struct l4_info_t *l4_info) {
	switch (protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = l4_hdr_start;
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            l4_info->src_port = __bpf_ntohs(tcp->source);
            l4_info->dst_port = __bpf_ntohs(tcp->dest);
            l4_info->conn_tstamp = set_flags(tcp, direction, &l4_info->flags);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = l4_hdr_start;
        if ((void *)udp + sizeof(*udp) <= data_end) {
            l4_info->src_port = __bpf_ntohs(udp->source);
            l4_info->dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    case IPPROTO_SCTP: {
        struct sctphdr *sctph = l4_hdr_start;
        if ((void *)sctph + sizeof(*sctph) <= data_end) {
            l4_info->src_port = __bpf_ntohs(sctph->source);
            l4_info->dst_port = __bpf_ntohs(sctph->dest);
        }
    } break;
    case IPPROTO_ICMP: {
        struct icmphdr *icmph = l4_hdr_start;
        if ((void *)icmph + sizeof(*icmph) <= data_end) {
            l4_info->icmp_type = icmph->type;
            l4_info->icmp_code = icmph->code;
        }
    } break;
    case IPPROTO_ICMPV6: {
        struct icmp6hdr *icmp6h = l4_hdr_start;
         if ((void *)icmp6h + sizeof(*icmp6h) <= data_end) {
            l4_info->icmp_type = icmp6h->icmp6_type;
            l4_info->icmp_code = icmp6h->icmp6_code;
        }
    } break;
    default:
        break;
    }
}

// sets flow fields from IPv4 header information
static inline int fill_iphdr(struct iphdr *ip, void *data_end, u8 direction, flow_id *id, u16 *flags, bool *conn_tstamp) {
    struct l4_info_t l4_info;
    void *l4_hdr_start;

    l4_hdr_start = (void *)ip + sizeof(*ip);
    if (l4_hdr_start > data_end) {
        return DISCARD;
    }
    __builtin_memset(&l4_info, 0, sizeof(l4_info));
    __builtin_memcpy(id->src_ip, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->dst_ip, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->src_ip + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));
    __builtin_memcpy(id->dst_ip + sizeof(ip4in6), &ip->daddr, sizeof(ip->daddr));
    id->transport_protocol = ip->protocol;
    fill_l4info(l4_hdr_start, data_end, direction, ip->protocol, &l4_info);
    id->src_port = l4_info.src_port;
    id->dst_port = l4_info.dst_port;
    id->icmp_type = l4_info.icmp_type;
    id->icmp_code = l4_info.icmp_code;
    *flags = l4_info.flags;
	*conn_tstamp = l4_info.conn_tstamp;

    return SUBMIT;
}

// sets flow fields from IPv6 header information
static inline int fill_ip6hdr(struct ipv6hdr *ip, void *data_end, u8 direction, flow_id *id, u16 *flags, bool *conn_tstamp) {
    struct l4_info_t l4_info;
    void *l4_hdr_start;

    l4_hdr_start = (void *)ip + sizeof(*ip);
    if (l4_hdr_start > data_end) {
        return DISCARD;
    }
    __builtin_memset(&l4_info, 0, sizeof(l4_info));

    __builtin_memcpy(id->src_ip, ip->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(id->dst_ip, ip->daddr.in6_u.u6_addr8, 16);
    id->transport_protocol = ip->nexthdr;
    fill_l4info(l4_hdr_start, data_end, direction, ip->nexthdr, &l4_info);
    id->src_port = l4_info.src_port;
    id->dst_port = l4_info.dst_port;
    id->icmp_type = l4_info.icmp_type;
    id->icmp_code = l4_info.icmp_code;
    *flags = l4_info.flags;
	*conn_tstamp = l4_info.conn_tstamp;

    return SUBMIT;
}
// sets flow fields from Ethernet header information
static inline int fill_ethhdr(struct ethhdr *eth, void *data_end, u8 direction, flow_id *id, u16 *flags, bool *conn_tstamp) {
    if ((void *)eth + sizeof(*eth) > data_end) {
        return DISCARD;
    }
    __builtin_memcpy(id->dst_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(id->src_mac, eth->h_source, ETH_ALEN);
    id->eth_protocol = __bpf_ntohs(eth->h_proto);

    if (id->eth_protocol == ETH_P_IP) {
        struct iphdr *ip = (void *)eth + sizeof(*eth);
        return fill_iphdr(ip, data_end, direction, id, flags, conn_tstamp);
    } else if (id->eth_protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
        return fill_ip6hdr(ip6, data_end, direction, id, flags, conn_tstamp);
    } else {
        // TODO : Need to implement other specific ethertypes if needed
        // For now other parts of flow id remain zero
        memset(&(id->src_ip), 0, sizeof(struct in6_addr));
        memset(&(id->dst_ip), 0, sizeof(struct in6_addr));
        id->transport_protocol = 0;
        id->src_port = 0;
        id->dst_port = 0;
    }
    return SUBMIT;
}

static inline int flow_monitor(struct __sk_buff *skb, u8 direction) {
    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling != 0 && (bpf_get_prandom_u32() % sampling) != 0) {
        return TC_ACT_OK;
    }
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    flow_id id;
	bool conn_tstamp = false;
    __builtin_memset(&id, 0, sizeof(id));
    u64 current_time = bpf_ktime_get_ns();
    struct ethhdr *eth = data;
    u16 flags = 0;
    if (fill_ethhdr(eth, data_end, direction, &id, &flags, &conn_tstamp) == DISCARD) {
        return TC_ACT_OK;
    }
    id.if_index = skb->ifindex;
    id.direction = direction;

    // TODO: we need to add spinlock here when we deprecate versions prior to 5.1, or provide
    // a spinlocked alternative version and use it selectively https://lwn.net/Articles/779120/
    flow_metrics *aggregate_flow = bpf_map_lookup_elem(&aggregated_flows, &id);
    if (aggregate_flow != NULL) {
        aggregate_flow->packets += 1;
        aggregate_flow->bytes += skb->len;
        aggregate_flow->end_mono_time_ts = current_time;
        // it might happen that start_mono_time hasn't been set due to
        // the way percpu hashmap deal with concurrent map entries
        if (aggregate_flow->start_mono_time_ts == 0) {
            aggregate_flow->start_mono_time_ts = current_time;
        }
        if (conn_tstamp) {
            aggregate_flow->conn_mono_time_ts = current_time;
        }
        aggregate_flow->flags |= flags;
        long ret = bpf_map_update_elem(&aggregated_flows, &id, aggregate_flow, BPF_ANY);
        if (trace_messages && ret != 0) {
            // usually error -16 (-EBUSY) is printed here.
            // In this case, the flow is dropped, as submitting it to the ringbuffer would cause
            // a duplicated UNION of flows (two different flows with partial aggregation of the same packets),
            // which can't be deduplicated.
            // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
            bpf_printk("error updating flow %d\n", ret);
        }
    } else {
        // Key does not exist in the map, and will need to create a new entry.
        flow_metrics new_flow = {
            .packets = 1,
            .bytes = skb->len,
            .start_mono_time_ts = current_time,
            .end_mono_time_ts = current_time,
            .flags = flags, 
        };
        if (conn_tstamp) {
            new_flow.conn_mono_time_ts = current_time;
        }

        // even if we know that the entry is new, another CPU might be concurrently inserting a flow
        // so we need to specify BPF_ANY
        long ret = bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_ANY);
        if (ret != 0) {
            // usually error -16 (-EBUSY) or -7 (E2BIG) is printed here.
            // In this case, we send the single-packet flow via ringbuffer as in the worst case we can have
            // a repeated INTERSECTION of flows (different flows aggregating different packets),
            // which can be re-aggregated at userpace.
            // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
            if (trace_messages) {
                bpf_printk("error adding flow %d\n", ret);
            }

            new_flow.errno = -ret;
            flow_record *record = bpf_ringbuf_reserve(&direct_flows, sizeof(flow_record), 0);
            if (!record) {
                if (trace_messages) {
                    bpf_printk("couldn't reserve space in the ringbuf. Dropping flow");
                }
                return TC_ACT_OK;
            }
            record->id = id;
            record->metrics = new_flow;
            bpf_ringbuf_submit(record, 0);
        }
    }
    return TC_ACT_OK;
}

static inline int export_packet_payload (struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    payload_meta meta;
    struct ethhdr *eth  = data;
    struct iphdr  *ip;
    struct udphdr *udp_data;
    
    bpf_printk("Into export packet payload\n");
    if ((void *)eth + sizeof(*eth) > data_end) {
       return TC_ACT_UNSPEC;	
    }

    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
       return TC_ACT_UNSPEC;	
    }

    udp_data = (void *)ip + sizeof(*ip);
    if ((void *)udp_data + sizeof(*udp_data) > data_end) {
       return TC_ACT_UNSPEC;	
    }

    if (eth->h_proto != __bpf_htons(ETH_P_IP)) {
       return TC_ACT_UNSPEC;	
    }

    //Only analyze UDP packets
    if (ip->protocol != IPPROTO_UDP ) {
       return TC_ACT_UNSPEC;	
    }

    __be16 port = udp_data->dest;
    //TODO: Update port number/filters to be read from ENV variable
    __be16 portFromPanoFilter = __bpf_htons(53);

    if (port == portFromPanoFilter) {

       meta.if_index = skb->ifindex;
       meta.pkt_len = data_end - data;
       bpf_perf_event_output(skb, &packet_payloads, ((u64) meta.pkt_len << 32) | BPF_F_CURRENT_CPU, &meta, sizeof(meta));
    }
       
    return TC_ACT_OK;

}

SEC("tc_pano_ingress")
int ingress_pano_parse (struct __sk_buff *skb) {
    return export_packet_payload(skb);
}

SEC("tc_pano_egress")
int egress_pano_parse (struct __sk_buff *skb) {
    return export_packet_payload(skb);
}

SEC("tc_ingress")
int ingress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb, INGRESS);
}

SEC("tc_egress")
int egress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb, EGRESS);
}
char _license[] SEC("license") = "GPL";
