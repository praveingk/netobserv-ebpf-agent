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

// sets flow fields from IPv4 header information
static inline int fill_iphdr(struct iphdr *ip, void *data_end, flow_id *id) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    __builtin_memcpy(id->src_ip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->dst_ip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->src_ip.s6_addr + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));
    __builtin_memcpy(id->dst_ip.s6_addr + sizeof(ip4in6), &ip->daddr, sizeof(ip->daddr));
    id->transport_protocol = ip->protocol;
    id->src_port = 0;
    id->dst_port = 0;
    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            id->src_port = __bpf_ntohs(tcp->source);
            id->dst_port = __bpf_ntohs(tcp->dest);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            id->src_port = __bpf_ntohs(udp->source);
            id->dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}

// sets flow fields from IPv6 header information
static inline int fill_ip6hdr(struct ipv6hdr *ip, void *data_end, flow_id *id) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    id->src_ip = ip->saddr;
    id->dst_ip = ip->daddr;
    id->transport_protocol = ip->nexthdr;
    id->src_port = 0;
    id->dst_port = 0;
    switch (ip->nexthdr) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            id->src_port = __bpf_ntohs(tcp->source);
            id->dst_port = __bpf_ntohs(tcp->dest);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            id->src_port = __bpf_ntohs(udp->source);
            id->dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}
// sets flow fields from Ethernet header information
static inline int fill_ethhdr(struct ethhdr *eth, void *data_end, flow_id *id) {
    if ((void *)eth + sizeof(*eth) > data_end) {
        return DISCARD;
    }
    __builtin_memcpy(id->dst_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(id->src_mac, eth->h_source, ETH_ALEN);
    id->eth_protocol = __bpf_ntohs(eth->h_proto);

    if (id->eth_protocol == ETH_P_IP) {
        struct iphdr *ip = (void *)eth + sizeof(*eth);
        return fill_iphdr(ip, data_end, id);
    } else if (id->eth_protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
        return fill_ip6hdr(ip6, data_end, id);
    } else {
        // TODO : Need to implement other specific ethertypes if needed
        // For now other parts of flow id remain zero
        memset (&(id->src_ip),0, sizeof(struct in6_addr));
        memset (&(id->dst_ip),0, sizeof(struct in6_addr));
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
    u64 current_time = bpf_ktime_get_ns();
    struct ethhdr *eth = data;
    if (fill_ethhdr(eth, data_end, &id) == DISCARD) {
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
            .bytes=skb->len,
            .start_mono_time_ts = current_time,
            .end_mono_time_ts = current_time,
        };

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
    //__be16 portFromPanoFilter = __bpf_htons(17152);
    __be16 portFromPanoFilter = 53;
    int i = ip->saddr;
    bpf_printk("%i.%i.%i.%i",
		    (i >> 24) & 0xFF,
		    (i >> 16) & 0xFF,
		    (i >> 8) & 0xFF,
		    i & 0xFF);


/*    if (( pTmp =getenv( "ENABLE_PANO" )) != NULL )
       bpf_printk( "PANO variable set.\n") ;
    else
       bpf_printk( "No PANO variable set.\n") ;
*/

    if (port == portFromPanoFilter) {
       bpf_printk("[3] Into Port Filter\n");

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
int ingress_flow_parse (struct __sk_buff *skb) {
    return flow_monitor(skb, INGRESS);
}

SEC("tc_egress")
int egress_flow_parse (struct __sk_buff *skb) {
    return flow_monitor(skb, EGRESS);
}
char _license[] SEC("license") = "GPL";
