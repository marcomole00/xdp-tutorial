/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdint.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

// Internet checksum calculation
static __inline __u16 csum16(__u16 *buf, __u32 len) {
    __u32 sum = 0;

    // Sum up 16-bit words
    for (__u32 i = 0; i < len / 2; i++) {
        sum += buf[i];
        if (sum > 0xFFFF) { // Handle carry
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    // If the length is odd, add the last byte
    if (len & 1) {
        sum += *((__u8 *)buf + len - 1);
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    return ~sum; // Return one's complement of the sum
}
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xdp_stats_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	int index = ctx->rx_queue_index;
	__u32 *pkt_count;
	void* data_end =(void *) (long) ctx->data_end;
	void* data = (void *) (long) ctx->data;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct icmphdr *icmp;
	struct hdr_cursor nh;
	int eth_type;
	int ip_type;
	int icmp_type;
	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end , &eth);
	if (eth_type != bpf_htons(ETH_P_IP)){
		bpf_printk("packet is not ipv4");
		goto pass;
	}
	ip_type = parse_iphdr(&nh, data_end, &ip);
	if (ip_type != IPPROTO_ICMP){
		bpf_printk("packet is not icmp");
		goto pass;
	}
	icmp_type = parse_icmphdr(&nh, data_end, &icmp);
	if (icmp_type != ICMP_ECHO){
		bpf_printk("packet is icmp but not an echo");
		goto pass;
	}
	int seq = bpf_ntohs((int) icmp->un.echo.sequence);
	if( (seq / 10) % 2 == 0 ){
		bpf_printk("%d %x",seq, eth->h_dest[0]);
		swap_src_dst_mac(eth);
		bpf_printk("%x", eth->h_dest[0] );
		swap_src_dst_ipv4(ip);
		icmp->type = ICMP_ECHOREPLY;
		icmp->checksum = 0;
		icmp->checksum = csum16((__u16 *)icmp, 4);
		return XDP_TX;
		
		}
	
	pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
	if (pkt_count) {

		bpf_printk("pkt_count %d", pkt_count);
		/* We pass every other packet */
		// if ((*pkt_count)++ & 1)
		// return XDP_PASS;
		(*pkt_count)++;
	}

	/* A set entry here means that the correspnding queue_id
	 * has an active AF_XDP socket bound to it. */
	if (bpf_map_lookup_elem(&xsks_map, &index))
		return bpf_redirect_map(&xsks_map, index, 0);
pass:
	bpf_printk("FINAL VERDICT: pass");
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
