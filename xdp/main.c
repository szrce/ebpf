#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h> //need linux ubuntu 
#include <linux/in.h> 


SEC("xdp")

int xdp_packet_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        __u16 dest_port = __constant_ntohs(tcp->dest);


        if (dest_port == 8000 || dest_port == 443) {
			 bpf_printk("Sezer detect Package: Port %d\n", dest_port);
            return XDP_DROP; 
        }
    }

    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
