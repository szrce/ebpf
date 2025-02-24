#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

__attribute__((section("classifier"), used))
int block_icmp(struct __sk_buff *skb) {
    const int l3_off = ETH_HLEN;                    // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr); // L4 header offset

    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    if (data_end < data + l4_off)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    if (ip + 1 > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_ICMP)
        return TC_ACT_OK;

    // 192.168.20.1 IP adresinden gelen paketleri engelle
    if (ip->saddr == htonl(0xc0a81401)) {  // 192.168.20.1 -> 0xc0a81401
        return TC_ACT_SHOT;  // Paketi dÃ¼ÅŸÃ¼r
    }

    return TC_ACT_OK;  // DiÄŸer paketleri geÃ§irebiliriz
}

char __license[] __attribute__((section("license"), used)) = "GPL";


/*

//build
clang -O2 -target bpf -D__TARGET_ARCH_x86 -c xdp_incoming.c -o IncomingFilter.o

//for delete
sudo tc filter del dev ens33 ingress
sudo tc qdisc del dev ens33 clsact

//reload programs
sudo tc qdisc add dev ens33 clsact
sudo tc filter add dev ens33 ingress bpf direct-action obj IncomingFilter.o
* 
*/
