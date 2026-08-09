// xdp-block.bpf.c — 网络流量阻断 XDP 程序 (v0.3.9, BCC 风格)
//
// 在网卡入口检查每个数据包，命中阻断表 (ip / ip:port) 则 XDP_DROP，
// 数据包在驱动层被丢弃（微秒级），业务流量不受影响。
//
// BCC 编译: 显式 include 内核网络头（BCC 虚拟环境提供）

#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// 阻断表: 整 IP 阻断（所有端口）
struct key_ip {
    u32 ip;    // 网络字节序（与 iphdr->daddr 一致）
};

// 阻断表: IP:端口 阻断
struct key_ip_port {
    u32 ip;
    u16 port;  // 网络字节序（与 tcp->dest 一致）
    u16 __pad;
};

BPF_HASH(block_ip_map, struct key_ip, u32);
BPF_HASH(block_port_map, struct key_ip_port, u32);

int xdp_block(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. 以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 2. 只处理 IPv4
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // 3. IP 头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 4a. 整 IP 阻断（所有端口）
    struct key_ip kip = {};
    kip.ip = ip->daddr;
    u32 *blocked = block_ip_map.lookup(&kip);
    if (blocked && *blocked == 1)
        return XDP_DROP;

    // 4b. 只处理 TCP/UDP
    u16 dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        dport = udp->dest;
    } else {
        return XDP_PASS;
    }

    // 5. 查 ip:port 阻断表
    struct key_ip_port kp = {};
    kp.ip = ip->daddr;
    kp.port = dport;
    blocked = block_port_map.lookup(&kp);
    if (blocked && *blocked == 1)
        return XDP_DROP;

    return XDP_PASS;
}
