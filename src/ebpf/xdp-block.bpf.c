// xdp-block.bpf.c — 网络流量阻断 XDP 程序 (v0.4.1, libbpf CO-RE)
//
// 在网卡入口检查每个数据包，命中阻断表 (ip / ip:port) 则 XDP_DROP，
// 数据包在驱动层被丢弃（微秒级），业务流量不受影响。
//
// 迁移自 BCC (v0.3.9): BPF_HASH → SEC(".maps"), map lookup 用
// bpf_map_lookup_elem。vmlinux.h 不含 #define 宏, 手动定义所需常量。
// 编译: make build
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// vmlinux.h 无宏 (BTF 只有类型), 手动定义
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct key_ip);
    __type(value, u32);
} block_ip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct key_ip_port);
    __type(value, u32);
} block_port_map SEC(".maps");

SEC("xdp")
int xdp_block(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 1. 以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 2. 只处理 IPv4
    if (eth->h_proto != ETH_P_IP)
        return XDP_PASS;

    // 3. IP 头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 4a. 整 IP 阻断（所有端口）
    struct key_ip kip = {};
    kip.ip = ip->daddr;
    u32 *blocked = bpf_map_lookup_elem(&block_ip_map, &kip);
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
    blocked = bpf_map_lookup_elem(&block_port_map, &kp);
    if (blocked && *blocked == 1)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
