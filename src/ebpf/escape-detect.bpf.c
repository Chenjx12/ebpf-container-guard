// escape-detect.bpf.c — 容器逃逸检测 eBPF 探针 (v0.4.2, libbpf CO-RE)
// Probes: mount + ptrace + execve + connect + openat(filtered) + capset
// Kernel 6.8 verified. 从 BCC 迁移: TRACEPOINT_PROBE → SEC("tracepoint/..."),
// 参数从 struct trace_event_raw_sys_enter 的 args[6] 按下标读取,
// 事件用 bpf_ringbuf_reserve/submit (绕开 512B 栈限制)。
// v0.4.2: +capset 探针, openat +cgroup release_agent 写入检测 (CVE-2022-0492)
// 编译: make build (clang -target bpf + vmlinux.h)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 事件类型定义 (与用户态 event_type_map 对应)
#define EVENT_MOUNT    1
#define EVENT_PTRACE   2
#define EVENT_OPENAT   3
#define EVENT_EXECVE   4
#define EVENT_CONNECT  5
#define EVENT_CAPSET   6   // v0.4.2: 能力设置检测

// 通用事件结构 (字段序/类型逐字节一致 — 用户态 ctypes 解析依赖;
// v0.4.2 尾部追加 capset/open_flags 字段, 兼容已有解析)
struct event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    char comm[16];
    char container_id[64];

    // mount / openat / execve 共用: 文件路径或命令路径
    char target_path[256];
    // mount 专用: 文件系统类型
    char fstype[32];

    // ptrace 专用
    u32 target_pid;
    u64 request_raw;

    // connect 专用
    u32 daddr;
    u16 dport;

    // v0.4.2: capset 专用 — 能力集 (data[0] 的 effective/permitted)
    u32 cap_effective;
    u32 cap_permitted;
    // v0.4.2: openat 专用 — 打开标志 (取证用, 规则不依赖)
    u32 open_flags;
};

// 容器ID结构体
struct container_id_t {
    char id[64];
};

// Ring Buffer: 1MB (v0.4.1 升级, 旧 BCC 4096B≈9 条事件过小)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// PID → 容器ID 映射表 (用户态定期填充)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct container_id_t);
} container_map SEC(".maps");

// 获取容器ID辅助函数
static inline void get_container_id(struct event *evt) {
    u32 pid = evt->pid;
    struct container_id_t *cid = bpf_map_lookup_elem(&container_map, &pid);
    if (cid) {
        __builtin_memcpy(evt->container_id, cid->id,
                         sizeof(evt->container_id));
    } else {
        evt->container_id[0] = 'h';
        evt->container_id[1] = 'o';
        evt->container_id[2] = 's';
        evt->container_id[3] = 't';
        evt->container_id[4] = '\0';
    }
}

// ==========================================
// 1. mount 探针: 文件系统挂载检测
//    sys_enter_mount(dir_name=args[1], type=args[2])
// ==========================================
SEC("tracepoint/syscalls/sys_enter_mount")
int tracepoint__syscalls__sys_enter_mount(
    struct trace_event_raw_sys_enter *ctx)
{
    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    evt->event_type = EVENT_MOUNT;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid();
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    bpf_probe_read_user_str(evt->fstype, sizeof(evt->fstype),
                            (void *)ctx->args[2]);
    bpf_probe_read_user_str(evt->target_path, sizeof(evt->target_path),
                            (void *)ctx->args[1]);

    get_container_id(evt);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ==========================================
// 2. ptrace 探针: 进程注入检测
//    sys_enter_ptrace(request=args[0], pid=args[1])
// ==========================================
SEC("tracepoint/syscalls/sys_enter_ptrace")
int tracepoint__syscalls__sys_enter_ptrace(
    struct trace_event_raw_sys_enter *ctx)
{
    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    evt->event_type = EVENT_PTRACE;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid();
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    evt->request_raw = (u64)ctx->args[0];
    evt->target_pid = (u32)ctx->args[1];

    get_container_id(evt);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ==========================================
// 3. execve 探针: 程序执行检测
//    sys_enter_execve(filename=args[0])
// ==========================================
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(
    struct trace_event_raw_sys_enter *ctx)
{
    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    evt->event_type = EVENT_EXECVE;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid();
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    bpf_probe_read_user_str(evt->target_path, sizeof(evt->target_path),
                            (void *)ctx->args[0]);

    get_container_id(evt);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ==========================================
// 4. connect 探针: 网络连接检测
//    sys_enter_connect(uservaddr=args[1])
// ==========================================
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(
    struct trace_event_raw_sys_enter *ctx)
{
    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    evt->event_type = EVENT_CONNECT;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid();
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), (void *)ctx->args[1]);

    // v0.6.1: 仅上报 IPv4 (AF_INET=2) 网络连接 — docker 单机形态首次暴露:
    // guard 自身 AF_UNIX connect (docker.sock) 被 sockaddr_in 误读,
    // 产生随机 daddr/dport → reverse_shell 假阳性风暴。
    // AF_INET6(10) 解析留 v0.6.x 顺风车 (IPv6 此前同样误读为乱码 IPv4, 无损失)。
    if (sin.sin_family != 2) {   // AF_INET (vmlinux.h 无此宏, 字面量 + 注释)
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    evt->daddr = sin.sin_addr.s_addr;
    evt->dport = sin.sin_port;

    get_container_id(evt);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ==========================================
// ==========================================
// 5. capset 探针: 能力设置检测 (v0.4.2)
//    sys_enter_capset(data=args[1]) — data[0]: effective/permitted
//    全量上报 (capset 低频); 位检查 (CAP_SYS_ADMIN) 留给用户态规则
// ==========================================
SEC("tracepoint/syscalls/sys_enter_capset")
int tracepoint__syscalls__sys_enter_capset(
    struct trace_event_raw_sys_enter *ctx)
{
    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    evt->event_type = EVENT_CAPSET;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid();
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    // data[0]: effective(偏移0) / permitted(偏移4) — v1/v3 布局相同
    // 必须 (char*) 强转再 +4, 否则按 struct 指针运算偏移 48 字节
    bpf_probe_read_user(&evt->cap_effective, sizeof(evt->cap_effective),
                        (void *)ctx->args[1]);
    bpf_probe_read_user(&evt->cap_permitted, sizeof(evt->cap_permitted),
                        (void *)((char *)ctx->args[1] + 4));

    get_container_id(evt);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ==========================================
// 6. openat 探针: 敏感文件访问 (内核态路径过滤)
//    sys_enter_openat(filename=args[1], flags=args[2])
// ==========================================
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(
    struct trace_event_raw_sys_enter *ctx)
{
    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    evt->event_type = EVENT_OPENAT;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid();
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    // 返回值为读取长度(含 '\0'), v0.4.2 用于 cgroup 后缀匹配
    int plen = bpf_probe_read_user_str(evt->target_path,
                                       sizeof(evt->target_path),
                                       (void *)ctx->args[1]);
    evt->open_flags = (u32)ctx->args[2];

    // 内核态路径过滤: 只上报访问敏感路径的事件
    // 大幅降低 Ring Buffer 压力 (从 ~50K/s 到 < 10/s)
    char *path = evt->target_path;
    int match = 0;

    // /etc/shadow, /etc/passwd — 凭据窃取
    if (path[0] == '/' && path[1] == 'e' && path[2] == 't' && path[3] == 'c' &&
        path[4] == '/' &&
        (path[5] == 's' || path[5] == 'p')) match = 1;

    // /proc/kcore, /proc/kallsyms — 内核信息泄漏
    // v0.5.5 修复: 原条件 `path[6] == 'k' || path[6] == 's'` 把 /proc/self/*、
    // /proc/stat、/proc/swaps、/proc/sys/* 全放行 → openat 事件风暴塞满 ring,
    // execve 事件随机丢弃 (privileged_exec 触发链曾丢)。只该匹配 kcore/kallsyms。
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' &&
        path[4] == 'c' && path[5] == '/' &&
        path[6] == 'k') match = 1;

    // /var/run/docker.sock — Docker socket 访问
    if (path[0] == '/' && path[1] == 'v' && path[2] == 'a' && path[3] == 'r' &&
        path[4] == '/' && path[5] == 'r' && path[6] == 'u' && path[7] == 'n' &&
        path[8] == '/' && path[9] == 'd') match = 1;

    // /run/docker.sock — Docker socket 访问 (符号链接)
    if (path[0] == '/' && path[1] == 'r' && path[2] == 'u' && path[3] == 'n' &&
        path[4] == '/' && path[5] == 'd') match = 1;

    // /proc/self/exe — 进程自身可执行文件 (runc 逃逸探测)
    // v0.5.5: 前缀检查误放行 /proc/self/mountinfo(/mem 前缀) / /proc/self/cgroup
    // (/cmdline 前缀) → openat 风暴; 精确匹配完整文件名
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' &&
        path[4] == 'c' && path[5] == '/' && path[6] == 's' && path[7] == 'e' &&
        path[8] == 'l' && path[9] == 'f' && path[10] == '/' && path[11] == 'e' &&
        path[12] == 'x' && path[13] == 'e') match = 1;

    // /proc/self/mem — 进程自身内存 (进程注入/修改)
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' &&
        path[4] == 'c' && path[5] == '/' && path[6] == 's' && path[7] == 'e' &&
        path[8] == 'l' && path[9] == 'f' && path[10] == '/' && path[11] == 'm' &&
        path[12] == 'e' && path[13] == 'm') match = 1;

    // /proc/self/cmdline — 进程命令行 (侦查/踩点)
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' &&
        path[4] == 'c' && path[5] == '/' && path[6] == 's' && path[7] == 'e' &&
        path[8] == 'l' && path[9] == 'f' && path[10] == '/' && path[11] == 'c' &&
        path[12] == 'm' && path[13] == 'd' && path[14] == 'l' &&
        path[15] == 'i' && path[16] == 'n' && path[17] == 'e') match = 1;

    // /host_* — 宿主机目录挂载点
    if (path[0] == '/' && path[1] == 'h' && path[2] == 'o' && path[3] == 's' &&
        path[4] == 't' && path[5] == '_') match = 1;

    if (match) {
        get_container_id(evt);
        bpf_ringbuf_submit(evt, 0);
        return 0;
    }

    // v0.4.2: cgroup release_agent 写入检测 (CVE-2022-0492 逃逸链)
    // 攻击者常 chdir 进 cgroup 目录后以相对路径打开 ("release_agent"),
    // 绝对前缀匹配会漏报。用返回长度做"后缀匹配":
    // 相对("release_agent") / 绝对(".../release_agent") / v2 前缀
    // ("cgroup.release_agent" 以 "release_agent" 结尾, 自动覆盖) 统一命中。
    // 零循环 (unroll 超 4096 指令); plen 先校验范围让 verifier 传播约束
    // (数组索引 plen-14 会被判 unbounded memory access)。
    if (plen <= 0 || plen > 256) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }
    // plen ∈ [1,256] (含 '\0'); "release_agent"(13) 后缀起点 = plen-14,
    // "notify_on_release"(17) = plen-18
    int is_release = 0;
    if (plen >= 14) {
        char *t = evt->target_path + plen - 14;
        is_release = t[0] == 'r' && t[1] == 'e' && t[2] == 'l'
            && t[3] == 'e' && t[4] == 'a' && t[5] == 's' && t[6] == 'e'
            && t[7] == '_' && t[8] == 'a' && t[9] == 'g' && t[10] == 'e'
            && t[11] == 'n' && t[12] == 't';
    }
    int is_notify = 0;
    if (plen >= 18) {
        char *t = evt->target_path + plen - 18;
        is_notify = t[0] == 'n' && t[1] == 'o' && t[2] == 't'
            && t[3] == 'i' && t[4] == 'f' && t[5] == 'y' && t[6] == '_'
            && t[7] == 'o' && t[8] == 'n' && t[9] == '_' && t[10] == 'r'
            && t[11] == 'e' && t[12] == 'l' && t[13] == 'e'
            && t[14] == 'a' && t[15] == 's' && t[16] == 'e';
    }

    // 写标志: O_WRONLY(1) | O_RDWR(2) — echo 重定向命中, 读访问不命中
    if ((is_release || is_notify) && (ctx->args[2] & 3)) {
        get_container_id(evt);
        bpf_ringbuf_submit(evt, 0);
    } else {
        bpf_ringbuf_discard(evt, 0);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
