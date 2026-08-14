// escape-detect.bpf.c — 容器逃逸检测 eBPF 探针 (v0.4.1, libbpf CO-RE)
// Probes: mount + ptrace + execve + connect + openat(filtered)
// Kernel 6.8 verified. 从 BCC 迁移: TRACEPOINT_PROBE → SEC("tracepoint/..."),
// 参数从 struct trace_event_raw_sys_enter 的 args[6] 按下标读取,
// 事件用 bpf_ringbuf_reserve/submit (绕开 512B 栈限制)。
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

// 通用事件结构 (字段序/类型与 BCC 版逐字节一致 — 用户态 ctypes 解析依赖)
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
    evt->daddr = sin.sin_addr.s_addr;
    evt->dport = sin.sin_port;

    get_container_id(evt);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ==========================================
// 5. openat 探针: 敏感文件访问 (内核态路径过滤)
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

    bpf_probe_read_user_str(evt->target_path, sizeof(evt->target_path),
                            (void *)ctx->args[1]);

    // 内核态路径过滤: 只上报访问敏感路径的事件
    // 大幅降低 Ring Buffer 压力 (从 ~50K/s 到 < 10/s)
    char *path = evt->target_path;
    int match = 0;

    // /etc/shadow, /etc/passwd — 凭据窃取
    if (path[0] == '/' && path[1] == 'e' && path[2] == 't' && path[3] == 'c' &&
        path[4] == '/' &&
        (path[5] == 's' || path[5] == 'p')) match = 1;

    // /proc/kcore, /proc/kallsyms — 内核信息泄漏
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' &&
        path[4] == 'c' && path[5] == '/' &&
        (path[6] == 'k' || path[6] == 's')) match = 1;

    // /var/run/docker.sock — Docker socket 访问
    if (path[0] == '/' && path[1] == 'v' && path[2] == 'a' && path[3] == 'r' &&
        path[4] == '/' && path[5] == 'r' && path[6] == 'u' && path[7] == 'n' &&
        path[8] == '/' && path[9] == 'd') match = 1;

    // /run/docker.sock — Docker socket 访问 (符号链接)
    if (path[0] == '/' && path[1] == 'r' && path[2] == 'u' && path[3] == 'n' &&
        path[4] == '/' && path[5] == 'd') match = 1;

    // /proc/self/exe — 进程自身可执行文件 (runc 逃逸探测)
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' &&
        path[4] == 'c' && path[5] == '/' && path[6] == 's' && path[7] == 'e' &&
        path[8] == 'l' && path[9] == 'f' && path[10] == '/' && path[11] == 'e') match = 1;

    // /proc/self/mem — 进程自身内存 (进程注入/修改)
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' &&
        path[4] == 'c' && path[5] == '/' && path[6] == 's' && path[7] == 'e' &&
        path[8] == 'l' && path[9] == 'f' && path[10] == '/' && path[11] == 'm') match = 1;

    // /proc/self/cmdline — 进程命令行 (侦查/踩点)
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' &&
        path[4] == 'c' && path[5] == '/' && path[6] == 's' && path[7] == 'e' &&
        path[8] == 'l' && path[9] == 'f' && path[10] == '/' && path[11] == 'c') match = 1;

    // /host_* — 宿主机目录挂载点
    if (path[0] == '/' && path[1] == 'h' && path[2] == 'o' && path[3] == 's' &&
        path[4] == 't' && path[5] == '_') match = 1;

    if (match) {
        get_container_id(evt);
        bpf_ringbuf_submit(evt, 0);
    } else {
        bpf_ringbuf_discard(evt, 0);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
