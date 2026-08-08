// escape-detect.c - 容器逃逸检测eBPF探针（v0.1.1: tracepoint + kernel 6.8 verified）
// v0.1.0: tracepoint probes, openat enabled — Ring Buffer flooded by high-frequency openat
// v0.1.1: tracepoint probes, openat disabled — stable event flow, platform verified on kernel 6.8
// Note: kprobe____x64_sys_* approach tested but PT_REGS_PARM fails on kernel 6.8 syscall wrappers
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 事件类型定义
#define EVENT_MOUNT 1
#define EVENT_PTRACE 2
#define EVENT_OPENAT 3

// 通用事件结构
struct event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u64 cgroup_id;  // 内核态直接记录 cgroup inode，解决 PID 映射竞态
    char comm[16];
    char container_id[64];

    // mount相关字段
    char fstype[32];
    char target_path[256];

    // ptrace相关字段
    u32 target_pid;
    u64 request_raw; // 使用 u64 保留完整的原始值
};

// 容器ID结构体
struct container_id_t {
    char id[64];
};

// Ring Buffer声明
BPF_RINGBUF_OUTPUT(events, 1 << 8);

// Hash Map声明
BPF_HASH(container_map, u32, struct container_id_t);

// 获取容器ID辅助函数
static inline void get_container_id(struct event *evt) {
    u32 pid = evt->pid;
    struct container_id_t *cid = container_map.lookup(&pid);
    if (cid) {
        bpf_probe_read_str(evt->container_id, sizeof(evt->container_id), cid->id);
    } else {
        // 默认标记为宿主机
        evt->container_id[0] = 'h';
        evt->container_id[1] = 'o';
        evt->container_id[2] = 's';
        evt->container_id[3] = 't';
        evt->container_id[4] = '\0';
    }
}

// ==========================================
// 监控 mount 系统调用 (tracepoint)
// ==========================================
TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    struct event evt = {};
    evt.event_type = EVENT_MOUNT;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // 从用户态指针读取字符串
    bpf_probe_read_user_str(&evt.fstype, sizeof(evt.fstype), (void *)args->type);
    bpf_probe_read_user_str(&evt.target_path, sizeof(evt.target_path), (void *)args->dir_name);

    get_container_id(&evt);
    events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

// ==========================================
// 监控 ptrace 系统调用 (tracepoint)
// ==========================================
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct event evt = {};
    evt.event_type = EVENT_PTRACE;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // 直接将完整的 64 位 request 值传回用户态
    evt.request_raw = (u64)args->request;
    evt.target_pid = (u32)args->pid;

    get_container_id(&evt);
    events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

// ==========================================
// 监控 openat 系统调用 (tracepoint)
// ⚠️ 已注释: openat 是高频调用(数千次/秒), 256条目的 Ring Buffer 瞬间淹没
// 启用前需增大 RINGBUF_SIZE (1<<12 以上) 并添加内核态路径过滤
// ==========================================
// TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
//     struct event evt = {};
//     evt.event_type = EVENT_OPENAT;
//     evt.pid = bpf_get_current_pid_tgid() >> 32;
//     evt.uid = bpf_get_current_uid_gid();
//     evt.cgroup_id = bpf_get_current_cgroup_id();
//     bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
//
//     bpf_probe_read_user_str(&evt.target_path, sizeof(evt.target_path), (void *)args->filename);
//
//     get_container_id(&evt);
//     events.ringbuf_output(&evt, sizeof(evt), 0);
//     return 0;
// }
