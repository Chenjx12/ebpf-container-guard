// escape-detect.c - 容器逃逸检测eBPF探针（v0.2.0: 4-probe behavioral matrix）
// Probes: mount + ptrace + execve + connect + openat(filtered)
// Kernel 6.8 verified with tracepoint probes
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

// 事件类型定义
#define EVENT_MOUNT    1
#define EVENT_PTRACE   2
#define EVENT_OPENAT   3
#define EVENT_EXECVE   4
#define EVENT_CONNECT  5

// 通用事件结构（union 复用节省 Ring Buffer 空间）
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

// Ring Buffer: 4096 条目（v0.2.0 升级，支持 openat 有限开启）
BPF_RINGBUF_OUTPUT(events, 1 << 12);

// PID → 容器ID 映射表（用户态定期填充）
BPF_HASH(container_map, u32, struct container_id_t);

// 获取容器ID辅助函数
static inline void get_container_id(struct event *evt) {
    u32 pid = evt->pid;
    struct container_id_t *cid = container_map.lookup(&pid);
    if (cid) {
        bpf_probe_read_str(evt->container_id, sizeof(evt->container_id), cid->id);
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
// ==========================================
TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    struct event evt = {};
    evt.event_type = EVENT_MOUNT;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_probe_read_user_str(&evt.fstype, sizeof(evt.fstype), (void *)args->type);
    bpf_probe_read_user_str(&evt.target_path, sizeof(evt.target_path), (void *)args->dir_name);

    get_container_id(&evt);
    events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

// ==========================================
// 2. ptrace 探针: 进程注入检测
// ==========================================
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct event evt = {};
    evt.event_type = EVENT_PTRACE;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    evt.request_raw = (u64)args->request;
    evt.target_pid = (u32)args->pid;

    get_container_id(&evt);
    events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

// ==========================================
// 3. execve 探针: 程序执行检测
// ==========================================
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event evt = {};
    evt.event_type = EVENT_EXECVE;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_probe_read_user_str(&evt.target_path, sizeof(evt.target_path), (void *)args->filename);

    get_container_id(&evt);
    events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

// ==========================================
// 4. connect 探针: 网络连接检测
// ==========================================
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct event evt = {};
    evt.event_type = EVENT_CONNECT;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), (void *)args->uservaddr);
    evt.daddr = sin.sin_addr.s_addr;
    evt.dport = sin.sin_port;

    get_container_id(&evt);
    events.ringbuf_output(&evt, sizeof(evt), 0);
    return 0;
}

// ==========================================
// 5. openat 探针: 敏感文件访问（内核态路径过滤）
// ==========================================
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event evt = {};
    evt.event_type = EVENT_OPENAT;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_probe_read_user_str(&evt.target_path, sizeof(evt.target_path), (void *)args->filename);

    // 内核态路径过滤：只上报访问敏感路径的事件
    // 大幅降低 Ring Buffer 压力（从 ~50K/s 到 < 10/s）
    char *path = evt.target_path;
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

    // /run/docker.sock — Docker socket 访问（符号链接）
    if (path[0] == '/' && path[1] == 'r' && path[2] == 'u' && path[3] == 'n' &&
        path[4] == '/' && path[5] == 'd') match = 1;

    // /proc/self/exe — 进程自身可执行文件（runc 逃逸探测）
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' &&
        path[4] == 'c' && path[5] == '/' && path[6] == 's' && path[7] == 'e' &&
        path[8] == 'l' && path[9] == 'f' && path[10] == '/' && path[11] == 'e') match = 1;

    // /proc/self/mem — 进程自身内存（进程注入/修改）
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' &&
        path[4] == 'c' && path[5] == '/' && path[6] == 's' && path[7] == 'e' &&
        path[8] == 'l' && path[9] == 'f' && path[10] == '/' && path[11] == 'm') match = 1;

    // /proc/self/cmdline — 进程命令行（侦查/踩点）
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' &&
        path[4] == 'c' && path[5] == '/' && path[6] == 's' && path[7] == 'e' &&
        path[8] == 'l' && path[9] == 'f' && path[10] == '/' && path[11] == 'c') match = 1;

    // /host_* — 宿主机目录挂载点
    if (path[0] == '/' && path[1] == 'h' && path[2] == 'o' && path[3] == 's' &&
        path[4] == 't' && path[5] == '_') match = 1;

    if (match) {
        get_container_id(&evt);
        events.ringbuf_output(&evt, sizeof(evt), 0);
    }
    return 0;
}
