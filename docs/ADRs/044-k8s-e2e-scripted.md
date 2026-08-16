# ADR-044: K8s E2E 全量脚本化——六重 bug 修复与验证纪律固化

## 状态
Accepted (v0.5.5)

## 背景
v0.5.1-0.5.4 的 K8s 适配闭环（发现/身份 → responder → DaemonSet → 真实断网）已就绪，但逃逸场景验证一直是手动 + 口头确认。v0.5.5 目标：全部场景脚本化可复现。过程中 privileged_exec 场景断言反复失败，调试链挖出 **6 个深层 bug**——多数是"检测链路静默失效"型（事件丢了、标错了、被吞了），比功能缺失更难发现。

## 验证过程（六重 bug 与修复）

1. **guard 自触发自噪声**：guard 自身 `os.system` 跑 iptables → `/bin/sh -c` → execve 探针捕获 → 自命中 privileged_exec（events.log 16 条事件全指向 guard 自身容器，之前场景"通过"竟是假阳性当通过条件）。修复：自豁免（ns/pod + 容器短 ID 双形态匹配）。**坑：hostNetwork 下 HOSTNAME env=节点名，需 downward API POD_NAME**
2. **PID map 张冠李戴**：`_pids_in_cgroup` 忽略 cgroup_path 参数，全 /proc 扫到任意 cri-containerd scope 就归入当前容器 → 252 pids 全混（exec 进程标成别的容器/标 host）。修复：按本容器 scope 名精确匹配（18-20 pids / 14-16 容器，0 错配）
3. **openat 过滤前缀 bug（事件风暴总根因）**：`path[6]=='s'` 本意匹配 /proc/kallsyms，放行了 /proc/self/*、/proc/stat；`/proc/self/mem|cmdline` 前缀匹配放行 mountinfo/cgroup——宿主桌面进程高频读这些路径 → 风暴塞满 1MB ringbuf → **execve 事件随机丢**（env→/bin/sh 成功 execve 2/2 丢）。修复：精确完整路径匹配
4. **TEST 2 假 PASS**：kubectl run 异步返回 + 固定 sleep 8 + exec 失败被 2>/dev/null 吞 → 触发从未发生。修复：`run_escape_pod` 轮询 pod Ready，失败响亮
5. **set -e 误杀**：timeout 124（容器冻结预期）触发 set -e 退出 → 场景全 PASS 但 run_all 记 FAIL；空 glob 的 `[ -f ]` 同理。修复：`|| true` 豁免
6. **秒退进程标 host**：exec 的 mount/cat/echo 在用户态处理前已退出，/proc 不可读 → resolve 兜底失败标 host → 规则跳过。修复：`resolve_by_cgroup` 用 cgroup_id（eBPF 原子捕获 inode，cgroup v2 kernfs ino == st_ino）遍历 scope stat 反查，不依赖进程存活

## 决策
- **E2E 脚本化作为一等公民**：`tests/k8s/scenarios/` 场景套件 + `run_all_k8s.sh` 一键跑；断言含行为铁证（paused container / iptables DROP / FROZEN），不停留在状态检查
- **触发链设计**：规则排除 comm ∈ {bash, dash, runc, runc:[2:INIT]}；kubectl exec 进程 pre-exec comm=runc 排除、镜像 /bin/sh=dash 排除；**comm=sh/env 可命中**。用 `/bin/sh -c "/bin/sh -c 'sleep 30...'"`（外层排除、子 sh 命中）；冻结后 exec 挂住，timeout -k 5 20（124 即冻结证据）
- **自豁免 + cgroup_id 反查作为产品能力**（非测试专用）：自豁免防自我冻结/自我处置；cgroup_id 反查解决所有秒退进程漏检
- **events.log 记录实际执行动作**（responder 回写 executed_action），矩阵建议仅兜底

## 后果
- ✅ 6 场景 × 4 断言全绿（procfs 冻结、sensitive 隔离、reverse_shell 断网、privileged_exec 冻结、cgroup 写入、capset），单测 105/105，自噪声 0
- ✅ 触发链/断言模式沉淀到 lib_k8s.sh，后续加场景照抄
- ✅ 修复了检测链路静默失效的三个真实产品 bug（PID map 错配、openat 风暴丢事件、秒退进程漏检）——不只是测试问题
- ❌ env→/bin/sh 成功 execve 丢事件未根因（ringbuf reserve 失败路径），当前用 comm=sh 链规避
- 📝 验证纪律固化：**"测试通过"必须追到行为证据；事件消失先查 ring 风暴（openat 过滤）；身份错乱先查 PID map 填充**（与 v0.5.2 的"验证必须追到行为证据"同族教训）

## 关联
- ADR-041（k8s responder）、ADR-042（DaemonSet）、ADR-043（nsenter 断网）
- 决策 #41（验证纪律）→ 本 ADR 为其 K8s 全量脚本化落地
