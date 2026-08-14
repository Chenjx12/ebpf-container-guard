# ADR-040: K8s 适配第一步——RuntimeBackend 双轨抽象

## 状态
Accepted (v0.5.1)

## 背景
迁移 K8s 时，现有代码全依赖 Docker API（容器发现 docker events、身份 `docker-{id}.scope`、响应 docker 动作）。但毕设已有 6 个 Docker E2E 场景——**直接切 K8s 会破坏现有验证体系**。需要"双轨并行、自动检测"，v0.5.1 只做容器发现 + 身份识别（响应留 v0.5.2）。

## 验证过程
- K8s cgroup 宿主侧路径：`kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<uid(下划线)>.slice/cri-containerd-<64位ID>.scope`——QoS 类变化中间 slice（glob 通配覆盖）；**容器内 /proc/self/cgroup 是 `0::/`**（cgroup ns 屏蔽），必须宿主侧解析
- **eBPF map value 64B 限制**：`ns/pod/container` 三件套超长（pod 名含 hash 后缀最长 91B）→ 改 `ns/pod` 紧凑格式（如 `default/client`）
- **Docker cgroup_path 需要完整 64 位 ID**（短 ID 拼不出路径）→ glob 通配前缀
- 实测：K8s 模式 12 容器/192 进程映射；k3s pod 读 /etc/shadow → sensitive_file_access 命中，容器身份 `default/client`；Docker mount 场景回归通过

## 备选方案
- **方案 A（选中）**：RuntimeBackend 接口 + Docker/K8s 平行实现 + `--runtime auto|docker|k8s` 自动检测——Docker E2E 不破坏，回归风险最小
- 方案 B：直接切 K8s（docker API 全删）——破坏 6 个 E2E 场景，毕设 Docker 证据链丢失
- 方案 C：CRI gRPC 接口（containerd.sock）——信息全但 grpcio 依赖重、pod 名需二次推断，收益低于 k8s watch

## 决策
采用方案 A。K8sBackend：kubernetes client watch pods（信息全：ns/pod/容器名/镜像）+ cgroup glob 扫描兜底。container_id（eBPF map value，64B）填 `ns/pod`（如 `default/client`，可读）。DockerBackend 现码平移零逻辑改动。

## 后果
- ✅ Docker 6 E2E 场景不破坏（双轨并行）；毕设 Docker/K8s 两套证据链都能交付
- ✅ guard 在 k3s 下检测到逃逸（sensitive_file_access 命中，身份 `default/client`）
- ❌ K8s 模式响应 no-op（v0.5.2 实现 K8s responder）
- ❌ 依赖 +kubernetes（纯 Python，轻）；k8s watch 权限在 DaemonSet 部署时需 RBAC（v0.5.3）
- 📝 螺旋式上升：新功能（K8s 发现/身份）+ 兼容既有验证体系

## 关联
- [ADR-039](039-single-instance-lock.md)：部署形态互斥基础（v0.5.0）
- [ADR-036](036-systemd-deployment.md)：单机形态（K8s 是集群形态）
- [ADR-033](033-libbpf-core.md)：CO-RE 迁移（eBPF 侧零改动，本适配全在用户态）
