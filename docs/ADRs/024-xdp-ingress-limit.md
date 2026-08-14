# ADR-024: XDP 网络阻断的 ingress 限制与混合后端

## 状态
Accepted (v0.3.9)

## 背景
计划用 XDP 内核级阻断替代 iptables，验证发现 XDP 对出站流量无效。

## 验证过程
端到端测试：容器出站 curl 在 XDP 阻断后仍 CONNECTED——基线/阻断/解除全 CONNECTED，排除了测试问题后确认是方向限制。

**技术结论**：**XDP 只处理接口 ingress（入站）方向**。容器出站流量（反弹 shell/C2）经 veth → docker0 egress → 路由 → eth0 egress，不经过 docker0 的 XDP。iptables FORWARD 双向处理转发流量所以有效。

## 备选方案
- **方案 A**（用户选择）：混合后端——XDP 入站（内核级微秒丢弃）+ iptables 出站（FORWARD，C2 主场景）
- 方案 B：纯 XDP——出站阻断失效，C2 主场景漏防
- 方案 C：纯 iptables——丢失内核级低延迟收益

## 决策
采用混合后端（CompositeNetBlocker）：`netblock_backend: mixed|iptables|xdp`（默认 mixed）。

## 后果
- ✅ 入站攻击内核级阻断（微秒级），出站 C2/横移 iptables 双向覆盖
- ❌ 双后端配置复杂度；v0.4.1 迁移 CO-RE 后 XDP attach 走 bpftool generic 模式（bridge 网卡不支持 native XDP）
- 📝 技术叙事："入站 XDP 内核级阻断，出站 iptables 双向覆盖"——如实呈现两种机制的分工，这是硬件级限制而非 bug

## 关联
- [ADR-014](014-graded-automation.md)：阻断是可逆自动动作的一部分
- [ADR-033](033-libbpf-core.md)：XDP 程序随 CO-RE 迁移，attach 方式变化
