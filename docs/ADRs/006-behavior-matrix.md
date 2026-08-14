# ADR-006: 行为矩阵而非 CVE 签名

## 状态
Accepted (v0.2.0)

## 背景
直接"一个 CVE 一条规则"会掉进签名检测的坑——变种一改参数就绕过。

## 验证过程
讨论规则库设计时提出"针对不同 CVE 做不同特征检测"，升级为行为特征抽取后，用真实场景验证：
- 现代 `strace` 实际使用了 6+ 种不同的 ptrace 操作码（PTRACE_SECCOMP_GET_METADATA、PTRACE_SYSCALL、PTRACE_GET_SYSCALL_INFO 等），不仅限于传统的 PTRACE_ATTACH
- 若匹配具体操作码，检测永远不触发

## 备选方案
- ❌ 签名式：`comm == "runc"` → 换名字即绕过
- ✅ 行为式：`fstype=proc + target_pid=1` → 匹配行为方向，CVE 作为关联元数据

## 决策
采用行为矩阵（`attack_matrix.py`）：8 攻击向量 × 6 组合规则，10 秒窗口组合评分。**关键洞察：从"怎么逃"到"逃向谁"**——ptrace 检测匹配 `target_pid=1` 而非具体操作码。

## 后果
- ✅ 抗绕过：参数级变化不影响检测；行为方向稳定
- ✅ CVE 降级为关联信息：攻击模式复用（同行为不同 CVE 变种）自动覆盖
- ❌ 抽象成本：规则编写需理解攻击意图而非表面特征
- 📝 设计哲学：检测匹配"攻击者想干什么"，而非"攻击者用了什么"

## 关联
- [ADR-032](032-rule-engine-conditions.md)：规则引擎条件树重构，行为表达式能力升级
- [ADR-014](014-graded-automation.md)：行为矩阵置信度驱动分级响应
