# ADR-032: 规则引擎重构——Falco 风格条件树

## 状态
Accepted (v0.4.0)

## 背景
v0.3 引擎的 condition 只有扁平单条件（多字段隐式 AND + 列表 OR），无法表达 `(A or B) and not C`；exclude 与 condition 分离，`reverse_shell` 这类"恒真 + 白名单"规则只能靠 exclude 支撑。

## 验证过程
CHANGELOG 未发布区早规划"AND/OR 组合条件（Falco 风格）"。迁移安全性验证：以旧 `_match`/`_is_excluded` 为参照，10 条规则 × 合成事件池（含 runc:[2:INIT]、字段缺失、通配路径边界）逐条等价——**迁移等价性测试**为安全网。

## 备选方案
- **方案 A**：嵌套 YAML 条件树（all/any/not，叶子为字段匹配）——零解析器维护，Streamlit 表单可逐行构建，LLM 建议规则输出 dict 树比 DSL 更易产对
- **方案 B**：Falco 式字符串 DSL（`evt.type=openat and fd.name=/etc/shadow`）——最贴近 Falco 字面形态，但需自研 tokenizer/parser，表单/LLM 生成成本高

## 决策
选择方案 A（嵌套 YAML 条件树）。保留 Falco 的语义精髓（组合条件 + 操作符），放弃字符串形态。配套决策：
- **event_type 提为顶层键**：做索引 + 隐式 AND，规避 `not event_type` 的索引死区
- **操作符一期 6 个**：neq / startswith / endswith / contains / glob / exists，不加 regex（热加载需预编译校验，收益低）
- **严格保语义迁移**：现有规则多字段→all、列表→OR 精确、exclude→`not(any)`；通配模式（如 `/proc/thread-self/fd/*`）必须转 glob 操作符，否则精确 OR 永远不命中
- **硬升级 + AI 兼容归一**：引擎不做双格式解析；AI 建议规则入库前 `normalize_ai_rule()` 转新树
- **校验分层防御**：rule_schema 校验（字段注册表/单键节点/深度≤5）；首次加载失败即报错；热加载失败保留旧规则集；面板入库前校验拒绝
- **pytest 单测层从零建立**（92 用例，含迁移等价性）

## 后果
- ✅ 规则表达力对齐 Falco（组合条件 + 操作符）；AI 建议规则可自动归一化入库
- ✅ 热加载安全性提升：坏规则不再清空规则集
- ❌ 嵌套 YAML 可读性弱于 Falco DSL；字段注册表需与事件构造同步维护
- 📝 迁移中发现两个易错点：(1) exclude 的 fnmatch 通配模式在"精确 OR"新语义下静默失效（必须显式转 glob）；(2) 嵌套列表穿透校验（需逐元素类型检查）。等价性测试正是为这类问题兜底

## 关联
- [ADR-006](006-behavior-matrix.md)：行为矩阵与规则引擎的分层关系
- [ADR-033](033-libbpf-core.md)：探针层 CO-RE 迁移与规则层重构同期进行
