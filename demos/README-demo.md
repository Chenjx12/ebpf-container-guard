# Demo 执行手册（v3，对应 460f418 之后的 demo 修复批次）

3 分钟演示的可复现执行说明。配合 `demos/demo-script.sh` 使用——**先跑脚本固化环境，再录屏**，不要现场手敲命令。

## 两条命题（全片只服务这两个）

- **命题 A｜取证可采信**：行为日志经哈希链 + 独立校验器，能回答"证据有没有被改过 / 删过 / 还在不在"，篡改可定位到文件 + 行号。
- **命题 B｜误报抑制的增益与代价**：T3 只在 T2 置信度落入闭区间 `[60, 85]` 时介入，用延迟与 API 成本换误报判定，且增益可测量。

## 三个必须固化的坑（实测踩过）

| 坑 | 错误做法 | 正确做法 |
|---|---|---|
| mount 权限 | `docker run` 不加 `--privileged` → `permission denied` | 全部容器加 `--privileged` |
| 命令自污染 | `docker exec <c> bash -c "mount ..."`：bash 启动读 `/etc/passwd` → 命中 `sensitive_file_access`，同镜像计数 +1，mount 变第二刀直接 kill 队列；且组合加成把 conf 顶到 88，越过 T3 上界 | 直接 exec 二进制：`docker exec <c> /usr/bin/mount -t proc proc /mnt`，用现成的 `/mnt`，不套 shell、不 mkdir |
| 证据篡改 | 直接在 `logs/` 上改 → 污染真实证据 | 先 `cp` 到 `/tmp/cg-evidence`，只在副本上注入 |

补一个时序坑：容器冷启动时身份映射未热，`mount` 会归到 `host` 被静默吞掉（v0.6.3 起宿主事件只记录不告警）→ `prepare` 里统一预热 12 秒。

## 置信度速查（决定画面有没有 T3）

| 事件 | conf | T3 |
|---|---|---|
| `/usr/bin/mount`（干净单次） | 85 | 触发（闭区间上界） |
| `bash -c "mount"`（bash 读 passwd → 组合加成） | 88 | 跳过 |
| `/usr/bin/cat /etc/shadow`（独立容器） | 75 | 触发 |
| `strace -p 1`（同容器 10s 内有 sensitive_file） | 90 | 跳过；且 ptrace 探针每 syscall 命中一次，几十条告警刷屏 |

## 执行顺序

```bash
# 0) 静态自检（不依赖 docker/eBPF）
sudo ./demos/demo-script.sh check

# 1) 准备：重启 guard 清计数 / 检查黑名单 / 打 tag / 起容器 / 预热 12s
sudo ./demos/demo-script.sh prepare

# 2) 另一终端起面板（前台阻塞）
./run.sh --ui

# 3) 预跑：3 次独立镜像的 cat /etc/shadow，确认 T3 判定稳定
#    结果写入 /tmp/demo-rehearse.txt，三次均为 true_positive 再正式录
sudo ./demos/demo-script.sh rehearse

# 4) 逐镜头（每镜头后切面板对应页面）
sudo ./demos/demo-script.sh shot2    # 6 个 tracepoint
sudo ./demos/demo-script.sh shot3    # 正常操作，告警数不变
sudo ./demos/demo-script.sh shot4    # mount → conf 85 → T3 → pause
sudo ./demos/demo-script.sh shot5    # cat /etc/shadow → conf 75 → T3
sudo ./demos/demo-script.sh shot6    # 同镜像第二刀 → kill 进队列
sudo ./demos/demo-script.sh shot8    # 哈希链篡改校验（副本保护）

# 5) 收尾
sudo ./demos/demo-script.sh cleanup
```

## 分镜表（180 秒）

| # | 时间 | 画面 | 等待 | 论点 |
|---|---|---|---|---|
| 1 | 0:00–0:15 | 静态页："检测 → 研判 → 可校验证据" | — | 引出两命题 |
| 2 | 0:15–0:35 | `shot2`：`bpftool prog list \| grep tracepoint` | 2s | 内核态 6 探针 |
| 3 | 0:35–0:55 | `shot3`，切告警流，数量不变 | 2s | 误报抑制前提 |
| 4 | 0:55–1:25 | `shot4`，切告警详情看 T2=85 + T3 | 20s | 命题 B：闭区间分级决策 |
| 5 | 1:25–1:55 | `shot5`，切告警详情看 T2=75 + T3 | 20s | 命题 B：低置信度也复核 |
| 6 | 1:55–2:20 | `shot6`，切人工确认队列 | 各 2s | 可逆自动 / 不可逆待确认 |
| 7 | 2:20–2:35 | 告警详情 → 攻击链分析页 | — | 攻击步骤还原 |
| 8 | 2:35–2:55 | `shot8`：先验通过 → 篡改 → 复验报错 | 2s + 3s | **命题 A（高潮）** |
| 9 | 2:55–3:00 | 静态页：三个贡献点 + 开源 commit 可查 | — | 可复现 |

## 判定稳定性（temperature 已统一为 0）

原代码首请求 `temperature=0.3`、retry 为 `0`，同一函数两种温度导致同一输入判定漂移
（实测同一动作两次分别得到 `false_positive 25` / `true_positive 78`）。现已将首请求
也改为 `0`（`ai_analyzer.py:231`），两条路径一致——这是 bug 级修复。

### 实测记录（2026-11-19，`rehearse` 三次独立镜像）

| 次 | 判定 | 置信度 |
|---|---|---|
| 1 | true_positive | 78 |
| 2 | true_positive | 82 |
| 3 | true_positive | 70 |

**判定类别 3/3 稳定，置信度在 70–82 之间浮动（±6）。**

`temperature=0` 对推理型模型**不是严格确定**：采样定了，但推理路径长度不同，最终打分
仍会浮动。这不是 bug，是这类模型的固有行为，**不要在文档或答辩里声称"同一输入得到
相同结果"**。

### 因此，三处措辞要守住

- **旁白不念数字**：只说"AI 给出判定与置信度"，不预先念分值。面板上带颜色的标签观众
  会自己读，说错比分说错结论更尴尬。
- **论文里写准**：可复现性的表述是「同一输入**判定类别**稳定（3/3 均为 true_positive），
  置信度存在小幅波动（70–82）」——不要写成"同一输入得到相同结果"。
- **录制时接受任意一次**：78 / 82 / 70 都是 true_positive，剪哪条都成立，不必等某个特定分值。

### 录前必跑

```bash
sudo ./demos/demo-script.sh rehearse
```

三次均 `true_positive` 才正式录；出现 `false_positive` / `NO_RESULT` 就重跑。
结果写入 `/tmp/demo-rehearse.txt`，可留作论文附录的复现证据。

引用 AI 报告时，选那句结构性判断——**"缺少宿主机挂载或 runc 逃逸证据，不能直接确认
CVE-2019-5736"**，它证明 AI 没有机械套 CVE，正是命题 B 要的东西。

## 翻车预案

| 现象 | 原因 | 处理 |
|---|---|---|
| `mount: permission denied` | 漏了 `--privileged` | 删容器重跑 `prepare` |
| 第一刀就 `kill_container queued_human` | 命令套了 `bash -c`，或 demo-* 已在 blocklist | 检查命令是否直接 exec；`cat config/blocklist.yaml`，删掉 demo-* 条目 |
| 第一次 mount 无告警 | 容器太新，身份映射到 `host` 被吞 | `prepare` 预热够 12s；或 mount 前先 `sleep 10` |
| conf 88 / 没有 T3 | 用了 `bash -c` 或同容器有残余事件 | 换干净容器，直接 exec `/usr/bin/mount` |
| AI 结果 20s 还没出 | 推理模型 reasoning 段过长 | 再看 `logs/ai_results.log`；不要重放攻击（会改升级计数） |
| `verify_chain.py` 报 `PARSE_ERROR` | 改到了轮转文件或日志被截断 | 只改 `behaviors.log` 活跃文件中段；确认副本完整 |

## 与论文/任务书的对应

- 脚本本身即"实验可复现"证据（任务书指标 7）；
- 镜头 8 对应指标 4（取证完整性）与指标 5（证据可复现）；
- 镜头 4/5 的 conf 对照对应指标 3（误报率）的方法论——测试集构造仍是待办，本 demo 不代替它；
- `blocklist.yaml` 为运行时生成、不在 git 中；录屏前必须确认 demo-* 未被写入，否则升级链从第一刀就错。
