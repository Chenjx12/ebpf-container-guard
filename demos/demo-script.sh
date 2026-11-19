#!/bin/bash
# demos/demo-script.sh — 毕设 3 分钟演示的可复现执行脚本 (v3)
#
# 对应提交: 460f418 之后的 demo 修复批次（含 temperature 统一为 0）
# 用法 (全部在任意目录执行，脚本自行 cd 到项目根):
#
#   sudo ./demos/demo-script.sh check      # 静态自检，不依赖 docker / eBPF
#   sudo ./demos/demo-script.sh prepare    # 环境准备（重启 guard / 打 tag / 起容器 / 等待 / 黑名单检查）
#   sudo ./demos/demo-script.sh rehearse   # 预跑：连跑3次 cat /etc/shadow，确认判定稳定再正式录
#   sudo ./demos/demo-script.sh shot2      # 镜头2：6 个 tracepoint
#   sudo ./demos/demo-script.sh shot3      # 镜头3：正常操作不告警
#   sudo ./demos/demo-script.sh shot4      # 镜头4：干净单次 mount → conf 85 → T3 触发 → pause 自动执行
#   sudo ./demos/demo-script.sh shot5      # 镜头5：敏感文件读取 → conf 75 → T3 触发
#   sudo ./demos/demo-script.sh shot6      # 镜头6：同镜像第二刀 → kill 进人工队列
#   sudo ./demos/demo-script.sh shot8      # 镜头8：哈希链篡改校验（副本保护）
#   sudo ./demos/demo-script.sh cleanup    # 清理容器与临时文件
#
# 面板由 prepare 之外的终端执行 ./run.sh --ui 启动（前台阻塞，不放在 prepare 里）。
# 三个必须固化的坑：--privileged / 直接 exec 二进制（不套 bash -c）/ 日志副本保护。

set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

BASE_IMAGE="ubuntu:22.04"
TAGS=("demo-mount:v1" "demo-ai:v1" "demo-resp:v1")
CONTAINERS=("cg-normal" "cg-mount" "cg-ai" "cg-resp-a" "cg-resp-b")
WARMUP_SECONDS=12   # 身份映射热起来（冷容器第一次 mount 会归到 host 被静默吞掉）
AI_WAIT_SECONDS=20  # 推理型模型先出 reasoning_content，实测约 18s 才落 ai_results.log

info() { printf '\n>>> %s\n' "$*"; }
die()  { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }

check_root() {
    [ "$EUID" -eq 0 ] || die "需要 root：sudo ./demos/demo-script.sh <cmd>"
}

check_deps() {
    command -v docker   >/dev/null 2>&1 || die "docker 未安装"
    command -v bpftool  >/dev/null 2>&1 || die "bpftool 未安装"
    [ -f "$ROOT/main.py" ]              || die "项目根目录异常: $ROOT"
    [ -f "$ROOT/tools/verify_chain.py" ] || die "校验器缺失"
}

# ---------------------------------------------------------------------------
cmd_check() {
    info "静态自检（不依赖 docker / eBPF）"
    command -v bash >/dev/null && echo "  [ok] bash"
    [ -f "$ROOT/tools/verify_chain.py" ] && echo "  [ok] verify_chain.py"
    [ -f "$ROOT/config/rules.yaml" ] && echo "  [ok] rules.yaml"
    grep -q '"procfs_mount_escape"' "$ROOT/config/rules.yaml" && echo "  [ok] procfs_mount_escape 规则存在"
    grep -q '"sensitive_file_access"' "$ROOT/config/rules.yaml" && echo "  [ok] sensitive_file_access 规则存在"
    grep -q '/etc/passwd' "$ROOT/config/rules.yaml" && echo "  [warn] /etc/passwd 在敏感路径列表：bash -c 会自污染，禁用它"
    grep -q 'COMBINATION_WINDOW = 10' "$ROOT/src/detector/attack_matrix.py" && echo "  [ok] 组合窗口 = 10s"
    grep -q '60 <= final_conf <= 85' "$ROOT/src/detector/attack_matrix.py" && echo "  [ok] T3 触发为闭区间 [60,85]"
    grep -q 'IRREVERSIBLE_ACTIONS' "$ROOT/src/responder/docker_responder.py" && echo "  [ok] 不可逆动作进人工队列"
    t_count=$(grep -c '"temperature": 0' "$ROOT/src/detector/ai_analyzer.py" || true)
    [ "$t_count" -ge 2 ] \
        && echo "  [ok] AI temperature 两条路径均为 0（首请求 + retry）" \
        || echo "  [warn] temperature 未统一：首请求与 retry 应同为 0"
    echo "  [ok] 脚本语法检查"
    bash -n "$0" && echo "  [ok] syntax OK"
}

# ---------------------------------------------------------------------------
cmd_prepare() {
    check_root
    check_deps

    info "1/5 检查 blocklist（持久化文件，必须确认 demo-* 不在其中）"
    if [ -f "$ROOT/config/blocklist.yaml" ]; then
        cat "$ROOT/config/blocklist.yaml"
        if grep -Eq 'demo-(mount|ai|resp)' "$ROOT/config/blocklist.yaml"; then
            die "demo-* 已在 blocklist 中，请先清空该文件（见 README 翻车预案）"
        fi
    else
        echo "  config/blocklist.yaml 不存在 — OK（运行时生成）"
    fi

    info "2/5 重启 guard（清空内存升级计数 _image_hits）"
    "$ROOT/run.sh" --stop
    "$ROOT/run.sh" --guard
    sleep 3

    info "3/5 准备镜像 tag"
    docker image inspect "$BASE_IMAGE" >/dev/null 2>&1 || docker pull "$BASE_IMAGE"
    for t in "${TAGS[@]}"; do
        docker tag "$BASE_IMAGE" "$t"
        echo "  tagged: $t"
    done

    info "4/5 起容器（全部 --privileged，mount 必需）"
    docker run -d --privileged --name cg-normal   demo-mount:v1 sleep infinity
    docker run -d --privileged --name cg-mount    demo-mount:v1 sleep infinity
    docker run -d --privileged --name cg-ai       demo-ai:v1    sleep infinity
    docker run -d --privileged --name cg-resp-a   demo-resp:v1  sleep infinity
    docker run -d --privileged --name cg-resp-b   demo-resp:v1  sleep infinity

    info "5/5 预热 ${WARMUP_SECONDS}s（身份映射冷启动）"
    sleep "$WARMUP_SECONDS"

    echo
    echo "准备完成。请在另一终端启动面板：cd $ROOT && ./run.sh --ui"
    echo "然后按 README-demo.md 的分镜表逐镜头执行。"
}

# ---------------------------------------------------------------------------
cmd_rehearse() {
    check_root
    check_deps
    [ -f "$ROOT/config/ai_config.yaml" ] \
        || die "config/ai_config.yaml 不存在 — 从 ai_config.yaml.example 复制并填入 API key"

    info "预跑：3 次独立镜像的 cat /etc/shadow，确认 T3 判定稳定"
    echo "  用三个独立镜像避免升级计数污染正式演示；结果写入 /tmp/demo-rehearse.txt"
    local out=/tmp/demo-rehearse.txt
    : > "$out"
    printf 'rehearse at %s\n' "$(date -Is)" >> "$out"

    local results="$ROOT/logs/ai_results.log"
    [ -f "$results" ] || die "$results 不存在 — 先启动 guard 并跑过一次告警"

    for i in 1 2 3; do
        local tag="rehearse-$i:v1" c="cg-rehearse-$i" before after verdict
        docker tag "$BASE_IMAGE" "$tag"
        docker run -d --privileged --name "$c" "$tag" sleep infinity >/dev/null
        sleep "$WARMUP_SECONDS"
        before=$(wc -l < "$results")

        docker exec "$c" /usr/bin/cat /etc/shadow >/dev/null 2>&1 || true
        info "第 $i/3 次已触发，等待 ${AI_WAIT_SECONDS}s"
        sleep "$AI_WAIT_SECONDS"

        after=$(wc -l < "$results")
        if [ "$after" -le "$before" ]; then
            verdict="NO_RESULT"
        else
            verdict=$(tail -n "$((after - before))" "$results" \
                | python3 -c '
import sys, json
last = None
for line in sys.stdin:
    try:
        r = json.loads(line)
        if r.get("rule") == "sensitive_file_access":
            last = r
    except ValueError:
        pass
print((last["ai_verdict"] + " " + str(last["ai_confidence"])) if last else "NO_RESULT")
')
        fi
        printf 'run %d: %s\n' "$i" "$verdict" | tee -a "$out"
        docker rm -f "$c" >/dev/null 2>&1 || true
        docker image rm "$tag" >/dev/null 2>&1 || true
    done

    echo
    echo "结果已写入 $out"
    if grep -qE '(NO_RESULT|false_positive)' "$out"; then
        echo "[WARN] 存在不稳定判定 — 建议重跑 rehearse，或调整旁白为中性表述"
    else
        echo "[OK] 三次均为 true_positive — 可以正式录制镜头5"
    fi
}

cmd_shot2() {
    info "镜头2：过滤后的 tracepoint（系统共约 57 个 BPF 程序，必须 grep）"
    sudo bpftool prog list | grep tracepoint
}

cmd_shot3() {
    info "镜头3：正常操作不告警 — 直接 exec，不套 shell"
    docker exec cg-normal /usr/bin/ls /tmp
    echo "（切面板告警流：数量应保持不变）"
}

cmd_shot4() {
    info "镜头4：干净单次 mount — conf 85（闭区间上界，T3 会触发）"
    echo "  禁用地雷：不要用 bash -c（bash 会读 /etc/passwd → 组合加成到 88 → 越过 T3 上界）"
    docker exec cg-mount /usr/bin/mount -t proc proc /mnt
    echo "（预期：procfs_mount_escape conf 85 → T3 触发 → pause_container 自动执行）"
    info "等待 ${AI_WAIT_SECONDS}s 让 T3 结果写入 logs/ai_results.log"
    sleep "$AI_WAIT_SECONDS"
}

cmd_shot5() {
    info "镜头5：敏感文件读取 — conf 75（无组合加成，T3 触发）"
    echo "  注意：temperature=0 仍非严格确定（推理模型后端调度），旁白只说'给出判定与置信度'"
    docker exec cg-ai /usr/bin/cat /etc/shadow
    info "等待 ${AI_WAIT_SECONDS}s"
    sleep "$AI_WAIT_SECONDS"
}

cmd_shot6() {
    info "镜头6①：全新镜像第一刀 → pause_container 自动执行"
    docker exec cg-resp-a /usr/bin/mount -t proc proc /mnt
    sleep 2
    info "镜头6②：同镜像第二个容器 → 计数=2 → kill_container 进人工队列"
    docker exec cg-resp-b /usr/bin/mount -t proc proc /mnt
    echo "（切面板人工确认队列：应看到待确认项）"
}

cmd_shot8() {
    info "镜头8：哈希链篡改校验（副本保护，绝不改真实日志）"
    local logdir=/tmp/cg-evidence
    rm -rf "$logdir" && mkdir -p "$logdir"
    cp "$ROOT"/logs/behaviors.log* "$logdir"/ 2>/dev/null || true
    local live="$logdir/behaviors.log"
    [ -f "$live" ] || die "$live 不存在 — 先跑镜头 4/5/6 产生日志"

    info "① 先验通过（画面停留 2s）"
    python3 "$ROOT/tools/verify_chain.py" "$logdir"
    sleep 2

    info "② 在副本上注入一行篡改"
    local n line
    n=$(wc -l < "$live")
    line=$((n / 2))
    sed -i "${line}s/\"version\":2/\"version\":9/" "$live"
    echo "  已篡改第 ${line}/${n} 行"

    info "③ 复验（应报 HASH_MISMATCH + 文件 + 行号，画面停留 3s）"
    python3 "$ROOT/tools/verify_chain.py" "$logdir"
    sleep 3
    rm -rf "$logdir"
}

cmd_cleanup() {
    info "清理演示容器与临时目录"
    for c in "${CONTAINERS[@]}"; do
        docker rm -f "$c" >/dev/null 2>&1 && echo "  removed: $c" || true
    done
    rm -rf /tmp/cg-evidence
    echo "完成。注意 config/blocklist.yaml 若被写入需手动清理。"
}

case "${1:-}" in
    check)    cmd_check ;;
    prepare)  cmd_prepare ;;
    rehearse) cmd_rehearse ;;
    shot2)    cmd_shot2 ;;
    shot3)    cmd_shot3 ;;
    shot4)    cmd_shot4 ;;
    shot5)    cmd_shot5 ;;
    shot6)    cmd_shot6 ;;
    shot8)    cmd_shot8 ;;
    cleanup)  cmd_cleanup ;;
    *) sed -n '2,18p' "$0" ;;
esac
