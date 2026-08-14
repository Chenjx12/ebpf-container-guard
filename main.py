#!/usr/bin/env python3
"""
eBPF Container Guard - Main Entry Point (v0.4.2)

Real-time container escape detection and response system based on eBPF.
3-tier detection: rule engine → attack matrix → AI judge
Copyright (c) 2026 chenjx12
Licensed under the MIT License. See LICENSE for details.
"""

import argparse
import sys
import time
import threading
from datetime import datetime
from pathlib import Path
from socket import htons

import docker

# Add src to path for module imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

# v0.4.1: BCC → libbpf CO-RE (自研 ctypes 加载层)
from core.bpf_runtime import BpfRuntime

from detector.engine import EscapeDetector, print_alert
from detector.attack_matrix import AttackMatrix
from detector.ai_analyzer import AsyncAIAnalyzer
from responder.docker_responder import ResponseEngine
from core.identity import ContainerIdentity
from core.event_log import EventLogger
from core.behavior_logger import BehaviorLogger
from core.scope import ContainerScope
from core.escalation import EscalationManager
from core.netblock import NetBlocker, ip_int_to_str
from core.netblock_xdp import XDPNetBlocker, CompositeNetBlocker
from core.decision_executor import DecisionExecutor
from core.behavior_logger import BehaviorLogger


# ============================================================
# ptrace request constant mapping table
# ============================================================
PTRACE_MAP = {
    0: "PTRACE_TRACEME",
    1: "PTRACE_PEEKTEXT",
    2: "PTRACE_PEEKDATA",
    3: "PTRACE_PEEKUSER",
    4: "PTRACE_POKETEXT",
    5: "PTRACE_POKEDATA",
    6: "PTRACE_POKEUSER",
    7: "PTRACE_CONT",
    8: "PTRACE_KILL",
    9: "PTRACE_SINGLESTEP",
    12: "PTRACE_GETREGS",
    13: "PTRACE_SETREGS",
    14: "PTRACE_GETFPREGS",
    15: "PTRACE_SETFPREGS",
    16: "PTRACE_ATTACH",
    17: "PTRACE_DETACH",
    24: "PTRACE_SYSCALL",
    0x4200: "PTRACE_SECCOMP_GET_FILTER",
    0x4201: "PTRACE_SECCOMP_GET_METADATA",
    0x4206: "PTRACE_SECCOMP_GET_METADATA",
    0x420e: "PTRACE_GET_SYSCALL_INFO",
    0x1000: "PTRACE_SEIZE",
    0x1001: "PTRACE_INTERRUPT",
    0x1002: "PTRACE_LISTEN",
}


class ContainerEscapeMonitor:
    """Container escape detection and active defense system"""

    def __init__(self, rules_file="config/rules.yaml",
                 responses_file="config/responses.yaml",
                 verbose=False):
        self.verbose = verbose

        # Resolve paths relative to this script
        script_dir = Path(__file__).parent.resolve()
        ebpf_obj_file = str(script_dir / ".build" / "escape-detect.bpf.o")

        # 1. Load eBPF program (CO-RE, make build 预编译)
        print("[1/8] Loading eBPF program (CO-RE)...")
        self.bpf = BpfRuntime(ebpf_obj_file)

        # 2. Load detection rules
        print("[2/8] Loading detection rules...")
        self.detector = EscapeDetector(rules_file)

        # 3. Load response strategies
        print("[3/8] Loading response strategies...")
        self.responder = ResponseEngine(responses_file)

        # 4. Initialize attack matrix (Tier 2: behavior → CVE)
        print("[4/8] Initializing attack matrix...")
        self.matrix = AttackMatrix()
        from detector.attack_matrix import BEHAVIOR_MATRIX, COMBINATION_BOOSTS
        print(f"  [Matrix] {len(BEHAVIOR_MATRIX)} vectors, "
              f"{len(COMBINATION_BOOSTS)} combination rules")

        # 5. Initialize AI analyzer (Tier 3: async DeepSeek judge)
        print("[5/8] Initializing AI analyzer...")
        self.ai = AsyncAIAnalyzer(
            config_path=str(script_dir / "config" / "ai_config.yaml"),
            results_path=str(script_dir / "ai_results.log"))
        self.ai.start()

        # 6. Connect to Docker daemon
        print("[6/8] Connecting to Docker daemon...")
        try:
            self.docker_client = docker.from_env()
        except docker.errors.DockerException as e:
            print(f"[!] Docker connection failed: {e}", file=sys.stderr)
            sys.exit(1)

        # 7. Initialize container identity + event log
        print("[7/8] Initializing container identity + event log...")
        self.identity = ContainerIdentity(self.bpf, self.docker_client)
        self.identity.start()
        self.logger = EventLogger(str(script_dir / "events.log"))

        # 8. Initialize monitoring scope (include/exclude filters)
        print("[8/8] Initializing monitoring scope...")
        self.scope = ContainerScope(str(script_dir / "config" / "monitor.yaml"))

        # 9. Initialize response escalation + network blocker
        self.escalation = EscalationManager(
            str(script_dir / "config" / "blocklist.yaml"))

        # v0.3.9: netblock backend
        #   iptables — outbound blocking (FORWARD, default, reliable)
        #   xdp      — inbound blocking (NIC ingress, kernel-level)
        #   mixed    — both: XDP inbound + iptables outbound (recommended)
        backend = self._get_netblock_backend()
        self.netblock_backend = backend
        if backend == 'mixed':
            xdp = XDPNetBlocker(iface=self._get_xdp_iface())
            self.netblocker = CompositeNetBlocker(
                xdp, NetBlocker())
        elif backend == 'xdp':
            self.netblocker = XDPNetBlocker(iface=self._get_xdp_iface())
            if not self.netblocker.enabled:
                print("  [NetBlock] XDP 加载失败，回退 iptables")
                self.netblocker = NetBlocker()
        else:
            self.netblocker = NetBlocker()

        # 10. Initialize decision executor (human verdicts → Docker actions)
        self.executor = DecisionExecutor(
            str(script_dir / "decisions.log"), self.docker_client)
        self.executor.start()

        # 11. Start rules hot-reload watcher (v0.3.3)
        self._rules_path = Path(rules_file)
        self._rules_mtime = self._rules_path.stat().st_mtime \
            if self._rules_path.exists() else 0
        self._rules_watcher = threading.Thread(
            target=self._rules_watch_loop, daemon=True)
        self._rules_watcher.start()

        # 12. Start AI config hot-reload watcher (v0.3.6)
        self._ai_cfg_path = script_dir / "config" / "ai_config.yaml"
        self._ai_cfg_mtime = self._ai_cfg_path.stat().st_mtime \
            if self._ai_cfg_path.exists() else 0
        self._ai_cfg_watcher = threading.Thread(
            target=self._ai_cfg_watch_loop, daemon=True)
        self._ai_cfg_watcher.start()

        # 13. Initialize BehaviorLogger (v0.3.12)
        self.behavior_logger = BehaviorLogger(
            log_path=str(script_dir / "behaviors.log"),
            enabled=self._get_behavior_log_enabled())
        print(f"  [Behavior] enabled: {self.behavior_logger.enabled}")

        print("\n========================================")
        print("  eBPF Container Guard v0.4.2")
        print("  6 probes | 12 rules | 3-tier detection")
        print("  Press Ctrl+C to stop")
        print("========================================\n")

    # ================================================================
    # Event processing pipeline
    # ================================================================

    def handle_event(self, cpu, data, size):
        """Ring buffer callback: parse -> detect -> respond"""
        try:
            event = self.bpf['events'].event(data)

            # Map numeric event type to string
            event_type_map = {1: 'mount', 2: 'ptrace', 3: 'openat',
                              4: 'execve', 5: 'connect', 6: 'capset'}

            # Resolve container identity (3-tier fallback)
            raw_cid = event.container_id.decode(
                'utf-8', errors='replace').rstrip('\x00')
            raw_cid = self.identity.resolve(
                event.pid, event.cgroup_id, raw_cid)

            # Apply monitoring scope filter (include/exclude)
            if not self.scope.should_monitor(raw_cid,
                                             self.identity.get_name(raw_cid)):
                return  # container excluded from monitoring scope

            # Build event dict for rule engine
            event_dict = {
                'event_type': event_type_map.get(event.event_type, 'unknown'),
                'pid': event.pid,
                'uid': event.uid,
                'comm': event.comm.decode('utf-8', errors='replace').strip('\x00'),
                'container_id': raw_cid,
                'timestamp': time.time()
            }

            # Add event-type-specific fields
            if event.event_type == 1:  # MOUNT
                event_dict['fstype'] = event.fstype.decode(
                    'utf-8', errors='replace').rstrip('\x00')
                event_dict['target_path'] = event.target_path.decode(
                    'utf-8', errors='replace').rstrip('\x00')
            elif event.event_type == 2:  # PTRACE
                event_dict['target_pid'] = event.target_pid
                request_val = event.request_raw
                mapped_req = PTRACE_MAP.get(
                    request_val,
                    PTRACE_MAP.get(request_val & 0xFFFFFFFF)
                )
                event_dict['request'] = (
                    mapped_req if mapped_req
                    else f"UNKNOWN(0x{request_val:x})"
                )
            elif event.event_type == 3:  # OPENAT
                event_dict['target_path'] = event.target_path.decode(
                    'utf-8', errors='replace').rstrip('\x00')
            elif event.event_type == 4:  # EXECVE
                event_dict['target_path'] = event.target_path.decode(
                    'utf-8', errors='replace').rstrip('\x00')
            elif event.event_type == 5:  # CONNECT
                event_dict['daddr'] = event.daddr
                event_dict['dport'] = event.dport
            elif event.event_type == 6:  # CAPSET (v0.4.2)
                event_dict['cap_effective'] = event.cap_effective
                event_dict['cap_permitted'] = event.cap_permitted

            # === Behavior Log (v0.3.12): ALL syscall events recorded ===
            self.behavior_logger.write(event_dict)

            # === Tier 1: Rule Engine ===
            matched_rules = self.detector.check_event(event_dict)
            if matched_rules:
                for rule in matched_rules:
                    # Skip container-specific rules for host processes
                    attack_vector = rule.get('attack_vector', '')
                    if raw_cid == 'host' and attack_vector not in (
                            'ptrace_host_init',):
                        continue

                    alert = self.detector.generate_alert(rule, event_dict)

                    # === Tier 2: Attack Matrix ===
                    attack_vector = rule.get('attack_vector', 'unknown')
                    if attack_vector != 'unknown':
                        matrix_result = self.matrix.analyze(
                            attack_vector, raw_cid)
                        alert['attack_vector'] = attack_vector
                        alert['cve_refs'] = rule.get('cve_refs', [])
                        alert['matrix_confidence'] = matrix_result.final_confidence
                        alert['suggested_action'] = matrix_result.suggested_action

                        # Print enriched alert
                        self._print_alert_v2(alert, matrix_result)

                        # === Tier 3: AI Judge (async, v0.3.2) ===
                        # 事件先记录 + 矩阵驱动响应（不阻塞），AI 结果异步
                        # 回填到 ai_results.log 供面板展示（AI 是顾问不是决策者）
                        ai_result = None
                        event_ts = datetime.now().strftime(
                            '%Y-%m-%dT%H:%M:%S.%f')[:-3]
                        if matrix_result.escalate_to_ai:
                            context = self.matrix.get_context_events(raw_cid)
                            self.ai.submit(
                                alert, context,
                                matrix_result.final_confidence,
                                event_ts)
                        action = matrix_result.suggested_action

                        # === v0.2.5: Escalation + Network Blocking ===
                        container_image = self.identity.get_image(raw_cid)

                        # Blocked image → immediate critical alert, queue kill
                        if self.escalation.is_image_blocked(container_image):
                            print(f"\n🚫 [BLOCKLIST] 镜像已被拉黑: "
                                  f"{container_image} (容器 {raw_cid})")
                            alert['event']['container_id'] = raw_cid
                            status = self.responder.handle_alert(
                                alert, forced_action='kill_container',
                                ai_confidence=100)
                            self.logger.write(alert, matrix_result,
                                              ai_result, 'block_image',
                                              action_status=status)
                            continue

                        # Escalation: repeated attacks from same image
                        esc_action = self.escalation.decide(container_image)
                        if esc_action in ('kill_container', 'block_image'):
                            print(f"\n⏫ [ESCALATION] 镜像 {container_image} "
                                  f"重复攻击 → {esc_action}")
                            alert['escalation'] = esc_action
                            forced = esc_action
                            # v0.3.2: AI 异步化，不可逆动作的置信度参考
                            # 使用矩阵置信度（AI 结果后补，不阻塞）
                            conf = matrix_result.final_confidence
                        else:
                            forced = None
                            conf = None

                        # Network attack → block malicious traffic (reversible)
                        netblocked = False
                        if attack_vector == 'reverse_shell' and \
                                event_dict.get('daddr'):
                            ip = ip_int_to_str(event_dict['daddr'])
                            port = htons(event_dict.get('dport', 0))
                            if self.netblocker.block(ip, port):
                                netblocked = True
                                print(f"🚫 [NETBLOCK] DROP {ip}:{port} "
                                      f"(C2/反弹Shell阻断, 业务流量保留)")

                        # === Response (graded automation) ===
                        alert['severity'] = alert.get('severity', 'LOW')
                        status = self.responder.handle_alert(
                            alert, forced_action=forced, ai_confidence=conf)

                        # === Event Log ===
                        self.logger.write(alert, matrix_result,
                                          ai_result, action,
                                          action_status=status,
                                          netblocked=netblocked,
                                          event_ts=event_ts)
                    else:
                        # No attack vector → basic alert only
                        print_alert(alert)
                        status = self.responder.handle_alert(alert)
                        self.logger.write(alert, action_status=status)
            else:
                # Normal event — green output (verbose mode)
                if self.verbose:
                    self._print_verbose(event_dict)

        except Exception as e:
            print(f"[ERROR] Event processing failed: {e}", file=sys.stderr)
            if self.verbose:
                import traceback
                traceback.print_exc()

    # ================================================================
    # Enriched alert printing
    # ================================================================

    def _print_alert_v2(self, alert, matrix_result):
        """Print alert with attack matrix enrichment."""
        RED = '\033[91m'; RESET = '\033[0m'; BG_RED = '\033[101m'
        YELLOW = '\033[93m'; CYAN = '\033[96m'; WHITE = '\033[97m'

        sev = alert.get('severity', 'HIGH')
        color = BG_RED if sev == 'CRITICAL' else RED

        print(f"\n{color}🚨 安全告警 - {sev} {RESET}")
        print(f"{RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")
        print(f"{RED}规则: {alert['rule_name']}{RESET}")
        print(f"{RED}攻击向量: {alert.get('attack_vector', 'unknown')}{RESET}")
        evt = alert.get('event', {})
        print(f"{RED}容器: {evt.get('container_id', 'unknown')}{RESET}")
        print(f"{RED}进程: {evt.get('pid')} ({evt.get('comm')}){RESET}")

        if 'fstype' in evt:
            print(f"{RED}文件系统: {evt['fstype']} → {evt.get('target_path', '')}{RESET}")
        if 'target_pid' in evt:
            print(f"{RED}Ptrace: {evt.get('request', '?')} → 目标PID:{evt['target_pid']}{RESET}")
        if evt.get('event_type') in ('execve', 'openat') and 'target_path' in evt:
            print(f"{RED}路径: {evt['target_path']}{RESET}")
        if 'daddr' in evt:
            from socket import htons
            ip = evt['daddr']
            port = htons(evt['dport'])
            print(f"{RED}连接: {(ip>>24)&0xFF}.{(ip>>16)&0xFF}.{(ip>>8)&0xFF}.{ip&0xFF}:{port}{RESET}")

        # Matrix enrichment
        print(f"{YELLOW}━━━ 行为矩阵分析 ━━━{RESET}")
        if matrix_result.boosted:
            print(f"{YELLOW}🔗 组合命中: {matrix_result.combination_narrative}{RESET}")
        print(f"{YELLOW}关联CVE: {', '.join(alert.get('cve_refs', [])) or 'none'}{RESET}")
        print(f"{YELLOW}攻击手法: {', '.join(matrix_result.techniques)}{RESET}")
        conf = matrix_result.final_confidence
        conf_color = BG_RED if conf > 85 else (RED if conf > 60 else CYAN)
        print(f"{YELLOW}置信度: {conf_color}{conf}%{RESET} "
              f"{'🔴 自动响应' if conf > 85 else '🟡 AI研判' if conf >= 60 else '🔵 仅记录'}")
        print(f"{color}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}\n")

    def _print_ai_report(self, ai_result):
        """Print the AI analysis report."""
        CYAN = '\033[96m'; RESET = '\033[0m'; GREEN = '\033[92m'
        print(f"{CYAN}🤖 AI 研判报告:{RESET}")
        print(f"{CYAN}   判定: {'✅ 攻击' if ai_result.is_attack else '⚠️ 误报'}{RESET}")
        print(f"{CYAN}   手法: {ai_result.technique}{RESET}")
        print(f"{CYAN}   置信度: {ai_result.confidence}%{RESET}")
        print(f"{CYAN}   分析: {ai_result.report}{RESET}")
        print(f"{CYAN}   建议: {ai_result.suggested_action}{RESET}")
        if ai_result.suggested_rule:
            print(f"{GREEN}   🔧 AI 建议新增规则: {ai_result.suggested_rule.get('name', '')}{RESET}")
        print()

    def _print_verbose(self, event_dict):
        """Print normal event in verbose mode."""
        etype = event_dict['event_type']
        pid = event_dict['pid']
        comm = event_dict['comm']
        cid = event_dict['container_id']
        if etype == 'execve':
            print(f"\033[92m[INFO] execve - PID:{pid} Comm:{comm} "
                  f"CID:{cid} Path:{event_dict.get('target_path', '')}\033[0m")
        elif etype == 'connect':
            print(f"\033[92m[INFO] connect - PID:{pid} Comm:{comm} "
                  f"CID:{cid}\033[0m")
        elif etype == 'ptrace':
            print(f"\033[92m[INFO] ptrace - PID:{pid} Comm:{comm} "
                  f"CID:{cid} Req:{event_dict.get('request', '')} "
                  f"Target:{event_dict.get('target_pid', '')}\033[0m")
        elif etype == 'mount':
            print(f"\033[92m[INFO] mount - PID:{pid} Comm:{comm} "
                  f"CID:{cid} FS:{event_dict.get('fstype', '')} "
                  f"Path:{event_dict.get('target_path', '')}\033[0m")
        # openat is filtered in kernel space; if it reaches here, print it

    # ================================================================
    # Netblock backend config (v0.3.9)
    # ================================================================

    def _get_netblock_backend(self) -> str:
        """Read netblock_backend from monitor.yaml: 'iptables' | 'xdp'."""
        try:
            import yaml
            with open(Path(__file__).parent / "config" / "monitor.yaml",
                      'r') as f:
                cfg = yaml.safe_load(f) or {}
            backend = cfg.get('netblock_backend', 'mixed')
            print(f"  [NetBlock] backend: {backend}")
            return backend if backend in ('iptables', 'xdp', 'mixed') \
                else 'iptables'
        except Exception:
            return 'iptables'

    def _get_behavior_log_enabled(self) -> bool:
        """Read behavior_log toggle from monitor.yaml (v0.3.12)."""
        try:
            import yaml
            with open(Path(__file__).parent / "config" / "monitor.yaml",
                      'r') as f:
                cfg = yaml.safe_load(f) or {}
            return cfg.get('behavior_log', True)
        except Exception:
            return True

    def _get_xdp_iface(self) -> str:
        """XDP attach interface — docker0 (container traffic) or eth0."""
        import subprocess
        try:
            out = subprocess.run(
                ["ip", "link", "show", "docker0"],
                capture_output=True, text=True, timeout=5)
            if out.returncode == 0:
                return "docker0"
        except Exception:
            pass
        return "eth0"

    # ================================================================
    # AI config hot-reload (v0.3.6)
    # ================================================================

    def _ai_cfg_watch_loop(self):
        """Watch ai_config.yaml mtime — dashboard settings take effect
        without restarting guard."""
        while True:
            time.sleep(3)
            try:
                if self._ai_cfg_path.exists():
                    mtime = self._ai_cfg_path.stat().st_mtime
                    if mtime != self._ai_cfg_mtime:
                        print("[AI] ⚡ 检测到 AI 配置变化，热加载中...")
                        self.ai.reload()
                        self._ai_cfg_mtime = mtime
            except Exception as e:
                print(f"  [!] AI config watcher error: {e}", file=sys.stderr)

    # ================================================================
    # Rules hot-reload (v0.3.3)
    # ================================================================

    def _rules_watch_loop(self):
        """Watch rules.yaml mtime — reload rules without restarting."""
        while True:
            time.sleep(3)
            try:
                if self._rules_path.exists():
                    mtime = self._rules_path.stat().st_mtime
                    if mtime != self._rules_mtime:
                        print("[Detector] ⚡ 检测到规则文件变化，热加载中...")
                        self.detector.reload()
                        self._rules_mtime = mtime
            except Exception as e:
                print(f"  [!] Rules watcher error: {e}", file=sys.stderr)

    # ================================================================
    # Main loop
    # ================================================================

    def run(self):
        """Start monitoring loop"""
        self.bpf['events'].open_ring_buffer(self.handle_event)

        try:
            while True:
                self.bpf.ring_buffer_poll()
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[i] Shutting down...")
            self.identity.stop()
            self.executor.stop()
            self.ai.stop()
            print("👋 eBPF Container Guard stopped.")


# ================================================================
# CLI entry point
# ================================================================

def main():
    parser = argparse.ArgumentParser(
        description='🛡️  eBPF Container Guard - '
                    'Real-time container escape detection and response'
    )
    parser.add_argument(
        '--rules',
        default='config/rules.yaml',
        help='Path to detection rules YAML (default: config/rules.yaml)'
    )
    parser.add_argument(
        '--responses',
        default='config/responses.yaml',
        help='Path to response strategies YAML (default: config/responses.yaml)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging (print all normal events)'
    )

    args = parser.parse_args()

    # Resolve config paths relative to project root
    script_dir = Path(__file__).parent.resolve()
    rules_path = script_dir / args.rules
    responses_path = script_dir / args.responses

    if not rules_path.exists():
        print(f"❌ Error: Rules file not found: {rules_path}")
        sys.exit(1)

    if not responses_path.exists():
        print(f"❌ Error: Responses file not found: {responses_path}")
        sys.exit(1)

    # Start monitor
    monitor = ContainerEscapeMonitor(
        rules_file=str(rules_path),
        responses_file=str(responses_path),
        verbose=args.verbose
    )
    monitor.run()


if __name__ == '__main__':
    main()
