"""
eBPF Container Guard — API routes (v0.5.6)

All endpoints organized by dashboard page. RBAC:
  admin     — everything
  operator  — everything except member management
  analyst   — read-only + own password change

File-channel linkage with main.py:
  - POST /api/review/decision → decisions.log (DecisionExecutor polls 2s)
  - POST /api/rules → rules.yaml (guard hot-reloads 3s)
  - PUT /api/config/ai → ai_config.yaml (guard hot-reloads 3s)
"""

from fastapi import APIRouter, Depends, HTTPException

import pandas as pd

from server import common
from server.deps import require_role

router = APIRouter(prefix="/api")

# Role dependencies
read_any = Depends(require_role("analyst"))
write_op = Depends(require_role("operator"))
admin_only = Depends(require_role("admin"))


def _norm_ts(ts) -> str:
    """归一化时间戳: events.log(空格+微秒) 与 ai_results( T+毫秒) 统一
    到 'YYYY-MM-DDTHH:MM:SS.mmm' 可比较格式。"""
    s = str(ts).strip()
    s = s.replace(' ', 'T')
    if '.' in s:
        head, frac = s.split('.', 1)
        return head + '.' + frac[:3]
    return s


def _df_records(df, **fill):
    """pandas DataFrame → JSON-safe records (NaN/Inf → None).

    v0.5.6 修复: fillna({"value": None}) 填充不存在的列, NaN/Inf 残留导致
    ValueError: Out of range float values are not JSON compliant (behaviors 500)。
    """
    if df.empty:
        return []
    df = df.replace([float('inf'), float('-inf')], float('nan'))
    # astype(object) 先行: float 列 where 填 None 会被强转回 nan
    return df.astype(object).where(pd.notna(df), None).to_dict(orient="records")


# ================================================================
# Overview
# ================================================================


@router.get("/overview/stats")
def overview_stats(user: dict = read_any):
    # v0.5.6: 尾部窗口统计 (全量 15MB 每次 ~0.4s; 尾部 2000 足够覆盖
    # 最近状态分布, 大幅提速)
    events = common.load_events(limit=2000)
    decisions = common.load_decisions()
    ai = common.load_ai_results()

    total = len(events)
    pending = int((events.get('state') == 'pending_review').sum()) \
        if total and 'state' in events.columns else 0
    frozen = int(events.get('state').eq('frozen').sum()) \
        if total and 'state' in events.columns else 0
    netblocked = int(events.get('netblocked').fillna(False).astype(bool).sum()) \
        if total and 'netblocked' in events.columns else 0
    ai_fp = 0
    if len(ai) and 'ai_verdict' in ai.columns:
        ai_fp = int((ai['ai_verdict'] == 'false_positive').sum())

    recent = _df_records(events.sort_values('timestamp', ascending=False)
                         .head(10)) if total else []

    return {
        "total_alerts": total,
        "pending_review": pending,
        "frozen": frozen,
        "netblocked": netblocked,
        "ai_false_positives": ai_fp,
        "ai_config": common.load_ai_config(),
        "recent_events": recent,
    }


# ================================================================
# Alerts
# ================================================================


@router.get("/alerts")
def alerts(limit: int = 50, filter: str = "all", container: str = "",
           rule: str = "", severity: str = "", user: dict = read_any):
    events = common.load_events(limit=2000)
    if events.empty:
        return {"events": [], "netblocks": []}
    # v0.5.6: KPI 下钻筛选 — netblocked / aifp / all
    if filter == "netblocked" and 'netblocked' in events.columns:
        events = events[events['netblocked'].fillna(False).astype(bool)]
    elif filter == "aifp":
        # v0.5.6 修复: events.log 的 tier3_ai_verdict 恒为 null (AI 结果
        # 异步写 ai_results.log 不回写 events) — 筛选必须按 event_ts 关联
        # ai_results.log, 与 KPI 统计同口径 (此前筛不出与 KPI 39 不一致)
        ai = common.load_ai_results()
        fp_ts = set()
        if not ai.empty and 'ai_verdict' in ai.columns and 'event_ts' in ai.columns:
            fp_ts = {_norm_ts(t) for t in
                     ai[ai['ai_verdict'] == 'false_positive']['event_ts']}
        if fp_ts:
            events = events[events['timestamp'].astype(str).map(_norm_ts)
                            .isin(fp_ts)]
        else:
            events = events.iloc[0:0]
    # v0.5.6: 页面筛选 — 容器/规则/严重度
    if container and 'container_id' in events.columns:
        events = events[events['container_id'].astype(str).str.contains(
            container, na=False)]
    if rule and 'rule' in events.columns:
        events = events[events['rule'].astype(str) == rule]
    if severity and 'severity' in events.columns:
        events = events[events['severity'].astype(str).str.upper() ==
                        severity.upper()]
    events = events.sort_values('timestamp', ascending=False).head(limit)
    records = _df_records(events)
    # join human decision (latest per container)
    decisions = common.load_decisions()
    if not decisions.empty and 'container_id' in decisions.columns:
        latest = decisions.sort_values('timestamp').groupby(
            'container_id').last()['decision'].to_dict()
        for r in records:
            r['human_decision'] = latest.get(r.get('container_id'))
    return {"events": records, "netblocks": []}


@router.get("/alerts/detail")
def alert_detail(ts: str = "", container_id: str = "", user: dict = read_any):
    """单事件详情 + 关联 AI 研判 (v0.5.6)。

    AI 结果在 ai_results.log (异步, events.log 无回写) — 按 event_ts
    归一化关联, 与 aifp 筛选同口径。
    """
    if not ts:
        raise HTTPException(status_code=400, detail="缺少 ts")
    events = common.load_events(limit=5000)
    if events.empty:
        return {"event": None, "ai": None}
    norm_ts = _norm_ts(ts)
    row = None
    for _, r in events.iterrows():
        if _norm_ts(r.get('timestamp')) == norm_ts:
            row = {k: (str(v) if hasattr(v, 'isoformat') else v)
                   for k, v in r.to_dict().items()}
            break
    ai = None
    if row:
        ai_df = common.load_ai_results()
        if not ai_df.empty and 'event_ts' in ai_df.columns:
            m = ai_df[ai_df['event_ts'].map(_norm_ts) == norm_ts]
            if len(m):
                ai = {k: (str(v) if hasattr(v, 'isoformat') else v)
                      for k, v in m.iloc[-1].to_dict().items()}
    return {"event": row, "ai": ai}
    events = common.load_events(limit=2000)
    if events.empty:
        return {"events": [], "netblocks": []}
    # v0.5.6: KPI 下钻筛选 — netblocked / aifp / all
    if filter == "netblocked" and 'netblocked' in events.columns:
        events = events[events['netblocked'].fillna(False).astype(bool)]
    elif filter == "aifp":
        # v0.5.6 修复: events.log 的 tier3_ai_verdict 恒为 null (AI 结果
        # 异步写 ai_results.log 不回写 events) — 筛选必须按 event_ts 关联
        # ai_results.log, 与 KPI 统计同口径 (此前筛不出与 KPI 39 不一致)
        ai = common.load_ai_results()
        fp_ts = set()
        if not ai.empty and 'ai_verdict' in ai.columns and 'event_ts' in ai.columns:
            fp_ts = {_norm_ts(t) for t in
                     ai[ai['ai_verdict'] == 'false_positive']['event_ts']}
        if fp_ts:
            events = events[events['timestamp'].astype(str).map(_norm_ts)
                            .isin(fp_ts)]
        else:
            events = events.iloc[0:0]
    # v0.5.6: 页面筛选 — 容器/规则/严重度
    if container and 'container_id' in events.columns:
        events = events[events['container_id'].astype(str).str.contains(
            container, na=False)]
    if rule and 'rule' in events.columns:
        events = events[events['rule'].astype(str) == rule]
    if severity and 'severity' in events.columns:
        events = events[events['severity'].astype(str).str.upper() ==
                        severity.upper()]
    events = events.sort_values('timestamp', ascending=False).head(limit)
    records = _df_records(events)
    # join human decision (latest per container)
    decisions = common.load_decisions()
    if not decisions.empty and 'container_id' in decisions.columns:
        latest = decisions.sort_values('timestamp').groupby(
            'container_id').last()['decision'].to_dict()
        for r in records:
            r['human_decision'] = latest.get(r.get('container_id'))
    return {"events": records, "netblocks": []}


# ================================================================
# Review queue
# ================================================================


@router.get("/review/queue")
def review_queue(user: dict = read_any):
    """队列组头默认不含画像 (v0.5.6: k8s API 慢, 收起态零调用);
    前端展开时调 /review/profile 按需加载。"""
    events = common.load_events(limit=2000)
    ai = common.load_ai_results()
    ai_by_ts = {}
    if not ai.empty and 'event_ts' in ai.columns:
        ai_by_ts = {r['event_ts']: r
                    for r in ai.to_dict(orient='records')
                    if r.get('event_ts')}

    if events.empty or 'state' not in events.columns:
        return {"groups": []}
    pend = events[events['state'] == 'pending_review']
    groups = []
    for cid, grp in pend.groupby('container_id'):
        items = []
        for _, row in grp.iterrows():
            evt = row.to_dict()
            ts = evt.get('timestamp')
            ts_str = ts.isoformat() if hasattr(ts, 'isoformat') else str(ts)
            items.append({
                **evt,
                'event_ts': ts_str,
                'ai': ai_by_ts.get(ts_str),
            })
        groups.append({
            "container_id": cid,
            "event_count": len(items),
            "profile": None,  # 懒加载
            "events": items,
        })
    return {"groups": groups}


@router.get("/review/profile")
def review_profile(container_id: str, user: dict = read_any):
    """单容器画像 (展开时按需加载, 避免轮询拖慢)。"""
    return {"profile": common.get_container_profile(container_id)}


@router.post("/review/decision")
def review_decision(body: dict, user: dict = write_op):
    cid = body.get("container_id") or ""
    decision = body.get("decision") or ""
    if decision not in ('confirmed', 'dismissed'):
        raise HTTPException(status_code=400, detail="decision 必须是 confirmed/dismissed")
    ok, err = common.record_decision(cid, decision,
                                     int(body.get("event_count", 1)))
    if not ok:
        raise HTTPException(status_code=500, detail=err)
    return {"ok": True}


# ================================================================
# Assets (v0.5.7)
# ================================================================


def _k8s_client_v1():
    """复用 common._k8s_pod_profile 的 k8s client 缓存。"""
    from server.common import _k8s_pod_profile
    v1 = getattr(_k8s_pod_profile, '_v1', None)
    if v1 is None:
        _k8s_pod_profile('kube-system/dummy-nonexistent')
        v1 = getattr(_k8s_pod_profile, '_v1', None)
    return v1


@router.get("/assets")
def assets(user: dict = read_any):
    """资产管理: k8s pod 按 node 分组 + 服务关联 (v0.5.7)。

    面板连集群 (kubeconfig ~/.kube/config) 拉全量 pod/service。
    关联维度: 节点归属 (同物理机) / 命名空间 / 服务 selector 匹配
    labels / 特权状态。
    """
    v1 = _k8s_client_v1()
    if v1 is None:
        return {"runtime": "k8s", "total": 0, "nodes": [], "services": [],
                "error": "k8s API 不可用 (kubeconfig 权限?)"}
    try:
        pods = v1.list_pod_for_all_namespaces().items
        svcs = v1.list_service_for_all_namespaces().items
    except Exception as e:
        return {"runtime": "k8s", "total": 0, "nodes": [], "services": [],
                "error": f"k8s API 调用失败: {e}"}

    svc_list = []
    for s in svcs:
        sel = dict(s.spec.selector or {})
        svc_list.append({
            'name': s.metadata.name,
            'namespace': s.metadata.namespace,
            'cluster_ip': s.spec.cluster_ip or '',
            'type': s.spec.type,
            'ports': [f"{p.port}/{p.protocol}" for p in (s.spec.ports or [])],
            'selector': sel,
        })

    node_map = {}
    for p in pods:
        if p.spec.node_name is None:
            continue
        containers = [c.image for c in (p.spec.containers or [])]
        labels = dict(p.metadata.labels or {})
        pod_services = []
        for s in svc_list:
            sel = s['selector']
            if sel and all(labels.get(k) == v for k, v in sel.items()):
                pod_services.append(s['name'])
        entry = {
            'name': p.metadata.name,
            'namespace': p.metadata.namespace,
            'node': p.spec.node_name,
            'pod_ip': p.status.pod_ip or '',
            'status': p.status.phase,
            'images': containers,
            'privileged': bool(
                (p.spec.containers[0].security_context.privileged
                 if p.spec.containers and p.spec.containers[0].security_context
                 else False)),
            'labels': labels,
            'created': str(p.metadata.creation_timestamp or '')[:19],
            'services': pod_services,
        }
        node_map.setdefault(p.spec.node_name, []).append(entry)

    nodes = [{"name": n, "pods": sorted(ps, key=lambda x: x['namespace'])}
             for n, ps in sorted(node_map.items())]
    return {"runtime": "k8s", "total": len(pods),
            "nodes": nodes, "services": svc_list}


# ================================================================
# Behavior log
# ================================================================


@router.get("/behaviors")
def behaviors(container: str = "", syscall: str = "", host_only: bool = False,
              limit: int = 500, user: dict = read_any):
    # v0.5.6: 只读尾部 limit 行 — 全量解析 58MB 文件需 ~2s
    df = common.load_behavior_log(limit=limit)
    if df.empty:
        return {"events": []}
    if container:
        df = df[df.get('container_id', '').astype(str).str.contains(
            container, na=False)]
    if syscall:
        df = df[df.get('event_type', '').astype(str) == syscall]
    if host_only:
        df = df[df.get('container_id', '') == 'host']
    df = df.sort_values('timestamp', ascending=False).head(limit)
    records = _df_records(df)
    # daddr int → IP
    for r in records:
        d = r.get('daddr')
        if isinstance(d, int) and d > 0:
            r['daddr'] = (f"{(d >> 24) & 0xFF}.{(d >> 16) & 0xFF}."
                          f"{(d >> 8) & 0xFF}.{d & 0xFF}")
    return {"events": records}


# ================================================================
# Attack Chain (v0.5.8) — 行为时间窗 → 阶段聚合 (方框箭头流程图)
# ================================================================

# 阶段启发式: 事件类型/目标 → 攻击阶段
_PHASE_RULES = [
    # (阶段名, 匹配函数) — 按优先级, 第一个命中
    ('窃取数据', lambda e: e.get('event_type') == 'openat' and
        any(k in str(e.get('target_path', '')) for k in
            ('shadow', 'kcore', 'kallsyms', 'docker.sock', 'host_'))),
    ('外联 C2', lambda e: e.get('event_type') == 'connect' and
        e.get('daddr', 0) not in (0,)),
    ('利用执行', lambda e: e.get('event_type') == 'execve' and
        e.get('comm') in ('sh', 'bash', 'dash', 'curl', 'wget', 'nc',
                          'ncat', 'python3', 'nsenter', 'mount')),
    ('提权逃逸', lambda e: e.get('event_type') in ('mount', 'capset') or
        (e.get('event_type') == 'ptrace')),
    ('侦察探测', lambda e: e.get('event_type') == 'openat' and
        any(str(e.get('target_path', '')).startswith(p) for p in
            ('/etc', '/proc', '/var/run'))),
]
_PHASE_COLORS = {
    '侦查探测': '#4a7dbd', '提权逃逸': '#c25e5e', '利用执行': '#c98a3d',
    '外联 C2': '#8b6bbd', '窃取数据': '#4a9e8a',
}


@router.get("/attack-chain")
def attack_chain(container: str = "", ts: str = "", window: int = 300,
                 user: dict = read_any):
    """攻击链: 容器告警时间窗的行为序列 → 分阶段步骤 (v0.5.8)。

    container (ns/pod) + 告警 ts → 前后 window 秒的 syscall →
    按阶段启发式聚合, 返回 [{phase, color, events: [...], ts}], 时间正序。
    """
    if not container or not ts:
        return {"steps": [], "alert": None, "error": "缺少 container/ts"}
    # v0.5.8: 跨轮转文件全量 (攻击链需完整时间窗, 低频)
    df = common.load_behavior_rotated(limit=0)
    if df.empty:
        return {"steps": [], "alert": None, "error": "无行为数据"}
    norm_alert = _norm_ts(ts)
    import datetime as _dt
    # 告警时间戳解析 (用于窗口比较)
    try:
        alert_dt = _dt.datetime.fromisoformat(norm_alert)
    except ValueError:
        return {"steps": [], "alert": None, "error": "时间戳格式无效"}

    # 过滤容器 + 时间窗 + 系统 comm (runc 初始化/containerd 噪声)
    df = df[df.get('container_id', '').astype(str) == container]
    if df.empty:
        return {"steps": [], "alert": None, "error": f"容器 {container} 无行为数据"}

    _SYS_COMMS = ('runc', 'runc:[2:INIT]', 'containerd', 'containerd-shim',
                  'k3s-server', 'kubelet', 'pause', 'systemd', 'coredns',
                  'flannel', 'traefik', 'local-path-prov', 'metrics-server')
    df = df[~df.get('comm', '').astype(str).isin(_SYS_COMMS)]

    def _to_dt(s):
        try:
            return _dt.datetime.fromisoformat(_norm_ts(s))
        except Exception:
            return None

    df = df.sort_values('timestamp')
    rows = []
    for _, r in df.iterrows():
        t = _to_dt(r.get('timestamp'))
        if t is None:
            continue
        delta = (t - alert_dt).total_seconds()
        if abs(delta) > window:
            continue
        # daddr int → IP (v0.5.8: connect 事件显示目标 IP)
        daddr = r.get('daddr')
        if isinstance(daddr, int) and daddr > 0:
            daddr = (f"{(daddr >> 24) & 0xFF}.{(daddr >> 16) & 0xFF}."
                     f"{(daddr >> 8) & 0xFF}.{daddr & 0xFF}")
        rows.append({
            'ts': str(r.get('timestamp'))[:23],
            'rel': int(round(delta)),
            'event_type': str(r.get('event_type') or ''),
            'comm': str(r.get('comm') or ''),
            'target': str(r.get('target_path') or daddr or ''),
            'pid': int(r.get('pid') or 0),
        })

    # 阶段聚合: 同阶段连续合并; "其他"作为间隔, 但前后同阶段时合并
    steps = []
    for ev in rows:
        phase = next((p for p, fn in _PHASE_RULES if fn(ev)), '其他')
        if steps:
            last = steps[-1]
            # 相邻: 同阶段 或 (前是其他 且 再前同当前阶段) 或 (当前其他 且 前同阶段)
            merge = False
            if last['phase'] == phase:
                merge = True
            elif last['phase'] == '其他' and len(steps) >= 2 and \
                    steps[-2]['phase'] == phase and \
                    ev['rel'] - last['end_rel'] <= 3:
                merge = True
            elif phase == '其他' and last['phase'] != '其他' and \
                    ev['rel'] - last['end_rel'] <= 3:
                merge = True
            if merge:
                steps[-1]['events'].append(ev)
                steps[-1]['end_rel'] = ev['rel']
                steps[-1]['abs_end'] = ev['ts']
                if phase != '其他':
                    steps[-1]['phase'] = phase
                continue
        steps.append({
            'phase': phase,
            'color': _PHASE_COLORS.get(phase, '#64748b'),
            'rel': ev['rel'], 'end_rel': ev['rel'],
            'abs_start': ev['ts'], 'abs_end': ev['ts'],
            'events': [ev],
        })
    # 去掉纯"其他"步骤
    steps = [s for s in steps if s['phase'] != '其他']
    return {"steps": steps, "alert": {"container": container, "ts": norm_alert},
            "window": window, "error": None}


# ================================================================
# Rules
# ================================================================


@router.get("/rules")
def rules(user: dict = read_any):
    rule_list = common.load_rules()
    # v0.5.6: join 审计 — 每条规则的来源/操作者/时间 (初始内置规则无审计 → '-')
    audit = common.load_rule_audit()
    by_name = {}
    if not audit.empty and 'rule_name' in audit.columns:
        for _, r in audit.iterrows():
            name = r.get('rule_name')
            if name:
                by_name.setdefault(name, []).append(r.to_dict())
    for rule in rule_list:
        name = rule.get('name')
        entries = by_name.get(name, [])
        latest = entries[-1] if entries else {}
        rule['added_by'] = latest.get('user') or '-'
        rule['added_at'] = latest.get('timestamp') or '-'
        rule['added_source'] = latest.get('source') or '-'
    return {"rules": rule_list}


@router.get("/rules/audit")
def rules_audit(user: dict = read_any):
    return {"audit": _df_records(common.load_rule_audit())}


@router.post("/rules")
def add_rule(body: dict, user: dict = write_op):
    rule = body.get("rule")
    source = body.get("source", "manual")
    if not rule:
        raise HTTPException(status_code=400, detail="缺少 rule")
    ok, err = common.append_rule_to_yaml(rule, source, user['username'])
    if not ok:
        raise HTTPException(status_code=400, detail=err)
    return {"ok": True}


# ================================================================
# AI suggested rules
# ================================================================


@router.get("/ai-rules")
def ai_rules(user: dict = read_any):
    ai = common.load_ai_results()
    decisions = common.load_decisions()
    if ai.empty or 'suggested_rule' not in ai.columns:
        return {"suggestions": []}
    decided = set()
    if not decisions.empty and 'scope' in decisions.columns:
        decided = set(decisions[decisions['scope'] == 'suggested_rule']
                      ['container_id'].dropna())
    out = []
    for r in ai.to_dict(orient='records'):
        if not r.get('suggested_rule'):
            continue
        key = r.get('event_ts') or r.get('timestamp')
        if key in decided:
            continue
        out.append({"event_ts": key, **r})
    return {"suggestions": out}


@router.post("/ai-rules/decision")
def ai_rule_decision(body: dict, user: dict = write_op):
    event_ts = body.get("event_ts") or ""
    decision = body.get("decision") or ""
    rule = body.get("rule")
    if decision not in ('confirmed', 'dismissed'):
        raise HTTPException(status_code=400, detail="decision 必须是 confirmed/dismissed")
    if decision == 'confirmed':
        if not rule:
            raise HTTPException(status_code=400, detail="缺少 rule")
        ok, err = common.append_rule_to_yaml(rule, "ai_suggestion",
                                             user['username'])
        if not ok:
            raise HTTPException(status_code=400, detail=err)
    # 去重标记 (scope=suggested_rule, container_id=event_ts — 与 streamlit 一致)
    ok, err = common.record_decision(event_ts, decision, 1, scope="suggested_rule")
    if not ok:
        raise HTTPException(status_code=500, detail=err)
    return {"ok": True}


# ================================================================
# AI config
# ================================================================


@router.get("/config/ai")
def get_ai_config(user: dict = read_any):
    return common.load_ai_config()


@router.put("/config/ai")
def put_ai_config(body: dict, user: dict = write_op):
    # merge 语义: 请求未带 api_key 时保留现有 (防止留空输入框覆盖掉 key → AI 禁用)
    merged = dict(body)
    if not merged.get('api_key'):
        try:
            import yaml
            with open(common.AI_CONFIG_PATH) as f:
                old_key = (yaml.safe_load(f) or {}).get('api_key')
            if old_key:
                merged['api_key'] = old_key
        except Exception:
            pass
    ok, err = common.save_ai_config(merged)
    if not ok:
        raise HTTPException(status_code=400, detail=err)
    return {"ok": True}


# ================================================================
# AI Profiles (v0.5.7) — 多配置管理
# ================================================================


@router.get("/ai/profiles")
def ai_profiles(user: dict = read_any):
    return common.load_ai_profiles()


@router.post("/ai/profiles")
def save_profile(body: dict, user: dict = write_op):
    name = (body.get("name") or "").strip()
    cfg = {k: body.get(k) for k in
           ('base_url', 'api_key', 'model', 'auto_response_threshold',
            'pending_review_threshold')}
    ok, err = common.save_ai_profile(name, cfg)
    if not ok:
        raise HTTPException(status_code=400, detail=err)
    return {"ok": True}


@router.delete("/ai/profiles/{name}")
def delete_profile(name: str, user: dict = write_op):
    ok, err = common.delete_ai_profile(name)
    if not ok:
        raise HTTPException(status_code=400, detail=err)
    return {"ok": True}


@router.post("/ai/models")
def fetch_ai_models(body: dict, user: dict = write_op):
    models, err = common.fetch_models(body.get("base_url", ""),
                                      body.get("api_key", ""))
    if err:
        raise HTTPException(status_code=400, detail=err)
    return {"models": models}


@router.post("/ai/activate")
def activate_profile(body: dict, user: dict = write_op):
    name = (body.get("name") or "").strip()
    thresholds = body.get("thresholds") or None
    ok, err = common.activate_ai_profile(name, thresholds)
    if not ok:
        raise HTTPException(status_code=400, detail=err)
    return {"ok": True, "active": name}


# ================================================================
# Members
# ================================================================


@router.get("/members")
def members(user: dict = read_any):
    return {"users": [
        {"username": u, "role": r, "created": c}
        for u, r, c in common.AUTH.list_users()
    ]}


@router.post("/members")
def add_member(body: dict, user: dict = admin_only):
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    role = body.get("role") or ""
    if role not in ('admin', 'operator', 'analyst'):
        raise HTTPException(status_code=400, detail="非法角色")
    if not common.AUTH.create_user(username, password, role, is_initial=True):
        raise HTTPException(status_code=400, detail="创建失败（用户名存在或密码过短）")
    return {"ok": True}


# ================================================================
# Tokens (temporary authorization, audited)
# ================================================================


@router.post("/tokens/issue")
def issue_token(body: dict, user: dict = admin_only):
    purpose = body.get("purpose") or ""
    ttl = int(body.get("ttl", 180))
    note = (body.get("note") or "").strip()[:100]
    for_user = (body.get("for_user") or "").strip()
    # v0.5.7: 授权对象校验 — 只能授权给比自己权限低的角色
    if for_user:
        from dashboard.auth import ROLE_RANK
        grantor_role = common.AUTH.get_role(user['username'])
        for_role = common.AUTH.get_role(for_user)
        if not for_role:
            raise HTTPException(status_code=400, detail=f"授权对象 {for_user} 不存在")
        if ROLE_RANK.get(for_role, 0) >= ROLE_RANK.get(grantor_role, 0):
            raise HTTPException(status_code=403,
                                detail="不能授权给自己/同级/更高权限的账号")
    token = common.TOKENS.generate(purpose, user['username'], ttl, note,
                                   for_user)
    if not token:
        raise HTTPException(status_code=403, detail="无权签发该目的 token")
    return {"token": token, "purpose": purpose, "note": note,
            "for_user": for_user}


@router.post("/tokens/consume")
def consume_token(body: dict, user: dict = read_any):
    token = body.get("token") or ""
    purpose = body.get("purpose") or ""
    if not common.TOKENS.verify(token, purpose, user['username']):
        raise HTTPException(status_code=400, detail="token 无效/过期/已用")
    return {"ok": True}


@router.get("/tokens/list")
def list_tokens(user: dict = admin_only):
    return {"tokens": common.TOKENS.list_active()}


@router.post("/tokens/revoke")
def revoke_token(body: dict, user: dict = admin_only):
    common.TOKENS.revoke(body.get("token", ""), user['username'])
    return {"ok": True}


# ================================================================
# Auth audit (admin)
# ================================================================


@router.get("/auth/audit")
def auth_audit(user: dict = admin_only):
    return {"audit": _df_records(common.load_auth_audit())}
