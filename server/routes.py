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

from server import common
from server.deps import require_role

router = APIRouter(prefix="/api")

# Role dependencies
read_any = Depends(require_role("analyst"))
write_op = Depends(require_role("operator"))
admin_only = Depends(require_role("admin"))


def _df_records(df, **fill):
    """pandas DataFrame → JSON-safe records (NaN → None)."""
    return df.fillna(fill or {"value": None}).to_dict(orient="records")


# ================================================================
# Overview
# ================================================================


@router.get("/overview/stats")
def overview_stats(user: dict = read_any):
    events = common.load_events()
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
def alerts(limit: int = 50, user: dict = read_any):
    events = common.load_events()
    if events.empty:
        return {"events": [], "netblocks": []}
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
    events = common.load_events()
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
            "profile": common.get_container_profile(cid),
            "events": items,
        })
    return {"groups": groups}


@router.post("/review/decision")
def review_decision(body: dict, user: dict = write_op):
    cid = body.get("container_id") or ""
    decision = body.get("decision") or ""
    if decision not in ('confirmed', 'dismissed'):
        raise HTTPException(status_code=400, detail="decision 必须是 confirmed/dismissed")
    common.record_decision(cid, decision, int(body.get("event_count", 1)))
    return {"ok": True}


# ================================================================
# Behavior log
# ================================================================


@router.get("/behaviors")
def behaviors(container: str = "", syscall: str = "", host_only: bool = False,
              limit: int = 500, user: dict = read_any):
    df = common.load_behavior_log()
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
# Rules
# ================================================================


@router.get("/rules")
def rules(user: dict = read_any):
    return {"rules": common.load_rules()}


@router.get("/rules/audit")
def rules_audit(user: dict = read_any):
    return {"audit": _df_records(common.load_rule_audit())}


@router.post("/rules")
def add_rule(body: dict, user: dict = write_op):
    rule = body.get("rule")
    source = body.get("source", "manual")
    if not rule:
        raise HTTPException(status_code=400, detail="缺少 rule")
    ok, err = common.append_rule_to_yaml(rule, source)
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
        ok, err = common.append_rule_to_yaml(rule, "ai_suggestion")
        if not ok:
            raise HTTPException(status_code=400, detail=err)
    # 去重标记 (scope=suggested_rule, container_id=event_ts — 与 streamlit 一致)
    common.record_decision(event_ts, decision, 1, scope="suggested_rule")
    return {"ok": True}


# ================================================================
# AI config
# ================================================================


@router.get("/config/ai")
def get_ai_config(user: dict = read_any):
    return common.load_ai_config()


@router.put("/config/ai")
def put_ai_config(body: dict, user: dict = write_op):
    ok, err = common.save_ai_config(body)
    if not ok:
        raise HTTPException(status_code=400, detail=err)
    return {"ok": True}


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
    token = common.TOKENS.generate(purpose, user['username'], ttl)
    if not token:
        raise HTTPException(status_code=403, detail="无权签发该目的 token")
    return {"token": token, "purpose": purpose}


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
