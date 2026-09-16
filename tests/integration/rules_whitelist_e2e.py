#!/usr/bin/env python3
"""v0.6.5 端到端验证 — 规则管理 (POST/PUT/DELETE) + 临时白名单。

隔离策略
--------
在 /tmp 下构建仓库副本并启动**真实 uvicorn**，绝不触碰仓库的
config/rules.yaml（git 追踪文件）。副本内删除 users.yaml 以触发全新随机
初始密码，密码从 server 日志解析。

覆盖场景
--------
R1  非空 rules.yaml 追加规则 → YAML 仍可解析、原 12 条规则完整、顺序不变
R2  PUT 更新规则 → 字段生效、条目数不变、原位置保序
R3  DELETE 规则 → 回到初始条数、YAML 可解析
R4  DELETE 不存在的规则 → 404
R5  审计留痕含 add_rule + update_rule 且记录操作者
W1  新增白名单 → 返回 id、列表可见、active=true
W2  同 match 幂等 → id 相同、不重复入库
W3  参数校验 → kind 非法 400 / 缺 note 400
W4  DELETE 白名单 → 列表移除
W5  到期条目 → active=false（告警恢复）
RBAC analyst(test) 可读不可写 → GET 200 / 写 403

PROBE（v0.6.5.1 修复点回归，修复后应 PASS；失败则记探针）
P1  同 match 已过期后再 add(未来时间) → 重新生效（原 id 续期）
P2  valid_until 格式非法 → API 400 / 存量坏值按已过期（fail-closed）

用法:  python3 tests/integration/rules_whitelist_e2e.py
退出码: 有硬失败时非 0。
"""

from http.cookiejar import CookieJar
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
PORT = int(os.environ.get("E2E_PORT", "8899"))
BASE = f"http://127.0.0.1:{PORT}"


class Reporter:
    def __init__(self):
        self.p = self.f = self.probes = 0

    def ok(self, m):
        print(f"  [PASS]  {m}")
        self.p += 1

    def fail(self, m):
        print(f"  [FAIL]  {m}")
        self.f += 1

    def probe(self, m):
        print(f"  [PROBE] {m}")
        self.probes += 1

    def check(self, cond, m):
        self.ok(m) if cond else self.fail(m)
        return bool(cond)


R = Reporter()


def http(opener, method, path, body=None):
    """Return (status_code, parsed_json_or_{}). 4xx 不抛异常。"""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=15) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def new_opener():
    cj = CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def rules_stats(path):
    """Return (yaml_ok, names). yaml_ok=False 时 names 为错误信息。"""
    try:
        d = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return True, [r.get("name") for r in (d.get("rules") or [])]
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def iso(offset_sec):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() + offset_sec))


def main():
    tmp = Path(tempfile.mkdtemp(prefix="ebpf-e2e-v065."))
    app, logs = tmp / "app", tmp / "logs"
    app.mkdir()
    logs.mkdir()

    print("== [1/6] 构建隔离副本 ==")
    for d in ("server", "src", "config", "scripts"):
        shutil.copytree(REPO / d, app / d,
                        ignore=shutil.ignore_patterns("__pycache__"))
    if (REPO / "main.py").exists():
        shutil.copy2(REPO / "main.py", app / "main.py")
    for f in ("users.yaml", "ai_config.yaml"):
        (app / "config" / f).unlink(missing_ok=True)
    # 预置已知凭据（不依赖首次启动随机密码的终端打印，规避 stdout 缓冲坑）
    seed = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, '.');"
         "from server.auth import AuthManager;"
         "am = AuthManager('config/users.yaml');"
         "assert am.create_user('admin', 'e2e-admin-pw', 'admin', is_initial=False);"
         "assert am.create_user('test', 'e2e-test-pw', 'analyst', is_initial=False);"
         "print('seeded')"],
        cwd=app, capture_output=True, text=True)
    if seed.returncode != 0:
        print(f"  预置凭据失败: {seed.stdout} {seed.stderr}")
        return 1

    rules_path = app / "config" / "rules.yaml"
    okb, names_before = rules_stats(rules_path)
    if not okb:
        print(f"  初始 rules.yaml 解析失败: {names_before}")
        return 1
    print(f"  隔离副本 {tmp}")
    print(f"  初始 rules.yaml: {len(names_before)} 条规则, YAML 可解析")

    print("== [2/6] 启动隔离 server ==")
    env = {**os.environ, "GUARD_LOGS_DIR": str(logs)}
    srvlog_path = tmp / "server.log"
    with open(srvlog_path, "w") as srvlog:
        proc = subprocess.Popen(
            # -u: 初始密码在 import 期 print，块缓冲会吞掉（v0.6.3 同款坑）
            [sys.executable, "-u", "-m", "uvicorn", "server.app:app",
             "--host", "127.0.0.1", "--port", str(PORT), "--workers", "1"],
            cwd=app, env=env, stdout=srvlog, stderr=subprocess.STDOUT)

    def stop():
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    try:
        up = False
        for _ in range(120):
            if proc.poll() is not None:
                break
            try:
                urllib.request.urlopen(BASE + "/api/auth/me", timeout=2)
                up = True
                break
            except urllib.error.HTTPError:
                up = True
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.25)
        if not up:
            print("  server 未能就绪，日志尾部：")
            print(srvlog_path.read_text(encoding="utf-8", errors="replace")[-1500:])
            stop()
            return 1

        pw_admin, pw_test = "e2e-admin-pw", "e2e-test-pw"
        R.ok(f"server 就绪 + 预置凭据可用 (pid={proc.pid})")

        print("== [3/6] 登录 + 规则管理 e2e ==")
        admin = new_opener()
        st, _ = http(admin, "POST", "/api/auth/login",
                     {"username": "admin", "password": pw_admin})
        R.check(st == 200, f"admin 登录 → 200 (got {st})")

        st, body = http(admin, "GET", "/api/rules")
        R.check(st == 200 and len(body.get("rules", [])) == len(names_before),
                f"R0 GET /api/rules 初始 {len(names_before)} 条 (HTTP {st})")

        new_rule = {
            "name": "e2e_v065_rule",
            "description": "v0.6.5 e2e test rule",
            "attack_vector": "e2e_test",
            "severity": "HIGH",
            "event_type": "openat",
            "condition": {"all": [{"target_path": {"startswith": "/tmp/e2e-v065-"}}]},
            "action": "alert_and_log",
        }
        st, body = http(admin, "POST", "/api/rules",
                        {"rule": new_rule, "source": "manual"})
        R.check(st == 200, f"R1 POST /api/rules 追加新规则 → 200 (got {st}: {body})")
        oka, names_a = rules_stats(rules_path)
        R.check(oka and len(names_a) == len(names_before) + 1
                and names_a[:len(names_before)] == names_before,
                "R1a 非空追加后 YAML 可解析 + 原规则保序完整（v0.6.5 修复点）")
        R.check(oka and "e2e_v065_rule" in names_a, "R1b 新规则已写入")

        upd = {**new_rule, "severity": "CRITICAL", "description": "updated by e2e"}
        st, body = http(admin, "PUT", "/api/rules/e2e_v065_rule",
                        {"rule": upd, "source": "manual"})
        R.check(st == 200, f"R2 PUT /api/rules/{{name}} → 200 (got {st}: {body})")
        oku, names_u = rules_stats(rules_path)
        sev = ""
        if oku:
            sev = next(r.get("severity") for r in yaml.safe_load(
                rules_path.read_text(encoding="utf-8"))["rules"]
                if r.get("name") == "e2e_v065_rule")
        R.check(oku and sev == "CRITICAL" and names_u == names_a,
                "R2a 更新生效 (severity=CRITICAL) 且条目保序")

        st, _ = http(admin, "DELETE", "/api/rules/e2e_v065_rule")
        R.check(st == 200, f"R3 DELETE /api/rules/{{name}} → 200 (got {st})")
        okd, names_d = rules_stats(rules_path)
        R.check(okd and names_d == names_before,
                "R3a 删除后回到初始状态且 YAML 可解析")

        st, _ = http(admin, "DELETE", "/api/rules/__no_such_rule__")
        R.check(st == 404, f"R4 删除不存在规则 → 404 (got {st})")

        st, body = http(admin, "GET", "/api/rules/audit")
        audit = body.get("audit", []) if st == 200 else []
        has_add = any(a.get("action") == "add_rule"
                      and a.get("rule_name") == "e2e_v065_rule" for a in audit)
        has_upd = any(a.get("action") == "update_rule"
                      and a.get("rule_name") == "e2e_v065_rule"
                      and a.get("user") == "admin" for a in audit)
        R.check(has_add and has_upd, "R5 审计留痕含 add_rule + update_rule(admin)")

        print("== [4/6] 白名单 e2e ==")
        future, past = iso(3600), iso(-3600)
        st, body = http(admin, "POST", "/api/whitelist",
                        {"kind": "comm", "match": "e2e-curl",
                         "valid_until": future, "note": "e2e 临时放行"})
        wid = body.get("id")
        R.check(st == 200 and bool(wid), f"W1 新增白名单 → 200/id={wid} (got {st}: {body})")
        st, body = http(admin, "GET", "/api/whitelist")
        items = [w for w in body.get("whitelist", []) if w.get("match") == "e2e-curl"]
        R.check(len(items) == 1 and items[0].get("active") is True,
                "W1a 列表可见且 active=true")

        http(admin, "POST", "/api/whitelist",
             {"kind": "comm", "match": "e2e-curl",
              "valid_until": future, "note": "again"})
        st, body = http(admin, "GET", "/api/whitelist")
        dup = [w for w in body.get("whitelist", []) if w.get("match") == "e2e-curl"]
        R.check(len(dup) == 1 and dup[0].get("id") == wid,
                "W2 同 match 幂等：不重复入库且 id 不变")

        st, _ = http(admin, "POST", "/api/whitelist",
                     {"kind": "bogus", "match": "x",
                      "valid_until": future, "note": "n"})
        R.check(st == 400, f"W3a kind 非法 → 400 (got {st})")
        st, _ = http(admin, "POST", "/api/whitelist",
                     {"kind": "comm", "match": "x", "valid_until": future})
        R.check(st == 400, f"W3b 缺 note → 400 (got {st})")

        st, _ = http(admin, "DELETE", f"/api/whitelist/{wid}")
        R.check(st == 200, f"W4 DELETE /api/whitelist/{{id}} → 200 (got {st})")
        st, body = http(admin, "GET", "/api/whitelist")
        R.check(not any(w.get("id") == wid for w in body.get("whitelist", [])),
                "W4a 删除后不可见")

        st, body = http(admin, "POST", "/api/whitelist",
                        {"kind": "container", "match": "e2e-expired",
                         "valid_until": past, "note": "expired"})
        eid = body.get("id")
        st, body = http(admin, "GET", "/api/whitelist")
        it = next((w for w in body.get("whitelist", [])
                   if w.get("match") == "e2e-expired"), None)
        R.check(it is not None and it.get("active") is False,
                "W5 过期条目 active=false（告警恢复）")
        if eid:
            http(admin, "DELETE", f"/api/whitelist/{eid}")

        print("== [5/6] RBAC (analyst=test) ==")
        analyst = new_opener()
        st, _ = http(analyst, "POST", "/api/auth/login",
                     {"username": "test", "password": pw_test})
        R.check(st == 200, f"test(analyst) 登录 → 200 (got {st})")
        st, _ = http(analyst, "GET", "/api/rules")
        R.check(st == 200, f"RBAC GET /api/rules → 200 (got {st})")
        st, _ = http(analyst, "POST", "/api/rules",
                     {"rule": new_rule, "source": "manual"})
        R.check(st == 403, f"RBAC POST /api/rules → 403 (got {st})")
        st, _ = http(analyst, "POST", "/api/whitelist",
                     {"kind": "comm", "match": "z",
                      "valid_until": future, "note": "n"})
        R.check(st == 403, f"RBAC POST /api/whitelist → 403 (got {st})")

        print("== [6/6] v0.6.5.1 修复点回归（P1/P2）==")
        http(admin, "POST", "/api/whitelist",
             {"kind": "comm", "match": "e2e-readd",
              "valid_until": past, "note": "expired"})
        st, body = http(admin, "POST", "/api/whitelist",
                        {"kind": "comm", "match": "e2e-readd",
                         "valid_until": future, "note": "renew"})
        st, body = http(admin, "GET", "/api/whitelist")
        ri = next((w for w in body.get("whitelist", [])
                   if w.get("match") == "e2e-readd"), None)
        if ri and ri.get("active") is True:
            R.ok("P1 过期后再 add(未来) → 重新生效")
        else:
            R.probe("P1 过期后再 add(未来) 未重新生效 "
                    f"(active={ri.get('active') if ri else None}) — "
                    "幂等分支命中已过期条目，需先 DELETE 才能续期")

        http(admin, "POST", "/api/whitelist",
             {"kind": "comm", "match": "e2e-baddate",
              "valid_until": "not-a-date", "note": "malformed"})
        st, body = http(admin, "GET", "/api/whitelist")
        bi = next((w for w in body.get("whitelist", [])
                   if w.get("match") == "e2e-baddate"), None)
        if bi and bi.get("active") is True:
            R.probe("P2 valid_until 非法格式被当作『永不过期』(active=true) — "
                    "fail-open，建议 API 层校验 ISO 格式")
        else:
            R.ok("P2 非法 valid_until 未 fail-open")

        okf, names_f = rules_stats(rules_path)
        R.check(okf and names_f == names_before,
                "FINAL rules.yaml 全程操作后仍等于初始 12 条且可解析")
    finally:
        stop()

    print("\n" + "=" * 60)
    print(f"通过 {R.p} / 失败 {R.f} / 探针 {R.probes}")
    if R.f == 0:
        shutil.rmtree(tmp, ignore_errors=True)
        print("隔离副本已清理")
    else:
        print(f"失败，保留现场：{tmp}")
    print("=" * 60)
    return 1 if R.f else 0


if __name__ == "__main__":
    sys.exit(main())
