"""routes 辅助函数单测 —— 时间戳归一化与 JSON 安全序列化。

v0.6.7 教训：pandas 行里的 NaN 直接进响应会让 json.dumps 抛
"Out of range float values are not JSON compliant"，接口 500。
alert_detail 与队列都踩过，这里钉住行为。
"""
import math

import pandas as pd
import pytest


def _row_to_dict():
    from server.routes import _row_to_dict as f
    return f


class TestNormTs:
    @pytest.mark.parametrize("raw,expected", [
        ("2026-11-19 22:20:08.926", "2026-11-19T22:20:08.926"),
        ("2026-11-19T22:20:08.926000", "2026-11-19T22:20:08.926"),
        ("2026-11-19T22:20:08", "2026-11-19T22:20:08"),
    ])
    def test_norm(self, raw, expected):
        from server.routes import _norm_ts
        assert _norm_ts(raw) == expected

    def test_events_and_ai_formats_meet(self):
        """events(微秒) 与 ai_results(毫秒) 归一化后必须相等 —— 否则 AI 永远关联不上。"""
        from server.routes import _norm_ts
        assert _norm_ts("2026-11-19T22:24:57.046000") == _norm_ts("2026-11-19T22:24:57.046")


class TestRowToDict:
    def test_nan_becomes_none(self):
        f = _row_to_dict()
        row = pd.Series({"rule": "x", "tier2_confidence": float("nan"),
                         "escalation": None})
        out = f(row)
        assert out["tier2_confidence"] is None
        assert out["escalation"] is None
        assert out["rule"] == "x"

    def test_timestamp_to_str(self):
        """pandas Timestamp 必须转成字符串，且归一化后与原值一致。

        str(Timestamp) 是空格分隔（"2026-11-19 22:20:08.926000"），
        前端拿它回传时由 _norm_ts 统一，这里钉住的是「可序列化 + 归一化等价」。
        """
        from server.routes import _norm_ts
        f = _row_to_dict()
        row = pd.Series({"timestamp": pd.Timestamp("2026-11-19T22:20:08.926")})
        out = f(row)
        assert isinstance(out["timestamp"], str)
        assert _norm_ts(out["timestamp"]) == "2026-11-19T22:20:08.926"

    def test_result_is_json_serializable(self):
        """核心断言：含 NaN 的行经 _row_to_dict 后必须能 json.dumps。"""
        import json
        f = _row_to_dict()
        row = pd.Series({"a": float("nan"), "b": pd.NaT, "c": 1, "d": "s"})
        json.dumps(f(row))   # 不抛异常即通过
