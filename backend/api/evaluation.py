"""规则效果评估 API：指标查询、趋势/重叠分析与导出。"""
import csv
import io
import json
import time

from flask import Blueprint, Response, jsonify, request

from backend import config, runtime
from backend.auth import login_required
from backend import rule_evaluation

bp = Blueprint("rule_evaluation", __name__, url_prefix="/api/rule-evaluation")


def _split_values(value):
    values = []
    for part in str(value or "").split(","):
        part = part.strip()
        if part and part not in values:
            values.append(part)
    return values


def _multi_param(*names):
    values = []
    for name in names:
        for raw in request.args.getlist(name):
            for value in _split_values(raw):
                if value not in values:
                    values.append(value)
    return values


def _parse_request():
    now = time.time()
    end_ts = request.args.get("end", type=float)
    start_ts = request.args.get("start", type=float)
    if end_ts is None:
        end_ts = now
    if start_ts is None:
        start_ts = end_ts - 7 * 86400
    if start_ts > end_ts:
        raise ValueError("开始时间不能晚于结束时间")

    low_hit_threshold = request.args.get("low_hit_threshold", type=int)
    if low_hit_threshold is None:
        low_hit_threshold = 5
    low_hit_threshold = max(0, min(low_hit_threshold, 100000))

    low_hit_rate = request.args.get("low_hit_rate", type=float)
    if low_hit_rate is None:
        low_hit_rate = 0.001
    low_hit_rate = max(0.0, min(low_hit_rate, 1.0))

    action = (request.args.get("action") or "").strip()
    if action and action not in config.ACTION_TYPES:
        action = ""
    status = (request.args.get("status") or "enabled").strip()
    if status not in ("all", "enabled", "disabled"):
        status = "enabled"

    filters = {
        "tags": _multi_param("tag", "tags"),
        "dimensions": _multi_param("dimension", "dimensions"),
        "action": action,
        "status": status,
        "keyword": (request.args.get("keyword") or "").strip(),
    }
    return start_ts, end_ts, filters, low_hit_threshold, low_hit_rate


def _build_evaluation():
    start_ts, end_ts, filters, low_hit_threshold, low_hit_rate = _parse_request()
    rules = runtime.engine.registry.list_rules()

    # 回放时需要把评估期之前的一个最大窗口也读入，用于预热频率类规则。
    warm_sec = rule_evaluation.max_window_sec(rules)
    scan_start = start_ts - warm_sec
    if scan_start < 0:
        scan_start = 0
    events = runtime.engine.events.scan(start_ts=scan_start, end_ts=end_ts)

    return rule_evaluation.evaluate_rules(
        rules,
        events,
        start_ts=start_ts,
        end_ts=end_ts,
        filters=filters,
        low_hit_threshold=low_hit_threshold,
        low_hit_rate=low_hit_rate,
    )


@bp.route("", methods=["GET"])
@login_required
def evaluate():
    try:
        result = _build_evaluation()
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "evaluation": result})


def _fmt_ts(ts):
    if not ts:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _csv_export(result):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "规则ID", "规则名称", "规则维度", "规则标签", "状态", "动作", "优先级", "版本",
        "命中量", "拦截量", "复核量", "告警量", "放行量",
        "命中率(%)", "覆盖率(%)", "事件覆盖率(%)",
        "首次命中时间", "最近命中时间", "冷门状态", "提醒",
    ])
    cold_labels = {"never": "从未命中", "low": "命中极低", "normal": "正常"}
    status_labels = {True: "启用", False: "停用"}
    action_labels = {"reject": "拦截", "review": "复核", "alert": "告警", "pass": "放行"}
    for row in result["rules"]:
        counts = row["action_counts"]
        writer.writerow([
            row["rule_id"],
            row["name"],
            "、".join(row["dimensions"]),
            "、".join(row["tags"]),
            status_labels[row["enabled"]],
            action_labels.get(row["action"], row["action"]),
            row["priority"],
            row["version"],
            row["hits"],
            counts.get("reject", 0),
            counts.get("review", 0),
            counts.get("alert", 0),
            counts.get("pass", 0),
            f"{row['hit_rate'] * 100:.2f}",
            f"{row['coverage'] * 100:.2f}",
            f"{row['event_coverage'] * 100:.2f}",
            _fmt_ts(row["first_hit_ts"]),
            _fmt_ts(row["last_hit_ts"]),
            cold_labels.get(row["cold_status"], row["cold_status"]),
            row["cold_reason"],
        ])
    return output.getvalue()


@bp.route("/export", methods=["GET"])
@login_required
def export_evaluation():
    fmt = (request.args.get("fmt") or "csv").lower()
    try:
        result = _build_evaluation()
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    if fmt == "json":
        body = json.dumps(result, ensure_ascii=False, indent=2)
        return Response(
            body,
            content_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename=rule_evaluation_{stamp}.json"},
        )

    body = "﻿" + _csv_export(result)
    return Response(
        body,
        content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=rule_evaluation_{stamp}.csv"},
    )
