"""规则效果评估 API。

统计口径：
- 命中量：区间内命中该规则的事件数（一条事件命中多条规则时分别计入）；
- 拦截 / 复核 / 告警 / 放行：命中事件按「最终动作」分布
  （最终动作 = 该事件所有命中规则中强度最高的动作，reject > review > alert > pass）；
- 告警量：区间内该规则新产生的告警记录数（去重累加不重复计入）；
- 命中率 = 命中量 / 区间总事件数；
- 覆盖率 = 命中量 / 区间命中事件数（至少命中一条规则的事件数）；
- 冷门规则：启用中的规则，区间内从未命中，或命中量低于阈值（默认 3 次）。
"""
import csv
import io
import json
import time

from flask import Blueprint, request, jsonify, Response

from backend import runtime
from backend.auth import login_required

bp = Blueprint("rule_eval", __name__, url_prefix="/api/rule_eval")

_STAT_KEYS = ("hits", "reject", "review", "alert", "pass", "alerts")

_VERDICT_LABEL = {
    "never_hit": "从未命中",
    "low_hit": "命中极低",
    "normal": "正常",
    "disabled": "已停用",
    "deleted": "已删除",
}


def _parse_range():
    """解析时间范围参数，默认最近 1 小时。"""
    end = request.args.get("end", type=float) or time.time()
    start = request.args.get("start", type=float)
    if not start:
        start = end - 3600
    if start > end:
        start, end = end, start
    return start, end


def _rule_meta():
    """当前规则元数据：rule_id -> 展示用字典。"""
    meta = {}
    for r in runtime.engine.registry.list_rules():
        meta[r["id"]] = {
            "rule_id": r["id"],
            "name": r.get("name", r["id"]),
            "tags": list(r.get("tags") or []),
            "action": (r.get("action") or {}).get("type", "alert"),
            "enabled": bool(r.get("enabled", True)),
            "deleted": False,
        }
    return meta


def _aggregate(start, end):
    """汇总区间内的分钟桶，返回 (totals, per_rule, pairs)。"""
    buckets = runtime.engine.rule_metrics.query(start, end)
    totals = {"events": 0, "matched": 0, "multi": 0}
    per_rule = {}
    pairs = {}
    for bts in sorted(buckets):
        b = buckets[bts]
        totals["events"] += b.get("total", 0)
        totals["matched"] += b.get("matched", 0)
        totals["multi"] += b.get("multi", 0)
        for rid, stat in b.get("rules", {}).items():
            agg = per_rule.setdefault(rid, {k: 0 for k in _STAT_KEYS})
            agg.setdefault("last_hit", 0)
            for k in _STAT_KEYS:
                agg[k] += stat.get(k, 0)
            if stat.get("hits"):
                agg["last_hit"] = max(agg["last_hit"], bts)
        for key, n in b.get("pairs", {}).items():
            pairs[key] = pairs.get(key, 0) + n
    return totals, per_rule, pairs


def _build_summary(start, end, tag=None, rule_id=None, cold_hits=3):
    """汇总评估表 + 冷门规则识别（供 summary 与 export 复用）。"""
    totals, per_rule, _pairs = _aggregate(start, end)
    meta = _rule_meta()

    # 区间内有命中记录但已被删除的规则也展示（标记已删除）
    for rid in per_rule:
        if rid not in meta:
            meta[rid] = {"rule_id": rid, "name": rid, "tags": [],
                         "action": "-", "enabled": False, "deleted": True}

    rows = []
    for rid, m in meta.items():
        if rule_id and rid != rule_id:
            continue
        if tag and tag not in m["tags"]:
            continue
        stat = per_rule.get(rid) or {}
        hits = stat.get("hits", 0)
        events = totals["events"]
        matched = totals["matched"]
        row = dict(m)
        row.update({
            "hits": hits,
            "reject": stat.get("reject", 0),
            "review": stat.get("review", 0),
            "alert": stat.get("alert", 0),
            "pass": stat.get("pass", 0),
            "alerts": stat.get("alerts", 0),
            "hit_rate": round(hits / events, 4) if events else 0,
            "coverage": round(hits / matched, 4) if matched else 0,
            "last_hit": stat.get("last_hit") or None,
        })
        # 冷门评估：仅针对启用中的规则
        if m["deleted"]:
            row["verdict"] = "deleted"
        elif not m["enabled"]:
            row["verdict"] = "disabled"
        elif hits == 0:
            row["verdict"] = "never_hit"
        elif hits < cold_hits:
            row["verdict"] = "low_hit"
        else:
            row["verdict"] = "normal"
        rows.append(row)

    rows.sort(key=lambda r: (-r["hits"], r["rule_id"]))

    cold_never = [r for r in rows if r["verdict"] == "never_hit"]
    cold_low = [r for r in rows if r["verdict"] == "low_hit"]
    all_tags = sorted({t for m in meta.values() for t in m["tags"]})

    return {
        "range": {"start": start, "end": end},
        "totals": {
            "events": totals["events"],
            "matched": totals["matched"],
            "multi_hit": totals["multi"],
            "hit_rate": round(totals["matched"] / totals["events"], 4) if totals["events"] else 0,
            "multi_hit_ratio": round(totals["multi"] / totals["matched"], 4) if totals["matched"] else 0,
            "rules": len(rows),
            "cold_rules": len(cold_never) + len(cold_low),
        },
        "rules": rows,
        "cold_rules": {
            "threshold": cold_hits,
            "never_hit": [{"rule_id": r["rule_id"], "name": r["name"],
                           "tags": r["tags"]} for r in cold_never],
            "low_hit": [{"rule_id": r["rule_id"], "name": r["name"],
                         "tags": r["tags"], "hits": r["hits"]} for r in cold_low],
        },
        "tags": all_tags,
    }


@bp.route("", methods=["GET"])
@login_required
def summary():
    """规则效果汇总：命中量/拦截/复核/告警量/命中率/覆盖率 + 冷门规则。"""
    start, end = _parse_range()
    tag = request.args.get("tag") or None
    rule_id = request.args.get("rule_id") or None
    cold_hits = request.args.get("cold_hits", type=int) or 3
    cold_hits = max(1, min(cold_hits, 1000))
    data = _build_summary(start, end, tag=tag, rule_id=rule_id, cold_hits=cold_hits)
    return jsonify({"ok": True, "eval": data})


def _auto_bucket(start, end):
    """根据时间跨度选择趋势图分桶粒度。"""
    span = end - start
    if span <= 3 * 3600:
        return 60
    if span <= 24 * 3600:
        return 300
    if span <= 7 * 86400:
        return 3600
    return 86400


@bp.route("/trend", methods=["GET"])
@login_required
def trend():
    """规则命中量时间趋势（默认取命中量 top N 的规则）。"""
    start, end = _parse_range()
    bucket_sec = request.args.get("bucket", type=int) or _auto_bucket(start, end)
    bucket_sec = max(60, min(bucket_sec, 86400))
    tag = request.args.get("tag") or None
    rule_ids = request.args.get("rule_ids")
    top = request.args.get("top", type=int) or 5
    top = max(1, min(top, 10))

    buckets = runtime.engine.rule_metrics.query(start, end)
    meta = _rule_meta()

    # 每个规则的区间总命中，用于挑选 top N
    totals = {}
    for b in buckets.values():
        for rid, stat in b.get("rules", {}).items():
            totals[rid] = totals.get(rid, 0) + stat.get("hits", 0)

    if rule_ids:
        selected = []
        for rid in rule_ids.split(","):
            rid = rid.strip()
            if rid and rid not in selected:
                selected.append(rid)
        selected = selected[:10]
    else:
        candidates = sorted(totals, key=lambda r: (-totals[r], r))
        if tag:
            candidates = [r for r in candidates
                          if tag in (meta.get(r) or {}).get("tags", [])]
        selected = candidates[:top]

    # 对齐时间轴
    first = int(start // bucket_sec) * bucket_sec
    axis = []
    t = first
    while t <= end:
        axis.append(t)
        t += bucket_sec
    index = {bts: i for i, bts in enumerate(axis)}

    series_map = {rid: [0] * len(axis) for rid in selected}
    selected_set = set(selected)
    for bts, b in buckets.items():
        slot = index.get(int(bts // bucket_sec) * bucket_sec)
        if slot is None:
            continue
        for rid, stat in b.get("rules", {}).items():
            if rid in selected_set:
                series_map[rid][slot] += stat.get("hits", 0)

    series = []
    for rid in selected:
        m = meta.get(rid) or {}
        series.append({
            "rule_id": rid,
            "name": m.get("name", rid),
            "hits": totals.get(rid, 0),
            "data": series_map[rid],
        })
    return jsonify({"ok": True, "trend": {
        "bucket_sec": bucket_sec,
        "buckets": axis,
        "series": series,
    }})


@bp.route("/overlap", methods=["GET"])
@login_required
def overlap():
    """规则命中重叠：多规则命中占比 + 规则对共现矩阵。"""
    start, end = _parse_range()
    tag = request.args.get("tag") or None
    rule_id = request.args.get("rule_id") or None
    totals, per_rule, pairs = _aggregate(start, end)
    meta = _rule_meta()

    def _name(rid):
        m = meta.get(rid)
        return m["name"] if m else rid

    def _has_tag(rid):
        m = meta.get(rid)
        return bool(m) and tag in m["tags"]

    pair_rows = []
    for key, n in pairs.items():
        a, b = key.split("|", 1)
        if rule_id and rule_id not in (a, b):
            continue
        if tag and not (_has_tag(a) or _has_tag(b)):
            continue
        hits_a = per_rule.get(a, {}).get("hits", 0)
        hits_b = per_rule.get(b, {}).get("hits", 0)
        pair_rows.append({
            "a": a, "b": b,
            "a_name": _name(a), "b_name": _name(b),
            "count": n,
            "pct_of_a": round(n / hits_a, 4) if hits_a else 0,
            "pct_of_b": round(n / hits_b, 4) if hits_b else 0,
        })
    pair_rows.sort(key=lambda p: -p["count"])

    # 单规则共现度：命中事件同时命中其他规则的次数合计 / 命中量
    # （一条事件命中 k 条规则时，每条规则计 k-1 次共现，比值可大于 1）
    co = {}
    for key, n in pairs.items():
        a, b = key.split("|", 1)
        co[a] = co.get(a, 0) + n
        co[b] = co.get(b, 0) + n
    rule_rows = []
    for rid, stat in per_rule.items():
        if rule_id and rid != rule_id:
            continue
        if tag and not _has_tag(rid):
            continue
        hits = stat.get("hits", 0)
        rule_rows.append({
            "rule_id": rid,
            "name": _name(rid),
            "hits": hits,
            "co_hits": co.get(rid, 0),
            "overlap_ratio": round(co.get(rid, 0) / hits, 4) if hits else 0,
        })
    rule_rows.sort(key=lambda r: (-r["overlap_ratio"], -r["hits"]))

    return jsonify({"ok": True, "overlap": {
        "matched_events": totals["matched"],
        "multi_hit_events": totals["multi"],
        "multi_hit_ratio": round(totals["multi"] / totals["matched"], 4) if totals["matched"] else 0,
        "pairs": pair_rows[:50],
        "rules": rule_rows,
    }})


@bp.route("/export", methods=["GET"])
@login_required
def export():
    """导出评估结果（CSV / JSON）。"""
    fmt = request.args.get("fmt", "csv")
    start, end = _parse_range()
    tag = request.args.get("tag") or None
    rule_id = request.args.get("rule_id") or None
    cold_hits = request.args.get("cold_hits", type=int) or 3
    cold_hits = max(1, min(cold_hits, 1000))
    data = _build_summary(start, end, tag=tag, rule_id=rule_id, cold_hits=cold_hits)
    ts = int(time.time())

    if fmt == "json":
        body = json.dumps(data, ensure_ascii=False, indent=2)
        return Response(body, content_type="application/json; charset=utf-8",
                        headers={"Content-Disposition":
                                 f"attachment; filename=rule_eval_{ts}.json"})

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["规则ID", "规则名称", "标签", "动作", "状态",
                     "命中量", "拦截", "复核", "告警量",
                     "命中率", "覆盖率", "最近命中", "评估"])
    for r in data["rules"]:
        writer.writerow([
            r["rule_id"], r["name"], "|".join(r["tags"]), r["action"],
            "启用" if r["enabled"] else "停用",
            r["hits"], r["reject"], r["review"], r["alerts"],
            f"{r['hit_rate'] * 100:.2f}%", f"{r['coverage'] * 100:.2f}%",
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["last_hit"])) if r["last_hit"] else "-",
            _VERDICT_LABEL.get(r["verdict"], r["verdict"]),
        ])
    # 带 BOM 的 UTF-8，保证 Excel 打开中文不乱码
    body = "﻿" + buf.getvalue()
    return Response(body, content_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition":
                             f"attachment; filename=rule_eval_{ts}.csv"})
