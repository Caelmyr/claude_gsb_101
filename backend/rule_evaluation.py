"""规则效果评估：历史事件回放、指标汇总、趋势与命中重叠分析。

评估口径：
- 命中量：某条规则 alpha + beta 条件同时满足的事件数；
- 拦截 / 复核 / 告警量：按规则当前配置动作分别统计命中量；
- 命中率：规则命中量 / 评估期事件总量；
- 覆盖率：规则命中量 / 评估期命中事件数（一条事件命中多规则会分别计入，
  因此所有规则覆盖率之和可能超过 100%）；
- 重叠率：命中事件数 >= 2 条规则的事件 / 全部命中事件。

历史事件可能由早期版本引擎写入、缺少决策明细，因此评估采用「当前规则快照 +
独立滑动窗口」按时间顺序回放，不污染线上引擎窗口与统计计数。
"""
import copy
import hashlib
import json
import time
from collections import Counter

from backend.engine.rule_parser import compile_rule, _get_field
from backend.engine.window import SlidingWindowAggregator

ACTIONS = ("reject", "review", "alert", "pass")
# 与 RiskEngine._ACTION_RANK 保持一致，用于汇总事件最终处置。
ACTION_RANK = {"reject": 2, "review": 3, "alert": 1, "pass": 0}


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v is not None and str(v) != ""]
    return [str(value)]


def rule_dimensions(rule):
    """返回规则维度：优先显式 dimension(s)，否则从事件类型条件推断。"""
    dims = []
    for value in _as_list(rule.get("dimensions")) + _as_list(rule.get("dimension")):
        if value not in dims:
            dims.append(value)

    for cond in rule.get("conditions", []) or []:
        if not isinstance(cond, dict) or "agg" in cond:
            continue
        if cond.get("field") != "type":
            continue
        op = cond.get("op")
        value = cond.get("value")
        candidates = []
        if op == "==" and value not in (None, ""):
            candidates = [value]
        elif op == "in" and isinstance(value, (list, tuple, set)):
            candidates = list(value)
        for item in candidates:
            item = str(item)
            if item and item not in dims:
                dims.append(item)
    return dims or ["通用"]


def max_window_sec(rules):
    """计算规则集合回放所需的最大滑动窗口。"""
    max_window = 0
    for rule in rules:
        for cond in rule.get("conditions", []) or []:
            if not isinstance(cond, dict):
                continue
            agg = cond.get("agg")
            if not isinstance(agg, dict):
                continue
            try:
                max_window = max(max_window, int(agg.get("window_sec", 60)))
            except (TypeError, ValueError):
                continue
    return max(max_window, 60)


def deduplicate_events(events):
    """去除事件存储/缓冲合并产生的完全重复记录，并按时间升序返回。"""
    unique = {}
    for event in events or []:
        if not isinstance(event, dict):
            continue
        try:
            ts = float(event.get("ts") or 0)
        except (TypeError, ValueError):
            continue
        if ts <= 0:
            continue
        event_id = event.get("id")
        if event_id:
            key = ("id_ts", str(event_id), round(ts, 6))
        else:
            try:
                raw = json.dumps(event, ensure_ascii=False, sort_keys=True,
                                 separators=(",", ":"), default=str)
            except (TypeError, ValueError):
                raw = repr(sorted(event.items(), key=lambda item: str(item[0])))
            key = ("raw", hashlib.sha1(raw.encode("utf-8")).hexdigest())
        if key not in unique:
            unique[key] = event
    return sorted(unique.values(), key=lambda e: float(e.get("ts") or 0))


def _choose_granularity(start_ts, end_ts):
    span = max(0, end_ts - start_ts)
    if span <= 2 * 3600:
        return "minute", 60
    if span <= 48 * 3600:
        return "hour", 3600
    return "day", 86400


def _ratio(numerator, denominator):
    if not denominator:
        return 0.0
    return round(numerator / denominator, 6)


def _matches_filters(rule, filters):
    filters = filters or {}
    tags = set(_as_list(rule.get("tags")))
    wanted_tags = set(filters.get("tags") or [])
    if wanted_tags and not (tags & wanted_tags):
        return False

    dimensions = set(rule_dimensions(rule))
    wanted_dimensions = set(filters.get("dimensions") or [])
    if wanted_dimensions and not (dimensions & wanted_dimensions):
        return False

    action = (rule.get("action") or {}).get("type", "alert")
    if filters.get("action") and action != filters["action"]:
        return False

    status = filters.get("status") or "all"
    enabled = bool(rule.get("enabled", True))
    if status == "enabled" and not enabled:
        return False
    if status == "disabled" and enabled:
        return False

    keyword = (filters.get("keyword") or "").strip().lower()
    if keyword:
        haystack = " ".join([
            str(rule.get("id", "")),
            str(rule.get("name", "")),
            str(rule.get("description", "")),
        ]).lower()
        if keyword not in haystack:
            return False
    return True


def _feed_window(window, agg_feeds, event, ts):
    for key_field, value_field in agg_feeds:
        key = _get_field(event, key_field)
        if key is None:
            continue
        value = _get_field(event, value_field) if value_field else None
        window.add(key, value=value, ts=ts)


def _final_action(fired):
    if not fired:
        return "pass"
    best = max(
        fired,
        key=lambda rule: (
            ACTION_RANK.get(rule.action.get("type", "alert"), 0),
            rule.priority,
        ),
    )
    return best.action.get("type", "alert")


def evaluate_rules(rules, events, start_ts, end_ts, filters=None,
                   low_hit_threshold=5, low_hit_rate=0.001):
    """回放事件并计算规则效果指标。"""
    filters = filters or {}
    all_rules = list(rules or [])
    filtered_rules = [r for r in all_rules if _matches_filters(r, filters)]

    compiled_rules = []
    invalid_rules = []
    for rule in filtered_rules:
        try:
            compiled = compile_rule(copy.deepcopy(rule), version=rule.get("version"))
            compiled_rules.append((rule, compiled))
        except Exception as exc:  # 单条坏规则不应拖垮整体评估
            invalid_rules.append({
                "rule_id": rule.get("id"),
                "name": rule.get("name"),
                "error": str(exc),
            })

    agg_feeds = []
    seen_feeds = set()
    replay_window_sec = 60
    for _, compiled in compiled_rules:
        for spec in compiled.agg_specs:
            feed = (spec.key_field, spec.value_field)
            if feed not in seen_feeds:
                seen_feeds.add(feed)
                agg_feeds.append(feed)
            replay_window_sec = max(replay_window_sec, spec.window_sec)

    events = deduplicate_events(events)
    event_capacity = max(10, len(events) + 10)
    window = SlidingWindowAggregator(
        max_keys=max(200000, event_capacity),
        max_events_per_key=max(20000, event_capacity),
        max_total_events=max(2000000, event_capacity),
        retention_sec=replay_window_sec,
    )

    in_range = []
    for event in events:
        ts = float(event.get("ts") or 0)
        if ts < start_ts:
            # 预热窗口：让评估期起点附近的频率/聚合规则得到完整上下文。
            _feed_window(window, agg_feeds, event, ts)
        elif ts <= end_ts:
            in_range.append(event)

    granularity, bucket_sec = _choose_granularity(start_ts, end_ts)
    first_bucket = int(start_ts // bucket_sec) * bucket_sec
    last_bucket = int(end_ts // bucket_sec) * bucket_sec
    buckets = list(range(first_bucket, last_bucket + 1, bucket_sec))

    rule_stats = {
        compiled.id: {
            "rule": raw,
            "compiled": compiled,
            "hits": 0,
            "actions": Counter(),
            "first_hit_ts": None,
            "last_hit_ts": None,
            "bucket_hits": Counter(),
        }
        for raw, compiled in compiled_rules
    }
    bucket_events = Counter()
    bucket_actions = {action: Counter() for action in ACTIONS}
    action_totals = Counter()
    final_action_totals = Counter()
    pair_counts = Counter()

    total_events = 0
    matched_events = 0
    overlap_events = 0
    total_rule_hits = 0

    for event in in_range:
        ts = float(event.get("ts") or 0)
        bucket = int(ts // bucket_sec) * bucket_sec
        total_events += 1
        bucket_events[bucket] += 1

        # 与线上引擎一致：先写入滑动窗口，再执行 alpha + beta 匹配。
        _feed_window(window, agg_feeds, event, ts)
        fired = []
        for _, compiled in compiled_rules:
            if not compiled.match_alpha(event):
                continue
            matched = True
            for spec in compiled.agg_specs:
                key = _get_field(event, spec.key_field)
                if key is None:
                    matched = False
                    break
                value = window.query(str(key), spec.window_sec, spec.agg_type, now=ts)
                if not spec.evaluate(value):
                    matched = False
                    break
            if matched:
                fired.append(compiled)

        final_action_totals[_final_action(fired)] += 1
        if not fired:
            continue

        matched_events += 1
        if len(fired) > 1:
            overlap_events += 1
        total_rule_hits += len(fired)

        fired_ids = []
        for compiled in fired:
            stats = rule_stats[compiled.id]
            stats["hits"] += 1
            action = compiled.action.get("type", "alert")
            if action not in ACTIONS:
                action = "alert"
            stats["actions"][action] += 1
            stats["bucket_hits"][bucket] += 1
            stats["first_hit_ts"] = stats["first_hit_ts"] or ts
            stats["last_hit_ts"] = ts
            action_totals[action] += 1
            bucket_actions[action][bucket] += 1
            fired_ids.append(compiled.id)

        fired_ids.sort()
        for i in range(len(fired_ids)):
            for j in range(i + 1, len(fired_ids)):
                pair_counts[(fired_ids[i], fired_ids[j])] += 1

    rows = []
    for raw, compiled in compiled_rules:
        stats = rule_stats[compiled.id]
        hits = stats["hits"]
        hit_rate = _ratio(hits, total_events)
        coverage = _ratio(hits, matched_events)
        if hits == 0:
            cold_status = "never"
            cold_reason = "评估期内从未命中，建议检查条件、阈值或是否下线"
        elif hits <= low_hit_threshold or hit_rate < low_hit_rate:
            cold_status = "low"
            cold_reason = (
                f"命中 {hits} 次，低于冷门阈值 {low_hit_threshold} 次"
                f"或命中率低于 {low_hit_rate * 100:.2f}%"
            )
        else:
            cold_status = "normal"
            cold_reason = ""

        action_counts = {action: stats["actions"].get(action, 0) for action in ACTIONS}
        rows.append({
            "rule_id": compiled.id,
            "name": raw.get("name", compiled.id),
            "description": raw.get("description", ""),
            "enabled": bool(raw.get("enabled", True)),
            "priority": raw.get("priority", 0),
            "version": raw.get("version", 1),
            "tags": _as_list(raw.get("tags")),
            "dimensions": rule_dimensions(raw),
            "action": compiled.action.get("type", "alert"),
            "risk_score": compiled.action.get("risk_score", 0),
            "hits": hits,
            "action_counts": action_counts,
            "hit_rate": hit_rate,
            "coverage": coverage,
            "event_coverage": _ratio(hits, total_events),
            "first_hit_ts": stats["first_hit_ts"],
            "last_hit_ts": stats["last_hit_ts"],
            "cold_status": cold_status,
            "cold_reason": cold_reason,
        })

    rows.sort(key=lambda row: (-row["hits"], str(row["rule_id"])))
    hits_by_id = {row["rule_id"]: row["hits"] for row in rows}

    matrix_rules = [{"rule_id": row["rule_id"], "name": row["name"]} for row in rows]
    matrix = []
    for i, left in enumerate(rows):
        for j, right in enumerate(rows):
            left_id = left["rule_id"]
            right_id = right["rule_id"]
            if i == j:
                co_hits = left["hits"]
            else:
                pair_key = tuple(sorted((left_id, right_id)))
                co_hits = pair_counts.get(pair_key, 0)
            union = left["hits"] + right["hits"] - co_hits
            matrix.append({
                "x": j,
                "y": i,
                "rule_x": right_id,
                "rule_y": left_id,
                "co_hits": co_hits,
                "overlap_rate": _ratio(co_hits, union),
            })

    overlap_pairs = []
    for (left_id, right_id), co_hits in pair_counts.items():
        if co_hits <= 0:
            continue
        union = hits_by_id.get(left_id, 0) + hits_by_id.get(right_id, 0) - co_hits
        overlap_pairs.append({
            "rule_a": left_id,
            "rule_b": right_id,
            "co_hits": co_hits,
            "overlap_rate": _ratio(co_hits, union),
            "event_coverage": _ratio(co_hits, matched_events),
        })
    overlap_pairs.sort(key=lambda item: (-item["co_hits"], item["rule_a"], item["rule_b"]))

    trend_series = []
    for row in rows:
        stats = rule_stats[row["rule_id"]]
        trend_series.append({
            "rule_id": row["rule_id"],
            "name": row["name"],
            "data": [stats["bucket_hits"].get(bucket, 0) for bucket in buckets],
        })

    trend_actions = []
    for action in ACTIONS:
        trend_actions.append({
            "action": action,
            "data": [bucket_actions[action].get(bucket, 0) for bucket in buckets],
        })

    all_tags = sorted({tag for rule in all_rules for tag in _as_list(rule.get("tags"))})
    all_dimensions = sorted({dim for rule in all_rules for dim in rule_dimensions(rule)})
    cold_rules = [row for row in rows if row["cold_status"] != "normal"]

    return {
        "range": {
            "start_ts": start_ts,
            "end_ts": end_ts,
            "granularity": granularity,
            "bucket_sec": bucket_sec,
            "scanned_events": len(events),
            "event_count": total_events,
        },
        "filters": {
            "tags": filters.get("tags") or [],
            "dimensions": filters.get("dimensions") or [],
            "action": filters.get("action") or "",
            "status": filters.get("status") or "all",
            "keyword": filters.get("keyword") or "",
            "low_hit_threshold": low_hit_threshold,
            "low_hit_rate": low_hit_rate,
        },
        "filter_options": {
            "tags": all_tags,
            "dimensions": all_dimensions,
            "actions": list(ACTIONS),
        },
        "summary": {
            "total_events": total_events,
            "matched_events": matched_events,
            "unmatched_events": max(0, total_events - matched_events),
            "rule_hits": total_rule_hits,
            "hit_rate": _ratio(total_rule_hits, total_events),
            "event_hit_rate": _ratio(matched_events, total_events),
            "coverage": _ratio(matched_events, total_events),
            "overlap_events": overlap_events,
            "overlap_rate": _ratio(overlap_events, matched_events),
            "avg_rules_per_matched_event": _ratio(total_rule_hits, matched_events),
            "actions": {action: action_totals.get(action, 0) for action in ACTIONS},
            "final_actions": {action: final_action_totals.get(action, 0) for action in ACTIONS},
            "rules_evaluated": len(rows),
            "cold_rules": len(cold_rules),
        },
        "rules": rows,
        "cold_rules": cold_rules,
        "trend": {
            "granularity": granularity,
            "buckets": buckets,
            "total_events": [bucket_events.get(bucket, 0) for bucket in buckets],
            "series": trend_series,
            "actions": trend_actions,
        },
        "overlap": {
            "rules": matrix_rules,
            "matrix": matrix,
            "pairs": overlap_pairs,
        },
        "invalid_rules": invalid_rules,
        "generated_at": time.time(),
    }
