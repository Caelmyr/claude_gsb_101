"""规则效果评估指标记录器。

为「规则效果评估」提供数据底座：按分钟桶统计每条规则的命中量、
最终动作分布（拦截/复核/告警/放行）、新产生的告警量，以及规则之间的
共现情况（同一事件命中多条规则的规则对计数）。

设计要点：
- 与事件存储相同的「内存缓冲 + 后台定时刷盘」模式，高频事件流下
  不在处理链路上做磁盘 IO；
- 按天分片持久化（data/rule_metrics/YYYYMMDD.json），刷盘时与磁盘
  已有数据按桶合并（读-改-写），进程重启不丢历史；
- 最终动作由命中规则集合独立判定（reject > review > alert > pass），
  口径稳定，不随引擎主链路的决策映射调整而变化；
- 查询时合并「磁盘分片 + 内存未刷盘缓冲」，保证读到最新数据。
"""
import os
import threading
import time

from backend import config
from backend.storage import atomic_write_json, read_json

# 最终动作强度：拦截 > 复核 > 告警 > 放行
_ACTION_RANK = {"reject": 3, "review": 2, "alert": 1, "pass": 0}
_RULE_KEYS = ("hits", "reject", "review", "alert", "pass", "alerts")


def _day_key(ts):
    """与告警分片一致的时区约定（UTC+8）。"""
    t = time.gmtime(ts - 8 * 3600)
    return f"{t.tm_year:04d}{t.tm_mon:02d}{t.tm_mday:02d}"


def _new_rule_stat():
    return {k: 0 for k in _RULE_KEYS}


def _new_bucket():
    return {"total": 0, "matched": 0, "multi": 0, "rules": {}, "pairs": {}}


def merge_bucket(dst, src):
    """把 src 桶数据累加进 dst 桶（dst 会被就地修改）。"""
    dst["total"] = dst.get("total", 0) + src.get("total", 0)
    dst["matched"] = dst.get("matched", 0) + src.get("matched", 0)
    dst["multi"] = dst.get("multi", 0) + src.get("multi", 0)
    rules = dst.setdefault("rules", {})
    for rid, stat in src.get("rules", {}).items():
        d = rules.setdefault(rid, _new_rule_stat())
        for k in _RULE_KEYS:
            d[k] = d.get(k, 0) + stat.get(k, 0)
    pairs = dst.setdefault("pairs", {})
    for key, n in src.get("pairs", {}).items():
        pairs[key] = pairs.get(key, 0) + n


class RuleMetricsRecorder:
    """按分钟桶记录规则命中指标，按天分片持久化。"""

    def __init__(self, bucket_sec=60, flush_interval=5.0, retention_days=90):
        self.bucket_sec = bucket_sec
        self.flush_interval = flush_interval
        self.retention_days = retention_days
        self._buffers = {}      # day_key -> {"buckets": {bucket_ts: bucket}}
        self._dirty = set()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._thread.start()

    # ------------------------------------------------------------------
    # 记录（引擎主链路调用）
    # ------------------------------------------------------------------
    def record(self, ts, fired_rules, alert_results=None):
        """记录一条事件的处理结果。

        fired_rules: 命中的 CompiledRule 列表（可为空）。
        alert_results: 引擎告警结果列表（元素含 rule_id / created）。
        """
        alerts_created = {}
        for ar in alert_results or []:
            if ar.get("created"):
                rid = ar.get("rule_id")
                if rid:
                    alerts_created[rid] = alerts_created.get(rid, 0) + 1

        # 最终动作：取命中规则中强度最高的动作类型
        final = "pass"
        best = -1
        for r in fired_rules:
            action_type = r.action.get("type", "alert")
            rank = _ACTION_RANK.get(action_type, 0)
            if rank > best:
                best = rank
                final = action_type
        if final not in _ACTION_RANK:
            final = "alert"

        day = _day_key(ts)
        bts = int(ts // self.bucket_sec) * self.bucket_sec
        with self._lock:
            buf = self._buffers.setdefault(day, {"buckets": {}})
            bucket = buf["buckets"].setdefault(bts, _new_bucket())
            bucket["total"] += 1
            n = len(fired_rules)
            if n:
                bucket["matched"] += 1
                if n >= 2:
                    bucket["multi"] += 1
                ids = []
                for r in fired_rules:
                    stat = bucket["rules"].setdefault(r.id, _new_rule_stat())
                    stat["hits"] += 1
                    stat[final] += 1
                    stat["alerts"] += alerts_created.get(r.id, 0)
                    ids.append(r.id)
                # 规则共现对（按 id 排序组合，保证键唯一）
                ids.sort()
                for i in range(len(ids)):
                    for j in range(i + 1, len(ids)):
                        key = ids[i] + "|" + ids[j]
                        bucket["pairs"][key] = bucket["pairs"].get(key, 0) + 1
            self._dirty.add(day)

    # ------------------------------------------------------------------
    # 刷盘
    # ------------------------------------------------------------------
    def _flush_loop(self):
        while not self._stop.is_set():
            self._stop.wait(self.flush_interval)
            try:
                self.flush_all()
            except Exception:
                pass

    def flush_all(self):
        with self._lock:
            days = list(self._dirty)
        for day in days:
            try:
                self._flush_day(day)
            except Exception:
                continue  # 缓冲保留，下个周期重试
            with self._lock:
                self._dirty.discard(day)
        self._cleanup_old()

    def _flush_day(self, day):
        path = os.path.join(config.RULE_METRICS_DIR, f"{day}.json")
        with self._lock:
            buf = self._buffers.get(day)
            if not buf or not buf["buckets"]:
                return
            data = read_json(path, {"buckets": {}})
            disk_buckets = data.setdefault("buckets", {})
            for bts, bucket in buf["buckets"].items():
                dst = disk_buckets.setdefault(str(bts), _new_bucket())
                merge_bucket(dst, bucket)
            atomic_write_json(path, data)
            buf["buckets"] = {}

    def _cleanup_old(self):
        """清理超过保留期的分片文件。"""
        if not self.retention_days:
            return
        cutoff = time.time() - self.retention_days * 86400
        try:
            names = os.listdir(config.RULE_METRICS_DIR)
        except OSError:
            return
        for name in names:
            if not name.endswith(".json"):
                continue
            try:
                ts = time.mktime(time.strptime(name[:-5], "%Y%m%d"))
            except (ValueError, OverflowError):
                continue
            if ts < cutoff:
                try:
                    os.remove(os.path.join(config.RULE_METRICS_DIR, name))
                except OSError:
                    pass

    def stop(self):
        self._stop.set()
        self.flush_all()

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def query(self, start_ts, end_ts):
        """查询 [start_ts, end_ts] 内的分钟桶，返回 {bucket_ts: bucket}。"""
        # 枚举覆盖区间的所有天分片（固定 UTC+8，每天恰好 86400 秒）
        days = []
        seen = set()
        t = start_ts
        while t <= end_ts:
            d = _day_key(t)
            if d not in seen:
                seen.add(d)
                days.append(d)
            t += 86400
        tail = _day_key(end_ts)
        if tail not in seen:
            days.append(tail)

        merged = {}
        for d in days:
            path = os.path.join(config.RULE_METRICS_DIR, f"{d}.json")
            data = read_json(path, {"buckets": {}})
            for key, bucket in data.get("buckets", {}).items():
                try:
                    bts = int(key)
                except (TypeError, ValueError):
                    continue
                if start_ts <= bts <= end_ts:
                    # read_json 每次返回全新对象，可直接作为合并基底
                    merged[bts] = bucket
            with self._lock:
                mem = list(self._buffers.get(d, {}).get("buckets", {}).items())
            for bts, bucket in mem:
                if not (start_ts <= bts <= end_ts):
                    continue
                # 内存桶是活跃对象，只作为合并来源，绝不被修改
                dst = merged.setdefault(bts, _new_bucket())
                merge_bucket(dst, bucket)
        return merged
