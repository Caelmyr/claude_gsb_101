import unittest

from backend.rule_evaluation import deduplicate_events, evaluate_rules


class RuleEvaluationTest(unittest.TestCase):
    def setUp(self):
        self.rules = [
            {
                "id": "rule_login",
                "name": "登录规则",
                "enabled": True,
                "conditions": [{"field": "type", "op": "==", "value": "login"}],
                "action": {"type": "reject"},
                "tags": ["登录"],
            },
            {
                "id": "rule_amount",
                "name": "金额规则",
                "enabled": True,
                "conditions": [{"field": "amount", "op": ">", "value": 10}],
                "action": {"type": "review"},
                "tags": ["金额"],
            },
            {
                "id": "rule_freq",
                "name": "频率规则",
                "enabled": True,
                "conditions": [
                    {"field": "type", "op": "==", "value": "login"},
                    {"agg": {"window_sec": 60, "key_field": "ip", "op": ">=",
                             "threshold": 2, "agg_type": "count"}},
                ],
                "action": {"type": "alert"},
                "tags": ["高频"],
            },
            {
                "id": "rule_never",
                "name": "冷门规则",
                "enabled": True,
                "conditions": [{"field": "type", "op": "==", "value": "sms"}],
                "action": {"type": "alert"},
                "tags": ["短信"],
            },
        ]
        self.events = [
            {"id": "e1", "ts": 100, "type": "login", "ip": "1.1.1.1", "amount": 20},
            {"id": "e1", "ts": 100, "type": "login", "ip": "1.1.1.1", "amount": 20},
            {"id": "e2", "ts": 101, "type": "login", "ip": "1.1.1.1", "amount": 1},
            {"id": "e3", "ts": 102, "type": "payment", "ip": "2.2.2.2", "amount": 1},
        ]

    def test_metrics_trend_and_overlap(self):
        result = evaluate_rules(
            self.rules,
            self.events,
            100,
            102,
            filters={"status": "all"},
            low_hit_threshold=0,
            low_hit_rate=0,
        )
        summary = result["summary"]
        self.assertEqual(summary["total_events"], 3)
        self.assertEqual(summary["matched_events"], 2)
        self.assertEqual(summary["rule_hits"], 4)
        self.assertEqual(summary["overlap_events"], 2)

        hits = {row["rule_id"]: row["hits"] for row in result["rules"]}
        self.assertEqual(hits, {
            "rule_login": 2,
            "rule_amount": 1,
            "rule_freq": 1,
            "rule_never": 0,
        })
        cold = {row["rule_id"]: row["cold_status"] for row in result["rules"]}
        self.assertEqual(cold["rule_never"], "never")
        self.assertEqual(len(result["overlap"]["pairs"]), 2)
        self.assertEqual(sum(result["trend"]["total_events"]), 3)

    def test_filters_and_deduplication(self):
        unique = deduplicate_events(self.events)
        self.assertEqual(len(unique), 3)

        result = evaluate_rules(
            self.rules,
            self.events,
            100,
            102,
            filters={"status": "all", "tags": ["金额"]},
            low_hit_threshold=0,
            low_hit_rate=0,
        )
        self.assertEqual([row["rule_id"] for row in result["rules"]], ["rule_amount"])
        self.assertEqual(result["rules"][0]["hits"], 1)

        result = evaluate_rules(
            self.rules,
            self.events,
            100,
            102,
            filters={"status": "all", "dimensions": ["login"]},
            low_hit_threshold=0,
            low_hit_rate=0,
        )
        self.assertEqual(
            {row["rule_id"] for row in result["rules"]},
            {"rule_login", "rule_freq"},
        )


if __name__ == "__main__":
    unittest.main()
