"""
Agent Evaluation Harness
────────────────────────
Runs the full agent pipeline on the test set and produces evaluation metrics:

  Phase 1 (fast, all flows):    Detection rate, false positive rate, per-type accuracy
  Phase 2 (slow, subset):       LLM triage accuracy, verdict quality

Usage:
    python evaluate_agent.py                    # full evaluation
    python evaluate_agent.py --detection-only    # skip LLM triage (fast)
    python evaluate_agent.py --triage-per-type 2 # 2 flows per type for triage
"""

import argparse
import json
import time
import warnings
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

BASE_DIR  = Path(__file__).parent
DATA_DIR  = BASE_DIR / "data"
TEST_FILE = DATA_DIR / "test_set.csv"

# ── Label normalization (same as train.py) ─────────────────────────────────────
LABEL_MAP = {
    "Infilteration"           : "Infiltration",
    "SSH-Bruteforce"          : "SSH-BruteForce",
    "DDOS attack-HOIC"        : "DDoS-HOIC",
    "DDOS attack-LOIC-UDP"    : "DDoS-LOIC-UDP",
    "DoS attacks-Hulk"        : "DoS-Hulk",
    "DoS attacks-SlowHTTPTest": "DoS-SlowHTTPTest",
    "DoS attacks-GoldenEye"   : "DoS-GoldenEye",
    "DoS attacks-Slowloris"   : "DoS-Slowloris",
    "Brute Force -Web"        : "BruteForce-Web",
    "Brute Force -XSS"        : "BruteForce-XSS",
    "SQL Injection"           : "SQL-Injection",
}


def normalize_label(label: str) -> str:
    return LABEL_MAP.get(label, label)


# ── Phase 1: Detection evaluation ─────────────────────────────────────────────
def run_detection_eval(alert_layer, test_df):
    """
    Run AlertLayer on every flow in the test set.
    Returns a DataFrame with detection results.
    """
    print("\n[Phase 1] Detection evaluation on all flows ...")
    results = []

    for idx, row in test_df.iterrows():
        flow       = row.to_dict()
        true_label = normalize_label(flow.get("Label", "Unknown"))
        seen       = flow.get("Seen_In_Training", True)
        timestamp  = flow.get("Timestamp", "")

        # Remove metadata columns before passing to AlertLayer
        for meta_col in ["Label", "Source_File", "Seen_In_Training"]:
            flow.pop(meta_col, None)

        alert = alert_layer.process_flow(flow)

        if alert is None:
            # No alert fired — Benign or missed attack
            results.append({
                "true_label"    : true_label,
                "seen_in_train" : seen,
                "alert_fired"   : False,
                "predicted_type" : "Benign",
                "confidence"    : 0.0,
                "decision"      : "Benign",
                "severity"      : "NONE",
            })
        else:
            results.append({
                "true_label"    : true_label,
                "seen_in_train" : seen,
                "alert_fired"   : True,
                "predicted_type": alert.attack_type,
                "confidence"    : alert.confidence,
                "decision"      : alert.decision,
                "severity"      : alert.severity,
            })

    results_df = pd.DataFrame(results)
    return results_df


def analyze_detection(results_df):
    """Compute detection metrics from Phase 1 results."""
    print("\n" + "=" * 65)
    print("  PHASE 1: DETECTION EVALUATION")
    print("=" * 65)

    total       = len(results_df)
    attack_rows = results_df[results_df["true_label"] != "Benign"]
    benign_rows = results_df[results_df["true_label"] == "Benign"]

    n_attacks = len(attack_rows)
    n_benign  = len(benign_rows)

    # Detection rate (attacks correctly fired alerts)
    attacks_detected = attack_rows["alert_fired"].sum()
    detection_rate    = attacks_detected / n_attacks if n_attacks > 0 else 0

    # False positive rate (Benign flows that fired alerts)
    benign_alerted = benign_rows["alert_fired"].sum()
    fp_rate        = benign_alerted / n_benign if n_benign > 0 else 0

    print(f"\n  Total flows       : {total}")
    print(f"  Attack flows      : {n_attacks}")
    print(f"  Benign flows      : {n_benign}")
    print(f"\n  Detection rate    : {detection_rate:.1%}  ({attacks_detected}/{n_attacks} attacks detected)")
    print(f"  False positive rate: {fp_rate:.1%}  ({benign_alerted}/{n_benign} Benign → alert)")

    # Per-attack-type breakdown
    print(f"\n  Per-attack-type detection:")
    print(f"  {'Attack Type':<30} {'Seen':>6} {'Total':>6} {'Detected':>9} {'Rate':>7} {'Avg Conf':>9}")
    print(f"  {'-'*30} {'-'*6} {'-'*6} {'-'*9} {'-'*7} {'-'*9}")

    per_type = {}
    for atk_type, group in attack_rows.groupby("true_label"):
        seen_tag = "✅" if group["seen_in_train"].iloc[0] else "❌"
        n        = len(group)
        detected = group["alert_fired"].sum()
        rate     = detected / n if n > 0 else 0
        avg_conf = group[group["alert_fired"]]["confidence"].mean() if detected > 0 else 0
        per_type[atk_type] = {
            "seen"      : bool(group["seen_in_train"].iloc[0]),
            "total"     : n,
            "detected"  : int(detected),
            "rate"      : round(rate, 3),
            "avg_conf"  : round(float(avg_conf), 3),
        }
        print(f"  {atk_type:<30} {seen_tag:>6} {n:>6} {detected:>9} {rate:>6.0%} {avg_conf:>9.1%}")

    # Misclassifications (detected but wrong attack type)
    print(f"\n  Misclassifications (detected but wrong type):")
    misclassified = attack_rows[
        (attack_rows["alert_fired"]) &
        (attack_rows["true_label"] != attack_rows["predicted_type"])
    ]
    if len(misclassified) > 0:
        for _, row in misclassified.iterrows():
            print(f"    True: {row['true_label']:<25} → Predicted: {row['predicted_type']:<25} "
                  f"conf={row['confidence']:.1%} decision={row['decision']}")
    else:
        print(f"    None ✅")

    return {
        "total_flows"      : total,
        "attack_flows"     : n_attacks,
        "benign_flows"     : n_benign,
        "detection_rate"   : round(detection_rate, 4),
        "false_positive_rate": round(fp_rate, 4),
        "attacks_detected" : int(attacks_detected),
        "benign_alerted"   : int(benign_alerted),
        "per_type"         : per_type,
        "misclassified"    : len(misclassified),
    }


# ── Phase 2: LLM triage evaluation ────────────────────────────────────────────
def run_triage_eval(alert_layer, agent, test_df, per_type_n=1):
    """
    Run full investigation + LLM triage on a subset of flows.
    Picks per_type_n flows per attack type.
    """
    print(f"\n[Phase 2] LLM triage evaluation ({per_type_n} per type) ...")

    results = []
    # Group by normalized label, pick N per group
    test_df = test_df.copy()
    test_df["norm_label"] = test_df["Label"].apply(normalize_label)

    for atk_type, group in test_df.groupby("norm_label"):
        if atk_type == "Benign":
            # Pick a couple Benign to check LLM says false_positive if alert fires
            sample = group.head(1)
        else:
            sample = group.head(per_type_n)

        for _, row in sample.iterrows():
            flow       = row.to_dict()
            true_label = flow.pop("norm_label")
            seen       = flow.pop("Seen_In_Training", True)
            flow.pop("Label", None)
            flow.pop("Source_File", None)

            print(f"\n  Investigating: {true_label} (seen={seen}) ...", end=" ", flush=True)
            t0 = time.time()

            alert = alert_layer.process_flow(flow)

            if alert is None:
                print(f"no alert fired ({time.time()-t0:.1f}s)")
                results.append({
                    "true_label"     : true_label,
                    "seen_in_train"  : seen,
                    "alert_fired"    : False,
                    "triage_verdict" : "N/A",
                    "triage_conf"    : 0.0,
                    "triage_backend" : "N/A",
                    "narrative"      : "",
                    "expected_verdict": "false_positive" if true_label == "Benign" else "true_positive",
                    "correct"        : True if true_label == "Benign" else False,
                    "invest_time"    : round(time.time() - t0, 1),
                })
                continue

            # Run full investigation
            try:
                report = agent.investigate(alert)
                triage = report.triage

                if true_label == "Benign":
                    expected = "false_positive"
                    correct = triage.verdict in ("false_positive", "benign")
                else:
                    expected = "true_positive"
                    # For unseen attacks, escalate is also acceptable
                    if not seen:
                        correct = triage.verdict in ("true_positive", "escalate")
                    else:
                        correct = triage.verdict == "true_positive"

                results.append({
                    "true_label"      : true_label,
                    "seen_in_train"   : seen,
                    "alert_fired"     : True,
                    "predicted_type"  : alert.attack_type,
                    "model_conf"      : alert.confidence,
                    "triage_verdict"  : triage.verdict,
                    "triage_conf"     : triage.confidence,
                    "triage_backend"  : triage.backend,
                    "triage_model"    : triage.model_name,
                    "narrative"       : triage.narrative[:200],
                    "expected_verdict": expected,
                    "correct"         : correct,
                    "invest_time"     : round(time.time() - t0, 1),
                })
                print(f"verdict={triage.verdict} conf={triage.confidence:.2f} "
                      f"backend={triage.backend} ({time.time()-t0:.1f}s) "
                      f"{'✅' if correct else '❌'}")

            except Exception as e:
                print(f"ERROR: {e}")
                results.append({
                    "true_label"     : true_label,
                    "seen_in_train"  : seen,
                    "alert_fired"    : True,
                    "triage_verdict" : "error",
                    "triage_conf"    : 0.0,
                    "expected_verdict": "true_positive",
                    "correct"        : False,
                    "invest_time"    : round(time.time() - t0, 1),
                    "error"          : str(e),
                })

    return pd.DataFrame(results)


def analyze_triage(triage_df):
    """Compute triage metrics from Phase 2 results."""
    print("\n" + "=" * 65)
    print("  PHASE 2: LLM TRIAGE EVALUATION")
    print("=" * 65)

    total   = len(triage_df)
    if total == 0:
        print("  No triage results.")
        return {}

    attacks = triage_df[triage_df["true_label"] != "Benign"]
    benign  = triage_df[triage_df["true_label"] == "Benign"]

    # Triage accuracy for attacks
    if len(attacks) > 0:
        triage_correct = attacks["correct"].sum()
        triage_acc     = triage_correct / len(attacks)
        print(f"\n  Attack triage accuracy : {triage_acc:.1%}  ({triage_correct}/{len(attacks)})")

        # Seen vs unseen
        for seen_tag, mask in [("seen", attacks["seen_in_train"] == True),
                               ("unseen", attacks["seen_in_train"] == False)]:
            subset = attacks[mask]
            if len(subset) > 0:
                acc = subset["correct"].sum() / len(subset)
                print(f"    {seen_tag:<8} attacks: {acc:.1%}  ({subset['correct'].sum()}/{len(subset)})")

    # Verdict distribution
    print(f"\n  Verdict distribution:")
    for verdict, count in triage_df["triage_verdict"].value_counts().items():
        print(f"    {verdict:<20} {count}")

    # Per-attack-type triage
    print(f"\n  Per-attack-type triage:")
    print(f"  {'Attack Type':<30} {'Seen':>6} {'Verdict':<20} {'Conf':>6} {'Correct':>8} {'Time':>6}")
    print(f"  {'-'*30} {'-'*6} {'-'*20} {'-'*6} {'-'*8} {'-'*6}")
    for _, row in triage_df.iterrows():
        seen_tag = "✅" if row["seen_in_train"] else "❌"
        correct  = "✅" if row["correct"] else "❌"
        print(f"  {row['true_label']:<30} {seen_tag:>6} {row['triage_verdict']:<20} "
              f"{row['triage_conf']:>5.0%} {correct:>8} {row['invest_time']:>5.1f}s")

    # Average investigation time
    avg_time = triage_df["invest_time"].mean()
    print(f"\n  Avg investigation time: {avg_time:.1f}s")

    return {
        "total_triaged"    : total,
        "attack_triage_acc": round(float(triage_acc), 4) if len(attacks) > 0 else 0,
        "verdict_dist"     : triage_df["triage_verdict"].value_counts().to_dict(),
        "avg_invest_time"  : round(float(avg_time), 1),
        "per_row"          : triage_df.to_dict(orient="records"),
    }


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Agent Evaluation")
    parser.add_argument("--detection-only", action="store_true",
                        help="Skip LLM triage (fast)")
    parser.add_argument("--triage-per-type", type=int, default=1,
                        help="Flows per attack type for triage (default: 1)")
    args = parser.parse_args()

    print("=" * 65)
    print("  AGENT EVALUATION")
    print("=" * 65)

    if not TEST_FILE.exists():
        print(f"\n  ❌ Test set not found: {TEST_FILE}")
        print(f"  Run: python create_test_set.py first")
        return

    # Load test set
    print(f"\n  Loading test set: {TEST_FILE.name}")
    test_df = pd.read_csv(TEST_FILE, low_memory=False)
    test_df = test_df[test_df["Label"] != "Label"].reset_index(drop=True)
    print(f"  Rows: {len(test_df)}")

    # Load AlertLayer
    import sys
    sys.path.insert(0, str(BASE_DIR))
    from alert_layer import AlertLayer

    print("  Loading models ...")
    alert_layer = AlertLayer()

    # Phase 1: Detection
    detection_results = run_detection_eval(alert_layer, test_df)
    detection_metrics = analyze_detection(detection_results)

    # Phase 2: LLM Triage
    triage_metrics = {}
    if not args.detection_only:
        from investigation_agent import InvestigationAgent
        print("\n  Starting investigation agent ...")
        agent = InvestigationAgent(verbose=False)

        triage_df = run_triage_eval(alert_layer, agent, test_df, args.triage_per_type)
        triage_metrics = analyze_triage(triage_df)

    # Save results
    report = {
        "evaluated_at"     : datetime.now().isoformat(),
        "test_set_size"    : len(test_df),
        "detection"        : detection_metrics,
        "triage"           : triage_metrics,
    }

    output = BASE_DIR / "data" / "agent_evaluation.json"
    with open(output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  Results saved: {output}")

    # Final summary
    print(f"\n{'='*65}")
    print(f"  FINAL SUMMARY")
    print(f"{'='*65}")
    print(f"  Detection rate      : {detection_metrics['detection_rate']:.1%}")
    print(f"  False positive rate  : {detection_metrics['false_positive_rate']:.1%}")
    if triage_metrics:
        print(f"  Triage accuracy      : {triage_metrics.get('attack_triage_acc',0):.1%}")
        print(f"  Avg investigation time: {triage_metrics.get('avg_invest_time',0):.1f}s")
    print(f"{'='*65}")


if __name__ == "__main__":
    main()
