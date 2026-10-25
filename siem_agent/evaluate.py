"""
SIEM Model Evaluation — Unseen Data
Test file : Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv
Classes   : Benign (known), DoS-GoldenEye (UNSEEN), DoS-Slowloris (UNSEEN)
"""

import json
import pickle
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR  = Path(__file__).parent
MODEL_DIR = BASE_DIR / "models"
TEST_FILE = BASE_DIR.parent / "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"

# ── Label normalization (same as train.py) ────────────────────────────────────
LABEL_MAP = {
    "DoS attacks-GoldenEye": "DoS-GoldenEye",
    "DoS attacks-Slowloris" : "DoS-Slowloris",
}


# ── Load artifacts ────────────────────────────────────────────────────────────
def load_artifacts():
    model = xgb.XGBClassifier()
    model.load_model(str(MODEL_DIR / "xgb_flow_classifier.json"))

    with open(MODEL_DIR / "isolation_forest.pkl", "rb") as f:
        iso = pickle.load(f)

    with open(MODEL_DIR / "label_encoder.pkl", "rb") as f:
        le = pickle.load(f)

    with open(MODEL_DIR / "feature_config.json") as f:
        features = json.load(f)["features"]

    print("✓ Models loaded")
    print(f"  XGBoost knows  : {list(le.classes_)}")
    return model, iso, le, features


# ── Load & preprocess test file ───────────────────────────────────────────────
def load_test(features: list) -> tuple[pd.DataFrame, pd.Series]:
    print(f"\nLoading {TEST_FILE.name} ...")
    df = pd.read_csv(TEST_FILE, low_memory=False)
    df = df[df["Label"] != "Label"]                     # drop header artifacts
    df["Label"] = df["Label"].replace(LABEL_MAP)        # normalize names

    print(f"Shape : {df.shape}")
    print("\nTrue label distribution:")
    for lbl, cnt in df["Label"].value_counts().items():
        known = "✅ known" if lbl == "Benign" else "❌ UNSEEN"
        print(f"  {lbl:<25} {cnt:>8,}   {known}")

    X = df[features].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    for col in features:
        cap = X[col].quantile(0.999)
        if cap > 0:
            X[col] = X[col].clip(upper=cap)

    return X, df["Label"]


# ── Run inference ─────────────────────────────────────────────────────────────
def run_inference(model, iso, le, X, y_true):

    y_pred_enc  = model.predict(X)
    y_pred_prob = model.predict_proba(X)
    y_pred_conf = y_pred_prob.max(axis=1)
    y_pred_lbl  = le.inverse_transform(y_pred_enc)

    # Isolation Forest: -1 = anomaly, 1 = normal
    print("\nRunning Isolation Forest  ...")
    iso_scores = iso.decision_function(X)   # lower = more anomalous
    iso_preds  = iso.predict(X)             # -1 = anomaly

    return y_pred_lbl, y_pred_conf, iso_preds, iso_scores


# ── Report ────────────────────────────────────────────────────────────────────
def report(y_true, y_pred_lbl, y_pred_conf, iso_preds, iso_scores, le):

    print("\n" + "="*65)
    print("1. XGBoost PREDICTION DISTRIBUTION (what model THINKS it sees)")
    print("="*65)
    pred_counts = pd.Series(y_pred_lbl).value_counts()
    for lbl, cnt in pred_counts.items():
        print(f"  {lbl:<25} {cnt:>8,}  ({cnt/len(y_pred_lbl)*100:.1f}%)")

    # ── Per true class analysis ───────────────────────────────────────────────
    print("\n" + "="*65)
    print("2. XGBoost — HOW EACH TRUE CLASS WAS PREDICTED")
    print("="*65)
    for true_cls in y_true.unique():
        mask   = y_true == true_cls
        preds  = pd.Series(y_pred_lbl[mask.values]).value_counts()
        confs  = y_pred_conf[mask.values]
        print(f"\n  True: {true_cls}  ({mask.sum():,} flows)")
        for pred_lbl, cnt in preds.items():
            flag = "✅" if (true_cls == "Benign" and pred_lbl == "Benign") else \
                   "⚠️ " if pred_lbl != "Benign" else "❌ missed"
            print(f"    → Predicted {pred_lbl:<25} {cnt:>7,}  ({cnt/mask.sum()*100:.1f}%)  {flag}")
        print(f"    Confidence: mean={confs.mean():.3f}  min={confs.min():.3f}  max={confs.max():.3f}")

    # ── Confidence threshold analysis ────────────────────────────────────────
    print("\n" + "="*65)
    print("3. CONFIDENCE THRESHOLD ANALYSIS")
    print("="*65)
    for cls in ["DoS-GoldenEye", "DoS-Slowloris"]:
        mask  = y_true == cls
        confs = y_pred_conf[mask.values]
        print(f"\n  {cls} ({mask.sum():,} flows):")
        for thresh in [0.99, 0.95, 0.85, 0.70, 0.50]:
            high = (confs >= thresh).sum()
            print(f"    confidence ≥ {thresh:.2f}  →  {high:>6,}  ({high/len(confs)*100:.1f}%)  flagged as high-confidence")

    # ── Isolation Forest results ──────────────────────────────────────────────
    print("\n" + "="*65)
    print("4. ISOLATION FOREST — ANOMALY DETECTION ON UNSEEN ATTACKS")
    print("="*65)
    for cls in y_true.unique():
        mask      = y_true == cls
        iso_cls   = iso_preds[mask.values]
        scores    = iso_scores[mask.values]
        anomalies = (iso_cls == -1).sum()
        total     = mask.sum()
        pct       = anomalies / total * 100
        status    = "✅ correctly flagged" if cls != "Benign" and pct > 30 else \
                    "✅ correctly clean"   if cls == "Benign" and pct < 5  else \
                    "⚠️  partial detection" if cls != "Benign" and pct > 5  else \
                    "❌ missed"
        print(f"  {cls:<25}  anomaly={anomalies:>7,}/{total:>7,} ({pct:5.1f}%)  score_mean={scores.mean():.4f}  {status}")

    # ── Combined decision simulation ──────────────────────────────────────────
    print("\n" + "="*65)
    print("5. COMBINED DECISION (XGBoost + Isolation Forest + Threshold)")
    print("="*65)
    print("   Rules:")
    print("   • XGBoost predicts known attack  → KNOWN_ATTACK alert")
    print("   • XGBoost predicts Benign + ISO anomaly  → UNKNOWN_THREAT alert")
    print("   • XGBoost predicts Benign + ISO normal   → Benign (ignored)")
    print("   • XGBoost confidence < 0.85  → SUSPICIOUS alert")

    decisions = []
    for i in range(len(y_pred_lbl)):
        pred  = y_pred_lbl[i]
        conf  = y_pred_conf[i]
        iso_p = iso_preds[i]

        if conf < 0.85:
            decision = "SUSPICIOUS"
        elif pred != "Benign":
            decision = f"KNOWN_ATTACK:{pred}"
        elif iso_p == -1:
            decision = "UNKNOWN_THREAT"
        else:
            decision = "Benign"
        decisions.append(decision)

    decisions = pd.Series(decisions)

    print("\n  Decision distribution:")
    for cls in y_true.unique():
        mask = y_true == cls
        d    = decisions[mask.values].value_counts()
        print(f"\n  True class: {cls}  ({mask.sum():,} flows)")
        for dec, cnt in d.items():
            pct = cnt / mask.sum() * 100
            print(f"    {dec:<40} {cnt:>7,}  ({pct:.1f}%)")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "="*65)
    print("SUMMARY")
    print("="*65)
    benign_mask  = y_true == "Benign"
    attack_mask  = y_true != "Benign"

    # True negative rate (Benign correctly ignored)
    benign_correct = ((decisions[benign_mask.values] == "Benign")).sum()
    tnr = benign_correct / benign_mask.sum() * 100

    # Detection rate (unseen attacks flagged by ANY mechanism)
    attack_detected = (decisions[attack_mask.values] != "Benign").sum()
    dr = attack_detected / attack_mask.sum() * 100

    print(f"  Benign correctly ignored      : {benign_correct:,}/{benign_mask.sum():,}  ({tnr:.2f}%)")
    print(f"  Unseen attacks detected       : {attack_detected:,}/{attack_mask.sum():,}  ({dr:.2f}%)")
    print(f"  False positives (Benign→alert): {(benign_mask.sum()-benign_correct):,}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 65)
    print("  SIEM MODEL EVALUATION — UNSEEN DATA")
    print("  Thursday 15/02/2018 | DoS-GoldenEye + DoS-Slowloris")
    print("=" * 65 + "\n")

    model, iso, le, features = load_artifacts()
    X, y_true = load_test(features)

    print("\nRunning XGBoost inference ...")
    y_pred_lbl, y_pred_conf, iso_preds, iso_scores = run_inference(
        model, iso, le, X, y_true
    )

    report(y_true, y_pred_lbl, y_pred_conf, iso_preds, iso_scores, le)


if __name__ == "__main__":
    main()
