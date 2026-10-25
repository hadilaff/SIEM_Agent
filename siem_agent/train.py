"""
SIEM Alert Triage — XGBoost Multiclass + Isolation Forest
Dataset : CSE-CIC-IDS2018 (6 CSV files)
Classes : 12 attack types + Benign
"""

import json
import pickle
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR  = Path(__file__).parent
DATA_DIR  = BASE_DIR.parent
MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

CSV_FILES = sorted(DATA_DIR.glob("*TrafficForML_CICFlowMeter.csv"))

# ── Features ──────────────────────────────────────────────────────────────────
SELECTED_FEATURES = [
    "Dst Port",
    "Fwd Seg Size Min",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
    "Flow Pkts/s",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Flow IAT Max",
    "Flow IAT Min",
    "Flow IAT Mean",
    "Fwd Pkt Len Mean",
    "Fwd Act Data Pkts",
    "Fwd Header Len",
    "PSH Flag Cnt",
    "Subflow Bwd Pkts",
]

TARGET_COL = "Label"

# ── Label normalization ───────────────────────────────────────────────────────
LABEL_MAP = {
    "Infilteration"           : "Infiltration",
    "SSH-Bruteforce"          : "SSH-BruteForce",
    "DDOS attack-HOIC"        : "DDoS-HOIC",
    "DDOS attack-LOIC-UDP"    : "DDoS-LOIC-UDP",
    "DoS attacks-Hulk"        : "DoS-Hulk",
    "DoS attacks-SlowHTTPTest": "DoS-SlowHTTPTest",
    "Brute Force -Web"        : "BruteForce-Web",
    "Brute Force -XSS"        : "BruteForce-XSS",
    "SQL Injection"           : "SQL-Injection",
}

DROP_LABELS = {"Label", "label", "nan", ""}

# Benign cap per file — prevents Benign from dominating
BENIGN_CAP = 300_000

# Minority class oversampling threshold
# Classes below this count get duplicated up to MIN_CLASS_TARGET
MIN_CLASS_THRESHOLD = 5_000
MIN_CLASS_TARGET    = 5_000


# ── 1. Load ───────────────────────────────────────────────────────────────────
def load_all(files: list[Path]) -> pd.DataFrame:
    print(f"[1/5] Loading {len(files)} CSV file(s) ...")
    dfs = []
    for fp in files:
        t0 = time.time()
        df = pd.read_csv(
            fp, low_memory=False,
            usecols=SELECTED_FEATURES + [TARGET_COL]
        )
        # Normalize labels
        df[TARGET_COL] = (
            df[TARGET_COL].astype(str).str.strip()
            .replace(LABEL_MAP)
        )
        # Drop junk rows (header artifacts, empty)
        df = df[~df[TARGET_COL].isin(DROP_LABELS)]

        # Cap Benign per file
        benign_mask = df[TARGET_COL] == "Benign"
        if benign_mask.sum() > BENIGN_CAP:
            df = pd.concat([
                df[~benign_mask],
                df[benign_mask].sample(BENIGN_CAP, random_state=42)
            ], ignore_index=True)

        print(f"   {fp.name:<58} {len(df):>7,} rows  ({time.time()-t0:.1f}s)")
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    print(f"\n   Combined total: {len(combined):,} rows")
    return combined


# ── 2. Preprocess ─────────────────────────────────────────────────────────────
def preprocess(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    print("\n[2/5] Preprocessing ...")

    X = df[SELECTED_FEATURES].apply(pd.to_numeric, errors="coerce")
    y = df[TARGET_COL].copy()

    # Clean Inf / NaN
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    # Clip outliers to 99.9th percentile
    for col in SELECTED_FEATURES:
        cap = X[col].quantile(0.999)
        if cap > 0:
            X[col] = X[col].clip(upper=cap)

    # Oversample minority classes to MIN_CLASS_TARGET
    counts = y.value_counts()
    minority = counts[counts < MIN_CLASS_THRESHOLD].index.tolist()
    if minority:
        extras_X, extras_y = [], []
        for cls in minority:
            mask = y == cls
            n    = mask.sum()
            need = MIN_CLASS_TARGET - n
            idx  = np.random.choice(np.where(mask)[0], size=need, replace=True)
            extras_X.append(X.iloc[idx])
            extras_y.append(pd.Series([cls] * need))
        X = pd.concat([X] + extras_X, ignore_index=True)
        y = pd.concat([y] + extras_y, ignore_index=True)
        print(f"   Oversampled minority classes: {minority}")

    print("\n   Final class distribution:")
    max_count = y.value_counts().max()
    for label, count in y.value_counts().items():
        bar = "█" * int(count / max_count * 28)
        print(f"     {label:<25} {count:>7,}  {bar}")

    return X, y


# ── 3. Train XGBoost ──────────────────────────────────────────────────────────
def train_xgb(
    X: pd.DataFrame,
    y_enc: np.ndarray,
    n_classes: int
) -> tuple[xgb.XGBClassifier, dict]:
    print(f"\n[3/5] Training XGBoost ({n_classes} classes) ...")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc,
        test_size=0.20,
        random_state=42,
        stratify=y_enc,
    )
    print(f"   Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # Sample weights to handle remaining imbalance
    sample_weights = compute_sample_weight("balanced", y_train)

    model = xgb.XGBClassifier(
        objective="multi:softprob",
        num_class=n_classes,
        n_estimators=500,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
        tree_method="hist",
        early_stopping_rounds=30,
    )

    t0 = time.time()
    model.fit(
        X_train, y_train,
        sample_weight=sample_weights,
        eval_set=[(X_test, y_test)],
        verbose=50,
    )
    elapsed = time.time() - t0
    print(f"\n   Done in {elapsed:.1f}s  |  Best iteration: {model.best_iteration}")

    return model, {
        "X_test"      : X_test,
        "y_test"      : y_test,
        "y_pred"      : model.predict(X_test),
        "y_pred_prob" : model.predict_proba(X_test),
        "elapsed"     : elapsed,
    }


# ── 4. Train Isolation Forest (anomaly/unknown detector) ─────────────────────
def train_iso(X: pd.DataFrame, y: pd.Series) -> IsolationForest:
    print("\n[4/5] Training Isolation Forest on Benign traffic ...")
    X_benign = X[y == "Benign"]
    print(f"   Benign samples used: {len(X_benign):,}")

    # Sample Benign for speed — ISO forest doesn't need all 1.8M rows
    if len(X_benign) > 200_000:
        X_benign = X_benign.sample(200_000, random_state=42)
        print(f"   Sampled down to 200,000 rows for speed")

    iso = IsolationForest(
        n_estimators=100,
        contamination=0.005,   # expect ~0.5% outliers within Benign
        random_state=42,
        n_jobs=-1,
    )
    t0 = time.time()
    iso.fit(X_benign)
    print(f"   Done in {time.time()-t0:.1f}s")
    return iso


# ── 5. Evaluate ───────────────────────────────────────────────────────────────
def evaluate(results: dict, le: LabelEncoder, iso: IsolationForest) -> dict:
    y_test      = results["y_test"]
    y_pred      = results["y_pred"]
    y_pred_prob = results["y_pred_prob"]

    print("\n" + "="*65)
    print("EVALUATION REPORT — XGBoost")
    print("="*65)
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion matrix:")
    print(pd.DataFrame(cm, index=le.classes_, columns=le.classes_).to_string())

    auc = roc_auc_score(y_test, y_pred_prob, multi_class="ovr", average="macro")
    print(f"\nROC-AUC (macro OvR): {auc:.6f}")

    # Isolation Forest: test on Benign test subset
    benign_idx  = y_test == le.transform(["Benign"])[0]
    X_test_ben  = results["X_test"][benign_idx]
    iso_preds   = iso.predict(X_test_ben)
    false_alarm = (iso_preds == -1).mean() * 100
    print(f"\nIsolation Forest false alarm rate on Benign: {false_alarm:.2f}%")

    p, r, f, s = precision_recall_fscore_support(y_test, y_pred)
    metrics = {
        "accuracy"       : float((y_pred == y_test).mean()),
        "roc_auc_macro"  : float(auc),
        "n_test_samples" : int(len(y_test)),
        "classes"        : le.classes_.tolist(),
        "elapsed_seconds": round(results["elapsed"], 2),
        "iso_false_alarm_pct": round(float(false_alarm), 3),
        "n_features"     : len(SELECTED_FEATURES),
    }
    for i, cls in enumerate(le.classes_):
        metrics[cls] = {
            "precision": round(float(p[i]), 4),
            "recall"   : round(float(r[i]), 4),
            "f1"       : round(float(f[i]), 4),
            "support"  : int(s[i]),
        }
    return metrics


# ── 6. Save ───────────────────────────────────────────────────────────────────
def save_artifacts(
    model  : xgb.XGBClassifier,
    iso    : IsolationForest,
    le     : LabelEncoder,
    metrics: dict,
):
    print("\n[5/5] Saving artifacts ...")

    mp = MODEL_DIR / "xgb_flow_classifier.json"
    model.save_model(str(mp))
    print(f"   XGBoost model    → {mp}  ({mp.stat().st_size//1024} KB)")

    ip = MODEL_DIR / "isolation_forest.pkl"
    with open(ip, "wb") as f:
        pickle.dump(iso, f)
    print(f"   Isolation Forest → {ip}")

    lp = MODEL_DIR / "label_encoder.pkl"
    with open(lp, "wb") as f:
        pickle.dump(le, f)
    print(f"   LabelEncoder     → {lp}")

    fp = MODEL_DIR / "feature_config.json"
    with open(fp, "w") as f:
        json.dump({"features": SELECTED_FEATURES, "target": TARGET_COL}, f, indent=2)
    print(f"   Feature config   → {fp}")

    tp = MODEL_DIR / "training_metrics.json"
    with open(tp, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"   Metrics          → {tp}")

    print(f"\n✓ All artifacts saved to {MODEL_DIR}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 65)
    print("  SIEM CLASSIFIER — XGBoost + Isolation Forest")
    print("  CSE-CIC-IDS2018 | 12 attack classes")
    print("=" * 65 + "\n")

    if not CSV_FILES:
        raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")

    print(f"Found {len(CSV_FILES)} CSV file(s):")
    for f in CSV_FILES:
        print(f"  • {f.name}")
    print()

    df          = load_all(CSV_FILES)
    X, y        = preprocess(df)

    le          = LabelEncoder()
    y_enc       = le.fit_transform(y)
    n_classes   = len(le.classes_)
    print(f"\n   {n_classes} classes: {list(le.classes_)}")

    model, results = train_xgb(X, y_enc, n_classes)
    results["best_iter"] = model.best_iteration

    iso = train_iso(X, y)

    metrics = evaluate(results, le, iso)
    metrics["best_iteration"] = model.best_iteration

    save_artifacts(model, iso, le, metrics)

    print("\n" + "=" * 65)
    print(f"  Accuracy        : {metrics['accuracy']*100:.4f}%")
    print(f"  ROC-AUC (macro) : {metrics['roc_auc_macro']:.6f}")
    print(f"  Classes trained : {n_classes}")
    print("=" * 65)


if __name__ == "__main__":
    main()
