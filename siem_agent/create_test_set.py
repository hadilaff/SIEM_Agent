"""
Create a small mixed test CSV for agent evaluation.

Sources:
  - Unseen attacks from Thursday-15-02-2018 (DoS-GoldenEye, DoS-Slowloris)
  - Known attacks sampled from training files (3 per attack type)
  - Benign flows from multiple files

Output: siem_agent/data/test_set.csv
       siem_agent/data/test_set_summary.json
"""

import json
from pathlib import Path

import pandas as pd

BASE_DIR  = Path(__file__).parent.parent
DATA_DIR  = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)

FLOWS_PER_ATTACK = 3
BENIGN_COUNT      = 30

SOURCES = {
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv": {
        "seen"  : True,
        "types" : ["FTP-BruteForce", "SSH-Bruteforce"],
    },
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv": {
        "seen"  : True,
        "types" : ["Bot"],
    },
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv": {
        "seen"  : True,
        "types" : ["DoS attacks-Hulk", "DoS attacks-SlowHTTPTest"],
    },
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv": {
        "seen"  : True,
        "types" : ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"],
    },
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv": {
        "seen"  : True,
        "types" : ["DDOS attack-HOIC", "DDOS attack-LOIC-UDP"],
    },
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv": {
        "seen"  : True,
        "types" : ["Infilteration"],
    },
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv": {
        "seen"  : False,
        "types" : ["DoS attacks-GoldenEye", "DoS attacks-Slowloris"],
    },
}


def sample_from_file(filepath, attack_types, n_per_type, benign_n):
    """
    Read file in chunks and collect samples for each attack type.
    Returns (attack_samples, benign_samples).
    """
    collected = {t: [] for t in attack_types}
    benign    = []
    benign_needed = benign_n
    done_types = set()

    for chunk in pd.read_csv(filepath, low_memory=False, chunksize=50000):
        chunk = chunk[chunk["Label"] != "Label"]

        # Collect attack samples
        for atk in attack_types:
            if atk in done_types:
                continue
            subset = chunk[chunk["Label"] == atk]
            need = n_per_type - len(collected[atk])
            if need > 0 and len(subset) > 0:
                take = subset.head(need)
                collected[atk].append(take)
                if len(collected[atk]) >= n_per_type:
                    done_types.add(atk)

        # Collect benign
        if benign_needed > 0:
            bn = chunk[chunk["Label"] == "Benign"].head(benign_needed)
            if len(bn) > 0:
                benign.append(bn)
                benign_needed -= len(bn)

        # Early exit if we have everything
        if len(done_types) == len(attack_types) and benign_needed <= 0:
            break

    # Flatten
    attack_samples = []
    for atk, parts in collected.items():
        if parts:
            attack_samples.append(pd.concat(parts, ignore_index=True))

    benign_samples = pd.concat(benign, ignore_index=True) if benign else pd.DataFrame()

    return attack_samples, benign_samples


def main():
    print("=" * 60)
    print("  Creating Test Set for Agent Evaluation")
    print("=" * 60)

    all_samples = []
    summary     = {"seen": {}, "unseen": {}, "benign": 0, "total": 0}

    benign_per_file = max(1, BENIGN_COUNT // len(SOURCES))

    for filename, info in SOURCES.items():
        filepath = BASE_DIR / filename
        if not filepath.exists():
            print(f"  ⚠️  {filename} not found — skipping")
            continue

        print(f"\n  Loading {filename} ...")
        attacks, benign = sample_from_file(
            filepath, info["types"], FLOWS_PER_ATTACK, benign_per_file
        )

        seen_tag = "seen" if info["seen"] else "UNSEEN"
        category = "seen" if info["seen"] else "unseen"

        for atk_df in attacks:
            if len(atk_df) == 0:
                continue
            atk_type = atk_df["Label"].iloc[0]
            atk_df = atk_df.copy()
            atk_df["Source_File"]      = filename
            atk_df["Seen_In_Training"] = info["seen"]
            all_samples.append(atk_df)
            summary[category][atk_type] = len(atk_df)
            print(f"    {atk_type:<30} {len(atk_df)} flows  ({seen_tag})")

        if len(benign) > 0:
            benign = benign.copy()
            benign["Source_File"]      = filename
            benign["Seen_In_Training"] = info["seen"]
            all_samples.append(benign)
            summary["benign"] += len(benign)
            print(f"    {'Benign':<30} {len(benign)} flows")

    # Combine
    test_df = pd.concat(all_samples, ignore_index=True)
    summary["total"] = len(test_df)

    # Save
    output_csv  = DATA_DIR / "test_set.csv"
    output_json = DATA_DIR / "test_set_summary.json"

    test_df.to_csv(output_csv, index=False)
    with open(output_json, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n{'='*60}")
    print(f"  Test set saved: {output_csv}")
    print(f"  Total rows    : {len(test_df)}")
    print(f"  Seen attacks  : {sum(summary['seen'].values())} flows "
          f"({len(summary['seen'])} types)")
    print(f"  Unseen attacks: {sum(summary['unseen'].values())} flows "
          f"({len(summary['unseen'])} types)")
    print(f"  Benign        : {summary['benign']} flows")
    print(f"{'='*60}")

    print(f"\n  Label distribution:")
    for label, count in test_df["Label"].value_counts().items():
        seen = test_df[test_df["Label"] == label]["Seen_In_Training"].iloc[0]
        tag = "✅ seen" if seen else "❌ unseen"
        print(f"    {label:<30} {count:>3} flows  ({tag})")


if __name__ == "__main__":
    main()
