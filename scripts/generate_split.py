import json, torch, pandas as pd
from collections import Counter

# Load the actual graph dataset for precise per-CVE graph counts
dataset = torch.load("D:/ml_binpool_attempt/graphs/full_dataset.pt", weights_only=False)
cve_graph_counts = Counter(d.cve_id for d in dataset)

df      = pd.read_csv("D:/ml_binpool_attempt/splits/master_index_pairs.csv")
cve_cwe = df.drop_duplicates("cve_id")[["cve_id","cwe_id"]].reset_index(drop=True)

# Sort CVEs by graph count descending (largest first for optimal bin-packing)
sorted_cves = sorted(
    [c for c in cve_graph_counts if c in set(cve_cwe["cve_id"])],
    key=lambda c: -cve_graph_counts[c]
)

# Greedy bin-packing: assign each CVE to the fold with fewest total graphs so far
fold_cves = {i: [] for i in range(5)}
fold_sizes = {i: 0 for i in range(5)}

for cve in sorted_cves:
    best = min(range(5), key=lambda f: fold_sizes[f])
    fold_cves[best].append(cve)
    fold_sizes[best] += cve_graph_counts[cve]

# Report the balanced sizes
total_graphs = sum(fold_sizes.values())
print("=" * 50)
print("SIZE-BALANCED CVE FOLD ASSIGNMENT")
print("=" * 50)
for f in range(5):
    pct = fold_sizes[f] / total_graphs * 100
    cwe_count = cve_cwe[cve_cwe["cve_id"].isin(fold_cves[f])]["cwe_id"].nunique()
    print(f"  Fold {f}: {len(fold_cves[f])} CVEs, {fold_sizes[f]} graphs ({pct:.1f}%), {cwe_count} CWEs")

print(f"\nTotal: {total_graphs} graphs across 5 folds")
print(f"Max imbalance: {max(fold_sizes.values()) - min(fold_sizes.values())} graphs "
      f"({max(fold_sizes.values())/min(fold_sizes.values()):.2f}x)")

# Build fold definitions (each fold becomes test once)
folds = []
for test_fold in range(5):
    train_cves = []
    for f in range(5):
        if f != test_fold:
            train_cves.extend(fold_cves[f])

    # Verify CWE coverage
    test_cwes  = cve_cwe[cve_cwe["cve_id"].isin(fold_cves[test_fold])]["cwe_id"].nunique()
    train_cwes = cve_cwe[cve_cwe["cve_id"].isin(train_cves)]["cwe_id"].nunique()

    print(f"\nFold {test_fold} as TEST: {len(fold_cves[test_fold])} CVEs ({test_cwes} CWEs, "
          f"{fold_sizes[test_fold]} graphs) | TRAIN: {len(train_cves)} CVEs ({train_cwes} CWEs)")

    if test_cwes < 5:
        print(f"  [WARN] Fold {test_fold} test set has only {test_cwes} CWEs.")

    folds.append({
        "fold":  test_fold,
        "train": train_cves,
        "test":  fold_cves[test_fold]
    })

with open("D:/ml_binpool_attempt/splits/cv_folds.json", "w") as f:
    json.dump(folds, f, indent=2)

print("\nSaved cv_folds.json")
