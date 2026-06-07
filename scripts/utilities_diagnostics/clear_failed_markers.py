import os, pandas as pd
from collections import defaultdict

OUTPUT_DIR = "D:/ml_binpool_attempt/processed/functions"
df = pd.read_csv("D:/ml_binpool_attempt/splits/master_index_valid.csv")

# Count expected targets per binary
binary_expected = defaultdict(int)
for _, row in df.iterrows():
    for bin_path in [row["vuln_bin_path"], row["patch_bin_path"]]:
        bin_basename = os.path.basename(bin_path).replace(".", "_")
        proj_name = f"p{abs(hash(bin_path)) % 99999}"
        binary_expected[(proj_name, bin_basename)] += 1

# Count actual JSONs per binary basename
json_files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".json")]
basename_json_count = defaultdict(int)
for jf in json_files:
    # Read the JSON to get the binary basename
    import json
    with open(os.path.join(OUTPUT_DIR, jf)) as f:
        data = json.load(f)
    basename_json_count[data.get("binary", "")] += 1

# Delete .done markers for binaries with partial or zero output
deleted = 0
kept = 0
for (proj_name, bin_basename), expected in binary_expected.items():
    marker = os.path.join(OUTPUT_DIR, f"{proj_name}.done")
    if not os.path.exists(marker):
        continue
    
    actual = basename_json_count.get(bin_basename, 0)
    if actual < expected:
        os.remove(marker)
        deleted += 1
    else:
        kept += 1

print(f"Kept .done markers (fully successful): {kept}")
print(f"Deleted .done markers (partial/zero):   {deleted}")
print(f"These {deleted} binaries will be reprocessed on next run.")
