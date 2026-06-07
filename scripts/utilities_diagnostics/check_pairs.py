import os, pandas as pd

OUTPUT_DIR = "D:/ml_binpool_attempt/processed/functions"
df = pd.read_csv("D:/ml_binpool_attempt/splits/master_index_valid.csv")

complete, incomplete = [], 0

# Build the set of expected paired JSONs
all_expected = set()

for _, row in df.iterrows():
    func     = row["function_name"].replace("/","_").replace("\\","_")
    cve      = row["cve_id"]
    basename = os.path.basename(row["vuln_bin_path"]).replace(".","_")

    opt = row["opt_level"]
    vuln_file  = os.path.join(OUTPUT_DIR, f"{cve}_{basename}_{func}_{opt}_1.json")
    patch_file = os.path.join(OUTPUT_DIR, f"{cve}_{basename}_{func}_{opt}_0.json")

    # The file path in all_expected should match exactly what os.listdir provides
    # Replacing backslashes with forward slashes for cross-platform matching
    vuln_file = vuln_file.replace("\\", "/")
    patch_file = patch_file.replace("\\", "/")

    if os.path.exists(vuln_file) and os.path.exists(patch_file):
        complete.append(row)
        all_expected.add(vuln_file)
        all_expected.add(patch_file)
    else:
        incomplete += 1

# Delete unpaired JSONs so downstream scripts never see them
deleted = 0
for fname in os.listdir(OUTPUT_DIR):
    if not fname.endswith(".json"):
        continue
    full_path = os.path.join(OUTPUT_DIR, fname).replace("\\", "/")
    if full_path not in all_expected:
        os.remove(full_path)
        deleted += 1

print(f"Complete pairs:   {len(complete)}")
print(f"Incomplete pairs: {incomplete}")
print(f"Deleted unpaired JSONs: {deleted}")
print(f"Remaining JSONs: {len(all_expected)}")

pd.DataFrame(complete).to_csv(
    "D:/ml_binpool_attempt/splits/master_index_pairs.csv", index=False)
print("Saved master_index_pairs.csv")
