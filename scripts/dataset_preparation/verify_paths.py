import pandas as pd
import os

print("Loading master_index.csv...")
df = pd.read_csv("D:/ml_binpool_attempt/splits/master_index.csv")

total_rows = len(df)
print(f"Total rows before filtering: {total_rows}")

missing_vuln = 0
missing_patch = 0
valid_rows = []

for _, row in df.iterrows():
    vuln_ok = os.path.isfile(row["vuln_bin_path"])
    patch_ok = os.path.isfile(row["patch_bin_path"])
    
    if not vuln_ok:
        missing_vuln += 1
    if not patch_ok:
        missing_patch += 1
        
    if vuln_ok and patch_ok:
        valid_rows.append(row)

print(f"\nMissing vulnerable binaries: {missing_vuln}")
print(f"Missing patch binaries: {missing_patch}")

df_valid = pd.DataFrame(valid_rows)
valid_count = len(df_valid)
print(f"\nTotal valid rows (both exist): {valid_count}")
print(f"Usable CVEs remaining: {df_valid['cve_id'].nunique() if valid_count > 0 else 0}")

if valid_count > 0:
    df_valid.to_csv("D:/ml_binpool_attempt/splits/master_index_valid.csv", index=False)
    print("Saved master_index_valid.csv")
