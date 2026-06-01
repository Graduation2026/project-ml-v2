import json
import os
import re
import pandas as pd

DATASET_ROOT = "D:/BinPool_dataset/binpool_dataset"

print("Loading JSON...")
with open("D:/ml_binpool_attempt/binpool_info.json") as f:
    data = json.load(f)

def clean_function_name(raw):
    name = raw.strip()
    if "::" in name:
        name = name.split("::")[-1]
    name = name.replace("*", " ")
    parts = name.split()
    if parts:
        name = parts[-1]
    name = name.split("(")[0].split("/")[0].strip()
    if not name or len(name) < 2:
        return None
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        return None
    return name

def remap_path(json_path):
    return json_path.replace("binpool_artifact/", DATASET_ROOT + "/")

rows = []
skipped_no_binaries = 0
skipped_no_func = 0
skipped_bad_name = 0

print("Parsing dataset...")
for cve_id, info in data.items():
    file_func = info.get("file_func", {})
    binaries = info.get("binaries", [])
    cwes = info.get("cwes", [])
    
    if not file_func:
        skipped_no_func += 1
        continue
    if not binaries:
        skipped_no_binaries += 1
        continue
        
    cwe_id = cwes[0] if cwes else "UNKNOWN"
    
    for src_file, raw_func in file_func.items():
        func = clean_function_name(raw_func)
        if not func:
            skipped_bad_name += 1
            continue
            
        for opt in ["opt0", "opt1", "opt2", "opt3"]:
            opt_binaries = [b for b in binaries if f"/{opt}/" in b]
            
            # Fallback: if opt1/2/3 are missing in JSON, derive from opt0
            if not opt_binaries and opt != "opt0":
                opt_binaries = [b.replace("/opt0/", f"/{opt}/") for b in binaries if "/opt0/" in b]

            for bin_path in opt_binaries:
                vuln_path = remap_path(bin_path)
                patch_path = vuln_path.replace("/vulnerable/", "/patch/")
                
                rows.append({
                    "cve_id": cve_id,
                    "cwe_id": cwe_id,
                    "source_file": src_file,
                    "raw_func": raw_func,
                    "function_name": func,
                    "opt_level": opt, 
                    "vuln_bin_path": vuln_path,
                    "patch_bin_path": patch_path
                })

print("Generating DataFrame...")
os.makedirs("D:/ml_binpool_attempt/splits", exist_ok=True)
df = pd.DataFrame(rows)
df.to_csv("D:/ml_binpool_attempt/splits/master_index.csv", index=False)

print(f"Total rows created: {len(df)}")
print(f"Unique CVEs: {df['cve_id'].nunique()}")
print(f"Skipped (no func): {skipped_no_func}")
print(f"Skipped (no binaries): {skipped_no_binaries}")
print(f"Skipped (bad func name): {skipped_bad_name}")
