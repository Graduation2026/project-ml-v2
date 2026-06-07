import subprocess, os, json, pandas as pd, tempfile, hashlib
from collections import defaultdict
from tqdm import tqdm

GHIDRA_HEADLESS = r"D:\ml_binpool_attempt\ghidra_12.0.3_PUBLIC\support\analyzeHeadless.bat"
SCRIPT_PATH     = r"D:\ml_binpool_attempt\scripts"
OUTPUT_DIR      = r"D:\ml_binpool_attempt\processed\functions"
GHIDRA_PROJECT  = r"C:\gh_proj"   # SHORT path

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(GHIDRA_PROJECT, exist_ok=True)

df = pd.read_csv("D:/ml_binpool_attempt/splits/master_index_valid.csv")

binary_to_targets = defaultdict(list)
for _, row in df.iterrows():
    binary_to_targets[row["vuln_bin_path"]].append({"func": row["function_name"], "cve_id": row["cve_id"], "label": 1, "opt": row["opt_level"]})
    binary_to_targets[row["patch_bin_path"]].append({"func": row["function_name"], "cve_id": row["cve_id"], "label": 0, "opt": row["opt_level"]})

print(f"Total unique binaries to process: {len(binary_to_targets)}")

for binary_path, targets in tqdm(binary_to_targets.items(), desc="Processing binaries"):
    if not os.path.isfile(binary_path): continue
    
    bin_basename = os.path.basename(binary_path).replace(".", "_")
    path_hash = hashlib.md5(binary_path.encode()).hexdigest()[:8]
    proj_name = f"p{bin_basename[:24]}_{path_hash}"
    marker = os.path.join(OUTPUT_DIR, f"{bin_basename}_{path_hash}.done")
    
    all_jsons_exist = all(
        os.path.exists(os.path.join(OUTPUT_DIR, f"{t['cve_id']}_{bin_basename}_{t['func']}_{t['opt']}_{t['label']}.json"))
        for t in targets
    )
    if all_jsons_exist:
        if not os.path.exists(marker): open(marker, "w").close()
        continue
        
    if os.path.exists(marker): continue

    # Pass via temp file to avoid Windows string escaping corruption
    tf = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump({"targets": targets, "bin_basename": bin_basename}, tf)
    tf.close()

    cmd = [
        GHIDRA_HEADLESS, GHIDRA_PROJECT, proj_name,
        "-import", binary_path,
        "-noanalysis",
        "-postScript", "ExtractFunctionCFG.java", OUTPUT_DIR, tf.name,
        "-scriptPath", SCRIPT_PATH, "-deleteProject"
    ]
    try:
        subprocess.run(cmd, timeout=600, capture_output=True, text=True)
        open(marker, "w").close()
    except subprocess.TimeoutExpired:
        print(f"Timeout: {binary_path}")
    except Exception as e:
        print(f"Error processing {binary_path}: {e}")
    finally:
        if os.path.exists(tf.name):
            os.unlink(tf.name)
