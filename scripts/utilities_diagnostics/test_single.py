import os, json, tempfile, subprocess

GHIDRA_HEADLESS = r"D:\ml_binpool_attempt\ghidra_12.0.3_PUBLIC\support\analyzeHeadless.bat"
SCRIPT_PATH     = r"D:\ml_binpool_attempt\scripts"
OUTPUT_DIR      = r"D:\ml_binpool_attempt\processed\functions"
GHIDRA_PROJECT  = r"C:\gh_proj"

binary_path = "D:/BinPool_dataset/binpool_dataset/CVE-2018-20761/vulnerable/opt0/debfiles/output_directory/bins/libgpac4_0.5.2-426-gc5ad4e4+dfsg5-4.1_amd64/usr/lib/x86_64-linux-gnu/libgpac.so.4"
bin_basename = os.path.basename(binary_path).replace(".", "_")
print(f"bin_basename: {bin_basename}")
proj_name = f"p{bin_basename[:28]}"
print(f"proj_name: {proj_name}")

targets = [{"func": "ps_mix_phase", "cve_id": "CVE-2018-20761", "label": 1, "opt": "opt0"}]

tf = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
json.dump({"targets": targets, "bin_basename": bin_basename}, tf)
tf.close()
print(f"temp file: {tf.name}")

cmd = [
    GHIDRA_HEADLESS, GHIDRA_PROJECT, proj_name,
    "-import", binary_path,
    "-noanalysis",
    "-postScript", "ExtractFunctionCFG.java", OUTPUT_DIR, tf.name,
    "-scriptPath", SCRIPT_PATH, "-deleteProject"
]
print("Running: " + " ".join(cmd))
try:
    result = subprocess.run(cmd, timeout=300, capture_output=True, text=True)
    print(f"Return code: {result.returncode}")
    out = result.stdout[-1000:] if result.stdout else ""
    err = result.stderr[-1000:] if result.stderr else ""
    print(f"Stdout tail: {out}")
    print(f"Stderr tail: {err}")
except subprocess.TimeoutExpired:
    print("Timeout!")
except Exception as e:
    print(f"Error: {e}")
finally:
    if os.path.exists(tf.name):
        os.unlink(tf.name)
