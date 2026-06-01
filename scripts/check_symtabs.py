import os, json, pandas as pd
from elftools.elf.elffile import ELFFile

OUTPUT_DIR = "D:/ml_binpool_attempt/processed/functions"
df = pd.read_csv("D:/ml_binpool_attempt/splits/master_index_valid.csv")

# Find binaries that produced .done markers but NO matching JSON
json_files = set(f for f in os.listdir(OUTPUT_DIR) if f.endswith(".json"))

# Build set of binaries that DID produce at least one JSON
successful_binaries = set()
for jf in json_files:
    # Parse the binary basename from the filename pattern: CVE_binbasename_func_label.json
    parts = jf.split("_")
    # The binary basename is everything between the CVE ID and the last two parts (func, label)
    # This is tricky, so let's just check from the JSON content
    with open(os.path.join(OUTPUT_DIR, jf)) as f:
        data = json.load(f)
    successful_binaries.add(data.get("binary", ""))

# Find unique binaries from the CSV
from collections import defaultdict
binary_to_targets = defaultdict(list)
for _, row in df.iterrows():
    binary_to_targets[row["vuln_bin_path"]].append(row["function_name"])
    binary_to_targets[row["patch_bin_path"]].append(row["function_name"])

# Sample 20 binaries that exist on disk
import random
random.seed(42)
all_binaries = [b for b in binary_to_targets.keys() if os.path.isfile(b)]
sample = random.sample(all_binaries, min(20, len(all_binaries)))

print(f"{'symtab':>8} {'dynsym':>8} {'binary'}")
print("-" * 80)

symtab_count = 0
dynsym_count = 0
neither_count = 0

for binary in sample:
    try:
        with open(binary, "rb") as f:
            elf = ELFFile(f)
            has_symtab = elf.get_section_by_name(".symtab") is not None
            has_dynsym = elf.get_section_by_name(".dynsym") is not None
            
            st = "symtab" if has_symtab else ""
            dy = "dynsym" if has_dynsym else ""
            print(f"{st:>8} {dy:>8} {os.path.basename(binary)}")
            
            if has_symtab:
                symtab_count += 1
            if has_dynsym:
                dynsym_count += 1
            if not has_symtab and not has_dynsym:
                neither_count += 1
    except Exception as e:
        print(f"{'ERROR':>8} {'':>8} {os.path.basename(binary)} ({e})")

print()
print(f"Has .symtab:  {symtab_count}/20")
print(f"Has .dynsym:  {dynsym_count}/20")
print(f"Has neither:  {neither_count}/20")
