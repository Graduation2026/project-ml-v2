import os, json, pandas as pd
from collections import defaultdict

OUTPUT_DIR = "D:/ml_binpool_attempt/processed/functions"
df = pd.read_csv("D:/ml_binpool_attempt/splits/master_index_valid.csv")

# Get all JSON files and extract which binaries produced output
json_files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith(".json")]
json_binaries = set()
for jf in json_files:
    with open(os.path.join(OUTPUT_DIR, jf)) as f:
        data = json.load(f)
    json_binaries.add(data.get("binary", ""))

# Group targets by binary
binary_to_targets = defaultdict(list)
for _, row in df.iterrows():
    for bin_path in [row["vuln_bin_path"], row["patch_bin_path"]]:
        bin_basename = os.path.basename(bin_path).replace(".", "_")
        binary_to_targets[bin_path].append({
            "func": row["function_name"],
            "cve_id": row["cve_id"],
            "bin_basename": bin_basename
        })

# Find binaries that have .done markers but produced ZERO JSONs
failed_binaries = []
for bin_path, targets in binary_to_targets.items():
    if not os.path.isfile(bin_path):
        continue
    bin_basename = os.path.basename(bin_path).replace(".", "_")
    proj_name = f"p{abs(hash(bin_path)) % 99999}"
    marker = os.path.join(OUTPUT_DIR, f"{proj_name}.done")
    
    if os.path.exists(marker) and bin_basename not in json_binaries:
        failed_binaries.append({
            "path": bin_path,
            "basename": bin_basename,
            "targets": targets
        })

print(f"Total binaries with .done but NO JSONs: {len(failed_binaries)}")
print()

# Show 10 examples
print("Sample of failed binaries and what we expected to find:")
print("=" * 80)
for fb in failed_binaries[:10]:
    print(f"\nBinary: {fb['basename']}")
    print(f"  Path: {fb['path']}")
    for t in fb['targets'][:3]:
        print(f"  Expected function: {t['func']}  (CVE: {t['cve_id']})")

# Now check: do these binaries actually contain the target function names?
print("\n\n" + "=" * 80)
print("Symbol table check on failed binaries:")
print("=" * 80)

from elftools.elf.elffile import ELFFile

for fb in failed_binaries[:5]:
    binary = fb['path']
    targets = [t['func'] for t in fb['targets']]
    
    print(f"\n--- {fb['basename']} ---")
    print(f"Looking for: {targets}")
    
    try:
        with open(binary, "rb") as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name(".symtab")
            if not symtab:
                symtab = elf.get_section_by_name(".dynsym")
            
            if not symtab:
                print("  NO SYMBOL TABLE!")
                continue
            
            # Find all symbols that contain any target name
            matches = []
            all_func_syms = []
            for sym in symtab.iter_symbols():
                # Check if it's a function symbol
                if sym['st_info']['type'] == 'STT_FUNC' and sym.name:
                    for t in targets:
                        if t in sym.name:
                            matches.append(f"  MATCH: '{sym.name}' contains '{t}'")
                    # Also collect first 10 function symbols for comparison
                    if len(all_func_syms) < 15:
                        all_func_syms.append(sym.name)
            
            if matches:
                for m in matches:
                    print(m)
            else:
                print(f"  NO MATCHES for {targets}")
                print(f"  First 15 function symbols: {all_func_syms}")
    except Exception as e:
        print(f"  ERROR: {e}")
