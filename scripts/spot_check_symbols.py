import pandas as pd
from elftools.elf.elffile import ELFFile
import os

print("Loading master_index_valid.csv...")
df = pd.read_csv("D:/ml_binpool_attempt/splits/master_index_valid.csv")

# We'll check 10 random samples to be sure
sample = df.sample(10, random_state=42)
print("Spot checking 10 random functions in their binaries...")

found_count = 0
for idx, row in sample.iterrows():
    binary = row["vuln_bin_path"]
    target = row["function_name"]
    found = False
    
    if not os.path.isfile(binary):
        print(f"[MISSING FILE] {binary}")
        continue
        
    try:
        with open(binary, "rb") as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name(".symtab")
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym.name == target:
                        found = True
                        break
            
            # Fallback to dynamic symbol table if standard symtab is stripped
            if not found:
                dynsym = elf.get_section_by_name(".dynsym")
                if dynsym:
                    for sym in dynsym.iter_symbols():
                        if sym.name == target:
                            found = True
                            break
                            
    except Exception as e:
        print(f"[ERROR reading {os.path.basename(binary)}] {e}")
        continue

    status = "FOUND" if found else "NOT FOUND"
    if found:
        found_count += 1
    print(f"[{status}] {target} in {os.path.basename(binary)}")

print(f"\nSummary: {found_count}/10 symbols found successfully.")
