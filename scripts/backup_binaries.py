import os, csv, hashlib, shutil, sys
from collections import OrderedDict

CSV_PATH = "D:/ml_binpool_attempt/splits/master_index_valid.csv"
BACKUP_DIR = "D:/ml_binpool_attempt/backup ( DO NOT TOUCH)/binaries"
MANIFEST_PATH = "D:/ml_binpool_attempt/backup ( DO NOT TOUCH)/manifest.csv"

os.makedirs(BACKUP_DIR, exist_ok=True)

# Extract all unique binary paths
paths = OrderedDict()
with open(CSV_PATH, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        for col in ("vuln_bin_path", "patch_bin_path"):
            p = row[col].strip()
            if p.startswith("D:"):
                paths[p] = None  # deduplicate preserving order

paths = list(paths.keys())
print(f"Unique binary paths: {len(paths)}")

# Compute manifest data and copy
manifest = []
errors = []
copied = 0
skipped = 0

for src in paths:
    if not os.path.isfile(src):
        errors.append(f"MISSING: {src}")
        continue
    
    path_hash = hashlib.md5(src.encode()).hexdigest()[:8]
    basename = os.path.basename(src)
    dst_name = f"{path_hash}_{basename}"
    dst = os.path.join(BACKUP_DIR, dst_name)
    
    if os.path.exists(dst):
        skipped += 1
    else:
        try:
            shutil.copy2(src, dst)
            copied += 1
        except Exception as e:
            errors.append(f"COPY FAILED: {src} -> {dst}: {e}")
            continue
    
    # Compute source MD5
    with open(src, 'rb') as f:
        src_md5 = hashlib.md5(f.read()).hexdigest()
    
    manifest.append({
        "backup_name": dst_name,
        "original_path": src,
        "size_bytes": os.path.getsize(src),
        "source_md5": src_md5
    })

# Write manifest
with open(MANIFEST_PATH, 'w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=["backup_name", "original_path", "size_bytes", "source_md5"])
    w.writeheader()
    w.writerows(manifest)

print(f"\nCopied: {copied}, Skipped (already exist): {skipped}, Errors: {len(errors)}")
print(f"Manifest entries: {len(manifest)}")
print(f"Manifest saved: {MANIFEST_PATH}")

if errors:
    print("\nErrors:")
    for e in errors[:10]:
        print(f"  {e}")
    if len(errors) > 10:
        print(f"  ... and {len(errors) - 10} more")

# Quick verification
backup_count = len([f for f in os.listdir(BACKUP_DIR) if os.path.isfile(os.path.join(BACKUP_DIR, f))])
print(f"\nFiles in backup dir: {backup_count}")
if backup_count == len(paths):
    print("VERIFIED: All binaries backed up successfully.")
else:
    print(f"WARNING: Expected {len(paths)} files, found {backup_count}")
