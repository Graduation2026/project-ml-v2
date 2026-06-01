import json

data = json.load(open("D:/ml_binpool_attempt/binpool_info.json"))

# Check function name patterns
bad_names = []
all_funcs = []
for cve, info in data.items():
    for src, func in info.get("file_func", {}).items():
        all_funcs.append(func)
        if " " in func or "::" in func or "*" in func:
            bad_names.append(func)

print(f"Total functions: {len(all_funcs)}")
print(f"Functions with spaces/scope/pointers: {len(bad_names)}")
print("Examples:")
for n in bad_names[:10]:
    print(f"  {n}")

# Check sample binary paths
for cve, info in data.items():
    if info.get("binaries"):
        print(f"\nSample CVE with binaries: {cve}")
        for b in info["binaries"][:3]:
            print(f"  {b}")
        # Check if patch path exists
        vuln_path = info["binaries"][0]
        patch_path = vuln_path.replace("/vulnerable/", "/patch/")
        print(f"\nDerived patch path: {patch_path}")
        break

# Check how many on-disk CVEs are NOT in JSON
import os
disk_cves = set(d for d in os.listdir("D:/BinPool_dataset/binpool_dataset") if d.startswith("CVE-"))
json_cves = set(data.keys())
print(f"\nCVEs on disk but NOT in JSON: {len(disk_cves - json_cves)}")
print(f"Sample: {list(disk_cves - json_cves)[:5]}")
