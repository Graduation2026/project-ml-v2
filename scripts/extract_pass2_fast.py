#!/usr/bin/env python3
"""
Fast Pass 2 ONLY — extract .deb files into bins/ folders.
Avoids os.walk() over the entire dataset. Instead, constructs paths directly
from the known BinPool structure:
  CVE-ID / {vulnerable,patch} / {opt0,opt1,opt2,opt3} / debfiles/
"""

import os
import subprocess
import sys
import glob

DATASET_ROOT = "/mnt/d/BinPool_dataset/binpool_dataset"

def main():
    # List CVE directories directly (fast — just one level)
    cve_dirs = [d for d in os.listdir(DATASET_ROOT)
                if os.path.isdir(os.path.join(DATASET_ROOT, d)) and d.startswith("CVE-")]
    cve_dirs.sort()
    print(f"Found {len(cve_dirs)} CVE directories.")

    total_extracted = 0
    total_skipped = 0
    total_failed = 0

    for ci, cve in enumerate(cve_dirs):
        cve_progress = 0
        for variant in ["vulnerable", "patch"]:
            for opt in ["opt0", "opt1", "opt2", "opt3"]:
                debfiles_dir = os.path.join(DATASET_ROOT, cve, variant, opt, "debfiles")
                if not os.path.isdir(debfiles_dir):
                    continue

                # Find .deb files — they might be directly in debfiles/ or in a subdirectory
                deb_files = []
                for root, dirs, files in os.walk(debfiles_dir):
                    for f in files:
                        if f.endswith(".deb"):
                            deb_files.append(os.path.join(root, f))

                for deb_path in deb_files:
                    deb_name = os.path.basename(deb_path).replace(".deb", "")
                    deb_parent = os.path.dirname(deb_path)
                    bins_dir = os.path.join(deb_parent, "bins")
                    extract_target = os.path.join(bins_dir, deb_name)

                    # Skip if already extracted
                    if os.path.isdir(extract_target):
                        total_skipped += 1
                        continue

                    os.makedirs(bins_dir, exist_ok=True)
                    try:
                        subprocess.run(
                            ["dpkg-deb", "-x", deb_path, extract_target],
                            check=True, capture_output=True
                        )
                        total_extracted += 1
                        cve_progress += 1
                    except subprocess.CalledProcessError:
                        total_failed += 1

        print(f"[{ci+1}/{len(cve_dirs)}] {cve} — extracted {cve_progress} new", flush=True)

    print(f"\n{'='*50}")
    print(f"DONE. Extracted: {total_extracted} | Skipped: {total_skipped} | Failed: {total_failed}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
