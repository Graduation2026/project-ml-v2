#!/usr/bin/env python3
"""
Adapted extract_deb_tar.py for Windows paths via WSL.
Original script by SimaArasteh/binpool — adapted for D:/BinPool_dataset path.
No external dependencies — uses only stdlib.

Two-pass extraction:
  Pass 1: _opt[0-3] files (POSIX tar archives) → debfiles/
  Pass 2: .deb files inside debfiles/          → bins/
"""

import os
import re
import subprocess
import sys

# ─── CONFIG ─────────────────────────────────────────────────────────────────
DATASET_ROOT = "/mnt/d/BinPool_dataset/binpool_dataset"
# ────────────────────────────────────────────────────────────────────────────


def ends_with_opt(file_name):
    return re.search(r"_opt[0-3]$", file_name) is not None


def progress(current, total, prefix=""):
    pct = current / total * 100 if total else 0
    bar_len = 40
    filled = int(bar_len * current / total) if total else 0
    bar = "█" * filled + "░" * (bar_len - filled)
    print(f"\r{prefix} [{bar}] {current}/{total} ({pct:.1f}%)", end="", flush=True)


def extract_tar_to_debfiles(tar_path):
    tar_dir = "/".join(tar_path.split("/")[:-1])
    debfiles_dir = tar_dir + "/debfiles"
    os.makedirs(debfiles_dir, exist_ok=True)
    try:
        subprocess.run(["tar", "-xf", tar_path, "-C", debfiles_dir],
                       check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n  [WARN] tar failed on {tar_path}: {e.stderr.decode()[:200]}")
        return False


def extract_debfiles_to_bin(deb_path):
    directory_name = deb_path.split("/")[-1].replace(".deb", "")
    directory_parts = deb_path.split("/")[:-1]
    directory_path = "/".join(directory_parts) + "/bins/"
    os.makedirs(directory_path, exist_ok=True)
    deb_extract_dir = directory_path + directory_name
    try:
        subprocess.run(["dpkg-deb", "-x", deb_path, deb_extract_dir],
                       check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n  [WARN] dpkg-deb failed on {deb_path}: {e.stderr.decode()[:200]}")
        return False


def collect_files(root_dir, filter_fn):
    matches = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            if filter_fn(full, fname):
                matches.append(full)
    return matches


def main():
    print("=" * 60)
    print("BinPool Extraction")
    print(f"Dataset root: {DATASET_ROOT}")
    print("=" * 60)

    # ── PASS 1: tar archives → debfiles/ ─────────────────────────────────
    def is_opt_tar(path, fname):
        return ("/patch/" in path or "/vulnerable/" in path) and ends_with_opt(fname)

    print("\n[Pass 1] Scanning for tar archives...")
    tar_files = collect_files(DATASET_ROOT, is_opt_tar)
    print(f"  Found {len(tar_files)} archives.\n")

    ok1, skip1 = 0, 0
    for i, tar_path in enumerate(tar_files, 1):
        progress(i, len(tar_files), "Pass 1")
        tar_dir = "/".join(tar_path.split("/")[:-1])
        debfiles_dir = tar_dir + "/debfiles"
        if os.path.isdir(debfiles_dir) and os.listdir(debfiles_dir):
            skip1 += 1
            continue
        if extract_tar_to_debfiles(tar_path):
            ok1 += 1

    print(f"\n  Done. Extracted: {ok1} | Skipped (resume): {skip1}")

    # ── PASS 2: .deb → bins/ ─────────────────────────────────────────────
    def is_deb(path, fname):
        # .deb files are inside debfiles/output_directory/*.deb
        return "/debfiles/" in path and fname.endswith(".deb")

    # Also fix bins extraction path to account for output_directory nesting
    # deb_path example: .../debfiles/output_directory/package.deb
    # bins should go:   .../debfiles/output_directory/bins/package_name/

    print("\n[Pass 2] Scanning for .deb packages...")
    deb_files = collect_files(DATASET_ROOT, is_deb)
    print(f"  Found {len(deb_files)} packages.\n")

    ok2, skip2 = 0, 0
    for i, deb_path in enumerate(deb_files, 1):
        progress(i, len(deb_files), "Pass 2")
        deb_name = deb_path.split("/")[-1].replace(".deb", "")
        deb_dir = "/".join(deb_path.split("/")[:-1])
        if os.path.isdir(deb_dir + "/bins/" + deb_name):
            skip2 += 1
            continue
        if extract_debfiles_to_bin(deb_path):
            ok2 += 1

    print(f"\n  Done. Extracted: {ok2} | Skipped (resume): {skip2}")

    print("\n" + "=" * 60)
    print("EXTRACTION COMPLETE — check D:\\BinPool_dataset for bins/ folders")
    print("=" * 60)


if __name__ == "__main__":
    main()
