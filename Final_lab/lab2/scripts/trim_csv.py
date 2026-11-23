#!/usr/bin/env python3
"""Cat CSV cua aes_bench ve toi da N lan do moi nhom (khong sua so lieu, chi bo dong du).

Nhom = (os, compiler, compiler_version, build_type, sbox, mode, size_bytes).

Vi du:
    python3 scripts/trim_csv.py docs/results/linux/bench.csv --n 30            # giu 30 dong DAU moi nhom
    python3 scripts/trim_csv.py docs/results/linux/bench.csv --n 30 --keep last
    python3 scripts/trim_csv.py bench.csv --n 30 --dry-run                     # chi in bang, khong ghi

Chi cat mot so nhom (cac nhom khac giu nguyen), vi du chi computed 1GiB:
    python3 scripts/trim_csv.py bench.csv --n 30 --sbox computed --size 1GiB
    python scripts/trim_csv.py docs/results/windows/bench.csv --n 30 --dry-run

File goc duoc sao luu thanh <file>.bak (neu chua co) truoc khi ghi de.
"""
import argparse
import csv
import os
import shutil
from collections import defaultdict

UNITS = {"gib": 1 << 30, "mib": 1 << 20, "kib": 1 << 10, "gb": 10**9, "mb": 10**6, "kb": 10**3, "b": 1}


def parse_size(s):
    s = s.strip().lower()
    for u in ("gib", "mib", "kib", "gb", "mb", "kb", "b"):
        if s.endswith(u):
            return int(float(s[: -len(u)]) * UNITS[u])
    return int(s)


KEY = ["os", "compiler", "compiler_version", "build_type", "sbox", "mode", "size_bytes"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--n", type=int, required=True, help="so dong toi da giu lai moi nhom")
    ap.add_argument("--keep", choices=["first", "last"], default="first",
                    help="giu cac lan do dau tien (mac dinh) hay cuoi cung")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--sbox", choices=["table", "computed"], help="chi cat nhom co sbox nay")
    ap.add_argument("--mode", choices=["compute", "e2e"], help="chi cat nhom co mode nay")
    ap.add_argument("--size", help="chi cat nhom co payload nay (vd 1GiB, 100MiB)")
    a = ap.parse_args()

    with open(a.csv, newline="", encoding="utf-8-sig") as f:
        rd = csv.reader(f)
        header = next(rd)
        rows = [r for r in rd if r]
    idx = [header.index(k) for k in KEY]

    groups = defaultdict(list)
    for i, r in enumerate(rows):
        groups[tuple(r[j] for j in idx)].append(i)

    want_size = parse_size(a.size) if a.size else None

    def selected(g):
        return ((a.sbox is None or g[4] == a.sbox) and (a.mode is None or g[5] == a.mode)
                and (want_size is None or int(g[6]) == want_size))

    keep = set()
    print(f"{'nhom (sbox, mode, size_bytes)':50s} {'truoc':>6s} {'sau':>6s}")
    for g, ids in groups.items():
        if not selected(g):
            chosen = ids  # nhom khong duoc chon: giu nguyen
        elif a.keep == "first":
            chosen = ids[: a.n]
        else:
            chosen = ids[-a.n:]
        keep.update(chosen)
        print(f"{g[4] + ', ' + g[5] + ', ' + g[6] + '  [' + g[0] + ' ' + g[1] + ']':50s} "
              f"{len(ids):6d} {len(chosen):6d}")

    removed = len(rows) - len(keep)
    print(f"\nTong: {len(rows)} -> {len(keep)} dong (bo {removed})")
    if a.dry_run or removed == 0:
        print("Khong ghi file." if a.dry_run else "Khong co dong du.")
        return

    bak = a.csv + ".bak"
    if not os.path.exists(bak):
        shutil.copy2(a.csv, bak)
        print(f"Da sao luu: {bak}")
    with open(a.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for i, r in enumerate(rows):
            if i in keep:
                w.writerow(r)
    print(f"Da ghi: {a.csv}")


if __name__ == "__main__":
    main()