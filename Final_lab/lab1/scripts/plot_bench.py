#!/usr/bin/env python3
"""Plot aestool benchmark CSV files.

Usage:
  python scripts/plot_bench.py bench_linux.csv [bench_windows.csv ...] --out plots

Needs: pip install matplotlib
Produces (PNG):
  throughput_vs_size.png  - MB/s per mode (log x), error bars = 95% CI
  latency_vs_size.png     - microseconds per operation
  aead_vs_nonaead.png     - bar chart at the largest size (tag overhead / AEAD cost)
  os_compare.png          - only when two or more CSVs are given (one per OS/machine)
"""
import argparse
import csv
import os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


def load(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            for k in ("size_bytes", "ops_per_block", "runs"):
                r[k] = int(r[k])
            for k in r:
                if k.startswith(("thr_", "lat_")):
                    r[k] = float(r[k])
            r["aead"] = 1 if r["mode"] in ("ccm", "gcm") else 0
            rows.append(r)
    return rows


def size_label(b):
    if b >= 1 << 20:
        return f"{b >> 20} MiB"
    return f"{b >> 10} KiB"


def series(rows, op="enc"):
    d = defaultdict(list)
    for r in rows:
        if r["dir"] == op:
            d[r["mode"]].append(r)
    for m in d:
        d[m].sort(key=lambda r: r["size_bytes"])
    return d


def line_plot(rows, key, ylabel, fname, outdir, title):
    d = series(rows)
    plt.figure(figsize=(8, 5))
    for mode, rs in sorted(d.items()):
        x = [r["size_bytes"] for r in rs]
        y = [r[f"{key}_mean_" + ("MBps" if key == "thr" else "us")] for r in rs]
        e = [r[f"{key}_ci95"] for r in rs]
        err = [e, e]
        plt.errorbar(x, y, yerr=err, marker="o", capsize=3, label=mode.upper())
    plt.xscale("log", base=2)
    if key == "lat":
        plt.yscale("log")
    plt.xticks([r["size_bytes"] for r in next(iter(d.values()))],
               [size_label(r["size_bytes"]) for r in next(iter(d.values()))])
    plt.xlabel("payload size")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.grid(True, which="both", alpha=0.3)
    plt.legend(ncol=2)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, fname), dpi=150)
    plt.close()


def aead_bar(rows, outdir, title):
    d = series(rows)
    biggest = max(r["size_bytes"] for rs in d.values() for r in rs)
    modes, vals, errs, colors = [], [], [], []
    for mode, rs in sorted(d.items()):
        for r in rs:
            if r["size_bytes"] == biggest:
                modes.append(mode.upper())
                vals.append(r["thr_mean_MBps"])
                errs.append(r["thr_ci95"])
                colors.append("tab:red" if r["aead"] else "tab:blue")
    plt.figure(figsize=(8, 5))
    plt.bar(modes, vals, yerr=errs, capsize=4, color=colors)
    plt.ylabel("throughput (MB/s)")
    plt.title(f"{title} - {size_label(biggest)} (red = AEAD)")
    plt.grid(True, axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "aead_vs_nonaead.png"), dpi=150)
    plt.close()


def os_compare(files, outdir):
    plt.figure(figsize=(9, 5))
    width = 0.8 / len(files)
    for i, (label, rows) in enumerate(files):
        d = series(rows)
        biggest = max(r["size_bytes"] for rs in d.values() for r in rs)
        modes = sorted(d)
        vals = [next(r["thr_mean_MBps"] for r in d[m] if r["size_bytes"] == biggest) for m in modes]
        xs = [j + i * width for j in range(len(modes))]
        plt.bar(xs, vals, width=width, label=label)
    plt.xticks([j + 0.4 - width / 2 for j in range(len(modes))], [m.upper() for m in modes])
    plt.ylabel("throughput (MB/s)")
    plt.title(f"Platform comparison at {size_label(biggest)}")
    plt.legend()
    plt.grid(True, axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "os_compare.png"), dpi=150)
    plt.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="+")
    ap.add_argument("--out", default="plots")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    files = []
    for p in a.csv:
        rows = load(p)
        files.append((os.path.basename(p), rows))
    label, rows = files[0]
    line_plot(rows, "thr", "throughput (MB/s)", "throughput_vs_size.png", a.out, f"Throughput - {label}")
    line_plot(rows, "lat", "latency per operation (us)", "latency_vs_size.png", a.out, f"Latency - {label}")
    aead_bar(rows, a.out, label)
    if len(files) > 1:
        os_compare(files, a.out)
    print("wrote plots to", a.out)


if __name__ == "__main__":
    main()
