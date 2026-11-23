#!/usr/bin/env python3
"""Generate platform-comparison figures + summary CSV from two aestool benchmark CSVs.

Input CSV columns (written by `aestool bench`):
  mode,dir,size_bytes,ops_per_block,runs,thr_mean_MBps,thr_median_MBps,thr_sd,thr_ci95,
  lat_mean_us,lat_median_us,lat_sd,lat_ci95

Usage (defaults match the repo layout result/bench_windows.csv + result/bench_linux.csv):
  python scripts/compare_platforms.py
  python scripts/compare_platforms.py --base result/bench_windows.csv --base-label "Windows GCC" \
      --cmp result/bench_linux.csv --cmp-label "Ubuntu GCC" --out result/compare

Output (in --out):
  compare_throughput_enc.png / _dec.png   grid: one panel per mode, mean +- 95% CI
  compare_latency_enc.png    / _dec.png   same for latency (log y)
  compare_ratio_enc.png      / _dec.png   cmp/base throughput ratio per mode
  compare_bars_1MB.png                    bars at 1 MB, enc and dec
  compare_summary.csv                     platform,baseline,mode,dir,size_bytes,base_MBps,cmp_MBps,
                                          ratio,diff_pct,significant
  mode_cmp/<platform>_{throughput,latency}_{enc,dec}.png   all modes on one chart per platform
  mode_cmp/<platform>_aead_vs_non_{enc,dec}.png            AEAD vs non-AEAD at 1 MB
Needs: pip install matplotlib
"""
import argparse
import csv
import math
import os
import re

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

MODE_ORDER = ["ecb", "cbc", "ofb", "cfb", "ctr", "xts", "ccm", "gcm"]
AEAD = {"ccm", "gcm"}
STYLES = [
    dict(color="tab:blue", marker="o", linestyle="-"),
    dict(color="tab:orange", marker="s", linestyle="--"),
]
REQUIRED = ["mode", "dir", "size_bytes", "runs", "thr_mean_MBps", "thr_sd", "thr_ci95",
            "lat_mean_us", "lat_sd", "lat_ci95"]


# ------------------------------------------------------------------ data
def load(path):
    data = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        rd = csv.DictReader(f)
        missing = [c for c in REQUIRED if c not in (rd.fieldnames or [])]
        if missing:
            raise SystemExit(f"{path}: missing columns {missing}")
        for r in rd:
            key = (r["mode"].strip().lower(), r["dir"].strip().lower(), int(r["size_bytes"]))
            row = {k: float(v) for k, v in r.items() if k not in ("mode", "dir") and v != ""}
            data[key] = row
    if not data:
        raise SystemExit(f"{path}: no rows")
    return data


def modes_of(*datas):
    present = {k[0] for d in datas for k in d}
    return [m for m in MODE_ORDER if m in present] + sorted(present - set(MODE_ORDER))


def sizes_of(*datas):
    return sorted({k[2] for d in datas for k in d})


def size_label(b):
    if b >= 1 << 20 and b % (1 << 20) == 0:
        return f"{b >> 20} MB"
    if b >= 1 << 10 and b % (1 << 10) == 0:
        return f"{b >> 10} KB"
    return f"{b} B"


def slug(s):
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def save(fig, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("wrote", path)


# ------------------------------------------------------------------ plots
def grid_plot(datas, labels, d, metric, ci, ylabel, title, path, logy=False, ncols=4):
    modes = modes_of(*datas)
    sizes = sizes_of(*datas)
    nrows = math.ceil(len(modes) / ncols)
    fig, axes = plt.subplots(nrows, ncols, figsize=(4.6 * ncols, 3.6 * nrows), squeeze=False)
    for ax in axes.flat[len(modes):]:
        ax.set_visible(False)
    for i, m in enumerate(modes):
        ax = axes.flat[i]
        for dt, lab, st in zip(datas, labels, STYLES):
            pts = [(sizes.index(s), dt[(m, d, s)]) for s in sizes if (m, d, s) in dt]
            if not pts:
                continue
            ax.errorbar([p[0] for p in pts], [p[1][metric] for p in pts], yerr=[p[1][ci] for p in pts],
                        capsize=2, markersize=4, label=lab, **st)
        ax.set_title(m.upper())
        ax.set_xticks(range(len(sizes)))
        ax.set_xticklabels([size_label(s) for s in sizes], rotation=45, fontsize=8)
        if logy:
            ax.set_yscale("log")
        if i % ncols == 0:
            ax.set_ylabel(ylabel)
        ax.grid(True, alpha=0.3)
    h, l = axes.flat[0].get_legend_handles_labels()
    if h:
        fig.legend(h, l, loc="upper center", ncol=len(labels), bbox_to_anchor=(0.5, 1.0))
    fig.suptitle(title, y=1.05, fontsize=13)
    fig.tight_layout()
    save(fig, path)


def ratio_plot(base, cmp_, bl, cl, d, path):
    modes = modes_of(base, cmp_)
    sizes = sizes_of(base, cmp_)
    fig, ax = plt.subplots(figsize=(8, 5))
    for m in modes:
        xs, ys = [], []
        for i, s in enumerate(sizes):
            if (m, d, s) in base and (m, d, s) in cmp_:
                xs.append(i)
                ys.append(cmp_[(m, d, s)]["thr_mean_MBps"] / base[(m, d, s)]["thr_mean_MBps"])
        if xs:
            ax.plot(xs, ys, marker="o", label=m.upper())
    ax.axhline(1.0, color="k", linewidth=1, linestyle=":")
    ax.set_xticks(range(len(sizes)))
    ax.set_xticklabels([size_label(s) for s in sizes])
    ax.set_xlabel("payload size")
    ax.set_ylabel(f"throughput ratio ({cl} / {bl})")
    ax.set_title(f"AES {d} throughput ratio: {cl} vs {bl}  (>1 = {cl} faster)")
    ax.grid(True, alpha=0.3)
    if ax.get_legend_handles_labels()[0]:
        ax.legend(ncol=2)
    save(fig, path)


def bars_plot(base, cmp_, bl, cl, size, path):
    modes = modes_of(base, cmp_)
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.8), sharey=False)
    w = 0.38
    for ax, d in zip(axes, ("enc", "dec")):
        for j, (dt, lab, st) in enumerate(((base, bl, STYLES[0]), (cmp_, cl, STYLES[1]))):
            xs, ys, es = [], [], []
            for i, m in enumerate(modes):
                if (m, d, size) in dt:
                    xs.append(i + (j - 0.5) * w)
                    ys.append(dt[(m, d, size)]["thr_mean_MBps"])
                    es.append(dt[(m, d, size)]["thr_ci95"])
            ax.bar(xs, ys, width=w, yerr=es, capsize=3, color=st["color"], label=lab)
        ax.set_xticks(range(len(modes)))
        ax.set_xticklabels([m.upper() for m in modes])
        ax.set_ylabel("Throughput (MB/s)")
        ax.set_title(f"{d} @ {size_label(size)}")
        ax.grid(True, axis="y", alpha=0.3)
        if ax.get_legend_handles_labels()[0]:
            ax.legend()
    fig.suptitle(f"Throughput at {size_label(size)}: {bl} vs {cl} (mean, 95% CI)")
    fig.tight_layout()
    save(fig, path)


# ------------------------------------------------------------------ summary
def significant(b, c):
    """Welch test on mean throughput (normal/Student approximation at 95%)."""
    nb, nc = b.get("runs", 0), c.get("runs", 0)
    if nb < 2 or nc < 2:
        return False
    vb, vc = b["thr_sd"] ** 2 / nb, c["thr_sd"] ** 2 / nc
    se = math.sqrt(vb + vc)
    if se == 0:
        return b["thr_mean_MBps"] != c["thr_mean_MBps"]
    df = (vb + vc) ** 2 / ((vb ** 2) / (nb - 1) + (vc ** 2) / (nc - 1)) if (vb or vc) else 1
    tcrit = 1.96 + 2.4 / max(df, 1.0)
    return abs(c["thr_mean_MBps"] - b["thr_mean_MBps"]) > tcrit * se


def write_summary(base, cmp_, bl, cl, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["platform", "baseline", "mode", "dir", "size_bytes", "base_MBps", "cmp_MBps",
                    "ratio", "diff_pct", "significant"])
        for d in ("enc", "dec"):
            for m in modes_of(base, cmp_):
                for s in sizes_of(base, cmp_):
                    k = (m, d, s)
                    if k not in base or k not in cmp_:
                        continue
                    bm, cm = base[k]["thr_mean_MBps"], cmp_[k]["thr_mean_MBps"]
                    ratio = cm / bm if bm else float("nan")
                    w.writerow([cl, bl, m, d, s, f"{bm:.2f}", f"{cm:.2f}", f"{ratio:.3f}",
                                f"{(ratio - 1) * 100:.1f}", significant(base[k], cmp_[k])])
    print("wrote", path)


# ------------------------------------------------------------------ per-platform mode comparison
def mode_lines(data, label, d, metric, ci, ylabel, path, logy=False):
    modes = modes_of(data)
    sizes = sizes_of(data)
    fig, ax = plt.subplots(figsize=(8, 5))
    for m in modes:
        pts = [(i, data[(m, d, s)]) for i, s in enumerate(sizes) if (m, d, s) in data]
        if pts:
            ax.errorbar([p[0] for p in pts], [p[1][metric] for p in pts], yerr=[p[1][ci] for p in pts],
                        marker="o", markersize=4, capsize=2,
                        linestyle="--" if m in AEAD else "-", label=m.upper())
    ax.set_xticks(range(len(sizes)))
    ax.set_xticklabels([size_label(s) for s in sizes])
    ax.set_xlabel("payload size")
    ax.set_ylabel(ylabel)
    if logy:
        ax.set_yscale("log")
    ax.set_title(f"{label}: {d} {ylabel.split(' ')[0].lower()} by mode (dashed = AEAD)")
    ax.grid(True, which="both", alpha=0.3)
    if ax.get_legend_handles_labels()[0]:
        ax.legend(ncol=2)
    save(fig, path)


def aead_bars(data, label, d, size, path):
    modes = [m for m in modes_of(data) if (m, d, size) in data]
    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.bar([m.upper() for m in modes], [data[(m, d, size)]["thr_mean_MBps"] for m in modes],
           yerr=[data[(m, d, size)]["thr_ci95"] for m in modes], capsize=4,
           color=["tab:red" if m in AEAD else "tab:blue" for m in modes])
    ax.set_ylabel("Throughput (MB/s)")
    ax.set_title(f"{label}: {d} @ {size_label(size)} (red = AEAD, blue = non-AEAD)")
    ax.grid(True, axis="y", alpha=0.3)
    save(fig, path)


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="result/bench_windows.csv", help="baseline CSV")
    ap.add_argument("--base-label", default="Windows GCC")
    ap.add_argument("--cmp", default="result/bench_linux.csv", help="CSV compared against the baseline")
    ap.add_argument("--cmp-label", default="Ubuntu GCC")
    ap.add_argument("--out", default="result/compare")
    ap.add_argument("--bar-size", type=int, default=1 << 20, help="payload size for the bar chart (bytes)")
    a = ap.parse_args()

    base, cmp_ = load(a.base), load(a.cmp)
    bl, cl = a.base_label, a.cmp_label
    out = a.out

    for d in ("enc", "dec"):
        grid_plot([base, cmp_], [bl, cl], d, "thr_mean_MBps", "thr_ci95", "Throughput (MB/s)",
                  f"AES {d} throughput: platform comparison (mean, 95% CI)",
                  os.path.join(out, f"compare_throughput_{d}.png"))
        grid_plot([base, cmp_], [bl, cl], d, "lat_mean_us", "lat_ci95", "Latency (us/op)",
                  f"AES {d} latency: platform comparison (mean, 95% CI)",
                  os.path.join(out, f"compare_latency_{d}.png"), logy=True)
        ratio_plot(base, cmp_, bl, cl, d, os.path.join(out, f"compare_ratio_{d}.png"))

    bars_plot(base, cmp_, bl, cl, a.bar_size, os.path.join(out, "compare_bars_1MB.png"))
    write_summary(base, cmp_, bl, cl, os.path.join(out, "compare_summary.csv"))

    for data, lab in ((base, bl), (cmp_, cl)):
        s = slug(lab)
        for d in ("enc", "dec"):
            mode_lines(data, lab, d, "thr_mean_MBps", "thr_ci95", "Throughput (MB/s)",
                       os.path.join(out, "mode_cmp", f"{s}_throughput_{d}.png"))
            mode_lines(data, lab, d, "lat_mean_us", "lat_ci95", "Latency (us/op)",
                       os.path.join(out, "mode_cmp", f"{s}_latency_{d}.png"), logy=True)
            aead_bars(data, lab, d, a.bar_size, os.path.join(out, "mode_cmp", f"{s}_aead_vs_non_{d}.png"))


if __name__ == "__main__":
    main()