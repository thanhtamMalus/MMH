#!/usr/bin/env python3
"""Ve figure so sanh tu CSV cua aes_bench (Lab 2) - ho tro nhieu payload, nhieu lan do.

CSV (do aes_bench sinh ra): os, compiler, compiler_version, build_type, sbox,
                            mode (compute|e2e), size_bytes, run, seconds, mib_per_s

Vi du (chay tu thu muc lab2/):
    python3 scripts/plot_bench.py docs/results/linux/bench.csv
    python3 scripts/plot_bench.py docs/results/linux/bench.csv docs/results/windows/bench.csv
    python3 scripts/plot_bench.py l.csv wm.csv wv.csv \
        --names "Linux GCC,Win MinGW,Win MSVC" --baseline "Linux GCC" --bar-size 1MiB

Figure tao ra (trong --out, mac dinh docs/results/compare):
    compare_throughput.png     throughput (MiB/s) theo payload, compute | e2e
    compare_latency.png        do tre moi lan chay (ms) theo payload, compute | e2e
    compare_ratio_sbox.png     toc do Table / Computed theo payload
    compare_ratio_e2e.png      E2E / Compute (%) theo payload
    compare_ratio_os.png       moi cau hinh / cau hinh goc (--baseline) theo payload
    compare_bars_<size>.png    cot so sanh tat ca cau hinh tai 1 payload
    compare_box_<size>.png     boxplot phan bo cac lan do tai 1 payload
    compare_summary.csv        median/mean/std/CI95/min/max/p5/p95 tung cau hinh
    compare_ratios.csv         cac ty so dung trong hinh
"""
import argparse
import csv
import math
import os
import statistics
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

T975 = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
        2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
        2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042]
UNITS = {"gib": 1 << 30, "mib": 1 << 20, "kib": 1 << 10,
         "gb": 10**9, "mb": 10**6, "kb": 10**3, "b": 1}


def parse_size(s):
    s = s.strip().lower()
    for u in ("gib", "mib", "kib", "gb", "mb", "kb", "b"):
        if s.endswith(u):
            return int(float(s[: -len(u)]) * UNITS[u])
    return int(s)


def human(n):
    for unit, d in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= d and n % d == 0:
            return f"{n // d}{unit}"
    return f"{n}B"


def pct(sorted_vals, p):
    k = (len(sorted_vals) - 1) * p / 100
    f, c = math.floor(k), math.ceil(k)
    return sorted_vals[f] if f == c else sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def summarize(vals):
    s = sorted(vals)
    n = len(s)
    sd = statistics.stdev(s) if n > 1 else 0.0
    t = T975[n - 2] if 2 <= n <= 31 else 1.96
    return {"n": n, "mean": sum(s) / n, "median": statistics.median(s), "sd": sd,
            "ci": (t * sd / math.sqrt(n)) if n > 1 else 0.0,
            "min": s[0], "max": s[-1], "p5": pct(s, 5), "p95": pct(s, 95)}


def load(paths, names):
    raw = defaultdict(lambda: {"tp": [], "sec": []})
    order = []
    for i, p in enumerate(paths):
        with open(p, newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                row = {k.strip(): (v or "").strip() for k, v in row.items() if k}
                try:
                    tp, sec = float(row["mib_per_s"]), float(row["seconds"])
                    size = int(row["size_bytes"])
                except (KeyError, ValueError):
                    continue
                label = names[i] if names else f"{row.get('os', '?')} {row.get('compiler', '?')}"
                if label not in order:
                    order.append(label)
                key = (label, row["sbox"], row["mode"], size)
                raw[key]["tp"].append(tp)
                raw[key]["sec"].append(sec)
    return raw, order


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="+")
    ap.add_argument("--out", default="docs/results/compare")
    ap.add_argument("--names", help="ten nhan cho tung CSV, cach nhau bang dau phay")
    ap.add_argument("--baseline", help="nhan lam goc cho ty so OS (mac dinh: CSV dau tien)")
    ap.add_argument("--bar-size", default="1MiB", help="payload cho hinh bars/box (vd 1MiB)")
    ap.add_argument("--dpi", type=int, default=150)
    a = ap.parse_args()

    names = [n.strip() for n in a.names.split(",")] if a.names else None
    if names and len(names) != len(a.csv):
        raise SystemExit("--names phai co dung so phan tu bang so file CSV")

    raw, labels = load(a.csv, names)
    if not raw:
        raise SystemExit("Khong doc duoc dong du lieu nao.")
    os.makedirs(a.out, exist_ok=True)

    S = {k: {"tp": summarize(v["tp"]), "sec": summarize(v["sec"])} for k, v in raw.items()}
    sboxes = sorted({k[1] for k in S}, key=lambda x: (x != "table", x))
    modes = [m for m in ("compute", "e2e") if any(k[2] == m for k in S)]
    sizes = sorted({k[3] for k in S})
    baseline = a.baseline if a.baseline in labels else labels[0]

    colors = {lb: plt.cm.tab10(i % 10) for i, lb in enumerate(labels)}
    markers = ["o", "s", "^", "D", "v", "P"]
    lstyle = {sb: ("-" if i == 0 else "--") for i, sb in enumerate(sboxes)}

    def has(lb, sb, m, sz):
        return (lb, sb, m, sz) in S

    def setup_x(ax):
        ax.set_xscale("log", base=2)
        ax.set_xticks(sizes)
        ax.set_xticklabels([human(s) for s in sizes], rotation=45, ha="right", fontsize=8)
        ax.minorticks_off()
        ax.set_xlabel("Payload")
        ax.grid(alpha=0.3)

    saved = []

    def save(fig, name):
        fig.tight_layout()
        path = os.path.join(a.out, name)
        fig.savefig(path, dpi=a.dpi)
        plt.close(fig)
        saved.append(path)

    # 1 & 2. throughput / latency theo payload ---------------------------
    for kind, scale, ylabel, fname, logy in (
            ("tp", 1.0, "Throughput (MiB/s)", "compare_throughput.png", False),
            ("sec", 1000.0, "Latency per run (ms, log)", "compare_latency.png", True)):
        fig, axes = plt.subplots(1, len(modes), figsize=(6.5 * len(modes), 4.6), squeeze=False)
        for ax, m in zip(axes[0], modes):
            for i, lb in enumerate(labels):
                for sb in sboxes:
                    xs = [s for s in sizes if has(lb, sb, m, s)]
                    if not xs:
                        continue
                    med = [S[(lb, sb, m, s)][kind]["median"] * scale for s in xs]
                    lo = [S[(lb, sb, m, s)][kind]["p5"] * scale for s in xs]
                    hi = [S[(lb, sb, m, s)][kind]["p95"] * scale for s in xs]
                    ax.plot(xs, med, marker=markers[i % 6], ls=lstyle[sb], color=colors[lb],
                            label=f"{lb} / {sb}", ms=4)
                    ax.fill_between(xs, lo, hi, color=colors[lb], alpha=0.12)
            setup_x(ax)
            ax.set_ylabel(ylabel)
            ax.set_title(m)
            if logy:
                ax.set_yscale("log")
            ax.legend(fontsize=7)
        fig.suptitle(f"{ylabel.split(' (')[0]} theo payload (duong = median, vung mo = p5-p95)")
        save(fig, fname)

    ratios = []  # (loai, label, sbox, mode, size, ratio)

    # 3. ty so Table / Computed -------------------------------------------
    if "table" in sboxes and "computed" in sboxes:
        fig, axes = plt.subplots(1, len(modes), figsize=(6.5 * len(modes), 4.4), squeeze=False)
        for ax, m in zip(axes[0], modes):
            for i, lb in enumerate(labels):
                xs = [s for s in sizes if has(lb, "table", m, s) and has(lb, "computed", m, s)]
                ys = [S[(lb, "table", m, s)]["tp"]["median"] / S[(lb, "computed", m, s)]["tp"]["median"]
                      for s in xs]
                ax.plot(xs, ys, marker=markers[i % 6], color=colors[lb], label=lb, ms=4)
                ratios += [("table_over_computed", lb, "", m, s, y) for s, y in zip(xs, ys)]
            ax.axhline(1, color="gray", lw=0.8)
            setup_x(ax)
            ax.set_ylabel("Table / Computed (x)")
            ax.set_title(m)
            ax.legend(fontsize=8)
        fig.suptitle("Table S-box nhanh hon Computed bao nhieu lan")
        save(fig, "compare_ratio_sbox.png")

    # 4. E2E / Compute ----------------------------------------------------
    if {"compute", "e2e"} <= set(modes):
        fig, axes = plt.subplots(1, len(sboxes), figsize=(6.5 * len(sboxes), 4.4), squeeze=False)
        for ax, sb in zip(axes[0], sboxes):
            for i, lb in enumerate(labels):
                xs = [s for s in sizes if has(lb, sb, "e2e", s) and has(lb, sb, "compute", s)]
                ys = [100 * S[(lb, sb, "e2e", s)]["tp"]["median"] / S[(lb, sb, "compute", s)]["tp"]["median"]
                      for s in xs]
                ax.plot(xs, ys, marker=markers[i % 6], color=colors[lb], label=lb, ms=4)
                ratios += [("e2e_over_compute_pct", lb, sb, "", s, y) for s, y in zip(xs, ys)]
            ax.axhline(100, color="gray", lw=0.8)
            setup_x(ax)
            ax.set_ylabel("E2E / Compute (%)")
            ax.set_title(sb)
            ax.legend(fontsize=8)
        fig.suptitle("Ty le throughput toan trinh (co I/O) so voi chi tinh toan")
        save(fig, "compare_ratio_e2e.png")

    # 5. ty so giua cac OS / compiler ------------------------------------
    others = [lb for lb in labels if lb != baseline]
    if others:
        fig, axes = plt.subplots(len(sboxes), len(modes),
                                 figsize=(6.5 * len(modes), 4.0 * len(sboxes)), squeeze=False)
        for r, sb in enumerate(sboxes):
            for c, m in enumerate(modes):
                ax = axes[r][c]
                for i, lb in enumerate(others):
                    xs = [s for s in sizes if has(lb, sb, m, s) and has(baseline, sb, m, s)]
                    ys = [S[(lb, sb, m, s)]["tp"]["median"] / S[(baseline, sb, m, s)]["tp"]["median"]
                          for s in xs]
                    ax.plot(xs, ys, marker=markers[i % 6], color=colors[lb], label=lb, ms=4)
                    ratios += [("vs_baseline:" + baseline, lb, sb, m, s, y) for s, y in zip(xs, ys)]
                ax.axhline(1, color="gray", lw=0.8)
                setup_x(ax)
                ax.set_ylabel(f"throughput / {baseline}")
                ax.set_title(f"{sb} - {m}")
                ax.legend(fontsize=8)
        fig.suptitle(f"So voi cau hinh goc: {baseline} (1.0 = bang nhau)")
        save(fig, "compare_ratio_os.png")

    # 6 & 7. bars + boxplot tai 1 payload --------------------------------
    want = parse_size(a.bar_size)
    bsize = min(sizes, key=lambda s: abs(math.log2(s) - math.log2(want)))
    if bsize != want:
        print(f"[!] Khong co payload {a.bar_size}, dung {human(bsize)}")
    tag = human(bsize)

    cats = [(sb, m) for sb in sboxes for m in modes]
    fig, ax = plt.subplots(figsize=(max(7, 2.2 * len(cats)), 4.8))
    n = len(labels)
    w = 0.8 / n
    for i, lb in enumerate(labels):
        xs, med, lo, hi = [], [], [], []
        for j, (sb, m) in enumerate(cats):
            if has(lb, sb, m, bsize):
                st = S[(lb, sb, m, bsize)]["tp"]
                xs.append(j + (i - (n - 1) / 2) * w)
                med.append(st["median"])
                lo.append(st["median"] - st["p5"])
                hi.append(st["p95"] - st["median"])
        ax.bar(xs, med, w, yerr=[lo, hi], capsize=3, label=lb, color=colors[lb])
    ax.set_xticks(range(len(cats)))
    ax.set_xticklabels([f"{sb}\n{m}" for sb, m in cats])
    ax.set_ylabel("Throughput (MiB/s)")
    ax.set_title(f"Tat ca cau hinh tai payload {tag} (median, thanh loi = p5-p95)")
    ax.grid(axis="y", alpha=0.3)
    ax.legend(fontsize=8)
    save(fig, f"compare_bars_{tag}.png")

    fig, axes = plt.subplots(1, len(modes), figsize=(6.5 * len(modes), 5), squeeze=False)
    for ax, m in zip(axes[0], modes):
        groups, tick = [], []
        for lb in labels:
            for sb in sboxes:
                if (lb, sb, m, bsize) in raw:
                    groups.append(raw[(lb, sb, m, bsize)]["tp"])
                    tick.append(f"{lb}\n{sb}")
        ax.boxplot(groups, tick_labels=tick, showfliers=True, flierprops={"markersize": 3})
        ax.tick_params(axis="x", labelsize=7, rotation=30)
        ax.set_ylabel("Throughput (MiB/s)")
        ax.set_title(f"{m} - {tag}")
        ax.grid(axis="y", alpha=0.3)
    fig.suptitle(f"Phan bo cac lan do tai payload {tag}")
    save(fig, f"compare_box_{tag}.png")

    # 8. CSV tong ket -----------------------------------------------------
    path = os.path.join(a.out, "compare_summary.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["label", "sbox", "mode", "size_bytes", "size", "n_runs", "median_mib_s",
                    "mean_mib_s", "std_mib_s", "ci95_mib_s", "min_mib_s", "max_mib_s",
                    "p5_mib_s", "p95_mib_s", "median_latency_ms", "mean_latency_ms"])
        for (lb, sb, m, sz), st in sorted(S.items(), key=lambda kv: (labels.index(kv[0][0]),) + kv[0][1:]):
            t, l = st["tp"], st["sec"]
            w.writerow([lb, sb, m, sz, human(sz), t["n"], f"{t['median']:.2f}", f"{t['mean']:.2f}",
                        f"{t['sd']:.2f}", f"{t['ci']:.2f}", f"{t['min']:.2f}", f"{t['max']:.2f}",
                        f"{t['p5']:.2f}", f"{t['p95']:.2f}", f"{l['median'] * 1000:.4f}",
                        f"{l['mean'] * 1000:.4f}"])
    saved.append(path)

    path = os.path.join(a.out, "compare_ratios.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "label", "sbox", "mode", "size", "ratio"])
        for t, lb, sb, m, sz, r in ratios:
            w.writerow([t, lb, sb, m, human(sz), f"{r:.4f}"])
    saved.append(path)

    print("Da tao:")
    for p in saved:
        print("  ", p)


if __name__ == "__main__":
    main()