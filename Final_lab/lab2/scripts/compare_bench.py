#!/usr/bin/env python3
"""So sanh ket qua aes_bench: (1) giua cac he (Linux vs Windows, MSVC vs MinGW),
(2) trong MOT he, hieu qua cua cac payload so voi nhau.

CSV: os, compiler, compiler_version, build_type, sbox, mode (compute|e2e),
     size_bytes, run, seconds, mib_per_s

--- cross: so 2 (hoac nhieu) he voi nhau ----------------------------------
    python3 scripts/compare_bench.py cross docs/results/linux/bench.csv docs/results/windows/bench_mingw.csv \
        --names "Linux GCC,Win MinGW" --out docs/results/cross
    (CSV dau tien la goc; them CSV thu 3, 4... de so tiep voi cung goc)

--- single: hieu qua theo payload trong tung he ---------------------------
    python3 scripts/compare_bench.py single docs/results/linux/bench.csv --names "Linux GCC" --out docs/results/single
    (dua nhieu CSV vao thi moi he ra mot bo hinh rieng)
"""
import argparse
import csv
import math
import os
import re
import statistics
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

T975 = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
        2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
        2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042]


def human(n):
    for unit, d in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= d and n % d == 0:
            return f"{n // d}{unit}"
    return f"{n}B"


def pct(s, p):
    k = (len(s) - 1) * p / 100
    f, c = math.floor(k), math.ceil(k)
    return s[f] if f == c else s[f] + (s[c] - s[f]) * (k - f)


def summarize(vals):
    s = sorted(vals)
    n = len(s)
    mean = sum(s) / n
    sd = statistics.stdev(s) if n > 1 else 0.0
    return {"n": n, "mean": mean, "median": statistics.median(s), "sd": sd,
            "cv": 100 * sd / mean if mean else 0.0, "p5": pct(s, 5), "p95": pct(s, 95)}


def load(paths, names):
    raw = defaultdict(lambda: {"tp": [], "sec": []})
    labels = []
    for i, p in enumerate(paths):
        with open(p, newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                row = {k.strip(): (v or "").strip() for k, v in row.items() if k}
                try:
                    tp, sec, size = float(row["mib_per_s"]), float(row["seconds"]), int(row["size_bytes"])
                except (KeyError, ValueError):
                    continue
                lb = names[i] if names else f"{row.get('os', '?')} {row.get('compiler', '?')}"
                if lb not in labels:
                    labels.append(lb)
                raw[(lb, row["sbox"], row["mode"], size)]["tp"].append(tp)
                raw[(lb, row["sbox"], row["mode"], size)]["sec"].append(sec)
    if not raw:
        raise SystemExit("Khong doc duoc dong du lieu nao.")
    S = {k: {"tp": summarize(v["tp"]), "sec": summarize(v["sec"])} for k, v in raw.items()}
    return S, labels


def dims(S):
    sboxes = sorted({k[1] for k in S}, key=lambda x: (x != "table", x))
    modes = [m for m in ("compute", "e2e") if any(k[2] == m for k in S)]
    sizes = sorted({k[3] for k in S})
    return sboxes, modes, sizes


def writer(path):
    f = open(path, "w", newline="", encoding="utf-8")
    return f, csv.writer(f, lineterminator="\n")


def safe(s):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)


# ============================ CROSS =========================================
def cmd_cross(a):
    names = [n.strip() for n in a.names.split(",")] if a.names else None
    if names and len(names) != len(a.csv):
        raise SystemExit("--names phai co dung so phan tu bang so file CSV")
    if len(a.csv) < 2:
        raise SystemExit("cross can it nhat 2 file CSV")
    S, labels = load(a.csv, names)
    sboxes, modes, sizes = dims(S)
    base = a.baseline if a.baseline in labels else labels[0]
    others = [l for l in labels if l != base]
    os.makedirs(a.out, exist_ok=True)
    colors = {lb: plt.cm.tab10(i % 10) for i, lb in enumerate(labels)}
    saved = []

    # bang so lieu ----------------------------------------------------------
    rows = []
    for lb in others:
        for sb in sboxes:
            for m in modes:
                for s in sizes:
                    kb, ko = (base, sb, m, s), (lb, sb, m, s)
                    if kb not in S or ko not in S:
                        continue
                    b, o = S[kb]["tp"], S[ko]["tp"]
                    se = math.sqrt(o["sd"] ** 2 / o["n"] + b["sd"] ** 2 / b["n"])
                    d_mean = o["mean"] - b["mean"]
                    rows.append({
                        "baseline": base, "other": lb, "sbox": sb, "mode": m, "size": human(s),
                        "n_base": b["n"], "n_other": o["n"],
                        "median_base": b["median"], "median_other": o["median"],
                        "diff_median_pct": 100 * (o["median"] / b["median"] - 1),
                        "diff_mean_pct": 100 * d_mean / b["mean"],
                        "ci95_pct": 100 * 1.96 * se / b["mean"],
                        "significant": "yes" if abs(d_mean) > 1.96 * se else "no",
                        "_size_bytes": s})
    path = os.path.join(a.out, "cross_table.csv")
    f, w = writer(path)
    cols = ["baseline", "other", "sbox", "mode", "size", "n_base", "n_other", "median_base",
            "median_other", "diff_median_pct", "diff_mean_pct", "ci95_pct", "significant"]
    w.writerow(cols)
    for r in rows:
        w.writerow([f"{r[c]:.2f}" if isinstance(r[c], float) else r[c] for c in cols])
    f.close()
    saved.append(path)

    # hinh 1: throughput cac he canh nhau -----------------------------------
    fig, axes = plt.subplots(len(sboxes), len(modes), figsize=(6.5 * len(modes), 4.2 * len(sboxes)),
                             squeeze=False)
    n = len(labels)
    w_ = 0.8 / n
    for r, sb in enumerate(sboxes):
        for c, m in enumerate(modes):
            ax = axes[r][c]
            for i, lb in enumerate(labels):
                xs, med, lo, hi = [], [], [], []
                for j, s in enumerate(sizes):
                    if (lb, sb, m, s) in S:
                        t = S[(lb, sb, m, s)]["tp"]
                        xs.append(j + (i - (n - 1) / 2) * w_)
                        med.append(t["median"])
                        lo.append(t["median"] - t["p5"])
                        hi.append(t["p95"] - t["median"])
                ax.bar(xs, med, w_, yerr=[lo, hi], capsize=2, color=colors[lb], label=lb)
            ax.set_xticks(range(len(sizes)))
            ax.set_xticklabels([human(s) for s in sizes], fontsize=8)
            ax.set_ylabel("Throughput (MiB/s)")
            ax.set_title(f"{sb} - {m}")
            ax.grid(axis="y", alpha=0.3)
            ax.legend(fontsize=8)
    fig.suptitle("So sanh throughput giua cac he (median, thanh loi = p5-p95)")
    fig.tight_layout()
    path = os.path.join(a.out, "cross_throughput.png")
    fig.savefig(path, dpi=a.dpi)
    plt.close(fig)
    saved.append(path)

    # hinh 2: % chenh lech so voi goc ---------------------------------------
    fig, axes = plt.subplots(len(sboxes), len(modes), figsize=(6.5 * len(modes), 4.2 * len(sboxes)),
                             squeeze=False)
    k = max(len(others), 1)
    w_ = 0.8 / k
    for r, sb in enumerate(sboxes):
        for c, m in enumerate(modes):
            ax = axes[r][c]
            for i, lb in enumerate(others):
                xs, ys, es = [], [], []
                for j, s in enumerate(sizes):
                    hit = [x for x in rows if x["other"] == lb and x["sbox"] == sb and x["mode"] == m
                           and x["_size_bytes"] == s]
                    if hit:
                        xs.append(j + (i - (k - 1) / 2) * w_)
                        ys.append(hit[0]["diff_mean_pct"])
                        es.append(hit[0]["ci95_pct"])
                ax.bar(xs, ys, w_, yerr=es, capsize=2, color=colors[lb], label=lb)
            ax.axhline(0, color="gray", lw=0.8)
            ax.set_xticks(range(len(sizes)))
            ax.set_xticklabels([human(s) for s in sizes], fontsize=8)
            ax.set_ylabel(f"Chenh lech so voi {base} (%)")
            ax.set_title(f"{sb} - {m}")
            ax.grid(axis="y", alpha=0.3)
            ax.legend(fontsize=8)
    fig.suptitle(f"% chenh lech trung binh so voi {base} (>0: nhanh hon; thanh loi = CI95 xap xi)")
    fig.tight_layout()
    path = os.path.join(a.out, "cross_diff_pct.png")
    fig.savefig(path, dpi=a.dpi)
    plt.close(fig)
    saved.append(path)

    print("Goc:", base, "| so voi:", ", ".join(others))
    print("Da tao:")
    for p in saved:
        print("  ", p)


# ============================ SINGLE ========================================
def cmd_single(a):
    names = [n.strip() for n in a.names.split(",")] if a.names else None
    if names and len(names) != len(a.csv):
        raise SystemExit("--names phai co dung so phan tu bang so file CSV")
    S, labels = load(a.csv, names)
    sboxes, modes, sizes = dims(S)
    os.makedirs(a.out, exist_ok=True)
    combos = [(sb, m) for sb in sboxes for m in modes]
    colors = {c: plt.cm.tab10(i % 10) for i, c in enumerate(combos)}
    saved = []

    for lb in labels:
        # bang so lieu + slope ---------------------------------------------
        table = []
        for sb, m in combos:
            ss = [s for s in sizes if (lb, sb, m, s) in S]
            if not ss:
                continue
            best = max(S[(lb, sb, m, s)]["tp"]["median"] for s in ss)
            if len(ss) >= 2:  # do doc log(thoi gian) theo log(payload): 1.0 = tuyen tinh
                xs = [math.log(s) for s in ss]
                ys = [math.log(S[(lb, sb, m, s)]["sec"]["median"]) for s in ss]
                mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
                slope = (sum((x - mx) * (y - my) for x, y in zip(xs, ys)) /
                         sum((x - mx) ** 2 for x in xs))
            else:
                slope = float("nan")
            for s in ss:
                t = S[(lb, sb, m, s)]["tp"]
                comp = S.get((lb, sb, "compute", s))
                e2e_over = (100 * t["median"] / comp["tp"]["median"]) if (m == "e2e" and comp) else None
                table.append({"sbox": sb, "mode": m, "size": human(s), "n": t["n"],
                              "median_mib_s": t["median"], "mean_mib_s": t["mean"], "sd": t["sd"],
                              "cv_pct": t["cv"], "eff_vs_best_pct": 100 * t["median"] / best,
                              "latency_ms": S[(lb, sb, m, s)]["sec"]["median"] * 1000,
                              "e2e_over_compute_pct": e2e_over, "time_scaling_slope": slope,
                              "_s": s})
        path = os.path.join(a.out, f"single_{safe(lb)}_table.csv")
        f, w = writer(path)
        cols = ["sbox", "mode", "size", "n", "median_mib_s", "mean_mib_s", "sd", "cv_pct",
                "eff_vs_best_pct", "latency_ms", "e2e_over_compute_pct", "time_scaling_slope"]
        w.writerow(cols)
        for r in table:
            w.writerow(["" if r[c] is None else (f"{r[c]:.3f}" if isinstance(r[c], float) else r[c])
                        for c in cols])
        f.close()
        saved.append(path)

        # hinh 2x2 ----------------------------------------------------------
        fig, axes = plt.subplots(2, 2, figsize=(13, 9))
        ax = axes[0][0]
        for sb, m in combos:
            ss = [s for s in sizes if (lb, sb, m, s) in S]
            if not ss:
                continue
            med = [S[(lb, sb, m, s)]["tp"]["median"] for s in ss]
            lo = [S[(lb, sb, m, s)]["tp"]["p5"] for s in ss]
            hi = [S[(lb, sb, m, s)]["tp"]["p95"] for s in ss]
            ax.plot(ss, med, marker="o", ms=4, color=colors[(sb, m)], label=f"{sb} / {m}")
            ax.fill_between(ss, lo, hi, color=colors[(sb, m)], alpha=0.12)
        ax.set_xscale("log", base=2)
        ax.set_xticks(sizes)
        ax.set_xticklabels([human(s) for s in sizes], rotation=45, ha="right", fontsize=8)
        ax.minorticks_off()
        ax.set_ylabel("Throughput (MiB/s)")
        ax.set_title("Throughput theo payload (median, vung mo = p5-p95)")
        ax.grid(alpha=0.3)
        ax.legend(fontsize=8)

        def bars(ax, key, ylabel, title, hline=None):
            n = len(combos)
            w_ = 0.8 / n
            for i, (sb, m) in enumerate(combos):
                xs, ys = [], []
                for j, s in enumerate(sizes):
                    hit = [r for r in table if r["sbox"] == sb and r["mode"] == m and r["_s"] == s]
                    if hit and hit[0][key] is not None:
                        xs.append(j + (i - (n - 1) / 2) * w_)
                        ys.append(hit[0][key])
                if xs:
                    ax.bar(xs, ys, w_, color=colors[(sb, m)], label=f"{sb} / {m}")
            if hline is not None:
                ax.axhline(hline, color="gray", lw=0.8)
            ax.set_xticks(range(len(sizes)))
            ax.set_xticklabels([human(s) for s in sizes], fontsize=8)
            ax.set_ylabel(ylabel)
            ax.set_title(title, fontsize=10)
            ax.grid(axis="y", alpha=0.3)
            ax.legend(fontsize=7, ncol=2, framealpha=0.85, loc="lower right")

        bars(axes[0][1], "eff_vs_best_pct", "% so voi payload tot nhat",
             "Hieu qua cua tung payload (100% = payload nhanh nhat cung cau hinh)", 100)
        bars(axes[1][0], "cv_pct", "CV = do lech chuan / trung binh (%)",
             "Do on dinh giua cac lan do (thap hon = on dinh hon)")
        bars(axes[1][1], "e2e_over_compute_pct", "E2E / Compute (%)",
             "Hieu suat con lai khi tinh ca I/O", 100)
        fig.suptitle(f"Hieu qua theo payload - {lb}")
        fig.tight_layout()
        path = os.path.join(a.out, f"single_{safe(lb)}.png")
        fig.savefig(path, dpi=a.dpi)
        plt.close(fig)
        saved.append(path)

    print("Da tao:")
    for p in saved:
        print("  ", p)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn, out in (("cross", cmd_cross, "docs/results/cross"),
                          ("single", cmd_single, "docs/results/single")):
        p = sub.add_parser(name)
        p.add_argument("csv", nargs="+")
        p.add_argument("--names", help="ten nhan cho tung CSV, cach nhau bang dau phay")
        p.add_argument("--out", default=out)
        p.add_argument("--dpi", type=int, default=150)
        if name == "cross":
            p.add_argument("--baseline", help="nhan lam goc (mac dinh: CSV dau tien)")
        p.set_defaults(fn=fn)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()