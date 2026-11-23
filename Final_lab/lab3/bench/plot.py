#!/usr/bin/env python3
"""
plot.py — Vẽ biểu đồ benchmark từ bench/results/bench_results.csv
Yêu cầu: pandas, numpy, scipy, matplotlib

Cài đặt:
    pip install pandas numpy scipy matplotlib

Chạy:
    python bench/plot.py
"""

import sys
import pathlib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

RESULTS_DIR = pathlib.Path(__file__).parent / "results"
CSV_PATH    = RESULTS_DIR / "bench_results.csv"


def load_data() -> pd.DataFrame:
    if not CSV_PATH.exists():
        print(f"ERROR: {CSV_PATH} not found. Run bench_rsatool first.", file=sys.stderr)
        sys.exit(1)
    df = pd.read_csv(CSV_PATH)
    print(f"Loaded {len(df)} rows from {CSV_PATH}")
    return df


def plot_rsa_latency(df: pd.DataFrame):
    """Bar chart: RSA keygen / encrypt / decrypt latency for 3072 and 4096."""
    rsa_ops = ["keygen", "oaep_encrypt", "oaep_decrypt"]
    bits_list = [3072, 4096]

    fig, axes = plt.subplots(1, 3, figsize=(14, 5))
    fig.suptitle("RSA Latency (mean ± 95% CI)", fontsize=14)

    for ax, op in zip(axes, rsa_ops):
        rows = df[df["benchmark"] == op]
        means = []
        cis   = []
        for bits in bits_list:
            r = rows[rows["bits"] == bits]
            means.append(r["mean_us"].values[0] / 1000.0 if len(r) else 0)
            cis.append(r["ci95_us"].values[0] / 1000.0  if len(r) else 0)

        bars = ax.bar([str(b) for b in bits_list], means, yerr=cis,
                      capsize=6, color=["#4C72B0", "#DD8452"])
        ax.set_title(op.replace("_", " ").title())
        ax.set_xlabel("Modulus bits")
        ax.set_ylabel("Latency (ms)")
        ax.set_yscale("log")
        ax.yaxis.set_major_formatter(ticker.FuncFormatter(
            lambda x, _: f"{x:.3g} ms"))
        for bar, m, c in zip(bars, means, cis):
            ax.text(bar.get_x() + bar.get_width() / 2, m + c + m * 0.02,
                    f"{m:.2f}", ha="center", va="bottom", fontsize=9)

    plt.tight_layout()
    out = RESULTS_DIR / "rsa_latency.png"
    plt.savefig(out, dpi=150)
    print(f"Saved {out}")
    plt.close()


def plot_aes_throughput(df: pd.DataFrame):
    """Bar chart: AES-256-GCM throughput for 1 KiB, 1 MiB, 100 MiB."""
    aes_ops = ["aes_gcm_1KiB", "aes_gcm_1MiB", "aes_gcm_100MiB"]
    labels  = ["1 KiB", "1 MiB", "100 MiB"]

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.suptitle("AES-256-GCM Encrypt Throughput (mean ± 95% CI)", fontsize=14)

    tps  = []
    cis  = []
    for op in aes_ops:
        r = df[df["benchmark"] == op]
        if len(r):
            tps.append(r["throughput_MiB_s"].values[0])
            # CI in throughput: propagate roughly as ci/mean * throughput
            m_us = r["mean_us"].values[0]
            ci_us = r["ci95_us"].values[0]
            size  = r["size_bytes"].values[0]
            tp    = (size / (1024**2)) / (m_us / 1e6)
            tp_ci = tp * (ci_us / m_us) if m_us > 0 else 0
            cis.append(tp_ci)
        else:
            tps.append(0)
            cis.append(0)

    bars = ax.bar(labels, tps, yerr=cis, capsize=6,
                  color=["#55A868", "#C44E52", "#8172B3"])
    ax.set_xlabel("Plaintext size")
    ax.set_ylabel("Throughput (MiB/s)")
    ax.set_yscale("log")
    for bar, tp, ci in zip(bars, tps, cis):
        ax.text(bar.get_x() + bar.get_width() / 2, tp + ci + tp * 0.02,
                f"{tp:.0f}", ha="center", va="bottom", fontsize=9)

    plt.tight_layout()
    out = RESULTS_DIR / "aes_throughput.png"
    plt.savefig(out, dpi=150)
    print(f"Saved {out}")
    plt.close()


def plot_hybrid_latency(df: pd.DataFrame):
    """Bar chart: hybrid encrypt+decrypt total latency for 1 KiB, 1 MiB, 100 MiB."""
    ops    = ["hybrid_1KiB", "hybrid_1MiB", "hybrid_100MiB"]
    labels = ["1 KiB", "1 MiB", "100 MiB"]

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.suptitle("Hybrid Encrypt+Decrypt Total Latency (mean ± 95% CI)", fontsize=14)

    ms_vals = []
    ci_ms   = []
    for op in ops:
        r = df[df["benchmark"] == op]
        if len(r):
            ms_vals.append(r["mean_us"].values[0] / 1000.0)
            ci_ms.append(r["ci95_us"].values[0] / 1000.0)
        else:
            ms_vals.append(0)
            ci_ms.append(0)

    bars = ax.bar(labels, ms_vals, yerr=ci_ms, capsize=6,
                  color=["#4C72B0", "#DD8452", "#55A868"])
    ax.set_xlabel("Payload size")
    ax.set_ylabel("Total latency (ms)")
    ax.set_yscale("log")
    for bar, m, c in zip(bars, ms_vals, ci_ms):
        ax.text(bar.get_x() + bar.get_width() / 2, m + c + m * 0.02,
                f"{m:.1f} ms", ha="center", va="bottom", fontsize=9)

    plt.tight_layout()
    out = RESULTS_DIR / "hybrid_latency.png"
    plt.savefig(out, dpi=150)
    print(f"Saved {out}")
    plt.close()


def main():
    df = load_data()
    print(df.to_string())
    print()

    plot_rsa_latency(df)
    plot_aes_throughput(df)
    plot_hybrid_latency(df)

    print("\nAll plots saved to", RESULTS_DIR)


if __name__ == "__main__":
    main()

