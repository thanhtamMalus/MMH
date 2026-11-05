#!/usr/bin/env python3
"""Analyze benchmark results: compute statistics and generate plots."""
import argparse
import sys
import os
import csv
import json
import numpy as np
from scipy import stats
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def parse_args():
    parser = argparse.ArgumentParser(description='Analyze rsatool benchmark results')
    parser.add_argument('--in', dest='input_file', required=True,
                        help='Path to raw benchmark CSV')
    parser.add_argument('--out-dir', default='results',
                        help='Output directory for summary and figures')
    parser.add_argument('--fig-dir', default='report/figures',
                        help='Directory for figure files (PNG/SVG)')
    return parser.parse_args()

def read_bench_csv(input_file):
    """Read raw benchmark CSV into structured data."""
    rows = []
    with open(input_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows

def write_csv(path, rows, fieldnames):
    """Write rows to CSV file."""
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

def compute_summary(rows, group_by):
    """Compute mean, std, median, min, max, and 95% CI for each group."""
    groups = {}
    for row in rows:
        key = tuple(row[g] for g in group_by)
        if key not in groups:
            groups[key] = []
        # Parse time_ns as integer
        try:
            groups[key].append(int(row['time_ns']))
        except (ValueError, KeyError):
            continue
    
    summary = []
    for key, values in groups.items():
        if not values:
            continue
        n = len(values)
        mean = np.mean(values)
        std = np.std(values, ddof=1) if n > 1 else 0.0
        median = np.median(values)
        min_val = min(values)
        max_val = max(values)
        # 95% CI using t-distribution
        sem = std / np.sqrt(n) if n > 0 else 0.0
        ci_lower, ci_upper = stats.t.interval(0.95, n-1, loc=mean, scale=sem) if n > 1 else (mean, mean)
        
        summary.append({
            'group': key,
            'n': n,
            'mean': mean,
            'std': std,
            'median': median,
            'min': min_val,
            'max': max_val,
            'ci_lower': ci_lower,
            'ci_upper': ci_upper,
        })
    return summary

def plot_latency_rsa_keygen(rows, fig_dir, output_name="latency_rsa_keygen"):
    """Plot keygen latency for RSA-3072 vs 4096."""
    os.makedirs(fig_dir, exist_ok=True)
    
    data_3072 = []
    data_4096 = []
    for row in rows:
        try:
            rsa_bits = int(row.get('rsa_bits', 0))
            time_ns = int(row.get('time_ns', 0))
        except (ValueError, TypeError):
            continue
        if rsa_bits == 3072:
            data_3072.append(time_ns)
        elif rsa_bits == 4096:
            data_4096.append(time_ns)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    if data_3072:
        ax.boxplot([data_3072], labels=['3072'], widths=0.5)
    if data_4096:
        ax.boxplot([data_4096], labels=['4096'], widths=0.5)
    
    ax.set_ylabel('Time (ns)')
    ax.set_title('RSA Keygen Latency: 3072 vs 4096')
    ax.set_yscale('log')
    
    plt.tight_layout()
    plt.savefig(os.path.join(fig_dir, f"{output_name}.png"), dpi=200)
    plt.savefig(os.path.join(fig_dir, f"{output_name}.svg"), dpi=200)
    plt.close()

def plot_latency_rsa_encdec(rows, fig_dir, output_name="latency_rsa_encdec"):
    """Plot encrypt/decrypt latency for RSA-3072 vs 4096."""
    os.makedirs(fig_dir, exist_ok=True)
    
    # Group by op (encrypt/decrypt) and rsa_bits
    data = {}
    for row in rows:
        try:
            rsa_bits = int(row.get('rsa_bits', 0))
            op = row.get('op', '')
            time_ns = int(row.get('time_ns', 0))
        except (ValueError, TypeError):
            continue
        key = (op, rsa_bits)
        if key not in data:
            data[key] = []
        data[key].append(time_ns)
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    ops = ['encrypt', 'decrypt']
    bits_list = [3072, 4096]
    
    for i, bits in enumerate(bits_list):
        for j, op in enumerate(ops):
            key = (op, bits)
            if key in data and data[key]:
                vals = data[key]
                positions = [i * 2 + j for _ in vals]
                ax.boxplot(vals, positions=[i * 2 + j], labels=[f"{bits}-bit {op}"],
                          widths=0.3)
    
    ax.set_ylabel('Time (ns)')
    ax.set_title('RSA OAEP Encrypt/Decrypt Latency')
    ax.set_yscale('log')
    ax.legend()
    
    plt.tight_layout()
    plt.savefig(os.path.join(fig_dir, f"{output_name}.png"), dpi=200)
    plt.savefig(os.path.join(fig_dir, f"{output_name}.svg"), dpi=200)
    plt.close()

def plot_throughput_aesgcm(rows, fig_dir, output_name="throughput_aesgcm"):
    """Plot AES-256-GCM throughput vs data size."""
    os.makedirs(fig_dir, exist_ok=True)
    
    # Group by size
    size_data = {}
    for row in rows:
        try:
            size = int(row.get('size_bytes', 0))
            throughput = float(row.get('throughput_mib_s', 0))
        except (ValueError, TypeError):
            continue
        if size not in size_data:
            size_data[size] = []
        size_data[size].append(throughput)
    
    sizes = sorted(size_data.keys())
    means = []
    for s in sizes:
        vals = size_data[s]
        means.append(np.mean(vals) if vals else 0)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(sizes, means, 'bo-')
    ax.set_xlabel('Data size (bytes)')
    ax.set_ylabel('Throughput (MiB/s)')
    ax.set_title('AES-256-GCM Throughput vs Data Size')
    ax.grid(True, alpha=0.3)
    
    # Set log scale for x-axis if we have wide range
    if sizes and sizes[0] < sizes[-1] and sizes[-1] / sizes[0] > 10:
        ax.set_xscale('log')
    
    plt.tight_layout()
    plt.savefig(os.path.join(fig_dir, f"{output_name}.png"), dpi=200)
    plt.savefig(os.path.join(fig_dir, f"{output_name}.svg"), dpi=200)
    plt.close()

def plot_latency_hybrid_total(rows, fig_dir, output_name="latency_hybrid_total"):
    """Plot hybrid total latency vs data size."""
    os.makedirs(fig_dir, exist_ok=True)
    
    # Group by data size and rsa_bits
    data = {}
    for row in rows:
        try:
            rsa_bits = int(row.get('rsa_bits', 0))
            size = int(row.get('size_bytes', 0))
            time_ns = int(row.get('time_ns', 0))
        except (ValueError, TypeError):
            continue
        key = (rsa_bits, size)
        if key not in data:
            data[key] = []
        data[key].append(time_ns)
    
    # Sort by size
    keys = sorted(data.keys(), key=lambda k: k[1])
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    for rsa_bits in [3072, 4096]:
        times = []
        labels = []
        for bits, size in keys:
            if bits == rsa_bits:
                times.append(data.get((bits, size), [0]))
                labels.append(f"{bits}-bit, {size} bytes")
        
        if times and times[0]:
            ax.boxplot(times, labels=labels, widths=0.8)
    
    ax.set_ylabel('Time (ns)')
    ax.set_title('Hybrid Encrypt/Decrypt Latency')
    ax.set_yscale('log')
    ax.legend([f"RSA-{b}" for b in [3072, 4096]])
    plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
    
    plt.tight_layout()
    plt.savefig(os.path.join(fig_dir, f"{output_name}.png"), dpi=200)
    plt.savefig(os.path.join(fig_dir, f"{output_name}.svg"), dpi=200)
    plt.close()

def main():
    args = parse_args()
    rows = read_bench_csv(args.input_file)
    
    # Write summary CSV
    summary = compute_summary(rows, ['rsa_bits', 'op', 'size_bytes'])
    write_csv(os.path.join(args.out_dir, 'bench_summary.csv'), summary,
              ['group', 'n', 'mean', 'std', 'median', 'min', 'max', 'ci_lower', 'ci_upper'])
    
    # Generate plots
    plot_latency_rsa_keygen(rows, args.fig_dir)
    plot_latency_rsa_encdec(rows, args.fig_dir)
    plot_throughput_aesgcm(rows, args.fig_dir)
    plot_latency_hybrid_total(rows, args.fig_dir)
    
    # Write summary markdown
    md_path = os.path.join(args.out_dir, 'bench_summary.md')
    with open(md_path, 'w') as f:
        f.write("# Benchmark Summary\n\n")
        for s in summary:
            f.write(f"## {s['group']}\n")
            f.write(f"- n: {s['n']}\n")
            f.write(f"- mean: {s['mean']:.2f} ns\n")
            f.write(f"- std: {s['std']:.2f} ns\n")
            f.write(f"- median: {s['median']:.2f} ns\n")
            f.write(f"- min: {s['min']:.2f} ns\n")
            f.write(f"- max: {s['max']:.2f} ns\n")
            f.write(f"- 95% CI: [{s['ci_lower']:.2f}, {s['ci_upper']:.2f}] ns\n")
            f.write("\n")
    
    print("Benchmark analysis complete.")
    print("  Summary CSV: bench_summary.csv")
    print("  Summary MD: bench_summary.md")
    print("  Figures in:", args.fig_dir)

if __name__ == "__main__":
    main()