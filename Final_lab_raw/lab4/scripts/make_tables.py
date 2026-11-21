#!/usr/bin/env python3
# make_tables.py - Read results/*.csv from Lab 4 benchmark và sinh bảng Markdown + đồ thị error bars
# Người dùng chạy sau khi dán kết quả từ run_all.* then tôi hoặc người dùng chạy thủ công.

import os
import sys
import csv
import glob
import re
import json
import statistics
import matplotlib
matplotlib.use('Agg')  # headless backend
import matplotlib.pyplot
import numpy as np

if hasattr(sys.stdout, 'reconfigure'):
  sys.stdout.reconfigure(encoding='utf-8')  # avoid UnicodeEncodeError on Windows consoles

# Thiết lập font để hiển thị ký tự Unicode/tiếng Việt nếu cần
matplotlib.pyplot.rcParams['font.sans-serif'] = ['DejaVu Sans']
matplotlib.pyplot.rcParams['figure.autolayout'] = True

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'results')
LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def parse_csv_benchmark(csv_path):
  """Parse file kết quả benchmark từ run_all.sh/.ps1 output.
  Đợi format: các dòng chứa mean, median, stddev, 95% CI."""
  results = {}
  with open(csv_path, 'r', encoding='utf-8') as f:
    content = f.read()
  # Tìm các cặp key::value
  # Ví dụ: "Throughput (MB/s): mean=523.4, median=521.1, stddev=12.3, 95% CI=[518.2, 528.6]"
  patterns = {
    'mean': r'mean=([\d.]+)',
    'median': r'median=([\d.]+)',
    'stddev': r'stddev=([\d.]+)',
    'ci_lower': r'95% CI=\[([\d.]+)',
    'ci_upper': r', ([\d.]+)\]$',
  }
  # Parse đơn giản hơn: tách lines
  for line in content.split('\n'):
    line = line.strip()
    if 'mean=' in line:
      # Trích xuất thông tin
      m_mean = re.search(r'mean=([\d.]+)', line)
      m_median = re.search(r'median=([\d.]+)', line)
      m_stddev = re.search(r'stddev=([\d.]+)', line)
      m_ci = re.search(r'95% CI=\[([\d.]+),\s*([\d.]+)\]', line)
      if m_mean:
        key = os.path.basename(csv_path)
        # Loại bỏ phần đường dẫn kết quả
        results[key] = {
          'mean': float(m_mean.group(1)),
          'median': float(m_median.group(1)) if m_median else None,
          'stddev': float(m_stddev.group(1)) if m_stddev else None,
          'ci_lower': float(m_ci.group(1)) if m_ci else None,
          'ci_upper': float(m_ci.group(2)) if m_ci else None,
        }
        break  # first line = Throughput (MB/s); later lines are latency
  return results

def collect_all_results():
  """Thu thập tất cả kết quả CSV từ thư mục results/."""
  all_results = {}
  csv_files = glob.glob(os.path.join(RESULTS_DIR, '*.csv'))
  if not csv_files:
    print(f"⚠️  No CSV files found in {RESULTS_DIR}")
    return all_results
  
  for csv_path in sorted(csv_files):
    name = os.path.basename(csv_path).replace('.csv', '')
    res = parse_csv_benchmark(csv_path)
    if res:
      all_results[name] = next(iter(res.values()))  # flatten {file: stats} -> stats
  
  return all_results

def generate_markdown_table(results):
  """Sinh bảng Markdown kết quả benchmark."""
  if not results:
    return "| Algorithm | Mean (MB/s) | Median (MB/s) | Std Dev | 95% CI |\n|-----------|-------------|----------------|-----------|---------|\n|---|---|---|---|---|"
  
  lines = ["| Algorithm | Mean (MB/s) | Median (MB/s) | Std Dev | 95% CI |"]
  lines.append("|---|---|---|---|---|")
  
  # Sắp xếp theo mean giảm dần
  sorted_algos = sorted(results.keys(), key=lambda k: results[k]['mean'], reverse=True)
  
  for algo in sorted_algos:
    r = results[algo]
    mean = r['mean']
    median = r['median'] if r['median'] is not None else 'N/A'
    stddev = r['stddev'] if r['stddev'] is not None else 'N/A'
    ci = f"[{r['ci_lower']:.2f}, {r['ci_upper']:.2f}]" if r['ci_lower'] is not None and r['ci_upper'] is not None else 'N/A'
    lines.append(f"| {algo} | {mean:.2f} | {median:.2f} | {stddev:.2f} | {ci} |")
  
  return '\n'.join(lines)

def generate_plot(results, output_path='figures/hash_benchmark.png'):
  """Sinh đồ thị throughput với error bars (95% CI)."""
  if not results:
    print("⚠️  No results to plot.")
    return
  
  sorted_algos = sorted(results.keys(), key=lambda k: results[k]['mean'], reverse=True)
  means = [results[a]['mean'] for a in sorted_algos]
  medians = [results[a]['median'] if results[a]['median'] is not None else 0 for a in sorted_algos]
  stddevs = [results[a]['stddev'] if results[a]['stddev'] is not None else 0 for a in sorted_algos]
  ci_lower = [results[a]['ci_lower'] if results[a]['ci_lower'] is not None else 0 for a in sorted_algos]
  ci_upper = [results[a]['ci_upper'] if results[a]['ci_upper'] is not None else 0 for a in sorted_algos]
  
  # Error bar: ci_upper - mean và mean - ci_lower
  error_lower = [m - l for m, l in zip(means, ci_lower)]
  error_upper = [u - m for u, m in zip(ci_upper, means)]
  # Matplotlib errorbar chấp nhận lỗi đồng đều hoặc tuple (lo, hi)
  errors = [error_lower, error_upper]  # shape (2, n) as matplotlib expects
  
  y_pos = np.arange(len(sorted_algos))
  
  fig, ax = matplotlib.pyplot.subplots(figsize=(10, 6))
  bars = ax.barh(y_pos, means, xerr=errors, capsize=5, color='steelblue', alpha=0.7)
  ax.set_yticks(y_pos)
  ax.set_yticklabels(sorted_algos)
  ax.set_xlabel('Throughput (MB/s)')
  ax.set_title('Hash Benchmark: Throughput với 95% CI (Student-t)')
  
  # In giá trị mean lên cột
  for i, bar in enumerate(bars):
    text = f"{means[i]:.1f} MB/s"
    ax.text(means[i] + 5, y_pos[i], text, va='center', fontsize=8)
  
  # Lưu figure
  os.makedirs(os.path.dirname(output_path), exist_ok=True)
  fig.savefig(output_path, dpi=150, bbox_inches='tight')
  matplotlib.pyplot.close(fig)
  print(f"✓ Plot saved to {output_path}")

def main():
  print("=== make_tables.py - Lab 4 ===")
  results = collect_all_results()
  
  if not results:
    print("⚠️  No benchmark results found. Run run_all.sh/.ps1 first.")
    sys.exit(1)
  
  # Hiển thị bảng Markdown
  md_table = generate_markdown_table(results)
  print("\n--- Benchmark Table (Markdown) ---")
  print(md_table)
  
  # Lưu bảng Markdown vào file
  table_path = os.path.join(LAB_DIR, 'results', 'benchmark_table.md')
  with open(table_path, 'w', encoding='utf-8') as f:
    f.write(md_table + '\n')
  print(f"\n✓ Table saved to {table_path}")
  
  # Tạo đồ thị
  plot_path = os.path.join(LAB_DIR, 'figures', 'hash_benchmark.png')
  generate_plot(results, plot_path)
  
  print("\n=== Done ===")
  print("Kết quả:")
  print(f"  - Bảng: {table_path}")
  print(f"  - Hình: {plot_path}")
  print("\nBạn có thể chèn bảng Markdown này vào báo cáo lab4/report_lab4.md.")
  print("Và chèn hình hash_benchmark.png vào figures/.")

if __name__ == '__main__':
  main()