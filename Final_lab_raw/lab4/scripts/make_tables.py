#!/usr/bin/env python3
# make_tables.py - Read results/*.csv from Lab 4 benchmark và sinh bảng Markdown + đồ thị error bars
# Người dùng chạy sau khi dán kết quả từ run_all.* then tôi hoặc người dùng chạy thủ công.

import os
import sys
import argparse
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

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RESULTS_ROOT = os.path.join(LAB_DIR, 'results')

def read_text_auto(path):
  """Đọc file text, tự nhận diện encoding qua BOM.
  PowerShell 5.1 ghi file bằng toán tử *> / > ở dạng UTF-16 LE (có BOM FF FE),
  còn Linux/pwsh 7 ghi UTF-8, nên cần xử lý cả hai."""
  with open(path, 'rb') as f:
    raw = f.read()
  if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
    return raw.decode('utf-16')          # utf-16 tự bỏ BOM và nhận LE/BE
  if raw.startswith(b'\xef\xbb\xbf'):
    return raw.decode('utf-8-sig')
  return raw.decode('utf-8', errors='replace')

def parse_csv_benchmark(csv_path):
  """Parse file kết quả benchmark từ run_all.sh/.ps1 output.
  Đợi format: các dòng chứa mean, median, stddev, 95% CI."""
  results = {}
  content = read_text_auto(csv_path)
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

def collect_all_results(results_dir):
  """Thu thập tất cả kết quả CSV từ thư mục results_dir."""
  all_results = {}
  csv_files = glob.glob(os.path.join(results_dir, '*.csv'))
  if not csv_files:
    print(f"⚠️  No CSV files found in {results_dir}")
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

def generate_plot(results, output_path='figures/hash_benchmark.png', title='Hash Benchmark: Throughput với 95% CI (Student-t)'):
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
  ax.set_title(title)
  
  # In giá trị mean lên cột
  for i, bar in enumerate(bars):
    text = f"{means[i]:.1f} MB/s"
    ax.text(means[i] + 5, y_pos[i], text, va='center', fontsize=8)
  
  # Lưu figure
  os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
  fig.savefig(output_path, dpi=150, bbox_inches='tight')
  matplotlib.pyplot.close(fig)
  print(f"✓ Plot saved to {output_path}")

def default_results_dir():
  """Mặc định: results/linux nếu có, ngược lại results/."""
  linux_dir = os.path.join(DEFAULT_RESULTS_ROOT, 'linux')
  return linux_dir if os.path.isdir(linux_dir) else DEFAULT_RESULTS_ROOT

def parse_args():
  p = argparse.ArgumentParser(
    prog='make_tables.py',
    description='Đọc các file CSV benchmark (Lab 4), sinh bảng Markdown và đồ thị error bars.',
    epilog=(
      'Ví dụ:\n'
      '  python3 scripts/make_tables.py\n'
      '  python3 scripts/make_tables.py -r results/windows\n'
      '  python3 scripts/make_tables.py -r results/linux -t out/linux.md -p out/linux.png\n'
      '  python3 scripts/make_tables.py -r /duong/dan/khac --title "SHA-2 vs SHA-3 (Linux)"'
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter,
  )
  p.add_argument('-r', '--results-dir', metavar='DIR', default=None,
                 help='Thư mục chứa các file *.csv (mặc định: results/linux nếu có, nếu không là results/)')
  p.add_argument('-t', '--table', metavar='FILE', default=None,
                 help='File Markdown đầu ra (mặc định: <results-dir>/benchmark_table.md)')
  p.add_argument('-p', '--plot', metavar='FILE', default=None,
                 help='File ảnh đầu ra (mặc định: figures/hash_benchmark_<tên thư mục>.png)')
  p.add_argument('--title', default=None, help='Tiêu đề đồ thị')
  return p.parse_args()

def main():
  args = parse_args()
  print("=== make_tables.py - Lab 4 ===")

  results_dir = os.path.abspath(args.results_dir) if args.results_dir else default_results_dir()
  if not os.path.isdir(results_dir):
    print(f"❌ Không tìm thấy thư mục: {results_dir}")
    sys.exit(2)
  label = os.path.basename(results_dir.rstrip('/\\')) or 'results'
  print(f"Đọc CSV từ: {results_dir}")

  results = collect_all_results(results_dir)

  if not results:
    print("⚠️  No benchmark results found. Run run_all.sh/.ps1 first.")
    sys.exit(1)

  # Hiển thị bảng Markdown
  md_table = generate_markdown_table(results)
  print("\n--- Benchmark Table (Markdown) ---")
  print(md_table)

  # Lưu bảng Markdown vào file
  table_path = os.path.abspath(args.table) if args.table else os.path.join(results_dir, 'benchmark_table.md')
  os.makedirs(os.path.dirname(table_path), exist_ok=True)
  with open(table_path, 'w', encoding='utf-8') as f:
    f.write(md_table + '\n')
  print(f"\n✓ Table saved to {table_path}")

  # Tạo đồ thị
  plot_path = os.path.abspath(args.plot) if args.plot else os.path.join(LAB_DIR, 'figures', f'hash_benchmark_{label}.png')
  title = args.title or f'Hash Benchmark ({label}): Throughput với 95% CI (Student-t)'
  generate_plot(results, plot_path, title)

  print("\n=== Done ===")
  print("Kết quả:")
  print(f"  - Bảng: {table_path}")
  print(f"  - Hình: {plot_path}")
  print("\nBạn có thể chèn bảng Markdown này vào báo cáo lab4/report_lab4.md.")

if __name__ == '__main__':
  main()