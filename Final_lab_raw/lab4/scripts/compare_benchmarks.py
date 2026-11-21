#!/usr/bin/env python3
# compare_benchmarks.py - Lab 4: so sanh benchmark theo payload (1 MiB / 100 MiB / 1 GiB)
# trong tung he dieu hanh va giua Linux vs Windows.
#
# Doc cac file *.csv do `hashtool --bench` sinh ra. Moi file co dang:
#   === BENCHMARK RESULTS (sha3-256, 1048576 bytes, mode=memory, 100 runs) ===
#   Throughput (MB/s): mean=..., median=..., stddev=..., 95% CI=[lo, hi]
#   Latency per op (ms): mean=..., ...
#   CPU utilization (%): 100.0 ...
#   Digest: ...
#   # run,seconds,MB_per_s
#   1,0.002696,388.90
#   ...
# => algo / payload / mode duoc lay tu dong header, KHONG phu thuoc ten file.
#
# Dau ra (trong --out-dir, mac dinh figures/compare/):
#   payload_<os>.png      throughput + CPU theo payload cua tung OS (error bar = 95% CI)
#   runs_<os>.png         phan bo tung lan chay (boxplot) cua tung OS
#   os_vs_os_<payload>.png  Linux vs Windows cho tung payload (1mib, 100mib, 1gib)
#   os_ratio_heatmap.png  ti le Linux/Windows cho cac cau hinh co ca hai OS
#   compare_table.md      bang chi tiet (mean, CI, ti le, CPU) cho moi cau hinh

import argparse
import glob
import math
import os
import re
import sys

import matplotlib
matplotlib.use('Agg')  # headless
import matplotlib.pyplot as plt
from matplotlib.colors import TwoSlopeNorm
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
import numpy as np

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

plt.rcParams['font.sans-serif'] = ['DejaVu Sans']
plt.rcParams['hatch.linewidth'] = 0.6

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OS_NAMES = ('Linux', 'Windows')
OS_COLORS = {'Linux': '#2E86AB', 'Windows': '#F18F01'}
SIZE_COLORS = ['#4C72B0', '#DD8452', '#55A868', '#C44E52', '#8172B3', '#937860']
MODE_ORDER = {'memory': 0, 'stream': 1, 'mmap': 2}
ALGO_ORDER = ['sha224', 'sha256', 'sha384', 'sha512',
              'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512',
              'shake128', 'shake256']

HEADER_RE = re.compile(r'===\s*BENCHMARK RESULTS\s*\((.*?),\s*(\d+)\s*bytes,\s*mode=(\w+),\s*(\d+)\s*runs\)')
SAMPLE_RE = re.compile(r'^\d+,[\d.eE+-]+,[\d.eE+-]+$')


# ----------------------------------------------------------------------------
# Doc va parse
# ----------------------------------------------------------------------------
def read_text_auto(path):
    """Doc text, tu nhan dien encoding qua BOM (PowerShell 5.1 ghi UTF-16 LE)."""
    with open(path, 'rb') as f:
        raw = f.read()
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        return raw.decode('utf-16')
    if raw.startswith(b'\xef\xbb\xbf'):
        return raw.decode('utf-8-sig')
    return raw.decode('utf-8', errors='replace')


def stats_from_line(line):
    num = r'([\d.eE+-]+)'
    out = {}
    for key in ('mean', 'median', 'stddev'):
        m = re.search(key + '=' + num, line)
        out[key] = float(m.group(1)) if m else None
    m = re.search(r'95% CI=\[\s*' + num + r'\s*,\s*' + num + r'\s*\]', line)
    out['ci_lo'], out['ci_hi'] = (float(m.group(1)), float(m.group(2))) if m else (None, None)
    return out if out['mean'] is not None else None


def parse_file(path):
    text = read_text_auto(path)
    m = HEADER_RE.search(text)
    if not m:
        return None
    rec = {
        'algo': m.group(1).strip().lower(),
        'bytes': int(m.group(2)),
        'mode': m.group(3).lower(),
        'runs': int(m.group(4)),
        'thr': None, 'lat': None, 'cpu': None,
        'samples': [],
        'file': os.path.basename(path),
    }
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('Throughput'):
            rec['thr'] = stats_from_line(line)
        elif line.startswith('Latency'):
            rec['lat'] = stats_from_line(line)
        elif line.startswith('CPU utilization'):
            mc = re.search(r':\s*([\d.]+)', line)
            rec['cpu'] = float(mc.group(1)) if mc else None
        elif SAMPLE_RE.match(line):
            rec['samples'].append(float(line.split(',')[2]))
    return rec if rec['thr'] else None


def load_dir(directory):
    """Tra ve dict {(algo, bytes, mode): record}."""
    index = {}
    if not os.path.isdir(directory):
        return index
    for path in sorted(glob.glob(os.path.join(directory, '*.csv'))):
        rec = parse_file(path)
        if rec is None:
            print(f'  ! Bo qua (khong dung dinh dang): {path}')
            continue
        key = (rec['algo'], rec['bytes'], rec['mode'])
        if key in index:
            print(f"  ! Trung cau hinh {key}: {index[key]['file']} bi thay boi {rec['file']}")
        index[key] = rec
    return index


# ----------------------------------------------------------------------------
# Tien ich hien thi
# ----------------------------------------------------------------------------
def size_label(n):
    for unit, div in (('GiB', 2 ** 30), ('MiB', 2 ** 20), ('KiB', 2 ** 10)):
        if n >= div and n % div == 0:
            return f'{n // div} {unit}'
    return f'{n} B'


def cfg_label(nbytes, mode):
    return f'{size_label(nbytes)} · {mode}'


def algo_key(a):
    return (ALGO_ORDER.index(a), a) if a in ALGO_ORDER else (len(ALGO_ORDER), a)


def cfg_key(c):
    return (c[0], MODE_ORDER.get(c[1], 9))


def make_style(all_sizes):
    """Mau theo payload; mmap = gach cheo."""
    color_of = {s: SIZE_COLORS[i % len(SIZE_COLORS)] for i, s in enumerate(sorted(all_sizes))}

    def style(nbytes, mode):
        return color_of[nbytes], ('//' if mode == 'mmap' else '')
    return style


def cfg_legend(cfgs, style):
    handles = []
    for nbytes, mode in cfgs:
        col, hatch = style(nbytes, mode)
        handles.append(Patch(facecolor=col, hatch=hatch, edgecolor='black', label=cfg_label(nbytes, mode)))
    return handles


def ci_err(rec):
    t = rec['thr']
    if t['ci_lo'] is None or t['ci_hi'] is None:
        return 0.0, 0.0
    return max(t['mean'] - t['ci_lo'], 0.0), max(t['ci_hi'] - t['mean'], 0.0)


def save(fig, path, dpi):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fig.savefig(path, dpi=dpi, bbox_inches='tight')
    plt.close(fig)
    print(f'  ✓ {path}')


# ----------------------------------------------------------------------------
# Hinh 1: payload trong tung OS
# ----------------------------------------------------------------------------
def plot_payload(os_name, index, style, out_path, dpi):
    recs = list(index.values())
    algos = sorted({r['algo'] for r in recs}, key=algo_key)
    cfgs = sorted({(r['bytes'], r['mode']) for r in recs}, key=cfg_key)
    max_n = max(sum(1 for c in cfgs if (a,) + c in index) for a in algos)
    w = 0.82 / max_n
    rot = 0 if max_n <= 2 else 90

    fig, (ax1, ax2) = plt.subplots(
        2, 1, sharex=True, figsize=(max(9, 1.5 * len(algos) + 3), 9),
        gridspec_kw={'height_ratios': [3, 1.3]})

    cpu_max = 100.0
    for xi, a in enumerate(algos):
        present = [c for c in cfgs if (a,) + c in index]
        n = len(present)
        for j, c in enumerate(present):
            r = index[(a,) + c]
            x = xi + (j - (n - 1) / 2) * w
            col, hatch = style(*c)
            lo, hi = ci_err(r)
            mean = r['thr']['mean']
            ax1.bar(x, mean, w * 0.92, yerr=[[lo], [hi]], capsize=2.5, color=col, hatch=hatch,
                    edgecolor='black', linewidth=0.6, error_kw=dict(elinewidth=1, ecolor='black'))
            ax1.annotate(f'{mean:.0f}', (x, mean + hi), xytext=(0, 4), textcoords='offset points',
                         ha='center', va='bottom', fontsize=7, rotation=rot)
            if r['cpu'] is not None:
                ax2.bar(x, r['cpu'], w * 0.92, color=col, hatch=hatch, edgecolor='black', linewidth=0.6)
                cpu_max = max(cpu_max, r['cpu'])
                ax2.annotate(f"{r['cpu']:.0f}", (x, r['cpu']), xytext=(0, 3), textcoords='offset points',
                             ha='center', va='bottom', fontsize=7, rotation=rot)

    ax1.set_ylabel('Throughput (MB/s)')
    ax1.set_title(f'{os_name} - throughput theo payload (error bar = 95% CI)')
    ax1.margins(y=0.15)
    ax1.grid(axis='y', alpha=0.3)
    ax1.set_axisbelow(True)

    ax2.axhline(100, ls='--', color='gray', lw=0.8)
    ax2.set_ylim(0, cpu_max * 1.2)
    ax2.set_ylabel('CPU utilization (%)')
    ax2.set_title('CPU time / wall time (100% = 1 core busy; mmap/stream thap hon => cho I/O)', fontsize=9)
    ax2.grid(axis='y', alpha=0.3)
    ax2.set_axisbelow(True)
    ax2.set_xticks(range(len(algos)))
    ax2.set_xticklabels(algos, rotation=30, ha='right')

    fig.tight_layout()
    fig.legend(handles=cfg_legend(cfgs, style), title='Payload · mode', loc='upper center',
               bbox_to_anchor=(0.5, 0.0), ncol=min(len(cfgs), 5), fontsize=8)
    save(fig, out_path, dpi)


# ----------------------------------------------------------------------------
# Hinh 2: phan bo tung lan chay
# ----------------------------------------------------------------------------
def plot_runs(os_name, index, style, out_path, dpi):
    items = sorted((r for r in index.values() if r['samples']),
                   key=lambda r: (r['bytes'], MODE_ORDER.get(r['mode'], 9), algo_key(r['algo'])))
    if not items:
        return
    fig, ax = plt.subplots(figsize=(10, max(4, 0.42 * len(items) + 1.8)))
    box_kw = dict(patch_artist=True, showmeans=True, widths=0.6,
                  flierprops=dict(marker='.', markersize=3, alpha=0.5),
                  medianprops=dict(color='black'),
                  meanprops=dict(marker='D', markerfacecolor='white', markeredgecolor='black', markersize=4))
    data = [r['samples'] for r in items]
    try:  # matplotlib >= 3.10
        bp = ax.boxplot(data, orientation='horizontal', **box_kw)
    except TypeError:  # matplotlib cu hon
        bp = ax.boxplot(data, vert=False, **box_kw)
    for patch, r in zip(bp['boxes'], items):
        col, hatch = style(r['bytes'], r['mode'])
        patch.set_facecolor(col)
        patch.set_hatch(hatch)
        patch.set_alpha(0.85)
    ax.set_yticklabels([f"{r['algo']} · {cfg_label(r['bytes'], r['mode'])}" for r in items])
    ax.invert_yaxis()
    ax.set_xlabel('Throughput moi lan chay (MB/s)')
    ax.set_title(f'{os_name} - phan bo {items[0]["runs"]} lan chay (hop = IQR, vach den = median, kim cuong = mean)')
    ax.grid(axis='x', alpha=0.3)
    ax.set_axisbelow(True)

    cfgs = sorted({(r['bytes'], r['mode']) for r in items}, key=cfg_key)
    handles = cfg_legend(cfgs, style) + [Line2D([0], [0], marker='D', color='w', markerfacecolor='white',
                                                markeredgecolor='black', markersize=5, label='mean')]
    fig.tight_layout()
    fig.legend(handles=handles, loc='upper center', bbox_to_anchor=(0.5, 0.0), ncol=min(len(handles), 6), fontsize=8)
    save(fig, out_path, dpi)


# ----------------------------------------------------------------------------
# Hinh 3: Linux vs Windows cho tung payload
# ----------------------------------------------------------------------------
def plot_os_vs_os(nbytes, ia, ib, name_a, name_b, out_path, dpi):
    keys = sorted({k for k in list(ia) + list(ib) if k[1] == nbytes},
                  key=lambda k: (MODE_ORDER.get(k[2], 9), algo_key(k[0])))
    if not keys:
        return False
    n = len(keys)
    w = 0.38
    rot = 0 if n <= 6 else 90
    fig, ax = plt.subplots(figsize=(max(8, 1.15 * n + 3), 6.2))

    top = 0.0
    ratios = {}
    for i, k in enumerate(keys):
        vals = {}
        for name, idx, dx in ((name_a, ia, -w / 2), (name_b, ib, w / 2)):
            r = idx.get(k)
            if r is None:
                ax.text(i + dx, 0, 'n/a', rotation=90, ha='center', va='bottom', fontsize=7, color='gray')
                continue
            lo, hi = ci_err(r)
            mean = r['thr']['mean']
            ax.bar(i + dx, mean, w * 0.95, yerr=[[lo], [hi]], capsize=2.5, color=OS_COLORS[name],
                   edgecolor='black', linewidth=0.5, error_kw=dict(elinewidth=1, ecolor='black'))
            ax.annotate(f'{mean:.0f}', (i + dx, mean + hi), xytext=(0, 4), textcoords='offset points',
                        ha='center', va='bottom', fontsize=7, rotation=rot)
            vals[name] = mean
            top = max(top, mean + hi)
        if len(vals) == 2:
            ratios[i] = vals[name_a] / vals[name_b]
    ax.set_ylim(0, top * 1.18 if top else 1)
    ax.set_xticks(range(n))
    ax.set_xticklabels([f'{k[0]}\n{k[2]}\n' + (f'{ratios[i]:.2f}×' if i in ratios else '—')
                        for i, k in enumerate(keys)], fontsize=8)
    ax.set_ylabel('Throughput (MB/s)')
    ax.set_title(f'Payload {size_label(nbytes)} - {name_a} vs {name_b} (error bar = 95% CI; '
                 f'dong cuoi truc x = {name_a}/{name_b})', fontsize=10)
    ax.grid(axis='y', alpha=0.3)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.legend(handles=[Patch(facecolor=OS_COLORS[name_a], edgecolor='black', label=name_a),
                        Patch(facecolor=OS_COLORS[name_b], edgecolor='black', label=name_b)],
               loc='upper center', bbox_to_anchor=(0.5, 0.0), ncol=2)
    save(fig, out_path, dpi)
    return True


# ----------------------------------------------------------------------------
# Hinh 4: heatmap ti le A/B
# ----------------------------------------------------------------------------
def plot_ratio_heatmap(ia, ib, name_a, name_b, out_path, dpi):
    common = set(ia) & set(ib)
    if not common:
        return False
    algos = sorted({k[0] for k in common}, key=algo_key)
    cfgs = sorted({(k[1], k[2]) for k in common}, key=cfg_key)
    M = np.full((len(algos), len(cfgs)), np.nan)
    for i, a in enumerate(algos):
        for j, c in enumerate(cfgs):
            k = (a,) + c
            if k in common:
                M[i, j] = ia[k]['thr']['mean'] / ib[k]['thr']['mean']
    L = np.log2(M)
    vmax = max(float(np.nanmax(np.abs(L))), 0.25)
    cmap = plt.get_cmap('coolwarm').copy()
    cmap.set_bad('#eeeeee')
    fig, ax = plt.subplots(figsize=(1.7 * len(cfgs) + 3, 0.6 * len(algos) + 2.6))
    im = ax.imshow(np.ma.masked_invalid(L), cmap=cmap, aspect='auto',
                   norm=TwoSlopeNorm(vcenter=0, vmin=-vmax, vmax=vmax))
    for i in range(len(algos)):
        for j in range(len(cfgs)):
            if np.isfinite(M[i, j]):
                col = 'white' if abs(L[i, j]) > 0.6 * vmax else 'black'
                ax.text(j, i, f'{M[i, j]:.2f}×', ha='center', va='center', fontsize=9, color=col)
            else:
                ax.text(j, i, '–', ha='center', va='center', color='gray')
    ax.set_xticks(range(len(cfgs)))
    ax.set_xticklabels([cfg_label(*c).replace(' · ', '\n') for c in cfgs], fontsize=8)
    ax.set_yticks(range(len(algos)))
    ax.set_yticklabels(algos)
    ax.set_title(f'Ti le throughput {name_a} / {name_b}  (>1× => {name_a} nhanh hon)')
    ticks = [t for t in (0.25, 0.5, 1, 2, 4, 8) if -vmax <= math.log2(t) <= vmax]
    cb = fig.colorbar(im, ax=ax)
    cb.set_ticks([math.log2(t) for t in ticks])
    cb.set_ticklabels([f'{t}×' for t in ticks])
    save(fig, out_path, dpi)
    return True


# ----------------------------------------------------------------------------
# Bang Markdown
# ----------------------------------------------------------------------------
def fmt(r):
    if r is None:
        return '—', '—'
    t = r['thr']
    ci = f"[{t['ci_lo']:.2f}, {t['ci_hi']:.2f}]" if t['ci_lo'] is not None else 'N/A'
    return f"{t['mean']:.2f}", ci


def fmt_cpu(r):
    return '—' if r is None or r['cpu'] is None else f"{r['cpu']:.0f}"


def build_table(ia, ib, name_a, name_b):
    keys = sorted(set(ia) | set(ib), key=lambda k: (k[1], MODE_ORDER.get(k[2], 9), algo_key(k[0])))
    lines = [
        f'| Payload | Mode | Algorithm | {name_a} MB/s | {name_a} 95% CI | {name_b} MB/s | {name_b} 95% CI '
        f'| {name_a}/{name_b} | CI khong giao nhau* | {name_a} CPU % | {name_b} CPU % |',
        '|---|---|---|---|---|---|---|---|---|---|---|',
    ]
    for k in keys:
        ra, rb = ia.get(k), ib.get(k)
        ma, ca = fmt(ra)
        mb, cb = fmt(rb)
        ratio, sig = '—', '—'
        if ra and rb:
            ratio = f"{ra['thr']['mean'] / rb['thr']['mean']:.2f}×"
            ta, tb = ra['thr'], rb['thr']
            if None not in (ta['ci_lo'], ta['ci_hi'], tb['ci_lo'], tb['ci_hi']):
                sig = 'co' if (ta['ci_lo'] > tb['ci_hi'] or tb['ci_lo'] > ta['ci_hi']) else 'khong'
        lines.append(f'| {size_label(k[1])} | {k[2]} | {k[0]} | {ma} | {ca} | {mb} | {cb} | {ratio} | {sig} '
                     f'| {fmt_cpu(ra)} | {fmt_cpu(rb)} |')
    lines.append('')
    lines.append('\\* "co" = hai khoang tin cay 95% khong giao nhau (khac biet co y nghia thong ke ro rang). '
                 '"—" = cau hinh chi co o mot he dieu hanh.')
    return '\n'.join(lines)


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        prog='compare_benchmarks.py',
        description='So sanh benchmark Lab 4 theo payload (trong tung OS) va giua Linux vs Windows.',
        epilog=('Vi du:\n'
                '  python3 scripts/compare_benchmarks.py\n'
                '  python3 scripts/compare_benchmarks.py --linux results/linux --windows results/windows\n'
                '  python3 scripts/compare_benchmarks.py -o out/compare --dpi 200'),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--linux', metavar='DIR', default=os.path.join(LAB_DIR, 'results', 'linux'),
                   help='Thu muc CSV cua Linux (mac dinh: results/linux)')
    p.add_argument('--windows', metavar='DIR', default=os.path.join(LAB_DIR, 'results', 'windows'),
                   help='Thu muc CSV cua Windows (mac dinh: results/windows)')
    p.add_argument('-o', '--out-dir', metavar='DIR', default=os.path.join(LAB_DIR, 'figures', 'compare'),
                   help='Thu muc dau ra cho hinh va bang (mac dinh: figures/compare)')
    p.add_argument('--dpi', type=int, default=150, help='Do phan giai anh (mac dinh: 150)')
    return p.parse_args()


def main():
    args = parse_args()
    print('=== compare_benchmarks.py - Lab 4 ===')
    dirs = {'Linux': os.path.abspath(args.linux), 'Windows': os.path.abspath(args.windows)}
    data = {}
    for name in OS_NAMES:
        print(f'Doc {name}: {dirs[name]}')
        if not os.path.isdir(dirs[name]):
            print(f'  ! Khong tim thay thu muc, bo qua {name}.')
        data[name] = load_dir(dirs[name])
        print(f'  -> {len(data[name])} cau hinh')

    if not any(data.values()):
        print('Khong co du lieu benchmark. Hay chay run_all truoc.')
        sys.exit(1)

    out = os.path.abspath(args.out_dir)
    os.makedirs(out, exist_ok=True)
    all_sizes = {k[1] for idx in data.values() for k in idx}
    style = make_style(all_sizes)

    print('\nHinh payload / phan bo tung OS:')
    for name in OS_NAMES:
        if data[name]:
            tag = name.lower()
            plot_payload(name, data[name], style, os.path.join(out, f'payload_{tag}.png'), args.dpi)
            plot_runs(name, data[name], style, os.path.join(out, f'runs_{tag}.png'), args.dpi)

    a, b = OS_NAMES
    if data[a] and data[b]:
        print('\nHinh so sanh Linux vs Windows:')
        for nbytes in sorted(all_sizes):
            tag = size_label(nbytes).replace(' ', '').lower()
            plot_os_vs_os(nbytes, data[a], data[b], a, b, os.path.join(out, f'os_vs_os_{tag}.png'), args.dpi)
        if not plot_ratio_heatmap(data[a], data[b], a, b, os.path.join(out, 'os_ratio_heatmap.png'), args.dpi):
            print('  ! Khong co cau hinh chung giua hai OS, bo qua heatmap.')
    else:
        print('\n! Chi co du lieu cua mot OS, bo qua phan so sanh Linux vs Windows.')

    table_path = os.path.join(out, 'compare_table.md')
    with open(table_path, 'w', encoding='utf-8') as f:
        f.write(build_table(data[a], data[b], a, b) + '\n')
    print(f'\n✓ Bang chi tiet: {table_path}')
    print('=== Done ===')


if __name__ == '__main__':
    main()