#pragma once
#include <string>
#include <vector>

#include "aescore.h"

struct BenchConfig {
  std::vector<aescore::Mode> modes;
  std::vector<size_t> sizes;
  int runs = 1000;                                 // timed blocks per (mode,dir,size)
  double warmup_sec = 1.0;                         // warm-up per (mode,size)
  size_t batch_bytes = 16ull * 1024 * 1024;        // target bytes per timed block
  size_t max_ops = 1000;                           // ops_per_block cap (1000 for small payloads)
  size_t key_bits = 256;
  bool do_enc = true;                              // run dir=enc tasks
  bool do_dec = true;                              // run dir=dec tasks (after all enc tasks of the mode)
  bool with_io = false;                            // enc only: include file read/write per op
  std::string csv_path;
  std::string tmp_dir;
  bool verbose = false;
};

std::vector<aescore::Mode> bench_all_modes();
std::vector<size_t> bench_default_sizes();   // 1K 4K 16K 256K 1M 8M
int run_bench(const BenchConfig& cfg);
