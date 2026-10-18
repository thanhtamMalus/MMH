#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <numeric>

// Example payload size (bytes)
constexpr size_t PAYLOAD_SIZE = 16; // e.g., AES block size

// Dummy encryption function (replace with your real one for testing algorithms)
void encryptDummy() {
    volatile int x = 0;
    for (int i = 0; i < 100; i++) x += i; // just some work
}

// Compute statistics
struct Stats {
    double mean;
    double median;
    double stdev;
    double ci95_low;
    double ci95_high;
};

Stats computeStats(const std::vector<double>& samples) {
    Stats s{};
    size_t n = samples.size();

    // Mean
    s.mean = std::accumulate(samples.begin(), samples.end(), 0.0) / n;

    // Median
    std::vector<double> sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    s.median = (n % 2 == 0) ? 
        (sorted[n/2 - 1] + sorted[n/2]) / 2.0 : 
        sorted[n/2];

    // Std dev
    double sq_sum = 0.0;
    for (double v : samples) sq_sum += (v - s.mean) * (v - s.mean);
    s.stdev = std::sqrt(sq_sum / (n - 1));

    // 95% CI (normal approximation)
    double margin = 1.96 * s.stdev / std::sqrt(n);
    s.ci95_low = s.mean - margin;
    s.ci95_high = s.mean + margin;

    return s;
}

int main() {
    constexpr int BLOCK_SIZE = 1000;   // ops per block
    constexpr int N_TRIALS   = 30;     // repeat count

    std::vector<double> latencies; // µs/op
    std::vector<double> throughputs; // MB/s

    // Warm-up (1–2 seconds equivalent work)
    auto warm_start = std::chrono::high_resolution_clock::now();
    while (true) {
        encryptDummy();
        auto warm_end = std::chrono::high_resolution_clock::now();
        double warm_sec = std::chrono::duration_cast<std::chrono::seconds>(warm_end - warm_start).count();
        if (warm_sec >= 2) break;
    }

    // Benchmark loop
    for (int trial = 0; trial < N_TRIALS; ++trial) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < BLOCK_SIZE; ++i) {
            encryptDummy(); // replace with real encryption/decryption
        }
        auto end = std::chrono::high_resolution_clock::now();

        auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        // Latency per op (µs)
        double avg_latency = static_cast<double>(duration_us) / BLOCK_SIZE;
        latencies.push_back(avg_latency);

        // Throughput (MB/s)
        double total_time_sec = static_cast<double>(duration_us) / 1e6;
        double throughput = (BLOCK_SIZE * PAYLOAD_SIZE / (1024.0 * 1024.0)) / total_time_sec;
        throughputs.push_back(throughput);
    }

    // Compute stats
    Stats latencyStats = computeStats(latencies);
    Stats throughputStats = computeStats(throughputs);

    // Print results
    std::cout << "=== Encryption Benchmark ===\n";
    std::cout << "Latency per op (µs):\n"
              << "  Mean   = " << latencyStats.mean
              << ", Median = " << latencyStats.median
              << ", Stdev  = " << latencyStats.stdev
              << ", 95% CI = [" << latencyStats.ci95_low << ", " << latencyStats.ci95_high << "]\n";

    std::cout << "Throughput (MB/s):\n"
              << "  Mean   = " << throughputStats.mean
              << ", Median = " << throughputStats.median
              << ", Stdev  = " << throughputStats.stdev
              << ", 95% CI = [" << throughputStats.ci95_low << ", " << throughputStats.ci95_high << "]\n";

    return 0;
}
