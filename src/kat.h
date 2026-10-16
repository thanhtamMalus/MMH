#pragma once
#include <string>

// Runs Known Answer Tests from a JSON file. Prints PASS/FAIL per case and a summary table.
// Returns 0 when every case passes, 1 otherwise (including unreadable/malformed files).
int run_kat(const std::string& json_path, bool verbose);
