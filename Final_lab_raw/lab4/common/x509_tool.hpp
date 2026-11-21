#ifndef X509_TOOL_HPP
#define X509_TOOL_HPP
#include <string>

// Analyse an X.509 certificate (PEM or DER). Fills `report` with a human-readable report.
// Returns 0 = PASS, 1 = FAIL (fail closed: anything that cannot be verified is FAIL).
// Throws IoError if the file cannot be read.
int x509_analyze(const std::string& cert_path, const std::string& issuer_path,
                 bool check_time, std::string& report);
#endif
