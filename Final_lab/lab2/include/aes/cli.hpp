#ifndef AES_CLI_HPP
#define AES_CLI_HPP

#include <string>
#include <vector>

namespace aes {
namespace cli {

/**
 * @brief Main entry point for CLI commands.
 * Runs directly without invoking shell, ideal for cross-platform unit testing.
 * @return Exit code:
 *  0 = Success
 *  1 = Parameter error
 *  2 = Key/IV error
 *  3 = I/O error
 *  4 = Counter overflow
 *  5 = KAT failure
 */
int run(const std::vector<std::string>& args);
int run(int argc, char* argv[]);

void print_help(const char* prog_name);

} // namespace cli
} // namespace aes

#endif // AES_CLI_HPP
