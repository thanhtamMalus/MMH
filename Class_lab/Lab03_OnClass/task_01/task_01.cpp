#include <openssl/bn.h>
#include <openssl/err.h>

#include <iostream>
#include <string>
#include <limits>
#include <cctype>

using namespace std;

// ============================================================
// Read a nonnegative decimal integer into an OpenSSL BIGNUM.
// Returns nullptr if the input is invalid or allocation fails.
// ============================================================
BIGNUM* readNumber(const string& prompt)
{
    string s;

    cout << prompt;

    if (!(cin >> s))
        return nullptr;

        
    if (s.empty())
        return nullptr;

    for (unsigned char c : s)
    {
        if (!isdigit(c))
        {
            cout << "Error: enter a nonnegative decimal integer.\n";
            return nullptr;
        }
    }

    BIGNUM* x = nullptr;

    if (BN_dec2bn(&x, s.c_str()) == 0)
    {
        BN_free(x);
        return nullptr;
    }

    return x;
}

// ============================================================
// Print a BIGNUM as a decimal integer.
// BN_bn2dec() allocates memory; release it using OPENSSL_free().
// ============================================================
void printNumber(const char* label, const BIGNUM* x)
{
    char* s = BN_bn2dec(x);

    if (s != nullptr)
    {
        cout << label << s << '\n';
        OPENSSL_free(s);
    }
    else
    {
        cout << "Error converting number to decimal.\n";
    }
}

// ============================================================
// Generate a probable prime with the requested bit length.
// This function is intended for the educational RSA lab.
// ============================================================
BIGNUM* generatePrime(int bits)
{
    if (bits < 2)
        return nullptr;

    BIGNUM* p = BN_new();

    if (p == nullptr)
        return nullptr;

    // safe = 0: generate an ordinary probable prime.
    if (BN_generate_prime_ex(
            p,
            bits,
            0,
            nullptr,
            nullptr,
            nullptr) != 1)
    {
        BN_free(p);
        return nullptr;
    }

    return p;
}

// ============================================================
// Read an integer choice with basic input validation.
// ============================================================
bool readChoice(int& choice)
{
    cout << "Choose: ";

    if (cin >> choice)
        return true;

    if (cin.eof())
        return false;

    cout << "Error: enter an integer menu choice.\n";

    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    return true;
}

// ============================================================
// Main CLI program.
// ============================================================
int main()
{
    // BN_CTX stores temporary values used by OpenSSL operations.
    BN_CTX* ctx = BN_CTX_new();

    if (ctx == nullptr)
    {
        cerr << "Error: cannot create BN_CTX.\n";
        ERR_print_errors_fp(stderr);
        return 1;
    }

    while (true)
    {
        cout << "\n====================================\n"
             << "       OpenSSL BIGNUM CLI Lab\n"
             << "====================================\n"
             << "1. Modular addition:       (a + b) mod m\n"
             << "2. Modular subtraction:    (a - b) mod m\n"
             << "3. Modular multiplication: (a * b) mod m\n"
             << "4. Greatest common divisor: gcd(a, b)\n"
             << "5. Modular exponentiation: a^b mod m\n"
             << "6. Modular inverse:        a^(-1) mod m\n"
             << "7. Generate a large prime for RSA\n"
             << "0. Exit\n";

        int choice;

        if (!readChoice(choice))
            break;

        if (choice == 0)
            break;

        if (choice < 1 || choice > 7)
        {
            cout << "Invalid choice. Select 0 through 7.\n";
            continue;
        }

        // ----------------------------------------------------
        // Option 7: generate a probable prime.
        // ----------------------------------------------------
        if (choice == 7)
        {
            int bits;

            cout << "Enter prime size in bits (e.g. 512, 1024): ";

            if (!(cin >> bits))
            {
                if (cin.eof())
                    break;

                cout << "Invalid bit length.\n";
                cin.clear();
                cin.ignore(
                    numeric_limits<streamsize>::max(), '\n');
                continue;
            }

            if (bits < 2 || bits > 16384)
            {
                cout << "Bit length must be between 2 and 16384.\n";
                continue;
            }

            cout << "Generating a " << bits
                 << "-bit probable prime...\n";

            BIGNUM* p = generatePrime(bits);

            if (p != nullptr)
            {
                cout << "Prime generated successfully.\n";
                cout << "Actual bit length: " << BN_num_bits(p) << '\n';
                printNumber("p = ", p);

                BN_free(p);
            }
            else
            {
                cerr << "Prime generation failed.\n";
                ERR_print_errors_fp(stderr);
            }

            continue;
        }

        // ----------------------------------------------------
        // Read the first operand.
        // ----------------------------------------------------
        BIGNUM* a = readNumber("Enter a: ");

        if (a == nullptr)
        {
            if (cin.eof())
                break;

            continue;
        }

        BIGNUM* b = nullptr;
        BIGNUM* m = nullptr;
        BIGNUM* r = BN_new();

        if (r == nullptr)
        {
            cerr << "Error: cannot allocate result.\n";
            BN_free(a);
            break;
        }

        bool ok = false;
        bool inverseFailure = false;

        // ----------------------------------------------------
        // Option 4: GCD(a, b).
        // ----------------------------------------------------
        if (choice == 4)
        {
            b = readNumber("Enter b: ");

            if (b != nullptr)
                ok = (BN_gcd(r, a, b, ctx) == 1);
        }
        else
        {
            // Option 6 needs only a and modulus m.
            if (choice != 6)
                b = readNumber("Enter b: ");

            // All other operations need a modulus.
            m = readNumber("Enter modulus m: ");

            if (m != nullptr && !BN_is_zero(m))
            {
                if (choice == 1 && b != nullptr)
                {
                    // r = (a + b) mod m
                    ok = (BN_mod_add(r, a, b, m, ctx) == 1);
                }
                else if (choice == 2 && b != nullptr)
                {
                    // r = (a - b) mod m
                    ok = (BN_mod_sub(r, a, b, m, ctx) == 1);
                }
                else if (choice == 3 && b != nullptr)
                {
                    // r = (a * b) mod m
                    ok = (BN_mod_mul(r, a, b, m, ctx) == 1);
                }
                else if (choice == 5 && b != nullptr)
                {
                    // r = a^b mod m
                    ok = (BN_mod_exp(r, a, b, m, ctx) == 1);
                }
                else if (choice == 6)
                {
                    // r = a^(-1) mod m, if the inverse exists.
                    BIGNUM* inv =
                        BN_mod_inverse(nullptr, a, m, ctx);

                    if (inv != nullptr)
                    {
                        BN_free(r);
                        r = inv;
                        ok = true;
                    }
                    else
                    {
                        inverseFailure = true;
                        ERR_clear_error();
                    }
                }
            }
            else if (m != nullptr)
            {
                cout << "Error: modulus must be greater than zero.\n";
            }
        }

        // ----------------------------------------------------
        // Display result or error.
        // ----------------------------------------------------
        if (ok)
        {
            printNumber("Result = ", r);
        }
        else if (inverseFailure)
        {
            cout << "No modular inverse exists for these values.\n"
                 << "An inverse exists exactly when gcd(a, m) = 1.\n";
        }
        else if (m != nullptr && BN_is_zero(m))
        {
            // The invalid modulus message was already printed
            // only if the modulus was successfully parsed as zero.
        }
        else
        {
            cout << "Operation failed. Check the input values.\n";

            if (ERR_peek_error() != 0)
                ERR_print_errors_fp(stderr);
        }

        // Release memory allocated for this operation.
        BN_free(a);
        BN_free(b);
        BN_free(m);
        BN_free(r);
    }

    BN_CTX_free(ctx);

    cout << "\nProgram terminated.\n";

    return 0;
}
