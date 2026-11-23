#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <limits>

#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

using namespace std;

/*
 * ================================================================
 * EC GROUP TOOL - STUDENT VERSION
 * ================================================================
 * Purpose:
 *   1. List elliptic curves built into OpenSSL.
 *   2. Show the domain parameters of one elliptic curve.
 *   3. Show EC-based key-exchange groups available to TLS 1.2/1.3.
 *
 * Main EC notation used in this program:
 *
 *     E: y^2 = x^3 + ax + b  (mod p)
 *
 *     p : prime modulus of the finite field F_p
 *     a,b : curve coefficients
 *     G : generator/base point
 *     n : order of G
 *     h : cofactor
 *
 * This file intentionally keeps each menu option in a separate
 * function so students can study one concept at a time.
 * ================================================================
 */

// ----------------------------------------------------------------
// Helper 1: Print an OpenSSL BIGNUM in hexadecimal
// ----------------------------------------------------------------
void print_bn_hex(const string& label, const BIGNUM* value)
{
    char* hex = BN_bn2hex(value);

    if (hex != nullptr) {
        cout << label << " = 0x" << hex << '\n';
        OPENSSL_free(hex);
    }
}

// ----------------------------------------------------------------
// Helper 2: Clear the rest of the current input line
// ----------------------------------------------------------------
void clear_input_line()
{
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

// =================================================================
// OPTION 1 - List all built-in elliptic curves
// =================================================================
void option1_list_curves()
{
    // Step 1: Ask OpenSSL how many curves are available.
    size_t number_of_curves = EC_get_builtin_curves(nullptr, 0);

    // Step 2: Create storage for the curve information.
    vector<EC_builtin_curve> curves(number_of_curves);

    // Step 3: Ask OpenSSL to fill the vector.
    EC_get_builtin_curves(curves.data(), number_of_curves);

    // Step 4: Display the result.
    cout << "\n========== OPTION 1: OPENSSL EC CURVES ==========\n";
    cout << "Total curves: " << number_of_curves << "\n\n";

    for (size_t i = 0; i < curves.size(); ++i) {
        const char* short_name = OBJ_nid2sn(curves[i].nid);

        cout << i + 1 << ". "
             << (short_name ? short_name : "unknown")
             << " - " << curves[i].comment << '\n';
    }

    cout << "=================================================\n";
}

// =================================================================
// OPTION 2 - Show domain parameters of one EC curve
// =================================================================
void option2_show_curve_parameters()
{
    string curve_name;

    cout << "\nEnter curve name (example: secp256r1, secp384r1): ";
    getline(cin, curve_name);

    // -------------------------------------------------------------
    // Step 1: Convert the text name to an OpenSSL curve identifier.
    // -------------------------------------------------------------
    int nid = OBJ_txt2nid(curve_name.c_str());

    // TLS says "secp256r1"; OpenSSL calls this curve "prime256v1".
    if (nid == NID_undef && curve_name == "secp256r1") {
        nid = OBJ_txt2nid("prime256v1");
    }

    if (nid == NID_undef) {
        cerr << "Unknown curve: " << curve_name << '\n';
        return;
    }

    // -------------------------------------------------------------
    // Step 2: Create the EC_GROUP object.
    // EC_GROUP represents the mathematical elliptic-curve group.
    // -------------------------------------------------------------
    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);

    if (group == nullptr) {
        cerr << "Cannot create EC_GROUP.\n";
        ERR_print_errors_fp(stderr);
        return;
    }

    // -------------------------------------------------------------
    // Step 3: Allocate numbers that will hold p, a, b, Gx, Gy, n, h.
    // -------------------------------------------------------------
    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* p  = BN_new();
    BIGNUM* a  = BN_new();
    BIGNUM* b  = BN_new();
    BIGNUM* gx = BN_new();
    BIGNUM* gy = BN_new();
    BIGNUM* n  = BN_new();
    BIGNUM* h  = BN_new();

    bool memory_ok =
        ctx != nullptr && p != nullptr && a != nullptr && b != nullptr &&
        gx != nullptr && gy != nullptr && n != nullptr && h != nullptr;

    if (!memory_ok) {
        cerr << "Memory allocation failed.\n";
    }
    else {
        // ---------------------------------------------------------
        // Step 4: Read the curve equation parameters p, a and b.
        // ---------------------------------------------------------
        bool curve_ok =
            EC_GROUP_get_curve(group, p, a, b, ctx) == 1;

        // ---------------------------------------------------------
        // Step 5: Read the generator G = (Gx, Gy).
        // ---------------------------------------------------------
        const EC_POINT* G = EC_GROUP_get0_generator(group);

        bool generator_ok =
            G != nullptr &&
            EC_POINT_get_affine_coordinates(group, G, gx, gy, ctx) == 1;

        // ---------------------------------------------------------
        // Step 6: Read group order n and cofactor h.
        // ---------------------------------------------------------
        bool group_ok =
            EC_GROUP_get_order(group, n, ctx) == 1 &&
            EC_GROUP_get_cofactor(group, h, ctx) == 1;

        if (!curve_ok || !generator_ok || !group_ok) {
            cerr << "Cannot read all EC domain parameters.\n";
            ERR_print_errors_fp(stderr);
        }
        else {
            // -----------------------------------------------------
            // Step 7: Display the mathematical domain parameters.
            // -----------------------------------------------------
            cout << "\n========== OPTION 2: EC DOMAIN PARAMETERS ==========\n";
            cout << "Curve input name : " << curve_name << '\n';
            cout << "OpenSSL name     : " << OBJ_nid2sn(nid) << '\n';
            cout << "OpenSSL NID      : " << nid << '\n';

            cout << "\n[1] Finite field F_p\n";
            print_bn_hex("p", p);

            cout << "\n[2] Curve equation\n";
            cout << "y^2 = x^3 + ax + b (mod p)\n";
            print_bn_hex("a", a);
            print_bn_hex("b", b);

            cout << "\n[3] Generator point G\n";
            print_bn_hex("Gx", gx);
            print_bn_hex("Gy", gy);

            cout << "\n[4] Group parameters\n";
            print_bn_hex("n (order of G)", n);
            print_bn_hex("h (cofactor)", h);

            cout << "\n[5] Size information\n";
            cout << "Field size : " << BN_num_bits(p) << " bits\n";
            cout << "Order size : " << BN_num_bits(n) << " bits\n";
            cout << "====================================================\n";
        }
    }

    // -------------------------------------------------------------
    // Step 8: Free every OpenSSL object created by this function.
    // -------------------------------------------------------------
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(gx);
    BN_free(gy);
    BN_free(n);
    BN_free(h);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
}

// ----------------------------------------------------------------
// Helper 3: Convert a string to lowercase
// ----------------------------------------------------------------
string to_lower_copy(string text)
{
    transform(text.begin(), text.end(), text.begin(),
              [](unsigned char c) {
                  return static_cast<char>(tolower(c));
              });

    return text;
}

// ----------------------------------------------------------------
// Helper 4: Check whether a TLS supported group is EC-based
//
// Notes for students:
//   - X25519 and X448 are Montgomery-curve groups.
//   - Named Weierstrass/Brainpool curves can be tested by creating
//     an EC_GROUP from their OpenSSL curve identifier.
// ----------------------------------------------------------------
bool is_ec_tls_group(const char* tls_group_name)
{
    if (tls_group_name == nullptr) {
        return false;
    }

    string original_name = tls_group_name;
    string lower_name = to_lower_copy(original_name);

    // X25519 and X448 are EC-based but are not created with
    // EC_GROUP_new_by_curve_name() in the same way as named curves.
    if (lower_name == "x25519" || lower_name == "x448") {
        return true;
    }

    // Resolve the TLS group name directly with the OpenSSL object API.
    int nid = OBJ_txt2nid(original_name.c_str());
    if (nid == NID_undef && lower_name == "secp256r1") {
        nid = OBJ_txt2nid("prime256v1");
    }

    // OpenSSL may expose Brainpool TLS 1.3 names with "tls13" suffix.
    const string suffix = "tls13";

    if (nid == NID_undef &&
        lower_name.size() > suffix.size() &&
        lower_name.compare(lower_name.size() - suffix.size(),
                           suffix.size(), suffix) == 0) {

        string base_name =
            original_name.substr(0, original_name.size() - suffix.size());

        nid = OBJ_txt2nid(base_name.c_str());
    }

    if (nid == NID_undef) {
        return false;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);

    if (group == nullptr) {
        return false;
    }

    EC_GROUP_free(group);
    return true;
}

// ----------------------------------------------------------------
// Print EC-based groups for one selected TLS version
// ----------------------------------------------------------------
void print_tls_ec_groups(int tls_version, const string& version_name)
{
    // Step 1: Create a TLS context.
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_method());

    if (ssl_ctx == nullptr) {
        cerr << "Cannot create SSL_CTX.\n";
        ERR_print_errors_fp(stderr);
        return;
    }

    // Step 2: Restrict the context to exactly one TLS version.
    bool version_ok =
        SSL_CTX_set_min_proto_version(ssl_ctx, tls_version) == 1 &&
        SSL_CTX_set_max_proto_version(ssl_ctx, tls_version) == 1;

    if (!version_ok) {
        cerr << "Cannot configure " << version_name << ".\n";
        SSL_CTX_free(ssl_ctx);
        return;
    }

    // Step 3: Create a stack for OpenSSL to return group names.
    STACK_OF(OPENSSL_CSTRING)* group_names =
        sk_OPENSSL_CSTRING_new_null();

    if (group_names == nullptr) {
        cerr << "Cannot allocate the TLS group list.\n";
        SSL_CTX_free(ssl_ctx);
        return;
    }

    // Step 4: Get the groups implemented by this OpenSSL build.
    if (SSL_CTX_get0_implemented_groups(ssl_ctx, 0, group_names) != 1) {
        cerr << "Cannot retrieve TLS supported groups.\n";
        ERR_print_errors_fp(stderr);

        sk_OPENSSL_CSTRING_free(group_names);
        SSL_CTX_free(ssl_ctx);
        return;
    }

    // Step 5: Keep only EC-based groups.
    cout << "\n========== " << version_name
         << " EC-BASED KEY-EXCHANGE GROUPS ==========\n";

    int ec_count = 0;

    for (int i = 0; i < sk_OPENSSL_CSTRING_num(group_names); ++i) {
        const char* name = sk_OPENSSL_CSTRING_value(group_names, i);

        if (is_ec_tls_group(name)) {
            cout << ++ec_count << ". " << name << '\n';
        }
    }

    if (ec_count == 0) {
        cout << "No EC-based groups found.\n";
    }

    cout << "Total: " << ec_count << '\n';
    cout << "====================================================\n";

    // Step 6: Free the OpenSSL objects created here.
    sk_OPENSSL_CSTRING_free(group_names);
    SSL_CTX_free(ssl_ctx);
}

// =================================================================
// OPTION 3 - Show TLS 1.2 and TLS 1.3 EC-based groups
// =================================================================
void option3_list_tls_ec_groups()
{
    cout << "\nTLS 'supported groups' are used during key exchange.\n";
    cout << "This option filters the OpenSSL list to EC-based groups.\n";

    print_tls_ec_groups(TLS1_2_VERSION, "TLS 1.2");
    print_tls_ec_groups(TLS1_3_VERSION, "TLS 1.3");
}

// ----------------------------------------------------------------
// Print the main menu
// ----------------------------------------------------------------
void print_menu()
{
    cout << "\n=================================================\n";
    cout << "       OPENSSL ELLIPTIC-CURVE GROUP TOOL\n";
    cout << "=================================================\n";
    cout << "1. List built-in EC curves\n";
    cout << "2. Show EC domain parameters\n";
    cout << "3. List EC-based TLS key-exchange groups\n";
    cout << "4. Exit\n";
    cout << "=================================================\n";
    cout << "Select option: ";
}

// =================================================================
// MAIN PROGRAM
// =================================================================
int main()
{
    cout << "OpenSSL version: "
         << OpenSSL_version(OPENSSL_VERSION) << '\n';

    while (true) {
        print_menu();

        int choice;

        if (!(cin >> choice)) {
            cout << "Invalid input. Please enter a number from 1 to 4.\n";
            cin.clear();
            clear_input_line();
            continue;
        }

        clear_input_line();

        switch (choice) {
            case 1:
                option1_list_curves();
                break;

            case 2:
                option2_show_curve_parameters();
                break;

            case 3:
                option3_list_tls_ec_groups();
                break;

            case 4:
                cout << "Program finished.\n";
                return 0;

            default:
                cout << "Please select 1, 2, 3 or 4.\n";
        }
    }
}
