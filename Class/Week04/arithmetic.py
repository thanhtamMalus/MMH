#!/usr/bin/env python3

# Helper: Convert a byte (0..255) into a polynomial string, e.g.:
#   0x57 => "x^6 + x^4 + x^2 + x + 1"

def byte_to_polynomial_str(b: int) -> str:
    """
    Return a string representing the polynomial in GF(2)[x] form.
    For example, 0x57 (01010111) -> x^6 + x^4 + x^2 + x + 1
    """
    terms = []
    for power in range(7, -1, -1):
        if b & (1 << power):
            if power == 0:
                terms.append("1")
            elif power == 1:
                terms.append("x")
            else:
                terms.append(f"x^{power}")
    return " + ".join(terms) if terms else "0"

def byte_to_binary_str(b: int) -> str:
    """
    Return a string with the 8-bit binary representation of b, splitting
    the first 4 bits from the last 4 bits for readability.
    E.g. 0x57 -> '0101 0111'
    """
    bits = f"{b:08b}"
    return bits[:4] + " " + bits[4:]

# Addition (XOR) and Multiplication in GF(2^8)

def gf_add(a: int, b: int) -> int:
    """
    Add (or subtract) two bytes in GF(2^8) => XOR
    """
    return a ^ b

def gf_mul(a: int, b: int) -> int:
    """
    Multiply two bytes a and b in GF(2^8) using the irreducible polynomial
    x^8 + x^4 + x^3 + x + 1 (0x11B). 
    """
    product = 0
    for _ in range(8):
        if (b & 1) == 1:
            product ^= a
        hi_bit_set = (a & 0x80) != 0
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return product

def gf_inv(a: int) -> int:
    """
    Brute-force multiplicative inverse in GF(2^8).
    Find x in [1..255] such that gf_mul(a, x) == 1.
    """
    if a == 0:
        raise ZeroDivisionError("Zero does not have an inverse in GF(2^8).")
    for x in range(1, 256):
        if gf_mul(a, x) == 1:
            return x
    return 0  # Should never happen for valid non-zero a

# Demonstration function

def demo_arithmetic(a: int, b: int):
    """
    Show how a and b behave under GF(2^8) addition, subtraction, multiplication,
    and how the bits map to polynomials.
    """
    a_binary = byte_to_binary_str(a)
    b_binary = byte_to_binary_str(b)

    a_poly = byte_to_polynomial_str(a)
    b_poly = byte_to_polynomial_str(b)

    print("===================================================")
    print(f"a = {hex(a)}")
    print(f"    binary:      {a_binary}")
    print(f"    polynomial:  {a_poly}\n")

    print(f"b = {hex(b)}")
    print(f"    binary:      {b_binary}")
    print(f"    polynomial:  {b_poly}")
    print("---------------------------------------------------")

    # Addition
    sum_ = gf_add(a, b)
    sum_binary = byte_to_binary_str(sum_)
    sum_poly   = byte_to_polynomial_str(sum_)

    print(f"a + b in GF(2^8) = {hex(a)} XOR {hex(b)} = {hex(sum_)}")
    print(f"    binary:      {sum_binary}")
    print(f"    polynomial:  {sum_poly}\n")

    # Subtraction (same as addition in GF(2))
    diff = gf_add(a, b)  # same as sum_
    diff_binary = byte_to_binary_str(diff)
    diff_poly   = byte_to_polynomial_str(diff)

    print(f"a - b in GF(2^8) = {hex(a)} XOR {hex(b)} = {hex(diff)}")
    print(f"    binary:      {diff_binary}")
    print(f"    polynomial:  {diff_poly}\n")

    # Multiplication
    prod = gf_mul(a, b)
    prod_binary = byte_to_binary_str(prod)
    prod_poly   = byte_to_polynomial_str(prod)

    print(f"a * b in GF(2^8) = {hex(prod)}")
    print(f"    binary:      {prod_binary}")
    print(f"    polynomial:  {prod_poly}\n")

    # Inversion of a, just as an example (if a != 0)
    if a != 0:
        a_inv = gf_inv(a)
        a_inv_binary = byte_to_binary_str(a_inv)
        a_inv_poly   = byte_to_polynomial_str(a_inv)
        check_a      = gf_mul(a, a_inv)

        print(f"a^-1 = {hex(a_inv)} (multiplicative inverse of a)")
        print(f"    binary:      {a_inv_binary}")
        print(f"    polynomial:  {a_inv_poly}")
        print(f"Check: a * a^-1 = {hex(a)} * {hex(a_inv)} = {hex(check_a)} (should be 0x1)\n")
    else:
        print("a = 0; no multiplicative inverse.\n")

    print("===================================================\n")

# MAIN

def main():
    # A few example pairs. Feel free to modify for exploration.
    pairs = [
        (0x57, 0x83),
        (0x53, 0xCA),
        (0x00, 0x89),
        (0x1B, 0x1),  # Interesting pair to highlight the polynomial 0x1B
        (0xFF, 0x01), # Just a boundary example
    ]

    for (a, b) in pairs:
        demo_arithmetic(a, b)

if __name__ == "__main__":
    main()
