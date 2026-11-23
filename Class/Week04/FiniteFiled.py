#!/usr/bin/env python3
import sys

# Finite Field (GF(2^8)) routines using AES polynomial (0x11B)

def gf_mul(a: int, b: int) -> int:
    """
    Multiply two bytes (0..255) 'a' and 'b' in GF(2^8), using the AES
    irreducible polynomial x^8 + x^4 + x^3 + x + 1 (often noted 0x11B).
    
    Explanation:
    1) In GF(2^8), each byte can be seen as a polynomial of degree ≤ 7.
       For example, 0x57 => 0101_0111 (binary) => x^6 + x^4 + x^2 + x + 1.
    2) Multiplication of two polynomials 'a' and 'b' is done by repeatedly
       checking if the current (lowest) bit of 'b' is 1. If it is, we XOR
       (add in GF(2)) the current 'a' into our product 'p'.
    3) After we handle that bit of 'b', we shift 'a' to the left by 1 (multiply
       by x in polynomial terms). If the highest bit of 'a' was set (meaning an
       x^7 term before shifting), shifting would produce an x^8 term—this must
       be reduced using the AES irreducible polynomial. Concretely, we XOR
       'a' with 0x1B (the low 8 bits of 0x11B) to subtract out the x^8 term and
       keep the result in 8 bits.
    4) We then shift 'b' right by 1 to move on to the next bit.
    5) After 8 iterations, 'p' is our product in GF(2^8).

    Returns an integer 0..255 representing the product in GF(2^8).
    """

    p = 0  # Will accumulate our product
    for _ in range(8):
        # Check if the current least significant bit of b is 1.
        if b & 1:
            # If so, XOR 'a' into our running product 'p'.
            p ^= a

        # Before shifting a, check if its leftmost (8th) bit is set.
        high_bit_set = (a & 0x80) != 0

        # Shift 'a' left by 1, keeping only the lower 8 bits.
        # This is equivalent to multiplying 'a' by x in polynomial form.
        a = (a << 1) & 0xFF

        # If shifting caused an x^8 term, reduce it by our AES polynomial
        # by XORing with 0x1B (which represents x^4 + x^3 + x + 1).
        if high_bit_set:
            a ^= 0x1B

        # Shift 'b' right by 1 to examine the next bit on the next iteration.
        b >>= 1

    return p & 0xFF

def gf_inv(a: int) -> int:
    """
    Compute the multiplicative inverse of a byte 'a' in GF(2^8).
    
    Brute-force approach:
      Find x in [1..255] such that gf_mul(a, x) == 1.
    Every non-zero 'a' in GF(2^8) has a unique multiplicative inverse.
    """

    if a == 0:
        raise ZeroDivisionError("No inverse for 0 in GF(2^8).")
    for x in range(1, 256):
        if gf_mul(a, x) == 1:
            return x
    # Should never be reached for valid (non-zero) a
    return 0

class GF256:
    """
    A convenient wrapper to perform operations on a single byte in GF(2^8).
    Uses the gf_mul() and gf_inv() functions above.
    """

    def __init__(self, value: int):
        # Ensure 'value' is 8 bits
        self.value = value & 0xFF

    def __add__(self, other: 'GF256') -> 'GF256':
        """
        Addition in GF(2^8) is XOR (bitwise exclusive OR).
        """
        return GF256(self.value ^ other.value)

    def __sub__(self, other: 'GF256') -> 'GF256':
        """
        Subtraction in GF(2^8) is also XOR (identical to addition).
        """
        return GF256(self.value ^ other.value)

    def __mul__(self, other: 'GF256') -> 'GF256':
        """
        Multiplication in GF(2^8) using gf_mul().
        """
        return GF256(gf_mul(self.value, other.value))

    def __truediv__(self, other: 'GF256') -> 'GF256':
        """
        Division in GF(2^8): multiply by the multiplicative inverse.
        """
        inv_val = gf_inv(other.value)
        return GF256(gf_mul(self.value, inv_val))

    def __repr__(self):
        return f"GF256({hex(self.value)})"

# AES MixColumns

MIX_COLUMNS_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02],
]

def mix_columns(state: list[list[int]]) -> list[list[int]]:
    """
    Perform the AES MixColumns operation on a 4×4 state array.
    
    - 'state' is a 4×4 list of integers, each 0..255, representing bytes.
    - We multiply each column by the fixed AES MixColumns matrix,
      doing all operations in GF(2^8).
    - Returns a new 4×4 list with MixColumns applied.
    """

    new_state = [[0]*4 for _ in range(4)]

    for col in range(4):
        for row in range(4):
            val = 0
            for k in range(4):
                val ^= gf_mul(MIX_COLUMNS_MATRIX[row][k], state[k][col])
            new_state[row][col] = val

    return new_state

# Main command-line interface

def print_usage():
    print("Usage:")
    print("  python gf256.py add <a> <b>")
    print("  python gf256.py sub <a> <b>")
    print("  python gf256.py mul <a> <b>")
    print("  python gf256.py div <a> <b>")
    print("  python gf256.py mixcolumns <16 bytes in hex or decimal>")
    print("\nExamples:")
    print("  python gf256.py add 0x57 0x83")
    print("  python gf256.py mul 0x57 0x83")
    print("  python gf256.py mixcolumns 87 f2 4d 97 6e 4c 90 ec 46 e7 4a c3 a6 8c d8 95")

def parse_byte(arg: str) -> int:
    """
    Parse a single byte from string (e.g. '0x1F' or '31') to an integer (0..255).
    """
    if arg.lower().startswith("0x"):
        return int(arg, 16)
    else:
        return int(arg, 10)

def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    operation = sys.argv[1].lower()

    if operation in ["add", "sub", "mul", "div"]:
        if len(sys.argv) < 4:
            print_usage()
            sys.exit(1)

        # Parse the two input bytes
        a_byte = parse_byte(sys.argv[2])
        b_byte = parse_byte(sys.argv[3])

        # Wrap them in GF256 objects for easy arithmetic
        a = GF256(a_byte)
        b = GF256(b_byte)

        if operation == "add":
            result = a + b
            print(f"{hex(a_byte)} + {hex(b_byte)} = {hex(result.value)}")
        elif operation == "sub":
            result = a - b
            print(f"{hex(a_byte)} - {hex(b_byte)} = {hex(result.value)}")
        elif operation == "mul":
            result = a * b
            print(f"{hex(a_byte)} * {hex(b_byte)} = {hex(result.value)}")
        elif operation == "div":
            try:
                result = a / b
                print(f"{hex(a_byte)} / {hex(b_byte)} = {hex(result.value)}")
            except ZeroDivisionError:
                print("Error: Division by zero in GF(2^8).")

    elif operation == "mixcolumns":
        # Expect 16 numbers (each in 0..255 or hex)
        if len(sys.argv) < 18:
            print("Error: mixcolumns requires 16 bytes for the 4×4 state.")
            print_usage()
            sys.exit(1)

        # Gather 16 bytes in column-major order
        raw_bytes = [parse_byte(arg) for arg in sys.argv[2:2+16]]

        # Construct a 4×4 state matrix in column-major order: state[row][col]
        state = [[0]*4 for _ in range(4)]
        idx = 0
        for col in range(4):
            for row in range(4):
                state[row][col] = raw_bytes[idx]
                idx += 1

        # Apply MixColumns
        new_state = mix_columns(state)

        print("Original state (hex):")
        for row in state:
            print(" ".join(hex(x) for x in row))

        print("\nAfter MixColumns (hex):")
        for row in new_state:
            print(" ".join(hex(x) for x in row))

    else:
        print("Error: Unknown operation.")
        print_usage()
        sys.exit(1)

if __name__ == "__main__":
    main()
