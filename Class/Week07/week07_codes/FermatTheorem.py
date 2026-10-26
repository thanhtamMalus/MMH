import math

def euler_totient(n):
    """Compute Euler's totient function φ(n)."""
    result = n
    for p in range(2, int(math.sqrt(n)) + 1):
        if n % p == 0:
            while n % p == 0:
                n //= p
            result -= result // p
    if n > 1:
        result -= result // n
    return result

def check_fermat(n):
    """Verify Fermat’s theorem for all a where gcd(a, n) = 1."""
    phi_n = euler_totient(n)
    print(f"\nEuler’s Totient Function: φ({n}) = {phi_n}")

    input("Press Enter to continue checking Fermat’s theorem...\n")

    for a in range(2, n):
        if math.gcd(a, n) == 1:  # a must be coprime to n
            power_value = a ** phi_n  # Compute raw exponentiation
            mod_value = power_value % n  # Compute (a^φ(n)) mod n
            
            print(f"{a}^{phi_n} = {power_value}")
            print(f"{a}^{phi_n} mod {n} = {mod_value}")

            if mod_value == 1:
                print(f"✔ Fermat holds for a = {a}\n")
            else:
                print(f"❌ Fermat fails for a = {a}\n")

# Main execution
if __name__ == "__main__":
    n = int(input("Enter an integer n: ").strip())
    check_fermat(n)
