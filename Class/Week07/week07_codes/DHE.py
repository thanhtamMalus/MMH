import random
from sympy import nextprime, mod_inverse

def fast_prime(bits=1024):
    """Generate a large prime number efficiently."""
    num = random.getrandbits(bits)
    return nextprime(num)  # Get the next prime number

def find_generator(p):
    """Find a generator g efficiently for Diffie-Hellman."""
    for g in range(2, p):
        if pow(g, (p-1)//2, p) != 1:  # Basic test for generator
            return g
    return None

def generate_dh_parameters(bits=1024):
    """Generate prime (p) and generator (g) faster."""
    p = fast_prime(bits)
    g = find_generator(p)
    print(f"\nGenerated Field Parameters:\nPrime (p): {p}\nGenerator (g): {g}")
    return p, g

def generate_key_pair(p, g):
    """Generate a private key and public key."""
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    print(f"\nGenerated Key Pair:\nPrivate Key x: {private_key}\nPublic Key g^x: {public_key}")
    return private_key, public_key

def compute_shared_secret(their_public, my_private, p):
    """Compute shared session key."""
    shared_secret = pow(their_public, my_private, p)
    print(f"\nComputed Shared Secret g^(x.y): {shared_secret}")
    return shared_secret

# Main Menu
def main():
    p = g = None
    my_private = my_public = None
    while True:
        print("\nDiffie-Hellman Key Exchange")
        print("1. Generate Field Parameters (p, g)")
        print("2. Generate Key Pair (x, g^x)")
        print("3. Compute Shared Secret (Session Key)")
        print("4. Exit")

        choice = input("Select an option: ").strip()

        if choice == "1":
            p, g = generate_dh_parameters(1024)

        elif choice == "2":
            if not p or not g:
                print("\nError: Generate field parameters first!")
                continue
            my_private, my_public = generate_key_pair(p, g)

        elif choice == "3":
            if not p or not my_private:
                print("\nError: Generate field parameters and key pair first!")
                continue
            their_public = int(input("Enter the other party's public key: ").strip())
            compute_shared_secret(their_public, my_private, p)

        elif choice == "4":
            print("Exiting...")
            break

        else:
            print("Invalid option. Try again.")

if __name__ == "__main__":
    main()
