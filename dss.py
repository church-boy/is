import hashlib
import random
import math


def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


def inverse(a, b):
    if gcd(a, b) == 1:
        for i in range(1, b):
            if (a * i) % b == 1:
                return i
    return None


def sha256_hash(filedata):
    sha256 = hashlib.sha256()
    sha256.update(filedata)
    return int(sha256.hexdigest(), 16)


def gen(p, q):
    h = 2
    while True:
        g = pow(h, (p - 1) // q, p)
        if g > 1:
            return g
        h += 1


def sign_file(filepath, g, p, q, x):
    """
    Signs a file using DSA.
    
    Parameters:
    - filepath: Path to the file to be signed.
    - g, p, q: DSA parameters (generator, prime modulus, and subgroup order).
    - x: The private key.

    Returns:
    - (r, s): The signature components.
    """
    try:
        with open(filepath, 'rb') as file:
            filedata = file.read()

        # Calculate the hash of the file data
        h = sha256_hash(filedata)

        # Generate a random ephemeral key k
        k = random.randint(1, q - 1)

        # Compute r
        r = pow(g, k, p) % q

        # Compute the modular inverse of k mod q
        k_inv = inverse(k, q)
        if k_inv is None:
            raise ValueError("k does not have a modular inverse modulo q.")

        # Compute s
        s = (k_inv * (h + (x * r))) % q

        return r, s
    except Exception as e:
        print(f"Error during signing: {e}")
        return None, None


def ver_file(filepath, g, p, q, r, s, y):
    """
    Verifies a file signature using DSA.

    Parameters:
    - filepath: Path to the file to verify.
    - g, p, q: DSA parameters.
    - r, s: Signature components.
    - y: The public key.

    Returns:
    - 1 if the signature is valid, -1 otherwise.
    """
    try:
        with open(filepath, 'rb') as file:
            filedata = file.read()

        h = sha256_hash(filedata)
        w = inverse(s, q)
        if w is None:
            raise ValueError("s does not have a modular inverse modulo q.")

        u1 = (h * w) % q
        u2 = (r * w) % q
        v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

        if v == r:
            print("Signature verified.")
            return 1
        else:
            print("Invalid signature.")
            return -1

    except Exception as e:
        print(f"Error during verification: {e}")
        return -1


# Main Execution
p = int(input("Enter the prime number (p): "))
q = (p - 1) // 2
x = random.randint(1, q - 1)  # Private key
filepath = input("Enter the file path: ")

g = gen(p, q)
y = pow(g, x, p)  # Public key

print(f"Prime p: {p}")
print(f"Subgroup order q: {q}")
print(f"Private key x: {x}")
print(f"Public key y: {y}")
print(f"Generator g: {g}")

# Signing the file
r, s = sign_file(filepath, g, p, q, x)
if r is not None and s is not None:
    print(f"Signature generated successfully: (r={r}, s={s})")
else:
    print("Signature generation failed.")

# Verifying the file
verification = ver_file(filepath, g, p, q, r, s, y)
if verification == 1:
    print("Signature is valid.")
else:
    print("Signature is invalid.")
