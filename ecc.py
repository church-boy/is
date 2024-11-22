import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
# ECC Methods without Class
def is_point_on_curve(a, b, p, point):
    x, y = point
    return (y**2) % p == (x**3 + a * x + b) % p
def point_addition(a, p, P, Q):
    if P == Q:
        return point_doubling(a, p, P)
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None  # Point at infinity
    try:
        slope = (y2 - y1) * pow(x2 - x1, -1, p) % p
    except ValueError:
        raise ValueError("Cannot compute the modular inverse.")
    xr = (slope ** 2 - x1 - x2) % p
    yr = (slope * (x1 - xr) - y1) % p
    return xr, yr
def point_doubling(a, p, P):
    if P is None:
        return None
    x, y = P
    if y == 0:
        return None  # Point at infinity
    slope = (3 * x ** 2 + a) * pow(2 * y, -1, p) % p
    xr = (slope ** 2 - 2 * x) % p
    yr = (slope * (x - xr) - y) % p
    return xr, yr
def scalar_multiplication(k, P, a, p):
    result = None
    addend = P
    while k:
        if k & 1:
            if result is None:
                result = addend
            else:
                result = point_addition(a, p, result, addend)
        addend = point_doubling(a, p, addend)
        k >>= 1
    return result
def generate_private_key(p):
    return random.randint(1, p - 1)
def generate_public_key(private_key, g, a, p):
    return scalar_multiplication(private_key, g, a, p)
def derive_shared_secret(private_key, public_key, a, p):
    return scalar_multiplication(private_key, public_key, a, p)

def hash_shared_secret(secret_point):
    if secret_point is None:
        raise ValueError("Shared secret point is None, cannot hash.")
    secret_x = secret_point[0]
    shared_key = hashlib.sha256(str(secret_x).encode()).digest()
    return shared_key
def encrypt_message(public_key, message, a, p, g):
    ephemeral_private_key = generate_private_key(p)
    ephemeral_public_key = generate_public_key(ephemeral_private_key, g, a, p)
    shared_secret = derive_shared_secret(ephemeral_private_key, public_key, a, p)
    shared_key = hash_shared_secret(shared_secret)
    cipher = AES.new(shared_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return (ciphertext, cipher.iv, ephemeral_public_key)
def decrypt_message(private_key, ciphertext, iv, ephemeral_public_key, a, p):
    shared_secret = derive_shared_secret(private_key, ephemeral_public_key, a, p)
    shared_key = hash_shared_secret(shared_secret)
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()
# Running ECDH and ECIES operations
def run_ecdh(a, b, p, g, alice_private_key, alice_public_key, bob_private_key, bob_public_key):
    alice_shared_secret = derive_shared_secret(alice_private_key, bob_public_key, a, p)
    print("Alice's Shared Secret:", alice_shared_secret)

    bob_shared_secret = derive_shared_secret(bob_private_key, alice_public_key, a, p)
    print("Bob's Shared Secret:", bob_shared_secret)

    if alice_shared_secret == bob_shared_secret:
        print("Key exchange successful! Shared secret is identical for both parties.")
    else:
        print("Key exchange failed! Shared secret mismatch.")

def run_ecies(a, b, p, g, bob_public_key, bob_private_key):
    message = input("Enter the Message to be encrypted: ")
    ciphertext, iv, ephemeral_public_key = encrypt_message(bob_public_key, message, a, p, g)
    print("Ciphertext:", ciphertext)

    decrypted_message = decrypt_message(bob_private_key, ciphertext, iv, ephemeral_public_key, a, p)
    print("Decrypted Message:", decrypted_message)


def main():
    a = 2
    b = 3
    p = 13
    g = (3, 6)

    # Generating Alice's and Bob's keys
    alice_private_key = generate_private_key(p)
    alice_public_key = generate_public_key(alice_private_key, g, a, p)
    bob_private_key = generate_private_key(p)
    bob_public_key = generate_public_key(bob_private_key, g, a, p)
    print("Alice's Private Key:", alice_private_key)
    print("Alice's Public Key:", alice_public_key)
    print("Bob's Private Key:", bob_private_key)
    print("Bob's Public Key:", bob_public_key)

    # Prompt user for choice
    choices = {'1': run_ecdh, '2': run_ecies}
    print("\nChoose an option:")
    print("1: Elliptic Curve Diffie-Hellman Key Exchange (ECDH)")
    print("2: Elliptic Curve Integrated Encryption Scheme (ECIES)")
    choice = input("Enter your choice (1 or 2): ")

    if choice == '1':
        choices[choice](a, b, p, g, alice_private_key, alice_public_key, bob_private_key, bob_public_key)
    elif choice == '2':
        choices[choice](a, b, p, g, bob_public_key, bob_private_key)
    else:
        print("Invalid choice. Please enter 1 or 2.")

if __name__ == "__main__":
    main()








import random
import hashlib


# Point on curve check
def point_on_curve(a, b, p, point):
    x, y = point
    return (y**2 % p) == (x**3 + a * x + b) % p


# Point addition
def point_addition(a, p, P, Q):
    if P == Q:
        return point_doubling(a, p, P)
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None
    
    slope = (y2 - y1) * pow((x2 - x1), -1, p) % p
    xr = (slope**2 - x1 - x2) % p
    yr = (slope * (x1 - xr) - y1) % p
    return xr, yr


# Point doubling
def point_doubling(a, p, P):
    if P is None:
        return None
    x, y = P
    if y == 0:
        return None
    slope = (3 * x**2 + a) * pow(2 * y, -1, p) % p
    xr = (slope**2 - 2 * x) % p
    yr = (slope * (x - xr) - y) % p
    return xr, yr


# Scalar multiplication
def scalar_multiplication(k, P, a, p):
    result = None
    addend = P
    while k:
        if k & 1:
            if result is None:
                result = addend
            else:
                result = point_addition(a, p, result, addend)
        addend = point_doubling(a, p, addend)
        k >>= 1
    return result


# Generate a private key
def generate_private_key(p):
    return random.randint(1, p - 1)


# Generate a public key
def generate_public_key(private_key, g, a, p):
    return scalar_multiplication(private_key, g, a, p)


# Derive shared secret
def derive_shared_secret(private_key, public_key, a, p):
    return scalar_multiplication(private_key, public_key, a, p)


# Encrypt a message using the public key
def encrypt(plaintext, public_key, a, p, g):
    # Generate ephemeral private key
    k = generate_private_key(p)
    # Calculate ephemeral public key
    kG = scalar_multiplication(k, g, a, p)
    # Derive shared secret
    shared_secret = derive_shared_secret(k, public_key, a, p)
    # Use only the x-coordinate of the shared secret for hashing
    shared_secret_hash = hashlib.sha256(str(shared_secret[0]).encode()).hexdigest()
    
    # Encrypt the plaintext using the shared secret
    ciphertext = ''.join(
        chr((ord(char) + int(shared_secret_hash, 16)) % 256) for char in plaintext
    )
    
    return (kG, ciphertext)


# Decrypt a message using the private key
def decrypt(ciphertext, private_key, ephemeral_public_key, a, p):
    # Derive the shared secret
    shared_secret = derive_shared_secret(private_key, ephemeral_public_key, a, p)
    # Use only the x-coordinate of the shared secret for hashing
    shared_secret_hash = hashlib.sha256(str(shared_secret[0]).encode()).hexdigest()
    
    # Decrypt the ciphertext using the shared secret
    plaintext = ''.join(
        chr((ord(char) - int(shared_secret_hash, 16)) % 256) for char in ciphertext
    )
    
    return plaintext


# Example usage
if __name__ == "__main__":
    # Define parameters for the elliptic curve
    a = 2
    b = 3
    p = 97  # A prime number
    g = (3, 6)  # A point on the curve

    # Check if g is a valid point
    if not point_on_curve(a, b, p, g):
        raise ValueError("The generator point is not on the curve.")

    # User A generates a private and public key
    private_key_a = generate_private_key(p)
    public_key_a = generate_public_key(private_key_a, g, a, p)

    # User B generates a private and public key
    private_key_b = generate_private_key(p)
    public_key_b = generate_public_key(private_key_b, g, a, p)

    # User A encrypts a message for User B
    message = "Hello, User B!"
    ephemeral_public_key, ciphertext = encrypt(message, public_key_b, a, p, g)
    print("Ciphertext:", ciphertext)

    # User B decrypts the message
    decrypted_message = decrypt(ciphertext, private_key_b, ephemeral_public_key, a, p)
    print("Decrypted Message:", decrypted_message)

