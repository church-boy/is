alphabet = "abcdefghijklmnopqrstuvwxyz"

# Caesar cipher encryption function
def encrypt(plaintext, key):
    cipher = ""
    for char in plaintext:
        if char in alphabet:
            pos = alphabet.index(char)
            position = (pos + key) % 26  # Fix the incorrect use of plaintext + pos
            cip = alphabet[position]
            cipher += cip
        else:
            cipher += char
    return cipher

# Caesar cipher decryption function
def decrypt(ciphertext, key):
    return encrypt(ciphertext, -key)

# Brute force attack to decrypt ciphertext
def bruteforce(ciphertext):
    for key in range(26):
        decrypted_text = decrypt(ciphertext, key)
        print(f"Trying key {key}: {decrypted_text}")
        decision = int(input("Is this the correct decryption? (Yes=1/No=0): "))
        if decision == 1:
            return decrypted_text, key
    return None

# Frequency analysis attack on ciphertext
def frequencyanal(ciphertext):
    frequency_dict = {}
    for char in ciphertext:
        if char in alphabet:
            frequency_dict[char] = frequency_dict.get(char, 0) + 1

    # Sort by frequency in descending order
    frequency_tuples = sorted(frequency_dict.items(), key=lambda x: x[1], reverse=True)

    # English letter frequency order
    genfreq = "etaoinsrhldcumfpgwybvkxjqz"

    # Try mapping the most frequent letters
    for i in range(len(genfreq)):
        if frequency_tuples:
            most_frequent_cipher_char = frequency_tuples[0][0]
            most_frequent_plain_char = genfreq[i]

            # Compute the key based on the position difference
            if most_frequent_cipher_char in alphabet:
                c = alphabet.index(most_frequent_cipher_char)
                p = alphabet.index(most_frequent_plain_char)
                k = (c - p) % 26

                decrypted_text = decrypt(ciphertext, k)
                print(f"Trying key {k}: {decrypted_text}")
                decision = int(input("Is this the correct decryption? (Yes=1/No=0): "))
                if decision == 1:
                    return decrypted_text, k
    return None

if __name__ == "__main__":
    print("Choose an option:")
    print("1. Encrypt a message")
    print("2. Decrypt a message (with a key)")
    print("3. Brute force attack")
    print("4. Frequency analysis attack")
    choice = int(input("Enter your choice: "))

    if choice == 1:
        plaintext = input("Enter the plaintext: ").lower()
        key = int(input("Enter the key (0-25): "))
        ciphertext = encrypt(plaintext, key)
        print(f"Encrypted message: {ciphertext}")

    elif choice == 2:
        ciphertext = input("Enter the ciphertext: ").lower()
        key = int(input("Enter the key (0-25): "))
        plaintext = decrypt(ciphertext, key)
        print(f"Decrypted message: {plaintext}")

    elif choice == 3:
        ciphertext = input("Enter the ciphertext: ").lower()
        result = bruteforce(ciphertext)
        if result:
            decrypted_text, key = result
            print(f"Decrypted message: {decrypted_text}, Key: {key}")
        else:
            print("Failed to decrypt using brute force.")

    elif choice == 4:
        ciphertext = input("Enter the ciphertext: ").lower()
        result = frequencyanal(ciphertext)
        if result:
            decrypted_text, key = result
            print(f"Decrypted message: {decrypted_text}, Key: {key}")
        else:
            print("Failed to decrypt using frequency analysis.")

    else:
        print("Invalid choice!")
