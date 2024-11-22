import time
import matplotlib.pyplot as plt
from collections import Counter
import string

# Caesar Cipher Encryption
def caesar_encrypt(text, shift):
    encrypted = ""
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            encrypted += char
    return encrypted

# Caesar Cipher Decryption
def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# Brute Force Attack
def caesar_brute_force(ciphertext):
    print("Brute Force Results:")
    for shift in range(26):
        print(f"Shift {shift}: {caesar_decrypt(ciphertext, shift)}")

# Frequency Analysis Attack
def caesar_frequency_analysis(ciphertext):
    english_letter_freq = "ETAOINSHRDLCUMWFGYPBVKJXQZ"  # Most to least common in English
    cipher_freq = Counter(filter(str.isalpha, ciphertext.upper()))
    most_common_char = cipher_freq.most_common(1)[0][0] if cipher_freq else 'A'
    # Assuming 'E' is the most common in English
    probable_shift = (ord(most_common_char) - ord('E')) % 26
    return probable_shift, caesar_decrypt(ciphertext, probable_shift)

# Known Plaintext Attack
def caesar_known_plaintext(ciphertext, plaintext):
    shift = (ord(ciphertext[0]) - ord(plaintext[0])) % 26
    return shift, caesar_decrypt(ciphertext, shift)

# Plot Encryption Time vs Input Size
def plot_encryption_time():
    input_sizes = [100, 1000, 5000, 10000, 20000]
    encryption_times = []
    shift = 3
    for size in input_sizes:
        test_text = "A" * size
        start_time = time.time()
        caesar_encrypt(test_text, shift)
        end_time = time.time()
        encryption_times.append(end_time - start_time)

    plt.plot(input_sizes, encryption_times, marker='o')
    plt.title("Encryption Time vs Input Size")
    plt.xlabel("Input Size (characters)")
    plt.ylabel("Time (seconds)")
    plt.grid()
    plt.show()

# Main Function
if __name__ == "__main__":
    text = "HELLO WORLD"
    shift = 3

    # Encryption
    encrypted = caesar_encrypt(text, shift)
    print(f"Encrypted Text: {encrypted}")

    # Decryption
    decrypted = caesar_decrypt(encrypted, shift)
    print(f"Decrypted Text: {decrypted}")

    # Brute Force
    caesar_brute_force(encrypted)

    # Frequency Analysis
    probable_shift, probable_decryption = caesar_frequency_analysis(encrypted)
    print(f"Frequency Analysis - Probable Shift: {probable_shift}, Decrypted Text: {probable_decryption}")

    # Known Plaintext Attack
    known_text = "HELLO"
    known_ciphertext = encrypted[:len(known_text)]
    shift, decrypted_text = caesar_known_plaintext(known_ciphertext, known_text)
    print(f"Known Plaintext Attack - Shift: {shift}, Decrypted Text: {decrypted_text}")

    # Plot Encryption Time vs Input Size
    plot_encryption_time()


alphabet="abcdefghijklmnopqrstuvwxyz"
def encrypt(plaintext,key):
    cipher=""
    for char in plaintext:
        if char in alphabet:
            pos=alphabet.index(char)
            position=(plaintext+pos)%26
            cip=alphabet[position]
            cipher+=cip
        else:
            cipher+=char
    return cipher
def decrypt(ciphertext,key):
    return encrypt(ciphertext,-key)

def bruteforce(ciphertext,key):
    for key in range(26):
        decrypted_text=decrypt(ciphertext,key)
        print(decrypted_text)
        decision=int(input(f"yes 1/No 0:"))
        if decision==1:
            return decrypted_text,key
    return None
def frequencyanal(ciphertext,key):
    frequency_dict={}
    for char in ciphertext:
        if char in alphabet:
            if char in frequency_dict:
                frequency_dict[char]+=1
            else:
                frequency_dict[char]=1
    
    frequency_tuples=sorted(frequency_dict.items,key=lambda x:x[1],reverse=True)

    genfreq="etaoindcumaklalk"
    
    for i in range(len(genfreq)):
        if frequency_tuples:
            most_frequent_cipher_char=frequency_tuples[0][0]
            most_frequent_plain_char=genfreq[i]


            if most_frequent_cipher_char in alphabet:
                c=alphabet.index(most_frequent_cipher_char)
                p=alphabet.index(most_frequent_plain_char)
                k=(c-p)%26


                decrypted_text=decrypt(ciphertext,k)
                decision=int(input(f"yes 1/No 0:"))
                if decision==1:
                    return decrypted_text,k
    return None
