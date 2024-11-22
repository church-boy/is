import hashlib

hashed_password = hashlib.md5("kumar".encode()).hexdigest()

with open("wordlist.txt", "r+") as f:
    words = f.read().split("\n")
    for word in words:
        hp = hashlib.md5(word.encode()).hexdigest()
        if hp == hashed_password:
            print(word)
            exit(0)  # Ensure proper alignment with the `if` block

# If no match is found, the loop will complete without exiting
print("Password not found in the wordlist.")
