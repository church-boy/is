import hashlib
from itertools import product
characters="01234"
def gen_pass(characters,length):
    passwords=[''.join(p) for p in product(characters,repeat=length)]
    return passwords
def hash_pass(password):
    return hashlib.sha256(password.encode()).hexdigest()
def create_dic(characters,length):
    passwords=gen_pass(characters,length)
    password_dic={}
    for password in passwords:
        hash_value=hash_pass(password)
        password_dic[password]=hash_value
    return password_dic
def launch(hashed_pass,characters,length):
    passwords=gen_pass(characters,length)
    for password in passwords:
        hash_value=hash_pass(password)
        if hash_value==hashed_pass:
            return password
    return None
length=int(input("enter teh lenght"))
password_dic=create_dic(characters,length)
for password,hash_value in password_dic.items():
    print(f"password{password}->hash{hash_value}")

username_dict={
    'user1':'12',
    'user2':'13',
    'user3':'14'
}
hashed_dic={}
for username,password in username_dict.items():
    hashed_pass=hash_pass(password)
    hashed_dic[username]=hashed_pass
for username,hashed_pass in hashed_dic.items():
    print(f"username{username}->password{hashed_pass}")

username=input("enter the username")
if username in hashed_dic:
    hashed_pass=hashed_dic[username]
cracked_pass=launch(hashed_pass,characters,length)
if cracked_pass:
    print(f"username{username}->password{cracked_pass}")
else:
    print("cant crack")




import hashlib
from itertools import product
characters="01234"
def gen_pass(characters,length):
    passwords=[''.join(p) for p in product(characters,repeat=length)]
    return passwords
def hash_pass(password):
    return hashlib.sha256(password.encode()).hexdigest()
def create_dic(characters,length):
    passwords=gen_pass(characters,length)
    password_dic={}
    for password in passwords:
        hash_value=hash_pass(password)
        password_dic[password]=hash_value
    return password_dic
def launch(hashed_pass,characters,length):
    passwords=gen_pass(characters,length)
    for password in passwords:
        hash_value=hash_pass(password)
        if hash_value==hashed_pass:
            return password
    return None
length=int(input("enter teh lenght"))
password_dic=create_dic(characters,length)
for password,hash_value in password_dic.items():
    print(f"password{password}->hash{hash_value}")

username_dict={
    'user1':'12',
    'user2':'13',
    'user3':'14'
}
hashed_dic={}
for username,password in username_dict.items():
    hashed_pass=hash_pass(password)
    hashed_dic[username]=hashed_pass
for username,hashed_pass in hashed_dic.items():
    print(f"username{username}->password{hashed_pass}")

username=input("enter the username")
if username in hashed_dic:
    hashed_pass=hashed_dic[username]
cracked_pass=launch(hashed_pass,characters,length)
if cracked_pass:
    print(f"username{username}->password{cracked_pass}")
else:
    print("cant crack")




import hashlib
import time
import matplotlib.pyplot as plt
from itertools import product

# Define the character set and hash function
characters = "01234"

def gen_pass(characters, length):
    """Generates all combinations of passwords of a given length."""
    return [''.join(p) for p in product(characters, repeat=length)]

def hash_pass(password):
    """Hashes the given password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def create_dic(characters, length):
    """Creates a dictionary of passwords and their hashed values."""
    passwords = gen_pass(characters, length)
    password_dic = {}
    for password in passwords:
        hash_value = hash_pass(password)
        password_dic[password] = hash_value
    return password_dic

def launch(hashed_pass, characters, length):
    """Attempts to find the password from the hashed value by brute-forcing."""
    passwords = gen_pass(characters, length)
    for password in passwords:
        hash_value = hash_pass(password)
        if hash_value == hashed_pass:
            return password
    return None

# Function to plot the graph of length vs. time
def plot_length_vs_time():
    lengths = range(1, 6)  # Range of password lengths to test (1 to 5)
    times = []

    for length in lengths:
        # Track time taken for cracking
        start_time = time.time()

        # Create the dictionary of password hashes
        password_dic = create_dic(characters, length)

        # Create a dictionary of username and hashed passwords
        username_dict = {
            'user1': '12', 
            'user2': '13', 
            'user3': '14'
        }
        hashed_dic = {}
        for username, password in username_dict.items():
            hashed_pass = hash_pass(password)
            hashed_dic[username] = hashed_pass

        # Choose a username and attempt to crack the password
        username = 'user1'
        if username in hashed_dic:
            hashed_pass = hashed_dic[username]
            cracked_pass = launch(hashed_pass, characters, length)

        # Measure the elapsed time for the cracking attempt
        end_time = time.time()
        times.append(end_time - start_time)

    # Plotting the graph
    plt.plot(lengths, times, marker='o')
    plt.xlabel('Password Length')
    plt.ylabel('Time (seconds)')
    plt.title('Time to Crack Password vs Length')
    plt.show()

# Call the function to plot the graph
plot_length_vs_time()

