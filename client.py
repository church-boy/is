import socket

# Modular Exponentiation Function
def power(base, exponent, mod):
    return pow(base, exponent, mod)  # Python's pow() handles modular exponentiation efficiently

def main():
    # Create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()  # Get the hostname of the server
    port = 12345  # Port number
    
    # Connect to the server
    client_socket.connect((host, port))
    print("Connected to server.")
    
    # Input prime number (p) and primitive root (g)
    p = int(input("Enter the large prime number (p): "))
    client_socket.send(str(p).encode())  # Send p to the server
    
    g = int(input("Enter the primitive root (g): "))
    client_socket.send(str(g).encode())  # Send g to the server
    
    # Input the private key
    a = int(input("Enter your private key (a): "))
    
    # Compute the public key x = g^a mod p
    x = power(g, a, p)
    client_socket.send(str(x).encode())  # Send x to the server
    
    # Receive the server's public key y
    y = int(client_socket.recv(1024).decode())
    print(f"Received server's public key (y): {y}")
    
    # Compute the shared secret key k = y^a mod p
    ka = power(y, a, p)
    print(f"Shared secret key (ka): {ka}")
    
    # Close the socket
    client_socket.close()
    print("Connection closed.")

if __name__ == "__main__":
    main()
