import socket

# Modular Exponentiation Function
def power(base, exponent, mod):
    return pow(base, exponent, mod)  # Efficient modular exponentiation

def main():
    # Create a server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()  # Get the hostname
    port = 12345  # Port number for the server

    # Bind the socket to the address and port
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Waiting for a connection...")

    # Accept a connection from the client
    client_socket, addr = server_socket.accept()
    print(f"Connected to client: {addr}")

    # Receive prime number (p) and primitive root (g) from the client
    p = int(client_socket.recv(1024).decode())
    g = int(client_socket.recv(1024).decode())
    print(f"Received prime number (p): {p}")
    print(f"Received primitive root (g): {g}")

    # Input the private key
    b = int(input("Enter your private key (b): "))

    # Compute the server's public key y = g^b mod p
    y = power(g, b, p)
    client_socket.send(str(y).encode())  # Send y to the client

    # Receive the client's public key x
    x = int(client_socket.recv(1024).decode())
    print(f"Received client's public key (x): {x}")

    # Compute the shared secret key kb = x^b mod p
    kb = power(x, b, p)
    print(f"Shared secret key (kb): {kb}")

    # Close the client socket
    client_socket.close()
    print("Connection closed.")

if __name__=="__main__":
    main()
