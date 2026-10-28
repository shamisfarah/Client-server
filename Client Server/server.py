
import socket
import time
import hashlib  # Convert the shared secret to an AES key
import secrets  # Generate a random secret number
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Public numbers: the modulus and the base
mod = 23
base = 5

# Create the server socket
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = socket.gethostname()
port = 9999

serversocket.bind((host, port))
serversocket.listen(5)

while True:
    # Accept the client connection and create a new socket
    clientsocket, addr = serversocket.accept()
    print("Got a connection from %s" % str(addr))

    # Generate the server's private number
    b = secrets.randbelow(mod - 3) + 2

    # Calculate the server's public value
    B = pow(base, b, mod)

    # Receive the client's public value
    A = int(clientsocket.makefile('r').readline())

    # Send the server's public value to the client
    clientsocket.sendall((str(B) + '\n').encode('ascii'))

    # Calculate the shared secret
    shared_secret = pow(A, b, mod)

    # Convert the shared secret into an AES key
    key = hashlib.sha256(str(shared_secret).encode('ascii')).digest()

    # Create the AES cipher using the key
    cipher = AES.new(key, AES.MODE_ECB)

    # Send the client the current time
    currentTime = time.ctime(time.time())
    clientsocket.sendall(currentTime.encode('ascii'))

    # Receive and decrypt the client's message
    encrypted = clientsocket.recv(1024)
    decrypted = cipher.decrypt(encrypted)

    print("Message from client:",
          unpad(decrypted, AES.block_size).decode('ascii'))

    # Get the server's reply
    reply = input("can i help with that? ")

    # Pad and encrypt the reply
    reply = pad(reply.encode('ascii'), AES.block_size)
    encrypted = cipher.encrypt(reply)

    # Send the encrypted reply
    clientsocket.sendall(encrypted)

    # Receive and decrypt the client's second message
    encrypted = clientsocket.recv(1024)
    decrypted = cipher.decrypt(encrypted)

    print("Second message from client:",
          unpad(decrypted, AES.block_size).decode('ascii'))

    clientsocket.close()
