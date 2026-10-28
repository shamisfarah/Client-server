
import socket
from Crypto.Cipher import AES
import hashlib # converts shared secret key into AES key
import secrets # generates random secret numbers
from Crypto.Util.Padding import pad, unpad
#importing aes for encryption/decryption tools
#pad to make the message fit the aes blocks

# public numbers used by both client and server 
mod = 23
base = 5


#Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = socket.gethostname()
port = 9999

#connect to the server 
s.connect((host, port))

# generate the clients private number 
a = secrets.randbelow(mod - 3) + 2

# calculate the clients public number
A = pow(base, a, mod)

# send the clients public number
s.sendall((str(A) + '\n').encode('ascii'))

# recieve the servers public number
b = int(s.makefile('r').readline())

# calculate the shared secret
shared_secret = pow(b, a, mod)

# convert shared secret into AES key
key = hashlib.sha256(str(shared_secret).encode('ascii')).digest()

#create the AES cipher
cipher = AES.new(key, AES.MODE_ECB)

#recieve the time 
tm = s.recv(1024)
print(tm.decode('ascii'))

#this is the user input so sending the client a message
question = input("ask something message:")
#add padding so the message fits the AES blocks also encode it 
question = pad(question.encode('ascii'), AES.block_size)
#encrypt the message
Encrypted = cipher.encrypt(question)
s.sendall(Encrypted)

#recieve the servers reply 
reply1 = s.recv(1024)
#Decrypt the reply
decrypted = cipher.decrypt(reply1)
#remove the padding and display the reply
print(unpad(decrypted, AES.block_size).decode('ascii'))

#encrypt the second message 
reply = input("reply:")
reply = pad(reply.encode('ascii'), AES.block_size)
Encrypted = cipher.encrypt(reply)
s.sendall(Encrypted)

s.close()
