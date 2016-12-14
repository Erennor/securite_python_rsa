import hashlib
import sys
import binascii
import os
import socket
from gmpy2 import mpz, iroot, powmod, mul, t_mod

if len(sys.argv) != 2:
    print("[BOB] Use : python3 bob.py [old|new]")
    sys.exit(0)

if sys.argv[1] == "old":
    print("[BOB] use of deprecated rsa package 3.2.3")
    sys.path.append("./rsa-3.2.3")
elif sys.argv[1] == "new":
    print("[BOB] use of new rsa package 3.4.2")
    sys.path.append("./rsa-3.4.2")

#Importing chosen rsa package
import rsa

#Importing alice public key
with open('alice.pub') as publicfile:
    pkeydata = publicfile.read().encode('ascii')
pubkey = rsa.PublicKey.load_pkcs1(pkeydata)
print( "[BOB] Alice key loaded")

def verify(message, signature):
    if rsa.verify(message, signature, pubkey):
        print("[BOB] I identify my contact as Alice")
    else:
        print("[BOB] I do not recognize my contact as Alice")

IP = 'localhost'
port = 5005
buffer_size = 1024
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((IP,port))
s.listen(0)
print("[BOB] ready to accept any connection")
connection, address = s.accept()
print('[BOB] connection address:', address)
waiting_for_hash = False
message = ''
while True:
        data = connection.recv(buffer_size)
        if not data: break
        print("[BOB] I received ", data)
        if waiting_for_hash:
            hash = data
            verify(message,signature=data)
        else:
            waiting_for_hash = True
            message = data
        connection.send(data)
connection.close()
