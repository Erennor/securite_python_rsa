import hashlib
import sys
import binascii
import os
import socket
from gmpy2 import mpz, iroot, powmod, mul, t_mod
#TODO : recover key from alice
sys.path.append("./rsa-3.4.2")
import rsa

TCP_IP = 'localhost'
TCP_PORT = 5005
BUFFER_SIZE = 1024
MESSAGE = 'Bonjour !'.encode('ascii')
HASH = 'NOT AN HASH'
message_hash = hashlib.sha256(MESSAGE).digest()
ASN1_blob = rsa.pkcs1.HASH_ASN1['SHA-256']
suffix = b'\x00' + ASN1_blob + message_hash


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
s.send(MESSAGE.encode())
data = s.recv(BUFFER_SIZE)
print("[OSCAR] received data:", data)
s.send(HASH.encode())
data = s.recv(BUFFER_SIZE)
s.close()

print("[OSCAR] received data:", data)
