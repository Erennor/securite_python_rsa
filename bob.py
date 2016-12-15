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

# Colors for writting in terminal
class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

#Importing alice public key
print(bcolors.BOLD + "\n----- Importing Alice public key -----\n" + bcolors.ENDC)
with open('alice.pub') as publicfile:
    pkeydata = publicfile.read().encode('ascii')
pubkey = rsa.PublicKey.load_pkcs1(pkeydata)
print("[BOB] Alice key loaded")

def verify(message, signature):
    try:
        rsa.verify(message, signature, pubkey)
        print(bcolors.GREEN + bcolors.BOLD + "[BOB] Python verify signature : PASSED" + bcolors.ENDC)
        print(bcolors.GREEN + bcolors.BOLD + "[BOB] I identify my contact as Alice" + bcolors.ENDC)
    except:
        print(bcolors.FAIL + bcolors.BOLD + "[BOB] Python verify signature : FAILED" + bcolors.ENDC)
        print(bcolors.FAIL + bcolors.BOLD + "[BOB] I do not recognize my contact as Alice" + bcolors.ENDC)

print(bcolors.BOLD + "\n----- Starting connection between Alice and Bob -----\n" + bcolors.ENDC)
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
verif = False

while True:
    data = connection.recv(buffer_size)
    if not data: break
    print("[BOB] received the signature : ", data)

    if waiting_for_hash:
        hash = data
        print(bcolors.BOLD + "\n----- Verification of the signature -----\n" + bcolors.ENDC)
        verify(message,signature=data)
    else:
        waiting_for_hash = True
        message = data
    if verif == False:
        connection.send("Prouve-le".encode('ASCII'))
        print("[BOB] sent to Oscar : Prouve-le")
        verif = True
    else: break

connection.close()
