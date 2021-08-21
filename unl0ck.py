from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64






ROOTPATH = '/home/'+os.getlogin()+'/Desktop'
SUBPATHS = []
KEY = b'UvJzgXfvtojkna1BJwXKch0WwILy-sOVENYOz46i_Fw='

def getFile():
    for r,d,f in os.walk(ROOTPATH):
        for files in f:
            SUBPATHS.append(os.path.join(r,files))

def decrypt(path,key):
    fernet = Fernet(key)
    filename = os.path.basename(path)
    file = open(path,'rb')
    output_name = filename.strip('.l0ck')
    output_file_path = path.replace(filename,output_name)
    filedata=file.read()
    file.close()
    decrypted = fernet.decrypt(filedata)
    try:
        efile = open(output_file_path,'wb')
        efile.write(decrypted)
        efile.close()
    except cryptography.fernet.InvalidToken:
        print("Invalid Key!!!")
    except:
        pass
'''
kdf = PBKDF2HMAC(
    salt=b'\x7f\xea\xf9,\xf5\xd3\xe3\xc7\xaeA\x18A\x88\xfa\x17ST\nF2}\x15f\xbe\xf4N7\xfcD\xa3\xdb\x95',
    #salt=salt,
    algorithm=hashes.SHA256(),
    length=32,
    iterations=10000,
)
'''

key = base64.urlsafe_b64encode(kdf.derive(id.encode()))
getFile()

for paths in SUBPATHS:
    print(paths)
for fil3 in SUBPATHS:
    if not fil3.endswith('.l0ck'):
        continue
    decrypt(fil3,KEY)
    os.remove(fil3)