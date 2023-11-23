import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password = b"secretPassword"
#salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b')1t\xd0{\xe6\x90\xf2\x80\x8d\x81\xb6\xb3\x8c\xfc\xd0',
    iterations=480000,
)

key = base64.urlsafe_b64encode(kdf.derive(password))

def encrypt(userData):
        
    # using the key
    fernet = Fernet(key)
    
    # encrypting the file
    encrypted = fernet.encrypt(userData.encode())

    return encrypted

def decrypt(encrypted):
    # using the key
    fernet = Fernet(key)
    
    # decrypting the file
    if type(encrypted) == str:
        decrypted = fernet.decrypt(encrypted[2:-1].encode('utf-8')).decode()
    else:
        decrypted = fernet.decrypt(encrypted).decode()
    
    return decrypted

# def main():
#     plain_text = input("Password: ")

#     encrypted = encrypt(plain_text)
#     print("Encrypted: ", encrypted)

#     decrypted = decrypt(encrypted)
#     print("Decrypted: ", decrypted)

# main()