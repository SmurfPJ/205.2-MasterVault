# import zlib
# import struct
# from crypto.cipher import AES

# class CheckSumError(Exception):
#     pass

# def _lazysecret(secret, blocksize=32, padding='}'):
#     """pads secret if not legal AES block size (16, 24, 32)"""
#     if not len(secret) in (16, 24, 32):
#         return secret + (blocksize - len(secret)) * padding
#     return secret

# def encrypt(plaintext, secret, lazy=True, checksum=True):
#     """encrypt plaintext with secret
#     plaintext   - content to encrypt
#     secret      - secret to encrypt plaintext
#     lazy        - pad secret if less than legal blocksize (default: True)
#     checksum    - attach crc32 byte encoded (default: True)
#     returns ciphertext
#     """

#     secret = _lazysecret(secret) if lazy else secret
#     encobj = AES.new(secret, AES.MODE_CFB)

#     if checksum:
#         plaintext += struct.pack("i", zlib.crc32(plaintext))

#     return encobj.encrypt(plaintext)

# def decrypt(ciphertext, secret, lazy=True, checksum=True):
#     """decrypt ciphertext with secret
#     ciphertext  - encrypted content to decrypt
#     secret      - secret to decrypt ciphertext
#     lazy        - pad secret if less than legal blocksize (default: True)
#     checksum    - verify crc32 byte encoded checksum (default: True)
#     returns plaintext
#     """

#     secret = _lazysecret(secret) if lazy else secret
#     encobj = AES.new(secret, AES.MODE_CFB)
#     plaintext = encobj.decrypt(ciphertext)

#     if checksum:
#         crc, plaintext = (plaintext[-4:], plaintext[:-4])
#         if not crc == struct.pack("i", zlib.crc32(plaintext)):
#             raise CheckSumError("checksum mismatch")

#     return plaintext

# ciphertext = encrypt("confidential data", "mySecret")
# print(ciphertext)
# print(decrypt(ciphertext, "mySecret"))


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



# def encrypt(plain_text):
#     # generate a random salt
#     salt = get_random_bytes(AES.block_size)

#     # use the Scrypt KDF to get a private key from the password
#     private_key = hashlib.scrypt(
#         encryptionPassword.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

#     # create cipher config
#     cipher_config = AES.new(private_key, AES.MODE_GCM)

#     # return a dictionary with the encrypted text
#     cipher_text = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8')) # , tag

#     # print("Tag: ", b64encode(tag).decode('utf-8'))
#     # print("Nonce: ", b64encode(cipher_config.nonce).decode('utf-8'))

#     return {
#         'cipher_text': b64encode(cipher_text).decode('utf-8'),
#         'salt': b64encode(salt).decode('utf-8'),
#         'nonce': b64encode(nonce).decode('utf-8'),
#         'tag': b64encode(tag).decode('utf-8')
#     }


# def decrypt(enc_dict):

#     # decode the dictionary entries from base64
#     salt = b64decode(enc_dict['salt'])
#     cipher_text = b64decode(enc_dict['cipher_text'])
#     decodedNonce = b64decode(enc_dict['nonce'])
#     decodedTag = b64decode(enc_dict['tag'])
    

#     # generate the private key from the password and salt
#     private_key = hashlib.scrypt(
#         encryptionPassword.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

#     # create the cipher config
#     cipher = AES.new(private_key, AES.MODE_GCM, decodedNonce=decodedNonce)

#     # decrypt the cipher text
#     decrypted = cipher.decrypt_and_verify(cipher_text, decodedTag)

#     return bytes.decode(decrypted)