import os
from OpenSSL import crypto
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify

def generateSecretKey():
    return os.urandom(16)

def generatePublicPrivateKey():
    private_key = RSA.generate(1024)
    public_key = private_key.publickey()

    private_pem = private_key.export_key().decode()
    public_pem = public_key.export_key().decode()

    with open('private_pem.pem', 'w') as pr:
        pr.write(private_pem)
    with open('public_pem.pem', 'w') as pu:
        pu.write(public_pem)

def encryptFile(secret_key):
    with open("Text.txt", 'rb') as fo:
        plaintext = fo.read()

    plaintext = pad(plaintext)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    enc = iv + cipher.encrypt(plaintext)

    with open("TextEncyrpted.txt", 'wb') as fo:
        fo.write(enc)

def shareSecretKeyUsingPublicKey(secret_key):
    pu_key = RSA.import_key(open('public_pem.pem', 'r').read())
    cipher = PKCS1_OAEP.new(key=pu_key)
    cipher_text = cipher.encrypt(secret_key)

    return cipher_text
        
def recoverSecretKeyUsingPrivateKey(cipher_text):
    pr_key = RSA.import_key(open('private_pem.pem', 'r').read())

    decrypt = PKCS1_OAEP.new(key=pr_key)
    decrypted_message = decrypt.decrypt(cipher_text)

    return decrypted_message

def decrypt_file(key):
    with open("TextEncyrpted.txt", 'rb') as fo:
        ciphertext = fo.read()

    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    dec =  plaintext.rstrip(b"\0")

    with open('TextDecyrpted.txt', 'wb') as fo:
        fo.write(dec)

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


#
# i. Generation of 128-bit secret key for AES Block cipher randomly.
#

secret_key = generateSecretKey()
print("Secret key is generated!\n", secret_key, "\n")

#
# ii. Generation of public and private key pair for RSA Algorithm (Here we assume that this keys are owned by your friend).
#

generatePublicPrivateKey()
print("Public key and private key are generated!\n")

#
# iii. Encrypting a file that you choose using secret key chosen in i).
#

encryptFile(secret_key)

#
# iv. Sharing this secret key using your friend’s public key.
#

cipher_text = shareSecretKeyUsingPublicKey(secret_key)
print("Chipher Text: ", cipher_text, "\n\n")

#
# v. Recovering the secret key using your friend’s private key.
#

decrypted_message = recoverSecretKeyUsingPrivateKey(cipher_text)
print("Decrypted Text: ", decrypted_message, "\n\n")

#
# vi. Decrypting the encrypted file to get a file shared.
#

decrypt_file(decrypted_message)