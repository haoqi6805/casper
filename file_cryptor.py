# Python 3.10.6
# pycryptodomex 3.16.0
# mnemonic 0.20

from os import system
from os import listdir
from base64 import b64encode
from base64 import b64decode
from getpass import getpass
import sys
import secrets
import readline

# pycryptodomex
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

# mnemonic
from mnemonic import Mnemonic

# key alphabet
# 0123456789
# ABCDEFGHJKLMNPQRSTUVWXYZ
# abcdefghijkmnopqrstuvwxyz
# /+

# key
# ylw3Sur3burHSxk4W5GXAXw4VqWQH5Yo2JIznuD6Q50

DEBUG = False
KEY_CIPHERTEXT = 'U5nVyG+EUZdUJPYCHIuBy7c9I0Toq0gNSqA9zVY0Z/tY3N1PturJ1do5EzyzENMPaZ/Q0tFORsL5RWem/b/oVYH6KkGrWW4mKriMlwltGek='
KEY_PADDING = 'LRctAHG2ruW2qrPowWJwzn6Rww0V2Xdu29sld1HiEqY'

class DataCryptor():
    @staticmethod
    def encrypt(key:bytes, data:bytes) -> bytes:
        header = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_EAX)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return header + cipher.nonce + tag + ciphertext

    @staticmethod
    def decrypt(key:bytes, data:bytes) -> bytes:
        header = data[0:16]
        nonce = data[16:32]
        tag = data[32:48]
        ciphertext = data[48:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

class FileCryptor():
    @staticmethod
    def encrypt(key:bytes, file_path):
        with open(file_path, 'rb') as f:
            data = f.read()
        ciphertext = DataCryptor.encrypt(key, data)
        with open(file_path, 'w') as f:
            f.write(b64encode(ciphertext).decode('utf-8'))
    
    @staticmethod
    def decrypt(key:bytes, file_path):
        with open(file_path, 'r') as f:
            data = f.read()
        ciphertext = b64decode((data.strip()).encode('utf-8'))
        plaintext = DataCryptor.decrypt(key, ciphertext)
        with open(file_path, 'wb') as f:
            f.write(plaintext)


if __name__ == "__main__":
    system('clear')
    brief_introduction = 'Casper File Cryptor v3.0.2'
    print(brief_introduction)
    print('**************************')

    mnemo = Mnemonic('english')
    while True:
        if DEBUG == True: print('[message] Debug mode')
        option = input('[menu] i.Input key  n.New key  3.Quit >> ')

        system('clear')
        print(brief_introduction)
        print('**************************')
        
        if option in ['i', 'I', 'input', 'INPUT']:
            key_input = getpass('Key: ')
            key_b64 = (key_input.strip().rstrip('=') + KEY_PADDING)[0:43] + '='
            if DEBUG == True: 
                print('Key input: ' + key_input)
                print('Base64: ' + key_b64 + '\n')
        
            try:
                key = b64decode(key_b64.encode('utf-8'))
                if DEBUG == True:
                    print('Key: {0}'.format(key))
                    print('Hex: ' + key.hex())
                    print('Base64: ' + b64encode(key).decode('utf-8'))
                    print('Ciphertext: ' + b64encode(DataCryptor.encrypt(key, key)).decode('utf-8'))
                    print('Mnemonic: ' + mnemo.to_mnemonic(key) + '\n')
            except Exception as e:
                print('[warning] Key format error' + '\n')
                continue

            try:
                key_plaintext = DataCryptor.decrypt(key, b64decode(KEY_CIPHERTEXT.encode('utf-8')))
                if DEBUG == True: print('Key plaintext: {0}'.format(key_plaintext))
            except Exception as e:
                print('[warning] Incorrect key' + '\n')
                continue

            if key == key_plaintext:
                if DEBUG == True: input('[message] Press any key to continue >> ')
                break
            else:
                print('[warning] Unknown error' + '\n')
                continue
            
        elif option in ['n', 'N', 'new', 'NEW']: 
            key_len = input('Length (default 32 bytes): ') or '32'
    
            try:
                new_key = secrets.token_bytes(int(key_len))
            except Exception as e:
                print('[warning] Key generation failed' + '\n')
                continue

            print('Key: {0}'.format(new_key))
            print('Hex: ' + new_key.hex())
            print('Base64: ' + b64encode(new_key).decode('utf-8'))
            try:
                print('Mnemonic: ' + mnemo.to_mnemonic(new_key) + '\n')
            except Exception as e:
                print('Mnemonic: None' + '\n')

        elif option in ['q', 'Q', 'quit', 'QUIT']:
            system('clear')
            sys.exit()

        else:
            print('[message] Invalid option' + '\n')

    while True:
        if DEBUG == True: print('[message] Debug mode')
        option = input('[menu] e.Encrypt file  d.Decrypt file  q.Quit >> ')

        system('clear')
        print(brief_introduction)
        print('*********************************')
        
        if option in ['e', 'E', 'encrypt','ENCRYPT']:
            print('List: ' + '  '.join(listdir('./')))
            file_name = input('File: ')
            try:
                FileCryptor.encrypt(key, file_name)
                print('[message] Encryption successful' + '\n')
            except Exception as e:
                print('[warning] Encryption failed' + '\n')
        
        elif option in ['d', 'D', 'decrypt', 'DECRYPT']:
            print('List: ' + '  '.join(listdir('./')))
            file_name = input('File: ')
            try:
                FileCryptor.decrypt(key, file_name)
                print('[message] Decryption successful' + '\n')
            except Exception as e:
                print('[warning] Decryption failed' + '\n')

        elif option in ['q', 'Q', 'quit', 'QUIT']:
            system('clear')
            sys.exit()

        else:
            print('[message] Invalid option' + '\n')
