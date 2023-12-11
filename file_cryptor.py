# Python 3.10.6
from os import system
from os import listdir
from base64 import b64encode
from base64 import b64decode
from getpass import getpass
import sys
import secrets
import readline

# pycryptodomex 3.16.0
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

# mnemonic 0.20
from mnemonic import Mnemonic

# key alphabet
# 0123456789
# ABCDEFGHJKLMNPQRSTUVWXYZ
# abcdefghijkmnopqrstuvwxyz
# /+

# key
# ylw3Sur3burHSxk4W5GXAXw4VqWQH5Yo2JIznuD6Q50
KEY_CIPHERTEXT = 'U5nVyG+EUZdUJPYCHIuBy7c9I0Toq0gNSqA9zVY0Z/tY3N1PturJ1do5EzyzENMPaZ/Q0tFORsL5RWem/b/oVYH6KkGrWW4mKriMlwltGek='

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
            f.write(b64encode(ciphertext).decode('utf-8').rstrip('='))
    
    @staticmethod
    def decrypt(key:bytes, file_path):
        with open(file_path, 'r') as f:
            data = f.read()
        ciphertext = b64decode((data.strip().rstrip('=') + ('=' * ((4 - (len(data.strip()) % 4)) % 4))).encode('utf-8'))
        plaintext = DataCryptor.decrypt(key, ciphertext)
        with open(file_path, 'wb') as f:
            f.write(plaintext)


if __name__ == "__main__":
    def clear_screen():
        brief_introduction = 'Casper File Cryptor 3.0.2'
        system('clear')
        print(brief_introduction)
        print('*************************')

    def print_key(key:bytes):
        print('\n' + 'Key: {0}'.format(key))
        try:
            print('Mnemonic: ' + mnemo.to_mnemonic(key))
        except Exception as e:
            print('Mnemonic: None')
        print('Hex: ' + key.hex())
        print('Base64: ' + b64encode(key).decode('utf-8'))
        try:
            print('Ciphertext: ' + b64encode(DataCryptor.encrypt(key, key)).decode('utf-8') + '\n')
        except Exception as e:
            print('Ciphertext: None' + '\n')

    def option_key(key:bytes):
        option = input('[Key] r.Random c.Current m.Mnemonic h.Hex b.Base64 >> ')
        if option in ['Random', 'r', 'R']:
            try:
                print_key(secrets.token_bytes(int(input('Length (default 32 bytes): ') or '32')))
            except Exception as e:
                print('Warning: Incorrect length' + '\n')
        elif option in ['Current', 'c', 'C']:
            if key == None:
                print('Key: None' + '\n')
            else:
                print_key(key)
        elif option in ['Mnemonic', 'm', 'M']:
            try:
                print_key(bytes(mnemo.to_entropy(input('Enter words: ').strip())))
            except Exception as e:
                print('Warning: Incorrect words' + '\n')
        elif option in ['Hex', 'h', 'H']:
            try:
                print_key(bytes.fromhex(input('Enter hex: ').strip()))
            except Exception as e:
                print('Warning: Incorrect hex' + '\n')
        elif option in ['Base64', 'b', 'B']:
            try:
                print_key(b64decode(input('Enter base64: ').strip().encode('utf-8')))
            except Exception as e:
                print('Warning: Incorrect base64' + '\n')
        else:
            print('Message: Invalid option' + '\n')

    clear_screen()
    key = None
    mnemo = Mnemonic('english')
    while True:
        option = input('[Menu] l.Login k.Key q.Quit >> ')
        clear_screen()
        if option in ['Login', 'l', 'L']:
            option = input('[Login] k.Key m.Mnemonic >> ')
            if option in ['Key', 'k', 'K']:
                key_input = getpass('Enter key: ').strip().rstrip('=')
                if len(key_input) >= 43:
                    key_b64 = key_input[0:43] + '='
                else:
                    key_b64 = key_input + ('0' * (43 - len(key_input))) + '='
                try:
                    key = b64decode((key_b64).encode('utf-8'))
                except Exception as e:
                    print('Warning: Key format error' + '\n')
                    continue
            elif option in ['Mnemonic', 'm', 'M']:
                try:
                    key = bytes(mnemo.to_entropy(input('Enter words: ').strip()))
                except Exception as e:
                    print('Warning: Incorrect words' + '\n')
                    continue
            else:
                print('Message: Invalid option' + '\n')
                continue
            try:
                if key == DataCryptor.decrypt(key, b64decode(KEY_CIPHERTEXT.encode('utf-8'))):
                    break
                else:
                    print('Warning: Incorrect key' + '\n')
            except Exception as e:
                print('Warning: Incorrect key' + '\n')
        elif option in ['Key', 'k', 'K']:
            option_key(key)
        elif option in ['Quit', 'q', 'Q']:
            system('clear')
            sys.exit()
        else:
            print('Message: Invalid option' + '\n')

    clear_screen()
    while True:
        option = input('[Menu] e.Encrypt d.Decrypt k.Key q.Quit >> ')
        clear_screen()
        if option in ['Encrypt', 'e', 'E']:
            print('List: ' + '  '.join(listdir('./')))
            file_name = input('File: ')
            try:
                FileCryptor.encrypt(key, file_name)
                print('Message: Done' + '\n')
            except Exception as e:
                print('Warning: Failed' + '\n')
        elif option in ['Decrypt', 'd', 'D']:
            print('List: ' + '  '.join(listdir('./')))
            file_name = input('File: ')
            try:
                FileCryptor.decrypt(key, file_name)
                print('Message: Done' + '\n')
            except Exception as e:
                print('Warning: Failed' + '\n')
        elif option in ['Key', 'k', 'K']:
            option_key(key)        
        elif option in ['Quit', 'q', 'Q']:
            system('clear')
            sys.exit()
        else:
            print('Message: Invalid option' + '\n')
