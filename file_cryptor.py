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

# Mnemonic example
# tomato never network lounge arena select
# quality diesel flash catalog imitate awkward
# tool assault mixture bid girl follow
# unable bonus medal finger name neither

# Key ciphertext example
# KEY_CIPHERTEXT = 'T90NfAQ/xe7FnltMevSbY/GpU4NwLMEpthvLoNm9qxpDH4yDXiA8oouAP5yDYrv/TZVJeTRmB0LYmMN4OfS63JUdk3ydqbF+AYdFhzPBA/w='

KEY_CIPHERTEXT = 'T90NfAQ/xe7FnltMevSbY/GpU4NwLMEpthvLoNm9qxpDH4yDXiA8oouAP5yDYrv/TZVJeTRmB0LYmMN4OfS63JUdk3ydqbF+AYdFhzPBA/w='
KEY_DEFAULT = '7ebfbdb5950ebb7c46d111962f47b4a11165bd9de79a9c1dd0426f9dab67856f'

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
        option = input('[menu] i.Input key  n.New key  q.Quit >> ')

        system('clear')
        print(brief_introduction)
        print('**************************')
        
        # Input key
        if option in ['i', 'I', 'input', 'INPUT']:
            word = input('Mnemonic: ')

            if word == '':
                if (input('[message] Use default key? [Y/n] >> ') or 'n') == 'Y':
                    key = bytes.fromhex(KEY_DEFAULT)
                    plaintext = None
                    break
                else:
                    print('\n')
                    continue

            try:
                key = (bytes(mnemo.to_entropy(word.strip())) + bytes.fromhex(KEY_DEFAULT))[0:32]
            except Exception as e:
                print('[warning] Mnemonic format error' + '\n')
                continue
            
            try:
                plaintext = DataCryptor.decrypt(key, b64decode(KEY_CIPHERTEXT.encode('utf-8')))
                break
            except Exception as e:
                if (input('[message] Use this unknow key? [Y/n] >> ') or 'n') == 'Y':
                    plaintext = None
                    break
                else:
                    print('\n')
                    continue

        # New key
        elif option in ['n', 'N', 'new', 'NEW']:
            print('[message] The default length is 32 bytes')
            key_len = input('Length: ') or '32'
    
            new_key = secrets.token_bytes(int(key_len))

            print('Key: {0}'.format(new_key))
            print('Hex: ' + new_key.hex())
            print('Base64: ' + b64encode(new_key).decode('utf-8'))
            print('Ciphertext: ' + b64encode(DataCryptor.encrypt((new_key + bytes.fromhex(KEY_DEFAULT))[0:32], new_key)).decode('utf-8'))
            try:
                print('Mnemonic: ' + mnemo.to_mnemonic(new_key) + '\n')
            except Exception as e:
                print('Mnemonic: None' + '\n')
            
        # Quit
        elif option in ['q', 'Q', 'quit', 'QUIT']:
            system('clear')
            sys.exit()

        # Invalid option
        else:
            print('[message] Invalid option' + '\n')

    system('clear')
    print(brief_introduction)
    print('**************************')
    while True:    
        if key == bytes.fromhex(KEY_DEFAULT):
            print('[message] Using default key')
        elif key == plaintext:
            pass
        else:
            print('[warning] Using unknow key')

        option = input('[menu] e.Encrypt file  d.Decrypt file  k.display Key  q.Quit >> ')

        system('clear')
        print(brief_introduction)
        print('**************************')
        
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
        
        elif option in ['k', 'K', 'key', 'KEY']:
            print('[tip] Press Enter to display the current key' + '\n')
            words = input('Mnemonic: ') or mnemo.to_mnemonic(key)
            try:
            	entropy = mnemo.to_entropy(words)
            except Exception as e:
            	print('[warning] Mnemonic error' + '\n')
            	continue
            	
            print('Key: {0}'.format(bytes(entropy)))
            print('Hex: ' + entropy.hex())
            print('Base64: ' + b64encode(entropy).decode('utf-8'))
            print('Ciphertext: ' + b64encode(DataCryptor.encrypt(entropy, entropy)).decode('utf-8'))
            if entropy == key:
                print('Mnemonic: ' + mnemo.to_mnemonic(entropy) + '\n')
            else:
                print('\n')

        elif option in ['q', 'Q', 'quit', 'QUIT']:
            system('clear')
            sys.exit()

        # Invalid option
        else:
            print('[message] Invalid option' + '\n')
