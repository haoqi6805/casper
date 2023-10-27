"""AES256 文件加密模块

功能: 采用AES256/EAX算法，对任意格式文件进行加密
版本: 2.0.1
日期: 2023.10.27

依赖环境: 
    Ubuntu 22.04.1 LTS
    Python 3.10.6
    pycryptodomex 3.16.0
    mnemonic 0.20

""" 

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

# AES默认密钥
KEY_DEFAULT = 'pvfjKp949jHW9jndfBRxDyMwIEz9mzuO3wQ2NIwls1A'

class AesEaxCryptor():
    """使用AES/EAX算法加密字节类型数据
    """
    # 加密数据
    @staticmethod
    def encrypt(key, data):
        header = get_random_bytes(16)
        nonce = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=16)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return header + nonce + tag + ciphertext

    # 解密数据
    @staticmethod
    def decrypt(key, data):
        header = data[0:16]
        nonce = data[16:32]
        tag = data[32:48]
        ciphertext = data[48:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

class FileCryptor():
    """使用AES256/EAX算法加密文件
    """
    def __get_key(key):
        return b64decode(((key.strip().rstrip('=') + KEY_DEFAULT)[0:43] + '=').encode('utf-8'))
    
    # 加密文件
    @staticmethod
    def encrypt(key, input_file_path, output_file_path):
        with open(input_file_path, 'rb') as f:
            data = f.read()
        ciphertext = AesEaxCryptor.encrypt(FileCryptor.__get_key(key), data)
        with open(output_file_path, 'w') as f:
            f.write(b64encode(ciphertext).decode('utf-8').rstrip('=') + '\n')
    
    # 解密文件
    @staticmethod
    def decrypt(key, input_file_path, output_file_path):
        with open(input_file_path, 'r') as f:
            data_str = f.read()
        data = b64decode((data_str.strip() + ('=' * ((4 - (len(data_str.strip()) % 4)) % 4))).encode('utf-8'))
        plaintext = AesEaxCryptor.decrypt(FileCryptor.__get_key(key), data)
        with open(output_file_path, 'wb') as f:
            f.write(plaintext)



# 模块测试
if __name__ == "__main__":
    system('clear')
    brief_introduction = 'CASPER AES256 文件加密模块 v2.0.1'
    print(brief_introduction)
    print('*********************************')

    key = None
    mnemo = Mnemonic('english')
    while True:
        option = input('[菜单] i.输入密钥 c.创建密钥 h.帮助 q.退出 >> ')

        system('clear')
        print(brief_introduction)
        print('*********************************')
        
        # 输入密钥
        if option in ['i', 'I', 'input', 'INPUT']:
            key = getpass('密钥: ')
            
            if key == '':
                conform = input('[消息] 使用空密钥？[Y/n] >> ') or 'n'
                print(' ')
                if conform == 'Y':
                    break
                else:
                    key = None
                    continue
            
            try:
                key_bytes = b64decode(((key.strip().rstrip('=') + KEY_DEFAULT)[0:43] + '=').encode('utf-8'))
            except Exception as e:
                print('[警告] 密钥格式错误' + '\n')
                key = None
                continue
            
            try:
                code_str = 'bQbAK/rA6MZj4cRxRj9aBC7MImDrUfcgGBb/uBx45wUqN7XaSA/OFVfIl3V1CTmgnrTMl/8b7asET5eihaF+MsairncjcmsbkA'
                code_bytes = b64decode((code_str.strip() + ('=' * ((4 - (len(code_str.strip()) % 4)) % 4 ))).encode('utf-8'))  
                print('校验码: ' + AesEaxCryptor.decrypt(key_bytes, code_bytes).decode('utf-8').rstrip('\n') + '\n')
                break
            except Exception as e:
                print('校验码: null')
                conform = input('[消息] 使用该密钥？[Y/n] >> ') or 'n'
                print(' ')
                if conform == 'Y':
                    break
                else:
                    key = None

        # 创建随机密钥
        elif option in ['c', 'C', 'creat', 'CREAT']: 
            key_len = input('密钥长度(默认32字节): ') or '32'
            try:
                key_random_bytes = secrets.token_bytes(int(key_len))

                print('新密钥: {0}'.format(key_random_bytes))
                print('16进制: ' + key_random_bytes.hex())
                print('Base64: ' + b64encode(key_random_bytes).decode('utf-8'))
                if int(key_len) not in [16, 20, 24, 32]:
                    print('助记词: 无' + '\n')
                else:
                    mnemonic = mnemo.to_mnemonic(key_random_bytes)
                    print('助记词: ' + mnemonic + '\n')
            except Exception as e:
                print('[消息] 密钥创建失败' + '\n')

        elif option in ['h', 'H', 'help', 'HELP']:
            print('帮助说明:')
            print('1. 本模块采用AES256/EAX算法，对任意格式文件进行加密。')
            print('2. AES是一种对称加密算法，即加密和解密使用相同密钥。')
            print('3. 密钥使用Base64编码格式，其助记词遵循BIP39协议。' + '\n')

        elif option in ['q', 'Q', 'quit', 'QUIT']:
            system('clear')
            sys.exit()

        else:
            print('[消息] 无效选项' + '\n')

    while True:
        option = input('[菜单] e.文件加密 d.文件解密 q.退出 >> ')

        system('clear')
        print(brief_introduction)
        print('*********************************')
        
        # 文件加密
        if option in ['e', 'E', 'encrypt','ENCRYPT']:
            print('文件列表: ' + '  '.join(listdir('./')))
            plaintext_file_name = input('加密文件: ')
            encrypted_file_name = plaintext_file_name
            try:
                FileCryptor.encrypt(key, plaintext_file_name, encrypted_file_name)
                print('[消息] 加密完成' + '\n')
            except Exception as e:
                print('[警告] 加密失败' + '\n')
        
        # 文件解密
        elif option in ['d', 'D', 'decrypt', 'DECRYPT']:
            print('文件列表: ' + '  '.join(listdir('./')))
            encrypted_file_name = input('解密文件: ')
            decrypted_file_name = encrypted_file_name
            try:
                FileCryptor.decrypt(key, encrypted_file_name, decrypted_file_name)
                print('[消息] 解密完成' + '\n')
            except Exception as e:
                print('[警告] 解密失败' + '\n')
        
        elif option in ['q', 'Q', 'quit', 'QUIT']:
            system('clear')
            sys.exit()

        else:
            print('[消息] 无效选项' + '\n')
