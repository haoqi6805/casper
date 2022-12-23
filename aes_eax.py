# 学习AES-EAX加密

# Python版本要求
# https://pycryptodome.readthedocs.io/en/latest/src/introduction.html

# 虚拟环境搭建
# python3 -m venv .venv
# source .venv/bin/activate
# python -m pip install --upgrade pip
# python -m pip install pycryptodomex

# 测试环境
# Ubuntu 22.04.1 LTS
# Python 3.10.6
# pycryptodomex 3.16.0

from os import system
from os import listdir
from base64 import b64encode
from base64 import b64decode
from getpass import getpass
import readline

# pycryptodomex
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

# AES默认密钥
KEY_DEFAULT = 'pvfjKp949jHW9jndfBRxDyMwIEz9mzuO3wQ2NIwls1A'

class AesEaxCryptor():
    """使用AES-EAX算法加密字节类型数据
    """
    @staticmethod
    def encrypt(key, data):
        header = get_random_bytes(16)
        nonce = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=16)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return header + nonce + tag + ciphertext

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
    """使用AES-EAX算法加密文件
    """
    def __get_key(key):
        return b64decode(((key.strip().rstrip('=') + KEY_DEFAULT)[0:43] + '=').encode('utf-8'))
        
    @staticmethod
    def encrypt(key, input_file_path, output_file_path):
        with open(input_file_path, 'rb') as f:
            data = f.read()
        ciphertext = AesEaxCryptor.encrypt(FileCryptor.__get_key(key), data)
        with open(output_file_path, 'w') as f:
            f.write(b64encode(ciphertext).decode('utf-8').rstrip('=') + '\n')
        
    @staticmethod
    def decrypt(key, input_file_path, output_file_path):
        with open(input_file_path, 'r') as f:
            data_str = f.read()
        data = b64decode((data_str.strip() + ('=' * ((4 - (len(data_str.strip()) % 4)) % 4))).encode('utf-8'))
        plaintext = AesEaxCryptor.decrypt(FileCryptor.__get_key(key), data)
        with open(output_file_path, 'wb') as f:
            f.write(plaintext)

if __name__ == "__main__":
    brief_introduction = 'AES-EAX Cryptor'
    print(brief_introduction)

    key = None
    while True:
        print('————————————————————————————————————————————————————————————')
        print('[菜单] e.文件加密 d.文件解密 k.生成密钥 h.帮助 c.清屏 q.退出')
        option = input('[菜单] 选项: ')

        if option in ['e', 'E', 'encrypt','ENCRYPT']:
            if (key is None):
                key = getpass('[加密] 输入密钥(空白则使用内置密钥): ')
            print('[加密] 当前目录列表:  ' + '  '.join(listdir('./')))
            plaintext_file_path = input('[加密] (读取)明文文件: ')
            encrypted_file_path = input('[加密] (生成)加密文件(默认覆盖明文文件): ') or plaintext_file_path
            try:
                FileCryptor.encrypt(key, plaintext_file_path, encrypted_file_path)
                print('[加密] [# 加密成功 #]')
            except Exception as e:
                print('[加密] [# 加密失败 #]')

        elif option in ['d', 'D', 'decrypt', 'DECRYPT']:
            if (key is None):
                key = getpass('[解密] 输入密钥(空白则使用内置密钥): ')
            print('[解密] 当前目录列表:  ' + '  '.join(listdir('./')))
            encrypted_file_path = input('[解密] (读取)加密文件: ')
            decrypted_file_path = input('[解密] (生成)解密文件(默认覆盖加密文件): ') or encrypted_file_path
            try:
                FileCryptor.decrypt(key, encrypted_file_path, decrypted_file_path)
                print('[解密] [# 解密成功 #]')
            except Exception as e:
                print('[解密] [# 解密失败 #]')
        
        elif option in ['k', 'K', 'key', 'KEY']:
            len = input('[密钥] 密钥长度(默认32字节): ') or '32'
            try:
                key_random_bytes = get_random_bytes(int(len))
                key_random = b64encode(key_random_bytes).decode('utf-8')
                print('[密钥] 随机生成: {0}'.format(key_random_bytes))
                print('[密钥] Base64编码: ' + key_random)
            except Exception as e:
                print('[密钥] [# 随机密钥生成失败 #]')

        elif option in ['h', 'H', 'help', 'HELP']:
            print('[帮助] AES-EAX是一种对称加密算法。密钥长度建议16~32字节，使用Base64编码格式。')
        
        elif option in ['c', 'C', 'clear', 'CLEAR']:
            system('clear')
            print(brief_introduction)
    
        elif option in ['q', 'Q', 'quit', 'QUIT']:
            break

        else:
            print('[菜单] [# 无效选项 #]')
