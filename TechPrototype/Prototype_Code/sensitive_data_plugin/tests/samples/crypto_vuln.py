# 加密漏洞样本代码

# SC200: 弱哈希算法检测
import hashlib

hashlib.md5(b"password")  # 漏洞：弱 MD5 哈希
hashlib.sha1(b"password")  # 漏洞：弱 SHA-1 哈希
hashlib.new("md5", b"password")  # 漏洞：弱 MD5 哈希
hashlib.new("sha1", b"password")  # 漏洞：弱 SHA-1 哈希

# SC201: 弱加密算法检测
from Crypto.Cipher import DES, ARC4

key = b"12345678"
des_cipher = DES.new(key, DES.MODE_ECB)  # 漏洞：弱 DES 算法
arc4_cipher = ARC4.new(key)  # 漏洞：弱 RC4 算法

# SC202: 不安全加密模式检测
from Crypto.Cipher import AES

aes_key = b"12345678901234561234567890123456"
aes_cipher = AES.new(aes_key, AES.MODE_ECB)  # 漏洞：ECB 模式

# SC203: 弱加密密钥长度
import rsa

# 漏洞：弱 RSA 密钥长度（1024 位）
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)

# 漏洞：弱 DSA 密钥长度
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend

dsa_key = dsa.generate_private_key(key_size=1024, backend=default_backend())  # 漏洞：弱 DSA 密钥长度

# 漏洞：弱 EC 密钥长度
from cryptography.hazmat.primitives.asymmetric import ec

ec_key = ec.generate_private_key(ec.SECP160R1(), backend=default_backend())  # 漏洞：弱 EC 密钥长度

# 更多弱哈希示例
hashlib.md4(b"password")  # 漏洞：弱 MD4 哈希

# 使用 pycryptodome 的弱加密算法
from Cryptodome.Cipher import Blowfish

blowfish_key = b"1234567890123456"
blowfish_cipher = Blowfish.new(blowfish_key, Blowfish.MODE_ECB)  # 漏洞：弱 Blowfish 算法