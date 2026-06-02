# 加密安全样本代码

# 安全：强哈希算法
import hashlib

hashlib.sha256(b"password")  # 安全：强 SHA-256 哈希
hashlib.sha512(b"password")  # 安全：强 SHA-512 哈希
hashlib.new("sha256", b"password")  # 安全：强 SHA-256 哈希

# 安全：使用 usedforsecurity=False 的弱哈希
hashlib.md5(b"data", usedforsecurity=False)  # 安全：显式声明不用于安全目的

# 安全：强加密算法
from Crypto.Cipher import AES

key = b"12345678901234561234567890123456"
nonce = b"1234567890123456"
aes_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # 安全：GCM 模式

# 安全：强密钥长度
import rsa

# 安全：强 RSA 密钥长度（2048 位）
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# 安全：强 DSA 密钥长度
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend

dsa_key = dsa.generate_private_key(key_size=2048, backend=default_backend())  # 安全：强 DSA 密钥长度

# 安全：强 EC 密钥长度
from cryptography.hazmat.primitives.asymmetric import ec

ec_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())  # 安全：强 EC 密钥长度

# 安全：使用变量密钥长度
import os

# 安全：密钥长度来自变量（假设为强密钥）
key_size = 2048
rsa_key2 = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

# 安全：现代加密库
from cryptography.fernet import Fernet

# 安全：Fernet 默认使用强加密
key = Fernet.generate_key()
cipher_suite = Fernet(key)