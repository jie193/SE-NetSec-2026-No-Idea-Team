# 硬编码敏感信息漏洞样本代码

# SC100: 变量赋值中的硬编码密码
password = "mysecret123"  # 漏洞：硬编码密码
api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"  # 漏洞：硬编码 API 密钥
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  # 漏洞：硬编码令牌
secret_key = "my-super-secret-key-123456"  # 漏洞：硬编码密钥

# SC101: 字典键值对中的敏感信息
config = {
    "password": "admin123",  # 漏洞：字典中的硬编码密码
    "api_key": "ak-1234567890abcdef",  # 漏洞：字典中的硬编码 API 密钥
    "secret": "my-secret-value",  # 漏洞：字典中的硬编码密钥
    "token": "Bearer abcdef123456",  # 漏洞：字典中的硬编码令牌
}

# SC102: 函数调用参数中的敏感信息
def login(username, password):
    pass

login(username="user", password="password123")  # 漏洞：函数参数中的硬编码密码

# 更多变体
user_secret = "user-secret-123"  # 漏洞：硬编码密钥
access_token = "access-token-123456"  # 漏洞：硬编码访问令牌
private_key = "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----"  # 漏洞：硬编码私钥

# 嵌套字典
nested_config = {
    "database": {
        "username": "admin",
        "password": "dbpass123",  # 漏洞：嵌套字典中的硬编码密码
    }
}

# 下标赋值
settings = {}
settings["api_secret"] = "api-secret-123"  # 漏洞：下标赋值中的硬编码密钥