# 硬编码敏感信息安全样本代码

# 安全：非敏感关键词
username = "admin"  # 安全：非敏感关键词
email = "user@example.com"  # 安全：非敏感关键词

# 安全：短字符串（长度 < 6）
short_pass = "1234"  # 安全：太短，不可能是密码
short_key = "abc"  # 安全：太短，不可能是密钥

# 安全：常见常量
localhost = "localhost"  # 安全：常见常量
default_port = "8080"  # 安全：常见常量

# 安全：环境变量
import os
password = os.environ.get("PASSWORD")  # 安全：来自环境变量
api_key = os.environ.get("API_KEY")  # 安全：来自环境变量

# 安全：函数调用返回值
password_var = get_password()  # 安全：来自函数调用
login(username="user", password=password_var)  # 安全：使用变量

# 安全：nosec 注释
password = "secret123"  # nosec: 测试用的故意硬编码密码

# 安全：非敏感字典
config = {
    "username": "user",  # 安全：非敏感关键词
    "port": "8080",  # 安全：非敏感关键词
    "host": "localhost",  # 安全：常见常量
}

# 安全：字典中使用变量
api_key_var = get_api_key()
settings = {
    "api_key": api_key_var,  # 安全：使用变量
    "endpoint": "https://api.example.com",  # 安全：URL
}

# 安全：下标赋值使用变量
secret_var = get_secret()
settings["secret"] = secret_var  # 安全：使用变量