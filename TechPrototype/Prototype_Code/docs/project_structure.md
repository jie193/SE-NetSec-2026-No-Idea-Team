# 项目结构说明

## 目录树

bandit-sensitive-data-plugin/
├── .editorconfig                # 编辑器格式统一配置
├── .gitignore                   # Git 忽略规则
├── README.md                    # 项目说明与快速开始
├── setup.cfg                    # 项目元数据、依赖、插件注册入口
├── setup.py                     # 最小化安装脚本
│
├── sensitive_data_plugin/       # 插件主包
│   ├── __init__.py
│   ├── checks/
│   │   ├── __init__.py
│   │   ├── base.py              # 【马杰】公共基类
│   │   ├── hardcoded/           # 【马杰+汪维咏】硬编码检测
│   │   │   ├── assign_detect.py #   SC100：变量赋值硬编码密码
│   │   │   ├── dict_detect.py   #   SC101：字典键值敏感信息
│   │   │   └── funcarg_detect.py#   SC102：函数调用参数凭证
│   │   └── crypto/              # 【朱宇航+林睿远】加密合规检测
│   │       ├── weak_hash.py     #   SC200：弱哈希算法
│   │       ├── weak_cipher.py   #   SC201：弱加密算法
│   │       ├── unsafe_mode.py   #   SC202：不安全加密模式
│   │       └── weak_key.py      #   SC203：密钥长度不足
│   └── utils/
│       ├── constants.py         # 敏感关键词、算法黑名单
│       └── filters.py           # 误报过滤工具函数
│
├── tests/
│   ├── samples/                 # 【马杰】测试样本
│   ├── test_hardcoded.py        # 【马杰】硬编码检测测试
│   ├── test_crypto.py           # 【马杰】加密合规测试
│   └── test_integration.py      # 【马杰】集成测试
│
└── .github/workflows/
    └── ci.yml                   # 【马杰】持续集成配置（第10周启用）

## 规则ID与需求映射

| 规则ID | 文件 | Must Have 需求 |
|--------|------|---------------|
| SC100 | hardcoded/assign_detect.py | 变量赋值硬编码检测 |
| SC101 | hardcoded/dict_detect.py | 字典键值敏感信息检测 |
| SC102 | hardcoded/funcarg_detect.py | 函数参数凭证检测 |
| SC200 | crypto/weak_hash.py | MD5/SHA1 弱哈希检测 |
| SC201 | crypto/weak_cipher.py | DES/RC4 弱加密检测 |
| SC202 | crypto/unsafe_mode.py | ECB 不安全模式检测 |
| SC203 | crypto/weak_key.py | RSA 密钥长度不足检测 |

## 分工总览

| 成员 | 负责文件 |
|------|---------|
| 马杰 | setup.cfg、base.py、constants.py、filters.py、ci.yml、assign_detect.py |
| 汪维咏 | dict_detect.py、funcarg_detect.py、tests/samples/*、test_*.py |
| 朱宇航 | weak_hash.py、weak_cipher.py |
| 林睿远 | unsafe_mode.py、weak_key.py |