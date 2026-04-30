# Bandit 敏感信息检测插件项目实现步骤

## 第一阶段：项目初始化与基础配置

### 步骤1：创建项目目录结构

- 在目标目录下创建项目根目录 `bandit-sensitive-data-plugin/`
- 创建所有必需的目录和空 `__init__.py` 文件
- 创建 `.editorconfig` 文件统一编辑器配置
- 创建 `.gitignore` 文件排除 Python 缓存、虚拟环境等

### 步骤2：配置 setup.py 和 setup.cfg

- 创建 `setup.py` 文件，最小化配置，调用 `setup()`
- 创建 `setup.cfg` 文件：
  - 配置 `[metadata]` 元数据（名称、版本、描述、作者）
  - 配置 `[options]` 包信息和依赖
  - 配置 `[entry_points]` 插件注册（预留位置）
  - 配置 `[options.entry_points]` 插件入口点

### 步骤3：创建主包初始化文件

- 创建 `sensitive_data_plugin/__init__.py`
- 创建 `sensitive_data_plugin/checks/__init__.py`
- 创建各子包的 `__init__.py` 文件

---

## 第二阶段：公共工具层实现

### 步骤4：实现常量定义（constants.py）

- 定义敏感关键词正则表达式（password, token, secret, api_key 等）
- 定义 API 密钥格式模式（AWS AK、OpenAI SK、Base64 格式等）
- 定义弱哈希算法黑名单（md4, md5, sha, sha1）
- 定义弱加密算法黑名单（des, 3des, rc4, arcfour）
- 定义弱加密模式黑名单（ecb）
- 定义最小密钥长度阈值（RSA: 2048, DSA: 2048, EC: 224）
- 定义常见无风险常量列表（localhost, default 等）

### 步骤5：实现误报过滤工具（filters.py）

- 实现 `is_nosec_line()` 函数检测 `# nosec` 注释
- 实现 `is_common_constant()` 函数过滤无风险常量
- 实现 `is_short_string()` 函数过滤短字符串
- 实现 `is_false_positive()` 综合判断函数
- 实现 `get_line_content()` 函数获取代码行内容

---

## 第三阶段：检测规则层实现

### 步骤6：实现硬编码检测规则

#### 6.1 SC100 - 变量赋值硬编码检测
- 实现 `assign_detect.py`
- 使用 `@test.checks("Str")` 装饰器
- 检测变量赋值语句中的硬编码敏感信息
- 返回标准化 Issue 对象

#### 6.2 SC101 - 字典键值对检测
- 实现 `dict_detect.py`
- 使用 `@test.checks("Str")` 装饰器
- 检测字典键值对中的敏感信息
- 处理嵌套字典和复杂结构

#### 6.3 SC102 - 函数参数检测
- 实现 `funcarg_detect.py`
- 使用 `@test.checks("Call")` 装饰器
- 检测函数调用关键字参数中的敏感信息
- 区分参数名称和参数值

### 步骤7：实现加密合规检测规则

#### 7.1 SC200 - 弱哈希算法检测
- 实现 `weak_hash.py`
- 使用 `@test.checks("Call")` 装饰器
- 检测 hashlib 和 crypt 模块中的弱哈希调用
- 识别 `usedforsecurity=False` 参数

#### 7.2 SC201 - 弱加密算法检测
- 实现 `weak_cipher.py`
- 使用 `@test.checks("Call")` 装饰器
- 检测 DES、3DES、RC4 等弱加密算法调用
- 识别 PyCrypto、pycryptodome 等库

#### 7.3 SC202 - 不安全加密模式检测
- 实现 `unsafe_mode.py`
- 使用 `@test.checks("Call")` 装饰器
- 检测 ECB 加密模式的使用
- 识别 Crypto.Cipher 等库的参数

#### 7.4 SC203 - 弱密钥长度检测
- 实现 `weak_key.py`
- 使用 `@test.checks("Call")` 装饰器
- 使用 `@test.takes_config` 装饰器支持配置
- 检测 RSA、DSA、EC 密钥长度不足
- 识别 cryptography 库的密钥生成函数

---

## 第四阶段：插件集成与配置

### 步骤8：完善插件注册配置

- 在 `setup.cfg` 的 `[entry_points]` 中注册所有检测函数
- 为每个检测函数指定唯一的插件名称
- 验证插件加载配置是否正确

### 步骤9：创建检测规则导出模块

- 更新各 `__init__.py` 文件
- 导出所有检测函数
- 确保模块导入路径正确

---

## 第五阶段：测试用例编写

### 步骤10：编写漏洞样本代码

- 创建 `tests/samples/hardcoded_vuln.py` 硬编码漏洞样本
- 创建 `tests/samples/hardcoded_clean.py` 硬编码安全样本
- 创建 `tests/samples/crypto_vuln.py` 加密漏洞样本
- 创建 `tests/samples/crypto_clean.py` 加密安全样本

### 步骤11：编写硬编码检测单元测试

- 创建 `tests/test_hardcoded.py`
- 测试 SC100 变量赋值检测
- 测试 SC101 字典键值对检测
- 测试 SC102 函数参数检测
- 验证误报过滤功能

### 步骤12：编写加密检测单元测试

- 创建 `tests/test_crypto.py`
- 测试 SC200 弱哈希检测
- 测试 SC201 弱加密检测
- 测试 SC202 不安全模式检测
- 测试 SC203 弱密钥长度检测

### 步骤13：编写集成测试

- 创建 `tests/test_integration.py`
- 测试插件完整加载
- 测试 Bandit 命令行调用
- 测试多种输出格式（JSON、HTML、TXT）
- 验证扫描结果完整性

---

## 第六阶段：持续集成与文档

### 步骤14：配置 GitHub Actions

- 创建 `.github/workflows/ci.yml`
- 配置 Python 环境
- 配置依赖安装（bandit, pytest）
- 配置测试运行步骤
- 配置代码质量检查

### 步骤15：编写项目文档

- 创建 `README.md` 项目说明
- 包含项目简介、功能特性、安装指南、使用方法
- 包含各检测规则说明和示例
- 包含配置说明和贡献指南

---

## 第七阶段：验证与优化

### 步骤16：功能验证

- 使用 Bandit 命令行扫描漏洞样本
- 验证所有检测规则正常工作
- 验证输出格式符合预期
- 验证文件路径和行号精确定位

### 步骤17：性能评估

- 测试不同大小代码库的扫描速度
- 分析扫描性能瓶颈
- 优化正则表达式匹配
- 优化 AST 遍历逻辑

### 步骤18：误报率评估

- 使用安全样本测试误报情况
- 调整过滤规则减少误报
- 验证 nosec 注释功能正常
- 优化短字符串过滤阈值

---

## 进度里程碑

| 阶段 | 里程碑 | 交付物 |
|------|--------|--------|
| 第一阶段 | 项目初始化完成 | 目录结构、配置文件 |
| 第二阶段 | 公共工具完成 | constants.py, filters.py |
| 第三阶段 | 检测规则完成 | SC100-SC203 全部实现 |
| 第四阶段 | 插件集成完成 | setup.cfg 配置完成 |
| 第五阶段 | 测试完成 | 样本代码和测试用例 |
| 第六阶段 | CI/CD 完成 | GitHub Actions 配置 |
| 第七阶段 | 项目验收 | 功能验证、性能达标 |

---

## 建议开发顺序

1. **基础先行**：步骤1-3（项目初始化）
2. **工具先行**：步骤4-5（公共工具层）
3. **核心实现**：步骤6-7（检测规则）
4. **配置集成**：步骤8-9（插件注册）
5. **测试保障**：步骤10-13（测试用例）
6. **自动化**：步骤14（CI配置）
7. **文档完善**：步骤15
8. **验证优化**：步骤16-18

这个步骤规划遵循了"基础→工具→核心→配置→测试→CI→文档"的逻辑顺序，便于团队协作和迭代开发。
这个加在docs文档里取名什么好