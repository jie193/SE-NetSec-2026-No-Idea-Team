# Bandit 插件 快速部署指南（Windows 专用）
适配 PowerShell 环境，一键完成虚拟环境、依赖安装、插件注册全流程

---

## 1. 创建并激活虚拟环境
```powershell
# 创建虚拟环境（文件夹名为 .venv）使用python3.8
py -3.8 -m venv .venv

# 激活虚拟环境
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
.\.venv\Scripts\Activate.ps1
```

✅ 激活成功标志：命令行前缀出现 `(.venv)`

---

## 2. 升级 pip 至最新版本
```powershell
python -m pip install --upgrade pip
```

---

## 3. 安装项目依赖 + 注册插件
```powershell
# 安装项目依赖包
pip install -r requirements.txt

# 以可编辑模式安装插件（核心：注册到 Bandit）
pip install -e .
```

---

## 4. 验证插件是否注册成功（关键校验）
```powershell
python -c "from stevedore import ExtensionManager; mgr = ExtensionManager('bandit.plugins', invoke_on_load=False); print([ep.name for ep in mgr if 'sc' in ep.name])"
```

### ✅ 预期输出（插件注册成功）
```text
['sc100_hardcoded_password', 'sc101_dict_sensitive', 'sc102_funcarg_sensitive', 'sc200_weak_hash', 'sc201_weak_cipher', 'sc202_unsafe_mode', 'sc203_weak_key']
```

---

## 5. 运行插件测试（验证功能）
```powershell
# 验收标准 哪一项测试通过率
python -m pytest tests/ -v
# 检验规则，会指出什么漏洞有
bandit -r tests/samples/
```