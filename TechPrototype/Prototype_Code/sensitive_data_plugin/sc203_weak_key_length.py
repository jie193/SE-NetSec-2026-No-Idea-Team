"""
SC203: 弱密钥长度检测规则

检测使用非对称加密算法时密钥长度不足的风险。
依据 NIST SP 800-57 规范：
    - RSA 密钥长度 < 2048 位
    - DSA 密钥长度 < 2048 位
    - EC 密钥长度 < 224 位

适用范围：Python 加密库调用（cryptography, pycryptodome 等）
"""

import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


# 不合规的密钥长度常量
WEAK_KEY_SIZES_RSA_DSA = {512, 768, 1024, 1536}
WEAK_KEY_SIZES_EC = {160, 163, 192}


def _check_rsa_dsa_key_size(call_node, context):
    """检查 RSA/DSA 密钥生成时的密钥长度。

    Args:
        call_node: AST Call 节点
        context: Bandit 上下文对象

    Returns:
        bandit.Issue 对象或 None
    """
    if not call_node.args:
        return None

    first_arg = call_node.args[0]

    # 处理直接传入整数的情况：RSA.generate(1024)
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, int):
        key_size = first_arg.value
        if key_size in WEAK_KEY_SIZES_RSA_DSA or key_size < 2048:
            return issue.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.HIGH,
                text=(
                    f"检测到弱密钥长度：当前使用 {key_size} 位，"
                    f"建议使用 2048 位及以上。"
                ),
                lineno=call_node.lineno,
            )

    # 处理传入变量名的情况：RSA.generate(key_size)
    if isinstance(first_arg, ast.Name):
        var_name = first_arg.id
        # 检查变量名是否暗示弱密钥（如 key_size = 1024）
        parent = call_node
        while hasattr(parent, 'parent'):
            parent = parent.parent
            if isinstance(parent, ast.Assign):
                for target in parent.targets:
                    if (isinstance(target, ast.Name)
                            and target.id == var_name
                            and isinstance(parent.value, ast.Constant)
                            and isinstance(parent.value.value, int)):
                        key_size = parent.value.value
                        if key_size in WEAK_KEY_SIZES_RSA_DSA or key_size < 2048:
                            return issue.Issue(
                                severity=bandit.MEDIUM,
                                confidence=bandit.MEDIUM,
                                text=(
                                    f"检测到弱密钥长度：变量 {var_name} = {key_size} 位，"
                                    f"建议使用 2048 位及以上。"
                                ),
                                lineno=call_node.lineno,
                            )
                break

    return None


def _check_ec_key_size(call_node, context):
    """检查 EC 密钥生成时的曲线选择。

    Args:
        call_node: AST Call 节点
        context: Bandit 上下文对象

    Returns:
        bandit.Issue 对象或 None
    """
    # 检测弱 EC 曲线名称常量
    weak_ec_curves = {
        'SECP192R1', 'secp192r1',
        'SECT163K1', 'sect163k1',
        'SECT163R2', 'sect163r2',
    }

    for arg in call_node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            if arg.value in weak_ec_curves:
                return issue.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.HIGH,
                    text=(
                        f"检测到弱EC曲线：{arg.value}，"
                        f"建议使用 secp256r1 或更高级别曲线。"
                    ),
                    lineno=call_node.lineno,
                )

    return None


def _check_keyword_key_size(call_node):
    """检查关键字参数中的弱密钥长度。

    Args:
        call_node: AST Call 节点

    Returns:
        bandit.Issue 对象或 None
    """
    for keyword in call_node.keywords:
        if keyword.arg in ('key_size', 'keysize'):
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, int):
                key_size = keyword.value.value
                if key_size in WEAK_KEY_SIZES_RSA_DSA or key_size < 2048:
                    return issue.Issue(
                        severity=bandit.MEDIUM,
                        confidence=bandit.HIGH,
                        text=(
                            f"检测到弱密钥长度：{keyword.arg}={key_size}，"
                            f"建议使用 2048 位及以上。"
                        ),
                        lineno=call_node.lineno,
                    )
    return None


@test.checks('Call')
@test.test_id('SC203')
def sc203_weak_key_length(context):
    """检测非对称加密算法中弱密钥长度的使用。

    检测场景：
        1. RSA.generate() / DSA.generate() 中密钥长度 < 2048
        2. EC 曲线选择使用弱曲线（secp192r1 等）
        3. 关键字参数指定弱密钥长度

    Args:
        context: Bandit 上下文对象

    Returns:
        bandit.Issue 对象列表
    """
    node = context.node

    # 仅处理函数调用节点
    if not isinstance(node, ast.Call):
        return

    # 获取被调用的函数名
    func_name = None
    if isinstance(node.func, ast.Attribute):
        func_name = node.func.attr
    elif isinstance(node.func, ast.Name):
        func_name = node.func.id

    if not func_name:
        return

    results = []

    # 检测 RSA.generate() 和 DSA.generate()
    if func_name == 'generate':
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                if module_name in ('RSA', 'DSA'):
                    result = _check_rsa_dsa_key_size(node, context)
                    if result:
                        results.append(result)
                    result = _check_keyword_key_size(node)
                    if result:
                        results.append(result)

    # 检测 EC 曲线选择：ec.generate_private_key(ec.SECP192R1())
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Call):
            inner_call = node.func.value
            if isinstance(inner_call.func, ast.Attribute):
                if inner_call.func.attr in ('SECP192R1', 'SECT163K1', 'SECT163R2'):
                    result = issue.Issue(
                        severity=bandit.MEDIUM,
                        confidence=bandit.HIGH,
                        text=(
                            f"检测到弱EC曲线：{inner_call.func.attr}，"
                            f"建议使用 SECP256R1 或更高级别曲线。"
                        ),
                        lineno=node.lineno,
                    )
                    results.append(result)

    return results
