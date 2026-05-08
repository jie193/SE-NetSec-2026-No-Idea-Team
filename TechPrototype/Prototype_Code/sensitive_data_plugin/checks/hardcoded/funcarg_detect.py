# SC102: Sensitive information in function call arguments
import ast
import re
import bandit
from bandit.core import issue
from bandit.core import test_properties as test
from sensitive_data_plugin.utils.constants import SENSITIVE_KEYWORD_REGEX
from sensitive_data_plugin.utils.filters import should_ignore

# 扩展敏感关键词模式
EXTENDED_SENSITIVE_PATTERNS = re.compile(
    r'(password|pass|passwd|pwd|'
    r'secret|secrete|'
    r'token|auth_token|access_token|refresh_token|'
    r'api_key|apikey|api_secret|apisecret|'
    r'access_key|accesskey|secret_key|secretkey|'
    r'credential|credentials|'
    r'private_key|privatekey|'
    r'client_secret|clientsecret|'
    r'session_key|sessionkey|'
    r'auth_key|authkey)',
    re.IGNORECASE
)

# 常见无风险常量（过滤误报）
SAFE_CONSTANTS = {
    'localhost', '127.0.0.1', 'default', 'none', 'null', 'true', 'false',
    'example', 'test', 'demo', 'sample', 'placeholder', 'changeme',
    'your_password', 'your_api_key', 'your_secret', 'your_token'
}

# 安全函数白名单 - 这些函数的参数即使名称敏感也忽略
SAFE_FUNCTION_WHITELIST = {
    'set_password', 'change_password', 'reset_password', 'validate_password',
    'check_password', 'verify_password', 'hash_password', 'encrypt_password',
    'get_credential', 'load_credential', 'read_credential'
}


def _assess_risk_level(value, arg_name):
    """根据敏感值特征评估风险等级"""
    value_lower = value.lower()

    # 高风险特征
    high_risk_patterns = [
        r'^sk-[A-Za-z0-9]{20,}$',
        r'^pk_[A-Za-z0-9]{20,}$',
        r'^AKIA[A-Z0-9]{16}$',
        r'^[A-Za-z0-9+/=]{32,}$',
        r'^[0-9a-f]{32,}$',
    ]

    for pattern in high_risk_patterns:
        if re.match(pattern, value, re.IGNORECASE):
            return bandit.HIGH

    # 占位符降低风险
    placeholder_patterns = [
        r'^<.*>$', r'^\{.*\}$', r'^\[.*\]$',
        r'^your_', r'^example_', r'^test_',
    ]

    for pattern in placeholder_patterns:
        if re.match(pattern, value_lower):
            return bandit.LOW

    if len(value) >= 12:
        return bandit.HIGH
    elif len(value) >= 6:
        return bandit.MEDIUM

    return bandit.MEDIUM


def _get_remediation_suggestion(arg_name):
    """根据参数类型返回修复建议"""
    arg_lower = arg_name.lower()

    if any(k in arg_lower for k in ['password', 'passwd', 'pwd']):
        return "Read password from environment variable (os.environ.get('PASSWORD')) or secure input"
    elif any(k in arg_lower for k in ['api_key', 'apikey', 'api_secret']):
        return "Load API key from environment variable or configuration file with restricted permissions"
    elif any(k in arg_lower for k in ['token', 'auth_token', 'access_token']):
        return "Obtain token from authentication service or environment variable at runtime"
    elif any(k in arg_lower for k in ['secret']):
        return "Use secret management service or encrypted environment variables"
    else:
        return "Move sensitive values to environment variables or secure configuration system"


@test.checks("Call")
@test.test_id("SC102")
def funcarg_sensitive_info(context):
    """SC102: Test for sensitive information in function call arguments

    This plugin test looks for function calls that have keyword arguments
    with names that look like sensitive information and string literal values.

    Argument names are considered to look like sensitive if they match any one of:
    - password, pass, passwd, pwd
    - secret, secrete
    - token, auth_token, access_token, refresh_token
    - api_key, api_secret, access_key, secret_key
    - credential, credentials
    - private_key, client_secret, session_key, auth_key

    :Example:

    .. code-block:: none

        >> Issue: [SC102:funcarg_sensitive_info] Possible hardcoded sensitive info in function arg: 'admin123'
           Severity: High   Confidence: Medium
           CWE: CWE-798 (https://cwe.mitre.org/data/definitions/798.html)
           Location: ./examples/auth.py:5
        5     login(password="admin123")

    .. seealso::

        - https://www.owasp.org/index.php/Use_of_hard-coded_password
        - https://cwe.mitre.org/data/definitions/798.html

    .. versionadded:: 1.0.0

    """
    node = context.node

    # 检查函数名是否在白名单中
    func_name = None
    if hasattr(node, 'func'):
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

    # Check if the function call has keyword arguments
    if hasattr(node, 'keywords') and node.keywords:
        for kw in node.keywords:
            # Check if the keyword name looks like a sensitive keyword
            if kw.arg and EXTENDED_SENSITIVE_PATTERNS.search(kw.arg):
                # 检查函数是否在白名单中
                if func_name and func_name in SAFE_FUNCTION_WHITELIST:
                    continue

                # Get the value
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    value = kw.value.value
                elif isinstance(kw.value, ast.Str):  # Python < 3.8 compatibility
                    value = kw.value.s
                else:
                    continue

                # 获取实际参数值（处理更复杂的表达式）
                if hasattr(kw.value, '_bandit_parent'):
                    # 可以进一步分析表达式
                    pass

                # Check if the value is a potential sensitive value
                if len(value) >= 6:
                    # 过滤无风险常量
                    value_lower = value.lower().strip()
                    if value_lower in SAFE_CONSTANTS:
                        continue

                    # 跳过环境变量引用
                    if value_lower.startswith('os.environ.') or value_lower.startswith('env('):
                        continue

                    if should_ignore(context, value, kw.arg):
                        continue

                    # 评估风险等级
                    severity = _assess_risk_level(value, kw.arg)

                    # 获取修复建议
                    remediation = _get_remediation_suggestion(kw.arg)

                    return bandit.Issue(
                        severity=severity,
                        confidence=bandit.MEDIUM,
                        cwe=issue.Cwe.from_int(798),
                        text=f"[SC102] Hardcoded {kw.arg} in function call: '{_mask_sensitive_value(value)}'\n"
                             f"    Function: {func_name if func_name else 'unknown'}\n"
                             f"    Fix: {remediation}",
                        lineno=kw.value.lineno,
                    )

    # 检测位置参数中的敏感信息（根据参数名推断）
    # 注意：位置参数需要知道函数签名，这里做简单检测
    if hasattr(node, 'args') and node.args and func_name:
        # 仅为已知的常见敏感函数做位置参数检测
        known_sensitive_funcs = {
            'connect', 'login', 'authenticate', 'authorize',
            'set_credential', 'save_secret', 'store_token'
        }

        if func_name in known_sensitive_funcs:
            for i, arg in enumerate(node.args):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    value = arg.value
                    if len(value) >= 8:
                        severity = _assess_risk_level(value, f"positional_arg_{i}")
                        if severity != bandit.LOW:
                            return bandit.Issue(
                                severity=severity,
                                confidence=bandit.LOW,  # 位置参数置信度较低
                                cwe=issue.Cwe.from_int(798),
                                text=f"[SC102] Possible hardcoded credential in positional argument of '{func_name}': '{_mask_sensitive_value(value)}'",
                                lineno=arg.lineno,
                            )

    return None


def _mask_sensitive_value(value):
    """对敏感值进行脱敏显示"""
    if len(value) <= 8:
        return '*' * len(value)
    else:
        return value[:4] + '*' * (len(value) - 8) + value[-4:]
