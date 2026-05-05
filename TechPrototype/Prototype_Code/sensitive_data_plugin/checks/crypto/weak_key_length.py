"""
SC203: Weak key length detection

This plugin checks for the usage of insufficient key lengths in
asymmetric encryption algorithms. According to NIST SP 800-57:

    - RSA key size < 2048 bits
    - DSA key size < 2048 bits
    - EC key size < 224 bits (using weak curves like secp192r1)

:Example:

.. code-block:: none

    >> Issue: [SC203:weak_key_length] RSA key size 1024 is insufficient
       Severity: Medium   Confidence: High
       CWE: CWE-326 (https://cwe.mitre.org/data/definitions/326.html)
       Location: ./examples/crypto.py:5
    5       private_key = rsa.generate_private_key(key_size=1024)

.. seealso::

    - https://cwe.mitre.org/data/definitions/326.html
    - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf

.. versionadded:: 1.0.0
"""

import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

from sensitive_data_plugin.checks.base import BaseDetector
from sensitive_data_plugin.utils.constants import WEAK_KEY_SIZES_RSA_DSA, WEAK_EC_CURVES


def _extract_key_size_from_args(args, keywords):
    """从函数参数和关键字参数中提取密钥长度数值。

    Args:
        args: 位置参数列表
        keywords: 关键字参数字典

    Returns:
        int or None: 提取到的密钥长度值
    """
    # 检查位置参数中的整数
    for arg in args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
            return arg.value
        if isinstance(arg, int):
            return arg

    # 检查关键字参数中的 key_size / keysize
    for keyword in keywords:
        if keyword.arg in ('key_size', 'keysize'):
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, int):
                return keyword.value.value
            if isinstance(keyword.value, int):
                return keyword.value

    return None


@test.checks("Call")
@test.test_id("SC203")
def weak_key_length(context):
    """SC203: Test for use of weak key lengths in asymmetric encryption.

    Detects insufficient key sizes when generating RSA, DSA, or EC keys.
    Flags RSA/DSA keys < 2048 bits and EC curves with < 224 bits security.

    :Example:

    .. code-block:: none

        >> Issue: [SC203:weak_key_length] RSA key size 1024 is insufficient
           Severity: Medium   Confidence: High
           CWE: CWE-326 (https://cwe.mitre.org/data/definitions/326.html)
           Location: ./examples/crypto.py:5
        5       private_key = rsa.generate_private_key(key_size=1024)

    .. seealso::

        - https://cwe.mitre.org/data/definitions/326.html
        - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf

    .. versionadded:: 1.0.0
    """
    detector = BaseDetector()

    # Check if line is ignored by # nosec comment
    if detector.is_ignored(context, None, None):
        return None

    # Get function call information
    if hasattr(context, 'call_function_name'):
        func_name = context.call_function_name
    elif hasattr(context, 'node') and hasattr(context.node, 'func'):
        func = context.node.func
        if hasattr(func, 'id'):
            func_name = func.id
        elif hasattr(func, 'attr'):
            func_name = func.attr
        else:
            func_name = None
    else:
        func_name = None

    if func_name is None:
        return None

    # Check for RSA/DSA key generation calls
    rsa_dsa_functions = {'generate_private_key', 'generate_key', 'generate'}
    if func_name in rsa_dsa_functions:
        # Get the module/class name (e.g., rsa.generate_private_key -> rsa)
        module_name = None
        if hasattr(context.node.func, 'value') and hasattr(context.node.func.value, 'id'):
            module_name = context.node.func.value.id

        if module_name in ('rsa', 'RSA', 'dsa', 'DSA'):
            args = getattr(context, 'call_args', [])
            keywords = getattr(context, 'call_keywords', {})

            key_size = _extract_key_size_from_args(args, keywords)

            if key_size is not None and key_size in WEAK_KEY_SIZES_RSA_DSA:
                return detector.create_issue(
                    rule_id='SC203',
                    severity=bandit.MEDIUM,
                    confidence=bandit.HIGH,
                    text=(
                        f"{module_name.upper()} key size {key_size} is insufficient. "
                        f"Use 2048 bits or greater."
                    ),
                    lineno=context.node.lineno,
                )

            if key_size is not None and key_size < 2048:
                return detector.create_issue(
                    rule_id='SC203',
                    severity=bandit.MEDIUM,
                    confidence=bandit.MEDIUM,
                    text=(
                        f"{module_name.upper()} key size {key_size} < 2048 is insufficient. "
                        f"Use 2048 bits or greater."
                    ),
                    lineno=context.node.lineno,
                )

    # Check for EC weak curve usage
    if func_name == 'generate_private_key':
        module_name = None
        if hasattr(context.node.func, 'value') and hasattr(context.node.func.value, 'id'):
            module_name = context.node.func.value.id

        if module_name in ('ec', 'EC'):
            args = getattr(context, 'call_args', [])
            for arg in args:
                # Check for weak EC curve instantiation
                if isinstance(arg, ast.Call) and hasattr(arg.func, 'attr'):
                    curve_name = arg.func.attr
                    curve_name_upper = curve_name.upper()
                    for weak_curve in WEAK_EC_CURVES:
                        if weak_curve.upper() in curve_name_upper:
                            return detector.create_issue(
                                rule_id='SC203',
                                severity=bandit.MEDIUM,
                                confidence=bandit.HIGH,
                                text=(
                                    f"Weak EC curve detected: {curve_name}. "
                                    f"Use SECP256R1 or stronger curve (>= 224 bits)."
                                ),
                                lineno=context.node.lineno,
                            )

    return None
