# SC201: Weak encryption algorithm detection
import bandit
from bandit.core import issue
from bandit.core import test_properties as test
from sensitive_data_plugin.checks.base import BaseDetector
from sensitive_data_plugin.utils.constants import WEAK_CIPHERS

@test.checks("Call")
@test.test_id("SC201")
def weak_cipher_algorithm(context):
    """SC201: Test for use of weak encryption algorithms

    This plugin checks for the usage of weak encryption algorithms such as
    DES, 3DES, RC4, ARCFOUR, and Blowfish. These algorithms are considered
    insecure due to their small key sizes or known vulnerabilities.

    This plugin detects usage in various cryptographic libraries including
    PyCrypto, pycryptodome, and other similar libraries.

    :Example:

    .. code-block:: none

        >> Issue: [SC201:weak_cipher_algorithm] Use of weak DES encryption algorithm
           Severity: High   Confidence: High
           CWE: CWE-327 (https://cwe.mitre.org/data/definitions/327.html)
           Location: ./examples/cipher.py:5
        5       cipher = DES.new(key, DES.MODE_ECB)

    .. seealso::

        - https://cwe.mitre.org/data/definitions/327.html
        - https://security.openstack.org/guidelines/dg_strong-crypto.html

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

    # Check for weak cipher algorithms
    func_name_lower = func_name.lower() if func_name else ''

    for weak_name, display_name in WEAK_CIPHERS.items():
        if weak_name in func_name_lower:
            return detector.create_issue(
                rule_id='SC201',
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text=f"Use of weak {display_name} encryption algorithm",
                lineno=context.node.lineno,
            )

    # Check for weak cipher in Crypto.Cipher module patterns
    if func_name:
        if any(weak.upper() in func_name.upper() for weak in WEAK_CIPHERS.keys()):
            return detector.create_issue(
                rule_id='SC201',
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text=f"Use of weak encryption algorithm",
                lineno=context.node.lineno,
            )

    # Check call arguments for weak cipher names
    args = getattr(context, 'call_args', [])
    keywords = getattr(context, 'call_keywords', {})

    for weak_name, display_name in WEAK_CIPHERS.items():
        # Check if any argument contains the weak cipher name
        for arg in args:
            if isinstance(arg, str) and weak_name in arg.lower():
                return detector.create_issue(
                    rule_id='SC201',
                    severity=bandit.HIGH,
                    confidence=bandit.HIGH,
                    text=f"Use of weak {display_name} encryption algorithm",
                    lineno=context.node.lineno,
                )

        # Check keyword values
        for key, value in keywords.items():
            if isinstance(value, str) and weak_name in value.lower():
                return detector.create_issue(
                    rule_id='SC201',
                    severity=bandit.HIGH,
                    confidence=bandit.HIGH,
                    text=f"Use of weak {display_name} encryption algorithm",
                    lineno=context.node.lineno,
                )

    return None