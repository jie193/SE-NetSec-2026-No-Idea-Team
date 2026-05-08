# SC202: Unsafe encryption mode detection
import bandit
from bandit.core import issue
from bandit.core import test_properties as test
from sensitive_data_plugin.checks.base import BaseDetector
from sensitive_data_plugin.utils.constants import WEAK_MODES

@test.checks("Call")
@test.test_id("SC202")
def unsafe_encryption_mode(context):
    """SC202: Test for use of unsafe encryption modes

    This plugin checks for the usage of unsafe encryption modes such as
    ECB (Electronic Code Book) mode. ECB mode is considered insecure because
    it encrypts identical plaintext blocks into identical ciphertext blocks,
    revealing patterns in the data.

    This plugin detects ECB mode usage in Crypto.Cipher modules and similar
    cryptographic libraries.

    :Example:

    .. code-block:: none

        >> Issue: [SC202:unsafe_encryption_mode] Use of insecure ECB encryption mode
           Severity: High   Confidence: High
           CWE: CWE-327 (https://cwe.mitre.org/data/definitions/327.html)
           Location: ./examples/cipher.py:5
        5       cipher = AES.new(key, AES.MODE_ECB)

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

    # Check for ECB mode or MODE_ECB in function name
    func_name_upper = func_name.upper() if func_name else ''
    if 'ECB' in func_name_upper or 'MODE_ECB' in func_name_upper:
        return detector.create_issue(
            rule_id='SC202',
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            text=f"Use of insecure ECB encryption mode",
            lineno=context.node.lineno,
        )

    # Check call arguments for ECB mode
    args = getattr(context, 'call_args', [])
    keywords = getattr(context, 'call_keywords', {})

    for arg in args:
        if isinstance(arg, str) and 'ecb' in arg.lower():
            return detector.create_issue(
                rule_id='SC202',
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text=f"Use of insecure ECB encryption mode",
                lineno=context.node.lineno,
            )
        # Check for module attributes like AES.MODE_ECB
        if hasattr(arg, 'attr') and 'ECB' in arg.attr.upper():
            return detector.create_issue(
                rule_id='SC202',
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text=f"Use of insecure ECB encryption mode",
                lineno=context.node.lineno,
            )

    # Check keyword arguments
    for key, value in keywords.items():
        if isinstance(value, str) and 'ecb' in value.lower():
            return detector.create_issue(
                rule_id='SC202',
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text=f"Use of insecure ECB encryption mode",
                lineno=context.node.lineno,
            )
        # Check for module attributes
        if hasattr(value, 'attr') and 'ECB' in str(value.attr).upper():
            return detector.create_issue(
                rule_id='SC202',
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text=f"Use of insecure ECB encryption mode",
                lineno=context.node.lineno,
            )

    return None