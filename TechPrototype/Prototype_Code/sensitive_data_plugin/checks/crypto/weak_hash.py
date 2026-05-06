# SC200: Weak hash algorithm detection
import bandit
from bandit.core import issue
from bandit.core import test_properties as test
from sensitive_data_plugin.utils.constants import WEAK_HASHES

@test.checks("Call")
@test.test_id("SC200")
def weak_hash_algorithm(context):
    """SC200: Test for use of weak hash algorithms

    Several highly publicized exploitable flaws have been discovered
    in MD4, MD5, and SHA-1 hash functions. It is strongly recommended
    that the use of these broken hash functions be avoided.

    This plugin checks for the usage of the insecure MD4, MD5, SHA-0, or SHA-1
    hash functions in hashlib and crypt. The hashlib.new function provides
    the ability to construct a new hashing object using the named algorithm.
    This can be used to create insecure hash functions like MD5 and SHA-1
    if they are passed as algorithm names to this function.

    This check does additional checking for usage of keyword 'usedforsecurity'
    on all function variations of hashlib.

    Similar to hashlib, this plugin also checks for usage of one of the
    crypt module's weak hashes. crypt also permits MD5 among other weak
    hash variants.

    :Example:

    .. code-block:: none

        >> Issue: [SC200:weak_hash_algorithm] Use of weak MD5 hash for security. Consider usedforsecurity=False
           Severity: High   Confidence: High
           CWE: CWE-327 (https://cwe.mitre.org/data/definitions/327.html)
           Location: ./examples/hashlib_md5.py:3
        3       hashlib.md5(b"password")

    .. seealso::

        - https://cwe.mitre.org/data/definitions/327.html
        - https://www.nist.gov/publications/specifications-random-number-generation

    .. versionadded:: 1.0.0

    """
    # Get function call information
    if hasattr(context, 'call_function_name'):
        func_name = context.call_function_name
    elif hasattr(context, 'node') and hasattr(context.node, 'func'):
        func_name = getattr(context.node.func, 'id', None)
    else:
        func_name = None

    # Check if it's a hashlib function
    if func_name in WEAK_HASHES:
        # Check for usedforsecurity parameter
        keywords = getattr(context, 'call_keywords', {})
        used_for_security = keywords.get('usedforsecurity', 'True')
        if used_for_security == 'True':
            return bandit.Issue(
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                cwe=issue.Cwe.BROKEN_CRYPTO,
                text=f"Use of weak {WEAK_HASHES[func_name]} hash for security. Consider usedforsecurity=False",
                lineno=context.node.lineno,
            )

    # Check for hashlib.new(name) pattern
    if func_name == 'new':
        args = getattr(context, 'call_args', [])
        keywords = getattr(context, 'call_keywords', {})
        
        # Get the algorithm name from args or keywords
        name = args[0] if args else keywords.get('name', None)
        
        if isinstance(name, str) and name.lower() in WEAK_HASHES:
            used_for_security = keywords.get('usedforsecurity', 'True')
            if used_for_security == 'True':
                return bandit.Issue(
                    severity=bandit.HIGH,
                    confidence=bandit.HIGH,
                    cwe=issue.Cwe.BROKEN_CRYPTO,
                    text=f"Use of weak {WEAK_HASHES[name.lower()]} hash for security. Consider usedforsecurity=False",
                    lineno=context.node.lineno,
                )

    # Check for crypt module weak hashes
    if func_name in ('crypt', 'mksalt'):
        args = getattr(context, 'call_args', [])
        keywords = getattr(context, 'call_keywords', {})
        
        if func_name == 'crypt':
            salt = args[1] if len(args) > 1 else keywords.get('salt', None)
            if isinstance(salt, str) and salt in ('METHOD_CRYPT', 'METHOD_MD5', 'METHOD_BLOWFISH'):
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.HIGH,
                    cwe=issue.Cwe.BROKEN_CRYPTO,
                    text=f"Use of insecure crypt.{salt.replace('METHOD_', '')} hash function",
                    lineno=context.node.lineno,
                )
        elif func_name == 'mksalt':
            method = args[0] if args else keywords.get('method', None)
            if isinstance(method, str) and method in ('METHOD_CRYPT', 'METHOD_MD5', 'METHOD_BLOWFISH'):
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.HIGH,
                    cwe=issue.Cwe.BROKEN_CRYPTO,
                    text=f"Use of insecure crypt.{method.replace('METHOD_', '')} hash function in mksalt",
                    lineno=context.node.lineno,
                )

    return None
