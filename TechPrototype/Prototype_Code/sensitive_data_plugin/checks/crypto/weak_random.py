"""
SC204: Weak random number generator detection

This plugin checks for the usage of weak pseudo-random number generators
in security-sensitive contexts. The Python ``random`` module is not
cryptographically secure and should not be used for generating tokens,
passwords, session IDs, or cryptographic keys.

Use ``secrets`` module or ``os.urandom()`` instead.

:Example:

.. code-block:: none

    >> Issue: [SC204:weak_random] Weak random number generator used: random.randint()
       Severity: Medium   Confidence: Medium
       CWE: CWE-338 (https://cwe.mitre.org/data/definitions/338.html)
       Location: ./examples/token.py:5
    5       token = random.randint(100000, 999999)

.. seealso::

    - https://cwe.mitre.org/data/definitions/338.html
    - https://docs.python.org/3/library/secrets.html

.. versionadded:: 1.0.0
"""

import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

from sensitive_data_plugin.checks.base import BaseDetector
from sensitive_data_plugin.utils.constants import WEAK_RANDOM_FUNCTIONS


def _is_random_module_call(node):
    """Check if the call is from the ``random`` module.

    Args:
        node: AST Call node

    Returns:
        bool: True if the call is of the form ``random.xxx()``
    """
    if not hasattr(node, 'func'):
        return False
    if not isinstance(node.func, ast.Attribute):
        return False
    if not isinstance(node.func.value, ast.Name):
        return False
    return node.func.value.id == 'random'


def _is_safe_context(node):
    """Try to determine if the call is in a non-security-sensitive context.

    If the enclosing function or class name contains keywords associated
    with non-security scenarios (games, simulations, tests, mocks),
    treat it as a safe context to reduce false positives.

    Args:
        node: AST Call node

    Returns:
        bool: True if the context appears non-security-sensitive
    """
    safe_keywords = {
        'game', 'dice', 'roll', 'simulation', 'simulate',
        'mock', 'dummy', 'test', 'example', 'sample', 'demo',
    }
    current = node
    while hasattr(current, 'parent'):
        current = current.parent
        if isinstance(current, ast.FunctionDef):
            func_name = current.name.lower()
            return any(kw in func_name for kw in safe_keywords)
        if isinstance(current, ast.ClassDef):
            class_name = current.name.lower()
            return any(kw in class_name for kw in safe_keywords)
    return False


@test.checks("Call")
@test.test_id("SC204")
def weak_random(context):
    """SC204: Test for use of weak random number generators.

    Detects calls to ``random.randint()``, ``random.choice()``,
    ``random.getrandbits()`` and other ``random`` module functions
    that may be used in security-sensitive contexts.

    :Example:

    .. code-block:: none

        >> Issue: [SC204:weak_random] Weak random number generator used: random.randint()
           Severity: Medium   Confidence: Medium
           CWE: CWE-338 (https://cwe.mitre.org/data/definitions/338.html)
           Location: ./examples/token.py:5
        5       token = random.randint(100000, 999999)

    .. seealso::

        - https://cwe.mitre.org/data/definitions/338.html
        - https://docs.python.org/3/library/secrets.html

    .. versionadded:: 1.0.0
    """
    detector = BaseDetector()

    # Check if line is ignored by # nosec comment
    if detector.is_ignored(context, None, None):
        return None

    node = context.node

    # Check if this is a random module call
    if not _is_random_module_call(node):
        return None

    func_name = node.func.attr

    # Check if the function is in the weak random function list
    if func_name not in WEAK_RANDOM_FUNCTIONS:
        return None

    # Skip non-security-sensitive contexts to reduce false positives
    if _is_safe_context(node):
        return None

    # Determine severity based on function type
    if func_name in ('getrandbits', 'seed'):
        severity = bandit.HIGH
        confidence = bandit.HIGH
    else:
        severity = bandit.MEDIUM
        confidence = bandit.MEDIUM

    return detector.create_issue(
        rule_id='SC204',
        severity=severity,
        confidence=confidence,
        text=(
            f"Weak random number generator used: random.{func_name}(). "
            f"Use secrets module (e.g., secrets.token_hex()) or "
            f"os.urandom() for security-sensitive contexts."
        ),
        lineno=node.lineno,
    )
