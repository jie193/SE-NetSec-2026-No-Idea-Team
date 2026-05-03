# False positive filtering utilities
import re
from sensitive_data_plugin.utils.constants import (
    COMMON_CONSTANTS, 
    MIN_SENSITIVE_LENGTH,
    SENSITIVE_KEYWORD_REGEX
)

def is_nosec_line(context):
    """Check if the line is ignored by # nosec comment
    
    Args:
        context: Bandit context object
        
    Returns:
        bool: True if the line is ignored by # nosec
    """
    if hasattr(context, 'nosec_lines'):
        return context.node.lineno in context.nosec_lines
    return False

def is_common_constant(value):
    """Check if the value is a common non-sensitive constant
    
    Args:
        value: The string value to check
        
    Returns:
        bool: True if the value is a common non-sensitive constant
    """
    if not isinstance(value, str):
        return False
    return value.lower() in COMMON_CONSTANTS

def is_short_string(value):
    """Check if the string is too short to be a sensitive value
    
    Args:
        value: The string value to check
        
    Returns:
        bool: True if the string is too short
    """
    if not isinstance(value, str):
        return False
    return len(value) < MIN_SENSITIVE_LENGTH

def contains_sensitive_keyword(name):
    """Check if the name contains sensitive keywords
    
    Args:
        name: The variable/argument name to check
        
    Returns:
        bool: True if the name contains sensitive keywords
    """
    if not isinstance(name, str):
        return False
    return bool(SENSITIVE_KEYWORD_REGEX.search(name))

def is_false_positive(context, value=None, name=None):
    """Check if the detection is a false positive
    
    Args:
        context: Bandit context object
        value: The value to check (optional)
        name: The variable/argument name to check (optional)
        
    Returns:
        bool: True if the detection is a false positive
    """
    # Check if the line is ignored by # nosec
    if is_nosec_line(context):
        return True
    
    # Check if the value is a common constant
    if value is not None and is_common_constant(value):
        return True
    
    # Check if the string is too short
    if value is not None and is_short_string(value):
        return True
    
    # Check if the name contains sensitive keywords (if provided)
    if name is not None and not contains_sensitive_keyword(name):
        return True
    
    return False

def get_line_content(file_path, line_number):
    """Get the content of a specific line from a file
    
    Args:
        file_path: Path to the file
        line_number: Line number to get
        
    Returns:
        str: The content of the line, or empty string if not found
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if 0 < line_number <= len(lines):
                return lines[line_number - 1].strip()
    except Exception:
        pass
    return ""

def is_ignored_pattern(value):
    """Check if the value matches any ignored patterns
    
    Args:
        value: The string value to check
        
    Returns:
        bool: True if the value matches an ignored pattern
    """
    if not isinstance(value, str):
        return False
    
    # Patterns that are likely not sensitive
    ignored_patterns = [
        r'^\d+$',  # Pure numbers
        r'^[a-zA-Z0-9]{1,5}$',  # Short alphanumeric
        r'^https?://',  # URLs
        r'^\w+@\w+\.\w+$',  # Email addresses
    ]
    
    for pattern in ignored_patterns:
        if re.match(pattern, value):
            return True
    
    return False

def should_ignore(context, value, name=None):
    """Determine if a detection should be ignored
    
    Args:
        context: Bandit context object
        value: The value to check
        name: The variable/argument name to check (optional)
        
    Returns:
        bool: True if the detection should be ignored
    """
    return (
        is_false_positive(context, value, name) or
        is_ignored_pattern(value)
    )
