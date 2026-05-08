# Constants for sensitive data detection
import re

# Sensitive keyword patterns
SENSITIVE_KEYWORDS = (
    r'(api[_-]?key|secret|token|password|pwd|'
    r'access[_-]?key|private[_-]?key|public[_-]?key|'
    r'auth[_-]?token|secret[_-]?key|api[_-]?secret|'
    r'credential|credentials|pass|passwd|secret_key|'
    r'access_token|refresh_token|api_secret|auth_key)'
)

# Compiled regex for sensitive keywords
SENSITIVE_KEYWORD_REGEX = re.compile(SENSITIVE_KEYWORDS, re.IGNORECASE)

# API key format patterns
API_KEY_PATTERNS = [
    r'^AKIA[0-9A-Z]{16}$',              # AWS access key
    r'^sk-[a-zA-Z0-9]{20,}$',           # OpenAI secret key
    r'^pk-[a-zA-Z0-9]{20,}$',           # Stripe publishable key
    r'^[a-zA-Z0-9+/=]{40,}$',            # Base64 encoded key
    r'^[a-f0-9]{32,}$',                  # Hex encoded key
    r'^[a-zA-Z0-9]{32,}$',               # Generic API key
]

# Compiled regex patterns for API keys
API_KEY_REGEXES = [re.compile(pattern) for pattern in API_KEY_PATTERNS]

# Weak hash algorithms
WEAK_HASHES = {
    'md4': 'MD4',
    'md5': 'MD5',
    'sha': 'SHA-0',
    'sha1': 'SHA-1',
}

# Weak encryption algorithms
WEAK_CIPHERS = {
    'des': 'DES',
    '3des': '3DES',
    'rc4': 'RC4',
    'arcfour': 'ARCFOUR',
    'blowfish': 'Blowfish',
}

# Weak encryption modes
WEAK_MODES = {
    'ecb': 'ECB',
}

# Minimum key lengths (in bits)
MIN_KEY_LENGTHS = {
    'RSA': 2048,
    'DSA': 2048,
    'EC': 224,
}

# Common non-sensitive constants
COMMON_CONSTANTS = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    'default',
    'test',
    'example',
    'demo',
    'dev',
    'development',
    'staging',
    'prod',
    'production',
    'local',
    'none',
    'null',
    'true',
    'false',
    'yes',
    'no',
    'on',
    'off',
    'enable',
    'disable',
    'enabled',
    'disabled',
    'active',
    'inactive',
    'success',
    'error',
    'warning',
    'info',
]

# Minimum string length for sensitive data
MIN_SENSITIVE_LENGTH = 6

# Rule IDs and descriptions
RULES = {
    'SC100': {
        'name': 'hardcoded_password_assign',
        'description': 'Hardcoded password in variable assignment',
        'severity': 'HIGH',
        'confidence': 'MEDIUM',
        'owasp_top_10': 'A02:2021 - Cryptographic Failures',
        'gb_t_22239': 'GB/T 22239-2019 第5.2.2.2条',
        'fix_recommendation': 'Remove hardcoded passwords from source code. Use environment variables or secure vault services to store sensitive credentials.',
    },
    'SC101': {
        'name': 'dict_sensitive_info',
        'description': 'Sensitive information in dictionary key-value pairs',
        'severity': 'HIGH',
        'confidence': 'MEDIUM',
        'owasp_top_10': 'A02:2021 - Cryptographic Failures',
        'gb_t_22239': 'GB/T 22239-2019 第5.2.2.2条',
        'fix_recommendation': 'Remove sensitive data from dictionaries. Store sensitive information in secure storage mechanisms.',
    },
    'SC102': {
        'name': 'funcarg_sensitive_info',
        'description': 'Sensitive information in function call arguments',
        'severity': 'HIGH',
        'confidence': 'MEDIUM',
        'owasp_top_10': 'A02:2021 - Cryptographic Failures',
        'gb_t_22239': 'GB/T 22239-2019 第5.2.2.2条',
        'fix_recommendation': 'Avoid passing sensitive data as plain text function arguments. Use secure parameter passing mechanisms.',
    },
    'SC200': {
        'name': 'weak_hash_algorithm',
        'description': 'Weak hash algorithm usage',
        'severity': 'HIGH',
        'confidence': 'HIGH',
        'owasp_top_10': 'A02:2021 - Cryptographic Failures',
        'gb_t_22239': 'GB/T 22239-2019 第5.2.2.3条',
        'fix_recommendation': 'Replace weak hash algorithms (MD5, SHA-1) with strong algorithms such as SHA-256 or SHA-3.',
    },
    'SC201': {
        'name': 'weak_cipher_algorithm',
        'description': 'Weak encryption algorithm usage',
        'severity': 'HIGH',
        'confidence': 'HIGH',
        'owasp_top_10': 'A02:2021 - Cryptographic Failures',
        'gb_t_22239': 'GB/T 22239-2019 第5.2.2.3条',
        'fix_recommendation': 'Replace weak encryption algorithms (DES, 3DES, RC4) with strong algorithms such as AES-256-GCM.',
    },
    'SC202': {
        'name': 'unsafe_encryption_mode',
        'description': 'Insecure encryption mode',
        'severity': 'HIGH',
        'confidence': 'HIGH',
        'owasp_top_10': 'A02:2021 - Cryptographic Failures',
        'gb_t_22239': 'GB/T 22239-2019 第5.2.2.3条',
        'fix_recommendation': 'Replace ECB mode with secure modes like CBC, GCM, or CTR. Always use authenticated encryption modes.',
    },
    'SC203': {
        'name': 'weak_cryptographic_key',
        'description': 'Weak cryptographic key size',
        'severity': 'HIGH',
        'confidence': 'HIGH',
        'owasp_top_10': 'A02:2021 - Cryptographic Failures',
        'gb_t_22239': 'GB/T 22239-2019 第5.2.2.3条',
        'fix_recommendation': 'Use cryptographic keys with sufficient length: RSA/DSA keys should be at least 2048 bits, EC keys at least 224 bits.',
    },
}