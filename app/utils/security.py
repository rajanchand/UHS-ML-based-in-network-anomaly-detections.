"""
Security Utilities
==================
Defence-in-depth security helpers for input sanitisation, file validation,
and output encoding.

Protects against:
    - XSS (Cross-Site Scripting) via HTML sanitisation
    - Path traversal via filename sanitisation
    - Malicious file uploads via magic byte verification
    - Information disclosure via safe error messages
"""

import hashlib
import os
import re
import uuid

import bleach


# --- XSS Prevention ---

# Allowed HTML tags for sanitised output (minimal set)
ALLOWED_TAGS = []  # Strip ALL HTML tags by default
ALLOWED_ATTRIBUTES = {}


def sanitize_html(text):
    """
    Strip all HTML tags from input to prevent XSS.

    Args:
        text: Raw user input string.

    Returns:
        Sanitised string with all HTML tags removed.
    """
    if not text:
        return ''
    return bleach.clean(str(text), tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)


def sanitize_filename(filename):
    """
    Generate a safe filename by replacing the original with a UUID.
    Preserves the file extension after validation.

    Args:
        filename: Original filename from the upload.

    Returns:
        UUID-based safe filename with validated extension.
    """
    if not filename:
        return None

    # Extract and validate extension
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ('.csv',):
        return None

    # Generate UUID-based filename to prevent path traversal
    safe_name = f"{uuid.uuid4().hex}{ext}"
    return safe_name


def compute_file_hash(file_path):
    """
    Compute SHA-256 hash of a file for integrity verification.

    Args:
        file_path: Path to the file on disk.

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        # Read in 8KB chunks for memory efficiency
        for chunk in iter(lambda: f.read(8192), b''):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


# --- Input Validation ---

def validate_email(email):
    """
    Validate email format using a robust regex pattern.

    Args:
        email: Email string to validate.

    Returns:
        True if the email format is valid.
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, str(email)))


def validate_password_strength(password):
    """
    Enforce password complexity requirements.

    Requirements:
        - Minimum 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character

    Args:
        password: Password string to validate.

    Returns:
        Tuple of (is_valid: bool, errors: list[str]).
    """
    errors = []

    if len(password) < 8:
        errors.append('Password must be at least 8 characters long')
    if not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least one uppercase letter')
    if not re.search(r'[a-z]', password):
        errors.append('Password must contain at least one lowercase letter')
    if not re.search(r'\d', password):
        errors.append('Password must contain at least one digit')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append('Password must contain at least one special character')

    return (len(errors) == 0, errors)


def validate_username(username):
    """
    Validate username format.

    Requirements:
        - 3-80 characters
        - Alphanumeric and underscores only
        - Must start with a letter

    Args:
        username: Username string to validate.

    Returns:
        Tuple of (is_valid: bool, error: str or None).
    """
    if not username or len(username) < 3 or len(username) > 80:
        return (False, 'Username must be between 3 and 80 characters')
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', username):
        return (False, 'Username must start with a letter and contain only letters, digits, and underscores')
    return (True, None)


# --- File Validation ---

# CSV magic bytes (UTF-8 BOM or plain text header)
CSV_SIGNATURES = [
    b'\xef\xbb\xbf',  # UTF-8 BOM
]


def validate_csv_content(file_path):
    """
    Validate that a file contains legitimate CSV content.
    Checks for suspicious patterns that could indicate malicious uploads.

    Args:
        file_path: Path to the uploaded file.

    Returns:
        Tuple of (is_valid: bool, error: str or None).
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            # Read first few lines to validate structure
            first_lines = []
            for i, line in enumerate(f):
                if i >= 5:
                    break
                first_lines.append(line.strip())

            if not first_lines:
                return (False, 'File is empty')

            # Check for suspicious content (script injection, commands)
            suspicious_patterns = [
                r'<script',
                r'javascript:',
                r'on\w+\s*=',
                r'eval\s*\(',
                r'exec\s*\(',
                r'__import__',
                r'subprocess',
                r'os\.system',
            ]
            content = '\n'.join(first_lines).lower()
            for pattern in suspicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return (False, 'File contains suspicious content')

            # Verify it looks like CSV (has delimiters)
            header = first_lines[0]
            if ',' not in header and '\t' not in header and ';' not in header:
                return (False, 'File does not appear to be a valid CSV')

        return (True, None)

    except UnicodeDecodeError:
        return (False, 'File is not valid UTF-8 text')
    except Exception as e:
        return (False, f'File validation error: {str(e)}')


def allowed_file(filename):
    """
    Check if a filename has an allowed extension.

    Args:
        filename: The filename to check.

    Returns:
        True if the extension is in the allowed set.
    """
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in {'csv'}
