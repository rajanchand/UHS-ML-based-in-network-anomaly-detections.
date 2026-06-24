"""
General Helpers
===============
Utility functions used across the application.
"""

import json
from datetime import datetime, timezone


def now_utc():
    """Get the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


def safe_json_loads(text, default=None):
    """
    Safely parse a JSON string, returning a default on failure.

    Args:
        text: JSON string to parse.
        default: Value to return if parsing fails.

    Returns:
        Parsed JSON object or the default value.
    """
    if not text:
        return default if default is not None else {}
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else {}


def safe_json_dumps(obj):
    """
    Safely serialise an object to JSON string.

    Args:
        obj: Object to serialise.

    Returns:
        JSON string representation.
    """
    try:
        return json.dumps(obj, default=str)
    except (TypeError, ValueError):
        return '{}'


def format_file_size(size_bytes):
    """
    Format a file size in bytes to a human-readable string.

    Args:
        size_bytes: File size in bytes.

    Returns:
        Formatted string (e.g., '2.5 MB').
    """
    if size_bytes < 1024:
        return f'{size_bytes} B'
    elif size_bytes < 1024 * 1024:
        return f'{size_bytes / 1024:.1f} KB'
    elif size_bytes < 1024 * 1024 * 1024:
        return f'{size_bytes / (1024 * 1024):.1f} MB'
    else:
        return f'{size_bytes / (1024 * 1024 * 1024):.1f} GB'


def paginate_query(query, page=1, per_page=20, max_per_page=100):
    """
    Apply pagination to a SQLAlchemy query.

    Args:
        query: SQLAlchemy query to paginate.
        page: Page number (1-indexed).
        per_page: Items per page.
        max_per_page: Maximum allowed items per page.

    Returns:
        Dict with items, pagination metadata, and navigation info.
    """
    # Enforce limits
    page = max(1, page)
    per_page = min(max(1, per_page), max_per_page)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return {
        'items': [item.to_dict() for item in pagination.items],
        'pagination': {
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total': pagination.total,
            'pages': pagination.pages,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev,
        }
    }
