"""
Custom Decorators
=================
Reusable decorators for authentication, authorisation, audit logging,
and input validation across all API endpoints.

Usage:
    @login_required          — Ensure user is authenticated
    @role_required('admin')  — Require specific role(s)
    @audit_action('upload')  — Log the action to audit trail
    @validate_json(schema)   — Validate request JSON against schema
"""

from functools import wraps

from flask import jsonify, request, abort, redirect, url_for, flash
from flask_login import current_user

from app.extensions import db
from app.models.audit_log import AuditLog


def role_required(*roles):
    """
    Decorator to enforce role-based access control.
    The user must be authenticated AND have one of the specified roles.

    Args:
        *roles: Allowed role strings (e.g., 'admin', 'analyst').

    Returns:
        Decorated function that checks user role before execution.

    Example:
        @role_required('admin', 'analyst')
        def upload_dataset():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Authentication required'}), 401
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login', next=request.path))

            if not current_user.has_role(*roles):
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Insufficient permissions'}), 403
                abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def audit_action(action_name):
    """
    Decorator to automatically log actions to the audit trail.
    Captures user ID, IP address, user agent, and resource details.

    Args:
        action_name: Description of the action (e.g., 'dataset_upload').

    Example:
        @audit_action('dataset_upload')
        def upload():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Execute the original function first
            result = f(*args, **kwargs)

            # Log the action after successful execution
            try:
                log_entry = AuditLog(
                    user_id=current_user.id if current_user.is_authenticated else None,
                    action=action_name,
                    resource=request.path,
                    ip_address=request.remote_addr or '',
                    user_agent=str(request.user_agent)[:500],  # Truncate long UAs
                    details=f'Method: {request.method}',
                )
                db.session.add(log_entry)
                db.session.commit()
            except Exception:
                # Audit logging should never break the main operation
                db.session.rollback()

            return result
        return decorated_function
    return decorator


def validate_json(required_fields=None):
    """
    Decorator to validate that the request contains valid JSON
    with the specified required fields.

    Args:
        required_fields: List of field names that must be present.

    Example:
        @validate_json(['username', 'password'])
        def login():
            data = request.get_json()
            ...
    """
    if required_fields is None:
        required_fields = []

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            data = request.get_json(silent=True)

            if data is None:
                return jsonify({
                    'error': 'Invalid request',
                    'message': 'Request body must be valid JSON'
                }), 400

            # Check for required fields
            missing = [field for field in required_fields if field not in data]
            if missing:
                return jsonify({
                    'error': 'Missing fields',
                    'message': f'Required fields missing: {", ".join(missing)}'
                }), 400

            return f(*args, **kwargs)
        return decorated_function
    return decorator
