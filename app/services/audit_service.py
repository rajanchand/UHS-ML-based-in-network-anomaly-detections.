"""
Audit Service
=============
Provides automatic audit trail logging for security-sensitive operations.
All audit entries are immutable and timestamped.
"""

from flask import request, current_app
from flask_login import current_user

from app.extensions import db
from app.models.audit_log import AuditLog


class AuditService:
    """Business logic for audit trail management."""

    @staticmethod
    def log_action(action, resource='', details='', user_id=None):
        """
        Create an audit log entry.

        Args:
            action: Action type string (e.g., 'login', 'upload', 'analyse').
            resource: Resource identifier (e.g., 'dataset:42').
            details: Additional context (free-form text).
            user_id: User ID (defaults to current authenticated user).
        """
        try:
            if user_id is None and current_user and current_user.is_authenticated:
                user_id = current_user.id

            entry = AuditLog(
                user_id=user_id,
                action=action,
                resource=resource,
                ip_address=request.remote_addr if request else '',
                user_agent=str(request.user_agent)[:500] if request else '',
                details=str(details)[:1000],  # Truncate to prevent abuse
            )
            db.session.add(entry)
            db.session.commit()

        except Exception as e:
            # Audit logging should never break application flow
            db.session.rollback()
            current_app.logger.error(f'Audit logging failed: {str(e)}')

    @staticmethod
    def get_recent_logs(limit=50):
        """Get the most recent audit log entries."""
        return AuditLog.query.order_by(AuditLog.timestamp.desc()) \
            .limit(limit).all()

    @staticmethod
    def get_user_logs(user_id, limit=50):
        """Get recent audit logs for a specific user."""
        return AuditLog.query.filter_by(user_id=user_id) \
            .order_by(AuditLog.timestamp.desc()) \
            .limit(limit).all()
