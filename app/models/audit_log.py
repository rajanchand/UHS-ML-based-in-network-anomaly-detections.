"""
Audit Log Model
===============
Immutable audit trail for security-sensitive operations.
Records user actions with IP addresses and timestamps for
compliance and forensic analysis.
"""

from datetime import datetime, timezone

from app.extensions import db


class AuditLog(db.Model):
    """
    Immutable audit log entry.
    These records should never be modified or deleted in production.
    """

    __tablename__ = 'audit_logs'

    # --- Columns ---
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('users.id'), nullable=True, index=True,
        comment='User who performed the action (null for anonymous)'
    )
    action = db.Column(
        db.String(50), nullable=False,
        comment='Action type: login, logout, upload, analyse, download, etc.'
    )
    resource = db.Column(
        db.String(100), default='',
        comment='Resource affected (e.g., dataset:42, report:7)'
    )
    ip_address = db.Column(
        db.String(45), default='',
        comment='Client IP address (supports IPv6)'
    )
    user_agent = db.Column(
        db.String(500), default='',
        comment='Client user agent string'
    )
    details = db.Column(
        db.Text, default='',
        comment='Additional context (JSON-encoded)'
    )
    timestamp = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc),
        nullable=False, index=True
    )

    def to_dict(self):
        """Serialize audit log entry for API responses."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource': self.resource,
            'ip_address': self.ip_address,
            'details': self.details,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
        }

    def __repr__(self):
        return f'<AuditLog {self.action} by user:{self.user_id} at {self.timestamp}>'
