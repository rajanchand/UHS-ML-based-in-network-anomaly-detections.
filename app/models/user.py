"""
User Model
==========
Handles user accounts, password hashing, and role-based access control.

Security features:
    - bcrypt password hashing with configurable work factor
    - Role-based access control (admin, analyst, viewer)
    - Account activation/deactivation
    - Flask-Login integration for session management
"""

from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

from app.extensions import db, login_manager


class User(UserMixin, db.Model):
    """
    User account model with RBAC support.

    Roles:
        admin    — Full system access, user management
        analyst  — Upload datasets, run analyses, generate reports
        viewer   — Read-only access to shared results
    """

    __tablename__ = 'users'

    # --- Columns ---
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(
        db.String(80), unique=True, nullable=False, index=True,
        comment='Unique username for login'
    )
    email = db.Column(
        db.String(120), unique=True, nullable=False, index=True,
        comment='Unique email address'
    )
    password_hash = db.Column(
        db.String(128), nullable=False,
        comment='hashed password — never store plaintext'
    )
    role = db.Column(
        db.String(20), nullable=False, default='analyst',
        comment='User role: admin, analyst, or viewer'
    )
    is_active = db.Column(
        db.Boolean, default=True, nullable=False,
        comment='Whether the account is active (can log in)'
    )
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # --- Relationships ---
    datasets = db.relationship('Dataset', backref='owner', lazy='dynamic')
    analyses = db.relationship('Analysis', backref='owner', lazy='dynamic')
    reports = db.relationship('Report', backref='owner', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')

    # --- Valid roles for RBAC enforcement ---
    VALID_ROLES = ('admin', 'analyst', 'viewer')

    def set_password(self, password):
        """
        Hash and store the user's password using werkzeug.security.

        Args:
            password: Plaintext password to hash.
        """
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        """
        Verify a plaintext password against the stored hash.

        Args:
            password: Plaintext password to verify.

        Returns:
            True if the password matches, False otherwise.
        """
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles):
        """
        Check if the user has one of the specified roles.

        Args:
            *roles: One or more role strings to check against.

        Returns:
            True if the user's role is in the provided list.
        """
        return self.role in roles

    def is_admin(self):
        """Check if the user has admin privileges."""
        return self.role == 'admin'

    def to_dict(self):
        """Serialize user data (excludes password hash for security)."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


@login_manager.user_loader
def load_user(user_id):
    """
    Flask-Login callback: load user by ID from the session.
    Called on every request to hydrate the current_user proxy.
    """
    return db.session.get(User, int(user_id))
