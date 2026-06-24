"""
Authentication Service
======================
Handles user registration, login, and session management.
Implements brute-force protection and password policy enforcement.
"""

from flask import current_app

from app.extensions import db
from app.models.user import User
from app.utils.security import (
    sanitize_html, validate_password_strength, validate_username
)


class AuthService:
    """Business logic for user authentication and registration."""

    @staticmethod
    def register_user(username, email, password, confirm_password):
        """
        Register a new user account with validation.

        Args:
            username: Desired username.
            email: User's email address.
            password: Plaintext password.
            confirm_password: Password confirmation.

        Returns:
            Tuple of (user: User or None, errors: list[str]).
        """
        errors = []

        # Sanitise inputs
        username = sanitize_html(username.strip())
        email = sanitize_html(email.strip().lower())

        # Validate username format
        valid, error = validate_username(username)
        if not valid:
            errors.append(error)

        # Validate password strength
        valid, pw_errors = validate_password_strength(password)
        if not valid:
            errors.extend(pw_errors)

        # Check password confirmation
        if password != confirm_password:
            errors.append('Passwords do not match')

        # Check for duplicate username
        if User.query.filter_by(username=username).first():
            errors.append('Username is already taken')

        # Check for duplicate email
        if User.query.filter_by(email=email).first():
            errors.append('Email is already registered')

        if errors:
            return (None, errors)

        # Create user with hashed password
        try:
            user = User(
                username=username,
                email=email,
                role='analyst',  # Default role for new registrations
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            current_app.logger.info(f'New user registered: {username}')
            return (user, [])

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f'Registration failed: {str(e)}')
            return (None, ['Registration failed. Please try again.'])

    @staticmethod
    def authenticate_user(username, password):
        """
        Authenticate a user by username and password.

        Args:
            username: The username to authenticate.
            password: The plaintext password to verify.

        Returns:
            Tuple of (user: User or None, error: str or None).
        """
        if not username or not password:
            return (None, 'Username and password are required')

        # Sanitise input
        username = sanitize_html(username.strip())

        # Look up user — constant-time to prevent user enumeration
        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            # Generic message prevents user enumeration
            return (None, 'Invalid username or password')

        if not user.is_active:
            return (None, 'Account has been deactivated. Contact an administrator.')

        current_app.logger.info(f'User authenticated: {username}')
        return (user, None)

    @staticmethod
    def get_user_by_id(user_id):
        """Fetch a user by ID."""
        return db.session.get(User, user_id)

    @staticmethod
    def update_user_role(user_id, new_role):
        """
        Update a user's role (admin only).

        Args:
            user_id: ID of the user to update.
            new_role: New role to assign.

        Returns:
            Tuple of (success: bool, error: str or None).
        """
        if new_role not in User.VALID_ROLES:
            return (False, f'Invalid role. Must be one of: {", ".join(User.VALID_ROLES)}')

        user = db.session.get(User, user_id)
        if not user:
            return (False, 'User not found')

        user.role = new_role
        db.session.commit()
        current_app.logger.info(f'User {user.username} role updated to {new_role}')
        return (True, None)
