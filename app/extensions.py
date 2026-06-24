"""
Flask Extensions
================
Centralised initialisation of all Flask extensions.
Extensions are created here without binding to a specific app instance,
then initialised in the app factory via init_app().

This pattern avoids circular imports and supports multiple app instances
(e.g. testing vs production).
"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- Database ORM ---
# Provides parameterised queries by default, preventing SQL injection.
db = SQLAlchemy()

# --- Database Migrations ---
# Alembic-based schema migration management.
migrate = Migrate()

# --- Authentication ---
# Session-based user authentication and session management.
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

# --- CSRF Protection ---
# Automatic CSRF token generation and validation for all forms.
csrf = CSRFProtect()

# --- Rate Limiting ---
# Protects endpoints against brute-force and DoS attacks.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri="memory://",
)
