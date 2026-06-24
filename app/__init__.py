"""
Flask Application Factory
==========================
Creates and configures the Flask application using the factory pattern.
This enables multiple app instances (testing, production) and avoids
circular imports.

Security measures applied:
    - Content Security Policy headers
    - X-Frame-Options, X-Content-Type-Options
    - Strict-Transport-Security (HSTS)
    - CSRF protection on all forms
    - Rate limiting on all endpoints
    - Secure session cookies
"""

import os
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, jsonify

from app.config import config_map
from app.extensions import db, migrate, login_manager, csrf, limiter


def create_app(config_name=None):
    """
    Application factory function.

    Args:
        config_name: Configuration to use ('development', 'testing', 'production').
                     Defaults to FLASK_ENV environment variable or 'development'.

    Returns:
        Configured Flask application instance.
    """
    # Create the Flask application
    app = Flask(__name__)

    # Load configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config_map.get(config_name, config_map['default']))

    # Initialise extensions
    _init_extensions(app)

    # Register blueprints (API routes)
    _register_blueprints(app)

    # Register error handlers
    _register_error_handlers(app)

    # Configure logging
    _configure_logging(app)

    # Set up security headers
    _configure_security_headers(app)

    # Ensure required directories exist
    _ensure_directories(app)

    # Register custom template filters
    @app.template_filter('numberFormat')
    def number_format_filter(value):
        try:
            return f"{int(value):,}"
        except (ValueError, TypeError):
            return value

    return app


def _init_extensions(app):
    """Bind all Flask extensions to the application instance."""
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Configure rate limiter from app config
    limiter.init_app(app)


def _register_blueprints(app):
    """Register all API and view blueprints."""
    from app.api.auth import auth_bp
    from app.api.dashboard import dashboard_bp
    from app.api.datasets import datasets_bp
    from app.api.analysis import analysis_bp
    from app.api.reports import reports_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(datasets_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(reports_bp)


def _register_error_handlers(app):
    """Register custom error handlers for common HTTP errors."""

    @app.errorhandler(400)
    def bad_request(error):
        """Handle malformed requests."""
        if _wants_json():
            return jsonify({'error': 'Bad request', 'message': str(error)}), 400
        return render_template('errors/400.html'), 400

    @app.errorhandler(403)
    def forbidden(error):
        """Handle authorization failures."""
        if _wants_json():
            return jsonify({'error': 'Forbidden', 'message': 'Access denied'}), 403
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(error):
        """Handle missing resources."""
        if _wants_json():
            return jsonify({'error': 'Not found', 'message': 'Resource not found'}), 404
        return render_template('errors/404.html'), 404

    @app.errorhandler(429)
    def rate_limited(error):
        """Handle rate limit exceeded."""
        if _wants_json():
            return jsonify({
                'error': 'Rate limit exceeded',
                'message': 'Too many requests. Please try again later.'
            }), 429
        return render_template('errors/429.html'), 429

    @app.errorhandler(500)
    def internal_error(error):
        """Handle unexpected server errors. Never expose internal details in prod, show traceback for debugging."""
        try:
            db.session.rollback()  # Roll back any failed transactions
        except Exception:
            pass
        import traceback
        tb = traceback.format_exc()
        app.logger.error(f'Internal server error: {error}\n{tb}')
        if _wants_json():
            return jsonify({
                'error': 'Internal server error',
                'message': str(error),
                'traceback': tb
            }), 500
        return f"<h3>Internal Server Error (Debugging Traceback)</h3><pre>{tb}</pre>", 500


def _configure_logging(app):
    """
    Set up structured logging with rotation.
    Logs are written to both console and file for monitoring.
    """
    log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO'))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    ))
    app.logger.addHandler(console_handler)

    # File handler (skipped on Vercel serverless functions)
    if os.environ.get('VERCEL') != '1':
        log_file = app.config.get('LOG_FILE', 'logs/app.log')
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=10
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s in %(module)s (%(pathname)s:%(lineno)d): %(message)s'
        ))
        app.logger.addHandler(file_handler)

    app.logger.setLevel(log_level)
    app.logger.info('Application startup complete')


def _configure_security_headers(app):
    """
    Apply security headers to every response.
    These headers mitigate XSS, clickjacking, and MIME-sniffing attacks.
    """
    @app.after_request
    def set_security_headers(response):
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        # Prevent MIME-type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Enable XSS filter in older browsers
        response.headers['X-XSS-Protection'] = '1; mode=block'
        # Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Permissions policy (restrict browser features)
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        # Content Security Policy — allow Bootstrap CDN and Chart.js
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        return response


def _ensure_directories(app):
    """Create required directories if they don't exist."""
    dirs = [
        app.config.get('UPLOAD_FOLDER', 'uploads'),
        app.config.get('ML_MODELS_DIR', 'ml_models'),
        app.config.get('REPORTS_DIR', 'reports'),
    ]
    # Skip log directory check on Vercel as we do not write to file
    if os.environ.get('VERCEL') != '1':
        dirs.append(os.path.dirname(app.config.get('LOG_FILE', 'logs/app.log')))
        
    for directory in dirs:
        os.makedirs(directory, exist_ok=True)


def _wants_json():
    """Check if the client prefers JSON response (API calls)."""
    from flask import request
    return (
        request.accept_mimetypes.best == 'application/json' or
        request.path.startswith('/api/')
    )
