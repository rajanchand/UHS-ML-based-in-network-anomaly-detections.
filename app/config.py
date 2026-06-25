"""
Application Configuration
=========================
Defines configuration classes for different environments.
All sensitive values are loaded from environment variables.

Classes:
    Config: Base configuration shared across all environments.
    DevelopmentConfig: Local development settings (debug mode on).
    TestingConfig: Test suite settings (in-memory SQLite).
    ProductionConfig: Production settings (strict security).
"""

import os
import socket
from datetime import timedelta
from urllib.parse import urlparse, urlunparse

# Base directory of the project
BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
IS_VERCEL = os.environ.get('VERCEL') == '1'

# Use /tmp for writable directories under Vercel serverless environment
DATA_DIR = '/tmp' if IS_VERCEL else BASE_DIR


def _resolve_db_host_to_ipv4(url_str):
    """
    Resolve the database host to an IPv4 address dynamically.
    This bypasses IPv6 socket connection issues on Vercel's AWS Lambda network environment,
    which does not support outbound IPv6 connections (Errno 99: Cannot assign requested address).
    """
    if not url_str:
        return url_str
    try:
        parsed = urlparse(url_str)
        if parsed.hostname:
            ipv4_address = socket.gethostbyname(parsed.hostname)
            netloc = parsed.netloc
            if parsed.port:
                old_host = f"{parsed.hostname}:{parsed.port}"
                new_host = f"{ipv4_address}:{parsed.port}"
            else:
                old_host = parsed.hostname
                new_host = ipv4_address
            
            if old_host in netloc:
                netloc = netloc.replace(old_host, new_host, 1)
            elif parsed.hostname in netloc:
                netloc = netloc.replace(parsed.hostname, ipv4_address, 1)
                
            parsed = parsed._replace(netloc=netloc)
            return urlunparse(parsed)
    except Exception:
        # Fallback to the original URL
        return url_str
    return url_str


class Config:
    """
    Base configuration class.
    Loads secrets from environment variables to prevent hardcoded credentials.
    """

    # --- Flask Core ---
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # --- Database ---
    _db_url = os.environ.get('DATABASE_URL')
    if _db_url and _db_url.startswith('postgres://'):
        _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
    
    if IS_VERCEL:
        _db_url = _resolve_db_host_to_ipv4(_db_url)

    SQLALCHEMY_DATABASE_URI = _db_url or f'sqlite:///{os.path.join(DATA_DIR, "anomaly_detection.db" if IS_VERCEL else os.path.join("instance", "anomaly_detection.db"))}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Configure engine options dynamically to set connection timeout for PostgreSQL
    _engine_options = {
        'pool_pre_ping': True,       # Verify connections before use
        'pool_recycle': 300,         # Recycle connections every 5 minutes
    }
    if SQLALCHEMY_DATABASE_URI.startswith('postgresql'):
        _engine_options['connect_args'] = {'connect_timeout': 5}
    SQLALCHEMY_ENGINE_OPTIONS = _engine_options

    # --- Session Security ---
    SESSION_COOKIE_HTTPONLY = True    # Prevent JS access to session cookie
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection for cookies
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    
    # --- File Upload ---
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500 MB max upload size
    UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
    ALLOWED_EXTENSIONS = {'csv'}
    
    # --- Rate Limiting ---
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '200/hour')
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')
    
    # --- CSRF Protection ---
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour token validity
    
    # --- Logging ---
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', os.path.join(DATA_DIR, 'app.log' if IS_VERCEL else os.path.join('logs', 'app.log')))
    
    # --- ML Configuration ---
    ML_MODELS_DIR = os.path.join(DATA_DIR, 'ml_models')
    SHAP_MAX_SAMPLES = 100  # Max samples for SHAP computation (performance)
    
    # --- Reports ---
    REPORTS_DIR = os.path.join(DATA_DIR, 'reports')


class DevelopmentConfig(Config):
    """Development configuration with debug mode enabled."""
    
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development
    
    # Relax rate limiting for development
    RATELIMIT_DEFAULT = '1000/hour'


class TestingConfig(Config):
    """Testing configuration with in-memory database."""
    
    TESTING = True
    DEBUG = True
    
    # Use in-memory SQLite for fast test execution
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for API testing convenience
    WTF_CSRF_ENABLED = False
    
    # Disable rate limiting in tests
    RATELIMIT_ENABLED = False
    
    SESSION_COOKIE_SECURE = False
    
    # Use temp directory for uploads in tests
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'tests', 'test_uploads')


class ProductionConfig(Config):
    """
    Production configuration with strict security settings.
    All secrets MUST be provided via environment variables.
    """
    
    DEBUG = False
    TESTING = False
    
    # Enforce HTTPS cookies in production (can be disabled for HTTP-only deployments)
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true'
    
    # Require DATABASE_URL in production, fallback to local/temp SQLite
    SQLALCHEMY_DATABASE_URI = Config.SQLALCHEMY_DATABASE_URI
    
    # Production-grade connection pooling with connection timeout for PostgreSQL
    _engine_options = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 10,
        'max_overflow': 20,
    }
    if SQLALCHEMY_DATABASE_URI.startswith('postgresql'):
        _engine_options['connect_args'] = {'connect_timeout': 5}
    SQLALCHEMY_ENGINE_OPTIONS = _engine_options


# Configuration mapping for easy lookup
config_map = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}
