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
from datetime import timedelta

# Base directory of the project
BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
IS_VERCEL = os.environ.get('VERCEL') == '1'

# Use /tmp for writable directories under Vercel serverless environment
DATA_DIR = '/tmp' if IS_VERCEL else BASE_DIR


class Config:
    """
    Base configuration class.
    Loads secrets from environment variables to prevent hardcoded credentials.
    """

    # --- Flask Core ---
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # --- Database ---
    _db_url = os.environ.get('DATABASE_URL')
    if _db_url:
        if _db_url.startswith('postgres://'):
            _db_url = _db_url.replace('postgres://', 'postgresql+pg8000://', 1)
        elif _db_url.startswith('postgresql://'):
            _db_url = _db_url.replace('postgresql://', 'postgresql+pg8000://', 1)

    SQLALCHEMY_DATABASE_URI = _db_url or f'sqlite:///{os.path.join(DATA_DIR, "anomaly_detection.db" if IS_VERCEL else os.path.join("instance", "anomaly_detection.db"))}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,       # Verify connections before use
        'pool_recycle': 300,         # Recycle connections every 5 minutes
    }

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
    
    # Enforce HTTPS cookies in production
    SESSION_COOKIE_SECURE = True
    
    # Require DATABASE_URL in production, fallback to local/temp SQLite
    SQLALCHEMY_DATABASE_URI = Config.SQLALCHEMY_DATABASE_URI
    
    # Production-grade connection pooling
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 10,
        'max_overflow': 20,
    }


# Configuration mapping for easy lookup
config_map = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
}
