"""
Pytest Configuration & Fixtures
===============================
Provides shared fixtures for the test suite, including database setup,
test clients, and mock/generated network dataset assets.
"""

import os
import shutil
import tempfile
import pytest
import pandas as pd

from app import create_app
from app.extensions import db as _db
from app.models.user import User


@pytest.fixture(scope='session')
def app():
    """Session-wide test Flask application."""
    # Ensure a clean testing environment
    app = create_app('testing')
    
    # Create database tables inside test context
    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()

    # Cleanup test uploads directory if it exists
    upload_dir = app.config.get('UPLOAD_FOLDER')
    if upload_dir and os.path.exists(upload_dir):
        shutil.rmtree(upload_dir)


@pytest.fixture
def client(app):
    """Test client for HTTP requests."""
    return app.test_client()


@pytest.fixture(autouse=True)
def db_session(app):
    """Clean database session context per test case."""
    with app.app_context():
        # Setup tables
        _db.create_all()
        yield _db.session
        # Teardown / Rollback session to isolate database runs
        _db.session.rollback()
        _db.drop_all()


@pytest.fixture
def seed_users(db_session):
    """Seeds default users with different roles for RBAC tests."""
    admin = User(username='admin_user', email='admin@aegis.com', role='admin')
    admin.set_password('AdminSecureP@ss1!')
    
    analyst = User(username='analyst_user', email='analyst@aegis.com', role='analyst')
    analyst.set_password('AnalystSecureP@ss1!')
    
    viewer = User(username='viewer_user', email='viewer@aegis.com', role='viewer')
    viewer.set_password('ViewerSecureP@ss1!')

    db_session.add_all([admin, analyst, viewer])
    db_session.commit()
    
    return {
        'admin': admin,
        'analyst': analyst,
        'viewer': viewer
    }


@pytest.fixture
def sample_traffic_csv():
    """Generates a mock network traffic CSV dataset for pipeline testing."""
    # Write a temporary CSV containing standard flow parameters
    data = {
        'duration': [0.1, 0.5, 0.05, 1.2, 0.0, 0.01, 3.5, 0.8, 0.2, 0.15],
        'protocol_type': ['tcp', 'udp', 'tcp', 'icmp', 'tcp', 'tcp', 'udp', 'tcp', 'tcp', 'tcp'],
        'src_bytes': [250, 45, 1024, 0, 0, 5600, 120, 340, 1050, 140],
        'dst_bytes': [4500, 120, 0, 0, 0, 80, 0, 1024, 0, 300],
        'wrong_fragment': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'urgent': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'hot': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'num_failed_logins': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'label': [0, 0, 0, 1, 1, 0, 0, 0, 0, 1]  # 0: normal, 1: anomaly
    }
    
    df = pd.DataFrame(data)
    fd, path = tempfile.mkstemp(suffix='.csv')
    try:
        df.to_csv(path, index=False)
        yield path
    finally:
        os.close(fd)
        if os.path.exists(path):
            os.remove(path)
