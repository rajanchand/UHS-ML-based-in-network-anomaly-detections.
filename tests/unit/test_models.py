"""
Unit Tests - Database Models
============================
Validates schema properties, constraints, serialization formats,
and password hashing algorithms of SQLAlchemy models.
"""

from datetime import datetime, timezone

from app.models.user import User
from app.models.dataset import Dataset
from app.models.analysis import Analysis
from app.models.audit_log import AuditLog


def test_user_password_hashing():
    """Verify that bcrypt password hashing is secure and accurate."""
    user = User(username='test_user', email='test@example.com')
    user.set_password('mySecureP@ss123')
    
    assert user.password_hash != 'mySecureP@ss123'
    assert len(user.password_hash) > 0
    assert user.check_password('mySecureP@ss123') is True
    assert user.check_password('wrong_password') is False


def test_user_roles():
    """Verify RBAC role checks."""
    admin = User(username='admin', email='admin@example.com', role='admin')
    analyst = User(username='analyst', email='analyst@example.com', role='analyst')
    viewer = User(username='viewer', email='viewer@example.com', role='viewer')
    
    assert admin.is_admin() is True
    assert analyst.is_admin() is False
    
    assert admin.has_role('admin') is True
    assert admin.has_role('analyst') is False
    assert analyst.has_role('analyst', 'admin') is True
    assert viewer.has_role('viewer') is True


def test_dataset_to_dict(db_session):
    """Verify Dataset model serialization structure."""
    dataset = Dataset(
        user_id=1,
        filename='abc.csv',
        original_filename='original.csv',
        file_hash='sha256hashstring',
        file_size=1024,
        row_count=100,
        column_count=5,
        columns_list='["col1", "col2"]',
        status='validated'
    )
    db_session.add(dataset)
    db_session.commit()
    
    data = dataset.to_dict()
    assert data['original_filename'] == 'original.csv'
    assert data['file_size'] == 1024
    assert data['row_count'] == 100
    assert data['status'] == 'validated'


def test_analysis_metrics():
    """Verify analysis duration and anomaly rate calculations."""
    analysis = Analysis(
        dataset_id=1,
        user_id=1,
        model_type='random_forest',
        total_records=200,
        anomalies_detected=50,
        started_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 1, 1, 12, 0, 15, tzinfo=timezone.utc)
    )
    
    assert analysis.anomaly_rate == 25.0
    assert analysis.duration_seconds == 15.0


def test_audit_log_creation(db_session):
    """Verify audit log entries record actions correctly."""
    log = AuditLog(
        user_id=1,
        action='test_action',
        resource='dataset:10',
        ip_address='127.0.0.1',
        details='details description'
    )
    db_session.add(log)
    db_session.commit()
    
    saved_log = AuditLog.query.first()
    assert saved_log.action == 'test_action'
    assert saved_log.ip_address == '127.0.0.1'
    assert saved_log.timestamp is not None
