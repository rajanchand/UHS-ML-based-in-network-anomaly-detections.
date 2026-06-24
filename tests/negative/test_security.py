"""
Negative Security Tests
=======================
Tests resilience against SQL injection inputs, XSS payloads, RBAC boundary escapes,
and malformed or oversized malicious uploads.
"""

import io
from flask_login import login_user
from app.models.user import User


def test_rbac_restrictions(client, seed_users):
    """Verify that viewer accounts cannot access write-level actions."""
    # Authenticate viewer
    with client.session_transaction() as sess:
        sess['_user_id'] = str(seed_users['viewer'].id)
        sess['_fresh'] = True

    # 1. Try to access dataset upload (requires admin/analyst)
    res_upload = client.get('/datasets/upload')
    assert res_upload.status_code == 403

    # 2. Try to run an analysis (requires admin/analyst)
    res_run = client.post('/analysis/run', data={'dataset_id': 1, 'model_type': 'random_forest'})
    assert res_run.status_code == 403


def test_sql_injection_defense(client, db_session):
    """Verify login endpoints handle SQLi escape attempts safely using parameterized DB queries."""
    payload = {
        'username': "admin' OR 1=1 --",
        'password': 'any_password'
    }
    res = client.post('/login', data=payload, follow_redirects=True)
    
    # Assert authentication fails without crashing the server
    assert res.status_code == 200
    assert b'Invalid username or password' in res.data


def test_malicious_xss_prevention(client, db_session):
    """Verify HTML sanitizers clean or reject usernames with script injection tags."""
    reg_payload = {
        'username': "<script>alert('xss')</script>user",
        'email': 'clean@example.com',
        'password': 'SecureP@ssword1!',
        'confirm_password': 'SecureP@ssword1!'
    }
    res = client.post('/register', data=reg_payload, follow_redirects=True)
    
    # Verification schemas should flag validation errors or sanitizer cleans payload
    assert b'Username contains invalid characters' in res.data or b"alert('xss')" not in res.data


def test_invalid_mime_file_upload(client, seed_users):
    """Verify uploads filter out non-CSV binary files."""
    with client.session_transaction() as sess:
        sess['_user_id'] = str(seed_users['analyst'].id)
        sess['_fresh'] = True

    # Upload an EXE/binary lookalike with .csv suffix
    malicious_bin = b'\x4d\x5a\x90\x00\x03\x00\x00\x00' # Executable signature MZ
    data = {
        'file': (io.BytesIO(malicious_bin), 'virus.csv')
    }
    
    res = client.post('/datasets/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200
    assert b'File validation failed' in res.data or b'Only CSV files are allowed' in res.data


def test_role_required_redirects_unauthenticated(client):
    """Verify that unauthenticated requests to role-protected pages are redirected to login."""
    res = client.get('/datasets/upload', follow_redirects=False)
    assert res.status_code == 302
    assert '/login' in res.headers['Location']
    assert 'next=%2Fdatasets%2Fupload' in res.headers['Location']
