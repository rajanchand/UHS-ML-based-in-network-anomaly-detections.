"""
Integration Tests - Authentication Flow
=======================================
Verifies user registration, login authentication, and logout session handling.
"""

from flask import url_for
from app.models.user import User


def test_auth_view_navigation(client):
    """Verify login and registration views return successful response codes."""
    res_login = client.get('/login')
    assert res_login.status_code == 200
    
    res_register = client.get('/register')
    assert res_register.status_code == 200


def test_registration_and_login_integration(client, db_session):
    """Verify registering a new user allows them to authenticate successfully."""
    # 1. Register user
    reg_payload = {
        'username': 'new_analyst',
        'email': 'new@aegis.com',
        'password': 'SecureP@ssword123!',
        'confirm_password': 'SecureP@ssword123!'
    }
    res_reg = client.post('/register', data=reg_payload, follow_redirects=True)
    assert res_reg.status_code == 200
    
    # Verify user committed to DB
    user = User.query.filter_by(username='new_analyst').first()
    assert user is not None
    assert user.email == 'new@aegis.com'
    
    # 2. Login User
    login_payload = {
        'username': 'new_analyst',
        'password': 'SecureP@ssword123!'
    }
    res_login = client.post('/login', data=login_payload, follow_redirects=True)
    assert res_login.status_code == 200
    assert b'Logged in successfully' in res_login.data
    
    # 3. Logout
    res_logout = client.get('/logout', follow_redirects=True)
    assert res_logout.status_code == 200
    assert b'You have been logged out' in res_logout.data
