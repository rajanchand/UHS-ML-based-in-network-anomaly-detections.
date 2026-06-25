"""
Integration Tests - Authentication Flow
=======================================
Verifies user registration, login authentication, and logout session handling.
"""

from flask import url_for
from app.models.user import User


def test_auth_view_navigation(client):
    """Verify login page is accessible and register returns 404."""
    res_login = client.get('/login')
    assert res_login.status_code == 200
    
    res_register = client.get('/register')
    assert res_register.status_code == 404


def test_login_and_logout_integration(client, seed_users):
    """Verify logging in with seeded credentials works and logs out successfully."""
    # 1. Login User using seeded test credentials
    login_payload = {
        'username': 'admin_user',
        'password': 'AdminSecureP@ss1!'
    }
    res_login = client.post('/login', data=login_payload, follow_redirects=True)
    assert res_login.status_code == 200
    assert b'Logged in successfully' in res_login.data
    
    # 2. Logout
    res_logout = client.get('/logout', follow_redirects=True)
    assert res_logout.status_code == 200
    assert b'You have been logged out' in res_logout.data
