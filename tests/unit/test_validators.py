"""
Unit Tests - Input Validation Schemas
======================================
Validates Marshmallow validators for user input forms, API endpoints,
and malicious injections checks.
"""

import pytest
from marshmallow import ValidationError

from app.utils.validators import RegistrationSchema, LoginSchema, AnalysisSchema


def test_registration_validation():
    """Verify RegistrationSchema validation rules (length, format, matching)."""
    schema = RegistrationSchema()
    
    # Valid registration
    valid_data = {
        'username': 'sec_analyst',
        'email': 'analyst@aegis.com',
        'password': 'SecureP@ssword1!',
        'confirm_password': 'SecureP@ssword1!'
    }
    loaded = schema.load(valid_data)
    assert loaded['username'] == 'sec_analyst'
    
    # Weak password
    invalid_pw = valid_data.copy()
    invalid_pw['password'] = 'weak'
    with pytest.raises(ValidationError) as excinfo:
        schema.load(invalid_pw)
    assert 'password' in excinfo.value.messages

    # Invalid characters in username (XSS block)
    invalid_user = valid_data.copy()
    invalid_user['username'] = '<script>alert(1)</script>'
    with pytest.raises(ValidationError) as excinfo:
        schema.load(invalid_user)
    assert 'username' in excinfo.value.messages


def test_login_validation():
    """Verify LoginSchema constraints."""
    schema = LoginSchema()
    
    # Missing parameters
    with pytest.raises(ValidationError):
        schema.load({'username': ''})


def test_analysis_schema_validation():
    """Verify AnalysisSchema inputs constraint matching."""
    schema = AnalysisSchema()
    
    # Valid input
    valid_data = {'dataset_id': 12, 'model_type': 'random_forest'}
    loaded = schema.load(valid_data)
    assert loaded['model_type'] == 'random_forest'
    
    # Invalid model selection
    invalid_data = {'dataset_id': 12, 'model_type': 'neural_network'}
    with pytest.raises(ValidationError) as excinfo:
        schema.load(invalid_data)
    assert 'model_type' in excinfo.value.messages
