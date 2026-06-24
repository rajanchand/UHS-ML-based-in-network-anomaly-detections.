"""
Input Validators
================
Marshmallow-based validation schemas for all API endpoints.
Ensures all user input is validated and sanitised before processing.

Schemas:
    RegistrationSchema — User registration input validation
    LoginSchema        — Login credentials validation
    DatasetUploadSchema — Dataset upload parameters
    AnalysisSchema     — ML analysis parameters
"""

from marshmallow import Schema, fields, validate, validates, ValidationError, EXCLUDE

from app.utils.security import sanitize_html


class RegistrationSchema(Schema):
    """Validates user registration input."""

    class Meta:
        unknown = EXCLUDE

    username = fields.String(
        required=True,
        validate=[
            validate.Length(min=3, max=80,
                            error='Username must be between 3 and 80 characters'),
            validate.Regexp(
                r'^[a-zA-Z][a-zA-Z0-9_]*$',
                error='Username must start with a letter and contain only letters, digits, and underscores'
            ),
        ]
    )
    email = fields.Email(
        required=True,
        error_messages={'invalid': 'Please provide a valid email address'}
    )
    password = fields.String(
        required=True,
        validate=validate.Length(min=8, error='Password must be at least 8 characters')
    )
    confirm_password = fields.String(required=True)

    @validates('username')
    def sanitize_username(self, value, **kwargs):
        """Strip HTML from username to prevent stored XSS."""
        sanitized = sanitize_html(value)
        if sanitized != value:
            raise ValidationError('Username contains invalid characters')


class LoginSchema(Schema):
    """Validates login credentials."""

    class Meta:
        unknown = EXCLUDE

    username = fields.String(
        required=True,
        validate=validate.Length(min=1, error='Username is required')
    )
    password = fields.String(
        required=True,
        validate=validate.Length(min=1, error='Password is required')
    )


class AnalysisSchema(Schema):
    """Validates ML analysis parameters."""

    class Meta:
        unknown = EXCLUDE

    dataset_id = fields.Integer(
        required=True,
        error_messages={'invalid': 'Dataset ID must be a valid integer'}
    )
    model_type = fields.String(
        required=True,
        validate=validate.OneOf(
            ['random_forest', 'xgboost', 'isolation_forest'],
            error='Model must be one of: random_forest, xgboost, isolation_forest'
        )
    )
    # Optional: target column name for supervised models
    target_column = fields.String(
        load_default='label',
        validate=validate.Length(max=100)
    )


class ReportSchema(Schema):
    """Validates report generation parameters."""

    class Meta:
        unknown = EXCLUDE

    analysis_id = fields.Integer(
        required=True,
        error_messages={'invalid': 'Analysis ID must be a valid integer'}
    )
    report_type = fields.String(
        load_default='full',
        validate=validate.OneOf(
            ['full', 'summary', 'executive'],
            error='Report type must be one of: full, summary, executive'
        )
    )
