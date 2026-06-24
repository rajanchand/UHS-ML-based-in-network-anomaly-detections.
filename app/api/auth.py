"""
Authentication Blueprint
========================
Handles user registration, login, logout, and session status.
Supports both HTML rendering and JSON API requests.
"""

from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from marshmallow import ValidationError

from app.services.auth_service import AuthService
from app.services.audit_service import AuditService
from app.utils.validators import RegistrationSchema, LoginSchema
from app.utils.decorators import audit_action

auth_bp = Blueprint('auth', __name__)

registration_schema = RegistrationSchema()
login_schema = LoginSchema()


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration view and API endpoint."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        # Check if JSON or form data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()

        try:
            # Validate input schema
            validated_data = registration_schema.load(data)
        except ValidationError as err:
            if request.is_json:
                return jsonify({'error': 'Validation error', 'messages': err.messages}), 400
            for field, messages in err.messages.items():
                for msg in messages:
                    flash(f"{field.capitalize()}: {msg}", 'danger')
            return render_template('auth/register.html')

        user, errors = AuthService.register_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            confirm_password=validated_data['confirm_password']
        )

        if errors:
            if request.is_json:
                return jsonify({'error': 'Registration failed', 'messages': errors}), 400
            for err in errors:
                flash(err, 'danger')
            return render_template('auth/register.html')

        # Log audit entry
        AuditService.log_action(
            action='register',
            resource=f'user:{user.id}',
            details=f'User registered: {user.username}',
            user_id=user.id
        )

        flash('Registration successful! Please log in.', 'success')
        if request.is_json:
            return jsonify({'message': 'Registration successful', 'user': user.to_dict()}), 201
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login view and API endpoint."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()

        try:
            validated_data = login_schema.load(data)
        except ValidationError as err:
            if request.is_json:
                return jsonify({'error': 'Validation error', 'messages': err.messages}), 400
            for field, messages in err.messages.items():
                for msg in messages:
                    flash(f"{field.capitalize()}: {msg}", 'danger')
            return render_template('auth/login.html')

        user, error = AuthService.authenticate_user(
            username=validated_data['username'],
            password=validated_data['password']
        )

        if error:
            # Audit failed attempt
            AuditService.log_action(
                action='login_failed',
                resource=f'username:{validated_data["username"]}',
                details=f'Failed login attempt: {error}'
            )
            if request.is_json:
                return jsonify({'error': 'Authentication failed', 'message': error}), 401
            flash(error, 'danger')
            return render_template('auth/login.html')

        # Log user in
        login_user(user, remember=True)

        # Audit successful login
        AuditService.log_action(
            action='login',
            resource=f'user:{user.id}',
            details=f'User logged in: {user.username}',
            user_id=user.id
        )

        flash('Logged in successfully.', 'success')
        if request.is_json:
            return jsonify({'message': 'Login successful', 'user': user.to_dict()}), 200
        
        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('dashboard.index')
        return redirect(next_page)

    return render_template('auth/login.html')


@auth_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    """Logs user out and destroys session."""
    username = current_user.username
    user_id = current_user.id

    logout_user()

    AuditService.log_action(
        action='logout',
        resource=f'user:{user_id}',
        details=f'User logged out: {username}',
        user_id=user_id
    )

    if request.is_json or request.method == 'POST' and request.path.startswith('/api/'):
        return jsonify({'message': 'Logout successful'}), 200

    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/api/auth/me', methods=['GET'])
@login_required
def me():
    """Returns details of currently authenticated user."""
    return jsonify(current_user.to_dict()), 200
