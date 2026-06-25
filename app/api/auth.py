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
from app.utils.validators import LoginSchema
from app.utils.decorators import audit_action

auth_bp = Blueprint('auth', __name__)

login_schema = LoginSchema()


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

        # Check Multi-Factor Authentication
        from flask import session
        if user.mfa_enabled:
            session['pending_mfa_user_id'] = user.id
            if request.is_json:
                return jsonify({'mfa_required': True, 'message': 'MFA code verification required.'}), 200
            return redirect(url_for('auth.login_mfa'))

        # Log user in directly if MFA not enabled
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


@auth_bp.route('/login-mfa', methods=['GET', 'POST'])
def login_mfa():
    """Verify MFA TOTP token for pending login user."""
    from flask import session
    import pyotp
    
    user_id = session.get('pending_mfa_user_id')
    if not user_id:
        flash('No login session pending. Please log in.', 'danger')
        return redirect(url_for('auth.login'))
        
    user = AuthService.get_user_by_id(user_id)
    if not user:
        return redirect(url_for('auth.login'))
        
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if not code:
            flash('MFA verification code is required.', 'danger')
            return render_template('auth/login_mfa.html')
            
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code):
            # Clear pending state and complete login
            session.pop('pending_mfa_user_id')
            login_user(user, remember=True)
            
            AuditService.log_action(
                action='login_mfa_success',
                resource=f'user:{user.id}',
                details=f'MFA challenge passed: {user.username}',
                user_id=user.id
            )
            flash('Logged in successfully with Multi-Factor Authentication.', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid or expired verification code.', 'danger')
            AuditService.log_action(
                action='login_mfa_failed',
                resource=f'user:{user.id}',
                details=f'MFA challenge failed for: {user.username}'
            )
            return render_template('auth/login_mfa.html')
            
    return render_template('auth/login_mfa.html')


@auth_bp.route('/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    """Setup or disable MFA for the logged in user."""
    import pyotp
    from app.extensions import db
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'enable':
            # Generate a new random secret
            secret = pyotp.random_base32()
            current_user.mfa_secret = secret
            current_user.mfa_enabled = True
            db.session.commit()
            
            # Setup standard provisioning URI for authenticator apps (e.g. Google Authenticator)
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name="MachineReplicaIDS")
            
            flash('MFA has been successfully enabled! Configure your authenticator application.', 'success')
            AuditService.log_action(
                action='mfa_enabled',
                resource=f'user:{current_user.id}',
                details='Enabled MFA',
                user_id=current_user.id
            )
            return render_template('auth/mfa_setup.html', secret=secret, uri=provisioning_uri)
            
        elif action == 'disable':
            current_user.mfa_enabled = False
            current_user.mfa_secret = None
            db.session.commit()
            flash('Multi-Factor Authentication has been disabled.', 'info')
            AuditService.log_action(
                action='mfa_disabled',
                resource=f'user:{current_user.id}',
                details='Disabled MFA',
                user_id=current_user.id
            )
            return redirect(url_for('auth.mfa_setup'))
        
    return render_template('auth/mfa_setup.html')


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
